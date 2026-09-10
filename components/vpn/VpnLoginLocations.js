import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import NotMeasured, { NotMeasuredBar } from '../ui/NotMeasured';
import { vendorLabel } from '../devices/vendorMeta';
import { SEVERITY_FILL } from '../analysis/severityRamp';
import { timeAgo, absoluteUtc } from '../../lib/formatDisplay';
import {
  getVpnLoginLocations,
  findUsernameSprayers,
  findFailureOnlyCountries,
  groupSourcesByCountry,
  MIN_USERNAMES_FOR_SPRAY,
} from '../../lib/syslog/vpnAuthStats';

export const dynamic = 'force-dynamic';

// Where VPN logins come from, and which are failing.
//
// ── ⛔ WHY THIS IS A TABLE AND NOT A WORLD MAP ────────────────────────────
// The ask was "a global map or geoip". A map was assessed and rejected on the
// merits, not on effort:
//
//   * recharts (the one charting dependency) has NO geographic component, and
//     CLAUDE.md forbids adding libraries. A world outline is 80-150 KB of SVG
//     path data that would have to be inlined into the bundle.
//   * It would render ~21 dots. Without a coastline the dots are unreadable;
//     with one, the reader must still FIND the country before reading it.
//   * A map structurally cannot show a success/failure RATIO per country —
//     which is the actual question ("is someone attacking us, and from where").
//
// A ranked table answers both halves directly, sorts by magnitude, and has
// honest places to put the rows a map would silently drop.
//
// ── ⛔ COVERAGE IS LOPSIDED AND THIS PAGE SAYS SO ─────────────────────────
// Measured over 12h on this fleet: Fortinet logged 2,037 SSL-VPN failures and
// ~4 successes. Its success logids are effectively absent — a DEVICE-SIDE
// logging setting, not something SecVault can fix. So Fortinet's success count
// renders as "not reported", never 0, and any fleet-wide success/failure ratio
// is deliberately NOT shown: it would be a Palo Alto ratio with Fortinet's
// failures added to the denominator, confidently wrong and looking fine.

// ⛔ ROW GEOMETRY COMES FROM THE DENSITY TOKENS, never a hardcoded padding.
// These were '9px 12px' / '8px 12px', so Settings → Appearance → Density did
// nothing to either table on this page while every shared <Table> elsewhere
// changed height. --row-pad-y/--row-pad-x/--row-font are exactly what
// globals.css's own th/td rules use, so a hand-rolled table tracks the switch
// identically to a shared one.
const CELL = {
  padding: 'var(--row-pad-y) var(--row-pad-x)',
  fontSize: 'var(--row-font)',
  verticalAlign: 'top',
};

const TH = {
  textAlign: 'left',
  padding: 'var(--row-pad-y) var(--row-pad-x)',
  fontSize: 'var(--text-xs)',
  letterSpacing: '0.07em',
  textTransform: 'uppercase',
  color: 'var(--text-muted)',
  borderBottom: '1px solid var(--border)',
  whiteSpace: 'nowrap',
};

// How many countries each of the two "unusual sources" lists shows before it
// says "of N". Never truncate silently.
const COUNTRIES_SHOWN = 5;

const MONO = { fontFamily: 'var(--font-mono)' };
const NUM = { textAlign: 'right', fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' };

// Module top level, plain functions returning JSX, called imperatively.
function kpi(value, label, sub, tone) {
  const color =
    tone === 'bad' ? 'var(--red)' : tone === 'good' ? 'var(--green)' : 'var(--text-primary)';
  return (
    <div style={{ background: 'var(--bg-card)', padding: '14px 16px' }}>
      <div style={{ fontSize: 'var(--text-xl)', fontWeight: 700, lineHeight: 1.1, color, fontVariantNumeric: 'tabular-nums' }}>
        {value}
      </div>
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: 4 }}>
        {label}
      </div>
      {sub ? (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>{sub}</div>
      ) : null}
    </div>
  );
}

// Bar scaled to the busiest row, with a visible floor so a one-event country
// does not vanish — the same treatment VpnSyslogActivity already uses.
//
// ⛔ `successMeasurable === false` means NO vendor in this window reported a
// successful login at all (findFailureOnlyCountries' own `evaluable` flag). A
// success/failure MIX cannot be drawn from a denominator nobody reported: the
// bar would be solid red for every country and read as "100% of logins here
// failed", which is a claim about the world made out of a device-side logging
// gap. It is hatched instead — the graphical form of "not measured".
function ratioBar(success, failure, max, successMeasurable) {
  if (!successMeasurable) {
    return (
      <NotMeasuredBar reason="No device in this window reports successful logins, so there is no success/failure mix to draw — only the failure count is real." />
    );
  }
  const w = (n) => (max > 0 ? Math.max(n > 0 ? 1.5 : 0, (n / max) * 100) : 0);
  return (
    <div style={{ display: 'flex', height: 7, borderRadius: 'var(--radius-pill)', overflow: 'hidden', background: 'var(--bg-primary)' }}>
      <div style={{ width: `${w(success)}%`, background: 'var(--green)' }} title={`${success} successful`} />
      <div style={{ width: `${w(failure)}%`, background: 'var(--red)' }} title={`${failure} failed`} />
    </div>
  );
}

// ── The flagged-source drill-down ─────────────────────────────────────────
//
// ⛔ WHY THIS IS A <details> ACCORDION AND NOT A CLICKABLE MAP. The ask was
// "a global heatmap the user can click and drill down, or collapse it". The
// map half is refused for the reasons already recorded at the top of this file
// (no geographic component in recharts, no library allowed, and a map cannot
// show a per-country ratio). The COLLAPSE half is the real complaint and is
// what this builds: 247 flagged addresses became 11 country rows.
//
// <details>/<summary> is native, server-rendered and needs no client bundle —
// this is a server component and the page ships no JS for it today. A
// client-side accordion would mean 'use client' on a component that queries a
// 28M-row/day rollup, for a triangle the browser already draws.
//
// ⛔ ROW GEOMETRY FROM THE DENSITY TOKENS, in every summary, same as CELL
// above. A hardcoded padding here would sit at one height while the tables
// beside it change with Settings → Appearance → Density.
const SUMMARY = {
  cursor: 'pointer',
  padding: 'var(--row-pad-y) var(--row-pad-x)',
  fontSize: 'var(--row-font)',
  lineHeight: 1.5,
};

// Proportional heat bar for one country row.
//
// ⛔ THE HUE COMES FROM components/analysis/severityRamp.js AND NOWHERE ELSE.
// That file exists because the v2.87.0 palette rewrite left six private copies
// of the ramp behind, each still drawing `medium` in BLUE — one step from the
// brand teal, which is the exact collapse the palette forbids. A seventh local
// colour map here would be the same bug again.
//
// ⛔ A GROUP WITH NO RESOLVABLE COUNTRY GETS NO HUE. Its bar is drawn at its
// real proportional width — the failure count IS measured — but hatched, in
// --unmeasured's vocabulary, because the thing we could not read is WHERE it
// is. Colouring it on the severity ramp would rank a gap in geolocation
// alongside eleven real places.
function heatBar(failure, max, band, located) {
  const pct = max > 0 ? Math.max(failure > 0 ? 2 : 0, (failure / max) * 100) : 0;
  const hue = band ? SEVERITY_FILL[band] : null;
  const title = located
    ? `${failure.toLocaleString()} failed logins — ${
        max > 0 ? Math.round((failure / max) * 100) : 0
      }% of the worst country in this window`
    : 'The firewall attached no country to these addresses. The failure count is real; the location is not measured, so this bar carries no severity colour.';
  return (
    <span
      title={title}
      style={{
        display: 'block',
        width: '100%',
        height: 8,
        borderRadius: 'var(--radius-pill)',
        background: 'var(--bg-primary)',
        border: '1px solid var(--border)',
        overflow: 'hidden',
      }}
    >
      <span
        style={{
          display: 'block',
          width: `${pct}%`,
          height: '100%',
          ...(located && hue
            ? { background: hue }
            : { background: 'var(--hatch)', backgroundColor: 'var(--surface-subtle)' }),
        }}
      />
    </span>
  );
}

// One flagged address — LEVEL 3. Collapsed to a single sentence of arithmetic;
// expands to the evidence and the provenance.
//
// ⛔ NEVER DEFINE A COMPONENT INSIDE A COMPONENT (CLAUDE.md Critical Rules).
// These are module-level plain functions returning JSX, called imperatively —
// the same convention kpi()/ratioBar() above already use.
function sourceRow(s) {
  return (
    <details key={s.srcIp} style={{ borderTop: '1px dashed var(--border-light)' }}>
      <summary style={{ ...SUMMARY, paddingLeft: 0, paddingRight: 0 }}>
        <span style={{ ...MONO, fontWeight: 600 }}>{s.srcIp}</span>{' '}
        <span style={{ color: 'var(--text-secondary)' }}>
          — {s.failure.toLocaleString()} failed logins across{' '}
          <strong>
            {s.usernames.toLocaleString()}
            {s.usernamesTruncated ? '+' : ''} different usernames
          </strong>
          , none successful.
        </span>
      </summary>
      <div
        style={{
          padding: `0 0 var(--row-pad-y) var(--s4)`,
          fontSize: 'var(--text-xs)',
          color: 'var(--text-muted)',
          lineHeight: 1.6,
        }}
      >
        {/* ⛔ VERBATIM, and still PER SOURCE. This sentence is the whole reason
            an operator trusts the flag — it is the rule stated as arithmetic,
            with no score and no severity band. Folding 247 stanzas into 11 rows
            must not cost the reader the one line that explains any of them. */}
        <div>
          Flagged because one address tried more than {MIN_USERNAMES_FOR_SPRAY} different usernames
          and none worked. A user mistyping a password fails against ONE username.
        </div>
        <div style={{ marginTop: 'var(--s1)' }}>
          Reported by {vendorLabel(s.vendor)} · last seen{' '}
          <span title={absoluteUtc(s.lastSeenAt) || ''}>
            {timeAgo(s.lastSeenAt) || (
              <NotMeasured reason="No usable timestamp on this source's most recent event." />
            )}
          </span>
        </div>
        {s.usernamesTruncated ? (
          <div style={{ marginTop: 'var(--s1)' }}>
            The rollup truncated this address&rsquo;s username list, so {s.usernames.toLocaleString()}{' '}
            is a FLOOR, not the total. It tried at least that many.
          </div>
        ) : null}
      </div>
    </details>
  );
}

// One country — LEVEL 2. The summary states the counts and previews the worst
// address in the group WITHOUT a click.
function countryRow(c, maxFailures) {
  const label = c.located ? c.country : '(no country reported)';
  return (
    <details key={label} style={{ borderTop: '1px solid var(--border)' }}>
      <summary style={SUMMARY}>
        <span
          style={{
            display: 'inline-flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            gap: 'var(--s3)',
            width: 'calc(100% - 1.5em)',
          }}
        >
          <span style={{ fontWeight: 700, minWidth: 150 }}>
            {c.located ? (
              c.country
            ) : (
              // ⛔ Never folded into a real country and never invented as
              // "Unknown". SecVault holds no GeoIP database of its own; this is
              // the firewall declining to answer.
              <NotMeasured
                text="No country reported"
                reason="The firewall attached no country to these addresses, and SecVault holds no GeoIP database of its own. These failures are real; their location is not measured."
              />
            )}
          </span>
          <span style={{ flex: '0 0 110px' }}>
            {heatBar(c.failure, maxFailures, c.band, c.located)}
          </span>
          {/* ⛔ THE COUNTS, STATED. A collapsed group that does not say what it
              collapsed is the silent-truncation bug this codebase keeps
              fixing. */}
          <span style={{ color: 'var(--text-secondary)', fontVariantNumeric: 'tabular-nums' }}>
            {c.sourceCount.toLocaleString()} source{c.sourceCount === 1 ? '' : 's'},{' '}
            {c.failure.toLocaleString()} failures
          </span>
        </span>
        {/* ⛔ THE PREVIEW — the point of the whole redesign. One Bulgarian
            address ran 1,680 failures against 834 usernames; hiding it behind
            two clicks to save scrolling would be a worse product than the
            scrolling. Every country shows its worst address with no
            interaction. */}
        {c.worst ? (
          <span
            style={{
              display: 'block',
              marginTop: 'var(--s1)',
              fontSize: 'var(--text-xs)',
              color: 'var(--text-muted)',
            }}
          >
            Worst: <span style={MONO}>{c.worst.srcIp}</span> — {c.worst.failure.toLocaleString()}{' '}
            failed logins across{' '}
            <strong>
              {c.worst.usernames.toLocaleString()}
              {c.worst.usernamesTruncated ? '+' : ''} different usernames
            </strong>
            , none successful.
          </span>
        ) : null}
      </summary>
      <div style={{ padding: '0 var(--row-pad-x) var(--row-pad-y) var(--row-pad-x)' }}>
        {c.sources.map((s) => sourceRow(s))}
        <div
          style={{
            marginTop: 'var(--s2)',
            fontSize: 'var(--text-xs)',
            color: 'var(--text-muted)',
          }}
        >
          {c.hiddenSources > 0
            ? `Showing ${c.sources.length} of ${c.sourceCount.toLocaleString()} flagged addresses in ${label}, worst first. ${c.hiddenSources.toLocaleString()} more are not listed.`
            : `Showing all ${c.sourceCount.toLocaleString()} flagged address${
                c.sourceCount === 1 ? '' : 'es'
              } in ${label}.`}
        </div>
      </div>
    </details>
  );
}

export default async function VpnLoginLocations() {
  let data;
  try {
    data = await getVpnLoginLocations(pool, 24);
  } catch (err) {
    return (
      <Card>
        <CardBody>
          {/* ⛔ An error is not an empty result. Name the question that went
              unanswered and say explicitly that nothing may be concluded from
              the blank space — a failed query that renders as "no attacks
              observed" is the failed-read-as-a-fact bug wearing a stack trace. */}
          <div
            style={{
              background: 'var(--tint-danger)',
              color: 'var(--tint-danger-fg)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: 'var(--s3) var(--s4)',
              fontSize: 'var(--text-sm)',
              lineHeight: 1.6,
            }}
          >
            <strong>Could not answer &ldquo;where are VPN logins coming from?&rdquo;</strong>
            <div style={{ marginTop: 'var(--s1)' }}>
              The query against the syslog rollups failed: {err.message}
            </div>
            <div style={{ marginTop: 'var(--s1)' }}>
              Nothing below this point was measured — this is not a report of zero login activity.
            </div>
          </div>
        </CardBody>
      </Card>
    );
  }

  const { countries, sources, totals, vendors, windowHours } = data;
  const sprayers = findUsernameSprayers(sources);
  // ⛔ PRESENTATION ONLY. `sprayers` is still exactly what findUsernameSprayers()
  // returned — the grouping reorders it, it does not re-decide what is flagged.
  const sprayerGroups = groupSourcesByCountry(sprayers);
  const failureOnly = findFailureOnlyCountries(countries, vendors);
  const maxTotal = countries.reduce((m, c) => Math.max(m, c.total), 0);

  // ⛔ The "no successful login from here" claim is now PER COUNTRY, because the
  // gate behind it is per vendor: a country whose failures were reported by a
  // vendor that reports no successes at all cannot be asserted, even while a
  // different vendor's countries in the same window can. These two sets are the
  // engine's own verdict, not a re-derivation of the rule in the view.
  const assertedNoSuccess = new Set(failureOnly.rows.map((c) => c.country));
  const caveatedNoSuccess = new Map(failureOnly.caveated.map((c) => [c.country, c]));
  // Why THIS country's zero is not a measurement, named down to the vendor.
  const caveatReason = (c) => {
    const v = (c && c.unmeasuredVendors) || [];
    const who = v.length ? v.map(vendorLabel).join(' and ') : 'the reporting device';
    return `${who} reported these failures but reported no successful VPN login anywhere in this window, so a zero here is a device-side logging gap, not a fact about this country.`;
  };

  // ⛔ THE SINGLE MOST DANGEROUS ZERO ON THIS PAGE. When no vendor in the window
  // reported ANY successful login (measured live: Fortinet's SSL-VPN success
  // logids are effectively absent on this fleet), every success count here is
  // 0 — not because nobody logged in, but because no firewall said so. Drawn as
  // a number, that 0 is a fabricated fact, and next to a four-digit failure
  // count it manufactures an incident. It is rendered as NotMeasured instead,
  // everywhere it appears: the KPI, both tables' Successful column, and the mix
  // bar. `failureOnly.evaluable` is exactly this question, already computed.
  const successMeasurable = failureOnly.evaluable;

  if (countries.length === 0 && totals.privateSuccess + totals.privateFailure === 0) {
    return (
      <Card>
        <CardBody>
          <EmptyState message="No VPN authentication events in the last 24 hours. This view counts only genuine login attempts — tunnel negotiation and session housekeeping are excluded, and they are the bulk of VPN log volume." />
        </CardBody>
      </Card>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: 1,
          background: 'var(--border)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          overflow: 'hidden',
        }}
      >
        {successMeasurable
          ? kpi(totals.success.toLocaleString(), 'successful logins', `last ${windowHours}h`, 'good')
          : kpi(
              <NotMeasured reason="No device in this window reported a successful VPN login. This is a device-side logging gap, not a count of zero." />,
              'successful logins',
              'not reported by any device'
            )}
        {kpi(totals.failure.toLocaleString(), 'failed logins', `last ${windowHours}h`, totals.failure > 0 ? 'bad' : null)}
        {kpi(String(countries.filter((c) => c.located).length), 'countries', 'with at least one attempt')}
        {kpi(String(sprayers.length), 'unusual sources', 'see below', sprayers.length > 0 ? 'bad' : null)}
      </div>

      {/* ⛔ Coverage stated as fact, per vendor, before any number is read. */}
      <Card>
        <CardBody>
          <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.7 }}>
            <strong>What this covers.</strong>{' '}
            {vendors.length === 0
              ? 'No vendor reported a VPN authentication in this window.'
              : vendors.map((v) => (
                  <span key={v.vendor} style={{ display: 'block' }}>
                    {vendorLabel(v.vendor)} — {v.failure.toLocaleString()} failed,{' '}
                    {/* ⛔ "not reported", never 0. Fortinet's SSL-VPN success
                        logids are absent on this fleet; rendering that as a
                        zero would report a device configuration gap as a
                        security fact. */}
                    {v.success > 0 ? (
                      `${v.success.toLocaleString()} successful.`
                    ) : (
                      // ⛔ HUELESS, not amber. This was --yellow, which spends
                      // the severity ramp on an absence of data: a reader
                      // scanning for colour saw a warning about the FIREWALL
                      // when the fact is about SECVAULT's visibility.
                      // components/ui/NotMeasured.js: never colour a gap.
                      <span style={{ color: 'var(--unmeasured)' }}>
                        successful logins <strong>not reported</strong> by these devices — so
                        failures here have no success baseline to compare against.
                      </span>
                    )}
                  </span>
                ))}
            <span style={{ display: 'block', color: 'var(--text-muted)', marginTop: 6 }}>
              Check Point, Cisco ASA, Sangfor and Forcepoint have no syslog parser and are not
              represented on this page.
            </span>
          </div>
        </CardBody>
      </Card>

      {sprayers.length > 0 || failureOnly.rows.length > 0 || failureOnly.caveated.length > 0 ? (
        <Card>
          <CardBody>
            <div style={{ fontWeight: 700, marginBottom: 10 }}>Unusual sources</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {/* ⛔ LEVEL 1 — the headline counts, before anything is collapsed.
                  This list used to render one stanza per flagged address: 247
                  of them on the live fleet, which is unreadable. It is now
                  folded into countries, and the fold states exactly what it
                  folded. A collapsed list that does not say what it collapsed is
                  indistinguishable from a short one. */}
              {sprayerGroups.totalSources > 0 ? (
                <div>
                  <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
                    <strong>Username sprays</strong>{' '}
                    <span style={{ color: 'var(--text-secondary)' }}>
                      — {sprayerGroups.totalCountries.toLocaleString()}{' '}
                      {sprayerGroups.totalCountries === 1 ? 'country' : 'countries'} ·{' '}
                      {sprayerGroups.totalSources.toLocaleString()} flagged sources ·{' '}
                      {sprayerGroups.totalFailures.toLocaleString()} failed logins in the last{' '}
                      {windowHours} hours.
                    </span>
                  </div>
                  <div
                    style={{
                      fontSize: 'var(--text-xs)',
                      color: 'var(--text-muted)',
                      lineHeight: 1.6,
                      marginTop: 2,
                    }}
                  >
                    Flagged because one address tried more than {MIN_USERNAMES_FOR_SPRAY} different
                    usernames and none worked. A user mistyping a password fails against ONE
                    username. Countries are ordered by failures; each shows its worst address
                    without expanding.
                  </div>
                  <div
                    style={{
                      marginTop: 'var(--s3)',
                      border: '1px solid var(--border)',
                      borderRadius: 'var(--radius)',
                      overflow: 'hidden',
                    }}
                  >
                    {sprayerGroups.countries.map((c) => countryRow(c, sprayerGroups.maxFailures))}
                  </div>
                </div>
              ) : null}

              {failureOnly.rows.slice(0, COUNTRIES_SHOWN).map((c) => (
                <div key={c.country} style={{ fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
                  <div style={{ fontWeight: 600 }}>{c.country}</div>
                  <div style={{ color: 'var(--text-secondary)' }}>
                    {c.failure.toLocaleString()} failed logins from {c.sources} address(es), none
                    successful.
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
                    {/* ⛔ Never "unauthorised country". A country with no
                        successes may simply be one no employee has
                        travelled to yet. */}
                    No successful login has been observed from here in the last {windowHours}{' '}
                    hours.
                  </div>
                </div>
              ))}
              {/* ⛔ "of N". A bare truncated list is indistinguishable from a
                  complete one, and the reader has no way to know a country was
                  cut off — the Busiest sources table two sections down already
                  says "15 of 21" for exactly this reason. */}
              {failureOnly.rows.length > COUNTRIES_SHOWN ? (
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  Showing {COUNTRIES_SHOWN} of {failureOnly.rows.length} countries with failures and
                  no successful login.
                </div>
              ) : null}

              {/* ⛔ THE UNGATED COUNTRIES. These look identical to the ones above
                  — failures, no successes — and the whole point is that they are
                  NOT the same finding. The vendor that reported these failures
                  reports no successful login anywhere in this window, so its
                  zero is our blindness, not the country's behaviour. Shown, not
                  hidden (the failures are real evidence), but never asserted. */}
              {failureOnly.caveated.slice(0, COUNTRIES_SHOWN).map((c) => (
                <div key={'caveat-' + c.country} style={{ fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
                  <div style={{ fontWeight: 600 }}>
                    {c.country}{' '}
                    <NotMeasured
                      text="outcome not measurable"
                      reason={caveatReason(c)}
                    />
                  </div>
                  <div style={{ color: 'var(--text-secondary)' }}>
                    {c.failure.toLocaleString()} failed logins from {c.sources} address(es).
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
                    Whether any login has SUCCEEDED from here is not measured: {caveatReason(c)}
                  </div>
                </div>
              ))}
              {failureOnly.caveated.length > COUNTRIES_SHOWN ? (
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  Showing {COUNTRIES_SHOWN} of {failureOnly.caveated.length} countries whose success
                  baseline is not measurable.
                </div>
              ) : null}
            </div>
            {!failureOnly.evaluable ? (
              <div style={{ marginTop: 10, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                The &ldquo;no successful login from here&rdquo; check is disabled: no vendor in this
                window reported a successful login, so there is no baseline to compare against.
                Enabling SSL-VPN success logging on the FortiGates would turn it on.
              </div>
            ) : null}
          </CardBody>
        </Card>
      ) : null}

      <Card>
        <CardBody>
          <div style={{ fontWeight: 700, marginBottom: 10 }}>Login attempts by country</div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 720 }}>
              <thead>
                <tr>
                  <th style={TH}>Country</th>
                  <th style={{ ...TH, ...NUM }}>Successful</th>
                  <th style={{ ...TH, ...NUM }}>Failed</th>
                  <th style={{ ...TH, ...NUM }}>Addresses</th>
                  <th style={{ ...TH, ...NUM }}>Usernames</th>
                  <th style={TH}>Mix</th>
                </tr>
              </thead>
              <tbody>
                {countries.map((c) => {
                  // Per-country, not fleet-wide: this country's zero successes
                  // is a measurement only if every vendor that reported its
                  // failures also reports successes somewhere.
                  const caveat = caveatedNoSuccess.get(c.country);
                  const countrySuccessMeasurable = successMeasurable && !caveat;
                  return (
                  <tr key={c.country} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={CELL}>
                      {c.located ? c.country : (
                        <span style={{ color: 'var(--text-muted)' }}>{c.country}</span>
                      )}
                      {/* ⛔ Only a claim worth making when a success COULD have
                          been observed FROM HERE. With no success baseline for
                          the vendor that reported these failures, "no success"
                          describes our logging, not this country. Badge takes no
                          `style` prop (it is silently dropped), so the spacing
                          hangs on a wrapper. */}
                      {assertedNoSuccess.has(c.country) ? (
                        <span style={{ marginLeft: 6 }}>
                          <Badge color="warning">no success</Badge>
                        </span>
                      ) : null}
                    </td>
                    <td style={{ ...CELL, ...NUM, color: c.success > 0 ? 'var(--green)' : 'var(--text-muted)' }}>
                      {countrySuccessMeasurable ? (
                        c.success.toLocaleString()
                      ) : caveat ? (
                        <NotMeasured reason={caveatReason(caveat)} />
                      ) : (
                        <NotMeasured reason="No device in this window reports successful logins, so this is not a count of zero." />
                      )}
                    </td>
                    <td style={{ ...CELL, ...NUM, color: c.failure > 0 ? 'var(--red)' : 'var(--text-muted)' }}>
                      {c.failure.toLocaleString()}
                    </td>
                    <td style={{ ...CELL, ...NUM }}>{c.sources.toLocaleString()}</td>
                    <td style={{ ...CELL, ...NUM }}>{c.usernames.toLocaleString()}</td>
                    <td style={{ ...CELL, width: 140 }}>
                      {ratioBar(c.success, c.failure, maxTotal, countrySuccessMeasurable)}
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* ⛔ The private-range pseudo-countries, bucketed and never ranked.
              PAN-OS writes "172.16.0.0-172.31.255.255" into the country field
              and FortiOS writes "Reserved" — the vendor's own answer, kept
              verbatim, but not a location. */}
          {totals.privateSuccess + totals.privateFailure > 0 ? (
            <div style={{ marginTop: 10, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              A further {(totals.privateSuccess + totals.privateFailure).toLocaleString()} attempt(s)
              came from internal or private addresses, which the firewall reports as a range rather
              than a country. They are counted here but not ranked as a location.
            </div>
          ) : null}
        </CardBody>
      </Card>

      {sources.length > 0 ? (
        <Card>
          <CardBody>
            <div style={{ fontWeight: 700, marginBottom: 10 }}>
              Busiest sources ({Math.min(sources.length, 15)} of {sources.length})
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 680 }}>
                <thead>
                  <tr>
                    <th style={TH}>Address</th>
                    <th style={TH}>Country</th>
                    <th style={{ ...TH, ...NUM }}>Successful</th>
                    <th style={{ ...TH, ...NUM }}>Failed</th>
                    <th style={{ ...TH, ...NUM }}>Usernames</th>
                    <th style={TH}>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {sources.slice(0, 15).map((s) => (
                    <tr key={s.srcIp} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ ...CELL, ...MONO, whiteSpace: 'nowrap' }}>{s.srcIp}</td>
                      <td style={{ ...CELL, color: 'var(--text-secondary)' }}>
                        {s.country || (
                          <NotMeasured reason="The firewall did not attach a country to this source. SecVault holds no GeoIP database of its own." />
                        )}
                      </td>
                      <td style={{ ...CELL, ...NUM, color: s.success > 0 ? 'var(--green)' : 'var(--text-muted)' }}>
                        {successMeasurable ? (
                          s.success.toLocaleString()
                        ) : (
                          <NotMeasured reason="No device in this window reports successful logins, so this is not a count of zero." />
                        )}
                      </td>
                      <td style={{ ...CELL, ...NUM, color: s.failure > 0 ? 'var(--red)' : 'var(--text-muted)' }}>
                        {s.failure.toLocaleString()}
                      </td>
                      <td style={{ ...CELL, ...NUM }}>
                        {s.usernames.toLocaleString()}
                        {s.usernamesTruncated ? '+' : ''}
                      </td>
                      <td style={{ ...CELL, whiteSpace: 'nowrap' }} title={absoluteUtc(s.lastSeenAt) || ''}>
                        {timeAgo(s.lastSeenAt) || (
                          <NotMeasured reason="No usable timestamp on this source's most recent event." />
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardBody>
        </Card>
      ) : null}
    </div>
  );
}
