import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import NotMeasured, { NotMeasuredBar } from '../ui/NotMeasured';
import { vendorLabel } from '../devices/vendorMeta';
import { timeAgo, absoluteUtc } from '../../lib/formatDisplay';
import {
  getVpnLoginLocations,
  findUsernameSprayers,
  findFailureOnlyCountries,
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

const CELL = { padding: '9px 12px', fontSize: 'var(--text-sm)', verticalAlign: 'top' };

const TH = {
  textAlign: 'left',
  padding: '8px 12px',
  fontSize: 'var(--text-xs)',
  letterSpacing: '0.07em',
  textTransform: 'uppercase',
  color: 'var(--text-muted)',
  borderBottom: '1px solid var(--border)',
  whiteSpace: 'nowrap',
};

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
  const failureOnly = findFailureOnlyCountries(countries, vendors);
  const maxTotal = countries.reduce((m, c) => Math.max(m, c.total), 0);

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

      {sprayers.length > 0 || (failureOnly.evaluable && failureOnly.rows.length > 0) ? (
        <Card>
          <CardBody>
            <div style={{ fontWeight: 700, marginBottom: 10 }}>Unusual sources</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {sprayers.map((s) => (
                <div key={s.srcIp} style={{ fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
                  <div style={{ ...MONO, fontWeight: 600 }}>
                    {s.srcIp}
                    {s.country ? ` — ${s.country}` : ''}
                  </div>
                  {/* ⛔ The arithmetic, in words. No score, no severity band —
                      the operator judges, and can see exactly why it is here. */}
                  <div style={{ color: 'var(--text-secondary)' }}>
                    {s.failure.toLocaleString()} failed logins across{' '}
                    <strong>{s.usernames.toLocaleString()} different usernames</strong>
                    {s.usernamesTruncated ? '+' : ''}, none successful.
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
                    Flagged because one address tried more than {MIN_USERNAMES_FOR_SPRAY} different
                    usernames and none worked. A user mistyping a password fails against ONE
                    username.
                  </div>
                </div>
              ))}
              {failureOnly.evaluable
                ? failureOnly.rows.slice(0, 5).map((c) => (
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
                  ))
                : null}
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
                {countries.map((c) => (
                  <tr key={c.country} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={CELL}>
                      {c.located ? c.country : (
                        <span style={{ color: 'var(--text-muted)' }}>{c.country}</span>
                      )}
                      {/* ⛔ Only a claim worth making when a success COULD have
                          been observed. With no success baseline anywhere in
                          the window, "no success" describes our logging, not
                          this country. Badge takes no `style` prop (it is
                          silently dropped), so the spacing hangs on a wrapper. */}
                      {successMeasurable && c.failure > 0 && c.success === 0 ? (
                        <span style={{ marginLeft: 6 }}>
                          <Badge color="warning">no success</Badge>
                        </span>
                      ) : null}
                    </td>
                    <td style={{ ...CELL, ...NUM, color: c.success > 0 ? 'var(--green)' : 'var(--text-muted)' }}>
                      {successMeasurable ? (
                        c.success.toLocaleString()
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
                      {ratioBar(c.success, c.failure, maxTotal, successMeasurable)}
                    </td>
                  </tr>
                ))}
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
