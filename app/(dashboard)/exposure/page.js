import Link from 'next/link';
import { pool } from '../../../lib/db';
import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../components/ui/Card';
import Badge from '../../../components/ui/Badge';
import EmptyState from '../../../components/ui/EmptyState';
import { computeFleetExposure } from '../../../lib/engines/exposureQuery';
import { SEVERITY_BADGE_COLOR, SEVERITY_LABEL } from '../../../components/analysis/severityRamp';
import Pagination from '../../../components/ui/Pagination';
import { resolvePage, resolvePageSize, paginateArray, DEFAULT_PAGE_SIZE } from '../../../lib/pagination';

export const dynamic = 'force-dynamic';

// Internet Exposure & Attack Surface.
//
// Answers "what is reachable from the internet, through which rule, to which
// internal host" — and, where syslog covers the device, whether it was
// actually reached.
//
// ⛔ THE THREE-STATE OBSERVATION IS THE POINT OF THIS PAGE, and the single
// thing most likely to be quietly broken by a later edit:
//
//   Reached      allowed traffic from a public source was seen arriving.
//   Not seen     we WERE watching and saw none. The path is still open.
//   Unmeasured   we could not pose the question at all -- no syslog from the
//                device, no inbound traffic we can match against its own
//                addresses, or a service that resolved to no port range. NOT
//                the same as "not seen", and the two must never be rendered
//                alike or merged into one column.
//
// A quiet path is NOT filtered out, dimmed to invisibility, or sorted to
// oblivion: an unused open door is still open, and treating quiet as closed is
// how a forgotten vendor rule survives an audit.

// ⛔ ROW GEOMETRY COMES FROM THE DENSITY TOKENS, never a hardcoded padding.
// These cells used to be '10px 12px' / '9px 12px' with a literal 10px heading,
// so Settings → Appearance → Density did nothing to this table while every
// shared <Table> around it changed height. --row-pad-y/--row-pad-x/--row-font
// are exactly what globals.css's own th/td rules use, so a hand-rolled table
// tracks the switch identically to a shared one.
const CELL = {
  padding: 'var(--row-pad-y) var(--row-pad-x)',
  verticalAlign: 'top',
  fontSize: 'var(--row-font)',
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

const KPI_GRID = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
  gap: 1,
  background: 'var(--border)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius)',
  overflow: 'hidden',
  marginBottom: 18,
};

const MONO = {
  fontFamily: 'var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace)',
  fontSize: 'var(--text-sm)',
};

function kpi(value, label, sub, tone) {
  const color =
    tone === 'bad'
      ? 'var(--red)'
      : tone === 'warn'
        ? 'var(--yellow)'
        : tone === 'muted'
          ? 'var(--text-muted)'
          : 'var(--text-primary)';
  return (
    <div key={label} style={{ background: 'var(--bg-card)', padding: '14px 16px' }}>
      <div
        style={{
          fontSize: 26,
          fontWeight: 700,
          lineHeight: 1.1,
          letterSpacing: '-0.02em',
          fontVariantNumeric: 'tabular-nums',
          color,
        }}
      >
        {value}
      </div>
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: 4 }}>
        {label}
      </div>
      {sub ? (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>
          {sub}
        </div>
      ) : null}
    </div>
  );
}

// ⛔ Module top level, a plain function returning JSX called imperatively.
//
// observed + notObserved + unmeasured === paths, but they were four peer tiles
// of identical weight, so the thing this page exists to say — what fraction of
// the attack surface we cannot see at all — had to be computed by the reader.
// The paragraph of prose underneath was the tell that the number needed a shape.
//
// ⛔ The three segments differ in KIND, not just hue, so "we could not look"
// cannot be mistaken for a measured quiet result at a glance or in greyscale:
//   reached      solid red      — measured, and in use
//   not seen     solid grey     — measured, and quiet. Still an open door.
//   unmeasured   HATCHED yellow — not a measurement at all
//
// ⛔ A zero-width segment still renders its label. A state that vanishes when
// its count is 0 reads as "that state does not apply here", which is a
// different claim from "zero".
function exposureProportionBar(totals) {
  const total = totals.observed + totals.notObserved + totals.unmeasured;
  if (total <= 0) return null;

  const pct = (n) => `${(n / total) * 100}%`;
  const segments = [
    { key: 'observed', n: totals.observed, label: 'reached', bg: 'var(--red)' },
    { key: 'notObserved', n: totals.notObserved, label: 'not seen', bg: 'var(--border)' },
    {
      key: 'unmeasured',
      n: totals.unmeasured,
      label: 'unmeasured',
      // ⛔ --hatch, the shared hueless token, NOT a hand-rolled yellow one.
      // This drew the same 45° pattern in --yellow until 2026-09-09, and
      // --yellow is the MEDIUM step of the severity ramp — so "we could not
      // look at this" rendered as a medium-severity finding sitting between a
      // red measured-reached and a grey measured-quiet. CLAUDE.md's design
      // system is explicit that a not-measured state has NO HUE: --unmeasured
      // for text, --hatch for a bar segment or swatch. The KIND distinction
      // this bar's comment above relies on survives intact — hatched versus
      // solid is what carries it, and it still works in greyscale.
      bg: 'var(--hatch)',
    },
  ];

  return (
    <div style={{ marginBottom: 18 }}>
      <div
        style={{
          display: 'flex',
          height: 12,
          borderRadius: 'var(--radius-pill)',
          overflow: 'hidden',
          background: 'var(--bg-primary)',
          border: '1px solid var(--border)',
        }}
      >
        {segments
          .filter((s) => s.n > 0)
          .map((s) => (
            <div
              key={s.key}
              title={`${s.n.toLocaleString()} ${s.label}`}
              style={{ width: pct(s.n), background: s.bg, height: '100%' }}
            />
          ))}
      </div>
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 14,
          marginTop: 6,
          fontSize: 'var(--text-xs)',
          color: 'var(--text-muted)',
        }}
      >
        {segments.map((s) => (
          <span key={s.key} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
            <span
              aria-hidden="true"
              style={{
                width: 10,
                height: 10,
                borderRadius: 2,
                border: '1px solid var(--border)',
                background: s.bg,
                display: 'inline-block',
              }}
            />
            {s.n.toLocaleString()} {s.label}
          </span>
        ))}
      </div>
    </div>
  );
}

// ⛔ THE RAMP, from components/analysis/severityRamp.js — not a local map.
// 'critical' and 'high' both returned `danger` here, so the most exposed path
// on the fleet was indistinguishable from the one below it and the sort order
// was the only thing carrying the difference. 'high' is --orange on this
// product's ramp; red stays reserved for the top band.
function severityBadge(sev) {
  const key = SEVERITY_BADGE_COLOR[sev] ? sev : 'low';
  return <Badge color={SEVERITY_BADGE_COLOR[key]}>{SEVERITY_LABEL[key]}</Badge>;
}

// ⛔ Three distinct renderings for three distinct states. "Not seen" and
// "Unmeasured" must never collapse into one another — see the file header.
function observationBadge(observation) {
  if (observation === 'observed') return <Badge color="danger">Reached</Badge>;
  if (observation === 'not_observed') return <Badge color="muted">Not seen</Badge>;
  return <Badge color="warning">Unmeasured</Badge>;
}

export default async function ExposurePage({ searchParams }) {
  const fleet = await computeFleetExposure(pool, { lookbackDays: 7 });
  const { totals } = fleet;

  // ⛔ `allRows` IS THE FLEET, and several things below must keep using it
  // rather than the current page: the KPI tiles, the unmeasured caveat, and the
  // "why the top paths scored as they did" panel, which is about the highest-
  // severity paths ANYWHERE — not the highest-severity paths that happen to be
  // on page 3. Scoping either of those to the page would turn a fleet statement
  // into a per-page one without changing a word of its label.
  const allRows = fleet.devices
    .flatMap((d) => d.paths.map((p) => ({ ...p, deviceName: d.name, deviceId: d.deviceId })))
    .sort((a, b) => b.score - a.score);

  // Paginated in memory: exposure paths are COMPUTED per request from rules,
  // interfaces and NAT, not selected from a table, so there is no LIMIT to push
  // down to SQL. paginateArray clamps a past-the-end ?page= to the last page
  // rather than rendering an empty table, which would read as "no exposure".
  const pageSize = resolvePageSize(searchParams?.limit, DEFAULT_PAGE_SIZE);
  const paged = paginateArray(allRows, resolvePage(searchParams?.page), pageSize);
  const rows = paged.rows;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader
        title="Internet Exposure"
        subtitle={
          'What is reachable from the internet, through which rule, to which internal host — ' +
          'and whether traffic was actually observed arriving.'
        }
      />

      {totals.devices === 0 ? (
        <Card>
          <CardBody>
            <EmptyState message="No active devices. Add a firewall to see its internet-facing attack surface." />
          </CardBody>
        </Card>
      ) : (
        <>
          <div style={KPI_GRID}>
            {kpi(String(totals.paths), 'exposure paths', `across ${totals.devicesWithExposure} device(s)`)}
            {kpi(
              String(totals.critical + totals.high),
              'critical or high',
              'broad source or service scope',
              totals.critical + totals.high > 0 ? 'bad' : null
            )}
            {kpi(
              String(totals.observed),
              'reached',
              'allowed traffic seen from a public source',
              totals.observed > 0 ? 'bad' : null
            )}
            {kpi(String(totals.notObserved), 'not seen', 'watched, no traffic — still open', 'muted')}
            {kpi(
              String(totals.unmeasured),
              'unmeasured',
              'cannot be measured — NOT "clean"',
              totals.unmeasured > 0 ? 'warn' : null
            )}
            {kpi(String(totals.publicIps), 'public addresses', 'on device interfaces')}
          </div>

          {exposureProportionBar(totals)}

          {totals.unmeasured > 0 ? (
            <Card>
              <CardBody>
                {/* ⛔ Stated up front rather than buried in a tooltip. A reader
                    who does not know these paths are unmeasured will read the
                    "reached" count as the whole story.
                    ⛔ Two DISTINCT gaps, deliberately not merged: a device we
                    cannot hear at all, and one we can hear but whose own
                    addresses we cannot match traffic against. The second used
                    to be reported as "watched, saw nothing". */}
                <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
                  <strong>{totals.unmeasured}</strong> of these paths cannot be measured, so
                  SecVault does not say whether they were reached.
                  {totals.devicesWithoutSyslog > 0 ? (
                    <>
                      {' '}
                      <strong>{totals.devicesWithoutSyslog}</strong> device(s) sent no syslog at all
                      in the window.
                    </>
                  ) : null}
                  {totals.devicesWithoutInboundCoverage > 0 ? (
                    <>
                      {' '}
                      <strong>{totals.devicesWithoutInboundCoverage}</strong> device(s) are sending
                      syslog, but none of it is addressed to an interface or NAT address SecVault
                      has collected — so there is nothing to match against. Collecting interfaces
                      for those devices is what turns these into real measurements.
                    </>
                  ) : null}{' '}
                  They are shown as <em>Unmeasured</em>, never as unused — absence of an
                  observation is not evidence of absence.
                </div>
              </CardBody>
            </Card>
          ) : null}

          {rows.length === 0 ? (
            <Card>
              <CardBody>
                <EmptyState message="No internet-facing exposure paths were found. This means no enabled allow rule was matched to a public interface address or a destination-NAT published address — not that the fleet has no public presence." />
              </CardBody>
            </Card>
          ) : (
            <Card>
              <CardBody>
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 980 }}>
                    <thead>
                      <tr>
                        <th style={TH}>Severity</th>
                        <th style={TH}>Device</th>
                        <th style={TH}>Public address</th>
                        <th style={TH}>Service</th>
                        <th style={TH}>Internal target</th>
                        <th style={TH}>Permitted by</th>
                        <th style={TH}>Observed</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((p, i) => (
                        <tr
                          key={`${p.deviceId}-${p.publicIp}-${p.ruleName}-${i}`}
                          style={{ borderBottom: '1px solid var(--border)' }}
                        >
                          <td style={{ ...CELL, whiteSpace: 'nowrap' }}>
                            {severityBadge(p.severity)}
                            <div
                              style={{
                                fontSize: 'var(--text-xs)',
                                color: 'var(--text-muted)',
                                marginTop: 4,
                                fontVariantNumeric: 'tabular-nums',
                              }}
                            >
                              score {p.score}
                            </div>
                          </td>
                          <td style={{ ...CELL, whiteSpace: 'nowrap' }}>
                            <Link
                              href={`/devices/${p.deviceId}`}
                              style={{ color: 'var(--text-primary)', fontWeight: 600 }}
                            >
                              {p.deviceName}
                            </Link>
                          </td>
                          <td style={{ ...CELL, ...MONO, whiteSpace: 'nowrap' }}>
                            {p.publicIp}
                            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                              {p.via === 'nat' ? 'via destination NAT' : p.interfaceName || 'interface'}
                            </div>
                          </td>
                          <td style={{ ...CELL, ...MONO }}>
                            {p.service.isAny ? (
                              <span style={{ color: 'var(--red)' }}>any</span>
                            ) : (
                              p.service.label
                            )}
                          </td>
                          <td style={{ ...CELL, ...MONO }}>
                            {/* ⛔ Em-dash, not a guess. The roadmap's graph
                                continues into applications and data stores;
                                SecVault has no asset inventory, so the path
                                honestly stops at the last collected fact. */}
                            {p.internal ? (
                              p.internal.join(', ')
                            ) : (
                              <span style={{ color: 'var(--text-muted)' }}>the device itself</span>
                            )}
                          </td>
                          <td style={{ ...CELL, maxWidth: 220 }}>
                            <div style={{ fontWeight: 600 }}>{p.ruleName || '(unnamed rule)'}</div>
                            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                              {p.ruleSequence !== null ? `seq ${p.ruleSequence}` : null}
                              {p.vdom ? ` · ${p.vdom}` : ''}
                              {p.logEnabled ? '' : ' · logging off'}
                            </div>
                            {/* ⛔ A path we could not direction-check is still
                                listed — under-reporting exposure is the worse
                                error — but it must not look confirmed. */}
                            {p.directionVerified === false ? (
                              <div
                                style={{
                                  fontSize: 'var(--text-xs)',
                                  color: 'var(--yellow)',
                                  marginTop: 4,
                                }}
                              >
                                direction unverified
                              </div>
                            ) : null}
                          </td>
                          <td style={{ ...CELL, whiteSpace: 'nowrap' }}>
                            {observationBadge(p.observation)}
                            {p.evidence ? (
                              <div
                                style={{
                                  fontSize: 'var(--text-xs)',
                                  color: 'var(--text-muted)',
                                  marginTop: 4,
                                }}
                              >
                                {p.evidence.sources} source(s)
                                {p.evidence.ports.length > 0
                                  ? ` · port ${p.evidence.ports.slice(0, 4).join(', ')}`
                                  : ''}
                              </div>
                            ) : null}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* ⛔ The label says "exposure paths" and the total is the FLEET total,
                    not this page’s row count. A pager that says "1-50 of 50" on a
                    fleet with 300 paths is the same class of error as a filtered view
                    reporting itself as the whole set. */}
                <Pagination
                  basePath="/exposure"
                  searchParams={searchParams}
                  page={paged.page}
                  pageSize={paged.pageSize}
                  total={paged.total}
                  label="exposure paths"
                  pageSizes={[25, 50, 100, 200]}
                />

                <div
                  style={{
                    marginTop: 12,
                    paddingTop: 12,
                    borderTop: '1px solid var(--border)',
                    fontSize: 'var(--text-sm)',
                    color: 'var(--text-muted)',
                    lineHeight: 1.6,
                  }}
                >
                  Every score is explainable — the reasons for the highest-severity paths are
                  listed below. <strong>Not seen</strong> means the path is open but unused in
                  the last {fleet.devices[0] ? fleet.devices[0].lookbackDays : 7} days; it is
                  never treated as closed.
                </div>
              </CardBody>
            </Card>
          )}

          {rows.length > 0 ? (
            <Card>
              <CardBody>
                <div style={{ fontWeight: 700, marginBottom: 10 }}>
                  Why the top paths scored as they did
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  {allRows.slice(0, 8).map((p, i) => (
                    <div key={`why-${i}`}>
                      <div style={{ ...MONO, fontWeight: 600, marginBottom: 4 }}>
                        {p.deviceName} · {p.publicIp} · {p.service.label} ·{' '}
                        {p.ruleName || '(unnamed rule)'}{' '}
                        <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>
                          ({p.severity}, {p.score})
                        </span>
                      </div>
                      <ul
                        style={{
                          margin: 0,
                          paddingLeft: 18,
                          fontSize: 'var(--text-sm)',
                          color: 'var(--text-secondary)',
                          lineHeight: 1.6,
                        }}
                      >
                        {p.reasons.map((r, j) => (
                          <li key={j}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </CardBody>
            </Card>
          ) : null}

          {fleet.errors.length > 0 ? (
            <Card>
              <CardBody>
                {/* ⛔ Surfaced, never swallowed. A device that failed to
                    compute is not a device with no exposure.

                    This was one semicolon-joined run-on sentence: with more
                    than two failures the device names and the Postgres error
                    text ran together into a paragraph nobody could pick a
                    single device out of. Same facts, one row each, name
                    separated from reason — and the name is a link, because the
                    next thing you do with a failed device is go and look at
                    it. */}
                <div
                  style={{
                    fontSize: 'var(--text-sm)',
                    color: 'var(--text-secondary)',
                    marginBottom: 8,
                  }}
                >
                  <strong style={{ color: 'var(--red)' }}>
                    {fleet.errors.length} device{fleet.errors.length === 1 ? '' : 's'} could not be
                    analysed
                  </strong>{' '}
                  and {fleet.errors.length === 1 ? 'is' : 'are'} NOT represented in the totals
                  above.
                </div>
                <table style={{ width: '100%', tableLayout: 'fixed', borderCollapse: 'collapse' }}>
                  <colgroup>
                    <col style={{ width: '30%' }} />
                    <col style={{ width: '70%' }} />
                  </colgroup>
                  <tbody>
                    {fleet.errors.map((e, i) => (
                      <tr key={e.deviceId || i}>
                        <td
                          style={{
                            padding: '4px 8px 4px 0',
                            verticalAlign: 'top',
                            fontSize: 'var(--text-sm)',
                            fontWeight: 600,
                          }}
                        >
                          {/* computeFleetExposure() also reports a
                              WHOLE-RUN failure, which carries no deviceId and
                              no name (exposureQuery.js:276). That row must not
                              render as a device called "undefined". */}
                          {e.deviceId && e.name ? (
                            <Link href={`/devices/${e.deviceId}`} className="link-quiet">
                              {e.name}
                            </Link>
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>Fleet computation</span>
                          )}
                        </td>
                        <td
                          style={{
                            padding: '4px 0',
                            verticalAlign: 'top',
                            fontSize: 'var(--text-sm)',
                            color: 'var(--red)',
                            wordBreak: 'break-word',
                          }}
                        >
                          {e.error}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </CardBody>
            </Card>
          ) : null}
        </>
      )}
    </div>
  );
}
