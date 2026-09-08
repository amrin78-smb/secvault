import Link from 'next/link';
import { pool } from '../../../lib/db';
import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../components/ui/Card';
import Badge from '../../../components/ui/Badge';
import EmptyState from '../../../components/ui/EmptyState';
import { computeFleetExposure } from '../../../lib/engines/exposureQuery';

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
//   Unmeasured   no syslog coverage. NOT the same as "not seen", and the two
//                must never be rendered alike or merged into one column.
//
// A quiet path is NOT filtered out, dimmed to invisibility, or sorted to
// oblivion: an unused open door is still open, and treating quiet as closed is
// how a forgotten vendor rule survives an audit.

const CELL = { padding: '10px 12px', verticalAlign: 'top', fontSize: 'var(--text-sm)' };

const TH = {
  textAlign: 'left',
  padding: '9px 12px',
  fontSize: 10,
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

function severityBadge(sev) {
  if (sev === 'critical') return <Badge color="danger">Critical</Badge>;
  if (sev === 'high') return <Badge color="danger">High</Badge>;
  if (sev === 'medium') return <Badge color="warning">Medium</Badge>;
  return <Badge color="muted">Low</Badge>;
}

// ⛔ Three distinct renderings for three distinct states. "Not seen" and
// "Unmeasured" must never collapse into one another — see the file header.
function observationBadge(observation) {
  if (observation === 'observed') return <Badge color="danger">Reached</Badge>;
  if (observation === 'not_observed') return <Badge color="muted">Not seen</Badge>;
  return <Badge color="warning">Unmeasured</Badge>;
}

export default async function ExposurePage() {
  const fleet = await computeFleetExposure(pool, { lookbackDays: 7 });
  const { totals } = fleet;

  const rows = fleet.devices
    .flatMap((d) => d.paths.map((p) => ({ ...p, deviceName: d.name, deviceId: d.deviceId })))
    .sort((a, b) => b.score - a.score);

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
              'no syslog coverage — not "clean"',
              totals.unmeasured > 0 ? 'warn' : null
            )}
            {kpi(String(totals.publicIps), 'public addresses', 'on device interfaces')}
          </div>

          {totals.unmeasured > 0 ? (
            <Card>
              <CardBody>
                {/* ⛔ Stated up front rather than buried in a tooltip. A reader
                    who does not know these paths are unmeasured will read the
                    "reached" count as the whole story. */}
                <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
                  <strong>{totals.unmeasured}</strong> of these paths are on{' '}
                  <strong>{totals.devicesWithoutSyslog}</strong> device(s) sending no syslog in the
                  window, so SecVault cannot say whether they were reached. They are shown as{' '}
                  <em>Unmeasured</em>, never as unused — absence of an observation is not evidence
                  of absence.
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
                  {rows.slice(0, 8).map((p, i) => (
                    <div key={`why-${i}`}>
                      <div style={{ ...MONO, fontWeight: 600, marginBottom: 4 }}>
                        {p.deviceName} · {p.publicIp} · {p.service.label}{' '}
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
                    compute is not a device with no exposure. */}
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--red)' }}>
                  {fleet.errors.length} device(s) could not be analysed and are NOT represented
                  above:{' '}
                  {fleet.errors.map((e) => `${e.name} (${e.error})`).join('; ')}
                </div>
              </CardBody>
            </Card>
          ) : null}
        </>
      )}
    </div>
  );
}
