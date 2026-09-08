import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import Table from '../ui/Table';
import IconChip from '../ui/IconChip';
import { IconDevices, IconGrid, IconShield, IconChart, IconActivity } from '../icons';
import {
  getTopHosts,
  getTopApplications,
  getProtocolBreakdown,
  getTopBlockedDestinations,
  getDeviceTrafficStats,
} from '../../lib/syslog/trafficStats';

export const dynamic = 'force-dynamic';

// Traffic-analysis widgets (Phase 8b UI) — the Firewall Analyzer equivalents.
//
// Split from SyslogWidgets.js on purpose: everything here reads one of the
// three DETAIL rollups (syslog_talker_hourly / syslog_app_hourly /
// syslog_blocked_dst_hourly), which have a bounded retention, whereas
// SyslogWidgets reads the two permanent ones. Keeping that boundary visible in
// the file layout makes it much harder to add a widget that quietly asks a
// 90-day question of a 30-day table.
//
// ⛔ Same two rules as SyslogWidgets, and they matter more here because these
// widgets rank things:
//   1. Never read syslog_events. At ~1,400 events/sec a ranking query over the
//      raw table is a full scan of ~120M rows per day of window.
//   2. "Not measurable" renders as an em-dash, never 0 — and for a RANKING
//      that is not cosmetic: sorting unmeasured rows as zero silently pushes
//      the vendors that do not report bytes to the bottom of a "top talkers by
//      volume" list, which reads as "these hosts are quiet" when the truth is
//      "we cannot tell". Every byte column here is ranked by EVENTS and shows
//      bytes as a secondary, nullable fact.

// Module top level, never nested — CLAUDE.md's React rule.
function Num({ value }) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) {
    return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  }
  return <span style={{ fontVariantNumeric: 'tabular-nums' }}>{Number(value).toLocaleString()}</span>;
}

/**
 * Bytes as a human string, or an em-dash when unmeasurable.
 * ⛔ null and 0 are different: null = "this vendor's counters cannot be summed"
 * (see bytes_summable), 0 = "measured, and it was zero".
 */
function Bytes({ value }) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) {
    return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  }
  const n = Number(value);
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return (
    <span style={{ fontVariantNumeric: 'tabular-nums' }}>
      {i === 0 ? v.toFixed(0) : v.toFixed(v < 10 ? 1 : 0)} {units[i]}
    </span>
  );
}

function Bar({ pct, tone }) {
  return (
    <div aria-hidden="true" style={{ height: 5, borderRadius: 3, background: 'var(--border)', overflow: 'hidden' }}>
      <div style={{ width: `${Math.max(0, Math.min(100, pct))}%`, height: '100%', background: tone }} />
    </div>
  );
}

function Empty({ children }) {
  return <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>{children}</div>;
}

const titleStyle = { display: 'flex', alignItems: 'center', gap: 8 };
const rowLabel = {
  fontSize: 'var(--text-base)',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
};

// ---------------------------------------------------------------------------

/**
 * Top source hosts by event count — Firewall Analyzer's "Top Hosts".
 *
 * ⛔ Distinct from SyslogWidgets' TopTalkersWidget, which ranks the FIREWALLS
 * sending us syslog. This ranks the hosts INSIDE the traffic they described.
 * The two widgets can legitimately appear on the same screen showing entirely
 * different numbers; the titles are written to make that obvious.
 */
export async function TopHostsWidget() {
  const rows = await getTopHosts(pool, 24, 8);
  const max = rows.reduce((n, r) => Math.max(n, r.events), 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconDevices} color="#38bdf8" bg="rgba(56,189,248,0.20)" />
          Top Hosts by Traffic (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>No per-host traffic recorded yet. Hosts appear once the collector has
            aggregated at least one rollup cycle of traffic logs carrying a source address.</Empty>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
            {rows.map((r) => (
              <div key={r.srcIp}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                  <span style={rowLabel}>
                    <Link
                      href={`/topology?view=query&srcIp=${encodeURIComponent(r.srcIp.replace('/32', ''))}`}
                      style={{ color: 'var(--text-primary)' }}
                      title="Trace this host through the fleet"
                    >
                      {r.srcIp.replace('/32', '')}
                    </Link>
                    {r.denied > 0 ? (
                      <span style={{ marginLeft: 6, fontSize: 'var(--text-sm)', color: 'var(--red)' }}>
                        {r.denied.toLocaleString()} denied
                      </span>
                    ) : null}
                  </span>
                  <span style={{ fontSize: 'var(--text-base)', whiteSpace: 'nowrap' }}>
                    <Num value={r.events} />
                    <span style={{ color: 'var(--text-muted)', marginLeft: 8 }}>
                      <Bytes value={
                        r.bytesSent === null && r.bytesReceived === null
                          ? null
                          : (r.bytesSent || 0) + (r.bytesReceived || 0)
                      } />
                    </span>
                  </span>
                </div>
                <Bar pct={max > 0 ? (r.events / max) * 100 : 0} tone="var(--accent-teal)" />
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

/** Top applications — Firewall Analyzer's application/protocol-group view. */
export async function TopApplicationsWidget() {
  const { applications, unclassified } = await getTopApplications(pool, 24, 8);
  const max = applications.reduce((n, r) => Math.max(n, r.events), 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconGrid} color="#a78bfa" bg="rgba(167,139,250,0.20)" />
          Top Applications (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {applications.length === 0 ? (
          <Empty>No application data. Palo Alto and FortiOS both report an application on
            traffic logs, so this staying empty points at a log-format gap, not a quiet network.</Empty>
        ) : (
          <>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              {applications.map((r) => (
                <div key={r.application}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                    <span style={rowLabel}>{r.application}</span>
                    <span style={{ fontSize: 'var(--text-base)', whiteSpace: 'nowrap' }}>
                      <Num value={r.events} />
                      <span style={{ color: 'var(--text-muted)', marginLeft: 8 }}>
                        <Bytes value={
                          r.bytesSent === null && r.bytesReceived === null
                            ? null
                            : (r.bytesSent || 0) + (r.bytesReceived || 0)
                        } />
                      </span>
                    </span>
                  </div>
                  <Bar pct={max > 0 ? (r.events / max) * 100 : 0} tone="#a78bfa" />
                </div>
              ))}
            </div>
            {/* ⛔ Surfaced as a caption rather than ranked as a fake "(unknown)"
                application, which would usually top the chart and hide the real
                answer behind a label that means nothing. */}
            {unclassified > 0 ? (
              <div style={{ marginTop: 8, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                {unclassified.toLocaleString()} further event{unclassified === 1 ? '' : 's'} carried no
                application field and are excluded from this ranking.
              </div>
            ) : null}
          </>
        )}
      </CardBody>
    </Card>
  );
}

/** Transport-protocol split. Small cardinality, so a plain list beats a chart. */
export async function ProtocolBreakdownWidget() {
  const rows = await getProtocolBreakdown(pool, 24);
  const total = rows.reduce((n, r) => n + r.events, 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconChart} color="#fbbf24" bg="rgba(251,191,36,0.20)" />
          Protocols (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>No protocol data in the last 24 hours.</Empty>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
            {rows.slice(0, 8).map((r) => (
              <div key={r.protocol}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                  <span style={rowLabel}>{r.protocol}</span>
                  <span style={{ fontSize: 'var(--text-base)', whiteSpace: 'nowrap' }}>
                    <Num value={r.events} />
                    <span style={{ color: 'var(--text-muted)', marginLeft: 8, fontSize: 'var(--text-sm)' }}>
                      {total > 0 ? `${((r.events / total) * 100).toFixed(1)}%` : '—'}
                    </span>
                  </span>
                </div>
                <Bar pct={total > 0 ? (r.events / total) * 100 : 0} tone="var(--yellow)" />
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

/**
 * Most-blocked destinations.
 *
 * ⛔ The title says BLOCKED and must keep saying so: only blocked destinations
 * are stored (the full destination set is unbounded internet addressing — see
 * syslog_blocked_dst_hourly in schema.sql). A future "Top Destinations" widget
 * cannot be built by relabelling this one.
 */
export async function BlockedDestinationsWidget() {
  const rows = await getTopBlockedDestinations(pool, 24, 8);
  const max = rows.reduce((n, r) => Math.max(n, r.events), 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconShield} color="#f87171" bg="rgba(248,113,113,0.20)" />
          Top Blocked Destinations (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>Nothing was blocked in the last 24 hours, or no denied traffic log carried a
            destination address.</Empty>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
            {rows.map((r) => (
              <div key={`${r.dstIp}-${r.dstPort}-${r.protocol}`}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                  <span style={rowLabel}>
                    {r.dstIp.replace('/32', '')}
                    {r.dstPort !== null ? (
                      <span style={{ color: 'var(--text-muted)' }}>:{r.dstPort}</span>
                    ) : null}
                    {r.protocol ? (
                      <span style={{ marginLeft: 6, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                        {r.protocol}
                      </span>
                    ) : null}
                  </span>
                  <span style={{ fontSize: 'var(--text-base)' }}><Num value={r.events} /></span>
                </div>
                <Bar pct={max > 0 ? (r.events / max) * 100 : 0} tone="var(--red)" />
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

/**
 * Per-device traffic and security statistics — Firewall Analyzer's per-device
 * summary table.
 *
 * ⛔ Every ACTIVE device is listed, including ones sending nothing. A firewall
 * that has silently stopped logging is the most valuable row in this table, and
 * a query that only listed devices present in the rollup would hide exactly
 * that. Those rows read "not logging" rather than a row of zeros.
 */
export async function DeviceTrafficTable() {
  const rows = await getDeviceTrafficStats(pool, 24);
  const silent = rows.filter((r) => r.events === 0).length;

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconActivity} color="#4ade80" bg="rgba(74,222,128,0.20)" />
          Traffic &amp; Security by Device (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>No active devices.</Empty>
        ) : (
          <>
            <Table minWidth={720}>
              <thead>
                <tr>
                  <th style={{ width: '26%' }}>Device</th>
                  <th style={{ width: '12%' }}>Vendor</th>
                  <th style={{ width: '13%', textAlign: 'right' }}>Events</th>
                  <th style={{ width: '12%', textAlign: 'right' }}>Denied</th>
                  <th style={{ width: '11%', textAlign: 'right' }}>Threats</th>
                  <th style={{ width: '10%', textAlign: 'right' }}>VPN</th>
                  <th style={{ width: '16%', textAlign: 'right' }}>Volume</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.deviceId}>
                    <td style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <Link href={`/devices/${r.deviceId}`} style={{ color: 'var(--text-primary)' }}>
                        {r.name}
                      </Link>
                      {r.events === 0 ? (
                        <span style={{ marginLeft: 6 }}>
                          {/* ⛔ Not "0 events" — a device sending nothing is a
                              collection problem, not a quiet firewall. */}
                          <Badge color="warning">not logging</Badge>
                        </span>
                      ) : null}
                    </td>
                    <td style={{ color: 'var(--text-muted)' }}>{r.vendor}</td>
                    <td style={{ textAlign: 'right' }}><Num value={r.events || null} /></td>
                    <td style={{ textAlign: 'right', color: r.denied > 0 ? 'var(--red)' : undefined }}>
                      <Num value={r.denied} />
                    </td>
                    <td style={{ textAlign: 'right', color: r.threats > 0 ? 'var(--red)' : undefined }}>
                      <Num value={r.threats} />
                    </td>
                    <td style={{ textAlign: 'right' }}><Num value={r.vpnEvents} /></td>
                    <td style={{ textAlign: 'right' }}>
                      <Bytes value={
                        r.bytesSent === null && r.bytesReceived === null
                          ? null
                          : (r.bytesSent || 0) + (r.bytesReceived || 0)
                      } />
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <div style={{ marginTop: 8, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              {silent > 0
                ? `${silent} active device${silent === 1 ? ' has' : 's have'} sent no logs in this window. `
                : ''}
              Volume is shown only where the device&apos;s byte counters can honestly be summed —
              FortiOS re-logs a session with a running cumulative total, so its rows are counted but
              not measured in bytes.
            </div>
          </>
        )}
      </CardBody>
    </Card>
  );
}
