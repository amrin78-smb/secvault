import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import IconChip from '../ui/IconChip';
import { IconActivity, IconShield, IconTrendingUp, IconDevices, IconRefresh } from '../icons';
import { classifyAction } from '../../lib/syslog/actions';
import {
  getTrafficTimeline,
  getTopTalkers,
  getActionBreakdown,
  getTopRules,
  getIngestHealth,
  getThreatActivity,
} from '../../lib/syslog/trafficStats';

export const dynamic = 'force-dynamic';

// Syslog dashboard widgets (Phase 8a UI).
//
// ⛔ EVERY WIDGET HERE READS A ROLLUP, never syslog_events. At ~1,400 events/sec
// the raw table gains ~120M rows/day, and a widget scanning it on each 60-second
// dashboard refresh is precisely the failure LogVault measured (a 24h aggregate
// reading 560 MB per cache-miss) before it pre-aggregated. The rollups exist so
// these queries stay in the tens of milliseconds.
//
// ⛔ "No data" renders as an em-dash, never 0. A collector that is down and a
// network that is quiet must not look the same on screen.

// Module top level, never nested — CLAUDE.md's React rule.
function Num({ value, suffix }) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) {
    return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  }
  return (
    <span style={{ fontVariantNumeric: 'tabular-nums' }}>
      {Number(value).toLocaleString()}
      {suffix ? <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}> {suffix}</span> : null}
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

// ---------------------------------------------------------------------------

// How many outcome rows the Session Outcomes card shows. The remainder is
// STATED, never dropped silently — see the ⛔ note at the render site.
const SESSION_OUTCOMES_SHOWN = 8;

export async function TrafficVolumeWidget() {
  const rows = await getTrafficTimeline(pool, 24);
  const total = rows.reduce((n, r) => n + r.events, 0);
  const max = rows.reduce((n, r) => Math.max(n, r.events), 0);
  // ⛔ `denied` is deliberately TRI-STATE in trafficStats.js: NULL means this
  // vendor never reports an action, which is not the same fact as "no denies
  // recorded in this hour". Summing a mix of real and NULL hours still totals
  // correctly, but an ALL-NULL window must not render a calm `0` under
  // "denied / dropped" — that is a measured-looking zero over an unmeasurable
  // window. `volumeGb` five lines below already draws this distinction; this
  // line now matches it.
  const deniedRows = rows.filter((r) => r.denied !== null && r.denied !== undefined);
  const denied =
    deniedRows.length === 0 ? null : deniedRows.reduce((n, r) => n + Number(r.denied), 0);
  // null when NO row had a summable byte count -- unmeasurable, not zero.
  const byteRows = rows.filter((r) => r.bytesSent !== null || r.bytesReceived !== null);
  const volumeGb = byteRows.length === 0
    ? null
    : (byteRows.reduce((n, r) => n + (r.bytesSent || 0) + (r.bytesReceived || 0), 0) / 1e9).toFixed(1);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconActivity} color="var(--tint-info-fg)" bg="var(--tint-info)" />
          Log Volume (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>No log data collected in the last 24 hours.</Empty>
        ) : (
          <>
            {/* ⛔ Volume is shown only where byte counters can honestly be
                summed. FortiOS re-logs a session with a running cumulative
                counter, so adding its rows counts the same bytes repeatedly
                (measured: 87.6 Gbps implied). Those contribute NULL, and the
                caption says whose traffic this actually covers. */}
            <div style={{ display: 'flex', gap: 18, alignItems: 'baseline', marginBottom: 10 }}>
              <div>
                <div style={{ fontSize: 22, fontWeight: 700 }}><Num value={total} /></div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>events</div>
              </div>
              <div>
                <div
                  style={{
                    fontSize: 22,
                    fontWeight: 700,
                    // Unmeasurable gets the hueless token, never red and never
                    // the reassuring default — the same treatment volumeGb
                    // gives its own null case directly below.
                    color:
                      denied === null
                        ? 'var(--unmeasured)'
                        : denied > 0
                          ? 'var(--red)'
                          : 'var(--text-primary)',
                  }}
                  title={
                    denied === null
                      ? 'No vendor in this window reported an action on its traffic logs, so denied traffic could not be counted. This is not zero.'
                      : undefined
                  }
                >
                  {denied === null ? '—' : <Num value={denied} />}
                </div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>denied / dropped</div>
              </div>
              <div>
                <div style={{ fontSize: 22, fontWeight: 700 }}>
                  {volumeGb === null ? <span style={{ color: 'var(--text-muted)' }}>—</span> : volumeGb + ' GB'}
                </div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>volume (measurable)</div>
              </div>
            </div>
            {/* Hand-rolled bars — this codebase has no charting library beyond
                recharts, and a 24-bucket bar strip does not warrant one. */}
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 46 }}>
              {rows.map((r) => (
                <div
                  key={r.hour.toISOString()}
                  title={`${r.hour.toISOString().slice(11, 16)} UTC — ${r.events.toLocaleString()} events`}
                  style={{
                    flex: 1,
                    height: `${max > 0 ? Math.max(3, (r.events / max) * 100) : 3}%`,
                    background: 'var(--accent-teal)',
                    borderRadius: 2,
                  }}
                />
              ))}
            </div>
            <div style={{ marginTop: 6, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              {rows.length} hour{rows.length === 1 ? '' : 's'} of history. Volume covers Palo Alto
              session-close records only — FortiOS reports running cumulative counters
              that cannot be summed, so its traffic is counted but not measured in bytes.
            </div>
          </>
        )}
      </CardBody>
    </Card>
  );
}

export async function TopTalkersWidget() {
  const rows = await getTopTalkers(pool, 24, 8);
  const max = rows.reduce((n, r) => Math.max(n, r.events), 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconDevices} color="var(--tint-success-fg)" bg="var(--tint-success)" />
          Top Log Sources (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>No log sources seen in the last 24 hours.</Empty>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
            {rows.map((r) => (
              <div key={r.sourceIp}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                  <span style={{ fontSize: 'var(--text-base)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {r.deviceName ? (
                      <Link href={`/devices/${r.deviceId}`} style={{ color: 'var(--text-primary)' }}>{r.deviceName}</Link>
                    ) : (
                      <>
                        {r.sourceIp.replace('/32', '')}{' '}
                        {/* ⛔ A sender we do not manage is a FINDING, not noise. */}
                        <Badge color="warning">unmanaged</Badge>
                      </>
                    )}
                  </span>
                  <span style={{ fontSize: 'var(--text-base)', fontVariantNumeric: 'tabular-nums' }}>
                    <Num value={r.events} />
                  </span>
                </div>
                <Bar pct={max > 0 ? (r.events / max) * 100 : 0} tone={r.deviceName ? 'var(--accent-teal)' : 'var(--yellow)'} />
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

export async function ActionBreakdownWidget() {
  const rows = await getActionBreakdown(pool, 24);
  const total = rows.reduce((n, r) => n + r.events, 0);
  // ⛔ Three-state, from lib/syslog/actions.js. This was a SIXTH private deny
  // list and it was wrong in the opposite direction to LogResults': it listed
  // client-rst/server-rst as DENIED, but those are Fortinet SESSION-END verbs —
  // the session existed and was permitted, then ended. Counting them as denied
  // inflated 'Session Outcomes' with established sessions. Anything the shared
  // vocabulary cannot classify renders as --unmeasured (the palette's no-hue
  // "not measured" token), never green and never red.
  const tone = (a) => {
    if (a === '(unreported)') return 'var(--unmeasured)';
    const verdict = classifyAction(a);
    if (verdict === 'blocked') return 'var(--red)';
    if (verdict === 'allowed') return 'var(--green)';
    return 'var(--unmeasured)';
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconShield} color="var(--tint-danger-fg)" bg="var(--tint-danger)" />
          Session Outcomes (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>No sessions recorded in the last 24 hours.</Empty>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {/* ⛔ This slice used to be silent. Live 2026-09-09 the fleet
                reported 41 distinct action verbs in 24h, and the eight shown
                excluded `drop` (686,947 events — a REAL deny verb) and
                `(unreported)` (248,203 — the bucket whose whole purpose is
                making unclassifiable traffic visible). A card presenting
                itself as the session-outcome breakdown, missing a deny verb
                with 687k events, is a wrong answer, not a shortened list.
                Every sibling ranking widget on this dashboard already states
                its exclusions; this one now does too. */}
            {rows.slice(0, SESSION_OUTCOMES_SHOWN).map((r) => (
              <div key={r.action}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-base)' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>{r.action}</span>
                  <span style={{ fontVariantNumeric: 'tabular-nums' }}>
                    <Num value={r.events} />
                    <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
                      {' '}({total > 0 ? Math.round((r.events / total) * 100) : 0}%)
                    </span>
                  </span>
                </div>
                <Bar pct={total > 0 ? (r.events / total) * 100 : 0} tone={tone(r.action)} />
              </div>
            ))}
            {rows.length > SESSION_OUTCOMES_SHOWN && (
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', paddingTop: 2 }}>
                {rows.length - SESSION_OUTCOMES_SHOWN} further outcome type
                {rows.length - SESSION_OUTCOMES_SHOWN === 1 ? '' : 's'} (
                <Num
                  value={rows
                    .slice(SESSION_OUTCOMES_SHOWN)
                    .reduce((n, r) => n + (Number(r.events) || 0), 0)}
                />{' '}
                events) not shown
              </div>
            )}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

export async function TopRulesWidget() {
  const rows = await getTopRules(pool, 1, 8);
  const max = rows.reduce((n, r) => Math.max(n, r.hits), 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconTrendingUp} color="var(--tint-warn-fg)" bg="var(--tint-warn)" />
          Busiest Rules (today)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>No rule activity recorded yet today.</Empty>
        ) : (
          <>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              {rows.map((r, i) => (
                <div key={`${r.rule}-${r.deviceName}-${i}`}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                    <span style={{ fontSize: 'var(--text-base)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.rule}
                      {r.deviceName ? (
                        <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}> · {r.deviceName}</span>
                      ) : null}
                    </span>
                    <span style={{ fontSize: 'var(--text-base)', fontVariantNumeric: 'tabular-nums' }}>
                      <Num value={r.hits} />
                    </span>
                  </div>
                  <Bar pct={max > 0 ? (r.hits / max) * 100 : 0} tone="var(--accent-teal)" />
                </div>
              ))}
            </div>
            <div style={{ marginTop: 8, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              Observed from logs — this is real traffic evidence, independent of
              what each vendor&apos;s API reports as a hit count.
            </div>
          </>
        )}
      </CardBody>
    </Card>
  );
}

export async function ThreatActivityWidget() {
  const rows = await getThreatActivity(pool, 24);
  const total = rows.reduce((n, r) => n + r.events, 0);
  const LABEL = { threat: 'Threat (Palo Alto)', utm: 'UTM (Fortinet)' };

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconShield} color="var(--tint-danger-fg)" bg="var(--tint-danger)" />
          Threat &amp; UTM Events (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>
            No threat or UTM events in the last 24 hours. Only Palo Alto THREAT and
            Fortinet UTM logs are counted here — other vendors do not send them.
          </Empty>
        ) : (
          <>
            <div style={{ fontSize: 26, fontWeight: 800, color: total > 0 ? 'var(--red)' : 'var(--text-primary)' }}>
              <Num value={total} />
            </div>
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginBottom: 8 }}>
              events flagged by the firewalls themselves
            </div>
            {rows.map((r) => (
              <div key={r.kind} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-base)', padding: '3px 0' }}>
                <span style={{ color: 'var(--text-secondary)' }}>{LABEL[r.kind] || r.kind}</span>
                <span style={{ fontVariantNumeric: 'tabular-nums' }}><Num value={r.events} /></span>
              </div>
            ))}
          </>
        )}
      </CardBody>
    </Card>
  );
}

export async function IngestHealthWidget() {
  const h = await getIngestHealth(pool, 15);

  // ⛔ dropped is the number that matters. A collector losing datagrams under
  // load looks exactly like a quiet network from every other angle.
  const dropTone = h.dropped === null ? 'var(--unmeasured)' : h.dropped > 0 ? 'var(--red)' : 'var(--green)';

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconRefresh} color="var(--tint-info-fg)" bg="var(--tint-info)" />
          Collector Health
        </CardTitle>
      </CardHeader>
      <CardBody>
        {h.flushes === 0 ? (
          // Not "0 events/sec" — the collector has not reported at all.
          <Empty>
            The collector has not recorded a flush in the last {h.windowMinutes} minutes.
            It may be stopped, or nothing is being sent to it.
          </Empty>
        ) : (
          <>
            <div style={{ display: 'flex', gap: 20, marginBottom: 8 }}>
              <div>
                <div style={{ fontSize: 24, fontWeight: 800 }}><Num value={h.eventsPerSec} /></div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>events/sec</div>
              </div>
              <div>
                <div style={{ fontSize: 24, fontWeight: 800, color: dropTone }}><Num value={h.dropped} /></div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>dropped</div>
              </div>
            </div>
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 2 }}>
              <span>{h.received?.toLocaleString()} received · {h.stored?.toLocaleString()} stored (last {h.windowMinutes}m)</span>
              <span>batch {h.avgMs}ms avg / {h.maxMs}ms peak · spool backlog {h.maxBacklog}</span>
              {h.unknownSource > 0 && (
                <span style={{ color: 'var(--yellow)' }}>
                  {h.unknownSource.toLocaleString()} from senders not in the device inventory
                </span>
              )}
            </div>
          </>
        )}
      </CardBody>
    </Card>
  );
}
