import { pool } from '../../lib/db';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import IconChip from '../ui/IconChip';
import { IconDevices, IconGrid, IconShield, IconChart, IconActivity } from '../icons';
import {
  getTrafficTimeline,
  getActionBreakdown,
  getTopHosts,
  getTopApplications,
  getProtocolBreakdown,
  getTopBlockedDestinations,
  getDeviceSyslogCoverage,
  getTopRules,
  getDeviceNamedThreats,
  getDeviceInboundHits,
} from '../../lib/syslog/trafficStats';

export const dynamic = 'force-dynamic';

// Per-firewall traffic. The fleet Traffic tab answers "what is the estate
// doing"; this answers "what is THIS firewall doing", which is the question an
// operator has when they are already looking at one device.
//
// ⛔ EVERY QUERY IS SCOPED IN SQL, NOT FILTERED IN JS. These rollups carry
// millions of rows per day; pulling the fleet and discarding most of it would
// work perfectly in a demo and fall over on the reference deployment.
//
// ⛔ NEVER READS syslog_events, same rule as the fleet widgets. At ~1,400
// events/sec a ranking query over the raw table is a full scan.
//
// ⛔ AND THE RULE THIS TAB EXISTS TO NOT BREAK: an empty widget means one of
// two OPPOSITE things — this firewall sends no syslog to SecVault (our gap), or
// it sent syslog and was quiet (a fact about the network). They render
// identically unless something says which, so coverage is resolved FIRST and
// stated at the top; the widgets are only drawn once it is established that
// there is something to draw.

const titleStyle = { display: 'flex', alignItems: 'center', gap: 8 };

function Num({ value }) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) {
    // ⛔ Em-dash, never 0 — see the ranking note in TrafficWidgets.
    return <span style={{ color: 'var(--unmeasured)' }}>—</span>;
  }
  return <>{Number(value).toLocaleString()}</>;
}

function Bar({ value, max, color = 'var(--primary)' }) {
  const pct = max > 0 ? Math.max(2, Math.round((value / max) * 100)) : 0;
  return (
    <div style={{ height: 6, background: 'var(--surface-subtle)', borderRadius: 3, overflow: 'hidden' }}>
      <div style={{ width: `${pct}%`, height: '100%', background: color }} />
    </div>
  );
}

function Empty({ children }) {
  return (
    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', padding: '8px 0' }}>
      {children}
    </div>
  );
}

function Panel({ icon, tint, tintBg, title, children }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={icon} color={tint} bg={tintBg} />
          {title}
        </CardTitle>
      </CardHeader>
      <CardBody>{children}</CardBody>
    </Card>
  );
}

function RankedList({ rows, labelOf, keyOf, color }) {
  const max = rows.reduce((n, r) => Math.max(n, r.events), 0);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
      {rows.map((r) => (
        <div key={keyOf(r)}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
            <span style={{ fontSize: 'var(--text-sm)', fontFamily: 'var(--font-mono)' }}>{labelOf(r)}</span>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
              <Num value={r.events} />
            </span>
          </div>
          <Bar value={r.events} max={max} color={color} />
        </div>
      ))}
    </div>
  );
}

export default async function DeviceTrafficTab({ deviceId, deviceName }) {
  // ⛔ COVERAGE FIRST. Everything below is meaningless without knowing whether
  // this device logs to SecVault at all.
  const coverage = await getDeviceSyslogCoverage(pool, deviceId, 24);

  if (!coverage.everSent) {
    return (
      <Card>
        <CardBody>
          <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.7 }}>
            <strong>{deviceName} has never sent syslog to SecVault.</strong>
            <div style={{ color: 'var(--text-secondary)', marginTop: 6 }}>
              {/* ⛔ NOT "no traffic". This is a COLLECTION gap on our side, and
                  saying otherwise would report a configuration omission as a
                  quiet firewall — the most misleading thing this tab could do. */}
              This is a collection gap, not a statement about the firewall&apos;s traffic — it is
              almost certainly passing traffic that SecVault cannot see. Point the device&apos;s syslog
              target at this server and confirm the inbound firewall rule for the collector port,
              then this tab fills in within a rollup cycle.
            </div>
          </div>
        </CardBody>
      </Card>
    );
  }

  if (!coverage.inWindow) {
    const last = coverage.lastBucket ? new Date(coverage.lastBucket) : null;
    return (
      <Card>
        <CardBody>
          <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.7 }}>
            <strong>{deviceName} has sent no syslog in the last 24 hours.</strong>
            <div style={{ color: 'var(--text-secondary)', marginTop: 6 }}>
              {/* ⛔ A device that logged before and stopped is a DIFFERENT
                  problem from one that never logged, and needs a different
                  remedy — so it gets a different message and keeps its last
                  known timestamp rather than rendering as "never". */}
              It has logged before
              {last ? <> — most recently for the hour beginning{' '}
                <strong>{last.toISOString().slice(0, 16).replace('T', ' ')} UTC</strong></> : null}
              , so the syslog path worked at some point. Something stopped: check the device is up,
              still has its syslog target configured, and that nothing between it and this server is
              dropping the traffic.
            </div>
          </div>
        </CardBody>
      </Card>
    );
  }

  const [timeline, actions, hosts, apps, protocols, blocked, rules, threats, inbound] =
    await Promise.all([
      getTrafficTimeline(pool, 24, deviceId),
      getActionBreakdown(pool, 24, deviceId),
      getTopHosts(pool, 24, 8, deviceId),
      getTopApplications(pool, 24, 8, deviceId),
      getProtocolBreakdown(pool, 24, deviceId),
      getTopBlockedDestinations(pool, 24, 8, deviceId),
      getTopRules(pool, 1, 8, deviceId),
      getDeviceNamedThreats(pool, deviceId, 24, 8),
      getDeviceInboundHits(pool, deviceId, 24, 8),
    ]);

  // ⛔ A null port renders as nothing, never the string "null". Live rows carry
  // dst_port NULL (an ICMP or protocol-only record), and `${ip}:${port}` on one
  // of those prints "49.231.158.90:null" — a fabricated port on a security page.
  const endpoint = (ip, port, proto) =>
    `${String(ip).replace('/32', '')}${port ? `:${port}` : ''}${proto ? ` ${proto}` : ''}`;

  const namedThreats = threats.threats.filter((t) => t.name !== '(unnamed)');
  const unnamedThreats = threats.threats.find((t) => t.name === '(unnamed)');
  const reachedAndAllowed = inbound.filter((r) => r.publicSource && r.allowed);

  const totalEvents = timeline.reduce((n, r) => n + r.events, 0);
  // ⛔ NULL-SAFE SUM. `denied` is null when the vendor never reports an action,
  // and Number(null) is 0 — summing it blind would turn "this vendor does not
  // tell us" into "nothing was denied".
  const measuredDenied = timeline.filter((r) => r.denied !== null);
  const totalDenied = measuredDenied.reduce((n, r) => n + r.denied, 0);
  const maxHour = timeline.reduce((n, r) => Math.max(n, r.events), 0);
  const actionTotal = actions.reduce((n, a) => n + a.events, 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
        <Panel icon={IconActivity} tint="var(--tint-teal-fg)" tintBg="var(--tint-teal)" title="Log Volume (24h)">
          <div style={{ display: 'flex', gap: 'var(--s5)', flexWrap: 'wrap', marginBottom: 'var(--s4)' }}>
            <div>
              <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 700 }}>
                {totalEvents.toLocaleString()}
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>events</div>
            </div>
            <div>
              <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--red)' }}>
                {measuredDenied.length === 0
                  ? <span style={{ color: 'var(--unmeasured)' }}>—</span>
                  : totalDenied.toLocaleString()}
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>denied / dropped</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 56 }}>
            {timeline.map((r) => (
              <div
                key={String(r.hour)}
                title={`${new Date(r.hour).toISOString().slice(0, 16).replace('T', ' ')} UTC — ${r.events.toLocaleString()} events`}
                style={{
                  flex: 1,
                  height: `${maxHour > 0 ? Math.max(3, Math.round((r.events / maxHour) * 100)) : 3}%`,
                  background: 'var(--primary)',
                  borderRadius: '2px 2px 0 0',
                }}
              />
            ))}
          </div>
          {measuredDenied.length > 0 && measuredDenied.length < timeline.length ? (
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 'var(--s3)' }}>
              {/* ⛔ Partial measurement is disclosed rather than averaged away. */}
              Deny counts are available for {measuredDenied.length} of {timeline.length} hours; the
              rest carried no action field and are excluded from that figure rather than counted as zero.
            </div>
          ) : null}
        </Panel>

        <Panel icon={IconShield} tint="var(--tint-danger-fg)" tintBg="var(--tint-danger)" title="Session Outcomes (24h)">
          {actions.length === 0 ? (
            <Empty>This firewall logged no action field in the window.</Empty>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              {actions.slice(0, 8).map((a) => (
                <div key={a.action}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                    <span style={{ fontSize: 'var(--text-sm)' }}>{a.action}</span>
                    <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                      {a.events.toLocaleString()}
                      {actionTotal > 0 ? (
                        <span style={{ color: 'var(--text-muted)' }}>
                          {' '}({Math.round((a.events / actionTotal) * 100)}%)
                        </span>
                      ) : null}
                    </span>
                  </div>
                  <Bar value={a.events} max={actions[0].events} />
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel icon={IconDevices} tint="var(--tint-info-fg)" tintBg="var(--tint-info)" title="Top Hosts (24h)">
          {hosts.length === 0 ? (
            <Empty>No per-host rows for this firewall — its logs carry no source address, or the
              detail rollup has aged out of its shorter retention window.</Empty>
          ) : (
            <RankedList
              rows={hosts}
              keyOf={(r) => r.srcIp}
              labelOf={(r) => r.srcIp.replace('/32', '')}
              color="var(--primary)"
            />
          )}
        </Panel>

        <Panel icon={IconGrid} tint="var(--tint-purple-fg)" tintBg="var(--tint-purple)" title="Top Applications (24h)">
          {/* ⛔ getTopApplications returns {applications, unclassified}, NOT an
              array — and the unclassified count is scoped to this device, so the
              caption describes the same population as the list above it. */}
          {apps.applications.length === 0 ? (
            <Empty>This firewall reports no application field. Only some vendors do — its absence is
              not a statement about what is running.</Empty>
          ) : (
            <>
              <RankedList
                rows={apps.applications}
                keyOf={(r) => r.application}
                labelOf={(r) => r.application}
                color="var(--purple)"
              />
              {apps.unclassified > 0 ? (
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 'var(--s3)' }}>
                  {apps.unclassified.toLocaleString()} further events from this firewall carried no
                  application field and are excluded from this ranking.
                </div>
              ) : null}
            </>
          )}
        </Panel>

        <Panel icon={IconChart} tint="var(--tint-warn-fg)" tintBg="var(--tint-warn)" title="Protocols (24h)">
          {protocols.length === 0 ? (
            <Empty>No protocol field recorded for this firewall.</Empty>
          ) : (
            <RankedList
              rows={protocols.slice(0, 8)}
              keyOf={(r) => String(r.protocol)}
              labelOf={(r) => String(r.protocol)}
              color="var(--yellow)"
            />
          )}
        </Panel>

        <Panel icon={IconActivity} tint="var(--tint-teal-fg)" tintBg="var(--tint-teal)" title="Top Rules by Traffic (24h)">
          {/* ⛔ THE ONE WIDGET HERE A LOG ANALYSER CANNOT DRAW. It joins traffic
              to this firewall's own RULEBASE, which is what makes the `unused`
              findings on Rule hygiene evidence rather than assumption. ⛔ A rule
              ABSENT from this list is NOT proven unused — `unused` requires a
              MEASURED zero, and a missing row is not a measurement. */}
          {rules.length === 0 ? (
            <Empty>No rule-attributed traffic for this firewall. Its logs carry no rule identifier,
              so rule usage here is NOT MEASURED — not zero.</Empty>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              {rules.map((r) => (
                <div key={`${r.rule}-${r.action}`}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                    <span style={{ fontSize: 'var(--text-sm)' }}>
                      {r.rule}
                      <span style={{ color: 'var(--text-muted)', marginLeft: 6, fontSize: 'var(--text-xs)' }}>
                        {r.action}
                      </span>
                    </span>
                    <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                      <Num value={r.hits} />
                    </span>
                  </div>
                  <Bar value={r.hits} max={rules[0].hits} color="var(--teal)" />
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel icon={IconShield} tint="var(--tint-danger-fg)" tintBg="var(--tint-danger)" title="Threat Activity (24h)">
          {/* ⛔ ATTACK CONTEXT, NOT PRIORITISATION. Threat signatures were
              deliberately REJECTED as a CVE band modifier: they fire on nearly
              every device, so admitting them would push ~every assessment to
              patch_now and leave the queue with no ordering at all. Beside a
              device's traffic is the use that was always considered correct. */}
          {threats.total === 0 ? (
            <Empty>No threat or UTM records from this firewall in the window. That means its logs
              carried none — not that nothing was attempted.</Empty>
          ) : (
            <>
              {namedThreats.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                  {namedThreats.map((t) => (
                    <div key={`${t.name}-${t.severity}`}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                        <span style={{ fontSize: 'var(--text-sm)' }}>
                          {t.name}
                          {t.severity ? (
                            <span style={{ color: 'var(--text-muted)', marginLeft: 6, fontSize: 'var(--text-xs)' }}>
                              {t.severity}
                            </span>
                          ) : null}
                        </span>
                        <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                          <Num value={t.events} />
                          <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
                            {' '}&middot; {t.sources} src
                          </span>
                        </span>
                      </div>
                      <Bar value={t.events} max={namedThreats[0].events} color="var(--red)" />
                    </div>
                  ))}
                </div>
              ) : (
                <Empty>This firewall logged threat activity, but none of it carried a signature name.</Empty>
              )}
              {unnamedThreats ? (
                /* ⛔ COUNTED, NEVER DROPPED. Measured live: 946,434 of ITC-SK's
                   949,950 threat events (99.6%) carry no name. Filtering them
                   out would hide almost the entire threat volume while looking
                   tidier on screen. */
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 'var(--s3)' }}>
                  A further <strong>{unnamedThreats.events.toLocaleString()}</strong> threat event(s)
                  carried no signature name from this vendor. They are counted in the total of{' '}
                  {threats.total.toLocaleString()} but cannot be ranked.
                </div>
              ) : null}
            </>
          )}
        </Panel>

        <Panel icon={IconChart} tint="var(--tint-warn-fg)" tintBg="var(--tint-warn)" title="Reached This Firewall (24h)">
          {/* ⛔ THE SAME EVIDENCE /exposure AND log_hit ARE BUILT ON. Exposure
              says a path is open; this says whether anyone knocked and whether
              they got in. ⛔ `public_source` and `allowed` are SEPARATE facts and
              neither may be collapsed into the other: a blocked probe from the
              internet and an allowed one are opposite outcomes, and an allowed
              one from the LAN is a far weaker claim than one from outside. */}
          {inbound.length === 0 ? (
            <Empty>Nothing was recorded arriving at this firewall&apos;s own addresses. Matching this
              needs collected interface or NAT addresses — without them the traffic is NOT MEASURED
              here, not absent.</Empty>
          ) : (
            <>
              {reachedAndAllowed.length > 0 ? (
                <div
                  style={{
                    fontSize: 'var(--text-xs)',
                    color: 'var(--tint-danger-fg)',
                    background: 'var(--tint-danger)',
                    padding: '6px 8px',
                    borderRadius: 'var(--radius-sm)',
                    marginBottom: 'var(--s3)',
                  }}
                >
                  <strong>{reachedAndAllowed.length}</strong> of these were reached from a PUBLIC
                  source and ALLOWED.
                </div>
              ) : null}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                {inbound.map((r) => (
                  <div key={`${r.dstIp}-${r.dstPort}-${r.protocol}-${r.allowed}-${r.publicSource}`}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                      <span style={{ fontSize: 'var(--text-sm)', fontFamily: 'var(--font-mono)' }}>
                        {endpoint(r.dstIp, r.dstPort, r.protocol)}
                      </span>
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                        <span style={{ color: r.publicSource ? 'var(--red)' : 'var(--text-muted)' }}>
                          {r.publicSource ? 'public' : 'internal'}
                        </span>
                        {' / '}
                        <span style={{ color: r.allowed ? 'var(--red)' : 'var(--green)' }}>
                          {r.allowed ? 'allowed' : 'blocked'}
                        </span>
                        {' '}&middot;{' '}
                        <Num value={r.events} />
                      </span>
                    </div>
                    <Bar
                      value={r.events}
                      max={inbound[0].events}
                      color={r.publicSource && r.allowed ? 'var(--red)' : 'var(--yellow)'}
                    />
                  </div>
                ))}
              </div>
            </>
          )}
        </Panel>

        <Panel icon={IconShield} tint="var(--tint-danger-fg)" tintBg="var(--tint-danger)" title="Top Blocked Destinations (24h)">
          {blocked.length === 0 ? (
            <Empty>Nothing blocked was recorded with a destination for this firewall in the window.</Empty>
          ) : (
            <RankedList
              rows={blocked}
              keyOf={(r) => `${r.dstIp}:${r.dstPort}:${r.protocol}`}
              labelOf={(r) => `${r.dstIp}${r.dstPort ? `:${r.dstPort}` : ''}${r.protocol ? ` ${r.protocol}` : ''}`}
              color="var(--red)"
            />
          )}
        </Panel>
      </div>

      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', lineHeight: 1.7 }}>
        {/* ⛔ The same caveat the fleet tab carries, repeated rather than
            assumed: a per-device page is exactly where someone compares two
            firewalls' byte totals and draws a conclusion the data cannot support. */}
        All figures cover the last 24 hours and come from the hourly rollups, never the raw event
        table. Volume in bytes is only measurable where the vendor reports it per session — FortiOS
        reports cumulative counters that cannot be summed, so its traffic is counted in events but
        not measured in bytes. An em-dash means not measured, never zero.
      </div>
    </div>
  );
}
