import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import Table from '../ui/Table';
import IconChip from '../ui/IconChip';
import { IconAlertTriangle, IconShield, IconActivity, IconBell } from '../icons';
import {
  getTopAttackers,
  getTopTargets,
  getTopThreats,
  getThreatsBySeverity,
  getDeviceThreatSummary,
} from '../../lib/syslog/threatStats';

export const dynamic = 'force-dynamic';

// Security-tab widgets built from log evidence — the ManageEngine Firewall
// Analyzer attack/virus/security report families the decommission review found
// missing (Top Attackers, Top Targets, Top Threats, threats by priority, and a
// per-device security summary).
//
// ⛔ These read syslog_events directly while every traffic widget reads a
// rollup. That is deliberate, not an oversight: threat events are 1.31% of the
// stream and are covered by a PARTIAL index over exactly the non-traffic rows,
// so a raw read is cheap AND keeps the attacker/target detail an aggregate
// destroys. See lib/syslog/threatStats.js.
//
// ⛔ Severity is the vendor's own word. Palo Alto and FortiOS use different
// vocabularies, mapped onto one scale by threatSeverityRank(); words it does
// not recognize are counted separately rather than guessed into a level.

const titleStyle = { display: 'flex', alignItems: 'center', gap: 8 };
const rowLabel = {
  fontSize: 'var(--text-base)',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
};

function Num({ value }) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) {
    return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  }
  return <span style={{ fontVariantNumeric: 'tabular-nums' }}>{Number(value).toLocaleString()}</span>;
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

// Rank -> tone. Only ranks the mapper produced; nothing is inferred.
function rankTone(rank) {
  if (rank >= 5) return 'var(--red)';
  if (rank === 4) return '#f97316';
  if (rank === 3) return 'var(--yellow)';
  if (rank === 2) return '#60a5fa';
  return 'var(--text-muted)';
}

function logsHref(params) {
  const q = new URLSearchParams(params).toString();
  return `/logs?${q}`;
}

// ---------------------------------------------------------------------------

export async function TopAttackersWidget() {
  const rows = await getTopAttackers(pool, 24, 8);
  const max = rows.reduce((n, r) => Math.max(n, r.events), 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconAlertTriangle} color="#f87171" bg="rgba(248,113,113,0.20)" />
          Top Attackers (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>No threat events with a source address in the last 24 hours.</Empty>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
            {rows.map((r) => (
              <div key={r.srcIp}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                  <span style={rowLabel}>
                    {/* Straight into the raw evidence for this host. */}
                    <Link
                      href={logsHref({ srcIp: r.srcIp.replace('/32', ''), logClass: 'threat', limit: '250' })}
                      style={{ color: 'var(--text-primary)' }}
                    >
                      {r.srcIp.replace('/32', '')}
                    </Link>
                    {r.srcCountry ? (
                      <span style={{ marginLeft: 6, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                        {r.srcCountry}
                      </span>
                    ) : null}
                  </span>
                  <span style={{ fontSize: 'var(--text-base)', whiteSpace: 'nowrap' }}>
                    <Num value={r.events} />
                    {/* One host hitting 400 targets and one hitting 1 are
                        different problems at the same event count. */}
                    <span style={{ color: 'var(--text-muted)', marginLeft: 8, fontSize: 'var(--text-sm)' }}>
                      {r.targets.toLocaleString()} target{r.targets === 1 ? '' : 's'}
                    </span>
                  </span>
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

export async function TopTargetsWidget() {
  const rows = await getTopTargets(pool, 24, 8);
  const max = rows.reduce((n, r) => Math.max(n, r.events), 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconShield} color="#fb923c" bg="rgba(251,146,60,0.20)" />
          Most Targeted Hosts (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>No threat events with a destination address in the last 24 hours.</Empty>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
            {rows.map((r) => (
              <div key={r.dstIp}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                  <span style={rowLabel}>
                    <Link
                      href={logsHref({ dstIp: r.dstIp.replace('/32', ''), logClass: 'threat', limit: '250' })}
                      style={{ color: 'var(--text-primary)' }}
                    >
                      {r.dstIp.replace('/32', '')}
                    </Link>
                  </span>
                  <span style={{ fontSize: 'var(--text-base)', whiteSpace: 'nowrap' }}>
                    <Num value={r.events} />
                    <span style={{ color: 'var(--text-muted)', marginLeft: 8, fontSize: 'var(--text-sm)' }}>
                      from {r.attackers.toLocaleString()}
                    </span>
                  </span>
                </div>
                <Bar pct={max > 0 ? (r.events / max) * 100 : 0} tone="#fb923c" />
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

export async function TopThreatsWidget() {
  const rows = await getTopThreats(pool, 24, 8);
  const max = rows.reduce((n, r) => Math.max(n, r.events), 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconBell} color="#c084fc" bg="rgba(192,132,252,0.20)" />
          Top Threats (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>
            No named threats in the last 24 hours. Signature names come from the
            firewall&apos;s own IPS, antivirus and URL-filtering engines.
          </Empty>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
            {rows.map((r) => (
              <div key={`${r.threatName}-${r.severity}-${r.subtype}`}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                  <span style={rowLabel}>
                    <Link
                      href={logsHref({ threatName: r.threatName, limit: '250' })}
                      style={{ color: 'var(--text-primary)' }}
                    >
                      {r.threatName}
                    </Link>
                    {r.subtype ? (
                      <span style={{ marginLeft: 6, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                        {r.subtype}
                      </span>
                    ) : null}
                  </span>
                  <span style={{ fontSize: 'var(--text-base)', whiteSpace: 'nowrap' }}>
                    <Num value={r.events} />
                    <span style={{ color: 'var(--text-muted)', marginLeft: 8, fontSize: 'var(--text-sm)' }}>
                      {r.sources} src
                    </span>
                  </span>
                </div>
                <Bar
                  pct={max > 0 ? (r.events / max) * 100 : 0}
                  tone={r.severityRank === null ? 'var(--text-muted)' : rankTone(r.severityRank)}
                />
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

export async function ThreatSeverityWidget() {
  const { levels, unranked, unreported } = await getThreatsBySeverity(pool, 24);
  const total = levels.reduce((n, l) => n + l.events, 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconActivity} color="#facc15" bg="rgba(250,204,21,0.20)" />
          Threats by Severity (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {levels.length === 0 && unranked === 0 && unreported === 0 ? (
          <Empty>No threat events in the last 24 hours.</Empty>
        ) : (
          <>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              {levels.map((l) => (
                <div key={l.rank}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                    <span style={rowLabel}>
                      {l.label}
                      {/* Both vendors' words are shown so a merged level is
                          visibly a merge, not a silent relabelling. */}
                      <span style={{ marginLeft: 6, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                        {l.vendorWords.join(', ')}
                      </span>
                    </span>
                    <span style={{ fontSize: 'var(--text-base)' }}><Num value={l.events} /></span>
                  </div>
                  <Bar pct={total > 0 ? (l.events / total) * 100 : 0} tone={rankTone(l.rank)} />
                </div>
              ))}
            </div>
            {unranked > 0 || unreported > 0 ? (
              <div style={{ marginTop: 8, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                {/* ⛔ Counted and named rather than folded into a level: a threat
                    filed under a guessed severity silently changes where it
                    sorts in a prioritized list. */}
                {unranked > 0
                  ? `${unranked.toLocaleString()} event${unranked === 1 ? '' : 's'} used a severity word SecVault does not rank. `
                  : ''}
                {unreported > 0
                  ? `${unreported.toLocaleString()} carried no severity at all.`
                  : ''}
              </div>
            ) : null}
          </>
        )}
      </CardBody>
    </Card>
  );
}

export async function DeviceThreatTable() {
  const rows = await getDeviceThreatSummary(pool, 24);
  const anyThreat = rows.some((r) => r.threatEvents > 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconShield} color="#f87171" bg="rgba(248,113,113,0.20)" />
          Security Events by Device (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>No active devices.</Empty>
        ) : (
          <>
            <Table minWidth={620}>
              <thead>
                <tr>
                  <th style={{ width: '32%' }}>Device</th>
                  <th style={{ width: '14%' }}>Vendor</th>
                  <th style={{ width: '18%', textAlign: 'right' }}>Threat events</th>
                  <th style={{ width: '18%', textAlign: 'right' }}>Distinct sources</th>
                  <th style={{ width: '18%', textAlign: 'right' }}>Signatures</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.deviceId}>
                    <td style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <Link href={`/devices/${r.deviceId}`} style={{ color: 'var(--text-primary)' }}>
                        {r.name}
                      </Link>
                    </td>
                    <td style={{ color: 'var(--text-muted)' }}>{r.vendor}</td>
                    <td style={{ textAlign: 'right', color: r.threatEvents > 0 ? 'var(--red)' : undefined }}>
                      <Num value={r.threatEvents || null} />
                    </td>
                    <td style={{ textAlign: 'right' }}><Num value={r.attackers || null} /></td>
                    <td style={{ textAlign: 'right' }}><Num value={r.distinctThreats || null} /></td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <div style={{ marginTop: 8, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              {/* A dash rather than a zero: a device with no threat events may
                  genuinely be clean, or may simply not be sending its IPS and
                  antivirus logs. Those are different, and this does not claim
                  to tell them apart. */}
              A dash means no threat events were received — which can mean a quiet
              device or one not forwarding its IPS/antivirus logs.
              {anyThreat ? '' : ' No device reported any threat events in this window.'}
            </div>
          </>
        )}
      </CardBody>
    </Card>
  );
}
