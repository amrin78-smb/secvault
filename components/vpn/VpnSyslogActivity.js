import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import IconChip from '../ui/IconChip';
import { IconActivity } from '../icons';
import { getVpnActivityByDevice, getVpnActivity } from '../../lib/syslog/trafficStats';

export const dynamic = 'force-dynamic';

// VPN activity OBSERVED IN LOGS, added 2026-09-08 alongside the syslog collector.
//
// This is the third and newest of three different VPN answers SecVault gives,
// and they must not be confused with one another:
//
//   1. CONFIG-derived  (vpnSummary.js)      — "is VPN configured/enabled here"
//   2. SESSION counts  (vpn_session_snapshots) — "how many are connected right
//                                              now", Fortinet API only
//   3. LOG activity    (this component)     — "what actually happened", from
//                                              syslog, and the only one that
//                                              covers Palo Alto
//
// ⛔ Coverage is stated, not implied. Only Palo Alto (GLOBALPROTECT) and
// Fortinet (event/vpn) emit VPN logs in this fleet — verified against real
// captured events, not vendor documentation. A device absent from this list has
// not sent VPN logs, which is NOT the same as "no VPN activity", and the empty
// state says so rather than showing a reassuring zero.

function fmt(ts) {
  if (!ts) return '—';
  return new Date(ts).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

export default async function VpnSyslogActivity() {
  const [byDevice, recent] = await Promise.all([
    getVpnActivityByDevice(pool, 24),
    getVpnActivity(pool, 24, 8),
  ]);

  const total = byDevice.reduce((n, r) => n + r.events, 0);
  const unmanaged = byDevice.filter((r) => !r.deviceName).length;

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconActivity} color="#4ade80" bg="rgba(74,222,128,0.20)" />
          VPN Activity from Logs (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {byDevice.length === 0 ? (
          <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>
            No VPN log events received in the last 24 hours. Only Palo Alto
            (GlobalProtect) and Fortinet (SSL-VPN) send these; a device missing
            here has sent no VPN logs, which is not the same as having no VPN
            activity.
          </div>
        ) : (
          <>
            <div style={{ display: 'flex', gap: 20, alignItems: 'baseline', marginBottom: 10 }}>
              <div>
                <div style={{ fontSize: 24, fontWeight: 800, fontVariantNumeric: 'tabular-nums' }}>
                  {total.toLocaleString()}
                </div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>VPN events</div>
              </div>
              <div>
                <div style={{ fontSize: 24, fontWeight: 800, fontVariantNumeric: 'tabular-nums' }}>
                  {byDevice.length}
                </div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>reporting sources</div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 10 }}>
              {byDevice.slice(0, 10).map((r, i) => (
                <div
                  key={`${r.deviceId || 'unmanaged'}-${i}`}
                  style={{ display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: 'var(--text-base)' }}
                >
                  <span>
                    {r.deviceName ? (
                      <Link href={`/devices/${r.deviceId}/vpn`} style={{ color: 'var(--text-primary)' }}>
                        {r.deviceName}
                      </Link>
                    ) : (
                      <>
                        <span style={{ color: 'var(--text-secondary)' }}>unmanaged source</span>{' '}
                        <Badge color="warning">not in inventory</Badge>
                      </>
                    )}
                    {r.vendor ? (
                      <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}> · {r.vendor}</span>
                    ) : null}
                  </span>
                  <span style={{ fontVariantNumeric: 'tabular-nums' }}>{r.events.toLocaleString()}</span>
                </div>
              ))}
            </div>

            {recent.length > 0 && (
              <details>
                <summary style={{ cursor: 'pointer', fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
                  Most recent VPN events
                </summary>
                <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {recent.map((e, i) => (
                    <div key={i} style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                      <span style={{ color: 'var(--text-muted)' }}>{fmt(e.receivedAt)}</span>{' '}
                      <strong>{e.deviceName || e.sourceIp.replace('/32', '')}</strong>{' '}
                      <span
                        style={{
                          display: 'inline-block',
                          maxWidth: '100%',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          verticalAlign: 'bottom',
                        }}
                      >
                        {e.message.slice(0, 160)}
                      </span>
                    </div>
                  ))}
                </div>
              </details>
            )}

            <div
              style={{
                marginTop: 10,
                paddingTop: 8,
                borderTop: '1px solid var(--border)',
                fontSize: 'var(--text-sm)',
                color: 'var(--text-muted)',
              }}
            >
              Observed in syslog — independent of the config-derived status and the
              Fortinet-only session counts in the table below.
              {unmanaged > 0
                ? ` ${unmanaged} source${unmanaged === 1 ? '' : 's'} sending VPN logs ${unmanaged === 1 ? 'is' : 'are'} not in the device inventory.`
                : ''}
            </div>
          </>
        )}
      </CardBody>
    </Card>
  );
}
