import Link from 'next/link';
import { pool } from '../../../lib/db';
import PageHeader from '../../../components/ui/PageHeader';
import Table from '../../../components/ui/Table';
import Badge from '../../../components/ui/Badge';
import EmptyState from '../../../components/ui/EmptyState';
import { summarizeVpnConfig } from '../../../lib/engines/vpnSummary';
import VpnSyslogActivity from '../../../components/vpn/VpnSyslogActivity';

export const dynamic = 'force-dynamic';

// Fleet-wide VPN exposure view. ⛔ THREE DIFFERENT VPN ANSWERS live on this
// page and must not be conflated:
//
//   1. CONFIG-derived (the table below, vpnSummary.js) — "is VPN configured
//      and enabled here", from device_configs.config_parsed.
//   2. SESSION counts (vpn_session_snapshots) — "how many are connected right
//      now", Fortinet API only.
//   3. LOG activity (VpnSyslogActivity, added 2026-09-08) — "what actually
//      happened", from syslog. This is the only one that covers Palo Alto.
//
// This comment previously said real usage data "needs syslog ingestion this
// app doesn't have yet". That stopped being true when services/collector.js
// shipped, and a stale caveat is worse than none: it would send the next
// reader looking for data that is now sitting right above the table.
//
// Server component queries the DB directly, same convention as every other
// fleet-wide page in this app (compliance/page.js, alerts/page.js).

// One row per active device: latest config_parsed (for the VPN summary) +
// latest vpn_session_snapshots.active_session_count (if this device's
// adapter supports session polling — currently Fortinet only). Two separate
// LEFT JOIN DISTINCT ON subqueries rather than a single query with window
// functions — clearer to read, and this table is fleet-sized (dozens, not
// millions of rows), not a place where that tradeoff matters.
async function getFleetVpnStatus(dbPool) {
  const { rows: devices } = await dbPool.query(
    `SELECT id AS device_id, name AS device_name, vendor
     FROM devices
     WHERE active = true
     ORDER BY name ASC`
  );

  const { rows: configRows } = await dbPool.query(
    `SELECT DISTINCT ON (device_id) device_id, config_parsed, collected_at
     FROM device_configs
     WHERE device_id = ANY($1::uuid[])
     ORDER BY device_id, collected_at DESC`,
    [devices.map((d) => d.device_id)]
  );
  const configByDevice = new Map(configRows.map((r) => [r.device_id, r]));

  const { rows: sessionRows } = await dbPool.query(
    `SELECT DISTINCT ON (device_id) device_id, active_session_count, sampled_at
     FROM vpn_session_snapshots
     WHERE device_id = ANY($1::uuid[])
     ORDER BY device_id, sampled_at DESC`,
    [devices.map((d) => d.device_id)]
  );
  const sessionByDevice = new Map(sessionRows.map((r) => [r.device_id, r]));

  return devices.map((d) => {
    const configRow = configByDevice.get(d.device_id);
    const summary = summarizeVpnConfig(d.vendor, configRow ? configRow.config_parsed : null);
    const session = sessionByDevice.get(d.device_id);
    return {
      ...d,
      summary,
      lastConfigAt: configRow ? configRow.collected_at : null,
      activeSessionCount: session ? session.active_session_count : null,
      sessionSampledAt: session ? session.sampled_at : null,
    };
  });
}

function formatDateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function statusBadge(summary) {
  if (!summary.supported) return <Badge color="muted">Not supported</Badge>;
  if (!summary.hasConfig) return <Badge color="muted">No VPN config</Badge>;
  if (summary.enabled === true) return <Badge color="success">Enabled</Badge>;
  if (summary.enabled === false) return <Badge color="muted">Disabled</Badge>;
  // enabled === null/undefined (Sangfor's tri-state, or a vendor like
  // Fortinet/Palo Alto whose config was found but this module doesn't infer
  // a confident on/off state for — see vpnSummary.js's own comments).
  return <Badge color="warning">Configured (state unknown)</Badge>;
}

export default async function VpnFleetPage() {
  const devices = await getFleetVpnStatus(pool);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <PageHeader
        title="VPN"
        subtitle="Fleet-wide VPN/remote-access exposure, derived from each device's latest collected config."
        actions={
          <a href="/api/vpn/fleet?format=csv" className="btn btn-secondary">
            Export CSV
          </a>
        }
      />

      {/* Log-observed activity sits ABOVE the config table: it is the only
          one of the three views that reflects what actually happened. */}
      <VpnSyslogActivity />

      {devices.length === 0 ? (
        <EmptyState message="No active devices." />
      ) : (
        <Table>
          <colgroup>
            <col style={{ width: '22%' }} />
            <col style={{ width: '12%' }} />
            <col style={{ width: '22%' }} />
            <col style={{ width: '16%' }} />
            <col style={{ width: '14%' }} />
            <col style={{ width: '14%' }} />
          </colgroup>
          <thead>
            <tr>
              <th>Device</th>
              <th>Vendor</th>
              <th>VPN Status</th>
              <th>Config as of</th>
              <th>Active Sessions</th>
              <th>Sampled</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.device_id}>
                <td title={d.device_name}>
                  <Link href={`/devices/${d.device_id}/vpn`} className="link-quiet">
                    {d.device_name}
                  </Link>
                </td>
                <td>
                  <Badge color="info">{d.vendor}</Badge>
                </td>
                <td>{statusBadge(d.summary)}</td>
                <td style={{ color: 'var(--text-secondary)' }}>{formatDateTime(d.lastConfigAt)}</td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  {d.activeSessionCount === null ? '—' : d.activeSessionCount}
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>{formatDateTime(d.sessionSampledAt)}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}
