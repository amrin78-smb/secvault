import Table from '../ui/Table';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';

// Live per-user active VPN session table (ManageEngine "Active VPN Users"
// equivalent), fed by vpn_active_sessions (see lib/engines/vpnSessions.js) —
// the per-user detail the management-plane commands already return, NOT syslog
// data. Presentational, server-safe (no hooks) — the page passes the rows it
// queried. A device/vendor with no per-user detail yet renders the empty
// state, distinct from "collected and nobody is connected".

function formatDuration(seconds) {
  if (seconds == null) return '—';
  const s = Number(seconds);
  if (!Number.isFinite(s) || s < 0) return '—';
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${s}s`;
}

export default function ActiveVpnUsersTable({ sessions }) {
  const rows = Array.isArray(sessions) ? sessions : [];
  return (
    <div>
      <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>
        Active VPN Users ({rows.length})
      </div>
      {rows.length === 0 ? (
        <EmptyState message="No users currently connected — or live per-user detail isn't available for this device/vendor yet (only the session count is collected there)." />
      ) : (
        <Table>
          <colgroup>
            <col style={{ width: '19%' }} />
            <col style={{ width: '11%' }} />
            <col style={{ width: '14%' }} />
            <col style={{ width: '14%' }} />
            <col style={{ width: '17%' }} />
            <col style={{ width: '9%' }} />
            <col style={{ width: '16%' }} />
          </colgroup>
          <thead>
            <tr>
              <th>User</th>
              <th>Tunnel</th>
              <th>Source IP</th>
              <th>Assigned IP</th>
              <th>Login Time</th>
              <th>Duration</th>
              <th>Client</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                <td className="mono" title={r.username || ''} style={{ wordBreak: 'break-word' }}>
                  {r.username || '—'}
                </td>
                <td>{r.tunnel_type ? <Badge color="info">{r.tunnel_type}</Badge> : '—'}</td>
                <td className="mono">{r.source_ip || '—'}</td>
                <td className="mono">{r.assigned_ip || '—'}</td>
                <td className="mono" title={r.login_time || ''}>
                  {r.login_time || '—'}
                </td>
                <td>{formatDuration(r.duration_seconds)}</td>
                <td title={r.client || ''} style={{ wordBreak: 'break-word' }}>
                  {r.client || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}
