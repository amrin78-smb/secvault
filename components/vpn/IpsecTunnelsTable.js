import Table from '../ui/Table';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';

// Live IPSec site-to-site tunnel table, fed by vpn_ipsec_tunnels (see
// lib/engines/vpnTunnels.js) — from the device query (Palo Alto `show vpn
// ipsec-sa`, Fortinet `diagnose vpn tunnel list`, Cisco `show vpn-sessiondb
// l2l`), NOT syslog. Presentational, server-safe (no hooks).

// Local duplicate of ActiveVpnUsersTable's byte formatter, per this codebase's
// duplicate-small-helper-per-file convention.
function formatBytes(n) {
  if (n == null) return null;
  const b = Number(n);
  if (!Number.isFinite(b) || b < 0) return null;
  if (b < 1024) return `${b} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = b / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 10 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function dataCell(bytesIn, bytesOut) {
  const din = formatBytes(bytesIn);
  const dout = formatBytes(bytesOut);
  if (din == null && dout == null) return '—';
  return `↓ ${din || '—'} / ↑ ${dout || '—'}`;
}

function StatusBadge({ status }) {
  if (!status) return <span>—</span>;
  const s = String(status).toLowerCase();
  if (s === 'up') return <Badge color="success">Up</Badge>;
  if (s === 'down') return <Badge color="danger">Down</Badge>;
  return <Badge color="muted">{status}</Badge>;
}

export default function IpsecTunnelsTable({ tunnels }) {
  const rows = Array.isArray(tunnels) ? tunnels : [];
  return (
    <div>
      <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>
        IPSec Site-to-Site Tunnels ({rows.length})
      </div>
      {rows.length === 0 ? (
        <EmptyState message="No IPSec tunnels reported — or tunnel status isn't collected for this device/vendor yet." />
      ) : (
        <Table>
          <colgroup>
            <col style={{ width: '30%' }} />
            <col style={{ width: '22%' }} />
            <col style={{ width: '12%' }} />
            <col style={{ width: '14%' }} />
            <col style={{ width: '22%' }} />
          </colgroup>
          <thead>
            <tr>
              <th>Tunnel</th>
              <th>Peer</th>
              <th>Status</th>
              <th>IKE</th>
              <th>Data</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                <td className="mono" title={r.name || ''} style={{ wordBreak: 'break-word' }}>
                  {r.name || '—'}
                </td>
                <td className="mono">{r.peer || '—'}</td>
                <td>
                  <StatusBadge status={r.status} />
                </td>
                <td>{r.ike_version || '—'}</td>
                <td className="mono" style={{ whiteSpace: 'normal' }}>
                  {dataCell(r.bytes_in, r.bytes_out)}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}
