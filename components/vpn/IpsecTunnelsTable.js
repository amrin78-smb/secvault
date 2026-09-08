import Table from '../ui/Table';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import Pagination from '../ui/Pagination';
import { paginateArray } from '../../lib/pagination';

// Live IPSec site-to-site tunnel table, fed by vpn_ipsec_tunnels (see
// lib/engines/vpnTunnels.js) — from the device query (Palo Alto `show vpn
// ipsec-sa`, Fortinet `diagnose vpn tunnel list`, Cisco `show vpn-sessiondb
// l2l`), NOT syslog. Presentational, server-safe (no hooks).
//
// ⛔ Pages on `?tunnelPage=`, NOT `?page=`. This device page also carries the
// Active VPN Users table, which keeps the plain `page` param; two tables
// sharing one param would move together, so paging the tunnels would silently
// repaginate the user list a floor above it. That is what Pagination's
// `paramName` is for.
//
// Rows come from an already-assembled engine snapshot (getVpnTunnels returns
// one device's tunnels), so this is paginateArray, not SQL LIMIT/OFFSET — the
// up/down/unknown tallies in the heading are computed over the FULL set, not
// the visible page, or a hub's second page of tunnels could report "0 down"
// while a tunnel on page 1 is down.

const PAGE_SIZE = 25;

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

// ⛔ Tri-state: a vendor that reports no counters gets a dash, never "0 B".
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

// Plain function returning JSX, called imperatively from both the visible table
// and the overflow one — NOT a nested component definition (CLAUDE.md).
function tunnelRow(r, key) {
  return (
    <tr key={key}>
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
  );
}

function tunnelColgroup() {
  return (
    <colgroup>
      <col style={{ width: '30%' }} />
      <col style={{ width: '22%' }} />
      <col style={{ width: '12%' }} />
      <col style={{ width: '14%' }} />
      <col style={{ width: '22%' }} />
    </colgroup>
  );
}

function tunnelHead() {
  return (
    <thead>
      <tr>
        <th>Tunnel</th>
        <th>Peer</th>
        <th>Status</th>
        <th>IKE</th>
        <th>Data</th>
      </tr>
    </thead>
  );
}

/**
 * @param {object[]} tunnels      every collected tunnel for this device
 * @param {string}   basePath     the page's own path, e.g. `/devices/<id>/vpn`
 * @param {object}   searchParams the page's searchParams (preserved on paging links)
 * @param {number}   page         1-based page from `?tunnelPage=`
 */
export default function IpsecTunnelsTable({ tunnels, basePath, searchParams, page }) {
  const rows = Array.isArray(tunnels) ? tunnels : [];
  const win = paginateArray(rows, page, PAGE_SIZE);

  // ⛔ Three counts, not two. A tunnel whose vendor reported no status is
  // neither up nor down, and folding it into "down" would raise an alarm that
  // no device actually raised — while folding it into "up" would hide one.
  let up = 0;
  let down = 0;
  let unknown = 0;
  for (const r of rows) {
    const s = r.status ? String(r.status).toLowerCase() : null;
    if (s === 'up') up += 1;
    else if (s === 'down') down += 1;
    else unknown += 1;
  }

  return (
    <div>
      <div
        style={{
          display: 'flex',
          alignItems: 'baseline',
          justifyContent: 'space-between',
          gap: 12,
          flexWrap: 'wrap',
          marginBottom: 8,
        }}
      >
        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
          IPSec Site-to-Site Tunnels ({rows.length})
        </div>
        {rows.length > 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <Badge color="success">{up} up</Badge>
            <Badge color={down > 0 ? 'danger' : 'muted'}>{down} down</Badge>
            {unknown > 0 ? (
              // Badge takes no title prop, so the explanation hangs on a
              // wrapping span rather than being dropped.
              <span title="Reported by the device without a usable status — neither up nor down">
                <Badge color="warning">{unknown} status not reported</Badge>
              </span>
            ) : null}
          </div>
        ) : null}
      </div>

      {rows.length === 0 ? (
        <EmptyState message="No IPSec tunnels reported — or tunnel status isn't collected for this device/vendor yet." />
      ) : (
        <>
          <Table>
            {tunnelColgroup()}
            {tunnelHead()}
            <tbody>{win.rows.map((r, i) => tunnelRow(r, `${win.page}-${i}`))}</tbody>
          </Table>

          <Pagination
            basePath={basePath}
            searchParams={searchParams || {}}
            page={win.page}
            pageSize={win.pageSize}
            total={win.total}
            label="tunnels"
            paramName="tunnelPage"
          />
        </>
      )}
    </div>
  );
}
