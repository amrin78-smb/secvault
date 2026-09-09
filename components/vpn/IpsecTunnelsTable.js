import Table from '../ui/Table';
import Badge from '../ui/Badge';
import NotMeasured from '../ui/NotMeasured';
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

// ⛔ Tri-state: a vendor that reports no counters gets a NotMeasured marker
// WITH A REASON, never "0 B" and never a bare dash — see
// components/ui/NotMeasured.js for why the reason is the load-bearing part.
function dataCell(bytesIn, bytesOut) {
  const din = formatBytes(bytesIn);
  const dout = formatBytes(bytesOut);
  if (din == null && dout == null) {
    return (
      <NotMeasured reason="This vendor does not report byte counters for IPsec tunnels. Not the same as no traffic having crossed it." />
    );
  }
  return (
    <>
      &darr; {din == null ? <NotMeasured reason="No inbound counter reported for this tunnel." /> : din} /
      &uarr;{' '}
      {dout == null ? <NotMeasured reason="No outbound counter reported for this tunnel." /> : dout}
    </>
  );
}

// ⛔ Four states, not two. `up`/`down` are the device's answer; an unrecognised
// verb is still the device's answer and is shown VERBATIM (never mapped to
// down); and NO status at all is not a state of the tunnel, it is a gap in what
// we could read — hueless, with a reason, never a severity colour.
function StatusBadge({ status }) {
  if (!status) {
    return <NotMeasured reason="The device returned this tunnel without a status — neither up nor down was reported." />;
  }
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
        {r.name || <NotMeasured reason="The device did not report a name for this tunnel." />}
      </td>
      <td className="mono">
        {r.peer || <NotMeasured reason="The device did not report a peer address for this tunnel." />}
      </td>
      <td>
        <StatusBadge status={r.status} />
      </td>
      <td>
        {r.ike_version || (
          <NotMeasured reason="The device did not report an IKE version for this tunnel." />
        )}
      </td>
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
              // ⛔ HUELESS, not amber. This used to be a `warning` Badge, which
              // borrows the severity ramp to describe a gap in what SecVault
              // could read — "we do not know" is neither good news nor bad, and
              // colouring it as a mild alarm is the same lie as colouring it
              // green (components/ui/NotMeasured.js's rule). The count is a real
              // measured number; what it counts is an absence.
              <span
                className="badge"
                title="Reported by the device without a usable status — neither up nor down. This is a gap in what the device told us, not a tunnel fault."
                style={{
                  background: 'var(--surface-subtle)',
                  color: 'var(--unmeasured)',
                  border: '1px solid var(--border)',
                }}
              >
                {unknown} status not reported
              </span>
            ) : null}
          </div>
        ) : null}
      </div>

      {rows.length === 0 ? (
        // ⛔ Two different facts, and this component cannot tell them apart: a
        // device that genuinely has no site-to-site tunnels, and a vendor whose
        // adapter does not implement getVpnTunnels() at all. Say both; do not
        // settle on "no tunnels", which would report a collection gap as a
        // configuration fact.
        <EmptyState message="No IPsec site-to-site tunnels were returned for this device — either it has none configured, or tunnel collection is not implemented for this vendor/transport. This view cannot tell those two apart." />
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
