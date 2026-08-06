import Link from 'next/link';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../api/auth/[...nextauth]/route';
import { isAdmin } from '../../../lib/rbac';
import { pool } from '../../../lib/db';
import Table from '../../../components/ui/Table';
import Badge from '../../../components/ui/Badge';
import Button from '../../../components/ui/Button';
import StatusDot from '../../../components/ui/StatusDot';
import EmptyState from '../../../components/ui/EmptyState';
import Modal from '../../../components/ui/Modal';
import PageHeader from '../../../components/ui/PageHeader';
import DeviceRowActions from '../../../components/devices/DeviceRowActions';
import DeviceInventoryTiles from '../../../components/devices/DeviceInventoryTiles';
import DeviceFilters from '../../../components/devices/DeviceFilters';
import { SecurityScoreCell, SupportCell, HaCell, CveCell } from '../../../components/devices/DevicePostureCells';
import { getDeviceInventory, computeTiles } from '../../../lib/engines/deviceInventory';

export const dynamic = 'force-dynamic';


// ────────────────────────────────────────────────────────────────────────
// NOTE on per-row actions:
// Collect Now / Test Connectivity used to be Server Actions (<form action={...}>)
// calling /api/devices/[id]/collect and /test via an internalFetch() cookie-
// forwarding helper -- no client JS in front of them, so clicking either one
// did a genuine top-level form navigation with zero pending UI, and just sat
// there (up to ~2 minutes on an unreachable device) until the response came
// back. Replaced with DeviceRowActions.js, a client component using the same
// fetch+pending+router.refresh() pattern as the device detail page's
// DeviceActions.js, styled to match this table's compact inline text links.
//   - View -> still a plain <Link> (no interactivity needed). The separate "Edit"
//     link that used to sit here was removed: it pointed at this same URL, and the
//     device detail page it led to has no field-editing form (identity/inventory
//     fields can only be changed via the PUT API directly, not from this UI) --
//     the link was dead/misleading, not a real affordance.
//   - Delete -> still a plain <Link href="?confirmDelete=<id>"> query-param flip
//     + the shared Modal component + a Confirm <form> Server Action -- a single
//     fast DB delete, not a network call to a firewall, so the blocking-
//     navigation cost that motivated the above change doesn't apply to it.
// ────────────────────────────────────────────────────────────────────────

async function deleteDeviceAction(formData) {
  'use server';
  // Server Actions can't return an HTTP status code the way an API route
  // can (see lib/rbac.js's own header comment) — the guard here redirects
  // back with ?error=forbidden instead, which the page renders as a
  // banner, rather than throwing an uncaught error into the framework's
  // generic error boundary.
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    redirect('/devices?error=forbidden');
  }
  const id = formData.get('deviceId');
  await pool.query('DELETE FROM devices WHERE id = $1', [id]);
  revalidatePath('/devices');
  redirect('/devices');
}

function formatDateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// Filtering is applied to the FULL decorated row set (server-side), so a
// filter narrows the whole fleet rather than just the visible page. Every
// predicate here is a pure function of an already-fetched row — no extra query.
function matchesFilters(row, f) {
  if (f.q) {
    const hay = [row.name, row.mgmt_ip, row.smc_host, row.site, row.vendor]
      .filter(Boolean).join(' ').toLowerCase();
    if (!hay.includes(f.q.toLowerCase())) return false;
  }
  if (f.vendor && row.vendor !== f.vendor) return false;
  if (f.risk) {
    // 'unanalysed' is a REAL state, distinct from 'low' — a device with no
    // analysis rows has earned no band at all and must not be filed under the
    // best one.
    if (f.risk === 'unanalysed') { if (row.riskBand !== null) return false; }
    else if (row.riskBand !== f.risk) return false;
  }
  if (f.status) {
    if (f.status === 'online' && row.last_connectivity_ok !== true) return false;
    if (f.status === 'offline' && row.last_connectivity_ok !== false) return false;
    if (f.status === 'unchecked' && row.last_connectivity_ok !== null) return false;
  }
  if (f.support) {
    const expired = (row.expired_count || 0) > 0;
    const expiring =
      !expired && row.soonest_future_expiry &&
      new Date(row.soonest_future_expiry).getTime() - Date.now() <= 90 * 86400000;
    if (f.support === 'expired' && !expired) return false;
    if (f.support === 'expiring' && !expiring) return false;
    if (f.support === 'unknown' && (row.unknown_expiry_count || 0) === 0) return false;
  }
  if (f.site) {
    if (f.site === '__none__') { if (row.site) return false; }
    else if (row.site !== f.site) return false;
  }
  return true;
}


// Module-top-level so a future refactor toward client-side interactive sort
// controls can't accidentally turn this into a component defined inside a
// component (see CLAUDE.md's "NEVER define a React component inside another
// React component" rule). Currently invoked as a plain function call
// ({sortLink(...)}), not a JSX tag, so it isn't a component today -- but this
// keeps it that way even if a later change starts rendering it as
// <SortLink/>. Takes the previously-closed-over `sortKey` explicitly instead
// of relying on closure.
function sortLink(activeSortKey, key, label) {
  const active = activeSortKey === key;
  return (
    <Link
      href={`/devices?sort=${key}`}
      style={{
        fontWeight: active ? 600 : 400,
        color: active ? 'var(--primary)' : 'var(--text-secondary)',
        textDecoration: active ? 'underline' : 'none',
      }}
    >
      {label}
    </Link>
  );
}

export default async function DevicesPage({ searchParams }) {
  // getDeviceInventory validates ?sort= against its own whitelist and returns
  // the key it actually used, so an unknown value can never reach any ordering.
  const { rows: allRows, tiles: fleetTiles, sortKey } = await getDeviceInventory(pool, {
    sort: searchParams?.sort,
  });

  const filters = {
    q: searchParams?.q || '',
    vendor: searchParams?.vendor || '',
    risk: searchParams?.risk || '',
    status: searchParams?.status || '',
    support: searchParams?.support || '',
    site: searchParams?.site || '',
  };
  const devices = allRows.filter((r) => matchesFilters(r, filters));

  // Filter dropdowns are built from the FULL set, not the filtered one —
  // otherwise picking a vendor removes every other vendor from the dropdown
  // and the filter becomes a one-way trip.
  const vendors = [...new Set(allRows.map((r) => r.vendor))].sort();
  const sites = [...new Set(allRows.map((r) => r.site).filter(Boolean))].sort();

  // ⛔ Tiles reflect the CURRENT view. With a filter applied they describe what
  // is on screen, which is what the numbers sitting directly above the table
  // have to mean; unfiltered they are the whole fleet.
  const tiles = devices.length === allRows.length ? fleetTiles : computeTiles(devices);

  const confirmDeleteId = searchParams?.confirmDelete || null;
  const confirmDevice = confirmDeleteId ? devices.find((d) => d.id === confirmDeleteId) : null;

  // Defense in depth only — deleteDeviceAction's own isAdmin() guard above
  // is the real enforcement. Hiding the Delete link/button for a viewer
  // just avoids a confusing "click Delete, land back with a forbidden
  // banner" round trip.
  const session = await getServerSession(authOptions);
  const canWrite = isAdmin(session);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader
        title="Devices"
        actions={
          canWrite && (
            <Link href="/devices/new" className="btn btn-primary">
              Add Device
            </Link>
          )
        }
      />

      {searchParams?.error === 'forbidden' && (
        <div
          style={{
            padding: '10px 14px',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--tint-danger)',
            color: 'var(--tint-danger-fg)',
            fontSize: 'var(--text-base)',
          }}
        >
          You don&apos;t have permission to do that — admin role required.
        </div>
      )}

      <DeviceInventoryTiles tiles={tiles} />

      <DeviceFilters
        vendors={vendors}
        sites={sites}
        activeCount={devices.length}
        totalCount={allRows.length}
      />

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 'var(--text-base)', flexWrap: 'wrap' }}>
        <span style={{ color: 'var(--text-muted)' }}>Sort by:</span>
        {sortLink(sortKey, 'name', 'Name')}
        {sortLink(sortKey, 'score', 'Security Score')}
        {sortLink(sortKey, 'cve_count', 'CVE Count')}
        {sortLink(sortKey, 'rules', 'Rules')}
        {sortLink(sortKey, 'last_collected', 'Last Collected')}
      </div>

      {devices.length === 0 ? (
        <EmptyState
          message={
            allRows.length === 0
              ? 'No devices yet. Add one to get started.'
              : 'No devices match these filters.'
          }
        />
      ) : (
        <Table>
          {/* 10 columns. The mockup had 13; Address and Monitor-band CVEs were
              dropped rather than shipped clipped -- this table already sits in
              Table's overflow-x box, but a column an operator cannot read
              without scrolling is not a column they will use. Address stays one
              click away on the device page. Site was dropped too (v2.56.2):
              exactly one of 16 devices has a value, so the column was spending
              9% of the width rendering em-dashes. It stays searchable and
              filterable -- only the column is gone. */}
          <colgroup>
            <col style={{ width: '16%' }} /> {/* Device   */}
            <col style={{ width: '9%' }} />  {/* Vendor   */}
            <col style={{ width: '11%' }} /> {/* Score    */}
            <col style={{ width: '11%' }} /> {/* Version  */}
            <col style={{ width: '7%' }} />  {/* Rules    */}
            <col style={{ width: '10%' }} /> {/* CVEs     */}
            <col style={{ width: '11%' }} /> {/* Support  */}
            <col style={{ width: '8%' }} />  {/* HA       */}
            <col style={{ width: '10%' }} /> {/* Collected*/}
            <col style={{ width: '7%' }} />  {/* Actions  */}
          </colgroup>
          <thead>
            <tr>
              <th>Device</th>
              <th>Vendor</th>
              <th title="Security Score — composite of vulnerability posture, rule hygiene and compliance (higher is better). Colour shows the rule-analysis risk band.">
                Score
              </th>
              <th>Version</th>
              <th>Rules</th>
              <th>CVEs</th>
              <th title="Support contract expiry from collected licences. NOT vendor OS end-of-life, which SecVault does not collect.">
                Support
              </th>
              <th>HA</th>
              <th>Collected</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id}>
                <td>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <StatusDot
                      status={
                        d.last_connectivity_ok === true ? 'green' : d.last_connectivity_ok === false ? 'red' : 'grey'
                      }
                    />
                    <Link href={`/devices/${d.id}`} className="link-quiet">
                      {d.name}
                    </Link>
                  </span>
                </td>
                <td>
                  <Badge color="info">{d.vendor}</Badge>
                </td>
                <td>
                  <SecurityScoreCell
                    score={d.securityScore}
                    riskBand={d.riskBand}
                    components={d.securityComponents}
                  />
                </td>
                <td>{d.version_string || '—'}</td>
                <td>
                  {d.rule_count > 0 ? (
                    <span title={`${d.enabled_rule_count} enabled`}>{d.rule_count.toLocaleString()}</span>
                  ) : (
                    <span style={{ color: 'var(--text-muted)' }}>—</span>
                  )}
                </td>
                <td>
                  <CveCell patchNow={d.patch_now_count} scheduled={d.scheduled_count} />
                </td>
                <td>
                  <SupportCell
                    expiredCount={d.expired_count}
                    soonestFutureExpiry={d.soonest_future_expiry}
                    unknownCount={d.unknown_expiry_count}
                  />
                </td>
                <td>
                  <HaCell
                    enabled={d.ha_enabled}
                    mode={d.ha_mode}
                    localState={d.ha_local_state}
                    peerStatus={d.ha_peer_status}
                  />
                </td>
                <td>{formatDateTime(d.last_collected_at)}</td>
                <td>
                  <DeviceRowActions deviceId={d.id} sortKey={sortKey} canWrite={canWrite} />
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      {canWrite && (
        <Modal open={Boolean(confirmDevice)} title="Delete Device">
          {confirmDevice && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
                Delete <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{confirmDevice.name}</span>?
                This removes all associated versions, rules, credentials, and CVE assessments.
              </p>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <form action={deleteDeviceAction}>
                  <input type="hidden" name="deviceId" value={confirmDevice.id} />
                  <Button type="submit" variant="danger">
                    Delete
                  </Button>
                </form>
                <Link
                  href={`/devices?sort=${sortKey}`}
                  style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', textDecoration: 'underline' }}
                >
                  Cancel
                </Link>
              </div>
            </div>
          )}
        </Modal>
      )}
    </div>
  );
}
