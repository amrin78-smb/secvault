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

export const dynamic = 'force-dynamic';

// Whitelist mapping ?sort= to a safe ORDER BY fragment — the raw query param is never
// interpolated into SQL, only used as a key lookup into this object.
const SORT_OPTIONS = {
  name: 'd.name ASC',
  cve_count: 'patch_now_count DESC, scheduled_count DESC, monitor_count DESC, d.name ASC',
  last_collected: 'd.last_collected_at DESC NULLS LAST',
};

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

async function getDevices(dbPool, sortKey) {
  const orderBy = SORT_OPTIONS[sortKey] || SORT_OPTIONS.name;
  const sql = `
    SELECT d.id, d.name, d.vendor, d.smc_host, d.mgmt_ip, d.last_connectivity_ok, d.last_collected_at,
           dv.version_string,
           COALESCE(band.patch_now_count, 0) AS patch_now_count,
           COALESCE(band.scheduled_count, 0) AS scheduled_count,
           COALESCE(band.monitor_count, 0) AS monitor_count
    FROM devices d
    LEFT JOIN LATERAL (
      SELECT version_string
      FROM device_versions
      WHERE device_versions.device_id = d.id
      ORDER BY collected_at DESC
      LIMIT 1
    ) dv ON true
    LEFT JOIN LATERAL (
      SELECT
        COUNT(*) FILTER (WHERE priority_band = 'patch_now') AS patch_now_count,
        COUNT(*) FILTER (WHERE priority_band = 'scheduled') AS scheduled_count,
        COUNT(*) FILTER (WHERE priority_band = 'monitor') AS monitor_count
      FROM device_cve_assessments
      WHERE device_cve_assessments.device_id = d.id
    ) band ON true
    ORDER BY ${orderBy}
  `;
  const result = await dbPool.query(sql);
  return result.rows;
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
  const sortKey = searchParams?.sort && SORT_OPTIONS[searchParams.sort] ? searchParams.sort : 'name';
  const devices = await getDevices(pool, sortKey);

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

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 'var(--text-base)' }}>
        <span style={{ color: 'var(--text-muted)' }}>Sort by:</span>
        {sortLink(sortKey, 'name', 'Name')}
        {sortLink(sortKey, 'cve_count', 'CVE Count')}
        {sortLink(sortKey, 'last_collected', 'Last Collected')}
      </div>

      {devices.length === 0 ? (
        <EmptyState message="No devices yet. Add one to get started." />
      ) : (
        <Table>
          <colgroup>
            <col style={{ width: '15%' }} />
            <col style={{ width: '9%' }} />
            <col style={{ width: '13%' }} />
            <col style={{ width: '9%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '11%' }} />
            <col style={{ width: '6%' }} />
            <col style={{ width: '13%' }} />
          </colgroup>
          <thead>
            <tr>
              <th>Name</th>
              <th>Vendor</th>
              <th>Address</th>
              <th>Version</th>
              <th>Patch Now</th>
              <th>Scheduled</th>
              <th>Monitor</th>
              <th>Last Collected</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id}>
                <td>
                  <Link href={`/devices/${d.id}`} style={{ fontWeight: 500, color: 'var(--primary)', textDecoration: 'none' }}>
                    {d.name}
                  </Link>
                </td>
                <td>
                  <Badge color="info">{d.vendor}</Badge>
                </td>
                <td>{d.vendor === 'forcepoint' ? d.smc_host || '—' : d.mgmt_ip || '—'}</td>
                <td>{d.version_string || '—'}</td>
                <td style={{ color: 'var(--red)' }}>{d.patch_now_count}</td>
                <td style={{ color: 'var(--yellow)' }}>{d.scheduled_count}</td>
                <td style={{ color: 'var(--text-muted)' }}>{d.monitor_count}</td>
                <td>{formatDateTime(d.last_collected_at)}</td>
                <td>
                  <StatusDot
                    status={
                      d.last_connectivity_ok === true ? 'green' : d.last_connectivity_ok === false ? 'red' : 'grey'
                    }
                  />
                </td>
                <td>
                  <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8, fontSize: 'var(--text-xs)' }}>
                    <Link href={`/devices/${d.id}`} style={{ color: 'var(--primary)', textDecoration: 'underline' }}>
                      View
                    </Link>
                    {canWrite && <DeviceRowActions deviceId={d.id} />}
                    {canWrite && (
                      <Link
                        href={`/devices?sort=${sortKey}&confirmDelete=${d.id}`}
                        style={{ color: 'var(--red)', textDecoration: 'underline' }}
                      >
                        Delete
                      </Link>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <Modal open={Boolean(confirmDevice)} title="Delete Device">
        {confirmDevice && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
              Delete <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{confirmDevice.name}</span>? This
              removes all associated versions, rules, credentials, and CVE assessments.
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
    </div>
  );
}
