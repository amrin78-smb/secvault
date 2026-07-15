import Link from 'next/link';
import { headers } from 'next/headers';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { pool } from '../../../lib/db';
import Table from '../../../components/ui/Table';
import Badge from '../../../components/ui/Badge';
import Button from '../../../components/ui/Button';
import StatusDot from '../../../components/ui/StatusDot';
import EmptyState from '../../../components/ui/EmptyState';
import Modal from '../../../components/ui/Modal';

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
// The spec called for small 'use client' components (module-top-level, in this same
// file) for View CVEs / Collect Now / Test Connectivity / Edit / Delete. That's not
// possible here — this file's default export is an async Server Component doing direct
// pool.query data-fetching, and 'use client' is a file-scope directive; adding it would
// turn the whole module (including the pg-backed fetch) into a client bundle, which
// can't run in the browser. Since no extra file is available for a client island, the
// same behavior is delivered with zero client JS:
//   - View CVEs / Edit -> plain <Link> (no interactivity needed).
//   - Collect Now / Test Connectivity -> Server Actions (<form action={...}>) that call
//     the owning workstreams' HTTP endpoints (/api/devices/[id]/collect,
//     /api/devices/[id]/test) via an internal fetch, forwarding the request's session
//     cookie (middleware.js requires a valid session on every /api/* route), then
//     revalidatePath('/devices') — the server-side equivalent of router.refresh().
//   - Delete -> a plain <Link href="?confirmDelete=<id>"> flips a query param; when it
//     matches a row, the shared Modal component (already 'use client' in its own file —
//     perfectly fine to import into a Server Component tree) renders a confirmation with
//     a Cancel link (clears the query param) and a Confirm <form> Server Action that
//     deletes the device and redirects back to a clean /devices URL.
// ────────────────────────────────────────────────────────────────────────

function internalFetch(path, init) {
  const h = headers();
  const host = h.get('host');
  const proto = h.get('x-forwarded-proto') || 'http';
  const cookie = h.get('cookie') || '';
  return fetch(`${proto}://${host}${path}`, {
    ...init,
    headers: { ...(init?.headers || {}), cookie },
    cache: 'no-store',
  });
}

async function collectNowAction(formData) {
  'use server';
  const id = formData.get('deviceId');
  await internalFetch(`/api/devices/${id}/collect`, { method: 'POST' });
  revalidatePath('/devices');
}

async function testConnectivityAction(formData) {
  'use server';
  const id = formData.get('deviceId');
  await internalFetch(`/api/devices/${id}/test`, { method: 'POST' });
  revalidatePath('/devices');
}

async function deleteDeviceAction(formData) {
  'use server';
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
    SELECT d.id, d.name, d.vendor, d.smc_host, d.last_connectivity_ok, d.last_collected_at,
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

export default async function DevicesPage({ searchParams }) {
  const sortKey = searchParams?.sort && SORT_OPTIONS[searchParams.sort] ? searchParams.sort : 'name';
  const devices = await getDevices(pool, sortKey);

  const confirmDeleteId = searchParams?.confirmDelete || null;
  const confirmDevice = confirmDeleteId ? devices.find((d) => d.id === confirmDeleteId) : null;

  function sortLink(key, label) {
    return (
      <Link
        href={`/devices?sort=${key}`}
        className={sortKey === key ? 'font-medium text-accent underline' : 'text-text-secondary hover:underline'}
      >
        {label}
      </Link>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-text-primary">Devices</h1>
        <Link
          href="/devices/new"
          className="inline-flex items-center justify-center rounded bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-hover"
        >
          Add Device
        </Link>
      </div>

      <div className="flex items-center gap-3 text-sm">
        <span className="text-text-muted">Sort by:</span>
        {sortLink('name', 'Name')}
        {sortLink('cve_count', 'CVE Count')}
        {sortLink('last_collected', 'Last Collected')}
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
            <tr className="border-b border-border bg-bg-surface text-left text-text-secondary">
              <th className="px-2 py-2">Name</th>
              <th className="px-2 py-2">Vendor</th>
              <th className="px-2 py-2">SMC Host</th>
              <th className="px-2 py-2">Version</th>
              <th className="px-2 py-2">Patch Now</th>
              <th className="px-2 py-2">Scheduled</th>
              <th className="px-2 py-2">Monitor</th>
              <th className="px-2 py-2">Last Collected</th>
              <th className="px-2 py-2">Status</th>
              <th className="px-2 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id} className="border-b border-border hover:bg-bg-elevated">
                <td className="truncate px-2 py-2">
                  <Link href={`/devices/${d.id}`} className="font-medium text-accent hover:underline">
                    {d.name}
                  </Link>
                </td>
                <td className="truncate px-2 py-2">
                  <Badge color="info">{d.vendor}</Badge>
                </td>
                <td className="truncate px-2 py-2 text-text-secondary">{d.smc_host || '—'}</td>
                <td className="truncate px-2 py-2 text-text-secondary">{d.version_string || '—'}</td>
                <td className="px-2 py-2 text-danger">{d.patch_now_count}</td>
                <td className="px-2 py-2 text-warning">{d.scheduled_count}</td>
                <td className="px-2 py-2 text-text-muted">{d.monitor_count}</td>
                <td className="truncate px-2 py-2 text-text-secondary">{formatDateTime(d.last_collected_at)}</td>
                <td className="px-2 py-2">
                  <StatusDot
                    status={
                      d.last_connectivity_ok === true ? 'green' : d.last_connectivity_ok === false ? 'red' : 'grey'
                    }
                  />
                </td>
                <td className="px-2 py-2">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <Link href={`/devices/${d.id}`} className="text-accent hover:underline">
                      View
                    </Link>
                    <form action={collectNowAction}>
                      <input type="hidden" name="deviceId" value={d.id} />
                      <button type="submit" className="text-accent hover:underline">
                        Collect
                      </button>
                    </form>
                    <form action={testConnectivityAction}>
                      <input type="hidden" name="deviceId" value={d.id} />
                      <button type="submit" className="text-accent hover:underline">
                        Test
                      </button>
                    </form>
                    <Link href={`/devices/${d.id}`} className="text-accent hover:underline">
                      Edit
                    </Link>
                    <Link href={`/devices?sort=${sortKey}&confirmDelete=${d.id}`} className="text-danger hover:underline">
                      Delete
                    </Link>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <Modal open={Boolean(confirmDevice)} title="Delete Device">
        {confirmDevice && (
          <div className="space-y-4">
            <p className="text-sm text-text-secondary">
              Delete <span className="font-medium text-text-primary">{confirmDevice.name}</span>? This removes all
              associated versions, rules, credentials, and CVE assessments.
            </p>
            <div className="flex items-center gap-3">
              <form action={deleteDeviceAction}>
                <input type="hidden" name="deviceId" value={confirmDevice.id} />
                <Button type="submit" variant="danger">
                  Delete
                </Button>
              </form>
              <Link href={`/devices?sort=${sortKey}`} className="text-sm text-text-secondary hover:underline">
                Cancel
              </Link>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
