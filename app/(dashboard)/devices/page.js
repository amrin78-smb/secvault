import Link from 'next/link';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { pool } from '../../../lib/db';
import Table from '../../../components/ui/Table';
import Badge from '../../../components/ui/Badge';
import Button from '../../../components/ui/Button';
import StatusDot from '../../../components/ui/StatusDot';
import EmptyState from '../../../components/ui/EmptyState';
import Modal from '../../../components/ui/Modal';
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
//   - View CVEs / Edit -> still a plain <Link> (no interactivity needed).
//   - Delete -> still a plain <Link href="?confirmDelete=<id>"> query-param flip
//     + the shared Modal component + a Confirm <form> Server Action -- a single
//     fast DB delete, not a network call to a firewall, so the blocking-
//     navigation cost that motivated the above change doesn't apply to it.
// ────────────────────────────────────────────────────────────────────────

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
  return (
    <Link
      href={`/devices?sort=${key}`}
      className={activeSortKey === key ? 'font-medium text-accent underline' : 'text-text-secondary hover:underline'}
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
            <tr className="border-b border-border bg-bg-surface text-left text-text-secondary">
              <th className="px-2 py-2">Name</th>
              <th className="px-2 py-2">Vendor</th>
              <th className="px-2 py-2">Address</th>
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
                <td className="truncate px-2 py-2 text-text-secondary">
                  {d.vendor === 'forcepoint' ? d.smc_host || '—' : d.mgmt_ip || '—'}
                </td>
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
                    <DeviceRowActions deviceId={d.id} />
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
