import Link from 'next/link';
import { pool } from '../../lib/db';
import DeviceCard from '../../components/devices/DeviceCard';
import Badge from '../../components/ui/Badge';
import EmptyState from '../../components/ui/EmptyState';

export const dynamic = 'force-dynamic';

// ────────────────────────────────────────────────────────────────────────
// NOTE on auto-refresh:
// The spec asked for a 'use client' island (useEffect + setInterval(() =>
// router.refresh(), 60000)) defined at module top level in this same file. That isn't
// achievable here: 'use client' is a file-scope directive — adding it to this file
// would turn the ENTIRE module, including the async Server Component default export
// below (which does direct pool.query fleet aggregation), into a client bundle. `pg`
// cannot be bundled for the browser, so that would break the build. Since only the
// files in the frozen list may be touched (no separate AutoRefresh.js is allowed), a
// dependency-free equivalent is used instead: a plain `<meta httpEquiv="refresh"
// content="60">` tag. Next.js App Router hoists <title>/<meta>/<link> elements
// rendered by a Server Component into <head>; even in the unlikely case a given
// browser doesn't hoist it, `<meta http-equiv="refresh">` is honored by all major
// engines regardless of where it sits in the document. This delivers the same
// "dashboard reflects the DB every 60s" outcome without violating the server/client
// module boundary and without adding a file outside the ones this task owns. See
// app/(dashboard)/advisories/page.js for the same reasoning applied to a different
// constraint (a Server Action instead of a client "Sync Now" button island).
// ────────────────────────────────────────────────────────────────────────

async function getFleetSummary(dbPool) {
  const result = await dbPool.query(
    `SELECT
       COUNT(*) FILTER (WHERE dca.priority_band = 'patch_now') AS patch_now_count,
       COUNT(*) FILTER (WHERE dca.priority_band = 'scheduled') AS scheduled_count,
       COUNT(*) FILTER (WHERE dca.priority_band = 'monitor') AS monitor_count
     FROM device_cve_assessments dca
     JOIN devices d ON d.id = dca.device_id
     WHERE d.active = true`
  );
  return (
    result.rows[0] || { patch_now_count: 0, scheduled_count: 0, monitor_count: 0 }
  );
}

async function getDeviceCount(dbPool) {
  const result = await dbPool.query('SELECT COUNT(*)::int AS total FROM devices WHERE active = true');
  return result.rows[0]?.total ?? 0;
}

async function getDevices(dbPool) {
  const result = await dbPool.query(
    `SELECT d.id, d.name, d.vendor, d.last_connectivity_ok, d.last_collected_at,
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
     WHERE d.active = true
     ORDER BY d.name ASC`
  );
  return result.rows;
}

async function getLastFeedSync(dbPool) {
  const result = await dbPool.query('SELECT * FROM feed_sync_log ORDER BY started_at DESC LIMIT 1');
  return result.rows[0] || null;
}

function formatDateTime(value) {
  if (!value) return null;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function syncBadgeColor(status) {
  if (status === 'success') return 'success';
  if (status === 'error') return 'danger';
  return 'warning';
}

export default async function DashboardPage() {
  const [summary, deviceCount, devices, lastSync] = await Promise.all([
    getFleetSummary(pool),
    getDeviceCount(pool),
    getDevices(pool),
    getLastFeedSync(pool),
  ]);

  const lastSyncTime = lastSync ? formatDateTime(lastSync.finished_at || lastSync.started_at) : null;

  return (
    <div className="space-y-6">
      <meta httpEquiv="refresh" content="60" />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">Devices</div>
          <div className="mt-1 text-2xl font-semibold text-text-primary">{deviceCount}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">Patch Now</div>
          <div className="mt-1 text-2xl font-semibold text-danger">{summary.patch_now_count}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">Scheduled</div>
          <div className="mt-1 text-2xl font-semibold text-warning">{summary.scheduled_count}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">Monitor</div>
          <div className="mt-1 text-2xl font-semibold text-text-muted">{summary.monitor_count}</div>
        </div>
      </div>

      <div>
        <div className="mb-3 flex items-center justify-between">
          <h1 className="text-lg font-semibold text-text-primary">Devices</h1>
          <Link href="/devices" className="text-sm text-accent hover:underline">
            View all →
          </Link>
        </div>
        {devices.length === 0 ? (
          <EmptyState message="No devices yet. Add one from the Devices page." />
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {devices.map((device) => (
              <DeviceCard key={device.id} device={device} />
            ))}
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2 rounded border border-border bg-bg-surface px-4 py-3 text-sm text-text-secondary">
        {lastSync ? (
          <>
            <span>Last feed sync:</span>
            <Badge color={syncBadgeColor(lastSync.status)}>{lastSync.status}</Badge>
            <span>
              ({lastSync.feed_name}) — {lastSyncTime || 'unknown time'}
            </span>
          </>
        ) : (
          <span>Never synced yet.</span>
        )}
      </div>
    </div>
  );
}
