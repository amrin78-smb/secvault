import Link from 'next/link';
import { pool } from '../../lib/db';
import DeviceCard from '../../components/devices/DeviceCard';
import Badge from '../../components/ui/Badge';
import EmptyState from '../../components/ui/EmptyState';
import StatCard from '../../components/ui/StatCard';
import Card, { CardHeader, CardTitle, CardBody } from '../../components/ui/Card';
import AutoRefresh from '../../components/dashboard/AutoRefresh';
import CveSeveritySummary from '../../components/dashboard/CveSeveritySummary';
import TopRiskyDevices from '../../components/dashboard/TopRiskyDevices';
import VendorDistribution from '../../components/dashboard/VendorDistribution';
import RulesetOverview from '../../components/dashboard/RulesetOverview';
import ComplianceScoreWidget from '../../components/dashboard/ComplianceScoreWidget';
import RiskByCategory from '../../components/dashboard/RiskByCategory';
import DeviceStatusSummary from '../../components/dashboard/DeviceStatusSummary';
import RecentCriticalAlerts from '../../components/dashboard/RecentCriticalAlerts';
import RecentActivityFeed from '../../components/dashboard/RecentActivityFeed';
import ConfigChangesWidget from '../../components/dashboard/ConfigChangesWidget';

export const dynamic = 'force-dynamic';

// Two-column responsive row used to pair widgets that are naturally
// half-width on a wide screen and stack to one column on a narrow one —
// matches the grid convention every individual widget already uses
// internally (see e.g. RulesetOverview.js's tile grid).
const twoColGrid = { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 16 };

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
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <AutoRefresh intervalMs={60000} />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16 }}>
        <StatCard label="Devices" value={deviceCount} />
        <StatCard label="Patch Now" value={summary.patch_now_count} color="var(--red)" />
        <StatCard label="Scheduled" value={summary.scheduled_count} color="var(--yellow)" />
        <StatCard label="Monitor" value={summary.monitor_count} color="var(--text-muted)" />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>CVE Severity (Fleet)</CardTitle>
        </CardHeader>
        <CardBody>
          <CveSeveritySummary />
        </CardBody>
      </Card>

      <div style={twoColGrid}>
        <RulesetOverview />
        <ComplianceScoreWidget />
      </div>

      <div style={twoColGrid}>
        <RiskByCategory />
        <Card>
          <CardHeader>
            <CardTitle>Vendor Distribution</CardTitle>
          </CardHeader>
          <CardBody>
            <VendorDistribution />
          </CardBody>
        </Card>
      </div>

      <div style={twoColGrid}>
        <Card>
          <CardHeader>
            <CardTitle>Top Risky Devices</CardTitle>
          </CardHeader>
          <CardBody>
            <TopRiskyDevices />
          </CardBody>
        </Card>
        <DeviceStatusSummary />
      </div>

      <div style={twoColGrid}>
        <RecentCriticalAlerts />
        <ConfigChangesWidget />
      </div>

      <RecentActivityFeed />

      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <h1 style={{ fontSize: 'var(--text-lg)', fontWeight: 600 }}>Devices</h1>
          <Link href="/devices" style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
            View all →
          </Link>
        </div>
        {devices.length === 0 ? (
          <EmptyState message="No devices yet. Add one from the Devices page." />
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 16 }}>
            {devices.map((device) => (
              <DeviceCard key={device.id} device={device} />
            ))}
          </div>
        )}
      </div>

      <div
        className="card"
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          gap: 8,
          padding: '12px 16px',
          fontSize: 'var(--text-base)',
          color: 'var(--text-secondary)',
        }}
      >
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
