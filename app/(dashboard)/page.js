import { pool } from '../../lib/db';
import Badge from '../../components/ui/Badge';
import StatCard from '../../components/ui/StatCard';
import Card from '../../components/ui/Card';
import IconChip from '../../components/ui/IconChip';
import { IconDevices, IconAlertTriangle, IconClock, IconActivity, IconShield, IconTrendingUp } from '../../components/icons';
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
  const [summary, deviceCount, lastSync] = await Promise.all([
    getFleetSummary(pool),
    getDeviceCount(pool),
    getLastFeedSync(pool),
  ]);

  const lastSyncTime = lastSync ? formatDateTime(lastSync.finished_at || lastSync.started_at) : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <AutoRefresh intervalMs={60000} />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 10 }}>
        <StatCard
          label="Devices"
          value={deviceCount}
          compact
          icon={IconDevices}
          iconColor="#60a5fa"
          iconBg="rgba(96,165,250,0.20)"
        />
        <StatCard
          label="Patch Now"
          value={summary.patch_now_count}
          color={summary.patch_now_count > 0 ? 'var(--red)' : 'var(--text-muted)'}
          compact
          icon={IconAlertTriangle}
          iconColor="#f87171"
          iconBg="rgba(248,113,113,0.22)"
        />
        <StatCard
          label="Scheduled"
          value={summary.scheduled_count}
          color={summary.scheduled_count > 0 ? 'var(--yellow)' : 'var(--text-muted)'}
          compact
          icon={IconClock}
          iconColor="#fbbf24"
          iconBg="rgba(251,191,36,0.20)"
        />
        <StatCard
          label="Monitor"
          value={summary.monitor_count}
          color="var(--text-muted)"
          compact
          icon={IconActivity}
          iconColor="#9ca3af"
          iconBg="rgba(156,163,175,0.20)"
        />
      </div>

      <Card>
        <div className="card-header-compact">
          <div className="card-title-compact" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <IconChip icon={IconShield} color="#f87171" bg="rgba(248,113,113,0.22)" />
            CVE Severity (Fleet)
          </div>
        </div>
        <div className="card-body-compact">
          <CveSeveritySummary />
        </div>
      </Card>

      <div className="dashboard-widget-grid">
        <RulesetOverview />
        <ComplianceScoreWidget />
        <RiskByCategory />
        <Card>
          <div className="card-header-compact">
            <div className="card-title-compact" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <IconChip icon={IconDevices} color="#60a5fa" bg="rgba(96,165,250,0.20)" />
              Vendor Distribution
            </div>
          </div>
          <div className="card-body-compact">
            <VendorDistribution />
          </div>
        </Card>
        <Card>
          <div className="card-header-compact">
            <div className="card-title-compact" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <IconChip icon={IconTrendingUp} color="#f87171" bg="rgba(248,113,113,0.22)" />
              Top Risky Devices
            </div>
          </div>
          <div className="card-body-compact">
            <TopRiskyDevices />
          </div>
        </Card>
        <DeviceStatusSummary />
        <RecentCriticalAlerts />
        <ConfigChangesWidget />
      </div>

      <RecentActivityFeed />

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
