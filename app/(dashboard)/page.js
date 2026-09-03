import { pool } from '../../lib/db';
import Badge from '../../components/ui/Badge';
import Card from '../../components/ui/Card';
import IconChip from '../../components/ui/IconChip';
import TabBar from '../../components/ui/TabBar';
import { IconDevices, IconShield, IconTrendingUp } from '../../components/icons';
import { DASHBOARD_TABS, resolveDashboardTab } from '../../lib/dashboardTabs';
import AutoRefresh from '../../components/dashboard/AutoRefresh';
import CveSeveritySummary from '../../components/dashboard/CveSeveritySummary';
import TopRiskyDevices from '../../components/dashboard/TopRiskyDevices';
import VendorDistribution from '../../components/dashboard/VendorDistribution';
import RulesetOverview from '../../components/dashboard/RulesetOverview';
import ComplianceScoreWidget from '../../components/dashboard/ComplianceScoreWidget';
import ComplianceStandardsBreakdown from '../../components/dashboard/ComplianceStandardsBreakdown';
import RiskByCategory from '../../components/dashboard/RiskByCategory';
import DeviceStatusSummary from '../../components/dashboard/DeviceStatusSummary';
import RecentCriticalAlerts from '../../components/dashboard/RecentCriticalAlerts';
import RecentActivityFeed from '../../components/dashboard/RecentActivityFeed';
import ConfigChangesWidget from '../../components/dashboard/ConfigChangesWidget';
import HeadlineStats from '../../components/dashboard/HeadlineStats';
import QuickActions from '../../components/dashboard/QuickActions';
import FleetSystemHealth from '../../components/dashboard/FleetSystemHealth';
import LicenceExpiryWidget from '../../components/dashboard/LicenceExpiryWidget';
import VulnerabilityTrends from '../../components/dashboard/VulnerabilityTrends';

export const dynamic = 'force-dynamic';

// ── Tabbed dashboard (v2.66.0) ────────────────────────────────────────────
//
// Twelve widgets in one grid had stopped being a dashboard and become a wall.
// Tabs split it by domain WITHOUT hiding fleet posture: HeadlineStats and the
// feed-sync footer sit OUTSIDE the tabs, so the numbers you must never miss
// are on screen whichever tab is open.
//
// ⛔ Tab state lives in the URL (`?tab=`), not React state, and that is
// load-bearing rather than stylistic:
//   - AutoRefresh calls router.refresh() every 60s. A useState tab would be
//     preserved, but a full reload (or an F5, or following a link back) would
//     snap the user to Overview. A URL survives all three.
//   - It makes a tab linkable — "look at /?tab=fleet" in a ticket.
//   - Every other tabbed page in this app already works this way
//     (/vulnerability, /compliance, /topology, /devices/[id]/analysis).
//
// A widget appearing on more than one tab is deliberate, not duplication to be
// factored out. Overview's job is "what needs attention now" across every
// domain; Security's job is depth. Both legitimately want CVE severity. Each
// widget is a self-contained Server Component that runs its own query, so the
// only cost of showing one twice is the tab you are NOT looking at — which is
// never rendered at all.
//
// ⛔ Only the ACTIVE tab's widgets are rendered, so switching tabs runs only
// that tab's queries. This is what makes the split a performance win as well
// as a clarity one: the old page ran all twelve widgets' queries on every
// single 60-second refresh.
//
// ── ADDING A WIDGET ──
// Render it in the relevant case below. ── ADDING A TAB ── add an entry to
// DASHBOARD_TABS in lib/dashboardTabs.js and a case here; the tab bar, the URL
// whitelist and the default all derive from that array. See that file for the
// Live Traffic tab that is deliberately absent until the Phase 8 syslog
// collector exists.

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

// Module top level, never nested in the page component — CLAUDE.md's React
// rule (a component defined inside a component remounts on every render).
function WidgetCard({ icon, color, bg, title, children }) {
  return (
    <Card>
      <div className="card-header-compact">
        <div className="card-title-compact" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={icon} color={color} bg={bg} />
          {title}
        </div>
      </div>
      <div className="card-body-compact">{children}</div>
    </Card>
  );
}

function CveSeverityCard() {
  return (
    <WidgetCard icon={IconShield} color="#f87171" bg="rgba(248,113,113,0.22)" title="CVE Severity (Fleet)">
      <CveSeveritySummary />
    </WidgetCard>
  );
}

function TopRiskyCard() {
  return (
    <WidgetCard
      icon={IconTrendingUp}
      color="#f87171"
      bg="rgba(248,113,113,0.22)"
      title="Top Risky Devices"
    >
      <TopRiskyDevices />
    </WidgetCard>
  );
}

function VendorCard() {
  return (
    <WidgetCard icon={IconDevices} color="#60a5fa" bg="rgba(96,165,250,0.20)" title="Vendor Distribution">
      <VendorDistribution />
    </WidgetCard>
  );
}

export default async function DashboardPage({ searchParams }) {
  const tab = resolveDashboardTab(searchParams?.tab);
  const lastSync = await getLastFeedSync(pool);
  const lastSyncTime = lastSync ? formatDateTime(lastSync.finished_at || lastSync.started_at) : null;

  const tabs = DASHBOARD_TABS.map((t) => ({
    key: t.key,
    label: t.label,
    // Overview is the default, so it gets the bare path — a canonical URL for
    // the landing page rather than two spellings of the same view.
    href: t.key === 'overview' ? '/' : `/?tab=${t.key}`,
  }));
  const activeHref = tab === 'overview' ? '/' : `/?tab=${tab}`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <AutoRefresh intervalMs={60000} />

      {/* Outside the tabs on purpose — fleet posture is never a tab away. */}
      <HeadlineStats />

      <TabBar tabs={tabs} activeHref={activeHref} ariaLabel="Dashboard sections" />

      {tab === 'overview' && (
        <div className="dashboard-widget-grid">
          <CveSeverityCard />
          <ComplianceScoreWidget />
          <RulesetOverview />
          <TopRiskyCard />
          <RecentCriticalAlerts />
          <QuickActions />
        </div>
      )}

      {tab === 'security' && (
        <div className="dashboard-widget-grid">
          <CveSeverityCard />
          <VulnerabilityTrends />
          <TopRiskyCard />
          <RecentCriticalAlerts />
          <RiskByCategory />
        </div>
      )}

      {tab === 'rules' && (
        <div className="dashboard-widget-grid">
          <RulesetOverview />
          <RiskByCategory />
          <TopRiskyCard />
        </div>
      )}

      {tab === 'compliance' && (
        <div className="dashboard-widget-grid">
          <ComplianceScoreWidget />
          <ComplianceStandardsBreakdown />
        </div>
      )}

      {tab === 'fleet' && (
        <>
          <div className="dashboard-widget-grid">
            <DeviceStatusSummary />
            <VendorCard />
            <FleetSystemHealth />
            <LicenceExpiryWidget />
            <ConfigChangesWidget />
          </div>
          {/* Full-width, so outside the grid. */}
          <RecentActivityFeed />
        </>
      )}

      {/* Outside the tabs: feed freshness qualifies every CVE number on every
          tab, so hiding it behind one of them would be misleading. */}
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
