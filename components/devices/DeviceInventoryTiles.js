import StatCard from '../ui/StatCard';
import {
  IconDevices,
  IconActivity,
  IconShield,
  IconAlertTriangle,
  IconClock,
  IconTrendingUp,
  IconRefresh,
} from '../icons';

// Fleet tiles above the Devices table. Every figure counts the rows actually
// rendered below, so the tiles and the table can never disagree.
//
// ⛔ The mockup this came from had an "Unsupported OS — 2 EOL/EOS devices" tile.
// SecVault collects NO vendor OS end-of-life dates and no feed supplies them,
// so that number cannot be produced and the tile is deliberately absent. What
// replaces it is support-CONTRACT expiry, which is a different and REAL fact
// (device_licenses, already collected for the Lifecycle page).
export default function DeviceInventoryTiles({ tiles }) {
  const reachSub =
    tiles.neverChecked > 0
      ? `${tiles.neverChecked} never checked`
      : tiles.total > 0
        ? `${Math.round((tiles.online / tiles.total) * 100)}% reachable`
        : '—';

  // Expired and expiring are different actions (renew now vs. plan a renewal),
  // so they are never merged into one count.
  const supportSub =
    tiles.supportExpired > 0
      ? `${tiles.supportExpired} with a lapsed licence`
      : tiles.supportExpiring > 0
        ? `${tiles.supportExpiring} expiring within 90d`
        : tiles.supportUnknown > 0
          ? `${tiles.supportUnknown} with unreadable dates`
          : 'All current';

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10 }}>
      <StatCard
        compact
        label="Total Firewalls"
        value={tiles.total}
        sub="Active devices"
        color="var(--accent-teal)"
        icon={IconDevices}
        iconColor="#60a5fa"
        iconBg="rgba(96,165,250,0.20)"
      />
      <StatCard
        compact
        label="Online"
        value={tiles.online}
        sub={reachSub}
        color={tiles.online === tiles.total ? 'var(--green)' : 'var(--red)'}
        icon={IconActivity}
        iconColor="#4ade80"
        iconBg="rgba(74,222,128,0.20)"
      />
      <StatCard
        compact
        label="Critical CVEs"
        value={tiles.criticalCves}
        sub={`Across ${tiles.criticalCveDevices} device${tiles.criticalCveDevices === 1 ? '' : 's'}`}
        color={tiles.criticalCves > 0 ? 'var(--red)' : 'var(--text-muted)'}
        icon={IconShield}
        iconColor="#f87171"
        iconBg="rgba(248,113,113,0.22)"
      />
      <StatCard
        compact
        label="Patch Now"
        value={tiles.patchNow}
        sub={`On ${tiles.patchNowDevices} device${tiles.patchNowDevices === 1 ? '' : 's'}`}
        color={tiles.patchNow > 0 ? 'var(--red)' : 'var(--text-muted)'}
        icon={IconAlertTriangle}
        iconColor="#f87171"
        iconBg="rgba(248,113,113,0.22)"
      />
      <StatCard
        compact
        label="Support Expiry"
        value={tiles.supportExpired || tiles.supportExpiring || tiles.supportUnknown || 0}
        sub={supportSub}
        color={
          tiles.supportExpired > 0
            ? 'var(--red)'
            : tiles.supportExpiring > 0 || tiles.supportUnknown > 0
              ? 'var(--yellow)'
              : 'var(--green)'
        }
        icon={IconClock}
        iconColor="#fbbf24"
        iconBg="rgba(251,191,36,0.20)"
      />
      {/* ⛔ Counts failing/degraded collectors. This is the tile that would
          have surfaced TSR_EKC — unreachable since 2026-08-06, every poll
          failing, visible only in engine.log. "Not observed" is reported
          separately: never having been polled is not the same as passing. */}
      <StatCard
        compact
        label="Collector Health"
        value={tiles.pollDegraded}
        sub={
          tiles.pollDegraded > 0
            ? 'Devices failing their polls'
            : tiles.pollUnknown > 0
              ? `${tiles.pollUnknown} not yet observed`
              : 'All devices polling'
        }
        color={tiles.pollDegraded > 0 ? 'var(--red)' : tiles.pollUnknown > 0 ? 'var(--yellow)' : 'var(--green)'}
        icon={IconRefresh}
        iconColor="#f87171"
        iconBg="rgba(248,113,113,0.22)"
      />
      <StatCard
        compact
        label="Config Drift"
        value={tiles.driftDevices}
        sub="Unacknowledged changes"
        color={tiles.driftDevices > 0 ? 'var(--yellow)' : 'var(--text-muted)'}
        icon={IconTrendingUp}
        iconColor="#fbbf24"
        iconBg="rgba(251,191,36,0.20)"
      />
    </div>
  );
}
