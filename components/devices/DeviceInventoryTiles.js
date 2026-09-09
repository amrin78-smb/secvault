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
          : // ⛔ "All current" is only sayable if we actually collected a
            // licence from every device. On this fleet most vendors report
            // none at all (only Palo Alto and Fortinet-over-SSH do), so the
            // old unconditional "All current" was an all-clear for a question
            // never asked. supportNoData is the count of devices SecVault
            // cannot answer for; when it covers the whole fleet the tile says
            // so rather than implying health.
            tiles.supportNoData >= tiles.total && tiles.total > 0
            ? 'Not collected for any device'
            : tiles.supportNoData > 0
              ? `All current — ${tiles.supportNoData} of ${tiles.total} not collected`
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
        iconColor="var(--tint-teal-fg)"
        iconBg="var(--tint-teal)"
      />
      <StatCard
        compact
        label="Online"
        value={tiles.online}
        sub={reachSub}
        color={tiles.online === tiles.total ? 'var(--green)' : 'var(--red)'}
        icon={IconActivity}
        iconColor="var(--tint-success-fg)"
        iconBg="var(--tint-success)"
      />
      <StatCard
        compact
        label="Critical CVEs"
        value={tiles.criticalCves}
        sub={`Across ${tiles.criticalCveDevices} device${tiles.criticalCveDevices === 1 ? '' : 's'}`}
        color={tiles.criticalCves > 0 ? 'var(--red)' : 'var(--text-muted)'}
        icon={IconShield}
        iconColor="var(--tint-danger-fg)"
        iconBg="var(--tint-danger)"
      />
      <StatCard
        compact
        label="Patch Now"
        value={tiles.patchNow}
        sub={`On ${tiles.patchNowDevices} device${tiles.patchNowDevices === 1 ? '' : 's'}`}
        color={tiles.patchNow > 0 ? 'var(--red)' : 'var(--text-muted)'}
        icon={IconAlertTriangle}
        iconColor="var(--tint-danger-fg)"
        iconBg="var(--tint-danger)"
      />
      {/* ⛔ The fall-through colour is NOT green, and that is not a style
          choice. computeTiles() derives all three counts from device_licenses
          rows, so a device with NO licence rows at all — every Check Point,
          Cisco ASA, Sangfor, Forcepoint and Fortinet-over-API device, none of
          which collect licences — lands in none of them. Green + "All current"
          there reports an uncollected fact as an all-clear, the
          failed-read-as-a-fact bug. --unmeasured until computeTiles() can
          report "no licence data" separately from "all current". */}
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
              : // Nothing lapsed and nothing expiring. That is only GOOD NEWS
                // if we collected something; otherwise it is silence.
                tiles.supportNoData >= tiles.total && tiles.total > 0
                ? 'var(--unmeasured)'
                : 'var(--green)'
        }
        icon={IconClock}
        iconColor="var(--tint-warn-fg)"
        iconBg="var(--tint-warn)"
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
        iconColor="var(--tint-danger-fg)"
        iconBg="var(--tint-danger)"
      />
      <StatCard
        compact
        label="Config Drift"
        value={tiles.driftDevices}
        sub="Unacknowledged changes"
        color={tiles.driftDevices > 0 ? 'var(--yellow)' : 'var(--text-muted)'}
        icon={IconTrendingUp}
        iconColor="var(--tint-warn-fg)"
        iconBg="var(--tint-warn)"
      />
    </div>
  );
}
