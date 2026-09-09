import StatCard from '../ui/StatCard';
import { CoverageNote } from '../ui/NotMeasured';
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

  // ⛔ COVERAGE FOR BOTH CVE TILES. Both are fleet SUMS over
  // device_cve_assessments, so a device with no completed assessment
  // contributes exactly 0 — the same as one assessed and found clean. The
  // colour was already honest (muted, never green at zero); the NUMBER still
  // could not say how much of the fleet it actually covers. computeTiles() now
  // supplies that as cveNotAssessed (no stamp AND no assessment rows, i.e. no
  // evidence of a run by either signal), with cveNoVersion naming the
  // definite subset the matcher skips outright.
  //
  // ⛔ Rendered as a CoverageNote UNDER the number, not as a tooltip: per
  // NotMeasured.js, a confident fleet figure over partial data is the most
  // dangerous thing this product can draw, and stating the gap belongs beside
  // the figure that depends on it. `covered` is derived by subtraction, never
  // from a second source that could disagree with the total.
  const cveNotAssessed = tiles.cveNotAssessed || 0;
  const cveCovered = tiles.total - cveNotAssessed;
  const cveNote =
    cveNotAssessed > 0 ? (
      <span
        title={
          tiles.cveNoVersion > 0
            ? `${tiles.cveNoVersion} of these have no firmware version collected, so CVE matching cannot begin for them. The rest have no completed assessment on record yet.`
            : 'These devices have no completed CVE assessment on record — no assessment run has been stamped and they hold no assessment rows.'
        }
      >
        <CoverageNote covered={cveCovered} total={tiles.total} />
      </span>
    ) : null;

  // ⛔ Same statement for drift, and it is NOT the same question as "no open
  // diffs". A config_diff is computed between two consecutive snapshots, so a
  // device holding fewer than two can never produce one no matter how much its
  // config changes. Its zero is arithmetic. Without this the tile read as a
  // fleet-wide all-clear that those devices never took part in.
  const driftNotComparable = tiles.driftNotComparable || 0;

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
      {/* ⛔ THE AMBIGUITY THAT USED TO BE RECORDED HERE IS NOW STATED ON THE
          TILE, not just in this comment. Both CVE tiles sum
          device_cve_assessments rows across the fleet, so a device with no
          completed assessment contributes 0 to both, exactly like a device
          assessed and found clean. The colour was already honest (muted, never
          green at zero); what was missing was any field on `tiles` able to say
          how much of the fleet the number covers. cveNotAssessed/cveNoVersion
          (computeTiles, lib/engines/deviceInventory.js) supply that, and
          cveNote renders it as a CoverageNote directly beneath the figure.
          ⛔ Both tiles carry the SAME note deliberately — an un-assessed device
          is missing from both sums, and stating it on only one would invite the
          reader to treat the other as complete. */}
      <StatCard
        compact
        label="Critical CVEs"
        value={tiles.criticalCves}
        sub={
          <>
            <span>
              Across {tiles.criticalCveDevices} device{tiles.criticalCveDevices === 1 ? '' : 's'}
            </span>
            {cveNote}
          </>
        }
        color={tiles.criticalCves > 0 ? 'var(--red)' : 'var(--text-muted)'}
        icon={IconShield}
        iconColor="var(--tint-danger-fg)"
        iconBg="var(--tint-danger)"
      />
      <StatCard
        compact
        label="Patch Now"
        value={tiles.patchNow}
        sub={
          <>
            <span>
              On {tiles.patchNowDevices} device{tiles.patchNowDevices === 1 ? '' : 's'}
            </span>
            {cveNote}
          </>
        }
        color={tiles.patchNow > 0 ? 'var(--red)' : 'var(--text-muted)'}
        icon={IconAlertTriangle}
        iconColor="var(--tint-danger-fg)"
        iconBg="var(--tint-danger)"
      />
      {/* ⛔ The fall-through colour is NOT unconditionally green, and that is
          not a style choice. computeTiles() derives all three counts from
          device_licenses rows, so a device with NO licence rows at all — every
          Check Point, Cisco ASA, Sangfor, Forcepoint and Fortinet-over-API
          device, none of which collect licences — lands in none of them.
          Green + "All current" there reports an uncollected fact as an
          all-clear, the failed-read-as-a-fact bug. `supportNoData` (added to
          computeTiles for exactly this) is what separates the two: when it
          covers the whole fleet the tile goes --unmeasured and says so, and
          when it covers part of it the sub-line states the coverage instead of
          claiming health for devices nobody asked. */}
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
      {/* ⛔ Same class again, weaker but real, and now STATED rather than only
          noted: a device with fewer than two config snapshots can never produce
          a config_diff — diffing needs a predecessor — so it contributes 0
          drift for a reason that has nothing to do with its stability. The
          per-device card (OverviewConfigChangesCard) already said this because
          it could count snapshots; getDeviceRows() now projects
          config_snapshot_count so computeTiles can too (driftNotComparable).
          The colour stays honest (muted at zero, never green) and goes
          --unmeasured when NO device in view could have produced a diff, since
          at that point the tile is measuring nothing at all. */}
      <StatCard
        compact
        label="Config Drift"
        value={tiles.driftDevices}
        sub={
          driftNotComparable >= tiles.total && tiles.total > 0
            ? 'No device has two config snapshots to compare'
            : driftNotComparable > 0
              ? `Unacknowledged changes — ${driftNotComparable} of ${tiles.total} cannot be compared`
              : 'Unacknowledged changes'
        }
        color={
          tiles.driftDevices > 0
            ? 'var(--yellow)'
            : driftNotComparable >= tiles.total && tiles.total > 0
              ? 'var(--unmeasured)'
              : 'var(--text-muted)'
        }
        icon={IconTrendingUp}
        iconColor="var(--tint-warn-fg)"
        iconBg="var(--tint-warn)"
      />
    </div>
  );
}
