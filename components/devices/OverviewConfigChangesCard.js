import Link from 'next/link';
import { describeConfigChange } from '../../lib/configChangeSummary';
import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import { classifyDiff } from '../../lib/engines/configDiff';

// Per-device Overview tab card: config-change summary over the trailing
// `days` window for ONE device. Near-exact analog of
// components/dashboard/ConfigChangesWidget.js (the fleet-wide version of
// this same card) -- see that file's own header comment for why the
// Added/Removed/Modified breakdown is real data (config_diffs.diff is a
// structured jsonb object, read via jsonb_array_length()), not a fabricated
// split. Two real differences from the fleet widget, both grounded in data
// this app already has (lib/schema.sql's config_diffs table):
//   1. Scoped to one already-resolved device_id -- no `d.active = true`
//      join needed, unlike the fleet-wide widget which spans every device.
//   2. Each row also shows a real Acknowledged/Unacknowledged badge, from
//      config_diffs.acknowledged_at, alongside a DERIVED High/Medium/Low
//      Impact badge -- see impactForDiff() below for why the latter is
//      computed, not stored.
//
// `days` is passed as a numeric bound parameter, never string-concatenated
// into the query, per CLAUDE.md's "always parameterized queries" rule.

async function getConfigChanges(dbPool, deviceId, days) {
  const { rows } = await dbPool.query(
    `SELECT cd.id, cd.diff, cd.change_summary, cd.detected_at, cd.acknowledged_at, cd.acknowledged_by,
            COALESCE(jsonb_array_length(cd.diff->'added'), 0) AS added_count,
            COALESCE(jsonb_array_length(cd.diff->'removed'), 0) AS removed_count,
            COALESCE(jsonb_array_length(cd.diff->'modified'), 0) AS modified_count
     FROM config_diffs cd
     WHERE cd.device_id = $1
       AND cd.detected_at > now() - ($2::int * interval '1 day')
     ORDER BY cd.detected_at DESC`,
    [deviceId, days]
  );
  return rows;
}

// ⛔ "No configuration changes" IS A CLAIM ABOUT STABILITY, and it is only
// sayable if SecVault has actually been comparing configurations. config_diffs
// rows are written by collectAndStore when a pull produces a config that
// DIFFERS from the previous snapshot — so a device that has never been
// collected, or has exactly one snapshot, has zero diffs for a reason that has
// nothing to do with the firewall being stable. Rendered as "No configuration
// changes in the last 7 days" that is a failed read reported as a reassuring
// fact, the same shape as the Support tile's old green "All current".
//
// Two OBSERVATIONS is the real threshold: change detection needs a predecessor
// to compare against, so a single collection can never produce a diff.
//
// ⛔ SUM(observation_count), not COUNT(*). Since write-time dedupe (v2.92.0)
// an unchanged pull UPDATEs the surviving row rather than inserting, so a ROW
// is a distinct CONFIGURATION and no longer a COLLECTION. Counting rows would
// tell an operator that a device collected 60 times has nothing to compare
// against — reporting our own storage efficiency as a coverage gap, which is
// the failed-read-as-a-fact rule wearing a new hat.
//
// coalesce because a pre-dedupe row can hold NULL until the backfill runs;
// one observation each is exactly what those rows were.
async function getConfigCoverage(dbPool, deviceId) {
  const { rows } = await dbPool.query(
    `SELECT COALESCE(SUM(COALESCE(observation_count, 1)), 0)::int AS snapshot_count
       FROM device_configs WHERE device_id = $1`,
    [deviceId]
  );
  return rows[0] || { snapshot_count: 0 };
}

// Section labels that classifyDiff() (lib/engines/configDiff.js) can produce
// which represent an actual rulebase/policy change -- always High regardless
// of ruleChanges, since a device where individual rule names can't be
// resolved (e.g. Palo Alto XML/API's array-indexed rulebase -- see that
// file's own RULE_PATH_MARKER/classifyPath() comments) still lands here via
// the generic section bucket rather than the rule table.
const HIGH_IMPACT_LABELS = new Set([
  'Security Rules',
  'Policy-Based Forwarding Rules',
]);

// NAT/VPN/admin/zone/interface/network/device-level config -- meaningful but
// not a live traffic-policy change.
const MEDIUM_IMPACT_LABELS = new Set([
  'NAT Rules',
  'VPN Configuration',
  'Admin Accounts',
  'Admin/Management Config',
  'Zones/Interfaces',
  'Network Configuration',
  'Device Configuration',
]);

// impactForDiff() is a DERIVED heuristic, computed fresh on every read from
// the same config_diffs.diff jsonb already persisted -- config_diffs has no
// impact/severity column of its own, and none is being added. The exact
// High/Medium/Low section mapping (rulebase/PBF = High; NAT/VPN/admin/zones/
// network/device config = Medium; objects/SNMP/NTP/DNS/logging/password
// policy/FortiGuard/system info/anything unrecognized = Low) was a
// deliberate product decision, not guessed or inferred from the data --
// reuses classifyDiff()'s already-verified section classification rather
// than re-parsing diff paths a second time. Any non-empty ruleChanges
// (an individually-resolved firewall rule add/remove/modify) is always High.
function impactForDiff(diff) {
  const { ruleChanges, sections } = classifyDiff(diff || {});
  if (ruleChanges.length > 0) return 'high';
  let worst = 'low';
  for (const s of sections) {
    if (HIGH_IMPACT_LABELS.has(s.label)) return 'high';
    if (MEDIUM_IMPACT_LABELS.has(s.label)) worst = 'medium';
  }
  return worst;
}

const IMPACT_BADGE = {
  high: { color: 'danger', label: 'High' },
  medium: { color: 'warning', label: 'Medium' },
  low: { color: 'muted', label: 'Low' },
};

function formatDateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

const RECENT_LIST_LIMIT = 5;

export default async function OverviewConfigChangesCard({ deviceId, days = 7 }) {
  const [rows, coverage] = await Promise.all([
    getConfigChanges(pool, deviceId, days),
    getConfigCoverage(pool, deviceId),
  ]);

  // Fewer than two snapshots -> change detection has never been able to run,
  // whatever the window says. See getConfigCoverage's note.
  const canDetectChanges = coverage.snapshot_count >= 2;

  const totalCount = rows.length;
  const totals = rows.reduce(
    (acc, r) => {
      acc.added += Number(r.added_count) || 0;
      acc.removed += Number(r.removed_count) || 0;
      acc.modified += Number(r.modified_count) || 0;
      return acc;
    },
    { added: 0, removed: 0, modified: 0 }
  );
  const recent = rows.slice(0, RECENT_LIST_LIMIT);
  const changesHref = `/devices/${deviceId}/changes`;

  return (
    <Card>
      <CardBody>
        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12 }}>
          Configuration Changes (Last {days} Days)
        </div>

        {totalCount === 0 ? (
          <EmptyState
            message={
              canDetectChanges
                ? `No configuration changes detected in the last ${days} days. SecVault holds ${coverage.snapshot_count} configuration snapshots for this device, so this is a real comparison, not a gap.`
                : coverage.snapshot_count === 0
                  ? 'No configuration has ever been collected from this device, so change detection has nothing to compare. This is NOT a statement that the configuration is unchanged — run Collect Now on the Manage tab.'
                  : 'Only one configuration snapshot has been collected from this device. A change is a difference between two snapshots, so nothing can be detected until the next successful pull — this is NOT a statement that the configuration is unchanged.'
            }
          />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
              <div>
                <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {totalCount}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                  Change{totalCount === 1 ? '' : 's'}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end', fontSize: 'var(--text-xs)' }}>
                <span style={{ color: 'var(--green)', fontWeight: 600 }}>{totals.added} added</span>
                <span style={{ color: 'var(--red)', fontWeight: 600 }}>{totals.removed} removed</span>
                <span style={{ color: 'var(--yellow)', fontWeight: 600 }}>{totals.modified} modified</span>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {recent.map((r) => {
                const impact = IMPACT_BADGE[impactForDiff(r.diff)];
                return (
                <Link
                  key={r.id}
                  href={changesHref}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 4,
                    // On the spacing scale (was an off-scale 8px/10px pair).
                    padding: 'var(--s2) var(--s3)',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border)',
                    color: 'inherit',
                    textDecoration: 'none',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                      {formatDateTime(r.detected_at)}
                    </span>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      <Badge color={impact.color}>{impact.label}</Badge>
                      {r.acknowledged_at ? (
                        <Badge color="success">Acknowledged</Badge>
                      ) : (
                        <Badge color="muted">Unacknowledged</Badge>
                      )}
                    </div>
                  </div>
                  <span
                    style={{
                      fontSize: 'var(--text-xs)',
                      color: 'var(--text-secondary)',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                    title={r.change_summary || 'Config changed'}
                  >
                    {describeConfigChange(r.diff, r.change_summary) || 'Config changed'}
                  </span>
                </Link>
                );
              })}
            </div>
          </div>
        )}

        <div style={{ marginTop: 12 }}>
          <Link href={changesHref} style={{ fontSize: 'var(--text-base)', color: 'var(--primary)', textDecoration: 'underline' }}>
            View all changes →
          </Link>
        </div>
      </CardBody>
    </Card>
  );
}
