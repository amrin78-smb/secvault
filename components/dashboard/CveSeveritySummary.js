import { pool } from '../../lib/db';
import StatCard from '../ui/StatCard';
import EmptyState from '../ui/EmptyState';

// Dashboard widget: CURRENT (live) fleet-wide CVE severity counts, plus an
// optional "vs yesterday" delta per band read from fleet_dashboard_snapshots.
// The main number is deliberately LIVE, not the snapshot table -- the
// snapshot table exists for the day-over-day TREND/delta computed here, see
// lib/engines/dashboardSnapshot.js's own header comment. Async server
// component -- no 'use client', no chart, just StatCard tiles.
//
// The live-count query mirrors lib/engines/dashboardSnapshot.js's
// computeFleetCveSeverity() exactly (bucket device_cve_assessments joined to
// advisories.cvss_score, active devices only, NULL/unparseable scores
// excluded from every bucket -- never guessed into 'low', same
// tri-state-honesty discipline as CLAUDE.md's Applicability Tri-State
// Default). Duplicated here rather than imported: that file is CommonJS
// (required by services/engine-worker.js under plain node), this is an ESM
// server component -- matches this app's established per-file-duplication
// convention (see e.g. the Alerts/events query split documented in
// CLAUDE.md).
export default async function CveSeveritySummary() {
  const [live, snapshots] = await Promise.all([getLiveSeverityCounts(pool), getRecentSnapshots(pool)]);

  const total = live.critical + live.high + live.medium + live.low;

  if (total === 0) {
    return <EmptyState message="No scored CVE assessments on active devices yet." />;
  }

  const comparison = pickComparisonSnapshot(snapshots);
  const comparisonGapDays = comparison ? daysAgo(comparison.snapshot_date) : null;
  const snapshotKey = { critical: 'cve_critical', high: 'cve_high', medium: 'cve_medium', low: 'cve_low' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 8 }}>
        {SEVERITY.map(({ key, label, color }) => {
          const sub = comparison
            ? deltaLabel(live[key] - Number(comparison[snapshotKey[key]] ?? 0), comparisonGapDays)
            : undefined;
          const tileColor = live[key] > 0 ? color : 'var(--text-muted)';
          return <StatCard key={key} label={label} value={live[key]} color={tileColor} sub={sub} compact />;
        })}
      </div>
      <div style={{ fontSize: 10, color: 'var(--text-secondary)' }}>
        {total} scored CVE assessment{total === 1 ? '' : 's'} across active devices.
      </div>
    </div>
  );
}

const SEVERITY = [
  { key: 'critical', label: 'Critical', color: 'var(--red)' },
  { key: 'high', label: 'High', color: 'var(--orange)' },
  { key: 'medium', label: 'Medium', color: 'var(--yellow)' },
  { key: 'low', label: 'Low', color: 'var(--blue)' },
];

async function getLiveSeverityCounts(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT a.cvss_score
     FROM device_cve_assessments dca
     JOIN advisories a ON a.id = dca.advisory_id
     JOIN devices d ON d.id = dca.device_id
     WHERE d.active = true`
  );
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const row of rows) {
    const score = row.cvss_score === null || row.cvss_score === undefined ? null : Number(row.cvss_score);
    if (score === null || Number.isNaN(score)) continue; // never guess an unscored CVE into 'low'
    if (score >= 9) counts.critical += 1;
    else if (score >= 7) counts.high += 1;
    else if (score >= 4) counts.medium += 1;
    else counts.low += 1;
  }
  return counts;
}

async function getRecentSnapshots(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT snapshot_date, cve_critical, cve_high, cve_medium, cve_low
     FROM fleet_dashboard_snapshots
     ORDER BY snapshot_date DESC
     LIMIT 2`
  );
  return rows;
}

function daysAgo(dateValue) {
  const d = new Date(dateValue);
  if (Number.isNaN(d.getTime())) return Infinity;
  const today = new Date();
  const utcDate = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  const utcToday = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate());
  return Math.round((utcToday - utcDate) / 86400000);
}

// Picks which snapshot row to diff the live count against. If the most
// recent snapshot is TODAY's (the daily job already ran today), "yesterday"
// is the second row; otherwise the most recent row itself is the last day
// the job ran. Returns null (no delta rendered) when fewer than 2 snapshot
// rows exist yet (fresh install -- a normal state, not an error) or the
// most recent snapshot is more than 2 days old (stale -- comparing against
// it would be misleading, not informative).
function pickComparisonSnapshot(snapshots) {
  if (!Array.isArray(snapshots) || snapshots.length < 2) return null;
  const [mostRecent, secondMostRecent] = snapshots;
  if (daysAgo(mostRecent.snapshot_date) > 2) return null;
  return daysAgo(mostRecent.snapshot_date) === 0 ? secondMostRecent : mostRecent;
}

// gapDays is how old the COMPARISON snapshot actually is (daysAgo() of the
// row pickComparisonSnapshot() chose), not assumed to be 1. Found
// 2026-07-18: if the daily snapshot job is ever down for a stretch (e.g.
// 10 days) and then resumes, pickComparisonSnapshot() can legitimately pick
// a comparison row that's several days old -- the label must say so rather
// than always claiming "since yesterday", which would misrepresent a
// multi-day delta as a single day's change.
function deltaLabel(delta, gapDays) {
  const suffix = gapDays === 1 ? 'since yesterday' : `vs ${gapDays}d ago`;
  if (delta > 0) return `+${delta} ${suffix}`;
  if (delta < 0) return `${delta} ${suffix}`;
  return `No change ${suffix}`;
}
