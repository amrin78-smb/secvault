import Link from 'next/link';
import { pool } from '../../lib/db';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import IconChip from '../ui/IconChip';
import { IconSearch } from '../icons';
import StandardDonut from '../compliance/StandardDonut';
import { STANDARDS, scoreColor } from '../compliance/ComplianceMatrix';

// Same scorePct formula used everywhere else in this app (pass / (pass+fail+
// warning) as a %, excluding 'na' from the denominator, null -- never 0 --
// when nothing is measurable) -- mirrors app/(dashboard)/compliance/page.js's
// scorePctFromCounts() and lib/engines/dashboardSnapshot.js's
// computeFleetComplianceScores() exactly. Kept as a small local copy per this
// codebase's established per-file-duplication convention for this exact
// formula (see CLAUDE.md's Compliance Engine section).
function scorePctFromCounts(counts) {
  const measurable = counts.pass + counts.fail + counts.warning;
  return measurable > 0 ? Math.round((counts.pass / measurable) * 100) : null;
}

async function getLatestSnapshot(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT snapshot_date, compliance_overall_score, compliance_by_standard
     FROM fleet_dashboard_snapshots
     ORDER BY snapshot_date DESC
     LIMIT 1`
  );
  return rows[0] || null;
}

// Mirrors CveSeveritySummary.js's own daysAgo()/staleness convention exactly
// (>2 days is stale) -- see this file's own header comment on why the
// snapshot can go stale indefinitely (the daily engine-worker job only
// logs-and-skips on failure, with no retry until the next day's cron tick).
function daysAgo(dateValue) {
  const d = new Date(dateValue);
  if (Number.isNaN(d.getTime())) return Infinity;
  const today = new Date();
  const utcDate = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  const utcToday = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate());
  return Math.round((utcToday - utcDate) / 86400000);
}

// Live fallback for when the daily snapshot job hasn't run yet (a normal
// state on a fresh install / day one, not an error) -- computed directly
// from audit_findings/audit_checks/devices, fleet-wide, active devices only.
// Deliberately mirrors lib/engines/dashboardSnapshot.js's
// computeFleetComplianceScores() query/shape exactly (read before writing
// this) rather than diverging, so the "live" number and the "snapshotted"
// number are always computed the same way and never disagree except by
// timing.
async function computeLiveFleetCompliance(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT af.status, ac.standards
     FROM audit_findings af
     JOIN audit_checks ac ON ac.id = af.check_id
     JOIN devices d ON d.id = af.device_id
     WHERE d.active = true`
  );

  const counts = {};
  for (const s of STANDARDS) counts[s.key] = { pass: 0, fail: 0, warning: 0 };

  for (const row of rows) {
    if (row.status !== 'pass' && row.status !== 'fail' && row.status !== 'warning') continue; // 'na' excluded
    const list = Array.isArray(row.standards) ? row.standards : [];
    for (const key of list) {
      if (!counts[key]) continue;
      counts[key][row.status] += 1;
    }
  }

  const byStandard = {};
  let totalPass = 0;
  let totalMeasurable = 0;
  for (const s of STANDARDS) {
    const c = counts[s.key];
    byStandard[s.key] = scorePctFromCounts(c);
    totalPass += c.pass;
    totalMeasurable += c.pass + c.fail + c.warning;
  }
  const overall = totalMeasurable > 0 ? Math.round((totalPass / totalMeasurable) * 100) : null;

  return { overall, byStandard };
}

const headingStyle = {
  fontSize: 'var(--text-xs)',
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  color: 'var(--text-muted)',
  marginBottom: 4,
};

const subtextStyle = {
  fontSize: 10,
  color: 'var(--text-muted)',
  marginBottom: 8,
};

function formatSnapshotDate(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

// Fleet-wide compliance score widget: a big StandardDonut gauge for the
// overall pooled score, plus a compact per-standard list. Reads the most
// recent fleet_dashboard_snapshots row when one exists AND is fresh enough
// (the normal case once the daily engine-worker job has run at least once);
// falls back to a live on-the-fly computation otherwise, so this widget is
// never empty just because the snapshot table is new/unpopulated, and never
// silently serves a stuck/stale score if the daily job stops running (it
// only logs-and-skips on failure, with no retry before the next day's cron
// tick -- see services/engine-worker.js's runDashboardSnapshotJob()).
// >2 days stale mirrors CveSeveritySummary.js's own pickComparisonSnapshot()
// threshold exactly.
export default async function ComplianceScoreWidget() {
  const snapshot = await getLatestSnapshot(pool);
  const snapshotFresh = snapshot && daysAgo(snapshot.snapshot_date) <= 2;

  let overall;
  let byStandard;
  let asOfLabel;

  if (snapshotFresh) {
    overall = snapshot.compliance_overall_score;
    byStandard = snapshot.compliance_by_standard || {};
    const dateLabel = formatSnapshotDate(snapshot.snapshot_date);
    asOfLabel = dateLabel ? `As of ${dateLabel} (daily snapshot)` : 'Daily snapshot';
  } else {
    const live = await computeLiveFleetCompliance(pool);
    overall = live.overall;
    byStandard = live.byStandard;
    asOfLabel = snapshot
      ? 'Live — daily snapshot is stale, recomputed live'
      : 'Live — no daily snapshot recorded yet';
  }

  return (
    <Card>
      <div className="card-body-compact">
        <div style={{ ...headingStyle, display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconSearch} color="#34d399" bg="rgba(52,211,153,0.20)" />
          Compliance Score
        </div>
        <div style={subtextStyle}>{asOfLabel}</div>
        <div style={{ display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
          <StandardDonut pct={overall} size={84} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, minWidth: 140 }}>
            {STANDARDS.map((s) => {
              const pct = byStandard ? byStandard[s.key] : null;
              return (
                <Link
                  key={s.key}
                  href="/compliance?view=table"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    textDecoration: 'none',
                    fontSize: 'var(--text-xs)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  <span>{s.label}</span>
                  <Badge color={scoreColor(pct == null ? null : pct)}>{pct == null ? '—' : `${pct}%`}</Badge>
                </Link>
              );
            })}
          </div>
        </div>
      </div>
    </Card>
  );
}
