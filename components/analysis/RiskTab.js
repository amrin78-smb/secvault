import { pool } from '../../lib/db';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import RiskTrendChart from './RiskTrendChart';
import { BAND_BADGE_COLOR, BAND_LABEL } from './severityRamp';

// Risk tab (Rule Analysis Dashboard): trend of the per-device risk score
// snapshotted into device_risk_history every time runAnalysisForDevice() runs
// (lib/engines/ruleAnalysis.js) -- both scheduled collects and manual "Run
// Analysis" clicks. Async server component -- does its own pool.query, same
// pattern as CleanupTab.js/OptimizationTab.js/ReorderTab.js. Do not add
// 'use client'.

// ⛔ Bands come from ./severityRamp.js. The "keep these in step" comment that
// used to sit here was the whole problem: FOUR files each held their own copy
// and a fifth (SeverityBadge.js) moved without them, so `medium` was still
// rendering BLUE here a full release after blue was pulled off the ramp.
// There is nothing left to keep in step.

function formatDateTime(value) {
  if (!value) return 'Never';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Never';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

async function getRiskHistory(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT score, band, recorded_at
     FROM device_risk_history
     WHERE device_id = $1
     ORDER BY recorded_at ASC`,
    [deviceId]
  );
  return result.rows;
}

export default async function RiskTab({ deviceId }) {
  const rows = await getRiskHistory(pool, deviceId);

  if (rows.length === 0) {
    return (
      <EmptyState message="No risk history yet — risk score is snapshotted every time rule analysis runs (scheduled collect or a manual Run Analysis click)." />
    );
  }

  const latest = rows[rows.length - 1];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 12 }}>
        <Badge color={BAND_BADGE_COLOR[latest.band] || 'muted'}>
          Risk: {BAND_LABEL[latest.band] || latest.band} ({latest.score})
        </Badge>
        <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          Latest of {rows.length} snapshot{rows.length === 1 ? '' : 's'} — as of{' '}
          {formatDateTime(latest.recorded_at)}
        </span>
      </div>

      <RiskTrendChart points={rows} />
    </div>
  );
}
