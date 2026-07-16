import { pool } from '../../lib/db';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import RiskTrendChart from './RiskTrendChart';

// Risk tab (Rule Analysis Dashboard): trend of the per-device risk score
// snapshotted into device_risk_history every time runAnalysisForDevice() runs
// (lib/engines/ruleAnalysis.js) -- both scheduled collects and manual "Run
// Analysis" clicks. Async server component -- does its own pool.query, same
// pattern as CleanupTab.js/OptimizationTab.js/ReorderTab.js. Do not add
// 'use client'.

// Same color/label convention as app/(dashboard)/devices/[id]/analysis/page.js's
// RISK_BAND_COLOR / RISK_BAND_LABEL consts -- keep these in step if that
// mapping ever changes.
const RISK_BAND_COLOR = { low: 'success', medium: 'info', high: 'warning', critical: 'danger' };
const RISK_BAND_LABEL = { low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };

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
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Badge color={RISK_BAND_COLOR[latest.band] || 'muted'}>
          Risk: {RISK_BAND_LABEL[latest.band] || latest.band} ({latest.score})
        </Badge>
        <span className="text-sm text-text-secondary">
          Latest of {rows.length} snapshot{rows.length === 1 ? '' : 's'} — as of{' '}
          {formatDateTime(latest.recorded_at)}
        </span>
      </div>

      <RiskTrendChart points={rows} />
    </div>
  );
}
