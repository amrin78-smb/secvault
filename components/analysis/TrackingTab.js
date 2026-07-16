import { pool } from '../../lib/db';
import Table from '../ui/Table';
import EmptyState from '../ui/EmptyState';

// Tracking tab (Rule Analysis Dashboard): shows this device's operator
// activity history (run analysis, acknowledge finding, acknowledge config
// diff, ...) from the activity_log table. Async server component -- does
// its own pool.query, same pattern as CleanupTab.js / OptimizationTab.js.
// Do not add 'use client'.

const MAX_ROWS = 100;

function formatDateTime(value) {
  const d = new Date(value);
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// Generic snake_case -> Title Case transform. Deliberately not an exhaustive
// lookup table -- new action strings may be logged by logActivity() later
// that this file doesn't know about.
function actionLabel(action) {
  if (!action) return '—';
  return action
    .split('_')
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

async function getActivityLog(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT actor, action, detail, occurred_at
     FROM activity_log
     WHERE device_id = $1
     ORDER BY occurred_at DESC
     LIMIT $2`,
    [deviceId, MAX_ROWS]
  );
  return result.rows;
}

export default async function TrackingTab({ deviceId }) {
  const entries = await getActivityLog(pool, deviceId);

  if (entries.length === 0) {
    return <EmptyState message="No activity recorded yet for this device." />;
  }

  return (
    <Table>
      <colgroup>
        <col style={{ width: '18%' }} />
        <col style={{ width: '15%' }} />
        <col style={{ width: '22%' }} />
        <col style={{ width: '45%' }} />
      </colgroup>
      <thead>
        <tr className="border-b border-border bg-bg-surface text-left text-text-secondary">
          <th className="px-2 py-2">When</th>
          <th className="px-2 py-2">Actor</th>
          <th className="px-2 py-2">Action</th>
          <th className="px-2 py-2">Detail</th>
        </tr>
      </thead>
      <tbody>
        {entries.map((row, idx) => (
          <tr key={`${row.occurred_at}-${idx}`} className="border-b border-border">
            <td className="px-2 py-2 text-text-secondary">{formatDateTime(row.occurred_at)}</td>
            <td className="truncate px-2 py-2" title={row.actor || ''}>
              {row.actor || '—'}
            </td>
            <td className="px-2 py-2">{actionLabel(row.action)}</td>
            <td className="px-2 py-2 text-text-secondary" title={row.detail || ''}>
              {row.detail || '—'}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
