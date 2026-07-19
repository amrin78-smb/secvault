import Link from 'next/link';
import { pool } from '../../lib/db';
import Card from '../ui/Card';
import Table from '../ui/Table';
import EmptyState from '../ui/EmptyState';
import IconChip from '../ui/IconChip';
import { IconClock } from '../icons';

// Dashboard widget: fleet-wide top-N view of activity_log -- the SAME table
// components/analysis/TrackingTab.js already renders per-device, just
// without a device filter. Standalone, read-only, server component -- not
// wired into any page yet (a later assembly pass does that).
//
// Rendering conventions (date format, action-label transform) are copied
// from TrackingTab.js verbatim, not reinvented, so this widget and the
// per-device Tracking tab read identically for the same underlying rows.

function formatDateTime(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// Generic snake_case -> Title Case transform, copied verbatim from
// components/analysis/TrackingTab.js's actionLabel() -- do not write a
// second version of this, reuse it if it ever needs a shared home.
function actionLabel(action) {
  if (!action) return '—';
  return action
    .split('_')
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

async function getRecentActivity(dbPool, limit) {
  const { rows } = await dbPool.query(
    `SELECT al.actor, al.action, al.device_id, d.name AS device_name, al.detail, al.occurred_at
     FROM activity_log al
     LEFT JOIN devices d ON d.id = al.device_id
     WHERE al.device_id IS NULL OR d.active = true
     ORDER BY al.occurred_at DESC
     LIMIT $1`,
    [limit]
  );
  return rows;
}

export default async function RecentActivityFeed({ limit = 8 }) {
  const entries = await getRecentActivity(pool, limit);

  return (
    <Card>
      <div className="card-header-compact">
        <div className="card-title-compact" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconClock} color="#9ca3af" bg="rgba(156,163,175,0.20)" />
          Recent Activity
        </div>
      </div>
      <div className="card-body-compact">
        {entries.length === 0 ? (
          <EmptyState message="No activity recorded yet." />
        ) : (
          <Table className="dashboard-compact-table">
            <colgroup>
              <col style={{ width: '20%' }} />
              <col style={{ width: '22%' }} />
              <col style={{ width: '20%' }} />
              <col style={{ width: '38%' }} />
            </colgroup>
            <thead>
              <tr>
                <th>When</th>
                <th>Action</th>
                <th>Device</th>
                <th>Actor</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((row, idx) => (
                <tr key={`${row.occurred_at}-${idx}`}>
                  <td style={{ color: 'var(--text-secondary)' }}>{formatDateTime(row.occurred_at)}</td>
                  <td title={row.detail || ''}>{actionLabel(row.action)}</td>
                  <td>
                    {row.device_id ? (
                      <Link href={`/devices/${row.device_id}`} style={{ color: 'var(--primary)' }}>
                        {row.device_name || row.device_id}
                      </Link>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>Fleet-wide</span>
                    )}
                  </td>
                  <td title={row.actor || ''}>{row.actor || '—'}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </div>
    </Card>
  );
}
