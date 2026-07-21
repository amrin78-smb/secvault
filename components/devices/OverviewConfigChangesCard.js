import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';

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
//      config_diffs.acknowledged_at -- NOT a fabricated "impact" badge;
//      no severity/impact field exists anywhere in this schema.
//
// `days` is passed as a numeric bound parameter, never string-concatenated
// into the query, per CLAUDE.md's "always parameterized queries" rule.

async function getConfigChanges(dbPool, deviceId, days) {
  const { rows } = await dbPool.query(
    `SELECT cd.id, cd.change_summary, cd.detected_at, cd.acknowledged_at, cd.acknowledged_by,
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

function formatDateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

const RECENT_LIST_LIMIT = 5;

export default async function OverviewConfigChangesCard({ deviceId, days = 7 }) {
  const rows = await getConfigChanges(pool, deviceId, days);

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
          <EmptyState message={`No configuration changes in the last ${days} days.`} />
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
              {recent.map((r) => (
                <Link
                  key={r.id}
                  href={changesHref}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 4,
                    padding: '8px 10px',
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
                    {r.acknowledged_at ? (
                      <Badge color="success">Acknowledged</Badge>
                    ) : (
                      <Badge color="muted">Unacknowledged</Badge>
                    )}
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
                    {r.change_summary || 'Config changed'}
                  </span>
                </Link>
              ))}
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
