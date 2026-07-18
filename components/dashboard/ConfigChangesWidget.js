import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import EmptyState from '../ui/EmptyState';

// Dashboard widget: fleet-wide config-change summary over the trailing
// `days` window. Standalone, read-only, server component -- not wired into
// any page yet (a later assembly pass does that).
//
// config_diffs.diff IS a structured jsonb object ({added:[...],
// removed:[...], modified:[...]} -- see lib/engines/configDiff.js's
// diffConfigs()/detectAndStoreDiff()), so an Added/Removed/Modified count
// breakdown below is real data read straight out of that column via
// jsonb_array_length(), not a fabricated split. What IS honestly absent is
// any structured "what changed" beyond that (no per-field type/severity),
// so beyond the counts this only lists change_summary strings (the same
// free-text field app/api/events/route.js's fetchConfigDiffs() and
// alerts/page.js already surface), not a synthesized categorization.
//
// `d.active = true` filter copied from the same convention as
// app/api/events/route.js's fetchConfigDiffs() / alerts/page.js. `days` is
// passed as a numeric parameter multiplied against interval '1 day' --
// never string-concatenated into the query -- per CLAUDE.md's "always
// parameterized queries" rule, with no exception for internally-supplied
// prop values.

async function getConfigChanges(dbPool, days) {
  const { rows } = await dbPool.query(
    `SELECT cd.id, cd.device_id, d.name AS device_name, cd.change_summary, cd.detected_at,
            COALESCE(jsonb_array_length(cd.diff->'added'), 0) AS added_count,
            COALESCE(jsonb_array_length(cd.diff->'removed'), 0) AS removed_count,
            COALESCE(jsonb_array_length(cd.diff->'modified'), 0) AS modified_count
     FROM config_diffs cd
     JOIN devices d ON d.id = cd.device_id
     WHERE d.active = true
       AND cd.detected_at > now() - ($1::int * interval '1 day')
     ORDER BY cd.detected_at DESC`,
    [days]
  );
  return rows;
}

const RECENT_LIST_LIMIT = 5;

export default async function ConfigChangesWidget({ days = 7 }) {
  const rows = await getConfigChanges(pool, days);

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

  return (
    <Card>
      <CardHeader>
        <CardTitle>Config Changes ({days}d)</CardTitle>
      </CardHeader>
      <CardBody>
        {totalCount === 0 ? (
          <EmptyState message={`No configuration changes in the last ${days} days.`} />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap' }}>
              <div>
                <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {totalCount}
                </div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                  Change{totalCount === 1 ? '' : 's'} detected
                </div>
              </div>
              <div style={{ display: 'flex', gap: 16, alignItems: 'flex-end' }}>
                <div>
                  <span style={{ color: 'var(--green)', fontWeight: 600 }}>{totals.added}</span>{' '}
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>added</span>
                </div>
                <div>
                  <span style={{ color: 'var(--red)', fontWeight: 600 }}>{totals.removed}</span>{' '}
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>removed</span>
                </div>
                <div>
                  <span style={{ color: 'var(--yellow)', fontWeight: 600 }}>{totals.modified}</span>{' '}
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>modified</span>
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {recent.map((r) => (
                <Link
                  key={r.id}
                  href={`/devices/${r.device_id}/changes`}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 2,
                    padding: '8px 10px',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border)',
                    color: 'inherit',
                    textDecoration: 'none',
                  }}
                >
                  <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{r.device_name}</span>
                  <span
                    style={{
                      fontSize: 'var(--text-sm)',
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
      </CardBody>
    </Card>
  );
}
