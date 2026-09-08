import Link from 'next/link';
import { pool } from '../../lib/db';
import Card from '../ui/Card';
import Table from '../ui/Table';
import EmptyState from '../ui/EmptyState';
import IconChip from '../ui/IconChip';
import Pagination from '../ui/Pagination';
import { resolvePage, pageWindow, DEFAULT_PAGE_SIZE } from '../../lib/pagination';
import { IconClock } from '../icons';

// Dashboard widget: fleet-wide view of activity_log -- the SAME table
// components/analysis/TrackingTab.js already renders per-device, just
// without a device filter. Read-only server component.
//
// Rendering conventions (date format, action-label transform) are copied
// from TrackingTab.js verbatim, not reinvented, so this widget and the
// per-device Tracking tab read identically for the same underlying rows.
//
// ── TWO MODES, ONE COMPONENT ─────────────────────────────────────────────
// 1. WIDGET (the dashboard's use): no `searchParams`, so no page links exist
//    to build. Shows the newest `limit` rows plus an HONEST footer saying how
//    many entries there are in total. activity_log grows without bound, so
//    "the last 8" with no denominator quietly implies that IS the activity.
// 2. PAGINATED: a host page passes its own `searchParams` (and a `basePath`),
//    and this renders the shared <Pagination> driven by `?page=`. Page state
//    lives in the URL, never useState -- AutoRefresh's router.refresh() would
//    reset component state, and a URL is linkable into a ticket.
//
// The COUNT runs in BOTH modes: it is what makes the footer honest, and in
// paginated mode pageWindow() needs it to clamp a past-the-end `?page=` back
// to the last page rather than rendering an empty table.

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

// The device predicate is repeated verbatim in the count and the page query
// on purpose: a total that counted rows the table cannot show would be a
// worse lie than no total at all.
const ACTIVITY_WHERE = 'WHERE al.device_id IS NULL OR d.active = true';

async function countActivity(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT COUNT(*)::int AS total
     FROM activity_log al
     LEFT JOIN devices d ON d.id = al.device_id
     ${ACTIVITY_WHERE}`
  );
  return rows[0]?.total ?? 0;
}

async function getRecentActivity(dbPool, limit, offset) {
  const { rows } = await dbPool.query(
    // ⛔ `al.id` is a tiebreaker, not decoration: occurred_at alone is not a
    // TOTAL order (a single job writes several entries within the same
    // millisecond), and without one Postgres may return ties in a different
    // order per query, so a row can show up on two pages or on none.
    `SELECT al.id, al.actor, al.action, al.device_id, d.name AS device_name, al.detail, al.occurred_at
     FROM activity_log al
     LEFT JOIN devices d ON d.id = al.device_id
     ${ACTIVITY_WHERE}
     ORDER BY al.occurred_at DESC, al.id DESC
     LIMIT $1 OFFSET $2`,
    [limit, offset]
  );
  return rows;
}

/**
 * @param {number} [limit]        rows per view (widget: how many to show)
 * @param {number} [pageSize]     paginated mode only; defaults to `limit`
 * @param {object} [searchParams] host page's searchParams -- PRESENCE of this
 *                                switches on paginated mode, since page links
 *                                cannot be built without it
 * @param {string} [basePath]     host page path for the page links
 */
export default async function RecentActivityFeed({
  limit = 8,
  pageSize,
  searchParams,
  basePath = '/',
}) {
  const paginated = Boolean(searchParams);
  const size = paginated ? Number(pageSize) || Number(limit) || DEFAULT_PAGE_SIZE : limit;

  const total = await countActivity(pool);
  const win = paginated
    ? pageWindow(resolvePage(searchParams?.page), size, total)
    : { page: 1, pageSize: size, limit: size, offset: 0 };
  const entries = total > 0 ? await getRecentActivity(pool, win.limit, win.offset) : [];

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
          <>
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
                {entries.map((row) => (
                  <tr key={row.id}>
                    <td style={{ color: 'var(--text-secondary)' }}>{formatDateTime(row.occurred_at)}</td>
                    <td title={row.detail || ''}>{actionLabel(row.action)}</td>
                    <td>
                      {row.device_id ? (
                        <Link href={`/devices/${row.device_id}`} className="link-quiet">
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

            {paginated ? (
              <Pagination
                basePath={basePath}
                searchParams={searchParams}
                page={win.page}
                pageSize={win.pageSize}
                total={total}
                label="activity entries"
              />
            ) : (
              // Widget mode has no page links, but it still owes the reader a
              // denominator. "8 most recent of 12,481" and "8 entries" are
              // different facts and must not look the same.
              <div
                style={{
                  marginTop: 10,
                  paddingTop: 10,
                  borderTop: '1px solid var(--border)',
                  fontSize: 'var(--text-sm)',
                  color: 'var(--text-muted)',
                }}
              >
                {total > entries.length
                  ? `${entries.length} most recent of ${total.toLocaleString()} activity entries`
                  : `${total.toLocaleString()} activity ${total === 1 ? 'entry' : 'entries'}`}
              </div>
            )}
          </>
        )}
      </div>
    </Card>
  );
}
