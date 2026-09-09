import Link from 'next/link';
import TimeAgo from '../../../components/ui/TimeAgo';
import { describeConfigChange } from '../../../lib/configChangeSummary';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../api/auth/[...nextauth]/route';
import { isAdmin } from '../../../lib/rbac';
import { pool } from '../../../lib/db';
import Table from '../../../components/ui/Table';
import Badge from '../../../components/ui/Badge';
import EmptyState from '../../../components/ui/EmptyState';
import PageHeader from '../../../components/ui/PageHeader';
import Pagination from '../../../components/ui/Pagination';
import AlertsFilters from '../../../components/alerts/AlertsFilters';
import AlertAckControl from '../../../components/alerts/AlertAckControl';
import { resolvePage, pageWindow } from '../../../lib/pagination';
import { isValidUuid } from '../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// Fleet-wide Alerts page -- the bell's destination, and the one place every
// "needs attention" item (patch_now CVEs, unacknowledged config diffs) can
// actually be acknowledged/dismissed/resolved in place.
//
// This is a server component, so per this app's established convention
// ("server components query the DB directly in their own query, API routes
// exist for client-triggered writes" -- see CLAUDE.md's Rule Analysis
// Dashboard Phase 2 section, and every other page under app/(dashboard)) it
// queries the DB directly for its initial render rather than fetching its
// own /api/events route. app/api/events/route.js exists for
// AlertAckControl's post-save router.refresh() path and any future
// client-side use, not for this page's read path.
//
// The query below is therefore a deliberate duplicate of
// app/api/events/route.js's fetchPatchNow/fetchConfigDiffs/GET -- the same
// duplication already exists once between app/api/notifications/summary/
// route.js (top-5 bell preview) and this route (full paginated feed), for
// the same reason: different call sites, shared logic that's cheap enough to
// keep in step by inspection. If the query logic in one changes, check the
// other.
//
// ⛔ 'new_finding' REMOVED 2026-07-20, direct user feedback -- see
// app/api/events/route.js's identical removal comment for the full
// reasoning (rule-level findings belong in Rule Analysis's Cleanup/
// Optimization/Reorder tabs, not the curated Alerts feed).
//
// ── PAGINATION (rewritten to real SQL LIMIT/OFFSET) ──────────────────────
// This page used to fetch BOTH sources with a hard `LIMIT 500` each, merge
// them in memory, and slice. Two things were wrong with that beyond the
// wasted work: the "N items" line was capped at 1,000 no matter how many
// alerts really existed (a fabricated total, the same class of lie as a
// truncated result presented as complete), and every page view dragged up to
// a thousand rows across the wire to show twenty-five.
//
// The two sources are now UNION ALL'd in ONE statement so Postgres does the
// ordering and the windowing, with a COUNT over the identical CTE for an
// honest total. Only the SQL SHAPE is composed here (which branches, which
// conditions); every value is still a bound parameter.

const TYPES = new Set(['patch_now', 'config_diff']);
const PAGE_SIZE = 25;

const TYPE_BADGE = {
  patch_now: { color: 'danger', label: 'Patch Now' },
  config_diff: { color: 'warning', label: 'Config Diff' },
};

function formatWhen(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// ⛔ BUG FIXED 2026-07-18, found in a bug-sweep pass (mirrored identically
// in app/api/events/route.js — see that file's comment for the full
// reasoning): d.active = true added unconditionally to both branches below,
// so a decommissioned device's stale alerts stop inflating the bell/feed
// forever; the patch_now "open" definition aligned to only count bare 'new'
// as open, not 'acknowledged', since AlertAckControl.js renders the
// identical select for both row kinds.
//
// ⛔ fetchNewFindings() REMOVED 2026-07-20, direct user feedback -- see
// app/api/events/route.js's identical removal comment for the full
// reasoning.
//
// Builds the `events` CTE body plus its bound values. Both branches project
// the SAME column list in the SAME order — a UNION ALL requires it — with an
// explicit ::type cast on every column one side cannot supply, since an
// untyped NULL leaves Postgres unable to resolve the union's column type.
function buildEventsCte(typeParam, deviceId, open) {
  const values = [];
  let deviceIdx = 0;
  if (deviceId) {
    values.push(deviceId);
    deviceIdx = values.length;
  }

  const branches = [];

  if (!typeParam || typeParam === 'patch_now') {
    const conds = [`dca.priority_band = 'patch_now'`, 'd.active = true'];
    if (open) conds.push(`(caa.status IS NULL OR caa.status = 'new')`);
    if (deviceIdx) conds.push(`dca.device_id = $${deviceIdx}`);
    branches.push(
      `SELECT 'patch_now'::text AS kind,
              dca.id                       AS id,
              dca.device_id                AS device_id,
              d.name                       AS device_name,
              a.cve_id                     AS label,
              NULL::jsonb                  AS diff,
              dca.assessed_at              AS occurred_at,
              COALESCE(caa.status, 'new')  AS status,
              dca.advisory_id              AS advisory_id,
              a.cvss_score                 AS cvss_score,
              NULL::timestamptz            AS acknowledged_at,
              NULL::text                   AS acknowledged_by,
              NULL::text                   AS acknowledged_note
       FROM device_cve_assessments dca
       JOIN advisories a ON a.id = dca.advisory_id
       JOIN devices d ON d.id = dca.device_id
       LEFT JOIN cve_assessment_acknowledgements caa
         ON caa.device_id = dca.device_id AND caa.advisory_id = dca.advisory_id
       WHERE ${conds.join(' AND ')}`
    );
  }

  if (!typeParam || typeParam === 'config_diff') {
    const conds = ['d.active = true'];
    if (open) conds.push('cd.acknowledged_at IS NULL');
    if (deviceIdx) conds.push(`cd.device_id = $${deviceIdx}`);
    branches.push(
      `SELECT 'config_diff'::text AS kind,
              cd.id                                        AS id,
              cd.device_id                                 AS device_id,
              d.name                                       AS device_name,
              COALESCE(cd.change_summary, 'Config changed') AS label,
              cd.diff                                      AS diff,
              cd.detected_at                               AS occurred_at,
              CASE WHEN cd.acknowledged_at IS NULL THEN 'new' ELSE 'acknowledged' END AS status,
              NULL::uuid                                   AS advisory_id,
              NULL::numeric                                AS cvss_score,
              cd.acknowledged_at                           AS acknowledged_at,
              cd.acknowledged_by                           AS acknowledged_by,
              cd.acknowledged_note                         AS acknowledged_note
       FROM config_diffs cd
       JOIN devices d ON d.id = cd.device_id
       WHERE ${conds.join(' AND ')}`
    );
  }

  return { cte: branches.join('\n       UNION ALL\n'), values };
}

async function countEvents(dbPool, cte, values) {
  const { rows } = await dbPool.query(`WITH events AS (${cte}) SELECT COUNT(*)::int AS total FROM events`, values);
  return rows[0]?.total ?? 0;
}

async function fetchEventPage(dbPool, cte, values, limit, offset) {
  // ⛔ `id` is a tiebreaker, not decoration. ORDER BY occurred_at alone is not
  // a TOTAL order — a config pull writes many diffs with near-identical
  // timestamps — and Postgres is free to return ties in any order per query,
  // which makes a row appear on both page 2 and page 3 (or on neither).
  const { rows } = await dbPool.query(
    `WITH events AS (${cte})
     SELECT * FROM events
     ORDER BY occurred_at DESC NULLS LAST, id DESC
     LIMIT $${values.length + 1} OFFSET $${values.length + 2}`,
    [...values, limit, offset]
  );

  return rows.map((r) =>
    r.kind === 'patch_now'
      ? {
          id: r.id,
          type: 'patch_now',
          deviceId: r.device_id,
          deviceName: r.device_name,
          label: r.label,
          severity: r.cvss_score != null ? `CVSS ${r.cvss_score}` : null,
          status: r.status,
          occurredAt: r.occurred_at,
          ack: { kind: 'cve', advisory_id: r.advisory_id },
        }
      : {
          id: r.id,
          type: 'config_diff',
          deviceId: r.device_id,
          deviceName: r.device_name,
          label: r.label,
          diff: r.diff,
          severity: null,
          status: r.status,
          occurredAt: r.occurred_at,
          acknowledgedBy: r.acknowledged_by,
          acknowledgedAt: r.acknowledged_at,
          acknowledgedNote: r.acknowledged_note,
          ack: { kind: 'diff', diff_id: r.id },
        }
  );
}

async function getDevices(dbPool) {
  const { rows } = await dbPool.query(`SELECT id, name FROM devices WHERE active = true ORDER BY name ASC`);
  return rows;
}

export default async function AlertsPage({ searchParams }) {
  // Defense in depth only -- PUT devices/[id]/diffs/[diffId] and POST
  // devices/[id]/cve-acknowledgements (both of which AlertAckControl calls)
  // are already server-side admin-only (lib/rbac.js). Hiding the control
  // here just avoids a viewer clicking it and getting a 403.
  const session = await getServerSession(authOptions);
  const canWrite = isAdmin(session);

  const typeParam = TYPES.has(searchParams?.type) ? searchParams.type : '';
  const statusParam = searchParams?.status === 'all' ? 'all' : 'open';
  const open = statusParam !== 'all';
  const rawDeviceId = searchParams?.device_id || '';
  // A malformed device_id (e.g. a stale/hand-edited link) must never reach
  // pool.query() -- Postgres throws a raw "invalid input syntax for type
  // uuid" error for a UUID-typed column, which would crash this page's
  // render. app/api/events/route.js rejects the same bad input with a clean
  // 400; a server-rendered page has no response-status channel to do that,
  // so instead the filter is silently dropped (same "needs attention" list
  // as no filter) and a notice is shown next to the filters below.
  const deviceIdParam = rawDeviceId && isValidUuid(rawDeviceId) ? rawDeviceId : '';
  const invalidDeviceId = rawDeviceId && !isValidUuid(rawDeviceId);

  const { cte, values } = buildEventsCte(typeParam, deviceIdParam, open);

  // ⛔ The COUNT runs BEFORE the row query, not alongside it, because
  // pageWindow() clamps a past-the-end `?page=` back to the LAST page and it
  // needs the total to do that. A bookmarked ?page=40 whose alerts have since
  // been acknowledged must land on real rows, not an empty table that reads
  // as "everything is gone". getDevices() has no such dependency, so it rides
  // along in parallel.
  const [total, devices] = await Promise.all([countEvents(pool, cte, values), getDevices(pool)]);
  const win = pageWindow(resolvePage(searchParams?.page), PAGE_SIZE, total);
  const items = total > 0 ? await fetchEventPage(pool, cte, values, win.limit, win.offset) : [];

  // ⛔ Page links must carry the ACTIVE FILTERS, or clicking "next" silently
  // changes what is being read. These are the params this render actually
  // honoured -- built exactly as AlertsFilters builds them (omit the default
  // status, omit empties), so a filter link and a page link produce the same
  // URL shape, and a rejected device_id is not carried forward into links
  // that would keep re-triggering the notice below.
  // AlertsFilters itself never emits `page`, so changing a filter always
  // resets to page 1 -- a stale page number from a larger result set would
  // otherwise land past the end.
  const linkParams = {};
  if (typeParam) linkParams.type = typeParam;
  if (statusParam !== 'open') linkParams.status = statusParam;
  if (deviceIdParam) linkParams.device_id = deviceIdParam;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <PageHeader
        title="Alerts"
        subtitle="Fleet-wide items needing attention — patch-now CVEs and unacknowledged config changes. Rule findings live in Rule Analysis."
      />

      <AlertsFilters
        currentType={typeParam}
        currentStatus={statusParam}
        currentDeviceId={deviceIdParam}
        devices={devices}
      />

      {invalidDeviceId && (
        <p style={{ fontSize: 'var(--text-sm)', color: 'var(--red)' }}>
          Ignored an invalid device filter in the link — showing all devices.
        </p>
      )}

      {items.length === 0 ? (
        <EmptyState message="Nothing needs attention." />
      ) : (
        <>
          <Table>
            <colgroup>
              <col style={{ width: '12%' }} />
              <col style={{ width: '18%' }} />
              <col style={{ width: '36%' }} />
              <col style={{ width: '16%' }} />
              <col style={{ width: '18%' }} />
            </colgroup>
            <thead>
              <tr>
                <th>Type</th>
                <th>Device</th>
                <th>Description</th>
                <th>Occurred</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => {
                const typeMeta = TYPE_BADGE[item.type] || { color: 'muted', label: item.type };
                return (
                  <tr key={`${item.type}-${item.id}`}>
                    <td>
                      <Badge color={typeMeta.color}>{typeMeta.label}</Badge>
                    </td>
                    <td title={item.deviceName}>
                      <Link href={`/devices/${item.deviceId}`} className="link-quiet">
                        {item.deviceName}
                      </Link>
                    </td>
                    <td style={{ color: 'var(--text-primary)' }} title={item.label}>
                      {item.type === 'config_diff' ? (
                        // ⛔ `?diff=` as well as the hash. Now that /changes is
                        // paginated, only the current page's anchors exist in
                        // the DOM, so a bare `#diff-<id>` for an older change
                        // resolves to nothing and the link silently lands on
                        // page 1 — looking like the change is gone. The query
                        // param tells that page which page to open; the hash
                        // still scrolls to the row once it is there.
                        <Link
                          href={`/devices/${item.deviceId}/changes?diff=${item.id}#diff-${item.id}`}
                          className="link-quiet"
                        >
                          {describeConfigChange(item.diff, item.label) || item.label}
                        </Link>
                      ) : (
                        item.label
                      )}
                      {item.severity && (
                        <span style={{ color: 'var(--text-muted)' }}> ({item.severity})</span>
                      )}
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>
                      <TimeAgo value={item.occurredAt} />
                    </td>
                    <td>
                      {canWrite ? (
                        <AlertAckControl item={item} />
                      ) : (
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{item.status}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </Table>

          <Pagination
            basePath="/alerts"
            searchParams={linkParams}
            page={win.page}
            pageSize={win.pageSize}
            total={total}
            label="alerts"
          />
        </>
      )}
    </div>
  );
}
