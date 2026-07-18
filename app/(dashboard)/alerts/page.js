import Link from 'next/link';
import { pool } from '../../../lib/db';
import Table from '../../../components/ui/Table';
import Badge from '../../../components/ui/Badge';
import EmptyState from '../../../components/ui/EmptyState';
import PageHeader from '../../../components/ui/PageHeader';
import AlertsFilters from '../../../components/alerts/AlertsFilters';
import AlertAckControl from '../../../components/alerts/AlertAckControl';
import { isValidUuid } from '../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// Fleet-wide Alerts page -- the bell's destination, and the one place every
// "needs attention" item (new rule findings, patch_now CVEs, unacknowledged
// config diffs) can actually be acknowledged/dismissed/resolved in place.
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
// The three fetch*/merge/sort/paginate functions below are therefore a
// deliberate duplicate of app/api/events/route.js's fetchNewFindings/
// fetchPatchNow/fetchConfigDiffs/GET -- the same duplication already exists
// once between app/api/notifications/summary/route.js (top-5 bell preview)
// and this route (full paginated feed), for the same reason: different call
// sites, shared logic that's cheap enough to keep in step by inspection.
// If the query logic in one changes, check the other.

const TYPES = new Set(['new_finding', 'patch_now', 'config_diff']);
const PAGE_SIZE = 25;

const TYPE_BADGE = {
  new_finding: { color: 'info', label: 'Finding' },
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
// reasoning): d.active = true added unconditionally to all three fetch
// functions below, so a decommissioned device's stale alerts stop
// inflating the bell/feed forever; fetchPatchNow's "open" definition
// aligned to match fetchNewFindings' (only 'new' counts as open, not
// 'acknowledged') since AlertAckControl.js renders the identical select for
// both row kinds.
async function fetchNewFindings(dbPool, deviceId, open) {
  const conditions = ['d.active = true'];
  const values = [];
  if (open) conditions.push(`fa.status = 'new'`);
  if (deviceId) {
    values.push(deviceId);
    conditions.push(`fa.device_id = $${values.length}`);
  }
  const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  // See app/api/events/route.js's fetchNewFindings for why severity is
  // resolved via a LATERAL join against firewall_rules/rule_analysis_results
  // rather than a plain column on finding_acknowledgements, and why a miss
  // (stale ack whose source finding no longer exists) yields severity = NULL
  // rather than failing the query.
  const { rows } = await dbPool.query(
    `SELECT fa.id, fa.device_id, d.name AS device_name, fa.rule_id_vendor,
            fa.finding_type, fa.status, fa.updated_at, rar.severity
     FROM finding_acknowledgements fa
     JOIN devices d ON d.id = fa.device_id
     LEFT JOIN LATERAL (
       SELECT rar_inner.severity
       FROM firewall_rules fr
       JOIN rule_analysis_results rar_inner
         ON rar_inner.rule_id = fr.id AND rar_inner.finding_type = fa.finding_type
       WHERE fr.device_id = fa.device_id AND fr.rule_id_vendor = fa.rule_id_vendor
       LIMIT 1
     ) rar ON true
     ${whereClause}
     ORDER BY fa.updated_at DESC
     LIMIT 500`,
    values
  );

  return rows.map((r) => ({
    id: r.id,
    type: 'new_finding',
    deviceId: r.device_id,
    deviceName: r.device_name,
    label: `${r.finding_type} on ${r.rule_id_vendor}`,
    severity: r.severity || null,
    status: r.status,
    occurredAt: r.updated_at,
    ack: { kind: 'finding', rule_id_vendor: r.rule_id_vendor, finding_type: r.finding_type },
  }));
}

async function fetchPatchNow(dbPool, deviceId, open) {
  const conditions = [`dca.priority_band = 'patch_now'`, 'd.active = true'];
  const values = [];
  if (open) conditions.push(`(caa.status IS NULL OR caa.status = 'new')`);
  if (deviceId) {
    values.push(deviceId);
    conditions.push(`dca.device_id = $${values.length}`);
  }
  const whereClause = `WHERE ${conditions.join(' AND ')}`;

  const { rows } = await dbPool.query(
    `SELECT dca.id, dca.device_id, d.name AS device_name, dca.advisory_id,
            a.cve_id, a.cvss_score, dca.assessed_at, caa.status AS caa_status
     FROM device_cve_assessments dca
     JOIN advisories a ON a.id = dca.advisory_id
     JOIN devices d ON d.id = dca.device_id
     LEFT JOIN cve_assessment_acknowledgements caa
       ON caa.device_id = dca.device_id AND caa.advisory_id = dca.advisory_id
     ${whereClause}
     ORDER BY dca.assessed_at DESC
     LIMIT 500`,
    values
  );

  return rows.map((r) => ({
    id: r.id,
    type: 'patch_now',
    deviceId: r.device_id,
    deviceName: r.device_name,
    label: r.cve_id,
    severity: r.cvss_score != null ? `CVSS ${r.cvss_score}` : null,
    status: r.caa_status || 'new',
    occurredAt: r.assessed_at,
    ack: { kind: 'cve', advisory_id: r.advisory_id },
  }));
}

async function fetchConfigDiffs(dbPool, deviceId, open) {
  const conditions = ['d.active = true'];
  const values = [];
  if (open) conditions.push(`cd.acknowledged_at IS NULL`);
  if (deviceId) {
    values.push(deviceId);
    conditions.push(`cd.device_id = $${values.length}`);
  }
  const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const { rows } = await dbPool.query(
    `SELECT cd.id, cd.device_id, d.name AS device_name, cd.change_summary,
            cd.detected_at, cd.acknowledged_at, cd.acknowledged_by
     FROM config_diffs cd
     JOIN devices d ON d.id = cd.device_id
     ${whereClause}
     ORDER BY cd.detected_at DESC
     LIMIT 500`,
    values
  );

  return rows.map((r) => ({
    id: r.id,
    type: 'config_diff',
    deviceId: r.device_id,
    deviceName: r.device_name,
    label: r.change_summary || 'Config changed',
    severity: null,
    status: r.acknowledged_at ? 'acknowledged' : 'new',
    occurredAt: r.detected_at,
    acknowledgedBy: r.acknowledged_by,
    acknowledgedAt: r.acknowledged_at,
    ack: { kind: 'diff', diff_id: r.id },
  }));
}

async function getDevices(dbPool) {
  const { rows } = await dbPool.query(`SELECT id, name FROM devices WHERE active = true ORDER BY name ASC`);
  return rows;
}

export default async function AlertsPage({ searchParams }) {
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
  const pageNum = Number(searchParams?.page);
  const page = Number.isInteger(pageNum) && pageNum >= 1 ? pageNum : 1;

  const fetchers = [];
  if (!typeParam || typeParam === 'new_finding') fetchers.push(fetchNewFindings(pool, deviceIdParam, open));
  if (!typeParam || typeParam === 'patch_now') fetchers.push(fetchPatchNow(pool, deviceIdParam, open));
  if (!typeParam || typeParam === 'config_diff') fetchers.push(fetchConfigDiffs(pool, deviceIdParam, open));

  const [results, devices] = await Promise.all([Promise.all(fetchers), getDevices(pool)]);

  const merged = results.flat().sort((a, b) => new Date(b.occurredAt) - new Date(a.occurredAt));
  const total = merged.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const offset = (page - 1) * PAGE_SIZE;
  const items = merged.slice(offset, offset + PAGE_SIZE);

  function pageHref(p) {
    const params = new URLSearchParams();
    if (typeParam) params.set('type', typeParam);
    if (statusParam !== 'open') params.set('status', statusParam);
    if (deviceIdParam) params.set('device_id', deviceIdParam);
    if (p > 1) params.set('page', String(p));
    const qs = params.toString();
    return `/alerts${qs ? `?${qs}` : ''}`;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <PageHeader
        title="Alerts"
        subtitle="Fleet-wide items needing attention — new rule findings, patch-now CVEs, and unacknowledged config changes."
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
                      <Link href={`/devices/${item.deviceId}`} style={{ color: 'var(--primary)' }}>
                        {item.deviceName}
                      </Link>
                    </td>
                    <td style={{ color: 'var(--text-primary)' }} title={item.label}>
                      {item.label}
                      {item.severity && (
                        <span style={{ color: 'var(--text-muted)' }}> ({item.severity})</span>
                      )}
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>{formatWhen(item.occurredAt)}</td>
                    <td>
                      <AlertAckControl item={item} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </Table>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              {total} item{total === 1 ? '' : 's'} · page {page} of {totalPages}
            </span>
            <div style={{ display: 'flex', gap: 8 }}>
              {page > 1 ? (
                <Link href={pageHref(page - 1)} className="btn btn-secondary">
                  ← Prev
                </Link>
              ) : (
                <span className="btn btn-secondary" style={{ opacity: 0.5, pointerEvents: 'none' }}>
                  ← Prev
                </span>
              )}
              {page < totalPages ? (
                <Link href={pageHref(page + 1)} className="btn btn-secondary">
                  Next →
                </Link>
              ) : (
                <span className="btn btn-secondary" style={{ opacity: 0.5, pointerEvents: 'none' }}>
                  Next →
                </span>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
