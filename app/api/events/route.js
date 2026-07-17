import { pool } from '../../../lib/db';
import { isValidUuid } from '../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// GET /api/events -- fleet-wide Alerts/Events feed.
//
// Same three "needs attention" sources app/api/notifications/summary/route.js
// already aggregates for the header-bell dropdown (new findings, patch_now
// CVEs, unacknowledged config diffs), but as a filterable, paginated feed
// rather than a top-5 snapshot. Deliberately three separate bounded queries
// merged/sorted/paginated in JS, not one DB-side UNION -- the three sources
// have incompatible native shapes (finding_acknowledgements, device_cve_
// assessments+advisories, config_diffs) and this app's other list views
// (e.g. rule analysis) already accept a bounded-then-in-memory-merge
// approach rather than building true cross-source DB pagination. Each
// source query is capped at 500 rows before the merge -- a firewall
// fleet's realistic open-event volume fits comfortably inside that.
//
// Query params:
//   type      - 'new_finding' | 'patch_now' | 'config_diff' (omit = all three)
//   status    - 'open' (default) | 'all'
//   device_id - optional UUID filter
//   page      - optional, default 1, 1-indexed

const TYPES = new Set(['new_finding', 'patch_now', 'config_diff']);
const STATUS_FILTERS = new Set(['open', 'all']);
const PAGE_SIZE = 25;

async function fetchNewFindings(deviceId, open) {
  const conditions = [];
  const values = [];

  if (open) {
    conditions.push(`fa.status = 'new'`);
  }
  if (deviceId) {
    values.push(deviceId);
    conditions.push(`fa.device_id = $${values.length}`);
  }
  const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  // rule_analysis_results has no rule_id_vendor column of its own (only a
  // rule_id FK into firewall_rules, which -- like rule_analysis_results
  // itself -- is fully DELETE+reinserted on every pull/analysis run). To
  // resolve severity for a finding_acknowledgements row we therefore go
  // through firewall_rules on (device_id, rule_id_vendor) first, matched
  // via a LATERAL subquery with LIMIT 1 so a device that happens to have
  // more than one live rule sharing a vendor rule id can never fan out the
  // finding_acknowledgements row into duplicates. A miss (stale ack whose
  // source finding no longer exists) yields severity = NULL, tolerated per
  // this route's contract -- rendered as unknown, never a query failure.
  const { rows } = await pool.query(
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

async function fetchPatchNow(deviceId, open) {
  const conditions = [`dca.priority_band = 'patch_now'`];
  const values = [];

  if (open) {
    conditions.push(`(caa.status IS NULL OR caa.status NOT IN ('dismissed', 'actioned'))`);
  }
  if (deviceId) {
    values.push(deviceId);
    conditions.push(`dca.device_id = $${values.length}`);
  }
  const whereClause = `WHERE ${conditions.join(' AND ')}`;

  const { rows } = await pool.query(
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

async function fetchConfigDiffs(deviceId, open) {
  const conditions = [];
  const values = [];

  if (open) {
    conditions.push(`cd.acknowledged_at IS NULL`);
  }
  if (deviceId) {
    values.push(deviceId);
    conditions.push(`cd.device_id = $${values.length}`);
  }
  const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const { rows } = await pool.query(
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

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);

    const typeParam = searchParams.get('type');
    if (typeParam !== null && !TYPES.has(typeParam)) {
      return Response.json(
        { error: `type must be one of: ${Array.from(TYPES).join(', ')}` },
        { status: 400 }
      );
    }

    const statusParam = searchParams.get('status') || 'open';
    if (!STATUS_FILTERS.has(statusParam)) {
      return Response.json(
        { error: `status must be one of: ${Array.from(STATUS_FILTERS).join(', ')}` },
        { status: 400 }
      );
    }
    const open = statusParam !== 'all';

    const deviceIdParam = searchParams.get('device_id');
    if (deviceIdParam !== null && !isValidUuid(deviceIdParam)) {
      return Response.json({ error: 'device_id must be a valid UUID' }, { status: 400 });
    }

    const pageParam = Number(searchParams.get('page'));
    const page = Number.isInteger(pageParam) && pageParam >= 1 ? pageParam : 1;

    const fetchers = [];
    if (!typeParam || typeParam === 'new_finding') {
      fetchers.push(fetchNewFindings(deviceIdParam, open));
    }
    if (!typeParam || typeParam === 'patch_now') {
      fetchers.push(fetchPatchNow(deviceIdParam, open));
    }
    if (!typeParam || typeParam === 'config_diff') {
      fetchers.push(fetchConfigDiffs(deviceIdParam, open));
    }

    const results = await Promise.all(fetchers);
    const merged = results
      .flat()
      .sort((a, b) => new Date(b.occurredAt) - new Date(a.occurredAt));

    const total = merged.length;
    const offset = (page - 1) * PAGE_SIZE;
    const items = merged.slice(offset, offset + PAGE_SIZE);

    return Response.json({ items, total, page, pageSize: PAGE_SIZE });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
