import { pool } from '../../../lib/db';
import { isValidUuid } from '../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// GET /api/events -- fleet-wide Alerts/Events feed.
//
// Same two "needs attention" sources app/api/notifications/summary/route.js
// already aggregates for the header-bell dropdown (patch_now CVEs,
// unacknowledged config diffs), but as a filterable, paginated feed rather
// than a top-5 snapshot. Deliberately two separate bounded queries
// merged/sorted/paginated in JS, not one DB-side UNION -- the two sources
// have incompatible native shapes (device_cve_assessments+advisories,
// config_diffs) and this app's other list views (e.g. rule analysis)
// already accept a bounded-then-in-memory-merge approach rather than
// building true cross-source DB pagination. Each source query is capped at
// 500 rows before the merge -- a firewall fleet's realistic open-event
// volume fits comfortably inside that.
//
// Query params:
//   type      - 'patch_now' | 'config_diff' (omit = both)
//   status    - 'open' (default) | 'all'
//   device_id - optional UUID filter
//
// ⛔ 'new_finding' REMOVED 2026-07-20, direct user feedback -- see
// fetchNewFindings' own removal comment below for the full reasoning.
//   page      - optional, default 1, 1-indexed

const TYPES = new Set(['patch_now', 'config_diff']);
const STATUS_FILTERS = new Set(['open', 'all']);
const PAGE_SIZE = 25;

// ⛔ BUG FIXED 2026-07-18, found in a bug-sweep pass: neither fetch function
// below filtered on d.active — every other fleet-wide view in this app
// (dashboard, fleet CVE/analysis/compliance/VPN pages, versionMatcher.js,
// ruleAnalysis.js, engine-worker.js) consistently excludes deactivated
// devices, but this one didn't. A decommissioned device's existing
// patch_now CVE / unacknowledged config diff kept inflating the header
// bell badge and the Alerts feed forever, with no way to even filter
// directly to it (the device dropdown, alerts/page.js's getDevices(),
// already correctly excludes inactive devices — only the actual event
// queries didn't). Fixed by adding `d.active = true` unconditionally (not
// just under the `open` filter — an inactive device's history shouldn't
// appear even under "All") to both queries here.
//
// ⛔ fetchNewFindings() REMOVED 2026-07-20, direct user feedback: a
// 'new_finding' type briefly existed here (rule-level findings surfaced as
// individual alert rows), correctly fixing a real bug where a fresh finding
// from a scheduled rule-analysis run was invisible everywhere -- but a
// single device can carry hundreds of 'unused'/'shadow' findings, and
// dumping every one into the curated "needs attention" Alerts feed defeated
// its purpose (the bell badge hit the 99+ cap, the feed became noise).
// Rule-level findings already have a correct, dedicated home with full
// triage tooling: the Cleanup/Optimization/Reorder tabs on
// devices/[id]/analysis (CleanupTab.js's getCleanupFindings(), never
// affected by the bug this removed function existed to fix).

async function fetchPatchNow(deviceId, open) {
  const conditions = [`dca.priority_band = 'patch_now'`, 'd.active = true'];
  const values = [];

  if (open) {
    // ⛔ BUG FIXED 2026-07-18, found in a bug-sweep pass: this used to be
    // `caa.status IS NULL OR caa.status NOT IN ('dismissed', 'actioned')` —
    // i.e. 'acknowledged' still counted as "open" for CVEs, while
    // fetchNewFindings above only ever treats bare 'new' as open.
    // AlertAckControl.js renders the IDENTICAL 4-state new/acknowledged/
    // dismissed/actioned <select> for both row kinds, so clicking
    // "Acknowledged" on a finding row (silently vanishes from the default
    // Open view) behaved differently from clicking the exact same option on
    // a CVE row (stayed visible) — confusing given it's the same control.
    // Aligned to the stricter, findings-side definition: only 'new' (or an
    // unset/NULL ack row, which is implicitly new) counts as open.
    conditions.push(`(caa.status IS NULL OR caa.status = 'new')`);
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
  const conditions = ['d.active = true'];
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
            cd.detected_at, cd.acknowledged_at, cd.acknowledged_by, cd.acknowledged_note
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
    acknowledgedNote: r.acknowledged_note,
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
