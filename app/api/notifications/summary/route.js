import { pool } from '../../../../lib/db';

export const dynamic = 'force-dynamic';

// GET /api/notifications/summary — powers the header bell. Two-way
// aggregate count (patch_now CVEs + unacknowledged config diffs) plus a
// handful of the most recent actionable items for the dropdown.
//
// ⛔ 'new_finding' REMOVED 2026-07-20, direct user feedback: rule-level
// findings (unused/shadow/any_any/...) used to be counted and listed here
// too, but a single device can carry hundreds of them -- correctly counting
// every one blew the bell badge past its 99+ cap and buried the two
// genuinely low-cardinality, curated alert types underneath a flood of
// findings that already have a proper triage home in Rule Analysis's
// Cleanup/Optimization/Reorder tabs. See app/api/events/route.js's
// identical removal comment for the full reasoning.
export async function GET() {
  try {
    // ⛔ BUG FIXED 2026-07-18, found in a bug-sweep pass: neither count query
    // (nor either "recent items" query below) joined devices/filtered on
    // d.active — see the identical fix + full reasoning in
    // app/api/events/route.js's fetchPatchNow comment. A decommissioned
    // device's alerts kept inflating this exact badge count forever.
    const [patchNow, unackedDiffs] = await Promise.all([
      pool.query(
        `SELECT COUNT(*)::int AS count
         FROM device_cve_assessments dca
         JOIN devices d ON d.id = dca.device_id
         LEFT JOIN cve_assessment_acknowledgements caa
           ON caa.device_id = dca.device_id AND caa.advisory_id = dca.advisory_id
         WHERE dca.priority_band = 'patch_now'
           AND d.active = true
           AND (caa.status IS NULL OR caa.status = 'new')`
      ),
      pool.query(
        `SELECT COUNT(*)::int AS count
         FROM config_diffs cd
         JOIN devices d ON d.id = cd.device_id
         WHERE cd.acknowledged_at IS NULL AND d.active = true`
      ),
    ]);

    const total = patchNow.rows[0].count + unackedDiffs.rows[0].count;

    const [recentPatchNow, recentDiffs] = await Promise.all([
      pool.query(
        `SELECT a.cve_id, d.id AS device_id, d.name AS device_name, dca.assessed_at
         FROM device_cve_assessments dca
         JOIN advisories a ON a.id = dca.advisory_id
         JOIN devices d ON d.id = dca.device_id
         LEFT JOIN cve_assessment_acknowledgements caa
           ON caa.device_id = dca.device_id AND caa.advisory_id = dca.advisory_id
         WHERE dca.priority_band = 'patch_now'
           AND d.active = true
           AND (caa.status IS NULL OR caa.status = 'new')
         ORDER BY dca.assessed_at DESC
         LIMIT 3`
      ),
      pool.query(
        `SELECT cd.id, cd.change_summary, cd.detected_at, d.id AS device_id, d.name AS device_name
         FROM config_diffs cd
         JOIN devices d ON d.id = cd.device_id
         WHERE cd.acknowledged_at IS NULL AND d.active = true
         ORDER BY cd.detected_at DESC
         LIMIT 3`
      ),
    ]);

    const items = [
      ...recentPatchNow.rows.map((r) => ({
        type: 'patch_now',
        label: `${r.cve_id} — ${r.device_name}`,
        href: `/alerts?type=patch_now&device_id=${r.device_id}`,
        occurredAt: r.assessed_at,
      })),
      ...recentDiffs.rows.map((r) => ({
        type: 'config_diff',
        label: `${r.device_name}: ${r.change_summary || 'Config changed'}`,
        href: `/alerts?type=config_diff&device_id=${r.device_id}`,
        occurredAt: r.detected_at,
      })),
    ]
      .sort((a, b) => new Date(b.occurredAt) - new Date(a.occurredAt))
      .slice(0, 5);

    return Response.json({
      total,
      counts: {
        patch_now: patchNow.rows[0].count,
        unacked_diffs: unackedDiffs.rows[0].count,
      },
      items,
    });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
