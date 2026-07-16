import { pool } from '../../../../lib/db';

export const dynamic = 'force-dynamic';

// GET /api/notifications/summary — powers the header bell. Three-way
// aggregate count (new findings + patch_now CVEs + unacknowledged config
// diffs) plus a handful of the most recent actionable items for the dropdown.
export async function GET() {
  try {
    const [newFindings, patchNow, unackedDiffs] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS count FROM finding_acknowledgements WHERE status = 'new'`),
      pool.query(`SELECT COUNT(*)::int AS count FROM device_cve_assessments WHERE priority_band = 'patch_now'`),
      pool.query(`SELECT COUNT(*)::int AS count FROM config_diffs WHERE acknowledged_at IS NULL`),
    ]);

    const total =
      newFindings.rows[0].count + patchNow.rows[0].count + unackedDiffs.rows[0].count;

    const [recentPatchNow, recentDiffs, recentNewFindings] = await Promise.all([
      pool.query(
        `SELECT a.cve_id, d.id AS device_id, d.name AS device_name, dca.assessed_at
         FROM device_cve_assessments dca
         JOIN advisories a ON a.id = dca.advisory_id
         JOIN devices d ON d.id = dca.device_id
         WHERE dca.priority_band = 'patch_now'
         ORDER BY dca.assessed_at DESC
         LIMIT 3`
      ),
      pool.query(
        `SELECT cd.id, cd.change_summary, cd.detected_at, d.id AS device_id, d.name AS device_name
         FROM config_diffs cd
         JOIN devices d ON d.id = cd.device_id
         WHERE cd.acknowledged_at IS NULL
         ORDER BY cd.detected_at DESC
         LIMIT 3`
      ),
      // Was missing entirely — `total`/`counts.new_findings` above already
      // counted these rows, but with no query pulling any of them into
      // `items`, the bell badge could show a nonzero count while the
      // dropdown rendered the empty "Nothing needs attention" state
      // whenever new-finding rows were the only open item. Found in the
      // final pre-deploy bug check (2026-07-17).
      pool.query(
        `SELECT fa.device_id, d.name AS device_name, fa.finding_type, fa.rule_id_vendor, fa.updated_at
         FROM finding_acknowledgements fa
         JOIN devices d ON d.id = fa.device_id
         WHERE fa.status = 'new'
         ORDER BY fa.updated_at DESC
         LIMIT 3`
      ),
    ]);

    const items = [
      ...recentPatchNow.rows.map((r) => ({
        type: 'patch_now',
        label: `${r.cve_id} — ${r.device_name}`,
        href: `/devices/${r.device_id}?tab=cve`,
        occurredAt: r.assessed_at,
      })),
      ...recentDiffs.rows.map((r) => ({
        type: 'config_diff',
        label: `${r.device_name}: ${r.change_summary || 'Config changed'}`,
        href: `/devices/${r.device_id}/changes`,
        occurredAt: r.detected_at,
      })),
      ...recentNewFindings.rows.map((r) => ({
        type: 'new_finding',
        label: `${r.device_name}: ${r.finding_type} (${r.rule_id_vendor})`,
        href: `/devices/${r.device_id}/analysis?tab=findings`,
        occurredAt: r.updated_at,
      })),
    ]
      .sort((a, b) => new Date(b.occurredAt) - new Date(a.occurredAt))
      .slice(0, 5);

    return Response.json({
      total,
      counts: {
        new_findings: newFindings.rows[0].count,
        patch_now: patchNow.rows[0].count,
        unacked_diffs: unackedDiffs.rows[0].count,
      },
      items,
    });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
