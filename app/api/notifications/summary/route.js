import { pool } from '../../../../lib/db';

export const dynamic = 'force-dynamic';

// GET /api/notifications/summary — powers the header bell. Three-way
// aggregate count (new findings + patch_now CVEs + unacknowledged config
// diffs) plus a handful of the most recent actionable items for the dropdown.
export async function GET() {
  try {
    // ⛔ BUG FIXED 2026-07-18, found in a bug-sweep pass: none of these
    // three count queries (nor the three "recent items" queries below) ever
    // joined devices/filtered on d.active — see the identical fix + full
    // reasoning in app/api/events/route.js's fetchNewFindings comment. A
    // decommissioned device's alerts kept inflating this exact badge count
    // forever. The patch_now "open" definition is also aligned here to
    // match findings' (only 'new' counts as open) for the same
    // AlertAckControl.js-shares-one-control reason.
    // ⛔ BUG FIXED 2026-07-19, found in an adversarially-verified bug-sweep
    // pass (mirrored identically from app/api/events/route.js — see that
    // file's comment for the full reasoning): rooted FROM
    // finding_acknowledgements, which only ever gets a row via a
    // human-triggered ack POST — a genuinely new finding from the latest
    // rule-analysis run had zero rows here, so the bell badge undercounted
    // and never listed it. Rooted FROM rule_analysis_results instead, LEFT
    // JOIN finding_acknowledgements, same COALESCE-equivalent
    // (fa.status IS NULL OR fa.status = 'new') pattern as the sibling fix.
    const [newFindings, patchNow, unackedDiffs] = await Promise.all([
      pool.query(
        `SELECT COUNT(*)::int AS count
         FROM rule_analysis_results rar
         JOIN devices d ON d.id = rar.device_id
         JOIN firewall_rules fr ON fr.id = rar.rule_id
         LEFT JOIN finding_acknowledgements fa
           ON fa.device_id = rar.device_id
           AND fa.rule_id_vendor = fr.rule_id_vendor
           AND fa.finding_type = rar.finding_type
         WHERE (fa.status IS NULL OR fa.status = 'new') AND d.active = true`
      ),
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

    const total =
      newFindings.rows[0].count + patchNow.rows[0].count + unackedDiffs.rows[0].count;

    const [recentPatchNow, recentDiffs, recentNewFindings] = await Promise.all([
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
      // Was missing entirely — `total`/`counts.new_findings` above already
      // counted these rows, but with no query pulling any of them into
      // `items`, the bell badge could show a nonzero count while the
      // dropdown rendered the empty "Nothing needs attention" state
      // whenever new-finding rows were the only open item. Found in the
      // final pre-deploy bug check (2026-07-17).
      pool.query(
        `SELECT rar.device_id, d.name AS device_name, rar.finding_type, fr.rule_id_vendor, rar.analyzed_at
         FROM rule_analysis_results rar
         JOIN devices d ON d.id = rar.device_id
         JOIN firewall_rules fr ON fr.id = rar.rule_id
         LEFT JOIN finding_acknowledgements fa
           ON fa.device_id = rar.device_id
           AND fa.rule_id_vendor = fr.rule_id_vendor
           AND fa.finding_type = rar.finding_type
         WHERE (fa.status IS NULL OR fa.status = 'new') AND d.active = true
         ORDER BY rar.analyzed_at DESC
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
      ...recentNewFindings.rows.map((r) => ({
        type: 'new_finding',
        label: `${r.device_name}: ${r.finding_type} (${r.rule_id_vendor})`,
        href: `/alerts?type=new_finding&device_id=${r.device_id}`,
        occurredAt: r.analyzed_at,
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
