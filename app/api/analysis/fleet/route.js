import { pool } from '../../../../lib/db';

export const dynamic = 'force-dynamic';

// GET /api/analysis/fleet
// One row per active device with rule hygiene finding counts by severity,
// ordered worst-first (critical DESC, high DESC, total DESC).
export async function GET() {
  try {
    const { rows } = await pool.query(
      `SELECT d.id, d.name, d.vendor, d.site,
              COUNT(rar.id) FILTER (WHERE rar.severity = 'critical')::int AS critical,
              COUNT(rar.id) FILTER (WHERE rar.severity = 'high')::int AS high,
              COUNT(rar.id) FILTER (WHERE rar.severity = 'medium')::int AS medium,
              COUNT(rar.id) FILTER (WHERE rar.severity = 'info')::int AS info,
              COUNT(rar.id)::int AS total
       FROM devices d
       LEFT JOIN rule_analysis_results rar ON rar.device_id = d.id
       WHERE d.active = true
       GROUP BY d.id, d.name, d.vendor, d.site
       ORDER BY critical DESC, high DESC, total DESC`,
      []
    );

    return Response.json({ devices: rows });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
