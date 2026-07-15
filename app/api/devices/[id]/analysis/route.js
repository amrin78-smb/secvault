import { pool } from '../../../../../lib/db';
import { runAnalysisForDevice } from '../../../../../lib/engines/ruleAnalysis';

export const dynamic = 'force-dynamic';

// GET /api/devices/[id]/analysis
// Returns rule hygiene findings for one device, joined with the affected rule,
// ordered by severity (critical -> high -> medium -> info) then finding_type,
// plus a summary block with per-type / per-severity counts.
export async function GET(request, { params }) {
  try {
    const { id } = params;

    const { rows } = await pool.query(
      `SELECT rar.*, fr.rule_name, fr.sequence_number, fr.action
       FROM rule_analysis_results rar
       JOIN firewall_rules fr ON fr.id = rar.rule_id
       WHERE rar.device_id = $1
       ORDER BY
         CASE rar.severity
           WHEN 'critical' THEN 0
           WHEN 'high' THEN 1
           WHEN 'medium' THEN 2
           ELSE 3
         END,
         rar.finding_type`,
      [id]
    );

    const byType = {};
    const bySeverity = {};
    for (const row of rows) {
      byType[row.finding_type] = (byType[row.finding_type] || 0) + 1;
      bySeverity[row.severity] = (bySeverity[row.severity] || 0) + 1;
    }

    return Response.json({
      findings: rows,
      summary: { by_type: byType, by_severity: bySeverity, total: rows.length },
    });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}

// POST /api/devices/[id]/analysis
// Re-runs rule analysis for this device and returns the engine result.
export async function POST(request, { params }) {
  try {
    const { id } = params;
    const result = await runAnalysisForDevice(id, pool);
    return Response.json(result);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
