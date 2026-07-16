import { pool } from '../../../../../lib/db';
import { runAnalysisForDevice } from '../../../../../lib/engines/ruleAnalysis';
import { computeRiskScoreFromCounts } from '../../../../../lib/engines/riskScore';

export const dynamic = 'force-dynamic';

// GET /api/devices/[id]/analysis
// Returns rule hygiene findings for one device, joined with the affected rule,
// ordered by severity (critical -> high -> medium -> info) then finding_type,
// plus a summary block with per-type / per-severity counts, a risk score, and
// the ManageEngine-style rule-level aggregate stats (Allowed/Denied/Any-Any/
// Logging Disabled) computed directly from firewall_rules rather than
// duplicating ruleAnalysis.js's isAllow/isAny logic in SQL:
//  - "Allowed"/"Denied" are a plain action-column count.
//  - "Any-Any" and "Logging Disabled" are EXACTLY the any_any/log_disabled
//    finding_type counts already in by_type -- same predicate, so counting
//    them twice with separate SQL would risk the two numbers drifting apart.
export async function GET(request, { params }) {
  try {
    const { id } = params;

    const [{ rows }, { rows: actionRows }] = await Promise.all([
      pool.query(
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
      ),
      pool.query(
        `SELECT
           COUNT(*) FILTER (WHERE action IN ('allow', 'permit', 'accept'))::int AS allowed_count,
           COUNT(*) FILTER (WHERE action IN ('deny', 'drop', 'reject', 'block'))::int AS denied_count,
           COUNT(*) FILTER (WHERE enabled = false)::int AS inactive_count,
           COUNT(*)::int AS total_rules
         FROM firewall_rules
         WHERE device_id = $1`,
        [id]
      ),
    ]);

    const byType = {};
    const bySeverity = {};
    for (const row of rows) {
      byType[row.finding_type] = (byType[row.finding_type] || 0) + 1;
      bySeverity[row.severity] = (bySeverity[row.severity] || 0) + 1;
    }

    const riskScore = computeRiskScoreFromCounts(bySeverity);
    const actionCounts = actionRows[0] || {
      allowed_count: 0,
      denied_count: 0,
      inactive_count: 0,
      total_rules: 0,
    };

    return Response.json({
      findings: rows,
      summary: {
        by_type: byType,
        by_severity: bySeverity,
        total: rows.length,
        risk_score: riskScore.score,
        risk_band: riskScore.band,
        allowed_count: actionCounts.allowed_count,
        denied_count: actionCounts.denied_count,
        inactive_count: actionCounts.inactive_count,
        total_rules: actionCounts.total_rules,
        any_any_count: byType.any_any || 0,
        log_disabled_count: byType.log_disabled || 0,
      },
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
