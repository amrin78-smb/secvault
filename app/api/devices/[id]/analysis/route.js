import { pool } from '../../../../../lib/db';
import { runAnalysisForDevice } from '../../../../../lib/engines/ruleAnalysis';
import { computeRiskScoreFromCounts } from '../../../../../lib/engines/riskScore';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { logActivity } from '../../../../../lib/activityLog';
import { isValidUuid } from '../../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const str = typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/[",\n\r]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function buildCsv(rows) {
  const headers = ['Severity', 'Finding Type', 'Rule Sequence', 'Rule Name', 'Action', 'Detail', 'Remediation'];
  const lines = [headers.join(',')];
  for (const r of rows) {
    lines.push(
      [
        csvEscape(r.severity),
        csvEscape(r.finding_type),
        csvEscape(r.sequence_number),
        csvEscape(r.rule_name),
        csvEscape(r.action),
        csvEscape(r.detail),
        csvEscape(r.remediation),
      ].join(',')
    );
  }
  return lines.join('\r\n');
}

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
    const { searchParams } = new URL(request.url);
    const format = searchParams.get('format');

    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid device id' }, { status: 400 });
    }

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

    if (format === 'csv') {
      const csv = buildCsv(rows);
      return new Response(csv, {
        status: 200,
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': `attachment; filename="rule-analysis-${id}.csv"`,
        },
      });
    }

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

    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid device id' }, { status: 400 });
    }

    const result = await runAnalysisForDevice(id, pool);

    // Audit logging is best-effort and must never turn a successful analysis
    // run into a reported failure to the client — a getServerSession/
    // logActivity hiccup here is a secondary concern (who did this), not the
    // primary action (the analysis already succeeded and committed above).
    try {
      const session = await getServerSession(authOptions);
      const actor = (session && session.user && session.user.name) || 'unknown';
      await logActivity(pool, {
        actor,
        action: 'run_analysis',
        deviceId: id,
        detail: `Analysis run — ${result.findings} finding(s)`,
      });
    } catch (auditErr) {
      console.warn(`[analysis route] Failed to record activity log: ${auditErr.message}`);
    }

    return Response.json(result);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
