import { pool } from '../../../../../lib/db';
import { runAnalysisForDevice } from '../../../../../lib/engines/ruleAnalysis';
import { computeRiskScoreFromCounts } from '../../../../../lib/engines/riskScore';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { logActivity } from '../../../../../lib/activityLog';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { can, OPERATE, forbiddenResponse } from '../../../../../lib/rbac';
// ⛔ THE SHARED ESCAPE, NOT A LOCAL ONE (migrated 2026-09-25), for the same
// reason app/api/compliance/fleet/route.js was: the local `csvEscape` this
// replaces quoted CONDITIONALLY and neutralised NOTHING, so a cell beginning
// `=`, `+`, `-` or `@` was EXECUTED as a formula when the export was opened in
// Excel, LibreOffice or Sheets. `Rule Name` is read straight off firewall
// configuration and the finding detail quotes it back, so this document was a
// path from a firewall config into code running on an operator's workstation.
// ⛔ Do not reintroduce a local copy. Two files deciding independently how to
// neutralise a spreadsheet formula would eventually disagree, and the one that
// disagreed quietly would be the one writing the document that executes.
import { csvRow, csvDocument } from '../../../../../lib/csv';

export const dynamic = 'force-dynamic';

// ⛔ THE OBJECT BRANCH THE LOCAL ESCAPE CARRIED, MOVED TO THE CALL SITE.
// `csvEscape` does a bare `String(value)`, which renders any object as
// `[object Object]`. The escape this file used to own stringified one instead,
// and dropping that would silently turn a readable cell into that literal —
// so the transformation happens HERE and a STRING is what reaches `csvRow`.
// ⛔ The null guard stays AHEAD of the object test, exactly as it did before:
// `typeof null === 'object'`, so checking the other way round would write the
// four characters `null` into a cell that has always been left empty. It also
// keeps a NUMERIC `sequence_number` of 0 exporting as `0` rather than as an
// empty cell — a falsy check here would be this codebase's own
// failed-read-as-a-fact bug, one rule position out.
function cellText(value) {
  if (value === null || value === undefined) return '';
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

// ⛔ THE COLUMNS AND THEIR ORDER ARE UNCHANGED BY THE ESCAPE MIGRATION, and
// deliberately so: this is a file customers already save, script against and
// attach to change requests. Only the ENCODING of a cell changed — every cell
// is now quoted (the shared escape always quotes, because deciding per value
// whether it contains a separator shifts every column after the one call you
// get wrong) and a leading formula character is prefixed with an apostrophe.
function buildCsv(rows) {
  const headers = ['Severity', 'Finding Type', 'Rule Sequence', 'Rule Name', 'Action', 'Detail', 'Remediation'];
  // The header goes through csvRow too: one escape for the whole document
  // means no row can be encoded by a different set of rules than the row
  // above it.
  const lines = [csvRow(headers)];
  for (const r of rows) {
    lines.push(
      csvRow([
        cellText(r.severity),
        cellText(r.finding_type),
        cellText(r.sequence_number),
        cellText(r.rule_name),
        cellText(r.action),
        cellText(r.detail),
        cellText(r.remediation),
      ])
    );
  }
  // ⛔ No BOM: this export has never carried one, and adding it is a separate,
  // visible decision (see lib/csv.js for why it is opt-in per caller). A
  // device with no findings still gets its header row — "the export is broken"
  // and "this device is clean" must never look the same.
  return csvDocument(lines);
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

    const session = await getServerSession(authOptions);
    if (!can(session, OPERATE)) {
      return forbiddenResponse(OPERATE);
    }

    const result = await runAnalysisForDevice(id, pool);

    // Audit logging is best-effort and must never turn a successful analysis
    // run into a reported failure to the client — a getServerSession/
    // logActivity hiccup here is a secondary concern (who did this), not the
    // primary action (the analysis already succeeded and committed above).
    try {
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
