import { NextResponse } from 'next/server';
import { pool } from '../../../../../lib/db';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { computeRecommendedOrder } from '../../../../../lib/engines/ruleReorder';
// ⛔ THE SHARED ESCAPE, NOT A LOCAL ONE (migrated 2026-09-25). This route
// carried its own `csvEscape` that predated lib/csv.js: it quoted
// CONDITIONALLY -- only on /[",\n\r]/ -- and neutralised NOTHING, so a cell
// beginning `=`, `+`, `-` or `@` was written raw and EXECUTED as a formula
// when the export was opened in Excel, LibreOffice or Sheets.
// ⛔ Do not reintroduce a local copy. Two files deciding independently how to
// neutralise a spreadsheet formula would eventually disagree, and the one that
// disagreed quietly would be the one writing the document that executes.
// ⛔ `Rule Name` and `Vendor Rule ID` are read off the firewall, i.e. free
// text that originates entirely outside SecVault. Verified against the
// migration fixture: the old escape wrote `=cmd|'/c calc'!A1` into the
// document RAW AND UNQUOTED, because that value contains no comma, quote or
// newline and so failed the conditional-quoting test.
import { csvRow, csvDocument } from '../../../../../lib/csv';

export const dynamic = 'force-dynamic';

async function getDeviceRules(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT id, sequence_number, rule_name, rule_id_vendor
     FROM firewall_rules
     WHERE device_id = $1
     ORDER BY sequence_number ASC NULLS LAST`,
    [deviceId]
  );
  return result.rows;
}

async function getReorderFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT rule_id, affected_rule_ids
     FROM rule_analysis_results
     WHERE device_id = $1 AND finding_type = 'reorder_candidate'`,
    [deviceId]
  );
  return result.rows;
}

// ⛔ COLUMNS AND THEIR ORDER ARE UNCHANGED BY THE MIGRATION -- only the
// encoding is: every cell is now quoted, a leading =/+/-/@ is neutralised, and
// the document ends with a CRLF. The header still goes out on zero rows, so
// "the export is broken" and "nothing to reorder" stay distinguishable.
//
// ⛔ PRE-EXISTING GAP, NOT INTRODUCED AND NOT CLOSED HERE: the escape this
// replaced had dropped the `typeof value === 'object'` branch its siblings in
// app/api/vpn/* carry, so an unexpected object serialised as `[object Object]`.
// csvEscape does a bare String(value) too, so this migration is NEUTRAL on that
// -- it neither fixes nor worsens it. Every column here is a scalar today
// (INTEGER, TEXT, TEXT) so nothing reaches it; it is reported separately so the
// object case can be decided on its own rather than smuggled in as a side
// effect of a security fix.
function buildCsv(recommendedOrder, changedRuleIdSet) {
  const rows = [
    csvRow(['New Position', 'Current Position', 'Rule Name', 'Vendor Rule ID', 'Moved']),
  ];
  recommendedOrder.forEach((rule, i) => {
    rows.push(
      csvRow([
        String(i + 1),
        rule.sequence_number,
        rule.rule_name,
        rule.rule_id_vendor,
        // Preserved verbatim: the call site, not the escape, decides this is a
        // 'yes'/empty pair rather than a boolean.
        changedRuleIdSet.has(rule.id) ? 'yes' : '',
      ])
    );
  });
  return csvDocument(rows);
}

// GET /api/devices/[id]/reorder-recommendation
// Computes a recommended rule order that resolves as many reorder_candidate
// findings as possible (lib/engines/ruleReorder.js's topological sort — see
// that file for the algorithm). JSON by default; ?format=csv exports the
// full recommended order as a downloadable CSV, matching the established
// ?format=csv convention used by /api/devices/[id]/rules and the
// compliance/analysis export routes. Read-only — this never writes back to
// the device or reorders firewall_rules in the DB; it's a recommendation
// for a human to apply manually, same "recommend-only" scope as every other
// finding in this dashboard (see CLAUDE.md's Rule Analysis Dashboard
// section — no adapter has ever gained a write-back-to-device capability).
export async function GET(request, { params }) {
  // ⛔ Was the ONLY route in app/api with no error handling at all: a DB
  // outage or a throw from computeRecommendedOrder returned an opaque 500
  // with no message for the ReorderTab to show. Matches the shape every
  // sibling analysis route already uses.
  try {
    const deviceId = params.id;

    if (!isValidUuid(deviceId)) {
      return NextResponse.json({ error: 'Invalid device id' }, { status: 400 });
    }

    const { searchParams } = new URL(request.url);
    const format = searchParams.get('format');

    const [rules, findings] = await Promise.all([
      getDeviceRules(pool, deviceId),
      getReorderFindings(pool, deviceId),
    ]);

    const {
      recommendedOrder,
      changedRuleIds,
      unresolvedRuleIds,
      resolvedFindingCount,
      unresolvedFindingCount,
    } = computeRecommendedOrder(rules, findings);

    if (format === 'csv') {
      const csv = buildCsv(recommendedOrder, new Set(changedRuleIds));
      return new Response(csv, {
        status: 200,
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': 'attachment; filename="reorder-recommendation.csv"',
        },
      });
    }

    return NextResponse.json({
      recommendedOrder,
      changedRuleIds,
      unresolvedRuleIds,
      resolvedFindingCount,
      unresolvedFindingCount,
    });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
