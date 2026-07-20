import { NextResponse } from 'next/server';
import { pool } from '../../../../../lib/db';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { computeRecommendedOrder } from '../../../../../lib/engines/ruleReorder';

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

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const str = String(value);
  if (/[",\n\r]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function buildCsv(recommendedOrder, changedRuleIdSet) {
  const headers = ['New Position', 'Current Position', 'Rule Name', 'Vendor Rule ID', 'Moved'];
  const lines = [headers.join(',')];
  recommendedOrder.forEach((rule, i) => {
    lines.push(
      [
        csvEscape(i + 1),
        csvEscape(rule.sequence_number),
        csvEscape(rule.rule_name),
        csvEscape(rule.rule_id_vendor),
        csvEscape(changedRuleIdSet.has(rule.id) ? 'yes' : ''),
      ].join(',')
    );
  });
  return lines.join('\r\n');
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
}
