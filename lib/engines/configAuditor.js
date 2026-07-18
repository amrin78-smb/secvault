// lib/engines/configAuditor.js
//
// Phase 7 compliance engine: evaluates a device's audit_checks library against
// its latest collected config and rewrites that device's audit_findings.
//
// Deliberately reuses lib/engines/applicability.js's PURE predicate evaluator
// (evaluatePredicate) and hasUsableConfig() guard rather than reimplementing
// tri-state predicate logic a second time — see CLAUDE.md's "tri-state ->
// four-state polarity problem" for why a compliance PASS/FAIL/WARNING/NA
// needs one more state than applicability.js's yes/no/unknown, and how
// `pass_when` on each check's predicate_config resolves that without
// touching applicability.js at all.
//
// runComplianceAuditForDevice() is the DB-backed per-device wrapper, mirroring
// lib/engines/ruleAnalysis.js's runAnalysisForDevice() shape: load inputs,
// evaluate, DELETE + reinsert findings inside one transaction (a partial
// rewrite must never leave audit_findings in a mixed old/new state — same
// reasoning as ruleAnalysis.js and the firewall_rules rewrite in
// lib/adapters/index.js). Called both by collectAndStore (after every
// successful config pull) and on-demand from
// POST /api/compliance/[deviceId]/run.

'use strict';

const { evaluatePredicate, hasUsableConfig, getLatestConfigParsed } = require('./applicability');

/**
 * Maps one evaluatePredicate() result + a check's pass_when polarity to a
 * compliance status. See CLAUDE.md's four-state mapping — this is a
 * deliberate design, not a placeholder:
 *   - result === 'unknown' -> 'warning' (something WAS collected, but this
 *     specific value couldn't be resolved against it)
 *   - result === pass_when -> 'pass'
 *   - otherwise            -> 'fail'
 *
 * @param {'yes'|'no'|'unknown'} result
 * @param {'yes'|'no'} passWhen
 * @returns {'pass'|'fail'|'warning'}
 */
function statusFromResult(result, passWhen) {
  if (result === 'unknown') return 'warning';
  return result === passWhen ? 'pass' : 'fail';
}

/**
 * Evaluate one audit_checks row against a device's parsed config.
 * Never throws — evaluatePredicate() itself never throws, and this function
 * adds no additional fallible logic beyond string formatting.
 *
 * @param {object} check - audit_checks row (predicate_config already-parsed jsonb)
 * @param {object} configParsed
 * @returns {{status: 'pass'|'fail'|'warning', detail: string}}
 */
function evaluateCheck(check, configParsed) {
  const predicateConfig = check.predicate_config || {};
  const predicateType = predicateConfig.predicate_type;
  const passWhen = predicateConfig.pass_when;

  // pass_when must be exactly 'yes' or 'no' -- it decides which
  // evaluatePredicate() outcome means PASS vs FAIL for this specific check
  // (see the module header comment). A missing/misspelled value must NEVER
  // silently default to either polarity: for a check whose predicate tests a
  // BAD condition (e.g. admin_access_from_zone, pass_when:'no'), quietly
  // assuming 'yes' would invert pass/fail with no error anywhere -- exactly
  // the "always wrong, looks fine" bug class this compliance feature exists
  // to catch, not commit. Surfacing it as a 'warning' finding (curated-data
  // problem, not a device problem) is the same tri-state-conservative
  // instinct CLAUDE.md already applies to applicability.js's own 'unknown'
  // handling: when genuinely unsure, never resolve to a definite pass/fail.
  if (passWhen !== 'yes' && passWhen !== 'no') {
    return {
      status: 'warning',
      detail: `Check "${check.name}" (${check.check_id}) has an invalid or missing pass_when in its predicate_config — cannot determine pass/fail polarity. This is a problem with the check definition, not this device.`,
    };
  }

  const result = evaluatePredicate(predicateType, predicateConfig, configParsed);
  const status = statusFromResult(result, passWhen);

  let detail;
  if (status === 'warning') {
    detail = `Could not determine "${check.name}" from this device's collected configuration (predicate "${predicateType}" resolved to unknown).`;
  } else if (status === 'pass') {
    detail = `"${check.name}" passed.`;
  } else {
    detail = `"${check.name}" failed — expected the "${predicateType}" predicate to resolve to "${passWhen}", got "${result}".`;
  }

  return { status, detail };
}

/**
 * Evaluate one 'rule_scan' audit_checks row against a device's CURRENT
 * rule_analysis_results (already bucketed by finding_type by the caller —
 * see loadRuleFindingsByType()). Distinct from evaluateCheck() above:
 * evaluatePredicate() only ever sees one fixed dot-path into
 * device_configs.config_parsed and has no "for every rule" concept at all
 * (see lib/auditChecksSeed.js's own header comment on
 * not_evaluable_from_config reason (b) for why that gap existed). A
 * rule_scan check instead asks "does ANY rule on this device carry one of
 * these Phase 5 finding_types" — reusing ruleAnalysis.js's ALREADY-DECIDED
 * findings rather than re-implementing per-rule detection logic a second
 * time here, same "reuse, don't duplicate" instinct as this file's own
 * header comment for evaluatePredicate().
 *
 * Fixed polarity, no pass_when: every rule_scan check today is a "this bad
 * pattern should not exist" check, so zero matches is always PASS. A
 * predicate_config with an empty/missing finding_types list is treated as a
 * curated-data problem (same 'warning' treatment as evaluateCheck()'s
 * invalid-pass_when guard above) rather than a vacuous automatic PASS.
 *
 * Never throws — matches evaluateCheck()'s contract.
 *
 * @param {object} check - audit_checks row
 * @param {Record<string, string[]>} ruleFindingsByType - finding_type -> rule_id[]
 * @returns {{status: 'pass'|'fail'|'warning', detail: string, matchedRuleIds: string[]}}
 */
function evaluateRuleScanCheck(check, ruleFindingsByType) {
  const predicateConfig = check.predicate_config || {};
  const types = Array.isArray(predicateConfig.finding_types) ? predicateConfig.finding_types : [];

  if (types.length === 0) {
    return {
      status: 'warning',
      detail: `Check "${check.name}" (${check.check_id}) has no finding_types in its predicate_config — cannot determine which rule findings to scan for. This is a problem with the check definition, not this device.`,
      matchedRuleIds: [],
    };
  }

  const seen = new Set();
  const matchedRuleIds = [];
  for (const type of types) {
    for (const ruleId of ruleFindingsByType[type] || []) {
      if (!seen.has(ruleId)) {
        seen.add(ruleId);
        matchedRuleIds.push(ruleId);
      }
    }
  }

  if (matchedRuleIds.length === 0) {
    return {
      status: 'pass',
      detail: `"${check.name}" passed — no rules on this device matched (${types.join(', ')}).`,
      matchedRuleIds: [],
    };
  }

  return {
    status: 'fail',
    detail: `"${check.name}" failed — ${matchedRuleIds.length} rule(s) matched (${types.join(', ')}). See the matched rules below for the specific offending policies.`,
    matchedRuleIds,
  };
}

/**
 * Bulk-load a device's current rule_analysis_results, bucketed by
 * finding_type -> [rule_id, ...]. One query for every rule_scan check to
 * share, rather than a per-check query — mirrors evaluateCheck()'s single
 * getLatestConfigParsed() call for config-predicate checks.
 *
 * @param {string} deviceId
 * @param {import('pg').Pool} pool
 * @returns {Promise<Record<string, string[]>>}
 */
async function loadRuleFindingsByType(deviceId, pool) {
  const { rows } = await pool.query(
    'SELECT finding_type, rule_id FROM rule_analysis_results WHERE device_id = $1',
    [deviceId]
  );
  const map = {};
  for (const row of rows) {
    if (!map[row.finding_type]) map[row.finding_type] = [];
    map[row.finding_type].push(row.rule_id);
  }
  return map;
}

/**
 * Run the compliance audit for one device: load the device + its applicable
 * checks + its latest parsed config + its current rule findings, evaluate
 * every check, and rewrite that device's audit_findings rows inside one
 * transaction.
 *
 * @param {string} deviceId
 * @param {import('pg').Pool} pool
 * @returns {Promise<{findings: object[]}>}
 */
async function runComplianceAuditForDevice(deviceId, pool) {
  const { rows: deviceRows } = await pool.query('SELECT id, vendor FROM devices WHERE id = $1', [
    deviceId,
  ]);
  if (deviceRows.length === 0) {
    throw new Error(`Device not found: ${deviceId}`);
  }
  const device = deviceRows[0];

  const configParsed = await getLatestConfigParsed(deviceId, pool);

  const { rows: checks } = await pool.query(
    'SELECT * FROM audit_checks WHERE vendor IS NULL OR vendor = $1 ORDER BY name ASC',
    [device.vendor]
  );

  const usable = hasUsableConfig(configParsed);

  // rule_scan checks don't need device_configs.config_parsed at all — they
  // need firewall_rules to exist. Counted once (not "usable", a different
  // input) so a device with rules but no successful config pull yet still
  // gets real rule_scan results instead of a blanket 'na'.
  const { rows: ruleCountRows } = await pool.query(
    'SELECT COUNT(*)::int AS count FROM firewall_rules WHERE device_id = $1',
    [deviceId]
  );
  const ruleCount = ruleCountRows[0] ? ruleCountRows[0].count : 0;
  const ruleFindingsByType = ruleCount > 0 ? await loadRuleFindingsByType(deviceId, pool) : {};

  const evaluated = checks.map((check) => {
    const predicateType = (check.predicate_config || {}).predicate_type;

    if (predicateType === 'rule_scan') {
      if (ruleCount === 0) {
        return {
          check,
          status: 'na',
          detail: 'No rules collected yet.',
          matchedRuleIds: [],
        };
      }
      const { status, detail, matchedRuleIds } = evaluateRuleScanCheck(check, ruleFindingsByType);
      return { check, status, detail, matchedRuleIds };
    }

    if (!usable) {
      return {
        check,
        status: 'na',
        detail: 'No device configuration collected yet.',
        matchedRuleIds: [],
      };
    }
    const { status, detail } = evaluateCheck(check, configParsed);
    return { check, status, detail, matchedRuleIds: [] };
  });

  const client = await pool.connect();
  let inserted = [];
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM audit_findings WHERE device_id = $1', [deviceId]);

    for (const item of evaluated) {
      const { rows } = await client.query(
        `INSERT INTO audit_findings (device_id, check_id, status, detail, matched_rule_ids)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, device_id, check_id, status, detail, matched_rule_ids, detected_at`,
        [
          deviceId,
          item.check.id,
          item.status,
          item.detail,
          item.matchedRuleIds && item.matchedRuleIds.length ? item.matchedRuleIds : null,
        ]
      );
      inserted.push({
        ...rows[0],
        check_id_slug: item.check.check_id,
        name: item.check.name,
        standards: item.check.standards,
        severity: item.check.severity,
        remediation_guidance: item.check.remediation_guidance,
      });
    }

    await client.query('COMMIT');
  } catch (txErr) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      // ignore — the client is being released either way
    }
    throw txErr;
  } finally {
    // ALWAYS release, or the pool leaks a client per failed audit run.
    client.release();
  }

  return { findings: inserted };
}

module.exports = {
  runComplianceAuditForDevice,
  evaluateCheck,
  evaluateRuleScanCheck,
  statusFromResult,
};
