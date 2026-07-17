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
 * Run the compliance audit for one device: load the device + its applicable
 * checks + its latest parsed config, evaluate every check, and rewrite that
 * device's audit_findings rows inside one transaction.
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

  const evaluated = checks.map((check) => {
    if (!usable) {
      return {
        check,
        status: 'na',
        detail: 'No device configuration collected yet.',
      };
    }
    const { status, detail } = evaluateCheck(check, configParsed);
    return { check, status, detail };
  });

  const client = await pool.connect();
  let inserted = [];
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM audit_findings WHERE device_id = $1', [deviceId]);

    for (const item of evaluated) {
      const { rows } = await client.query(
        `INSERT INTO audit_findings (device_id, check_id, status, detail)
         VALUES ($1, $2, $3, $4)
         RETURNING id, device_id, check_id, status, detail, detected_at`,
        [deviceId, item.check.id, item.status, item.detail]
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

module.exports = { runComplianceAuditForDevice, evaluateCheck, statusFromResult };
