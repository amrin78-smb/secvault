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
const { getZoneRoleMap } = require('./zoneClassification');

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

// ─────────────────────────────────────────────────────────────────────────
// 'ruleset_property' — added 2026-07-18, alongside two new checks
// (rule-has-explicit-deny-all, rule-blocks-icmp) found missing during a
// direct comparison against a competing product's compliance report for
// the SAME real devices. Distinct from BOTH evaluateCheck() (one fixed
// config_parsed path) and evaluateRuleScanCheck() (reuses ALREADY-DECIDED
// Phase 5 findings, "zero matches" is always pass): this is a POSITIVE
// existence check directly against a device's CURRENT firewall_rules rows
// — "does at least one rule matching this pattern exist" — a shape neither
// of the other two evaluators covers. Phase 5's ruleAnalysis.js has no
// equivalent finding_type for either of these two concepts (an explicit
// catch-all deny rule, or a rule specifically blocking ICMP) because Phase
// 5 findings are about flagging PROBLEMS in individual rules, not "the
// whole ruleset lacks property X" — a genuinely different question shape.
//
// Small helpers duplicated here (isAnyField/isDenyAction) rather than
// imported from lib/engines/ruleAnalysis.js — that file's own equivalents
// (isAny/DENY_ACTIONS) are internal, unexported implementation details, and
// this codebase's established convention is to duplicate small per-file
// logic rather than widen another engine's public surface for a two-line
// helper (see CLAUDE.md's Alerts/Compliance query-triplication notes for
// other examples of this same tradeoff).

const DENY_ACTIONS = new Set(['deny', 'drop', 'reject', 'block']);
const ANY_ALIASES = new Set(['any', 'all', 'any4', 'any6']);

// Service-field-only extension of ANY_ALIASES: Cisco ASA ACEs encode
// "all IP protocols" as the literal protocol token `ip` in the services
// field (e.g. `access-list OUTSIDE_IN extended deny ip any any` —
// lib/adapters/cisco_asa/parser.js never normalizes this to the string
// "any"), which is semantically an unrestricted service exactly like "any"
// is for an address field. Found 2026-07-18: without this, the single most
// common real-world ASA explicit-deny-all pattern failed
// hasExplicitDenyAll() because isAnyField(['ip']) returned false — a
// compliant device would report FAIL. Scoped to the SERVICE check only
// (not folded into ANY_ALIASES itself) because "ip"/"ip4"/"ip6" are
// protocol-wildcard tokens, not address wildcards — merging them into the
// shared address-field vocabulary would risk misclassifying an address
// object literally named "ip" as a wildcard. ruleAnalysis.js's own
// any_any finding has the identical blind spot for `permit ip any any`;
// not fixed there in this pass — that has a much wider blast radius
// (every existing ASA shadow/redundant/any_any finding) and needs its own
// independently-verified change, not a side effect of this one.
const SERVICE_ANY_ALIASES = new Set([...ANY_ALIASES, 'ip', 'ip4', 'ip6']);

function isDenyAction(action) {
  const norm = action === null || action === undefined ? '' : String(action).trim().toLowerCase();
  return DENY_ACTIONS.has(norm);
}

// A field is "any" when null/undefined, an empty array (or an array of only
// empty/whitespace entries, matching ruleAnalysis.js's own normList()
// filtering), or contains a recognized wildcard entry — same semantics as
// ruleAnalysis.js's isAny(), duplicated rather than imported (see header
// comment above). `aliases` defaults to ANY_ALIASES; hasExplicitDenyAll()
// passes SERVICE_ANY_ALIASES for the services field specifically.
function isAnyField(list, aliases = ANY_ALIASES) {
  if (list === null || list === undefined) return true;
  if (!Array.isArray(list)) return false;
  const nonEmpty = list.map((item) => String(item).trim()).filter((item) => item.length > 0);
  if (nonEmpty.length === 0) return true;
  return nonEmpty.some((item) => aliases.has(item.toLowerCase()));
}

// "Explicit deny-all" = an ENABLED rule whose action is a deny synonym and
// whose source, destination, AND service are all unrestricted. Deliberately
// does NOT require this to be the LAST rule in sequence — a real policy
// can legitimately have housekeeping/logging rules after its catch-all deny
// (e.g. a final explicit-log rule); what this check verifies is that a
// deliberate catch-all deny exists SOMEWHERE, not its exact position.
function hasExplicitDenyAll(rules) {
  return rules.some(
    (r) =>
      r.enabled !== false &&
      isDenyAction(r.action) &&
      isAnyField(r.src_addresses) &&
      isAnyField(r.dst_addresses) &&
      isAnyField(r.services, SERVICE_ANY_ALIASES)
  );
}

// "Blocks ICMP" = an ENABLED deny-synonym rule whose services field names
// ICMP specifically (a plain case-insensitive substring match against each
// service string — vendors spell this "ICMP"/"icmp"/"ping" inconsistently
// across normalized service names, so a loose match is intentional here,
// same conservative-toward-more-matches instinct as ruleAnalysis.js's own
// risky-service alias matching).
//
// Left-boundary-only match (not \bicmp\b): FortiOS's own default builtin
// service objects are literally named "ALL_ICMP"/"ALL_ICMP6" — `\b` does
// NOT fire between `_` and `I` because underscore is a \w character, so
// the original \bicmp\b pattern silently failed to match FortiOS's own
// out-of-the-box "block all ICMP" object, reporting FAIL on a device that
// was in fact correctly blocking ICMP. `(^|[^a-z])icmp` only requires the
// character immediately before "icmp" to NOT be a letter (start-of-string,
// underscore, digit, hyphen all qualify) — matches "icmp", "ALL_ICMP",
// "ALL_ICMP6", "icmpv6", "ICMP-ALL", while still correctly excluding an
// unrelated service name that merely CONTAINS "icmp" as a non-leading
// letter run (e.g. a hypothetical "richmp" — 'h' before "icmp" is a letter,
// excluded).
const ICMP_PATTERN = /(^|[^a-z])icmp/i;
function blocksIcmp(rules) {
  return rules.some((r) => {
    if (r.enabled === false) return false;
    if (!isDenyAction(r.action)) return false;
    const services = Array.isArray(r.services) ? r.services : [];
    return services.some((s) => ICMP_PATTERN.test(String(s)));
  });
}

// Distinct real (non-wildcard) zone names referenced by ANY of this
// device's rules' src_zones/dst_zones — small, standalone duplicate of the
// same collection logic lib/engines/reachabilityMatrix.js already has (this
// file's own established per-file-duplication convention, not a shared
// import). Only used to answer "does THIS device even have both an
// External-classified and an Internal-classified zone among its own rules"
// — the actual per-rule EXTERNAL-to-INTERNAL detection logic lives ONLY in
// ruleAnalysis.js's external_exposure finding (reused below via
// ruleFindingsByType, never reimplemented here), so this stays a small,
// single-purpose helper rather than a second copy of that detection.
function collectDeviceZoneNames(rules) {
  const set = new Set();
  for (const r of rules) {
    for (const list of [r.src_zones, r.dst_zones]) {
      if (!Array.isArray(list)) continue;
      for (const z of list) {
        const norm = String(z).trim().toLowerCase();
        if (norm && !ANY_ALIASES.has(norm)) set.add(norm);
      }
    }
  }
  return set;
}

/**
 * The 'no_external_to_internal_access' ruleset_property — a THIRD kind of
 * result shape alongside has_explicit_deny_all/blocks_icmp below: those two
 * are boolean "does X exist somewhere" checks with no natural NA state
 * (firewall_rules already being non-empty, per this file's ruleCount===0
 * guard, is all either of them needs to be measurable). This one is
 * different on purpose: it depends on OPERATOR-SUPPLIED zone classification
 * data (see lib/engines/zoneClassification.js) that may not exist yet for
 * this device's own zones — a fresh install, or a device whose zones simply
 * haven't been classified, has genuinely NOTHING to measure here, and must
 * resolve 'na', never a false 'pass'. Reporting "pass" just because zero
 * rules HAPPENED to match, when the real reason is "we can't tell", is
 * exactly the "looks fine, isn't" trap this whole compliance engine's
 * tri-state design exists to prevent — the plain zero-matches-is-pass
 * shape evaluateRuleScanCheck() uses for every OTHER check would be WRONG
 * here specifically, because zone_classifications starts completely empty
 * on every fresh install (unlike e.g. risky_ports, which always has a
 * built-in default), so every device would silently show "pass" fleet-wide
 * from day one, with 100% certainty, until an admin manually classifies at
 * least one zone.
 *
 * Reuses ruleAnalysis.js's ALREADY-COMPUTED external_exposure finding (via
 * ruleFindingsByType, the same bulk-loaded map evaluateRuleScanCheck() uses)
 * for the actual pass/fail decision and matched_rule_ids — this function's
 * only real job is the 'na' pre-check, not re-detecting the exposure a
 * second time.
 *
 * @param {object} check
 * @param {Array<object>} rules - this device's current firewall_rules rows (src_zones/dst_zones only needed)
 * @param {Record<string, string>} zoneRoleMap - zone_name -> 'internal'|'external'|'dmz'
 * @param {Record<string, string[]>} ruleFindingsByType - finding_type -> rule_id[]
 * @returns {{status: 'pass'|'fail'|'na', detail: string, matchedRuleIds: string[]}}
 */
function evaluateExternalToInternalExposure(check, rules, zoneRoleMap, ruleFindingsByType) {
  const deviceZones = collectDeviceZoneNames(rules);
  const roles = zoneRoleMap || {};
  let hasExternal = false;
  let hasInternal = false;
  for (const z of deviceZones) {
    if (roles[z] === 'external') hasExternal = true;
    if (roles[z] === 'internal') hasInternal = true;
  }

  if (!hasExternal || !hasInternal) {
    return {
      status: 'na',
      detail: `"${check.name}" could not be evaluated — this device's zones haven't been classified as both External and Internal yet (Settings > Zones).`,
      matchedRuleIds: [],
    };
  }

  const matchedRuleIds = (ruleFindingsByType || {}).external_exposure || [];
  if (matchedRuleIds.length === 0) {
    return {
      status: 'pass',
      detail: `"${check.name}" passed — no enabled allow rule on this device spans a zone classified External directly to a zone classified Internal.`,
      matchedRuleIds: [],
    };
  }
  return {
    status: 'fail',
    detail: `"${check.name}" failed — ${matchedRuleIds.length} enabled allow rule(s) permit traffic from an External zone directly to an Internal zone. See the matched rules below.`,
    matchedRuleIds,
  };
}

/**
 * Evaluate one 'ruleset_property' audit_checks row against a device's
 * CURRENT firewall_rules rows. No pass_when for the two boolean properties
 * below (same fixed-polarity reasoning as evaluateRuleScanCheck() — every
 * property here is "this should exist", so finding it is always PASS). An
 * unrecognized `property` value is a curated-data problem (same 'warning'
 * treatment as this file's other two evaluators' malformed-config-guards),
 * never a silent false PASS or FAIL.
 *
 * @param {object} check
 * @param {Array<object>} rules - this device's current firewall_rules rows
 * @param {Record<string, string>} [zoneRoleMap] - only used by no_external_to_internal_access
 * @param {Record<string, string[]>} [ruleFindingsByType] - only used by no_external_to_internal_access
 * @returns {{status: 'pass'|'fail'|'warning'|'na', detail: string, matchedRuleIds?: string[]}}
 */
function evaluateRulesetPropertyCheck(check, rules, zoneRoleMap, ruleFindingsByType) {
  const predicateConfig = check.predicate_config || {};
  const property = predicateConfig.property;

  if (property === 'no_external_to_internal_access') {
    return evaluateExternalToInternalExposure(check, rules, zoneRoleMap, ruleFindingsByType);
  }

  let matched;
  if (property === 'has_explicit_deny_all') {
    matched = hasExplicitDenyAll(rules);
  } else if (property === 'blocks_icmp') {
    matched = blocksIcmp(rules);
  } else {
    return {
      status: 'warning',
      detail: `Check "${check.name}" (${check.check_id}) has an unrecognized ruleset_property "${property}" in its predicate_config. This is a problem with the check definition, not this device.`,
    };
  }

  if (matched) {
    return { status: 'pass', detail: `"${check.name}" passed.` };
  }
  return {
    status: 'fail',
    detail: `"${check.name}" failed — no enabled rule on this device matches the required pattern.`,
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

  // ruleset_property checks need actual rule CONTENT (action/addresses/
  // services/zones), not just Phase 5 finding buckets — loaded once, shared
  // by every ruleset_property check, same "one query, not per-check"
  // convention as ruleFindingsByType above. Only fetched when there's
  // actually a rule to look at (ruleCount > 0), same guard. src_zones/
  // dst_zones added alongside the no_external_to_internal_access property —
  // the other two properties (has_explicit_deny_all/blocks_icmp) never read
  // them, unaffected by the wider SELECT.
  let rulesForPropertyChecks = [];
  if (ruleCount > 0) {
    const { rows } = await pool.query(
      'SELECT action, src_addresses, dst_addresses, services, enabled, src_zones, dst_zones FROM firewall_rules WHERE device_id = $1',
      [deviceId]
    );
    rulesForPropertyChecks = rows;
  }

  // Best-effort: a zone-classification load failure must never block the
  // rest of the compliance audit — it just means no_external_to_internal_access
  // resolves 'na' for every device this run (empty map -> collectDeviceZoneNames'
  // hasExternal/hasInternal both false), same fail-safe posture
  // ruleAnalysis.js's own zone-role load already has.
  let zoneRoleMap = {};
  try {
    zoneRoleMap = await getZoneRoleMap(pool);
  } catch (err) {
    console.warn(`[configAuditor] Failed to load zone classifications: ${err.message}`);
  }

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

    if (predicateType === 'ruleset_property') {
      if (ruleCount === 0) {
        return {
          check,
          status: 'na',
          detail: 'No rules collected yet.',
          matchedRuleIds: [],
        };
      }
      const { status, detail, matchedRuleIds } = evaluateRulesetPropertyCheck(
        check,
        rulesForPropertyChecks,
        zoneRoleMap,
        ruleFindingsByType
      );
      return { check, status, detail, matchedRuleIds: matchedRuleIds || [] };
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
  evaluateRulesetPropertyCheck,
  statusFromResult,
};
