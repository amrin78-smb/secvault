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
// Imported (not re-derived) so this file and ruleAnalysis.js can never disagree about WHICH
// finding types the O(n^2) cap skips, or about where that cap sits -- see
// evaluateRuleScanCheck()'s skippedFindingTypes handling below.
const { skippedPairwiseFindingTypes } = require('./ruleAnalysis');

// The one predicate_type that means "SecVault cannot ask this question of any
// device", as opposed to "the answer is uncertain on this device". Declared
// here rather than inline so the seed file and the evaluator cannot drift on
// the spelling -- lib/auditChecksSeed.js uses the same literal.
const NOT_EVALUABLE_PREDICATE = 'not_evaluable_from_config';

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
 * @returns {{status: 'pass'|'fail'|'warning'|'na', detail: string}}
 */
function evaluateCheck(check, configParsed) {
  const predicateConfig = check.predicate_config || {};
  const predicateType = predicateConfig.predicate_type;
  const passWhen = predicateConfig.pass_when;

  // ⛔ Declared unanswerable BY CONSTRUCTION -> `na`, not `warning`.
  //
  // See CLAUDE.md's "`warning` vs `na` -- whose limitation is it?". A
  // `warning` says something about THIS DEVICE (we asked a real question of
  // a config we collected and got an indeterminate answer) and so belongs in
  // the score denominator. These checks say something about SECVAULT: the
  // question cannot be posed at all, and nothing an operator changes on the
  // firewall would make it answerable -- the fact is inherently per-rule
  // while the predicate engine supports one fixed dot-path, or it needs
  // telemetry a static config snapshot never contains.
  //
  // Until 2026-08-25 these fell through to evaluatePredicate()'s
  // `default: return 'unknown'` and became warnings, so 43 of the fleet's 61
  // warnings were SecVault's own coverage gap scored against the customer's
  // devices -- the same error as hit_count's old NOT NULL DEFAULT 0.
  //
  // Handled BEFORE the pass_when guard below on purpose: these checks carry a
  // placeholder pass_when that is never consulted, so validating a polarity
  // that cannot be applied would be noise. The finding is still written and
  // still shown WITH its reason -- `na` removes it from the score, never
  // from the operator, who still needs it on the manual-verification list.
  if (predicateType === NOT_EVALUABLE_PREDICATE) {
    const reason = predicateConfig.reason;
    return {
      status: 'na',
      detail:
        `"${check.name}" cannot be determined from a configuration snapshot, so it is excluded ` +
        'from the compliance score rather than counted against this device. ' +
        (reason ? `Reason: ${reason} ` : '') +
        'Verify it manually.',
    };
  }

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
 * ⛔ `na` GUARD ADDED 2026-09-09 -- the third parameter, and the reason it exists.
 *
 * "Zero rules carry this finding type" has TWO causes and they are not the same answer:
 * ruleAnalysis.js ran the pass and found nothing, or ruleAnalysis.js NEVER RAN THE PASS.
 * Above `maxRulesForShadow` (1000) it skips the whole O(n^2) block -- shadow, redundant,
 * correlation, generalization, reorder_candidate -- and until now left only a console.warn
 * behind. `rule-no-shadowed-rules` and `rule-no-redundant-rules` scan exactly those types, so
 * a device with more than 1000 rules scored PASS on both and was CREDITED in the compliance
 * denominator for an analysis SecVault deliberately declined to run.
 *
 * That is the `warning`/`na` distinction inverted into a full pass. The correct state is `na`:
 * this is a fact about SECVAULT (our own O(n^2) cap), not about the device -- nothing the
 * operator changes on the firewall makes the question answerable -- so it leaves the
 * denominator entirely rather than counting as a free point. `warning` would be wrong too: it
 * would score the device down for our limitation, the mirror of the same error.
 *
 * Latent today: the largest live ruleset is IDC FW at 706 rules, 70% of the cap.
 *
 * @param {object} check - audit_checks row
 * @param {Record<string, string[]>} ruleFindingsByType - finding_type -> rule_id[]
 * @param {string[]} [skippedFindingTypes] - finding types NOT COMPUTED for this device
 * @returns {{status: 'pass'|'fail'|'warning'|'na', detail: string, matchedRuleIds: string[]}}
 */
function evaluateRuleScanCheck(check, ruleFindingsByType, skippedFindingTypes) {
  const predicateConfig = check.predicate_config || {};
  const types = Array.isArray(predicateConfig.finding_types) ? predicateConfig.finding_types : [];

  const skipped = Array.isArray(skippedFindingTypes) ? new Set(skippedFindingTypes) : new Set();
  const notMeasured = types.filter((type) => skipped.has(type));
  // ANY intersection is enough. A check scanning [shadow, redundant] where only `shadow` was
  // skipped still cannot honestly report "no rules matched" -- half the question went unasked,
  // and a partial answer presented as a whole one is the failure this guard exists to prevent.
  if (types.length > 0 && notMeasured.length > 0) {
    return {
      status: 'na',
      detail:
        `"${check.name}" could not be evaluated — SecVault did not run the ${notMeasured.join(', ')} ` +
        'analysis on this device (its ruleset is above the pairwise-analysis size cap), so zero ' +
        'matching findings means NOT MEASURED, not clean. Excluded from the compliance score ' +
        'rather than counted as a pass.',
      matchedRuleIds: [],
    };
  }

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
  // ⛔ `null` = THE READ FAILED; `{}` = it succeeded and nothing is classified.
  // Collapsing them printed "this device's zones haven't been classified yet"
  // on a device whose zones may all be classified — our failure reported as
  // the operator's omission. Same distinction evaluateRulePropertyCheck makes.
  if (zoneRoleMap === null || zoneRoleMap === undefined) {
    return {
      status: 'na',
      detail: `"${check.name}" could not be evaluated — SecVault could not read this device's `
        + 'zone classifications, so it could not tell which zones are External and which are '
        + 'Internal. This is a SecVault-side read failure, not a gap in this firewall\'s '
        + 'configuration, and it says nothing about whether the check would pass.',
      matchedRuleIds: [],
    };
  }
  const deviceZones = collectDeviceZoneNames(rules);
  // ⛔ Keys NORMALISED the same way collectDeviceZoneNames normalises the rule
  // side. `zone_classifications.zone_name` is operator-typed, so an untrimmed
  // key never matched a trimmed rule zone and the check silently reported "not
  // classified" on a device that was.
  const roles = {};
  for (const [zone, role] of Object.entries(zoneRoleMap || {})) {
    roles[normZone(zone)] = String(role).trim().toLowerCase();
  }
  let hasExternal = false;
  let hasInternal = false;
  for (const z of deviceZones) {
    if (roles[z] === 'external') hasExternal = true;
    if (roles[z] === 'internal') hasInternal = true;
  }

  if (!hasExternal || !hasInternal) {
    return {
      status: 'na',
      detail: `"${check.name}" could not be evaluated — this device's zones haven't been classified as both External and Internal yet (see this device's Manage tab).`,
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

// ─────────────────────────────────────────────────────────────────────────
// 'rule_property' — the FOURTH evaluator shape, added v2.167.0.
//
// ⛔ IT EXISTS BECAUSE "one fixed dot-path" WAS THE ROOT CAUSE OF `na`.
// Three checks were declared `not_evaluable_from_config` for the same
// structural reason: the fact they ask about is attached to EVERY RULE, and
// the predicate engine could only follow one fixed path into
// `device_configs.config_parsed`. `rule_scan` reuses already-decided Phase 5
// findings; `ruleset_property` asks "does at least one rule exist with
// property X" — an EXISTENTIAL question. This is the missing UNIVERSAL one:
// "does every rule the question applies to carry property Y".
//
// ⛔ THE DATA WAS ALREADY COLLECTED AND WAS NEVER LOOKED AT. `raw_rule` is the
// verbatim vendor rule object (`raw_rule: entry` in the PAN-OS parser, the
// unmodified parsed element). Measured on the live fleet 2026-09-22:
//
//   1,586 Palo Alto rules — 1,063 carry `profile-setting`
//                             (975 individual `profiles`, 88 a `group`)
//     181 Fortinet rules   —    36 carry `ips-sensor`, 45 `utm-status`
//
// So the answer was sitting in a JSONB column on a table this engine already
// queries. What was missing was a question shape that could reach it.
//
// ⛔ ABSENCE IS ONLY A FINDING WHEN ABSENCE IS A FACT. This is the whole
// correctness argument and it is not uniform across rules. On PAN-OS a rule
// with no `profile-setting` element genuinely has no security profiles — the
// device did not omit it, it does not exist. But 33 of those 1,586 rules carry
// `@_panorama`: they were PUSHED FROM PANORAMA, and a profile GROUP attached
// there is not visible in this device's own config. Reading those 33 the same
// way would manufacture 33 findings out of a place we cannot see, which is
// this codebase's signature bug with a new hat on. They are UNDECIDABLE,
// counted, named, and never scored as compliant either.

const RULE_PROPERTY_PREDICATE = 'rule_property';

// Dot-path read over a rule's raw_rule. Deliberately NOT applicability.js's
// getByPath: that one walks `config_parsed` and is shared with the CVE
// engine, and widening its contract for this would couple two engines that
// have no reason to move together (the same call ruleset_property's own
// duplicated isAnyField/isDenyAction helpers make).
function rawRuleValue(rawRule, path) {
  if (!rawRule || typeof rawRule !== 'object') return undefined;
  let cur = rawRule;
  for (const seg of String(path).split('.')) {
    if (cur === null || typeof cur !== 'object' || Array.isArray(cur)) return undefined;
    if (!Object.prototype.hasOwnProperty.call(cur, seg)) return undefined;
    cur = cur[seg];
  }
  return cur;
}

// ⛔ PRESENT-BUT-EMPTY IS NOT SET. A vendor emitting `profile-setting: {}` or
// `ips-sensor: ""` has told us the field exists and carries nothing, which is
// the same posture as omitting it — and reading it as "configured" would turn
// an empty element into a pass. Mirrors hasUsableConfig()'s treatment of `{}`.
function isSetValue(v) {
  if (v === undefined || v === null) return false;
  // ⛔ AN EXPLICIT `false` IS OFF, NOT CONFIGURED. This fell through to the
  // `return true` below, so a vendor boolean flag at a required path passed the
  // check while naming a feature that is switched off.
  //
  // ⛔ A NUMERIC 0 IS LEFT AS SET, deliberately. 0 is a real value for a real
  // field (a metric, a priority) and refusing it would invent a meaning the
  // vendor did not give it. A vendor "off" STRING ('disable', 'no') is also
  // left as set, because this predicate asks whether a value is PRESENT, not
  // whether a feature is enabled — a check that needs enablement semantics
  // must say so in its own paths, and one that guessed would fail a profile
  // legitimately named "disable".
  if (v === false) return false;
  if (typeof v === 'string') return v.trim() !== '';
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === 'object') return Object.keys(v).length > 0;
  return true;
}

// ⛔ TRIM, NOT JUST LOWER-CASE. `zone_classifications.zone_name` is typed by an
// operator and `firewall_rules.src_zones` comes verbatim off the device, so one
// stray leading/trailing space on either side made the two sets disjoint — and
// a zone-scoped check whose requiredZones match NOTHING silently removes every
// rule from its own scope and reports `na` ("nothing to assess") on a firewall
// that has plenty. Lower-casing without trimming fixed the easy half of the
// same problem and left the invisible half.
const normZone = (z) => String(z).trim().toLowerCase();

function zoneNamesWithRole(zoneRoleMap, role) {
  const out = new Set();
  for (const [zone, r] of Object.entries(zoneRoleMap || {})) {
    if (String(r).trim().toLowerCase() === String(role).trim().toLowerCase()) out.add(normZone(zone));
  }
  return out;
}

function ruleZoneList(rule, field) {
  const raw = rule[field];
  if (Array.isArray(raw)) return raw.map(normZone).filter((z) => z.length > 0);
  if (typeof raw === 'string' && raw.trim()) return [normZone(raw)];
  return [];
}

// The `applies_to` keys this evaluator actually reads. ⛔ AN UNRECOGNISED KEY IS
// A CURATED-DATA PROBLEM AND MUST SAY SO, never be dropped. `applies_to` is the
// SCOPE of the question, so a typo there does not narrow the check — it WIDENS
// it, silently, and the engine then returns a confident pass/fail for a
// different question than the one the check's name promises. Measured shape of
// the damage: `dst_zone_role` written for `src_zone_role` turns an
// internet-facing check into "every enabled allow rule", which on a 447-rule
// Palo Alto is a 415-violation `fail` with nothing on screen saying the scope
// was never applied. Every other evaluator in this file already treats a
// malformed predicate_config as `warning`; this one silently ignored it.
const APPLIES_TO_KEYS = new Set(['enabled_only', 'action', 'src_zone_role']);

// ⛔ THE UNDECIDABLE MARKER MUST ITSELF BE OBSERVABLE, OR THE GUARD IS INERT.
// `undecidable_when_key: '@_panorama'` is an XML ATTRIBUTE, and the `@_` prefix
// exists only because the API transport parses XML with
// `attributeNamePrefix: '@_'`. The PAN-OS SSH transport builds `raw_rule` from a
// brace-parsed config and produces NO `@_*` key at all — while still collecting
// `pre-rulebase`/`post-rulebase`, i.e. Panorama-pushed rules, carrying no origin
// marker. Same firewall, same rules: over `api` those rules are undecidable, over
// `ssh` they are named as definite failures. That is a finding manufactured from
// a place SecVault cannot see, on one of two supported transports, silently.
//
// It cannot be repaired here — the marker is a COLLECTION fact, and no amount of
// reasoning over rows that never carried it will put it back. What this file can
// do is refuse the false certainty: when the marker's whole namespace is absent
// from every rule read, the finding says so instead of asserting an exact count.
//
// ⛔ THE TEST IS ON THE NAMESPACE, NOT ON THE KEY. "No rule carries `@_panorama`"
// is a perfectly normal, correct answer (a firewall with no pushed rules), so it
// cannot be the trigger. "No rule carries ANY `@_*` key" is a different
// statement: the metadata CHANNEL is missing, which is only ever true when the
// transport does not report it. A plain-named marker has no separate channel —
// the vendor object was captured verbatim and simply does not carry the key —
// so it is treated as observable and attracts no caveat.
const MARKER_PREFIX = /^[^A-Za-z0-9]+/;
function markerFamilyPrefix(key) {
  const m = MARKER_PREFIX.exec(String(key));
  return m ? m[0] : null;
}

/**
 * Evaluate one 'rule_property' check against a device's CURRENT firewall_rules.
 *
 * @returns {{status, detail, matchedRuleIds}}
 */
function evaluateRulePropertyCheck(check, rules, zoneRoleMap) {
  const cfg = check.predicate_config || {};
  const paths = Array.isArray(cfg.require_any_path) ? cfg.require_any_path.filter(Boolean) : [];
  // ⛔ `require_all_path` EXISTS BECAUSE ONE VENDOR FACT NEEDS TWO FIELDS.
  // On FortiOS a UTM profile only applies when `set utm-status enable`, and
  // `show` omits fields left at their default (which is disable). So an
  // `ips-sensor` on its own says a sensor is NAMED, not that it is ACTIVE, and
  // a check called "IPS profile applied" that passed on the name alone would
  // be a false all-clear on an inactive sensor.
  const allPaths = Array.isArray(cfg.require_all_path) ? cfg.require_all_path.filter(Boolean) : [];
  // A curated-data problem, not a device problem — `warning`, the same
  // treatment this file's other evaluators give a malformed predicate_config.
  if (paths.length === 0 && allPaths.length === 0) {
    return {
      status: 'warning',
      detail: `"${check.name}" declares no rule property to look for, so it could not be evaluated. `
        + 'This is a problem with the check definition, not with this firewall.',
      matchedRuleIds: [],
    };
  }

  // ⛔ ABSENT is fine and common — plenty of checks ask about every rule. PRESENT
  // BUT MALFORMED is not: it is a declared scope that cannot be applied, which
  // is the same curated-data problem as an unrecognised key below.
  const scopeDeclared = cfg.applies_to !== undefined && cfg.applies_to !== null;
  const scopeIsObject = scopeDeclared
    && typeof cfg.applies_to === 'object' && !Array.isArray(cfg.applies_to);
  if (scopeDeclared && !scopeIsObject) {
    return {
      status: 'warning',
      detail: `"${check.name}" could not be evaluated — its definition declares an `
        + 'applies_to scope that SecVault could not read, so the scope could not be applied. '
        + 'Evaluating it anyway would answer a wider question than this check asks. This is a '
        + 'problem with the check definition, not with this firewall.',
      matchedRuleIds: [],
    };
  }
  const appliesTo = scopeIsObject ? cfg.applies_to : {};
  const subject = cfg.subject || 'the required setting';

  // ⛔ AN UNRECOGNISED SCOPE KEY IS REFUSED, NOT IGNORED. See APPLIES_TO_KEYS:
  // dropping it does not narrow the question, it widens it, and the engine then
  // answers a different question under this check's name with full confidence.
  const unknownScopeKeys = Object.keys(appliesTo).filter((k) => !APPLIES_TO_KEYS.has(k));
  if (unknownScopeKeys.length > 0) {
    return {
      status: 'warning',
      detail: `"${check.name}" could not be evaluated — its definition scopes the question with `
        + `${unknownScopeKeys.map((k) => `"${k}"`).join(', ')}, which SecVault does not recognise, `
        + 'so the scope could not be applied. Evaluating it anyway would answer a wider question '
        + 'than this check asks. This is a problem with the check definition, not with this firewall.',
      matchedRuleIds: [],
    };
  }

  // ⛔ A ZONE-SCOPED QUESTION NEEDS OPERATOR-SUPPLIED ZONE ROLES, AND SAYING SO
  // IS THE POINT. Only 5 of the reference fleet's 16 firewalls have their zones
  // classified. Guessing which zone faces the internet from its NAME would be
  // the "documentation lies" trap applied to a customer's own naming, and
  // silently widening the question to every rule would answer a DIFFERENT
  // question under this check's name. So it is `na` — but with a reason naming
  // the missing input, which is a thing the operator can fix in a few minutes.
  // That is a materially better `na` than "cannot be determined, by
  // construction", which is what this check reported before and which nobody
  // could ever act on.
  let requiredZones = null;
  if (appliesTo.src_zone_role) {
    // ⛔ AN UNREADABLE ZONE MAP IS NOT AN UNCLASSIFIED ONE, AND THE TWO MUST NOT
    // SHARE A SENTENCE. `null` means the zone-classification read FAILED;
    // `{}` means it succeeded and this device has no classifications yet. Until
    // now both arrived here as `{}` and produced "none of this firewall's zones
    // have been classified... Classify this device's zones" — an instruction
    // blaming the operator, printed on a device whose zones may all be
    // classified, on the strength of a read WE could not complete. That is a
    // failed read rendered as a definite fact about the customer's firewall.
    if (zoneRoleMap === null || zoneRoleMap === undefined) {
      return {
        status: 'na',
        detail: `"${check.name}" applies only to rules arriving from an `
          + `${appliesTo.src_zone_role} zone, and SecVault could not read this device's zone `
          + 'classifications, so it could not tell which rules those are. This is a SecVault-side '
          + 'read failure, not a gap in this firewall\'s configuration, and it says nothing about '
          + 'whether the check would pass. It is excluded from the score; re-run the audit once '
          + 'the classifications can be read.',
        matchedRuleIds: [],
      };
    }
    requiredZones = zoneNamesWithRole(zoneRoleMap, appliesTo.src_zone_role);
    if (requiredZones.size === 0) {
      return {
        status: 'na',
        detail: `"${check.name}" applies only to rules arriving from an `
          + `${appliesTo.src_zone_role} zone, and none of this firewall's zones have been `
          + `classified as ${appliesTo.src_zone_role} yet. Classify this device's zones to have `
          + 'this check evaluated — until then it is excluded from the score rather than '
          + 'counted against the device.',
        matchedRuleIds: [],
      };
    }
  }

  const undecidableKey = typeof cfg.undecidable_when_key === 'string' ? cfg.undecidable_when_key : null;
  const markerFamily = undecidableKey ? markerFamilyPrefix(undecidableKey) : null;
  // Set the moment ONE applicable rule is seen carrying a key from the marker's
  // namespace — proof the transport reports that namespace at all.
  let markerFamilySeen = false;

  const violations = [];
  const undecidable = [];
  let applicable = 0;

  for (const rule of rules) {
    if (appliesTo.enabled_only !== false && rule.enabled === false) continue;
    if (appliesTo.action && String(rule.action || '').toLowerCase() !== String(appliesTo.action).toLowerCase()) continue;
    if (requiredZones) {
      const zones = ruleZoneList(rule, 'src_zones');
      // `any` matches every zone, so a rule with an unconstrained source DOES
      // include the external one — matching it literally would understate
      // exposure, the dangerous direction on a security report (the same call
      // segmentation.js makes about `any`).
      //
      // ⛔ AN EMPTY OR ABSENT ZONE LIST IS UNCONSTRAINED FOR THE SAME REASON,
      // and this is the half that was missing. `firewall_rules.src_zones` is
      // NULLABLE, and a rule whose source zone the device did not report was
      // neither treated as unconstrained NOR counted as undecidable — it fell
      // out of the applicable set entirely, disclosed nowhere. An internet-edge
      // policy with no IPS and a missing srcintf therefore took the whole check
      // to `na` ("nothing to assess") instead of `fail`: a rule vanishing from
      // its own scope, which is a silent under-report on a security report. The
      // same call segmentation.js already makes about an empty zone list.
      const unconstrained = zones.length === 0 || zones.some((z) => z === 'any' || z === 'all');
      if (!unconstrained && !zones.some((z) => requiredZones.has(z))) continue;
    }
    applicable += 1;

    const raw = rule.raw_rule;
    // ⛔ NO raw_rule IS NOT "NO PROFILE". An adapter that could not supply the
    // verbatim rule tells us nothing about what is on it.
    if (!raw || typeof raw !== 'object') {
      undecidable.push({ rule, why: 'the vendor rule was not captured for it' });
      continue;
    }
    if (markerFamily && !markerFamilySeen
      && Object.keys(raw).some((k) => k.startsWith(markerFamily))) {
      markerFamilySeen = true;
    }
    if (undecidableKey && Object.prototype.hasOwnProperty.call(raw, undecidableKey)) {
      undecidable.push({ rule, why: cfg.undecidable_reason || 'it is managed elsewhere' });
      continue;
    }
    const anyOk = paths.length === 0 || paths.some((p) => isSetValue(rawRuleValue(raw, p)));
    const allOk = allPaths.every((p) => isSetValue(rawRuleValue(raw, p)));
    if (!anyOk || !allOk) violations.push(rule);
  }

  // ⛔ THE GUARD RAN AND COULD NEVER HAVE FIRED. See MARKER_PREFIX above: the
  // marker's whole namespace is absent from every rule read, so "no rule is
  // managed elsewhere" is not something this device told us — it is something
  // this transport cannot say. Stated, not silently assumed away.
  const markerInert = Boolean(markerFamily) && applicable > 0 && !markerFamilySeen;
  const inertNote = markerInert
    ? ' SecVault could not tell which of these rules are managed from a central manager: '
      + 'none of this firewall\'s collected rules carry any origin metadata, which is a limit of '
      + 'the collection method in use here rather than a statement about the rules. Any of them '
      + `may carry ${subject} attached somewhere this firewall cannot see, so treat the count as `
      + 'an upper bound and verify before acting on it.'
    : '';

  const idOf = (r) => r.id;
  const nameList = (list, n = 3) => list.slice(0, n)
    .map((x) => (x.rule || x).rule_name || (x.rule || x).rule_id_vendor || 'unnamed')
    .join(', ');
  const undecidableNote = undecidable.length
    ? ` ${undecidable.length} further rule(s) could not be judged (${undecidable[0].why}): `
      + `${nameList(undecidable)}${undecidable.length > 3 ? ', …' : ''}.`
    : '';

  // ⛔ NOTHING TO ASSESS IS `na`, NEVER `pass`. A firewall with no rules of this
  // kind has not demonstrated anything, and "0 of 0 rules are missing a
  // profile" rendered as a pass is a clean score computed from an empty set —
  // the same reason no_external_to_internal_access refuses that shape.
  if (applicable === 0) {
    return {
      status: 'na',
      detail: `"${check.name}" found no rules of the kind it asks about on this firewall, so there `
        + 'was nothing to assess. It is excluded from the score rather than counted as a pass.',
      matchedRuleIds: [],
    };
  }

  // ⛔ A DEFINITE VIOLATION OUTRANKS AN UNDECIDABLE ONE. Rules we cannot judge
  // must not suppress rules we can: reporting `warning` while 490 rules
  // definitely lack a profile would bury a real finding behind a caveat.
  if (violations.length > 0) {
    return {
      status: 'fail',
      // ⛔ The count is still reported and the rules are still named — a real
      // absence observed on a real rule is a real finding, and burying it
      // behind a caveat is the mistake `undecidableNote` already refuses to
      // make. What `inertNote` removes is the CERTAINTY, not the finding.
      detail: `"${check.name}" failed — ${violations.length} of ${applicable} applicable rule(s) `
        + `are missing ${subject}: ${nameList(violations)}${violations.length > 3 ? ', …' : ''}.`
        + undecidableNote + inertNote,
      matchedRuleIds: violations.map(idOf).filter(Boolean),
      originMarkerUnobservable: markerInert,
    };
  }

  // ⛔ AN ALL-CLEAR IS FORBIDDEN WHILE COVERAGE IS INCOMPLETE — the rule
  // lib/evidence.js enforces product-wide. Every rule we COULD judge carries
  // the setting, but some we could not, so this is not a pass.
  if (undecidable.length > 0) {
    return {
      status: 'warning',
      detail: `"${check.name}" — every rule that could be checked carries ${subject}, but `
        + `${undecidable.length} of ${applicable} could not be judged`
        + `${undecidable[0] ? ` (${undecidable[0].why})` : ''}: `
        + `${nameList(undecidable)}${undecidable.length > 3 ? ', …' : ''}. `
        + 'Verify those manually before treating this as clean.',
      matchedRuleIds: undecidable.map((u) => idOf(u.rule)).filter(Boolean),
      originMarkerUnobservable: markerInert,
    };
  }

  // ⛔ A PASS CARRIES NO inertNote ON PURPOSE. Every applicable rule was read and
  // every one of them carries the setting — whether some were pushed from a
  // central manager changes nothing about that, because the thing being asserted
  // is presence, and presence was observed. The inert marker only ever weakens a
  // claim about ABSENCE.
  return {
    status: 'pass',
    detail: `"${check.name}" passed — all ${applicable} applicable rule(s) carry ${subject}.`,
    matchedRuleIds: [],
    originMarkerUnobservable: markerInert,
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

  // ⛔ Which Phase 5 passes ruleAnalysis.js would NOT have run for a ruleset this size. Derived
  // from the same helper and the same cap as the producer, because rule_analysis_results itself
  // cannot tell "the pass ran and found nothing" from "the pass never ran" -- both are zero
  // rows. See evaluateRuleScanCheck()'s header for the compliance-PASS bug this closes.
  const skippedFindingTypes = skippedPairwiseFindingTypes(ruleCount);

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
      // ⛔ `raw_rule` IS THE VERBATIM VENDOR RULE and is what makes
      // 'rule_property' possible at all -- the per-rule facts three checks were
      // declared unanswerable for were already in this column. `id`/`rule_name`
      // are for naming the offenders in the finding, not decoration: "12 rules
      // have no security profile" without saying WHICH is not actionable.
      `SELECT id, rule_name, rule_id_vendor, action, src_addresses, dst_addresses,
              services, enabled, src_zones, dst_zones, raw_rule
         FROM firewall_rules WHERE device_id = $1`,
      [deviceId]
    );
    rulesForPropertyChecks = rows;
  }

  // Best-effort: a zone-classification load failure must never block the rest of
  // the compliance audit.
  //
  // ⛔ BUT IT IS REPORTED AS A FAILURE, NOT AS AN EMPTY MAP. This used to leave
  // `{}` behind, which every zone-dependent evaluator reads as "this device has
  // no classified zones" — so the finding told the operator to go and classify
  // zones that may already all be classified, on the strength of a read SecVault
  // could not complete. A failed read recorded as a fact about the device, and
  // the most misleading kind: one that hands the customer an action item for our
  // own outage. `null` is the unreadable state and the evaluators say so.
  let zoneRoleMap = null;
  try {
    zoneRoleMap = await getZoneRoleMap(deviceId, pool);
    // ⛔ A loader returning a non-object is not an empty classification set.
    if (!zoneRoleMap || typeof zoneRoleMap !== 'object' || Array.isArray(zoneRoleMap)) {
      zoneRoleMap = null;
    }
  } catch (err) {
    console.warn(`[configAuditor] Failed to load zone classifications: ${err.message}`);
    zoneRoleMap = null;
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
      const { status, detail, matchedRuleIds } = evaluateRuleScanCheck(
        check,
        ruleFindingsByType,
        skippedFindingTypes
      );
      return { check, status, detail, matchedRuleIds };
    }

    if (predicateType === RULE_PROPERTY_PREDICATE) {
      if (ruleCount === 0) {
        return {
          check,
          status: 'na',
          detail: 'No rules collected yet.',
          matchedRuleIds: [],
        };
      }
      const r = evaluateRulePropertyCheck(check, rulesForPropertyChecks, zoneRoleMap);
      return { check, status: r.status, detail: r.detail, matchedRuleIds: r.matchedRuleIds || [] };
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
  evaluateRulePropertyCheck,
  RULE_PROPERTY_PREDICATE,
  statusFromResult,
};
