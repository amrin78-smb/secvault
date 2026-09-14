'use strict';

// lib/engines/segmentation.js
//
// Declared segmentation intent, tested TWO WAYS: can this zone reach that zone
// (the rulebase), and did it (the logs).
//
// ⛔ WHY THIS IS THE DIFFERENTIATOR. Tufin and AlgoSec answer the first half
// with a policy model. Nobody answers the second, because it needs traffic
// evidence joined to the rulebase on the same inventory — which this product
// already has. The valuable cell is the one only this combination can produce:
// a path that is PERMITTED and has carried NO TRAFFIC. That is a standing hole
// with no business justification and the safest possible thing to close, and it
// is a segmentation programme's entire backlog, ranked, for free.
//
// ⛔ WHAT THIS CLAIMS, PRECISELY. "CAN" means AT LEAST ONE ENABLED ALLOW RULE
// MATCHES THIS ZONE PAIR. It does NOT claim a packet would actually pass:
// addresses, services, profiles and rule order all still apply, and this engine
// deliberately does not model them. Overclaiming here would be worse than
// useless on a security product — an operator who trusts "reachable" and finds
// it was a guess stops trusting the honest answers too. The UI says "a rule
// permits this", never "this is reachable".
//
// ⛔ THE THREE-STATE RULE APPLIES TO "DID" AND IS THE POINT. A permitting rule
// whose hit count was never measured (Fortinet over SSH reports none at all —
// 0 of 180 rules on the live fleet) is UNKNOWN, never "never used". Reporting
// an unmeasured path as unused would recommend deleting a rule that may be
// carrying production traffic, which is exactly the mistake every competing
// tool makes. lib/engines/ruleHitCorrelation.js already distinguishes
// measured-zero from no-coverage; this engine consumes that rather than
// re-deriving it.

const ALLOW_ACTIONS = new Set(['allow', 'accept', 'permit']);
// 'block' is in this family per firewall_rules.action's own comment.
const DENY_ACTIONS = new Set(['deny', 'drop', 'reject', 'block']);

const ANY_ZONE = 'any';

/** Normalise a zone name for comparison. zone_classifications is already lowercased. */
function normaliseZone(z) {
  return String(z == null ? '' : z).trim().toLowerCase();
}

/**
 * Does a rule's zone list cover this zone?
 *
 * ⛔ `any` IS A WILDCARD AND MUST BE TREATED AS ONE. It appears 114 times on the
 * live fleet. Matching it literally would understate CAN — and understating
 * reachability on a segmentation report is the dangerous direction: it reports a
 * hole as closed.
 *
 * ⛔ An EMPTY or absent zone list is also treated as `any`. A rule with no zone
 * constraint constrains nothing; reading it as "matches nothing" would silently
 * drop real rules from the analysis.
 */
function zoneListMatches(zones, zone) {
  const target = normaliseZone(zone);
  if (!Array.isArray(zones) || zones.length === 0) return true;
  for (const z of zones) {
    const n = normaliseZone(z);
    if (n === ANY_ZONE || n === target) return true;
  }
  return false;
}

function isAllowAction(action) {
  return ALLOW_ACTIONS.has(normaliseZone(action));
}

function isDenyAction(action) {
  return DENY_ACTIONS.has(normaliseZone(action));
}

/** Rules that match this ordered zone pair, in their own sequence order. */
function rulesForPair(rules, srcZone, dstZone) {
  return (rules || []).filter(
    (r) => r.enabled !== false
      && zoneListMatches(r.src_zones, srcZone)
      && zoneListMatches(r.dst_zones, dstZone)
  );
}

/**
 * Did traffic actually use any of these rules?
 *
 * @returns {{did:boolean|null, measured:number, unmeasured:number, reasons:string[]}}
 *   `did` is TRI-STATE: true / false (measured, genuinely none) / null (unknown).
 *
 * ⛔ null WINS OVER false. If even one permitting rule could not be measured,
 * the pair as a whole is UNKNOWN — because that one rule might be the one
 * carrying the traffic. Collapsing to "no traffic" because the OTHERS were quiet
 * is precisely how an in-use path gets recommended for deletion.
 */
function trafficEvidence(rules) {
  let measured = 0;
  let unmeasured = 0;
  let anyHits = false;
  const reasons = new Set();

  for (const r of rules) {
    const hits = r.effectiveHitCount;
    if (hits === null || hits === undefined) {
      unmeasured += 1;
      if (r.logEvidence) reasons.add(r.logEvidence);
      continue;
    }
    measured += 1;
    if (Number(hits) > 0) anyHits = true;
  }

  if (anyHits) return { did: true, measured, unmeasured, reasons: [...reasons] };
  if (unmeasured > 0) return { did: null, measured, unmeasured, reasons: [...reasons] };
  if (measured === 0) return { did: null, measured, unmeasured, reasons: ['no-rules'] };
  return { did: false, measured, unmeasured, reasons: [...reasons] };
}

// ── verdicts ────────────────────────────────────────────────────────────────
//
// ⛔ Ordered by how much they should alarm an operator, and NAMED so that no
// verdict can be mistaken for a clean result when it is not one.
//
// ⛔ "DID" IS NOT A WINDOWED MEASUREMENT FOR MOST RULES, AND THE PROSE MAY NOT
// SAY IT IS. `effectiveHitCount` (ruleHitCorrelation.js) prefers the DEVICE'S
// OWN hit counter, which is cumulative since that counter was last reset —
// often since the device was last rebooted, i.e. potentially years. Only when
// the device supplies no count at all does the number come from the bounded
// log window. Measured on the live fleet: 1,524 of 1,757 rules are
// device-sourced, so "in the window" would be FALSE for ~87% of the rules
// behind these verdicts.
//
// The error direction is tolerable — a lifetime counter overstates usage, so it
// OVERSTATES violations and SUPPRESSES removal candidates, never the reverse —
// but the sentence still has to describe the measurement that was actually
// taken. An operator who reads "used in the last 30 days", checks, and finds
// the packet was from 2023 stops believing the honest verdicts too. Each
// detail below therefore says "has recorded traffic" / "has recorded none",
// and names the lifetime-counter caveat where it changes what to do next.
const VERDICTS = {
  // intent: deny
  violation_active: {
    severity: 'critical',
    label: 'Violation — permitted and in use',
    detail: 'A rule allows this, and it has recorded traffic. Where the count came from the device\'s own counter it is cumulative since that counter was last reset, so the traffic is not necessarily recent — but it did happen.',
  },
  violation_permitted: {
    severity: 'high',
    label: 'Violation — permitted, no traffic recorded',
    detail: 'A rule allows this and has recorded no traffic at all, so it is a standing hole rather than an active breach — and the safest kind to close.',
  },
  violation_unverified: {
    severity: 'high',
    label: 'Violation — permitted, traffic not measurable',
    detail: 'A rule allows this. Whether anything used it cannot be determined, so it must be assumed live.',
  },
  ok_blocked: {
    severity: 'ok',
    label: 'Blocked, as intended',
    detail: 'No enabled rule permits this zone pair.',
  },
  // intent: allow
  ok_in_use: {
    severity: 'ok',
    label: 'Allowed and in use',
    detail: 'Permitted as intended, and it has recorded traffic.',
  },
  unused_permission: {
    severity: 'medium',
    label: 'Allowed but never used',
    detail: 'Permitted as intended, with no traffic recorded against any permitting rule. A candidate for removal — the permission exists without a demonstrated purpose. Where the count is the device\'s own, "never" means since that counter was last reset.',
  },
  ok_unverified: {
    severity: 'unknown',
    label: 'Allowed — usage not measurable',
    detail: 'Permitted as intended. Whether anything used it cannot be determined here.',
  },
  expected_allow_missing: {
    severity: 'medium',
    label: 'Expected to be allowed, but nothing permits it',
    detail: 'You expect this to work and no enabled rule permits it. Either the intent is wrong or the rule is missing.',
  },
  unknown: {
    severity: 'unknown',
    label: 'Cannot be determined',
    detail: 'SecVault cannot answer this pair: either no ruleset has been collected for the devices that would carry it, or the rules that match it use an action verb this engine does not recognise.',
  },
};

/**
 * ⛔ A RULE WHOSE ACTION VERB WE DO NOT RECOGNISE IS NOT A RULE WE CAN IGNORE.
 *
 * `permitting` requires isAllowAction and `denying` requires isDenyAction, so a
 * rule whose action is a new vendor verb, an empty string or null used to match
 * NEITHER filter and silently vanish from the analysis. For a deny-intent that
 * produced `can = false` -> `ok_blocked`: a rule SecVault could not read was
 * reported to the operator as proof the path is CLOSED. That is the direction
 * this file's header names as the dangerous one — a hole reported as closed is
 * a false assurance, not a missed finding.
 *
 * ⛔ THIS IS DELIBERATELY THE OPPOSITE POLICY FROM logHit.js, where an
 * unrecognised verb never fires. The failure modes are mirror images: there an
 * unknown verb that counted as "allowed" would MANUFACTURE a patch_now, so
 * silence is safe; here an unknown verb that counted as nothing MANUFACTURES an
 * all-clear, so silence is not. Both rules say the same thing — never let an
 * unread value become the reassuring answer.
 *
 * Today the live fleet uses only allow/deny/drop (1,510/183/64 of 1,757), so
 * this fires on nothing. It exists for the next vendor, the next firmware verb,
 * and the adapter that returns null for an action it could not parse.
 */
function isUnrecognisedAction(action) {
  return !isAllowAction(action) && !isDenyAction(action);
}

/** Shape one rule for the "go and look at this" list in the UI. */
function exampleOf(r) {
  return {
    deviceId: r.device_id,
    deviceName: r.device_name || null,
    ruleName: r.rule_name || null,
    sequence: r.sequence_number == null ? null : Number(r.sequence_number),
    action: r.action == null ? null : String(r.action),
    hits: r.effectiveHitCount === null || r.effectiveHitCount === undefined
      ? null
      : Number(r.effectiveHitCount),
    logEvidence: r.logEvidence || null,
  };
}

/**
 * How many active devices could not contribute rules to this evaluation?
 *
 * ⛔ COVERAGE IS PER DEVICE, NOT PER FLEET. The old test was a single
 * fleet-wide boolean: `rules.length === 0` meant unknown, anything else meant
 * "we have the rulebase". With 1 of 16 devices collected, the other 15 were
 * simply absent from the array, so every deny-intent whose permitting rule
 * lives on one of them came back `ok_blocked` — severity `ok`, "Blocked, as
 * intended" — computed from 15 firewalls nobody had ever read. That is the
 * exact failure this file's header says the all-or-nothing check prevents; it
 * just prevented it at the wrong granularity.
 */
function missingDeviceCount(ctx) {
  if (Array.isArray(ctx.devicesWithoutRules)) return ctx.devicesWithoutRules.length;
  const active = Number(ctx.activeDeviceCount);
  const withRules = Number(ctx.devicesWithRules);
  if (!Number.isFinite(active) || !Number.isFinite(withRules)) return 0;
  return Math.max(0, active - withRules);
}

/**
 * Evaluate one declared intent against the rules.
 *
 * @param {{sourceZone:string,destZone:string,expectation:'allow'|'deny'}} intent
 * @param {Array} rules  rules already enriched by ruleHitCorrelation
 * @param {{rulesCollected?:boolean, activeDeviceCount?:number,
 *          devicesWithRules?:number, devicesWithoutRules?:string[]}} [context]
 */
function evaluateIntent(intent, rules, context) {
  const src = normaliseZone(intent.sourceZone);
  const dst = normaliseZone(intent.destZone);
  const expectation = intent.expectation === 'allow' ? 'allow' : 'deny';
  const ctx = context || {};

  // ⛔ NO RULES COLLECTED IS NOT "BLOCKED". A fleet whose rulesets have never
  // been pulled would otherwise report every deny-intent as satisfied — a
  // perfect segmentation score generated entirely from missing data.
  if (ctx.rulesCollected === false || !Array.isArray(rules) || rules.length === 0) {
    return {
      ...intent,
      verdict: 'unknown',
      can: null,
      did: null,
      permittingRuleCount: 0,
      denyingRuleCount: 0,
      unrecognisedActionRuleCount: 0,
      unmeasuredRuleCount: 0,
      uncollectedDeviceCount: missingDeviceCount(ctx),
      evidenceReasons: ['no-rules-collected'],
      examples: [],
    };
  }

  const matching = rulesForPair(rules, src, dst);
  const permitting = matching.filter((r) => isAllowAction(r.action));
  const denying = matching.filter((r) => isDenyAction(r.action));
  const unrecognised = matching.filter((r) => isUnrecognisedAction(r.action));

  const can = permitting.length > 0;
  const uncollected = missingDeviceCount(ctx);

  // ⛔ A NEGATIVE ANSWER NEEDS COMPLETE EVIDENCE; A POSITIVE ONE DOES NOT.
  //
  // "Something permits this" is proved by ONE rule, so `can === true` stands
  // however patchy the rest of the collection is. "NOTHING permits this" is a
  // claim about every rule on every firewall in the path, and it is the claim
  // that renders as `ok_blocked` ("Blocked, as intended") or as
  // `expected_allow_missing`. Two things can make it unsupportable, and both
  // land here rather than being quietly rounded down to a clean result:
  //   - a device whose ruleset was never collected (the permitting rule may be
  //     sitting on it), and
  //   - a matching rule whose action verb this engine could not classify (it
  //     may well be an allow under another name).
  if (!can && (uncollected > 0 || unrecognised.length > 0)) {
    const reasons = [];
    if (uncollected > 0) reasons.push('partial-rule-coverage');
    if (unrecognised.length > 0) reasons.push('unrecognised-action');
    return {
      ...intent,
      verdict: 'unknown',
      can: null,
      did: null,
      permittingRuleCount: 0,
      denyingRuleCount: denying.length,
      unrecognisedActionRuleCount: unrecognised.length,
      unmeasuredRuleCount: 0,
      measuredRuleCount: 0,
      uncollectedDeviceCount: uncollected,
      evidenceReasons: reasons,
      // The unreadable rules ARE the finding here — an operator cannot go and
      // check a verb we refused to name.
      examples: unrecognised.slice(0, 5).map(exampleOf),
    };
  }

  const evidence = can
    ? trafficEvidence(permitting)
    : { did: null, measured: 0, unmeasured: 0, reasons: [] };

  let verdict;
  if (expectation === 'deny') {
    if (!can) verdict = 'ok_blocked';
    else if (evidence.did === true) verdict = 'violation_active';
    else if (evidence.did === false) verdict = 'violation_permitted';
    else verdict = 'violation_unverified';
  } else if (!can) {
    verdict = 'expected_allow_missing';
  } else if (evidence.did === true) {
    verdict = 'ok_in_use';
  } else if (evidence.did === false) {
    verdict = 'unused_permission';
  } else {
    verdict = 'ok_unverified';
  }

  return {
    ...intent,
    verdict,
    can,
    did: evidence.did,
    permittingRuleCount: permitting.length,
    denyingRuleCount: denying.length,
    // Reported even when the verdict stands on its own (a path that IS
    // permitted), because an unreadable verb beside a real allow is still
    // something the operator should go and look at.
    unrecognisedActionRuleCount: unrecognised.length,
    unmeasuredRuleCount: evidence.unmeasured,
    measuredRuleCount: evidence.measured,
    uncollectedDeviceCount: uncollected,
    evidenceReasons: evidence.reasons,
    // The rules an operator would actually go and look at, capped so a
    // catch-all any->any rule does not return the entire rulebase.
    examples: permitting.slice(0, 5).map(exampleOf),
  };
}

/** Roll a set of evaluated intents into a headline. */
// ⛔ The ONLY three verdicts that mean SecVault could not answer. `ok_blocked`
// is deliberately ABSENT: when nothing permits a path there is no rule whose
// usage could be unmeasured, and that is the INTENDED outcome, not a gap.
// Counting it here made tone `ok` unreachable and printed a fabricated
// "N of N paths could not be measured" over paths measured perfectly.
const UNMEASURABLE_VERDICTS = new Set([
  'violation_unverified',
  'ok_unverified',
  'unknown',
]);

function summarise(results) {
  const out = {
    total: results.length,
    violations: 0,
    activeViolations: 0,
    unusedPermissions: 0,
    unknown: 0,
    ok: 0,
    // ⛔ Counted separately and reported: a matrix where a third of the cells
    // could not be evaluated is not a 67% pass.
    unmeasurable: 0,
    // A declared 'must connect' that nothing permits. It is a FINDING (either
    // the intent is wrong or a rule is missing) and was previously counted
    // nowhere at all, while being swept into `unmeasurable` by the old `did`
    // test — so the board listed it under "What to act on" while the headline
    // called it a measurement gap and never mentioned it.
    expectedAllowMissing: 0,
    // ⛔ WHY the unknowns are unknown, counted separately so a coverage gap
    // cannot be read as an engine limitation or vice versa. "15 firewalls have
    // never been read" and "these rules use a verb we cannot classify" are
    // different problems with different fixes, and a single `unknown` total
    // tells the operator neither.
    pairsBlockedByUncollectedDevices: 0,
    pairsWithUnrecognisedActions: 0,
  };
  for (const r of results) {
    const sev = (VERDICTS[r.verdict] || {}).severity;
    if (r.verdict === 'violation_active') { out.violations += 1; out.activeViolations += 1; }
    else if (r.verdict.startsWith('violation_')) out.violations += 1;
    else if (r.verdict === 'unused_permission') out.unusedPermissions += 1;
    else if (r.verdict === 'unknown') out.unknown += 1;
    else if (r.verdict === 'expected_allow_missing') out.expectedAllowMissing += 1;
    else if (sev === 'ok') out.ok += 1;

    // ⛔ UNMEASURABLE IS A PROPERTY OF THE VERDICT, NOT OF `did`.
    //
    // This read `sev === 'unknown' || r.did === null`, and `did === null` is
    // exactly what `ok_blocked` sets — because when NOTHING permits a path
    // there are no permitting rules whose usage could be measured, which is the
    // desired outcome, not a gap. The effect: three deny-intents that the
    // firewalls correctly enforce produced `ok: 3` AND `unmeasurable: 3`, and
    // the page rendered "3 of 3 paths could not be measured." over three paths
    // that were measured perfectly.
    //
    // Worse than a wrong count: the evidence drawer then asserted a specific,
    // checkable reason — "at least one rule permitting each of these paths
    // cannot report whether it was used" — when there are no permitting rules
    // at all. And it made tone `ok` unreachable in practice: the moment a
    // customer declares an intent their fleet actually enforces, the product
    // said it could not tell.
    //
    // Only these three verdicts mean SecVault could not answer: the two
    // *_unverified states (a permitting rule exists but cannot report usage)
    // and `unknown` (no ruleset collected at all).
    if (UNMEASURABLE_VERDICTS.has(r.verdict)) out.unmeasurable += 1;

    const reasons = Array.isArray(r.evidenceReasons) ? r.evidenceReasons : [];
    if (reasons.includes('partial-rule-coverage') || reasons.includes('no-rules-collected')) {
      out.pairsBlockedByUncollectedDevices += 1;
    }
    if (Number(r.unrecognisedActionRuleCount) > 0) out.pairsWithUnrecognisedActions += 1;
  }
  return out;
}

module.exports = {
  UNMEASURABLE_VERDICTS,
  evaluateIntent,
  summarise,
  rulesForPair,
  trafficEvidence,
  zoneListMatches,
  isAllowAction,
  isDenyAction,
  isUnrecognisedAction,
  normaliseZone,
  VERDICTS,
  ALLOW_ACTIONS,
  DENY_ACTIONS,
};
