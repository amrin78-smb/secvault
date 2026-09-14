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
const VERDICTS = {
  // intent: deny
  violation_active: {
    severity: 'critical',
    label: 'Violation — permitted and in use',
    detail: 'A rule allows this, and traffic has actually used it.',
  },
  violation_permitted: {
    severity: 'high',
    label: 'Violation — permitted, no traffic seen',
    detail: 'A rule allows this. No traffic has used it in the window, so it is a standing hole rather than an active breach — and the safest kind to close.',
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
    detail: 'Permitted as intended, and traffic has used it.',
  },
  unused_permission: {
    severity: 'medium',
    label: 'Allowed but never used',
    detail: 'Permitted as intended, but no traffic has used it in the window. A candidate for removal — the permission exists without a demonstrated purpose.',
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
    detail: 'No ruleset has been collected for the devices that would carry this path.',
  },
};

/**
 * Evaluate one declared intent against the rules.
 *
 * @param {{sourceZone:string,destZone:string,expectation:'allow'|'deny'}} intent
 * @param {Array} rules  rules already enriched by ruleHitCorrelation
 * @param {{rulesCollected:boolean}} [context]
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
      unmeasuredRuleCount: 0,
      evidenceReasons: ['no-rules-collected'],
    };
  }

  const matching = rulesForPair(rules, src, dst);
  const permitting = matching.filter((r) => isAllowAction(r.action));
  const denying = matching.filter((r) => isDenyAction(r.action));

  const can = permitting.length > 0;
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
    unmeasuredRuleCount: evidence.unmeasured,
    measuredRuleCount: evidence.measured,
    evidenceReasons: evidence.reasons,
    // The rules an operator would actually go and look at, capped so a
    // catch-all any->any rule does not return the entire rulebase.
    examples: permitting.slice(0, 5).map((r) => ({
      deviceId: r.device_id,
      deviceName: r.device_name || null,
      ruleName: r.rule_name || null,
      sequence: r.sequence_number == null ? null : Number(r.sequence_number),
      hits: r.effectiveHitCount === null || r.effectiveHitCount === undefined
        ? null
        : Number(r.effectiveHitCount),
      logEvidence: r.logEvidence || null,
    })),
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
  normaliseZone,
  VERDICTS,
  ALLOW_ACTIONS,
  DENY_ACTIONS,
};
