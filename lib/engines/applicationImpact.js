// lib/engines/applicationImpact.js
//
// Phase 2a of the application-centric view: the REVERSE INDEX.
//
// applicationView.js answers "which rules permit this flow". This answers the
// question an operator standing over a delete button actually has:
//
//     "If I remove this rule, which DECLARED flows lose their only permission?"
//
// ⛔ THE CLAIM IS EXACTLY ONE SENTENCE AND MAY NOT GROW:
//
//     "Removing this rule would leave N DECLARED flows with nothing
//      permitting them."
//
// It is as complete as the declaration and NO MORE. A rule serving no declared
// application is NOT proven safe to remove — with nothing declared, EVERY rule
// serves nothing, and rendering that as "safe" would turn an empty declaration
// into a fleet-wide deletion licence. That is this codebase's signature bug
// (a failed/absent read recorded as an affirmative fact) with a delete button
// attached, which is why `declarationEmpty` travels on the index AND on every
// single per-rule answer, where a caller cannot fail to receive it.
//
// ⛔ "ONLY SUPPORT" IS COMPUTED, NEVER ASSUMED. A flow permitted by five rules
// loses nothing when one of them goes; a flow permitted by exactly one is
// broken by that deletion. Those are different findings and they do not share a
// label: `breaks` vs `shared`. Collapsing them would put a red warning on ~every
// rule a declaration touches, and a warning that fires on everything stops being
// read — the same reasoning that keeps `log_hit` off threat-signature data.
//
// ⛔ AN UNVERIFIED EVALUATION CANNOT SUPPORT A DELETION CLAIM. If the flow's
// evaluation was unverified — an unresolved object, a device with no collected
// ruleset, the fragmentation cap — then how much of that flow each rule really
// covers is unknown, and so is what happens when one is removed. Such a flow
// lands in `unknownFlows` and the rule's state becomes `unknown`. It is NEVER
// counted as a proven break and it is NEVER counted as zero. Zero and unknown
// are structurally distinct objects here (different state, different arrays,
// different counts) precisely so no renderer can accidentally draw them alike.
//
// ⛔ FLOW EVALUATION IS NOT RE-IMPLEMENTED. Everything below consumes
// `evaluateAllApplications` / `evaluateFlow` output UNCHANGED. Two
// implementations of "does this rule permit this flow" would eventually
// disagree, and the wrong one would be the one authorising a deletion.
//
// ⛔ A `deny`-EXPECTATION FLOW IS NOT A DEPENDENCY. A rule permitting a flow the
// operator declared should be DENIED is a violation that rule causes; removing
// it FIXES something rather than breaking it. Counting those toward "3
// applications depend on this rule" would invert the meaning of the figure in
// the one case where it matters most. They are carried separately, in
// `violationFlows`.
//
// ⛔ COST. Building this needs the whole fleet's rulebase (loadFleet is ~750ms)
// and an evaluation of every declared flow against every device. It is computed
// ONCE per request by getImpactIndex() and then looked up per rule in O(1).
// Never call getImpactIndex() inside a loop over rules.
//
// CommonJS — same as every other engine in this directory.

'use strict';

const { evaluateAllApplications } = require('./applicationViewData');

/**
 * ⛔ THE SENTENCE. Exported so the UI cannot paraphrase it into something
 * stronger, and so a test can assert the wording that actually ships.
 */
const IMPACT_CLAIM =
  'Removing this rule would leave N declared flows with nothing permitting them.';

/**
 * ⛔ THE CAVEAT THAT MUST TRAVEL WITH THE FIGURE, wherever it appears.
 */
const IMPACT_CAVEAT =
  'This is only as complete as what has been declared. A rule that no declared application '
  + 'uses is not proven safe to remove — with nothing declared, every rule serves nothing.';

// The four states a rule can be in with respect to the declaration. They are
// ordered by how much they should stop a deletion, worst first.
const IMPACT = {
  BREAKS: 'breaks',   // at least one declared flow loses ALL permission
  UNKNOWN: 'unknown', // this rule touches a flow whose evaluation was unverified
  SHARED: 'shared',   // declared flows use it, but each is permitted elsewhere too
  NONE: 'none',       // no declared flow is permitted by this rule
};

function ruleKey(deviceId, ruleIdVendor) {
  return `${deviceId || ''}|${ruleIdVendor === null || ruleIdVendor === undefined ? '' : ruleIdVendor}`;
}

/**
 * A compact reference to a flow, for showing WHICH flows an answer is about.
 * The application is carried on it because the figure the operator reads is
 * "3 applications depend on this rule", and an anonymous flow id cannot be
 * traced back to an owner.
 */
function flowRef(app, evaluated) {
  const f = evaluated.flow || {};
  return {
    flowId: f.id || null,
    applicationId: app.id || null,
    applicationName: app.name || null,
    criticality: app.criticality || null,
    src: f.src || null,
    dst: f.dst || null,
    protocol: f.protocol || null,
    portStart: f.port_start === undefined ? null : f.port_start,
    portEnd: f.port_end === undefined ? null : f.port_end,
    expectation: f.expectation === 'deny' ? 'deny' : 'allow',
    unverified: !!evaluated.unverified,
  };
}

function newEntry(deviceId, deviceName, deviceRuleId, ruleIdVendor, ruleName) {
  return {
    deviceId: deviceId || null,
    deviceName: deviceName || null,
    deviceRuleId: deviceRuleId || null,
    ruleIdVendor: ruleIdVendor === undefined ? null : ruleIdVendor,
    ruleName: ruleName === undefined ? null : ruleName,
    // Distinct arrays, never one array with a status field: a caller that
    // forgets to read the status still cannot mistake one bucket for another.
    onlySupportFlows: [],
    sharedFlows: [],
    unknownFlows: [],
    violationFlows: [],
  };
}

/**
 * Resolve an entry's state. Precedence is deliberate and is NOT "worst count
 * wins": `unknown` outranks `shared` because a rule with three proven
 * alternatives for flow A and one unverifiable flow B is still a rule whose
 * removal we cannot vouch for.
 */
function stateOf(entry) {
  if (entry.onlySupportFlows.length > 0) return IMPACT.BREAKS;
  if (entry.unknownFlows.length > 0) return IMPACT.UNKNOWN;
  if (entry.sharedFlows.length > 0) return IMPACT.SHARED;
  return IMPACT.NONE;
}

function finaliseEntry(entry, index) {
  const apps = new Map();
  for (const f of [...entry.onlySupportFlows, ...entry.sharedFlows, ...entry.unknownFlows]) {
    if (f.applicationId && !apps.has(f.applicationId)) {
      apps.set(f.applicationId, { id: f.applicationId, name: f.applicationName, criticality: f.criticality });
    }
  }
  return {
    deviceId: entry.deviceId,
    deviceName: entry.deviceName,
    deviceRuleId: entry.deviceRuleId,
    ruleIdVendor: entry.ruleIdVendor,
    ruleName: entry.ruleName,
    impact: stateOf(entry),
    applications: [...apps.values()],
    applicationCount: apps.size,
    // The headline number. ⛔ It counts ONLY flows proven to lose every
    // permitting rule, and only from VERIFIED evaluations.
    onlySupportCount: entry.onlySupportFlows.length,
    onlySupportFlows: entry.onlySupportFlows,
    sharedCount: entry.sharedFlows.length,
    sharedFlows: entry.sharedFlows,
    // ⛔ NEVER FOLDED INTO onlySupportCount, IN EITHER DIRECTION. Not added
    // (it would fabricate breakage) and not dropped (it would fabricate
    // safety).
    unknownCount: entry.unknownFlows.length,
    unknownFlows: entry.unknownFlows,
    violationCount: entry.violationFlows.length,
    violationFlows: entry.violationFlows,
    dependentFlowCount:
      entry.onlySupportFlows.length + entry.sharedFlows.length + entry.unknownFlows.length,
    // ⛔ Carried on EVERY answer, not just on the index, so a component that
    // only ever holds one rule's result still cannot render a 0 as an
    // all-clear. See IMPACT_CAVEAT.
    declarationEmpty: !!index.declarationEmpty,
    available: index.available !== false,
    claim: IMPACT_CLAIM,
    caveat: IMPACT_CAVEAT,
  };
}

/**
 * An answer for a rule the index has never heard of.
 *
 * ⛔ THIS IS THE DANGEROUS ONE, AND IT IS WHY THE FUNCTION EXISTS RATHER THAN
 * THE CALLER DEFAULTING TO ZERO AT THE CALL SITE. "No declared flow uses this"
 * and "there is nothing declared" and "the evaluation failed" all produce a
 * zero count, and only one of them is a measurement. The state and the flags
 * are what separate them.
 */
function absentEntry(index, key = {}) {
  const unavailable = index.available === false;
  return {
    deviceId: key.deviceId || null,
    deviceName: key.deviceName || null,
    deviceRuleId: key.deviceRuleId || null,
    ruleIdVendor: key.ruleIdVendor === undefined ? null : key.ruleIdVendor,
    ruleName: key.ruleName === undefined ? null : key.ruleName,
    impact: unavailable ? IMPACT.UNKNOWN : IMPACT.NONE,
    applications: [],
    applicationCount: 0,
    onlySupportCount: unavailable ? null : 0,
    onlySupportFlows: [],
    sharedCount: unavailable ? null : 0,
    sharedFlows: [],
    unknownCount: unavailable ? null : 0,
    unknownFlows: [],
    violationCount: unavailable ? null : 0,
    violationFlows: [],
    dependentFlowCount: unavailable ? null : 0,
    declarationEmpty: !!index.declarationEmpty,
    available: !unavailable,
    claim: IMPACT_CLAIM,
    caveat: IMPACT_CAVEAT,
  };
}

/**
 * THE PURE HALF. Invert evaluated applications into rule → dependants.
 *
 * @param {{application:object, flows:object[], unevaluated?:boolean}[]} applications
 *   exactly `evaluateAllApplications(pool).applications`.
 * @param {{available?:boolean, errors?:object[]}} [meta]
 * @returns {object} the index. `byDeviceRuleId` / `byDeviceAndVendorId` are Maps.
 */
function buildImpactIndex(applications, meta = {}) {
  const apps = Array.isArray(applications) ? applications : [];

  const byDeviceRuleId = new Map();
  const byDeviceAndVendorId = new Map();

  let flowCount = 0;
  let evaluatedFlowCount = 0;
  let unverifiedFlowCount = 0;
  let invalidFlowCount = 0;
  let denyFlowCount = 0;
  let unevaluatedApplications = 0;

  const touch = (p, r) => {
    let entry = byDeviceRuleId.get(r.deviceRuleId);
    if (!entry) {
      entry = newEntry(p.deviceId, p.deviceName, r.deviceRuleId, r.ruleId, r.name);
      byDeviceRuleId.set(r.deviceRuleId, entry);
      // ⛔ rule_id_vendor is the identity that survives a ruleset
      // DELETE+reinsert, and it is what the cleanup flow keys on
      // (ruleChangeRequests.js says why the UUID cannot be used there). It is
      // NULLABLE, so the vendor-id map is only populated when there is one —
      // an absent id must not collapse every such rule onto one shared key.
      if (r.ruleId !== null && r.ruleId !== undefined && r.ruleId !== '') {
        byDeviceAndVendorId.set(ruleKey(p.deviceId, r.ruleId), entry);
      }
    }
    return entry;
  };

  for (const a of apps) {
    const app = (a && a.application) || {};
    if (a && a.unevaluated) unevaluatedApplications += 1;
    const flows = (a && a.flows) || [];
    for (const e of flows) {
      flowCount += 1;
      if (e.invalid) {
        // ⛔ COUNTED, NEVER DROPPED. An unreadable flow attaches to no rule, so
        // it can only be disclosed at index level — but a declaration with
        // unreadable rows in it is not a complete declaration and the header
        // has to say so.
        invalidFlowCount += 1;
        continue;
      }
      evaluatedFlowCount += 1;
      if (e.unverified) unverifiedFlowCount += 1;

      const ref = flowRef(app, e);
      if (ref.expectation === 'deny') denyFlowCount += 1;

      // Every rule, on every device, that permits any part of this flow.
      const permitting = [];
      for (const p of e.permittedBy || []) {
        for (const r of p.rules || []) permitting.push({ p, r });
      }

      // ⛔ THE SUPPORT COUNT IS OVER DISTINCT RULES ACROSS THE WHOLE FLEET.
      // "Nothing permits it" has to mean nothing ANYWHERE, so a flow permitted
      // by one rule on firewall A and one on firewall B is not broken by losing
      // either. (Volumes are still never unioned across devices — that is
      // applicationView's rule and this does not touch it. This counts RULES,
      // not coverage.)
      const distinct = new Set(permitting.map((x) => x.r.deviceRuleId));
      const supportCount = distinct.size;

      for (const { p, r } of permitting) {
        const entry = touch(p, r);
        if (ref.expectation === 'deny') {
          // Removing this rule would remove a permission the operator declared
          // should not exist. Not a dependency; the opposite of one.
          entry.violationFlows.push(ref);
          continue;
        }
        if (e.unverified) {
          // ⛔ UNKNOWN WINS OVER "ONLY SUPPORT", even at supportCount === 1.
          // An unverified evaluation applies only a rule's RESOLVED extent, so
          // other rules may permit this flow without appearing here at all. We
          // cannot prove this is the only support, and we will not claim it.
          entry.unknownFlows.push(ref);
        } else if (supportCount === 1) {
          entry.onlySupportFlows.push(ref);
        } else {
          entry.sharedFlows.push(ref);
        }
      }
    }
  }

  const available = meta.available !== false && unevaluatedApplications === 0;

  const index = {
    // ⛔ EMPTY MEANS "NOTHING TO COMPARE AGAINST", NOT "EVERYTHING IS FREE".
    // True when no application is declared, or none of them declares a flow.
    //
    // ⛔ AND IT IS FALSE WHENEVER THE EVALUATION WAS NOT AVAILABLE. A read that
    // failed also produces zero flows, and a `declarationEmpty: true` there
    // would let a caller print the reassuring "nothing is declared yet" copy
    // over a fault.
    // evaluateAllApplications ISOLATES its sources and returns {errors} rather
    // than throwing, so this is the path a real failure actually takes — the
    // catch below is only reached by something unexpected. Found by a test.
    declarationEmpty: flowCount === 0 && available,
    available,
    errors: Array.isArray(meta.errors) ? meta.errors : [],
    applicationCount: apps.length,
    flowCount,
    evaluatedFlowCount,
    unverifiedFlowCount,
    invalidFlowCount,
    denyFlowCount,
    unevaluatedApplications,
    byDeviceRuleId,
    byDeviceAndVendorId,
    claim: IMPACT_CLAIM,
    caveat: IMPACT_CAVEAT,
  };

  index.rules = [...byDeviceRuleId.values()].map((e) => finaliseEntry(e, index));
  // Re-point the maps at the FINALISED objects so a lookup and a list entry are
  // the same shape. Two shapes for one answer is how a renderer ends up reading
  // `onlySupportFlows.length` off an object that does not have it.
  const finalised = new Map();
  for (const r of index.rules) finalised.set(r.deviceRuleId, r);
  index.byDeviceRuleId = finalised;
  const finalisedVendor = new Map();
  for (const r of index.rules) {
    if (r.ruleIdVendor !== null && r.ruleIdVendor !== undefined && r.ruleIdVendor !== '') {
      finalisedVendor.set(ruleKey(r.deviceId, r.ruleIdVendor), r);
    }
  }
  index.byDeviceAndVendorId = finalisedVendor;

  // Fleet-level totals, for a header that has to state what the figures below
  // it are worth.
  index.rulesWithDependants = index.rules.filter((r) => r.dependentFlowCount > 0).length;
  index.rulesBreakingSomething = index.rules.filter((r) => r.impact === IMPACT.BREAKS).length;
  index.rulesUnknown = index.rules.filter((r) => r.impact === IMPACT.UNKNOWN).length;

  return index;
}

/**
 * One rule's answer. ⛔ ALWAYS returns an object — never undefined — because a
 * missing lookup at a call site becomes `?? 0` within a week, and `0` is the
 * one value that must never be manufactured here.
 *
 * @param {object} index from buildImpactIndex
 * @param {{deviceId?:string, ruleIdVendor?:string, deviceRuleId?:string, ruleName?:string}} key
 */
function impactForRule(index, key = {}) {
  if (!index || typeof index !== 'object') {
    return absentEntry({ available: false, declarationEmpty: false }, key);
  }
  if (key.deviceRuleId && index.byDeviceRuleId instanceof Map) {
    const hit = index.byDeviceRuleId.get(key.deviceRuleId);
    if (hit) return hit;
  }
  if (
    key.ruleIdVendor !== null && key.ruleIdVendor !== undefined && key.ruleIdVendor !== ''
    && index.byDeviceAndVendorId instanceof Map
  ) {
    const hit = index.byDeviceAndVendorId.get(ruleKey(key.deviceId, key.ruleIdVendor));
    if (hit) return hit;
  }
  return absentEntry(index, key);
}

/**
 * The index without Maps, for a JSON response.
 *
 * ⛔ `rules` is the WHOLE list and is deliberately not capped. It is bounded by
 * the size of the DECLARATION, not by the fleet: only rules a declared flow
 * actually touches appear at all (2 flows on the live fleet → a handful of
 * rules). A cap here would silently answer "0 dependants" for a rule that was
 * merely truncated out of the list — the exact failure this module exists to
 * prevent.
 */
function serialiseImpactIndex(index, { deviceId } = {}) {
  const rules = deviceId ? index.rules.filter((r) => r.deviceId === deviceId) : index.rules;
  return {
    claim: index.claim,
    caveat: index.caveat,
    available: index.available,
    declarationEmpty: index.declarationEmpty,
    applicationCount: index.applicationCount,
    flowCount: index.flowCount,
    evaluatedFlowCount: index.evaluatedFlowCount,
    unverifiedFlowCount: index.unverifiedFlowCount,
    invalidFlowCount: index.invalidFlowCount,
    denyFlowCount: index.denyFlowCount,
    rulesWithDependants: index.rulesWithDependants,
    rulesBreakingSomething: index.rulesBreakingSomething,
    rulesUnknown: index.rulesUnknown,
    windowDays: index.windowDays === undefined ? null : index.windowDays,
    coverage: index.coverage === undefined ? null : index.coverage,
    errors: index.errors || [],
    rules,
  };
}

/**
 * THE PLUMBING. Evaluate every declared application ONCE and invert the result.
 *
 * ⛔ NEVER THROWS. A page rendering deletion candidates must not be taken down
 * because the application view failed — but it must also not quietly show
 * "0 applications depend on this" when the reason is that nothing could be
 * evaluated. A failure returns `available:false`, which makes every lookup
 * report UNKNOWN rather than zero.
 *
 * ⛔ THE COUNT PROBE STANDS IN FRONT OF THE WHOLE-FLEET LOAD, the same guard
 * the work queue's application source uses: with nothing declared there is
 * nothing to invert, and paying ~750ms of loadFleet plus a full evaluation to
 * discover that would be a cost every operator pays for a feature nobody here
 * uses yet. ⛔ THE PROBE FAILS OPEN — if the count itself cannot be read we do
 * the full load, because guessing "nothing is declared" is the failed read
 * recorded as a fact.
 */
async function getImpactIndex(pool, options = {}) {
  let declaredFlows = null;
  try {
    const { rows } = await pool.query('SELECT count(*)::int AS n FROM application_flows');
    declaredFlows = rows && rows[0] ? Number(rows[0].n) : null;
  } catch (err) {
    declaredFlows = null; // fail OPEN — fall through to the full evaluation
  }

  if (declaredFlows === 0) {
    const empty = buildImpactIndex([], { available: true, errors: [] });
    empty.probe = 'no_flows_declared';
    return empty;
  }

  try {
    const evaluated = await evaluateAllApplications(pool, options);
    const index = buildImpactIndex(evaluated.applications, {
      // ⛔ ANY isolated source failure inside evaluateAllApplications makes the
      // whole inversion unusable for a deletion decision. If `application_flows`
      // could not be read, every rule would report zero dependants — a
      // fleet-wide "safe to delete" computed entirely from a failed query.
      available: (evaluated.errors || []).length === 0,
      errors: evaluated.errors || [],
    });
    index.windowDays = evaluated.windowDays === undefined ? null : evaluated.windowDays;
    index.coverage = evaluated.coverage || null;
    index.probe = declaredFlows === null ? 'probe_failed_open' : 'declared';
    return index;
  } catch (err) {
    const failed = buildImpactIndex([], {
      available: false,
      errors: [{ source: 'application_impact', error: (err && err.message) || String(err) }],
    });
    // ⛔ NOT "declaration empty". Nothing was read, so nothing is known about
    // the declaration either — and `declarationEmpty:true` here would let a
    // caller print the reassuring "nothing is declared yet" copy over a fault.
    failed.declarationEmpty = false;
    failed.available = false;
    failed.probe = 'failed';
    return failed;
  }
}

module.exports = {
  IMPACT,
  IMPACT_CLAIM,
  IMPACT_CAVEAT,
  ruleKey,
  buildImpactIndex,
  impactForRule,
  serialiseImpactIndex,
  getImpactIndex,
};
