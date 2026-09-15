// lib/engines/applicationRetire.js
//
// RETIRING a declared application: which firewall rules exist ONLY to serve it,
// and can they now go?
//
// `applications.status` could already be set to `retired` and nothing followed
// from it. This is what follows: the rules that only this application claims,
// offered to the EXISTING rule-cleanup loop as a change request, which then
// proves independently — against a later re-collected ruleset — whether they
// actually went.
//
// ⛔ "ONLY IT" IS THE ENTIRE SAFETY PROPERTY OF THIS FILE. A rule that permits a
// flow of this application AND a flow of another must never be proposed. So the
// claimed-rule set of EVERY OTHER declared application is computed and
// subtracted; a rule with any other claimant is withheld and named, never
// quietly dropped. Getting this wrong deletes a rule another application
// depends on — and the verify loop would then confirm that deletion as a
// SUCCESS, which is the worst direction this product can be wrong in.
//
// ⛔ AN UNVERIFIED EVALUATION CANNOT AUTHORISE A DELETION. If this
// application's flows — or any other application's — were evaluated against a
// rule referencing an object the device never reported, a firewall whose
// ruleset was never collected, or a rulebase that hit the evaluator's
// fragmentation cap, then "only this application claims it" was not
// established. It was not disproved either: those rules are WITHHELD with that
// reason, which is a refusal to answer, never a proposal.
//
// ⛔ AN UNMEASURED HIT COUNT IS REFUSED, NOT WARNED ABOUT. `effectiveHitCount`
// is ruleHitCorrelation's tri-state — a real count, a measured zero, or NULL
// meaning no vendor/transport could report one. "We cannot tell whether this
// rule is used" is not a reason to delete it. Same refusal
// ruleChangeRequests.getCleanupCandidates already makes, applied at this grain
// too so the reason is visible here rather than only as an absence downstream.
//
// ⛔ A RULE CLAIMED BY NO APPLICATION IS NOT OURS TO PROPOSE EITHER. That is
// orphanCoverage's figure, and it is a COVERAGE statement: with nothing
// declared, every rule on the fleet is unclaimed. This file proposes only rules
// POSITIVELY claimed by this application and by nothing else.
//
// ⛔ NOTHING HERE DELETES ANYTHING, AND NOTHING HERE VERIFIES ANYTHING. It
// produces a REQUEST through createRequest/submitRequest unchanged. The rules go
// when whoever edits the firewall removes them, and the existing loop confirms
// it against a ruleset collected strictly after submission — which is also why
// this file writes no verifier of its own: two verifiers would eventually
// disagree, and the wrong one would be the one reporting a success.
//
// CommonJS, same as every other engine here.

'use strict';

const {
  normaliseFlow,
  evaluateFlowOnDevice,
} = require('./applicationView');

const {
  loadFleet,
  listApplications,
} = require('./applicationViewData');

const {
  getCleanupCandidates,
  createRequest,
  submitRequest,
} = require('./ruleChangeRequests');

// ── Why a rule was held back ───────────────────────────────────────────────
//
// ⛔ ONE VOCABULARY, and every withheld rule carries one of these codes plus a
// sentence an operator can act on. A withheld list whose entries say only
// "withheld" is a shorter list wearing a label.
const REASONS = {
  ALSO_CLAIMED: 'also_claimed',
  UNVERIFIED: 'unverified_evaluation',
  NO_VENDOR_ID: 'no_vendor_identifier',
  USAGE_NOT_MEASURED: 'usage_not_measured',
  CLEANUP_WITHHELD: 'cleanup_engine_withheld',
  NOT_CLEANUP_ELIGIBLE: 'not_cleanup_eligible',
};

// Why nothing was proposed, when nothing was. ⛔ These are DIFFERENT facts and
// are never collapsed into one empty state: "you declared nothing" and "we
// could not establish anything" are answers to different questions, and only
// one of them is about the operator's own data.
const NOTES = {
  NO_FLOWS: 'no_flows_declared',
  NO_ALLOW_FLOWS: 'no_allow_flows_declared',
  NOTHING_CLAIMED: 'nothing_claimed',
  ALL_WITHHELD: 'all_withheld',
};

// ── Claim index ────────────────────────────────────────────────────────────

/**
 * Which rules each declared application claims, and where the evaluation that
 * decided it could not be trusted.
 *
 * A CLAIM is a rule that PERMITS one of the application's declared flows, which
 * is exactly orphanCoverage's definition — the two must agree, or the coverage
 * figure on /applications and the proposal here would be computed from
 * different ideas of the same word.
 *
 * ⛔ CLAIMS BY OTHERS ARE COUNTED BROADLY, INCLUDING FROM `deny` FLOWS. A rule
 * permitting another application's deny-expectation flow is that application's
 * violation, and deleting it out from under them — as a side effect of retiring
 * an unrelated system — is not this feature's call to make. Broad here means
 * "withhold more", which is the safe direction.
 *
 * ⛔ AND A RETIRED OR RETIRING APPLICATION STILL COUNTS AS A CLAIMANT. Its
 * status is a label an operator typed, not evidence that its traffic stopped.
 *
 * @param {object} fleet - from loadFleet()
 * @param {{application:object, flows:object[]}[]} applications
 */
function buildClaimIndex(fleet, applications) {
  const devices = (fleet && Array.isArray(fleet.devices)) ? fleet.devices : [];
  const apps = Array.isArray(applications) ? applications : [];

  /** @type {Map<string, Map<string, object>>} appId -> deviceRuleId -> claim */
  const claimsByApp = new Map();
  /** @type {Map<string, Set<string>>} deviceRuleId -> claiming appIds */
  const claimantsByRule = new Map();
  /** @type {Map<string, string[]>} deviceId -> reasons its evaluation is unverified */
  const taintedDevices = new Map();
  /** Reasons NO device's evaluation can be trusted for this purpose. */
  const globalTaints = [];

  const taint = (deviceId, reason) => {
    if (!taintedDevices.has(deviceId)) taintedDevices.set(deviceId, []);
    const list = taintedDevices.get(deviceId);
    if (!list.includes(reason)) list.push(reason);
  };

  // ⛔ A FIREWALL WITH NO COLLECTED RULESET TAINTS EVERYTHING, not just itself.
  // It hosts no rule we could propose, but its absence is the plainest possible
  // statement that the fleet's rulebase is not fully known — and this action
  // rests on a claim about the WHOLE rulebase ("nothing else claims this"),
  // not about one device.
  const withoutRules = Array.isArray(fleet && fleet.devicesWithoutRules)
    ? fleet.devicesWithoutRules : [];
  if (withoutRules.length > 0) {
    globalTaints.push(
      `${withoutRules.length} active firewall${withoutRules.length === 1 ? ' has' : 's have'} no `
      + `collected ruleset (${withoutRules.join(', ')}), so what they permit — and which `
      + 'applications depend on it — is unknown.'
    );
  }
  const evaluable = devices.filter((d) => d.hasRules);
  if (evaluable.length === 0) {
    globalTaints.push(
      'No firewall with a collected ruleset was evaluated, so nothing has been established about '
      + 'any rule.'
    );
  }

  for (const entry of apps) {
    const app = (entry && entry.application) || {};
    const appId = app.id;
    const flows = Array.isArray(entry && entry.flows) ? entry.flows : [];
    if (!claimsByApp.has(appId)) claimsByApp.set(appId, new Map());
    const mine = claimsByApp.get(appId);

    for (const flow of flows) {
      const normalised = normaliseFlow(flow);
      if (!normalised.ok) {
        // ⛔ A flow that cannot be read could claim ANY rule ANYWHERE. It is not
        // evidence of nothing; it is an absence of evidence about everything, so
        // it taints the whole fleet rather than one device.
        globalTaints.push(
          `"${app.name || appId}" declares a flow SecVault cannot read (${normalised.reason}) — `
          + 'until it is corrected, which rules that application depends on is unknown.'
        );
        continue;
      }

      for (const device of evaluable) {
        const result = evaluateFlowOnDevice(normalised, device.rules, device.objects, {
          addressObjects: device.addressObjects,
          serviceObjects: device.serviceObjects,
        });

        if (result.unverified) {
          for (const reason of result.unverifiedReasons) {
            taint(device.id, `${device.name || device.id}: ${reason}`);
          }
          // ⛔ Never allow an unverified evaluation to pass silently for want of
          // a printable reason — the flag is what withholds, the text only
          // explains.
          if (result.unverifiedReasons.length === 0) {
            taint(device.id, `${device.name || device.id}: the evaluation was not fully verified.`);
          }
        }

        for (const rule of result.permittingRules) {
          const key = `${device.id}::${rule.deviceRuleId}`;
          if (!claimantsByRule.has(key)) claimantsByRule.set(key, new Set());
          claimantsByRule.get(key).add(appId);

          // ⛔ Only an `allow` expectation makes a rule one that exists TO SERVE
          // this application. A rule permitting a flow the operator declared
          // must NEVER happen is this application's violation, not its
          // plumbing, and retiring the application is not the occasion to
          // delete it.
          if ((flow.expectation === 'deny' ? 'deny' : 'allow') !== 'allow') continue;

          if (!mine.has(key)) {
            mine.set(key, {
              key,
              deviceId: device.id,
              deviceName: device.name || null,
              deviceRuleId: rule.deviceRuleId,
              ruleIdVendor: rule.ruleId === undefined ? null : rule.ruleId,
              ruleName: rule.name === undefined ? null : rule.name,
              action: rule.action === undefined ? null : rule.action,
              sequence: rule.sequence === undefined ? null : rule.sequence,
              // ⛔ TRI-STATE, CARRIED THROUGH UNTOUCHED. null means no source
              // could report usage. It is not zero here and must not become
              // zero anywhere downstream.
              effectiveHitCount: rule.effectiveHitCount === undefined ? null : rule.effectiveHitCount,
              hasUnresolved: !!rule.hasUnresolved,
              servesFlowIds: [],
            });
          }
          const claim = mine.get(key);
          if (flow.id !== undefined && flow.id !== null && !claim.servesFlowIds.includes(flow.id)) {
            claim.servesFlowIds.push(flow.id);
          }
        }
      }
    }
  }

  return { claimsByApp, claimantsByRule, taintedDevices, globalTaints };
}

// ── The plan ───────────────────────────────────────────────────────────────

function candidatesFor(candidatesByDevice, deviceId) {
  if (!candidatesByDevice) return null;
  if (typeof candidatesByDevice.get === 'function') return candidatesByDevice.get(deviceId) || null;
  return candidatesByDevice[deviceId] || null;
}

/**
 * PURE. What retiring this application would propose, what it would withhold,
 * and why — given an already-loaded fleet, every declared application, and the
 * existing cleanup engine's own verdict per device.
 *
 * ⛔ THE TWO LISTS COME BACK TOGETHER, ALWAYS. The caller must be able to show
 * the withheld half beside the proposed half; a route or a screen that returns
 * only `proposed` presents a shorter list that looks complete, which is this
 * codebase's signature bug with a delete button attached.
 *
 * @param {object} args
 * @param {object} args.fleet - loadFleet() result
 * @param {{application:object, flows:object[]}[]} args.applications - ALL of them
 * @param {string} args.targetApplicationId
 * @param {Map<string,{eligible:object[],withheld:object[]}>} [args.candidatesByDevice]
 * @param {object} [args.index] - a buildClaimIndex() result, when the caller
 *   already has one. Evaluating the whole fleet twice for one answer is the
 *   dominant cost of this feature; nothing about the result changes.
 */
function planRetirement({ fleet, applications, targetApplicationId, candidatesByDevice, index }) {
  const apps = Array.isArray(applications) ? applications : [];
  const target = apps.find((a) => a && a.application && a.application.id === targetApplicationId);
  if (!target) return null;

  const { claimsByApp, claimantsByRule, taintedDevices, globalTaints } =
    index || buildClaimIndex(fleet, apps);

  const nameOf = new Map(apps.map((a) => [a.application.id, a.application.name || a.application.id]));
  const claims = Array.from((claimsByApp.get(targetApplicationId) || new Map()).values());

  const proposed = [];
  const withheld = [];

  for (const claim of claims) {
    const claimants = claimantsByRule.get(claim.key) || new Set();
    const others = Array.from(claimants).filter((id) => id !== targetApplicationId);

    // 1. ⛔ SHARED WITH ANOTHER APPLICATION. Checked first because it is the one
    // exclusion whose absence would break something an operator is still using.
    if (others.length > 0) {
      const names = others.map((id) => nameOf.get(id) || id);
      withheld.push({
        ...claim,
        reasonCode: REASONS.ALSO_CLAIMED,
        alsoClaimedBy: names,
        reason:
          `This rule also permits a declared flow of ${names.join(', ')}. Removing it would change `
          + 'what that application can do, so it is not part of retiring this one.',
      });
      continue;
    }

    // 2. ⛔ THE EVALUATION THAT ESTABLISHED "ONLY THIS ONE" WAS NOT VERIFIED.
    const deviceTaints = taintedDevices.get(claim.deviceId) || [];
    const taints = globalTaints.concat(deviceTaints);
    if (taints.length > 0) {
      withheld.push({
        ...claim,
        reasonCode: REASONS.UNVERIFIED,
        unverifiedReasons: taints,
        reason:
          'SecVault could not fully verify which applications this rule serves, so "only this '
          + 'application claims it" has not been established.',
      });
      continue;
    }

    // 3. ⛔ NO IDENTITY THAT SURVIVES THE NEXT COLLECTION. firewall_rules is
    // DELETEd and reinserted on every successful pull, so without
    // rule_id_vendor a request could never be verified afterwards — it would
    // sit unverifiable forever, which looks like progress and is not.
    if (claim.ruleIdVendor === null || claim.ruleIdVendor === undefined || claim.ruleIdVendor === '') {
      withheld.push({
        ...claim,
        reasonCode: REASONS.NO_VENDOR_ID,
        reason:
          'This rule carries no vendor identifier, so SecVault could not confirm afterwards whether '
          + 'it was actually removed.',
      });
      continue;
    }

    // 4. ⛔ USAGE WAS NEVER MEASURED. Refused, not warned about.
    if (claim.effectiveHitCount === null || claim.effectiveHitCount === undefined) {
      withheld.push({
        ...claim,
        reasonCode: REASONS.USAGE_NOT_MEASURED,
        reason:
          'Usage was never measured for this rule — neither this firewall nor its logs can report '
          + 'one. That is not evidence the rule is unused, so it is not offered for removal.',
      });
      continue;
    }

    // 5. The existing cleanup engine's own verdict for this device. ⛔ ITS
    // ANSWER IS AUTHORITATIVE, not advisory: createRequest re-checks against it
    // server-side and refuses anything it did not offer, so proposing a rule it
    // withheld would produce a request that simply fails at submission time.
    // Where it has its own sentence for the refusal, that sentence is what the
    // operator sees — two engines wording the same refusal differently is how
    // the two start disagreeing.
    const cand = candidatesFor(candidatesByDevice, claim.deviceId);
    if (cand) {
      const heldBack = (cand.withheld || []).find((w) => w.ruleIdVendor === claim.ruleIdVendor);
      if (heldBack) {
        withheld.push({
          ...claim,
          reasonCode: REASONS.CLEANUP_WITHHELD,
          reason: heldBack.reason,
        });
        continue;
      }
      const offered = (cand.eligible || []).find((e) => e.ruleIdVendor === claim.ruleIdVendor);
      if (!offered) {
        withheld.push({
          ...claim,
          reasonCode: REASONS.NOT_CLEANUP_ELIGIBLE,
          reason:
            'SecVault only submits rules its own rule analysis has independently flagged as '
            + 'removable (unused, redundant or shadowed) and not dismissed. This rule is not '
            + 'currently one of them, so retiring the application does not propose it. Review it '
            + 'with the firewall owner instead.',
        });
        continue;
      }
      proposed.push({ ...claim, findingType: offered.findingType, severity: offered.severity });
      continue;
    }

    // ⛔ NO ANSWER FROM THE CLEANUP ENGINE IS NOT A YES. A device whose
    // candidates could not be read is a failed read, and a failed read may never
    // authorise a deletion.
    withheld.push({
      ...claim,
      reasonCode: REASONS.NOT_CLEANUP_ELIGIBLE,
      reason:
        'SecVault could not read the rule-analysis findings for this firewall, so it cannot '
        + 'confirm this rule is independently flagged as removable.',
    });
  }

  const byDevice = new Map();
  for (const p of proposed) {
    if (!byDevice.has(p.deviceId)) {
      byDevice.set(p.deviceId, { deviceId: p.deviceId, deviceName: p.deviceName, ruleIdVendors: [] });
    }
    byDevice.get(p.deviceId).ruleIdVendors.push(p.ruleIdVendor);
  }

  // ⛔ WHY NOTHING WAS PROPOSED IS ALWAYS STATED. An empty proposal with no
  // explanation reads as "there is nothing to do here", which is a conclusion,
  // and four quite different situations produce the same empty list.
  const flows = Array.isArray(target.flows) ? target.flows : [];
  const notes = [];
  if (proposed.length === 0) {
    if (flows.length === 0) {
      notes.push({
        code: NOTES.NO_FLOWS,
        text:
          'This application declares no flows, so SecVault has no basis for saying any rule exists '
          + 'to serve it. Nothing is proposed — and nothing here says its rules are already gone.',
      });
    } else if (!flows.some((f) => (f.expectation === 'deny' ? 'deny' : 'allow') === 'allow')) {
      notes.push({
        code: NOTES.NO_ALLOW_FLOWS,
        text:
          'This application declares only flows that must be denied. A rule permitting one of those '
          + 'is a violation to review, never something retiring the application should delete.',
      });
    } else if (claims.length === 0) {
      notes.push({
        code: NOTES.NOTHING_CLAIMED,
        text:
          'No collected rule on any firewall permits a flow this application declares, so there is '
          + 'nothing that exists only to serve it. That is a statement about the rules SecVault has '
          + 'collected, not a guarantee the application has no remaining access.',
      });
    } else {
      notes.push({
        code: NOTES.ALL_WITHHELD,
        text:
          `All ${claims.length} rule${claims.length === 1 ? '' : 's'} this application claims were `
          + 'held back. Each reason is listed below — none of them says the rule should stay, only '
          + 'that SecVault will not propose deleting it on this evidence.',
      });
    }
  }

  return {
    application: target.application,
    proposed,
    withheld,
    notes,
    byDevice: Array.from(byDevice.values()),
    summary: {
      claimedRules: claims.length,
      proposedRules: proposed.length,
      withheldRules: withheld.length,
      devices: byDevice.size,
      // ⛔ Surfaced even when it withheld nothing, so a caller can say the
      // evaluation was clean rather than leaving the reader to infer it.
      globalTaints,
      taintedDeviceCount: taintedDevices.size,
    },
  };
}

// ── Plumbing ───────────────────────────────────────────────────────────────

async function loadApplicationsWithFlows(pool) {
  const apps = await listApplications(pool);
  const { rows } = await pool.query(
    `SELECT id, application_id, src, dst, protocol, port_start, port_end, expectation, note
       FROM application_flows`
  );
  const byApp = new Map();
  for (const f of rows) {
    if (!byApp.has(f.application_id)) byApp.set(f.application_id, []);
    byApp.get(f.application_id).push(f);
  }
  return apps.map((a) => ({ application: a, flows: byApp.get(a.id) || [] }));
}

/**
 * The plan, against the live database. Read-only: computes, persists nothing.
 */
async function planApplicationRetirement(pool, applicationId, options = {}) {
  const applications = await loadApplicationsWithFlows(pool);
  if (!applications.some((a) => a.application.id === applicationId)) return null;

  const fleet = await loadFleet(pool, options);

  // ⛔ THE FLEET IS EVALUATED EXACTLY ONCE. The index is what the whole answer
  // rests on and it is expensive — every declared flow of every application
  // against every device's rulebase — so it is built here and handed to
  // planRetirement rather than recomputed for a second pass. Only the devices
  // this application actually claims a rule on are then asked for their cleanup
  // verdict; the query is bounded by the claim, not by the fleet.
  const index = buildClaimIndex(fleet, applications);
  const deviceIds = new Set();
  for (const claim of (index.claimsByApp.get(applicationId) || new Map()).values()) {
    deviceIds.add(claim.deviceId);
  }

  const candidatesByDevice = new Map();
  for (const deviceId of deviceIds) {
    try {
      // eslint-disable-next-line no-await-in-loop
      candidatesByDevice.set(deviceId, await getCleanupCandidates(pool, deviceId));
    } catch (err) {
      // ⛔ Left ABSENT, never defaulted to an empty candidate set. An empty
      // `{eligible:[],withheld:[]}` would read as "this engine considered the
      // rule and declined it"; absence routes to the failed-read wording
      // instead, which is what actually happened.
      candidatesByDevice.delete(deviceId);
    }
  }

  const plan = planRetirement({
    fleet, applications, targetApplicationId: applicationId, candidatesByDevice, index,
  });
  plan.coverage = {
    windowDays: fleet.windowDays,
    activeDeviceCount: fleet.activeDeviceCount,
    devicesWithRules: fleet.devicesWithRules,
    devicesWithoutRules: fleet.devicesWithoutRules,
  };
  return plan;
}

/**
 * Raise the change requests — ONE PER DEVICE, because a rule change request
 * belongs to a device and its verification runs against that device's next
 * ruleset pull.
 *
 * ⛔ THE PLAN IS RECOMPUTED HERE AND THE CALLER'S RULE IDS ARE NEVER TRUSTED.
 * `expect` (what the operator was actually shown) can only NARROW the result:
 * anything the server now proposes that the reviewer did not see is reported as
 * drift and nothing is submitted. A confirmation screen that can be overtaken
 * by a re-collection between display and click is not a confirmation.
 *
 * ⛔ NOTHING IS DELETED HERE. This writes a request and submits it; the rules go
 * when a human edits the firewall, and the existing loop proves it afterwards.
 */
async function retireApplication(pool, applicationId, opts = {}) {
  const plan = await planApplicationRetirement(pool, applicationId, opts);
  if (!plan) return null;

  if (plan.proposed.length === 0) {
    return { ok: true, plan, requests: [], failures: [], submitted: 0 };
  }

  if (Array.isArray(opts.expect)) {
    const seen = new Set(opts.expect);
    const added = plan.proposed.filter((p) => !seen.has(p.ruleIdVendor)).map((p) => p.ruleIdVendor);
    if (added.length > 0) {
      return {
        ok: false,
        drifted: true,
        plan,
        added,
        requests: [],
        failures: [],
        submitted: 0,
        error:
          'The proposal changed since it was reviewed — these rules were not on the list that was '
          + `shown: ${added.join(', ')}. Nothing was submitted; review it again.`,
      };
    }
  }

  const appName = (plan.application && plan.application.name) || applicationId;
  const requests = [];
  const failures = [];

  for (const device of plan.byDevice) {
    const ruleIds = Array.isArray(opts.expect)
      ? device.ruleIdVendors.filter((id) => opts.expect.includes(id))
      : device.ruleIdVendors;
    if (ruleIds.length === 0) continue;
    try {
      // eslint-disable-next-line no-await-in-loop
      const created = await createRequest(pool, {
        deviceId: device.deviceId,
        title: `Retire ${appName}`,
        note: opts.note
          || `Raised by retiring the declared application "${appName}". These rules permit one or `
            + 'more of its declared flows and no other declared application claims them.',
        createdBy: opts.createdBy || null,
        ruleIds,
      });
      // eslint-disable-next-line no-await-in-loop
      const submitted = await submitRequest(pool, created.id);
      requests.push({
        deviceId: device.deviceId,
        deviceName: device.deviceName,
        requestId: submitted.id,
        status: submitted.status,
        ruleCount: ruleIds.length,
      });
    } catch (err) {
      // ⛔ PER-DEVICE ISOLATION, AND A FAILURE IS REPORTED, NEVER SWALLOWED.
      // createRequest re-checks eligibility itself, so a ruleset re-collected
      // between planning and submission can legitimately reject a device here —
      // and an operator who is told "done" while one firewall was skipped would
      // never look again.
      failures.push({
        deviceId: device.deviceId,
        deviceName: device.deviceName,
        error: err && err.message ? err.message : String(err),
      });
    }
  }

  return {
    ok: failures.length === 0,
    plan,
    requests,
    failures,
    submitted: requests.reduce((n, r) => n + r.ruleCount, 0),
  };
}

module.exports = {
  REASONS,
  NOTES,
  buildClaimIndex,
  planRetirement,
  loadApplicationsWithFlows,
  planApplicationRetirement,
  retireApplication,
};
