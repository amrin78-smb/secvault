'use strict';

// lib/engines/upgradePlan.js
//
// ONE UPGRADE DECISION PER FIREWALL, from the CVE assessments already computed.
// PURE — takes already-fetched rows, returns a plan. No pool, no clock, no
// queries; `upgradePlanData.js` is the plumbing.
//
// ⛔ AN ITEM IS A DECISION, NOT A FINDING — the rule /work already follows.
// Measured on the live fleet 2026-09-25: 246 open assessments across 16
// firewalls collapse to 16 upgrade decisions, because every Palo Alto carries
// the same 17 advisories across 7 distinct target versions and ONE upgrade
// clears all 17. A list whose length grows with the advisory count rather than
// with the outstanding work is a database dump, not a plan.
//
// ── ⛔ THE THING THIS FILE MUST GET RIGHT ─────────────────────────────────
//
// A BRANCH JUMP IS NOT A PATCH, AND MUST NEVER BE RECOMMENDED AS ONE. The
// first prototype ranked purely on "clears the most, KEV first" and told three
// FortiGates running 7.4.9 to go to 7.6.7 — a platform migration — because it
// cleared eight advisories against 7.4.11's fewer. That is a different KIND of
// change: a different feature set, a different support window, a different
// regression risk, and a maintenance window nobody scheduled from a CVE list.
//
// So the plan reports the two separately and ALWAYS shows both:
//   * `inBranch`    — the best target inside the version branch the device is
//                     already on. A patch upgrade.
//   * `crossBranch` — what a branch move would additionally clear, per branch.
// `recommended` names the in-branch option whenever one exists, even when a
// branch move clears more, and states what the move would add. The operator
// chooses the bigger change; the product does not choose it for them.
//
// ⛔ AND "CLEARS" IS A CLAIM ABOUT THE ADVISORY SET WE HOLD, not about safety.
// It means: for these N assessments, the recorded fixed version is at or below
// this target. It does not mean the device becomes free of vulnerabilities, and
// no wording here may imply that.

const { parseVersion, compareVersions } = require('./versionComparator');

/**
 * The branch a version belongs to: its first two components.
 *
 * ⛔ TWO COMPONENTS, NOT ONE. FortiOS 7.4 and 7.6 are different products in
 * every way that matters operationally, though both are "7". Palo Alto 11.1
 * and 11.2 likewise. A one-component branch would call a 7.4 -> 7.6 move
 * in-branch and reintroduce exactly the conflation this file exists to prevent.
 */
function branchOf(vendor, version) {
  if (typeof version !== 'string' || version.trim() === '') return null;
  // ⛔ A STRING WITH NO DIGIT CANNOT YIELD A VERSION, and parseVersion does not
  // say so — it returns a tuple of ZEROS. Measured: parseVersion('fortinet',
  // 'nope') is [0,0,...], so branchOf returned the string "0.0", two
  // unreadable versions shared that branch, and the plan would have called
  // them in-branch with each other and recommended "stay on your current
  // branch" from two values it could not read. A fabricated zero presented as
  // a measurement — this codebase's most-repeated bug, in a version parser.
  if (!/\d/.test(version)) return null;
  const t = parseVersion(vendor, version);
  if (!Array.isArray(t) || t.length === 0) return null;
  // ⛔ EVERY COMPONENT MUST BE A REAL NUMBER. parseVersion returns a tuple for
  // input it could not read — NaN entries, or zeros — and `[NaN, NaN].join('.')`
  // is the string "NaN.NaN", which compares equal to itself. Two unparseable
  // versions would then share a branch and be reported as in-branch with each
  // other: a recommendation to "stay on your current branch" derived from two
  // values we could not read at all.
  const head = t.slice(0, 2);
  if (head.length < 2 || !head.every((n) => Number.isFinite(n))) return null;
  return head.join('.');
}

/** Does `target` clear an assessment whose own recorded fix is `fixedIn`? */
function clears(vendor, fixedIn, targetTuple) {
  if (!fixedIn) return false;
  const f = parseVersion(vendor, fixedIn);
  if (!Array.isArray(f) || f.length === 0) return false;
  return compareVersions(f, targetTuple) <= 0;
}

/**
 * Score a candidate target against a set of assessments.
 * ⛔ KEV IS COUNTED SEPARATELY, never folded into the total. Branch 1 of the
 * priority tree is "known exploited in the wild"; one of those outranks a
 * dozen advisories nobody has ever seen used.
 */
function scoreTarget(vendor, target, assessments) {
  const tt = parseVersion(vendor, target);
  const cleared = assessments.filter((a) => clears(vendor, a.fixed_in, tt));
  return {
    target,
    tuple: tt,
    clears: cleared.length,
    kevCleared: cleared.filter((a) => a.kev_listed).length,
    patchNowCleared: cleared.filter((a) => a.priority_band === 'patch_now').length,
  };
}

// Best of a candidate list: most KEV, then most cleared, then the LOWEST
// version. ⛔ The tie-break matters — two targets clearing the same set are not
// equivalent, and the smaller move is the one to offer.
function bestOf(candidates) {
  let best = null;
  for (const c of candidates) {
    if (!best
      || c.kevCleared > best.kevCleared
      || (c.kevCleared === best.kevCleared && c.clears > best.clears)
      || (c.kevCleared === best.kevCleared && c.clears === best.clears
          && compareVersions(c.tuple, best.tuple) < 0)) {
      best = c;
    }
  }
  return best;
}

/**
 * Build one firewall's upgrade plan.
 *
 * @param {{id, name, vendor, asset_criticality}} device
 * @param {string|null} runningVersion  latest device_versions.version_string
 * @param {Array<{cve_id, fixed_in, kev_listed, priority_band, cvss_score}>} assessments
 *        the device's OPEN assessments (version_affected = true)
 * @returns {object} the plan
 */
function buildUpgradePlan(device, runningVersion, assessments) {
  const vendor = device && device.vendor;
  const rows = Array.isArray(assessments) ? assessments : [];

  // ⛔ NO RUNNING VERSION MEANS NO PLAN, AND SAYS SO. Ranking targets against
  // an unknown current version would produce a confident recommendation from
  // nothing — and "upgrade to X" is an instruction somebody acts on.
  const currentBranch = runningVersion ? branchOf(vendor, runningVersion) : null;

  // ⛔ COUNTED AND NAMED, NEVER DROPPED. An assessment with no recorded fix
  // version is the most important row on the page when it is also urgent: it
  // is work that cannot be planned, and folding it into "everything else"
  // hides exactly the thing an operator needs to chase.
  const unplannable = rows
    .filter((a) => !a.fixed_in)
    .map((a) => ({
      cve_id: a.cve_id,
      kev_listed: !!a.kev_listed,
      priority_band: a.priority_band || null,
      reason: 'no_known_fix',
    }));

  const plannable = rows.filter((a) => a.fixed_in);
  const targets = [...new Set(plannable.map((a) => a.fixed_in))];
  const scored = targets.map((t) => scoreTarget(vendor, t, plannable));

  const inBranchCandidates = currentBranch
    ? scored.filter((c) => branchOf(vendor, c.target) === currentBranch)
    : [];
  const inBranch = bestOf(inBranchCandidates);

  // One entry per OTHER branch, each showing its own best target.
  //
  // ⛔ "OTHER" IS MEANINGLESS WITHOUT A CURRENT BRANCH, and leaving this to
  // fall through was a live contradiction of this file's own header. With
  // `runningVersion` null, `currentBranch` is null, so `b === currentBranch`
  // was false for EVERY target: all of them landed here, `inBranch` stayed
  // null, and `recommendation` became 'cross_branch_only' — a BRANCH-MOVE
  // RECOMMENDATION FOR A DEVICE WHOSE CURRENT VERSION IS UNKNOWN. The header
  // four screens up says the opposite in capitals.
  //
  // ⛔ AND MY OWN TEST PASSED OVER IT. It asserted `inBranch === null` and
  // `currentBranch === null` and stopped, never checking what was RECOMMENDED
  // — so it confirmed two symptoms of the bug and called them the fix. Found
  // by the agent building the data layer, reading the header against the code.
  const otherBranches = new Map();
  if (currentBranch) {
    for (const c of scored) {
      const b = branchOf(vendor, c.target);
      if (!b || b === currentBranch) continue;
      const cur = otherBranches.get(b);
      if (!cur || bestOf([c, cur]) === c) otherBranches.set(b, c);
    }
  }
  const crossBranch = [...otherBranches.entries()]
    .map(([branch, c]) => ({ ...c, branch }))
    .sort((a, b) => b.kevCleared - a.kevCleared || b.clears - a.clears);

  // ⛔ THE IN-BRANCH OPTION IS THE RECOMMENDATION WHENEVER ONE EXISTS, even
  // when a branch move clears strictly more. See the header: those are
  // different kinds of change and the operator makes that call.
  //
  // ⛔ AND A DEVICE WITH NO KNOWN VERSION IS NOT PLANNABLE AT ALL. Both
  // "stay on your branch" and "move branch" are statements ABOUT a current
  // version; without one, neither is a claim we are entitled to make. The
  // blocking reason travels with the plan so a renderer states the gap rather
  // than rendering an empty row that reads as "nothing to do".
  let blockedReason = null;
  if (!currentBranch) {
    blockedReason = runningVersion ? 'unreadable_running_version' : 'no_running_version';
  }

  let recommendation = 'none';
  if (blockedReason) recommendation = 'none';
  else if (inBranch) recommendation = 'in_branch';
  else if (crossBranch.length > 0) recommendation = 'cross_branch_only';

  const chosen = inBranch || (crossBranch.length ? crossBranch[0] : null);

  return {
    deviceId: device && device.id,
    deviceName: device && device.name,
    vendor,
    assetCriticality: (device && device.asset_criticality) || null,
    runningVersion: runningVersion || null,
    currentBranch,
    openCount: rows.length,
    plannableCount: plannable.length,
    unplannableCount: unplannable.length,
    unplannable,
    kevOpen: rows.filter((a) => a.kev_listed).length,
    inBranch,
    crossBranch,
    recommendation,
    blockedReason,
    // What the recommended move leaves behind — the honest remainder.
    remainingAfterRecommended: chosen ? rows.length - chosen.clears : rows.length,
    // ⛔ Stated, not implied: a branch move may clear more, and the operator
    // is told by how much rather than being steered.
    crossBranchWouldAdd: inBranch && crossBranch.length
      ? Math.max(0, crossBranch[0].clears - inBranch.clears)
      : 0,
  };
}

/**
 * Rank a fleet's plans. ⛔ KEV first, then patch_now, then how much one move
 * clears — the same ordering the priority tree uses, so the plan cannot
 * disagree with the page it came from.
 */
function rankPlans(plans) {
  // ⛔ Array.isArray, not `|| []`. A string spreads into characters and a
  // number throws "is not iterable" — and this runs on whatever a caller
  // hands it, including a failed query result.
  return [...(Array.isArray(plans) ? plans : [])].sort((a, b) => {
    const aK = a.inBranch ? a.inBranch.kevCleared : 0;
    const bK = b.inBranch ? b.inBranch.kevCleared : 0;
    if (aK !== bK) return bK - aK;
    if (a.kevOpen !== b.kevOpen) return b.kevOpen - a.kevOpen;
    const aC = a.inBranch ? a.inBranch.clears : 0;
    const bC = b.inBranch ? b.inBranch.clears : 0;
    if (aC !== bC) return bC - aC;
    return String(a.deviceName || '').localeCompare(String(b.deviceName || ''));
  });
}

/** Fleet totals. ⛔ `unplannable` is surfaced at fleet level too. */
function summarisePlans(plans) {
  const list = Array.isArray(plans) ? plans : [];
  return {
    devices: list.length,
    decisions: list.filter((p) => p.recommendation !== 'none').length,
    openAssessments: list.reduce((n, p) => n + p.openCount, 0),
    unplannable: list.reduce((n, p) => n + p.unplannableCount, 0),
    kevUnplannable: list.reduce(
      (n, p) => n + p.unplannable.filter((u) => u.kev_listed).length, 0
    ),
    devicesWithNoVersion: list.filter((p) => !p.runningVersion).length,
  };
}

module.exports = { buildUpgradePlan, rankPlans, summarisePlans, branchOf, scoreTarget, bestOf };
