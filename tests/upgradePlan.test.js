'use strict';
// tests/upgradePlan.test.js
//
// Pins lib/engines/upgradePlan.js — one upgrade DECISION per firewall, from
// the CVE assessments already computed.
//
// ⛔ THE FIRST PROTOTYPE GAVE DANGEROUS ADVICE, AND IT LOOKED LIKE GOOD ADVICE.
// Ranking purely on "clears the most, KEV first" told three FortiGates running
// 7.4.9 to upgrade to 7.6.7 — a PLATFORM MIGRATION — because it cleared eight
// advisories where the in-branch 7.4.12 cleared three. Both numbers were
// correct. The recommendation was still wrong, because a branch move is a
// different KIND of change: different feature set, different support window,
// different regression risk, and a maintenance window nobody scheduled off a
// CVE list.
//
// Nothing would have caught that. The plan would have rendered, the arithmetic
// would have checked out, and an operator following it would have discovered
// the difference during the change window. So the branch rule is the thing
// this file mostly exists to hold.
//
// The fixtures are the live fleet as measured 2026-09-25.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  buildUpgradePlan, rankPlans, summarisePlans, branchOf,
} = require('../lib/engines/upgradePlan');

const FORTI = { id: 'd1', name: 'TSR-TL', vendor: 'fortinet', asset_criticality: 'medium' };
const PALO = { id: 'd2', name: 'IDC FW', vendor: 'paloalto', asset_criticality: 'high' };

// The live 7.4.9 case: an in-branch fix that clears the KEV, and a branch move
// that clears more.
const FORTI_ROWS = [
  { cve_id: 'CVE-2026-24858', fixed_in: '7.4.11', kev_listed: true, priority_band: 'patch_now' },
  { cve_id: 'CVE-A', fixed_in: '7.4.12', kev_listed: false, priority_band: 'scheduled' },
  { cve_id: 'CVE-B', fixed_in: '7.4.12', kev_listed: false, priority_band: 'scheduled' },
  { cve_id: 'CVE-C', fixed_in: '7.6.7', kev_listed: false, priority_band: 'scheduled' },
  { cve_id: 'CVE-D', fixed_in: '7.6.7', kev_listed: false, priority_band: 'scheduled' },
  // Unplannable: no recorded fix.
  { cve_id: 'CVE-E', fixed_in: null, kev_listed: false, priority_band: 'scheduled' },
];

describe('branchOf — two components, not one', () => {
  it('separates FortiOS 7.4 from 7.6', () => {
    assert.notEqual(branchOf('fortinet', '7.4.11'), branchOf('fortinet', '7.6.7'));
  });

  it('⛔ a ONE-component branch would call 7.4 -> 7.6 in-branch', () => {
    // Both are "7". That is the conflation the whole file exists to prevent,
    // and it is the single most tempting simplification here.
    assert.equal(branchOf('fortinet', '7.4.11'), '7.4');
    assert.equal(branchOf('fortinet', '7.6.7'), '7.6');
    assert.equal(branchOf('paloalto', '11.1.16-h2'), '11.1');
  });

  it('an unparseable version has no branch, rather than a made-up one', () => {
    for (const bad of [null, undefined, '', 'nope', {}]) {
      assert.equal(branchOf('fortinet', bad), null);
    }
  });
});

describe('⛔ a branch jump is never recommended as though it were a patch', () => {
  const plan = buildUpgradePlan(FORTI, 'v7.4.9,build2829,250924', FORTI_ROWS);

  it('recommends the IN-BRANCH target even though a branch move clears more', () => {
    assert.equal(plan.recommendation, 'in_branch');
    assert.equal(plan.currentBranch, '7.4');
    assert.equal(branchOf('fortinet', plan.inBranch.target), '7.4');
  });

  it('the in-branch target clears the KEV — the thing that makes it urgent', () => {
    assert.equal(plan.inBranch.kevCleared, 1);
    assert.equal(plan.inBranch.clears, 3);
  });

  it('the branch move is OFFERED, with what it would add, not chosen', () => {
    assert.ok(plan.crossBranch.length > 0);
    assert.equal(plan.crossBranch[0].branch, '7.6');
    // 5 cleared by 7.6.7 vs 3 in-branch.
    assert.equal(plan.crossBranchWouldAdd, 2);
  });

  it('⛔ the two are kept in SEPARATE fields, never one ranked list', () => {
    // A single ranked list is how the wrong answer gets back in: the reader
    // takes the top row, and the top row is whichever clears most.
    assert.ok(Object.prototype.hasOwnProperty.call(plan, 'inBranch'));
    assert.ok(Array.isArray(plan.crossBranch));
    assert.ok(!plan.crossBranch.some((c) => c.branch === plan.currentBranch));
  });

  it('with NO in-branch fix available, a branch move is named as exactly that', () => {
    const rows = FORTI_ROWS.filter((r) => !r.fixed_in || !r.fixed_in.startsWith('7.4'));
    const p = buildUpgradePlan(FORTI, 'v7.4.9,build2829,250924', rows);
    assert.equal(p.recommendation, 'cross_branch_only');
    assert.equal(p.inBranch, null);
  });
});

describe('⛔ what cannot be planned is counted and named', () => {
  const plan = buildUpgradePlan(FORTI, 'v7.4.9,build2829,250924', FORTI_ROWS);

  it('an assessment with no recorded fix is not silently dropped', () => {
    assert.equal(plan.unplannableCount, 1);
    assert.deepEqual(plan.unplannable.map((u) => u.cve_id), ['CVE-E']);
    assert.equal(plan.unplannable[0].reason, 'no_known_fix');
  });

  it('it is excluded from `clears` but NOT from `openCount`', () => {
    // Otherwise the plan reports a smaller problem than exists.
    assert.equal(plan.openCount, 6);
    assert.equal(plan.plannableCount, 5);
    assert.equal(plan.remainingAfterRecommended, 3);
  });

  it('⛔ a KEV with no fix is flagged as such — the worst row available', () => {
    const p = buildUpgradePlan(FORTI, 'v7.4.9', [
      { cve_id: 'CVE-X', fixed_in: null, kev_listed: true, priority_band: 'patch_now' },
    ]);
    assert.equal(p.unplannable[0].kev_listed, true);
    assert.equal(p.recommendation, 'none');
  });
});

describe('⛔ no running version means no plan, not a confident guess', () => {
  it('a device whose version was never collected gets no recommendation', () => {
    // "Upgrade to X" is an instruction somebody acts on. Ranking targets
    // against an unknown current version would produce one out of nothing.
    for (const missing of [null, undefined, '']) {
      const p = buildUpgradePlan(FORTI, missing, FORTI_ROWS);
      assert.equal(p.currentBranch, null);
      assert.equal(p.inBranch, null);
      assert.equal(p.runningVersion, null);
    }
  });

  it('...and the fleet summary counts those devices separately', () => {
    const s = summarisePlans([
      buildUpgradePlan(FORTI, null, FORTI_ROWS),
      buildUpgradePlan(PALO, '11.1.13-h5', []),
    ]);
    assert.equal(s.devicesWithNoVersion, 1);
  });
});

describe('the live Palo Alto case: one upgrade clears all seventeen', () => {
  const rows = Array.from({ length: 17 }, (_, i) => ({
    cve_id: `CVE-P${i}`,
    fixed_in: ['11.1.14-h1', '11.1.15', '11.1.16-h2'][i % 3],
    kev_listed: false,
    priority_band: 'scheduled',
  }));

  it('picks the single target that clears the lot', () => {
    const p = buildUpgradePlan(PALO, '11.1.13-h5', rows);
    assert.equal(p.inBranch.target, '11.1.16-h2');
    assert.equal(p.inBranch.clears, 17);
    assert.equal(p.remainingAfterRecommended, 0);
    assert.equal(p.crossBranch.length, 0, 'every fix is in the running branch');
  });

  it('⛔ the tie-break takes the LOWEST version that clears the same set', () => {
    // Two targets clearing an identical set are not equivalent; the smaller
    // move is the one to offer.
    const same = [
      { cve_id: 'A', fixed_in: '11.1.14-h1', kev_listed: false, priority_band: 'scheduled' },
    ];
    const p = buildUpgradePlan(PALO, '11.1.13-h5', same);
    assert.equal(p.inBranch.target, '11.1.14-h1');
  });
});

describe('rankPlans and summarisePlans', () => {
  it('KEV outranks sheer volume', () => {
    const kevDevice = buildUpgradePlan(FORTI, 'v7.4.9', FORTI_ROWS);
    const bulk = buildUpgradePlan(PALO, '11.1.13-h5', Array.from({ length: 17 }, (_, i) => ({
      cve_id: `CVE-P${i}`, fixed_in: '11.1.16-h2', kev_listed: false, priority_band: 'scheduled',
    })));
    const [first] = rankPlans([bulk, kevDevice]);
    assert.equal(first.deviceName, 'TSR-TL', 'a KEV-clearing upgrade must rank above a bigger one');
  });

  it('⛔ the fleet summary surfaces what could NOT be planned', () => {
    const s = summarisePlans([buildUpgradePlan(FORTI, 'v7.4.9', FORTI_ROWS)]);
    assert.equal(s.devices, 1);
    assert.equal(s.decisions, 1);
    assert.equal(s.openAssessments, 6);
    assert.equal(s.unplannable, 1);
  });

  it('never throws on junk', () => {
    for (const bad of [null, undefined, 'x', 0, {}]) {
      assert.doesNotThrow(() => buildUpgradePlan(bad, bad, bad));
      assert.doesNotThrow(() => rankPlans(bad));
      assert.doesNotThrow(() => summarisePlans(bad));
    }
    const p = buildUpgradePlan(null, null, null);
    assert.equal(p.openCount, 0);
    assert.equal(p.recommendation, 'none');
  });
});

// ── The bug my own test walked past ──────────────────────────────────────

describe('⛔ no running version means NO RECOMMENDATION, not a branch move', () => {
  // The header of upgradePlan.js says this in capitals. The code did not hold
  // to it: with `runningVersion` null, `currentBranch` is null, so
  // `b === currentBranch` was false for EVERY target — all of them landed in
  // crossBranch, and `recommendation` became 'cross_branch_only'. A BRANCH-MOVE
  // RECOMMENDATION FOR A DEVICE WHOSE CURRENT VERSION IS UNKNOWN.
  //
  // ⛔ AND THE TEST ABOVE PASSED OVER IT. It asserted `inBranch === null` and
  // `currentBranch === null` and stopped — two SYMPTOMS of the bug, checked and
  // called a fix. Nothing asserted what was actually RECOMMENDED, which is the
  // only field an operator acts on. Found by the agent building the data layer,
  // reading the header against the code rather than against the test.
  const ROWS = [
    { cve_id: 'CVE-A', fixed_in: '7.6.7', kev_listed: false, priority_band: 'scheduled' },
    { cve_id: 'CVE-B', fixed_in: '7.4.12', kev_listed: true, priority_band: 'patch_now' },
  ];

  it('recommends NOTHING when the running version is absent', () => {
    for (const missing of [null, undefined, '']) {
      const p = buildUpgradePlan(FORTI, missing, ROWS);
      assert.equal(p.recommendation, 'none', 'a device with no known version was given a plan');
      assert.equal(p.blockedReason, 'no_running_version');
    }
  });

  it('recommends NOTHING when the running version cannot be read', () => {
    // Distinguished from absent: the collector returned something, and we could
    // not parse it. Different fact, different thing for an operator to chase.
    const p = buildUpgradePlan(FORTI, 'not-a-version', ROWS);
    assert.equal(p.recommendation, 'none');
    assert.equal(p.blockedReason, 'unreadable_running_version');
  });

  it('⛔ and offers no cross-branch options either', () => {
    // "Other branch" is a statement ABOUT a current branch. Without one it is
    // not a weaker claim, it is not a claim at all.
    const p = buildUpgradePlan(FORTI, null, ROWS);
    assert.deepEqual(p.crossBranch, []);
    assert.equal(p.inBranch, null);
  });

  it('but still counts the open work, so the device is not rendered as clear', () => {
    const p = buildUpgradePlan(FORTI, null, ROWS);
    assert.equal(p.openCount, 2);
    assert.equal(p.kevOpen, 1);
    assert.equal(p.remainingAfterRecommended, 2);
  });

  it('a device WITH a version is unaffected and still gets its plan', () => {
    const p = buildUpgradePlan(FORTI, 'v7.4.9,build2829,250924', ROWS);
    assert.equal(p.blockedReason, null);
    assert.equal(p.recommendation, 'in_branch');
    assert.equal(p.inBranch.target, '7.4.12');
  });
});
