'use strict';
// Pins lib/engines/segmentation.js — declared segmentation intent, tested as
// "can this reach that" AND "did it" (Phase 3, v2.113.0).
//
// ⛔ THE TWO WAYS THIS CAN LIE, and both are worse than saying nothing:
//
//   1. UNDERSTATING REACHABILITY. `any` is a wildcard and appears 114 times on
//      the live fleet; treating it literally would report a wide-open path as
//      blocked. On a segmentation report that is the dangerous direction — a
//      hole reported as closed is not a missed finding, it is a false
//      assurance.
//   2. CALLING AN UNMEASURED PATH UNUSED. Fortinet over SSH reports no hit
//      counts at all (0 of 180 rules live). If a permitting rule cannot be
//      measured, the pair is UNKNOWN, never "never used" — recommending the
//      removal of a rule that may be carrying production traffic is exactly the
//      mistake every competing tool makes.
//
// The verdict names are asserted literally rather than by severity, because the
// whole value of the feature is that "permitted but unused" and "permitted,
// unmeasurable" are DIFFERENT answers.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  evaluateIntent,
  summarise,
  zoneListMatches,
  trafficEvidence,
  isAllowAction,
  isDenyAction,
} = require('../lib/engines/segmentation');

// A rule as ruleHitCorrelation hands it over.
const rule = (over) => ({
  device_id: 'd1',
  enabled: true,
  action: 'allow',
  src_zones: ['branch'],
  dst_zones: ['cardholder'],
  rule_name: 'r',
  sequence_number: 1,
  effectiveHitCount: 0,
  logEvidence: 'measured-zero',
  ...over,
});

const DENY_INTENT = { sourceZone: 'branch', destZone: 'cardholder', expectation: 'deny' };
const ALLOW_INTENT = { sourceZone: 'branch', destZone: 'core', expectation: 'allow' };

describe('zone matching', () => {
  it('matches exactly, case-insensitively', () => {
    assert.equal(zoneListMatches(['LAN'], 'lan'), true);
    assert.equal(zoneListMatches(['lan'], 'LAN'), true);
    assert.equal(zoneListMatches(['lan'], 'dmz1'), false);
  });

  it('⛔ treats `any` as a WILDCARD', () => {
    // 114 occurrences live. Matching it literally reports open paths as blocked.
    assert.equal(zoneListMatches(['any'], 'cardholder'), true);
    assert.equal(zoneListMatches(['ANY'], 'anything-at-all'), true);
  });

  it('⛔ treats an EMPTY or absent zone list as unconstrained', () => {
    // A rule with no zone constraint constrains nothing. Reading it as
    // "matches nothing" silently drops real rules from the analysis.
    assert.equal(zoneListMatches([], 'cardholder'), true);
    assert.equal(zoneListMatches(null, 'cardholder'), true);
    assert.equal(zoneListMatches(undefined, 'cardholder'), true);
  });

  it('knows the allow and deny action families', () => {
    for (const a of ['allow', 'accept', 'permit']) assert.equal(isAllowAction(a), true);
    // ⛔ 'block' belongs to the deny family — firewall_rules.action says so.
    for (const d of ['deny', 'drop', 'reject', 'block']) assert.equal(isDenyAction(d), true);
    assert.equal(isAllowAction('deny'), false);
    assert.equal(isDenyAction('allow'), false);
  });
});

describe('⛔ traffic evidence is TRI-STATE', () => {
  it('true when any permitting rule has hits', () => {
    const e = trafficEvidence([rule({ effectiveHitCount: 0 }), rule({ effectiveHitCount: 42 })]);
    assert.equal(e.did, true);
  });

  it('false only when EVERY permitting rule was measured and all were zero', () => {
    const e = trafficEvidence([rule({ effectiveHitCount: 0 }), rule({ effectiveHitCount: 0 })]);
    assert.equal(e.did, false);
    assert.equal(e.measured, 2);
  });

  it('⛔ NULL WINS OVER FALSE — one unmeasured rule makes the pair unknown', () => {
    // The unmeasured rule might be the one carrying the traffic. Collapsing to
    // "no traffic" because the others were quiet is how an in-use path gets
    // recommended for deletion.
    const e = trafficEvidence([
      rule({ effectiveHitCount: 0, logEvidence: 'measured-zero' }),
      rule({ effectiveHitCount: null, logEvidence: 'no-coverage' }),
    ]);
    assert.equal(e.did, null);
    assert.equal(e.unmeasured, 1);
    assert.ok(e.reasons.includes('no-coverage'));
  });

  it('no rules at all is unknown, never false', () => {
    assert.equal(trafficEvidence([]).did, null);
  });
});

describe('deny intent', () => {
  it('⛔ permitted AND used is the worst verdict', () => {
    const r = evaluateIntent(DENY_INTENT, [rule({ effectiveHitCount: 500 })]);
    assert.equal(r.verdict, 'violation_active');
    assert.equal(r.can, true);
    assert.equal(r.did, true);
  });

  it('⛔ permitted but NEVER USED is its own verdict — the cleanup backlog', () => {
    // The cell no competitor can produce: a standing hole with no demonstrated
    // purpose, and the safest possible thing to close.
    const r = evaluateIntent(DENY_INTENT, [rule({ effectiveHitCount: 0 })]);
    assert.equal(r.verdict, 'violation_permitted');
    assert.equal(r.did, false);
  });

  it('⛔ permitted but UNMEASURABLE is NOT reported as unused', () => {
    const r = evaluateIntent(DENY_INTENT, [
      rule({ effectiveHitCount: null, logEvidence: 'no-coverage' }),
    ]);
    assert.equal(r.verdict, 'violation_unverified');
    assert.equal(r.did, null);
    assert.notEqual(r.verdict, 'violation_permitted');
  });

  it('nothing permits it -> blocked as intended', () => {
    const r = evaluateIntent(DENY_INTENT, [rule({ action: 'deny' })]);
    assert.equal(r.verdict, 'ok_blocked');
    assert.equal(r.can, false);
  });

  it('⛔ an any->any ALLOW rule is a violation, not a miss', () => {
    const r = evaluateIntent(DENY_INTENT, [
      rule({ src_zones: ['any'], dst_zones: ['any'], effectiveHitCount: 7 }),
    ]);
    assert.equal(r.verdict, 'violation_active');
  });

  it('a DISABLED permitting rule does not create a violation', () => {
    const r = evaluateIntent(DENY_INTENT, [rule({ enabled: false, effectiveHitCount: 99 })]);
    assert.equal(r.verdict, 'ok_blocked');
  });
});

describe('allow intent', () => {
  const allowRule = (over) => rule({ dst_zones: ['core'], ...over });

  it('permitted and used is fine', () => {
    const r = evaluateIntent(ALLOW_INTENT, [allowRule({ effectiveHitCount: 10 })]);
    assert.equal(r.verdict, 'ok_in_use');
  });

  it('⛔ permitted but never used is a REMOVAL CANDIDATE, not a pass', () => {
    const r = evaluateIntent(ALLOW_INTENT, [allowRule({ effectiveHitCount: 0 })]);
    assert.equal(r.verdict, 'unused_permission');
  });

  it('permitted but unmeasurable is neither', () => {
    const r = evaluateIntent(ALLOW_INTENT, [allowRule({ effectiveHitCount: null, logEvidence: 'no-coverage' })]);
    assert.equal(r.verdict, 'ok_unverified');
  });

  it('⛔ expected to work but nothing permits it is surfaced, not ignored', () => {
    // Either the intent is wrong or a rule is missing. Both need a human.
    const r = evaluateIntent(ALLOW_INTENT, [allowRule({ action: 'deny' })]);
    assert.equal(r.verdict, 'expected_allow_missing');
  });
});

describe('⛔ missing data never becomes a clean result', () => {
  it('no rules collected is UNKNOWN, not "blocked"', () => {
    // A fleet whose rulesets were never pulled would otherwise report every
    // deny-intent as satisfied — a perfect score generated from missing data.
    const r = evaluateIntent(DENY_INTENT, [], { rulesCollected: false });
    assert.equal(r.verdict, 'unknown');
    assert.equal(r.can, null);
    assert.ok(r.evidenceReasons.includes('no-rules-collected'));
  });

  it('an empty rule array is unknown even without the flag', () => {
    assert.equal(evaluateIntent(DENY_INTENT, []).verdict, 'unknown');
  });

  it('the summary counts what could not be measured, separately', () => {
    const results = [
      evaluateIntent(DENY_INTENT, [rule({ effectiveHitCount: 5 })]),          // active violation
      evaluateIntent(DENY_INTENT, [rule({ effectiveHitCount: null })]),       // unverified
      evaluateIntent(ALLOW_INTENT, [rule({ dst_zones: ['core'], effectiveHitCount: 0 })]), // unused
      evaluateIntent(DENY_INTENT, [], { rulesCollected: false }),             // unknown
    ];
    const s = summarise(results);
    assert.equal(s.total, 4);
    assert.equal(s.violations, 2);
    assert.equal(s.activeViolations, 1);
    assert.equal(s.unusedPermissions, 1);
    assert.equal(s.unknown, 1);
    // ⛔ A matrix where cells could not be evaluated is not a pass rate.
    assert.ok(s.unmeasurable >= 2);
  });
});

describe('examples are capped', () => {
  it('an any->any rule does not return the whole rulebase', () => {
    const many = Array.from({ length: 50 }, (_, i) =>
      rule({ src_zones: ['any'], dst_zones: ['any'], rule_name: 'r' + i }));
    const r = evaluateIntent(DENY_INTENT, many);
    assert.equal(r.permittingRuleCount, 50);
    assert.ok(r.examples.length <= 5, 'examples must be capped for the UI');
  });
});

describe('the segmentation sentence may not claim more than was measured', () => {
  const { buildSegmentationAnswer } = require('../lib/answers');
  const base = { intents: [1], windowDays: 30, rulesWithoutHitData: 0 };

  it('⛔ an EMPTY matrix is unknown, never a pass', () => {
    // Nobody has said what should be segmented. That is the least informed
    // state possible, not a clean one.
    const a = buildSegmentationAnswer({ intents: [], summary: { total: 0 } });
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /No segmentation intent has been declared/);
  });

  it('leads with violations that are actually carrying traffic', () => {
    const a = buildSegmentationAnswer({
      ...base, summary: { total: 9, violations: 3, activeViolations: 1, unusedPermissions: 0, unmeasurable: 0 },
    });
    assert.equal(a.tone, 'critical');
    assert.match(a.sentence, /carrying traffic right now/);
  });

  it('distinguishes a standing hole from an active breach', () => {
    const a = buildSegmentationAnswer({
      ...base, summary: { total: 9, violations: 2, activeViolations: 0, unusedPermissions: 0, unmeasurable: 0 },
    });
    assert.equal(a.tone, 'critical');
    assert.match(a.sentence, /standing holes rather than active breaches/);
  });

  it('⛔ REFUSES an all-clear while any path was unmeasurable', () => {
    const a = buildSegmentationAnswer({
      ...base, rulesWithoutHitData: 232,
      summary: { total: 9, violations: 0, activeViolations: 0, unusedPermissions: 0, unmeasurable: 3 },
    });
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /not every path could be/);
    assert.match(a.coverage, /3 of 9/);
    assert.match(a.coverage, /232 rules cannot report usage/);
  });

  it('allows the all-clear only when everything was measurable', () => {
    const a = buildSegmentationAnswer({
      ...base, summary: { total: 9, violations: 0, activeViolations: 0, unusedPermissions: 0, unmeasurable: 0 },
    });
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
    assert.match(a.sentence, /every one was measurable/);
  });

  it('never throws on a missing or malformed result', () => {
    for (const bad of [null, undefined, {}, { intents: 'x' }]) {
      const a = buildSegmentationAnswer(bad);
      assert.equal(typeof a.sentence, 'string');
      assert.equal(a.tone, 'unknown');
    }
  });
});
