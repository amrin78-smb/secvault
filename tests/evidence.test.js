'use strict';
// Pins lib/evidence.js + lib/answers.js — Phase 1 of the evidence-grade rework.
//
// WHAT THIS GUARDS. These two modules exist to make CLAUDE.md's most-repeated
// rule visible to the operator: a failed read is not a measurement. That makes
// their own failure mode unusually nasty, because a broken evidence drawer does
// not crash — it renders a confident, well-formatted explanation that is
// WRONG, in the one place the operator went specifically to check. A wrong
// number on a tile is a bug; a wrong number in its own evidence panel is a lie
// with a citation.
//
// So the three things pinned here are, in order of how badly each one bites:
//
//   1. AN ALL-CLEAR IS FORBIDDEN WHILE COVERAGE IS INCOMPLETE. buildFleetAnswer
//      must return tone 'unknown', never 'ok', when firewalls were not
//      assessed. This is the failed-read-as-a-fact bug in prose form, and it is
//      the single reason lib/answers.js is a module rather than a template
//      string in a component.
//   2. `unmeasured: []` IS A CLAIM, not a default. The drawer renders an empty
//      array as "everything this number depends on was measured". A builder
//      that returns [] because it never looked would print that sentence over a
//      gap — so the builders that KNOW about gaps are asserted to report them.
//   3. NOTHING IS FABRICATED. A missing input produces no row and no evidence
//      at all, never a plausible 0.
//
// Per tests/README.md: every case below includes the "we could not measure
// this" arm, not just the happy path.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  isRenderableEvidence,
  deviceCountEvidence,
  securityScoreEvidence,
  patchNowEvidence,
  rulesEvidence,
  complianceScoreEvidence,
  cveCoverageGap,
} = require('../lib/evidence');

const { buildFleetAnswer } = require('../lib/answers');

// A fully-measured fleet: every device assessed, every score present.
const FULL = {
  deviceCount: 16,
  devicesOnline: 16,
  devicesCveAssessed: 16,
  rulesTotal: 1716,
  rulesEnabled: 1600,
  patchNowCount: 0,
  highRiskCount: 0,
  complianceScore: 51,
  complianceCounts: {
    'PCI DSS': { pass: 10, fail: 6, warning: 4 },
    'ISO 27001': { pass: 9, fail: 6, warning: 3 },
  },
  securityComponents: [
    { key: 'vulnerability', label: 'Vulnerability posture', score: 49, weight: 40 },
    { key: 'hygiene', label: 'Rule hygiene', score: 46, weight: 30 },
    { key: 'compliance', label: 'Compliance', score: 51, weight: 30 },
  ],
  securityScore: 49,
};

// The same fleet with a real coverage gap and an unmeasurable component.
const PARTIAL = {
  ...FULL,
  devicesCveAssessed: 13,
  securityComponents: [
    { key: 'vulnerability', label: 'Vulnerability posture', score: 49, weight: 40 },
    { key: 'hygiene', label: 'Rule hygiene', score: null, weight: 30 },
    { key: 'compliance', label: 'Compliance', score: 51, weight: 30 },
  ],
};

describe('the guard that stops an empty drawer opening', () => {
  it('rejects evidence with no inputs', () => {
    assert.equal(isRenderableEvidence({ title: 't', formula: 'f', inputs: [], unmeasured: [] }), false);
  });

  it('rejects a missing unmeasured array outright', () => {
    // ⛔ Not "treat as empty". An absent array means the builder never
    // considered the question, and defaulting it to [] would make the drawer
    // print "everything was measured" on a builder that never checked.
    assert.equal(isRenderableEvidence({ title: 't', formula: 'f', inputs: [{ label: 'a', value: '1' }] }), false);
  });

  it('accepts a complete descriptor', () => {
    assert.equal(
      isRenderableEvidence({ title: 't', formula: 'f', inputs: [{ label: 'a', value: '1' }], unmeasured: [] }),
      true
    );
  });

  it('rejects null, so an unbuildable figure simply renders no mark', () => {
    assert.equal(isRenderableEvidence(null), false);
    assert.equal(isRenderableEvidence(undefined), false);
  });
});

describe('coverage gap detection', () => {
  it('reports the gap when devices were not assessed', () => {
    const gap = cveCoverageGap(PARTIAL);
    assert.ok(gap, 'a 13-of-16 fleet must produce a gap');
    assert.match(gap.label, /3 of 16/);
  });

  it('returns null when everything was assessed', () => {
    assert.equal(cveCoverageGap(FULL), null);
  });

  it('returns null rather than guessing when coverage is unknown', () => {
    assert.equal(cveCoverageGap({ deviceCount: 16, devicesCveAssessed: null }), null);
  });
});

describe('security score evidence', () => {
  it('derives the formula from the components, not from hardcoded weights', () => {
    // ⛔ This is what keeps the drawer honest if securityScore.js's weights
    // ever change: the displayed arithmetic comes from the engine's own output.
    const ev = securityScoreEvidence(FULL);
    assert.match(ev.formula, /Vulnerability posture/);
    assert.match(ev.formula, /49 × 40/);
    assert.match(ev.formula, /measured weight 100 of 100/);
  });

  it('reports an unmeasurable component as DROPPED, never as zero', () => {
    const ev = securityScoreEvidence(PARTIAL);
    assert.match(ev.formula, /Rule hygiene\s+not measurable — dropped/);
    assert.match(ev.formula, /measured weight 70 of 100/);

    const labels = ev.unmeasured.map((u) => u.label).join(' | ');
    assert.match(labels, /Rule hygiene/);
    // and the coverage gap rides along in the same list
    assert.match(labels, /3 of 16/);
  });

  it('shows the dropped component as an em-dash in the inputs, not 0', () => {
    const ev = securityScoreEvidence(PARTIAL);
    const hygiene = ev.inputs.find((r) => r.label === 'Rule hygiene');
    assert.equal(hygiene.value, '—');
  });

  it('claims no score at all when nothing is measurable', () => {
    const ev = securityScoreEvidence({
      ...FULL,
      securityScore: null,
      securityComponents: FULL.securityComponents.map((c) => ({ ...c, score: null })),
    });
    assert.match(ev.title, /not measurable/);
    assert.match(ev.formula, /Nothing measurable, so no score is claimed/);
  });

  it('returns null when there are no components to explain', () => {
    assert.equal(securityScoreEvidence({ securityComponents: [] }), null);
  });
});

describe('compliance evidence states the na exclusion', () => {
  it('sums the counts the engine already produced', () => {
    const ev = complianceScoreEvidence(FULL);
    // 10+9 pass, 6+6 fail, 4+3 warning
    assert.equal(ev.inputs.find((r) => r.label === 'Passing').value, '19');
    assert.equal(ev.inputs.find((r) => r.label === 'Failing').value, '12');
    assert.equal(ev.inputs.find((r) => r.label === 'Warning').value, '7');
    assert.equal(ev.inputs.find((r) => r.label === 'Measurable total').value, '38');
  });

  it('says in the formula that na is excluded from the denominator', () => {
    // ⛔ This exclusion moved the live fleet from 46% to 51%. Until Phase 1
    // there was nowhere on screen an operator could have discovered it.
    const ev = complianceScoreEvidence(FULL);
    assert.match(ev.formula, /`na` is EXCLUDED from the denominator/);
    assert.match(ev.formula, /warning = we asked/);
  });

  it('always lists na and no-config as measurement gaps', () => {
    const ev = complianceScoreEvidence(FULL);
    assert.ok(ev.unmeasured.length >= 2);
    assert.match(ev.unmeasured.map((u) => u.label).join(' | '), /na/);
  });

  it('renders a null score as an em-dash, never 0', () => {
    const ev = complianceScoreEvidence({ complianceScore: null, complianceCounts: {} });
    assert.match(ev.title, /nothing measurable/i);
    assert.equal(ev.inputs.find((r) => r.label === 'Score').value, '—');
  });
});

describe('builders never fabricate', () => {
  it('device count returns null rather than inventing a fleet', () => {
    assert.equal(deviceCountEvidence({}), null);
  });

  it('patch-now returns null when the count is absent', () => {
    assert.equal(patchNowEvidence({ patchNowCount: null }), null);
  });

  it('a genuine zero still produces evidence — 0 is a measurement', () => {
    // ⛔ The mirror of the rule. NULL means unmeasured and yields no evidence;
    // 0 means measured-and-none and must still be explainable.
    const ev = patchNowEvidence(FULL);
    assert.ok(isRenderableEvidence(ev));
    assert.equal(ev.inputs[0].value, '0');
  });

  it('omits the online/offline split when it was not reported', () => {
    const ev = deviceCountEvidence({ deviceCount: 5, devicesOnline: null });
    assert.equal(ev.inputs.length, 1);
  });

  it('device count claims full measurement, because a row count really is one', () => {
    assert.deepEqual(deviceCountEvidence(FULL).unmeasured, []);
  });

  it('rule totals always carry the failed-pull caveat', () => {
    const ev = rulesEvidence(FULL);
    assert.match(ev.unmeasured.map((u) => u.reason).join(' '), /never reduced to 0/i);
  });
});

describe('the answer sentence may not claim more than was measured', () => {
  it('leads with an exploitable vulnerability when there is one', () => {
    const a = buildFleetAnswer({ ...FULL, patchNowCount: 1 });
    assert.equal(a.tone, 'critical');
    assert.match(a.lead, /1 vulnerability/);
  });

  it('falls back to high-risk findings when nothing is exploitable', () => {
    const a = buildFleetAnswer({ ...FULL, patchNowCount: 0, highRiskCount: 12 });
    assert.equal(a.tone, 'warn');
    assert.match(a.lead, /12 high-risk findings/);
  });

  it('⛔ REFUSES an all-clear while any firewall is unassessed', () => {
    // The single most important assertion in this file. Both arms below have
    // zero outstanding issues; only the fully-covered one may look reassuring.
    const partial = buildFleetAnswer({ ...PARTIAL, patchNowCount: 0, highRiskCount: 0 });
    assert.equal(partial.tone, 'unknown', 'incomplete coverage must never be ok/green');
    assert.match(partial.sentence, /could measure/);
    assert.ok(partial.coverage, 'the gap must be stated, not implied');
    assert.match(partial.coverage, /3 of 16/);
  });

  it('allows the all-clear only when every firewall was assessed', () => {
    const full = buildFleetAnswer({ ...FULL, patchNowCount: 0, highRiskCount: 0 });
    assert.equal(full.tone, 'ok');
    assert.equal(full.coverage, null);
    assert.match(full.sentence, /every one of them was assessed/);
  });

  it('a critical finding still carries the coverage caveat', () => {
    // ⛔ A gap does not stop mattering because something worse was found —
    // the real number may be HIGHER than the one displayed.
    const a = buildFleetAnswer({ ...PARTIAL, patchNowCount: 2 });
    assert.equal(a.tone, 'critical');
    assert.ok(a.coverage, 'coverage must survive the critical branch');
  });

  it('distinguishes "assessed and clean" from "never assessed"', () => {
    const never = buildFleetAnswer({ ...FULL, patchNowCount: null, highRiskCount: null });
    assert.equal(never.tone, 'unknown');
    assert.match(never.sentence, /Nothing has been assessed yet/);
  });

  it('handles an empty install without claiming health', () => {
    const a = buildFleetAnswer({ deviceCount: 0 });
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /nothing here has been measured/);
  });

  it('never throws on a malformed headline', () => {
    for (const input of [null, undefined, {}, { deviceCount: 'x' }]) {
      const a = buildFleetAnswer(input);
      assert.equal(typeof a.sentence, 'string');
      assert.ok(a.sentence.length > 0);
    }
  });
});
