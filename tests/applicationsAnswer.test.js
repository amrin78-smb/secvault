'use strict';
// Pins buildApplicationsAnswer (lib/answers.js) and applicationsEvidence
// (lib/evidence.js) — the headline sentence and the evidence drawer on
// /applications.
//
// ⛔ WHY A NEW FILE. Both builders shipped in v2.124.0 with NO test coverage of
// any kind, which is how the defect below survived: `rollUp` computes
// `flowsFailed` and NOTHING in the repository ever read it.
//
// ⛔ WHAT THESE TESTS ARE FOR. This page's one job is to be trusted about what
// the rules permit, so the failure that matters is not a wrong number — it is a
// CONFIDENT number over a read that never returned. Every case here is a
// could-not-measure case; the pass and fail cases are the easy half.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { buildApplicationsAnswer, rollUpApplications } = require('../lib/answers');
const { applicationsEvidence } = require('../lib/evidence');

// The evaluator's own output shape (evaluateAllApplications), hand-built.
const app = (id, name, flows) => ({
  application: { id, name, criticality: 'normal' },
  flows,
  summary: { state: flows.some((f) => f.finding.state !== 'ok') ? 'problem' : 'ok' },
});
const flow = (state, over = {}) => ({
  flow: { id: 'f1' },
  finding: { state, label: state },
  unverified: false,
  used: 'rule-active',
  permittedBy: [],
  blockedBy: [],
  ...over,
});
const coverage = (n = 3) => ({
  windowDays: 30, activeDeviceCount: n, devicesWithRules: n, devicesWithoutRules: [],
});

describe('⛔ a failed flow read is not "no flows have been declared"', () => {
  // THE BUG THIS PINS. evaluateAllApplications() reports a failed
  // `application_flows` query in `errors` and CARRIES ON with an empty flow
  // list — the declarations are still listed, which is right. But the sentence
  // then reached its `r.flows === 0` branch and announced "none of them has a
  // flow yet": a statement about the operator's own data, made from a query
  // that never returned. `rollUp` has computed `flowsFailed` since the feature
  // shipped, and nothing read it.
  const failed = {
    applications: [
      app('a1', 'SAP', []),
      app('a2', 'Payroll', []),
    ],
    errors: [{ source: 'application_flows', error: 'canceling statement due to statement timeout' }],
    coverage: coverage(),
    orphans: null,
    windowDays: 30,
  };

  it('rollUp sees it', () => {
    const r = rollUpApplications(failed);
    assert.equal(r.flowsFailed, true);
    assert.equal(r.flows, 0);
  });

  it('⛔ the sentence must not claim the flows are absent', () => {
    const a = buildApplicationsAnswer(failed);
    assert.equal(a.tone, 'unknown');
    assert.doesNotMatch(
      a.sentence,
      /none of them has a flow yet/,
      'that sentence states a fact about a read that failed'
    );
    assert.match(a.sentence, /could not be read/);
    assert.match(a.coverage, /failure to read/);
  });

  it('a genuinely empty declaration still reads as one', () => {
    // The guard must not swallow the real case it resembles: two applications
    // declared, no flows typed yet, and nothing failed.
    const empty = { ...failed, errors: [] };
    const a = buildApplicationsAnswer(empty);
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /none of them has a flow yet/);
  });

  it('the drawer stays shut either way — a 0-of-0 ratio is not evidence', () => {
    assert.equal(applicationsEvidence(failed), null);
    assert.equal(applicationsEvidence({ ...failed, errors: [] }), null);
  });
});

describe('⛔ an all-clear is forbidden while coverage is incomplete', () => {
  const clean = {
    applications: [app('a1', 'SAP', [flow('ok'), flow('ok')])],
    errors: [],
    coverage: coverage(3),
    orphans: { allowRules: 100, claimedRules: 12 },
    windowDays: 30,
  };

  it('a fully measured clean result is allowed to say so', () => {
    const a = buildApplicationsAnswer(clean);
    assert.equal(a.tone, 'ok');
    assert.match(a.sentence, /everything the answer rests on was measured/);
  });

  it('⛔ one uncollected firewall removes the all-clear, even with no unverified flow', () => {
    const partial = {
      ...clean,
      coverage: { ...coverage(3), devicesWithRules: 2, devicesWithoutRules: ['FW-3'] },
    };
    const a = buildApplicationsAnswer(partial);
    assert.equal(a.tone, 'unknown');
    assert.notEqual(a.tone, 'ok');
    assert.match(a.sentence, /not everything this rests on could be measured/);
  });

  it('⛔ one unverified flow does the same', () => {
    const partial = {
      ...clean,
      applications: [app('a1', 'SAP', [flow('ok'), flow('ok_unverified', { unverified: true })])],
    };
    assert.equal(buildApplicationsAnswer(partial).tone, 'unknown');
  });
});

describe('⛔ the drawer and the sentence share ONE roll-up', () => {
  it('evidence.js imports rollUp rather than re-deriving it', () => {
    // Two implementations of "what counts as a problem" would eventually
    // disagree, putting the headline and the drawer beneath it in conflict on
    // the same screen. Asserted structurally, not by comparing two numbers that
    // happen to agree today.
    const src = require('node:fs').readFileSync(require.resolve('../lib/evidence.js'), 'utf8');
    assert.match(src, /rollUpApplications:\s*rollUp/, 'the shared roll-up must be imported');
    assert.doesNotMatch(src, /function rollUp\s*\(/, 'evidence.js must not define its own');
  });
});

describe('⛔ an unmeasured traffic window is never printed as one', () => {
  // THE BUG THIS PINS. The guard was
  // `Number.isFinite(Number(result.windowDays))` — and Number(null) is 0, which
  // is finite. A null window walked straight through it and the drawer rendered
  // the row "Traffic window: null days", a stated measurement with nothing
  // behind it. evaluateAllApplications() really does return `windowDays: null`
  // on both of its early-error paths, and segmentationEvidence() in the same
  // file already carries the explicit check, with a comment recording that this
  // exact defect shipped once before.
  const base = {
    applications: [app('a1', 'SAP', [flow('ok')])],
    errors: [],
    coverage: coverage(1),
    orphans: null,
  };
  const windowRow = (result) => {
    const ev = applicationsEvidence(result);
    return (ev.inputs || []).find((i) => i.label === 'Traffic window') || null;
  };

  it('⛔ a null window produces NO row, not a row saying "null days"', () => {
    const row = windowRow({ ...base, windowDays: null });
    assert.equal(row, null, `rendered a fabricated window: ${JSON.stringify(row)}`);
  });

  it('undefined is refused too', () => {
    assert.equal(windowRow({ ...base }), null);
  });

  it('a real window is still stated', () => {
    assert.deepEqual(windowRow({ ...base, windowDays: 30 }).value, '30 days');
  });

  it('⛔ and a genuine zero-day window is not mistaken for an absent one', () => {
    // 0 is a real value here, so the guard must key on absence, not falsiness.
    assert.deepEqual(windowRow({ ...base, windowDays: 0 }).value, '0 days');
  });
});
