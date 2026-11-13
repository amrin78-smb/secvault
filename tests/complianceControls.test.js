'use strict';

// ⛔ WHAT THIS FILE IS FOR.
//
// Every bug this page could ship is one shape: a control that nobody measured
// rendering as a control that passed. The library has 74 checks, a fresh
// install has zero findings, and the difference between "clean" and "never
// asked" is invisible in the arithmetic — both produce zero failures. So the
// cases below lead with the NOT-MEASURED ones, per CLAUDE.md's rule that a new
// test must include the case where SecVault could not measure, not only pass
// and fail.
//
// The second shape is the unit error: counting CHECKS where the number means
// (firewall, check) PAIRS. Those are asserted apart deliberately.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  FAILING,
  WARNING,
  NOT_MEASURED,
  PARTIAL,
  CLEAN,
  NOT_EVALUABLE,
  NOT_APPLICABLE,
  CONTROL_STATES,
  STATE_TONES,
  CONTROL_CLAIM,
  buildControl,
  sortControls,
  parseControlFilters,
  filterControls,
  summariseControls,
} = require('../lib/engines/complianceControls');

const { buildControlsAnswer } = require('../lib/answers');

const STANDARDS = ['PCI_DSS', 'ISO_27001', 'CIS_V8', 'NIST', 'SANS'];

function finding(deviceId, status, name = null) {
  return { deviceId, deviceName: name || `fw-${deviceId}`, status, detectedAt: '2026-11-13T03:00:00.000Z' };
}

function control(over = {}) {
  return buildControl({
    slug: 'rule-no-any-any-allow',
    name: 'No unrestricted any-to-any allow rules',
    description: 'Avoid broad any-to-any allow rules.',
    severity: 'high',
    standards: ['CIS_V8'],
    vendor: null,
    predicateType: 'rule_scan',
    findings: [],
    applicableDeviceCount: 4,
    liveExceptions: [],
    ...over,
  });
}

describe('a control that was not measured never reads as one that passed', () => {
  it('no findings at all, with firewalls it applies to, is never_measured', () => {
    const c = control({ findings: [] });
    assert.equal(c.status, NOT_MEASURED);
    assert.equal(c.counts.pass, 0);
    assert.equal(c.notEvaluatedDeviceCount, 4);
  });

  it('passing on SOME applicable firewalls is `partial`, not `clean`', () => {
    // ⛔ THE CENTRAL CASE. Three passes and a silent gap is the shape a
    // green tick would be most wrong about.
    const c = control({ findings: [finding('a', 'pass'), finding('b', 'pass'), finding('c', 'pass')] });
    assert.equal(c.status, PARTIAL);
    assert.equal(c.notEvaluatedDeviceCount, 1);
  });

  it('`clean` requires every applicable firewall to have answered', () => {
    const c = control({
      findings: [finding('a', 'pass'), finding('b', 'pass'), finding('c', 'pass'), finding('d', 'pass')],
    });
    assert.equal(c.status, CLEAN);
    assert.equal(c.notEvaluatedDeviceCount, 0);
  });

  it('an UNREADABLE applicable count cannot produce `clean`', () => {
    const c = control({
      applicableDeviceCount: null,
      findings: [finding('a', 'pass'), finding('b', 'pass')],
    });
    assert.equal(c.notEvaluatedDeviceCount, null);
    assert.equal(c.status, PARTIAL);
  });

  it('an unrecognised finding status is counted, not read as a pass', () => {
    // audit_findings.status has no CHECK constraint, so this is reachable.
    const c = control({
      findings: [finding('a', 'pass'), finding('b', 'pass'), finding('c', 'pass'), finding('d', 'weird')],
    });
    assert.equal(c.counts.unreadable, 1);
    assert.equal(c.counts.pass, 3);
    assert.notEqual(c.status, CLEAN);
    assert.equal(c.status, PARTIAL);
  });

  it('every firewall answering `na` is not_measured, not clean', () => {
    const c = control({
      findings: [finding('a', 'na'), finding('b', 'na'), finding('c', 'na'), finding('d', 'na')],
    });
    assert.equal(c.counts.na, 4);
    assert.equal(c.status, NOT_MEASURED);
  });
});

describe('the four not-a-failure states stay apart', () => {
  it('a check declared unanswerable from config is not_evaluable, not not_measured', () => {
    const c = control({ predicateType: 'not_evaluable_from_config', findings: [] });
    assert.equal(c.status, NOT_EVALUABLE);
  });

  it('a MEASUREMENT outranks the declaration', () => {
    // A present finding is evidence whatever the predicate says about itself.
    const c = control({ predicateType: 'not_evaluable_from_config', findings: [finding('a', 'fail')] });
    assert.equal(c.status, FAILING);
  });

  it('no firewall of this vendor is not_applicable, not not_measured', () => {
    const c = control({ vendor: 'checkpoint', applicableDeviceCount: 0, findings: [] });
    assert.equal(c.status, NOT_APPLICABLE);
  });

  it('all four carry NO hue — they are gaps in our reach, not severities', () => {
    for (const s of [NOT_MEASURED, PARTIAL, NOT_EVALUABLE, NOT_APPLICABLE]) {
      assert.equal(STATE_TONES[s], 'unmeasured', `${s} must be hueless`);
    }
    assert.equal(STATE_TONES[FAILING], 'danger');
    assert.equal(STATE_TONES[CLEAN], 'success');
  });
});

describe('a control is failing and passing at the same time', () => {
  it('one failure among passes makes the control failing, and both counts survive', () => {
    const c = control({
      findings: [finding('a', 'fail'), finding('b', 'pass'), finding('c', 'pass'), finding('d', 'pass')],
    });
    assert.equal(c.status, FAILING);
    assert.equal(c.counts.fail, 1);
    assert.equal(c.counts.pass, 3);
    assert.deepEqual(c.failingDevices.map((d) => d.deviceId), ['a']);
  });

  it('a warning only counts when nothing failed', () => {
    assert.equal(control({ findings: [finding('a', 'warning'), finding('b', 'pass')] }).status, WARNING);
    assert.equal(control({ findings: [finding('a', 'warning'), finding('b', 'fail')] }).status, FAILING);
  });

  it('a duplicated (firewall, check) pair collapses to the WORST status', () => {
    const c = control({ findings: [finding('a', 'pass'), finding('a', 'fail')] });
    assert.equal(c.answeredDeviceCount, 1);
    assert.equal(c.counts.fail, 1);
    assert.equal(c.counts.pass, 0);
  });
});

describe('nothing is defaulted into existence', () => {
  it('an unrecognised severity is kept raw and flagged, never shown as medium', () => {
    const c = control({ severity: 'catastrophic' });
    assert.equal(c.severity, 'catastrophic');
    assert.equal(c.severityKnown, false);
  });

  it('an unreadable exceptions table reports null, not zero', () => {
    assert.equal(control({ liveExceptions: null }).exceptionDeviceCount, null);
    assert.equal(control({ liveExceptions: [] }).exceptionDeviceCount, 0);
  });

  it('a control carries no percentage of its own', () => {
    // ⛔ One compliance percentage exists in this product. A second one here,
    // over a different denominator, would disagree with the headline on the
    // same screen — the artefact compliance_exceptions is barred from making.
    const c = control({ findings: [finding('a', 'fail'), finding('b', 'pass')] });
    for (const k of Object.keys(c)) {
      assert.ok(!/pct|percent|score/i.test(k), `control must not carry ${k}`);
    }
  });
});

describe('the summary counts checks and pairs as different numbers', () => {
  const controls = [
    control({ slug: 'a', findings: [finding('d1', 'fail'), finding('d2', 'fail')] }),
    control({ slug: 'b', findings: [finding('d2', 'fail'), finding('d3', 'fail')] }),
    control({ slug: 'c', findings: [] }),
    control({ slug: 'd', predicateType: 'not_evaluable_from_config', findings: [] }),
  ];
  const s = summariseControls(controls);

  it('failingControls counts CHECKS and failingPairs counts (firewall, check)', () => {
    assert.equal(s.failingControls, 2);
    assert.equal(s.failingPairs, 4);
  });

  it('firewallsAffected de-duplicates a firewall failing two controls', () => {
    assert.equal(s.firewallsAffected, 3); // d1, d2, d3 — d2 appears twice
  });

  it('the gap states are counted separately from each other', () => {
    assert.equal(s.notMeasured, 1);
    assert.equal(s.notEvaluable, 1);
  });

  it('an unreadable exception column makes the roll-up null, not zero', () => {
    const withNull = summariseControls([control({ liveExceptions: null })]);
    assert.equal(withNull.controlsWithLiveException, null);
  });
});

describe('a filter can never become an all-clear', () => {
  const all = [
    control({ slug: 'a', findings: [finding('d1', 'fail')] }),
    control({ slug: 'b', standards: ['NIST'], findings: [] }),
  ];

  it('an unrecognised status value matches NOTHING, never everything', () => {
    const { filters, unknown } = parseControlFilters({ status: 'broken' }, STANDARDS);
    assert.deepEqual(unknown, [{ key: 'status', value: 'broken' }]);
    assert.equal(filterControls(all, filters).length, 0);
  });

  it('an unrecognised standard and severity are reported, not dropped', () => {
    const { unknown } = parseControlFilters({ standard: 'HIPAA', severity: 'urgent' }, STANDARDS);
    assert.deepEqual(unknown.map((u) => u.key).sort(), ['severity', 'standard']);
  });

  it('a recognised filter narrows, and the summary is computed on the FULL list', () => {
    const { filters } = parseControlFilters({ status: FAILING }, STANDARDS);
    const shown = filterControls(all, filters);
    assert.equal(shown.length, 1);
    // ⛔ The headline must still see the control the filter hid.
    assert.equal(summariseControls(all).total, 2);
    assert.equal(summariseControls(all).notMeasured, 1);
  });

  it('the free-text search reads the slug, the name and the description', () => {
    const c = [control({ slug: 'zzz', name: 'Deny all', description: 'Explicit terminal rule.' })];
    assert.equal(filterControls(c, { q: 'zzz' }).length, 1);
    assert.equal(filterControls(c, { q: 'deny' }).length, 1);
    assert.equal(filterControls(c, { q: 'terminal' }).length, 1);
    assert.equal(filterControls(c, { q: 'nonsense' }).length, 0);
  });
});

describe('the default order answers the question the page was built for', () => {
  it('failing first, and within failing the MOST firewalls first', () => {
    const sorted = sortControls([
      control({ slug: 'one', findings: [finding('d1', 'fail')] }),
      control({ slug: 'five', findings: ['a', 'b', 'c', 'd', 'e'].map((d) => finding(d, 'fail')) }),
      control({ slug: 'three', findings: ['a', 'b', 'c'].map((d) => finding(d, 'fail')) }),
    ]);
    assert.deepEqual(sorted.map((c) => c.slug), ['five', 'three', 'one']);
  });

  it('a never-measured control ranks ABOVE a passing one', () => {
    const sorted = sortControls([
      control({ slug: 'clean', findings: ['a', 'b', 'c', 'd'].map((d) => finding(d, 'pass')) }),
      control({ slug: 'gap', findings: [] }),
      control({ slug: 'partial', findings: [finding('a', 'pass')] }),
    ]);
    assert.deepEqual(sorted.map((c) => c.slug), ['gap', 'partial', 'clean']);
  });

  it('the order is total — it never depends on the order rows arrived', () => {
    const mk = () => [
      control({ slug: 'b', severity: 'low', findings: [finding('d1', 'fail')] }),
      control({ slug: 'a', severity: 'critical', findings: [finding('d2', 'fail')] }),
    ];
    assert.deepEqual(sortControls(mk()).map((c) => c.slug), ['a', 'b']);
    assert.deepEqual(sortControls(mk().reverse()).map((c) => c.slug), ['a', 'b']);
  });
});

describe('the sentence refuses an all-clear it did not earn', () => {
  it('a missing summary is unknown, never "no control is failing"', () => {
    const a = buildControlsAnswer(null);
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /could not be read/i);
  });

  it('zero failures over an unevaluated library is NOT ok', () => {
    const a = buildControlsAnswer(summariseControls([control({ slug: 'x', findings: [] })]));
    assert.equal(a.failing, undefined);
    assert.equal(a.tone, 'unknown');
    assert.ok(a.coverage, 'the gap must be stated beside the claim');
    assert.match(a.coverage, /never been answered/i);
  });

  it('`ok` is reachable only when the whole library was answered everywhere', () => {
    const clean = control({ slug: 'x', findings: ['a', 'b', 'c', 'd'].map((d) => finding(d, 'pass')) });
    const a = buildControlsAnswer(summariseControls([clean]));
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
  });

  it('a failure leads with CONTROLS and qualifies with FIREWALLS', () => {
    const a = buildControlsAnswer(summariseControls([
      control({ slug: 'x', findings: [finding('d1', 'fail'), finding('d2', 'fail')] }),
    ]));
    assert.equal(a.tone, 'critical');
    assert.match(a.lead, /^1 control failing$/);
    assert.match(a.sentence, /on 2 firewalls/);
  });
});

describe('the exported claim names the unit', () => {
  it('CONTROL_CLAIM says firewalls, and says a control has no single verdict', () => {
    assert.match(CONTROL_CLAIM, /FIREWALLS/);
    assert.match(CONTROL_CLAIM, /no single/i);
  });

  it('every state has a tone and a rank', () => {
    for (const s of CONTROL_STATES) {
      assert.ok(STATE_TONES[s], `${s} needs a tone`);
    }
  });
});

describe('the filter options are derived from what is actually there', () => {
  const { controlFilterOptions } = require('../lib/engines/complianceControls');

  it('offers only the statuses, standards and severities present', () => {
    const o = controlFilterOptions([
      control({ slug: 'a', severity: 'high', standards: ['CIS_V8'], findings: [finding('d', 'fail')] }),
      control({ slug: 'b', severity: 'low', standards: ['NIST', 'CIS_V8'], findings: [] }),
    ]);
    // ⛔ No option that can only ever return nothing: `clean` is absent
    // because no control here is clean.
    assert.deepEqual(o.statuses, [FAILING, NOT_MEASURED]);
    assert.deepEqual(o.standards, ['CIS_V8', 'NIST']);
    assert.deepEqual(o.severities, ['high', 'low']);
  });

  it('severities come back in ramp order, not alphabetical', () => {
    const o = controlFilterOptions([
      control({ slug: 'a', severity: 'low' }),
      control({ slug: 'b', severity: 'critical' }),
      control({ slug: 'c', severity: 'medium' }),
    ]);
    assert.deepEqual(o.severities, ['critical', 'medium', 'low']);
  });

  it('an unrecognised severity is still offered, and sorts last', () => {
    const o = controlFilterOptions([
      control({ slug: 'a', severity: 'critical' }),
      control({ slug: 'b', severity: 'catastrophic' }),
    ]);
    assert.deepEqual(o.severities, ['critical', 'catastrophic']);
  });
});
