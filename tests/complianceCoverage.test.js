'use strict';
// Pins lib/engines/complianceCoverage.js — the statement that stops a
// per-standard compliance percentage standing on its own.
//
// ⛔ THE DEFECT THIS GUARDS. /compliance printed "NIST 42%" and let it read as
// that framework's posture. Measured live on 2026-09-22: the curated library is
// 45 checks and a check carries a `standards` ARRAY, so the five denominators
// are CIS_V8 44 · ISO_27001 35 · PCI_DSS 21 · SANS 12 · NIST 7. The NIST figure
// is computed over SEVEN checks, three of them vendor-scoped. The arithmetic was
// always right; the claim a bare figure invited was not.
//
// ⛔ AND THE OPPOSITE FAILURE IS JUST AS BAD. "21 of about 300 PCI DSS
// requirements" would look like a measurement, would be quoted, and is not
// something this codebase knows or can derive. Half these cases exist to keep
// the fix from becoming a fabricated denominator.
//
// ⛔ EVERY CASE HERE HAS A "WE COULD NOT MEASURE THIS" COUNTERPART, because that
// is the one that regresses silently: an absent library count coerced to 0
// prints "0 of 45 checks are mapped to PCI DSS", which reads as "SecVault does
// not support this standard" and is a confident, plausible, wrong sentence
// rather than a crash.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  COVERAGE_CLAIM,
  GRADES,
  GRADE_LABEL,
  GRADE_PIPS,
  GRADE_PIP_TOTAL,
  GRADE_THIN_MAX,
  GRADE_BROAD_MIN,
  gradeFor,
  buildStandardCoverage,
  buildCoverageSet,
  coverageEvidence,
} = require('../lib/engines/complianceCoverage');
const { isRenderableEvidence } = require('../lib/evidence');

// The live shape, so a regression shows up as a change in a number someone can
// go and re-measure rather than as an abstract failure.
const LIVE = {
  PCI_DSS: { label: 'PCI DSS', mapped: 21, applicable: 19, evaluated: 19, answered: 16, score: 49 },
  ISO_27001: { label: 'ISO 27001', mapped: 35, applicable: 34, evaluated: 34, answered: 30, score: 58 },
  CIS_V8: { label: 'CIS v8', mapped: 44, applicable: 41, evaluated: 41, answered: 36, score: 50 },
  NIST: { label: 'NIST', mapped: 7, applicable: 7, evaluated: 7, answered: 7, score: 42 },
  SANS: { label: 'SANS', mapped: 12, applicable: 12, evaluated: 12, answered: 12, score: 45 },
};

function live(key, overrides = {}) {
  const l = LIVE[key];
  return buildStandardCoverage({
    standard: key,
    label: l.label,
    scope: 'fleet',
    deviceCount: 16,
    libraryTotal: 45,
    mapped: l.mapped,
    applicable: l.applicable,
    evaluatedChecks: l.evaluated,
    answeredChecks: l.answered,
    findings: { pass: 33, fail: 30, warning: 16, na: 12 },
    scorePct: l.score,
    ...overrides,
  });
}

// ── the claim ─────────────────────────────────────────────────────────────

describe('⛔ COVERAGE_CLAIM says what the denominator IS and refuses the other one', () => {
  it('names SecVault’s own checks as the denominator', () => {
    assert.match(COVERAGE_CLAIM, /SecVault/);
    assert.match(COVERAGE_CLAIM, /mapped checks/);
  });

  it('⛔ states that framework coverage is NOT known', () => {
    // The whole point. Without this sentence the numbers beside it are an
    // improvement in honesty that still lets the old reading stand.
    assert.match(COVERAGE_CLAIM, /does not hold a count of the requirements/);
    assert.match(COVERAGE_CLAIM, /how much of that framework is covered/);
  });

  it('⛔ never claims compliance, certification, or a framework total', () => {
    // The four words that would put the overclaim back. A "coverage" feature
    // that says "fully compliant" anywhere has undone itself.
    for (const bad of [/\bcertified\b/i, /\bfully compliant\b/i, /\bguarantee/i, /\bapproximately \d/i]) {
      assert.equal(bad.test(COVERAGE_CLAIM), false, `claim contains ${bad}`);
    }
  });

  it('⛔ carries no internal documentation reference', () => {
    // tests/noInternalRefs.test.js already scans app/components/lib, but this
    // string is the one a buyer reads most directly, so it is asserted here too.
    assert.equal(/CLAUDE\.md/.test(COVERAGE_CLAIM), false);
  });
});

// ── evidence grading ──────────────────────────────────────────────────────

describe('gradeFor — how many checks the figure rests on', () => {
  it('bands an absolute count, not a share of the library', () => {
    assert.equal(gradeFor(1), 'thin');
    assert.equal(gradeFor(GRADE_THIN_MAX), 'thin');
    assert.equal(gradeFor(GRADE_THIN_MAX + 1), 'moderate');
    assert.equal(gradeFor(GRADE_BROAD_MIN - 1), 'moderate');
    assert.equal(gradeFor(GRADE_BROAD_MIN), 'broad');
    assert.equal(gradeFor(500), 'broad');
  });

  it('⛔ null is `unknown`, NOT `none` — and they are different facts', () => {
    // "we could not determine how many checks ran" is a gap in SecVault;
    // "no check ran" is a fact about the target that an audit run would fix.
    // Collapsing them would report our own failed read as an empty result.
    assert.equal(gradeFor(null), 'unknown');
    assert.equal(gradeFor(undefined), 'unknown');
    assert.equal(gradeFor(NaN), 'unknown');
    assert.equal(gradeFor(0), 'none');
    assert.notEqual(gradeFor(null), gradeFor(0));
  });

  it('⛔ neither `unknown` nor `none` is ever shown as a grade word', () => {
    // A meter reading "1 of 3" over a failed read would claim thin evidence
    // where there is no evidence figure at all.
    assert.equal(GRADE_PIPS.unknown, 0);
    assert.equal(GRADE_PIPS.none, 0);
    assert.equal(GRADE_PIPS.thin, 1);
    assert.equal(GRADE_PIPS.broad, GRADE_PIP_TOTAL);
    for (const g of GRADES) assert.equal(typeof GRADE_LABEL[g], 'string');
    assert.match(GRADE_LABEL.unknown, /not known/);
  });

  it('the live fleet grades in the order the counts imply', () => {
    assert.equal(live('NIST').grade, 'thin');
    assert.equal(live('SANS').grade, 'moderate');
    assert.equal(live('PCI_DSS').grade, 'moderate');
    assert.equal(live('ISO_27001').grade, 'broad');
    assert.equal(live('CIS_V8').grade, 'broad');
  });
});

// ── the figures ───────────────────────────────────────────────────────────

describe('buildStandardCoverage — what is known is stated', () => {
  it('reproduces the live NIST case that motivated all of this', () => {
    const c = live('NIST');
    assert.equal(c.mapped, 7);
    assert.equal(c.libraryTotal, 45);
    assert.equal(c.cell, '7 of 45');
    assert.equal(c.available, true);
    assert.match(c.headline, /7 of 45 checks in SecVault’s library are mapped to NIST/);
    assert.match(c.detail, /rests on 7 checks/);
  });

  it('⛔ the figure never appears without its denominator in the same string', () => {
    const c = live('NIST');
    assert.match(c.detail, /42%/);
    assert.match(c.detail, /7 checks/);
  });

  it('⛔ NO SCORE ARITHMETIC HAPPENS HERE — scorePct is carried through verbatim', () => {
    // The scoring formula is documented and pinned elsewhere. This module
    // changes presentation only; a recomputation here would be a second,
    // drifting copy of it.
    assert.equal(live('NIST', { scorePct: 42 }).scorePct, 42);
    assert.equal(live('NIST', { scorePct: 0 }).scorePct, 0);
    // Counts that disagree with the score do not move it.
    assert.equal(
      live('NIST', { scorePct: 42, findings: { pass: 999, fail: 0, warning: 0, na: 0 } }).scorePct,
      42
    );
  });

  it('⛔ a score of null stays null and is rendered as a dash, never 0%', () => {
    const c = live('NIST', { scorePct: null, answeredChecks: 0, evaluatedChecks: 7 });
    assert.equal(c.scorePct, null);
    assert.equal(c.grade, 'none');
    assert.match(c.detail, /rests on 0 checks/);
    const ev = coverageEvidence(c);
    assert.ok(ev.inputs.some((r) => r.label === 'Score' && r.value === '—'));
  });

  it('counts the vendor-scoped checks that can never run here', () => {
    // Live: three of NIST's seven are vendor-scoped, so at most six can run on
    // one firewall.
    const c = buildStandardCoverage({
      standard: 'NIST', label: 'NIST', scope: 'device',
      libraryTotal: 45, mapped: 7, applicable: 6,
      evaluatedChecks: 6, answeredChecks: 6,
      findings: { pass: 1, fail: 4, warning: 1, na: 0 }, scorePct: 17,
    });
    assert.equal(c.notApplicable, 1);
    assert.equal(c.neverRan, 0);
    assert.match(c.detail, /6 apply to this firewall’s vendor/);
  });

  it('⛔ `na` leaves the score and is reported separately, not as a fail', () => {
    const c = live('CIS_V8');
    assert.equal(c.unanswerable, 5); // 41 evaluated, 36 answered
    assert.match(c.detail, /5 could not be assessed at all/);
    assert.match(c.detail, /excluded from the score/);
  });

  it('basis omits the per-standard refusal; statement includes it', () => {
    // Two forms, because a surface already printing COVERAGE_CLAIM beside the
    // figure would otherwise repeat the same disclaimer five times in one
    // eyeful — and the one a reader then skips is the one that matters.
    const c = live('NIST');
    assert.equal(c.statement.startsWith(c.basis), true);
    assert.equal(/holds no count/.test(c.basis), false);
    assert.match(c.statement, /holds no count of the requirements NIST publishes/);
    assert.match(c.statement, /does not state how much of NIST is covered/);
  });

  it('⛔ names the standard in its own refusal, not just generically', () => {
    // A reader looking at the NIST card needs the sentence to say NIST; a
    // generic disclaimer elsewhere on the page is not attached to this figure.
    assert.match(live('PCI_DSS').caveat, /PCI DSS/);
    assert.match(live('SANS').caveat, /SANS/);
  });

  it('⛔ invents no framework requirement total, in any field', () => {
    // The single worst possible regression: replacing one overclaim with a
    // fabricated denominator that looks measured.
    for (const key of Object.keys(LIVE)) {
      const c = live(key);
      for (const field of [c.headline, c.detail, c.caveat, c.basis, c.statement, c.cell]) {
        assert.equal(/\b(?:about|roughly|approximately|est\.?|circa|~)\s*\d/i.test(field), false,
          `${key} hedges a number: ${field}`);
        assert.equal(/\d+\s+requirements\b/i.test(field), false,
          `${key} states a requirement count: ${field}`);
      }
    }
  });
});

// ── "we could not measure this" ───────────────────────────────────────────

describe('⛔ the cases that regress silently: a failed read is never a figure', () => {
  it('⛔ an unreadable library is UNAVAILABLE, never "0 of 45" and never "0 of 0"', () => {
    // "0 of 45 checks are mapped to PCI DSS" reads as "SecVault does not
    // support this standard". It is a claim, and a false one.
    const c = buildStandardCoverage({
      standard: 'PCI_DSS', label: 'PCI DSS', libraryTotal: null, mapped: null, scorePct: 49,
    });
    assert.equal(c.available, false);
    assert.equal(c.cell, '—');
    assert.equal(c.mapped, null);
    assert.notEqual(c.mapped, 0);
    assert.match(c.headline, /could not be read/);
    assert.equal(/0 of/.test(c.statement), false);
    assert.equal(c.detail, '', 'no basis may be asserted over an unreadable library');
  });

  it('⛔ a partly-unreadable library is unavailable too — no half-statement', () => {
    const noTotal = buildStandardCoverage({ standard: 'NIST', libraryTotal: null, mapped: 7 });
    const noMapped = buildStandardCoverage({ standard: 'NIST', libraryTotal: 45, mapped: null });
    assert.equal(noTotal.available, false);
    assert.equal(noMapped.available, false);
    assert.equal(noTotal.cell, '—');
    assert.equal(noMapped.cell, '—');
  });

  it('⛔ an unknown evaluated count says so, and does not read as "none ran"', () => {
    const c = buildStandardCoverage({
      standard: 'NIST', label: 'NIST', libraryTotal: 45, mapped: 7, applicable: 7,
      evaluatedChecks: null, answeredChecks: null, scorePct: 42,
    });
    assert.equal(c.grade, 'unknown');
    assert.equal(c.evaluatedChecks, null);
    assert.equal(c.answeredChecks, null);
    assert.match(c.detail, /how many of them ran here is not known/);
    assert.equal(/0 ran/.test(c.detail), false);
  });

  it('⛔ A DERIVED GAP OVER AN ABSENT INPUT IS NULL, NOT ZERO', () => {
    // This is the arithmetic half of the same bug. `mapped - applicable` with
    // applicable absent would print "0 checks cannot apply here" — an itemised,
    // reassuring claim of full applicability made from a number nobody read.
    const c = buildStandardCoverage({
      standard: 'NIST', libraryTotal: 45, mapped: 7,
      applicable: null, evaluatedChecks: null, answeredChecks: null,
    });
    assert.equal(c.notApplicable, null);
    assert.equal(c.neverRan, null);
    assert.equal(c.unanswerable, null);
    assert.notEqual(c.notApplicable, 0);
    assert.notEqual(c.unanswerable, 0);
  });

  it('⛔ an absent `na` bucket is an em-dash, not "Not assessable 0"', () => {
    const withNa = coverageEvidence(live('NIST'));
    const withoutNa = coverageEvidence(live('NIST', { findings: null }));
    assert.ok(withNa.inputs.some((r) => /Not assessable/.test(r.label)));
    assert.equal(
      withoutNa.inputs.some((r) => /Not assessable/.test(r.label)), false,
      'a row nobody supplied must not appear at all'
    );
  });

  it('a gap never goes negative, however inconsistent the inputs', () => {
    const c = buildStandardCoverage({
      standard: 'NIST', libraryTotal: 45, mapped: 7, applicable: 9,
      evaluatedChecks: 12, answeredChecks: 20,
    });
    assert.equal(c.notApplicable, 0);
    assert.equal(c.neverRan, 0);
    assert.equal(c.unanswerable, 0);
  });
});

// ── the evidence drawer ───────────────────────────────────────────────────

describe('coverageEvidence — reuses the existing drawer rather than a parallel mechanism', () => {
  it('produces a descriptor the shared drawer will actually render', () => {
    for (const key of Object.keys(LIVE)) {
      const ev = coverageEvidence(live(key));
      assert.equal(isRenderableEvidence(ev), true, `${key} descriptor is not renderable`);
    }
  });

  it('returns null rather than an empty drawer', () => {
    assert.equal(coverageEvidence(null), null);
    assert.equal(coverageEvidence(undefined), null);
  });

  it('⛔ AN ALL-CLEAR IS FORBIDDEN: the framework gap is ALWAYS listed', () => {
    // The drawer renders an EMPTY `unmeasured` as the sentence "Everything this
    // number depends on was measured. No gaps, no assumptions." For a
    // per-standard compliance percentage that sentence can never be true, no
    // matter how broad the evidence — because how much of the framework is
    // covered is not knowable from here.
    const perfect = buildStandardCoverage({
      standard: 'CIS_V8', label: 'CIS v8', libraryTotal: 45, mapped: 44,
      applicable: 44, evaluatedChecks: 44, answeredChecks: 44,
      findings: { pass: 44, fail: 0, warning: 0, na: 0 }, scorePct: 100,
    });
    const ev = coverageEvidence(perfect);
    assert.ok(ev.unmeasured.length > 0, 'a 100% broad-evidence standard still has a coverage gap');
    assert.match(ev.unmeasured[0].label, /How much of CIS v8 this covers is not known/);
  });

  it('⛔ the unreadable-library case gets its OWN gap entry', () => {
    const ev = coverageEvidence(buildStandardCoverage({
      standard: 'PCI_DSS', label: 'PCI DSS', libraryTotal: null, mapped: null, scorePct: 49,
    }));
    assert.ok(ev.unmeasured.some((u) => /could not be read/.test(u.label)));
    // And it must not also claim the score rests on a known number of checks.
    assert.ok(ev.inputs.some((r) => r.value === '—'));
  });

  it('⛔ a thin figure says how few checks it rests on', () => {
    const ev = coverageEvidence(live('NIST'));
    assert.ok(ev.unmeasured.some((u) => /rests on 7 checks/.test(u.label)));
    assert.ok(ev.inputs.some((r) => r.label === 'Evidence behind the figure' && r.value === 'Thin evidence'));
  });

  it('a broad figure does NOT carry the thin caveat — or it becomes noise', () => {
    const ev = coverageEvidence(live('CIS_V8'));
    assert.equal(ev.unmeasured.some((u) => /rests on \d+ check/.test(u.label)), false);
  });

  it('⛔ the formula shows the denominator chain, not just the percentage', () => {
    const ev = coverageEvidence(live('NIST'));
    assert.match(ev.formula, /mapped to NIST/);
    assert.match(ev.formula, /produced a gradeable answer/);
    assert.match(ev.formula, /not a measure of framework coverage/);
  });

  it('⛔ absent counts print as em-dashes inside the formula, never as zeros', () => {
    const ev = coverageEvidence(buildStandardCoverage({
      standard: 'NIST', label: 'NIST', libraryTotal: null, mapped: null,
      evaluatedChecks: null, answeredChecks: null, scorePct: null,
    }));
    assert.match(ev.formula, /—/);
    assert.equal(/produced a gradeable answer\s+0\b/.test(ev.formula), false);
  });

  it('⛔ source and rule are customer-facing product prose, not file paths', () => {
    const ev = coverageEvidence(live('NIST'));
    assert.equal(/CLAUDE\.md/.test(ev.source + ev.rule), false);
    assert.equal(/\.js\b/.test(ev.source + ev.rule), false);
    assert.equal(/lib\//.test(ev.source + ev.rule), false);
  });

  it('⛔ no string anywhere in the descriptor leaks an internal reference', () => {
    const ev = coverageEvidence(live('PCI_DSS'));
    const blob = JSON.stringify(ev);
    assert.equal(/CLAUDE\.md/.test(blob), false);
  });
});

// ── the set ───────────────────────────────────────────────────────────────

describe('buildCoverageSet', () => {
  const STANDARDS = [
    { key: 'PCI_DSS', label: 'PCI DSS' },
    { key: 'NIST', label: 'NIST' },
  ];

  it('keys by standard and carries each label through', () => {
    const set = buildCoverageSet(
      STANDARDS,
      (key) => ({ mapped: key === 'NIST' ? 7 : 21, answeredChecks: key === 'NIST' ? 7 : 16 }),
      { libraryTotal: 45, scope: 'fleet' }
    );
    assert.deepEqual(Object.keys(set), ['PCI_DSS', 'NIST']);
    assert.equal(set.NIST.label, 'NIST');
    assert.equal(set.PCI_DSS.label, 'PCI DSS');
    assert.equal(set.NIST.grade, 'thin');
    assert.equal(set.PCI_DSS.grade, 'moderate');
  });

  it('⛔ a standard the per-key lookup knows nothing about is UNAVAILABLE, not zeroed', () => {
    // A standard missing from the library read must not report "0 of 45" — the
    // same rule as the whole-library failure, one row down.
    const set = buildCoverageSet(STANDARDS, () => ({}), { libraryTotal: 45 });
    assert.equal(set.NIST.available, false);
    assert.equal(set.NIST.cell, '—');
    assert.equal(set.NIST.grade, 'unknown');
  });

  it('tolerates a missing standards list and a missing lookup', () => {
    assert.deepEqual(buildCoverageSet(null, null), {});
    assert.deepEqual(Object.keys(buildCoverageSet(STANDARDS, null)), ['PCI_DSS', 'NIST']);
  });
});

// ── the report the auditors actually receive ──────────────────────────────

describe('⛔ the compliance PDF prints the denominator beside the percentage', () => {
  // THE FAILURE THIS PINS. The fleet-wide document — the one
  // services/engine-worker.js emails monthly — printed five framework
  // percentages with no statement of what any of them was computed over. A
  // reader with "NIST 42%" in an audit file has no way to learn it came from
  // seven checks.
  //
  // Driven through the real pdfkit render and read back out of the PDF's own
  // content streams, because the notes are chosen inside renderReportBody(),
  // which is not exported — and a test that read the source instead would pass
  // on a branch that never executes.

  const { generateReportPdf, buildCoverageIndex } = require('../lib/engines/complianceReport');
  const { contentStreams } = require('../lib/reports/pdfCompare');

  const devices = [
    { id: 'd1', name: 'fw-a', vendor: 'fortinet' },
    { id: 'd2', name: 'fw-b', vendor: 'paloalto' },
  ];
  const findings = [
    { device_id: 'd1', status: 'pass', standards: ['NIST', 'CIS_V8'] },
    { device_id: 'd1', status: 'fail', standards: ['NIST', 'CIS_V8'] },
    { device_id: 'd2', status: 'na', standards: ['NIST'] },
  ];

  function stubPool(opts = {}) {
    return {
      query: async (sql) => {
        if (sql.includes('library_total')) {
          return opts.libraryFails
            ? Promise.reject(new Error('library read failed'))
            : { rows: [
              { standard: 'NIST', mapped: 7, applicable: 7, library_total: 45 },
              { standard: 'CIS_V8', mapped: 44, applicable: 41, library_total: 45 },
              { standard: 'PCI_DSS', mapped: 21, applicable: 19, library_total: 45 },
              { standard: 'ISO_27001', mapped: 35, applicable: 34, library_total: 45 },
              { standard: 'SANS', mapped: 12, applicable: 12, library_total: 45 },
            ] };
        }
        if (sql.includes('answered_checks')) {
          return { rows: [{ standard: 'NIST', evaluated_checks: 7, answered_checks: 5 }] };
        }
        if (sql.includes('FROM devices WHERE active')) return { rows: devices };
        if (sql.includes('FROM audit_checks')) return { rows: [{ total: 45, mapped: 7 }] };
        if (sql.includes('remediation_guidance')) {
          return { rows: findings.filter((f) => f.status === 'fail' || f.status === 'warning') };
        }
        return { rows: findings };
      },
    };
  }

  // pdfkit writes every glyph run as a hex string inside a TJ array, so the
  // rendered words are invisible to a plain search of the buffer.
  function pdfText(buf) {
    return contentStreams(buf).map((stream) => {
      let out = '';
      stream.replace(/<([0-9a-fA-F]+)>/g, (whole, hex) => {
        for (let i = 0; i < hex.length; i += 2) out += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
        return whole;
      });
      return out;
    }).join('');
  }

  it('⛔ the UNSCOPED report states the claim and every standard’s basis', async () => {
    const text = pdfText(await generateReportPdf(stubPool()));
    assert.match(text, /share of SecVault's own mapped checks/, 'the claim is missing');
    assert.match(text, /how much of that framework is covered/);
    assert.match(text, /SecVault checks/, 'the denominator column is missing');
    assert.match(text, /7 of 45/, 'the NIST denominator is missing');
    assert.match(text, /Thin evidence/, 'the evidence grade is missing');
    assert.match(text, /NIST \(7\)/, 'the per-device matrix header carries no count');
  });

  it('⛔ a scoped report says its score is not a measure of the framework', async () => {
    const text = pdfText(await generateReportPdf(stubPool(), { standard: 'NIST' }));
    assert.match(text, /are mapped to NIST/);
    assert.match(text, /how much of that framework is covered/);
    assert.match(text, /not comparable with the overall compliance score/);
  });

  it('⛔ AN UNREADABLE LIBRARY STILL PRINTS THE CAVEAT — it just cannot print the basis', async () => {
    // The case that regresses silently: a failed read must not take the whole
    // qualification with it and leave the percentage standing bare again.
    const text = pdfText(await generateReportPdf(stubPool({ libraryFails: true })));
    assert.match(text, /how much of that framework is covered/);
    assert.equal(/0 of 45/.test(text), false, 'a failed read must never print as a zero');
    assert.match(text, /Evidence not known/);
  });

  it('⛔ buildCoverageIndex reports UNAVAILABLE rather than zero when both reads fail', () => {
    const idx = buildCoverageIndex({ library: null, checkCoverage: null, perDevice: [] });
    for (const key of Object.keys(idx)) {
      assert.equal(idx[key].available, false);
      assert.equal(idx[key].cell, '—');
      assert.equal(idx[key].grade, 'unknown');
      assert.notEqual(idx[key].mapped, 0);
    }
  });
});

describe('⛔ the two coverage reads fail to NULL, never to a plausible map', () => {
  // ⛔ WHY THESE ARE SEPARATE FROM THE RENDER TESTS ABOVE. A mutation that made
  // libraryCoverage() return `{ libraryTotal: 45, byStandard: {} }` on a thrown
  // read SURVIVED the PDF assertions — the page looked identical, because with
  // no per-standard row the cell falls back to a dash either way. What it
  // quietly fabricated was the 45: the evidence drawer's "Checks in SecVault's
  // library" row would state a library size read from nothing. Caught only by
  // asserting the return value itself.

  const { libraryCoverage, fleetCheckCoverage, buildFleetSummaryTable } = require('../lib/engines/complianceReport');

  const throwingPool = { query: async () => { throw new Error('nope'); } };

  it('⛔ libraryCoverage is NULL on a read failure, not a zeroed or defaulted map', async () => {
    assert.equal(await libraryCoverage(throwingPool), null);
  });

  it('⛔ libraryCoverage is NULL when the rows carry no library total', async () => {
    // The shape a differently-worded query would return. A partial read is not
    // a measurement, and a missing total must not be filled in from the code.
    const pool = { query: async () => ({ rows: [{ standard: 'NIST', mapped: 7, applicable: 7 }] }) };
    assert.equal(await libraryCoverage(pool), null);
  });

  it('reads the real shape correctly', async () => {
    const pool = {
      query: async () => ({ rows: [{ standard: 'NIST', mapped: 7, applicable: 6, library_total: 45 }] }),
    };
    const c = await libraryCoverage(pool);
    assert.equal(c.libraryTotal, 45);
    assert.deepEqual(c.byStandard.NIST, { mapped: 7, applicable: 6 });
  });

  it('⛔ fleetCheckCoverage is NULL on a read failure — so the grade reads `unknown`, not `none`', async () => {
    // `none` would assert that no check produced an answer anywhere on the
    // fleet, from a failed read of our own tables.
    assert.equal(await fleetCheckCoverage(throwingPool), null);
  });

  it('an EMPTY result is a real answer (nothing audited yet) and stays an empty map', async () => {
    const pool = { query: async () => ({ rows: [] }) };
    assert.deepEqual(await fleetCheckCoverage(pool), {});
  });

  it('⛔ an unrecognisable result is NULL, not an empty map', async () => {
    const pool = { query: async () => ({ rows: [{ something_else: 1 }] }) };
    assert.equal(await fleetCheckCoverage(pool), null);
  });

  it('⛔ with NO coverage index at all the summary table prints dashes, never zeros', () => {
    // The defensive branch, reachable only from a direct caller — and the one
    // place a "default it to something plausible" would survive review.
    const fleet = {
      byStandard: { PCI_DSS: 49, ISO_27001: 58, CIS_V8: 50, NIST: 42, SANS: 45 },
      byStandardCounts: {
        PCI_DSS: { pass: 1, fail: 1, warning: 0 }, ISO_27001: { pass: 1, fail: 1, warning: 0 },
        CIS_V8: { pass: 1, fail: 1, warning: 0 }, NIST: { pass: 1, fail: 1, warning: 0 },
        SANS: { pass: 1, fail: 1, warning: 0 },
      },
    };
    const t = buildFleetSummaryTable(fleet, null, null);
    for (const r of t.rows) {
      assert.equal(r.checks, '-', 'an absent denominator must be a dash');
      assert.equal(r.evidence, 'Evidence not known');
      assert.equal(/\bof 45\b/.test(String(r.checks)), false);
      assert.equal(/^0\b/.test(String(r.checks)), false);
    }
  });

  it('⛔ the denominator column is drawn hueless — it is coverage, not a result', () => {
    const t = buildFleetSummaryTable(
      { byStandard: { NIST: 42 }, byStandardCounts: { NIST: { pass: 1, fail: 1, warning: 0 } } },
      'NIST',
      null
    );
    for (const key of ['checks', 'evidence']) {
      const col = t.columns.find((c) => c.key === key);
      assert.equal(typeof col.color, 'function', `${key} has no colour rule`);
      assert.equal(col.color(t.rows[0]), '#6D7784', `${key} must use the unmeasured grey`);
    }
  });
});
