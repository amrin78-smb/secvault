'use strict';
// tests/complianceDeviceCoverage.test.js
//
// Pins the PER-DEVICE half of lib/engines/complianceCoverage.js — the gradeable
// denominator beside a per-firewall compliance percentage.
//
// ⛔ THE DEFECT. v2.163.0 fixed "NIST 42%" by keying coverage on the STANDARD.
// Nothing keyed it on the DEVICE, and that is the axis where this product's own
// signature bug bites hardest, because the denominator varies by VENDOR rather
// than by anything the customer did. Measured 2026-11-12 against the six-vendor
// mock fleet (`secvault_mock`), scored with the product's own formula:
//
//   MOCK-FP-DC-07          forcepoint  78%   9 gradeable of 10 applicable
//   MOCK-CP-Perimeter-04   checkpoint  78%   9 of 10
//   MOCK-SANGFOR-Branch-06 sangfor     78%   9 of 10
//   MOCK-ASA-Edge-05       cisco_asa   73%  11 of 13
//   MOCK-FGT-Branch-01     fortinet    60%  25 of 28
//   MOCK-FGT-Edge-02       fortinet    40%  25 of 28
//   MOCK-PAN-DC-01         paloalto    38%  21 of 24
//   MOCK-UNREACHABLE-03    cisco_asa    —    0 of 13 (every check `na`)
//
// The library behind those numbers is 45 checks, of which 10 carry NO vendor,
// fortinet 18, paloalto 14, cisco_asa 3, and checkpoint/sangfor/forcepoint
// NONE. So the three vendors SecVault holds no vendor-specific checks for came
// out TOP of the fleet, and a Palo Alto assessed on more than twice as many
// checks came out bottom. The arithmetic was right; the comparison the bare
// figures invited was not.
//
// ⛔ EVERY CASE HERE HAS A "WE COULD NOT MEASURE THIS" COUNTERPART, because
// that is the one that regresses silently: an absent applicable count coerced
// to 0 prints "0 of 0 checks apply", which reads as a firewall nobody can
// audit — a confident, plausible, wrong sentence rather than a crash.
//
// ⛔ AND THE UI ASSERTIONS RENDER. A source scan for the right variable name
// cannot tell a coverage column that paints from one that does not; three
// features shipped broken in this repo in one day on exactly that mistake. The
// matrix is mounted with react-dom/server and its WORDS are read.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const {
  DEVICE_COVERAGE_CLAIM,
  GRADES,
  GRADE_LABEL,
  GRADE_THIN_MAX,
  GRADE_BROAD_MIN,
  DEVICE_GRADE_THIN_MAX,
  DEVICE_GRADE_BROAD_MIN,
  gradeFor,
  deviceGradeFor,
  buildDeviceCoverage,
  buildDeviceCoverageSet,
  deviceCoverageEvidence,
} = require('../lib/engines/complianceCoverage');
const { isRenderableEvidence } = require('../lib/evidence');

// ── the live shape, so a regression is a number someone can re-measure ────

const LIBRARY_TOTAL = 45;

// Measured per vendor on 2026-11-12: `SELECT vendor, count(*) FROM audit_checks
// GROUP BY vendor` gave fortinet 18, paloalto 14, NULL 10, cisco_asa 3, and no
// row at all for checkpoint/sangfor/forcepoint. Applicable = the 10 shared plus
// the vendor's own.
const APPLICABLE = {
  fortinet: 28,
  paloalto: 24,
  cisco_asa: 13,
  checkpoint: 10,
  sangfor: 10,
  forcepoint: 10,
};

const FLEET = [
  { name: 'MOCK-FP-DC-07', vendor: 'forcepoint', evaluated: 10, answered: 9, score: 78, findings: { pass: 7, fail: 2, warning: 0, na: 1 } },
  { name: 'MOCK-CP-Perimeter-04', vendor: 'checkpoint', evaluated: 10, answered: 9, score: 78, findings: { pass: 7, fail: 2, warning: 0, na: 1 } },
  { name: 'MOCK-SANGFOR-Branch-06', vendor: 'sangfor', evaluated: 10, answered: 9, score: 78, findings: { pass: 7, fail: 2, warning: 0, na: 1 } },
  { name: 'MOCK-ASA-Edge-05', vendor: 'cisco_asa', evaluated: 13, answered: 11, score: 73, findings: { pass: 8, fail: 3, warning: 0, na: 2 } },
  { name: 'MOCK-FGT-Branch-01', vendor: 'fortinet', evaluated: 28, answered: 25, score: 60, findings: { pass: 15, fail: 9, warning: 1, na: 3 } },
  { name: 'MOCK-FGT-Edge-02', vendor: 'fortinet', evaluated: 28, answered: 25, score: 40, findings: { pass: 10, fail: 14, warning: 1, na: 3 } },
  { name: 'MOCK-PAN-DC-01', vendor: 'paloalto', evaluated: 24, answered: 21, score: 38, findings: { pass: 8, fail: 11, warning: 2, na: 3 } },
  { name: 'MOCK-UNREACHABLE-03', vendor: 'cisco_asa', evaluated: 13, answered: 0, score: null, findings: { pass: 0, fail: 0, warning: 0, na: 13 } },
];

function cover(spec, overrides = {}) {
  return buildDeviceCoverage({
    deviceId: spec.name,
    deviceName: spec.name,
    vendor: spec.vendor,
    vendorLabel: spec.vendor,
    libraryTotal: LIBRARY_TOTAL,
    applicable: APPLICABLE[spec.vendor],
    evaluatedChecks: spec.evaluated,
    answeredChecks: spec.answered,
    findings: spec.findings,
    scorePct: spec.score,
    ...overrides,
  });
}

const byName = (name) => cover(FLEET.find((d) => d.name === name));

// ⛔ THE SECOND READING, taken later the same day after vendor coverage for
// checkpoint/forcepoint/sangfor landed and the library went 45 -> 74. Pinned
// alongside the first because the FIRST would otherwise read as the permanent
// shape of the fleet, and because the band justification has to hold on both:
// cisco_asa is still the least-covered vendor and 13 is still its full
// applicable count, so DEVICE_GRADE_THIN_MAX did not move.
const FLEET_74 = {
  libraryTotal: 74,
  applicable: { fortinet: 28, paloalto: 24, checkpoint: 20, forcepoint: 20, sangfor: 19, cisco_asa: 13 },
  devices: [
    { name: 'MOCK-SANGFOR-Branch-06', vendor: 'sangfor', evaluated: 19, answered: 9, score: 78 },
    { name: 'MOCK-FP-DC-07', vendor: 'forcepoint', evaluated: 20, answered: 10, score: 70 },
    { name: 'MOCK-CP-Perimeter-04', vendor: 'checkpoint', evaluated: 20, answered: 10, score: 70 },
    { name: 'MOCK-ASA-Edge-05', vendor: 'cisco_asa', evaluated: 0, answered: 0, score: null },
    { name: 'MOCK-FGT-Branch-01', vendor: 'fortinet', evaluated: 0, answered: 0, score: null },
    { name: 'MOCK-PAN-DC-01', vendor: 'paloalto', evaluated: 0, answered: 0, score: null },
  ],
};

describe('⛔ the bands still hold after the library grew 45 -> 74', () => {
  it('the three vendors that gained coverage are still THIN, on their real counts', () => {
    const got = FLEET_74.devices.map((d) => {
      const c = buildDeviceCoverage({
        deviceName: d.name,
        vendor: d.vendor,
        vendorLabel: d.vendor,
        libraryTotal: FLEET_74.libraryTotal,
        applicable: FLEET_74.applicable[d.vendor],
        evaluatedChecks: d.evaluated,
        answeredChecks: d.answered,
        scorePct: d.score,
      });
      return `${d.name} ${d.score === null ? '—' : d.score + '%'} ${c.cell} ${c.grade}`;
    });
    assert.deepEqual(got, [
      'MOCK-SANGFOR-Branch-06 78% 9 of 19 thin',
      'MOCK-FP-DC-07 70% 10 of 20 thin',
      'MOCK-CP-Perimeter-04 70% 10 of 20 thin',
      'MOCK-ASA-Edge-05 — 0 of 13 none',
      'MOCK-FGT-Branch-01 — 0 of 28 none',
      'MOCK-PAN-DC-01 — 0 of 24 none',
    ]);
  });

  it('⛔ cisco_asa is STILL the lowest ceiling, which is what pins DEVICE_GRADE_THIN_MAX', () => {
    // If this ever stops being true, the constant has to be re-derived from the
    // new lowest ceiling in the same commit — not left at 13 because it passed.
    const lowest = Math.min(...Object.values(FLEET_74.applicable));
    assert.equal(lowest, FLEET_74.applicable.cisco_asa);
    assert.equal(DEVICE_GRADE_THIN_MAX, lowest,
      'the thin ceiling is the least-covered vendor’s full applicable count');
  });

  it('⛔ half-`na` coverage is still a THIN basis, not a moderate one', () => {
    // 20 checks ran and 10 produced a gradeable answer. The 20 is not the
    // denominator of anything; grading on it would be the two-units trap with a
    // kinder face.
    assert.equal(deviceGradeFor(20), 'broad', 'the count that RAN');
    assert.equal(deviceGradeFor(10), 'thin', 'the count that was ANSWERED — the one that counts');
  });
});

// ── the claim ─────────────────────────────────────────────────────────────

describe('⛔ DEVICE_COVERAGE_CLAIM refuses the league table a column of bare percentages becomes', () => {
  it('names the denominator', () => {
    assert.match(DEVICE_COVERAGE_CLAIM, /SecVault checks/);
    assert.match(DEVICE_COVERAGE_CLAIM, /vendor/);
  });

  it('⛔ states outright that two firewalls’ figures are not comparable', () => {
    // Without this sentence the counts beside the figures are an improvement in
    // honesty that still lets the old reading stand.
    assert.match(DEVICE_COVERAGE_CLAIM, /not comparable/);
  });

  it('⛔ invents no framework requirement total and claims no compliance', () => {
    for (const bad of [/\d+\s+requirements/i, /certified/i, /fully compliant/i, /\broughly\b/i, /\bapproximately\b/i, /\babout \d/i, /~\s*\d/]) {
      assert.doesNotMatch(DEVICE_COVERAGE_CLAIM, bad, String(bad));
    }
  });

  it('⛔ carries no internal documentation reference', () => {
    assert.doesNotMatch(DEVICE_COVERAGE_CLAIM, /CLAUDE\.md|lib\/|\.js\b/);
  });
});

// ── the bands, at DEVICE grain ────────────────────────────────────────────

describe('deviceGradeFor — the bands were measured at device grain, not inherited', () => {
  it('⛔ NINE GRADEABLE CHECKS IS THIN HERE AND WOULD BE MODERATE AT STANDARD GRAIN', () => {
    // This single assertion is the fix. Three of eight mock firewalls rest on
    // exactly nine checks, and nine is nearly everything the library can ask of
    // their vendors — a fact about SecVault's coverage, not about the firewall.
    assert.equal(gradeFor(9), 'moderate', 'the standard-grain band, unchanged');
    assert.equal(deviceGradeFor(9), 'thin', 'the device-grain band');
  });

  it('bands the measured counts the way the ceilings imply', () => {
    assert.equal(deviceGradeFor(9), 'thin', 'checkpoint/sangfor/forcepoint, ceiling 10');
    assert.equal(deviceGradeFor(11), 'thin', 'cisco_asa, ceiling 13');
    assert.equal(deviceGradeFor(21), 'broad', 'paloalto, ceiling 24');
    assert.equal(deviceGradeFor(25), 'broad', 'fortinet, ceiling 28');
  });

  it('⛔ the thin ceiling is cisco_asa’s FULL applicable count, so that vendor can never read broad', () => {
    // 13 is not a round number chosen to fit: it is the largest number of
    // checks this library can put to a firewall from the four vendors it barely
    // covers, so a count at or below it cannot be a broad measurement.
    assert.equal(DEVICE_GRADE_THIN_MAX, 13);
    assert.equal(deviceGradeFor(APPLICABLE.cisco_asa), 'thin');
    assert.equal(deviceGradeFor(APPLICABLE.checkpoint), 'thin');
    assert.equal(deviceGradeFor(DEVICE_GRADE_THIN_MAX + 1), 'moderate');
  });

  it('⛔ broad stays at 20, or paloalto could never grade broad however completely it was assessed', () => {
    // Its ceiling is 24. A broad threshold of 25 would have put a fully
    // assessed Palo Alto permanently in `moderate`.
    assert.equal(DEVICE_GRADE_BROAD_MIN, GRADE_BROAD_MIN);
    // ⛔ THIS MESSAGE USED TO SAY "reachable by every supported vendor", WHICH IS
    // FALSE AND THE ASSERTION NEVER CHECKED IT. Corrected 2026-11-12. It checks
    // paloalto, and paloalto is the right vendor to pin because it is the
    // LOWEST ceiling that still clears 20 — so it is what the threshold is
    // actually constrained by.
    assert.ok(DEVICE_GRADE_BROAD_MIN <= APPLICABLE.paloalto,
      'the broad threshold must stay reachable by paloalto, the lowest ceiling above it');
    assert.equal(deviceGradeFor(APPLICABLE.paloalto), 'broad');
  });

  it('⛔ two vendors can NEVER grade broad, and that is recorded rather than implied', () => {
    // ⛔ A CONSEQUENCE OF THE BAND, NOT A BUG, BUT IT MUST BE WRITTEN DOWN.
    // cisco_asa's applicable ceiling is 13 and sangfor's is 19, both below the
    // broad threshold of 20 — so however completely either is assessed it can
    // never read better than `thin` and `moderate` respectively. That is
    // HONEST: the library genuinely covers those vendors least, and this whole
    // feature exists to stop a thin denominator reading as a good result. The
    // trap is a future maintainer "fixing" it by lowering the threshold, which
    // would re-admit exactly the 9-check firewall grading moderate.
    //
    // If a vendor's check coverage is later expanded, this test will fail —
    // which is the point: re-derive the bands then, deliberately.
    // ⛔ DERIVED FROM THE LIVE SEED, NOT FROM THE `APPLICABLE` FIXTURE ABOVE.
    // That fixture is a representative snapshot taken while the library was 45
    // checks; the library is now 74, and a guard about REAL vendor coverage has
    // to read the real library or it pins a number that has already moved. (It
    // caught exactly that on its first run: the fixture still said sangfor 10.)
    const { CHECKS } = require('../lib/auditChecksSeed');
    const shared = CHECKS.filter((c) => !c.vendor).length;
    const ceilingFor = (vendor) =>
      CHECKS.filter((c) => c.vendor === vendor).length + shared;

    const asa = ceilingFor('cisco_asa');
    const sangfor = ceilingFor('sangfor');
    assert.ok(asa < DEVICE_GRADE_BROAD_MIN,
      `cisco_asa ceiling is now ${asa}; re-derive the device bands rather than lowering broad`);
    assert.ok(sangfor < DEVICE_GRADE_BROAD_MIN,
      `sangfor ceiling is now ${sangfor}; re-derive the device bands rather than lowering broad`);
    assert.equal(deviceGradeFor(asa), 'thin');
    assert.equal(deviceGradeFor(sangfor), 'moderate');
  });

  it('⛔ the device band is WIDER than the standard band, never narrower', () => {
    // A device grade answers a bigger question than one standard's, so it may
    // never be easier to earn.
    assert.ok(DEVICE_GRADE_THIN_MAX > GRADE_THIN_MAX,
      'a device assessed on 8 checks must not grade better than a standard measured on 8');
  });

  it('⛔ null is `unknown`, 0 is `none`, and they are different facts', () => {
    assert.equal(deviceGradeFor(null), 'unknown');
    assert.equal(deviceGradeFor(undefined), 'unknown');
    assert.equal(deviceGradeFor(NaN), 'unknown');
    assert.equal(deviceGradeFor('nonsense'), 'unknown');
    assert.equal(deviceGradeFor(0), 'none');
    assert.notEqual(GRADE_LABEL.unknown, GRADE_LABEL.none);
  });

  it('⛔ it is an absolute count, never a share of `applicable`', () => {
    // A ratio would grade the Check Point's 9-of-10 as the best-evidenced
    // firewall on the fleet, which is exactly the reading being fixed.
    const cp = byName('MOCK-CP-Perimeter-04');
    const pan = byName('MOCK-PAN-DC-01');
    assert.ok(cp.answeredChecks / cp.applicable > pan.answeredChecks / pan.applicable,
      'the ratio really does favour the thin firewall — that is why a ratio is refused');
    assert.equal(cp.grade, 'thin');
    assert.equal(pan.grade, 'broad');
  });

  it('every grade is a declared one', () => {
    for (const n of [null, 0, 1, 13, 14, 19, 20, 100]) {
      assert.ok(GRADES.includes(deviceGradeFor(n)), String(n));
    }
  });
});

// ── the defect itself ─────────────────────────────────────────────────────

describe('⛔ the fleet no longer ranks the least-covered vendor highest, unqualified', () => {
  it('the three 78%s are thin and the 38% is broad', () => {
    const got = FLEET.map((d) => {
      const c = cover(d);
      return `${d.name} ${d.score === null ? '—' : d.score + '%'} ${c.cell} ${c.grade}`;
    });
    assert.deepEqual(got, [
      'MOCK-FP-DC-07 78% 9 of 10 thin',
      'MOCK-CP-Perimeter-04 78% 9 of 10 thin',
      'MOCK-SANGFOR-Branch-06 78% 9 of 10 thin',
      'MOCK-ASA-Edge-05 73% 11 of 13 thin',
      'MOCK-FGT-Branch-01 60% 25 of 28 broad',
      'MOCK-FGT-Edge-02 40% 25 of 28 broad',
      'MOCK-PAN-DC-01 38% 21 of 24 broad',
      'MOCK-UNREACHABLE-03 — 0 of 13 none',
    ]);
  });

  it('⛔ a higher score on fewer checks never carries a stronger evidence grade', () => {
    // The property, not a table: this is what "78% on 9 renders identically to
    // 78% on 25" was.
    const rank = { unknown: 0, none: 0, thin: 1, moderate: 2, broad: 3 };
    for (const a of FLEET) {
      for (const b of FLEET) {
        if (a.answered <= b.answered) continue;
        assert.ok(
          rank[cover(a).grade] >= rank[cover(b).grade],
          `${a.name} rests on more checks than ${b.name} and must not grade weaker`
        );
      }
    }
  });

  it('⛔ the figure never appears without its denominator in the same string', () => {
    const c = byName('MOCK-CP-Perimeter-04');
    assert.match(c.statement, /78%/);
    assert.match(c.statement, /rests on 9 checks/);
    assert.match(c.statement, /10 of 45/);
  });

  it('⛔ names the vendor as the reason the bases differ', () => {
    const c = byName('MOCK-CP-Perimeter-04');
    assert.match(c.caveat, /checkpoint/);
    assert.match(c.caveat, /not comparable/);
  });

  it('⛔ NO SCORE ARITHMETIC HAPPENS HERE — scorePct is carried through verbatim', () => {
    // Including values no formula in this product would produce: this module
    // may never recompute, clamp or round the figure it qualifies.
    for (const pct of [0, 1, 38, 57, 78, 100, -3, 137]) {
      assert.equal(cover(FLEET[0], { scorePct: pct }).scorePct, pct, String(pct));
    }
  });

  it('⛔ a null score stays null and is never rendered as 0%', () => {
    const c = byName('MOCK-UNREACHABLE-03');
    assert.equal(c.scorePct, null);
    assert.doesNotMatch(c.statement, /0%/);
    assert.match(c.detail, /no percentage to read/);
  });

  it('⛔ the caveat NEVER says "this percentage" where there is no percentage', () => {
    // Found by rendering all eight per-device pages against the mock database:
    // MOCK-UNREACHABLE-03 printed "none produced a gradeable answer, so there is
    // no percentage to read" and then "so this percentage is not comparable
    // with…" in the very next sentence — a caveat about a figure the reader then
    // goes looking for. The engine's own unit tests had not noticed, which is
    // why the words are now asserted and not only the fields.
    const none = byName('MOCK-UNREACHABLE-03');
    assert.doesNotMatch(none.caveat, /this percentage/);
    assert.match(none.caveat, /how thoroughly this firewall can be assessed/);

    // And it DOES say it where a percentage exists, or the point is lost.
    assert.match(byName('MOCK-CP-Perimeter-04').caveat, /this percentage is not comparable/);
  });
});

// ── two units, kept apart ─────────────────────────────────────────────────

describe('⛔ TWO UNITS: distinct checks, never finding rows summed across standards', () => {
  // Measured per device per standard on the mock fleet:
  //   MOCK-CP-Perimeter-04  PCI 5 · ISO 5 · CIS 8 · NIST 3 · SANS 5  = 26
  //   MOCK-FGT-Branch-01    PCI 12 · ISO 19 · CIS 24 · NIST 4 · SANS 9 = 68
  // against 10 applicable checks and a 45-check library. On ONE device a
  // finding row and a check coincide (verified: finding_rows ===
  // distinct_checks on all 8 firewalls), which is what makes this invisible
  // until the per-standard buckets are added up.
  const SUMMED = { 'MOCK-CP-Perimeter-04': 26, 'MOCK-FGT-Branch-01': 68 };

  for (const [name, summed] of Object.entries(SUMMED)) {
    it(`⛔ ${name}: ${summed} answered "checks" is impossible and is reported UNKNOWN`, () => {
      const spec = FLEET.find((d) => d.name === name);
      const c = cover(spec, { evaluatedChecks: summed, answeredChecks: summed });
      assert.equal(c.inconsistent, true);
      assert.equal(c.grade, 'unknown', 'never a confident grade over a count that cannot be true');
      assert.equal(c.answeredChecks, null);
      assert.equal(c.cell, '—', 'and never the impossible number itself');
      assert.doesNotMatch(c.statement, new RegExp(String(summed)));
      assert.match(c.statement, /could not be established|could not be counted/);
    });
  }

  it('⛔ a count above the LIBRARY total is impossible even with no applicable count', () => {
    const c = cover(FLEET[0], { applicable: null, answeredChecks: 68, evaluatedChecks: 68 });
    assert.equal(c.inconsistent, true);
    assert.equal(c.grade, 'unknown');
  });

  it('a count at the bound exactly is fine — the guard is strictly greater', () => {
    const c = cover(FLEET[0], { evaluatedChecks: 10, answeredChecks: 10 });
    assert.equal(c.inconsistent, false);
    assert.equal(c.answeredChecks, 10);
    assert.equal(c.grade, 'thin');
  });

  it('⛔ the inconsistent case degrades toward UNKNOWN, never toward a grade', () => {
    // A device re-platformed to another vendor after being audited produces the
    // same shape legitimately. Either way the honest answer is that the basis
    // could not be established.
    const c = cover(FLEET[1], { evaluatedChecks: 28, answeredChecks: 25 });
    assert.equal(c.grade, 'unknown');
    assert.equal(c.available, false);
    const ev = deviceCoverageEvidence(c);
    assert.ok(ev.unmeasured.some((u) => /could not be established/.test(u.label)));
    assert.ok(ev.unmeasured.some((u) => /earlier vendor/.test(u.reason)));
  });
});

// ── the cases that regress silently ───────────────────────────────────────

describe('⛔ a failed read is never a figure', () => {
  it('⛔ an unreadable applicable count is UNAVAILABLE, never "0 of 0"', () => {
    const c = cover(FLEET[0], { applicable: null, libraryTotal: null });
    assert.equal(c.available, false);
    assert.doesNotMatch(c.statement, /\b0 of 0\b/);
    assert.doesNotMatch(c.statement, /\b0 of 45\b/);
    assert.match(c.headline, /could not be read/);
  });

  it('⛔ a half-readable library is unavailable too — no half-statement', () => {
    for (const o of [{ applicable: null }, { libraryTotal: null }]) {
      const c = cover(FLEET[0], o);
      assert.equal(c.available, false, JSON.stringify(o));
      assert.equal(c.detail, '', 'a detail line over an absent denominator is the defect');
    }
  });

  it('⛔ an unknown evaluated count says so and does not read as "none ran"', () => {
    const c = cover(FLEET[0], { evaluatedChecks: null });
    assert.match(c.detail, /not known/);
    assert.doesNotMatch(c.detail, /\b0 ran\b/);
  });

  it('⛔ A DERIVED GAP OVER AN ABSENT INPUT IS NULL, NOT ZERO', () => {
    // "0 checks could not be assessed" is a reassuring sentence computed from
    // nothing — the exact defect this file exists to prevent.
    const c = cover(FLEET[0], { evaluatedChecks: null, answeredChecks: null });
    assert.equal(c.neverRan, null);
    assert.equal(c.unanswerable, null);
    const d = cover(FLEET[0], { applicable: null });
    assert.equal(d.notApplicable, null);
    assert.equal(d.neverRan, null);
  });

  it('⛔ an absent `na` bucket is an em-dash in the drawer, not "Not assessable 0"', () => {
    const c = cover(FLEET[0], { findings: null });
    const ev = deviceCoverageEvidence(c);
    assert.ok(!ev.inputs.some((i) => /Not assessable/.test(i.label)),
      'an unread bucket is omitted rather than printed as zero');
  });

  it('a gap never goes negative, however inconsistent the inputs', () => {
    const c = cover(FLEET[0], { applicable: 10, libraryTotal: 4, evaluatedChecks: 2, answeredChecks: 1 });
    for (const k of ['notApplicable', 'neverRan', 'unanswerable']) {
      assert.ok(c[k] === null || c[k] >= 0, `${k} = ${c[k]}`);
    }
  });

  it('⛔ `none` and `unknown` never share a label or a cell meaning', () => {
    const none = byName('MOCK-UNREACHABLE-03');
    const unknown = cover(FLEET[0], { answeredChecks: null });
    assert.equal(none.grade, 'none');
    assert.equal(unknown.grade, 'unknown');
    assert.notEqual(none.gradeLabel, unknown.gradeLabel);
    assert.equal(none.cell, '0 of 13', 'a measured zero IS a measurement');
    assert.equal(unknown.cell, '—', 'an unknown count is never a zero');
  });
});

// ── the drawer ────────────────────────────────────────────────────────────

describe('deviceCoverageEvidence — reuses the one drawer', () => {
  it('produces a descriptor the shared drawer will actually render', () => {
    for (const d of FLEET) {
      assert.ok(isRenderableEvidence(deviceCoverageEvidence(cover(d))), d.name);
    }
  });

  it('returns null rather than an empty drawer', () => {
    assert.equal(deviceCoverageEvidence(null), null);
    assert.equal(deviceCoverageEvidence(undefined), null);
  });

  it('⛔ AN ALL-CLEAR IS FORBIDDEN: the vendor-coverage limit is ALWAYS listed', () => {
    // It never closes — the number of checks SecVault holds for a vendor is not
    // something an audit run can improve — so a firewall assessed on all 28 of
    // its applicable checks still carries it.
    for (const d of FLEET) {
      const ev = deviceCoverageEvidence(cover(d));
      assert.ok(ev.unmeasured.length > 0, d.name);
      assert.match(ev.unmeasured[0].label, /limit of SecVault/, d.name);
    }
  });

  it('⛔ a thin figure says how few checks it rests on; a broad one does not', () => {
    const thin = deviceCoverageEvidence(byName('MOCK-CP-Perimeter-04'));
    assert.ok(thin.unmeasured.some((u) => /rests on 9 checks/.test(u.label)));
    assert.ok(thin.unmeasured.some((u) => /do not rank this/.test(u.reason)));

    const broad = deviceCoverageEvidence(byName('MOCK-FGT-Branch-01'));
    assert.ok(!broad.unmeasured.some((u) => /rests on 25 checks/.test(u.label)),
      'the thin caveat on every firewall is noise, and noise gets skipped');
  });

  it('⛔ the formula shows the denominator chain, not just the percentage', () => {
    const ev = deviceCoverageEvidence(byName('MOCK-PAN-DC-01'));
    assert.match(ev.formula, /checks in SecVault/);
    assert.match(ev.formula, /can be asked of a paloalto/);
    assert.match(ev.formula, /produced a gradeable answer/);
    assert.match(ev.formula, /not on the firewall/);
  });

  it('⛔ absent counts print as em-dashes inside the formula, never as zeros', () => {
    const ev = deviceCoverageEvidence(cover(FLEET[0], {
      libraryTotal: null, applicable: null, evaluatedChecks: null, answeredChecks: null,
    }));
    assert.match(ev.formula, /—/);
    assert.doesNotMatch(ev.formula, /\b0\b/);
  });

  it('⛔ source and rule are customer-facing product prose, not file paths', () => {
    const ev = deviceCoverageEvidence(byName('MOCK-FGT-Edge-02'));
    assert.doesNotMatch(ev.source, /\.js|lib\//);
    assert.doesNotMatch(ev.rule, /\.js|lib\//);
  });

  it('⛔ no string anywhere in the descriptor leaks an internal reference', () => {
    const ev = deviceCoverageEvidence(byName('MOCK-FGT-Edge-02'));
    const all = JSON.stringify(ev);
    assert.doesNotMatch(all, /CLAUDE\.md/);
    assert.doesNotMatch(all, /ai-codex/);
  });

  it('⛔ invents no framework requirement total, in any field', () => {
    for (const d of FLEET) {
      const all = JSON.stringify(deviceCoverageEvidence(cover(d)));
      for (const bad of [/\d+\s+requirements/i, /\broughly\b/i, /\bapproximately\b/i, /~\s*\d/]) {
        assert.doesNotMatch(all, bad, `${d.name} ${String(bad)}`);
      }
    }
  });
});

// ── the set builder ───────────────────────────────────────────────────────

describe('buildDeviceCoverageSet', () => {
  const devices = FLEET.map((d) => ({ deviceId: d.name, deviceName: d.name, vendor: d.vendor }));

  it('keys by device id and carries each vendor through', () => {
    const set = buildDeviceCoverageSet(devices, (id) => {
      const d = FLEET.find((x) => x.name === id);
      return {
        vendorLabel: d.vendor,
        libraryTotal: LIBRARY_TOTAL,
        applicable: APPLICABLE[d.vendor],
        evaluatedChecks: d.evaluated,
        answeredChecks: d.answered,
        scorePct: d.score,
      };
    });
    assert.deepEqual(Object.keys(set).sort(), devices.map((d) => d.deviceId).sort());
    assert.equal(set['MOCK-PAN-DC-01'].applicable, 24);
    assert.equal(set['MOCK-CP-Perimeter-04'].grade, 'thin');
  });

  it('⛔ a device the per-id lookup knows nothing about is UNAVAILABLE, not zeroed', () => {
    const set = buildDeviceCoverageSet(devices, () => null);
    const c = set['MOCK-FGT-Edge-02'];
    assert.equal(c.available, false);
    assert.equal(c.grade, 'unknown');
    assert.equal(c.cell, '—');
  });

  it('tolerates a missing device list, a missing lookup and an id-less row', () => {
    assert.deepEqual(buildDeviceCoverageSet(null, null), {});
    assert.deepEqual(buildDeviceCoverageSet([{ deviceName: 'no id' }, null], null), {});
  });
});

// ── what actually renders ─────────────────────────────────────────────────
//
// ⛔ ASSERT THE OUTCOME, NOT THE MECHANISM. A grep for `coverageByDevice` in
// ComplianceMatrix.js would pass over a column that paints nothing — the MFA
// field shipped with `hidden=""` and fully visible past exactly that kind of
// check. These mount the component and read the words.

function installRenderHooks() {
  const swc = require('next/dist/build/swc');
  const origExt = Module._extensions['.js'];
  Module._extensions['.js'] = function (mod, filename) {
    if (filename.split(path.sep).join('/').includes('/node_modules/')) {
      return origExt(mod, filename);
    }
    const out = swc.transformSync(fs.readFileSync(filename, 'utf8'), {
      filename,
      jsc: {
        parser: { syntax: 'ecmascript', jsx: true },
        target: 'es2020',
        transform: { react: { runtime: 'automatic' } },
      },
      module: { type: 'commonjs' },
    });
    return mod._compile(out.code, filename);
  };
}

let React = null;
let renderToStaticMarkup = null;
let ComplianceMatrix = null;
let DeviceCoverageStrip = null;
let loadError = null;
try {
  installRenderHooks();
  React = require('react');
  ({ renderToStaticMarkup } = require('react-dom/server'));
  const mod = require('../components/compliance/ComplianceMatrix');
  ComplianceMatrix = mod.default;
  DeviceCoverageStrip = mod.DeviceCoverageStrip;
} catch (err) {
  // Reported as a failure rather than skipped: a suite that quietly stops
  // checking is the same shape of problem as the bugs it covers.
  loadError = err;
}

function matrixHtml(coverageByDevice) {
  assert.ok(ComplianceMatrix, 'could not load ComplianceMatrix: '
    + (loadError ? loadError.message : 'unknown'));
  const devices = FLEET.map((d) => ({
    deviceId: d.name,
    deviceName: d.name,
    vendor: d.vendor,
    lastRunAt: '2026-11-12T00:00:00.000Z',
    configCollectedAt: '2026-11-12T00:00:00.000Z',
    standards: {
      PCI_DSS: { pass: 1, fail: 1, warning: 0, na: 0, total: 2, scorePct: d.score },
      ISO_27001: { pass: 1, fail: 1, warning: 0, na: 0, total: 2, scorePct: d.score },
      CIS_V8: { pass: 1, fail: 1, warning: 0, na: 0, total: 2, scorePct: d.score },
      NIST: { pass: 1, fail: 1, warning: 0, na: 0, total: 2, scorePct: d.score },
      SANS: { pass: 1, fail: 1, warning: 0, na: 0, total: 2, scorePct: d.score },
    },
  }));
  return renderToStaticMarkup(
    React.createElement(ComplianceMatrix, { devices, coverageByDevice })
  );
}

const strip = () => Object.fromEntries(FLEET.map((d) => [d.name, cover(d)]));
const words = (html) => html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();

describe('⛔ the fleet matrix PRINTS the denominator beside the percentages', () => {
  it('every row shows its own gradeable count and grade', () => {
    const text = words(matrixHtml(strip()));
    assert.match(text, /Checks behind/, 'the column exists');
    for (const [cell, grade] of [
      ['9 of 10', 'Thin evidence'],
      ['11 of 13', 'Thin evidence'],
      ['21 of 24', 'Broad evidence'],
      ['25 of 28', 'Broad evidence'],
      ['0 of 13', 'No evidence'],
    ]) {
      assert.ok(text.includes(cell), `missing "${cell}"`);
      assert.ok(text.includes(grade), `missing "${grade}"`);
    }
  });

  it('⛔ the two 78%s and the 38% no longer render alike', () => {
    const text = words(matrixHtml(strip()));
    // The thin and broad grades both appear, which is the whole point: the
    // table used to carry no signal distinguishing them at all.
    assert.ok(text.includes('Thin evidence') && text.includes('Broad evidence'));
  });

  it('⛔ the header and the body are gated the same number of times', () => {
    // A <th> without its <td> shifts every cell after it one column left — a
    // table that is WRONG rather than narrow.
    const html = matrixHtml(strip());
    const ths = (html.match(/<th\b/g) || []).length;
    const firstRow = html.split('<tbody>')[1].split('</tr>')[0];
    const tds = (firstRow.match(/<td\b/g) || []).length;
    assert.equal(tds, ths, `${ths} header cells, ${tds} body cells in the first row`);
  });

  it('⛔ every column still has a width under the mandatory fixed layout', () => {
    const html = matrixHtml(strip());
    const cols = [...html.matchAll(/<col style="width:([^"]+)"/g)].map((m) => m[1]);
    const ths = (html.match(/<th\b/g) || []).length;
    assert.equal(cols.length, ths, 'a column with no <col> gets zero width and paints nothing');
    const total = cols.reduce((a, w) => a + parseFloat(w), 0);
    assert.ok(Math.abs(total - 100) < 0.5, `widths sum to ${total}%`);
  });

  it('⛔ A MISSING COVERAGE MAP IS NOT MEASURED, never a blank column', () => {
    // ⛔ ASSERTED ON WHAT EACH READER GETS, NOT ON THE MARKUP. The first draft
    // of this case looked for "Not measured" in the stripped text and FAILED on
    // correct code: NotMeasured carries that phrase in `title`/`aria-label`
    // only, so the cell was a lone em-dash on screen — visually identical to an
    // EMPTY CELL, which reads as "nothing to report". That is the column built
    // to announce a thin basis becoming the column that hides it, and the test
    // found it precisely because it asked what renders.
    for (const missing of [undefined, null, {}]) {
      const html = matrixHtml(missing);
      const text = words(html);
      const label = JSON.stringify(missing);
      assert.match(text, /Evidence not known/, `visible on screen: ${label}`);
      assert.match(html, /aria-label="Not measured: [^"]*could not be\s*read/,
        `announced to a screen reader: ${label}`);
      assert.ok(!/\b0 of 0\b/.test(text), 'and never a fabricated zero');
      assert.ok(!/\b0 of 45\b/.test(text), 'and never a fabricated denominator');
      // ⛔ And it is never mistaken for a measured grade.
      for (const grade of ['Thin evidence', 'Moderate evidence', 'Broad evidence']) {
        assert.ok(!text.includes(grade), `${label} must not read as ${grade}`);
      }
    }
  });

  it('⛔ the coverage column carries no severity hue — a gap in OUR evidence is hueless', () => {
    // ⛔ THE FIRST DRAFT OF THIS CASE COULD NOT FAIL. It counted occurrences of
    // `var(--unmeasured)` in a slice of the markup and required at least one per
    // row — but the count text and the NotMeasured chip carry that token too, so
    // repainting the pips `var(--green)` left the count untouched and the test
    // stayed GREEN through the mutation. Verified by running it. It now isolates
    // each coverage <td> and asserts the ABSENCE of every severity token, which
    // is the actual rule.
    const html = matrixHtml(strip());
    const rows = html.split('<tbody>')[1].split('</tr>').filter((r) => r.includes('<td'));
    assert.equal(rows.length, FLEET.length, 'one row per firewall');
    const SEVERITY = /var\(--(green|red|yellow|orange|blue|purple|teal|primary|sev-[a-z]+|tint-[a-z]+)\)/;
    for (const row of rows) {
      // The coverage cell is the FOURTH <td>: Device, Vendor, Last Run, then it.
      const cell = row.split('<td')[4];
      assert.ok(cell, 'the coverage cell is rendered');
      assert.doesNotMatch(cell, SEVERITY,
        'a severity hue here would rank OUR measurement gap on the customer’s severity ramp');
      assert.match(cell, /var\(--unmeasured\)/, 'the hueless vocabulary is used');
    }
  });

  it('⛔ the pip meter itself is hueless, and the filled count matches the grade', () => {
    // Asserted on the meter in isolation so a hue cannot hide behind the text
    // beside it.
    const SEVERITY = /var\(--(green|red|yellow|orange|blue|purple|teal|primary|sev-[a-z]+|tint-[a-z]+)\)/;
    const cases = [
      [byName('MOCK-CP-Perimeter-04'), 1],
      [byName('MOCK-PAN-DC-01'), 3],
      [byName('MOCK-UNREACHABLE-03'), 0],
      [cover(FLEET[0], { answeredChecks: null }), 0],
      // ⛔ A fortinet, not FLEET[0]: 15 answered checks on a forcepoint whose
      // ceiling is 10 is the impossible case, and it correctly grades `unknown`.
      [cover(FLEET.find((d) => d.vendor === 'fortinet'), { answeredChecks: 15 }), 2],
    ];
    for (const [coverage, filled] of cases) {
      const { coveragePips } = require('../components/compliance/ComplianceMatrix');
      const markup = renderToStaticMarkup(coveragePips(coverage));
      assert.doesNotMatch(markup, SEVERITY, `${coverage.grade} meter must be hueless`);
      const on = (markup.match(/var\(--unmeasured\)/g) || []).length;
      const off = (markup.match(/var\(--hatch\)/g) || []).length;
      assert.equal(on, filled, `${coverage.grade}: filled pips`);
      assert.equal(on + off, coverage.pipTotal, `${coverage.grade}: total pips`);
    }
  });

  it('⛔ a grade is WORDS, never colour alone', () => {
    // The pips are aria-hidden, so the phrase is the only thing a screen reader
    // or a monochrome print gets.
    const html = matrixHtml(strip());
    for (const phrase of ['Thin evidence', 'Broad evidence', 'No evidence']) {
      assert.ok(html.includes(phrase), phrase);
    }
    assert.match(html, /aria-hidden="true"[^>]*style="display:inline-flex/,
      'the meter is decorative and the words carry the grade');
  });
});

describe('⛔ the per-firewall strip PRINTS the basis above the donuts', () => {
  it('states the applicable count, the gradeable count and the caveat', () => {
    assert.ok(DeviceCoverageStrip, 'could not load DeviceCoverageStrip: '
      + (loadError ? loadError.message : 'unknown'));
    const text = words(renderToStaticMarkup(
      React.createElement(DeviceCoverageStrip, { coverage: byName('MOCK-CP-Perimeter-04') })
    ));
    assert.match(text, /Thin evidence/);
    assert.match(text, /10 of 45 SecVault checks can be asked of MOCK-CP-Perimeter-04/);
    assert.match(text, /rests on 9 checks/);
    assert.match(text, /not comparable/);
  });

  it('⛔ a firewall with nothing gradeable says so instead of showing a zero score', () => {
    const text = words(renderToStaticMarkup(
      React.createElement(DeviceCoverageStrip, { coverage: byName('MOCK-UNREACHABLE-03') })
    ));
    assert.match(text, /No evidence/);
    assert.match(text, /no percentage to read/);
    assert.ok(!/\b0%/.test(text));
  });

  it('⛔ it prints NO rival percentage', () => {
    // compliance_exceptions' rule: a second figure differing from the headline
    // by a measurement nobody asked for is the artefact to avoid. The strip
    // carries counts, a grade and the score it qualifies — nothing else.
    for (const d of FLEET) {
      const text = words(renderToStaticMarkup(
        React.createElement(DeviceCoverageStrip, { coverage: cover(d) })
      ));
      const pcts = [...text.matchAll(/(\d+)%/g)].map((m) => Number(m[1]));
      for (const p of pcts) {
        assert.equal(p, d.score, `${d.name} printed ${p}% beside a score of ${d.score}%`);
      }
    }
  });

  it('renders nothing at all rather than an empty box when there is no coverage', () => {
    for (const c of [null, undefined]) {
      assert.equal(
        renderToStaticMarkup(React.createElement(DeviceCoverageStrip, { coverage: c })),
        ''
      );
    }
  });
});
