'use strict';
// tests/complianceScoreFormula.test.js
//
// ⛔ THE FLEET PDF PRINTED TWO DIFFERENT PERCENTAGES FOR THE SAME STANDARD ON
// THE SAME PAGE. `Math.round((100 * pass) / measurable)` and
// `Math.round((pass / measurable) * 100)` are not the same function: at an
// exact .5 boundary the float lands either side of it. 23 pass of 40 is 57.5
// one way and 57.49999999999999 the other — 58 vs 57.
//
// lib/engines/complianceReport.js used the first form; dashboardSnapshot.js and
// both compliance pages used the second. So the summary table said "PCI DSS
// 57%" while the basis line directly beneath it said "the 58% rests on 40
// checks", and the device-scoped PDF sat one point away from that firewall's
// own compliance page.
//
// ⛔ THE EXISTING TEST COULD NOT SEE IT, and that is the lesson worth keeping:
// tests/complianceDeviceScope.test.js asserts "summaryFromPerDevice reproduces
// the fleet formula" against HAND-WRITTEN numbers. Hand-written numbers agree
// with whatever the author computed; they cannot catch a divergence between two
// implementations. This file compares the two implementations DIRECTLY.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { summaryFromPerDevice, STANDARD_KEYS } = require('../lib/engines/complianceReport');

// The form used by dashboardSnapshot.js and by both compliance pages — the
// canonical one, because it is what an operator reads on screen.
const canonical = (pass, measurable) => (measurable > 0 ? Math.round((pass / measurable) * 100) : null);

function deviceWith(counts) {
  const standards = {};
  for (const k of STANDARD_KEYS) standards[k] = { pass: 0, fail: 0, warning: 0, na: 0 };
  standards.PCI_DSS = counts;
  return { standards };
}

describe('⛔ every copy of the score formula agrees, exactly', () => {
  it('matches the canonical form across every small pass/fail split', () => {
    // Exhaustive rather than sampled: the disagreements are sparse and land on
    // specific ratios, so a handful of round numbers would miss them all.
    const mismatches = [];
    for (let measurable = 1; measurable <= 300; measurable += 1) {
      for (let pass = 0; pass <= measurable; pass += 1) {
        const got = summaryFromPerDevice([
          deviceWith({ pass, fail: measurable - pass, warning: 0, na: 0 }),
        ]).byStandard.PCI_DSS;
        const want = canonical(pass, measurable);
        if (got !== want) mismatches.push(`${pass}/${measurable}: got ${got}, canonical ${want}`);
      }
    }
    assert.deepEqual(mismatches.slice(0, 5), [],
      `${mismatches.length} ratio(s) disagree with the form the pages use`);
  });

  it('⛔ the known 23-of-40 boundary lands on the same integer', () => {
    // Named explicitly so the regression has a face: this is the smallest
    // realistic split that diverged.
    //
    // ⛔ THE ANSWER IS 57, AND THAT IS A DELIBERATE CHOICE RATHER THAN THE
    // "right" one. 23/40 is exactly 0.575, so 58 is arguably the better
    // rounding — but `(23/40)*100` is 57.49999999999999 in binary floating
    // point, and that is what dashboardSnapshot.js and both compliance pages
    // have always shown. Making the PDF agree with the screen matters more
    // than which side of .5 the float lands on; changing the screens instead
    // would move every displayed score in the product to settle a rounding
    // argument nobody has raised.
    const got = summaryFromPerDevice([
      deviceWith({ pass: 23, fail: 17, warning: 0, na: 0 }),
    ]).byStandard.PCI_DSS;
    assert.equal(got, canonical(23, 40));
    assert.equal(got, 57, 'the value the compliance pages show for this split');
  });

  it('and `overall` uses the same form as the per-standard figures', () => {
    // `overall` sums the per-standard counts, so with one standard populated it
    // must equal that standard exactly.
    const s = summaryFromPerDevice([deviceWith({ pass: 23, fail: 17, warning: 0, na: 0 })]);
    assert.equal(s.overall, s.byStandard.PCI_DSS);
  });
});

describe('⛔ nothing measurable is null, never 0', () => {
  it('an all-na standard scores null', () => {
    const s = summaryFromPerDevice([deviceWith({ pass: 0, fail: 0, warning: 0, na: 7 })]);
    assert.equal(s.byStandard.PCI_DSS, null, 'na is excluded from the denominator');
    assert.equal(s.overall, null, '0% would report a coverage gap as total failure');
  });

  it('an empty fleet scores null rather than 0%', () => {
    const s = summaryFromPerDevice([]);
    assert.equal(s.overall, null);
    for (const k of STANDARD_KEYS) assert.equal(s.byStandard[k], null, k);
  });

  it('⛔ `na` never enters the denominator', () => {
    // 3 pass, 1 fail, 6 na must be 75% — not 30%. Scoring a device down for
    // questions SecVault could not ask is the failed-read-as-a-fact rule.
    const s = summaryFromPerDevice([deviceWith({ pass: 3, fail: 1, warning: 0, na: 6 })]);
    assert.equal(s.byStandard.PCI_DSS, 75);
  });

  it('warning DOES enter the denominator', () => {
    // A warning is a fact about the device, not about SecVault.
    const s = summaryFromPerDevice([deviceWith({ pass: 3, fail: 0, warning: 1, na: 0 })]);
    assert.equal(s.byStandard.PCI_DSS, 75);
  });
});
