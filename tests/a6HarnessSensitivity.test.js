// tests/a6HarnessSensitivity.test.js
//
// ⛔ WHY THIS EXISTS — A SENSITIVITY FIGURE NOW DECIDES A REGISTRATION, SO THE
// ARITHMETIC BEHIND IT HAS TO BE PINNED.
//
// `assertRegisteredDetector` will not let a detector register without a
// measured alert rate AND a measured sensitivity, and `scripts/a6Harness.js` is
// what produces both. Until 2026-11-24 it reported sensitivity as a bare
// percentage over whatever plants happened to fall in the judged window —
// typically 28 — and that number was then read against a >=90% viability bar.
//
// ⛔ THE BAR WAS NOT MEASURABLE AT THAT SAMPLE SIZE, WHICH IS THE FINDING THIS
// FILE EXISTS TO KEEP TRUE. At n=28 even a PERFECT 28/28 has a 95% Wilson lower
// bound of 87.9% — below 90 — so no result at that sample could ever have
// demonstrated the bar was met, in either direction. Measured consequence: the
// shipped `denied_spike` configuration read **89% at n=28 and 94% at n=375**,
// and only the second supports a decision. The first nearly cost a threshold
// change made on one event's worth of evidence.
//
// ⛔ WILSON, NOT THE TEXTBOOK NORMAL APPROXIMATION. At small n with p near 1 the
// normal interval runs past 100% (25/28 gives an upper limit of 1.006, which is
// not a probability) and understates the lower bound — the half that the
// viability bar is read against.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { wilson, sensText, plantAnomalies, rng } = require('../scripts/a6Harness.js');

const pct = (x) => Math.round(x * 1000) / 10;

describe('⛔ the sensitivity interval', () => {
  it('matches hand-computed Wilson bounds for the measured case', () => {
    // 25/28 is the figure the old 28-plant sample produced for the shipped
    // configuration. Hand-computed: centre 0.96146, half-width 0.13353,
    // divisor 1.13720 -> [0.7280, 0.9629].
    const [lo, hi] = wilson(25, 28);
    assert.ok(Math.abs(lo - 0.7280) < 0.001, `lower bound ${lo}`);
    assert.ok(Math.abs(hi - 0.9629) < 0.001, `upper bound ${hi}`);
  });

  it('⛔ a PERFECT score at n=28 still cannot clear a 90% bar', () => {
    // The whole reason the planted sample had to grow. If this ever stops being
    // true the bar and the sample have been changed and the reasoning recorded
    // in EVIDENCE.denied_spike needs revisiting.
    const [lo] = wilson(28, 28);
    assert.ok(lo < 0.90,
      `28/28 gives a lower bound of ${pct(lo)}%, which would clear the bar — the `
      + 'sample-size argument in EVIDENCE.denied_spike no longer holds');
  });

  it('a large sample CAN clear it', () => {
    const [lo] = wilson(353, 375); // the measured 2026-11-24 result
    assert.ok(lo >= 0.90,
      `353/375 should prove >=90%; lower bound was ${pct(lo)}%`);
  });

  it('⛔ never reports a probability outside [0, 1]', () => {
    // The normal approximation does, which is why it is not used here.
    for (const [k, n] of [[28, 28], [0, 28], [1, 1], [0, 1], [375, 375], [0, 375]]) {
      const [lo, hi] = wilson(k, n);
      assert.ok(lo >= 0 && lo <= 1, `lower ${lo} out of range for ${k}/${n}`);
      assert.ok(hi >= 0 && hi <= 1, `upper ${hi} out of range for ${k}/${n}`);
      assert.ok(lo <= hi, `inverted interval for ${k}/${n}`);
    }
  });

  it('the interval narrows as the sample grows at a fixed rate', () => {
    const width = (k, n) => { const [lo, hi] = wilson(k, n); return hi - lo; };
    assert.ok(width(90, 100) < width(9, 10));
    assert.ok(width(900, 1000) < width(90, 100));
  });

  it('⛔ an empty sample is null, never a confident 0% or 100%', () => {
    assert.equal(wilson(0, 0), null);
    assert.equal(wilson(1, 0), null);
    assert.equal(wilson(NaN, 10), null);
    assert.equal(sensText(0, 0), 'n/a');
  });

  it('⛔ more hits than plants is refused, not clamped into a proportion', () => {
    // Impossible input: it means the scoring and the planting disagree about
    // the sample, and inventing a 100% from it would hide that.
    assert.equal(wilson(30, 28), null);
    assert.equal(wilson(-1, 28), null);
  });

  it('⛔ the printed string always carries the sample AND the interval', () => {
    const t = sensText(353, 375);
    assert.match(t, /94%/, 'point estimate');
    assert.match(t, /353\/375/, 'the sample must travel with the percentage');
    assert.match(t, /CI 91-96%/, 'the interval is the part a bar is read against');
  });
});

describe('⛔ plants can be confined to the judged region', () => {
  // Scattering plants over the whole series puts ~70% of them in the TRAINING
  // portion, where they raise the very quantile threshold the judged plants are
  // measured against. Growing the sample that way degrades the baseline at the
  // same time, so sensitivity moves for a reason unrelated to the detector.
  const series = () => Array.from({ length: 1000 }, (_, i) => ({
    at: new Date(Date.UTC(2026, 9, 1, i)), value: 100,
  }));

  it('every plant lands at or after minIndex', () => {
    const rows = series();
    const planted = plantAnomalies(rows, rng(1), 40, 3, 6, 700);
    assert.ok(planted.length > 0, 'nothing planted');
    for (const w of planted) {
      assert.ok(w.start >= 700,
        `plant at ${w.start} fell before minIndex — it would contaminate the baseline`);
    }
  });

  it('the default is unchanged (plants may land anywhere)', () => {
    const planted = plantAnomalies(series(), rng(2), 60, 3, 6);
    assert.ok(planted.some((w) => w.start < 300),
      'omitting minIndex must keep the original whole-series behaviour');
  });

  it('⛔ an out-of-range minIndex plants NOTHING, never a stack on the last index', () => {
    // Found by mutation testing: clamping `from` to `usable - 1` puts every
    // plant on one index, and the harness then prints a confident sensitivity
    // over a denominator of events that are all the same event.
    const planted = plantAnomalies(series(), rng(3), 25, 3, 6, 10_000);
    assert.deepEqual(planted, [],
      'a region that does not exist must yield no sample, so the interval '
      + 'reports n/a rather than a percentage over stacked plants');
  });

  it('⛔ a negative minIndex is floored at the start, not used as an index', () => {
    // ⛔ DETERMINISTIC rand, NOT a seed. The first version of this used rng(7)
    // and 10 plants, and a mutation that removed the floor SURVIVED: with
    // `from = -50` a plant only lands out of range when a draw falls in the
    // lowest ~5% of the span, and that seed never produced one. A test whose
    // verdict depends on which numbers a PRNG happens to emit is not pinning
    // the property. `() => 0` lands on the lowest possible index by
    // construction, which is exactly the case the floor exists for — unfloored
    // it indexes rows[-50] and throws.
    const planted = plantAnomalies(series(), () => 0, 3, 3, 6, -50);
    assert.equal(planted.length, 3);
    for (const w of planted) {
      assert.equal(w.start, 0, 'the lowest draw must floor to index 0');
    }
  });

  it('the requested count is planted when there is room', () => {
    const planted = plantAnomalies(series(), rng(4), 25, 3, 6, 400);
    assert.equal(planted.length, 25,
      'the scored sample size is the planted count — if this drifts, every '
      + 'interval above is computed over a denominator nobody chose');
  });
});
