'use strict';

// tests/seasonalBaseline.test.js
//
// Pins lib/engines/seasonalBaseline.js — A6's baseline and its NAMED threshold.
//
// ⛔ WHAT A TEST HERE IS FOR. The failure this engine can produce is not a
// crash, it is a confident wrong answer: a thin bucket reported as "normal", a
// missing hour counted as a zero, or a threshold that is really just the
// maximum ever seen. Every one of those looks like a measurement. So the cases
// below are weighted toward "we could not measure this", which is the state
// that regresses silently.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const sb = require('../lib/engines/seasonalBaseline');

function series(weeks, { start = Date.UTC(2026, 0, 5), value } = {}) {
  const rows = [];
  for (let h = 0; h < 24 * 7 * weeks; h += 1) {
    const at = new Date(start + h * 3600e3);
    rows.push({ at, value: value ? value(at, h) : 1000 + at.getUTCHours() * 10 });
  }
  return rows;
}

describe('⛔ the arming gate is OBSERVATIONS PER BUCKET, not weeks elapsed', () => {
  it('a quantile needs enough points for two to sit in its tail', () => {
    // analytics-proposal.md gates A6 on ">=3 weeks for a 168-bucket model".
    // Three weeks is ~3 observations per bucket, and three observations cannot
    // support a 0.95 threshold — the threshold would BE the maximum observed,
    // so every new high is an anomaly by definition.
    assert.equal(sb.minObservationsFor(0.95), 40);
    assert.equal(sb.minObservationsFor(0.99), 200);
    assert.equal(sb.minObservationsFor(0.9), 20);
  });

  it('an impossible quantile yields null rather than a number', () => {
    for (const q of [0, 1, -1, 2, 'x', null, undefined, NaN]) {
      assert.equal(sb.minObservationsFor(q), null, `q=${q}`);
    }
  });

  it('⛔ three weeks at hour-of-week does NOT arm', () => {
    // The specific claim the proposal got wrong, pinned.
    const b = sb.buildSeasonalBaseline(series(3), { grain: sb.GRAINS.HOUR_OF_WEEK, quantile: 0.95 });
    assert.equal(b.armed, false);
    assert.equal(b.usableBuckets, 0);
    assert.equal(b.reason, sb.STATES.INSUFFICIENT_BASELINE);
  });

  it('enough history DOES arm, and says what it needed', () => {
    const b = sb.buildSeasonalBaseline(series(45), { grain: sb.GRAINS.HOUR_OF_WEEK, quantile: 0.95 });
    assert.equal(b.armed, true);
    assert.equal(b.needPerBucket, 40);
    assert.ok(b.usableBuckets > 160, `only ${b.usableBuckets} usable buckets`);
  });
});

describe('⛔ a thin bucket is INSUFFICIENT, never NORMAL', () => {
  it('judging against a thin bucket reports insufficient_baseline', () => {
    // Reporting it as normal is the failed-read-as-a-fact rule in statistical
    // clothing: an unjudgeable hour rendered as a clean one.
    const b = sb.buildSeasonalBaseline(series(2), { grain: sb.GRAINS.HOUR_OF_WEEK, quantile: 0.95 });
    const j = sb.judge(999999, b, new Date(Date.UTC(2026, 0, 6, 10)));
    assert.equal(j.state, sb.STATES.INSUFFICIENT_BASELINE);
    assert.ok(j.needed > 0, 'it must say what it needed');
  });

  it('a bucket never observed at all is insufficient, not normal', () => {
    const rows = series(50).filter((r) => r.at.getUTCHours() !== 3);  // 03:00 never seen
    const b = sb.buildSeasonalBaseline(rows, { grain: sb.GRAINS.HOUR_OF_DAY, quantile: 0.95 });
    const j = sb.judge(5000, b, new Date(Date.UTC(2026, 0, 6, 3)));
    assert.equal(j.state, sb.STATES.INSUFFICIENT_BASELINE);
    assert.equal(j.observations, 0);
  });

  it('no baseline at all is its own state', () => {
    assert.equal(sb.judge(5, null, new Date()).state, sb.STATES.NO_BASELINE);
    const b = sb.buildSeasonalBaseline(series(50), { grain: sb.GRAINS.HOUR_OF_DAY });
    assert.equal(sb.judge(null, b, new Date()).state, sb.STATES.NO_BASELINE);
    assert.equal(sb.judge(5, b, 'not a date').state, sb.STATES.NO_BASELINE);
  });
});

describe('⛔ a missing hour is NOT a zero hour', () => {
  it('rows with no usable value are dropped, not counted as zero', () => {
    // Counting absences as zeros drags every threshold down and suppresses the
    // real spikes the detector exists to find.
    const rows = series(50);
    const withGaps = rows.map((r, i) => (i % 5 === 0 ? { at: r.at, value: null } : r));
    const clean = sb.buildSeasonalBaseline(rows, { grain: sb.GRAINS.HOUR_OF_DAY, quantile: 0.9 });
    const gappy = sb.buildSeasonalBaseline(withGaps, { grain: sb.GRAINS.HOUR_OF_DAY, quantile: 0.9 });
    assert.ok(gappy.totalObservations < clean.totalObservations, 'the gaps must reduce the count');
    for (const [bucket, stats] of gappy.buckets) {
      const ref = clean.buckets.get(bucket);
      assert.ok(stats.median >= ref.median * 0.9,
        `bucket ${bucket}: median fell from ${ref.median} to ${stats.median} — gaps were counted as zeros`);
    }
  });

  it('a genuine zero IS a measurement and counts', () => {
    const rows = series(50).map((r, i) => ({ at: r.at, value: i % 7 === 0 ? 0 : r.value }));
    const b = sb.buildSeasonalBaseline(rows, { grain: sb.GRAINS.HOUR_OF_DAY, quantile: 0.9 });
    assert.ok(b.totalObservations === rows.length, 'zeros must not be dropped');
  });
});

describe('⛔ the grain is CHOSEN from the data and upgrades itself', () => {
  it('a short history picks a coarse grain; a long one picks the fine grain', () => {
    // Hardcoding hour-of-week would leave the feature reporting
    // insufficient_baseline for months while a usable coarser model sat
    // available; hardcoding hour-of-day would cap it there for ever.
    assert.equal(sb.selectGrain(series(4), { quantile: 0.9 }).grain, sb.GRAINS.HOUR_OF_DAY);
    assert.equal(sb.selectGrain(series(45), { quantile: 0.95 }).grain, sb.GRAINS.HOUR_OF_WEEK);
  });

  it('⛔ when NO grain qualifies it returns null, never the coarsest as a fallback', () => {
    // "We cannot yet say what normal looks like" is a real answer. Falling back
    // would arm a detector on a baseline that cannot support its threshold.
    const r = sb.selectGrain(series(1), { quantile: 0.99 });
    assert.equal(r.grain, null);
    assert.equal(r.baseline, null);
    assert.ok(r.tried.length === 3, 'it must report what it tried');
  });

  it('a grain qualifies only when MOST buckets are usable, not one', () => {
    // A model that can judge 3 of 168 buckets is armed for 2% of the week and
    // silent for the other 98% — and silence reads as "nothing wrong".
    const rows = series(45).filter((r) => r.at.getUTCDay() === 1);   // Mondays only
    const r = sb.selectGrain(rows, { quantile: 0.9 });
    assert.notEqual(r.grain, sb.GRAINS.HOUR_OF_WEEK,
      'Mondays-only data must not qualify the full hour-of-week model');
  });
});

describe('⛔ persistence is what makes the alert rate survivable', () => {
  it('an isolated outlier is dropped; a sustained run is kept', () => {
    // 16 devices x 168 hours = 2,688 device-hours/week, so a 5% per-bucket rate
    // is ~142 false alerts a week. That is how `new_finding` got pulled from
    // the Alerts feed in July.
    const A = { state: sb.STATES.ANOMALOUS, value: 10 };
    const N = { state: sb.STATES.NORMAL, value: 1 };
    assert.equal(sb.sustainedRuns([N, A, N, A, N], 2).length, 0, 'isolated outliers must not alert');
    assert.equal(sb.sustainedRuns([N, A, A, N], 2).length, 1, 'a 2-hour run must alert');
    assert.equal(sb.sustainedRuns([N, A, A, A, N], 3).length, 1);
    assert.equal(sb.sustainedRuns([N, A, A, N], 3).length, 0);
  });

  it('a run that reaches the end of the window still counts', () => {
    // An anomaly still in progress is the one most worth reporting.
    const A = { state: sb.STATES.ANOMALOUS, value: 10 };
    assert.equal(sb.sustainedRuns([A, A, A], 2).length, 1);
  });

  it('the run reports its PEAK, so the alert can state a number', () => {
    const runs = sb.sustainedRuns([
      { state: sb.STATES.ANOMALOUS, value: 10 },
      { state: sb.STATES.ANOMALOUS, value: 99 },
      { state: sb.STATES.ANOMALOUS, value: 20 },
    ], 2);
    assert.equal(runs[0].peak.value, 99);
  });

  it('insufficient_baseline buckets do not count toward a run', () => {
    // Otherwise an unjudgeable stretch would manufacture an alert.
    const A = { state: sb.STATES.ANOMALOUS, value: 10 };
    const U = { state: sb.STATES.INSUFFICIENT_BASELINE, value: 10 };
    assert.equal(sb.sustainedRuns([A, U, A], 2).length, 0);
  });
});

describe('⛔ the output is a NAMED THRESHOLD, never an anomaly score', () => {
  it('a judgement carries the threshold and the observation count', () => {
    // roadmap.md's rule. An alert must be able to say "47,000 denied; this
    // device's 95th percentile for this hour is 12,000 over 45 weeks" rather
    // than "anomaly score 3.7", which nobody can act on or argue with.
    const b = sb.buildSeasonalBaseline(series(50), { grain: sb.GRAINS.HOUR_OF_DAY, quantile: 0.95 });
    const j = sb.judge(10_000_000, b, new Date(Date.UTC(2026, 0, 6, 10)));
    assert.equal(j.state, sb.STATES.ANOMALOUS);
    assert.equal(typeof j.threshold, 'number');
    assert.equal(typeof j.median, 'number');
    assert.ok(j.observations > 0);
    assert.ok(!('score' in j), 'there must be no composite score');
  });

  it('a value at or below the threshold is normal', () => {
    const b = sb.buildSeasonalBaseline(series(50), { grain: sb.GRAINS.HOUR_OF_DAY, quantile: 0.95 });
    const at = new Date(Date.UTC(2026, 0, 6, 10));
    const t = sb.judge(1, b, at).threshold;
    assert.equal(sb.judge(t, b, at).state, sb.STATES.NORMAL, 'at the threshold is not above it');
  });
});

describe('bucketing is UTC and total', () => {
  it('hour-of-week spans 0..167 and hour-of-day 0..23', () => {
    // UTC deliberately: a locally-keyed baseline silently re-buckets every
    // observation on a DST change, which looks exactly like a traffic shift.
    assert.equal(sb.bucketOf(new Date(Date.UTC(2026, 0, 4, 0)), sb.GRAINS.HOUR_OF_WEEK), 0);   // Sunday 00
    assert.equal(sb.bucketOf(new Date(Date.UTC(2026, 0, 10, 23)), sb.GRAINS.HOUR_OF_WEEK), 167);
    assert.equal(sb.bucketOf(new Date(Date.UTC(2026, 0, 7, 9)), sb.GRAINS.HOUR_OF_DAY), 9);
  });

  it('weekday/weekend split puts weekends in the upper half', () => {
    assert.ok(sb.bucketOf(new Date(Date.UTC(2026, 0, 7, 9)), sb.GRAINS.HOUR_OF_DAY_SPLIT) < 24);
    assert.ok(sb.bucketOf(new Date(Date.UTC(2026, 0, 10, 9)), sb.GRAINS.HOUR_OF_DAY_SPLIT) >= 24);
  });

  it('junk input yields null, never bucket 0', () => {
    for (const bad of [null, undefined, 'nope', {}, NaN]) {
      assert.equal(sb.bucketOf(bad, sb.GRAINS.HOUR_OF_DAY), null, String(bad));
    }
    assert.equal(sb.bucketOf(new Date(), 'no_such_grain'), null);
  });
});
