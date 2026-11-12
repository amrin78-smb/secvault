'use strict';

// tests/capacityForecast.test.js — Tier 2, capacity planning / bandwidth trend.
//
// ⛔ THE MEASUREMENTS THAT SHAPED THIS ENGINE, so the tests defend them.
// Live fleet, 2026-11-12, read-only, 16 active firewalls, 66 day buckets:
//
//   10 forecastable (all paloalto). Median GB/day 1630.01 (SMT) down to 0.0024
//      (HRIS) — a factor of ~680,000, which is why there is no fleet figure.
//    5 bytes_not_summable (all fortinet): TSR_EKC, TSR_EKM, TSR-TL, OKF(F2),
//      Vietnam-YCC. 66 day buckets each, ZERO byte-bearing hours. PERMANENT.
//    1 no_log_coverage: PAKFood. No rollup rows at all. A GAP THAT CAN CLEAR.
//
//   Verdicts the shipped engine produced on those rows:
//      8 no_detectable_trend, 2 rising (TUFF(TUTH3), HRIS), 0 insufficient.
//
//   MK's calibration was MEASURED, not assumed — each device's own values
//   shuffled, 40 reps, trend destroyed and distribution kept:
//      10d 4.3%   13d 4.6%   20d 4.1%   30d 6.1%   45d 6.0%   (nominal 5%)
//
// So, as with A7, these tests care far more about what this engine REFUSES to
// conclude than about what it concludes.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const E = require('../lib/engines/capacityForecast');
const { minObservationsFor } = require('../lib/engines/seasonalBaseline');
const { getCapacityForecasts, getDeviceCapacityForecast } = require('../lib/engines/capacityForecastData');

const DAY = 24 * 3600 * 1000;
const T0 = Date.UTC(2026, 8, 1);

// ── fixtures ───────────────────────────────────────────────────────────────

/** `n` complete days starting at T0, value from `fn(i)`. */
function days(n, fn, byteHours = 24) {
  const out = [];
  for (let i = 0; i < n; i += 1) {
    out.push({ day: new Date(T0 + i * DAY), byteHours, bytes: fn(i) });
  }
  return out;
}

/** A hard, unambiguous ramp — the only shape that must produce a projection. */
const ramp = (n = 40, base = 1000, step = 100) => days(n, (i) => base + i * step);

/** Pure alternating noise around a level: no trend to find, by construction. */
const noisy = (n = 40, base = 1000) => days(n, (i) => base + ((i % 2) ? 900 : -900));

// ⛔ TFM-RN's REAL 62 DAY BUCKETS, read off the production fleet 2026-11-12.
// `[dayOffsetFromFirstBucket, byteBearingHours, megabytes]`. Four of the 62 are
// short: day 0 (9h — the collector's first afternoon), day 47 (17h), day 48
// (3h, 13,285 MB against a ~180,000 MB typical day — a 13x understatement) and
// day 61 (18h — the LAST bucket, 2026-11-08 17:00, after which this firewall
// stopped being heard from).
//
// It is embedded because two synthetic fixtures were tried first and BOTH were
// degenerate: a clean ramp puts every pairwise slope on one value, and a
// perfectly alternating series makes the slope distribution symmetric about
// zero. Neither can move a median, so neither could show what the completeness
// rule is worth — and the first version of this test passed while proving
// nothing. Real heavy-tailed data can, and does.
const TFM_RN = [[0,9,35224],[1,24,208990],[2,24,186116],[3,24,181956],[4,24,126742],[5,24,91671],[6,24,135967],[7,24,192833],[8,24,180935],[9,24,216669],[10,24,257182],[11,24,272276],[12,24,103354],[13,24,169830],[14,24,244952],[15,24,174784],[16,24,302001],[17,24,164694],[18,24,123225],[19,24,91102],[20,24,178025],[21,24,191127],[22,24,206768],[23,24,182772],[24,24,201506],[25,24,182471],[26,24,93820],[27,24,216649],[28,24,327332],[29,24,183529],[30,24,213486],[31,24,219676],[32,24,150277],[33,24,85644],[34,24,84112],[35,24,97361],[36,24,278463],[37,24,182232],[38,24,198785],[39,24,216612],[40,24,162117],[41,24,248787],[42,24,221221],[43,24,257058],[44,24,190463],[45,24,243515],[46,24,150171],[47,17,77225],[48,3,13285],[49,24,167264],[50,24,217959],[51,24,238044],[52,24,178668],[53,24,146507],[54,24,80949],[55,24,172510],[56,24,201019],[57,24,201369],[58,24,181696],[59,24,170527],[60,24,165850],[61,18,137567]];

const device = { deviceId: 'dev-1', deviceName: 'FW-1', vendor: 'paloalto' };
const ok = (series, opts = {}) => E.forecastDevice(
  device, series, { hasLogCoverage: true, ...opts },
);

// ── the claim ──────────────────────────────────────────────────────────────

const SRC_ENGINE = fs.readFileSync(
  path.join(__dirname, '..', 'lib', 'engines', 'capacityForecast.js'), 'utf8',
);
const SRC_DATA = fs.readFileSync(
  path.join(__dirname, '..', 'lib', 'engines', 'capacityForecastData.js'), 'utf8',
);

// ⛔ COMMENTS STRIPPED BEFORE ANY SOURCE SCAN. The prose in both files
// deliberately discusses the words these scans ban (a forbidden table name, the
// overclaiming vocabulary), so a scan that read comments would report a false
// hit on the documentation that exists to prevent the defect. The strip can
// only ever REDUCE coverage; it cannot invent a failure.
const BLOCK_COMMENT = new RegExp('/\\*[\\s\\S]*?\\*/', 'g');
const LINE_COMMENT = new RegExp('(^|[\\s{(;,])//[^\\n]*', 'g');
const stripComments = (src) => String(src)
  .replace(BLOCK_COMMENT, ' ')
  .replace(LINE_COMMENT, '$1 ');

const CODE_ENGINE = stripComments(SRC_ENGINE);
const CODE_DATA = stripComments(SRC_DATA);

/** Every string literal the engine can emit. */
function engineStrings() {
  const out = [];
  // Template and plain literals in the stripped code.
  for (const m of CODE_ENGINE.matchAll(/'((?:[^'\\]|\\.)*)'/g)) out.push(m[1]);
  for (const m of CODE_ENGINE.matchAll(/`((?:[^`\\]|\\.)*)`/g)) out.push(m[1]);
  return out;
}

// ⛔ A PROJECTION IS A CLAIM AND MAY NOT BE DRESSED AS A CERTAINTY. The pattern
// IMPACT_CLAIM and COVERAGE_CLAIM already establish. `will` is the dangerous
// one: "you will need 8 TB" is a promise, "on this trend, 8 TB by 11 December"
// is a measurement extended to a date.
const OVERCLAIM = [/\bwill\b/i, /\bguaranteed?\b/i, /\bexactly\b/i];

describe('FORECAST_CLAIM', () => {
  it('⛔ exists, is one sentence block, and names the limits', () => {
    assert.equal(typeof E.FORECAST_CLAIM, 'string');
    assert.ok(E.FORECAST_CLAIM.length > 120);
    assert.match(E.FORECAST_CLAIM, /if nothing changes/i);
    assert.match(E.FORECAST_CLAIM, /no projection at all/i);
    assert.match(E.FORECAST_CLAIM, /cannot see/i);
  });

  it('⛔ does not overclaim', () => {
    for (const re of OVERCLAIM) {
      assert.doesNotMatch(E.FORECAST_CLAIM, re, `FORECAST_CLAIM must not say ${re}`);
    }
  });

  it('⛔ NOR DOES ANY OTHER STRING THE ENGINE CAN EMIT — the claim being clean '
    + 'is worth nothing if the sentence beside it promises something', () => {
    for (const s of engineStrings()) {
      for (const re of OVERCLAIM) {
        assert.doesNotMatch(s, re, `engine string overclaims (${re}): ${s}`);
      }
    }
  });

  it('⛔ the scan can actually see the strings it is checking', () => {
    // A guard that matches nothing passes silently. Pin that the harvester
    // found the claim itself and a good number of other strings.
    const all = engineStrings();
    assert.ok(all.length > 20, `expected many strings, found ${all.length}`);
    assert.ok(
      all.some((s) => s.includes('no projection at all')),
      'the harvester did not find FORECAST_CLAIM, so the scan proves nothing',
    );
  });

  it('⛔ travels on every summary', () => {
    assert.equal(E.summariseForecasts([]).claim, E.FORECAST_CLAIM);
  });
});

// ── the arming gate ────────────────────────────────────────────────────────

describe('the minimum-history gate is DERIVED, not picked', () => {
  it('⛔ is computed, and equals 13 on the shipped constants', () => {
    assert.equal(E.MIN_HISTORY_DAYS, 13);
    assert.equal(E.minHistoryDays(), 13);
  });

  it('⛔ is tied to minObservationsFor, not to elapsed weeks', () => {
    const needed = minObservationsFor(E.SLOPE_BAND_QUANTILE);
    assert.equal(needed, 20);
    // The arithmetic the derivation claims: at MIN_HISTORY_DAYS the lower
    // order statistic has `needed` slopes beneath it, and one day fewer does
    // not. This is the property, not the number.
    const m1 = (n) => {
      const N = (n * (n - 1)) / 2;
      const varS = (n * (n - 1) * (2 * n + 5)) / 18;
      return Math.floor((N - E.Z_CRITICAL * Math.sqrt(varS)) / 2);
    };
    assert.ok(m1(E.MIN_HISTORY_DAYS) >= needed, 'gate must satisfy the requirement');
    assert.ok(m1(E.MIN_HISTORY_DAYS - 1) < needed, 'gate must be the SMALLEST n that does');
  });

  it('⛔ COUNTS DAYS, NOT PAIRS — 20 pairwise slopes are reached at 7 days, and '
    + 'pairwise slopes are not independent observations', () => {
    const pairsAt = (n) => (n * (n - 1)) / 2;
    assert.ok(pairsAt(7) >= minObservationsFor(E.SLOPE_BAND_QUANTILE));
    assert.ok(E.MIN_HISTORY_DAYS > 7, 'a pair-counting gate would have armed at 7 days');
  });

  it('a nonsense quantile yields null rather than a silent default', () => {
    assert.equal(E.minHistoryDays(1), null);
    assert.equal(E.minHistoryDays(0), null);
    assert.equal(E.minHistoryDays('nope'), null);
  });

  it('⛔ BELOW THE GATE: insufficient_history, with what it needed BESIDE what '
    + 'it has — never a zero, never a flat trend', () => {
    const r = ok(ramp(E.MIN_HISTORY_DAYS - 1));
    assert.equal(r.state, E.STATES.INSUFFICIENT_HISTORY);
    assert.equal(r.completeDays, E.MIN_HISTORY_DAYS - 1);
    assert.equal(r.neededDays, E.MIN_HISTORY_DAYS);
    assert.match(r.reason, new RegExp(String(E.MIN_HISTORY_DAYS)));
    assert.match(r.reason, /has not been measured/i);
    // ⛔ NOT a zero and NOT a projection.
    assert.equal(r.projected, false);
    assert.equal(r.projectedDailyBytes, null);
    assert.equal(r.slopeBytesPerDay, null);
    assert.equal(r.growthPctOverWindow, null);
  });

  it('at the gate exactly, a hard ramp DOES produce a trend', () => {
    const r = ok(ramp(E.MIN_HISTORY_DAYS));
    assert.equal(r.state, E.STATES.RISING);
    assert.equal(r.projected, true);
  });
});

// ── the two "cannot forecast" reasons ──────────────────────────────────────

describe('⛔ the two reasons a firewall cannot be forecast are NEVER collapsed', () => {
  it('no rollup rows at all => no_log_coverage, clearable, with a collection '
    + 'first step', () => {
    const r = E.forecastDevice(device, [], { hasLogCoverage: false });
    assert.equal(r.state, E.STATES.NO_LOG_COVERAGE);
    assert.equal(r.permanent, false);
    assert.match(r.reason, /forwarding syslog/i);
    assert.match(r.reason, /collection gap/i);
  });

  it('logging but no summable bytes => bytes_not_summable, PERMANENT, and says '
    + 'nothing on the firewall can change it', () => {
    const r = ok(days(40, () => null, 0));
    assert.equal(r.state, E.STATES.BYTES_NOT_SUMMABLE);
    assert.equal(r.permanent, true);
    assert.match(r.reason, /Nothing on the firewall can change this/i);
    assert.match(r.reason, /running total/i);
  });

  it('⛔ the two reasons have DIFFERENT wording and DIFFERENT permanence — a '
    + 'shared sentence would send an operator to the wrong place', () => {
    assert.notEqual(E.NOT_SUMMABLE_REASON, E.NO_COVERAGE_REASON);
    assert.doesNotMatch(E.NO_COVERAGE_REASON, /FortiOS/);
    assert.doesNotMatch(E.NOT_SUMMABLE_REASON, /collection gap/i);
  });

  it('⛔ ORDER: a firewall with NO logs is reported as a coverage gap even '
    + 'though it also has no summable bytes — blaming the vendor would send '
    + 'the operator to a problem they cannot fix', () => {
    const r = E.forecastDevice(device, days(40, () => null, 0), { hasLogCoverage: false });
    assert.equal(r.state, E.STATES.NO_LOG_COVERAGE);
  });

  it('⛔ "THE VENDOR CANNOT SUPPLY SUMMABLE BYTES" IS A CLAIM ABOUT ALL TIME '
    + 'AND MAY NOT BE DECIDED INSIDE THE LOOKBACK WINDOW. Found by executing '
    + 'the data layer against a real schema rather than a stub: with a 30-day '
    + 'lookback, a firewall whose byte history was OLDER than the window came '
    + 'back `bytes_not_summable` — a PERMANENT vendor limitation asserted '
    + 'about a firewall that reports byte counts perfectly well', () => {
    // No byte-bearing day INSIDE the window, but the unbounded probe says this
    // firewall has produced summable bytes at some point.
    const r = ok(days(40, () => null, 0), { hasSummableBytes: true });
    assert.equal(
      r.state, E.STATES.INSUFFICIENT_HISTORY,
      'history exists, none usable in this window — that is not a vendor limit',
    );
    assert.equal(r.permanent, false);
    assert.doesNotMatch(r.reason, /FortiOS/);
  });

  it('⛔ AND THE ALL-TIME PROBE WINS OVER THE WINDOW IN BOTH DIRECTIONS: a '
    + 'firewall the probe says has never produced a summable byte count is '
    + '`bytes_not_summable` even where the window happens to hold some', () => {
    const r = ok(ramp(40), { hasSummableBytes: false });
    assert.equal(r.state, E.STATES.BYTES_NOT_SUMMABLE);
    assert.equal(r.permanent, true);
  });

  it('⛔ WITH NO PROBE SUPPLIED it falls back to the window — a caller that did '
    + 'not ask cannot be assumed to have found nothing', () => {
    assert.equal(ok(days(40, () => null, 0)).state, E.STATES.BYTES_NOT_SUMMABLE);
    assert.equal(ok(ramp(40)).state, E.STATES.RISING);
  });

  it('⛔ an UNKNOWN coverage flag falls to the gap, never to a trend', () => {
    // hasLogCoverage omitted entirely.
    const r = E.forecastDevice(device, ramp(40), {});
    assert.equal(r.state, E.STATES.NO_LOG_COVERAGE);
    assert.equal(r.projected, false);
  });

  it('⛔ the summary counts and NAMES them separately, and publishes no '
    + 'combined "unavailable" total', () => {
    const list = [
      E.forecastDevice({ deviceName: 'FortiA' }, days(30, () => null, 0), { hasLogCoverage: true }),
      E.forecastDevice({ deviceName: 'FortiB' }, days(30, () => null, 0), { hasLogCoverage: true }),
      E.forecastDevice({ deviceName: 'Quiet' }, [], { hasLogCoverage: false }),
    ];
    const s = E.summariseForecasts(list);
    assert.equal(s.bytesNotSummable, 2);
    assert.deepEqual(s.bytesNotSummableDevices, ['FortiA', 'FortiB']);
    assert.equal(s.noLogCoverage, 1);
    assert.deepEqual(s.noLogCoverageDevices, ['Quiet']);
    assert.equal(s.measurable, 0);
    assert.equal(s.unavailable, undefined, 'no combined total may exist');
  });
});

// ── the deploy-gap problem ─────────────────────────────────────────────────

describe('⛔ a deploy gap is not a traffic drop', () => {
  it('a day short of COMPLETE_DAY_HOURS is COUNTED and EXCLUDED, never used as '
    + 'a low observation', () => {
    const series = ramp(40);
    // The collector lost an hour on day 20 and the day's bytes came in low.
    series[20] = { day: series[20].day, byteHours: 23, bytes: 1 };
    const r = ok(series);
    assert.equal(r.completeDays, 39);
    assert.equal(r.partialDays, 1);
    assert.equal(r.state, E.STATES.RISING, 'the ramp must survive the gap');
  });

  it('⛔ A PARTIAL DAY IS TREATED IDENTICALLY TO AN ABSENT ONE, which is the '
    + 'whole rule', () => {
    const clean = ramp(40);
    const withGap = ramp(40);
    withGap[20] = { day: withGap[20].day, byteHours: 10, bytes: 5 };
    const a = ok(withGap);
    const b = ok(clean.filter((_, i) => i !== 20));
    assert.equal(a.slopeBytesPerDay, b.slopeBytesPerDay);
    assert.equal(a.slopeLowBytesPerDay, b.slopeLowBytesPerDay);
    assert.equal(a.slopeHighBytesPerDay, b.slopeHighBytesPerDay);
    assert.equal(a.trendLevelAtEndBytes, b.trendLevelAtEndBytes);
  });

  it('⛔ ON A CLEAN RAMP, COUNTING A SHORT DAY CHANGES NOTHING — and that is '
    + 'why the first version of THIS TEST passed while proving nothing. '
    + 'Theil–Sen\'s median absorbs an outlier, so a noiseless fixture cannot '
    + 'show what the completeness rule is worth; a measurement on the real '
    + 'fleet can, and did (next test)', () => {
    const clean = ramp(40, 100000, 1000);
    const counted = ok(clean.map((d, i) => (i >= 36 ? { ...d, bytes: 50 } : d)));
    assert.equal(counted.slopeBytesPerDay, 1000, 'unmoved — the fixture is degenerate');
  });

  it('⛔ ON A NOISY SERIES — WHICH IS WHAT EVERY REAL FIREWALL IS — COUNTING '
    + 'THE OUTAGE MOVES THE RATE AND CAN FLIP ITS SIGN. Measured on the live '
    + 'fleet with partial days counted as real days: TFM-RN +0.0141 -> '
    + '-0.0625 GB/day (a SIGN FLIP, 543%), TFM-MH -0.3640 -> -1.5504 (326%, '
    + '4x the magnitude, and the level the projection starts from drops 12.1%), '
    + 'TUG +0.1179 -> +0.4194 (256%), IDC FW -0.0309 -> -0.0098 (69%). A dip '
    + 'that is OUR collector being restarted, read as the customer\'s traffic', () => {
    // ⛔ THE FIXTURE IS THE MEASUREMENT. TFM-RN's own 62 day buckets, read off
    // production on 2026-11-12 — the convention CLAUDE.md sets for the syslog
    // parsers ("the captured lines are the test fixtures"), for the same
    // reason: two synthetic series were tried above and both were degenerate
    // in a way no amount of care would have predicted.
    const counted = ok(TFM_RN.map(([d, h, mb]) => ({
      day: new Date(T0 + d * DAY), byteHours: 24, bytes: mb * 1e6,
    })));
    const excluded = ok(TFM_RN.map(([d, h, mb]) => ({
      day: new Date(T0 + d * DAY), byteHours: h, bytes: mb * 1e6,
    })));
    assert.equal(excluded.completeDays, 58);
    assert.equal(excluded.partialDays, 4);
    assert.equal(counted.completeDays, 62);
    assert.ok(
      excluded.slopeBytesPerDay > 0 && counted.slopeBytesPerDay < 0,
      '⛔ THE SIGN FLIPS: counting the outage turns a rising firewall into a '
      + `falling one (${excluded.slopeBytesPerDay} -> ${counted.slopeBytesPerDay})`,
    );
    assert.ok(
      counted.trendLevelAtEndBytes < excluded.trendLevelAtEndBytes,
      'and it drags down the level a projection would start from',
    );
    // Both answers are honestly `no_detectable_trend` on this firewall, which
    // is why the sign flip alone is the assertion — it is the rate that the
    // page prints, and it would have printed the wrong direction.
    assert.equal(excluded.state, E.STATES.NO_DETECTABLE_TREND);
  });

  it('⛔ AND THE TRAILING PARTIAL DAY IS WHAT WOULD HAVE BROKEN THE PROJECTION. '
    + 'TFM-RN\'s last bucket is 2026-11-08 at 17:00 — an 18-hour day — and the '
    + 'projection pivots on the line\'s value at the LAST OBSERVED DAY, so a '
    + 'short final day drags the base a projection starts from', () => {
    const excluded = ok(TFM_RN.map(([d, h, mb]) => ({
      day: new Date(T0 + d * DAY), byteHours: h, bytes: mb * 1e6,
    })));
    // Day 61 is partial, so the observed window ends on day 60.
    assert.equal(
      excluded.observedTo.getTime(), T0 + 60 * DAY,
      'the short final day must not be the anchor',
    );
    // Day 0 is ALSO partial (9h), so the window runs day 1..day 60 inclusive.
    assert.equal(excluded.observedFrom.getTime(), T0 + 1 * DAY);
    assert.equal(excluded.spanDays, 60);
    // ⛔ 60 days of span holding 58 observations — the two are reported apart,
    // so a reader can see that two days inside the window were not measured.
    assert.equal(excluded.windowDays, 58);
  });

  it('⛔ AND PARTIAL DAYS MAY NOT HELP A FIREWALL THROUGH THE ARMING GATE. '
    + 'TFM-RN holds 58 complete days and 62 byte-bearing ones; near the gate '
    + 'those four would be fabricated observations deciding whether a trend is '
    + 'published at all', () => {
    const n = E.MIN_HISTORY_DAYS;
    // n-3 complete days plus 3 partials: byte-bearing days reach the gate,
    // complete days do not.
    const series = ramp(n, 1000, 100).map((d, i) => (
      i >= n - 3 ? { ...d, byteHours: 11 } : d
    ));
    const r = ok(series);
    assert.equal(r.byteBearingDays, undefined, 'not published on the device shape');
    assert.equal(r.completeDays, n - 3);
    assert.equal(r.partialDays, 3);
    assert.equal(
      r.state, E.STATES.INSUFFICIENT_HISTORY,
      'the gate must count complete days, not byte-bearing ones',
    );
  });

  it('⛔ A MISSING DAY IS NOT A ZERO DAY: an absent day shortens the evidence '
    + 'and the slope is fitted on REAL day indices, so a hole does not become '
    + 'a cliff', () => {
    const series = ramp(40).filter((_, i) => i < 10 || i > 19);  // ten days gone
    const r = ok(series);
    assert.equal(r.completeDays, 30);
    assert.equal(r.partialDays, 0);
    assert.equal(r.state, E.STATES.RISING);
    // 100/day ramp preserved across the hole, because t is the real day index.
    assert.equal(r.slopeBytesPerDay, 100);
    assert.equal(r.spanDays, 40, 'the span states how much was NOT observed');
  });

  it('a complete day whose BYTES could not be read is unreadable, not zero', () => {
    const series = ramp(40);
    series[5] = { day: series[5].day, byteHours: 24, bytes: null };
    const r = ok(series);
    assert.equal(r.completeDays, 39);
    assert.equal(r.unreadableDays, 1);
    assert.equal(r.partialDays, 0, 'an unreadable day is not a partial day');
  });

  it('an unreadable HOUR COUNT is also not a partial day and not a zero', () => {
    const series = ramp(40);
    series[5] = { day: series[5].day, byteHours: null, bytes: 999 };
    const r = ok(series);
    assert.equal(r.unreadableDays, 1);
    assert.equal(r.partialDays, 0);
  });

  it('COMPLETE_DAY_HOURS is 24 with no tolerance', () => {
    assert.equal(E.COMPLETE_DAY_HOURS, 24);
    assert.equal(ok(ramp(40, 1000, 100), { completeDayHours: 24 }).completeDays, 40);
    assert.equal(ok(days(40, (i) => 1000 + i * 100, 23)).completeDays, 0);
  });
});

// ── the direction test, and what it refuses ────────────────────────────────

describe('⛔ no_detectable_trend is the common answer and is NOT flat', () => {
  it('pure alternating noise is no_detectable_trend, not rising, not zero', () => {
    const r = ok(noisy(60));
    assert.equal(r.state, E.STATES.NO_DETECTABLE_TREND);
    assert.equal(r.projected, false);
    assert.equal(r.projectedDailyBytes, null, 'the projection is WITHHELD');
    assert.equal(r.projectedFor, null);
    assert.match(r.reason, /not a measurement of zero growth/i);
  });

  it('⛔ the SLOPE AND THE GROWTH ARE STILL REPORTED — they are real '
    + 'measurements; only the JUDGEMENT is withheld', () => {
    const r = ok(noisy(60));
    assert.notEqual(r.slopeBytesPerDay, null);
    assert.notEqual(r.slopeLowBytesPerDay, null);
    assert.notEqual(r.slopeHighBytesPerDay, null);
    assert.notEqual(r.medianDailyBytes, null);
  });

  it('⛔ THE DIRECTION COMES FROM THE INTERVAL, NOT THE SIGN OF THE SLOPE. '
    + 'Live, SMT has a slope of +1.19 GB/day and an interval of [-0.68, +5.02] '
    + '— "rising" there would be a coin toss printed as a finding', () => {
    const r = ok(noisy(60));
    // The interval straddles zero even where the point slope does not.
    assert.ok(
      !(r.slopeLowBytesPerDay > 0 && r.slopeHighBytesPerDay > 0)
      && !(r.slopeLowBytesPerDay < 0 && r.slopeHighBytesPerDay < 0),
      'fixture must straddle zero for this test to mean anything',
    );
    assert.equal(r.state, E.STATES.NO_DETECTABLE_TREND);
  });

  it('a hard downward ramp is `falling` and does carry a projection', () => {
    const r = ok(days(40, (i) => 100000 - i * 1000));
    assert.equal(r.state, E.STATES.FALLING);
    assert.equal(r.projected, true);
    assert.ok(r.projectedDailyBytes < r.trendLevelAtEndBytes);
  });

  it('⛔ THE INTERVAL AND THE DIRECTION TEST AGREE BY CONSTRUCTION — this '
    + 'engine can never print a direction its own interval contradicts', () => {
    for (const series of [ramp(40), noisy(40), days(40, (i) => 5000 - i * 60), ramp(20, 10, 1)]) {
      const r = ok(series);
      const t = E.senTrend(series.map((d, i) => ({ t: i, y: d.bytes })));
      const intervalExcludesZero = (t.lowPerDay > 0 && t.highPerDay > 0)
        || (t.lowPerDay < 0 && t.highPerDay < 0);
      const mkRejects = Math.abs(t.z) > E.Z_CRITICAL;
      assert.equal(
        intervalExcludesZero, mkRejects,
        'Sen interval and Mann-Kendall must agree; they share Var(S)',
      );
      assert.equal(r.projected, intervalExcludesZero);
    }
  });

  it('`increasingShare` is a checkable restatement of S', () => {
    const r = ok(ramp(40));
    assert.equal(r.increasingShare, 100, 'a monotone ramp: every pair increases');
    assert.equal(ok(days(40, (i) => 5000 - i * 60)).increasingShare, 0);
  });
});

// ── growth never travels alone ─────────────────────────────────────────────

describe('⛔ growth is stated with the window it was measured over', () => {
  it('growthPctOverWindow is always accompanied by windowDays', () => {
    const r = ok(ramp(40, 1000, 100));
    assert.notEqual(r.growthPctOverWindow, null);
    assert.equal(r.windowDays, 40);
    // And the two are consistent: slope * windowDays / level.
    const expected = Math.round((100 * 40 / r.medianDailyBytes) * 100 * 10) / 10;
    assert.equal(r.growthPctOverWindow, expected);
  });

  it('⛔ windowDays is the COMPLETE day count, not the span — otherwise a '
    + 'firewall with a hole in its history would claim more evidence than it '
    + 'has', () => {
    const series = ramp(40).filter((_, i) => i < 10 || i > 19);
    const r = ok(series);
    assert.equal(r.windowDays, 30);
    assert.equal(r.spanDays, 40);
    assert.notEqual(r.windowDays, r.spanDays);
  });

  it('⛔ a non-positive level yields a null growth figure, never Infinity or '
    + 'NaN — and the protection is DOUBLED, which a mutation proved. Removing '
    + 'the `level > 0` guard changes nothing because `round()` returns null for '
    + 'any non-finite value, so both halves are asserted here rather than one '
    + 'being mistaken for the whole', () => {
    const r = ok(days(40, () => 0));
    assert.equal(r.growthPctOverWindow, null);
    assert.ok(!Number.isNaN(r.growthPctOverWindow));
    // Half two, independently: the rounding helper refuses a non-finite input,
    // so an Infinity can never be published even if the guard above were lost.
    const t = E.senTrend([{ t: 0, y: 0 }, { t: 1, y: 0 }]);
    assert.equal(t.slopePerDay, 0);
    assert.ok(Number.isFinite(t.levelAtEnd));
  });

  it('⛔ nothing in the engine returns a growth figure without a window', () => {
    for (const series of [ramp(40), noisy(40), ramp(5), []]) {
      const r = E.forecastDevice(device, series, { hasLogCoverage: true });
      if (r.growthPctOverWindow !== null) {
        assert.equal(typeof r.windowDays, 'number', 'growth without a window');
        assert.ok(r.windowDays > 0);
      }
    }
  });
});

// ── the projection ─────────────────────────────────────────────────────────

describe('the projection', () => {
  it('⛔ PIVOTS ON THE LINE\'S VALUE AT THE LAST OBSERVED DAY. The first draft '
    + 'held a t=0 intercept and swapped the slope, which moves the line by '
    + 'Δslope × 20,769 days and published [0.00, 772.24] GB/day around a point '
    + 'projection of 6.81 on TUFF(TUTH3)', () => {
    const r = ok(ramp(40, 1000, 100), { horizonDays: 10 });
    assert.equal(r.state, E.STATES.RISING);
    // level at end = 1000 + 39*100 = 4900; +10 days at 100/day = 5900.
    assert.equal(r.trendLevelAtEndBytes, 4900);
    assert.equal(r.projectedDailyBytes, 5900);
    // ⛔ THE RANGE MUST BRACKET THE POINT AND STAY NEAR IT — the bug's
    // signature was a range orders of magnitude wide.
    assert.ok(r.projectedLowDailyBytes <= r.projectedDailyBytes);
    assert.ok(r.projectedHighDailyBytes >= r.projectedDailyBytes);
    assert.ok(
      r.projectedHighDailyBytes < r.trendLevelAtEndBytes * 3,
      `range escaped the data: ${r.projectedHighDailyBytes}`,
    );
  });

  it('⛔ uses a REBASED x axis, so an epoch-scale day index cannot blow it up', () => {
    // Real day indices (~20,769). The fixture days are real Dates already, so
    // this is the production path; pin the invariant it protects.
    const r = ok(ramp(60, 3_000_000_000, 50_000_000), { horizonDays: 30 });
    assert.equal(r.state, E.STATES.RISING);
    const spread = r.projectedHighDailyBytes - r.projectedLowDailyBytes;
    assert.ok(
      spread < r.projectedDailyBytes,
      `the interval must be narrower than the projection itself, got ${spread}`,
    );
  });

  it('⛔ HORIZON CAPPED AT THE HISTORY IT IS FITTED FROM, and the cap is '
    + 'disclosed rather than applied silently', () => {
    const r = ok(ramp(20), { horizonDays: 90 });
    assert.equal(r.horizonDays, 20);
    assert.equal(r.horizonCapped, true);
    const r2 = ok(ramp(60), { horizonDays: 30 });
    assert.equal(r2.horizonDays, 30);
    assert.equal(r2.horizonCapped, false);
  });

  it('projectedFor is the last observed day plus the horizon', () => {
    const r = ok(ramp(40), { horizonDays: 7 });
    assert.equal(
      r.projectedFor.getTime(),
      r.observedTo.getTime() + 7 * DAY,
    );
  });

  it('⛔ never projects negative bytes — a falling trend that reaches the floor '
    + 'means the trend runs out before the horizon', () => {
    const r = ok(days(40, (i) => 4000 - i * 100), { horizonDays: 40 });
    assert.equal(r.state, E.STATES.FALLING);
    assert.ok(r.projectedDailyBytes >= 0);
    assert.ok(r.projectedLowDailyBytes >= 0);
  });

  it('an out-of-range horizon falls back to the default, never to an edge', () => {
    assert.equal(ok(ramp(60), { horizonDays: 0 }).horizonDays, E.DEFAULT_HORIZON_DAYS);
    assert.equal(ok(ramp(60), { horizonDays: 9999 }).horizonDays, E.DEFAULT_HORIZON_DAYS);
    assert.equal(ok(ramp(60), { horizonDays: 'soon' }).horizonDays, E.DEFAULT_HORIZON_DAYS);
  });

  it('⛔ every projection field is PRESENT AND NULL on every shape, so a '
    + 'missing key can never read as a zero', () => {
    const keys = [
      'medianDailyBytes', 'trendLevelAtEndBytes', 'slopeBytesPerDay',
      'slopeLowBytesPerDay', 'slopeHighBytesPerDay', 'growthPctOverWindow',
      'windowDays', 'projectedDailyBytes', 'projectedLowDailyBytes',
      'projectedHighDailyBytes', 'projectedFor', 'horizonDays',
    ];
    for (const r of [
      E.forecastDevice(device, [], { hasLogCoverage: false }),
      ok(days(30, () => null, 0)),
      ok(ramp(5)),
      ok(noisy(40)),
      ok(ramp(40)),
    ]) {
      for (const k of keys) {
        assert.ok(k in r, `${r.state} is missing ${k}`);
      }
    }
  });
});

// ── ranking ────────────────────────────────────────────────────────────────

describe('⛔ ranking puts the least-known firewalls FIRST', () => {
  it('unforecastable above measured — a firewall nothing can be measured on is '
    + 'the one whose capacity is unknown, and must not sort to the bottom of a '
    + 'capacity page', () => {
    const list = [
      ok(ramp(40, 10 ** 12, 10 ** 9)),                                   // big, rising
      ok(noisy(40)),                                                      // no trend
      E.forecastDevice({ deviceName: 'Quiet' }, [], { hasLogCoverage: false }),
      E.forecastDevice({ deviceName: 'Forti' }, days(30, () => null, 0), { hasLogCoverage: true }),
    ];
    const ranked = E.rankForecasts(list).map((d) => d.state);
    assert.equal(ranked[0], E.STATES.NO_LOG_COVERAGE);
    assert.equal(ranked[1], E.STATES.BYTES_NOT_SUMMABLE);
    assert.ok(ranked.indexOf(E.STATES.RISING) < ranked.indexOf(E.STATES.NO_DETECTABLE_TREND));
  });

  it('⛔ NULLS LAST on the volume tie-break — JavaScript\'s `-` on null is 0, '
    + 'which would sort an unmeasured firewall into the middle of the volumes', () => {
    const measured = (name, level) => ({
      ...ok(days(40, () => level)), deviceName: name,
    });
    const list = [
      measured('small', 10),
      { ...ok(days(40, () => 100)), deviceName: 'nullish', medianDailyBytes: null },
      measured('big', 10_000),
    ];
    const ranked = E.rankForecasts(list).map((d) => d.deviceName);
    assert.deepEqual(ranked, ['big', 'small', 'nullish']);
  });

  it('STATE_ORDER covers every state, so no state can rank by accident', () => {
    for (const s of Object.values(E.STATES)) {
      assert.ok(E.STATE_ORDER.includes(s), `${s} has no rank`);
    }
  });

  it('does not mutate its input', () => {
    const list = [ok(ramp(40)), E.forecastDevice({}, [], { hasLogCoverage: false })];
    const first = list[0];
    E.rankForecasts(list);
    assert.equal(list[0], first);
  });
});

describe('the summary', () => {
  it('⛔ publishes NO fleet bandwidth figure, score, grade or percentage — the '
    + 'measured spread across the forecastable ten is ~680,000x on the daily '
    + 'medians, so a fleet sum is its two largest members wearing the estate\'s '
    + 'name', () => {
    const s = E.summariseForecasts([ok(ramp(40)), ok(noisy(40))]);
    for (const k of Object.keys(s)) {
      assert.doesNotMatch(k, /score|grade|percent|pct|healthy|total.*bytes|fleet.*bytes/i,
        `summary must not publish ${k}`);
    }
    assert.equal(s.devices, 2);
    assert.equal(s.projected, 1);
    assert.equal(s.noDetectableTrend, 1);
  });

  it('an empty fleet is counted, not an error', () => {
    const s = E.summariseForecasts([]);
    assert.equal(s.devices, 0);
    assert.equal(s.measurable, 0);
    assert.equal(s.projected, 0);
  });

  it('a non-array is tolerated and never throws', () => {
    assert.equal(E.summariseForecasts(null).devices, 0);
    assert.equal(E.summariseForecasts('nope').devices, 0);
  });
});

// ── the engine never throws ────────────────────────────────────────────────

describe('⛔ the engine never throws — it is chrome on an operator\'s page', () => {
  for (const [name, series] of [
    ['null', null],
    ['a string', 'nope'],
    ['rows of junk', [{}, { day: 'not a date' }, { day: null, bytes: 'x' }]],
    ['a NaN byte count', [{ day: new Date(T0), byteHours: 24, bytes: NaN }]],
    ['one day', [{ day: new Date(T0), byteHours: 24, bytes: 5 }]],
    ['all the same day', days(20, () => 5).map((d) => ({ ...d, day: new Date(T0) }))],
  ]) {
    it(name, () => {
      const r = E.forecastDevice(device, series, { hasLogCoverage: true });
      assert.ok(Object.values(E.STATES).includes(r.state));
      assert.equal(r.projected, false);
    });
  }

  it('⛔ observations sharing one day index cannot yield a slope, and that is '
    + 'insufficient_history rather than a divide by zero', () => {
    const same = days(20, (i) => 1000 + i).map((d) => ({ ...d, day: new Date(T0) }));
    const r = E.forecastDevice(device, same, { hasLogCoverage: true });
    assert.equal(r.state, E.STATES.INSUFFICIENT_HISTORY);
    assert.ok(Number.isFinite(r.completeDays));
  });
});

// ── reused estimators, not reimplemented ───────────────────────────────────

describe('⛔ it reuses the existing estimators rather than writing a second opinion', () => {
  it('median and quantile come from changeOutcome.js', () => {
    const co = require('../lib/engines/changeOutcome');
    assert.equal(E.median, co.median);
    assert.equal(E.quantile, co.quantile);
  });

  it('the gate comes from seasonalBaseline.minObservationsFor', () => {
    assert.match(CODE_ENGINE, /require\('\.\/seasonalBaseline'\)/);
    assert.match(CODE_ENGINE, /minObservationsFor/);
  });

  it('⛔ NO SECOND STATISTICS HELPER — no local median/quantile/mean/stddev', () => {
    assert.doesNotMatch(CODE_ENGINE, /function\s+median\s*\(/);
    assert.doesNotMatch(CODE_ENGINE, /function\s+quantile\s*\(/);
    assert.doesNotMatch(CODE_ENGINE, /function\s+(mean|average|stddev|stdev)\s*\(/i);
  });
});

// ── the data layer ─────────────────────────────────────────────────────────

function stubPool(handlers) {
  const seen = [];
  return {
    seen,
    query: async (sql, params) => {
      seen.push({ sql, params });
      for (const [re, rows] of handlers) {
        if (re.test(sql)) {
          if (rows instanceof Error) throw rows;
          return { rows };
        }
      }
      return { rows: [] };
    },
  };
}

const DEV_RE = /FROM devices d/;
const DAILY_RE = /WITH per_hour/;
const COV_RE = /rows_held/;

describe('capacityForecastData', () => {
  it('⛔ NEVER NAMES THE RAW EVENT TABLE in code', () => {
    // Prove the stripper works before trusting it, the way
    // tests/changeOutcomeData.test.js does.
    assert.match(SRC_DATA, /syslog_events/, 'expected the prose to name it');
    assert.doesNotMatch(CODE_DATA, /syslog_events/, 'the code must not');
  });

  it('⛔ reads only the hourly rollup', () => {
    assert.match(CODE_DATA, /syslog_rollup_hourly/);
  });

  it('⛔ every statement is a named constant, never an interpolated template', () => {
    const named = CODE_DATA.match(/pool\.query\(\s*[A-Z_]+_SQL\s*,/g) || [];
    assert.equal(named.length, 3);
    assert.doesNotMatch(CODE_DATA, /pool\.query\(\s*`/);
    assert.doesNotMatch(CODE_DATA, /pool\.query\(\s*['"]/);
  });

  it('⛔ casts the timestamp parameter explicitly — without ::timestamptz '
    + 'PostgreSQL answers "could not determine data type of parameter". '
    + '⛔ EVERY USE OF $2 IS CHECKED, NOT ONE: the window has TWO bounds, and '
    + 'the first version of this assertion was a bare `match` that a mutation '
    + 'dropping the cast from the lower bound SURVIVED, because the upper '
    + 'bound still satisfied the regex', () => {
    const uses = CODE_DATA.match(/\$2(::\w+)?/g) || [];
    assert.ok(uses.length >= 2, `expected both bounds, found ${uses.length}`);
    for (const u of uses) {
      assert.equal(u, '$2::timestamptz', `an uncast $2 reached the SQL: ${u}`);
    }
  });

  it('⛔ passes device ids as a uuid[] parameter, never interpolated', () => {
    assert.match(CODE_DATA, /\$1::uuid\[\]/);
    assert.doesNotMatch(CODE_DATA, /\$\{/, 'no template interpolation anywhere');
  });

  it('⛔ THE COVERAGE PROBE IS UNBOUNDED while the series is not — "no traffic '
    + 'logs at all" must be true of all time, or a firewall that went quiet '
    + 'four months ago is blamed on a collection gap when the answer is '
    + '"history exists, none inside the window"', () => {
    const covStart = CODE_DATA.indexOf('const COVERAGE_SQL');
    const cov = CODE_DATA.slice(covStart, CODE_DATA.indexOf('`', CODE_DATA.indexOf('`', covStart) + 1));
    assert.doesNotMatch(cov, /bucket_hour >=/, 'the probe must not be time-bounded');
    const dailyStart = CODE_DATA.indexOf('const DAILY_SQL');
    const daily = CODE_DATA.slice(dailyStart, CODE_DATA.indexOf('ORDER BY 1, 2', dailyStart));
    assert.match(daily, /bucket_hour >=/, 'the series must be time-bounded');
  });

  it('⛔ THE COVERAGE PROBE CARRIES BOTH ALL-TIME FACTS — has this firewall '
    + 'ever been heard from, and has it ever produced a summable byte count. '
    + 'Both decide states that are claims about all time', () => {
    assert.match(CODE_DATA, /byte_rows_held/);
    assert.match(CODE_DATA, /hasSummableBytes/);
  });

  it('⛔ a firewall with byte history OUTSIDE the window is '
    + 'insufficient_history, NOT a vendor limitation', async () => {
    const pool = stubPool([
      [DEV_RE, [{ id: 'a', name: 'A', vendor: 'paloalto' }]],
      // Nothing inside the window...
      [DAILY_RE, []],
      // ...but the unbounded probe found byte history.
      [COV_RE, [{ device_id: 'a', rows_held: '5034', byte_rows_held: '2808' }]],
    ]);
    const out = await getCapacityForecasts(pool);
    assert.equal(out.devices[0].state, E.STATES.INSUFFICIENT_HISTORY);
    assert.equal(out.summary.bytesNotSummable, 0);
  });

  it('⛔ a firewall logging plenty and never a byte IS a vendor limitation — '
    + 'the live Fortinet shape (TSR_EKM: 44,706 rollup rows, 0 byte rows)', async () => {
    const pool = stubPool([
      [DEV_RE, [{ id: 'a', name: 'TSR_EKM', vendor: 'fortinet' }]],
      [DAILY_RE, []],
      [COV_RE, [{ device_id: 'a', rows_held: '44706', byte_rows_held: '0' }]],
    ]);
    const out = await getCapacityForecasts(pool);
    assert.equal(out.devices[0].state, E.STATES.BYTES_NOT_SUMMABLE);
    assert.equal(out.devices[0].permanent, true);
  });

  it('⛔ excludes the unmatched-sender rows — folding a null device_id into a '
    + 'group would build a trend for a firewall out of another host\'s traffic', () => {
    assert.match(CODE_DATA, /device_id IS NOT NULL/);
  });

  it('⛔ ANY failed read returns NO devices WITH failures — a short board looks '
    + 'like a fleet with headroom', async () => {
    // ⛔ THE OTHER TWO READS MUST SUCCEED AND RETURN REAL ROWS, or this test
    // cannot see the rule it is checking. The first version supplied only the
    // failing handler, so every other query fell through to the stub's empty
    // default and `devices` was [] whether the guard existed or not — the
    // withholding rule could be DELETED and this test stayed green. Caught by
    // mutation, which is the only way a test this shape gets found out.
    const liveDevices = [
      { id: 'a', name: 'A', vendor: 'paloalto' },
      { id: 'b', name: 'B', vendor: 'paloalto' },
    ];
    const liveDaily = ['a', 'b'].flatMap((id) => Array.from({ length: 40 }, (_, i) => ({
      device_id: id, day: new Date(T0 + i * DAY), hours: '24', byte_hours: '24',
      bytes: String(1_000_000 + i * 10_000),
    })));
    const liveCov = [
      { device_id: 'a', rows_held: '960', byte_rows_held: '960' },
      { device_id: 'b', rows_held: '960', byte_rows_held: '960' },
    ];

    // Sanity: with nothing failing, this fixture DOES produce a full board —
    // otherwise an empty result below would prove nothing.
    const healthy = await getCapacityForecasts(stubPool([
      [DEV_RE, liveDevices], [DAILY_RE, liveDaily], [COV_RE, liveCov],
    ]));
    assert.deepEqual(healthy.failures, []);
    assert.equal(healthy.devices.length, 2);
    assert.equal(healthy.devices[0].state, E.STATES.RISING);

    for (const broken of [DEV_RE, DAILY_RE, COV_RE]) {
      const handlers = [
        [DEV_RE, liveDevices], [DAILY_RE, liveDaily], [COV_RE, liveCov],
      ].map(([re, rows]) => [re, re === broken ? new Error('boom') : rows]);
      const out = await getCapacityForecasts(stubPool(handlers));
      assert.deepEqual(out.devices, [], `a failed ${broken} must withhold the board`);
      assert.equal(out.failures.length, 1);
      assert.match(out.failures[0].error, /boom/);
      assert.equal(out.summary.devices, 0);
      // ⛔ And the summary may not carry a count either.
      assert.equal(out.summary.projected, 0);
      assert.equal(out.summary.measurable, 0);
    }
  });

  it('⛔ each source gets its OWN failures entry — which read failed changes '
    + 'what an operator does next', async () => {
    const pool = stubPool([
      [DEV_RE, new Error('a')], [DAILY_RE, new Error('b')], [COV_RE, new Error('c')],
    ]);
    const out = await getCapacityForecasts(pool);
    assert.deepEqual(
      out.failures.map((f) => f.source).sort(),
      ['daily_traffic', 'devices', 'log_coverage'],
    );
  });

  it('⛔ an EMPTY id list is an instruction, not a failure — a scoped account '
    + 'granted nothing gets an empty board with NO failures entry', async () => {
    const pool = stubPool([]);
    const out = await getCapacityForecasts(pool, { deviceIds: [] });
    assert.deepEqual(out.devices, []);
    assert.deepEqual(out.failures, []);
    assert.equal(pool.seen.length, 0, 'and it must not query at all');
  });

  it('undefined deviceIds means the WHOLE FLEET, not none', async () => {
    const pool = stubPool([[DEV_RE, [{ id: 'a', name: 'A', vendor: 'paloalto' }]]]);
    const out = await getCapacityForecasts(pool);
    assert.equal(out.devices.length, 1);
    assert.equal(pool.seen[0].params[0], null, 'null parameter = no filter');
  });

  it('⛔ builds one row per ACTIVE FIREWALL from `devices`, so a firewall that '
    + 'sends no syslog still appears', async () => {
    const pool = stubPool([
      [DEV_RE, [
        { id: 'a', name: 'Quiet', vendor: 'paloalto' },
        { id: 'b', name: 'Forti', vendor: 'fortinet' },
      ]],
      [DAILY_RE, [
        // Forti logs plenty of hours and never a byte.
        ...Array.from({ length: 30 }, (_, i) => ({
          device_id: 'b', day: new Date(T0 + i * DAY), hours: '24', byte_hours: '0', bytes: null,
        })),
      ]],
      // ⛔ Forti: plenty of rows, never a byte — an all-time vendor limit.
      [COV_RE, [{ device_id: 'b', rows_held: '720', byte_rows_held: '0' }]],
    ]);
    const out = await getCapacityForecasts(pool);
    assert.equal(out.devices.length, 2);
    const byName = Object.fromEntries(out.devices.map((d) => [d.deviceName, d.state]));
    assert.equal(byName.Quiet, E.STATES.NO_LOG_COVERAGE);
    assert.equal(byName.Forti, E.STATES.BYTES_NOT_SUMMABLE);
    assert.equal(out.summary.noLogCoverage, 1);
    assert.equal(out.summary.bytesNotSummable, 1);
  });

  it('⛔ `pg` HANDS BIGINT SUMS BACK AS STRINGS and they survive the trip', async () => {
    const pool = stubPool([
      [DEV_RE, [{ id: 'a', name: 'A', vendor: 'paloalto' }]],
      [DAILY_RE, Array.from({ length: 40 }, (_, i) => ({
        device_id: 'a',
        day: new Date(T0 + i * DAY),
        hours: '24',
        byte_hours: '24',
        bytes: String(1_000_000_000_000 + i * 50_000_000_000),
      }))],
      [COV_RE, [{ device_id: 'a', rows_held: '960', byte_rows_held: '960' }]],
    ]);
    const out = await getCapacityForecasts(pool);
    assert.equal(out.devices[0].state, E.STATES.RISING);
    assert.equal(out.devices[0].slopeBytesPerDay, 50_000_000_000);
  });

  it('a zero rows_held is NOT coverage', async () => {
    const pool = stubPool([
      [DEV_RE, [{ id: 'a', name: 'A', vendor: 'paloalto' }]],
      [COV_RE, [{ device_id: 'a', rows_held: '0', byte_rows_held: '0' }]],
    ]);
    const out = await getCapacityForecasts(pool);
    assert.equal(out.devices[0].state, E.STATES.NO_LOG_COVERAGE);
  });

  it('a bad lookback or horizon falls back to the default, never to an edge', async () => {
    const pool = stubPool([]);
    const a = await getCapacityForecasts(pool, { lookbackDays: 9999, horizonDays: -3 });
    assert.equal(a.lookbackDays, E.DEFAULT_LOOKBACK_DAYS);
    assert.equal(a.horizonDays, E.DEFAULT_HORIZON_DAYS);
  });

  it('⛔ the lookback is a COST BOUND as well as a window — the rollups are '
    + 'permanent and the estimator is O(days squared)', () => {
    assert.ok(E.MAX_LOOKBACK_DAYS <= 365);
    assert.equal(E.DEFAULT_LOOKBACK_DAYS, 90);
  });

  it('⛔ A MISSING OR MALFORMED DEVICE ID IS A FAILURE, NOT "NO FILTER" — '
    + 'passing it through would print the whole fleet under one firewall\'s '
    + 'name', async () => {
    const pool = stubPool([[DEV_RE, [{ id: 'a', name: 'A', vendor: 'paloalto' }]]]);
    for (const bad of ['', null, undefined, 7]) {
      const out = await getDeviceCapacityForecast(pool, bad);
      assert.equal(out.device, null);
      assert.equal(out.failures.length, 1);
      assert.equal(out.failures[0].source, 'device');
    }
    assert.equal(pool.seen.length, 0);
  });

  it('a named device returns that one firewall', async () => {
    const pool = stubPool([
      [DEV_RE, [{ id: 'a', name: 'A', vendor: 'paloalto' }]],
      [COV_RE, [{ device_id: 'a', rows_held: '1', byte_rows_held: '1' }]],
    ]);
    const out = await getDeviceCapacityForecast(pool, 'a');
    assert.equal(out.device.deviceName, 'A');
    assert.deepEqual(pool.seen[0].params[0], ['a']);
  });

  it('`now` is injectable, so a test pins the window', async () => {
    const pool = stubPool([]);
    const out = await getCapacityForecasts(pool, { now: '2026-11-12T00:00:00Z' });
    assert.equal(out.generatedAt, '2026-11-12T00:00:00.000Z');
  });
});

// ── the live fleet, reproduced from its measured shape ─────────────────────

describe('⛔ the live fleet\'s own answer is reproduced', () => {
  it('eight of ten forecastable firewalls report no_detectable_trend, and the '
    + 'six that cannot be forecast split 5 / 1 across TWO reasons', () => {
    // The shape measured on production: five Fortinets logging with no summable
    // bytes, one Palo Alto with no rollups at all, and a noisy Palo Alto.
    const list = [];
    for (const n of ['TSR_EKC', 'TSR_EKM', 'TSR-TL', 'OKF(F2)', 'Vietnam-YCC']) {
      list.push(E.forecastDevice(
        { deviceName: n, vendor: 'fortinet' }, days(65, () => null, 24 ? 0 : 0),
        { hasLogCoverage: true },
      ));
    }
    list.push(E.forecastDevice(
      { deviceName: 'PAKFood', vendor: 'paloalto' }, [], { hasLogCoverage: false },
    ));
    for (let i = 0; i < 8; i += 1) {
      list.push(E.forecastDevice(
        { deviceName: `noisy-${i}`, vendor: 'paloalto' }, noisy(65, 10 ** 11),
        { hasLogCoverage: true },
      ));
    }
    for (const n of ['TUFF(TUTH3)', 'HRIS']) {
      list.push(E.forecastDevice(
        { deviceName: n, vendor: 'paloalto' }, ramp(65, 3 * 10 ** 9, 5 * 10 ** 7),
        { hasLogCoverage: true },
      ));
    }
    const s = E.summariseForecasts(list);
    assert.equal(s.devices, 16);
    assert.equal(s.measurable, 10);
    assert.equal(s.bytesNotSummable, 5);
    assert.equal(s.noLogCoverage, 1);
    assert.equal(s.noDetectableTrend, 8);
    assert.equal(s.projected, 2);
  });
});

// ── the rendering vocabulary ───────────────────────────────────────────────
//
// ⛔ THESE ARE DECISIONS ABOUT WHAT A READER SEES, so they are pinned by
// BEHAVIOUR. `components/capacity/formatRate.js` is split out of the JSX board
// for exactly that reason: `node:test` cannot require a JSX file, so a
// formatter living inside the board could only have been checked by scanning
// its source — "testing the mechanism, not the outcome".

const { bytesText, rateText, rateGroup, levelGroup } = require('../components/capacity/formatRate');

const GB = 1024 ** 3;
const MB = 1024 ** 2;

describe('rate formatting', () => {
  it('⛔ NULL IS NEVER FORMATTED AS A NUMBER', () => {
    for (const v of [null, undefined, '', NaN, Infinity, 'nope']) {
      assert.equal(bytesText(v), null, String(v));
      assert.equal(rateText(v), null);
    }
    assert.deepEqual(rateGroup([null, 5 * GB, null])[0], null);
  });

  it('⛔ A RATE ALWAYS CARRIES ITS "/day", so it cannot be read as a total', () => {
    assert.match(rateText(5 * GB), /\/day$/);
    for (const t of rateGroup([5 * GB, 1 * GB, 9 * GB])) assert.match(t, /\/day$/);
  });

  it('⛔ A VALUE AND ITS INTERVAL SHARE ONE UNIT, CHOSEN FROM THE LARGEST. '
    + 'Found by rendering the live fleet: SMT printed "+1.19 GB/day" against '
    + '"-699 MB/day to +5.02 GB/day", and -699 beside +5.02 reads as the '
    + 'LARGER of the two — on the one figure whose job is to say the '
    + 'direction is not settled', () => {
    const [rate, low, high] = rateGroup([1.18697 * GB, -0.6826 * GB, 5.0243 * GB]);
    assert.equal(rate, '+1.19 GB/day');
    assert.equal(low, '-0.68 GB/day');
    assert.equal(high, '+5.02 GB/day');
    // The property, not the three strings: one unit across the group.
    const unitsOf = (ts) => new Set(ts.map((t) => t.match(/[A-Z]+\/day$/)[0]));
    assert.equal(unitsOf([rate, low, high]).size, 1);
    assert.equal(unitsOf(rateGroup([5 * GB, 900 * MB, 12 * GB])).size, 1);
    assert.equal(unitsOf(rateGroup([2 * MB, 1024, 9 * MB])).size, 1);
  });

  it('⛔ AND THE PRECISION COMES FROM THE GROUP, or the point and its bounds '
    + 'print to different numbers of decimals and stop reading as one '
    + 'statement', () => {
    const places = (t) => (t.split('.')[1] || '').replace(/[^\d]/g, '').length;
    for (const group of [
      rateGroup([1.1 * GB, 0.2 * GB, 5 * GB]),
      rateGroup([300 * GB, 1 * GB, 900 * GB]),
    ]) {
      assert.equal(new Set(group.map(places)).size, 1, group.join(' | '));
    }
  });

  it('⛔ ONLY A POSITIVE VALUE IS SIGNED — a measured zero is not "+0", which '
    + 'would read as a movement', () => {
    assert.equal(rateGroup([0, -1 * GB, 1 * GB])[0], '0.00 GB/day');
    assert.match(rateGroup([1 * GB, 0, 2 * GB])[0], /^\+/);
    assert.ok(!rateGroup([-1 * GB, -2 * GB, -0.5 * GB])[0].startsWith('+'));
  });

  it('⛔ A PROJECTION IS A LEVEL, NOT A DELTA, so levelGroup never signs it: '
    + '"On this trend, +6.81 GB/day" reads as 6.81 GB/day ON TOP of today', () => {
    for (const t of levelGroup([6.81 * GB, 5.78 * GB, 7.92 * GB])) {
      assert.ok(!t.startsWith('+'), t);
    }
    assert.equal(levelGroup([6.81 * GB, 5.78 * GB, 7.92 * GB])[0], '6.81 GB/day');
  });

  it('an all-null or empty group does not throw and invents no unit', () => {
    assert.deepEqual(rateGroup([]), []);
    assert.deepEqual(rateGroup([null, null]), [null, null]);
    assert.deepEqual(rateGroup(null), []);
    assert.equal(rateGroup([0, 0, 0])[0], '0 B/day');
  });

  it('⛔ a sub-kilobyte rate is bytes, not a rounded-to-zero KB. HRIS\'s '
    + 'measured interval is 468 to 2,658 bytes/day, and the smallest of those '
    + 'must not print as "0.00 KB/day"', () => {
    // The group picks KB because its largest member clears 1,024 — correct,
    // and the small end is still legible at two decimals.
    assert.deepEqual(
      rateGroup([1430, 468, 2658]),
      ['+1.40 KB/day', '+0.46 KB/day', '+2.60 KB/day'],
    );
    // A group entirely under a kilobyte stays in bytes rather than rounding
    // itself away.
    assert.deepEqual(rateGroup([468, 120, 900]), ['+468 B/day', '+120 B/day', '+900 B/day']);
  });
});
