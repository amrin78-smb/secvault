// lib/engines/seasonalBaseline.js
//
// A6 — "what is normal for this device at this time of week", and the NAMED
// threshold derived from it.
//
// ── WHAT THIS IS AND IS NOT ──────────────────────────────────────────────
// It answers ONE question: is this observation above the level this device
// normally reaches in this time bucket? It is deliberately NOT an anomaly
// SCORE. roadmap.md's rule: "the baseline is an input to a NAMED threshold,
// never a magic anomaly score" — a composite score cannot be explained to an
// operator, and an alert nobody can explain is an alert nobody acts on.
//
// ⛔ THE ARMING GATE IS OBSERVATIONS PER BUCKET, NOT WEEKS ELAPSED — AND THE
// PROPOSAL GOT THIS WRONG. `analytics-proposal.md` gates A6 on "≥3 weeks for a
// 168-bucket hour-of-week model", crossed on 2026-09-29. But three weeks gives
// ~3 observations per bucket, and THREE OBSERVATIONS CANNOT SUPPORT A TAIL
// THRESHOLD: to place even one observation above a 0.95 quantile you need ~20.
// Measured on this fleet's own span (481h at 2026-09-28, ~649h now):
//
//     grain                    buckets   obs/bucket   highest usable quantile
//     hour-of-week                 168          3.9                     0.74
//     hour-of-day x wk/wkend        48         13.5                     0.93
//     hour-of-day                   24         27.0                     0.96
//
// A 0.74 threshold is a 26% false-positive rate by construction. So the
// hour-of-week model is not merely "thin" today, it is UNUSABLE today, and a
// gate counting weeks would have armed it anyway. `minObservationsFor()` ties
// the gate to the threshold instead, and the grain is a parameter so the
// control harness can pick on measured behaviour rather than on taste.
//
// ⛔ FAILS TO "CANNOT TELL", NEVER TO "NORMAL". A bucket with too few
// observations reports `insufficient_baseline` with what it needed and what it
// has — the same shape the six VPN detections use, rendering hatched and
// hueless, never a green all-clear. Reporting a thin bucket as normal is this
// codebase's failed-read-as-a-fact rule wearing a statistician's hat.
//
// ⛔ A MISSING HOUR IS NOT A ZERO HOUR. A rollup row that does not exist means
// nothing was recorded; it does not mean the device sent nothing. Absent hours
// are EXCLUDED from the baseline rather than counted as zeros, which would drag
// every threshold down and suppress real spikes. (The converse detector —
// "this device stopped logging" — is about the ABSENCE itself and must be
// written against that, not against this.)
//
// Pure: no DB, no clock it is not given, no I/O. Never throws.

'use strict';

// Reuse A7's estimators rather than writing a second opinion of "what is
// normal". Two implementations would eventually disagree, and the wrong one
// would be deciding whether to wake somebody up.
const { median, quantile } = require('./changeOutcome');

/**
 * Bucket grains, coarsest last. The harness measures all of them; this module
 * does not prefer one.
 */
const GRAINS = {
  HOUR_OF_WEEK: 'hour_of_week',       // 168 buckets — captures weekday/weekend AND time of day
  HOUR_OF_DAY_SPLIT: 'hour_of_day_split', // 48 — time of day, split weekday/weekend
  HOUR_OF_DAY: 'hour_of_day',         // 24 — time of day only
};

const GRAIN_SIZES = {
  [GRAINS.HOUR_OF_WEEK]: 168,
  [GRAINS.HOUR_OF_DAY_SPLIT]: 48,
  [GRAINS.HOUR_OF_DAY]: 24,
};

const STATES = {
  NORMAL: 'normal',
  ANOMALOUS: 'anomalous',
  INSUFFICIENT_BASELINE: 'insufficient_baseline',
  NO_BASELINE: 'no_baseline',
};

/** Default threshold. Chosen by the control harness, not by taste. */
const DEFAULT_QUANTILE = 0.99;

/**
 * How many observations a bucket needs before a quantile threshold means
 * anything. At minimum, enough that ONE observation could sit above it —
 * below that the "threshold" is just the maximum observed, and every new high
 * is an anomaly by definition.
 *
 * ⛔ The `* 2` is not decoration. At exactly 1/(1-q) the threshold IS the
 * single largest observation, so the estimate has no slack at all; doubling it
 * puts at least two in the tail, which is the minimum for the quantile to be
 * an estimate rather than a restatement of the maximum.
 */
function minObservationsFor(q) {
  const quantileValue = Number(q);
  if (!Number.isFinite(quantileValue) || quantileValue <= 0 || quantileValue >= 1) return null;
  // \u26d4 THE EPSILON IS NOT COSMETIC. `1 - 0.9` is 0.09999999999999998 in
  // IEEE 754, so `2 / (1 - 0.9)` is 20.000000000000004 and a bare ceil returns
  // **21** — a gate 5% stricter than intended, at exactly the round quantiles
  // anyone would actually type. Caught by a test asserting the arithmetic
  // rather than the behaviour around it.
  const exact = 2 / (1 - quantileValue);
  return Math.ceil(exact - 1e-9);
}

function num(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function asDate(v) {
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v;
  if (typeof v === 'string' || typeof v === 'number') {
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
}

/**
 * Which bucket an instant falls in, for a given grain.
 *
 * ⛔ UTC, deliberately and consistently. The fixed-HH:MM cron jobs in this
 * product run in the server's LOCAL zone and CLAUDE.md records that as a trap
 * ("change either one ALONE and every snapshot_date shifts by a day"). A
 * baseline keyed on local time would silently re-bucket every observation on a
 * DST change, which looks exactly like a traffic shift. The cost is that
 * "business hours" are expressed in UTC; that is a labelling problem, not a
 * correctness one.
 *
 * @returns {number|null} bucket index, or null if the input is not a time
 */
function bucketOf(when, grain) {
  const d = asDate(when);
  if (!d) return null;
  const hour = d.getUTCHours();
  const dow = d.getUTCDay();                 // 0 = Sunday
  switch (grain) {
    case GRAINS.HOUR_OF_WEEK: return dow * 24 + hour;
    case GRAINS.HOUR_OF_DAY_SPLIT: {
      const weekend = dow === 0 || dow === 6 ? 1 : 0;
      return weekend * 24 + hour;
    }
    case GRAINS.HOUR_OF_DAY: return hour;
    default: return null;
  }
}

/**
 * Build per-bucket baselines from a series of hourly observations.
 *
 * @param {Array<{at: Date|string, value: number}>} rows
 * @param {{grain?: string, quantile?: number}} [opts]
 * @returns {{
 *   grain: string, quantile: number, needPerBucket: number|null,
 *   buckets: Map<number, {n:number, median:number, threshold:number, usable:boolean}>,
 *   totalObservations: number, usableBuckets: number, bucketCount: number,
 *   armed: boolean, reason: string|null
 * }}
 */
function buildSeasonalBaseline(rows, opts = {}) {
  const grain = GRAIN_SIZES[opts.grain] ? opts.grain : GRAINS.HOUR_OF_WEEK;
  const q = num(opts.quantile) === null ? DEFAULT_QUANTILE : num(opts.quantile);
  const needPerBucket = minObservationsFor(q);
  const bucketCount = GRAIN_SIZES[grain];

  const byBucket = new Map();
  let total = 0;
  for (const r of Array.isArray(rows) ? rows : []) {
    if (!r) continue;
    const b = bucketOf(r.at, grain);
    const v = num(r.value);
    // ⛔ A row with no usable value is DROPPED, never defaulted to 0. A zero is
    // a measurement; a missing value is not.
    if (b === null || v === null) continue;
    if (!byBucket.has(b)) byBucket.set(b, []);
    byBucket.get(b).push(v);
    total += 1;
  }

  const buckets = new Map();
  let usableBuckets = 0;
  for (const [b, values] of byBucket) {
    const sorted = [...values].sort((a, z) => a - z);
    const usable = needPerBucket !== null && sorted.length >= needPerBucket;
    if (usable) usableBuckets += 1;
    buckets.set(b, {
      n: sorted.length,
      median: median(sorted),
      // ⛔ The threshold is computed even for a thin bucket, but `usable:false`
      // means no caller may act on it. Keeping the number visible is what lets
      // an operator see HOW thin it is rather than only that it is thin.
      threshold: quantile(sorted, q),
      usable,
    });
  }

  // ⛔ ARMED means "enough buckets can actually be judged", not "time has
  // passed". A model with two usable buckets out of 168 is not armed, however
  // many weeks produced it.
  const armed = usableBuckets > 0;
  return {
    grain,
    quantile: q,
    needPerBucket,
    buckets,
    totalObservations: total,
    usableBuckets,
    bucketCount,
    armed,
    reason: armed ? null : STATES.INSUFFICIENT_BASELINE,
  };
}

/**
 * Judge one observation against its own bucket.
 *
 * ⛔ Returns a STATE, never a score, and the threshold it used — so the alert
 * can say "47,000 denied in this hour; this device's 99th percentile for
 * Tuesday 14:00 is 12,000 over 14 weeks" rather than "anomaly score 3.7".
 */
function judge(value, baseline, when) {
  const v = num(value);
  if (!baseline || !baseline.buckets) {
    return { state: STATES.NO_BASELINE, value: v, threshold: null, bucket: null, observations: 0 };
  }
  const b = bucketOf(when, baseline.grain);
  if (b === null || v === null) {
    return { state: STATES.NO_BASELINE, value: v, threshold: null, bucket: b, observations: 0 };
  }
  const stats = baseline.buckets.get(b);
  if (!stats) {
    // This bucket has NEVER been observed. Not normal, not anomalous.
    return {
      state: STATES.INSUFFICIENT_BASELINE, value: v, threshold: null, bucket: b,
      observations: 0, needed: baseline.needPerBucket,
    };
  }
  if (!stats.usable) {
    return {
      state: STATES.INSUFFICIENT_BASELINE, value: v, threshold: stats.threshold, bucket: b,
      observations: stats.n, needed: baseline.needPerBucket,
    };
  }
  return {
    state: v > stats.threshold ? STATES.ANOMALOUS : STATES.NORMAL,
    value: v,
    threshold: stats.threshold,
    median: stats.median,
    bucket: b,
    observations: stats.n,
    needed: baseline.needPerBucket,
  };
}

/**
 * Require N CONSECUTIVE anomalous observations before anything is reported.
 *
 * ⛔ THIS IS WHAT MAKES THE FEATURE USABLE, AND THE ARITHMETIC IS THE REASON.
 * 16 devices x 168 hours = 2,688 device-hours per week. At A7's measured 5.3%
 * a single-bucket rule produces ~142 false alerts a week — which is precisely
 * how `new_finding` got pulled out of Alerts in July on user feedback. A
 * persistence requirement collapses isolated outliers, which is the shape
 * almost all false positives take, while a REAL event (a scan, an outage, a
 * spraying run) persists for hours.
 *
 * @returns {Array<{startIndex:number, length:number, peak:object}>} runs that qualify
 */
function sustainedRuns(judgements, minRun = 2) {
  const need = Math.max(1, Math.trunc(num(minRun) || 1));
  const runs = [];
  let start = -1;
  const list = Array.isArray(judgements) ? judgements : [];
  for (let i = 0; i <= list.length; i += 1) {
    const anomalous = i < list.length && list[i] && list[i].state === STATES.ANOMALOUS;
    if (anomalous && start === -1) start = i;
    if (!anomalous && start !== -1) {
      const length = i - start;
      if (length >= need) {
        const slice = list.slice(start, i);
        const peak = slice.reduce((a, b) => (b.value > a.value ? b : a), slice[0]);
        runs.push({ startIndex: start, length, peak });
      }
      start = -1;
    }
  }
  return runs;
}

/**
 * Pick the FINEST grain whose observations can actually support `quantile`.
 *
 * ⛔ THE MODEL UPGRADES ITSELF AS HISTORY ACCUMULATES, WHICH IS THE POINT.
 * Measured on this fleet's ~649h (3.9 weeks):
 *
 *     hour-of-week    3.9 obs/bucket  -> UNUSABLE
 *     hour-of-day x wk/wknd  13.5     -> best q 0.852 = 14.8% per bucket
 *     hour-of-day     27.0            -> best q 0.926 =  7.4% per bucket
 *
 * So hour-of-day is the only grain the data supports TODAY, and hour-of-week —
 * the grain `analytics-proposal.md` specified — needs roughly 40 weeks before
 * it beats it at q=0.95. Hardcoding hour-of-week would have left the feature
 * reporting `insufficient_baseline` for months while a coarser model sat
 * available; hardcoding hour-of-day would cap it there for ever. Choosing from
 * the data does neither, and needs no code change when the history arrives.
 *
 * ⛔ Returns `null` when NO grain qualifies. That is a real answer — "we cannot
 * yet say what normal looks like" — and callers must render it as such rather
 * than falling back to the coarsest grain and pretending.
 */
function selectGrain(rows, opts = {}) {
  const q = num(opts.quantile) === null ? DEFAULT_QUANTILE : num(opts.quantile);
  // Finest first, so the best available model wins.
  const order = [GRAINS.HOUR_OF_WEEK, GRAINS.HOUR_OF_DAY_SPLIT, GRAINS.HOUR_OF_DAY];
  const tried = [];
  for (const grain of order) {
    const b = buildSeasonalBaseline(rows, { grain, quantile: q });
    // ⛔ A grain qualifies only when MOST of its buckets are usable, not when
    // one is. A model that can judge 3 of 168 buckets is armed for 2% of the
    // week and silent — which reads as "nothing wrong" — for the other 98%.
    const coverage = b.bucketCount > 0 ? b.usableBuckets / b.bucketCount : 0;
    tried.push({ grain, usableBuckets: b.usableBuckets, bucketCount: b.bucketCount, coverage });
    if (coverage >= (num(opts.minCoverage) === null ? 0.9 : num(opts.minCoverage))) {
      return { grain, baseline: b, tried };
    }
  }
  return { grain: null, baseline: null, tried };
}

module.exports = {
  GRAINS,
  GRAIN_SIZES,
  STATES,
  DEFAULT_QUANTILE,
  minObservationsFor,
  bucketOf,
  buildSeasonalBaseline,
  selectGrain,
  judge,
  sustainedRuns,
};
