'use strict';

// lib/engines/capacityForecast.js
//
// TIER 2 — CAPACITY PLANNING / BANDWIDTH TREND.
//
// Pure: a per-device daily byte series in, a trend and (sometimes) a projection
// out. No pool, no queries, no clock it is not handed. The plumbing is
// `capacityForecastData.js`.
//
// ── ⛔ MEASURED FIRST, ON THE LIVE FLEET (2026-11-12, read-only) ───────────
//
// 16 active firewalls. `syslog_rollup_hourly` spans 2026-09-08 → 2026-11-12,
// 66 day buckets, 251,380 rows. What actually carries summable bytes:
//
//   forecastable (paloalto, complete byte-days / total / median GB/day)
//     SMT           65/66   1630.01      TFM-MH        60/66    405.00
//     TUM(TUTH1)    64/66   1559.23      TFM-RN        58/62    170.08
//     ITC-SK        65/66    843.06      IDC FW        65/66    105.44
//     TUG           65/66    723.79      ITC-SLY       65/66     19.42
//     TUFF(TUTH3)   65/66      3.13      HRIS          65/66      0.0024
//
//   ⛔ NOT forecastable, FOR TWO DIFFERENT REASONS THAT MUST NEVER BE COLLAPSED
//     bytes_not_summable  TSR_EKC, TSR_EKM, TSR-TL, OKF(F2), Vietnam-YCC
//                         — 5 Fortinets. Measured over ALL the history held,
//                         rollup rows against byte-bearing rows: 21,378/0 ·
//                         44,706/0 · 26,763/0 · 45,107/0 · 25,002/0. They log
//                         heavily and have never produced one summable byte
//                         count. FortiOS logs a long-lived session repeatedly
//                         with a CUMULATIVE counter, so summing double-counts
//                         (lib/schema.sql's bytes_summable note measured 55 Gbps
//                         implied on TSR_EKM from two hours). The ingest flag
//                         excludes them and MUST KEEP excluding them. This is a
//                         PERMANENT property of the vendor's log format.
//     no_log_coverage     PAKFood — a paloalto with 0 rollup rows, full stop.
//                         It is fully collected over its management API and
//                         sends no syslog (roadmap A2 records the same
//                         firewall). This is a COLLECTION GAP and it can clear.
//
//   For contrast, the ten that CAN be measured, same two figures: HRIS
//   5,198/1,569 · IDC FW 7,832/1,571 · ITC-SK 15,407/1,570 · ITC-SLY
//   3,171/1,569 · SMT 18,822/3,403 · TFM-MH 8,929/4,444 · TFM-RN 5,034/2,808 ·
//   TUFF(TUTH3) 8,547/1,571 · TUG 3,792/3,691 · TUM(TUTH1) 11,702/4,694.
//
//   ⛔ The spread across the forecastable ten is 1630 GB/day down to 0.0024
//   GB/day — a factor of ~680,000 on the daily medians, 94.9 TB to 181 MB on
//   the totals. A fleet-wide aggregate over that is arithmetic with no
//   meaning: the per-device grain is the only honest one, and there is
//   deliberately no fleet bandwidth figure anywhere in this engine.
//
// ── ⛔ WHAT THE ESTIMATOR IS, AND WHAT WAS MEASURED AND REJECTED ───────────
//
// Theil–Sen (median of pairwise slopes) for the MAGNITUDE, Mann–Kendall for the
// DIRECTION, and Sen's own distribution-free interval — built from MK's
// variance — for the uncertainty. The two agree by construction: the interval
// excludes zero exactly when MK rejects, so this engine cannot print a
// direction its own interval contradicts. Verified on all ten forecastable
// firewalls (`agree` true for every one).
//
// ⛔ LEAST SQUARES IS OUT, for the reason changeOutcome.js already records:
// this traffic is heavy-tailed. Measured p90 of ABSOLUTE day-over-day change
// on the forecastable ten: HRIS 8.4%, TFM-RN 63.0%, TFM-MH 77.2%, ITC-SLY
// 167.1%, TUFF 192.1%, TUM 272.8%, TUG 395.7%, ITC-SK 420.1%, IDC FW 2585.0%,
// SMT 3328.8%. A single spike at 3328% moves an OLS slope permanently.
//
// ⛔ AND THE NAIVE ROBUST BAND WAS MEASURED AND REJECTED TOO. The first draft
// bounded the slope with the 10th–90th percentile of the pairwise slopes, which
// is robust, obvious, and far too wide: short-lag pairs divide a huge day-over-
// day swing by one day, so that band straddled zero on ALL TEN firewalls,
// including the two where a trend is genuinely resolvable. ⛔ A detector that
// cannot fire on any device in the fleet it was measured against is the
// guard-that-cannot-fire pattern, and it would have shipped looking careful.
// Sen's interval uses ORDER STATISTICS chosen by MK's variance — M1 = (N − C)/2
// with C = z·√Var(S) — which on 65 days reads the 41.7th–58.3rd percentile of
// the same 2,080 slopes instead of the 10th–90th.
//
// ── ⛔ THE CONTROL. MK'S CALIBRATION WAS NOT ASSUMED, IT WAS MEASURED ──────
//
// MK's normal approximation assumes independent observations, and daily traffic
// is autocorrelated — so the published 5% could have been a fiction here. Each
// firewall's own daily values were SHUFFLED (trend destroyed, distribution
// kept) and the test re-run, 40 reps per device, at five window lengths:
//
//   window  shuffled control fires   real sliding windows fire
//     10d          4.3%                      3.5%
//     13d          4.6%                      8.1%
//     20d          4.1%                     10.3%
//     30d          6.1%                      8.1%
//     45d          6.0%                     18.3%
//
// ⛔ The control sits at 4.1–6.1% against a nominal 5% at EVERY length, so MK
// is calibrated on this data and no inflation factor is warranted. (Measured
// lag-1 autocorrelation of daily bytes: 0.01–0.30, which is why.) The real
// windows fire MORE often and more often with more history — the shape a weak
// genuine signal makes, and the reason the gate below is about the ESTIMATOR
// rather than about power.
//
// ── ⛔ THE HONEST RESULT ON THIS FLEET TODAY ───────────────────────────────
//
// EIGHT of the ten forecastable firewalls report `no_detectable_trend` over 65
// days. Only TUFF(TUTH3) (+0.0508 GB/day, interval [0.016, 0.088]) and HRIS
// (tiny but consistent) have a direction this much history can separate from
// their own variation. That is the answer, not a failure of the feature —
// SMT's trend is +4.7% over the window against a p90 daily swing of 3328%.
// A8's note applies: its honest first output IS the finding.
//
// ⛔ SO THE COMMON VERDICT IS "NO DETECTABLE TREND", AND IT IS NOT "FLAT" AND
// NOT ZERO GROWTH. The slope and the growth figure are still REPORTED — they
// are real measurements — and only the PROJECTION is withheld, because
// extending an unresolved direction to a date is the overclaim this whole file
// exists to refuse. That is changeOutcome.js's own split: report the delta,
// withhold the judgement.
//
// ── ⛔ A DEPLOY GAP IS NOT A TRAFFIC DROP ──────────────────────────────────
//
// CLAUDE.md measures collector downtime at 144–182s per deploy, during which
// nothing is listening on 514 and UDP datagrams are discarded by the OS — at
// 381–1,280 events/sec that is 18,000–60,000 events lost, permanently, per
// deploy. A dip in bytes may therefore be OUR outage rather than the customer's
// traffic falling, and a slope fitted across it UNDERSTATES growth.
//
// The rule: a day is an observation only if it has COMPLETE_DAY_HOURS hourly
// buckets that carry bytes. Partial days are COUNTED and EXCLUDED, never used
// as a low observation. Measured cost on this fleet: 1 day for seven firewalls
// (2026-09-08, when the collector started at 14:00 and only 10 hours exist),
// 2 for TUM(TUTH1), 4 for TFM-RN, 6 for TFM-MH — and TFM-RN's last bucket is
// 2026-11-08 17:00, so without this rule its four most recent days would have
// read as a collapse to near-zero on a firewall that simply stopped being
// heard from.
//
// ⛔ AND THE RULE IS WORTH A GREAT DEAL — MEASURED, not assumed. Re-running the
// shipped engine over the same production rows with partial days COUNTED as
// real days instead of excluded:
//
//   TFM-RN   +0.0141 → −0.0625 GB/day   543%  ⛔ A SIGN FLIP
//   TFM-MH   −0.3640 → −1.5504 GB/day   326%  (4x, level −12.1%)
//   TUG      +0.1179 → +0.4194 GB/day   256%
//   ITC-SLY  −0.0396 → −0.0241 GB/day    39%
//   IDC FW   −0.0309 → −0.0098 GB/day    69%
//   ITC-SK   +1.5725 → +1.9231 GB/day    22%
//
// TFM-RN's day 48 holds 3 hours and 13.3 GB against a ~180 GB typical day — a
// 13x understatement that is entirely ours — and counting it reverses the
// direction this page would print for that firewall.
//
// ⛔ A 170-SECOND DEPLOY DOES NOT ITSELF DROP AN HOUR BUCKET — it depresses one
// hour by ~5%, i.e. ~0.2% of a day, which is three orders of magnitude inside
// the noise above. The completeness rule catches the gaps that MATTER (a whole
// hour missing, a device that went quiet) and does not pretend to correct the
// ones that do not. Stating that is the point; silently "repairing" a 0.2%
// shortfall would be inventing data.
//
// ⛔ AND DO NOT TRY TO SHOW THIS WITH A SYNTHETIC SERIES. Two were written and
// both were degenerate: a clean ramp puts every pairwise slope on one value and
// a perfectly alternating series makes the distribution symmetric about zero,
// so neither can move a median and a test built on either PASSES WHILE PROVING
// NOTHING (it did). `tests/capacityForecast.test.js` embeds TFM-RN's real 62
// buckets instead — the convention this codebase already applies to the syslog
// parsers, for exactly this reason.
//
// ⛔ A MISSING DAY IS NOT A ZERO DAY. Absent days are simply absent from the
// series — never filled with 0, which would manufacture a cliff. And the slope
// is fitted against each day's REAL day index, so a hole in the middle of the
// window shortens the evidence without distorting the rate.
//
// ⛔ GROWTH NEVER TRAVELS AS A BARE PERCENTAGE. Every growth figure is returned
// beside `windowDays` — the number of complete days it was measured over — and
// the renderer is required to print them together. "+12%" means nothing; "+12%
// across the 64 complete days measured" is checkable.

const { median, quantile } = require('./changeOutcome');
const { minObservationsFor } = require('./seasonalBaseline');

// ── Constants that may not drift without a decision ────────────────────────

/**
 * How many hourly buckets a day must carry bytes in before it is an
 * observation. 24, and deliberately not 23-or-so: see the deploy-gap note
 * above for why a tolerance would be inventing data rather than allowing for
 * it.
 */
const COMPLETE_DAY_HOURS = 24;

/**
 * The two-sided level the direction test and the interval share.
 *
 * ⛔ ONE NUMBER FOR BOTH, which is what makes them agree by construction. The
 * control above measures what it actually costs on this data (4.1–6.1%), so
 * this is a measured false-positive rate rather than a hoped-for one.
 */
const ALPHA = 0.05;

/** The standard normal two-sided critical value for ALPHA. */
const Z_CRITICAL = 1.959963984540054;

/**
 * The quantile whose resolution the arming gate is derived from.
 *
 * ⛔ NOT the interval's own percentile — that is computed from MK's variance
 * and moves with n. This is the quantile `minObservationsFor` is asked about,
 * i.e. how much slack the lower bound of the interval must have beneath it
 * before it is an ESTIMATE rather than a restatement of the smallest slope
 * observed.
 */
const SLOPE_BAND_QUANTILE = 0.9;

/**
 * ⛔ THE ARMING GATE IS DERIVED FROM THE ESTIMATOR, NOT PICKED — the rule
 * `seasonalBaseline.minObservationsFor` exists to enforce, and the rule
 * CLAUDE.md records A6 getting wrong first (a 3-week gate would have armed a
 * model whose best usable quantile was 0.74, a 26% false-positive rate by
 * construction).
 *
 * The decision this engine makes is read off the M1-th order statistic of the
 * N = n(n−1)/2 sorted pairwise slopes, where M1 = (N − z·√Var(S)) / 2. For that
 * bound to be an interior estimate it needs at least
 * `minObservationsFor(SLOPE_BAND_QUANTILE)` = 20 slopes below it — the same
 * "at least two in the tail, never one" arithmetic that function encodes.
 * Solving M1 ≥ 20:
 *
 *     n=10  N=45   C=21.9  M1=11     n=13  N=78   C=32.1  M1=22  ← first pass
 *     n=11  N=55   C=25.2  M1=14     n=14  N=91   C=35.8  M1=27
 *     n=12  N=66   C=28.6  M1=18     n=20  N=190  C=60.4  M1=64
 *
 * ⛔ IT COUNTS DAYS, NOT PAIRS, and that is the half the obvious version gets
 * wrong. Twenty pairwise slopes are reached at n=7, but pairwise slopes are not
 * independent observations — seven days cannot support a 20-observation claim,
 * and counting the pairs would arm the model at 7 days while appearing to
 * satisfy a 20-observation gate. Days are the independent unit.
 *
 * ⛔ AND IT IS A GATE ON THE ARITHMETIC, NOT A PROMISE OF POWER. 13 days of
 * this fleet's noise resolves almost nothing, and that is correct: the gate
 * stops the interval being theatre, and the TEST — not the gate — refuses a
 * trend it cannot separate from the variation. Measured: at 13 days the
 * shuffled control fires 4.6%, matching the nominal 5%.
 */
function minHistoryDays(bandQuantile = SLOPE_BAND_QUANTILE, alpha = ALPHA) {
  const needed = minObservationsFor(bandQuantile);
  if (needed === null) return null;
  const z = alpha === ALPHA ? Z_CRITICAL : null;
  if (z === null) return null;
  for (let n = 3; n <= 400; n += 1) {
    const N = (n * (n - 1)) / 2;
    const varS = (n * (n - 1) * (2 * n + 5)) / 18;
    const C = z * Math.sqrt(varS);
    if (Math.floor((N - C) / 2) >= needed) return n;
  }
  return null;
}

/** 13 on the shipped constants. Computed, never typed. */
const MIN_HISTORY_DAYS = minHistoryDays();

/**
 * How far back the series is read.
 *
 * ⛔ DELIBERATELY NOT `evidenceWindow.resolveLogEvidenceWindow()`. That window
 * is the ONE definition of how far rule-usage evidence reaches, shared by seven
 * surfaces so the register agrees with the pages it indexes, and its 30-day
 * FLOOR is a no-regression guarantee for the rule-cleanup loop. Reusing it here
 * would couple a bandwidth trend to whether a rule may be deleted, and a change
 * made for one would silently move the other. Different question, own bound,
 * stated.
 *
 * ⛔ IT IS ALSO A COST BOUND, AND THAT IS NOT OPTIONAL. `syslog_rollup_hourly`
 * is PERMANENT, and Theil–Sen is O(n²) in days: at 365 days this is 66,430
 * pairwise slopes, at ten years it would be 6.6 million allocated and sorted on
 * a page render.
 */
const DEFAULT_LOOKBACK_DAYS = 90;
const MAX_LOOKBACK_DAYS = 365;

/**
 * The projection horizon.
 *
 * ⛔ CAPPED AT THE HISTORY IT IS FITTED FROM, always. Projecting 90 days from
 * 65 days of observations extends the evidence further than the evidence
 * reaches, and the cap is reported (`horizonCapped`) rather than applied
 * silently.
 */
const DEFAULT_HORIZON_DAYS = 30;
const MAX_HORIZON_DAYS = 365;

const STATES = Object.freeze({
  // A direction this much history can separate from the firewall's own daily
  // variation. These two are the ONLY states that carry a projection.
  RISING: 'rising',
  FALLING: 'falling',
  // ⛔ The common answer. NOT "flat", NOT zero growth, NOT an all-clear: the
  // slope is reported and the projection is withheld.
  NO_DETECTABLE_TREND: 'no_detectable_trend',
  // Fewer than MIN_HISTORY_DAYS complete days. Reports what it needed beside
  // what it has, hatched and hueless.
  INSUFFICIENT_HISTORY: 'insufficient_history',
  // ⛔ THE TWO "CANNOT FORECAST" REASONS, KEPT APART ON PURPOSE. They send an
  // operator to different places and one of them can never clear.
  BYTES_NOT_SUMMABLE: 'bytes_not_summable',   // vendor's counters; permanent
  NO_LOG_COVERAGE: 'no_log_coverage',         // nothing received; a gap
});

/** Which states mean "SecVault cannot forecast this firewall at all". */
const UNFORECASTABLE_STATES = Object.freeze([
  STATES.BYTES_NOT_SUMMABLE,
  STATES.NO_LOG_COVERAGE,
]);

// ⛔ ONE SENTENCE, EXPORTED, AND IT IS THE CLAIM — the pattern IMPACT_CLAIM and
// COVERAGE_CLAIM already establish. A test rejects the overclaiming vocabulary
// from it and from every other string this engine can emit, so a later edit
// cannot quietly turn a projection into a promise.
const FORECAST_CLAIM =
  'SecVault measures the daily traffic volume each firewall’s own logs account for, and reports '
  + 'the trend across the window it measured. A projection states where that measured trend '
  + 'reaches by a given date if nothing changes; it is not a statement about future demand, it '
  + 'accounts for nothing SecVault cannot see, and a firewall whose trend cannot be separated '
  + 'from its own day-to-day variation is given no projection at all.';

// ⛔ WORDED AS A PERMANENT PROPERTY OF THE LOG FORMAT, because it is one. An
// operator must not go looking for a setting to change.
const NOT_SUMMABLE_REASON =
  'This firewall is sending logs, but none of them carry a byte count that can be added up. '
  + 'FortiOS reports a long-lived session repeatedly with a running total, so summing those '
  + 'figures counts the same traffic many times over — SecVault excludes them at ingest rather '
  + 'than publishing a number that is wrong by a large multiple. Nothing on the firewall can '
  + 'change this, and no bandwidth trend is available for it.';

// ⛔ A DIFFERENT SENTENCE WITH A DIFFERENT FIRST STEP. This one can clear.
const NO_COVERAGE_REASON =
  'SecVault holds no traffic logs at all for this firewall, so there is nothing to measure a '
  + 'trend from. That is a collection gap rather than a limit of the vendor: check that the '
  + 'firewall is forwarding syslog to this server and that the collector is reachable on its '
  + 'syslog port.';

const UNMEASURED_REASON =
  'Not measured. A figure is absent here because SecVault could not read it, which is not the '
  + 'same as the figure being zero.';

// ── helpers ────────────────────────────────────────────────────────────────

/**
 * ⛔ `pg` HANDS BACK A `bigint`/`numeric` SUM AS A STRING rather than silently
 * truncating past 2^53, and `Number(null)` is 0. Both shapes go through here so
 * SQL NULL — the one value that must never become a number — stays null.
 */
function num(v) {
  if (v === null || v === undefined || v === '') return null;
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
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

const DAY_MS = 24 * 3600 * 1000;

/** Whole days since the epoch — the x axis the slope is fitted against. */
function dayIndex(d) {
  return Math.floor(d.getTime() / DAY_MS);
}

function round(v, places) {
  if (v === null || !Number.isFinite(v)) return null;
  const f = 10 ** places;
  return Math.round(v * f) / f;
}

function clampInt(v, lo, hi, fallback) {
  const n = num(v);
  if (n === null) return fallback;
  const whole = Math.trunc(n);
  if (whole < lo || whole > hi) return fallback;
  return whole;
}

// ── the estimator ──────────────────────────────────────────────────────────

/**
 * Theil–Sen slope, Mann–Kendall direction test and Sen's distribution-free
 * interval, over points already known to be complete observations.
 *
 * ⛔ THE INTERVAL AND THE DIRECTION COME FROM THE SAME Var(S), which is what
 * makes them agree. Verified on all ten forecastable firewalls: the interval
 * excludes zero exactly where |Z| > z, with no device disagreeing.
 *
 * ⛔ TIES CONTRIBUTE sign() === 0 TO S, which is Mann–Kendall's own handling.
 * The variance is NOT tie-corrected: daily byte totals are effectively
 * continuous (ten firewalls, 643 observations, no repeated value), so the
 * correction term would be zero and implementing it would be untested code on
 * a path nothing reaches.
 *
 * ⛔ THE x AXIS IS RE-BASED TO THE FIRST OBSERVED DAY, AND THIS IS NOT
 * COSMETIC. A raw day index is ~20,769 (days since the epoch), so an intercept
 * fitted at t=0 sits fifty-six years before the data. The first draft of this
 * engine built its projection range by holding that intercept and swapping the
 * slope for each end of the interval — which moves the line by
 * (Δslope × 20,769) at the data, and produced a published range of
 * **[0.00, 772.24] GB/day** on TUFF(TUTH3) around a point projection of 6.81.
 * A confident, plausible, catastrophically wrong number, caught only by reading
 * the real fleet's output. Re-basing also removes the catastrophic cancellation
 * in `y − slope·t` at that magnitude.
 *
 * @param {Array<{t: number, y: number}>} points  t = day index, y = bytes
 * @returns {{slopePerDay, lowPerDay, highPerDay, s, z, pairs, increasingShare,
 *            levelAtEnd}|null}
 */
function senTrend(points) {
  const n = Array.isArray(points) ? points.length : 0;
  if (n < 2) return null;

  const slopes = [];
  let s = 0;
  for (let i = 0; i < n; i += 1) {
    for (let j = i + 1; j < n; j += 1) {
      const dt = points[j].t - points[i].t;
      // ⛔ Two observations sharing a day index cannot yield a slope. Dropped
      // from the SLOPE, and still counted by S, which only looks at order.
      s += Math.sign(points[j].y - points[i].y);
      if (dt !== 0) slopes.push((points[j].y - points[i].y) / dt);
    }
  }
  if (!slopes.length) return null;
  slopes.sort((a, b) => a - b);

  const pairs = slopes.length;
  const varS = (n * (n - 1) * (2 * n + 5)) / 18;
  const sd = Math.sqrt(varS);
  // MK's continuity correction: S is a sum of signs and so is discrete.
  const z = (s === 0 || sd === 0) ? 0 : (s - Math.sign(s)) / sd;

  const slope = median(slopes);

  // Sen's interval: the order statistics either side of the median that
  // Var(S) places the critical value at.
  const C = Z_CRITICAL * sd;
  const m1 = Math.floor((pairs - C) / 2);
  const m2 = Math.ceil((pairs + C) / 2);
  const low = slopes[Math.min(Math.max(m1 - 1, 0), pairs - 1)];
  const high = slopes[Math.min(Math.max(m2 - 1, 0), pairs - 1)];

  // ⛔ THE CANONICAL THEIL–SEN ANCHOR, not "the median of the last few days".
  // A second window length would be a second arbitrary choice, and it would be
  // the one deciding where a projection starts from. Fitted on the re-based
  // axis, so the intercept is the line's value on the FIRST observed day.
  const t0 = points[0].t;
  const tEnd = points[points.length - 1].t;
  const intercept = median(
    points.map((p) => p.y - slope * (p.t - t0)).sort((a, b) => a - b),
  );

  const totalPairs = (n * (n - 1)) / 2;
  return {
    slopePerDay: slope,
    lowPerDay: low,
    highPerDay: high,
    s,
    z,
    pairs,
    // A checkable restatement of S: "of N pairs of days, X% have the later day
    // higher". A reader can verify that; a Z score they must take on trust.
    increasingShare: totalPairs > 0 ? ((s + totalPairs) / 2) / totalPairs : null,
    // ⛔ WHERE THE LINE SITS ON THE LAST OBSERVED DAY — the one and only point a
    // projection may start from, and the point all three slopes pivot about.
    // See the header note for the 772 GB/day artefact that holding an intercept
    // instead produced.
    levelAtEnd: intercept + slope * (tEnd - t0),
  };
}

/**
 * Split a raw daily series into the observations the trend may use and the
 * ones it may not, and say why.
 *
 * @param {Array<{day, byteHours, bytes}>} series
 */
function partitionSeries(series, opts = {}) {
  const completeHours = clampInt(opts.completeDayHours, 1, 24, COMPLETE_DAY_HOURS);
  const rows = (Array.isArray(series) ? series : [])
    .map((r) => ({
      day: asDate(r && r.day),
      byteHours: num(r && r.byteHours),
      bytes: num(r && r.bytes),
    }))
    .filter((r) => r.day !== null)
    .sort((a, b) => a.day - b.day);

  const complete = [];
  let partialDays = 0;
  let unreadableDays = 0;
  let byteBearingDays = 0;

  for (const r of rows) {
    if (r.byteHours === null) {
      // The hour count itself did not arrive. Not a zero, not a partial day.
      unreadableDays += 1;
      continue;
    }
    if (r.byteHours <= 0) continue;        // a day with no summable bytes at all
    byteBearingDays += 1;
    if (r.byteHours < completeHours) {
      // ⛔ A PARTIAL DAY IS NOT A LOW DAY. Counted, excluded, reported.
      partialDays += 1;
      continue;
    }
    // ⛔ A complete day whose BYTES could not be read is still not an
    // observation, and it is not a zero either.
    if (r.bytes === null) {
      unreadableDays += 1;
      continue;
    }
    complete.push(r);
  }

  return {
    complete,
    completeDays: complete.length,
    partialDays,
    unreadableDays,
    byteBearingDays,
    totalDays: rows.length,
    completeDayHours: completeHours,
  };
}

/**
 * The trend, and where it reaches, for ONE firewall.
 *
 * @param {object} device  {deviceId, deviceName, vendor}
 * @param {Array} series   [{day, byteHours, bytes}] — raw, including partials
 * @param {object} [opts]
 * @param {boolean} [opts.hasLogCoverage] does SecVault hold ANY rollup rows for
 *   this firewall? ⛔ REQUIRED to tell `no_log_coverage` from
 *   `bytes_not_summable`; passing it as `undefined` is read as "unknown" and
 *   falls to the gap wording, never to a trend.
 * @param {number} [opts.horizonDays]
 * @param {Date|string} [opts.now]
 */
function forecastDevice(device, series, opts = {}) {
  const d = device && typeof device === 'object' ? device : {};
  const parts = partitionSeries(series, opts);
  const minDays = num(opts.minHistoryDays) || MIN_HISTORY_DAYS;
  const requestedHorizon = clampInt(
    opts.horizonDays, 1, MAX_HORIZON_DAYS, DEFAULT_HORIZON_DAYS,
  );

  const base = {
    deviceId: d.deviceId,
    deviceName: d.deviceName,
    vendor: d.vendor,
    completeDays: parts.completeDays,
    partialDays: parts.partialDays,
    unreadableDays: parts.unreadableDays,
    totalDays: parts.totalDays,
    completeDayHours: parts.completeDayHours,
    neededDays: minDays,
    // Every projection field, present and null, on every shape — so a renderer
    // reading `projectedDailyBytes` on an unforecastable firewall gets null
    // rather than undefined, and a missing key can never read as a zero.
    medianDailyBytes: null,
    trendLevelAtEndBytes: null,
    slopeBytesPerDay: null,
    slopeLowBytesPerDay: null,
    slopeHighBytesPerDay: null,
    growthPctOverWindow: null,
    windowDays: null,
    observedFrom: null,
    observedTo: null,
    spanDays: null,
    increasingShare: null,
    z: null,
    pairs: null,
    horizonDays: null,
    horizonCapped: false,
    projectedDailyBytes: null,
    projectedLowDailyBytes: null,
    projectedHighDailyBytes: null,
    projectedFor: null,
    projected: false,
  };

  // ⛔ ORDER MATTERS AND IS THE POINT OF THIS FUNCTION. "No logs at all" is
  // tested FIRST, because a firewall sending nothing also has no summable
  // bytes, and reporting it as a vendor limitation would blame the wrong thing
  // and send the operator to a problem they cannot fix.
  if (opts.hasLogCoverage !== true) {
    return {
      ...base,
      state: STATES.NO_LOG_COVERAGE,
      reason: NO_COVERAGE_REASON,
      // ⛔ A permanent vendor limit and a clearable gap are told apart by this
      // flag as well as by the state, so a consumer cannot get it wrong by
      // string-matching.
      permanent: false,
    };
  }

  // ⛔ "THE VENDOR'S COUNTERS CANNOT BE SUMMED" IS A CLAIM ABOUT ALL TIME, SO
  // IT MAY NOT BE DECIDED INSIDE THE LOOKBACK WINDOW — a bug found by running
  // this against a real schema rather than a stub. With a 30-day lookback on
  // the local fleet, a firewall holding byte history OLDER than the window
  // reported `bytes_not_summable`: a permanent vendor limitation asserted about
  // a firewall whose logs carry byte counts perfectly well, which is the
  // "two reasons must never be collapsed" rule failing one level further down
  // than it was written for. The honest answer there is
  // `insufficient_history` — the history exists, none of it is usable in this
  // window — so the caller supplies an UNBOUNDED probe, exactly as it does for
  // coverage, and `COVERAGE_SQL` carries both.
  //
  // ⛔ WITH NO PROBE SUPPLIED it falls back to the window, because a caller
  // that did not ask cannot be assumed to have found nothing.
  const summable = opts.hasSummableBytes === undefined
    ? parts.byteBearingDays > 0
    : opts.hasSummableBytes === true;

  if (!summable) {
    return {
      ...base,
      state: STATES.BYTES_NOT_SUMMABLE,
      reason: NOT_SUMMABLE_REASON,
      permanent: true,
    };
  }

  const pts = parts.complete.map((r) => ({ t: dayIndex(r.day), y: r.bytes }));
  const observedFrom = parts.complete.length ? parts.complete[0].day : null;
  const observedTo = parts.complete.length
    ? parts.complete[parts.complete.length - 1].day
    : null;
  const spanDays = (observedFrom && observedTo)
    ? dayIndex(observedTo) - dayIndex(observedFrom) + 1
    : null;

  if (parts.completeDays < minDays) {
    return {
      ...base,
      state: STATES.INSUFFICIENT_HISTORY,
      observedFrom,
      observedTo,
      spanDays,
      reason:
        `A trend needs ${minDays} complete days of traffic for this firewall and `
        + `${parts.completeDays} ${parts.completeDays === 1 ? 'is' : 'are'} available. `
        + 'Nothing here has been measured as flat — it has not been measured.',
      permanent: false,
    };
  }

  const trend = senTrend(pts);
  if (trend === null) {
    return {
      ...base,
      state: STATES.INSUFFICIENT_HISTORY,
      observedFrom,
      observedTo,
      spanDays,
      reason:
        'The complete days available all fall on one date, so no rate of change can be '
        + 'measured from them.',
      permanent: false,
    };
  }

  const level = median([...pts.map((p) => p.y)].sort((a, b) => a - b));
  const windowDays = parts.completeDays;

  // ⛔ DIRECTION FROM THE INTERVAL, NOT FROM THE SIGN OF THE SLOPE. A slope of
  // +1.19 GB/day on SMT has an interval of [−0.68, +5.02]: pairs of days there
  // disagree about the direction, so "rising" would be a coin toss printed as a
  // finding.
  let state = STATES.NO_DETECTABLE_TREND;
  if (trend.lowPerDay > 0 && trend.highPerDay > 0) state = STATES.RISING;
  else if (trend.lowPerDay < 0 && trend.highPerDay < 0) state = STATES.FALLING;

  // ⛔ CAPPED AT THE HISTORY IT IS FITTED FROM, and the cap is disclosed.
  const horizonDays = Math.min(requestedHorizon, windowDays);
  const horizonCapped = horizonDays < requestedHorizon;

  const detectable = state === STATES.RISING || state === STATES.FALLING;

  // ⛔ EVERY SLOPE PIVOTS ABOUT THE SAME POINT — the line's value on the last
  // observed day — so the three projections differ ONLY in the rate applied
  // over the horizon. Varying the slope against a t=0 intercept instead is what
  // produced the 772 GB/day range recorded in `senTrend`'s header.
  const line = (slope) => trend.levelAtEnd + slope * horizonDays;

  // ⛔ A PROJECTION IS NEVER NEGATIVE BYTES, and clamping at zero is a
  // STATEMENT rather than a tidy-up: traffic volume has a floor, so a falling
  // trend reaching it means "this trend runs out before the horizon", which the
  // renderer says in words. It is only reachable on a FALLING firewall.
  const floorAtZero = (v) => (v === null ? null : Math.max(0, v));

  const projectedFor = detectable
    ? new Date(observedTo.getTime() + horizonDays * DAY_MS)
    : null;

  return {
    ...base,
    state,
    reason: detectable
      ? null
      : 'Across the complete days measured, pairs of days disagree about the direction, so no '
        + 'trend can be separated from this firewall’s own day-to-day variation. That is not a '
        + 'measurement of zero growth.',
    permanent: false,
    medianDailyBytes: level,
    // Where the fitted line sits on the last observed day. ⛔ Reported so the
    // projection can be read as a movement FROM something rather than as a
    // free-standing number — and so a reader can see that a projection is the
    // level plus a rate, never a separate model.
    trendLevelAtEndBytes: trend.levelAtEnd,
    slopeBytesPerDay: trend.slopePerDay,
    slopeLowBytesPerDay: trend.lowPerDay,
    slopeHighBytesPerDay: trend.highPerDay,
    // ⛔ NEVER TRAVELS ALONE — `windowDays` is returned beside it and the
    // renderer is required to print the pair.
    growthPctOverWindow: level > 0
      ? round((trend.slopePerDay * windowDays / level) * 100, 1)
      : null,
    windowDays,
    observedFrom,
    observedTo,
    spanDays,
    increasingShare: trend.increasingShare === null
      ? null
      : round(trend.increasingShare * 100, 1),
    z: round(trend.z, 2),
    pairs: trend.pairs,
    horizonDays,
    horizonCapped,
    projectedDailyBytes: detectable ? floorAtZero(line(trend.slopePerDay)) : null,
    projectedLowDailyBytes: detectable ? floorAtZero(line(trend.lowPerDay)) : null,
    projectedHighDailyBytes: detectable ? floorAtZero(line(trend.highPerDay)) : null,
    projectedFor,
    projected: detectable,
  };
}

/**
 * Fleet totals.
 *
 * ⛔ NO FLEET BANDWIDTH FIGURE, NO SCORE, NO PERCENTAGE OF FIREWALLS "HEALTHY".
 * The measured spread across the forecastable ten is ~680,000x on the daily
 * medians, so a fleet sum is dominated entirely by its two largest members and
 * would move with them while reading as a property of the estate.
 *
 * ⛔ AND THE TWO "CANNOT FORECAST" REASONS ARE COUNTED SEPARATELY ALL THE WAY
 * UP. There is deliberately no combined `unavailable` total: one is a permanent
 * property of a vendor's log format and the other is a collection gap somebody
 * can go and fix, and a single number would send an operator to the wrong one.
 */
function summariseForecasts(devices) {
  const list = Array.isArray(devices) ? devices : [];
  const byState = {};
  for (const v of Object.values(STATES)) byState[v] = 0;
  for (const dev of list) byState[dev.state] = (byState[dev.state] || 0) + 1;

  const notSummable = list.filter((d) => d.state === STATES.BYTES_NOT_SUMMABLE);
  const noCoverage = list.filter((d) => d.state === STATES.NO_LOG_COVERAGE);

  return {
    devices: list.length,
    byState,
    projected: list.filter((d) => d.projected).length,
    noDetectableTrend: byState[STATES.NO_DETECTABLE_TREND] || 0,
    insufficientHistory: byState[STATES.INSUFFICIENT_HISTORY] || 0,
    // ⛔ TWO COUNTS, TWO NAME LISTS, NEVER SUMMED INTO ONE.
    bytesNotSummable: notSummable.length,
    bytesNotSummableDevices: notSummable.map((d) => d.deviceName),
    noLogCoverage: noCoverage.length,
    noLogCoverageDevices: noCoverage.map((d) => d.deviceName),
    // How many firewalls a trend could be attempted on at all.
    measurable: list.filter((d) => !UNFORECASTABLE_STATES.includes(d.state)).length,
    claim: FORECAST_CLAIM,
  };
}

/**
 * ⛔ WORST FIRST MEANS LEAST-KNOWN FIRST, NOT BIGGEST FIRST, and the
 * unforecastable firewalls rank ABOVE the measured ones — the ranking
 * `ChangeOutcomeBoard` holds and `tests/changeOutcomeBoard.test.js` fails the
 * build if it inverts. A firewall nothing can be measured on must not sort to
 * the bottom of a capacity page: it is the one whose capacity is unknown.
 *
 * ⛔ `NULLS LAST` ON THE VOLUME TIE-BREAK. A null median is unmeasured, and
 * JavaScript's `-` on null yields 0, which would sort an unmeasured firewall
 * into the middle of the volumes as though it were one of them.
 */
const STATE_ORDER = Object.freeze([
  STATES.NO_LOG_COVERAGE,
  STATES.BYTES_NOT_SUMMABLE,
  STATES.INSUFFICIENT_HISTORY,
  STATES.RISING,
  STATES.FALLING,
  STATES.NO_DETECTABLE_TREND,
]);

function rankForecasts(devices) {
  const list = Array.isArray(devices) ? [...devices] : [];
  return list.sort((a, b) => {
    const ra = STATE_ORDER.indexOf(a.state);
    const rb = STATE_ORDER.indexOf(b.state);
    if (ra !== rb) return (ra < 0 ? STATE_ORDER.length : ra) - (rb < 0 ? STATE_ORDER.length : rb);
    const va = num(a.medianDailyBytes);
    const vb = num(b.medianDailyBytes);
    if (va === null && vb === null) return String(a.deviceName).localeCompare(String(b.deviceName));
    if (va === null) return 1;   // NULLS LAST
    if (vb === null) return -1;
    if (vb !== va) return vb - va;
    return String(a.deviceName).localeCompare(String(b.deviceName));
  });
}

module.exports = {
  forecastDevice,
  summariseForecasts,
  rankForecasts,
  partitionSeries,
  senTrend,
  minHistoryDays,
  FORECAST_CLAIM,
  NOT_SUMMABLE_REASON,
  NO_COVERAGE_REASON,
  UNMEASURED_REASON,
  STATES,
  STATE_ORDER,
  UNFORECASTABLE_STATES,
  COMPLETE_DAY_HOURS,
  MIN_HISTORY_DAYS,
  SLOPE_BAND_QUANTILE,
  ALPHA,
  Z_CRITICAL,
  DEFAULT_HORIZON_DAYS,
  MAX_HORIZON_DAYS,
  DEFAULT_LOOKBACK_DAYS,
  MAX_LOOKBACK_DAYS,
  // Re-exported so a consumer never builds a second opinion of either.
  median,
  quantile,
};
