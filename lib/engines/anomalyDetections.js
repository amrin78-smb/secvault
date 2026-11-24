// lib/engines/anomalyDetections.js
//
// A6 stage 2 — the detectors. PURE: series in, findings out.
//
// ── WHAT A DETECTOR IS ALLOWED TO BE HERE ────────────────────────────────
//
// ⛔ EVERY DETECTOR CARRIES ITS OWN MEASUREMENT, AND ONE THAT HAS NOT BEEN
// MEASURED CANNOT BE REGISTERED. `scripts/a6Harness.js` exists because
// `analytics-proposal.md` records a method being falsified on this very data
// (A7: Iglewicz-Hoaglin at 3.5 flagged 17.3% of change-free days). The rule
// that follows from that is simple: a detector ships only with a measured
// alert rate AND a measured sensitivity, both recorded in `EVIDENCE` below,
// and `assertRegisteredDetector()` refuses anything without them.
//
// ⛔ MEASURED AND REFUSED IS A RESULT, NOT A GAP. Two candidates from
// roadmap.md Tier 1 #2 were measured on the live fleet and are NOT here:
//
//   total-events spike   6.91 alerts/day at the best configuration the data
//                        supports. Over the 3/day bar; needs a tighter
//                        quantile, which needs more history.
//   vpn auth burst       3.32 alerts/day, AND 33% of control buckets fired
//                        against the ~10% a 0.9 quantile can produce by
//                        construction. That gap is DRIFT, not noise: VPN auth
//                        failures rose ~7x over the window (mean per row
//                        1 -> 3 -> 5 -> 5 -> 7 by week) while denied traffic
//                        stayed flat. A STATIC seasonal baseline is the wrong
//                        instrument for a trending metric, and loosening the
//                        threshold would not fix it.
//
// Adding either one back needs a new harness run, not a judgement call.
//
// ── RE-MEASURED 2026-11-12 ON 2.3x THE HISTORY. BOTH STILL REFUSED. ──────
//
// The fleet now holds 65.3 days of `syslog_rollup_hourly` (2026-09-08 ->
// 2026-11-12, 15 devices) against the ~27 days the October run had. Both
// candidates were re-run. Neither becomes shippable, and the REASONS have
// changed in a way worth recording, because one of them was previously
// written down wrongly.
//
//   total-events spike   `--metric events --days 63`:
//                          q=0.90 persist=3  ->  7.30 alerts/day   (96% sens)
//                          q=0.95 persist=3  ->  4.21 alerts/day   (96% sens)
//                          q=0.975 / q=0.99  ->  INSUFFICIENT BASELINE, all
//                                                persistences, every grain.
//
//     ⛔ THE OCTOBER REASON WAS RIGHT IN MECHANISM AND WRONG IN MAGNITUDE,
//     AND "NEEDS MORE HISTORY" WAS TOO VAGUE TO ACT ON. The arming gate is
//     `minObservationsFor(q) = ceil(2 / (1 - q))` observations PER BUCKET
//     (seasonalBaseline.js), so at hour-of-day grain -- 24 buckets, ~1
//     observation per bucket per day -- a quantile needs that many DAYS:
//
//         q=0.90   20 obs/bucket    20 days   available
//         q=0.95   40 obs/bucket    40 days   available
//         q=0.975  80 obs/bucket    80 days   NOT YET
//         q=0.99  200 obs/bucket   200 days   NOT YET
//
//     2.3x the history moved q=0.90 -> q=0.95 and nothing further. 63 days
//     cannot arm q=0.975 at all, so "a tighter quantile" was not available to
//     this run and the alert rate it would produce is still unmeasured.
//     ⛔ The trend across the two quantiles that ARE armed roughly halves the
//     rate (7.30 -> 4.21), so q=0.975 may well land under the 3/day bar --
//     but that is an EXTRAPOLATION, not a measurement, and this detector
//     cannot register on one. The rollups are permanent, so the dates are
//     known exactly:
//         q=0.975 becomes measurable 2026-11-27  (80 days after 2026-09-08)
//         q=0.99  becomes measurable 2027-03-27  (200 days)
//     Re-run `node scripts/a6Harness.js --metric events --days 78` on or
//     after 2026-11-27. That is a scheduled check with a date, not a wish.
//
//   vpn auth burst       `--metric vpn_auth_fail --days 29`:
//                          q=0.90 persist=3  ->  2.89 alerts/day, 100% sens
//                          and the harness PRINTS THIS AS "VIABLE".
//
//     ⛔ IT IS NOT VIABLE, AND THIS IS THE TRAP THE OCTOBER NOTE EXISTS TO
//     PREVENT. 47.6% of buckets fired against the ~10% a q=0.90 threshold can
//     produce by construction -- WORSE than October's 33%. The alerts/day
//     figure only clears the bar because persist=3 filters it and because
//     only 8 of 15 devices report VPN auth at all; it is not evidence the
//     instrument fits. Registering on the one number that passed while
//     ignoring the diagnostic beside it is exactly how a detector ships and
//     then floods the feed.
//
//     ⛔ AND THE DRIFT IS CONFIRMED, INDEPENDENTLY, FIVE WEEKS LATER. The
//     harness's OWN series (failures per device-hour), by week:
//         2026-10-12   mean 134.82   median  88    (partial week)
//         2026-10-19   mean 224.75   median 193
//         2026-10-26   mean 403.07   median 346
//         2026-11-02   mean 512.63   median 405
//         2026-11-09   mean 418.11   median 405    (partial week)
//     A ~3.8x rise in the mean and ~4.6x in the median over five weeks. A
//     static seasonal baseline learns that trend and is then exceeded by most
//     recent hours BY CONSTRUCTION. No threshold and no persistence fixes a
//     model whose baseline is climbing with the signal.
//
//     ⛔ THE CAUSE IS A REAL, ONGOING ATTACK -- WHICH MAKES THE BASELINE WORSE,
//     NOT BETTER. The rise is fleet-wide across all 8 VPN-reporting firewalls
//     rising in near-lockstep, which is not 8 simultaneous local events; the
//     sources are concentrated external infrastructure (one 29-day example:
//     12,875 failures from 5 Bulgarian addresses, 1,615 from a single
//     Kazakh one). So the series is not noisy, it is TRENDING BECAUSE THE
//     CAMPAIGN IS GROWING, and a detector that learns it would normalise the
//     attack it exists to report.
//
//     ⛔ So this candidate does not need a looser threshold or more history.
//     It needs a TREND-AWARE instrument, which is a new method and must be
//     validated by its own harness run before it is proposed here. Do not
//     register this detector off the "viable" line above.
//
// ⛔ THE OUTPUT IS A NAMED THRESHOLD, NEVER A SCORE. roadmap.md's rule. An
// alert says "4,812 denied in this hour; this firewall's 90th percentile for
// 14:00 is 1,230 over 27 observations" — something an operator can check,
// argue with, and act on. "Anomaly score 3.7" is none of those.
//
// Pure: no DB, no clock it is not given, no I/O. Never throws.

'use strict';

const { buildSeasonalBaseline, selectGrain, judge, sustainedRuns, STATES } = require('./seasonalBaseline');

/**
 * ⛔ THE MEASURED EVIDENCE FOR EACH SHIPPED DETECTOR. Live fleet, 15 devices,
 * ~646-672 hours, measured 2026-10-05/06. These are not decoration: a detector
 * with no entry here is refused at registration.
 */
// ⛔ `denied_spike` WAS MEASURED AT 2.48/day AND IS NOW 1.0/day. Nothing about
// the threshold changed — a 5% MARGIN FLOOR was added after production showed an
// alert reading "2,897 against a ceiling of 2,897, 0.0% above it". The floor is
// measured, not chosen: planted anomalies carry a MINIMUM margin of 10.9%, so
// every floor to 10% keeps 100% sensitivity (table at the filter's use site).
// Re-measured over the same 28-day window: 22 runs / 22 judged days.
const EVIDENCE = {
  device_silent: {
    measuredOn: '2026-10-06',
    alertsPerDay: 0.074,
    sensitivity: null,          // not applicable — see `method` below
    method:
      'Absence, not level. 16 silent device-hours in 9,720 (0.16%) across 15 devices over 27 '
      + 'days, falling in exactly TWO runs (3h and 13h) — silence on this fleet is rare AND '
      + 'clustered, so a 2-consecutive-hour rule would have fired twice in 27 days. '
      + 'Sensitivity is not measured by planting because the signal IS the absence: there is '
      + 'nothing to plant that the rule could miss.',
  },
  denied_spike: {
    // ⛔ RE-MEASURED 2026-11-24 AGAINST THE REAL DETECTOR. The previous entry
    // (1.0/day, sensitivity 1.0, 15/15) came from a harness that RE-IMPLEMENTED
    // the pipeline: it omitted detectSpike's 5% margin floor and its per-device
    // selectGrain, so it described a detector that does not ship. See
    // scripts/a6Harness.js' "REAL DETECTOR" pass, which now drives detectSpike
    // itself, one simulated day at a time, deduped by the dispatcher's key.
    measuredOn: '2026-11-24',
    alertsPerDay: 3.75,
    sensitivity: 0.94,
    method:
      'q=0.90, 3 consecutive hours, grain self-selected per device. Measured by driving the '
      + 'REAL detectSpike over 77 days of live rollups (15 devices, 352 device-days judged): '
      + '3.75 alerts/day, 353 of 375 planted events found = 94% (95% Wilson CI 91-96%). '
      + '⛔ THE RATE EXCEEDS THE HARNESS’S OWN <=3/day GUIDELINE BY 25% AND THE '
      + 'CONFIGURATION WAS KEPT ANYWAY, DELIBERATELY: the only configuration inside that '
      + 'ceiling (q=0.95, persist=3, 2.34/day) scores 91% with a CI of 88-94%, so its '
      + 'sensitivity CANNOT BE SHOWN to clear the 90% bar, while this one’s can. No '
      + 'configuration on this data satisfies both bars; trading proven detection for 1.4 '
      + 'fewer alerts a day was refused. '
      + '⛔ SENSITIVITY IS JUDGED ON THE INTERVAL’S LOWER BOUND, NOT THE POINT '
      + 'ESTIMATE. At the harness’s old 28-plant sample this same configuration read 89% '
      + '— and at n=28 even a PERFECT 28/28 has a lower bound of 87.9%, so the 90% bar was '
      + 'not measurable at that sample size at all. 375 plants is what settles it. '
      + '⛔ The rate is 13x what independence predicts because firewall traffic is '
      + 'AUTOCORRELATED, which is why this is measured rather than computed.',
  },
  volume_collapse: {
    measuredOn: '2026-11-24',
    alertsPerDay: 0.017,
    sensitivity: 0.93,
    method:
      'drop=0.99, a 3-day recent window, 14 judgeable days of baseline. Measured by driving '
      + 'the REAL detectVolumeCollapse over 78 days of live DAILY rollups (16 reporting '
      + 'devices, 930 device-days judged): 0.017 alerts/day — ONE alert, which is the real '
      + 'collapse on this fleet (TFM-MH, 5.5M/day to 28/day on 2026-11-09). Sensitivity 826 '
      + 'of 885 planted collapses found = 93% (95% Wilson CI 91-95%). '
      + '⛔ SENSITIVITY IS JUDGED ON THE INTERVAL’S LOWER BOUND, NOT THE POINT ESTIMATE, '
      + 'and that is what chose the 3-day window: at 2 days the point estimate is 92% but '
      + 'the lower bound is 89.85%, so it CANNOT BE SHOWN to clear the 90% bar. 5 days '
      + 'scores identically to 3 and detects two days later. '
      + '⛔ PLANT MAGNITUDES ARE MULTIPLES OF THE BAR, NOT ABSOLUTE FRACTIONS. A plant whose '
      + 'remainder EQUALS the bar’s sits exactly on the threshold, where a detector is a '
      + 'coin toss — measured at 51% on a flat canvas and 25-43% on real series, which the '
      + 'first draft of the harness read as a detector fault. The figure above is a tenth '
      + 'inside the bar; 944 of 944 are found there on a flat canvas. '
      + '⛔ SPECIFICITY IS MEASURED ON A FLAT SYNTHETIC CANVAS: a plant TEN TIMES outside '
      + 'the bar fires 0 of 944 in every configuration. It cannot be measured on the real '
      + 'series, because a plant lands on top of a device’s own variation and a day already '
      + 'a tenth down plus a ten-times plant is a genuine hundred-fold fall — the detector '
      + 'is right to fire there. '
      + '⛔ drop=0.99 IS A STATED JUDGEMENT, NOT A MEASUREMENT: 0.95, 0.99 and 0.999 give '
      + 'the identical alert, rate and sensitivity on this fleet, because the one real '
      + 'collapse clears every bar and nothing else comes close. 0.99 is kept because a '
      + 'hundred-fold fall is not a plausible traffic change while a twenty-fold one is '
      + 'reachable by a branch closing.',
  },
};

/** How many consecutive silent hours before a device is reported as stopped. */
const SILENCE_MIN_HOURS = 2;

/** How many consecutive anomalous hours before a spike is reported. */
const SPIKE_MIN_HOURS = 3;

/** The threshold the harness picked. Not exposed as a setting — see the header. */
const SPIKE_QUANTILE = 0.90;
/** Minimum exceedance over the bucket threshold for a run to be reported. See
 *  the measurement table at its use site — 5% keeps 100% measured sensitivity. */
const SPIKE_MIN_MARGIN_PCT = 5;

/**
 * How many recent hours are JUDGED on each run. The rest trains the baseline.
 * 24h with dispatch dedup by `natural_key` means a sustained event is ONE alert,
 * not one per hour — which is a large part of why the measured rate is bearable.
 */
const DEFAULT_JUDGE_WINDOW_HOURS = 24;

const DETECTOR_STATES = {
  MEASURED: 'measured',
  INSUFFICIENT_BASELINE: 'insufficient_baseline',
  NO_DATA: 'no_data',
  // ⛔ A DEVICE THAT REPORTED AND THEN WENT DARK FOR LONGER THAN THE WHOLE
  // WINDOW. It is JUDGED, not unjudged — the verdict is simply measured from
  // the permanent rollups rather than from the grid, because the grid holds
  // nothing but absence for it. Reusing MEASURED would hand the finding an
  // `hours` the window cannot supply; reusing NO_DATA is the defect this state
  // exists to end, where the most completely silent firewall on the fleet is
  // the one nothing reports.
  STOPPED_BEFORE_WINDOW: 'stopped_before_window',
};

/** A usable Date, never a string and never an Invalid Date. */
function isDate(v) {
  return v instanceof Date && Number.isFinite(v.getTime());
}

function num(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/**
 * ⛔ A DETECTOR MAY NOT SHIP WITHOUT A MEASUREMENT. Called at module load for
 * every registered detector, so an unmeasured one fails immediately and
 * loudly rather than quietly alerting on a threshold nobody checked.
 */
function assertRegisteredDetector(key) {
  const e = EVIDENCE[key];
  if (!e || typeof e.alertsPerDay !== 'number' || !e.measuredOn || !e.method) {
    throw new Error(
      `anomalyDetections: detector "${key}" has no measured evidence. Run scripts/a6Harness.js `
      + 'against the live rollups and record alertsPerDay, sensitivity, measuredOn and method '
      + 'in EVIDENCE before registering it.'
    );
  }
  return e;
}

/**
 * ⛔ THE REGISTERED RATE IS A CLAIM ABOUT ONE AFTERNOON, AND NOTHING RE-TESTED
 * IT (added 2026-11-14). `assertRegisteredDetector` checks only that
 * `alertsPerDay`, `measuredOn` and `method` EXIST — so a rate measured on
 * 2026-10-06 stays authoritative for ever while the fleet moves underneath it.
 * Measured against production on 2026-11-14: `device_silent` produced **17
 * findings over 28 days = 0.607/day against a registered 0.074**, i.e. 8.2x.
 * The roadmap had filed it at 6.8x, so it had drifted FURTHER between two
 * measurements — which is the argument for testing it on every run rather
 * than at registration.
 *
 * ⛔ IT REPORTS AND NEVER REFUSES. A drifted rate must not disarm a detector:
 * this product's rule is that monitoring runs in every state, and a detector
 * switched off for failing a meta-check is the guard-that-cannot-fire pattern
 * aimed at the alerting engine itself. `rateDrift` returns a STATE; nothing
 * branches on it.
 *
 * ⛔ A RATIO THRESHOLD WOULD BE THE WRONG TEST, and that is why this is a
 * POISSON TAIL on the COUNT. The registered 0.074/day comes from TWO observed
 * runs in 27 days; the 95% interval on a count of 2 spans roughly 0.24 to 7.2
 * events, so a 2x "deviation" is noise and no fixed ratio can separate the two
 * cases. Expected count over the window is `alertsPerDay * windowDays`, and
 * the question asked is the honest one: how surprising is the observed count
 * if the registered rate were still true. 17 against an expected 2.07 is not
 * a borderline call.
 *
 * ⛔ BOTH DIRECTIONS ARE REPORTED. Firing far LESS than measured is also
 * drift, and is the more dangerous one — a detector that quietly stopped
 * producing anything is indistinguishable from a healthy fleet, which is this
 * codebase's signature bug in detector form.
 *
 * ⛔ `indistinguishable` IS NOT `consistent`, deliberately borrowing
 * `changeOutcome`'s word: observing 0 events against an expected 2.07 is
 * p=0.126 and settles nothing, so it may not be reported as agreement.
 */
const RATE_STATES = {
  DRIFTED_HIGH: 'drifted_high',
  DRIFTED_LOW: 'drifted_low',
  INDISTINGUISHABLE: 'indistinguishable',
  UNMEASURABLE: 'unmeasurable',
};

/** Two-sided significance for the drift test. */
const DRIFT_P = 0.01;

/**
 * ⛔ A CADENCE, STATED AS A JUDGEMENT RATHER THAN DRESSED AS A DERIVATION.
 * Nothing in the data says 90 days; it is the longest a threshold on a
 * security product can go unexamined while still being called "measured".
 * It is reported as a FACT (`reviewOverdue`) beside the statistical verdict,
 * never mixed into it — the tail test is what carries evidence.
 */
const EVIDENCE_REVIEW_DAYS = 90;

/**
 * ⛔ THE DOMAIN IS BOUNDED AND SAYS SO. `Math.exp(-lambda)` underflows to 0
 * above ~745, which would make the cumulative sum 0 and turn `atLeast` into a
 * confident 1 — a fabricated "not surprising" from an arithmetic failure.
 * Rather than carry a log-space implementation for a case this product does
 * not have (real lambdas here are ~2 and ~28), the bound is explicit and
 * anything beyond it is UNMEASURABLE.
 */
const MAX_LAMBDA = 200;

function poissonAtMost(k, lambda) {
  if (!Number.isFinite(k) || k < 0) return null;
  if (!Number.isFinite(lambda) || lambda < 0 || lambda > MAX_LAMBDA) return null;
  if (lambda === 0) return 1;
  let term = Math.exp(-lambda);
  let sum = term;
  for (let i = 1; i <= k; i++) {
    term = (term * lambda) / i;
    sum += term;
  }
  return Math.min(1, sum);
}

function poissonAtLeast(k, lambda) {
  if (!Number.isFinite(k)) return null;
  if (k <= 0) return 1;
  if (!Number.isFinite(lambda) || lambda < 0 || lambda > MAX_LAMBDA) return null;
  if (lambda === 0) return 0;
  const below = poissonAtMost(k - 1, lambda);
  return below === null ? null : Math.max(0, 1 - below);
}

/**
 * Compare a detector's OBSERVED firing count against its registered rate.
 *
 * @param {string} key          detector key in EVIDENCE
 * @param {number} observedCount findings this detector produced over the window
 * @param {number} windowDays   the window those findings were counted over
 * @param {Date}   now          for the measurement-age fact
 */
function rateDrift(key, observedCount, windowDays, now) {
  const e = EVIDENCE[key];
  const at = now instanceof Date && !Number.isNaN(now.getTime()) ? now : new Date();
  const registeredPerDay = e && typeof e.alertsPerDay === 'number' ? e.alertsPerDay : null;
  const measuredOn = (e && e.measuredOn) || null;

  let measurementAgeDays = null;
  if (measuredOn) {
    const ms = Date.parse(`${measuredOn}T00:00:00Z`);
    if (Number.isFinite(ms)) measurementAgeDays = Math.floor((at.getTime() - ms) / 86400000);
  }
  const reviewOverdue = measurementAgeDays === null ? null : measurementAgeDays > EVIDENCE_REVIEW_DAYS;

  const count = num(observedCount);
  const days = num(windowDays);
  const base = {
    detector: key,
    registeredPerDay,
    measuredOn,
    measurementAgeDays,
    reviewOverdue,
    observedCount: count,
    windowDays: days,
    observedPerDay: count !== null && days !== null && days > 0 ? count / days : null,
    expectedCount: registeredPerDay !== null && days !== null && days > 0 ? registeredPerDay * days : null,
  };

  if (registeredPerDay === null || count === null || days === null || days <= 0 || count < 0) {
    return { ...base, ratio: null, p: null, state: RATE_STATES.UNMEASURABLE };
  }

  const lambda = registeredPerDay * days;
  // ⛔ A ratio against a registered ZERO is not infinity, it is undefined —
  // and a detector registered at 0/day that fires at all is drift the tail
  // test already catches.
  const ratio = registeredPerDay > 0 ? count / lambda : null;

  const high = poissonAtLeast(count, lambda);
  const low = poissonAtMost(count, lambda);
  if (high === null || low === null) {
    return { ...base, ratio, p: null, state: RATE_STATES.UNMEASURABLE };
  }

  let state = RATE_STATES.INDISTINGUISHABLE;
  let p = null;
  if (high < DRIFT_P / 2) { state = RATE_STATES.DRIFTED_HIGH; p = high; }
  else if (low < DRIFT_P / 2) { state = RATE_STATES.DRIFTED_LOW; p = low; }

  return { ...base, ratio, p, state };
}

// ---------------------------------------------------------------------------
// Detector 1 — a device STOPPED LOGGING
// ---------------------------------------------------------------------------
//
// ⛔ THE HIGHEST-VALUE DETECTOR, AND IT NEEDS NO BASELINE AT ALL.
// `analytics-proposal.md`: "Highest-value detector when it does arm: a device
// that STOPS logging — which is A2's finding made continuous." It reads the
// ABSENCE of rows, which `seasonalBaseline` deliberately excludes from its
// levels, so it cannot be expressed as a spike and must not be.
//
// ⛔ AND IT IS THE ONE DETECTOR THE REST OF THIS PRODUCT MOST NEEDS. A firewall
// that stopped reporting contributes no CVEs, no failing checks and no rule
// findings — CLAUDE.md's own words: it "renders as the healthiest device on the
// fleet". This turns that silence into a positive, actionable statement.

/**
 * @param {Array<{at: Date, reported: boolean}>} hours ordered ascending, one entry per hour
 * @param {{minHours?: number}} [opts]
 * @returns {{state: string, runs: Array<{startAt: Date, endAt: Date, hours: number}>}}
 */
function detectSilence(hours, opts = {}) {
  const list = Array.isArray(hours) ? hours : [];
  const need = Math.max(1, Math.trunc(num(opts.minHours) ?? SILENCE_MIN_HOURS));

  // ⛔ AN ALL-SILENT GRID HAS TWO CAUSES AND THEY ARE OPPOSITE FACTS. A device
  // that has NEVER reported is NOT silent — it is uncollected, a different fact
  // with a different owner, and saying "stopped logging" about a firewall that
  // never started sends someone to look for an outage that never happened. But
  // a device that reported for a year and went dark LONGER AGO than the window
  // produces the identical grid, and calling that one "never reported" is this
  // codebase's signature bug aimed at its own most important detector: the
  // alert goes quiet exactly as the silence becomes total.
  //
  // ⛔ THE WINDOW CANNOT TELL THEM APART, SO THIS FUNCTION DOES NOT GUESS.
  // `opts.lastReportedAt` comes from an UNBOUNDED `MAX(bucket_hour)` over the
  // PERMANENT rollups — a Date means "it reported then", an explicit `null`
  // means "it never has", and OMITTING it means nobody asked, which is its own
  // answer and must never be reported as either of the other two.
  if (!list.some((h) => h && h.reported)) {
    const last = isDate(opts.lastReportedAt) ? opts.lastReportedAt : null;
    if (last) {
      const now = isDate(opts.now) ? opts.now : null;
      // ⛔ `hours` STAYS NULL. Every other run counts silent hours INSIDE the
      // grid; here the run started before it, so a grid-derived count would be
      // the window's length wearing a measurement's clothes — the same
      // fabricated-edge defect `truncated` was added for. `silentDays` is a
      // real measurement from a permanent table and is reported instead.
      return {
        state: DETECTOR_STATES.STOPPED_BEFORE_WINDOW,
        runs: [{
          startAt: null,
          endAt: list.length ? list[list.length - 1].at : null,
          hours: null,
          truncated: true,
          lastReportedAt: last,
          silentDays: now ? Math.max(0, Math.floor((now.getTime() - last.getTime()) / 86400000)) : null,
        }],
        reason: 'this device reported before the window and has been silent for all of it',
      };
    }
    return {
      state: DETECTOR_STATES.NO_DATA,
      runs: [],
      reason: opts.lastReportedAt === null
        ? 'this device has never reported'
        : 'no last-reported time was supplied, so never-reported and stopped-before-the-window '
          + 'cannot be told apart',
    };
  }

  const runs = [];
  let start = -1;
  for (let i = 0; i <= list.length; i += 1) {
    const silent = i < list.length && list[i] && list[i].reported === false;
    if (silent && start === -1) start = i;
    if (!silent && start !== -1) {
      const length = i - start;
      if (length >= need) {
        // ⛔ A RUN THAT BEGINS AT THE WINDOW'S LEFT EDGE HAS NO KNOWN START, AND
        // REPORTING THE EDGE AS ONE IS A FABRICATED MEASUREMENT. The grid is
        // generated from `now() - N days`, so index 0 advances every hour: the
        // "start" of a run that really began earlier slides forward with it, and
        // `hours` SHRINKS by one every hour while the device stays silent. An
        // operator watching sees a silence that keeps getting shorter.
        // ⛔ It also churned the dispatcher's natural_key once an hour, so each
        // tick cleared the previous key as RESOLVED and raised the next as new —
        // ~24 false resolve/renotify pairs a day for as long as the run spans
        // the edge. `truncated` is what lets both of those be fixed without
        // guessing a start time nobody measured.
        // ⛔ `gridStartIsKnown` IS THE ONE CASE WHERE INDEX 0 IS A MEASUREMENT
        // RATHER THAN A MOVING EDGE. The paragraph above is about a grid
        // generated from `now() - N days`, whose index 0 slides forward every
        // hour. When the caller has trimmed the grid to the hour the DEVICE
        // WAS CREATED, index 0 is a fixed, recorded timestamp that does not
        // move — so flagging it `truncated` would claim the start is unknown
        // when it is the best-known fact about the run. Default false: a
        // caller that says nothing gets the safe answer.
        runs.push({
          startAt: list[start].at,
          endAt: list[i - 1].at,
          hours: length,
          truncated: start === 0 && opts.gridStartIsKnown !== true,
        });
      }
      start = -1;
    }
  }
  return { state: DETECTOR_STATES.MEASURED, runs };
}

// ---------------------------------------------------------------------------
// Detector 2 — a DENIED-TRAFFIC SPIKE
// ---------------------------------------------------------------------------

/**
 * ⛔ THE BASELINE IS BUILT FROM HISTORY AND THE RECENT WINDOW IS JUDGED AGAINST
 * IT — THEY ARE NOT THE SAME ROWS. An anomaly included in its own baseline
 * raises its own threshold and can hide itself. Measured: a 4-hour spike does
 * NOT self-mask (the bucket threshold moved 149 -> 146, i.e. not at all, because
 * four hours among ~140 observations cannot shift a 90th percentile) — but a
 * SUSTAINED event would, and that is exactly the event most worth catching. The
 * split costs nothing and removes the whole class.
 *
 * It also matches how this runs: an hourly job judging the last `judgeWindowHours`
 * against everything before them.
 *
 * @param {Array<{at: Date, value: number}>} series hourly observations, ascending
 * @param {{quantile?: number, minHours?: number, judgeWindowHours?: number}} [opts]
 * @returns {{state, runs, baseline, reason?}}
 */
function detectSpike(series, opts = {}) {
  const all = Array.isArray(series) ? series : [];
  const q = num(opts.quantile) ?? SPIKE_QUANTILE;
  const need = Math.max(1, Math.trunc(num(opts.minHours) ?? SPIKE_MIN_HOURS));
  const windowHours = Math.max(need, Math.trunc(num(opts.judgeWindowHours) ?? DEFAULT_JUDGE_WINDOW_HOURS));

  if (all.length === 0) {
    return { state: DETECTOR_STATES.NO_DATA, runs: [], baseline: null };
  }

  // Split: everything before the window trains, the window is judged.
  const cut = Math.max(0, all.length - windowHours);
  const history = all.slice(0, cut);
  const rows = all.slice(cut);
  if (history.length === 0 || rows.length === 0) {
    return {
      state: DETECTOR_STATES.INSUFFICIENT_BASELINE,
      runs: [],
      baseline: null,
      reason: 'not enough history before the judged window',
    };
  }

  // ⛔ The grain is CHOSEN from the data, never hardcoded — the hour-of-week
  // model the proposal specified needs ~40 weeks and would otherwise report
  // insufficient_baseline for months while a usable coarser model sat there.
  const picked = selectGrain(history, { quantile: q });
  if (!picked.grain) {
    const best = picked.tried.reduce((a, b) => (b.coverage > a.coverage ? b : a), picked.tried[0]);
    return {
      state: DETECTOR_STATES.INSUFFICIENT_BASELINE,
      runs: [],
      baseline: null,
      // ⛔ Report what was needed and what exists — the same shape the six VPN
      // detections use. A gated detector renders hatched and hueless, never as
      // a green all-clear.
      reason: 'not enough history for any grain to support this threshold',
      tried: picked.tried,
      bestCoverage: best ? best.coverage : 0,
    };
  }

  const baseline = picked.baseline;
  const judgements = rows.map((r) => judge(r.value, baseline, r.at));
  const runs = sustainedRuns(judgements, need).map((run) => {
    const row = rows[run.startIndex];
    const endRow = rows[Math.min(run.startIndex + run.length - 1, rows.length - 1)];
    // ⛔ THE REPRESENTATIVE HOUR IS THE ONE WITH THE LARGEST EXCEEDANCE, NOT
    // THE LARGEST VALUE. Each hour is judged against ITS OWN bucket, so the
    // biggest-value hour can be the one that barely cleared its threshold while
    // another hour in the same run cleared a lower threshold by far more. The
    // live result read "2,897 against a ceiling of 2,897, 0.0% above it" — two
    // identical numbers and a margin of nothing, which reads as an alert fired
    // on empty air. Reporting the hour that actually drove the run makes the
    // sentence coherent with the reason it exists.
    const slice = judgements.slice(run.startIndex, run.startIndex + run.length);
    const rel = (j) => (j && j.threshold > 0 ? (j.value - j.threshold) / j.threshold : -Infinity);
    const lead = slice.reduce((a, b) => (rel(b) > rel(a) ? b : a), slice[0]) || run.peak;
    return {
      startAt: row ? row.at : null,
      endAt: endRow ? endRow.at : null,
      hours: run.length,
      // ⛔ THE SAME TRUNCATION, IN THE OTHER DETECTOR. A spike run starting at
      // index 0 began before the window too, so its startAt is the advancing
      // edge and its key would churn identically. Rarer than a silence run —
      // it needs denied traffic elevated continuously across the boundary —
      // but structurally the same, and a defect fixed in one of two detectors
      // is a defect waiting to be rediscovered.
      truncated: run.startIndex === 0,
      peak: lead ? lead.value : null,
      threshold: lead ? lead.threshold : null,
      median: lead ? lead.median : null,
      observations: lead ? lead.observations : null,
      exceedancePct: lead && lead.threshold > 0
        ? ((lead.value - lead.threshold) / lead.threshold) * 100 : null,
    };
  })
    // ⛔ THE MARGIN FLOOR, AND IT IS MEASURED RATHER THAN CHOSEN. Live on the
    // reference fleet, run margins span 0.0%–1025% (median 7%). The planted
    // anomalies the stage-1 harness detects have a MINIMUM margin of 10.9%
    // (median 71.5%), so every floor up to 10% retains 100% sensitivity while
    // cutting the trivial tail:
    //
    //     floor   live runs kept   planted still detected
    //      0%          32/32            30/30 (100%)
    //      2%          27/32            30/30 (100%)
    //      5%          20/32            30/30 (100%)
    //     10%          10/32            30/30 (100%)
    //
    // 5% is the pick: it removes the "0.0% above it" class that teaches an
    // operator to ignore the channel, and keeps a 2x gap to the smallest
    // anomaly this harness can detect. ⛔ 10% cuts more noise and was REFUSED —
    // it sits 0.9pp under that smallest real margin, which is no gap at all.
    .filter((r) => r.exceedancePct === null || r.exceedancePct >= SPIKE_MIN_MARGIN_PCT);

  return {
    state: DETECTOR_STATES.MEASURED,
    runs,
    baseline: { grain: baseline.grain, quantile: baseline.quantile, usableBuckets: baseline.usableBuckets },
  };
}

/**
 * The sentence an alert carries.
 *
 * ⛔ IT NAMES THE THRESHOLD AND ITS EVIDENCE, because that is what makes the
 * alert checkable. An operator who cannot see WHY something fired cannot tell
 * a real event from a bad threshold, and will eventually mute both.
 */
/**
 * \u26d4 THE WORD "SPIKE" OVERSOLD WHAT THIS MEASURES, AND THE LIVE RUN SHOWED IT.
 * On the real fleet the first findings were "2,953 against a ceiling of 2,910"
 * and "16,276 against 15,216" — exceedances of 1.5% and 7%, sustained three
 * hours. Those ARE the measured signal (above the 90th percentile for three
 * consecutive hours, which happens ~2.5 times a day fleet-wide) but calling a
 * 1.5% exceedance a spike is the kind of overclaim this product refuses
 * everywhere else. The title says what happened; the margin is stated outright
 * so the reader can size it without doing the arithmetic.
 */
function describeSpike(run, deviceName) {
  const peak = num(run && run.peak);
  const threshold = num(run && run.threshold);
  const obs = num(run && run.observations);
  if (peak === null || threshold === null) {
    return `${deviceName}: denied traffic stayed above its normal ceiling for ${run.hours} consecutive hours.`;
  }
  // \u26d4 NEVER PRINT "0% above it" FOR SOMETHING THAT DID EXCEED. The run only
  // exists because the value was ABOVE the threshold, so a margin rounding to
  // zero is a DISPLAY defect, not a detector one — and it reads as an alert
  // fired on nothing, which is how an operator learns to ignore the channel.
  // Sub-1% margins get a decimal instead.
  const overPct = threshold > 0 ? ((peak - threshold) / threshold) * 100 : null;
  const margin = overPct === null ? ''
    : `, ${overPct < 1 ? overPct.toFixed(1) : Math.round(overPct)}% above it`;
  return `${deviceName}: ${peak.toLocaleString()} denied events in one hour against a normal `
    + `ceiling of ${Math.round(threshold).toLocaleString()} for this time of day${margin} `
    + `(${Math.round(SPIKE_QUANTILE * 100)}th percentile over ${obs} observations). `
    + `Sustained ${run.hours} hours.`;
}

function describeSilence(run, deviceName) {
  // ⛔ A TRUNCATED RUN'S `hours` IS A LOWER BOUND AND MUST BE WORDED AS ONE.
  // Said plainly ("stopped sending syslog for 3 consecutive hours") it
  // UNDER-STATES a silence that may have lasted weeks, and it is the only
  // number the operator gets — the same contract vpn_sessions states for a
  // duration whose end is only known to within one poll.
  // ⛔ THREE SHAPES, BECAUSE THE EVIDENCE DIFFERS. A run wholly inside the
  // window has a measured start and a measured length. A run that CROSSES the
  // left edge has neither — only a lower bound. A run that began entirely
  // BEFORE the window has no grid evidence at all, and its length comes from
  // the permanent rollups instead: that one is exact and must not be worded as
  // a lower bound, which would under-state the worst case on the fleet.
  const stopped = run && run.lastReportedAt instanceof Date;
  const span = stopped
    ? `has sent no syslog for ${run.silentDays === null || run.silentDays === undefined
      ? 'longer than this detector\u2019s evidence window' : `${run.silentDays} days`} — it `
      + 'last reported before the window opened, so this is measured from the permanent '
      + 'rollups rather than from the window'
    : run && run.truncated
      ? `has not sent syslog for AT LEAST ${run.hours} hours — the silence began before `
        + "SecVault's evidence window, so its true length is longer than this and its start is "
        + 'not known'
      : `stopped sending syslog for ${run.hours} consecutive hours`;
  return `${deviceName} ${span}. `
    + 'A firewall that is not reporting contributes no CVE findings, no failing compliance '
    + 'checks and no rule findings — it reads as healthy everywhere else in this product.';
}

/**
 * ⛔ THE ONE CLAIM THIS DETECTOR MAKES. Exported so a test can pin it, the way
 * IMPACT_CLAIM, CONTROL_CLAIM and BRANCH_CLAIM are.
 *
 * It states a FALL IN VOLUME and nothing about the cause. SecVault cannot tell
 * a firewall that stopped GENERATING these events (a policy change, a quiet
 * site, logging switched off) from one that stopped SENDING them (a broken
 * syslog target, a filtered path), and guessing between them would send an
 * operator to the wrong console.
 */
const COLLAPSE_CLAIM = 'This firewall is still sending syslog, at a small fraction of its own '
  + 'historical volume. SecVault cannot tell whether it stopped generating these events or '
  + 'stopped sending them.';

/**
 * ⛔ IT MUST NOT BORROW device_silent'S SENTENCE. "Stopped sending syslog" is
 * that detector's claim and is FALSE here — the firewall is still reporting,
 * which is the entire reason this detector exists. Measured on production: of 42
 * anomaly findings fleet-wide, 38 were device_silent on ONE collapsed firewall,
 * each titled "stopped sending syslog" about a device that had not stopped. Two
 * detectors with one vocabulary cannot be told apart by the person reading them.
 */
function describeCollapse(result, deviceName, opts = {}) {
  const base = Math.round(Number(result && result.baseline));
  const rec = Math.round(Number(result && result.recent));
  const ok = Number.isFinite(base) && Number.isFinite(rec) && base > 0;
  // ⛔ The percentage is DERIVED from the two figures that travel with it, so a
  // reader can check it. A bare "99.999%" with no levels beside it is a number
  // nobody can audit.
  const fall = ok ? (100 * (1 - rec / base)) : null;
  const pct = fall === null ? null
    : (fall >= 99.9 ? fall.toFixed(3) : fall >= 99 ? fall.toFixed(2) : fall.toFixed(1));
  const onset = result && result.onsetDay ? result.onsetDay : null;
  const level = ok
    ? `about ${rec.toLocaleString('en-GB')} events a day, against ${base.toLocaleString('en-GB')} `
      + `a day before that${pct === null ? '' : ` — a fall of ${pct}%`}`
    // ⛔ Never a fabricated number. If either level is unreadable the sentence
    // says so rather than printing a percentage computed from nothing.
    : 'a volume SecVault could not quantify';
  const since = onset ? ` since ${onset}` : '';
  const suppressed = Number(opts.supersededSilenceRuns);
  const also = Number.isFinite(suppressed) && suppressed > 0
    ? ` Its syslog arrives in gaps, which produced ${suppressed} separate `
      + `silence run${suppressed === 1 ? '' : 's'} in this window; those are symptoms of this `
      + 'collapse and are reported here rather than as separate findings.'
    : '';
  return `${deviceName} has been sending${since} ${level}. ${COLLAPSE_CLAIM}${also} `
    + 'A firewall that is barely reporting contributes almost no CVE findings, no failing '
    + 'compliance checks and no rule findings — it reads as healthy everywhere else in '
    + 'this product.';
}

// Registered detectors. ⛔ Each is asserted to carry measured evidence.
// ---------------------------------------------------------------------------
// Detector 3 (UNREGISTERED) — a VOLUME COLLAPSE
// ---------------------------------------------------------------------------
//
// ⛔ WHAT IT CATCHES THAT NOTHING ELSE DOES. `device_silent` asks only "did ANY
// event arrive this hour". A firewall whose syslog falls by 99.999% but keeps
// dribbling is therefore invisible to it: measured on production 2026-11-24,
// TFM-MH went from ~5,900,000 events/day to ~30 on 2026-11-08 and was still
// dark 16 days later, having produced nothing but scattered 2-hour silence
// runs that read as noise. `denied_spike` detects increases. A6 measured and
// refused a total-events SPIKE; a DROP is a different question and was never
// tested.
//
// ⛔ IT IS NOT IN `DETECTORS` AND MUST NOT BE UNTIL IT IS MEASURED.
// `assertRegisteredDetector` requires a measured alert rate AND a measured
// sensitivity, and v2.237.6 is the whole argument for not guessing either:
// the same configuration of an existing detector read 89% at a 28-plant sample
// and 94% at 375. Registration waits for `scripts/a6Harness.js`.
//
// ⛔ THE BASELINE IS ANCHORED IN PERMANENT HISTORY, NOT A SLIDING WINDOW, AND
// THAT WAS MEASURED RATHER THAN PREFERRED. Swept against 77 days of live
// rollups: with a 14-day trailing baseline EVERY candidate threshold had
// ALREADY CLEARED on TFM-MH while it was still dark — the baseline adapted and
// decided ~30 events/day was normal. A 28-day baseline only defers the same
// failure to ~2026-12-06. Any baseline short enough to be responsive is short
// enough to forget, so the comparison is against the device's own history in
// the PERMANENT `syslog_rollup_hourly`, exactly as `loadLastReported` escapes
// the window for `device_silent`. The alert then persists while the condition
// does, with no stored verdict and nothing to go stale.
//
// ⛔ A DAY THE FLEET WAS NOT COLLECTING IS NOT A DAY THIS DEVICE WENT QUIET.
// A collector outage or a deploy zeroes every device at once, and at a 2-day
// sustain that would flag the entire fleet. The caller marks each day
// `judgeable`, and an unjudgeable day is EXCLUDED from both the baseline and
// the recent window — never counted as a zero. Same call `capacityForecast.js`
// makes when it excludes partial days rather than letting a 3-hour day drag a
// slope negative.
//
// ⛔ IT NEVER FIRES ON A FIREWALL THAT IS FULLY DARK. That is `device_silent`'s
// finding, and two detectors reporting one event is the duplicate-vocabulary
// problem this file names elsewhere. A collapse requires the device to still
// be emitting something across the sustain window.
//
// ⛔ AND NEVER ON ONE THAT NEVER REPORTED. A firewall with no history is
// UNCOLLECTED, not collapsed — the same distinction `detectSilence` draws
// between "never started" and "stopped".

/**
 * Fraction a device's volume must fall BELOW its own historical level.
 *
 * ⛔ THIS ONE IS A STATED JUDGEMENT, NOT A MEASUREMENT, AND THE DIFFERENCE IS
 * RECORDED BECAUSE THE DATA CANNOT SETTLE IT. `scripts/a6Harness.js --detector
 * collapse` measured 0.95, 0.99 and 0.999 against 78 days of the live fleet and
 * all three produce the IDENTICAL result at every sustain -- one alert, the same
 * alert, and the same sensitivity -- because the only real collapse on this
 * fleet (TFM-MH, 5.5M/day -> 28/day) is a 99.999% fall that clears every bar,
 * and nothing else comes close. So the fleet does not discriminate it.
 *
 * 0.99 is kept on the argument that a hundred-fold fall in log volume is not a
 * plausible traffic change, while 0.95 -- a twenty-fold fall -- is reachable by
 * a branch closing or a holiday shutdown, which this fleet simply has not done
 * in the measured window. Same class of statement as `reviewOverdue`'s 90 days:
 * a cadence somebody chose, labelled as one, rather than a derivation dressed up
 * as a measurement.
 */
const COLLAPSE_DROP_RATIO = 0.99;
/**
 * Length of the recent window, in judgeable days. 1 would fire on maintenance.
 *
 * ⛔ IT IS A WINDOW LENGTH, NOT A RUN OF CONSECUTIVE COLLAPSED DAYS, AND THIS
 * COMMENT SAID "consecutive" UNTIL IT WAS EXERCISED. The verdict is the window's
 * MEDIAN, so a MAJORITY of the window has to be down: at 3 days, [1M, 10, 10]
 * medians to 10 and FIRES on two collapsed days, and a recovery takes two days
 * to clear it ([10, 1M, 1M] medians to 1M). The hysteresis is wanted -- it stops
 * a dribbling firewall flapping in and out of the finding -- but it is a weaker
 * guarantee than "three consecutive days" and must not be described as one.
 * A test pins the majority behaviour from both sides.
 *
 * ⛔ MEASURED, AND IT MOVED FROM 2. At 2 days the planted sensitivity is 92%
 * (840/915) with a 95% Wilson lower bound of **89.85%** -- so it CANNOT BE SHOWN
 * to clear the >=90% bar, while its point estimate reads like a pass. At 3 days
 * it is 93% (826/885, lower bound 91.5%) and CLEARS, at the same alert rate
 * (0.017/day, one alert in 930 device-days). 5 days scores identically to 3 and
 * detects two days later, so 3 is the cheapest configuration that can be
 * demonstrated.
 *
 * ⛔ JUDGED ON THE INTERVAL'S LOWER BOUND, NEVER THE POINT ESTIMATE. Ranking on
 * the bare percentage picks 2 days -- 91.8% looks fine -- which is the same
 * error v2.237.6 corrected for `denied_spike` two releases ago, met again here
 * on a different detector 0.15 points from passing.
 */
const COLLAPSE_SUSTAIN_DAYS = 3;
/**
 * Judgeable days of history required before any verdict is offered.
 *
 * ⛔ 14 AND 28 WERE BOTH MEASURED AND SCORE THE SAME (93%, lower bounds 91.5%
 * and 91.3%), so the shorter one is kept: it is the only difference that matters
 * operationally, because 28 days of required history means a newly onboarded
 * firewall is unjudgeable for a month.
 */
const COLLAPSE_MIN_BASELINE_DAYS = 14;

function medianOf(values) {
  if (!values.length) return null;
  const s = [...values].sort((x, y) => x - y);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

/**
 * @param {Array<{day: string, events: number, judgeable?: boolean}>} daily
 *        ascending, one entry per calendar day the fleet was observed.
 * @param {{dropRatio?, sustainDays?, minBaselineDays?}} [opts]
 * @returns {{state, collapsed, baseline, recent, onsetDay, judgeableDays, reason?}}
 */
function detectVolumeCollapse(daily, opts = {}) {
  const rows = Array.isArray(daily) ? daily : [];
  const ratio = num(opts.dropRatio) ?? COLLAPSE_DROP_RATIO;
  const sustain = Math.max(1, Math.trunc(num(opts.sustainDays) ?? COLLAPSE_SUSTAIN_DAYS));
  const minBase = Math.max(1, Math.trunc(num(opts.minBaselineDays) ?? COLLAPSE_MIN_BASELINE_DAYS));

  // ⛔ An unjudgeable day is DROPPED, not zeroed.
  const usable = rows.filter((r) => r && r.judgeable !== false && Number.isFinite(Number(r.events)))
    .map((r) => ({ day: String(r.day), events: Number(r.events) }));

  // ⛔ TWO FACTS, ONE STATE, AND THEY MAY NOT SHARE A SENTENCE. Both mean
  // "nothing to judge", so both are NO_DATA — but "we have not had a chance to
  // look yet" and "we looked and it has never reported" send an operator to
  // different places, and only the second is a statement about the firewall.
  //
  // ⛔ MEASURED ON PRODUCTION 2026-11-24, which is how this was found. StarUnion
  // was added to the inventory that day, so its only gridded day was TODAY —
  // always partial and therefore never judgeable — giving it ZERO judgeable
  // days. The single branch reported `reason: 'this device has never reported'`
  // about a firewall that was actively sending syslog, which is this file's own
  // failed-read-as-a-fact rule inside the detector written to enforce it.
  if (usable.length === 0) {
    return {
      state: DETECTOR_STATES.NO_DATA,
      collapsed: false,
      baseline: null,
      recent: null,
      onsetDay: null,
      judgeableDays: 0,
      reason: 'no judgeable days yet — this firewall was added too recently, or SecVault '
        + 'was not collecting on every day in the window',
    };
  }
  if (usable.every((r) => r.events === 0)) {
    return {
      state: DETECTOR_STATES.NO_DATA,
      collapsed: false,
      baseline: null,
      recent: null,
      onsetDay: null,
      judgeableDays: usable.length,
      reason: 'this device has never reported',
    };
  }
  if (usable.length < minBase + sustain) {
    return {
      state: DETECTOR_STATES.INSUFFICIENT_BASELINE,
      collapsed: false,
      baseline: null,
      recent: null,
      onsetDay: null,
      judgeableDays: usable.length,
      reason: `needs ${minBase + sustain} judgeable days, has ${usable.length}`,
    };
  }

  const collapsedAt = (endIdx) => {
    // The window ENDING at endIdx (inclusive), judged against everything before it.
    const start = endIdx - sustain + 1;
    if (start < minBase) return null;
    const window = usable.slice(start, endIdx + 1);
    const history = usable.slice(0, start);
    const base = medianOf(history.map((r) => r.events));
    const rec = medianOf(window.map((r) => r.events));
    if (base === null || base <= 0 || rec === null) return null;
    // ⛔ A DARK DEVICE BELONGS TO device_silent, AND THE GUARD MUST TEST THE
    // SAME STATISTIC THE VERDICT DOES. This was `window.reduce(sum) <= 0`, which
    // disagrees with the median the verdict uses: measured on production
    // 2026-11-24, TFM-RN reported NOTHING from 2026-11-09 to 11-17, and a window
    // straddling the boundary -- [758646, 0, 0] -- sums to 758,646 while its
    // median is 0. So the guard passed, the verdict fired, and the finding
    // claimed `recent: 0 events/day`: device_silent's exact claim, made by the
    // detector built for the case where silence does NOT apply. It also churned,
    // because walking back across a dark stretch produced TWO onsets for ONE
    // outage (2026-11-08 and 2026-11-16).
    //
    // A zero recent MEDIAN means the device was dark for at least half the
    // window, which is silence. `rec <= 0` strictly subsumes the old sum test
    // (a zero sum implies a zero median, not the reverse), so this narrows the
    // detector and removes a class of finding rather than trading one for
    // another. TFM-MH -- the firewall this detector exists for -- is unaffected:
    // it never reaches zero on any day.
    if (rec <= 0) return null;
    return rec <= base * (1 - ratio) ? { base, rec } : null;
  };

  const last = usable.length - 1;
  const now = collapsedAt(last);
  if (!now) {
    return {
      state: DETECTOR_STATES.MEASURED,
      collapsed: false,
      baseline: medianOf(usable.slice(0, last - sustain + 1).map((r) => r.events)),
      recent: medianOf(usable.slice(last - sustain + 1).map((r) => r.events)),
      onsetDay: null,
      judgeableDays: usable.length,
    };
  }

  // ⛔ WALK BACK TO THE ONSET so the natural key is stable. Keyed on the day the
  // collapse began, an alert raised today and the same alert next week are ONE
  // alert; keyed on "today" the dispatcher would resolve and re-raise it daily
  // for as long as the firewall stays dark — the churn v2.228.10 fixed for
  // silence runs, which is reachable here by simply waiting.
  let onset = last;
  for (let i = last - 1; i >= minBase + sustain - 1; i -= 1) {
    if (!collapsedAt(i)) break;
    onset = i;
  }

  return {
    state: DETECTOR_STATES.MEASURED,
    collapsed: true,
    baseline: now.base,
    recent: now.rec,
    onsetDay: usable[onset - sustain + 1] ? usable[onset - sustain + 1].day : usable[onset].day,
    judgeableDays: usable.length,
  };
}

const DETECTORS = {
  device_silent: {
    alertType: 'anomaly_device_silent',
    label: 'Firewall stopped sending syslog',
    evidence: assertRegisteredDetector('device_silent'),
    describe: describeSilence,
  },
  denied_spike: {
    alertType: 'anomaly_denied_spike',
    label: 'Denied-traffic spike',
    evidence: assertRegisteredDetector('denied_spike'),
    describe: describeSpike,
  },
  volume_collapse: {
    alertType: 'anomaly_volume_collapse',
    label: 'Firewall log volume collapsed',
    evidence: assertRegisteredDetector('volume_collapse'),
    describe: describeCollapse,
  },
};

const ANOMALY_ALERT_TYPES = Object.values(DETECTORS).map((d) => d.alertType);

module.exports = {
  DETECTORS,
  ANOMALY_ALERT_TYPES,
  DETECTOR_STATES,
  EVIDENCE,
  detectVolumeCollapse,
  describeCollapse,
  COLLAPSE_CLAIM,
  COLLAPSE_DROP_RATIO,
  COLLAPSE_SUSTAIN_DAYS,
  COLLAPSE_MIN_BASELINE_DAYS,
  SILENCE_MIN_HOURS,
  SPIKE_MIN_HOURS,
  SPIKE_QUANTILE,
  SPIKE_MIN_MARGIN_PCT,
  DEFAULT_JUDGE_WINDOW_HOURS,
  detectSilence,
  detectSpike,
  describeSpike,
  describeSilence,
  assertRegisteredDetector,
  // rate-drift meta-check (2026-11-14) — reports, never refuses
  RATE_STATES,
  DRIFT_P,
  EVIDENCE_REVIEW_DAYS,
  MAX_LAMBDA,
  poissonAtMost,
  poissonAtLeast,
  rateDrift,
  // re-exported so callers do not reach past this module into the baseline
  STATES,
  buildSeasonalBaseline,
};
