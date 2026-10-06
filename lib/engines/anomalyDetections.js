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
    measuredOn: '2026-10-06',
    alertsPerDay: 1.0,
    sensitivity: 1.0,
    method:
      'hour-of-day grain, q=0.90, 3 consecutive hours. 8.0% of buckets fired; 100% of planted '
      + 'events found (15/15). ⛔ The measured rate is 13x what independence predicts '
      + '(0.08^3 x 24 x 15 = 0.18/day) because firewall traffic is AUTOCORRELATED — which is '
      + 'why this is measured rather than computed.',
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
};

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

  // ⛔ A device that has NEVER reported is NOT silent — it is uncollected, and
  // that is a different fact with a different owner. Saying "stopped logging"
  // about a firewall that never started would send someone to look for an
  // outage that never happened.
  if (!list.some((h) => h && h.reported)) {
    return { state: DETECTOR_STATES.NO_DATA, runs: [], reason: 'this device has never reported' };
  }

  const runs = [];
  let start = -1;
  for (let i = 0; i <= list.length; i += 1) {
    const silent = i < list.length && list[i] && list[i].reported === false;
    if (silent && start === -1) start = i;
    if (!silent && start !== -1) {
      const length = i - start;
      if (length >= need) {
        runs.push({ startAt: list[start].at, endAt: list[i - 1].at, hours: length });
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
  return `${deviceName} stopped sending syslog for ${run.hours} consecutive hours. `
    + 'A firewall that is not reporting contributes no CVE findings, no failing compliance '
    + 'checks and no rule findings — it reads as healthy everywhere else in this product.';
}

// Registered detectors. ⛔ Each is asserted to carry measured evidence.
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
};

const ANOMALY_ALERT_TYPES = Object.values(DETECTORS).map((d) => d.alertType);

module.exports = {
  DETECTORS,
  ANOMALY_ALERT_TYPES,
  DETECTOR_STATES,
  EVIDENCE,
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
  // re-exported so callers do not reach past this module into the baseline
  STATES,
  buildSeasonalBaseline,
};
