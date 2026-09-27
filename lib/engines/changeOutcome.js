'use strict';

// lib/engines/changeOutcome.js
//
// A7 — WHAT HAPPENED TO THE TRAFFIC AFTER A CONFIGURATION CHANGE.
//
// Pure: takes an already-fetched per-device daily traffic series and a list of
// config changes, returns a verdict per change. No pool, no queries, no clock
// it is not handed. The plumbing is `changeOutcomeData.js`.
//
// SecVault is the only product in this market holding the change record and the
// traffic outcome in one database — CLAUDE.md's own framing is that "the log
// storage is not the point; the fusion is". This is that fusion.
//
// ── ⛔ THE CONTROL IS THE FEATURE. MEASURE IT BEFORE YOU BELIEVE ANYTHING ──
//
// Measured on the live fleet 2026-09-27, and it is the whole reason this engine
// is shaped the way it is:
//
//   24h either side of a CONFIG CHANGE (61 changes)   avg delta  +13.6%
//   24h either side of an ORDINARY DAY (284 pairs)    avg delta  +17.6%
//
// ⛔ THE CHANGE-ADJACENT DELTA IS SMALLER THAN ORDINARY DAY-TO-DAY VARIATION.
// Per-change deltas ran -92.1% to +126.0%, and the fleet's own p90 of absolute
// daily variation is 113.8%. Every one of those 61 "effects" sits inside the
// noise. A naive version of this feature — compute the before/after delta and
// print it — would have produced 61 plausible percentages, and an operator
// would have read causation into every one.
//
// So this engine does not report a delta. It reports a delta AGAINST THAT
// DEVICE'S OWN MEASURED VARIABILITY, and its common answer is
// `indistinguishable`.
//
// ── ⛔ THE BAND IS PER DEVICE. A FLEET BAND IS WRONG AT BOTH ENDS ──────────
//
// Measured p90 of absolute daily variation, same fleet, same window:
//
//   HRIS         23.2%      TSR-TL        69.3%     IDC FW      131.2%
//   TUFF(TUTH3)  44.6%      OKF(F2)       94.3%     ITC-SK      161.5%
//   TFM-RN       46.4%      TSR_EKC       95.5%     Vietnam-YCC 284.3%
//
// A 12x spread. One fleet-wide band would flag routine Vietnam-YCC fluctuation
// as an effect AND miss a genuine change on HRIS.
//
// ── ⛔ NEVER MEAN + σ — AND MEDIAN + MAD WAS NOT ENOUGH EITHER ────────────
//
// Firewall traffic is heavy-tailed — those same devices show medians of
// 2.4%-30% against p90s of 23%-284%. A single spike poisons a mean and the
// detector then under-reports for a week, so mean + sigma is out.
//
// ⛔ BUT THE ROBUST ALTERNATIVE FAILED TOO, AND ONLY THE CONTROL REVEALED IT.
// See the BAND_QUANTILE note below: median + MAD with Iglewicz-Hoaglin's own
// 3.5 cut-off flagged 17.3% of ORDINARY days. The decision rule is an empirical
// quantile; median and MAD survive as DESCRIPTION only.
//
// ── ⛔ CO-OCCURRENCE, NEVER CAUSATION ─────────────────────────────────────
//
// Every phrase this engine emits is "was followed by". A firewall change and a
// traffic change on the same day are two facts in sequence; this product cannot
// see a mechanism between them and must not imply one. `OUTCOME_CLAIM` is
// exported and a test rejects the causal vocabulary from every string here.

// ── ⛔ THE DECISION RULE IS AN EMPIRICAL QUANTILE, AND MEDIAN+MAD WAS TRIED
//      AND MEASURED WRONG (2026-09-27) ────────────────────────────────────
//
// The first version of this engine used the Iglewicz-Hoaglin MODIFIED Z-SCORE
// (median + MAD, cut-off 3.5) because it is robust, published, and the right
// answer for the mean+sigma trap. It was still wrong here, and only running it
// against the CONTROL showed it:
//
//   ordinary day-pairs it flagged as "exceeding normal variation":
//     SMT 42.1%   Vietnam-YCC 36.8%   ITC-SK 31.6%   fleet 49/284 = 17.3%
//
// ⛔ A DETECTOR THAT FIRES ON ONE ORDINARY DAY IN SIX MANUFACTURES EFFECTS FROM
// NOISE — precisely the failure this engine exists to prevent, reached by a
// correct-looking robust statistic. The 3.5 cut-off assumes approximately
// normal data; these deltas are heavy-tailed (medians 2.4%-30% against p90s of
// 23%-284%), so MAD measures a tight core that the tail routinely clears.
//
// The band is now the device's OWN EMPIRICAL QUANTILE of absolute day-over-day
// change. It is distribution-free and self-calibrating: the share of ordinary
// days it flags is 1 - BAND_QUANTILE BY CONSTRUCTION, not by hope. Median and
// MAD are still computed and reported, but as DESCRIPTION, never as the rule.
const BAND_QUANTILE = 0.95;

// ⛔ AND THE OBSERVATION COUNT LIMITS WHAT MAY BE CLAIMED. With n day-pairs the
// finest false-positive rate expressible is 1/(n+1) — live, n=19 gives 5%, so
// the 95th percentile IS the resolution floor here and a tighter quantile would
// be arithmetic theatre. `resolutionPct` is reported so a reader can see it.
const MIN_BASELINE_PAIRS = 10;

// Hours either side of the change that are compared. ⛔ NOT a tuning knob for
// making results appear: widening it reduces the number of changes that have a
// complete window at all (live: 61 changes have 24h either side, only 18 have
// 7 days), so a wider window buys precision by discarding most of the subject.
const DEFAULT_WINDOW_HOURS = 24;

const OUTCOME_CLAIM =
  'A change and a traffic movement on the same day are two facts in sequence. SecVault compares '
  + 'the traffic either side of a change against how much that firewall normally varies day to '
  + 'day, and reports whether the movement stands out from that. It does not observe a mechanism '
  + 'between the two and cannot say the change produced the movement.';

const VERDICTS = Object.freeze({
  // The movement is inside this firewall's normal day-to-day variation. This is
  // the common answer and is NOT "no effect" — it is "not distinguishable from
  // ordinary fluctuation", which is a statement about what we can resolve.
  INDISTINGUISHABLE: 'indistinguishable',
  // Outside the band. Worded "was followed by" everywhere it is rendered.
  EXCEEDED: 'exceeded_normal_variation',
  // ⛔ Each of these is its own state, never folded into INDISTINGUISHABLE.
  NO_TRAFFIC_WINDOW: 'no_traffic_window',      // no traffic data either side
  INSUFFICIENT_BASELINE: 'insufficient_baseline', // too few day-pairs to build a band
  BASELINE_DEGENERATE: 'baseline_degenerate',  // band = 0; no spread to compare against
  // ⛔ THE WINDOW REACHES OUTSIDE THE PERIOD WE WERE COLLECTING, which is a
  // different fact from "there was no traffic" and produced the most
  // embarrassing possible artefact on the first live run: FOUR changes dated
  // 2026-09-08 -- the rollup's own first day -- reported deltas of +814%, +691%
  // and +239% and cleared every band. Their 24h "before" window lay in the
  // hours when the collector had only just started, so `before_events` was
  // small for reasons that have nothing to do with the firewall. A confident,
  // plausible, completely wrong number, which is this codebase's signature bug
  // arriving through the front door of a feature built to prevent it.
  WINDOW_INCOMPLETE: 'window_incomplete',
});

const num = (v) => {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }
  return null;
};

function median(sorted) {
  if (!sorted.length) return null;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

// Linear-interpolated quantile of an ASCENDING array. Distribution-free.
function quantile(sorted, q) {
  if (!sorted.length) return null;
  if (sorted.length === 1) return sorted[0];
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  if (lo === hi) return sorted[lo];
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
}

/**
 * A device's own day-to-day variability from the ABSOLUTE percentage change
 * between consecutive days.
 *
 * ⛔ `bandPct` is the DECISION RULE (an empirical quantile, so its
 * false-positive rate is 1 - quantile by construction). `medianAbsPct` and `mad`
 * are DESCRIPTION and must not be used to decide anything — see the header for
 * the measurement that ruled them out.
 *
 * @param {Array<{day: string|Date, events: number|string}>} series
 * @returns {{observations, medianAbsPct, mad, bandPct, deltas, quantile,
 *            resolutionPct, usable, reason, needed}}
 */
function buildBaseline(series) {
  const rows = (Array.isArray(series) ? series : [])
    .map((r) => ({ day: r && r.day, events: num(r && r.events) }))
    .filter((r) => r.day !== undefined && r.day !== null && r.events !== null)
    .sort((a, b) => new Date(a.day) - new Date(b.day));

  const deltas = [];
  for (let i = 1; i < rows.length; i += 1) {
    const prev = rows[i - 1].events;
    const cur = rows[i].events;
    // ⛔ A zero previous day yields no ratio. It is DROPPED from the baseline
    // rather than treated as an infinite change — a device that was silent and
    // then spoke is a coverage event, not a variability observation.
    if (prev > 0) deltas.push(Math.abs(((cur - prev) / prev) * 100));
  }

  const observations = deltas.length;
  if (observations < MIN_BASELINE_PAIRS) {
    return {
      observations,
      medianAbsPct: null,
      mad: null,
      bandPct: null,
      deltas: [],
      quantile: BAND_QUANTILE,
      resolutionPct: null,
      usable: false,
      reason: VERDICTS.INSUFFICIENT_BASELINE,
      needed: MIN_BASELINE_PAIRS,
    };
  }

  const sorted = [...deltas].sort((a, b) => a - b);
  const med = median(sorted);
  const mad = median([...deltas.map((d) => Math.abs(d - med))].sort((a, b) => a - b));
  const band = quantile(sorted, BAND_QUANTILE);

  // ⛔ A BAND OF ZERO WOULD FLAG EVERY MOVEMENT. Reachable when a device's
  // daily traffic never changes at all, which is not a firewall SecVault can
  // say anything about — there is no spread to compare against.
  if (!(band > 0)) {
    return {
      observations,
      medianAbsPct: med === null ? null : Math.round(med * 10) / 10,
      mad: mad === null ? null : Math.round(mad * 10) / 10,
      bandPct: null,
      deltas: sorted,
      quantile: BAND_QUANTILE,
      resolutionPct: null,
      usable: false,
      reason: VERDICTS.BASELINE_DEGENERATE,
      needed: MIN_BASELINE_PAIRS,
    };
  }

  return {
    observations,
    // Descriptive only — see the header. Neither of these decides anything.
    medianAbsPct: Math.round(med * 10) / 10,
    mad: Math.round(mad * 10) / 10,
    // THE RULE: the absolute daily change this firewall exceeds on only
    // (1 - BAND_QUANTILE) of its ordinary days.
    bandPct: Math.round(band * 10) / 10,
    // Kept so a verdict can state WHERE in this firewall's own history a
    // movement sits, rather than only whether it cleared a line.
    deltas: sorted,
    quantile: BAND_QUANTILE,
    // ⛔ The finest false-positive rate this many observations can express.
    resolutionPct: Math.round((100 / (observations + 1)) * 10) / 10,
    usable: true,
    reason: null,
    needed: MIN_BASELINE_PAIRS,
  };
}

/**
 * Judge one change against a baseline.
 *
 * @param {{beforeEvents, afterEvents}} window  traffic either side
 * @param {object} baseline  from buildBaseline()
 */
function judgeChange(window, baseline) {
  const before = num(window && window.beforeEvents);
  const after = num(window && window.afterEvents);

  // ⛔ TESTED BEFORE THE TRAFFIC, because an incomplete window can still carry
  // plenty of events -- it is the COMPARISON that is invalid, not the data. The
  // caller marks this; `assessDevice` derives it from the series it already has.
  if (window && window.windowComplete === false) {
    return {
      verdict: VERDICTS.WINDOW_INCOMPLETE,
      deltaPct: null,
      largerThanDays: null,
      ordinaryDays: null,
      baseline,
    };
  }

  // ⛔ NO WINDOW IS NOT "NO EFFECT". Live, 133 of 203 config changes predate the
  // traffic rollup entirely — SecVault simply was not collecting yet. Reporting
  // those as unaffected would be a claim about 66% of the change history built
  // from its own absence.
  if (before === null || after === null || before <= 0) {
    return {
      verdict: VERDICTS.NO_TRAFFIC_WINDOW,
      deltaPct: null,
      largerThanDays: null,
      ordinaryDays: null,
      baseline,
    };
  }

  const deltaPct = ((after - before) / before) * 100;
  const rounded = Math.round(deltaPct * 10) / 10;

  if (!baseline || !baseline.usable) {
    return {
      verdict: baseline && baseline.reason ? baseline.reason : VERDICTS.INSUFFICIENT_BASELINE,
      // ⛔ The delta is still REPORTED — it is a real measurement. What is
      // withheld is the JUDGEMENT, because there is nothing to judge it
      // against. Hiding the number would be its own dishonesty.
      deltaPct: rounded,
      largerThanDays: null,
      ordinaryDays: null,
      baseline,
    };
  }

  // ⛔ COMPARED AGAINST THIS FIREWALL'S OWN ORDINARY DAYS, and the verdict
  // states WHERE among them it falls — "larger than 18 of 19 ordinary daily
  // swings" is a claim a reader can check, where a z-score is one they must
  // take on trust.
  const abs = Math.abs(deltaPct);
  const series = Array.isArray(baseline.deltas) ? baseline.deltas : [];
  const exceededDays = series.filter((d) => abs > d).length;
  return {
    verdict: abs > baseline.bandPct ? VERDICTS.EXCEEDED : VERDICTS.INDISTINGUISHABLE,
    deltaPct: rounded,
    // How many of this device's ordinary day-over-day swings this movement is
    // larger than, out of how many were observed.
    largerThanDays: exceededDays,
    ordinaryDays: series.length,
    baseline,
  };
}

/**
 * Judge every change for one device.
 *
 * @param {object} device  {deviceId, deviceName, vendor}
 * @param {Array} series   daily traffic, [{day, events}]
 * @param {Array} changes  [{id, detectedAt, beforeEvents, afterEvents, summary?}]
 */
function assessDevice(device, series, changes, opts = {}) {
  const d = device && typeof device === 'object' ? device : {};
  const baseline = buildBaseline(series);
  const list = Array.isArray(changes) ? changes : [];
  const windowHours = num(opts.windowHours) || DEFAULT_WINDOW_HOURS;

  // ⛔ THE PERIOD WE WERE ACTUALLY COLLECTING, taken from the series the
  // caller already supplied rather than trusted from elsewhere -- the two could
  // disagree, and this is the value the deltas were computed from.
  const days = (Array.isArray(series) ? series : [])
    .map((r) => (r && r.day !== undefined && r.day !== null ? new Date(r.day) : null))
    .filter((t) => t && !Number.isNaN(t.getTime()))
    .sort((a, b) => a - b);
  const observedFrom = days.length ? days[0] : null;
  // A daily bucket labelled D covers D..D+24h, so the observed period ends a
  // day after the last label.
  const observedTo = days.length
    ? new Date(days[days.length - 1].getTime() + 24 * 3600 * 1000)
    : null;
  const ms = windowHours * 3600 * 1000;

  const results = list.map((c) => {
    const at = c && c.detectedAt ? new Date(c.detectedAt) : null;
    const known = at && !Number.isNaN(at.getTime()) && observedFrom && observedTo;
    // ⛔ An UNKNOWN timestamp cannot be shown to be inside the window either,
    // so it is incomplete rather than assumed fine.
    const windowComplete = known
      ? (at.getTime() - ms >= observedFrom.getTime() && at.getTime() + ms <= observedTo.getTime())
      : false;
    return Object.assign(
      {
        changeId: c && c.id,
        detectedAt: c && c.detectedAt,
        summary: (c && c.summary) || null,
        windowComplete,
      },
      judgeChange(Object.assign({}, c, { windowComplete }), baseline)
    );
  });

  const by = {};
  for (const v of Object.values(VERDICTS)) by[v] = 0;
  for (const r of results) by[r.verdict] = (by[r.verdict] || 0) + 1;

  return {
    deviceId: d.deviceId,
    deviceName: d.deviceName,
    vendor: d.vendor,
    observedFrom,
    observedTo,
    windowHours,
    baseline,
    changes: results,
    changeCount: results.length,
    byVerdict: by,
    // ⛔ Named for what it is. `exceeded` is not "caused" and not "broke".
    exceeded: results.filter((r) => r.verdict === VERDICTS.EXCEEDED),
  };
}

/** Fleet totals. ⛔ No score, no grade, no percentage of changes "safe". */
function summariseOutcomes(devices) {
  const list = Array.isArray(devices) ? devices : [];
  const by = {};
  for (const v of Object.values(VERDICTS)) by[v] = 0;
  for (const d of list) {
    for (const [k, n] of Object.entries(d.byVerdict || {})) by[k] = (by[k] || 0) + n;
  }
  return {
    devices: list.length,
    devicesWithUsableBaseline: list.filter((d) => d.baseline && d.baseline.usable).length,
    // A distinct count: a device we could not build a band for is not a device
    // whose changes were harmless.
    devicesWithoutBaseline: list.filter((d) => !d.baseline || !d.baseline.usable).length,
    changes: list.reduce((n, d) => n + (d.changeCount || 0), 0),
    byVerdict: by,
    exceeded: list.flatMap((d) => (d.exceeded || []).map((e) => ({
      deviceId: d.deviceId, deviceName: d.deviceName, ...e,
    }))),
    claim: OUTCOME_CLAIM,
  };
}

module.exports = {
  buildBaseline,
  judgeChange,
  assessDevice,
  summariseOutcomes,
  median,
  quantile,
  OUTCOME_CLAIM,
  VERDICTS,
  BAND_QUANTILE,
  MIN_BASELINE_PAIRS,
  DEFAULT_WINDOW_HOURS,
};
