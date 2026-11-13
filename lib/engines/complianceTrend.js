// lib/engines/complianceTrend.js
//
// Compliance score OVER TIME, from fleet_dashboard_snapshots.
//
// The table has been written nightly for a long time and carries
// `compliance_overall_score` plus `compliance_by_standard` (one scorePct per
// standard). Nothing in the product has ever read it as a SERIES —
// components/dashboard/ComplianceScoreWidget.js reads it `LIMIT 1`, i.e.
// today's number only. So a per-standard compliance history has been
// accumulating and has never been rendered. This engine turns those rows into
// something chartable WITHOUT inventing any of the three things that would
// make the chart a lie.
//
// PURE. No pool, no `new Date()` that is not derived from the rows handed in.
// Every number below is a function of its arguments, which is what makes the
// "we could not measure this" cases testable at all — they are exactly the
// cases a live render can never produce on demand.
//
// CommonJS, like every other lib/engines/* module (services/engine-worker.js
// requires them under plain node, which cannot load ESM). A 'use client'
// component may still `import { buildComplianceTrend } from …` — several
// already do this with lib/engines/reportSchedule.js and
// lib/engines/ruleChangeRequests.js.
//
// ─────────────────────────────────────────────────────────────────────────
// ⛔ THE THREE STATES THIS FILE EXISTS TO KEEP APART
//
// A compliance score for a given day is NOT a number-or-nothing. It is one of
// four distinct things, and collapsing any pair of them produces a confident
// wrong answer on a chart — CLAUDE.md's most-repeated bug class, drawn at
// 200px tall:
//
//   MEASURED      a real percentage. The fleet was assessed and scored.
//
//   UNMEASURABLE  the nightly row EXISTS and the score in it is NULL. The job
//                 ran; nothing was gradeable that day (no audit findings, or
//                 every finding `na`). lib/schema.sql spells this out on the
//                 column itself: "null when nothing is measurable yet, never
//                 0". Plotting it as 0 draws a cliff to 0% and reads as a
//                 catastrophic overnight collapse in the fleet's posture.
//
//   NOT RECORDED  there is no row for that calendar date at all. The nightly
//                 tick was LOST. This is not hypothetical: CLAUDE.md records
//                 four permanently missing days on the reference deployment
//                 (2026-10-11, -12, -13 and -15) because a daily cron tick
//                 whose second passed while the event loop was busy is not
//                 deferred, it is dropped. Those days can never be
//                 reconstructed.
//
//   UNREADABLE    a row exists and carries something that is not a usable
//                 percentage. A fault of ours or of the data, never a reading.
//
// ⛔ UNMEASURABLE AND NOT RECORDED ARE DIFFERENT FACTS WITH DIFFERENT FIRST
// STEPS, AND THEY ARE COUNTED SEPARATELY FOR THAT REASON. "Nothing was
// gradeable" is a compliance-coverage problem — collect configs, run an
// assessment. "No row was written" is an ENGINE problem — the snapshot job
// lost a tick. An operator shown one combined "5 days missing" cannot tell
// which they have, and would go and look in the wrong place. This is the same
// call lib/engines/capacityForecast.js makes when it refuses to add
// `bytes_not_summable` to `no_log_coverage`, and the same one CLAUDE.md makes
// about "never collected from" versus "last collected over N days ago".
//
// ⛔ HOW EACH IS REPRESENTED IN THE SERIES, since a chart can only draw what
// is in the array:
//
//   * Every CALENDAR day between the first and last snapshot is emitted as a
//     point, carrying `presence: 'snapshot' | 'absent'`. A not-recorded day is
//     therefore a REAL POINT ON THE X AXIS with null values — it occupies its
//     own slot in time. If it were simply omitted, recharts (which spaces a
//     categorical axis evenly, not by date) would stand the two surviving
//     snapshots side by side and run the line straight between them: a smooth,
//     confident segment across four days nobody measured, reading as "no
//     change over that week". That exact defect was found and fixed once
//     already, one directory over, in components/dashboard/
//     VulnerabilityTrends.js — this is the same hole in a second table.
//
//   * A day that IS recorded but whose score is NULL also carries null, and
//     also breaks the line. Both breaks look the same in the stroke; they are
//     told apart by `states[key]`, which drives the tooltip's reason sentence,
//     and by the two separate counters in the summary, which the caption
//     prints side by side.
//
//   * ⛔ Only the INTERIOR is filled. Days before the first snapshot are not
//     padded with absences: "the job had not started yet" is a different
//     statement from "the job was down", and the window label already reports
//     the real span. Padding the lead-in would manufacture an outage.
//
// ⛔ NOTHING IS EVER INTERPOLATED, SMOOTHED OR CARRIED FORWARD. There is no
// last-known-value fill in this file. A carried-forward score is a measurement
// nobody took, printed in the same ink as the ones somebody did.
//
// ⛔ NO TARGET LINE, NO BENCHMARK, NO PROJECTION. This product holds no
// compliance target anywhere, and a drawn target is a claim about what the
// customer should be at that nobody in this codebase is entitled to make. The
// delta below is the difference between two readings that exist; it is not a
// rate, not a forecast, and it is not extrapolated past the newest reading.

'use strict';

// The five real standards this app scores against. Kept as a literal rather
// than imported from components/compliance/ComplianceMatrix.js, matching
// lib/engines/dashboardSnapshot.js's own note: that file is a React component
// module and is not cleanly requirable from plain-node engine code. The WRITER
// of this data (dashboardSnapshot.js) carries the identical literal, so these
// two must be changed together — which is why an unrecognised key found in the
// stored JSON is reported rather than dropped (see `unrecognisedStandards`).
const STANDARD_KEYS = ['PCI_DSS', 'ISO_27001', 'CIS_V8', 'NIST', 'SANS'];

const STANDARD_LABELS = {
  PCI_DSS: 'PCI DSS',
  ISO_27001: 'ISO 27001',
  CIS_V8: 'CIS v8',
  NIST: 'NIST',
  SANS: 'SANS',
};

const OVERALL_KEY = 'overall';

// Per-day presence of the snapshot ROW itself.
const SNAPSHOT = 'snapshot';
const ABSENT = 'absent';

// Per (day, series) state of the VALUE. Four, never two — see the header.
const MEASURED = 'measured';
const UNMEASURABLE = 'unmeasurable';
const UNREADABLE = 'unreadable';
const NOT_RECORDED = 'not_recorded';

// One sentence, exported so a test can pin it, in the shape `CONTROL_CLAIM`
// (lib/engines/complianceControls.js), `IMPACT_CLAIM` and `COVERAGE_CLAIM`
// already use. It names the thing every mock of a trend chart gets wrong: the
// gaps are not zeroes and they are not nothing, they are two different kinds
// of absence, and the line is broken rather than bridged at both.
const TREND_CLAIM =
  'This is a history of readings, not a continuous measurement. A break in a '
  + 'line is a day with no score: either the nightly snapshot was never '
  + 'recorded, or it was recorded and nothing was gradeable. Neither is a '
  + 'zero, neither is interpolated across, and the two are counted separately '
  + 'because they are fixed in different places.';

// A score outside 0-100 cannot have come from this product's own formula
// (pass / (pass + fail + warning), rounded), so it is corrupt rather than
// extreme. Plotting it would stretch the axis and present a fault as a
// posture. See `readScore`.
const MIN_SCORE = 0;
const MAX_SCORE = 100;

// ⛔ A HARD CEILING ON THE FILLED SPAN, and it truncates from the OLD end and
// SAYS SO. Nothing in this file bounds the caller's query, and the interior
// fill walks the calendar, so a single stray 1970 snapshot_date would
// otherwise generate twenty thousand absent points — a browser freeze whose
// cause is invisible. Truncation is reported in `window.truncated` and printed
// in the caption, because a shortened series that looks complete is the more
// insidious failure (CLAUDE.md's PER_SOURCE_CAP reasoning, applied to days).
const MAX_SPAN_DAYS = 400;

const MS_PER_DAY = 86400000;

/**
 * 'YYYY-MM-DD' for a pg DATE (a JS Date), an ISO string, or null if it cannot
 * be placed on the calendar at all.
 *
 * ⛔ UTC throughout, deliberately and consistently. These are DATE columns, so
 * node builds them as local midnight; reading them back with local getters and
 * writing them with UTC ones (or the reverse) shifts a row by a day near a
 * zone boundary and would silently invent an absent day beside a duplicate.
 * The only property that matters here is that the same calendar key comes out
 * for the same stored date, every time.
 */
function isoDay(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') {
    // Already a plain date key — accept it without a Date round trip, which is
    // what would reintroduce a zone shift on a bare 'YYYY-MM-DD'.
    const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(value.trim());
    if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  }
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

function dayToUtcMs(day) {
  return Date.parse(`${day}T00:00:00Z`);
}

function addDays(day, n) {
  return new Date(dayToUtcMs(day) + n * MS_PER_DAY).toISOString().slice(0, 10);
}

function daysBetween(fromDay, toDay) {
  return Math.round((dayToUtcMs(toDay) - dayToUtcMs(fromDay)) / MS_PER_DAY);
}

/**
 * Classify one stored score.
 *
 * ⛔ THREE OUTCOMES, NOT TWO. `null` means the job ran and nothing was
 * gradeable (the column's own documented meaning). Anything present but not a
 * usable percentage — a string that will not parse, NaN, Infinity, a negative,
 * 150 — is UNREADABLE: a fault, not a posture. Returning 0 for any of these,
 * or quietly treating them as null, is the failed-read-recorded-as-a-fact bug
 * this whole engine is built around.
 *
 * @returns {{score: number|null, state: string}}
 */
function readScore(value) {
  if (value === null || value === undefined) return { score: null, state: UNMEASURABLE };
  // ⛔ TYPE FIRST, THEN Number(). `Number([])` is 0 and `Number(true)` is 1 —
  // both finite, both inside 0-100, so a bare Number() coercion would have
  // turned an empty array into a confident "0% compliant" and a boolean into
  // "1%". Found by the test below, which is why it feeds this function an
  // array. Only a real number, or a string that is entirely a number, is a
  // candidate for a reading; everything else is a fault.
  const numeric =
    typeof value === 'number' || (typeof value === 'string' && value.trim() !== '');
  if (!numeric) return { score: null, state: UNREADABLE };
  const n = Number(value);
  if (!Number.isFinite(n)) return { score: null, state: UNREADABLE };
  if (n < MIN_SCORE || n > MAX_SCORE) return { score: null, state: UNREADABLE };
  return { score: n, state: MEASURED };
}

function emptySeriesSummary() {
  return {
    readings: 0,
    unmeasurable: 0,
    unreadable: 0,
    // Shared with every other series on the same chart (an absent ROW has no
    // value for any of them); carried per-series so a per-standard row in a
    // table is self-contained and nobody has to reach back into `window`.
    notRecorded: 0,
    latest: null,
    earliest: null,
  };
}

/**
 * The delta between the newest and oldest READABLE points of one series.
 *
 * ⛔ A DELTA NEEDS TWO READABLE ENDPOINTS. With none, or with exactly one, the
 * value is `null` and `reason` says which — never 0. A zero delta is a
 * measurement ("it did not move"); printing one from a single point, or from
 * none at all, states that the fleet's compliance has held steady when nothing
 * has been compared. That is the same substitution as `hit_count`'s old
 * `NOT NULL DEFAULT 0`.
 *
 * ⛔ `spanDays` TRAVELS WITH IT, ALWAYS. "+6 points" over three days and
 * "+6 points" over three months are different claims and render identically
 * without it.
 */
function deltaFor(summary) {
  if (!summary || summary.readings === 0) {
    return { value: null, from: null, to: null, spanDays: null, readings: 0, reason: 'no_readings' };
  }
  if (summary.readings === 1) {
    return {
      value: null,
      from: summary.earliest,
      to: summary.latest,
      spanDays: 0,
      readings: 1,
      reason: 'single_reading',
    };
  }
  return {
    value: summary.latest.score - summary.earliest.score,
    from: summary.earliest,
    to: summary.latest,
    spanDays: daysBetween(summary.earliest.day, summary.latest.day),
    readings: summary.readings,
    reason: null,
  };
}

/**
 * Can this series be drawn as a line at all?
 *
 *   'plotted' — two or more readable points: a line exists.
 *   'single'  — exactly one: a dot, and nothing to join it to.
 *   'none'    — nothing readable in the window at all.
 *
 * ⛔ 'none' MUST NOT RENDER AS A FLAT OR EMPTY PLOT. An axis with no stroke on
 * it reads as a steady score, which is the strongest possible all-clear drawn
 * from the complete absence of evidence.
 */
function seriesStatus(summary) {
  if (!summary || summary.readings === 0) return 'none';
  if (summary.readings === 1) return 'single';
  return 'plotted';
}

/**
 * Why a point has no value, for a tooltip. One sentence per state, and the
 * two absence states say different things on purpose — that difference is the
 * whole reason the states exist.
 */
function pointReason(point, key) {
  const state = point && point.states ? point.states[key] : undefined;
  if (state === NOT_RECORDED) {
    return 'No nightly snapshot was recorded for this day, so no score exists for it. It is not zero, and it cannot be recovered.';
  }
  if (state === UNMEASURABLE) {
    return 'The nightly snapshot ran for this day and nothing was gradeable, so the score is unknown — not zero.';
  }
  if (state === UNREADABLE) {
    return 'The stored value for this day is not a usable percentage, so it is treated as no reading rather than plotted.';
  }
  return 'No reading for this day.';
}

/**
 * Build the chartable series from raw fleet_dashboard_snapshots rows.
 *
 * @param {Array<{snapshot_date: any, compliance_overall_score: any, compliance_by_standard: any}>} rows
 *        Any order; this function sorts. Column names are the table's own.
 * @param {{requestedDays?: number}} [options]
 *        `requestedDays` is only ever used to SAY what was asked for beside
 *        what exists. It never pads, trims or back-fills — asking for 90 days
 *        and holding 3 must look like 3 days of history, loudly.
 */
function buildComplianceTrend(rows, options = {}) {
  const requestedDays =
    Number.isFinite(Number(options.requestedDays)) && Number(options.requestedDays) > 0
      ? Math.round(Number(options.requestedDays))
      : null;

  const base = {
    claim: TREND_CLAIM,
    standards: STANDARD_KEYS.map((k) => ({ key: k, label: STANDARD_LABELS[k] })),
    points: [],
    summary: { overall: emptySeriesSummary(), byStandard: {} },
    delta: { overall: deltaFor(null), byStandard: {} },
    window: {
      firstDay: null,
      lastDay: null,
      spanDays: 0,
      snapshotDays: 0,
      absentDays: 0,
      requestedDays,
      truncated: false,
      unreadableDates: 0,
      duplicateDates: 0,
    },
    unrecognisedStandards: [],
    caption: '',
  };
  for (const k of STANDARD_KEYS) {
    base.summary.byStandard[k] = emptySeriesSummary();
    base.delta.byStandard[k] = deltaFor(null);
  }

  // ⛔ "THE READ FAILED" AND "THERE IS NOTHING TO READ" ARE DIFFERENT ANSWERS
  // and must never share a sentence. An empty table means the nightly job has
  // never written a row — a true, ordinary state on a fresh install. A caller
  // that handed us something that is not an array has had a read go wrong, and
  // saying "no history yet" about that would be this engine reporting someone
  // else's failure as a fact about the fleet.
  if (!Array.isArray(rows)) {
    return {
      ...base,
      available: false,
      unavailableReason:
        'The compliance snapshot history could not be read, so no trend can be shown. This is a fault, not an empty history.',
      caption: 'history unavailable',
    };
  }

  if (rows.length === 0) {
    return {
      ...base,
      available: false,
      // ⛔ NO ALL-CLEAR FROM AN ABSENT SERIES. Zero rows is not a flat line at
      // today's score and it is not "no change" — it is the absence of any
      // history at all, and the sentence has to say so or an empty plot will
      // say the opposite.
      unavailableReason:
        'No nightly fleet snapshots have been recorded, so there is no compliance history to plot. The trend appears once the nightly snapshot job has run on at least two days.',
      caption: 'no history recorded yet',
    };
  }

  // ── Read the rows ──────────────────────────────────────────────────────
  const byDay = new Map();
  let unreadableDates = 0;
  let duplicateDates = 0;
  const unrecognised = new Set();

  for (const row of rows) {
    const day = isoDay(row && row.snapshot_date);
    if (day === null) {
      // A row we cannot place on the calendar is counted, never dropped
      // silently and never guessed at a position.
      unreadableDates += 1;
      continue;
    }
    if (byDay.has(day)) {
      // snapshot_date is UNIQUE in lib/schema.sql, so this is unreachable
      // through the schema. Counted rather than assumed away: if it ever
      // happens, "the first one wins" is a stated rule, not row order deciding
      // silently.
      duplicateDates += 1;
      continue;
    }

    const stored = row && row.compliance_by_standard;
    const byStandardRaw = stored && typeof stored === 'object' && !Array.isArray(stored) ? stored : {};
    for (const k of Object.keys(byStandardRaw)) {
      if (!STANDARD_KEYS.includes(k)) unrecognised.add(k);
    }

    const values = {};
    const states = {};
    const o = readScore(row.compliance_overall_score);
    values[OVERALL_KEY] = o.score;
    states[OVERALL_KEY] = o.state;
    for (const k of STANDARD_KEYS) {
      // ⛔ A standard MISSING from the stored JSON is read exactly like a
      // stored null: the row exists and holds no score for it. It is not a
      // zero and it is not an absent day. `readScore(undefined)` is the one
      // call that makes those two inputs land in the same honest bucket.
      const s = readScore(byStandardRaw[k]);
      values[k] = s.score;
      states[k] = s.state;
    }
    byDay.set(day, { values, states });
  }

  const measuredDays = [...byDay.keys()].sort();
  if (measuredDays.length === 0) {
    return {
      ...base,
      available: false,
      unavailableReason:
        'Nightly fleet snapshots exist but none of them carries a readable date, so they cannot be placed in time. This is a fault, not an empty history.',
      caption: 'history unavailable',
      window: { ...base.window, unreadableDates, duplicateDates },
    };
  }

  // ── Walk the calendar, filling the interior only ───────────────────────
  let firstDay = measuredDays[0];
  const lastDay = measuredDays[measuredDays.length - 1];
  let truncated = false;
  if (daysBetween(firstDay, lastDay) + 1 > MAX_SPAN_DAYS) {
    // Keep the NEWEST window — a trend chart that silently showed the oldest
    // 400 days of a longer history would be stale data wearing a current
    // label. Reported in `window.truncated` and in the caption.
    firstDay = addDays(lastDay, -(MAX_SPAN_DAYS - 1));
    truncated = true;
  }

  const points = [];
  const summary = { overall: emptySeriesSummary(), byStandard: {} };
  for (const k of STANDARD_KEYS) summary.byStandard[k] = emptySeriesSummary();
  const seriesSummary = (key) => (key === OVERALL_KEY ? summary.overall : summary.byStandard[key]);
  const allKeys = [OVERALL_KEY, ...STANDARD_KEYS];

  let snapshotDays = 0;
  let absentDays = 0;
  let cursor = firstDay;
  for (;;) {
    const hit = byDay.get(cursor);
    const point = { day: cursor, presence: hit ? SNAPSHOT : ABSENT, states: {} };
    if (hit) {
      snapshotDays += 1;
      for (const key of allKeys) {
        point[key] = hit.values[key];
        point.states[key] = hit.states[key];
        const s = seriesSummary(key);
        if (hit.states[key] === MEASURED) {
          s.readings += 1;
          const reading = { day: cursor, score: hit.values[key] };
          if (s.earliest === null) s.earliest = reading;
          s.latest = reading;
        } else if (hit.states[key] === UNMEASURABLE) {
          s.unmeasurable += 1;
        } else {
          s.unreadable += 1;
        }
      }
    } else {
      absentDays += 1;
      for (const key of allKeys) {
        // ⛔ null, never 0, and never the previous day's value. This is the
        // single line that decides whether the chart tells the truth about
        // the four days the reference deployment permanently lost.
        point[key] = null;
        point.states[key] = NOT_RECORDED;
        seriesSummary(key).notRecorded += 1;
      }
    }
    points.push(point);
    if (cursor === lastDay) break;
    cursor = addDays(cursor, 1);
  }

  const delta = { overall: deltaFor(summary.overall), byStandard: {} };
  for (const k of STANDARD_KEYS) delta.byStandard[k] = deltaFor(summary.byStandard[k]);

  const trend = {
    ...base,
    available: true,
    unavailableReason: null,
    points,
    summary,
    delta,
    window: {
      firstDay,
      lastDay,
      spanDays: points.length,
      snapshotDays,
      absentDays,
      requestedDays,
      truncated,
      unreadableDates,
      duplicateDates,
    },
    unrecognisedStandards: [...unrecognised].sort(),
  };
  trend.caption = trendCaption(trend);
  return trend;
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

/**
 * The visible one-line statement of what this chart is drawn from.
 *
 * ⛔ THIS IS NOT DECORATION AND IT MAY NOT LIVE IN A TOOLTIP. A 3-day window
 * and a 90-day window produce chart geometry that is indistinguishable at a
 * glance, and a short history read as a long one turns three days of noise
 * into a quarter-long trend. The span, the number of real snapshots behind it,
 * and both kinds of gap are all stated here, on screen.
 *
 * ⛔ THE TWO GAP COUNTS ARE PRINTED SEPARATELY, never summed — see the file
 * header. The caller is given both numbers and no total, so there is nothing
 * to render that would hide which one it has.
 */
function trendCaption(trend) {
  if (!trend || !trend.available) return trend && trend.caption ? trend.caption : 'no history';
  const w = trend.window;
  const parts = [];

  const span =
    w.requestedDays && w.spanDays < w.requestedDays
      ? `${plural(w.spanDays, 'day', 'days')} of history (asked for ${w.requestedDays})`
      : `${plural(w.spanDays, 'day', 'days')} of history`;
  parts.push(`${span}, ${w.firstDay} → ${w.lastDay}`);
  parts.push(plural(w.snapshotDays, 'nightly snapshot', 'nightly snapshots'));

  // ⛔ Each gap is named by its CAUSE. "4 days never recorded" sends an
  // operator to the engine; "2 days nothing gradeable" sends them to
  // compliance coverage. A combined "6 days missing" sends them nowhere.
  if (w.absentDays > 0) parts.push(`${plural(w.absentDays, 'day', 'days')} never recorded`);
  const un = trend.summary.overall.unmeasurable;
  if (un > 0) parts.push(`${plural(un, 'day', 'days')} nothing gradeable`);
  const bad = trend.summary.overall.unreadable;
  if (bad > 0) parts.push(`${plural(bad, 'day', 'days')} unreadable`);
  if (w.truncated) parts.push(`showing the most recent ${MAX_SPAN_DAYS} days`);

  return parts.join(' · ');
}

module.exports = {
  // identity
  TREND_CLAIM,
  STANDARD_KEYS,
  STANDARD_LABELS,
  OVERALL_KEY,
  MAX_SPAN_DAYS,
  // day presence
  SNAPSHOT,
  ABSENT,
  // value states
  MEASURED,
  UNMEASURABLE,
  UNREADABLE,
  NOT_RECORDED,
  // pure
  isoDay,
  readScore,
  buildComplianceTrend,
  deltaFor,
  seriesStatus,
  pointReason,
  trendCaption,
};
