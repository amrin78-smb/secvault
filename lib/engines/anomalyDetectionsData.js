// lib/engines/anomalyDetectionsData.js
//
// A6 stage 2 — the plumbing. Loads hourly rollups and runs the detectors in
// `anomalyDetections.js`, which is pure and holds the judgement.
//
// ⛔ A PARTIAL LOAD THROWS. IT MUST NEVER RETURN A SHORTER LIST.
// `notificationDispatch.js` reconciles by clearing every `natural_key` that is
// NOT in the list it is handed — that is what lets a genuine re-occurrence
// re-notify. So a fetcher that silently returned fewer items on a bad query
// would mark real, still-open security findings RESOLVED, then re-notify on
// recovery. CLAUDE.md records exactly this for the work queue ("silence for one
// cycle is recoverable; a false all-clear is not"), and the same rule binds
// here. Every query below is unguarded on purpose: a throw reaches the
// dispatcher's per-type catch, which logs and `continue`s BEFORE the reconcile.
//
// ⛔ DETECTION IS NOT GATED BY THE ALERT TOGGLE. Whether a channel subscribes to
// `anomaly_*` decides whether an alert is SENT, never whether the measurement
// happens. A switch that stopped the product measuring would reproduce its own
// most-repeated bug: a thing that is not assessed renders as healthy.
//
// ⛔ ROLLUPS ONLY — `syslog_events` is refused (no `src_ip` index, ~28M rows/day,
// and the write cost of adding one lands on the collector). The same refusal
// VPN traffic attribution and log search both make.

'use strict';

const {
  DETECTORS, DETECTOR_STATES, detectSilence, detectSpike,
  describeSilence, describeSpike, SILENCE_MIN_HOURS, rateDrift, RATE_STATES,
} = require('./anomalyDetections');

// ⛔ Per-process, so a drift notice appears once rather than once per page load.
const WARNED_DRIFT = new Set();

/** How much history to load. More is better for the baseline; this is cheap. */
const LOOKBACK_DAYS = 28;

const DENIED_ACTIONS_SQL = `('deny','drop','drop-packet','block','blocked','denied','discard',
  'block-url','block-ip','block-continue','block-override','reset-both','reset-client','reset-server')`;

/**
 * Hour-by-hour reporting grid per device: did this device produce ANY rollup row
 * in this hour?
 *
 * ⛔ THE GRID IS GENERATED, NOT READ. An hour a device did not report has NO
 * ROW, so a plain SELECT cannot see it — the absence is the signal, and it only
 * exists relative to a complete set of hours. This is the one place in the
 * product where a missing row is the measurement rather than a gap in one.
 *
 * ⛔ AND THE DEVICE LIST IS THE FLEET, NOT THE ROLLUP (fixed v2.237.3). The
 * `dev` CTE used to carry `AND EXISTS (SELECT 1 FROM syslog_rollup_hourly r
 * WHERE r.device_id = d.id)`, so a firewall that has NEVER produced a rollup
 * row was not in the grid at all: `gatherAnomalies` iterates this map, so that
 * device reached no detector, incremented no `states` bucket, and was missing
 * from the numerator AND the denominator. The absence was the signal for an
 * HOUR and silently became a gap for a DEVICE.
 *
 * ⛔ IT WAS A RECORDED RESIDUAL, NOT AN UNKNOWN. `components/alerts/
 * AnomalyPanel.js` named it when v2.237.1 fixed the neighbouring case —
 * "a monitoring-only firewall and PAKFood (which sends no syslog) are invisible
 * to it, so 13-of-16 judged reads exactly like 16". Writing a gap down does not
 * close it.
 *
 * ⛔ MEASURED ON PRODUCTION 2026-11-24: 17 active firewalls, `measured` 15,
 * `no_data` **0**. The two uncounted were PAKFood (has never sent syslog) and
 * StarUnion (added logs-only that afternoon). CLAUDE.md asserted PAKFood was
 * "correctly `no_data`" — two files in this repo disagreed about one firewall,
 * and the measured one was right.
 *
 * ⛔ IT CANNOT MANUFACTURE AN ALERT, WHICH IS WHAT MAKES IT SAFE.
 * `detectSilence` receives an all-silent grid plus an EXPLICIT `null`
 * `lastReportedAt` (never `undefined` — `loadLastReported` simply has no row
 * for it), which is its "never reported" arm: state `no_data`, zero runs, and
 * `gatherAnomalies` `continue`s on any state that is not MEASURED or
 * STOPPED_BEFORE_WINDOW. A firewall that never started is UNCOLLECTED, not
 * silent — saying "stopped logging" about it would send somebody hunting an
 * outage that never happened. This adds a COUNT and never a finding.
 *
 * ⛔ The v2.230.0 case is untouched: the old EXISTS was UNWINDOWED, so a device
 * with rollup rows only outside the window was already here and still resolves
 * to `stopped_before_window`.
 *
 * ⛔ EACH DEVICE'S GRID STARTS THE HOUR IT WAS CREATED (v2.237.4), BECAUSE A
 * FIREWALL CANNOT HAVE BEEN SILENT BEFORE SECVAULT KNEW IT EXISTED.
 * `syslog_rollup_hourly.device_id` is stamped at INGEST, so a row cannot
 * predate the device — which means a newly-added firewall's first 28 days of
 * grid are silent by construction, and `detectSilence` read that as one long
 * silence run.
 *
 * ⛔ MEASURED ON PRODUCTION 2026-11-24, 48 minutes after the fleet's first
 * logs-only device was added: *"StarUnion stopped sending syslog — AT LEAST 671
 * hours"*, about a firewall that was created at 14:28 and was sending at the
 * moment the alert was generated. ⛔ **It is NOT a regression from the EXISTS
 * removal above** — StarUnion had rollup rows by then, so the old predicate
 * admitted it too. It is a defect that needed a firewall to be ADDED to show
 * itself, which on this fleet had not happened in months.
 *
 * ⛔ IT WOULD HAVE BEEN DISPATCHED. `device_silent` is a registered A6 detector
 * whose alert type is in `notificationDispatch.js`'s ALERT_TYPES, so on an
 * installation with channels configured, onboarding a firewall would email an
 * outage alert about it. (This deployment has none, which is why it was only
 * ever on screen.)
 *
 * ⛔ `gridStartsAtBirth` TRAVELS WITH THE GRID AND SUPPRESSES `truncated`.
 * v2.228.10 flags a run at index 0 as having no known start, because the
 * window's left edge MOVES every hour. A grid trimmed to `created_at` has a
 * FIXED index 0, so the same flag would claim the start is unknown when it is
 * the best-recorded fact about the run. The two cases must not share an answer.
 *
 * ⛔ WHAT IT DELIBERATELY DOES NOT DO: suppress a gap between a device being
 * created and its first log arriving. That gap is real and observed — SecVault
 * was listening and nothing came — and it is bounded by the onboarding itself.
 * A device that has NEVER reported still has no rollup rows at all and so is
 * `no_data`, not silent. ⛔ `LEAST(created_at, now())` guards a created_at in
 * the future: a clock disagreement must not produce an EMPTY grid, which the
 * all-silent branch would read as total silence.
 */
async function loadReportingGrid(pool, { days = LOOKBACK_DAYS } = {}) {
  const { rows } = await pool.query(
    `WITH hours AS (
       SELECT generate_series(date_trunc('hour', now()) - ($1 || ' days')::interval,
                              date_trunc('hour', now()) - interval '1 hour',
                              interval '1 hour') AS h
     ),
     dev AS (
       -- EVERY ACTIVE FIREWALL, NOT ONLY THE ONES WITH EVIDENCE, and each one
       -- carries the hour it was CREATED so its grid can start there. Full
       -- reasoning in the JS comment above this function -- NOT here, because
       -- a backtick inside a template literal ends the literal, which has now
       -- cost this repo three syntax errors.
       -- LEAST(created_at, now()) because a created_at in the future is a
       -- clock disagreement, and an empty grid would be read as total silence.
       SELECT d.id, d.name,
              date_trunc('hour', LEAST(d.created_at, now())) AS born
         FROM devices d
        WHERE d.active = true
     ),
     seen AS (
       SELECT device_id, bucket_hour FROM syslog_rollup_hourly
        WHERE device_id IS NOT NULL
          AND bucket_hour >= date_trunc('hour', now()) - ($1 || ' days')::interval
        GROUP BY 1, 2
     )
     SELECT dev.id::text AS device_id, dev.name AS device_name, hours.h AS at,
            (seen.device_id IS NOT NULL) AS reported,
            (dev.born > (SELECT min(h) FROM hours)) AS grid_starts_at_birth
       FROM dev CROSS JOIN hours
       LEFT JOIN seen ON seen.device_id = dev.id AND seen.bucket_hour = hours.h
      WHERE hours.h >= dev.born
      ORDER BY dev.name, hours.h`,
    [String(days)]
  );
  const byDevice = new Map();
  for (const r of rows) {
    if (!byDevice.has(r.device_id)) {
      byDevice.set(r.device_id, {
        name: r.device_name,
        hours: [],
        // Index 0 of this device's grid is its CREATION hour, not the window's
        // moving left edge — so a run starting there has a known start.
        gridStartsAtBirth: r.grid_starts_at_birth === true,
      });
    }
    byDevice.get(r.device_id).hours.push({ at: r.at, reported: r.reported });
  }
  return byDevice;
}

/**
 * The last hour each device produced ANY rollup row, UNBOUNDED by the window.
 *
 * ⛔ THIS IS THE ONE READ IN THIS FILE THAT DELIBERATELY IGNORES THE WINDOW,
 * AND THAT IS THE WHOLE POINT. `loadReportingGrid` can only report what is
 * inside 28 days; a firewall dark for 29 looks identical to one that never
 * existed, and the detector went silent exactly as the silence became total.
 * The answer is not in the grid at any window length — widening it only moves
 * the boundary — so it comes from the permanent table instead.
 *
 * ⛔ IT IS AFFORDABLE BECAUSE `syslog_rollup_hourly` IS THE PERMANENT,
 * LOW-CARDINALITY ROLLUP, NEVER `syslog_events`. One grouped MAX over the whole
 * table (8.0 GiB, ~159k rows) and never an event scan — the refusal
 * `logSearch.js` and the VPN attribution both record.
 *
 * ⛔ A DEVICE MISSING FROM THE RESULT HAS NEVER REPORTED, which the caller
 * passes on as an explicit `null`. It must not be left undefined: "nobody
 * asked" and "it never reported" are different answers and `detectSilence`
 * refuses to collapse them.
 */
async function loadLastReported(pool) {
  const { rows } = await pool.query(
    `SELECT device_id::text AS device_id, max(bucket_hour) AS last_at
       FROM syslog_rollup_hourly
      WHERE device_id IS NOT NULL
      GROUP BY 1`
  );
  const byDevice = new Map();
  for (const r of rows) {
    if (r.last_at instanceof Date) byDevice.set(r.device_id, r.last_at);
  }
  return byDevice;
}

/**
 * Denied events per device-hour, for hours the device actually reported.
 *
 * ⛔ A DEVICE-HOUR WITH TRAFFIC BUT NO DENIES IS A GENUINE ZERO; A DEVICE-HOUR
 * WITH NO ROWS AT ALL IS MISSING AND IS EXCLUDED. Counting the second as zero
 * would drag every threshold down and suppress the spikes this exists to find —
 * and the silence detector above is what covers those hours instead.
 */
async function loadDeniedSeries(pool, { days = LOOKBACK_DAYS } = {}) {
  const { rows } = await pool.query(
    `WITH reporting AS (
       SELECT device_id, bucket_hour FROM syslog_rollup_hourly
        WHERE device_id IS NOT NULL
          AND bucket_hour >= date_trunc('hour', now()) - ($1 || ' days')::interval
        GROUP BY 1, 2
     )
     SELECT r.device_id::text AS device_id, d.name AS device_name, r.bucket_hour AS at,
            COALESCE(SUM(s.event_count) FILTER (WHERE s.action IN ${DENIED_ACTIONS_SQL}), 0)::bigint AS value
       FROM reporting r
       JOIN devices d ON d.id = r.device_id AND d.active = true
       LEFT JOIN syslog_rollup_hourly s
         ON s.device_id = r.device_id AND s.bucket_hour = r.bucket_hour
      GROUP BY 1, 2, 3
      ORDER BY 2, 3`,
    [String(days)]
  );
  const byDevice = new Map();
  for (const r of rows) {
    if (!byDevice.has(r.device_id)) byDevice.set(r.device_id, { name: r.device_name, series: [] });
    byDevice.get(r.device_id).series.push({ at: r.at, value: Number(r.value) });
  }
  return byDevice;
}

// ⛔ THE SENTINEL FOR A RUN WHOSE START IS BEFORE THE EVIDENCE WINDOW. It must
// not contain a timestamp of any kind: the whole defect was a key built from a
// boundary that moves.
const START_BEFORE_WINDOW = 'start-before-window';

/**
 * A stable key per (detector, device, event start) so a sustained event is ONE
 * alert.
 *
 * ⛔ "STABLE" WAS NOT TRUE FOR A RUN THAT SPANS THE WINDOW'S LEFT EDGE, AND
 * THAT IS THIS FUNCTION'S WHOLE JOB. `loadReportingGrid` generates hours from
 * `now() - N days`, so a run that really began earlier has its `startAt`
 * clamped to an edge that ADVANCES EVERY HOUR — and the key with it. The
 * dispatcher's reconcile clears every natural_key absent from the new list, so
 * each hourly tick marked the previous key RESOLVED and raised the next one as
 * a fresh alert: ~24 false resolve/renotify pairs a day, for as long as the run
 * spans the boundary.
 *
 * ⛔ IT IS NOT A RARE CONDITION ON A SCHEDULE. Every silence run that has ever
 * been detected crosses the 28-day boundary eventually, and churns for its own
 * duration while it does — TFM-RN's measured 108-hour run would churn for 108
 * hours. The roadmap row called it latent; what is true is that it is deferred,
 * by exactly the window length.
 *
 * ⛔ A SENTINEL, NOT A GUESSED START. There is nothing stable to key on inside
 * the window — the true start is outside our evidence — so the honest key says
 * "this began before we were looking" and stays the same on every tick. One
 * alert, and when the run finally ages out the key disappears once and
 * reconcile clears it once, which is correct.
 */
function naturalKey(alertType, deviceId, startAt, truncated = false) {
  if (truncated) return `${alertType}:${deviceId}:${START_BEFORE_WINDOW}`;
  const t = startAt instanceof Date ? startAt.toISOString() : String(startAt);
  return `${alertType}:${deviceId}:${t}`;
}

/**
 * Run both detectors across the fleet.
 *
 * @returns {{findings: Array, states: Object}} `states` reports, per detector,
 *   how many devices were MEASURED vs `insufficient_baseline` vs `no_data` —
 *   ⛔ so a detector that judged nothing is visible as such rather than reading
 *   as "nothing is wrong". A gated detector is hatched and hueless, never green.
 */
async function gatherAnomalies(pool, opts = {}) {
  const days = opts.days || LOOKBACK_DAYS;
  const findings = [];
  const states = {
    device_silent: {
      measured: 0, no_data: 0, insufficient_baseline: 0, stopped_before_window: 0,
    },
    denied_spike: { measured: 0, no_data: 0, insufficient_baseline: 0 },
  };

  const grid = await loadReportingGrid(pool, { days });
  // ⛔ READ EVEN WHEN THE GRID IS EMPTY, so the wiring cannot be true only on
  // the happy path. A device missing here has never reported and is passed an
  // explicit null — never `undefined`, which `detectSilence` reads as "nobody
  // asked" and refuses to turn into either verdict.
  const lastReported = await loadLastReported(pool);
  // ⛔ ONE CLOCK FOR THE WHOLE RUN, read once and shared with the rate-drift
  // check below. Two `new Date()` calls in one pass can straddle a day
  // boundary, and `silentDays` is a number an operator acts on.
  const now = opts.now instanceof Date ? opts.now : new Date();
  for (const [deviceId, { name, hours, gridStartsAtBirth }] of grid) {
    const r = detectSilence(hours, {
      minHours: opts.silenceMinHours ?? SILENCE_MIN_HOURS,
      lastReportedAt: lastReported.has(deviceId) ? lastReported.get(deviceId) : null,
      gridStartIsKnown: gridStartsAtBirth === true,
      now,
    });
    states.device_silent[r.state] = (states.device_silent[r.state] || 0) + 1;
    // ⛔ STOPPED_BEFORE_WINDOW IS A JUDGED STATE AND MUST REACH THE FINDINGS.
    // It was the `continue` here that produced the defect: the one firewall on
    // the fleet that had stopped reporting ALTOGETHER was the only one the
    // detector said nothing about.
    if (r.state !== DETECTOR_STATES.MEASURED
      && r.state !== DETECTOR_STATES.STOPPED_BEFORE_WINDOW) continue;
    for (const run of r.runs) {
      findings.push({
        detector: 'device_silent',
        alertType: DETECTORS.device_silent.alertType,
        naturalKey: naturalKey(DETECTORS.device_silent.alertType, deviceId, run.startAt, run.truncated),
        deviceId,
        deviceName: name,
        title: `${name} stopped sending syslog`,
        summary: describeSilence(run, name),
        // ⛔ NOT '/logs'. The filtered log search is the most informative
        // destination, but it needs `view_log_search`, which an OPERATOR does
        // not hold — and /alerts is gated on OPERATE. So that link would be
        // dead for exactly the role most likely to be reading this. The device
        // page is reachable by anyone who can see the finding, and is where you
        // check whether a firewall is actually up.
        path: `/devices/${deviceId}`,
        startAt: run.startAt,
        hours: run.hours,
        // ⛔ CARRIED SO A CONSUMER NEED NOT RE-DERIVE THE ONE FACT THE WINDOW
        // CANNOT GIVE IT. `hours` is null on a stopped-before-window run — a
        // renderer that prints it as 0 repeats the defect one layer out, which
        // is why the measured figure travels beside it under its own name.
        lastReportedAt: run.lastReportedAt || null,
        silentDays: run.silentDays === undefined ? null : run.silentDays,
        stoppedBeforeWindow: r.state === DETECTOR_STATES.STOPPED_BEFORE_WINDOW,
        // ⛔ Carried onto the finding, not just used for the key: `hours` is a
        // LOWER BOUND when this is set, and `startAt` is the window edge rather
        // than a measured start. A consumer that renders either as exact is
        // repeating the defect one layer out.
        truncated: !!run.truncated,
        hoursAreLowerBound: !!run.truncated,
      });
    }
  }

  const denied = await loadDeniedSeries(pool, { days });
  // ⛔ THE DENOMINATOR IS THE FLEET, NOT THE ROLLUP — THE SAME HOLE AS THE GRID,
  // IN THE SECOND DETECTOR. `loadDeniedSeries` derives its device list from a
  // `reporting` CTE bounded to the window, so a firewall dark for the WHOLE
  // window (or that never reported at all) produced no series and so was never
  // iterated: absent from `states.denied_spike` entirely rather than counted as
  // `no_data`.
  //
  // ⛔ FIXED HERE RATHER THAN IN THE SQL, DELIBERATELY. The query's job is to
  // return the series it can measure; the DENOMINATOR is a property of the
  // fleet, and `grid` already holds exactly that set (every active firewall,
  // see `loadReportingGrid`). Restating "which firewalls exist" in a second
  // statement is how two reads of one question drift apart — and `denied` is a
  // subset of `grid` by construction, because its own JOIN filters
  // `d.active = true`.
  //
  // ⛔ AND FIXING ONLY ONE OF THE TWO DETECTORS IS THE TRAP CLAUDE.md NAMES BY
  // NAME ("a fix applied to one of two detectors is a defect waiting to be
  // rediscovered") — it is exactly what happened to the window-edge bug in
  // v2.228.10, where `detectSpike` carried the same defect as `detectSilence`
  // and nobody had noticed.
  //
  // An empty series is `detectSpike`'s own NO_DATA arm, which yields no runs,
  // so this adds a COUNT and can never add a finding.
  for (const [deviceId, { name }] of grid) {
    const series = denied.has(deviceId) ? denied.get(deviceId).series : [];
    const r = detectSpike(series, {
      quantile: opts.quantile,
      minHours: opts.spikeMinHours,
      judgeWindowHours: opts.judgeWindowHours,
    });
    states.denied_spike[r.state] = (states.denied_spike[r.state] || 0) + 1;
    if (r.state !== DETECTOR_STATES.MEASURED) continue;
    for (const run of r.runs) {
      findings.push({
        detector: 'denied_spike',
        alertType: DETECTORS.denied_spike.alertType,
        naturalKey: naturalKey(DETECTORS.denied_spike.alertType, deviceId, run.startAt, run.truncated),
        deviceId,
        deviceName: name,
        // \u26d4 Not "spike": see describeSpike's note. The measured exceedance is
        // often a few percent, and the title must not promise more than that.
        title: `Denied traffic above normal on ${name}`,
        summary: describeSpike(run, name),
        path: `/devices/${deviceId}`,
        startAt: run.startAt,
        hours: run.hours,
        truncated: !!run.truncated,
        hoursAreLowerBound: !!run.truncated,
      });
    }
  }

  // ⛔ THE REGISTERED ALERT RATE IS CHECKED AGAINST WHAT ACTUALLY FIRED, every
  // run (2026-11-14). `assertRegisteredDetector` only ever confirmed the
  // EVIDENCE fields exist, so a rate measured once in October stayed
  // authoritative while the fleet moved — measured at 8.2x for
  // `device_silent` on the day this was added.
  // ⛔ ADDITIVE AND NON-BRANCHING: `rates` rides alongside `findings`, nothing
  // reads it to decide whether to detect, and no caller that ignores it
  // changes behaviour. A meta-check that could disarm a detector would be
  // worse than the drift it reports.
  const counts = { device_silent: 0, denied_spike: 0 };
  for (const f of findings) {
    if (f && typeof f.detector === 'string' && counts[f.detector] !== undefined) counts[f.detector] += 1;
  }
  const rates = {};
  for (const key of Object.keys(counts)) {
    const r = rateDrift(key, counts[key], days, now);
    rates[key] = r;
    // ⛔ IT HAS TO SAY SOMETHING. `rates` riding on the return value is a
    // guard nothing reads — the pattern this codebase names most often — so a
    // drifted rate is logged as well. ⛔ DEDUPED PER PROCESS on
    // `detector:state`, the same call `evidenceWindow.js` makes when it logs
    // once per cache fill: `/alerts` calls this gather on every page load and
    // a line per refresh is noise that gets filtered, which would lose the
    // signal exactly as silence would.
    if (r.state === RATE_STATES.DRIFTED_HIGH || r.state === RATE_STATES.DRIFTED_LOW) {
      const seen = `${key}:${r.state}`;
      if (!WARNED_DRIFT.has(seen)) {
        WARNED_DRIFT.add(seen);
        console.warn(
          `[anomaly-detections] ${key} is ${r.state}: ${r.observedCount} alert(s) in `
          + `${r.windowDays} days against a registered ${r.registeredPerDay}/day `
          + `(expected ${r.expectedCount === null ? '?' : r.expectedCount.toFixed(2)}, `
          + `p=${r.p === null ? '?' : r.p.toExponential(1)}). The rate recorded on `
          + `${r.measuredOn} no longer describes this fleet — re-run scripts/a6Harness.js `
          + 'and update EVIDENCE. Detection is UNCHANGED; this is a measurement notice.'
        );
      }
    }
  }

  return { findings, states, rates };
}

/** Dispatch-shaped fetchers. ⛔ Unguarded on purpose — see the header. */
async function fetchOpenAnomalies(pool, detector) {
  const { findings } = await gatherAnomalies(pool);
  return findings
    .filter((f) => f.detector === detector)
    .map((f) => ({
      naturalKey: f.naturalKey,
      deviceId: f.deviceId,
      deviceName: f.deviceName,
      title: f.title,
      summary: f.summary,
      path: f.path,
    }));
}

module.exports = {
  START_BEFORE_WINDOW,
  LOOKBACK_DAYS,
  loadReportingGrid,
  loadLastReported,
  loadDeniedSeries,
  gatherAnomalies,
  fetchOpenAnomalies,
  naturalKey,
};
