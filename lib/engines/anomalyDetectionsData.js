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
  describeSilence, describeSpike, SILENCE_MIN_HOURS,
} = require('./anomalyDetections');

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
 */
async function loadReportingGrid(pool, { days = LOOKBACK_DAYS } = {}) {
  const { rows } = await pool.query(
    `WITH hours AS (
       SELECT generate_series(date_trunc('hour', now()) - ($1 || ' days')::interval,
                              date_trunc('hour', now()) - interval '1 hour',
                              interval '1 hour') AS h
     ),
     dev AS (
       SELECT d.id, d.name FROM devices d
        WHERE d.active = true
          AND EXISTS (SELECT 1 FROM syslog_rollup_hourly r WHERE r.device_id = d.id)
     ),
     seen AS (
       SELECT device_id, bucket_hour FROM syslog_rollup_hourly
        WHERE device_id IS NOT NULL
          AND bucket_hour >= date_trunc('hour', now()) - ($1 || ' days')::interval
        GROUP BY 1, 2
     )
     SELECT dev.id::text AS device_id, dev.name AS device_name, hours.h AS at,
            (seen.device_id IS NOT NULL) AS reported
       FROM dev CROSS JOIN hours
       LEFT JOIN seen ON seen.device_id = dev.id AND seen.bucket_hour = hours.h
      ORDER BY dev.name, hours.h`,
    [String(days)]
  );
  const byDevice = new Map();
  for (const r of rows) {
    if (!byDevice.has(r.device_id)) byDevice.set(r.device_id, { name: r.device_name, hours: [] });
    byDevice.get(r.device_id).hours.push({ at: r.at, reported: r.reported });
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

/** A stable key per (detector, device, event start) so a sustained event is ONE alert. */
function naturalKey(alertType, deviceId, startAt) {
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
    device_silent: { measured: 0, no_data: 0, insufficient_baseline: 0 },
    denied_spike: { measured: 0, no_data: 0, insufficient_baseline: 0 },
  };

  const grid = await loadReportingGrid(pool, { days });
  for (const [deviceId, { name, hours }] of grid) {
    const r = detectSilence(hours, { minHours: opts.silenceMinHours ?? SILENCE_MIN_HOURS });
    states.device_silent[r.state] = (states.device_silent[r.state] || 0) + 1;
    if (r.state !== DETECTOR_STATES.MEASURED) continue;
    for (const run of r.runs) {
      findings.push({
        detector: 'device_silent',
        alertType: DETECTORS.device_silent.alertType,
        naturalKey: naturalKey(DETECTORS.device_silent.alertType, deviceId, run.startAt),
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
      });
    }
  }

  const denied = await loadDeniedSeries(pool, { days });
  for (const [deviceId, { name, series }] of denied) {
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
        naturalKey: naturalKey(DETECTORS.denied_spike.alertType, deviceId, run.startAt),
        deviceId,
        deviceName: name,
        // \u26d4 Not "spike": see describeSpike's note. The measured exceedance is
        // often a few percent, and the title must not promise more than that.
        title: `Denied traffic above normal on ${name}`,
        summary: describeSpike(run, name),
        path: `/devices/${deviceId}`,
        startAt: run.startAt,
        hours: run.hours,
      });
    }
  }

  return { findings, states };
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
  LOOKBACK_DAYS,
  loadReportingGrid,
  loadDeniedSeries,
  gatherAnomalies,
  fetchOpenAnomalies,
  naturalKey,
};
