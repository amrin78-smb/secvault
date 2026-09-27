'use strict';

// lib/engines/changeOutcomeData.js
//
// A7's PLUMBING. Fetches the three things `changeOutcome.js` needs — the active
// firewalls, each one's daily traffic series, and each config change with the
// traffic either side of it — and hands them to that pure engine unchanged.
//
// ⛔ SPLIT FROM changeOutcome.js DELIBERATELY, the same split
// coverageRegister/coverageRegisterData, segmentation/segmentationData and
// applicationView/applicationViewData already use. That file is pure (a series
// and a change list in, a verdict out), which is what lets a test drive every
// branch with literal data. Nothing here decides anything: it queries, it
// shapes, and it reports what it could not read.
//
// ⛔ READ TIME. NO TABLE, NO CRON JOB, NO CACHE. A stored verdict is a function
// of the traffic window it was computed over, and a stored one goes stale and is
// then read as fact — the rule /segmentation and /applications already follow.
//
// ── ⛔ WHAT THIS FILE MUST GET RIGHT ──────────────────────────────────────
//
// 1. ⛔ THE RAW EVENT TABLE IS FORBIDDEN HERE. Every traffic figure comes from
//    `syslog_rollup_hourly`. The raw table carries ~28M rows/day in daily
//    partitions with no index that would serve a per-device time range, and a
//    sum over it would land its cost on a page render while the collector is
//    inserting at ~1,000 rows/sec. `tests/changeOutcomeData.test.js` scans this
//    file with comments stripped and fails the build if that table is named in
//    the code, so this paragraph cannot satisfy the scan.
//
// 2. ⛔ A FAILED READ IS REPORTED, NEVER RENDERED AS A QUIET FLEET. If any of
//    the three statements throws, this returns `devices: []` WITH a populated
//    `failures`, and the caller must refuse to print a verdict or a count while
//    it is non-empty. The alternative is the worst answer this feature can give:
//    zero changes assessed reads exactly like a fleet whose changes were all
//    uneventful. An empty result and an unreadable one must never look alike.
//
// 3. ⛔ ONE ROW PER ACTIVE FIREWALL, DRIVEN FROM `devices`. A firewall that
//    sends no syslog has no rollup rows at all, so driving this from the traffic
//    table would DROP exactly the firewall whose verdicts are least trustworthy.
//    Live, PAKFood is that firewall: it sends nothing, so no band can be built
//    for it, and `insufficient_baseline` is the honest answer rather than
//    silence.
//
// 4. ⛔ `null`, NEVER 0, FOR A COUNT THAT DID NOT ARRIVE. `countOrNull` is the
//    only thing standing between "we hold no traffic in that window" and "we
//    could not read the traffic in that window", and `Number(null)` is 0.
//
// ── ⛔ THE DAILY BUCKET IS THE SERVER'S LOCAL DAY ─────────────────────────
//
// `date_trunc('day', bucket_hour)` resolves in the database session's own
// timezone, which on the reference deployment is Asia/Bangkok. That is the same
// assumption every fixed-HH:MM cron job in this product already makes, and it
// is deliberately not overridden here: the engine only ever uses consecutive
// days to measure how much a firewall varies from one day to the next, and a
// consistent boundary is all that requires. ⛔ It would matter if a day
// boundary were ever compared against a UTC timestamp from elsewhere, so do not
// start mixing the two.

const {
  assessDevice,
  summariseOutcomes,
  DEFAULT_WINDOW_HOURS,
} = require('./changeOutcome');

// ⛔ THE WINDOW IS BOUNDED, AND NOT AS A TUNING KNOB. The engine's own header
// records the measurement: 61 changes have a complete 24h window either side
// and only 18 have 7 days, so widening this buys precision by discarding most
// of the subject. The bound exists so a caller cannot pass something that makes
// the interval arithmetic meaningless, and anything outside it falls back to the
// engine's default rather than being clamped to an edge — a value nobody chose
// is safer than a value silently rewritten to the extreme.
const MIN_WINDOW_HOURS = 1;
const MAX_WINDOW_HOURS = 168;

/**
 * ⛔ COUNTS COME BACK FROM `pg` AS STRINGS. `sum(...)` over a `bigint` column is
 * `numeric`/`bigint`, which node-postgres hands over as a STRING rather than
 * silently truncating past 2^53. Both shapes go through here so the engine is
 * handed one consistent type, and so the one value that must never be coerced —
 * SQL NULL — stays null.
 *
 * `null` means the figure could not be read at all. It is not zero. The engine
 * turns a null side of a window into `no_traffic_window` rather than into a
 * delta, which is the whole reason this distinction is kept alive this far down.
 */
function countOrNull(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/**
 * ⛔ `deviceIds` DISTINGUISHES "NO FILTER" FROM "NO DEVICES", and the two are
 * opposite instructions — the asymmetry `ldapRoles.js` draws between no mappings
 * configured and no mapping matched, and the one `coverageRegisterData.js` and
 * `upgradePlanData.js` already draw for this same parameter.
 *
 *   undefined / null  the whole active fleet (the ordinary call)
 *   []                NO firewalls — a scoped account granted nothing
 *   [id, …]           exactly those
 *
 * Returned as a parameter for `= ANY($1::uuid[])`, never interpolated.
 */
function normaliseDeviceIds(deviceIds) {
  if (deviceIds === null || deviceIds === undefined) return null;
  if (!Array.isArray(deviceIds)) return null;
  return deviceIds.filter((id) => typeof id === 'string' && id.length > 0);
}

function normaliseWindowHours(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return DEFAULT_WINDOW_HOURS;
  const whole = Math.trunc(n);
  if (whole < MIN_WINDOW_HOURS || whole > MAX_WINDOW_HOURS) return DEFAULT_WINDOW_HOURS;
  return whole;
}

/** A thrown non-Error still has to read as something. */
function errorText(err) {
  return (err && err.message) ? err.message : String(err);
}

// ─────────────────────────────────────────────────────────────────────────
// The statements
// ─────────────────────────────────────────────────────────────────────────

// ⛔ THE DRIVER. Inactive firewalls are excluded, matching every other fleet
// read in this product; a firewall with no traffic and no changes still gets a
// row, carrying the verdict that says so.
const DEVICES_SQL = `
  SELECT d.id, d.name, d.vendor
    FROM devices d
   WHERE d.active
     AND ($1::uuid[] IS NULL OR d.id = ANY($1::uuid[]))
   ORDER BY d.name
`;

// The daily traffic series each firewall's band is measured from.
//
// ⛔ `device_id IS NOT NULL` is not tidiness. The collector deliberately stores
// an unmatched sender with a null `device_id`, and those rows belong to no
// firewall in this fleet; folding them into a group would build a band for a
// firewall out of another host's traffic.
const SERIES_SQL = `
  SELECT s.device_id,
         date_trunc('day', s.bucket_hour) AS day,
         sum(s.event_count)::bigint       AS events
    FROM syslog_rollup_hourly s
   WHERE s.device_id IS NOT NULL
     AND ($1::uuid[] IS NULL OR s.device_id = ANY($1::uuid[]))
   GROUP BY 1, 2
   ORDER BY 1, 2
`;

// Every config change on an active firewall, with the traffic either side.
//
// ⛔ THE COLUMNS ARE `change_summary`, `detected_at`, `diff` — there is NO
// `changes` column on `config_diffs`, and a wrong name here does not degrade
// gracefully: the statement throws and the whole board comes back empty.
//
// ⛔ THE HALF-OPEN BOUNDS ARE DELIBERATE AND MUST STAY THAT WAY. `before` is
// [detected_at - window, detected_at) and `after` is [detected_at, detected_at +
// window), so the hour the change was detected in belongs to exactly one side.
// Overlapping them would count that hour twice and shrink every delta towards
// zero, which on this board reads as "nothing stands out" — a reassuring
// artefact rather than a measurement.
//
// ⛔ `coalesce(..., 0)` IS CORRECT HERE AND IS NOT A FABRICATED ZERO. An empty
// sum means SecVault holds no buckets for that firewall in those hours, which
// the engine reads as `no_traffic_window` rather than as a delta — it never
// becomes a percentage. What would be fabricated is a zero standing in for a
// statement that failed to read, and that cannot arise from an aggregate.
//
// ⛔ COMPOSITE ORDER (`detected_at DESC, id DESC`), the same stability rule the
// Changes page's own diff list follows: two diffs detected in one collection run
// can share a timestamp, and an unstable order silently reshuffles them.
const CHANGES_SQL = `
  SELECT cd.id,
         cd.device_id,
         cd.detected_at,
         cd.change_summary,
         (SELECT coalesce(sum(s.event_count), 0)::bigint
            FROM syslog_rollup_hourly s
           WHERE s.device_id = cd.device_id
             AND s.bucket_hour >= cd.detected_at - ($2::int * interval '1 hour')
             AND s.bucket_hour <  cd.detected_at)                            AS before_events,
         (SELECT coalesce(sum(s.event_count), 0)::bigint
            FROM syslog_rollup_hourly s
           WHERE s.device_id = cd.device_id
             AND s.bucket_hour >= cd.detected_at
             AND s.bucket_hour <  cd.detected_at + ($2::int * interval '1 hour')) AS after_events
    FROM config_diffs cd
    JOIN devices d ON d.id = cd.device_id
   WHERE d.active
     AND ($1::uuid[] IS NULL OR cd.device_id = ANY($1::uuid[]))
   ORDER BY cd.device_id, cd.detected_at DESC, cd.id DESC
`;

/**
 * One series row → the engine's `{day, events}`.
 * ⛔ `events` may be null (unreadable) and stays null; the engine drops a row it
 * cannot read from the band rather than treating it as a silent day.
 */
function toSeriesPoint(row) {
  return { day: row.day, events: countOrNull(row.events) };
}

/**
 * One `config_diffs` row → the engine's change shape.
 *
 * ⛔ SPELLED OUT ONE KEY PER LINE. A key this function misnames does not fail
 * loudly — the engine reads `undefined`, treats the side as unreadable, and
 * reports `no_traffic_window` on a change whose window SecVault holds in full.
 * A wrong verdict that looks like a coverage gap is the hardest kind to notice.
 */
function toChange(row) {
  return {
    id: row.id,
    detectedAt: row.detected_at,
    summary: row.change_summary || null,
    beforeEvents: countOrNull(row.before_events),
    afterEvents: countOrNull(row.after_events),
  };
}

function groupBy(rows, key, shape) {
  const out = new Map();
  for (const row of rows) {
    const id = row[key];
    if (!id) continue;
    if (!out.has(id)) out.set(id, []);
    out.get(id).push(shape(row));
  }
  return out;
}

/**
 * What followed each configuration change, computed at read time.
 *
 * @param {object} pool  ⛔ A PARAMETER, never imported — CLAUDE.md's Database
 *   rule. A function that loses it breaks DB access silently: builds clean,
 *   fails at runtime.
 * @param {object} [opts]
 * @param {string[]|null} [opts.deviceIds] restrict to these firewalls; see
 *   normaliseDeviceIds for why `[]` and `undefined` are opposite instructions.
 * @param {number} [opts.windowHours] hours either side, default 24. Bounded,
 *   and not a knob for making results appear — see MIN/MAX above.
 * @param {Date|string} [opts.now] injectable clock, so `generatedAt` is
 *   pinnable by a test rather than being whatever the suite ran at.
 * @returns {Promise<{devices:Array, summary:object, failures:Array,
 *                    windowHours:number, generatedAt:string}>}
 *
 * ⛔ `failures` IS PART OF THE ANSWER, NOT A LOG LINE. `devices: []` with a
 * populated `failures` means nothing could be assessed, which is the opposite
 * of "no change here was followed by anything unusual".
 */
async function getChangeOutcomes(pool, opts = {}) {
  const ids = normaliseDeviceIds(opts.deviceIds);
  const windowHours = normaliseWindowHours(opts.windowHours);
  const generatedAt = (opts.now ? new Date(opts.now) : new Date()).toISOString();
  const failures = [];

  // ⛔ AN EMPTY ID LIST IS AN INSTRUCTION, NOT A FAILURE. A scoped account
  // granted no firewalls gets an empty board and NO failures entry — the two
  // must stay distinguishable, since one says "you may see nothing" and the
  // other says "we could not look".
  if (ids !== null && ids.length === 0) {
    return {
      devices: [],
      summary: summariseOutcomes([]),
      failures,
      windowHours,
      generatedAt,
    };
  }

  let deviceRows = [];
  let seriesRows = [];
  let changeRows = [];

  // Three sources, three try/catch blocks, three distinct `failures` entries.
  // ⛔ NOT FOLDED TOGETHER. Which read failed changes what an operator does
  // next, and a single "could not build the board" line would hide that.
  try {
    const res = await pool.query(DEVICES_SQL, [ids]);
    deviceRows = (res && Array.isArray(res.rows)) ? res.rows : [];
  } catch (err) {
    failures.push({ source: 'devices', error: errorText(err) });
  }

  try {
    const res = await pool.query(SERIES_SQL, [ids]);
    seriesRows = (res && Array.isArray(res.rows)) ? res.rows : [];
  } catch (err) {
    failures.push({ source: 'traffic_series', error: errorText(err) });
  }

  try {
    const res = await pool.query(CHANGES_SQL, [ids, windowHours]);
    changeRows = (res && Array.isArray(res.rows)) ? res.rows : [];
  } catch (err) {
    failures.push({ source: 'config_changes', error: errorText(err) });
  }

  // ⛔ NOTHING IS ASSESSED WHILE ANY SOURCE IS MISSING, AND THIS IS THE CENTRAL
  // RULE OF THIS FILE. Assessing on a partial read would not merely lose rows:
  //   · no series ⇒ every firewall reports `insufficient_baseline`, which is a
  //     CLAIM about that firewall's history rather than about our failed read;
  //   · no changes ⇒ every firewall reports zero changes, which reads as a
  //     fleet nobody has touched.
  // Both are confident, plausible and wrong, so the board refuses to exist
  // instead — not because the rows are worthless, but because a shorter list
  // here is indistinguishable from a quieter fleet. `failures` carries the
  // reason and the caller renders it.
  if (failures.length > 0) {
    return {
      devices: [],
      summary: summariseOutcomes([]),
      failures,
      windowHours,
      generatedAt,
    };
  }

  const seriesByDevice = groupBy(seriesRows, 'device_id', toSeriesPoint);
  const changesByDevice = groupBy(changeRows, 'device_id', toChange);

  // ⛔ IN THE ORDER THE DRIVER GAVE THEM (by name). There is deliberately no
  // ranking here: the engine publishes none, and inventing one in the plumbing
  // would put a judgement in the layer whose whole job is to avoid making any.
  const devices = deviceRows.map((row) => assessDevice(
    { deviceId: row.id, deviceName: row.name, vendor: row.vendor },
    seriesByDevice.get(row.id) || [],
    changesByDevice.get(row.id) || [],
    { windowHours },
  ));

  return {
    devices,
    summary: summariseOutcomes(devices),
    failures,
    windowHours,
    generatedAt,
  };
}

/**
 * The same answer for ONE firewall, which is how the per-firewall Changes page
 * consumes it.
 *
 * ⛔ A MISSING OR MALFORMED ID IS A FAILURE, NOT "NO FILTER". Passing it
 * straight through as `deviceIds: [deviceId]` would have `normaliseDeviceIds`
 * drop it, leaving `[]` — which this module defines as "no firewalls, and that
 * is fine" — so a broken link would render a clean empty board for a firewall
 * that exists. Worse, a bare `undefined` would mean the WHOLE FLEET, printing
 * another firewall's changes under this one's name.
 *
 * @returns {Promise<{device:object|null, devices:Array, summary:object,
 *                    failures:Array, windowHours:number, generatedAt:string}>}
 */
async function getDeviceChangeOutcome(pool, deviceId, opts = {}) {
  if (typeof deviceId !== 'string' || deviceId === '') {
    return {
      device: null,
      devices: [],
      summary: summariseOutcomes([]),
      failures: [{
        source: 'device',
        error: 'No firewall was named, so nothing was assessed.',
      }],
      windowHours: normaliseWindowHours(opts.windowHours),
      generatedAt: (opts.now ? new Date(opts.now) : new Date()).toISOString(),
    };
  }
  const answer = await getChangeOutcomes(pool, { ...opts, deviceIds: [deviceId] });
  return { ...answer, device: answer.devices[0] || null };
}

module.exports = {
  getChangeOutcomes,
  getDeviceChangeOutcome,
  MIN_WINDOW_HOURS,
  MAX_WINDOW_HOURS,
};
