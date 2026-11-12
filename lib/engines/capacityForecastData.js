'use strict';

// lib/engines/capacityForecastData.js
//
// THE PLUMBING FOR THE BANDWIDTH TREND. Fetches the three things
// `capacityForecast.js` needs — the active firewalls, each one's daily byte
// series with its hourly completeness, and whether SecVault holds ANY traffic
// logs for each firewall at all — and hands them to that pure engine unchanged.
//
// ⛔ SPLIT FROM THE ENGINE DELIBERATELY, the same split
// changeOutcome/changeOutcomeData, segmentation/segmentationData and
// applicationView/applicationViewData already use. That file is pure (a series
// in, a trend out), which is what lets a test drive every branch with literal
// data. Nothing here decides anything.
//
// ⛔ READ TIME. NO TABLE, NO CRON JOB, NO SCHEMA CHANGE. The history is already
// permanent in `syslog_rollup_hourly` and a trend is a function of it plus the
// current clock, so a stored projection goes stale and is then read as fact —
// the rule /segmentation, /applications and baseline config drift all follow.
//
// ── ⛔ WHAT THIS FILE MUST GET RIGHT ──────────────────────────────────────
//
// 1. ⛔ THE RAW EVENT TABLE IS FORBIDDEN HERE — `syslog_events` must not be
//    named in the code of this file. Every byte figure comes from
//    `syslog_rollup_hourly`. The raw table carries ~28M rows/day in daily
//    partitions with no index that would serve a per-device time range, and a
//    sum over it would land its cost on a page render while the collector is
//    inserting at ~1,000 rows/sec. `tests/capacityForecast.test.js` scans this
//    file with COMMENTS STRIPPED and fails the build if that table is named in
//    the code, so this paragraph cannot satisfy the scan.
//
// 2. ⛔ A FAILED READ IS REPORTED, NEVER RENDERED AS A QUIET FLEET. If any of
//    the three statements throws, this returns `devices: []` WITH a populated
//    `failures`, and the caller must refuse to print a count while it is
//    non-empty. The alternative is the worst answer this feature can give: zero
//    firewalls with a rising trend reads exactly like a fleet with headroom.
//
// 3. ⛔ ONE ROW PER ACTIVE FIREWALL, DRIVEN FROM `devices`. A firewall that
//    sends no syslog has no rollup rows, so driving this from the traffic table
//    would DROP exactly the firewall whose capacity is least known. Live,
//    PAKFood is that firewall, and `no_log_coverage` is the honest answer
//    rather than silence.
//
// 4. ⛔ THE COVERAGE PROBE IS UNBOUNDED WHILE THE SERIES IS NOT, and the
//    asymmetry is the whole reason there are three statements rather than two.
//    "SecVault holds no traffic logs for this firewall" must be true of ALL
//    time, or a firewall that went quiet four months ago would be reported as a
//    collection gap it may already have been diagnosed for — when the real
//    answer is "there is history, just none inside the window", which the
//    engine reports as `insufficient_history`. Two different first steps.
//
// 5. ⛔ `null`, NEVER 0, FOR A FIGURE THAT DID NOT ARRIVE. The engine's `num()`
//    is the only thing standing between "no summable bytes that day" and "we
//    could not read that day", and `Number(null)` is 0.
//
// ── ⛔ THE TWO-STAGE AGGREGATE IS A MEASURED CHOICE ───────────────────────
//
// `syslog_rollup_hourly` holds several rows per (device, hour) — the vendor,
// action and severity dimensions — so the completeness test needs hours, not
// rows. The obvious form, `count(DISTINCT bucket_hour)` grouped straight to the
// day, sorts every matching row: measured on the live fleet, 251,380 rows,
// quicksort over 20 MB, **441 ms**. Collapsing to one row per (device, hour)
// first and counting those is a HashAggregate: **181 ms** for the identical
// answer, verified row for row against the slower form. 2.4x, on a page render.
//
// ── ⛔ THE DAILY BUCKET IS THE SERVER'S LOCAL DAY ─────────────────────────
//
// `date_trunc('day', bucket_hour)` resolves in the database session's own
// timezone, which on the reference deployment is Asia/Bangkok. That is the same
// assumption every fixed-HH:MM cron job in this product already makes, and it
// is deliberately not overridden: the engine uses day boundaries only to decide
// which hours belong together and how far apart two observations are, and a
// CONSISTENT boundary is all that requires. ⛔ It would matter if a day
// boundary were compared against a UTC timestamp from elsewhere, so do not
// start mixing the two.

const {
  forecastDevice,
  summariseForecasts,
  rankForecasts,
  DEFAULT_HORIZON_DAYS,
  MAX_HORIZON_DAYS,
  DEFAULT_LOOKBACK_DAYS,
  MAX_LOOKBACK_DAYS,
} = require('./capacityForecast');

/** A thrown non-Error still has to read as something. */
function errorText(err) {
  return (err && err.message) ? err.message : String(err);
}

/**
 * ⛔ `deviceIds` DISTINGUISHES "NO FILTER" FROM "NO DEVICES", and the two are
 * opposite instructions — the asymmetry `ldapRoles.js` draws between no
 * mappings configured and no mapping matched, and the one `changeOutcomeData.js`
 * and `coverageRegisterData.js` already draw for this same parameter.
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

function boundedInt(v, lo, hi, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  const whole = Math.trunc(n);
  // ⛔ OUT OF RANGE FALLS BACK TO THE DEFAULT RATHER THAN BEING CLAMPED TO AN
  // EDGE — changeOutcomeData.js's rule, for its reason: a value nobody chose is
  // safer than a value silently rewritten to the extreme.
  if (whole < lo || whole > hi) return fallback;
  return whole;
}

// ─────────────────────────────────────────────────────────────────────────
// The statements
// ─────────────────────────────────────────────────────────────────────────

// ⛔ THE DRIVER. Inactive firewalls are excluded, matching every other fleet
// read in this product; a firewall with no traffic still gets a row, carrying
// the state that says so.
const DEVICES_SQL = `
  SELECT d.id, d.name, d.vendor
    FROM devices d
   WHERE d.active
     AND ($1::uuid[] IS NULL OR d.id = ANY($1::uuid[]))
   ORDER BY d.name
`;

// The daily byte series, with the hourly completeness the engine needs to tell
// a deploy gap from a traffic drop.
//
// ⛔ `device_id IS NOT NULL` IS NOT TIDINESS. The collector deliberately stores
// an unmatched sender with a null `device_id`, and those rows belong to no
// firewall in this fleet; folding them into a group would build a trend for a
// firewall out of another host's traffic. Live: 2,363 such rows.
//
// ⛔ THE BYTE SUM KEEPS SQL NULL AND DOES NOT MANUFACTURE A ZERO. `sum(a) +
// sum(b)` would be NULL whenever EITHER column is null even though the other
// carried a real figure; a bare `coalesce(a,0) + coalesce(b,0)` would turn an
// hour with no summable bytes at all into a confident 0. The FILTER keeps the
// hour NULL when nothing in it carried bytes, and the coalesce inside it adds
// the two directions of a row that reported one of them. `count(bytes)` at the
// day level then counts BYTE-BEARING HOURS, which is exactly the completeness
// test — the rollup itself only populates these columns
// `FILTER (WHERE bytes_summable)`, so a FortiOS hour is honestly NULL here
// rather than zero (lib/syslog/rollups.js, and lib/schema.sql's
// `bytes_summable` note for the 55 Gbps that proved why).
const DAILY_SQL = `
  WITH per_hour AS (
    SELECT s.device_id,
           s.bucket_hour,
           sum(coalesce(s.bytes_sent, 0) + coalesce(s.bytes_received, 0))
             FILTER (WHERE s.bytes_sent IS NOT NULL OR s.bytes_received IS NOT NULL)
             AS bytes
      FROM syslog_rollup_hourly s
     WHERE s.device_id IS NOT NULL
       AND ($1::uuid[] IS NULL OR s.device_id = ANY($1::uuid[]))
       AND s.bucket_hour >= $2::timestamptz - ($3::int * interval '1 day')
       AND s.bucket_hour <  $2::timestamptz
     GROUP BY 1, 2
  )
  SELECT device_id,
         date_trunc('day', bucket_hour) AS day,
         count(*)      AS hours,
         count(bytes)  AS byte_hours,
         sum(bytes)    AS bytes
    FROM per_hour
   GROUP BY 1, 2
   ORDER BY 1, 2
`;

// ⛔ UNBOUNDED BY TIME, AND THAT IS THE POINT — see rule 4 in the header. It
// answers two questions about ALL of the history SecVault holds: has this
// firewall EVER been heard from, and has it EVER produced a byte count that can
// be summed. Both of the states those decide are claims about all time, so
// neither may be decided inside the series window.
//
// ⛔ `byte_rows_held` WAS ADDED AFTER A REAL BUG, found only by executing this
// against a schema instead of a stub. With a 30-day lookback, a firewall whose
// byte history was OLDER than the window came back `bytes_not_summable` — a
// PERMANENT vendor limitation asserted about a firewall that reports byte
// counts perfectly well. The honest answer is `insufficient_history`.
const COVERAGE_SQL = `
  SELECT s.device_id,
         count(*)::bigint AS rows_held,
         count(*) FILTER (
           WHERE s.bytes_sent IS NOT NULL OR s.bytes_received IS NOT NULL
         )::bigint AS byte_rows_held
    FROM syslog_rollup_hourly s
   WHERE s.device_id IS NOT NULL
     AND ($1::uuid[] IS NULL OR s.device_id = ANY($1::uuid[]))
   GROUP BY 1
`;

/**
 * One series row → the engine's `{day, byteHours, bytes}`.
 *
 * ⛔ SPELLED OUT ONE KEY PER LINE. A key this function misnames does not fail
 * loudly — the engine reads `undefined`, treats the day as unreadable, and
 * reports `insufficient_history` on a firewall whose window SecVault holds in
 * full. A wrong verdict that looks like a coverage gap is the hardest kind to
 * notice.
 */
function toSeriesPoint(row) {
  return {
    day: row.day,
    byteHours: row.byte_hours,
    bytes: row.bytes,
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
 * The per-firewall bandwidth trend, computed at read time.
 *
 * @param {object} pool  ⛔ A PARAMETER, never imported — CLAUDE.md's Database
 *   rule. A function that loses it breaks DB access silently: builds clean,
 *   fails at runtime.
 * @param {object} [opts]
 * @param {string[]|null} [opts.deviceIds] restrict to these firewalls; see
 *   normaliseDeviceIds for why `[]` and `undefined` are opposite instructions.
 * @param {number} [opts.horizonDays] default 30, capped per firewall at the
 *   history it is fitted from.
 * @param {number} [opts.lookbackDays] default 90. Also a cost bound: the
 *   rollups are permanent and the estimator is O(days²).
 * @param {Date|string} [opts.now] injectable clock, so a test pins the window
 *   rather than inheriting whatever the suite ran at.
 * @returns {Promise<{devices, summary, failures, horizonDays, lookbackDays,
 *                    generatedAt}>}
 *
 * ⛔ `failures` IS PART OF THE ANSWER, NOT A LOG LINE. `devices: []` with a
 * populated `failures` means nothing could be measured, which is the opposite
 * of "no firewall here is growing".
 */
async function getCapacityForecasts(pool, opts = {}) {
  const ids = normaliseDeviceIds(opts.deviceIds);
  const horizonDays = boundedInt(opts.horizonDays, 1, MAX_HORIZON_DAYS, DEFAULT_HORIZON_DAYS);
  const lookbackDays = boundedInt(
    opts.lookbackDays, 1, MAX_LOOKBACK_DAYS, DEFAULT_LOOKBACK_DAYS,
  );
  const now = opts.now ? new Date(opts.now) : new Date();
  const generatedAt = now.toISOString();
  const failures = [];

  const empty = () => ({
    devices: [],
    summary: summariseForecasts([]),
    failures,
    horizonDays,
    lookbackDays,
    generatedAt,
  });

  // ⛔ AN EMPTY ID LIST IS AN INSTRUCTION, NOT A FAILURE. A scoped account
  // granted no firewalls gets an empty board and NO failures entry — the two
  // must stay distinguishable, since one says "you may see nothing" and the
  // other says "we could not look".
  if (ids !== null && ids.length === 0) return empty();

  let deviceRows = [];
  let dailyRows = [];
  let coverageRows = [];

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
    const res = await pool.query(DAILY_SQL, [ids, now.toISOString(), lookbackDays]);
    dailyRows = (res && Array.isArray(res.rows)) ? res.rows : [];
  } catch (err) {
    failures.push({ source: 'daily_traffic', error: errorText(err) });
  }

  try {
    const res = await pool.query(COVERAGE_SQL, [ids]);
    coverageRows = (res && Array.isArray(res.rows)) ? res.rows : [];
  } catch (err) {
    failures.push({ source: 'log_coverage', error: errorText(err) });
  }

  // ⛔ NOTHING IS MEASURED WHILE ANY SOURCE IS MISSING, AND THIS IS THE CENTRAL
  // RULE OF THIS FILE. Measuring on a partial read would not merely lose rows:
  //   · no series   ⇒ every firewall reports `insufficient_history`, which is a
  //     CLAIM about that firewall's history rather than about our failed read;
  //   · no coverage ⇒ every firewall reports `no_log_coverage`, which blames a
  //     collection gap for our own unreadable query and would send an operator
  //     to check sixteen firewalls that are all fine.
  // Both are confident, plausible and wrong, so the board refuses to exist
  // instead. `failures` carries the reason and the caller renders it.
  if (failures.length > 0) return empty();

  const seriesByDevice = groupBy(dailyRows, 'device_id', toSeriesPoint);

  // ⛔ A SET OF IDs THAT HAVE EVER LOGGED, built from the rows the probe
  // returned. A device absent from this set has no rollup rows at all; that is
  // the ONLY thing this structure is allowed to mean, and it is why the probe
  // is unbounded.
  const hasCoverage = new Set(
    coverageRows
      .filter((r) => r && r.device_id && Number(r.rows_held) > 0)
      .map((r) => r.device_id),
  );

  // ⛔ A SEPARATE SET, FROM THE SAME UNBOUNDED PROBE. A firewall in
  // `hasCoverage` but not here has never produced a summable byte count in any
  // history SecVault holds, which is the only basis on which the permanent
  // vendor claim may be made.
  const hasSummable = new Set(
    coverageRows
      .filter((r) => r && r.device_id && Number(r.byte_rows_held) > 0)
      .map((r) => r.device_id),
  );

  const devices = rankForecasts(deviceRows.map((row) => forecastDevice(
    { deviceId: row.id, deviceName: row.name, vendor: row.vendor },
    seriesByDevice.get(row.id) || [],
    {
      horizonDays,
      hasLogCoverage: hasCoverage.has(row.id),
      hasSummableBytes: hasSummable.has(row.id),
      now,
    },
  )));

  return {
    devices,
    summary: summariseForecasts(devices),
    failures,
    horizonDays,
    lookbackDays,
    generatedAt,
  };
}

/**
 * The same answer for ONE firewall.
 *
 * ⛔ A MISSING OR MALFORMED ID IS A FAILURE, NOT "NO FILTER". Passing it
 * straight through as `deviceIds: [deviceId]` would have `normaliseDeviceIds`
 * drop it, leaving `[]` — which this module defines as "no firewalls, and that
 * is fine" — so a broken link would render a clean empty board for a firewall
 * that exists. Worse, a bare `undefined` would mean the WHOLE FLEET, printing
 * another firewall's trend under this one's name.
 */
async function getDeviceCapacityForecast(pool, deviceId, opts = {}) {
  if (typeof deviceId !== 'string' || deviceId === '') {
    return {
      device: null,
      devices: [],
      summary: summariseForecasts([]),
      failures: [{
        source: 'device',
        error: 'No firewall was named, so nothing was measured.',
      }],
      horizonDays: boundedInt(opts.horizonDays, 1, MAX_HORIZON_DAYS, DEFAULT_HORIZON_DAYS),
      lookbackDays: boundedInt(opts.lookbackDays, 1, MAX_LOOKBACK_DAYS, DEFAULT_LOOKBACK_DAYS),
      generatedAt: (opts.now ? new Date(opts.now) : new Date()).toISOString(),
    };
  }
  const answer = await getCapacityForecasts(pool, { ...opts, deviceIds: [deviceId] });
  return { ...answer, device: answer.devices[0] || null };
}

module.exports = {
  getCapacityForecasts,
  getDeviceCapacityForecast,
};
