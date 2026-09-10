// lib/syslog/vpnPresence.js
//
// Per-user VPN activity grid — the "who is using the VPN, and when" view.
//
// ⛔ ═══ THIS DOES NOT MEASURE CONNECTED TIME. READ THIS BEFORE CHANGING IT ═══
//
// The only per-user VPN evidence SecVault holds is `syslog_vpn_auth_hourly`,
// which records, per hour, the SET of usernames that AUTHENTICATED. It carries
// no session start, no session end and no duration. So the one honest unit
// available here is:
//
//     "the number of distinct hours in which this user authenticated"
//
// A user who logs in once at 09:00 and stays connected until 17:00 appears in
// ONE bucket, not eight. A user whose client re-authenticates every 30 minutes
// appears in eight. Calling either number "hours connected" would be a
// fabricated measurement of exactly the class CLAUDE.md keeps fixing — a real
// number, plausibly shaped, answering a question the data cannot answer. Every
// label this module feeds must say "authenticated", never "connected".
//
// The operator asked for connected duration and is entitled to know why they
// are not getting it, so `notes.durationGap` states the gap in words and the
// UI renders it on screen rather than hiding it in a tooltip.
//
// TRUE connected duration would need `vpn_active_sessions` retained. That table
// already carries username / assigned_ip / login_time — everything required —
// but it is DELETE+reinserted on every poll, so it only ever holds "right now"
// and history is destroyed each cycle. Retaining it (an append-only snapshot
// table plus a session-stitching pass) is a schema change and is deliberately
// NOT done here.
//
// ── ⛔ WHY DAY COLUMNS ────────────────────────────────────────────────────
// 30 days x 24 hours = 720 columns. That is not a table, it is a barcode: no
// column would be wide enough to hover, and no reader could locate "last
// Tuesday afternoon" in it. So a column is one UTC DAY and its intensity is the
// number of DISTINCT HOURS that user authenticated in during that day (0-24).
// The hour detail is not thrown away — each cell carries its own hour list,
// which the UI shows on hover, so the drill-down is one pointer move rather
// than another page.
//
// ── ⛔ WHY THE ROLLUP, NEVER `syslog_events` ──────────────────────────────
// The raw table takes ~28M rows/day. The equivalent VPN question against it was
// measured at 85.6 SECONDS over a 24h WINDOW (see vpnAuthStats.js); over 30
// days it would be a production incident. Nothing in this file may ever read
// `syslog_events`.

'use strict';

const DEFAULT_WINDOW_DAYS = 30;
const MAX_WINDOW_DAYS = 90;
const DEFAULT_TOP_USERS = 25;
const MAX_TOP_USERS = 100;
const HOURS_IN_DAY = 24;
const MS_PER_DAY = 86400000;

// The sequential intensity ramp, as thresholds in DISTINCT AUTHENTICATED HOURS.
//
// ⛔ FIVE STEPS OF ONE HUE, NOT THE SEVERITY RAMP. A heavily-used VPN account
// is busy, not critical, and painting the busiest row red would put the
// product's loudest visual signal on its most ordinary fact. Kept here rather
// than in the component so the test can pin it and so the legend and the cells
// cannot drift apart.
const INTENSITY_THRESHOLDS = [1, 3, 6, 10, 16];

/**
 * Distinct authenticated hours -> 0..5. 0 means "no activity", never "no data" —
 * the two are different states and only the caller knows which one it has.
 */
function intensityLevel(hours) {
  const n = Number(hours);
  if (!Number.isFinite(n) || n <= 0) return 0;
  let level = 0;
  for (const t of INTENSITY_THRESHOLDS) if (n >= t) level += 1;
  return level;
}

function clampInt(value, def, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

function utcDayKey(date) {
  return date.toISOString().slice(0, 10);
}

/**
 * The N UTC day keys ending with the day `now` falls in, oldest first.
 *
 * ⛔ UTC, matching every other timestamp this app renders (the fleet table
 * stamps "UTC" on its own dates). A grid whose columns silently used the
 * server's local midnight while its tooltips read UTC would put an evening
 * login in the wrong column for half the fleet.
 */
function buildDayKeys(days, now) {
  const n = clampInt(days, DEFAULT_WINDOW_DAYS, 1, MAX_WINDOW_DAYS);
  const ref = now instanceof Date ? now : new Date();
  const endUtcMidnight = Date.UTC(ref.getUTCFullYear(), ref.getUTCMonth(), ref.getUTCDate());
  const keys = [];
  for (let i = n - 1; i >= 0; i -= 1) keys.push(utcDayKey(new Date(endUtcMidnight - i * MS_PER_DAY)));
  return keys;
}

// ── Cell states ───────────────────────────────────────────────────────────
//
// ⛔ ZERO AND NO-DATA ARE DIFFERENT AND MUST STAY DIFFERENT. This is
// CLAUDE.md's failed-read-as-a-fact rule expressed in a grid: an empty cell
// that means "this user did not log in" and an empty cell that means "we were
// not listening" look identical and read as the first. Four states:
//
//   'active'       the user authenticated in N hours of this day.       MEASURED
//   'zero'         at least one SUCCESSFUL VPN authentication was
//                  recorded from this scope that day, and this user is
//                  in none of them. A real, earned zero.               MEASURED
//   'no-logs'      no syslog at all reached SecVault from this scope
//                  that day. Says nothing about the user.           NOT MEASURED
//   'pre-history'  the day predates the first log we hold. The
//                  collector did not exist yet.                     NOT MEASURED
//   'no-vpn-logs'  syslog arrived, but NOT ONE successful VPN
//                  authentication was recorded from this scope that
//                  day.                                             NOT MEASURED
//   'truncated'    logs arrived, but at least one username array in
//                  that day was CAPPED, so this user may have been
//                  dropped from it rather than absent.              NOT MEASURED
//
// ⛔ 'no-vpn-logs' is the state this file was WRONG about on its first live
// run. 2026-09-08 had 17 hours of syslog from 14 firewalls and zero rows in
// `syslog_vpn_auth_hourly`, and every user was rendered as an earned zero for
// that day. Two causes are indistinguishable from here — nobody logged in, or
// the VPN rollup was not yet populating (which is what it actually was) — and
// asserting the first would be exactly the failed-read-as-a-fact bug. A day
// with no successful-auth evidence cannot support a zero for anybody.
const CELL_STATES = ['active', 'zero', 'no-logs', 'pre-history', 'no-vpn-logs', 'truncated'];
const MEASURED_STATES = new Set(['active', 'zero']);

/**
 * Assemble the grid from already-fetched rows. Pure — no pool, no clock beyond
 * the `dayKeys` it is handed — so the state machine above is unit-testable
 * without a database.
 */
function buildPresenceGrid({ dayKeys, coverageRows, authDayRows, userRows, cellRows, firstLogAt }) {
  const coverage = new Map((coverageRows || []).map((r) => [r.day_key, r]));
  const authDays = new Map((authDayRows || []).map((r) => [r.day_key, r]));
  const firstLogDay = firstLogAt ? utcDayKey(new Date(firstLogAt)) : null;

  const days = (dayKeys || []).map((key) => {
    const cov = coverage.get(key);
    const auth = authDays.get(key);
    const hoursCovered = cov ? Number(cov.hours_covered) || 0 : 0;
    const truncatedRows = auth ? Number(auth.truncated_rows) || 0 : 0;
    // ⛔ "Before the first log we hold" is a DIFFERENT absence from "the
    // collector was up and nothing arrived", and an operator looking at a
    // month-long grid that is mostly blank needs to be told which one they are
    // looking at. Both are unmeasured; only one is ever going to fill in.
    const preHistory = firstLogDay ? key < firstLogDay : true;
    return {
      key,
      hoursCovered,
      // 24 hours of buckets is a full day; the current day and the first day
      // are legitimately partial and say so rather than being called a gap.
      partial: hoursCovered > 0 && hoursCovered < HOURS_IN_DAY,
      devicesReporting: cov ? Number(cov.devices_reporting) || 0 : 0,
      covered: hoursCovered > 0,
      preHistory,
      truncatedRows,
      truncated: truncatedRows > 0,
      successRows: auth ? Number(auth.success_rows) || 0 : 0,
      failureRows: auth ? Number(auth.failure_rows) || 0 : 0,
      // Can this day support a real zero for a user absent from it? Only if
      // SOMETHING succeeded on it. See the 'no-vpn-logs' note above.
      hasSuccessEvidence: auth ? (Number(auth.success_rows) || 0) > 0 : false,
      // ⛔ Summed WITHOUT any unnest in the query, so it is the plain
      // sum(event_count) that the per-user numbers can be sanity-checked
      // against. See the fan-out note on the queries below.
      authEvents: auth ? Number(auth.auth_events) || 0 : 0,
    };
  });

  const dayByKey = new Map(days.map((d) => [d.key, d]));

  const cellsByUser = new Map();
  for (const r of cellRows || []) {
    if (!cellsByUser.has(r.username)) cellsByUser.set(r.username, new Map());
    cellsByUser.get(r.username).set(r.day_key, r);
  }

  const users = (userRows || []).map((u) => {
    const own = cellsByUser.get(u.username) || new Map();
    const cells = days.map((day) => {
      const hit = own.get(day.key);
      const hours = hit ? Number(hit.auth_hours) || 0 : 0;
      const hourList = hit && Array.isArray(hit.hours) ? hit.hours.map(Number) : [];

      if (hours > 0) {
        return {
          day: day.key,
          state: 'active',
          hours,
          hourList,
          level: intensityLevel(hours),
          // ⛔ A day containing a capped username array can only ever
          // UNDER-report this user, never over-report, so an active cell in
          // such a day is a floor rather than a count.
          lowerBound: day.truncated,
          reason: null,
        };
      }
      if (day.preHistory) {
        return {
          day: day.key, state: 'pre-history', hours: null, hourList: [], level: null, lowerBound: false,
          reason: 'Before SecVault held any syslog for this selection — not measured.',
        };
      }
      if (!day.covered) {
        return {
          day: day.key, state: 'no-logs', hours: null, hourList: [], level: null, lowerBound: false,
          reason: 'No syslog reached SecVault from this selection on this day — not measured, not a quiet day.',
        };
      }
      if (!day.hasSuccessEvidence) {
        return {
          day: day.key, state: 'no-vpn-logs', hours: null, hourList: [], level: null, lowerBound: false,
          reason: day.failureRows > 0
            ? `Syslog arrived and ${day.failureRows} FAILED VPN logins were recorded from this selection, but not one successful login was — an absence here is a gap in what the firewall reports, not evidence this user stayed away. Not measured.`
            : 'Syslog arrived from this selection, but it carried no VPN authentication at all — indistinguishable from the rollup not yet covering this day. Not measured.',
        };
      }
      if (day.truncated) {
        return {
          day: day.key, state: 'truncated', hours: null, hourList: [], level: null, lowerBound: false,
          reason: `Username list was capped in ${day.truncatedRows} bucket(s) this day — this user may have been dropped from it rather than absent. Not measured.`,
        };
      }
      return {
        day: day.key, state: 'zero', hours: 0, hourList: [], level: 0, lowerBound: false,
        reason: 'Logs arrived from this selection this day and this user authenticated in none of them.',
      };
    });

    return {
      username: u.username,
      authHours: Number(u.auth_hours) || 0,
      authDays: Number(u.auth_days) || 0,
      devices: Number(u.devices) || 0,
      firstSeenAt: u.first_seen_at || null,
      lastSeenAt: u.last_seen_at || null,
      cells,
      measuredDays: cells.filter((c) => MEASURED_STATES.has(c.state)).length,
    };
  });

  return { days, users };
}

/**
 * Per-user x per-day VPN authentication grid for the fleet or one device.
 *
 * @param {object} pool           pg pool (never omitted — CLAUDE.md's rule)
 * @param {object} [opts]
 * @param {number} [opts.days]      window length, clamped 1..90
 * @param {string} [opts.deviceId]  UUID, or null/'' for the whole fleet
 * @param {number} [opts.topUsers]  row cap, clamped 1..100
 * @param {Date}   [opts.now]       injectable clock, for tests
 */
async function getVpnUserPresence(pool, opts = {}) {
  const days = clampInt(opts.days, DEFAULT_WINDOW_DAYS, 1, MAX_WINDOW_DAYS);
  const topUsers = clampInt(opts.topUsers, DEFAULT_TOP_USERS, 1, MAX_TOP_USERS);
  const deviceId = opts.deviceId ? String(opts.deviceId) : null;
  const now = opts.now instanceof Date ? opts.now : new Date();

  const dayKeys = buildDayKeys(days, now);
  const windowStart = new Date(`${dayKeys[0]}T00:00:00.000Z`);

  // ⛔ Every timestamp parameter is cast explicitly — CLAUDE.md's rule; without
  // ::timestamptz PostgreSQL cannot infer the type of $1 here at all.
  const scopeArgs = [windowStart.toISOString(), deviceId];

  // ── 1. COVERAGE: was SecVault listening? ────────────────────────────────
  // ⛔ This is the whole reason zero and no-data can be told apart, and it
  // deliberately does NOT come from the VPN table. Asking "were there VPN auth
  // rows that day" cannot distinguish a dead collector from a quiet Sunday;
  // asking `syslog_rollup_hourly` (permanent, ~3.5k rows/day, indexed on
  // bucket_hour) asks whether ANY log arrived from this scope, which is the
  // question that separates the two.
  const coveragePromise = pool.query(
    `SELECT to_char(bucket_hour AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day_key,
            count(DISTINCT bucket_hour)::int AS hours_covered,
            count(DISTINCT device_id)::int   AS devices_reporting,
            sum(event_count)::bigint         AS events
       FROM syslog_rollup_hourly
      WHERE bucket_hour >= $1::timestamptz
        AND ($2::uuid IS NULL OR device_id = $2::uuid)
      GROUP BY 1`,
    scopeArgs
  );

  // How far back the evidence goes AT ALL, so a 30-day window over 2 days of
  // history says so instead of drawing 28 empty columns.
  const historyPromise = pool.query(
    `SELECT min(bucket_hour) AS first_log_at, max(bucket_hour) AS last_log_at
       FROM syslog_rollup_hourly
      WHERE ($1::uuid IS NULL OR device_id = $1::uuid)`,
    [deviceId]
  );

  // ── 2. VPN auth day meta ────────────────────────────────────────────────
  // ⛔ NO unnest anywhere in this query, which is what makes `auth_events` the
  // honest plain sum(event_count). Unnesting a text[] under a sum FANS THE ROW
  // OUT ONCE PER USERNAME: on this same table that bug inflated the VPN failure
  // count 8.2x (see vpnAuthStats.js). The username side lives in its own
  // queries below, where nothing is summed.
  const authDayPromise = pool.query(
    `SELECT to_char(bucket_hour AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day_key,
            count(*) FILTER (WHERE auth_outcome = 'success')::int AS success_rows,
            count(*) FILTER (WHERE auth_outcome = 'failure')::int AS failure_rows,
            count(*) FILTER (WHERE usernames_truncated)::int      AS truncated_rows,
            sum(event_count)::bigint                              AS auth_events
       FROM syslog_vpn_auth_hourly
      WHERE bucket_hour >= $1::timestamptz
        AND ($2::uuid IS NULL OR device_id = $2::uuid)
      GROUP BY 1`,
    scopeArgs
  );

  // ⛔ Per-vendor success/failure ROW counts, for the reporting-gap caveat.
  // Measured on this fleet: Fortinet logs SSL-VPN failures in bulk and
  // successes essentially not at all (a device-side logging setting SecVault
  // cannot change). A Fortinet-only selection therefore renders a nearly empty
  // grid, and without this the reader would take that as "nobody uses the VPN
  // here" rather than "we cannot see the logins".
  const vendorPromise = pool.query(
    `SELECT vendor,
            count(*) FILTER (WHERE auth_outcome = 'success')::int AS success_rows,
            count(*) FILTER (WHERE auth_outcome = 'failure')::int AS failure_rows
       FROM syslog_vpn_auth_hourly
      WHERE bucket_hour >= $1::timestamptz
        AND ($2::uuid IS NULL OR device_id = $2::uuid)
      GROUP BY 1`,
    scopeArgs
  );

  // ── 3. Per-user totals ──────────────────────────────────────────────────
  // ⛔ SUCCESSFUL authentications only. A failed login is not presence, and
  // mixing the two would let a brute-force source's guessed usernames appear as
  // the fleet's busiest "users".
  //
  // ⛔ NOTHING IS SUMMED HERE. The unnest is allowed precisely because every
  // aggregate below is a COUNT(DISTINCT) over a set, and a set does not care
  // how many times it saw a member. A per-user EVENT count is not derivable
  // from this table at any price: one rollup row's `event_count` covers every
  // username in its array with no split, so attributing it per user would be
  // invention. That is why this module counts hours and never events.
  const totalsPromise = pool.query(
    `WITH scoped AS (
        SELECT bucket_hour, device_id, usernames
          FROM syslog_vpn_auth_hourly
         WHERE auth_outcome = 'success'
           AND bucket_hour >= $1::timestamptz
           AND ($2::uuid IS NULL OR device_id = $2::uuid)
     )
     SELECT u AS username,
            count(DISTINCT s.bucket_hour)::int AS auth_hours,
            count(DISTINCT to_char(s.bucket_hour AT TIME ZONE 'UTC', 'YYYY-MM-DD'))::int AS auth_days,
            count(DISTINCT s.device_id)::int   AS devices,
            min(s.bucket_hour)                 AS first_seen_at,
            max(s.bucket_hour)                 AS last_seen_at,
            count(*) OVER ()::int              AS total_users
       FROM scoped s
       CROSS JOIN LATERAL unnest(coalesce(s.usernames, ARRAY[]::text[])) AS u
      GROUP BY 1
      ORDER BY auth_hours DESC, auth_days DESC, username ASC
      LIMIT $3`,
    [windowStart.toISOString(), deviceId, topUsers]
  );

  const [coverage, history, authDay, vendorRows, totals] = await Promise.all([
    coveragePromise, historyPromise, authDayPromise, vendorPromise, totalsPromise,
  ]);

  const userRows = totals.rows;
  const totalUsers = userRows.length > 0 ? Number(userRows[0].total_users) || userRows.length : 0;
  const usernames = userRows.map((r) => r.username);

  // ── 4. The cells, for the ranked users only ─────────────────────────────
  let cellRows = [];
  if (usernames.length > 0) {
    const cells = await pool.query(
      `WITH scoped AS (
          SELECT bucket_hour, usernames
            FROM syslog_vpn_auth_hourly
           WHERE auth_outcome = 'success'
             AND bucket_hour >= $1::timestamptz
             AND ($2::uuid IS NULL OR device_id = $2::uuid)
       ),
       exploded AS (
          SELECT u AS username,
                 to_char(s.bucket_hour AT TIME ZONE 'UTC', 'YYYY-MM-DD')  AS day_key,
                 extract(hour FROM s.bucket_hour AT TIME ZONE 'UTC')::int AS hour_of_day
            FROM scoped s
            CROSS JOIN LATERAL unnest(coalesce(s.usernames, ARRAY[]::text[])) AS u
           WHERE u = ANY($3::text[])
       )
       SELECT username, day_key,
              count(DISTINCT hour_of_day)::int AS auth_hours,
              array_agg(DISTINCT hour_of_day ORDER BY hour_of_day) AS hours
         FROM exploded
        GROUP BY 1, 2`,
      [windowStart.toISOString(), deviceId, usernames]
    );
    cellRows = cells.rows;
  }

  const firstLogAt = history.rows[0] ? history.rows[0].first_log_at : null;
  const lastLogAt = history.rows[0] ? history.rows[0].last_log_at : null;

  const { days: dayMeta, users } = buildPresenceGrid({
    dayKeys,
    coverageRows: coverage.rows,
    authDayRows: authDay.rows,
    userRows,
    cellRows,
    firstLogAt,
  });

  // ⛔ Two different counts, and only the second one licenses a zero in the
  // grid: `coveredDays` is "we were listening"; `measuredDays` is "and we saw a
  // successful VPN login that day, so an absent user is genuinely absent".
  const coveredDays = dayMeta.filter((d) => d.covered && !d.preHistory).length;
  const measuredDays = dayMeta.filter((d) => d.covered && !d.preHistory && d.hasSuccessEvidence).length;
  const historyDays = firstLogAt
    ? Math.max(1, Math.round((now.getTime() - new Date(firstLogAt).getTime()) / MS_PER_DAY))
    : 0;
  const truncatedBuckets = dayMeta.reduce((acc, d) => acc + d.truncatedRows, 0);

  const vendors = vendorRows.rows.map((v) => ({
    vendor: v.vendor,
    successRows: Number(v.success_rows) || 0,
    failureRows: Number(v.failure_rows) || 0,
  }));
  // A vendor that reports failures but no successes cannot contribute a single
  // row to this grid, however busy its VPN actually is.
  const successReportingGaps = vendors.filter((v) => v.failureRows > 0 && v.successRows === 0);

  return {
    windowDays: days,
    deviceId,
    dayKeys,
    days: dayMeta,
    users,
    coverage: {
      firstLogAt,
      lastLogAt,
      historyDays,
      // ⛔ The honest answer to "why is most of this grid blank".
      requestedExceedsHistory: !firstLogAt || historyDays < days,
      coveredDays,
      measuredDays,
      unmeasuredDays: dayMeta.length - measuredDays,
      truncatedBuckets,
      rankedUsers: users.length,
      totalUsers,
      vendors,
      successReportingGaps,
    },
    notes: {
      unit: 'Distinct hours in which the user authenticated. Not connected time.',
      durationGap:
        'SecVault records the hours a user AUTHENTICATED in, not how long they stayed connected: '
        + 'one login held open for eight hours counts as one hour here, and a client that '
        + 're-authenticates every 30 minutes counts as several. True session duration would '
        + 'require retaining vpn_active_sessions history, which is not collected today.',
    },
  };
}

module.exports = {
  getVpnUserPresence,
  buildPresenceGrid,
  buildDayKeys,
  intensityLevel,
  clampInt,
  utcDayKey,
  CELL_STATES,
  MEASURED_STATES,
  INTENSITY_THRESHOLDS,
  DEFAULT_WINDOW_DAYS,
  MAX_WINDOW_DAYS,
  DEFAULT_TOP_USERS,
  MAX_TOP_USERS,
};
