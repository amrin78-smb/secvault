// lib/engines/vpnSessions.js
//
// Two tables, two different questions, ONE transaction:
//
//   vpn_active_sessions — "who is connected RIGHT NOW". DELETE+reinsert every
//     poll, no history, no retention. Unchanged by Phase B.
//   vpn_sessions        — "who was connected, when, for how long, from where".
//     Upserted on the natural key (device_id, username, login_time), ended by
//     absence, kept for a year. Added 2026-09-10 (Phase B).
//
// ⛔ WHY vpn_sessions EXISTS. Every poll already returned username,
// assigned_ip, login_time and client for every connected user — measured live
// on the Palo Alto fleet, 180 of 180 rows populated on all four. The
// DELETE+reinsert above then threw all of it away, every poll, and only a bare
// count survived in vpn_session_snapshots. Every question an operator asks
// about VPN was unanswerable not because SecVault could not see the answer but
// because it discarded it.
//
// The engine-worker only ever calls storeVpnSessions() after a SUCCESSFUL
// poll, so a failed pull never wipes the last-known active set AND never ends
// a single history row — see the ⛔ note on endMissingSessions() below, and
// verify the call site in services/engine-worker.js before changing either.
// An empty array from a SUCCESSFUL poll legitimately clears the active set
// (nobody is connected) and legitimately ends every open session.
//
// Takes `pool` as a parameter per CLAUDE.md (never omit pool from a DB
// function). Session objects are the vendor-agnostic normalized shape produced
// by the adapters:
//   { username, tunnel_type, source_ip, assigned_ip, login_time,
//     duration_seconds, bytes_in, bytes_out, client, gateway, raw }
// Any field may be null/absent — different vendors report different subsets.
//
// ⛔ VENDOR COVERAGE IS ONE VENDOR. Only Palo Alto's getVpnSessionSummary()
// currently returns a `sessions` array at all; Fortinet's returns a count with
// no per-user detail, and the other four vendors have no VPN capability wired.
// vpn_sessions is therefore a PALO ALTO history today. Nothing here assumes
// otherwise — every field is optional and a vendor emitting no sessions simply
// contributes no rows — but no UI may present it as fleet-wide VPN history.

'use strict';

// The lower bound on a duration is only as good as the poll cadence, and a
// session shorter than one interval may never be observed at all. Callers get
// the interval back alongside every duration so they can state the precision.
const DEFAULT_HISTORY_LIMIT = 200;
const MAX_HISTORY_LIMIT = 2000;

// Sessions live far longer than raw syslog events (30 days) on purpose: one
// row per session, ~180/day on the reference fleet, and they are the record
// that VPN traffic attribution, audits and "when was this account last used"
// all reference. Deleting them to save space would be deleting the answer to
// keep the question.
const DEFAULT_VPN_SESSION_RETENTION_DAYS = 365;

const MONTHS = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
};

// A device clock may legitimately run ahead of the server's by a little. More
// than this and a no-year timestamp is read as LAST year instead of a session
// that started in the future, which no session ever does.
const FUTURE_SKEW_TOLERANCE_MS = 36 * 60 * 60 * 1000;

function numericOrNull(v) {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function textOrNull(v) {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

function positiveIntOrNull(v) {
  const n = typeof v === 'string' ? parseInt(v, 10) : v;
  return Number.isInteger(n) && n > 0 ? n : null;
}

/**
 * Parse a vendor login-time string into a Date, or null if it cannot be
 * parsed. NULL IS A REAL ANSWER HERE — see storeVpnSessions()'s
 * `unsessionizable` counter. Never guess: a wrong start time is a fabricated
 * duration, and a wrong key silently merges two separate connections by the
 * same person into one session that never happened.
 *
 * Shapes handled:
 *   - Date instance (passed straight through if valid)
 *   - epoch seconds / milliseconds (all-digit string or number)
 *   - ISO-8601 ("2026-09-10T06:35:14Z", "2026-09-10 06:35:14+07")
 *   - PAN-OS GlobalProtect "Sep.09 01:31:51" / "Sep 09 01:31:51", optionally
 *     carrying a year ("Sep.09 2026 01:31:51")
 *
 * ⛔ THE PAN-OS SHAPE CARRIES NO YEAR AND NO ZONE, and that is what the whole
 * fleet reports today (verified live: 180/180 rows in this format). Two
 * assumptions are therefore stated here rather than buried:
 *
 *   1. YEAR is inferred as "the most recent year in which this month/day/time
 *      is not in the future". A session cannot start in the future, so this is
 *      an inference from an ordering fact, not a guess. It stays stable across
 *      a New Year boundary: "Dec.31 23:50:00" read on Jan 1 resolves to the
 *      December that just passed, both before and after midnight.
 *   2. ZONE is the SERVER's local zone (the same assumption the fixed-HH:MM
 *      cron jobs already make). If a firewall is configured in a different
 *      zone from the SecVault host, absolute times shift by that fixed offset.
 *      That does NOT break sessionization — the key stays stable because the
 *      mapping is deterministic — but it WOULD skew a duration, which is why
 *      getVpnSessionHistory() reports a NEGATIVE observed duration as
 *      unmeasurable (`clock_mismatch`) rather than as a number.
 *
 * @param {*} value raw login_time from the adapter
 * @param {Date} [now] reference point for year inference (injectable for tests)
 * @returns {Date|null}
 */
function parseLoginTime(value, now) {
  const reference = now instanceof Date && !Number.isNaN(now.getTime()) ? now : new Date();

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    return epochToDate(value);
  }

  if (typeof value !== 'string') return null;
  const raw = value.trim();
  if (!raw) return null;

  if (/^\d+$/.test(raw)) {
    return epochToDate(Number(raw));
  }

  // ISO-8601 / anything Date can read unambiguously with an explicit year.
  if (/^\d{4}-\d{2}-\d{2}/.test(raw)) {
    const d = new Date(raw.includes('T') ? raw : raw.replace(' ', 'T'));
    return Number.isNaN(d.getTime()) ? null : d;
  }

  // PAN-OS: "Sep.09 01:31:51", "Sep 9 01:31:51", "Sep.09 2026 01:31:51"
  const m = raw.match(/^([A-Za-z]{3})[.\s]+(\d{1,2})(?:[,\s]+(\d{4}))?\s+(\d{1,2}):(\d{2}):(\d{2})$/);
  if (m) {
    const month = MONTHS[m[1].toLowerCase()];
    if (month === undefined) return null;
    const day = Number(m[2]);
    const hour = Number(m[4]);
    const minute = Number(m[5]);
    const second = Number(m[6]);
    if (day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) return null;

    if (m[3]) {
      const explicit = new Date(Number(m[3]), month, day, hour, minute, second);
      return Number.isNaN(explicit.getTime()) ? null : explicit;
    }

    let year = reference.getFullYear();
    let candidate = new Date(year, month, day, hour, minute, second);
    if (Number.isNaN(candidate.getTime())) return null;
    if (candidate.getTime() - reference.getTime() > FUTURE_SKEW_TOLERANCE_MS) {
      year -= 1;
      candidate = new Date(year, month, day, hour, minute, second);
      if (Number.isNaN(candidate.getTime())) return null;
    }
    // Feb 29 in a non-leap year rolls over to Mar 1 — reject rather than
    // silently record a different day than the device reported.
    if (candidate.getDate() !== day || candidate.getMonth() !== month) return null;
    return candidate;
  }

  return null;
}

function epochToDate(n) {
  if (!Number.isFinite(n) || n <= 0) return null;
  // Anything below 1e11 is seconds (1e11 seconds is year 5138); above is ms.
  const ms = n < 1e11 ? n * 1000 : n;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * Replace a device's active-session rows with `sessions` and fold the same
 * sessions into vpn_sessions history — ONE transaction, so the "who is
 * connected now" set and the history can never disagree about a poll.
 *
 * @param {string} deviceId
 * @param {object[]} sessions - normalized session objects (see file header)
 * @param {import('pg').Pool} pool
 * @param {object} [options]
 * @param {number} [options.pollIntervalSeconds] cadence this device is polled
 *   at, stored per row as the ERROR BAR on that session's end time.
 * @param {Date} [options.now] reference point for login-time year inference.
 * @returns {Promise<{count:number, historyUpserted:number,
 *   unsessionizable:number, ended:number}>}
 */
async function storeVpnSessions(deviceId, sessions, pool, options = {}) {
  const list = Array.isArray(sessions) ? sessions : [];
  const opts = options && typeof options === 'object' ? options : {};
  const pollIntervalSeconds = positiveIntOrNull(opts.pollIntervalSeconds);
  const now = opts.now instanceof Date && !Number.isNaN(opts.now.getTime()) ? opts.now : new Date();

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM vpn_active_sessions WHERE device_id = $1', [deviceId]);

    // Natural keys observed in THIS poll, collected while inserting the live
    // rows so history and the live set are built from exactly one reading.
    const seenUsernames = [];
    const seenLoginTimes = [];
    let unsessionizable = 0;
    let historyUpserted = 0;

    for (const s of list) {
      const rec = s && typeof s === 'object' ? s : {};
      const username = textOrNull(rec.username);
      await client.query(
        `INSERT INTO vpn_active_sessions
           (device_id, username, tunnel_type, source_ip, assigned_ip, login_time,
            duration_seconds, bytes_in, bytes_out, client, gateway, raw)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)`,
        [
          deviceId,
          username,
          textOrNull(rec.tunnel_type),
          textOrNull(rec.source_ip),
          textOrNull(rec.assigned_ip),
          textOrNull(rec.login_time),
          numericOrNull(rec.duration_seconds),
          numericOrNull(rec.bytes_in),
          numericOrNull(rec.bytes_out),
          textOrNull(rec.client),
          textOrNull(rec.gateway),
          JSON.stringify(rec.raw == null ? null : rec.raw),
        ]
      );

      // ⛔ NO USABLE START TIME => NOT SESSIONIZABLE, AND WE COUNT IT.
      // The obvious fallback — keying on (device, username, source_ip) — would
      // silently MERGE two separate connections by the same person into one
      // long session, inventing duration that never happened. The row still
      // appears in vpn_active_sessions above (it IS connected); it simply
      // cannot enter history, and the caller logs how many were skipped so the
      // gap is visible instead of looking like a quiet VPN.
      const loginAt = parseLoginTime(rec.login_time, now);
      if (!username || !loginAt) {
        unsessionizable += 1;
        continue;
      }

      // ⛔ COALESCE(EXCLUDED.x, vpn_sessions.x), never a bare EXCLUDED.x: a
      // field the device did not report on THIS poll must not overwrite a
      // value it DID report earlier. Same rule as everywhere else in this
      // codebase — a failed/absent read is not a measurement.
      // ended_at goes back to NULL unconditionally: this session is present in
      // a successful poll, so it is demonstrably open again (a device that
      // dropped a user from one poll and listed them in the next never really
      // ended the session; the previous end was our sampling, not their
      // disconnect).
      await client.query(
        `INSERT INTO vpn_sessions
           (device_id, username, login_time, tunnel_type, source_ip, assigned_ip,
            client, gateway, first_seen_at, last_seen_at, ended_at,
            poll_interval_seconds, raw)
         VALUES ($1, $2, $3::timestamptz, $4, $5, $6, $7, $8, now(), now(), NULL, $9, $10::jsonb)
         ON CONFLICT (device_id, username, login_time) DO UPDATE SET
           last_seen_at          = now(),
           ended_at              = NULL,
           tunnel_type           = COALESCE(EXCLUDED.tunnel_type, vpn_sessions.tunnel_type),
           source_ip             = COALESCE(EXCLUDED.source_ip, vpn_sessions.source_ip),
           assigned_ip           = COALESCE(EXCLUDED.assigned_ip, vpn_sessions.assigned_ip),
           client                = COALESCE(EXCLUDED.client, vpn_sessions.client),
           gateway               = COALESCE(EXCLUDED.gateway, vpn_sessions.gateway),
           poll_interval_seconds = COALESCE(EXCLUDED.poll_interval_seconds, vpn_sessions.poll_interval_seconds),
           raw                   = COALESCE(EXCLUDED.raw, vpn_sessions.raw)`,
        [
          deviceId,
          username,
          loginAt.toISOString(),
          textOrNull(rec.tunnel_type),
          textOrNull(rec.source_ip),
          textOrNull(rec.assigned_ip),
          textOrNull(rec.client),
          textOrNull(rec.gateway),
          pollIntervalSeconds,
          JSON.stringify(rec.raw == null ? null : rec.raw),
        ]
      );
      historyUpserted += 1;
      seenUsernames.push(username);
      seenLoginTimes.push(loginAt.toISOString());
    }

    // ⛔ END-DETECTION. Reached ONLY from inside storeVpnSessions(), which
    // services/engine-worker.js calls ONLY after a successful
    // getVpnSessionSummary() — a poll that threw never reaches this line, so
    // one unreachable firewall can never fabricate a mass disconnection of
    // every user on it. Verified at the call site, not assumed.
    //
    // ended_at = last_seen_at, NEVER now(): the last confirmed SIGHTING is the
    // last moment we know the session was up. now() would assert it stayed
    // connected right up to this poll, which is exactly the interval we did
    // not observe.
    const endResult = await client.query(
      `UPDATE vpn_sessions v
          SET ended_at = v.last_seen_at
        WHERE v.device_id = $1
          AND v.ended_at IS NULL
          AND NOT EXISTS (
                SELECT 1
                  FROM unnest($2::text[], $3::timestamptz[]) AS s(username, login_time)
                 WHERE s.username = v.username
                   AND s.login_time = v.login_time
              )`,
      [deviceId, seenUsernames, seenLoginTimes]
    );

    await client.query('COMMIT');
    return {
      count: list.length,
      historyUpserted,
      unsessionizable,
      ended: endResult.rowCount || 0,
    };
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (_rollbackErr) {
      /* ignore rollback failure — surface the original error */
    }
    throw err;
  } finally {
    client.release();
  }
}

/**
 * The current active-session rows for a device, ordered by username.
 * @param {string} deviceId
 * @param {import('pg').Pool} pool
 * @returns {Promise<object[]>}
 */
async function getVpnSessions(deviceId, pool) {
  const { rows } = await pool.query(
    `SELECT username, tunnel_type, source_ip, assigned_ip, login_time,
            duration_seconds, bytes_in, bytes_out, client, gateway, collected_at
     FROM vpn_active_sessions
     WHERE device_id = $1
     ORDER BY username ASC NULLS LAST`,
    [deviceId]
  );
  return rows;
}

/**
 * VPN session HISTORY — one row per (device, user, login), open or ended.
 *
 * ⛔ DURATION IS A LOWER BOUND WITH A KNOWN ERROR BAR, and every row says so.
 * The START is exact — the device reported login_time. The END is only known
 * to within one poll interval, because all we ever observe is "present in this
 * poll, absent in the next". So the true duration lies somewhere in
 * [duration_seconds, duration_seconds + duration_precision_seconds], and a
 * session shorter than the poll interval may never be observed AT ALL. This is
 * a SAMPLE of connections, not a complete register; a UI that renders
 * duration_seconds as an exact figure, or sums it into a confident "total
 * connected time", is misreporting it.
 *
 * Each row carries:
 *   duration_seconds            lower bound, or null when not measurable
 *   duration_is_lower_bound     always true — never present it as exact
 *   duration_precision_seconds  the poll interval, or null if it was unknown
 *                               when the row was written (unknown error bar)
 *   duration_unavailable_reason 'clock_mismatch' | 'not_computable' | null
 *   is_open                     still connected as of last_seen_at
 *
 * @param {import('pg').Pool} pool
 * @param {object} [filters]
 * @param {string} [filters.deviceId]
 * @param {string} [filters.username] exact match
 * @param {Date|string} [filters.since] sessions overlapping at/after this point
 * @param {Date|string} [filters.until] sessions starting at/before this point
 * @param {boolean} [filters.openOnly]
 * @param {number} [filters.limit]
 * @returns {Promise<object[]>}
 */
async function getVpnSessionHistory(pool, filters = {}) {
  const f = filters && typeof filters === 'object' ? filters : {};
  const conditions = [];
  const params = [];

  if (f.deviceId) {
    params.push(f.deviceId);
    conditions.push(`v.device_id = $${params.length}::uuid`);
  }
  if (f.username) {
    params.push(f.username);
    conditions.push(`v.username = $${params.length}`);
  }
  if (f.since) {
    // Overlap, not "started after": a session that began before the window and
    // was still up inside it belongs in the answer.
    params.push(toIsoOrNull(f.since));
    conditions.push(`COALESCE(v.ended_at, v.last_seen_at) >= $${params.length}::timestamptz`);
  }
  if (f.until) {
    params.push(toIsoOrNull(f.until));
    conditions.push(`v.login_time <= $${params.length}::timestamptz`);
  }
  if (f.openOnly === true) {
    conditions.push('v.ended_at IS NULL');
  }

  const limit = clampLimit(f.limit);
  params.push(limit);
  const limitParam = `$${params.length}`;
  // Built OUTSIDE the SQL template on purpose: a nested template literal
  // truncates tests/sqlColumns.test.js's `[^`]*` scan at the inner backtick,
  // which silently exempted this whole query from the column lint.
  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const { rows } = await pool.query(
    `SELECT v.id, v.device_id, d.name AS device_name, d.vendor AS device_vendor,
            v.username, v.login_time, v.tunnel_type, v.source_ip, v.assigned_ip,
            v.client, v.gateway, v.first_seen_at, v.last_seen_at, v.ended_at,
            v.poll_interval_seconds,
            (v.ended_at IS NULL) AS is_open,
            EXTRACT(EPOCH FROM (COALESCE(v.ended_at, v.last_seen_at) - v.login_time)) AS observed_seconds
       FROM vpn_sessions v
       LEFT JOIN devices d ON d.id = v.device_id
      ${whereClause}
      ORDER BY v.login_time DESC
      LIMIT ${limitParam}`,
    params
  );

  return rows.map(decorateDuration);
}

function decorateDuration(row) {
  const observedRaw = row.observed_seconds;
  const observed =
    observedRaw === null || observedRaw === undefined || Number.isNaN(Number(observedRaw))
      ? null
      : Math.round(Number(observedRaw));

  let durationSeconds = null;
  let reason = null;
  if (observed === null) {
    // Nothing to compute from — not a zero-length session.
    reason = 'not_computable';
  } else if (observed < 0) {
    // The device's clock/zone and the server's disagree. A negative duration is
    // proof of that disagreement, not a measurement; reporting it as 0 would be
    // a fabricated one.
    reason = 'clock_mismatch';
  } else {
    durationSeconds = observed;
  }

  const out = { ...row };
  delete out.observed_seconds;
  out.duration_seconds = durationSeconds;
  out.duration_is_lower_bound = true;
  out.duration_precision_seconds =
    row.poll_interval_seconds === null || row.poll_interval_seconds === undefined
      ? null
      : Number(row.poll_interval_seconds);
  out.duration_unavailable_reason = reason;
  return out;
}

function clampLimit(value) {
  const n = typeof value === 'string' ? parseInt(value, 10) : value;
  if (!Number.isInteger(n) || n < 1) return DEFAULT_HISTORY_LIMIT;
  return Math.min(n, MAX_HISTORY_LIMIT);
}

function toIsoOrNull(v) {
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v.toISOString();
  if (typeof v === 'string' && v.trim()) return v.trim();
  return null;
}

/**
 * Retention for vpn_sessions. Deliberately keyed on last_seen_at, not
 * login_time: a session still being seen is never deleted no matter how long
 * it has been up, and a row we stopped having evidence for a year ago is the
 * only kind that ages out.
 *
 * ⛔ Window is far LONGER than raw syslog retention (30 days) on purpose —
 * these rows are tiny (~180/day) and are the record everything else
 * references. Never "align" the two.
 *
 * Never throws: returns { deleted, error } so the caller's job log can report
 * a failure without one table's problem aborting the rest of the sweep.
 *
 * @param {import('pg').Pool} pool
 * @param {object} [options]
 * @param {number} [options.retentionDays]
 * @returns {Promise<{deleted:number, retentionDays:number, error:(string|null)}>}
 */
async function runVpnSessionRetention(pool, options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const retentionDays = positiveIntOrNull(opts.retentionDays) || DEFAULT_VPN_SESSION_RETENTION_DAYS;
  try {
    const result = await pool.query(
      `DELETE FROM vpn_sessions WHERE last_seen_at < now() - ($1 || ' days')::interval`,
      [retentionDays]
    );
    return { deleted: result.rowCount || 0, retentionDays, error: null };
  } catch (err) {
    return { deleted: 0, retentionDays, error: err.message || String(err) };
  }
}

module.exports = {
  storeVpnSessions,
  getVpnSessions,
  getVpnSessionHistory,
  runVpnSessionRetention,
  parseLoginTime,
  DEFAULT_HISTORY_LIMIT,
  MAX_HISTORY_LIMIT,
  DEFAULT_VPN_SESSION_RETENTION_DAYS,
};
