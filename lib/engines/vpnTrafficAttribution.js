// lib/engines/vpnTrafficAttribution.js
//
// Phase C — attribute firewall TRAFFIC to a named VPN USER.
//
// A remote user's packets do not carry their name. They carry the address the
// gateway ASSIGNED them, and that address is recycled: `10.10.50.75` belongs to
// one employee this morning and a different one this afternoon. `vpn_sessions`
// (v2.99.0) is what makes the join possible at all, because it retains
// `assigned_ip` alongside `username`, `login_time` and `ended_at`/`last_seen_at`
// — i.e. WHO held WHICH address BETWEEN WHICH TIMES.
//
// ⛔ ═══ THE ONLY RULE THAT MATTERS HERE ═══════════════════════════════════
// This module names a real employee and states what they accessed. Getting it
// wrong is not a wrong number on a dashboard, it is a fabricated accusation
// about a person. So every ambiguity resolves to NOBODY, loudly:
//
//   * attribution happens ONLY inside [login_time, COALESCE(ended_at,
//     last_seen_at)] — the interval the session demonstrably held the address —
//     and that interval is further clipped to when SecVault could first
//     ENUMERATE that gateway's sessions at all (see DEVICE_COVERAGE_SQL);
//   * traffic from a pool address at a time no known session held it is
//     UNATTRIBUTED and is COUNTED as such (never dropped, which would hide the
//     coverage gap; never assigned to the nearest session, which would invent);
//   * if two sessions overlap on one address in the same bucket, the traffic
//     goes to NEITHER and the collision is surfaced;
//   * a bucket only PARTLY covered by a session is not that session's, because
//     the rest of the bucket may be someone else's or nobody's.
//
// Being able to say "we cannot tell" is the feature. A confident wrong name is
// the failure mode, and it is the same failed-read-as-a-fact bug CLAUDE.md
// keeps finding, in the one place where it has a human cost.
//
// ── ⛔ WHY THE TALKER ROLLUP, AND WHY THE GRAIN IS AN HOUR ────────────────
// `syslog_talker_hourly` (bucket_hour, device_id, src_ip -> event_count,
// denied_count, bytes_sent, bytes_received) is the ONLY per-source-address
// aggregate this database keeps. Measured on the live host 2026-09-10:
// `syslog_events` has NO index on `src_ip` and its daily partitions are 27 GB,
// so the "obvious" per-user drill-down is a full partition scan on a database
// simultaneously taking ~1,000 inserts a second. Nothing here may read
// `syslog_events` — the same rule vpnPresence.js already carries.
//
// The price of the rollup is the GRAIN: one hour. A session boundary almost
// never lands on an hour boundary, so the first and last hour of every session
// are ambiguous by construction and are reported as such rather than rounded in
// the flattering direction. With sessions typically running hours, this loses a
// little at each end and keeps everything in between.
//
// ── ⛔ WHAT IS NOT AVAILABLE, MEASURED RATHER THAN ASSUMED ────────────────
// DESTINATIONS and APPLICATIONS per user cannot be answered today, and this
// module says so instead of approximating. `syslog_app_hourly` is keyed
// (bucket_hour, device_id, application, protocol) and `syslog_blocked_dst_hourly`
// by destination — NEITHER carries `src_ip`, so neither can be narrowed to one
// user's address. The only source that could is the raw table, see above.
// Volume, event counts and denial counts ARE answerable, so those are what this
// builds.
//
// ── ⛔ BYTES ARE A LOWER BOUND, NOT A TOTAL ───────────────────────────────
// The rollup sums bytes only from rows with `bytes_summable = true` (PAN-OS
// session-close rows; FortiOS re-logs a cumulative counter and cannot be summed
// — see lib/schema.sql). A bucket whose byte columns are NULL is UNMEASURED,
// not zero, so a user whose buckets are all NULL reports `null`, and a user with
// a mix reports what was measurable and flags `bytesArePartial`.
//
// ── ⛔ PALO ALTO ONLY, TODAY ──────────────────────────────────────────────
// Only Palo Alto's `getVpnSessionSummary()` returns per-session detail;
// Fortinet returns a bare count. So `vpn_sessions` is a Palo Alto history and
// this is a Palo Alto answer. The return value carries `coverage.vendors` and
// the UI states it — a fleet-wide reading of this would be false.

'use strict';

const DEFAULT_WINDOW_DAYS = 7;
// 30 days is not a preference, it is SYSLOG_DETAIL_RETENTION_DAYS: the talker
// rollup is aged out at 30, so a wider window would silently answer "no
// traffic" for days whose evidence was deleted.
const MAX_WINDOW_DAYS = 30;
const DEFAULT_TOP_USERS = 50;
const MAX_TOP_USERS = 250;

const HOUR_MS = 3600000;
const MS_PER_DAY = 86400000;

// Defensive ceilings. Both are far above the live fleet (187 concurrent
// sessions, ~140 talker buckets/hour across all pool addresses) and exist so a
// pathological window cannot pull an unbounded result set into memory. Hitting
// either is reported in `coverage.truncated`, never silently absorbed.
const MAX_SESSIONS = 20000;
const MAX_BUCKETS = 300000;

// Every reason a bucket of traffic was NOT attributed. These are the product,
// not the leftovers: an operator who cannot see how much traffic SecVault
// declined to name has no way to judge the names it did produce.
const UNATTRIBUTED_REASONS = ['partial_hour', 'collision', 'gap'];

function clampInt(value, fallback, min, max) {
  const n = typeof value === 'number' ? value : Number(String(value == null ? '' : value).trim());
  if (!Number.isFinite(n)) return fallback;
  const i = Math.trunc(n);
  if (i < min) return min;
  if (i > max) return max;
  return i;
}

function toMs(value) {
  if (value instanceof Date) {
    const t = value.getTime();
    return Number.isNaN(t) ? null : t;
  }
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim()) {
    const t = new Date(value).getTime();
    return Number.isNaN(t) ? null : t;
  }
  return null;
}

function toIso(ms) {
  return ms == null ? null : new Date(ms).toISOString();
}

function toNumberOrNull(value) {
  if (value == null) return null;
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(n) ? n : null;
}

// `inet` comes back from pg as '10.10.50.75' or '10.10.50.75/32' depending on
// the column and the cast. The join key must be the bare address in both
// directions or every match silently fails — which would look exactly like "no
// VPN user generated any traffic", a plausible and completely wrong answer.
function normalizeIp(value) {
  if (value == null) return null;
  const s = String(value).trim();
  if (!s) return null;
  const slash = s.indexOf('/');
  return slash === -1 ? s : s.slice(0, slash);
}

/**
 * ⛔ THE PURE CORE. Everything correctness-critical lives here, with no pool,
 * so it can be tested exhaustively against hand-built session/bucket sets —
 * including the cases that matter most and never show up in a happy-path
 * fixture: the reused address, the overlapping pair, the orphan hour.
 *
 * @param {object} input
 * @param {Array}  input.sessions  [{ id, deviceId, deviceName, username,
 *                                    assignedIp, tenureStart, tenureEnd,
 *                                    loginTime, isOpen, pollIntervalSeconds }]
 *                                  (ms times). `tenureStart` is the interval
 *                                  attribution may use; `loginTime` is the
 *                                  device's own claim, reported but never used
 *                                  for the arithmetic.
 * @param {Array}  input.buckets   [{ ip, hourStart, deviceId, deviceName,
 *                                    events, denied, bytesSent, bytesReceived }]
 * @returns {object} { users, sessions, unattributed, collisions, totals }
 */
function attributeTraffic(input) {
  const sessions = Array.isArray(input && input.sessions) ? input.sessions : [];
  const buckets = Array.isArray(input && input.buckets) ? input.buckets : [];

  // Sessions grouped by the address they held. Collisions are detected across
  // ALL devices, never per device: two gateways can hand out overlapping pools
  // (10.10.x.x on both), and "different firewalls, same address, same hour" is
  // exactly as ambiguous as one firewall doing it.
  const byIp = new Map();
  const sessionState = new Map();
  for (const s of sessions) {
    const ip = normalizeIp(s.assignedIp);
    if (!ip) continue;
    if (s.tenureStart == null || s.tenureEnd == null) continue;
    // A session with no name cannot attribute anything to anybody, and letting
    // it through would produce a row headed by `null` that reads like a user.
    if (typeof s.username !== 'string' || !s.username) continue;
    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip).push(s);
    sessionState.set(s.id, {
      id: s.id,
      username: s.username,
      deviceId: s.deviceId,
      deviceName: s.deviceName,
      assignedIp: ip,
      // The device's own claim, kept distinct from the interval we are willing
      // to attribute over — which may start later, where our coverage does.
      loginTime: s.loginTime == null ? s.tenureStart : s.loginTime,
      tenureStart: s.tenureStart,
      tenureEnd: s.tenureEnd,
      isOpen: s.isOpen === true,
      pollIntervalSeconds: s.pollIntervalSeconds == null ? null : s.pollIntervalSeconds,
      attributedHours: 0,
      events: 0,
      denied: 0,
      bytesSent: 0,
      bytesReceived: 0,
      bytesBuckets: 0,
      unmeasuredByteBuckets: 0,
      deviceIds: new Set(),
    });
  }

  const users = new Map();
  const unattributed = {
    partial_hour: { buckets: 0, events: 0 },
    collision: { buckets: 0, events: 0 },
    gap: { buckets: 0, events: 0 },
  };
  const collisions = [];
  const totals = {
    bucketsConsidered: 0,
    eventsConsidered: 0,
    bucketsAttributed: 0,
    eventsAttributed: 0,
  };

  for (const b of buckets) {
    const ip = normalizeIp(b.ip);
    const hourStart = b.hourStart;
    if (!ip || hourStart == null) continue;
    const hourEnd = hourStart + HOUR_MS;
    const events = toNumberOrNull(b.events) || 0;

    totals.bucketsConsidered += 1;
    totals.eventsConsidered += events;

    const candidates = byIp.get(ip) || [];
    // Half-open intersection. A session that ended exactly at the hour boundary
    // held nothing inside this hour.
    const overlapping = candidates.filter(
      (s) => s.tenureStart < hourEnd && s.tenureEnd > hourStart
    );

    if (overlapping.length === 0) {
      // ⛔ Traffic from a known pool address in an hour no session covers.
      // Someone generated it. We do not know who, and saying so is the whole
      // point — the alternative (nearest session wins) is how one person's
      // browsing ends up under another person's name.
      unattributed.gap.buckets += 1;
      unattributed.gap.events += events;
      continue;
    }

    if (overlapping.length > 1) {
      // ⛔ Attribute to NEITHER. The `sameUser` split is reported because a
      // reconnection by one person is a benign ambiguity and a genuine overlap
      // between two people is not — but neither one gets the traffic.
      const names = [...new Set(overlapping.map((s) => s.username))];
      unattributed.collision.buckets += 1;
      unattributed.collision.events += events;
      collisions.push({
        assignedIp: ip,
        hourStart: toIso(hourStart),
        sessionCount: overlapping.length,
        usernames: names,
        sameUser: names.length === 1,
        events,
      });
      continue;
    }

    const only = overlapping[0];
    const contained = only.tenureStart <= hourStart && only.tenureEnd >= hourEnd;
    if (!contained) {
      // The session held the address for part of this hour. The rest of the
      // hour belongs to nobody we know of, and the rollup cannot tell the two
      // halves apart, so the bucket is ambiguous in full.
      unattributed.partial_hour.buckets += 1;
      unattributed.partial_hour.events += events;
      continue;
    }

    const denied = toNumberOrNull(b.denied) || 0;
    const bytesSent = toNumberOrNull(b.bytesSent);
    const bytesReceived = toNumberOrNull(b.bytesReceived);
    const hasBytes = bytesSent != null || bytesReceived != null;

    totals.bucketsAttributed += 1;
    totals.eventsAttributed += events;

    const st = sessionState.get(only.id);
    if (st) {
      st.attributedHours += 1;
      st.events += events;
      st.denied += denied;
      if (hasBytes) {
        st.bytesBuckets += 1;
        st.bytesSent += bytesSent || 0;
        st.bytesReceived += bytesReceived || 0;
      } else {
        st.unmeasuredByteBuckets += 1;
      }
      if (b.deviceId) st.deviceIds.add(b.deviceId);
    }

    let u = users.get(only.username);
    if (!u) {
      u = {
        username: only.username,
        sessionIds: new Set(),
        assignedIps: new Set(),
        gatewayIds: new Set(),
        gatewayNames: new Set(),
        loggingDeviceIds: new Set(),
        loggingDeviceNames: new Set(),
        attributedHours: 0,
        events: 0,
        denied: 0,
        bytesSent: 0,
        bytesReceived: 0,
        bytesBuckets: 0,
        unmeasuredByteBuckets: 0,
        firstSeen: null,
        lastSeen: null,
      };
      users.set(only.username, u);
    }
    u.sessionIds.add(only.id);
    u.assignedIps.add(ip);
    if (only.deviceId) u.gatewayIds.add(only.deviceId);
    if (only.deviceName) u.gatewayNames.add(only.deviceName);
    if (b.deviceId) u.loggingDeviceIds.add(b.deviceId);
    if (b.deviceName) u.loggingDeviceNames.add(b.deviceName);
    u.attributedHours += 1;
    u.events += events;
    u.denied += denied;
    if (hasBytes) {
      u.bytesBuckets += 1;
      u.bytesSent += bytesSent || 0;
      u.bytesReceived += bytesReceived || 0;
    } else {
      u.unmeasuredByteBuckets += 1;
    }
    if (u.firstSeen == null || hourStart < u.firstSeen) u.firstSeen = hourStart;
    if (u.lastSeen == null || hourStart > u.lastSeen) u.lastSeen = hourStart;
  }

  const userRows = [...users.values()].map((u) => ({
    username: u.username,
    sessionCount: u.sessionIds.size,
    assignedIpCount: u.assignedIps.size,
    gateways: [...u.gatewayNames].sort(),
    gatewayCount: u.gatewayIds.size,
    loggingDeviceCount: u.loggingDeviceIds.size,
    loggingDevices: [...u.loggingDeviceNames].sort(),
    // ⛔ More than one firewall logged this address, so a single flow crossing
    // two managed devices is counted by each. The number is a count of LOG
    // EVENTS, not of unique connections, and this flag is what says so.
    multiDeviceCounted: u.loggingDeviceIds.size > 1,
    attributedHours: u.attributedHours,
    events: u.events,
    denied: u.denied,
    ...byteFields(u),
    firstAttributedHour: toIso(u.firstSeen),
    lastAttributedHour: toIso(u.lastSeen),
  }));

  userRows.sort(
    (a, b) => b.events - a.events || a.username.localeCompare(b.username)
  );

  const sessionRows = [...sessionState.values()]
    .filter((s) => s.attributedHours > 0)
    .map((s) => ({
      id: s.id,
      username: s.username,
      deviceId: s.deviceId,
      deviceName: s.deviceName,
      assignedIp: s.assignedIp,
      loginTime: toIso(s.loginTime),
      // Where attribution was actually allowed to begin. Differs from
      // loginTime only when this gateway's own history began later.
      attributionFrom: toIso(s.tenureStart),
      attributionClipped: s.tenureStart > s.loginTime,
      tenureEnd: toIso(s.tenureEnd),
      isOpen: s.isOpen,
      pollIntervalSeconds: s.pollIntervalSeconds,
      attributedHours: s.attributedHours,
      events: s.events,
      denied: s.denied,
      ...byteFields(s),
      loggingDeviceCount: s.deviceIds.size,
      multiDeviceCounted: s.deviceIds.size > 1,
    }))
    .sort((a, b) => b.events - a.events || a.username.localeCompare(b.username));

  collisions.sort((a, b) => b.events - a.events);

  return {
    users: userRows,
    sessions: sessionRows,
    unattributed,
    collisions,
    totals,
  };
}

// ⛔ Tri-state bytes. Zero measurable buckets means UNMEASURED, which is `null`
// and renders as an em-dash — never `0`, which would read as "this person moved
// no data" when the truth is "this vendor's counters cannot be summed".
function byteFields(acc) {
  const measured = acc.bytesBuckets > 0;
  return {
    bytesSent: measured ? acc.bytesSent : null,
    bytesReceived: measured ? acc.bytesReceived : null,
    byteBuckets: acc.bytesBuckets,
    unmeasuredByteBuckets: acc.unmeasuredByteBuckets,
    // Some buckets contributed bytes and some could not, so the total is a
    // floor. Same convention as vpn_sessions' duration lower bound.
    bytesArePartial: measured && acc.unmeasuredByteBuckets > 0,
  };
}

const COVERAGE_SQL = `
  SELECT (SELECT count(*) FROM vpn_sessions) AS session_rows,
         (SELECT min(first_seen_at) FROM vpn_sessions) AS history_start,
         (SELECT min(login_time) FROM vpn_sessions) AS earliest_login,
         (SELECT max(last_seen_at) FROM vpn_sessions) AS latest_observation,
         (SELECT min(bucket_hour) FROM syslog_talker_hourly) AS traffic_start,
         (SELECT max(bucket_hour) FROM syslog_talker_hourly) AS traffic_end`;

// ⛔ OVERLAP, not "started inside the window" — the same rule
// getVpnSessionHistory() already carries. A session that began yesterday and
// was still up this morning owns this morning's traffic, and filtering on
// login_time alone would drop exactly the long connections an operator cares
// about.
const SESSIONS_SQL = `
  SELECT v.id, v.device_id, v.username, v.assigned_ip, v.login_time,
         v.ended_at, v.last_seen_at, v.poll_interval_seconds,
         (v.ended_at IS NULL) AS is_open,
         d.name AS device_name, d.vendor AS device_vendor
    FROM vpn_sessions v
    LEFT JOIN devices d ON d.id = v.device_id
   WHERE v.assigned_ip IS NOT NULL
     AND v.login_time < $2::timestamptz
     AND COALESCE(v.ended_at, v.last_seen_at) > $1::timestamptz
   ORDER BY v.login_time ASC
   LIMIT $3`;

// ⛔ COVERAGE IS PER GATEWAY, NOT FLEET-WIDE, and the difference is a real bug
// rather than a refinement. A gateway added to SecVault next month will report
// sessions whose `login_time` the device says began weeks earlier. Judged
// against a FLEET-wide history start those weeks look covered, so an hour with
// exactly one known session on that address reads as unambiguous — while
// SecVault was in fact unable to enumerate that gateway's sessions at all, and
// somebody else may have held the address. That is the same false unambiguity
// the global bound exists to prevent, arriving through the side door. Each
// session's tenure is therefore clipped to its OWN device's first observation.
const DEVICE_COVERAGE_SQL = `
  SELECT v.device_id, min(v.first_seen_at) AS device_start
    FROM vpn_sessions v
   GROUP BY v.device_id`;

// Sessions in the window that can NEVER be attributed, because the device did
// not report the address. Counted, not hidden: their traffic is somewhere in
// the `gap` bucket and the operator is entitled to know why.
const UNJOINABLE_SQL = `
  SELECT count(*) AS unjoinable
    FROM vpn_sessions v
   WHERE v.assigned_ip IS NULL
     AND v.login_time < $2::timestamptz
     AND COALESCE(v.ended_at, v.last_seen_at) > $1::timestamptz`;

// ⛔ Bounded on THREE axes at once: the hour range (which the bucket_hour index
// serves), the specific pool addresses, and a row ceiling. The address list is
// the set this app has OBSERVED a gateway assign — the only defensible
// definition of "a VPN pool address" available, and the thing that makes gap
// traffic detectable at all.
const BUCKETS_SQL = `
  SELECT t.bucket_hour, t.src_ip, t.device_id, t.event_count, t.denied_count,
         t.bytes_sent, t.bytes_received, d.name AS device_name
    FROM syslog_talker_hourly t
    LEFT JOIN devices d ON d.id = t.device_id
   WHERE t.bucket_hour >= $1::timestamptz
     AND t.bucket_hour < $2::timestamptz
     AND t.src_ip = ANY($3::inet[])
   ORDER BY t.bucket_hour ASC
   LIMIT $4`;

/**
 * Per-user VPN traffic attribution over a bounded window.
 *
 * @param {object} pool  pg pool (REQUIRED — never construct one here)
 * @param {object} [options]
 * @param {number} [options.days]      window size, 1..30 (default 7)
 * @param {Date|string} [options.until] window end (default now)
 * @param {string} [options.username]  restrict to one user
 * @param {string} [options.deviceId]  restrict to one GATEWAY's sessions
 * @param {number} [options.topUsers]  cap on rows returned (default 50)
 * @returns {Promise<object>}
 */
async function getVpnUserTraffic(pool, options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const days = clampInt(opts.days, DEFAULT_WINDOW_DAYS, 1, MAX_WINDOW_DAYS);
  const topUsers = clampInt(opts.topUsers, DEFAULT_TOP_USERS, 1, MAX_TOP_USERS);
  const untilMs = toMs(opts.until) == null ? Date.now() : toMs(opts.until);
  const requestedFromMs = untilMs - days * MS_PER_DAY;

  const empty = emptyResult({ requestedFromMs, untilMs, days, topUsers });
  if (!pool || typeof pool.query !== 'function') {
    empty.coverage.reason = 'no_pool';
    empty.coverage.reasonText = 'No database connection was supplied.';
    return empty;
  }

  const coverageRow = (await pool.query(COVERAGE_SQL)).rows[0] || {};
  const historyStartMs = toMs(coverageRow.history_start);
  const trafficStartMs = toMs(coverageRow.traffic_start);
  const trafficEndMs = toMs(coverageRow.traffic_end);
  const sessionRows = toNumberOrNull(coverageRow.session_rows) || 0;

  // ⛔ BOTH BOUNDS, ALWAYS VISIBLE. The window is clipped by whichever of the
  // two evidence streams starts later, and the caller is told WHICH — because
  // "this user did nothing before Tuesday" and "SecVault has no idea what this
  // user did before Tuesday" are different statements and only one of them is
  // true.
  //
  // ⛔ THE SESSION-HISTORY BOUND IS NOT COSMETIC, and it is not made redundant
  // by a session whose `login_time` predates it. Before the first poll, the
  // session set is not merely sparse, it is UNENUMERABLE: any session that
  // began AND ended before collection started was never recorded at all. So an
  // hour before that point can look unambiguous — exactly one known session
  // covering it — while a second, invisible session also held the address. That
  // is a FALSE unambiguity, and it produces precisely the confident wrong name
  // this module exists to prevent. Attribution therefore never reaches back
  // past the first observation, however far back the device says the session
  // started.
  const bounds = [];
  let fromMs = requestedFromMs;
  if (historyStartMs != null && historyStartMs > fromMs) {
    fromMs = historyStartMs;
    bounds.push('session_history_start');
  }
  if (trafficStartMs != null && trafficStartMs > fromMs) {
    fromMs = trafficStartMs;
    bounds.push('traffic_retention');
  }

  const result = emptyResult({ requestedFromMs, untilMs, days, topUsers });
  result.window.from = toIso(fromMs);
  result.coverage.sessionHistoryStart = toIso(historyStartMs);
  result.coverage.earliestLogin = toIso(toMs(coverageRow.earliest_login));
  result.coverage.latestObservation = toIso(toMs(coverageRow.latest_observation));
  result.coverage.trafficRollupStart = toIso(trafficStartMs);
  result.coverage.trafficRollupEnd = toIso(trafficEndMs);
  result.coverage.bounds = bounds;
  result.coverage.truncatedAtStart = bounds.length > 0;
  result.coverage.boundNote = boundNote(bounds, requestedFromMs, fromMs);
  // How many whole clock hours the surviving window could possibly contain.
  // Zero means the grain is wider than the evidence, which is a real answer.
  result.coverage.attributableHours = Math.max(0, Math.floor((untilMs - fromMs) / HOUR_MS));

  if (sessionRows === 0 || historyStartMs == null) {
    // ⛔ NOT an empty answer with zeros in it. There is no session history at
    // all, so nothing about any user's traffic has been measured.
    result.coverage.reason = 'no_session_history';
    result.coverage.reasonText =
      'No VPN session history has been collected yet, so no traffic can be attributed to any user. '
      + 'This is not evidence that nobody used the VPN.';
    return result;
  }

  if (fromMs >= untilMs) {
    result.coverage.reason = 'window_empty_after_bounds';
    result.coverage.reasonText =
      'The requested window lies entirely before the earliest evidence SecVault holds.';
    return result;
  }

  const fromIso = toIso(fromMs);
  const untilIso = toIso(untilMs);

  const { rows: rawSessions } = await pool.query(SESSIONS_SQL, [fromIso, untilIso, MAX_SESSIONS + 1]);
  const sessionsTruncated = rawSessions.length > MAX_SESSIONS;
  const sessionSlice = sessionsTruncated ? rawSessions.slice(0, MAX_SESSIONS) : rawSessions;

  const unjoinable = toNumberOrNull(
    ((await pool.query(UNJOINABLE_SQL, [fromIso, untilIso])).rows[0] || {}).unjoinable
  ) || 0;

  // Vendor scope is REPORTED, never assumed. If a second vendor ever starts
  // producing per-session rows this stops being a Palo Alto answer on its own,
  // without anybody editing a hardcoded string.
  const vendors = [...new Set(sessionSlice.map((r) => r.device_vendor).filter(Boolean))].sort();

  // Filters are applied to the SESSION SET, not to the traffic: collisions must
  // still be detected against EVERY session that held the address, including
  // ones belonging to another user or another gateway. Narrowing the SQL would
  // make an ambiguous address look unambiguous — the exact failure this module
  // exists to prevent.
  const wantUser = typeof opts.username === 'string' && opts.username.trim()
    ? opts.username.trim().toLowerCase()
    : null;
  const wantDevice = typeof opts.deviceId === 'string' && opts.deviceId.trim()
    ? opts.deviceId.trim()
    : null;

  const deviceStart = new Map();
  for (const r of (await pool.query(DEVICE_COVERAGE_SQL)).rows) {
    const ms = toMs(r.device_start);
    if (r.device_id && ms != null) deviceStart.set(r.device_id, ms);
  }

  let clippedByDeviceCoverage = 0;
  const sessions = sessionSlice.map((r) => {
    const login = toMs(r.login_time);
    const covered = deviceStart.has(r.device_id) ? deviceStart.get(r.device_id) : null;
    const start = covered != null && login != null && covered > login ? covered : login;
    if (start !== login) clippedByDeviceCoverage += 1;
    return {
      id: r.id,
      deviceId: r.device_id,
      deviceName: r.device_name || null,
      deviceVendor: r.device_vendor || null,
      username: r.username,
      assignedIp: normalizeIp(r.assigned_ip),
      loginTime: login,
      tenureStart: start,
      tenureEnd: toMs(r.ended_at) == null ? toMs(r.last_seen_at) : toMs(r.ended_at),
      isOpen: r.is_open === true,
      pollIntervalSeconds: toNumberOrNull(r.poll_interval_seconds),
    };
  }).filter((s) => s.assignedIp && s.tenureStart != null && s.tenureEnd != null);
  result.coverage.sessionsClippedByDeviceCoverage = clippedByDeviceCoverage;

  const ips = [...new Set(sessions.map((s) => s.assignedIp))];
  result.coverage.sessionsJoinable = sessionSlice.length;
  result.coverage.sessionsUnjoinable = unjoinable;
  result.coverage.poolAddresses = ips.length;
  result.coverage.vendors = vendors;
  result.coverage.truncatedSessions = sessionsTruncated;

  if (ips.length === 0) {
    result.coverage.reason = 'no_assigned_addresses';
    result.coverage.reasonText =
      'No session in this window reported the address the gateway assigned, so there is nothing to join traffic to.';
    return result;
  }

  const { rows: rawBuckets } = await pool.query(BUCKETS_SQL, [
    fromIso,
    untilIso,
    ips,
    MAX_BUCKETS + 1,
  ]);
  const bucketsTruncated = rawBuckets.length > MAX_BUCKETS;
  const bucketSlice = bucketsTruncated ? rawBuckets.slice(0, MAX_BUCKETS) : rawBuckets;
  result.coverage.truncatedBuckets = bucketsTruncated;

  const buckets = bucketSlice.map((r) => ({
    ip: normalizeIp(r.src_ip),
    hourStart: toMs(r.bucket_hour),
    deviceId: r.device_id,
    deviceName: r.device_name || null,
    events: toNumberOrNull(r.event_count),
    denied: toNumberOrNull(r.denied_count),
    bytesSent: toNumberOrNull(r.bytes_sent),
    bytesReceived: toNumberOrNull(r.bytes_received),
  }));

  const attributed = attributeTraffic({ sessions, buckets });

  let users = attributed.users;
  let sessionRowsOut = attributed.sessions;
  if (wantUser) {
    users = users.filter((u) => u.username.toLowerCase() === wantUser);
    sessionRowsOut = sessionRowsOut.filter((s) => s.username.toLowerCase() === wantUser);
  }
  if (wantDevice) {
    sessionRowsOut = sessionRowsOut.filter((s) => s.deviceId === wantDevice);
    const keep = new Set(sessionRowsOut.map((s) => s.username));
    users = users.filter((u) => keep.has(u.username));
  }

  result.usersTotal = users.length;
  result.usersTruncated = users.length > topUsers;
  result.users = users.slice(0, topUsers);
  result.sessions = sessionRowsOut;
  result.unattributed = attributed.unattributed;
  // A collision list is evidence, and a long one is itself the finding — but it
  // does not need to be unbounded on screen. The COUNTS above are complete.
  result.collisions = attributed.collisions.slice(0, 50);
  result.collisionsTotal = attributed.collisions.length;
  result.totals = attributed.totals;
  result.measured = true;

  // ⛔ ZERO ATTRIBUTED IS NOT ZERO USED, and the two ways of arriving at it are
  // different facts. On the day session history starts, the clipped window is
  // minutes wide and CANNOT contain a whole clock hour, so the honest answer is
  // "too early to tell" — rendering that as an empty table of users would say
  // the opposite.
  if (result.coverage.attributableHours === 0) {
    result.coverage.reason = 'window_shorter_than_one_hour';
    result.coverage.reasonText =
      'The window that survives both coverage bounds is shorter than the one-hour '
      + 'aggregation grain, so no traffic can be attributed yet. This is not evidence '
      + 'that nobody used the VPN.';
  } else if (attributed.totals.bucketsConsidered === 0) {
    result.coverage.reason = 'no_traffic_rows';
    result.coverage.reasonText =
      'No traffic rows were recorded against any address these sessions were assigned, '
      + 'within the window that survives both coverage bounds.';
  }
  return result;
}

function boundNote(bounds, requestedFromMs, fromMs) {
  if (bounds.length === 0) return null;
  const parts = [];
  if (bounds.includes('session_history_start')) {
    parts.push('VPN session history begins later than the requested window');
  }
  if (bounds.includes('traffic_retention')) {
    parts.push('the traffic rollup is retained for a limited number of days');
  }
  const requested = toIso(requestedFromMs);
  const effective = toIso(fromMs);
  return (
    'The window was clipped from ' + requested + ' to ' + effective + ' because '
    + parts.join(' and ')
    + '. Anything before that is NOT MEASURED, not zero.'
  );
}

function emptyResult(meta) {
  return {
    measured: false,
    window: {
      from: toIso(meta.requestedFromMs),
      until: toIso(meta.untilMs),
      requestedFrom: toIso(meta.requestedFromMs),
      days: meta.days,
      grain: 'hour',
    },
    coverage: {
      reason: null,
      reasonText: null,
      sessionHistoryStart: null,
      earliestLogin: null,
      latestObservation: null,
      trafficRollupStart: null,
      trafficRollupEnd: null,
      bounds: [],
      boundNote: null,
      truncatedAtStart: false,
      sessionsJoinable: 0,
      sessionsUnjoinable: 0,
      sessionsClippedByDeviceCoverage: 0,
      poolAddresses: 0,
      vendors: [],
      truncatedSessions: false,
      truncatedBuckets: false,
      attributableHours: 0,
    },
    users: [],
    usersTotal: 0,
    usersTruncated: false,
    topUsers: meta.topUsers,
    sessions: [],
    unattributed: {
      partial_hour: { buckets: 0, events: 0 },
      collision: { buckets: 0, events: 0 },
      gap: { buckets: 0, events: 0 },
    },
    collisions: [],
    collisionsTotal: 0,
    totals: {
      bucketsConsidered: 0,
      eventsConsidered: 0,
      bucketsAttributed: 0,
      eventsAttributed: 0,
    },
    notes: {
      grain:
        'Traffic is aggregated per hour, so the first and last hour of a session are only '
        + 'partly covered by it and are reported as unattributed rather than assigned.',
      bytes:
        'Byte totals come only from log rows whose counters can be summed (Palo Alto '
        + 'session-close rows). A user whose buckets carry no summable bytes reports NOT '
        + 'MEASURED, never zero.',
      destinations:
        'Per-user destinations and applications are NOT available: the application and '
        + 'blocked-destination rollups are not keyed by source address, and the raw event '
        + 'table has no source-address index.',
      doubleCount:
        'Where more than one firewall logged the same address, a flow crossing both is '
        + 'counted by each. These are log event counts, not unique connections.',
      vendorScope:
        'Only Palo Alto reports per-session VPN detail, so this covers Palo Alto gateways '
        + 'only and is not a fleet-wide view.',
    },
  };
}

module.exports = {
  getVpnUserTraffic,
  attributeTraffic,
  normalizeIp,
  clampInt,
  DEFAULT_WINDOW_DAYS,
  MAX_WINDOW_DAYS,
  DEFAULT_TOP_USERS,
  MAX_TOP_USERS,
  UNATTRIBUTED_REASONS,
};
