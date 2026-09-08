// lib/syslog/rollups.js
//
// Pre-aggregation of syslog_events into the permanent rollup tables.
//
// ── THE MODEL: RECOMPUTE-WINDOW, NOT INCREMENT-ON-INSERT ──────────────────
// Each cycle DELETEs and re-INSERTs whole time buckets from the raw source of
// truth. That makes every cycle idempotent and self-healing: a missed cycle, a
// collector restart, a double-run or a retry can never double-count or drift.
//
// ⛔ DO NOT "optimize" this into incrementing counters at insert time. It looks
// like an obvious efficiency win and quietly reintroduces double-counting on
// every restart or retry. LogVault reached the same conclusion the hard way and
// its CLAUDE.md carries the same warning; this is a deliberate, shared
// convention, not an oversight.
//
// ── WHY TIERED, WHERE LOGVAULT IS SINGLE-WINDOW ───────────────────────────
// LogVault recomputes a trailing 24h every 5 minutes. At its volume that is
// cheap. SecVault ingests ~1,400 events/sec (~93M/day after FWA's removal), so
// the identical design would re-aggregate ~93M rows 288 times a day. So:
//
//   RECENT sweep  (every few minutes)  trailing SYSLOG_ROLLUP_RECENT_HOURS
//   WIDE sweep    (hourly)             trailing SYSLOG_ROLLUP_LOOKBACK_HOURS
//
// ⛔ The WIDE sweep is the one that must not be removed "to save cycles".
// `received_at` is stamped when the collector parses the line and is never
// rewritten, so an event that lands late — a DB outage, ingest backpressure, or
// simply the collector being down during a deploy, all ROUTINE — belongs to a
// bucket that has already scrolled out of the recent window. Without a wider
// periodic sweep that bucket is never revisited and the rollup silently and
// PERMANENTLY under-counts, with no error anywhere. LogVault shipped exactly
// that bug with a 2-hour window and had to widen it; this is that lesson
// applied up front rather than after the fact.
//
// A gap LONGER than the wide window still needs a manual backfill over the
// affected range — see backfillRange().

'use strict';

// ⛔ ONE deny/allow list for the whole codebase. There used to be four, and
// the narrowest of them drove every dashboard number -- measured live, that
// under-counted blocks by 6.8% fleet-wide and 24% on URL-category rows,
// because `block-url` (the only URL-filtering block verb PAN-OS emits) was
// missing. See lib/syslog/actions.js.
const { ALLOWED_SQL, DENIED_SQL } = require('./actions');

// ── ONE SCAN, FIVE ROLLUPS ────────────────────────────────────────────────
// Every rollup aggregates the SAME rows over the SAME window, so the window
// is materialized ONCE into a temp table and each rollup aggregates that
// instead of re-scanning syslog_events.
//
// Measured on the live host before this existed (2026-09-08, 9.3M rows in a
// 3-hour window): each rollup was a parallel SEQ SCAN of the whole 9.9 GB
// daily partition -- 7.3s and ~9.1 GB of buffer reads EACH, five times over,
// for an 84s recent sweep every 5 minutes and a 170s wide sweep every hour.
// Projected to the steady state (~133 GB/day) the hourly wide sweep alone
// would have read ~600 GB off the same disk that is taking ~1,500 inserts a
// second. The temp table excludes `message`, which is ~90% of a row by
// bytes and which no rollup reads, so it is roughly a tenth of the size.
//
// ⛔ The window now appears in exactly ONE statement. That is the real prize:
// a DELETE range that disagrees with its INSERT range is precisely the bug
// that broke syslog_rule_hits_daily, and it is now structurally impossible
// for two rollups to be built over different windows.
//
// ⛔ ON COMMIT DROP, not an explicit DROP: the client goes back to a POOL, so
// a temp table surviving the transaction would leak onto a pooled connection
// and the next sweep would fail with "relation already exists". ON COMMIT
// DROP also cleans up on ROLLBACK, which an explicit DROP after the COMMIT
// would not.
const WINDOW_TEMP = `
  CREATE TEMP TABLE rollup_src ON COMMIT DROP AS
  SELECT date_trunc('hour', received_at) AS bucket_hour,
         received_at, source_ip, device_id, vendor, action, severity, log_class,
         rule_id, rule_uuid, rule_name,
         src_ip, dst_ip, dst_port, protocol, application,
         bytes_sent, bytes_received, bytes_summable,
         -- Added 2026-09-08 for the country/user/URL rollups. Deliberately
         -- NOT threat_name/threat_severity: threat events are 1.3% of the
         -- stream and are read straight from syslog_events through their own
         -- index, which keeps the per-event attacker/target detail an
         -- aggregate would destroy. Every column added here is copied for
         -- all ~10M rows in the window, so the list stays minimal.
         src_user, src_country, dst_country, url_category
    FROM syslog_events
   WHERE received_at >= $1 AND received_at < $2`;

// Lets the planner choose a real aggregation strategy for the five passes
// below. A freshly created temp table has NO statistics at all, so without
// this every one of them is planned off a hardcoded row-count guess.
const WINDOW_ANALYZE = 'ANALYZE rollup_src';

const HOURLY_DELETE = `
  DELETE FROM syslog_rollup_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// ⛔ sum() over all-NULL yields NULL, and that is CORRECT here: a vendor that
// never reports byte counts must stay unmeasured in the rollup rather than
// being aggregated into a confident 0. Same tri-state rule as hit_count.
const HOURLY_INSERT = `
  INSERT INTO syslog_rollup_hourly
    (bucket_hour, source_ip, device_id, vendor, action, severity, log_class,
     event_count, bytes_sent, bytes_received, updated_at)
  SELECT bucket_hour, source_ip, device_id, vendor, action, severity, log_class,
         count(*),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable), now()
    FROM rollup_src
   GROUP BY 1, 2, 3, 4, 5, 6, 7`;

const RULE_DELETE = `
  DELETE FROM syslog_rule_hits_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// Only rows that actually identify a rule. A traffic log with no rule identity
// is real data but contributes nothing to "has this rule seen traffic", and
// including it would create a NULL-rule bucket that reads like a real rule.
const RULE_INSERT = `
  INSERT INTO syslog_rule_hits_hourly
    (bucket_hour, device_id, source_ip, vendor, rule_id, rule_uuid, rule_name, action,
     hit_count, bytes_sent, bytes_received, first_seen_at, last_seen_at)
  SELECT bucket_hour, device_id, source_ip, vendor, rule_id, rule_uuid, rule_name, action,
         count(*),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable),
         min(received_at), max(received_at)
    FROM rollup_src
   WHERE (rule_id IS NOT NULL OR rule_uuid IS NOT NULL OR rule_name IS NOT NULL)
   GROUP BY 1, 2, 3, 4, 5, 6, 7, 8`;

// ── Detail rollups (Phase 8b) ─────────────────────────────────────────────
// Three NARROW tables rather than more dimensions on the hourly rollup --
// see lib/schema.sql for why, and LogVault's schema for the same warning.
// All three use the SAME [from, to) window and the same DELETE-then-INSERT
// model, so they inherit the correctness already proven for the other two.

const TALKER_DELETE = `
  DELETE FROM syslog_talker_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// ⛔ Only rows with a real src_ip. A traffic log without one is still a real
// event, but it says nothing about which host was talking.
const TALKER_INSERT = `
  INSERT INTO syslog_talker_hourly
    (bucket_hour, device_id, src_ip, event_count, denied_count, bytes_sent, bytes_received)
  SELECT bucket_hour, device_id, src_ip,
         count(*),
         count(*) FILTER (WHERE lower(action) IN ${DENIED_SQL}),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable)
    FROM rollup_src
   WHERE src_ip IS NOT NULL
   GROUP BY 1, 2, 3`;

const APP_DELETE = `
  DELETE FROM syslog_app_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

const APP_INSERT = `
  INSERT INTO syslog_app_hourly
    (bucket_hour, device_id, application, protocol, event_count, bytes_sent, bytes_received)
  SELECT bucket_hour, device_id, application, protocol,
         count(*),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable)
    FROM rollup_src
   WHERE (application IS NOT NULL OR protocol IS NOT NULL)
   GROUP BY 1, 2, 3, 4`;

const BLOCKED_DELETE = `
  DELETE FROM syslog_blocked_dst_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// ⛔ BLOCKED destinations only -- the full destination set is unbounded
// internet addressing, and this is the question actually worth asking.
const BLOCKED_INSERT = `
  INSERT INTO syslog_blocked_dst_hourly
    (bucket_hour, device_id, dst_ip, dst_port, protocol, event_count)
  SELECT bucket_hour, device_id, dst_ip, dst_port, protocol, count(*)
    FROM rollup_src
   WHERE dst_ip IS NOT NULL
     AND lower(action) IN ${DENIED_SQL}
   GROUP BY 1, 2, 3, 4, 5`;

const INBOUND_DELETE = `
  DELETE FROM syslog_device_inbound_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// Traffic addressed TO a device's own published addresses.
//
// ⛔ The `devip` CTE is what BOUNDS this rollup: a device's own interface
// addresses plus anything a destination-NAT rule publishes. Without it this
// would aggregate every destination on the internet.
//
// ⛔ The regex guard runs BEFORE the ::inet cast, not after. device_interfaces
// .ip_address is TEXT and carries the literal sentinel 'N/A' on live rows;
// casting that raises "invalid input syntax for type inet" and would abort the
// whole sweep transaction, taking the other seven rollups down with it.
//
// ⛔ `allowed` uses the same verified action list as logHit.js: Fortinet logs
// an ESTABLISHED session that ended as close/client-rst/server-rst, so those
// count as reached. Palo Alto's reset-both is a block. An action in neither
// list stays NULL -- unknown, never folded into either bucket.
const INBOUND_INSERT = `
  INSERT INTO syslog_device_inbound_hourly
    (bucket_hour, device_id, dst_ip, dst_port, protocol, allowed, public_source,
     event_count, distinct_sources, last_seen_at)
  SELECT s.bucket_hour, s.device_id, s.dst_ip, s.dst_port, s.protocol,
         CASE
           WHEN lower(s.action) IN ${ALLOWED_SQL} THEN true
           WHEN lower(s.action) IN ${DENIED_SQL} THEN false
           ELSE NULL
         END,
         CASE WHEN s.src_ip IS NULL THEN NULL ELSE NOT (
           s.src_ip <<= '10.0.0.0/8'::inet OR s.src_ip <<= '172.16.0.0/12'::inet OR
           s.src_ip <<= '192.168.0.0/16'::inet OR s.src_ip <<= '127.0.0.0/8'::inet OR
           s.src_ip <<= '169.254.0.0/16'::inet OR s.src_ip <<= '100.64.0.0/10'::inet) END,
         count(*), count(DISTINCT s.src_ip), max(s.received_at)
    FROM rollup_src s
    JOIN (
           SELECT device_id, split_part(ip_address, '/', 1)::inet AS ip
             FROM device_interfaces
            WHERE ip_address IS NOT NULL
              AND split_part(ip_address, '/', 1) ~ '^[0-9]{1,3}([.][0-9]{1,3}){3}$'
           UNION
           SELECT n.device_id, e::inet
             FROM nat_rules n,
                  LATERAL jsonb_array_elements_text(n.original_dst_addresses) AS e
            WHERE lower(n.nat_type) = 'destination'
              AND e ~ '^[0-9]{1,3}([.][0-9]{1,3}){3}$'
         ) devip ON devip.device_id = s.device_id AND devip.ip = s.dst_ip
   WHERE s.dst_ip IS NOT NULL
   GROUP BY 1, 2, 3, 4, 5, 6, 7`;

const COUNTRY_DELETE = `
  DELETE FROM syslog_country_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// ⛔ dst_country is NOT filtered to non-null: "we could not tell where this
// went" is a real and interesting bucket, and dropping it would make the
// percentages in the widget add up to 100% of a smaller number while looking
// like 100% of the traffic.
const COUNTRY_INSERT = `
  INSERT INTO syslog_country_hourly
    (bucket_hour, device_id, dst_country, event_count, denied_count, bytes_sent, bytes_received)
  SELECT bucket_hour, device_id, dst_country,
         count(*),
         count(*) FILTER (WHERE lower(action) IN ${DENIED_SQL}),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable)
    FROM rollup_src
   GROUP BY 1, 2, 3`;

const USER_DELETE = `
  DELETE FROM syslog_user_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// Only rows that actually name a user. An unattributed session is the
// NORMAL case on this fleet (identity is resolved on a small fraction of
// events), so a NULL-user bucket would dwarf every real user and say nothing.
// The widget states its own coverage instead.
const USER_INSERT = `
  INSERT INTO syslog_user_hourly
    (bucket_hour, device_id, src_user, log_class, event_count, denied_count, bytes_sent, bytes_received)
  SELECT bucket_hour, device_id, src_user, log_class,
         count(*),
         count(*) FILTER (WHERE lower(action) IN ${DENIED_SQL}),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable)
    FROM rollup_src
   WHERE src_user IS NOT NULL
   GROUP BY 1, 2, 3, 4`;

const URLCAT_DELETE = `
  DELETE FROM syslog_urlcat_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

const URLCAT_INSERT = `
  INSERT INTO syslog_urlcat_hourly
    (bucket_hour, device_id, url_category, event_count, denied_count)
  SELECT bucket_hour, device_id, url_category,
         count(*),
         count(*) FILTER (WHERE lower(action) IN ${DENIED_SQL})
    FROM rollup_src
   WHERE url_category IS NOT NULL
   GROUP BY 1, 2, 3`;

/**
 * Snap a Date back to the start of its UTC hour.
 * Buckets are UTC so they do not shift under DST and a bucket boundary is the
 * same instant everywhere — the same reasoning as the daily partitions.
 */
function floorHour(date) {
  const d = new Date(date.getTime());
  d.setUTCMinutes(0, 0, 0);
  return d;
}

function addHours(date, hours) {
  return new Date(date.getTime() + hours * 3600 * 1000);
}

/**
 * The [from, to) window a sweep should recompute.
 *
 * `to` is the start of the NEXT hour, so the in-progress hour is included and
 * gets corrected on every subsequent sweep. Excluding it would leave the
 * current hour permanently empty until it happened to roll over between two
 * cycles.
 *
 * @param {Date} now
 * @param {number} hours trailing hours to cover
 * @returns {{from: Date, to: Date}}
 */
function sweepWindow(now, hours) {
  const h = Number.isFinite(Number(hours)) && Number(hours) >= 1 ? Math.trunc(Number(hours)) : 1;
  const to = addHours(floorHour(now), 1);
  const from = addHours(to, -(h + 1)); // +1 so the whole earliest hour is covered
  return { from, to };
}

/**
 * Recompute ALL FIVE rollups for a window. Idempotent: DELETE then INSERT, so
 * running it twice produces the same result as running it once.
 *
 * ⛔ Wrapped in ONE transaction so a reader never sees a bucket mid-rebuild —
 * without it, a dashboard query landing between a DELETE and its INSERT would
 * show zero traffic for that hour and look like an outage. One transaction
 * for all five (it was one EACH until 2026-09-08) also means the rollups can
 * never disagree with each other about an hour, and is what lets the window
 * be scanned once into a temp table — see WINDOW_TEMP above.
 *
 * Readers are not blocked by any of this: under MVCC they keep seeing the
 * previous contents until the COMMIT.
 *
 * Never throws: the caller is a timer inside a long-running service, and one
 * failed sweep must not take the collector down. The failure is returned.
 *
 * @returns {{ok, from, to, hourlyRows, ruleRows, ms, error}}
 */
async function recomputeWindow(pool, from, to) {
  const started = Date.now();
  const result = {
    ok: false, from, to,
    hourlyRows: 0, ruleRows: 0, talkerRows: 0, appRows: 0, blockedRows: 0,
    inboundRows: 0, countryRows: 0, userRows: 0, urlCatRows: 0,
    ms: 0, error: null,
  };
  if (!pool) { result.error = 'no pool supplied'; return result; }

  let client;
  try {
    client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Read the window ONCE. Everything below aggregates this.
      await client.query(WINDOW_TEMP, [from, to]);
      await client.query(WINDOW_ANALYZE);

      for (const [del, ins, key] of [
        [HOURLY_DELETE, HOURLY_INSERT, 'hourlyRows'],
        [RULE_DELETE, RULE_INSERT, 'ruleRows'],
        [TALKER_DELETE, TALKER_INSERT, 'talkerRows'],
        [APP_DELETE, APP_INSERT, 'appRows'],
        [BLOCKED_DELETE, BLOCKED_INSERT, 'blockedRows'],
        [INBOUND_DELETE, INBOUND_INSERT, 'inboundRows'],
        [COUNTRY_DELETE, COUNTRY_INSERT, 'countryRows'],
        [USER_DELETE, USER_INSERT, 'userRows'],
        [URLCAT_DELETE, URLCAT_INSERT, 'urlCatRows'],
      ]) {
        await client.query(del, [from, to]);
        const res = await client.query(ins);
        result[key] = res.rowCount || 0;
      }

      await client.query('COMMIT');
    } catch (err) {
      // ROLLBACK also drops the temp table (ON COMMIT DROP), so a failed
      // sweep leaves nothing behind on the pooled connection.
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    }

    result.ok = true;
  } catch (err) {
    result.error = err && err.message ? err.message : String(err);
  } finally {
    if (client) client.release();
  }
  result.ms = Date.now() - started;
  return result;
}

// How many hours of raw data one WIDE pass may cover. The wide sweep used to
// recompute its whole lookback in a single pass, which is fine at 2 hours of
// stored data and impossible at 24: measured on the live fleet, that pass grew
// 155s -> 248s -> 327s as the partition filled, started overrunning the
// 5-minute cycle ("rollup skipped - previous sweep still running"), and was on
// course to be re-aggregating ~120M rows every hour at steady state.
//
// ⛔ The fix is to SLICE the lookback, never to shrink it. Dropping the wide
// sweep to a couple of hours would silently and permanently under-count every
// bucket that receives a late event -- the exact LogVault bug this file's
// header exists to prevent. Slicing keeps full coverage and only changes how
// OFTEN a given bucket is revisited: with a 24h lookback and a 6h slice, every
// hour is rebuilt every 4 wide passes, which for late arrivals is still far
// more often than necessary.
const WIDE_SLICE_HOURS = 6;

/**
 * Which slice of the lookback this wide pass should rebuild.
 *
 * Derived from the clock rather than stored state, so it needs no
 * coordination and survives a restart: consecutive passes walk backwards
 * through the lookback and wrap. Returns the slice INDEX, 0 being the most
 * recent slice.
 */
function wideSliceIndex(now, lookbackHours, sliceHours) {
  const slices = Math.max(1, Math.ceil(lookbackHours / sliceHours));
  const hourNumber = Math.floor(now.getTime() / 3600000);
  return ((hourNumber % slices) + slices) % slices;
}

/**
 * The [from, to) window for one wide pass.
 *
 * ⛔ Slices OVERLAP by one hour at each edge (the +1 in `sweepWindow`'s
 * spirit) so a bucket can never fall between two slices and be skipped by
 * both. Recomputing an hour twice is free -- the whole model is DELETE then
 * INSERT -- while missing one is a permanent under-count.
 */
function wideSliceWindow(now, lookbackHours, sliceHours) {
  const slices = Math.max(1, Math.ceil(lookbackHours / sliceHours));
  const idx = wideSliceIndex(now, lookbackHours, sliceHours);
  const top = addHours(floorHour(now), 1); // include the in-progress hour
  const to = addHours(top, -(idx * sliceHours));
  // ⛔ The overlap is the SLICE COUNT, not one hour, and that is not obvious:
  // `now` advances an hour per pass while the slice index steps back a whole
  // slice, so the window drifts forward one hour per pass and by the slice
  // count over a full rotation. With a one-hour overlap the OLDEST hours of
  // the lookback were covered by no slice at all — caught by the coverage test
  // in tests/rollups.test.js, which is the only reason this is right.
  const from = addHours(to, -(sliceHours + slices));
  return { from, to, sliceIndex: idx };
}

/**
 * One maintenance cycle.
 *
 * `recent` covers the newest hours every few minutes and is what keeps the
 * dashboards live. `wide` walks the rest of the lookback one slice per pass,
 * which is what catches events that arrived LATE.
 */
async function runRollupMaintenance(pool, opts) {
  const o = opts || {};
  const now = o.now instanceof Date ? o.now : new Date();
  const sliceHours = Number.isFinite(Number(o.sliceHours)) && Number(o.sliceHours) >= 1
    ? Math.trunc(Number(o.sliceHours))
    : WIDE_SLICE_HOURS;

  let from;
  let to;
  let sliceIndex = null;
  const hours = o.wide ? (o.lookbackHours || 24) : (o.recentHours || 3);
  if (o.wide) {
    ({ from, to, sliceIndex } = wideSliceWindow(now, hours, sliceHours));
  } else {
    ({ from, to } = sweepWindow(now, hours));
  }

  const r = await recomputeWindow(pool, from, to);
  r.tier = o.wide ? 'wide' : 'recent';
  r.hours = hours;
  r.sliceIndex = sliceIndex;
  r.sliceHours = o.wide ? sliceHours : null;
  return r;
}

/**
 * Manual recovery for a gap LONGER than the wide window: recompute an
 * arbitrary range, one day at a time so a multi-week backfill never becomes a
 * single enormous transaction.
 */
async function backfillRange(pool, from, to, onProgress) {
  const results = [];
  let cursor = floorHour(from);
  const end = floorHour(to);
  while (cursor < end) {
    const next = new Date(Math.min(addHours(cursor, 24).getTime(), end.getTime()));
    const r = await recomputeWindow(pool, cursor, next);
    results.push(r);
    if (typeof onProgress === 'function') onProgress(r);
    cursor = next;
  }
  return results;
}

/**
 * Trim the DETAIL rollups, which unlike the permanent ones are bounded by
 * time rather than kept forever.
 *
 * ⛔ These are DELETEd, not dropped by partition, and that is fine here: they
 * are small (tens of thousands of rows a day, not ~120M) and a day's worth is
 * a routine delete. The raw event table is the one that must never be DELETEd
 * from -- see dropOldPartitions() in eventStore.js.
 *
 * Never throws; the caller is a timer inside a long-running service.
 */
async function trimDetailRollups(pool, retentionDays) {
  const days = Number.isFinite(Number(retentionDays)) && Number(retentionDays) >= 1
    ? Math.trunc(Number(retentionDays))
    : 30;
  const out = { days, deleted: {}, error: null };
  if (!pool) { out.error = 'no pool supplied'; return out; }
  // ⛔ Every DETAIL rollup must be listed here. One left off is not an error,
  // it is a table that grows forever while the log line still says the trim
  // succeeded.
  for (const t of [
    'syslog_talker_hourly', 'syslog_app_hourly', 'syslog_blocked_dst_hourly',
    'syslog_country_hourly', 'syslog_user_hourly', 'syslog_urlcat_hourly',
    'syslog_device_inbound_hourly',
  ]) {
    try {
      // Table names are a fixed literal list, never user input.
      const r = await pool.query(
        `DELETE FROM ${t} WHERE bucket_hour < now() - ($1::int * interval '1 day')`,
        [days]
      );
      out.deleted[t] = r.rowCount || 0;
    } catch (err) {
      out.error = `${t}: ${err.message}`;
    }
  }
  return out;
}

module.exports = {
  floorHour,
  trimDetailRollups,
  TALKER_INSERT,
  APP_INSERT,
  BLOCKED_INSERT,
  INBOUND_INSERT,
  COUNTRY_INSERT,
  USER_INSERT,
  URLCAT_INSERT,
  addHours,
  sweepWindow,
  wideSliceIndex,
  wideSliceWindow,
  WIDE_SLICE_HOURS,
  recomputeWindow,
  runRollupMaintenance,
  backfillRange,
  WINDOW_TEMP,
  HOURLY_INSERT,
  RULE_INSERT,
};
