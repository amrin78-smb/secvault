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

// Both rollups are rebuilt from the same raw rows, so they share one window.
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
  SELECT date_trunc('hour', received_at), source_ip, device_id, vendor, action, severity, log_class,
         count(*),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable), now()
    FROM syslog_events
   WHERE received_at >= $1 AND received_at < $2
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
  SELECT date_trunc('hour', received_at), device_id, source_ip, vendor, rule_id, rule_uuid, rule_name, action,
         count(*),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable),
         min(received_at), max(received_at)
    FROM syslog_events
   WHERE received_at >= $1 AND received_at < $2
     AND (rule_id IS NOT NULL OR rule_uuid IS NOT NULL OR rule_name IS NOT NULL)
   GROUP BY 1, 2, 3, 4, 5, 6, 7, 8`;

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
 * Recompute both rollups for a window. Idempotent: DELETE then INSERT, so
 * running it twice produces the same result as running it once.
 *
 * ⛔ Wrapped in ONE transaction per rollup so a reader never sees a bucket
 * mid-rebuild — without it, a dashboard query landing between the DELETE and
 * the INSERT would show zero traffic for that hour and look like an outage.
 *
 * Never throws: the caller is a timer inside a long-running service, and one
 * failed sweep must not take the collector down. The failure is returned.
 *
 * @returns {{ok, from, to, hourlyRows, ruleRows, ms, error}}
 */
async function recomputeWindow(pool, from, to) {
  const started = Date.now();
  const result = { ok: false, from, to, hourlyRows: 0, ruleRows: 0, ms: 0, error: null };
  if (!pool) { result.error = 'no pool supplied'; return result; }

  let client;
  try {
    client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(HOURLY_DELETE, [from, to]);
      const h = await client.query(HOURLY_INSERT, [from, to]);
      result.hourlyRows = h.rowCount || 0;
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    }

    try {
      await client.query('BEGIN');
      await client.query(RULE_DELETE, [from, to]);
      const r = await client.query(RULE_INSERT, [from, to]);
      result.ruleRows = r.rowCount || 0;
      await client.query('COMMIT');
    } catch (err) {
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

/**
 * One maintenance cycle. `wide` selects the lookback tier.
 */
async function runRollupMaintenance(pool, opts) {
  const o = opts || {};
  const now = o.now instanceof Date ? o.now : new Date();
  const hours = o.wide ? (o.lookbackHours || 24) : (o.recentHours || 3);
  const { from, to } = sweepWindow(now, hours);
  const r = await recomputeWindow(pool, from, to);
  r.tier = o.wide ? 'wide' : 'recent';
  r.hours = hours;
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

module.exports = {
  floorHour,
  addHours,
  sweepWindow,
  recomputeWindow,
  runRollupMaintenance,
  backfillRange,
  HOURLY_INSERT,
  RULE_INSERT,
};
