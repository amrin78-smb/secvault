// lib/syslog/trafficStats.js
//
// Read-side queries for the syslog dashboards.
//
// ⛔ EVERY QUERY HERE READS A ROLLUP, NOT syslog_events — that is the entire
// reason the rollups exist. A widget that scans the raw table would be reading
// tens of millions of rows on every 60-second dashboard refresh; LogVault
// measured exactly that shape of query reading 560 MB per cache-miss before it
// pre-aggregated. The two deliberate exceptions are documented at their call
// site: VPN per-event DETAIL, which is bounded by log_class + a recent window
// and carries per-event fields an aggregate would destroy. Ingest health reads
// syslog_ingest_stats, which is already one small row per flush.
//
// ⛔ "No data" is NULL, never 0. A fleet that has not been collected from yet
// must render as "—", not as a confident zero — a dashboard that shows 0
// events/sec when the collector is down looks identical to a quiet network.
//
// pool is always a parameter (CLAUDE.md). Parameterized queries only.

'use strict';

function clampHours(h, def, max) {
  const n = Number(h);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(Math.trunc(n), 1), max);
}

/**
 * Events per hour for the fleet, optionally split by action class.
 * Reads syslog_rollup_hourly.
 */
async function getTrafficTimeline(pool, hours = 24) {
  const h = clampHours(hours, 24, 24 * 30);
  const { rows } = await pool.query(
    `SELECT bucket_hour,
            sum(event_count)::bigint AS events,
            sum(event_count) FILTER (WHERE action IN ('deny','drop','reset-both','block'))::bigint AS denied,
            sum(bytes_sent)::bigint  AS bytes_sent,
            sum(bytes_received)::bigint AS bytes_received
       FROM syslog_rollup_hourly
      WHERE bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
      GROUP BY bucket_hour
      ORDER BY bucket_hour ASC`,
    [h]
  );
  return rows.map((r) => ({
    hour: r.bucket_hour,
    events: Number(r.events),
    // ⛔ FILTER over no matching rows yields NULL, and that is kept: "no denies
    // recorded in this hour" and "this vendor never reports an action" are
    // different, and only the first is a zero.
    denied: r.denied === null ? null : Number(r.denied),
    bytesSent: r.bytes_sent === null ? null : Number(r.bytes_sent),
    bytesReceived: r.bytes_received === null ? null : Number(r.bytes_received),
  }));
}

/** Busiest senders. Resolves device names where the sender is a managed device. */
async function getTopTalkers(pool, hours = 24, limit = 10) {
  const h = clampHours(hours, 24, 24 * 30);
  const lim = clampHours(limit, 10, 100);
  const { rows } = await pool.query(
    `SELECT r.source_ip::text AS source_ip,
            r.device_id,
            d.name AS device_name,
            d.vendor AS device_vendor,
            sum(r.event_count)::bigint AS events,
            sum(r.event_count) FILTER (WHERE r.action IN ('deny','drop','reset-both','block'))::bigint AS denied
       FROM syslog_rollup_hourly r
       LEFT JOIN devices d ON d.id = r.device_id
      WHERE r.bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
      GROUP BY 1, 2, 3, 4
      ORDER BY events DESC
      LIMIT $2`,
    [h, lim]
  );
  return rows.map((r) => ({
    sourceIp: r.source_ip,
    deviceId: r.device_id,
    // ⛔ null name = a sender that is NOT a managed device. Surfaced as such by
    // the widget rather than hidden, because "a firewall is logging to us that
    // we do not manage" is a finding, not noise.
    deviceName: r.device_name || null,
    vendor: r.device_vendor || null,
    events: Number(r.events),
    denied: r.denied === null ? null : Number(r.denied),
  }));
}

/** Allow/deny/other split across the window. */
async function getActionBreakdown(pool, hours = 24) {
  const h = clampHours(hours, 24, 24 * 30);
  const { rows } = await pool.query(
    `SELECT coalesce(action, '(unreported)') AS action,
            sum(event_count)::bigint AS events
       FROM syslog_rollup_hourly
      WHERE bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
      GROUP BY 1
      ORDER BY events DESC`,
    [h]
  );
  return rows.map((r) => ({ action: r.action, events: Number(r.events) }));
}

/**
 * Busiest firewall rules, from syslog_rule_hits_hourly.
 * This is the read side of the evidence that will later give real hit counts
 * to vendors whose APIs cannot report them.
 *
 * ⛔ The rollup buckets HOURLY and this aggregates to the requested span at
 * read time. It was daily, which broke: the recompute window is a timestamp
 * range, so a DELETE over whole days either missed the final partial day (a
 * duplicate-key collision on every rerun, which is how it was caught) or wiped
 * a whole day the INSERT only partly rebuilt (a silent under-count). Hourly
 * buckets share the traffic rollup's already-correct window semantics.
 */
async function getTopRules(pool, days = 1, limit = 10) {
  const d = clampHours(days, 1, 400);
  const lim = clampHours(limit, 10, 100);
  const { rows } = await pool.query(
    `SELECT coalesce(h.rule_name, h.rule_id) AS rule,
            h.vendor,
            h.action,
            d.name AS device_name,
            sum(h.hit_count)::bigint AS hits
       FROM syslog_rule_hits_hourly h
       LEFT JOIN devices d ON d.id = h.device_id
      WHERE h.bucket_hour >= date_trunc('day', now()) - ($1::int - 1) * interval '1 day'
      GROUP BY 1, 2, 3, 4
      ORDER BY hits DESC
      LIMIT $2`,
    [d, lim]
  );
  return rows.map((r) => ({
    rule: r.rule,
    vendor: r.vendor,
    action: r.action,
    deviceName: r.device_name || null,
    hits: Number(r.hits),
  }));
}

/**
 * Collector health. Reads syslog_ingest_stats, which is deliberately NOT a
 * rollup — it is already one small row per flush.
 *
 * ⛔ Returns null (not 0) for every figure when no flush has EVER been
 * recorded. "The collector has never run" and "the collector is running and
 * seeing no traffic" are different answers and must not render identically.
 */
async function getIngestHealth(pool, minutes = 15) {
  const m = clampHours(minutes, 15, 1440);
  const { rows } = await pool.query(
    `SELECT sum(received)::bigint  AS received,
            sum(stored)::bigint    AS stored,
            sum(dropped)::bigint   AS dropped,
            sum(unknown_source)::bigint AS unknown_source,
            max(spool_backlog)::int AS max_backlog,
            round(avg(batch_ms))::int AS avg_ms,
            max(batch_ms)::int      AS max_ms,
            count(*)::int           AS flushes,
            min(recorded_at)        AS since,
            max(recorded_at)        AS last_flush
       FROM syslog_ingest_stats
      WHERE recorded_at >= now() - ($1::int * interval '1 minute')`,
    [m]
  );
  const r = rows[0] || {};
  if (!r.flushes || r.flushes === 0) {
    return {
      received: null, stored: null, dropped: null, unknownSource: null,
      eventsPerSec: null, maxBacklog: null, avgMs: null, maxMs: null,
      flushes: 0, lastFlush: null, windowMinutes: m,
    };
  }
  const spanSec = r.since && r.last_flush
    ? Math.max(1, (new Date(r.last_flush) - new Date(r.since)) / 1000)
    : null;
  return {
    received: Number(r.received),
    stored: Number(r.stored),
    dropped: Number(r.dropped),
    unknownSource: Number(r.unknown_source),
    eventsPerSec: spanSec ? Math.round(Number(r.received) / spanSec) : null,
    maxBacklog: r.max_backlog,
    avgMs: r.avg_ms,
    maxMs: r.max_ms,
    flushes: r.flushes,
    lastFlush: r.last_flush,
    windowMinutes: m,
  };
}

/**
 * VPN activity observed in syslog.
 *
 * ⛔ DELIBERATELY reads syslog_events rather than a rollup. VPN events are a
 * tiny fraction of traffic (~3.5k of 3.7M observed) and carry per-event detail
 * — user, source address, action — that an aggregate would destroy, which is
 * the entire value here. The window is bounded and the predicate is selective,
 * so this is a small scan, not a fleet-wide one.
 *
 * Verified against real captured logs on this fleet:
 *   Palo Alto  CSV log type GLOBALPROTECT
 *   FortiOS    type="event" subtype="vpn"
 */
async function getVpnActivity(pool, hours = 24, limit = 50) {
  const h = clampHours(hours, 24, 24 * 7);
  const lim = clampHours(limit, 50, 500);
  const { rows } = await pool.query(
    `SELECT e.received_at, e.source_ip::text AS source_ip, e.vendor,
            d.name AS device_name, e.severity, e.message
       FROM syslog_events e
       LEFT JOIN devices d ON d.id = e.device_id
      WHERE e.received_at >= now() - ($1::int * interval '1 hour')
        AND e.log_class = 'vpn'
      ORDER BY e.received_at DESC
      LIMIT $2`,
    [h, lim]
  );
  return rows.map((r) => ({
    receivedAt: r.received_at,
    sourceIp: r.source_ip,
    vendor: r.vendor,
    deviceName: r.device_name || null,
    severity: r.severity,
    message: r.message,
  }));
}

/** Per-device VPN event counts for the fleet VPN page. */
async function getVpnActivityByDevice(pool, hours = 24) {
  const h = clampHours(hours, 24, 24 * 7);
  const { rows } = await pool.query(
    `SELECT e.device_id, d.name AS device_name, e.vendor,
            count(*)::bigint AS events,
            max(e.received_at) AS last_seen
       FROM syslog_events e
       LEFT JOIN devices d ON d.id = e.device_id
      WHERE e.received_at >= now() - ($1::int * interval '1 hour')
        AND e.log_class = 'vpn'
      GROUP BY 1, 2, 3
      ORDER BY events DESC`,
    [h]
  );
  return rows.map((r) => ({
    deviceId: r.device_id,
    deviceName: r.device_name || null,
    vendor: r.vendor,
    events: Number(r.events),
    lastSeen: r.last_seen,
  }));
}

/**
 * Threat / UTM signal counts.
 *
 * Reads the ROLLUP by log_class. The earlier version matched
 * `message LIKE '%subtype="virus"%'` against the raw table for a per-subtype
 * breakdown; measured at 2.5s over 4M rows, which extrapolates to ~400s at the
 * 7-day steady state of ~650M. The finer virus/webfilter/app-control split was
 * dropped rather than kept at that cost — it would need its own rollup
 * dimension, and threat-vs-UTM is what the widget actually shows.
 */
async function getThreatActivity(pool, hours = 24) {
  const h = clampHours(hours, 24, 24 * 30);
  const { rows } = await pool.query(
    `SELECT log_class AS kind,
            sum(event_count)::bigint AS events
       FROM syslog_rollup_hourly
      WHERE bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
        AND log_class IN ('threat', 'utm')
      GROUP BY 1
      ORDER BY events DESC`,
    [h]
  );
  return rows.map((r) => ({ kind: r.kind, events: Number(r.events) }));
}

/** Per-hour counts for one log class — powers the VPN and threat trend lines. */
async function getClassTimeline(pool, logClass, hours = 24) {
  const h = clampHours(hours, 24, 24 * 30);
  const { rows } = await pool.query(
    `SELECT bucket_hour, sum(event_count)::bigint AS events
       FROM syslog_rollup_hourly
      WHERE bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
        AND log_class = $2
      GROUP BY bucket_hour
      ORDER BY bucket_hour ASC`,
    [h, logClass]
  );
  return rows.map((r) => ({ hour: r.bucket_hour, events: Number(r.events) }));
}

module.exports = {
  getTrafficTimeline,
  getTopTalkers,
  getActionBreakdown,
  getTopRules,
  getIngestHealth,
  getVpnActivity,
  getVpnActivityByDevice,
  getThreatActivity,
  getClassTimeline,
};
