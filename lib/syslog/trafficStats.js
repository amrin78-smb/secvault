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

// ── Detail-rollup readers (Phase 8b) ──────────────────────────────────────
// These read the three NARROW rollups (host / application / blocked
// destination), which unlike syslog_rollup_hourly have a bounded retention.
//
// ⛔ A window LONGER than SYSLOG_DETAIL_RETENTION_DAYS is not an error and
// must not be reported as one -- it simply has less data behind it than the
// caller asked for. Each reader returns the window it actually covered so a
// widget can say "30 days available" rather than silently implying the
// answer spans the full range requested.

/** Byte totals are NULL when nothing in the window was summable. Never 0. */
function bytesOrNull(v) {
  return v === null || v === undefined ? null : Number(v);
}

/**
 * Busiest source HOSTS -- Firewall Analyzer's "Top Hosts" widget.
 *
 * ⛔ NOT the same question as getTopTalkers() above, despite the similar
 * name: that one ranks the FIREWALLS sending us syslog (source_ip of the
 * datagram), this ranks the HOSTS inside the traffic those firewalls
 * described (src_ip parsed out of the payload). Conflating them would rank
 * 16 firewalls where the operator expects thousands of workstations.
 */
async function getTopHosts(pool, hours = 24, limit = 10) {
  const h = clampHours(hours, 24, 24 * 90);
  const lim = clampHours(limit, 10, 200);
  const { rows } = await pool.query(
    `SELECT t.src_ip::text AS src_ip,
            sum(t.event_count)::bigint  AS events,
            sum(t.denied_count)::bigint AS denied,
            sum(t.bytes_sent)::bigint     AS bytes_sent,
            sum(t.bytes_received)::bigint AS bytes_received,
            count(DISTINCT t.device_id)   AS device_count
       FROM syslog_talker_hourly t
      WHERE t.bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
      GROUP BY 1
      ORDER BY events DESC
      LIMIT $2`,
    [h, lim]
  );
  return rows.map((r) => ({
    srcIp: r.src_ip,
    events: Number(r.events),
    denied: r.denied === null ? null : Number(r.denied),
    bytesSent: bytesOrNull(r.bytes_sent),
    bytesReceived: bytesOrNull(r.bytes_received),
    // How many different firewalls saw this host. >1 means the host crosses
    // sites, which is why the byte totals are not double-counted per device.
    deviceCount: Number(r.device_count),
  }));
}

/**
 * Top applications -- Firewall Analyzer's protocol-group traffic view.
 *
 * ⛔ Rows where the vendor reported no application at all are EXCLUDED from
 * the ranking and returned separately as `unclassified`, rather than being
 * bucketed under a synthetic '(unknown)' label that would usually rank #1 and
 * make the widget useless. Fortinet and PAN-OS both report an application on
 * traffic logs; a device contributing only unclassified rows is a collection
 * gap worth seeing as such.
 */
async function getTopApplications(pool, hours = 24, limit = 10) {
  const h = clampHours(hours, 24, 24 * 90);
  const lim = clampHours(limit, 10, 200);
  const { rows } = await pool.query(
    `SELECT a.application,
            sum(a.event_count)::bigint    AS events,
            sum(a.bytes_sent)::bigint     AS bytes_sent,
            sum(a.bytes_received)::bigint AS bytes_received
       FROM syslog_app_hourly a
      WHERE a.bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
        AND a.application IS NOT NULL
      GROUP BY 1
      ORDER BY events DESC
      LIMIT $2`,
    [h, lim]
  );
  const { rows: unk } = await pool.query(
    `SELECT sum(a.event_count)::bigint AS events
       FROM syslog_app_hourly a
      WHERE a.bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
        AND a.application IS NULL`,
    [h]
  );
  return {
    applications: rows.map((r) => ({
      application: r.application,
      events: Number(r.events),
      bytesSent: bytesOrNull(r.bytes_sent),
      bytesReceived: bytesOrNull(r.bytes_received),
    })),
    unclassified: unk[0] && unk[0].events !== null ? Number(unk[0].events) : 0,
  };
}

/** Transport-protocol split (tcp/udp/icmp/...), from the same rollup. */
async function getProtocolBreakdown(pool, hours = 24) {
  const h = clampHours(hours, 24, 24 * 90);
  const { rows } = await pool.query(
    `SELECT a.protocol,
            sum(a.event_count)::bigint    AS events,
            sum(a.bytes_sent)::bigint     AS bytes_sent,
            sum(a.bytes_received)::bigint AS bytes_received
       FROM syslog_app_hourly a
      WHERE a.bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
        AND a.protocol IS NOT NULL
      GROUP BY 1
      ORDER BY events DESC`,
    [h]
  );
  return rows.map((r) => ({
    protocol: r.protocol,
    events: Number(r.events),
    bytesSent: bytesOrNull(r.bytes_sent),
    bytesReceived: bytesOrNull(r.bytes_received),
  }));
}

/**
 * Most-blocked destinations, with the port that was blocked.
 *
 * ⛔ Only BLOCKED destinations exist in this rollup by design (see the table
 * comment in schema.sql). This can never answer "top destinations overall",
 * and the widget must not be labelled as if it does.
 */
async function getTopBlockedDestinations(pool, hours = 24, limit = 10) {
  const h = clampHours(hours, 24, 24 * 90);
  const lim = clampHours(limit, 10, 200);
  const { rows } = await pool.query(
    `SELECT b.dst_ip::text AS dst_ip,
            b.dst_port,
            b.protocol,
            sum(b.event_count)::bigint AS events
       FROM syslog_blocked_dst_hourly b
      WHERE b.bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
      GROUP BY 1, 2, 3
      ORDER BY events DESC
      LIMIT $2`,
    [h, lim]
  );
  return rows.map((r) => ({
    dstIp: r.dst_ip,
    dstPort: r.dst_port === null ? null : Number(r.dst_port),
    protocol: r.protocol || null,
    events: Number(r.events),
  }));
}

/**
 * Per-device traffic + security statistics -- Firewall Analyzer's per-device
 * summary table, assembled from the hourly rollup in ONE pass.
 *
 * Every device that is ACTIVE appears, including ones that have sent nothing:
 * a firewall silently not logging is the single most useful row in this table
 * and omitting it would hide exactly the problem the table exists to reveal.
 * Those rows carry events:0 with lastSeen:null -- distinguishable from a
 * device that logged and genuinely saw no traffic.
 */
async function getDeviceTrafficStats(pool, hours = 24) {
  const h = clampHours(hours, 24, 24 * 90);
  const { rows } = await pool.query(
    `WITH agg AS (
       SELECT r.device_id,
              sum(r.event_count)::bigint AS events,
              sum(r.event_count) FILTER (WHERE r.action = 'allow')::bigint AS allowed,
              sum(r.event_count) FILTER (WHERE r.action IN ('deny','drop','reset-both','block'))::bigint AS denied,
              sum(r.event_count) FILTER (WHERE r.log_class = 'threat')::bigint AS threats,
              sum(r.event_count) FILTER (WHERE r.log_class = 'vpn')::bigint AS vpn_events,
              sum(r.bytes_sent)::bigint     AS bytes_sent,
              sum(r.bytes_received)::bigint AS bytes_received,
              max(r.updated_at) AS last_rollup
         FROM syslog_rollup_hourly r
        WHERE r.bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
          AND r.device_id IS NOT NULL
        GROUP BY 1
     )
     SELECT d.id AS device_id, d.name, d.vendor, d.mgmt_ip,
            coalesce(agg.events, 0)  AS events,
            agg.allowed, agg.denied, agg.threats, agg.vpn_events,
            agg.bytes_sent, agg.bytes_received, agg.last_rollup
       FROM devices d
       LEFT JOIN agg ON agg.device_id = d.id
      WHERE d.active = true
      ORDER BY coalesce(agg.events, 0) DESC, d.name ASC`,
    [h]
  );
  return rows.map((r) => ({
    deviceId: r.device_id,
    name: r.name,
    vendor: r.vendor,
    mgmtIp: r.mgmt_ip || null,
    events: Number(r.events),
    // ⛔ NULL, not 0, when the device sent nothing at all: "logging nothing"
    // and "logged, denied nothing" are different facts and the table renders
    // them differently.
    allowed: r.allowed === null ? null : Number(r.allowed),
    denied: r.denied === null ? null : Number(r.denied),
    threats: r.threats === null ? null : Number(r.threats),
    vpnEvents: r.vpn_events === null ? null : Number(r.vpn_events),
    bytesSent: bytesOrNull(r.bytes_sent),
    bytesReceived: bytesOrNull(r.bytes_received),
    lastSeen: r.last_rollup || null,
  }));
}

// ── Country / user / URL-category readers (Phase 8b) ──────────────────────

// ⛔ Both vendors report PRIVATE address space with a word rather than a
// country, and each uses its own: FortiOS says "Reserved", PAN-OS writes the
// literal range ("192.168.0.0-192.168.255.255", "172.16.0.0-172.31.255.255").
// Those are REAL answers meaning "this stayed internal", not missing ones, so
// they are stored verbatim and only grouped for DISPLAY here. Leaving them
// ungrouped puts three different spellings of "internal" in a Top Countries
// chart; rewriting them at ingest would destroy what the device actually said.
const INTERNAL_COUNTRY = /^(reserved|private|unknown)$|^\d{1,3}(\.\d{1,3}){3}\s*-\s*\d{1,3}(\.\d{1,3}){3}$/i;

function isInternalCountry(v) {
  return typeof v === 'string' && INTERNAL_COUNTRY.test(v.trim());
}

/**
 * Destination countries — Firewall Analyzer's geographic reporting.
 *
 * ⛔ Needs NO GeoIP database: both Palo Alto and FortiOS put the country in
 * every traffic log and SecVault simply was not reading it until 2026-09-08.
 *
 * Returns external destinations ranked, plus `internal` and `unreported` as
 * separate totals. ⛔ They are NOT dropped: excluded silently, the
 * percentages would add up to 100% of a smaller number while presenting as
 * 100% of the traffic.
 */
async function getTopCountries(pool, hours = 24, limit = 10) {
  const h = clampHours(hours, 24, 24 * 30);
  const lim = clampHours(limit, 10, 200);
  const { rows } = await pool.query(
    `SELECT c.dst_country,
            sum(c.event_count)::bigint  AS events,
            sum(c.denied_count)::bigint AS denied,
            sum(c.bytes_sent)::bigint     AS bytes_sent,
            sum(c.bytes_received)::bigint AS bytes_received
       FROM syslog_country_hourly c
      WHERE c.bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
      GROUP BY 1`,
    [h]
  );

  const external = [];
  let internal = 0;
  let unreported = 0;
  for (const r of rows) {
    const events = Number(r.events);
    if (r.dst_country === null) { unreported += events; continue; }
    if (isInternalCountry(r.dst_country)) { internal += events; continue; }
    external.push({
      country: r.dst_country,
      events,
      denied: r.denied === null ? null : Number(r.denied),
      bytesSent: bytesOrNull(r.bytes_sent),
      bytesReceived: bytesOrNull(r.bytes_received),
    });
  }
  external.sort((a, b) => b.events - a.events);
  return { countries: external.slice(0, lim), internal, unreported };
}

/**
 * Busiest users.
 *
 * ⛔ Identity is resolved on only a FRACTION of events on this fleet (it
 * needs PAN-OS User-ID or an authenticated FortiOS session), so this returns
 * its own coverage alongside the ranking. A top-users chart that does not say
 * what share of traffic it can attribute invites the conclusion that the
 * listed users are the only ones active.
 */
async function getTopUsers(pool, hours = 24, limit = 10) {
  const h = clampHours(hours, 24, 24 * 30);
  const lim = clampHours(limit, 10, 200);
  const [users, total] = await Promise.all([
    pool.query(
      `SELECT u.src_user,
              sum(u.event_count)::bigint  AS events,
              sum(u.denied_count)::bigint AS denied,
              sum(u.bytes_sent)::bigint     AS bytes_sent,
              sum(u.bytes_received)::bigint AS bytes_received
         FROM syslog_user_hourly u
        WHERE u.bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
        GROUP BY 1
        ORDER BY events DESC
        LIMIT $2`,
      [h, lim]
    ),
    pool.query(
      `SELECT coalesce(sum(event_count), 0)::bigint AS attributed
         FROM syslog_user_hourly
        WHERE bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'`,
      [h]
    ),
  ]);
  const { rows: allRows } = await pool.query(
    `SELECT coalesce(sum(event_count), 0)::bigint AS total
       FROM syslog_rollup_hourly
      WHERE bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'`,
    [h]
  );
  const attributed = Number(total.rows[0]?.attributed || 0);
  const allEvents = Number(allRows[0]?.total || 0);
  return {
    users: users.rows.map((r) => ({
      user: r.src_user,
      events: Number(r.events),
      denied: r.denied === null ? null : Number(r.denied),
      bytesSent: bytesOrNull(r.bytes_sent),
      bytesReceived: bytesOrNull(r.bytes_received),
    })),
    attributed,
    totalEvents: allEvents,
    // null, not 0, when there is nothing to divide by — "no traffic at all"
    // and "traffic with no identity on any of it" are different facts.
    coveragePct: allEvents > 0 ? Math.round((attributed / allEvents) * 1000) / 10 : null,
  };
}

/** URL / application categories, with how much of each was blocked. */
async function getTopUrlCategories(pool, hours = 24, limit = 12) {
  const h = clampHours(hours, 24, 24 * 30);
  const lim = clampHours(limit, 12, 200);
  const { rows } = await pool.query(
    `SELECT u.url_category,
            sum(u.event_count)::bigint  AS events,
            sum(u.denied_count)::bigint AS denied
       FROM syslog_urlcat_hourly u
      WHERE u.bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'
      GROUP BY 1
      ORDER BY events DESC
      LIMIT $2`,
    [h, lim]
  );
  return rows.map((r) => ({
    category: r.url_category,
    events: Number(r.events),
    denied: r.denied === null ? null : Number(r.denied),
  }));
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
  getTopHosts,
  getTopApplications,
  getProtocolBreakdown,
  getTopBlockedDestinations,
  getDeviceTrafficStats,
  getTopCountries,
  getTopUsers,
  getTopUrlCategories,
  isInternalCountry,
};
