'use strict';
//
// lib/reports/trafficWindow.js — traffic aggregates over an ARBITRARY window.
//
// ⛔ WHY THIS IS NOT lib/syslog/trafficStats.js. Every query there is anchored to
// NOW ("the last N hours"), which is right for a dashboard widget and cannot
// answer "1–15 September" at all. A report offering a date range that silently
// slid to "the last 14 days" would be the exact class of quiet wrongness this
// codebase spends its comments on.
//
// ⛔ WHAT IS SHARED, AND WHY THAT IS THE PART THAT MATTERS. The allowed/denied
// vocabulary comes from lib/syslog/actions.js UNCHANGED. That is the only
// judgement in here — everything else is a GROUP BY — and it is the one thing
// that would drift: the 2026-09-09 `timeout` reclassification moved ~213,000
// sessions a day, 5.2% of the fleet's denied total. A second copy of that list
// would put the PDF and the dashboard permanently 5% apart.
//
// ⛔ THE WINDOW IS CLAMPED AND THE CLAMP IS DECLARED. The detail rollups are
// trimmed to SYSLOG_DETAIL_RETENTION_DAYS (30 by default), so a range reaching
// further back has no data to find — not "no traffic", NO DATA. Every function
// here reports the window it actually covered, and the report prints it.

const { ALLOWED_SQL, DENIED_SQL } = require('../syslog/actions');

const HOUR_MS = 3600000;

// Same default as the collector's SYSLOG_DETAIL_RETENTION_DAYS. Read at call
// time rather than captured, so a deployment that raised it is honoured.
function detailRetentionDays() {
  const n = Number(process.env.SYSLOG_DETAIL_RETENTION_DAYS);
  return Number.isFinite(n) && n > 0 ? Math.min(Math.trunc(n), 3650) : 30;
}

/**
 * Resolve a requested range into one the rollups can actually answer.
 *
 * ⛔ CLAMPED, NEVER SILENTLY. Returns what was asked for AND what will be
 * covered, so the document can say "you asked for 90 days; 30 are retained".
 *
 * @returns {{from: Date, to: Date, requestedFrom: Date, requestedTo: Date,
 *            clamped: boolean, reasons: string[], hours: number}}
 */
function resolveWindow(fromInput, toInput, now = new Date(), retentionDays = detailRetentionDays()) {
  const nowMs = now.getTime();
  const parse = (v, fallback) => {
    if (v === null || v === undefined || v === '') return fallback;
    const d = v instanceof Date ? v : new Date(v);
    return Number.isNaN(d.getTime()) ? fallback : d;
  };

  let to = parse(toInput, new Date(nowMs));
  let from = parse(fromInput, new Date(nowMs - 24 * HOUR_MS));
  const requestedFrom = new Date(from.getTime());
  const requestedTo = new Date(to.getTime());
  const reasons = [];

  // An inverted range is a mistake, not an empty result: swapping is the one
  // repair that cannot be wrong about intent.
  if (from > to) {
    const t = from; from = to; to = t;
    reasons.push('The start was after the end, so the two were swapped.');
  }
  // ⛔ THE FUTURE IS NOT A MEASUREMENT. A range ending tomorrow would render as
  // a flat line that reads like an outage.
  if (to.getTime() > nowMs) {
    to = new Date(nowMs);
    reasons.push('The end was in the future and has been trimmed to now.');
  }
  const floor = nowMs - retentionDays * 24 * HOUR_MS;
  if (from.getTime() < floor) {
    from = new Date(floor);
    reasons.push(
      `Detail rollups are retained for ${retentionDays} days, so the start was moved forward. `
      + 'Anything before that was deleted by retention — it is missing data, not quiet traffic.'
    );
  }
  if (from.getTime() >= to.getTime()) {
    // Degenerate after clamping: give an hour rather than an empty window, and
    // say so, so the reader is not shown a blank report with no explanation.
    from = new Date(to.getTime() - HOUR_MS);
    reasons.push('The range collapsed after clamping; the last hour is shown instead.');
  }

  return {
    from, to, requestedFrom, requestedTo,
    clamped: reasons.length > 0,
    reasons,
    hours: Math.max(1, Math.round((to.getTime() - from.getTime()) / HOUR_MS)),
  };
}

// Every query below shares this: a half-open [from, to) window on bucket_hour,
// plus an optional device scope. ⛔ Half-open so two adjacent ranges cannot
// double-count the boundary hour.
function windowSql(col, deviceCol, deviceId) {
  const dev = deviceId ? ` AND ${deviceCol} = $3::uuid` : '';
  return `${col} >= $1::timestamptz AND ${col} < $2::timestamptz${dev}`;
}
const windowParams = (w, deviceId) => (deviceId ? [w.from, w.to, deviceId] : [w.from, w.to]);

async function timeline(pool, w, deviceId) {
  const { rows } = await pool.query(
    `SELECT bucket_hour,
            sum(event_count)::bigint AS events,
            sum(event_count) FILTER (WHERE lower(action) IN ${DENIED_SQL})::bigint AS denied,
            sum(bytes_sent)::bigint AS bytes_sent,
            sum(bytes_received)::bigint AS bytes_received
       FROM syslog_rollup_hourly
      WHERE ${windowSql('bucket_hour', 'device_id', deviceId)}
      GROUP BY bucket_hour
      ORDER BY bucket_hour ASC`,
    windowParams(w, deviceId)
  );
  return rows.map((r) => ({
    hour: r.bucket_hour,
    events: Number(r.events),
    // ⛔ NULL stays NULL. "No denies recorded in this hour" and "this vendor
    // never reports an action" are different facts and only the first is a zero.
    denied: r.denied === null ? null : Number(r.denied),
    bytesSent: r.bytes_sent === null ? null : Number(r.bytes_sent),
    bytesReceived: r.bytes_received === null ? null : Number(r.bytes_received),
  }));
}

async function actions(pool, w, deviceId) {
  const { rows } = await pool.query(
    `SELECT coalesce(action, '(unreported)') AS action,
            sum(event_count)::bigint AS events
       FROM syslog_rollup_hourly
      WHERE ${windowSql('bucket_hour', 'device_id', deviceId)}
      GROUP BY 1 ORDER BY 2 DESC`,
    windowParams(w, deviceId)
  );
  return rows.map((r) => ({ action: r.action, events: Number(r.events) }));
}

async function topHosts(pool, w, deviceId, limit = 15) {
  const { rows } = await pool.query(
    `SELECT t.src_ip::text AS src_ip,
            sum(t.event_count)::bigint AS events,
            sum(t.denied_count)::bigint AS denied
       FROM syslog_talker_hourly t
      WHERE ${windowSql('t.bucket_hour', 't.device_id', deviceId)}
      GROUP BY 1 ORDER BY 2 DESC LIMIT ${Number(limit) || 15}`,
    windowParams(w, deviceId)
  );
  return rows.map((r) => ({
    srcIp: r.src_ip,
    events: Number(r.events),
    denied: r.denied === null ? null : Number(r.denied),
  }));
}

async function topApplications(pool, w, deviceId, limit = 15) {
  const { rows } = await pool.query(
    `SELECT a.application, sum(a.event_count)::bigint AS events
       FROM syslog_app_hourly a
      WHERE ${windowSql('a.bucket_hour', 'a.device_id', deviceId)}
        AND a.application IS NOT NULL
      GROUP BY 1 ORDER BY 2 DESC LIMIT ${Number(limit) || 15}`,
    windowParams(w, deviceId)
  );
  return rows.map((r) => ({ application: r.application, events: Number(r.events) }));
}

async function protocols(pool, w, deviceId) {
  const { rows } = await pool.query(
    `SELECT a.protocol, sum(a.event_count)::bigint AS events
       FROM syslog_app_hourly a
      WHERE ${windowSql('a.bucket_hour', 'a.device_id', deviceId)}
        AND a.protocol IS NOT NULL
      GROUP BY 1 ORDER BY 2 DESC LIMIT 12`,
    windowParams(w, deviceId)
  );
  return rows.map((r) => ({ protocol: r.protocol, events: Number(r.events) }));
}

async function topBlocked(pool, w, deviceId, limit = 15) {
  const { rows } = await pool.query(
    `SELECT b.dst_ip::text AS dst_ip, b.dst_port, b.protocol,
            sum(b.event_count)::bigint AS events
       FROM syslog_blocked_dst_hourly b
      WHERE ${windowSql('b.bucket_hour', 'b.device_id', deviceId)}
      GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT ${Number(limit) || 15}`,
    windowParams(w, deviceId)
  );
  return rows.map((r) => ({
    dstIp: r.dst_ip,
    dstPort: r.dst_port === null ? null : Number(r.dst_port),
    protocol: r.protocol,
    events: Number(r.events),
  }));
}

async function topRules(pool, w, deviceId, limit = 15) {
  const { rows } = await pool.query(
    `SELECT h.rule_name, h.rule_id, h.action, d.name AS device_name,
            sum(h.hit_count)::bigint AS hits
       FROM syslog_rule_hits_hourly h
       LEFT JOIN devices d ON d.id = h.device_id
      WHERE ${windowSql('h.bucket_hour', 'h.device_id', deviceId)}
      GROUP BY 1, 2, 3, 4 ORDER BY 5 DESC LIMIT ${Number(limit) || 15}`,
    windowParams(w, deviceId)
  );
  return rows.map((r) => ({
    rule: r.rule_name || r.rule_id,
    ruleName: r.rule_name || null,
    ruleId: r.rule_id || null,
    action: r.action,
    deviceName: r.device_name || null,
    hits: Number(r.hits),
  }));
}

/**
 * Which firewalls actually logged in this window.
 *
 * ⛔ THE COVERAGE STATEMENT, AND THE REASON THIS REPORT BEATS A LOG ANALYSER'S.
 * A device that sent nothing is NOT a quiet device — it may not be logging to
 * us at all. Printing a traffic total without saying how much of the fleet it
 * covers is how a report about 4 of 16 firewalls reads like a report about the
 * estate.
 */
async function coverage(pool, w) {
  const { rows } = await pool.query(
    `SELECT d.id, d.name, d.vendor,
            coalesce(r.events, 0)::bigint AS events,
            r.bytes_measured
       FROM devices d
       LEFT JOIN (
         SELECT device_id,
                sum(event_count)::bigint AS events,
                bool_or(bytes_sent IS NOT NULL OR bytes_received IS NOT NULL) AS bytes_measured
           FROM syslog_rollup_hourly
          WHERE bucket_hour >= $1::timestamptz AND bucket_hour < $2::timestamptz
          GROUP BY device_id
       ) r ON r.device_id = d.id
      WHERE d.active = true
      ORDER BY 4 DESC, d.name ASC`,
    [w.from, w.to]
  );
  return rows.map((x) => ({
    deviceId: x.id,
    name: x.name,
    vendor: x.vendor,
    events: Number(x.events),
    // ⛔ TRI-STATE. NULL means this device logged nothing at all, so whether it
    // can report bytes is UNKNOWN — not false. FortiOS re-logs a session with a
    // running cumulative counter, so its bytes are deliberately unsummable and
    // that is a different fact from "no bytes were seen".
    bytesMeasured: x.bytes_measured === null ? null : x.bytes_measured === true,
  }));
}

module.exports = {
  resolveWindow,
  detailRetentionDays,
  timeline,
  actions,
  topHosts,
  topApplications,
  protocols,
  topBlocked,
  topRules,
  coverage,
  HOUR_MS,
};
