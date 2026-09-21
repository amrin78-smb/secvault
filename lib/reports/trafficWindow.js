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
// ⛔ Vendor vocabulary lives in ONE place, beside actions.js. The dashboard
// widget and this report must agree on what `ssl` and `license-expired` mean,
// or the PDF and the screen will disagree about the same window.
const {
  UNCLASSIFIED_URL_CATEGORIES, isUnclassifiedCategory, isUnattributedApplication,
} = require('../syslog/applications');

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
    // ⛔ AND RE-APPLY THE RETENTION FLOOR. This used to derive `from` from the
    // clamped `to` and stop, which could put it back BEFORE the floor — asking
    // for 1-2 January produced a window in January, every firewall reporting
    // "sent nothing", and a coverage sentence saying that "may mean no traffic,
    // or may mean they are not logging". It meant neither: retention had
    // deleted it, which the function knew one branch earlier and threw away.
    from = new Date(to.getTime() - HOUR_MS);
    if (from.getTime() < floor) {
      to = new Date(Math.min(nowMs, floor + HOUR_MS));
      from = new Date(to.getTime() - HOUR_MS);
      reasons.push(
        'The whole range predates what is retained, so the oldest retained hour is shown instead. '
        + 'Nothing exists before that — it was deleted by retention, not quiet.'
      );
    } else {
      reasons.push('The range collapsed after clamping; the last hour is shown instead.');
    }
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

async function windowTimeline(pool, w, deviceId) {
  const { rows } = await pool.query(
    `SELECT bucket_hour,
            sum(event_count)::bigint AS events,
            sum(event_count) FILTER (WHERE lower(action) IN ${DENIED_SQL})::bigint AS denied,
            count(*) FILTER (WHERE action IS NOT NULL)::bigint AS action_rows,
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
    // ⛔ THE SQL COULD NOT MAKE THE DISTINCTION THE OLD COMMENT CLAIMED.
    // `sum(...) FILTER (...)` returns NULL when NO ROW MATCHES THE FILTER, not
    // when the vendor reported no action — so an hour of real traffic with
    // genuinely zero denies was indistinguishable from an unmeasurable one, and
    // the report printed "No vendor in this window reported an action, so this
    // is NOT zero" over firewalls that plainly did report actions and simply
    // denied nothing. `action_rows` is what separates them: rows carrying an
    // action at all. None of those => genuinely unmeasured (null); some, with
    // no denies among them => a real, measured 0.
    denied: Number(r.action_rows) === 0 ? null : Number(r.denied || 0),
    bytesSent: r.bytes_sent === null ? null : Number(r.bytes_sent),
    bytesReceived: r.bytes_received === null ? null : Number(r.bytes_received),
  }));
}

async function windowActions(pool, w, deviceId) {
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

async function windowTopHosts(pool, w, deviceId, limit = 15) {
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

async function windowTopApplications(pool, w, deviceId, limit = 15) {
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

async function windowProtocols(pool, w, deviceId) {
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

async function windowTopBlocked(pool, w, deviceId, limit = 15) {
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

async function windowTopRules(pool, w, deviceId, limit = 15) {
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
async function windowCoverage(pool, w) {
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

// ── Web / application activity ──────────────────────────────────────────────
//
// ⛔ "WHICH WEBSITES" IS ANSWERABLE AT APPLICATION GRAIN AND NOT AT URL GRAIN,
// and the difference is not a nuance a management report may round off.
//
// WHAT EXISTS: the firewall's own application identity (PAN-OS App-ID,
// FortiOS application control) — `youtube-base`, `facebook-base`,
// `tiktok-base` — rolled up hourly with byte counts, kept as long as every
// other detail rollup. That is a real, per-application bandwidth answer.
//
// WHAT DOES NOT: the hostname. syslog_events carries `url_hostname`, but it is
// populated on a small minority of events, several firewalls report it on none
// at all, and it has no rollup, so it dies with the 30-day partitions. Ranking
// "top websites" off that would describe a fraction of the traffic under a
// heading that claims the estate. Measured 2026-09-21: 18,723 of 1,405,000
// events in a 20-minute sample, 1.3%. Closing that gap needs a
// syslog_url_hourly rollup AND URL-filtering log profiles enabled on the
// firewalls — a decision with an ingest cost, not a query change.
//
// ⛔ A NAMED APPLICATION IS A FLOOR, NEVER A TOTAL. `ssl` and `quic-base` are
// the firewall saying it could not attribute the session — and a large share of
// video rides QUIC. "YouTube used 4.2 GB" is therefore AT LEAST 4.2 GB. Every
// caller must print it that way.



/**
 * Applications ranked by VOLUME, not by event count.
 *
 * ⛔ SCOPED TO THE DEVICES WHOSE BYTES CAN BE SUMMED, passed in by the caller
 * from windowCoverage(). A vendor that re-logs a session with a running
 * cumulative counter would inflate every figure here, and the caller already
 * knows which those are — recomputing it locally would let the two disagree,
 * and the disagreement would be invisible.
 *
 * capableDeviceIds empty => an empty IDENTIFIED list AND a caller that must say
 * volume is not measurable, never a zero.
 *
 * ⛔ RETURNS TWO LISTS, NEVER ONE. `identified` is what a person would
 * recognise; `unattributed` is the traffic the firewall could not name, kept
 * whole so the caller can state how much of the total it represents. Merging
 * them produces a chart whose largest bars all mean "we do not know".
 */
// ⛔ ONE SHAPE, ALWAYS. The two early exits below used to `return []` while the
// success path returned an object, so `wApps.identified.length` threw and EVERY
// per-device report on a firewall that cannot report bytes died as a 500 — 5 of
// 16 on the reference fleet, all Fortinet. A function whose empty case has a
// different type from its full case is a crash waiting for the first caller who
// does not check, and the caller here was written against the full case.
const EMPTY_APP_BYTES = Object.freeze({
  identified: [], identifiedTotal: 0, unattributed: [], unattributedTotal: 0, devices: 0,
});

async function windowAppBytes(pool, w, deviceId, capableDeviceIds, limit = 15) {
  const ids = (capableDeviceIds || []).filter(Boolean);
  if (ids.length === 0) return EMPTY_APP_BYTES;
  const scoped = deviceId ? ids.filter((x) => x === deviceId) : ids;
  if (scoped.length === 0) return EMPTY_APP_BYTES;
  const { rows } = await pool.query(
    `SELECT a.application,
            sum(a.event_count)::bigint AS events,
            sum(coalesce(a.bytes_sent, 0) + coalesce(a.bytes_received, 0))::bigint AS bytes
       FROM syslog_app_hourly a
      WHERE a.bucket_hour >= $1::timestamptz AND a.bucket_hour < $2::timestamptz
        AND a.device_id = ANY($3::uuid[])
        AND a.application IS NOT NULL
        AND (a.bytes_sent IS NOT NULL OR a.bytes_received IS NOT NULL)
      GROUP BY 1
      HAVING sum(coalesce(a.bytes_sent, 0) + coalesce(a.bytes_received, 0)) > 0
      ORDER BY 3 DESC`,
    [w.from, w.to, scoped]
  );
  const all = rows.map((r) => ({
    application: r.application,
    events: Number(r.events),
    bytes: r.bytes === null ? null : Number(r.bytes),
  }));
  const identified = all.filter((r) => !isUnattributedApplication(r.application));
  const unattributed = all.filter((r) => isUnattributedApplication(r.application));
  const sum = (xs) => xs.reduce((n, r) => n + (r.bytes || 0), 0);
  return {
    identified: identified.slice(0, Number(limit) || 15),
    identifiedTotal: sum(identified),
    unattributed: unattributed.slice(0, 8),
    unattributedTotal: sum(unattributed),
    devices: scoped.length,
  };
}

/**
 * URL categories as the firewall classified them.
 *
 * Returns classified and unclassified SEPARATELY. ⛔ They are not two ends of
 * one ranked list: the second is a measure of how much of the traffic the
 * firewall declined or was unable to categorise, and merging them produces a
 * chart whose largest slice means "no answer".
 */
async function windowUrlCategories(pool, w, deviceId, limit = 15) {
  const { rows } = await pool.query(
    `SELECT u.url_category,
            sum(u.event_count)::bigint AS events,
            sum(u.denied_count)::bigint AS denied
       FROM syslog_urlcat_hourly u
      WHERE ${windowSql('u.bucket_hour', 'u.device_id', deviceId)}
      GROUP BY 1 ORDER BY 2 DESC`,
    windowParams(w, deviceId)
  );
  const all = rows.map((r) => ({
    category: r.url_category,
    events: Number(r.events),
    denied: r.denied === null ? null : Number(r.denied),
  }));
  const classified = all.filter((r) => !isUnclassifiedCategory(r.category));
  const unclassified = all.filter((r) => isUnclassifiedCategory(r.category))
    .map((r) => ({ ...r, reason: UNCLASSIFIED_URL_CATEGORIES.get(String(r.category).toLowerCase()) }));
  // ⛔ WHICH FIREWALL, BY NAME. A lapsed URL-filtering subscription is an
  // ACTIONABLE finding, not a footnote: that firewall has stopped classifying
  // anything, so its users are absent from every category figure above while
  // its traffic is still counted everywhere else. Naming it is the difference
  // between a report and a renewal.
  const { rows: perDev } = await pool.query(
    `SELECT d.name, u.url_category, sum(u.event_count)::bigint AS events
       FROM syslog_urlcat_hourly u JOIN devices d ON d.id = u.device_id
      WHERE ${windowSql('u.bucket_hour', 'u.device_id', deviceId)}
        AND lower(u.url_category) = ANY($${deviceId ? 4 : 3}::text[])
      GROUP BY 1, 2 ORDER BY 3 DESC`,
    [...windowParams(w, deviceId), [...UNCLASSIFIED_URL_CATEGORIES.keys()]]
  );

  return {
    classified: classified.slice(0, Number(limit) || 15),
    classifiedTotal: classified.reduce((n, r) => n + r.events, 0),
    unclassified,
    unclassifiedTotal: unclassified.reduce((n, r) => n + r.events, 0),
    unclassifiedByDevice: perDev.map((r) => ({
      name: r.name,
      category: r.url_category,
      events: Number(r.events),
      reason: UNCLASSIFIED_URL_CATEGORIES.get(String(r.url_category).toLowerCase()) || null,
    })),
  };
}

/**
 * Per firewall: how much of its traffic carries an application name at all.
 *
 * ⛔ THIS IS THE SECTION'S DENOMINATOR AND IT IS NOT OPTIONAL. Application
 * identity comes from a licensed inspection feature, so coverage is wildly
 * uneven across a real fleet — measured here, PAN-OS firewalls name almost
 * everything while several FortiGates name almost nothing. A "top applications"
 * table without this reads as a statement about the estate when it is a
 * statement about whichever firewalls happen to inspect.
 */
async function windowAppCoverage(pool, w, deviceId) {
  const { rows } = await pool.query(
    `SELECT d.id, d.name, d.vendor,
            coalesce(sum(a.event_count) FILTER (WHERE a.application IS NOT NULL), 0)::bigint AS named,
            coalesce(sum(a.event_count), 0)::bigint AS total,
            -- ⛔ THE FILTER IS WHAT MAKES THIS TRI-STATE. bool_or sits on the
            -- OUTER side of a LEFT JOIN, and with no matching rows PostgreSQL
            -- still feeds it one all-NULL row where x IS NOT NULL evaluates
            -- to FALSE (never NULL) — so it returned false, and the
            -- === null ? null guard below could never fire. A firewall that
            -- simply sent nothing was reported as one whose bytes may not be
            -- summed, which is a claim about the VENDOR, not about coverage.
            -- Filtering the phantom row out makes bool_or aggregate over zero
            -- rows, which is NULL, which is the honest answer.
            bool_or(a.bytes_sent IS NOT NULL OR a.bytes_received IS NOT NULL)
              FILTER (WHERE a.device_id IS NOT NULL) AS bytes_reported
       FROM devices d
       LEFT JOIN syslog_app_hourly a
         ON a.device_id = d.id
        AND a.bucket_hour >= $1::timestamptz AND a.bucket_hour < $2::timestamptz
      WHERE d.active = true${deviceId ? ' AND d.id = $3::uuid' : ''}
      GROUP BY 1, 2, 3
      ORDER BY 4 DESC, d.name ASC`,
    windowParams(w, deviceId)
  );
  return rows.map((r) => {
    const named = Number(r.named);
    const total = Number(r.total);
    return {
      deviceId: r.id,
      name: r.name,
      vendor: r.vendor,
      named,
      total,
      // ⛔ TRI-STATE, same rule as bytesMeasured. A device that sent nothing to
      // this rollup has an UNKNOWN naming rate, not a rate of zero — zero would
      // read as "this firewall identifies nothing", a claim about the device
      // rather than about our coverage of it.
      namedRatio: total > 0 ? named / total : null,
      bytesReported: r.bytes_reported === null ? null : r.bytes_reported === true,
    };
  });
}

module.exports = {
  resolveWindow,
  detailRetentionDays,
  windowTimeline,
  windowActions,
  windowTopHosts,
  windowTopApplications,
  windowProtocols,
  windowTopBlocked,
  windowTopRules,
  windowCoverage,
  windowAppBytes,
  windowUrlCategories,
  windowAppCoverage,
  HOUR_MS,
};
