// lib/syslog/threatStats.js
//
// The Security-tab reports: attackers, targets, threats, severity — the
// ManageEngine Firewall Analyzer families (Attack Reports, Virus Reports,
// Security Reports) that the decommission review found SecVault had no
// counterpart for.
//
// ── THESE READ syslog_threat_hourly. THEY USED TO READ syslog_events. ─────
//
// The original reasoning, kept because it was right about the hour and wrong
// about the day: threat events are ~1.3% of the stream and are covered by
// idx_syslog_events_class, a partial index over exactly the non-traffic rows,
// so a raw read is cheap. Measured 2026-09-09: one hour of threat events is
// 59,129 rows and reads in 256 ms. Entirely true.
//
// ⛔ But the Security tab asks for 24 HOURS across SIX widgets. That is ~1.4M
// rows scanned six times on every page load, and the tab was visibly slow.
// "Cheap per hour" does not survive multiplication by the window and the
// number of questions.
//
// The other half of the old argument — that an aggregate destroys the
// per-event attacker/target detail — turned out not to apply, because every
// widget here ASKS FOR AN AGGREGATE. Keeping src_ip, dst_ip and threat_name
// as grouping keys in the rollup preserves every question this file asks,
// including the distinct counts. Per-event detail still exists and still
// comes from the raw table, on /logs, which is where that question is asked.
//
// ⛔ Every window is still bounded. The rollup is small, but the habit is the
// point: an open-ended scan of anything fed by this ingest is an outage for
// the collector, not a slow page.
//
// ⛔ Severity is the VENDOR'S OWN WORD, and PAN-OS and FortiOS use different
// vocabularies. threatSeverityRank() maps both onto one ordered scale and
// returns null for anything unrecognized — a threat filed under a guessed
// severity silently changes where it sorts in a prioritized list.

'use strict';

const { threatSeverityRank, THREAT_SEVERITY_RANK } = require('./vendorParsers');

// ⛔ `max(threat_severity)` is an ALPHABETICAL comparison — the column is TEXT.
// It disagrees with real severity exactly where it matters:
//   {high, informational} -> "informational"   {critical, low} -> "low"
//   {critical, high}      -> "high"            {high, medium}  -> "medium"
// so a Top Attackers table could label a critical attacker "low". Rank in SQL
// instead, and GENERATE the CASE from the same table the parser uses so the
// two can never drift. Word list is a module constant, never user input.
const SEVERITY_RANK_CASE =
  'CASE lower(e.threat_severity) ' +
  Object.entries(THREAT_SEVERITY_RANK)
    .map(([word, rank]) => `WHEN '${word}' THEN ${rank}`)
    .join(' ') +
  ' ELSE NULL END';

// Rank -> the label we render. PAN-OS's vocabulary is the canonical one; the
// FortiOS synonyms collapse onto the same ranks by design.
const RANK_LABEL = {
  0: 'debug',
  1: 'informational',
  2: 'low',
  3: 'medium',
  4: 'high',
  5: 'critical',
};

// ⛔ The local DENY_ACTIONS array that used to live here was a FOURTH,
// divergent copy of the deny vocabulary that nothing imported — dead code that
// read like the authoritative definition, which is exactly how a future fix
// gets applied to the wrong list. The shared set is lib/syslog/actions.js.
const { DENIED_ACTIONS } = require('./actions');
const DENY_ACTIONS = Array.from(DENIED_ACTIONS);

function clampHours(h, def, max) {
  const n = Number(h);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(Math.trunc(n), 1), max);
}

function clampLimit(v, def) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(Math.trunc(n), 1), 200);
}

// ⛔ EVERY QUERY IN THIS FILE READS syslog_threat_hourly, NEVER syslog_events.
//
// They all read the raw table until 2026-09-09, and the Security tab was
// visibly slow because of it. Measured on the live fleet: one hour of threat
// events is 59,129 rows, so the tab’s 24-hour window is ~1.4M rows — scanned
// SIX TIMES, once per widget, on every page load. The rollup covers the same
// window in ~121k much narrower rows.
//
// ⛔ The rollup keeps dst_ip in its grain precisely so the DISTINCT counts
// below stay exact. A per-hour COUNT(DISTINCT) is NOT additive — summing 24
// of them over-counts badly, which is the same trap syslog_vpn_auth_hourly
// avoids by storing a username array. Because dst_ip, src_ip and threat_name
// are grouping keys here, count(DISTINCT ...) over any span of buckets is
// the true distinct count, not a sum of per-hour counts.
//
// ⛔ event_count must be SUMmed, never counted. count(*) over the rollup
// would count BUCKETS, not events.
const WINDOW = `bucket_hour >= date_trunc('hour', now() - ($1::int * interval '1 hour'))`;

/**
 * Top attacking sources — Firewall Analyzer's "Top Attackers".
 * Ranked by event count, with the distinct targets each one touched, because
 * one host hitting 400 targets and one host hitting 1 are different problems
 * at the same event count.
 */
async function getTopAttackers(pool, hours = 24, limit = 10) {
  const h = clampHours(hours, 24, 24 * 8);
  const lim = clampLimit(limit, 10);
  const { rows } = await pool.query(
    `SELECT e.src_ip::text AS src_ip,
            sum(e.event_count)::bigint AS events,
            count(DISTINCT e.dst_ip)::bigint AS targets,
            count(DISTINCT e.threat_name)::bigint AS distinct_threats,
            -- ⛔ NOT max(threat_severity). That column is TEXT, so max() picks
            -- the ALPHABETICALLY largest word, which disagrees with severity
            -- wherever it matters: {high, informational} -> "informational",
            -- {critical, low} -> "low", {critical, high} -> "high". A Top
            -- Attackers table could label a critical attacker "low".
            -- Rank numerically here and map back below, mirroring the ranking
            -- getThreatsBySeverity already does. The CASE is GENERATED from
            -- THREAT_SEVERITY_RANK so the SQL and the JS can never disagree
            -- about what a word is worth.
            max(${SEVERITY_RANK_CASE}) AS worst_severity_rank,
            max(e.last_seen_at) AS last_seen,
            min(e.src_country) AS src_country
       FROM syslog_threat_hourly e
      WHERE ${WINDOW}
        AND e.src_ip IS NOT NULL
      GROUP BY 1
      ORDER BY events DESC
      LIMIT $2`,
    [h, lim]
  );
  return rows.map((r) => ({
    srcIp: r.src_ip,
    events: Number(r.events),
    targets: Number(r.targets),
    distinctThreats: Number(r.distinct_threats),
    // ⛔ null when no row carried a severity this engine recognises — an
    // unranked word is not a severity level, and inventing one here would be
    // the same fabrication the parser refuses at ingest.
    worstSeverity: RANK_LABEL[r.worst_severity_rank] || null,
    worstSeverityRank: r.worst_severity_rank === null ? null : Number(r.worst_severity_rank),
    srcCountry: r.src_country || null,
    lastSeen: r.last_seen,
  }));
}

/** Most-targeted destinations — Firewall Analyzer's "Top Targets". */
async function getTopTargets(pool, hours = 24, limit = 10) {
  const h = clampHours(hours, 24, 24 * 8);
  const lim = clampLimit(limit, 10);
  const { rows } = await pool.query(
    `SELECT e.dst_ip::text AS dst_ip,
            sum(e.event_count)::bigint AS events,
            count(DISTINCT e.src_ip)::bigint AS attackers,
            max(e.last_seen_at) AS last_seen
       FROM syslog_threat_hourly e
      WHERE ${WINDOW}
        AND e.dst_ip IS NOT NULL
      GROUP BY 1
      ORDER BY events DESC
      LIMIT $2`,
    [h, lim]
  );
  return rows.map((r) => ({
    dstIp: r.dst_ip,
    events: Number(r.events),
    attackers: Number(r.attackers),
    lastSeen: r.last_seen,
  }));
}

/**
 * Top threat signatures by name — the union of Firewall Analyzer's attack and
 * virus report families, which SecVault does not split because the vendors do
 * not either: FortiOS puts an IPS signature in `attack` and a virus in
 * `virus`, and PAN-OS puts both in the same threat-name column.
 *
 * ⛔ Rows with no threat name are EXCLUDED, not bucketed under a synthetic
 * label. A "(unnamed)" entry would top this chart on url-filtering events and
 * bury every real signature.
 */
async function getTopThreats(pool, hours = 24, limit = 10) {
  const h = clampHours(hours, 24, 24 * 8);
  const lim = clampLimit(limit, 10);
  const { rows } = await pool.query(
    `SELECT e.threat_name,
            e.threat_severity,
            e.log_subtype,
            sum(e.event_count)::bigint AS events,
            count(DISTINCT e.src_ip)::bigint AS sources,
            count(DISTINCT e.dst_ip)::bigint AS targets,
            max(e.last_seen_at) AS last_seen
       FROM syslog_threat_hourly e
      WHERE ${WINDOW}
        AND e.threat_name IS NOT NULL
      GROUP BY 1, 2, 3
      ORDER BY events DESC
      LIMIT $2`,
    [h, lim]
  );
  return rows.map((r) => ({
    threatName: r.threat_name,
    severity: r.threat_severity || null,
    severityRank: threatSeverityRank(r.threat_severity),
    subtype: r.log_subtype || null,
    events: Number(r.events),
    sources: Number(r.sources),
    targets: Number(r.targets),
    lastSeen: r.last_seen,
  }));
}

/**
 * Threat counts grouped onto ONE severity scale across both vendors.
 *
 * ⛔ Words the rank table does not recognize are returned as a separate
 * `unranked` count rather than folded into a level. Guessing would move a
 * threat up or down a prioritized list silently.
 */
async function getThreatsBySeverity(pool, hours = 24) {
  const h = clampHours(hours, 24, 24 * 8);
  const { rows } = await pool.query(
    `SELECT e.threat_severity, sum(e.event_count)::bigint AS events
       FROM syslog_threat_hourly e
      WHERE ${WINDOW}
      GROUP BY 1`,
    [h]
  );

  const byRank = new Map();
  let unranked = 0;
  let unreported = 0;
  for (const r of rows) {
    const n = Number(r.events);
    if (r.threat_severity === null) { unreported += n; continue; }
    const rank = threatSeverityRank(r.threat_severity);
    if (rank === null) { unranked += n; continue; }
    const cur = byRank.get(rank) || { rank, events: 0, words: new Set() };
    cur.events += n;
    cur.words.add(r.threat_severity);
    byRank.set(rank, cur);
  }

  const LABELS = ['Debug', 'Informational', 'Low', 'Medium', 'High', 'Critical'];
  return {
    levels: [...byRank.values()]
      .sort((a, b) => b.rank - a.rank)
      .map((v) => ({
        rank: v.rank,
        label: LABELS[v.rank] || `Level ${v.rank}`,
        // The vendor words that landed on this level, so an operator can see
        // that "critical" and "emergency" were merged deliberately.
        vendorWords: [...v.words].sort(),
        events: v.events,
      })),
    unranked,
    unreported,
  };
}

/** Threat events per hour, for the trend strip. */
async function getThreatTimeline(pool, hours = 24) {
  const h = clampHours(hours, 24, 24 * 8);
  const { rows } = await pool.query(
    // The rollup is ALREADY bucketed by hour, so this is a plain read —
    // no date_trunc, and no risk of the session TimeZone shifting a bucket.
    `SELECT e.bucket_hour,
            sum(e.event_count)::bigint AS events
       FROM syslog_threat_hourly e
      WHERE ${WINDOW}
      GROUP BY 1
      ORDER BY 1 ASC`,
    [h]
  );
  return rows.map((r) => ({ hour: r.bucket_hour, events: Number(r.events) }));
}

/**
 * Per-device security summary — threat / denied / distinct-attacker counts.
 * Reads the hourly rollup for denies (cheap, it is a rollup dimension) and the
 * raw table for threat detail.
 */
async function getDeviceThreatSummary(pool, hours = 24) {
  const h = clampHours(hours, 24, 24 * 8);
  const { rows } = await pool.query(
    `SELECT d.id AS device_id, d.name, d.vendor,
            -- ⛔ coalesce, because a LEFT JOIN with no match makes sum()
            -- return NULL. Zero threat events IS a real measured answer for
            -- a device that sends logs; the "we have no coverage" case is
            -- carried separately by the widget, not by a NULL here.
            coalesce(sum(e.event_count), 0)::bigint AS threat_events,
            count(DISTINCT e.src_ip)::bigint AS attackers,
            count(DISTINCT e.threat_name)::bigint AS distinct_threats,
            max(e.last_seen_at) AS last_threat
       FROM devices d
       LEFT JOIN syslog_threat_hourly e
         ON e.device_id = d.id
        AND e.bucket_hour >= date_trunc('hour', now() - ($1::int * interval '1 hour'))
      WHERE d.active
      GROUP BY 1, 2, 3
      ORDER BY threat_events DESC, d.name ASC`,
    [h]
  );
  return rows.map((r) => ({
    deviceId: r.device_id,
    name: r.name,
    vendor: r.vendor,
    threatEvents: Number(r.threat_events),
    attackers: Number(r.attackers),
    distinctThreats: Number(r.distinct_threats),
    lastThreat: r.last_threat || null,
  }));
}

/**
 * Has the threat rollup actually been built for this window?
 *
 * ⛔ WITHOUT THIS, AN EMPTY ROLLUP READS AS "NO ATTACKS". Every widget on
 * the Security tab now reads syslog_threat_hourly, and an unpopulated table
 * answers every one of them with a confident zero — "no attackers", "no
 * threats", "0 critical". That is the failed-read-as-a-fact rule in its most
 * dangerous form: a security dashboard asserting calm because its own
 * aggregation has not run. It is not hypothetical — it was the live state for
 * the first minutes after the rollup shipped, before the first sweep.
 *
 * ⛔ THE SIGNAL IS syslog_rollup_hourly, NOT a row count on the threat table.
 * "Zero threat rows" cannot distinguish "no attacks happened" from "nobody
 * aggregated yet". But both tables are written by the SAME sweep inside the
 * SAME transaction, so a bucket in syslog_rollup_hourly proves the sweep
 * covered that hour. If it ran and produced no threat rows, zero is a real,
 * earned measurement. If it never ran, nothing can be concluded.
 *
 * @returns {{aggregatedHours:number, sweptHours:number, evaluable:boolean}}
 */
async function getThreatCoverage(pool, hours = 24) {
  const h = clampHours(hours, 24, 24 * 8);
  const { rows } = await pool.query(
    `SELECT
       (SELECT count(DISTINCT bucket_hour) FROM syslog_threat_hourly
         WHERE bucket_hour >= date_trunc('hour', now() - ($1::int * interval '1 hour')))::int
         AS aggregated_hours,
       (SELECT count(DISTINCT bucket_hour) FROM syslog_rollup_hourly
         WHERE bucket_hour >= date_trunc('hour', now() - ($1::int * interval '1 hour')))::int
         AS swept_hours`,
    [h]
  );
  const r = rows[0] || {};
  const sweptHours = Number(r.swept_hours || 0);
  return {
    aggregatedHours: Number(r.aggregated_hours || 0),
    sweptHours,
    windowHours: h,
    // The sweep having run at all for this window is what makes a zero
    // meaningful. Partial coverage is still evaluable — the widgets report
    // how many hours are covered rather than refusing to answer.
    evaluable: sweptHours > 0,
  };
}

module.exports = {
  getThreatCoverage,
  getTopAttackers,
  getTopTargets,
  getTopThreats,
  getThreatsBySeverity,
  getThreatTimeline,
  getDeviceThreatSummary,
  DENY_ACTIONS,
};
