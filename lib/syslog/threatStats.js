// lib/syslog/threatStats.js
//
// The Security-tab reports: attackers, targets, threats, severity — the
// ManageEngine Firewall Analyzer families (Attack Reports, Virus Reports,
// Security Reports) that the decommission review found SecVault had no
// counterpart for.
//
// ── WHY THESE READ syslog_events AND THE TRAFFIC WIDGETS DO NOT ───────────
// Every traffic widget reads a rollup because traffic is 98.4% of the stream.
// Threat events are 1.31% — about 70,000/hour on this fleet — and are covered
// by idx_syslog_events_class, a PARTIAL index over exactly the non-traffic
// rows. So a raw read here is both cheap and strictly better: it keeps the
// per-event attacker/target/signature detail that an aggregate destroys, and
// "which host attacked which host" is precisely the question being asked.
//
// ⛔ Every window is bounded, for the same reason as logSearch.js: an
// open-ended scan of a table growing at ~133 GB/day is an outage for the
// ingest, not a slow page.
//
// ⛔ Severity is the VENDOR'S OWN WORD, and PAN-OS and FortiOS use different
// vocabularies. threatSeverityRank() maps both onto one ordered scale and
// returns null for anything unrecognized — a threat filed under a guessed
// severity silently changes where it sorts in a prioritized list.

'use strict';

const { threatSeverityRank } = require('./vendorParsers');

const DENY_ACTIONS = ['deny', 'drop', 'reset-both', 'block', 'block-url'];

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

const WINDOW = `received_at >= now() - ($1::int * interval '1 hour')`;

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
            count(*)::bigint AS events,
            count(DISTINCT e.dst_ip)::bigint AS targets,
            count(DISTINCT e.threat_name)::bigint AS distinct_threats,
            max(e.threat_severity) AS worst_severity,
            max(e.received_at) AS last_seen,
            min(e.src_country) AS src_country
       FROM syslog_events e
      WHERE ${WINDOW}
        AND e.log_class = 'threat'
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
    worstSeverity: r.worst_severity || null,
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
            count(*)::bigint AS events,
            count(DISTINCT e.src_ip)::bigint AS attackers,
            max(e.received_at) AS last_seen
       FROM syslog_events e
      WHERE ${WINDOW}
        AND e.log_class = 'threat'
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
            count(*)::bigint AS events,
            count(DISTINCT e.src_ip)::bigint AS sources,
            count(DISTINCT e.dst_ip)::bigint AS targets,
            max(e.received_at) AS last_seen
       FROM syslog_events e
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
    `SELECT e.threat_severity, count(*)::bigint AS events
       FROM syslog_events e
      WHERE ${WINDOW}
        AND e.log_class = 'threat'
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
    `SELECT date_trunc('hour', e.received_at) AS bucket_hour,
            count(*)::bigint AS events
       FROM syslog_events e
      WHERE ${WINDOW}
        AND e.log_class = 'threat'
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
            count(e.*)::bigint AS threat_events,
            count(DISTINCT e.src_ip)::bigint AS attackers,
            count(DISTINCT e.threat_name)::bigint AS distinct_threats,
            max(e.received_at) AS last_threat
       FROM devices d
       LEFT JOIN syslog_events e
         ON e.device_id = d.id
        AND e.received_at >= now() - ($1::int * interval '1 hour')
        AND e.log_class = 'threat'
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

module.exports = {
  getTopAttackers,
  getTopTargets,
  getTopThreats,
  getThreatsBySeverity,
  getThreatTimeline,
  getDeviceThreatSummary,
  DENY_ACTIONS,
};
