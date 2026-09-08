// lib/engines/ruleHitCorrelation.js
//
// Phase 8b — turning log evidence into rule usage.
//
// This is the reason CLAUDE.md gives for syslog ingestion belonging in SecVault
// rather than being left to LogVault: a general log analyser does not know the
// rulebase. Measured on this fleet, 164 rules have `hit_count IS NULL` —
// Fortinet-SSH and Palo-Alto-SSH cannot report hit counts at all — so they can
// produce no usage finding whatsoever today. Logs can answer 58 of them
// outright, and the rest become answerable as the log window grows.
//
// ── THE ONLY HARD PART: WHEN IS "NO LOGGED HITS" A MEASURED ZERO? ─────────
// Never by default. A rule absent from the logs is unused ONLY if we can show
// the logs would have contained it had it been used. Three things must all
// hold, and each one, missed, recreates the exact `hit_count DEFAULT 0` bug
// this codebase spent a release removing:
//
//   1. THE DEVICE WAS LOGGING throughout the window. If the collector was
//      down, or the firewall stopped forwarding, zero logged hits measures the
//      collector, not the rule.
//   2. THE RULE HAS LOGGING ENABLED. `log_enabled = false` means the rule can
//      never appear in a log no matter how much traffic it passes. Zero hits
//      there is not evidence of anything — and SecVault already reports that
//      separately as a `log_disabled` finding.
//   3. THE WINDOW IS LONG ENOUGH to be meaningful. A rule idle for six hours
//      is not unused.
//
// Fail any of those and the answer is NULL — not measured — exactly as a
// vendor that cannot read hit counts yields NULL rather than 0.
//
// ⛔ Log-derived counts are NEVER written into `firewall_rules.hit_count`.
// That column means "what the device itself reported over the rule's lifetime";
// a logged count means "what we observed in a bounded window". Merging them
// would silently change what the number means, and `firewall_rules` is
// DELETE+reinserted on every pull anyway. This is computed at READ time from
// `syslog_rule_hits_hourly`, like deviceHealth.js derives status.

'use strict';

// Below this, "no traffic seen" is not a statement about the rule.
const MIN_WINDOW_HOURS = 24;

// Fraction of hours in the window that must actually contain events from the
// device before its silence counts as evidence. Not 1.0: a collector restart
// or a brief network blip should not permanently disqualify a device, and this
// fleet's own deploys produce exactly those gaps.
const MIN_COVERAGE_RATIO = 0.9;

function clampDays(d, def, max) {
  const n = Number(d);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(Math.trunc(n), 1), max);
}

/**
 * Per-device log coverage over the window.
 *
 * Reads `syslog_rollup_hourly` (cheap — it is an aggregate) and counts how many
 * distinct hours actually carried events for each device.
 *
 * @returns {Map<string, {hoursWithEvents, windowHours, ratio, covered, firstSeen, lastSeen}>}
 *   `covered` is the only field callers should branch on. It is FALSE, never
 *   undefined, for a device that sent nothing at all.
 */
async function getDeviceLogCoverage(pool, days, now) {
  const d = clampDays(days, 30, 400);
  const windowHours = d * 24;
  const { rows } = await pool.query(
    `SELECT device_id,
            count(DISTINCT bucket_hour)::int AS hours_with_events,
            min(bucket_hour) AS first_seen,
            max(bucket_hour) AS last_seen,
            sum(event_count)::bigint AS events
       FROM syslog_rollup_hourly
      WHERE bucket_hour >= date_trunc('hour', $1::timestamptz) - ($2::int * interval '1 hour')
        AND device_id IS NOT NULL
      GROUP BY 1`,
    [now instanceof Date ? now : new Date(), windowHours]
  );

  const out = new Map();
  for (const r of rows) {
    const hours = Number(r.hours_with_events);
    const ratio = windowHours > 0 ? hours / windowHours : 0;
    out.set(r.device_id, {
      hoursWithEvents: hours,
      windowHours,
      ratio: Math.round(ratio * 1000) / 1000,
      // ⛔ Both conditions. A device logging densely for two hours has a ratio
      // near zero over a 30-day window and must not qualify; a device with a
      // long window but a big outage must not either.
      covered: hours >= MIN_WINDOW_HOURS && ratio >= MIN_COVERAGE_RATIO,
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
      events: Number(r.events),
    });
  }
  return out;
}

/**
 * Logged hits per rule identity for one device.
 *
 * ⛔ Fortinet reports `policyid=0` with an empty name for its IMPLICIT DENY.
 * That is not a configured rule and must never be matched to one — it would
 * attach a large hit count to whichever real rule happened to share the key.
 *
 * @returns {{byVendorId: Map, byName: Map}} both keyed to
 *   `{hits, firstHit, lastHit}`.
 */
async function getLoggedRuleHits(pool, deviceId, days, now) {
  const d = clampDays(days, 30, 400);
  const { rows } = await pool.query(
    `SELECT rule_id, rule_name,
            sum(hit_count)::bigint AS hits,
            min(first_seen_at) AS first_hit,
            max(last_seen_at)  AS last_hit
       FROM syslog_rule_hits_hourly
      WHERE device_id = $1::uuid
        AND bucket_hour >= date_trunc('hour', $2::timestamptz) - ($3::int * interval '1 day')
      GROUP BY 1, 2`,
    [deviceId, now instanceof Date ? now : new Date(), d]
  );

  const byVendorId = new Map();
  const byName = new Map();
  for (const r of rows) {
    const isImplicitDeny =
      (r.rule_id === '0' || r.rule_id === 0) && (!r.rule_name || r.rule_name === '');
    if (isImplicitDeny) continue;

    const v = { hits: Number(r.hits), firstHit: r.first_hit, lastHit: r.last_hit };
    if (r.rule_id !== null && r.rule_id !== undefined && String(r.rule_id) !== '') {
      const k = String(r.rule_id);
      const prev = byVendorId.get(k);
      byVendorId.set(k, prev ? mergeHit(prev, v) : v);
    }
    if (r.rule_name) {
      const prev = byName.get(r.rule_name);
      byName.set(r.rule_name, prev ? mergeHit(prev, v) : v);
    }
  }
  return { byVendorId, byName };
}

function mergeHit(a, b) {
  return {
    hits: a.hits + b.hits,
    firstHit: a.firstHit && b.firstHit ? (a.firstHit < b.firstHit ? a.firstHit : b.firstHit) : (a.firstHit || b.firstHit),
    lastHit: a.lastHit && b.lastHit ? (a.lastHit > b.lastHit ? a.lastHit : b.lastHit) : (a.lastHit || b.lastHit),
  };
}

/**
 * Attach log evidence to a device's rules. PURE — takes the already-fetched
 * coverage and hit maps so it can be unit-tested without a database.
 *
 * Adds, per rule:
 *   loggedHits        number | null   null = not measurable, never 0-by-absence
 *   loggedLastHit     Date   | null
 *   logEvidence       'hits' | 'measured-zero' | 'no-coverage' |
 *                     'rule-logging-disabled' | 'window-too-short'
 *   effectiveHitCount number | null   the device's own count if it has one,
 *                                     otherwise the logged count
 *   hitCountSource    'device' | 'logs' | null
 *
 * ⛔ `effectiveHitCount` is null whenever neither source can answer. It is
 * never 0 as a stand-in for "we do not know" — that is the bug this whole file
 * exists to avoid repeating.
 */
function enrichRulesWithLogEvidence(rules, coverage, hitMaps) {
  const cov = coverage || null;
  const byVendorId = (hitMaps && hitMaps.byVendorId) || new Map();
  const byName = (hitMaps && hitMaps.byName) || new Map();

  return (rules || []).map((rule) => {
    const deviceHits =
      rule.hit_count === null || rule.hit_count === undefined ? null : Number(rule.hit_count);

    // Vendor id first: it is exact. Name is a fallback and can collide across
    // VDOMs, which is why the id is preferred wherever the vendor supplies one.
    let match = null;
    if (rule.rule_id_vendor !== null && rule.rule_id_vendor !== undefined) {
      match = byVendorId.get(String(rule.rule_id_vendor)) || null;
    }
    if (!match && rule.rule_name) match = byName.get(rule.rule_name) || null;

    let loggedHits = null;
    let logEvidence;
    if (match) {
      loggedHits = match.hits;
      logEvidence = 'hits';
    } else if (rule.log_enabled === false) {
      // ⛔ The rule cannot appear in a log at all. Its absence measures the
      // logging setting, not the traffic.
      logEvidence = 'rule-logging-disabled';
    } else if (!cov || !cov.covered) {
      // ⛔ Either the device was not logging throughout, or we have too little
      // history. Its silence measures the collector, not the rule.
      logEvidence = !cov || cov.hoursWithEvents < MIN_WINDOW_HOURS
        ? 'window-too-short'
        : 'no-coverage';
    } else {
      // All three conditions hold, so zero really is zero.
      loggedHits = 0;
      logEvidence = 'measured-zero';
    }

    const hitCountSource = deviceHits !== null ? 'device' : (loggedHits !== null ? 'logs' : null);
    const effectiveHitCount = deviceHits !== null ? deviceHits : loggedHits;

    return Object.assign({}, rule, {
      loggedHits,
      loggedLastHit: match ? match.lastHit : null,
      logEvidence,
      hitCountSource,
      effectiveHitCount,
      logCoverageRatio: cov ? cov.ratio : null,
    });
  });
}

/**
 * Convenience: fetch coverage + hits and enrich in one call.
 * pool is always a parameter (CLAUDE.md).
 */
async function correlateDeviceRules(pool, deviceId, rules, days, now) {
  const coverageMap = await getDeviceLogCoverage(pool, days, now);
  const hitMaps = await getLoggedRuleHits(pool, deviceId, days, now);
  return enrichRulesWithLogEvidence(rules, coverageMap.get(deviceId) || null, hitMaps);
}

module.exports = {
  getDeviceLogCoverage,
  getLoggedRuleHits,
  enrichRulesWithLogEvidence,
  correlateDeviceRules,
  MIN_WINDOW_HOURS,
  MIN_COVERAGE_RATIO,
};
