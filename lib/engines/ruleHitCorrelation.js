// lib/engines/ruleHitCorrelation.js
//
// Phase 8b — turning log evidence into rule usage.
//
// This is the reason CLAUDE.md gives for syslog ingestion belonging in SecVault
// rather than being left to LogVault: a general log analyser does not know the
// rulebase. Measured on this fleet 2026-09-25, 235 rules have
// `hit_count IS NULL` — Fortinet-SSH and Palo-Alto-SSH cannot report hit counts
// at all — so they can produce no usage finding whatsoever from the device.
// Logs answer 84 of them: 54 Fortinet by rule ID and 30 Palo Alto by NAME.
//
// ⛔ THOSE TWO NUMBERS ARE NOT THE SAME KIND OF ANSWER (A3). Every rule-hit row
// this fleet has ever stored splits cleanly by vendor:
//
//   Fortinet    61,835 rows — rule_id present on EVERY one (44 distinct)
//   Palo Alto   80,203 rows — rule_id NULL on EVERY one; names only (223)
//
// An ID is exact. A NAME is neither unique nor stable across a config change,
// so a rule renamed during the window reads as having had no traffic while it
// is passing some. Both were previously reported as plain `logEvidence: 'hits'`
// with nothing distinguishing them, and the same blindness applied to the far
// more dangerous direction — a name-derived MEASURED ZERO, which becomes an
// `unused` finding and a deletion candidate. `usageGrade`/`deletionEvidence`
// below is that distinction.
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

const DEFAULT_WINDOW_DAYS = 30;

// ⛔ FLOOR OF 7, NOT 1. With a floor of 1 a caller passing days=1 got
// windowHours=24, and 24 hours of events satisfied BOTH coverage tests
// (hours >= MIN_WINDOW_HOURS, and ratio = 24/24 = 1.0 >= MIN_COVERAGE_RATIO) —
// so a single day of logs could certify a rule as a MEASURED zero and produce
// an `unused` finding. That is exactly what the coverage gate exists to
// prevent. Note also that MIN_WINDOW_HOURS is subsumed by the ratio test for
// any window beyond ~27 hours, so this floor is what actually carries the
// guard at realistic settings.
function clampDays(d, def, max) {
  const n = Number(d);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(Math.trunc(n), 7), max);
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
  const at = now instanceof Date ? now : new Date();

  // ⛔ HOW MUCH HISTORY EXISTS AT ALL — AND WHOSE LIMITATION IS IT?
  //
  // Measured 2026-09-25: the rollup began 2026-09-08 (the day the collector
  // shipped), so only 412 of a 30-day window's 720 hours COULD hold data. Every
  // device scored ratio 0.572 and failed the gate — while logging 100% of every
  // hour it was possible to log. The gate was measuring SECVAULT'S INSTALL DATE
  // and reporting it as `no-coverage`, i.e. as a fact about the firewall.
  //
  // That is the `warning` vs `na` distinction this codebase already draws for
  // compliance: an uncertainty that is OURS must not be recorded as a negative
  // fact about the device. It is also the reason nobody noticed — the effect
  // was conservative, so the whole log-derived measured-zero path had simply
  // never armed once.
  //
  // ⛔ AND IT WOULD HAVE ARMED ITSELF, FLEET-WIDE, WITH NO DEPLOY. At the
  // observed ~100% logging density the trailing 720-hour window reaches the 0.9
  // ratio around 2026-10-05 purely by the passage of time. A guard that flips
  // from "never fires" to "fires everywhere" on a date nobody wrote down is not
  // a guard. So the history test is now EXPLICIT and has its own state.
  // ⛔ ONE QUERY, NOT TWO. `first_bucket` is an UNCORRELATED scalar subquery —
  // PostgreSQL evaluates it once, as an index-only min — so the history costs
  // no extra round trip and every caller's stub states its history in one field
  // instead of growing a second branch.
  const { rows } = await pool.query(
    `SELECT s.device_id,
            count(DISTINCT s.bucket_hour)::int AS hours_with_events,
            min(s.bucket_hour) AS first_seen,
            max(s.bucket_hour) AS last_seen,
            sum(s.event_count)::bigint AS events,
            (SELECT min(bucket_hour) FROM syslog_rollup_hourly) AS first_bucket
       FROM syslog_rollup_hourly s
      WHERE s.bucket_hour >= date_trunc('hour', $1::timestamptz) - ($2::int * interval '1 hour')
        AND s.device_id IS NOT NULL
      GROUP BY 1`,
    [at, windowHours]
  );

  // ⛔ NULL, never 0 and never "assume plenty". A row set that cannot say when
  // collection began certifies nothing — the same call every other failed read
  // in this file makes. It is read off the first row because the subquery is
  // fleet-wide and therefore identical on all of them.
  let historyHours = null;
  const firstBucketRaw = rows.length > 0 ? rows[0].first_bucket : null;
  if (firstBucketRaw !== null && firstBucketRaw !== undefined) {
    const first = new Date(firstBucketRaw);
    if (!Number.isNaN(first.getTime())) {
      historyHours = Math.max(0, Math.floor((at - first) / 3600000) + 1);
    }
  }

  // ⛔ FLEET-WIDE, NOT PER DEVICE, AND DELIBERATELY SO. "SecVault has not been
  // collecting long enough" is one fact about this installation. A device that
  // started logging late WITHIN that history is a different fact, and the
  // per-device ratio below already catches it.
  const sufficientHistory = historyHours !== null && historyHours >= windowHours;

  const out = new Map();
  for (const r of rows) {
    const hours = Number(r.hours_with_events);
    const ratio = windowHours > 0 ? hours / windowHours : 0;
    out.set(r.device_id, {
      hoursWithEvents: hours,
      windowHours,
      historyHours,
      sufficientHistory,
      ratio: Math.round(ratio * 1000) / 1000,
      // ⛔ THREE conditions now. A device logging densely for two hours has a
      // ratio near zero over a 30-day window and must not qualify; a device
      // with a long window but a big outage must not either; and NOBODY
      // qualifies for a window longer than the history that exists.
      covered: sufficientHistory && hours >= MIN_WINDOW_HOURS && ratio >= MIN_COVERAGE_RATIO,
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
  // ⛔ "NO ROWS" AND "ROWS THAT NAME NOTHING" ARE DIFFERENT FACTS, and only the
  // second proves the device's logs cannot identify a rule. An empty map alone
  // cannot tell them apart, and treating both as the format case would refuse
  // to certify a genuinely idle firewall. Live shape of the second: PAKFood's
  // single rollup row carries neither a rule id nor a rule name.
  let rowsSeen = 0;
  for (const r of rows) {
    rowsSeen += 1;
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
  return { byVendorId, byName, rowsSeen };
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
 *                     'rule-logging-disabled' | 'window-too-short' |
 *                     'insufficient-history' | 'no-rule-identity'
 *   logGrade          'log-id' | 'log-name' | null   how the log answer was reached
 *   usageGrade        'device' | 'log-id' | 'log-name' | null
 *   deletionEvidence  boolean   ⛔ ONLY 'device' and 'log-id' qualify
 *   effectiveHitCount number | null   the device's own count if it has one,
 *                                     otherwise the logged count
 *   hitCountSource    'device' | 'logs' | null
 *
 * ⛔ `logEvidence` KEPT ITS EXISTING VALUES. The grade is an ADDITIVE field,
 * not a renaming of 'hits' into 'hits-id'/'hits-name' — `ruleAnalysis.js`
 * compares `logEvidence === 'hits'` to decide that a device-reported zero is
 * CONTRADICTED by observed traffic, and splitting the value would have silently
 * disarmed that check. A guard that stops firing because a string moved is this
 * codebase's most expensive shape of mistake.
 *
 * ⛔ `effectiveHitCount` is null whenever neither source can answer. It is
 * never 0 as a stand-in for "we do not know" — that is the bug this whole file
 * exists to avoid repeating.
 */
function enrichRulesWithLogEvidence(rules, coverage, hitMaps) {
  const cov = coverage || null;
  const byVendorId = (hitMaps && hitMaps.byVendorId) || new Map();
  const byName = (hitMaps && hitMaps.byName) || new Map();

  // ⛔ WHAT IDENTITY DO THIS DEVICE'S LOGS ACTUALLY CARRY? Measured on the live
  // fleet 2026-09-25 and it splits completely by vendor:
  //   Fortinet   61,835 rollup rows, rule_id on EVERY one (44 distinct)
  //   Palo Alto  80,203 rollup rows, rule_id NULL on EVERY one — names only
  // So "this rule never appears in the logs" is a far stronger statement on a
  // Fortinet than on a Palo Alto, and the two were previously indistinguishable.
  const logsHaveIds = byVendorId.size > 0;
  // ⛔ PROVEN unable to identify a rule: the device DID produce rule-hit
  // rows and not one of them carried an id or a name. `rowsSeen === 0` is a
  // different and much weaker statement -- it is also what a genuinely idle
  // firewall looks like -- so it must NOT take this branch, or an honestly
  // quiet ruleset could never be reported at all.
  const rowsSeen = Number(hitMaps && hitMaps.rowsSeen) || 0;
  const logsNameNothing = rowsSeen > 0 && byVendorId.size === 0 && byName.size === 0;

  return (rules || []).map((rule) => {
    const deviceHits =
      rule.hit_count === null || rule.hit_count === undefined ? null : Number(rule.hit_count);

    // Vendor id first: it is exact. Name is a fallback and can collide across
    // VDOMs, which is why the id is preferred wherever the vendor supplies one.
    const hasVendorId =
      rule.rule_id_vendor !== null && rule.rule_id_vendor !== undefined
      && String(rule.rule_id_vendor) !== '';

    let match = null;
    let matchGrade = null;
    if (hasVendorId) {
      match = byVendorId.get(String(rule.rule_id_vendor)) || null;
      if (match) matchGrade = 'log-id';
    }
    if (!match && rule.rule_name) {
      match = byName.get(rule.rule_name) || null;
      if (match) matchGrade = 'log-name';
    }

    let loggedHits = null;
    let logEvidence;
    let logGrade = null;
    if (match) {
      loggedHits = match.hits;
      logEvidence = 'hits';
      logGrade = matchGrade;
    } else if (rule.log_enabled === false) {
      // ⛔ The rule cannot appear in a log at all. Its absence measures the
      // logging setting, not the traffic.
      logEvidence = 'rule-logging-disabled';
    } else if (logsNameNothing) {
      // ⛔ THE DEVICE LOGS, BUT ITS LOGS NAME NO RULE — so every rule on it is
      // "absent" and, with good coverage, every one would certify as a measured
      // zero. That is a whole ruleset condemned by a logging FORMAT. Reachable
      // today: PAKFood's single rollup row carries neither a rule id nor a rule
      // name.
      logEvidence = 'no-rule-identity';
    } else if (!cov || !cov.covered) {
      // ⛔ ORDER IS LOAD-BEARING: insufficient history is tested BEFORE the
      // ratio. With 17 days of rollup a 30-day window yields ratio 0.57 on a
      // device that logged every single hour, and reporting that as
      // `no-coverage` blames the firewall for SecVault's own install date.
      logEvidence = (cov && cov.sufficientHistory === false)
        ? 'insufficient-history'
        : (!cov || cov.hoursWithEvents < MIN_WINDOW_HOURS ? 'window-too-short' : 'no-coverage');
    } else {
      // All conditions hold, so zero really is zero.
      loggedHits = 0;
      logEvidence = 'measured-zero';
      // ⛔ AN ABSENCE IS ONLY AS STRONG AS THE IDENTITY WE COULD HAVE SEARCHED
      // BY. Certifying by id needs BOTH: logs that carry ids, and a rule that
      // has one to be looked up under.
      logGrade = (logsHaveIds && hasVendorId) ? 'log-id' : 'log-name';
    }

    const hitCountSource = deviceHits !== null ? 'device' : (loggedHits !== null ? 'logs' : null);
    const effectiveHitCount = deviceHits !== null ? deviceHits : loggedHits;

    // ⛔ THE GRADE, AND THE ONE QUESTION IT EXISTS TO ANSWER.
    //
    //   'device'    the firewall reported its own counter. Strongest.
    //   'log-id'    matched, or proven absent, by the vendor's own rule ID.
    //   'log-name'  by rule NAME only. WEAK — a name is neither unique nor
    //               stable across a config change, so a RENAMED rule reads as
    //               having no traffic while it is busily passing some.
    //   null        not measured.
    //
    // ⛔ `deletionEvidence` is the whole point: a name-grade answer may inform
    // an operator and may NEVER authorise removing a rule from a firewall. The
    // failure it prevents is deleting a live rule because somebody renamed it.
    const usageGrade = deviceHits !== null ? 'device' : logGrade;
    const deletionEvidence = usageGrade === 'device' || usageGrade === 'log-id';

    return Object.assign({}, rule, {
      loggedHits,
      loggedLastHit: match ? match.lastHit : null,
      logEvidence,
      logGrade,
      usageGrade,
      deletionEvidence,
      hitCountSource,
      effectiveHitCount,
      logCoverageRatio: cov ? cov.ratio : null,
      logHistoryHours: cov ? cov.historyHours : null,
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
  const enriched = enrichRulesWithLogEvidence(
    rules,
    coverageMap.get(deviceId) || null,
    hitMaps
  );
  // ⛔ Stamp the window the evidence ACTUALLY covers. The `unused` finding used
  // to render `opts.unusedDays` (default 90) in its detail text while the
  // evidence came from this window (default 30) and could not exceed
  // SYSLOG_RETENTION_DAYS anyway — an operator read "no traffic in 90 days of
  // firewall logs" for a measurement that spanned at most 30. A confident
  // number derived from a shorter measurement is the same error class as
  // hit_count's old DEFAULT 0, moved into the sentence.
  const windowDays = clampDays(days, DEFAULT_WINDOW_DAYS, 400);
  for (const r of enriched) r.logWindowDays = windowDays;
  return enriched;
}

module.exports = {
  getDeviceLogCoverage,
  getLoggedRuleHits,
  enrichRulesWithLogEvidence,
  correlateDeviceRules,
  MIN_WINDOW_HOURS,
  MIN_COVERAGE_RATIO,
};
