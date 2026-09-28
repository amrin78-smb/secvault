'use strict';

// lib/engines/remediationVelocityData.js
//
// A8 plumbing. The judgement lives in `remediationVelocity.js`, which is pure;
// this file only fetches and shapes. Same split as A7 and segmentation, for the
// same reason: the judgement is the value, so the judgement has to be testable
// without a database.
//
// ── ⛔ A REMEDIATED EXPOSURE IS DELETED, SO IT MUST BE RECONSTRUCTED ──────
//
// `device_cve_assessments` is DELETE+reinserted on every match run. A device
// that moves onto a fixed version simply STOPS HAVING A ROW — the evidence that
// an exposure ever existed, and that it closed, is gone. So the obvious query
// ("assessments that disappeared") cannot be written at all, and an engine fed
// only from that table would see nothing but open exposures forever and report
// a 0% remediation rate that is an ARTEFACT OF THE SCHEMA rather than a fact
// about the fleet.
//
// The events are therefore reconstructed from `device_versions`, which IS
// append-only history: a device observed on an affected version at T1 and on a
// non-affected version at T2 remediated in between. We date the event at T2, the
// first observation of the fixed version, and say so — the true moment lies in
// (T1, T2] and our collection interval is the resolution, exactly as
// `vpn_sessions` bounds a session end by its poll interval.
//
// ⛔ ON THIS FLEET THAT RECONSTRUCTION CURRENTLY YIELDS NOTHING, AND THE
// DISTINCTION STILL MATTERS. Measured 2026-09-28: 3,954 version rows, 16
// devices, 16 distinct (device, version) pairs — not one firewall has changed
// version in 74 days. The 0% is real. But it is only KNOWN to be real because
// this path exists to have found an event if there had been one; without it the
// same 0% would have been unfalsifiable.
//
// ⛔ AND IT IS BOUNDED BY WHAT THE FEED STILL HOLDS. If a device moved off an
// affected version AND the advisory later left the corpus, the exposure is
// invisible to us. That is a coverage gap, reported in `caveats`, never
// silently folded into the denominator.

const { isInRange, parseVersion } = require('./versionComparator');
const { buildExposure, summariseVelocity, velocityHeadline } = require('./remediationVelocity');

// ⛔ ONLY `version_affected` EXPOSURES. An advisory that never applied to the
// running version was never an exposure, and counting it would dilute the
// denominator with work that did not exist.
const OPEN_EXPOSURES_SQL = `
  SELECT /* rv:open */
    dca.device_id,
    d.name  AS device_name,
    a.cve_id,
    a.kev_listed,
    dca.priority_band,
    a.cvss_score,
    a.published_at   AS advisory_published_at,
    a.created_at     AS advisory_known_at,
    dv.first_seen_at AS device_first_seen_at
  FROM device_cve_assessments dca
  JOIN advisories a ON a.id = dca.advisory_id
  JOIN devices d ON d.id = dca.device_id
  JOIN (
    SELECT device_id, min(collected_at) AS first_seen_at
      FROM device_versions GROUP BY device_id
  ) dv ON dv.device_id = dca.device_id
  WHERE dca.version_affected = true
    AND d.active = true`;

// The append-only half: every distinct version a device has been observed on,
// with when it was first and last seen.
const VERSION_HISTORY_SQL = `
  SELECT /* rv:versions */
    v.device_id, d.name AS device_name, d.vendor,
    v.version_string,
    min(v.collected_at) AS first_seen_at,
    max(v.collected_at) AS last_seen_at
  FROM device_versions v
  JOIN devices d ON d.id = v.device_id
  WHERE d.active = true AND v.version_string IS NOT NULL
  GROUP BY v.device_id, d.name, d.vendor, v.version_string
  ORDER BY v.device_id, min(v.collected_at)`;

// Advisories with usable ranges, for testing a historical version against.
const ADVISORY_RANGES_SQL = `
  SELECT /* rv:advisories */
    a.id, a.cve_id, a.vendor, a.kev_listed, a.cvss_score,
    a.published_at, a.created_at, a.affected_version_ranges
  FROM advisories a
  WHERE a.matchability = 'matched'
    AND jsonb_typeof(a.affected_version_ranges) = 'array'
    AND jsonb_array_length(a.affected_version_ranges) > 0`;

/** Does this advisory cover this version string? Reuses isInRange UNCHANGED. */
function advisoryCovers(vendor, versionString, ranges) {
  const tuple = parseVersion(vendor, versionString);
  // ⛔ parseVersion RETURNS FABRICATED ZEROS for an unparseable string, so an
  // unreadable version would test as 0.0.0 and match any range starting at 0.
  // CLAUDE.md flags this as a property of parseVersion that call sites inherit.
  if (!Array.isArray(tuple) || !/\d/.test(String(versionString || ''))) return null;
  const list = Array.isArray(ranges) ? ranges : [];
  if (list.length === 0) return null;
  for (const r of list) {
    if (!r || typeof r !== 'object') continue;
    const min = r.min === undefined ? null : r.min;
    const max = r.max === undefined ? null : r.max;
    const safe = Array.isArray(r.safe_exact_versions) ? r.safe_exact_versions : [];
    if (isInRange(vendor, tuple, min, max, r.exclude_fixed === true, safe)) return true;
  }
  return false;
}

/**
 * Remediation events reconstructed from version history.
 *
 * ⛔ AN UNREADABLE VERSION ON EITHER SIDE PRODUCES NO EVENT, NOT A REMEDIATION.
 * `advisoryCovers` returns null when it cannot tell, and a null is skipped —
 * concluding "no longer affected" from a version we could not parse would
 * manufacture a remediation that never happened, which on this page is the
 * flattering direction and therefore the dangerous one.
 */
function findRemediationEvents(historyRows, advisories) {
  const byDevice = new Map();
  for (const h of Array.isArray(historyRows) ? historyRows : []) {
    if (!h || !h.device_id) continue;
    if (!byDevice.has(h.device_id)) byDevice.set(h.device_id, []);
    byDevice.get(h.device_id).push(h);
  }

  const events = [];
  const advList = Array.isArray(advisories) ? advisories : [];

  for (const [deviceId, versions] of byDevice) {
    if (versions.length < 2) continue;   // no transition, nothing to observe
    const ordered = versions.slice().sort((a, b) =>
      new Date(a.first_seen_at) - new Date(b.first_seen_at));

    for (let i = 1; i < ordered.length; i++) {
      const before = ordered[i - 1];
      const after = ordered[i];
      const vendor = after.vendor || before.vendor;
      for (const a of advList) {
        if (a.vendor && vendor && a.vendor !== vendor) continue;
        const wasAffected = advisoryCovers(vendor, before.version_string, a.affected_version_ranges);
        const nowAffected = advisoryCovers(vendor, after.version_string, a.affected_version_ranges);
        if (wasAffected !== true || nowAffected !== false) continue;
        events.push({
          device_id: deviceId,
          device_name: after.device_name || before.device_name || null,
          cve_id: a.cve_id,
          kev_listed: a.kev_listed === true,
          priority_band: null,          // the band is gone with the assessment row
          cvss_score: a.cvss_score,
          advisory_published_at: a.published_at,
          advisory_known_at: a.created_at,
          device_first_seen_at: ordered[0].first_seen_at,
          // ⛔ DATED AT THE FIRST OBSERVATION OF THE FIXED VERSION. The true
          // moment is somewhere in (before.last_seen_at, after.first_seen_at];
          // our collection interval is the resolution and this is the LATE end,
          // so a reported time-to-remediate is an OVER-estimate here while the
          // open ages are UNDER-estimates. Both err away from flattering us.
          remediated_at: after.first_seen_at,
          remediation_dated_from: 'first_observation_of_fixed_version',
        });
      }
    }
  }
  return events;
}

async function safeQuery(pool, sql, label, failures) {
  try {
    const res = await pool.query(sql);
    return (res && res.rows) || [];
  } catch (err) {
    // ⛔ REPORTED, NEVER SWALLOWED. A failed read here shortens the exposure
    // list, and a shorter list on this page reads as a better-performing fleet.
    failures.push({ source: label, error: err && err.message ? err.message : String(err) });
    return null;
  }
}

/**
 * The whole fleet's remediation velocity.
 *
 * ⛔ A FAILED READ IS NOT AN EMPTY FLEET. Any failure leaves `ok: false` and the
 * summary null; no consumer may render a velocity figure while `failures` is
 * non-empty, the rule `coverageRegister` follows.
 */
async function getRemediationVelocity(pool, opts) {
  const o = opts || {};
  const now = o.now instanceof Date ? o.now : new Date();
  const failures = [];

  const openRows = await safeQuery(pool, OPEN_EXPOSURES_SQL, 'open_exposures', failures);
  const history = await safeQuery(pool, VERSION_HISTORY_SQL, 'version_history', failures);
  const advisories = await safeQuery(pool, ADVISORY_RANGES_SQL, 'advisory_ranges', failures);

  if (openRows === null || history === null || advisories === null) {
    return {
      ok: false,
      failures,
      exposures: [],
      summary: null,
      headline: null,
      caveats: [],
      generatedAt: now,
    };
  }

  const events = findRemediationEvents(history, advisories);
  const exposures = openRows.concat(events).map((r) => buildExposure(r, now));
  const summary = summariseVelocity(exposures, now);

  // ⛔ THE CAVEATS ARE PART OF THE ANSWER, NOT DECORATION. Each names a way the
  // measurement is bounded, so a reader cannot take the headline as complete.
  const versionsPerDevice = new Map();
  for (const h of history) {
    versionsPerDevice.set(h.device_id, (versionsPerDevice.get(h.device_id) || 0) + 1);
  }
  const devicesWithHistory = versionsPerDevice.size;
  // A device with two or more DISTINCT versions has been observed moving. On
  // this fleet that count is 0, which is the finding.
  const devicesWithTransition =
    [...versionsPerDevice.values()].filter((n) => n > 1).length;

  const caveats = [
    {
      key: 'remediations_are_reconstructed',
      text: 'A remediated exposure leaves no record of its own — the assessment row is rewritten '
        + 'on every run — so remediations are reconstructed from collected version history. An '
        + 'exposure that closed while its advisory also left the feed is not visible here.',
    },
    {
      key: 'ages_are_lower_bounds',
      text: 'Every open age is measured from the later of the advisory reaching SecVault and the '
        + 'firewall first being collected from. A firewall may have run an affected version long '
        + 'before either, so these are minimums.',
    },
  ];
  if (devicesWithTransition === 0 && devicesWithHistory > 0) {
    caveats.push({
      key: 'no_transitions_observed',
      text: `No firewall has been observed changing version at all (${devicesWithHistory} with `
        + 'version history), so this fleet has produced no remediation events to measure. The '
        + 'rate is 0% because nothing was patched, not because nothing was looked for.',
    });
  }

  return {
    ok: true,
    failures,
    exposures,
    summary,
    headline: velocityHeadline(summary),
    caveats,
    coverage: {
      devicesWithVersionHistory: devicesWithHistory,
      devicesWithAVersionChange: devicesWithTransition,
      advisoriesTestable: advisories.length,
      reconstructedEvents: events.length,
    },
    generatedAt: now,
  };
}

module.exports = {
  getRemediationVelocity,
  findRemediationEvents,
  advisoryCovers,
  OPEN_EXPOSURES_SQL,
  VERSION_HISTORY_SQL,
  ADVISORY_RANGES_SQL,
};
