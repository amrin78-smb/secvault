// lib/engines/exposureCorrelation.js
//
// "Path A" rule-analysis intelligence round, item 1: correlates
// already-computed rule_analysis_results findings with already-computed
// device_cve_assessments (patch_now CVEs) for the SAME device. This is the
// headline differentiator competitive research (Tufin, FireMon) attributes
// to "intelligent" policy platforms -- config analysis correlated with
// vulnerability/exposure data -- and it needs ZERO new data sources here:
// SecVault already runs a rule-hygiene engine (ruleAnalysis.js) and a CVE
// prioritization engine (versionMatcher.js/prioritization.js) completely
// independently. This file is the join that was never built between them.
//
// Deliberately COMPUTED AT READ TIME, never stored as a new table/column --
// same convention as riskScore.js's computeRiskScore()/configAuditor.js's
// scorePctFromCounts(). rule_analysis_results and device_cve_assessments are
// refreshed on two INDEPENDENT schedules (rule analysis: every rule pull or
// manual "Run Analysis"; CVE assessment: every feed sync, or a
// config-change-triggered re-match) -- storing a derived join would need its
// own staleness/invalidation model for no real benefit. A live join is
// always accurate as of the two inputs' own last-refresh times, and it's
// cheap: bounded by (exposure findings on the device) x (patch_now CVEs on
// the device), not the O(n^2) rule-pair cost ruleAnalysis.js itself has to
// manage.
//
// CommonJS only, per this codebase's lib/*.js convention (consumed by both
// Next.js App Router routes/pages and, potentially, services/engine-worker.js
// in the future).

'use strict';

// Only finding types that describe a WIDENED attack surface belong here --
// this is specifically an exposure correlation, not a general rule-hygiene
// one. shadow/redundant/correlation/generalization/unused/expiring_soon/
// log_disabled are ruleset-cleanliness concerns, not exposure concerns, and
// deliberately excluded: pairing them with a device's CVE posture wouldn't
// mean anything (e.g. "this rule is a byte-for-byte duplicate" says nothing
// about whether the device is more or less reachable/exploitable).
const EXPOSURE_FINDING_TYPES = ['any_any', 'overly_permissive', 'risky_service'];

/**
 * For one device, return every open exposure-widening rule finding
 * (any_any / overly_permissive / risky_service) paired with that SAME
 * device's open patch_now CVE assessments.
 *
 * This is a DEVICE-LEVEL correlation, not a claim that a specific rule and a
 * specific CVE target the identical service/port -- no such mapping exists
 * anywhere in this codebase's data model (device_cve_assessments has no
 * concept of "which port/service is vulnerable", only "this device's
 * installed version is affected by this CVE"). The finding is: "this rule
 * widens what can reach this box, and this same box also has an actively
 * relevant, unpatched vulnerability" -- which is exactly how Tufin/FireMon's
 * own exposure-context risk scoring is described in the competitive
 * research this feature is built from (correlate policy with vulnerability
 * data to prioritize cleanup around actual exposure), not a per-port claim.
 *
 * Returns [] (never throws) when the device has no exposure findings or no
 * open patch_now CVEs -- both are the ordinary, common case, not an error.
 *
 * @param {string} deviceId
 * @param {import('pg').Pool} pool
 * @returns {Promise<{
 *   finding: {id: string, rule_id: string, finding_type: string, severity: string, detail: string},
 *   cves: {advisory_id: string, cve_id: string, cvss_score: number|null, kev_listed: boolean, advisory_url: string|null}[]
 * }[]>}
 */
async function getExposureCorrelationForDevice(deviceId, pool) {
  const { rows: findings } = await pool.query(
    `SELECT id, rule_id, finding_type, severity, detail
     FROM rule_analysis_results
     WHERE device_id = $1 AND finding_type = ANY($2::text[])
     ORDER BY
       CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
       analyzed_at DESC`,
    [deviceId, EXPOSURE_FINDING_TYPES]
  );
  if (findings.length === 0) return [];

  const { rows: cves } = await pool.query(
    `SELECT dca.advisory_id, a.cve_id, a.cvss_score, dca.kev_listed, a.advisory_url
     FROM device_cve_assessments dca
     JOIN advisories a ON a.id = dca.advisory_id
     WHERE dca.device_id = $1 AND dca.priority_band = 'patch_now'
     ORDER BY dca.kev_listed DESC, a.cvss_score DESC NULLS LAST`,
    [deviceId]
  );
  if (cves.length === 0) return [];

  const cveList = cves.map((c) => ({
    advisory_id: c.advisory_id,
    cve_id: c.cve_id,
    cvss_score: c.cvss_score === null ? null : Number(c.cvss_score),
    kev_listed: c.kev_listed,
    advisory_url: c.advisory_url,
  }));

  return findings.map((f) => ({
    finding: {
      id: f.id,
      rule_id: f.rule_id,
      finding_type: f.finding_type,
      severity: f.severity,
      detail: f.detail,
    },
    cves: cveList,
  }));
}

/**
 * Fleet-wide count of devices carrying at least one exposure/CVE
 * correlation, for a dashboard-style summary tile. Cheap: COUNT DISTINCT
 * over an inner join, not N per-device calls.
 *
 * @param {import('pg').Pool} pool
 * @returns {Promise<number>}
 */
async function countDevicesWithExposureCorrelation(pool) {
  const { rows } = await pool.query(
    `SELECT COUNT(DISTINCT rar.device_id)::int AS count
     FROM rule_analysis_results rar
     JOIN device_cve_assessments dca
       ON dca.device_id = rar.device_id AND dca.priority_band = 'patch_now'
     JOIN devices d ON d.id = rar.device_id AND d.active = true
     WHERE rar.finding_type = ANY($1::text[])`,
    [EXPOSURE_FINDING_TYPES]
  );
  return rows.length > 0 ? rows[0].count : 0;
}

module.exports = {
  EXPOSURE_FINDING_TYPES,
  getExposureCorrelationForDevice,
  countDevicesWithExposureCorrelation,
};
