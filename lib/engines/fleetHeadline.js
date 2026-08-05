// lib/engines/fleetHeadline.js
//
// The six numbers behind the dashboard's headline stat cards, plus the fleet
// Security Score, gathered in ONE place.
//
// ⛔ WHY THIS FILE EXISTS. These values are needed by two independent callers:
// the dashboard server component (renders them now) and
// services/engine-worker.js's nightly snapshot job (stores them so tomorrow's
// dashboard can show a "vs yesterday" delta). If each computed its own, the
// delta would silently compare two DIFFERENT definitions of the same metric and
// show drift that never happened. One function, both callers.
//
// CommonJS — the engine worker runs under plain node.

'use strict';

const { computeRiskScoreFromCounts } = require('./riskScore');
const { computeSecurityScore } = require('./securityScore');
const { computeFleetComplianceScores } = require('./dashboardSnapshot');

/**
 * Per-device rule-analysis severity counts -> one risk score per device, using
 * the SAME engine the per-device risk pages use. Devices with no analysis rows
 * are absent from the result entirely (not scored 0) so hygieneSubscore can
 * tell "clean ruleset" from "never analysed".
 */
async function getDeviceRiskScores(pool) {
  const { rows } = await pool.query(
    `SELECT rar.device_id,
            COUNT(*) FILTER (WHERE rar.severity = 'critical')::int AS critical,
            COUNT(*) FILTER (WHERE rar.severity = 'high')::int     AS high,
            COUNT(*) FILTER (WHERE rar.severity = 'medium')::int   AS medium,
            COUNT(*) FILTER (WHERE rar.severity = 'info')::int     AS info
       FROM rule_analysis_results rar
       JOIN devices d ON d.id = rar.device_id
      WHERE d.active = true
      GROUP BY rar.device_id`
  );
  // ⛔ computeRiskScoreFromCounts returns {score, band, raw} — NOT a bare
  // number. Passing the object straight through made every element fail
  // hygieneSubscore's Number.isFinite check, so the whole 30%-weighted rule
  // hygiene component silently reported "not measurable" and dropped out of
  // the denominator: the fleet scored purely on vulnerability + compliance
  // while looking completely healthy about it. Caught only by running this
  // against the real fleet before wiring any UI to it.
  return rows.map((r) => computeRiskScoreFromCounts(r).score);
}

/**
 * Device-level CVE exposure. ⛔ Counts DISTINCT DEVICES, not assessments, and
 * the scheduled bucket EXCLUDES any device already counted as patch_now —
 * otherwise one badly-off device is penalized twice by
 * vulnerabilitySubscore().
 */
async function getCveExposure(pool) {
  const { rows } = await pool.query(
    `SELECT
       COUNT(DISTINCT dca.device_id) FILTER (WHERE dca.priority_band = 'patch_now')::int AS devices_patch_now,
       COUNT(DISTINCT dca.device_id) FILTER (
         WHERE dca.priority_band = 'scheduled'
           AND dca.device_id NOT IN (
             SELECT device_id FROM device_cve_assessments WHERE priority_band = 'patch_now'
           )
       )::int AS devices_scheduled,
       COUNT(*) FILTER (WHERE dca.priority_band = 'patch_now')::int AS patch_now_count
     FROM device_cve_assessments dca
     JOIN devices d ON d.id = dca.device_id
     WHERE d.active = true`
  );
  return rows[0] || { devices_patch_now: 0, devices_scheduled: 0, patch_now_count: 0 };
}

async function getDeviceCounts(pool) {
  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE last_connectivity_ok = true)::int AS online
       FROM devices WHERE active = true`
  );
  return rows[0] || { total: 0, online: 0 };
}

async function getRuleCounts(pool) {
  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE fr.enabled = true)::int AS enabled
       FROM firewall_rules fr
       JOIN devices d ON d.id = fr.device_id
      WHERE d.active = true`
  );
  return rows[0] || { total: 0, enabled: 0 };
}

/** Findings that genuinely need a human today — critical + high only. */
async function getHighRiskCount(pool) {
  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS n
       FROM rule_analysis_results rar
       JOIN devices d ON d.id = rar.device_id
      WHERE d.active = true AND rar.severity IN ('critical', 'high')`
  );
  return rows[0]?.n ?? 0;
}

/**
 * Everything the headline row needs, in one round of queries.
 * @returns {Promise<{deviceCount, devicesOnline, rulesTotal, rulesEnabled,
 *   patchNowCount, highRiskCount, complianceScore, securityScore,
 *   securityComponents}>}
 */
async function getFleetHeadline(pool) {
  const [devices, rules, cve, highRisk, riskScores, compliance] = await Promise.all([
    getDeviceCounts(pool),
    getRuleCounts(pool),
    getCveExposure(pool),
    getHighRiskCount(pool),
    getDeviceRiskScores(pool),
    computeFleetComplianceScores(pool),
  ]);

  const security = computeSecurityScore({
    activeDevices: devices.total,
    devicesWithPatchNow: cve.devices_patch_now,
    devicesWithScheduled: cve.devices_scheduled,
    deviceRiskScores: riskScores,
    fleetCompliancePct: compliance.overall,
  });

  return {
    deviceCount: devices.total,
    devicesOnline: devices.online,
    rulesTotal: rules.total,
    rulesEnabled: rules.enabled,
    patchNowCount: cve.patch_now_count,
    highRiskCount: highRisk,
    complianceScore: compliance.overall,
    securityScore: security.score,
    securityComponents: security.components,
  };
}

/**
 * Yesterday's stored headline values, for the "vs yesterday" deltas.
 * ⛔ Returns null when there is no prior row, and each field may itself be null
 * (rows written before v2.53.0 have no headline columns). The caller must show
 * NO delta in that case — never a 0, which reads as "unchanged" when the truth
 * is "unknown".
 */
async function getPreviousHeadline(pool) {
  const { rows } = await pool.query(
    `SELECT device_count, devices_online, rules_total, rules_enabled,
            patch_now_count, high_risk_count, security_score,
            compliance_overall_score, snapshot_date
       FROM fleet_dashboard_snapshots
      WHERE snapshot_date < CURRENT_DATE
      ORDER BY snapshot_date DESC
      LIMIT 1`
  );
  return rows[0] || null;
}

module.exports = {
  getFleetHeadline,
  getPreviousHeadline,
  getDeviceRiskScores,
  getCveExposure,
};
