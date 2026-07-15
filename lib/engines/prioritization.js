// lib/engines/prioritization.js
//
// Priority band decision tree. Source of truth: CLAUDE.md "CVE Engine
// Architecture" > "Priority Decision Tree (strict order - do not reorder)".
// ANY CHANGE TO THIS LOGIC MUST BE DOCUMENTED IN CLAUDE.md FIRST.

'use strict';

const BAND_RANK = { monitor: 0, scheduled: 1, patch_now: 2 };
const RANK_BAND = ['monitor', 'scheduled', 'patch_now'];

/**
 * Compute the priority band for a single device/advisory assessment.
 *
 * Decision tree (exact order, per CLAUDE.md -- do not reorder):
 *   1. kev_listed=true AND version_affected=true AND config_applies!='no' -> patch_now
 *   2. log_hit=true AND version_affected=true AND config_applies!='no'    -> patch_now
 *   3. cvssScore>=9.0 AND version_affected=true AND config_applies='yes' -> patch_now
 *   4. cvssScore>=7.0 AND version_affected=true AND config_applies='yes':
 *        is_fixed_recommended=true  -> scheduled
 *        is_fixed_recommended=false -> monitor
 *   5. version_affected=true AND config_applies='unknown'                -> scheduled
 *   6. all others                                                        -> monitor
 *
 * Then apply the asset criticality modifier: if device.asset_criticality
 * === 'critical', bump one band up (monitor -> scheduled, scheduled ->
 * patch_now; patch_now stays patch_now).
 *
 * @param {{kev_listed: boolean, version_affected: boolean, config_applies: string, log_hit: boolean, is_fixed_recommended: boolean}} assessment
 * @param {{asset_criticality: string}} device
 * @param {number|null} cvssScore
 * @returns {'patch_now'|'scheduled'|'monitor'}
 */
function computePriority(assessment, device, cvssScore) {
  const { kev_listed, version_affected, config_applies, log_hit, is_fixed_recommended } = assessment;
  const score = cvssScore === null || cvssScore === undefined ? 0 : Number(cvssScore);

  let band;

  // 1. KEV-listed
  if (kev_listed === true && version_affected === true && config_applies !== 'no') {
    band = 'patch_now';
  }
  // 2. Log hit (exploitation observed)
  else if (log_hit === true && version_affected === true && config_applies !== 'no') {
    band = 'patch_now';
  }
  // 3. Critical CVSS, confirmed applicable config
  else if (score >= 9.0 && version_affected === true && config_applies === 'yes') {
    band = 'patch_now';
  }
  // 4. High CVSS, confirmed applicable config
  else if (score >= 7.0 && version_affected === true && config_applies === 'yes') {
    band = is_fixed_recommended === true ? 'scheduled' : 'monitor';
  }
  // 5. Affected but applicability unknown -- treated conservatively
  else if (version_affected === true && config_applies === 'unknown') {
    band = 'scheduled';
  }
  // 6. Everything else
  else {
    band = 'monitor';
  }

  // Asset criticality modifier: bump one band up for critical assets.
  if (device && device.asset_criticality === 'critical') {
    const rank = BAND_RANK[band];
    const bumpedRank = Math.min(rank + 1, BAND_RANK.patch_now);
    band = RANK_BAND[bumpedRank];
  }

  return band;
}

/**
 * Recompute and persist priority_band for every device_cve_assessments row
 * belonging to a device.
 *
 * @param {string} deviceId
 * @param {import('pg').Pool} pool
 */
async function updatePrioritiesForDevice(deviceId, pool) {
  const { rows: assessmentRows } = await pool.query(
    `SELECT dca.*, a.cvss_score
     FROM device_cve_assessments dca
     JOIN advisories a ON a.id = dca.advisory_id
     WHERE dca.device_id = $1`,
    [deviceId]
  );

  const { rows: deviceRows } = await pool.query(
    'SELECT asset_criticality FROM devices WHERE id = $1',
    [deviceId]
  );
  const device = deviceRows[0] || { asset_criticality: null };

  for (const row of assessmentRows) {
    const band = computePriority(row, device, row.cvss_score);
    await pool.query('UPDATE device_cve_assessments SET priority_band = $1 WHERE id = $2', [
      band,
      row.id,
    ]);
  }
}

module.exports = {
  computePriority,
  updatePrioritiesForDevice,
};
