// lib/engines/versionMatcher.js
//
// Matches devices against advisories for their vendor, producing
// device_cve_assessments rows. See CLAUDE.md "CVE Engine Architecture".
//
// NOTE: config_applies is ALWAYS 'unknown' in Phase 1+2 -- the predicate
// evaluator is Phase 6 scope. Per CLAUDE.md "Applicability Tri-State
// Default", unknown must NEVER default to 'no' (it is treated conservatively
// downstream in prioritization.js).

'use strict';

const { parseVersion, compareVersions, isInRange } = require('./versionComparator');
const { updatePrioritiesForDevice } = require('./prioritization');

/**
 * Pure function: match a single device against a pre-filtered list of
 * advisories (already filtered to advisory.vendor === device.vendor) and a
 * pre-loaded list of vendor_recommended_releases rows for that vendor.
 *
 * @param {object} device - devices row
 * @param {number[]} deviceVersionTuple
 * @param {object[]} advisories - advisories rows (already vendor-filtered)
 * @param {object[]} recommendedReleases - vendor_recommended_releases rows (already vendor-filtered)
 * @returns {object[]} assessment objects, one per advisory where version_affected === true
 */
function matchDeviceToAdvisories(device, deviceVersionTuple, advisories, recommendedReleases) {
  const assessments = [];

  for (const advisory of advisories) {
    let versionAffected = false;
    const ranges = advisory.affected_version_ranges || [];

    for (const range of ranges) {
      const min = range.min !== undefined ? range.min : null;
      const max = range.max !== undefined ? range.max : null;
      const excludeFixed = range.exclude_fixed || [];
      if (isInRange(device.vendor, deviceVersionTuple, min, max, excludeFixed)) {
        versionAffected = true;
        break;
      }
    }

    // Only emit assessment objects for advisories that actually match --
    // skip non-matching advisories entirely.
    if (!versionAffected) {
      continue;
    }

    // config_applies is ALWAYS 'unknown' in Phase 1+2 (predicate evaluator is
    // Phase 6 scope). NEVER default to 'no' -- see CLAUDE.md warning.
    const configApplies = 'unknown';

    const kevListed = !!advisory.kev_listed;

    // Determine fixed_in: nearest fix strictly above the device's current
    // version, from advisory.fixed_in_versions.
    const fixedInCandidates = advisory.fixed_in_versions || [];
    let fixedIn = null;
    let fixedInTuple = null;
    for (const candidate of fixedInCandidates) {
      const candidateTuple = parseVersion(device.vendor, candidate);
      if (compareVersions(candidateTuple, deviceVersionTuple) > 0) {
        if (fixedInTuple === null || compareVersions(candidateTuple, fixedInTuple) < 0) {
          fixedIn = candidate;
          fixedInTuple = candidateTuple;
        }
      }
    }

    // is_fixed_recommended: look up recommendedReleases for an entry whose
    // version (by tuple, not raw string) matches fixed_in and is_recommended.
    let isFixedRecommended = false;
    if (fixedInTuple !== null) {
      for (const rec of recommendedReleases) {
        const recTuple = rec.version_tuple || parseVersion(device.vendor, rec.version);
        if (compareVersions(recTuple, fixedInTuple) === 0 && rec.is_recommended === true) {
          isFixedRecommended = true;
          break;
        }
      }
    }

    assessments.push({
      device_id: device.id,
      advisory_id: advisory.id,
      version_affected: true,
      config_applies: configApplies,
      kev_listed: kevListed,
      fixed_in: fixedIn,
      is_fixed_recommended: isFixedRecommended,
    });
  }

  return assessments;
}

/**
 * Run the version-match engine against all active devices, upsert the
 * resulting device_cve_assessments rows, and recompute priority bands for
 * each device immediately after matching (per CLAUDE.md, the engine
 * auto-runs prioritization after each match).
 *
 * @param {import('pg').Pool} pool
 * @returns {Promise<{assessed: number, matched_cves: number, errors: object[]}>}
 */
async function runMatchForAllDevices(pool) {
  const errors = [];
  let assessed = 0;
  let matchedCves = 0;

  const { rows: devices } = await pool.query('SELECT * FROM devices WHERE active = true');

  for (const device of devices) {
    try {
      const { rows: versionRows } = await pool.query(
        'SELECT * FROM device_versions WHERE device_id = $1 ORDER BY collected_at DESC LIMIT 1',
        [device.id]
      );

      if (versionRows.length === 0) {
        errors.push({ device_id: device.id, error: 'no version row - skipped' });
        continue;
      }

      const versionRow = versionRows[0];
      const deviceVersionTuple = parseVersion(device.vendor, versionRow.version_string);

      const { rows: advisories } = await pool.query(
        'SELECT * FROM advisories WHERE vendor = $1',
        [device.vendor]
      );

      const { rows: recommendedReleases } = await pool.query(
        'SELECT * FROM vendor_recommended_releases WHERE vendor = $1',
        [device.vendor]
      );

      const assessments = matchDeviceToAdvisories(
        device,
        deviceVersionTuple,
        advisories,
        recommendedReleases
      );

      for (const a of assessments) {
        await pool.query(
          `INSERT INTO device_cve_assessments
             (device_id, advisory_id, version_affected, config_applies, kev_listed, fixed_in, is_fixed_recommended, assessed_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7, now())
           ON CONFLICT (device_id, advisory_id) DO UPDATE SET
             version_affected = EXCLUDED.version_affected,
             config_applies = EXCLUDED.config_applies,
             kev_listed = EXCLUDED.kev_listed,
             fixed_in = EXCLUDED.fixed_in,
             is_fixed_recommended = EXCLUDED.is_fixed_recommended,
             assessed_at = now()`,
          [
            a.device_id,
            a.advisory_id,
            a.version_affected,
            a.config_applies,
            a.kev_listed,
            a.fixed_in,
            a.is_fixed_recommended,
          ]
        );
        matchedCves += 1;
      }

      // Recompute priority bands for this device immediately after matching.
      await updatePrioritiesForDevice(device.id, pool);

      assessed += 1;
    } catch (err) {
      errors.push({ device_id: device.id, error: err.message });
    }
  }

  return { assessed, matched_cves: matchedCves, errors };
}

module.exports = {
  matchDeviceToAdvisories,
  runMatchForAllDevices,
};
