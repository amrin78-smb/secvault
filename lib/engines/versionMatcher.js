// lib/engines/versionMatcher.js
//
// Matches devices against advisories for their vendor, producing
// device_cve_assessments rows. See CLAUDE.md "CVE Engine Architecture".
//
// Phase 6: config_applies is now computed by the applicability predicate
// engine (lib/engines/applicability.js) against the device's latest parsed
// config. Per CLAUDE.md "Applicability Tri-State Default", when no
// advisory_conditions rows exist for an advisory — or no config has been
// collected yet — the result is 'unknown', NEVER 'no' (unknown is treated
// conservatively downstream in prioritization.js).

'use strict';

const { parseVersion, compareVersions, isInRange } = require('./versionComparator');
const { updatePrioritiesForDevice } = require('./prioritization');
const {
  loadConditionsByAdvisory,
  getLatestConfigParsed,
  computeConfigApplies,
} = require('./applicability');

// ────────────────────────────────────────────────────────────────────────
// UNASSESSABLE ADVISORIES — `advisories.matchability`
//
// ⛔ THE PROBLEM THIS SOLVES. The loop below does `if (!versionAffected) continue;`, and
// `versionAffected` is derived purely from `affected_version_ranges`. An EMPTY range list is
// therefore indistinguishable from "every range was evaluated and none matched" — so an
// advisory whose ranges could not be EXTRACTED (a failed read at ingest time) was consumed
// here as an affirmative "this device is not affected". That is CLAUDE.md's "a failed read is
// NOT a measurement" rule, one layer in from `hit_count` and `getRules()`.
//
// `advisories.matchability` = 'unmatchable' is the ingest pipeline's own record that it could
// not extract a bound from a record that DECLARES this product affected (see
// lib/feeds/nvd.js's classifyCveRecordMatchability / classifyNvdNativeMatchability).
//
// ⛔ THE DECISION, and why it is not "assume affected". There are exactly three things this
// engine could do with such an advisory, and two of them fabricate:
//   - emit version_affected=true  → fabricates a vulnerability on a device that may well be
//     patched. device_cve_assessments has no third state (the column is BOOLEAN NOT NULL), so
//     there is no way to store "we do not know" in a row that exists.
//   - let it fall through           → what happens today: it silently joins the not-affected
//     pile and the device reads assessed-and-clean. This is the bug.
//   - SKIP IT, AND COUNT IT         → what this does. The advisory produces no assessment (we
//     genuinely cannot evaluate it), but the run reports how many advisories it could not
//     evaluate per device, so "we could not assess N of this vendor's advisories" is a number
//     the fleet can show instead of a silence. Skipping without counting would be the same
//     lie as before, just deliberate.
//
// ⛔ NULL is NOT unassessable. NULL means "ingested before this column existed and not yet
// reclassified" — lib/migrate.js's backfill fills it from each row's own raw_data. Treating
// NULL as unassessable would make every pre-column advisory vanish from matching on the first
// deploy, which is a far larger and much more silent change than the bug being fixed.
// 'other_product' is likewise left alone: an advisory about somebody else's product genuinely
// has nothing to say about this device, and its empty range list is an answer, not a failed
// read.
const UNASSESSABLE_MATCHABILITY = 'unmatchable';

function isUnassessableAdvisory(advisory) {
  return !!advisory && advisory.matchability === UNASSESSABLE_MATCHABILITY;
}

/**
 * How many of these advisories could not be evaluated at all. Pure; the counterpart of the
 * skip inside matchDeviceToAdvisories, kept as its own export so callers count with exactly
 * the same predicate the matcher skips on rather than a second, driftable copy of the rule.
 *
 * @param {object[]} advisories
 * @returns {number}
 */
function countUnassessableAdvisories(advisories) {
  return (advisories || []).filter(isUnassessableAdvisory).length;
}

/**
 * Pure function: match a single device against a pre-filtered list of
 * advisories (already filtered to advisory.vendor === device.vendor) and a
 * pre-loaded list of vendor_recommended_releases rows for that vendor.
 *
 * @param {object} device - devices row
 * @param {number[]} deviceVersionTuple
 * @param {object[]} advisories - advisories rows (already vendor-filtered)
 * @param {object[]} recommendedReleases - vendor_recommended_releases rows (already vendor-filtered)
 * @param {{conditionsByAdvisory: Map<string, object[]>, configParsed: object|null}|null} applicability
 *   Optional pre-loaded applicability context. When null (e.g. legacy callers),
 *   config_applies falls back to 'unknown' for every assessment.
 * @returns {object[]} assessment objects, one per advisory where version_affected === true
 */
function matchDeviceToAdvisories(device, deviceVersionTuple, advisories, recommendedReleases, applicability = null) {
  const assessments = [];

  for (const advisory of advisories) {
    // ⛔ See UNASSESSABLE_MATCHABILITY above. This advisory's ranges are empty because
    // extraction FAILED, not because it was evaluated and missed — falling through to
    // `if (!versionAffected) continue;` would launder that failed read into "not affected".
    // It is skipped here and COUNTED by the caller, never assessed either way.
    if (isUnassessableAdvisory(advisory)) continue;

    let versionAffected = false;
    const ranges = advisory.affected_version_ranges || [];

    for (const range of ranges) {
      const min = range.min !== undefined ? range.min : null;
      const max = range.max !== undefined ? range.max : null;
      const maxExclusive = !!range.exclude_fixed;
      // safe_exact_versions: named per-hotfix-train fix checkpoints (see
      // isInRange/isSafeOnMatchingTrain in versionComparator.js) — populated
      // by feed extractors when a CVE's changes[] timeline names multiple
      // independently-patched trains; absent/undefined for ranges that don't
      // have one (e.g. a plain NVD versionEndExcluding range), which is fully
      // backward compatible (isInRange treats it as "no effect").
      const safeCheckpoints = Array.isArray(range.safe_exact_versions) ? range.safe_exact_versions : [];
      if (isInRange(device.vendor, deviceVersionTuple, min, max, maxExclusive, safeCheckpoints)) {
        versionAffected = true;
        break;
      }
    }

    // Only emit assessment objects for advisories that actually match --
    // skip non-matching advisories entirely.
    if (!versionAffected) {
      continue;
    }

    // Phase 6 applicability: evaluate this advisory's curated predicates
    // against the device's latest parsed config. computeConfigApplies returns
    // 'unknown' when there are no conditions or no config — NEVER 'no' by
    // default (see CLAUDE.md warning).
    const configApplies = applicability
      ? computeConfigApplies(
          applicability.conditionsByAdvisory.get(String(advisory.id)) || [],
          applicability.configParsed
        )
      : 'unknown';

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
 * ⛔ The summary now also reports `unassessable_advisories` (fleet total) and
 * `unassessable_by_device` — advisories this run could not evaluate AT ALL for that device
 * (see UNASSESSABLE_MATCHABILITY above). They are deliberately NOT in `errors`: nothing
 * failed during this run, the gap was recorded at ingest time. But they must not be silent
 * either, because the alternative reading of a device with zero assessments is "clean".
 *
 * @param {import('pg').Pool} pool
 * @returns {Promise<{assessed: number, matched_cves: number, unassessable_advisories: number,
 *   unassessable_by_device: object[], errors: object[]}>}
 */
async function runMatchForAllDevices(pool) {
  const errors = [];
  let assessed = 0;
  let matchedCves = 0;
  let unassessableTotal = 0;
  const unassessableByDevice = [];

  const { rows: devices } = await pool.query('SELECT * FROM devices WHERE active = true');

  // advisory_conditions rarely change between devices of the same vendor —
  // load them once per vendor, not once per device.
  const conditionsCacheByVendor = new Map();

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

      // Counted with the SAME predicate matchDeviceToAdvisories skips on, so the two can
      // never disagree about what was left unevaluated.
      const unassessable = countUnassessableAdvisories(advisories);
      if (unassessable > 0) {
        unassessableTotal += unassessable;
        unassessableByDevice.push({
          device_id: device.id,
          name: device.name || null,
          vendor: device.vendor,
          unassessable_advisories: unassessable,
          vendor_advisories: advisories.length,
        });
        // ⛔ Logged at WARN, not debug: on this fleet a single cisco_asa device can carry 257
        // of these, and a device whose vendor corpus is mostly unassessable is one whose "0
        // CVEs" reading means far less than it appears to.
        console.warn(
          `[versionMatcher] ${device.name || device.id} (${device.vendor}): ` +
            `${unassessable} of ${advisories.length} advisories could NOT be evaluated ` +
            '(matchability=unmatchable — ranges were never extractable). They are excluded ' +
            'from this assessment rather than counted as "not affected".'
        );
      }

      if (!conditionsCacheByVendor.has(device.vendor)) {
        conditionsCacheByVendor.set(device.vendor, await loadConditionsByAdvisory(pool, device.vendor));
      }

      const applicability = {
        conditionsByAdvisory: conditionsCacheByVendor.get(device.vendor),
        configParsed: await getLatestConfigParsed(device.id, pool),
      };

      const assessments = matchDeviceToAdvisories(
        device,
        deviceVersionTuple,
        advisories,
        recommendedReleases,
        applicability
      );

      // ⛔ Reconciliation — found missing in a full-app audit (2026-07-16).
      // matchDeviceToAdvisories() only EMITS a row for advisories still
      // affected (see its own "skip non-matching advisories entirely"
      // comment) — it never signals which PREVIOUSLY-matched advisories no
      // longer apply. Without this delete, a device patched out of a CVE's
      // vulnerable range keeps its stale device_cve_assessments row
      // (version_affected=true, priority_band='patch_now') forever: nothing
      // else in this file, or in prioritization.js (which recomputes
      // priority_band from the row's ALREADY-STORED version_affected, never
      // re-deriving it), or in engine-worker.js's callers ever revisits it.
      // The fleet/per-device CVE views query this table directly with no
      // freshness filter, so a resolved CVE would display as needing to be
      // patched indefinitely — a permanent false positive.
      //
      // `<> ALL($2::uuid[])` is correct even when assessments is empty: ALL
      // over an empty array is vacuously true, so an empty array clears
      // every existing row for this device (device is vendor-matched against
      // zero advisories currently, e.g. mid feed-sync) — the same "delete
      // what's no longer current" semantics as firewall_rules' pull-time
      // rewrite, just as an UPSERT+prune instead of a full DELETE+reinsert
      // (assessments is typically a small subset of all advisories, so
      // upserting only the current matches and pruning the rest is cheaper
      // than rewriting everything every run).
      const currentAdvisoryIds = assessments.map((a) => a.advisory_id);

      // ⛔ Concurrency guard — found in a follow-up bug sweep (2026-07-17).
      // runMatchForAllDevices() has THREE independent call sites that can run
      // concurrently for the same device: the "Assess Now" button
      // (app/api/cve/assess/route.js), the scheduled feed-sync-and-match job,
      // and the config-change-triggered re-match (both in
      // services/engine-worker.js). With no locking, two overlapping runs
      // reading device_versions/advisories at different instants can race:
      // a run computed from stale data can DELETE+INSERT AFTER a newer run
      // already correctly removed a since-patched CVE's row, resurrecting a
      // stale 'patch_now' assessment. A per-device pg_advisory_xact_lock
      // (auto-released at COMMIT/ROLLBACK, so a crash can't leave it held)
      // serializes the write phase per device across every call site. The
      // reads above stay unlocked (cheap, and staleness there just means
      // picking up slightly older source data, not a correctness bug) —
      // only DELETE+INSERT+prioritization is now atomic per device.
      let client = null;
      try {
        client = await pool.connect();
        try {
          await client.query('BEGIN');
          // hashtext() returns int4; pg_advisory_xact_lock(bigint) accepts it
          // via the standard implicit int4->int8 widening — no cast needed.
          await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [device.id]);

          await client.query(
            'DELETE FROM device_cve_assessments WHERE device_id = $1 AND advisory_id <> ALL($2::uuid[])',
            [device.id, currentAdvisoryIds]
          );

          for (const a of assessments) {
            await client.query(
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

          // Recompute priority bands for this device immediately after
          // matching, on the SAME connection/transaction so the lock covers
          // this write too.
          await updatePrioritiesForDevice(device.id, client);

          // ⛔ STAMP THE RUN, NOT ITS OUTPUT. Added 2026-09-09.
          // device_cve_assessments cannot answer "was this device assessed?":
          // matchDeviceToAdvisories() emits rows only for advisories that
          // still apply and the reconciliation DELETE above removes the rest,
          // so a device assessed and found CLEAN ends the transaction holding
          // ZERO rows — indistinguishable, from the output alone, from one
          // that has never been assessed. Both then render as a confident `0`
          // on /devices. Persisting the fact that the run completed is the
          // only thing that separates them.
          //
          // ⛔ THIS EXACT POSITION IS THE POINT. It is:
          //   - INSIDE the transaction and the per-device advisory lock, so
          //     the stamp commits atomically with the assessments it
          //     describes: a ROLLBACK discards both, and the timestamp can
          //     never claim a run whose writes were thrown away.
          //   - AFTER the DELETE, every INSERT and updatePrioritiesForDevice(),
          //     i.e. after the match actually ran to completion for this
          //     device. Stamping on ENTRY, or before prioritisation, would
          //     record "assessed" for a run that then threw — recreating the
          //     precise lie this column exists to remove.
          //   - Unreachable for a device the matcher SKIPPED: the
          //     'no version row - skipped' branch `continue`s long before this
          //     transaction opens, so such a device keeps a NULL stamp and the
          //     UI correctly reports it as never assessed rather than clean.
          // Anything that throws between here and COMMIT also rolls the stamp
          // back, which is the safe direction: an unrecorded real run reads as
          // "not measured", never a fabricated clean bill of health.
          await client.query('UPDATE devices SET last_cve_assessed_at = now() WHERE id = $1', [
            device.id,
          ]);

          await client.query('COMMIT');
        } catch (txErr) {
          await client.query('ROLLBACK').catch(() => {});
          throw txErr;
        } finally {
          client.release();
          client = null;
        }
      } finally {
        if (client) client.release();
      }

      assessed += 1;
    } catch (err) {
      errors.push({ device_id: device.id, error: err.message });
    }
  }

  return {
    assessed,
    matched_cves: matchedCves,
    unassessable_advisories: unassessableTotal,
    unassessable_by_device: unassessableByDevice,
    errors,
  };
}

module.exports = {
  matchDeviceToAdvisories,
  runMatchForAllDevices,
  countUnassessableAdvisories,
  isUnassessableAdvisory,
  UNASSESSABLE_MATCHABILITY,
};
