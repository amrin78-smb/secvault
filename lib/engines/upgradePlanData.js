'use strict';

// lib/engines/upgradePlanData.js
//
// The upgrade plan's PLUMBING. Loads the fleet's active firewalls, each one's
// running version and its OPEN CVE assessments, hands them to the pure
// `upgradePlan.js`, and returns what a page or a route renders.
//
// ⛔ SPLIT FROM upgradePlan.js DELIBERATELY — the same split segmentation.js /
// segmentationData.js and applicationView.js / applicationViewData.js already
// use. That file is pure (a device, a version and some rows in; a decision
// out), which is what lets a test drive every branch with literal data.
// Nothing in here decides anything: it fetches, groups, and labels coverage.
//
// ⛔ READ TIME. NO TABLE, NO CRON JOB, NO CACHE. A stored upgrade plan goes
// stale against the assessments it indexes and is then read as fact — the same
// rule /segmentation and /applications follow, and for the same reason: the
// product's claim is that its answer is re-derived from what was last
// collected, not typed once and left to decay.
//
// ── ⛔ THE THING THIS FILE MUST GET RIGHT ─────────────────────────────────
//
// A FIREWALL ABSENT FROM THE PLAN READS AS "NOTHING TO DO". The obvious query
// starts at `device_cve_assessments` and joins outwards, which silently drops
// every device that has no open assessment — and a device has no open
// assessment for two OPPOSITE reasons:
//
//   * it was assessed and nothing matched  — genuinely clear, today
//   * it was NEVER ASSESSED                — we have no idea, and the blank
//                                            row looks identical
//
// That is this codebase's signature bug (a failed read rendered as an
// affirmative fact) aimed squarely at the page whose entire job is to say what
// still needs doing. So EVERY ACTIVE DEVICE GETS EXACTLY ONE PLAN, and each
// plan carries an explicit `coverage` state — never merely `openCount: 0`.
//
// `devices.last_cve_assessed_at` is what separates the two, exactly as it was
// added to do in v2.91.0. ⛔ The test is NOT the stamp alone: rows written
// before that column existed carry assessments with no stamp, and those
// devices WERE assessed. `fleetHeadline.isAssessed()` already encodes that
// (stamp OR any assessment row) and is REUSED UNCHANGED here — a second
// definition of "assessed" would eventually disagree with the dashboard about
// the same fleet, which is the defect fleetHeadline.js documents having just
// repaired between itself and the Vulnerability Posture PDF.

const { buildUpgradePlan, rankPlans, summarisePlans } = require('./upgradePlan');
const { isAssessed } = require('./fleetHeadline');

/**
 * Coverage states. ⛔ FOUR, NOT TWO — an empty plan is not one fact.
 *
 *   never_assessed       no stamp and no assessment row of any kind. The plan
 *                        is EMPTY BECAUSE NOTHING WAS ASKED. Must never be
 *                        rendered as an all-clear.
 *   assessed_no_version  assessed, but there is no `device_versions` row, so
 *                        there is no running version to plan a move FROM.
 *                        Anything the plan proposes is unanchored.
 *   assessed_clear       assessed, a running version is known, and no open
 *                        version-affected assessment remains. This is the only
 *                        one of the four that means "nothing to do", and it
 *                        means it only as of `lastAssessedAt`.
 *   assessed             assessed, version known, open assessments to plan.
 */
const COVERAGE = {
  NEVER_ASSESSED: 'never_assessed',
  ASSESSED_NO_VERSION: 'assessed_no_version',
  ASSESSED_CLEAR: 'assessed_clear',
  ASSESSED: 'assessed',
};

/**
 * ⛔ A CVSS SCORE OF 0.0 IS A SCORE AND AN ABSENT ONE IS NOT ZERO.
 * `advisories.cvss_score` is NUMERIC, so `pg` hands it back as a STRING, and
 * the lazy coercion (`Number(row.cvss_score)`) turns SQL NULL into 0 — which
 * this product reads as a real, vendor-published "not impacted" score (see
 * CLAUDE.md's "A VENDOR-PUBLISHED 0.0 IS A SCORE"). Absent stays null.
 */
function numericOrNull(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/**
 * ⛔ `deviceIds` DISTINGUISHES "NO FILTER" FROM "NO DEVICES", and the two are
 * opposite instructions — the same asymmetry `ldapRoles.js` draws between no
 * mappings configured and no mapping matched.
 *
 *   undefined / null  the whole active fleet (the ordinary call)
 *   []                NO devices — a scoped account granted nothing
 *   [id, …]           exactly those
 *
 * Returned as a parameter for `= ANY($1::uuid[])`, never interpolated.
 */
function normaliseDeviceIds(deviceIds) {
  if (deviceIds === null || deviceIds === undefined) return null;
  if (!Array.isArray(deviceIds)) return null;
  return deviceIds.filter((id) => typeof id === 'string' && id.length > 0);
}

// ⛔ One row per ACTIVE device, whether or not it has an assessment. The
// LATERAL takes the newest `device_versions` row; a device with none yields
// NULL, which is the truth and is labelled `assessed_no_version` below rather
// than being dropped.
//
// ⛔ `has_assessment_rows` is EXISTS over ALL assessments, deliberately NOT
// filtered by `version_affected`. A device whose every assessment came back
// "this version is not affected" HAS been assessed — filtering here would
// report a completed assessment as an absent one, which is the same mistake
// inverted.
const DEVICES_SQL = `
  SELECT d.id,
         d.name,
         d.vendor,
         d.asset_criticality,
         d.last_cve_assessed_at,
         dv.version_string AS running,
         EXISTS (
           SELECT 1 FROM device_cve_assessments dca WHERE dca.device_id = d.id
         ) AS has_assessment_rows
  FROM devices d
  LEFT JOIN LATERAL (
    SELECT version_string
    FROM device_versions v
    WHERE v.device_id = d.id
    ORDER BY collected_at DESC
    LIMIT 1
  ) dv ON true
  WHERE d.active
    AND ($1::uuid[] IS NULL OR d.id = ANY($1::uuid[]))
  ORDER BY d.name
`;

// ⛔ `version_affected` ONLY. These are the rows an upgrade can clear; an
// assessment that did not match this device's version is not outstanding work.
// ⛔ `a.kev_listed`, not the advisory's copy — the assessment's own flag is
// what the priority tree was evaluated against, so using the other one would
// let this page disagree with the band printed beside it. Measured on the live
// fleet 2026-09-25: the two never disagree on any of the 246 open rows, so
// this is a choice about which is AUTHORITATIVE, not a difference in counts.
const ASSESSMENTS_SQL = `
  SELECT a.device_id,
         a.fixed_in,
         a.kev_listed,
         a.priority_band,
         adv.cve_id,
         adv.cvss_score
  FROM device_cve_assessments a
  JOIN advisories adv ON adv.id = a.advisory_id
  JOIN devices d ON d.id = a.device_id
  WHERE a.version_affected
    AND d.active
    AND ($1::uuid[] IS NULL OR d.id = ANY($1::uuid[]))
  ORDER BY a.device_id, adv.cve_id
`;

/**
 * Which of the four coverage states a device is in.
 * @param {object} device a devices row (+ has_assessment_rows)
 * @param {number} openCount that device's open, version-affected assessments
 */
function coverageOf(device, openCount) {
  const assessed = isAssessed(
    device,
    device && device.has_assessment_rows ? new Set([device.id]) : null
  );
  if (!assessed) return COVERAGE.NEVER_ASSESSED;
  if (!device.running) return COVERAGE.ASSESSED_NO_VERSION;
  if (openCount === 0) return COVERAGE.ASSESSED_CLEAR;
  return COVERAGE.ASSESSED;
}

/**
 * The fleet's upgrade plan, computed at read time.
 *
 * @param {object} pool  ⛔ A PARAMETER, never imported — CLAUDE.md's Database
 *   rule. Removing it breaks DB access silently.
 * @param {object} [opts]
 * @param {string[]|null} [opts.deviceIds] see normaliseDeviceIds
 * @param {Date|string} [opts.now] injectable clock, so `generatedAt` is
 *   pinnable by a test rather than being whatever the suite ran at.
 * @returns {Promise<{plans:Array, summary:object, generatedAt:string}>}
 */
async function getFleetUpgradePlan(pool, opts = {}) {
  const ids = normaliseDeviceIds(opts.deviceIds);

  // Two statements, one round trip each, issued together. They are independent
  // reads and neither depends on the other's result.
  const [deviceRes, assessmentRes] = await Promise.all([
    pool.query(DEVICES_SQL, [ids]),
    pool.query(ASSESSMENTS_SQL, [ids]),
  ]);

  const deviceRows = (deviceRes && deviceRes.rows) || [];
  const assessmentRows = (assessmentRes && assessmentRes.rows) || [];

  // Group the assessments by device, in the shape upgradePlan.js documents.
  const byDevice = new Map();
  for (const r of assessmentRows) {
    if (!r || !r.device_id) continue;
    if (!byDevice.has(r.device_id)) byDevice.set(r.device_id, []);
    byDevice.get(r.device_id).push({
      cve_id: r.cve_id,
      fixed_in: r.fixed_in,
      kev_listed: !!r.kev_listed,
      priority_band: r.priority_band || null,
      cvss_score: numericOrNull(r.cvss_score),
    });
  }

  const plans = deviceRows.map((d) => {
    const assessments = byDevice.get(d.id) || [];
    const plan = buildUpgradePlan(
      {
        id: d.id,
        name: d.name,
        vendor: d.vendor,
        asset_criticality: d.asset_criticality,
      },
      d.running || null,
      assessments
    );
    const coverage = coverageOf(d, assessments.length);
    return {
      ...plan,
      coverage,
      // ⛔ THE LABEL AND THE FACT BEHIND IT TRAVEL TOGETHER. A reader deciding
      // whether to trust `assessed_clear` needs to know how old it is; a
      // coverage word with no timestamp is an assertion, not evidence.
      lastAssessedAt: d.last_cve_assessed_at
        ? new Date(d.last_cve_assessed_at).toISOString()
        : null,
      // ⛔ Named so no caller has to infer it from `openCount === 0`, which is
      // the inference this whole file exists to prevent.
      neverAssessed: coverage === COVERAGE.NEVER_ASSESSED,
    };
  });

  const ranked = rankPlans(plans);
  const base = summarisePlans(ranked);

  const neverAssessed = ranked.filter((p) => p.coverage === COVERAGE.NEVER_ASSESSED).length;
  const assessedClear = ranked.filter((p) => p.coverage === COVERAGE.ASSESSED_CLEAR).length;
  const assessedNoVersion = ranked.filter(
    (p) => p.coverage === COVERAGE.ASSESSED_NO_VERSION
  ).length;

  return {
    plans: ranked,
    summary: {
      ...base,
      neverAssessed,
      assessedClear,
      assessedNoVersion,
      // ⛔ AN ALL-CLEAR IS FORBIDDEN WHILE COVERAGE IS INCOMPLETE — the rule
      // lib/evidence.js enforces product-wide. This is the one flag a renderer
      // needs to refuse a green headline over a fleet that was only partly
      // asked. It is computed here, not left to each caller to re-derive, so a
      // page cannot quietly forget to.
      coverageComplete: neverAssessed === 0 && assessedNoVersion === 0,
    },
    generatedAt: (opts.now ? new Date(opts.now) : new Date()).toISOString(),
  };
}

module.exports = {
  getFleetUpgradePlan,
  coverageOf,
  normaliseDeviceIds,
  numericOrNull,
  COVERAGE,
  DEVICES_SQL,
  ASSESSMENTS_SQL,
};
