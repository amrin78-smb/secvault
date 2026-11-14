// lib/engines/dashboardSnapshot.js
//
// Fleet-wide Dashboard trend snapshots — one row per calendar day in
// fleet_dashboard_snapshots (lib/schema.sql), feeding the main Dashboard's
// day-over-day CVE-severity deltas/sparklines and compliance-score trend.
// Computed on demand by services/engine-worker.js's daily
// dashboard-snapshot job (see that file), not on every page load — a
// dashboard render just reads the last N rows.
//
// CommonJS — required by services/engine-worker.js (plain node).

'use strict';

// Same 5 real standards this app scores against everywhere else (see
// components/compliance/ComplianceMatrix.js's STANDARDS export) — kept as a
// literal here rather than imported, matching this codebase's established
// per-file duplication convention for small constants (ComplianceMatrix.js
// is a React component file, not cleanly requirable from plain-node
// engine-worker.js anyway).
const STANDARDS = ['PCI_DSS', 'ISO_27001', 'CIS_V8', 'NIST', 'SANS'];

/**
 * Fleet-wide CVE severity counts, bucketed from device_cve_assessments'
 * joined advisories.cvss_score, active devices only. A NULL/unparseable
 * CVSS score is excluded from every bucket (never guessed into 'low') —
 * consistent with this app's own tri-state-honesty discipline elsewhere
 * (see CLAUDE.md's Applicability Tri-State Default): an unscored CVE isn't
 * confirmed low-severity, it's unscored.
 *
 * @param {import('pg').Pool} pool
 * @returns {Promise<{critical: number, high: number, medium: number, low: number}>}
 */
async function computeFleetCveSeverity(pool) {
  const { rows } = await pool.query(
    `SELECT a.cvss_score
     FROM device_cve_assessments dca
     JOIN advisories a ON a.id = dca.advisory_id
     JOIN devices d ON d.id = dca.device_id
     WHERE d.active = true`
  );
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const row of rows) {
    const score = row.cvss_score === null || row.cvss_score === undefined ? null : Number(row.cvss_score);
    if (score === null || Number.isNaN(score)) continue;
    if (score >= 9) counts.critical += 1;
    else if (score >= 7) counts.high += 1;
    else if (score >= 4) counts.medium += 1;
    else counts.low += 1;
  }
  return counts;
}

/**
 * Fleet-wide compliance scores: overall and per-standard, active devices only.
 * Same scorePct formula used everywhere else in this app
 * (pass / (pass+fail+warning), excluding 'na' — see
 * app/(dashboard)/compliance/page.js's scorePctFromCounts for the canonical
 * version this mirrors), null (not 0) when nothing is measurable yet.
 *
 * ⛔ THE UNIT OF `overall` IS THE (device, check) PAIR — ONE ROW PER FINDING,
 * COUNTED ONCE, WHATEVER ITS STANDARDS MAPPING SAYS. That is CLAUDE.md's "TWO
 * UNITS, KEPT APART": a fleet finding is a pair, and a count of pairs may
 * never be mixed with a count of distinct checks or with a count of
 * standard-mappings. It is byte-for-byte the arithmetic
 * app/(dashboard)/compliance/page.js already applies to ONE firewall
 * (`statusCounts` reduced over `findings`, then scorePctFromCounts), lifted to
 * the fleet — deliberately not a third definition.
 *
 * ⛔ IT USED TO SUM THE PER-STANDARD BUCKETS, AND THAT WAS WRONG IN BOTH
 * DIRECTIONS AT ONCE (fixed, roadmap row 30):
 *
 *  1. A check mapped to five frameworks was counted FIVE TIMES. Measured
 *     against the live 74-check seed library, the expansion factor is 2.642x,
 *     and because the mapping is not uniform the skew does not cancel: with a
 *     pass rate correlated to mapping breadth, 16 devices x 74 checks scored
 *     51% standard-expanded against 45% per finding. On the reference fleet
 *     the two happened to sit one point apart (479/1016 = 47% against
 *     175/365 = 48%), which is exactly why nothing looked wrong — but the
 *     skew is a function of how many frameworks the LIBRARY maps a check to,
 *     so it moves when curation changes and not when the fleet does.
 *
 *  2. ⛔ A check mapped to NO recognised standard was DISCARDED ENTIRELY —
 *     the more dangerous half, because a real measurement was thrown away.
 *     `audit_checks.standards` is `TEXT[] NOT NULL`, which permits `'{}'`,
 *     and schema.sql names `'CUSTOM'` as a legitimate value outside the five
 *     scored frameworks (app/(dashboard)/compliance/page.js:302 guards for it
 *     by name). Either value made the row contribute to zero buckets and so
 *     vanish from `overall`. Measured: one `pass` mapped to PCI_DSS beside one
 *     `fail` mapped to `{CUSTOM}` reported overall = 100%, not 50% — a
 *     FAILING check erased from the fleet score by a curation field. Latent
 *     in today's seed (0 of 74 checks map to none of the five) and structural
 *     in the schema, so it is fixed rather than waited for.
 *
 * ⛔ THE PER-STANDARD FIGURES KEEP THE STANDARD-EXPANDED COUNTING, UNCHANGED.
 * There it is correct by construction: a check mapped to PCI_DSS and NIST
 * genuinely is evidence about both, and a check mapped to neither genuinely is
 * not evidence about either. Only the pooled figure was wrong. `byStandard`
 * and `byStandardCounts` are untouched, and tests pin them that way.
 *
 * ⛔ `scorePct`'s ARITHMETIC IS CARRIED THROUGH VERBATIM — same operand order
 * `(pass / measurable) * 100`, which tests/complianceScoreFormula.test.js
 * records as load-bearing at exact-.5 float boundaries. This changed the
 * DENOMINATOR's unit, never the formula, and no weight or polarity moved.
 *
 * @param {import('pg').Pool} pool
 * @returns {Promise<{overall: number|null, overallCounts: {pass: number, fail: number, warning: number, na: number}, byStandard: Record<string, number|null>, byStandardCounts: Record<string, object>}>}
 */
async function computeFleetComplianceScores(pool) {
  const { rows } = await pool.query(
    `SELECT af.status, ac.standards
     FROM audit_findings af
     JOIN audit_checks ac ON ac.id = af.check_id
     JOIN devices d ON d.id = af.device_id
     WHERE d.active = true`
  );

  const counts = {};
  for (const s of STANDARDS) counts[s] = { pass: 0, fail: 0, warning: 0 };

  // ⛔ THE (device, check)-PAIR TALLY — one increment per FINDING ROW, read
  // before `standards` is looked at at all, so no curation field can add a
  // row to it twice or remove one from it. `na` is tallied here and then
  // excluded from the denominator below, exactly as the per-device page does:
  // "SecVault could not ask this question" is a fact worth carrying, and it is
  // not a compliance failure. An UNRECOGNISED status enters no bucket and so
  // no denominator — matching `statusCounts`' own hasOwnProperty guard, and
  // deliberately not counted as a `fail`, which would manufacture a failure
  // out of a column that has no CHECK constraint.
  const overallCounts = { pass: 0, fail: 0, warning: 0, na: 0 };

  for (const row of rows) {
    if (Object.prototype.hasOwnProperty.call(overallCounts, row.status)) {
      overallCounts[row.status] += 1;
    }
    if (row.status !== 'pass' && row.status !== 'fail' && row.status !== 'warning') continue; // 'na' excluded
    const list = Array.isArray(row.standards) ? row.standards : [];
    for (const key of list) {
      if (!counts[key]) continue;
      counts[key][row.status] += 1;
    }
  }

  const byStandard = {};
  // Additive (2026-08-02, for lib/engines/complianceReport.js) -- the raw
  // pass/fail/warning counts behind each byStandard percentage, so a
  // caller can show "62% -- 38 pass, 14 fail, 8 warning" the same way
  // every finding-detail view already does, without a second query.
  // Existing callers (runDashboardSnapshotJob) simply ignore this field.
  const byStandardCounts = {};
  // ⛔ STANDARD-EXPANDED ON PURPOSE, AND NO LONGER SUMMED INTO `overall`.
  // These five are shares OF ONE FRAMEWORK'S OWN MAPPED CHECKS, which is what
  // the framework question asks; the loop below no longer accumulates a
  // `totalPass`/`totalMeasurable` across them, because that cross-framework
  // sum is the thing that was wrong.
  for (const s of STANDARDS) {
    const c = counts[s];
    const measurable = c.pass + c.fail + c.warning;
    byStandard[s] = measurable > 0 ? Math.round((c.pass / measurable) * 100) : null;
    byStandardCounts[s] = { pass: c.pass, fail: c.fail, warning: c.warning };
  }

  // ⛔ null, NEVER 0. A fleet with nothing gradeable has not failed
  // compliance; it has not been measured. 0 here would travel into
  // fleet_dashboard_snapshots.compliance_overall_score and into
  // computeSecurityScore's 30%-weighted compliance component, where a fresh
  // install's data gap would be scored as a security problem — the opposite of
  // that engine's own "an unmeasurable component is DROPPED FROM THE
  // DENOMINATOR" rule, which only works if it is handed null.
  const overallMeasurable = overallCounts.pass + overallCounts.fail + overallCounts.warning;
  const overall = overallMeasurable > 0
    ? Math.round((overallCounts.pass / overallMeasurable) * 100)
    : null;

  // `overallCounts` is ADDITIVE (same convention as byStandardCounts above):
  // the pair-unit arithmetic `overall` actually rests on, so a caller showing
  // the basis of the figure reads it from here rather than re-deriving a
  // parallel one. ⛔ Two existing callers still re-derive the OLD definition
  // and now disagree with `overall` — lib/evidence.js's
  // complianceScoreEvidence sums byStandardCounts for the evidence drawer, and
  // lib/engines/complianceReport.js's summaryFromPerDevice reproduces the old
  // cross-framework sum for the device-scoped PDF. Both should read this field
  // instead; neither is in this change's scope.
  return { overall, overallCounts, byStandard, byStandardCounts };
}

// The INSERT's column list + VALUES, shared by both conflict modes below.
// Kept as literal constants (never string-built from caller input) so the two
// statements stay byte-identical apart from their ON CONFLICT action.
const SNAPSHOT_INSERT_HEAD = `INSERT INTO fleet_dashboard_snapshots
       (snapshot_date, cve_critical, cve_high, cve_medium, cve_low, compliance_overall_score, compliance_by_standard,
        device_count, devices_online, rules_total, rules_enabled, patch_now_count, high_risk_count, security_score)
     VALUES (CURRENT_DATE, $1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $12, $13)`;

// Default mode — the 00:10 daily tick and any deliberate manual re-run. The
// row reflects the LATEST computation for that day, never a duplicate.
const SNAPSHOT_SQL_OVERWRITE = `${SNAPSHOT_INSERT_HEAD}
     ON CONFLICT (snapshot_date) DO UPDATE SET
       cve_critical = EXCLUDED.cve_critical,
       cve_high = EXCLUDED.cve_high,
       cve_medium = EXCLUDED.cve_medium,
       cve_low = EXCLUDED.cve_low,
       compliance_overall_score = EXCLUDED.compliance_overall_score,
       compliance_by_standard = EXCLUDED.compliance_by_standard,
       device_count = EXCLUDED.device_count,
       devices_online = EXCLUDED.devices_online,
       rules_total = EXCLUDED.rules_total,
       rules_enabled = EXCLUDED.rules_enabled,
       patch_now_count = EXCLUDED.patch_now_count,
       high_risk_count = EXCLUDED.high_risk_count,
       security_score = EXCLUDED.security_score,
       recorded_at = now()
     RETURNING snapshot_date`;

// ⛔ ifAbsent mode — the engine-startup catch-up (services/engine-worker.js's
// runDashboardSnapshotIfMissing). A snapshot is a POINT-IN-TIME measurement:
// rewriting today's 00:10 row with 14:00 numbers because a deploy restarted
// the engine silently rewrites history, and every day-over-day delta drawn
// from it. DO NOTHING leans on fleet_dashboard_snapshots' own
// UNIQUE(snapshot_date) rather than on a read-then-write check, so two engine
// processes racing at startup cannot both decide the row is missing.
const SNAPSHOT_SQL_IF_ABSENT = `${SNAPSHOT_INSERT_HEAD}
     ON CONFLICT (snapshot_date) DO NOTHING
     RETURNING snapshot_date`;

/**
 * Compute today's fleet CVE-severity + compliance-score snapshot and write it
 * to fleet_dashboard_snapshots, keyed on CURRENT_DATE.
 *
 * Two modes, both idempotent within the same calendar day and neither ever
 * able to create a duplicate row:
 *  - default (`ifAbsent` falsy) — upsert; today's row is refreshed if present.
 *  - `{ ifAbsent: true }` — insert only if today has no row yet; an existing
 *    row is left EXACTLY as recorded. Never touches any other date, so it can
 *    never fabricate a missed day's history from today's numbers.
 *
 * `stored` in the result reports honestly whether a row was actually written
 * — false in ifAbsent mode means "today was already recorded", not a failure.
 *
 * @param {import('pg').Pool} pool
 * @param {{ifAbsent?: boolean}} [options]
 * @returns {Promise<{cve: object, compliance: object, headline: object, stored: boolean}>}
 */
async function computeAndStoreDashboardSnapshot(pool, options = {}) {
  const ifAbsent = (options && options.ifAbsent) === true;
  const cve = await computeFleetCveSeverity(pool);
  const compliance = await computeFleetComplianceScores(pool);
  // Headline tiles (v2.53.0). Required lazily: fleetHeadline.js requires THIS
  // module for computeFleetComplianceScores, so a top-level require here would
  // be a cycle. A cycle would not throw — it would hand one side a
  // half-initialised module object and fail later as an undefined function.
  const { getFleetHeadline } = require('./fleetHeadline');
  const headline = await getFleetHeadline(pool);

  const res = await pool.query(
    ifAbsent ? SNAPSHOT_SQL_IF_ABSENT : SNAPSHOT_SQL_OVERWRITE,
    [
      cve.critical, cve.high, cve.medium, cve.low, compliance.overall, JSON.stringify(compliance.byStandard),
      headline.deviceCount, headline.devicesOnline, headline.rulesTotal, headline.rulesEnabled,
      headline.patchNowCount, headline.highRiskCount, headline.securityScore,
    ]
  );

  // rowCount is 0 only in ifAbsent mode, and only because today's row already
  // existed — the RETURNING clause makes that observable instead of guessed.
  const stored = !!res && Number(res.rowCount) > 0;

  return { cve, compliance, headline, stored };
}

module.exports = {
  computeFleetCveSeverity,
  computeFleetComplianceScores,
  computeAndStoreDashboardSnapshot,
  SNAPSHOT_SQL_OVERWRITE,
  SNAPSHOT_SQL_IF_ABSENT,
};
