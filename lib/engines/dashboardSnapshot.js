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
 * Fleet-wide compliance scores: overall (every standard's pass/fail/warning
 * pooled together) and per-standard, active devices only. Same scorePct
 * formula used everywhere else in this app (pass / (pass+fail+warning),
 * excluding 'na' — see app/(dashboard)/compliance/page.js's
 * scorePctFromCounts for the canonical version this mirrors), null (not 0)
 * when nothing is measurable for that standard yet.
 *
 * @param {import('pg').Pool} pool
 * @returns {Promise<{overall: number|null, byStandard: Record<string, number|null>}>}
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

  for (const row of rows) {
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
  let totalPass = 0;
  let totalMeasurable = 0;
  for (const s of STANDARDS) {
    const c = counts[s];
    const measurable = c.pass + c.fail + c.warning;
    byStandard[s] = measurable > 0 ? Math.round((c.pass / measurable) * 100) : null;
    byStandardCounts[s] = { pass: c.pass, fail: c.fail, warning: c.warning };
    totalPass += c.pass;
    totalMeasurable += measurable;
  }
  const overall = totalMeasurable > 0 ? Math.round((totalPass / totalMeasurable) * 100) : null;

  return { overall, byStandard, byStandardCounts };
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
