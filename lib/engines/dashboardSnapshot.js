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
  let totalPass = 0;
  let totalMeasurable = 0;
  for (const s of STANDARDS) {
    const c = counts[s];
    const measurable = c.pass + c.fail + c.warning;
    byStandard[s] = measurable > 0 ? Math.round((c.pass / measurable) * 100) : null;
    totalPass += c.pass;
    totalMeasurable += measurable;
  }
  const overall = totalMeasurable > 0 ? Math.round((totalPass / totalMeasurable) * 100) : null;

  return { overall, byStandard };
}

/**
 * Compute today's fleet CVE-severity + compliance-score snapshot and
 * upsert it into fleet_dashboard_snapshots. Idempotent within the same
 * calendar day (ON CONFLICT (snapshot_date) DO UPDATE) — safe to call more
 * than once on the same day (a manual re-run, a retry after a transient
 * failure); the row always reflects the LATEST computation for that day,
 * never a duplicate.
 *
 * @param {import('pg').Pool} pool
 * @returns {Promise<{cve: object, compliance: object}>}
 */
async function computeAndStoreDashboardSnapshot(pool) {
  const cve = await computeFleetCveSeverity(pool);
  const compliance = await computeFleetComplianceScores(pool);

  await pool.query(
    `INSERT INTO fleet_dashboard_snapshots
       (snapshot_date, cve_critical, cve_high, cve_medium, cve_low, compliance_overall_score, compliance_by_standard)
     VALUES (CURRENT_DATE, $1, $2, $3, $4, $5, $6::jsonb)
     ON CONFLICT (snapshot_date) DO UPDATE SET
       cve_critical = EXCLUDED.cve_critical,
       cve_high = EXCLUDED.cve_high,
       cve_medium = EXCLUDED.cve_medium,
       cve_low = EXCLUDED.cve_low,
       compliance_overall_score = EXCLUDED.compliance_overall_score,
       compliance_by_standard = EXCLUDED.compliance_by_standard,
       recorded_at = now()`,
    [cve.critical, cve.high, cve.medium, cve.low, compliance.overall, JSON.stringify(compliance.byStandard)]
  );

  return { cve, compliance };
}

module.exports = {
  computeFleetCveSeverity,
  computeFleetComplianceScores,
  computeAndStoreDashboardSnapshot,
};
