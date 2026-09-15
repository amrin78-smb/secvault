'use strict';

// lib/reports/reportStats.js — the headline figures the Reports page shows for
// each report BEFORE you download it.
//
// ⛔ WHY THIS EXISTS. The first Reports page listed each report's name and a
// paragraph of description, with a Download button. Side by side with
// LogVault's reports page it read as a list of links rather than a product
// surface — and the difference was not styling. LogVault SHOWS the report;
// SecVault only DESCRIBED it. An operator could not tell whether a report was
// worth opening without opening it.
//
// ⛔ ONE ROUND TRIP, NOT ONE PER REPORT. Every figure below is a scalar
// subquery in a single statement — measured at 172ms against the live fleet.
// Calling each report's real engine to populate its tiles would mean running
// the analysis twice for every page view (once for the tiles, once for the
// PDF), and the segmentation engine alone was ~700ms before it was fixed. A
// page that costs more than the document it offers is a page people stop
// opening.
//
// ⛔ THESE ARE NOT THE REPORT'S OWN NUMBERS, AND MUST NOT BE PRESENTED AS
// PROOF. They are cheap counts over the same tables the engines read. The
// report itself applies acknowledgements, coverage rules, caps and the
// priority tree; a tile saying "1,132 findings" and a PDF saying "1,090 open
// findings" are both right and are answering different questions. So the tiles
// are labelled as an at-a-glance figure, never as the report's result.

/**
 * @returns {Promise<object|null>} null when the counts could not be read —
 *   ⛔ never a zero-filled object. A page of confident zeros is exactly the
 *   failed-read-as-a-fact bug this codebase keeps finding, and it would be
 *   telling an operator their fleet is clean when the query simply failed.
 */
async function getReportStats(pool) {
  try {
    const { rows } = await pool.query(`
      SELECT
        (SELECT count(*)::int FROM devices WHERE active)                                  AS devices,
        (SELECT count(DISTINCT device_id)::int FROM device_cve_assessments
          WHERE priority_band = 'patch_now')                                              AS cve_patch_now_devices,
        (SELECT count(DISTINCT advisory_id)::int FROM device_cve_assessments
          WHERE priority_band = 'patch_now')                                              AS cve_patch_now,
        (SELECT count(DISTINCT advisory_id)::int FROM device_cve_assessments
          WHERE priority_band = 'scheduled')                                              AS cve_scheduled,
        (SELECT count(*)::int FROM rule_analysis_results)                                 AS rule_findings,
        (SELECT count(*)::int FROM firewall_rules WHERE hit_count IS NULL)                AS rules_unmeasured,
        (SELECT count(*)::int FROM firewall_rules)                                        AS rules_total,
        (SELECT count(*)::int FROM audit_findings f
            JOIN audit_checks c ON c.id = f.check_id
          WHERE f.status = 'fail' AND c.severity IN ('critical', 'high'))                 AS compliance_fails,
        (SELECT count(DISTINCT device_id)::int FROM audit_findings)                       AS compliance_devices
    `);
    return rows[0] || null;
  } catch (_err) {
    return null;
  }
}

const dash = (n) => (n === null || n === undefined ? '—' : Number(n).toLocaleString('en-US'));

/**
 * The tiles for one report, given the shared stats.
 *
 * ⛔ A `tone` of 'unmeasured' is the hueless treatment — the printed and
 * on-screen form of --unmeasured. "233 rules we could not measure" is neither
 * good news nor bad, and colouring it either way is a claim.
 */
function tilesFor(reportId, s) {
  if (!s) return null;
  const pct = (a, b) => (b > 0 ? `${Math.round((a / b) * 100)}%` : '—');

  switch (reportId) {
    case 'executive-summary':
      return [
        { label: 'Firewalls', value: dash(s.devices) },
        { label: 'Urgent CVEs', value: dash(s.cve_patch_now), tone: s.cve_patch_now > 0 ? 'bad' : 'ok' },
        { label: 'Critical/high checks failing', value: dash(s.compliance_fails), tone: s.compliance_fails > 0 ? 'bad' : 'ok' },
        { label: 'Rules with no usage data', value: dash(s.rules_unmeasured), tone: 'unmeasured' },
      ];
    case 'rule-hygiene':
      return [
        { label: 'Findings', value: dash(s.rule_findings) },
        { label: 'Rules examined', value: dash(s.rules_total) },
        { label: 'No usage data', value: dash(s.rules_unmeasured), tone: 'unmeasured' },
        { label: 'Of the ruleset', value: pct(s.rules_unmeasured, s.rules_total), tone: 'unmeasured' },
      ];
    case 'vulnerability-posture':
      return [
        { label: 'Patch now', value: dash(s.cve_patch_now), tone: s.cve_patch_now > 0 ? 'bad' : 'ok' },
        { label: 'Firewalls affected', value: dash(s.cve_patch_now_devices) },
        { label: 'Scheduled', value: dash(s.cve_scheduled), tone: 'warn' },
        { label: 'Firewalls', value: dash(s.devices) },
      ];
    case 'compliance-fleet':
      return [
        { label: 'Critical/high failing', value: dash(s.compliance_fails), tone: s.compliance_fails > 0 ? 'bad' : 'ok' },
        { label: 'Firewalls assessed', value: dash(s.compliance_devices) },
        { label: 'Firewalls', value: dash(s.devices) },
      ];
    default:
      return null;
  }
}

module.exports = { getReportStats, tilesFor };
