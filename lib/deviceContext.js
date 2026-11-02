'use strict';

// THE PERSISTENT DEVICE CONTEXT — who this firewall is, how well we can see
// it, and what is outstanding on it. Rendered at the top of EVERY per-device
// route by components/devices/DeviceContextHeader.js.
//
// PURE, plus one loader at the bottom. `deviceContextFacts` takes a plain row
// and returns the facts; nothing in it queries, formats for a particular
// viewport, or knows what a React component is.
//
// ⛔ ═══ WHY THIS EXISTS AT ALL ═══════════════════════════════════════════
// A firewall's pages were six separate destinations — /devices/[id], /rules,
// /changes, /vpn, /snmp, /analysis — each opening with a "← Back to <name>"
// link, its own `PageHeader` title ending in the device name, and NOTHING
// else carrying the asset. So on /devices/<id>/rules an operator could read
// 706 rules without the page ever saying which firewall they belonged to
// beyond the title, whether it had been collected from this month, or whether
// those rules were the current ones. The asset identity was a breadcrumb.
//
// ⛔ ═══ REACHABILITY IS POLL HEALTH, NEVER `last_connectivity_ok` ════════
// `last_connectivity_ok` is a SINGLE LATEST BOOLEAN; poll health is a success
// RATE over history, and only the second can distinguish a firewall that is
// answering from one that answered once. It showed TSR_EKC green while every
// scheduled poll had failed for 19 days. /devices already learned this and
// drives its row dot from poll health; a context header shown on six more
// pages must not reintroduce the bug on all of them.
//
// ⛔ THE REASON THIS COMMENT USED TO GIVE WAS STALE, AND IT IS WORTH CORRECTING
// RATHER THAN DELETING. It said that column is "written ONLY by the manual
// 'Test connectivity' button" — true when /devices learned the lesson, and no
// longer: `lib/adapters/index.js` now writes it on EVERY collectAndStore pass,
// and says so in its own comment. So the column is not weeks stale any more;
// it is simply a different and weaker measurement than a rate. The conclusion
// survives, the mechanism behind it does not, and a confident wrong mechanism
// is what sends the next session to fix the wrong thing.
//
// ⛔ AND THE TWO FIELDS BUILT ON THE STALE PREMISE ARE GONE. `lastManualOk` /
// `lastManualAt` were carried under the claim that the manual result "is still
// displayed, but as what it is" — nothing read either of them, on any page, so
// the sentence described code that did not exist. The dot and the poll-health
// note carry reachability here; the latest-probe boolean is still shown on
// /devices, which is where the fleet comparison lives.
//
// ⛔ ═══ A ZERO IS NOT AN ALL-CLEAR, AND THIS IS WHERE IT WOULD HURT MOST ══
// Every count here is a fleet-of-one version of a figure /devices already
// draws, which means every failed-read-as-a-fact trap this codebase has met
// is available again in a header that now appears on six pages instead of
// one. So each posture figure is TRI-STATE: a real number, a measured zero,
// or `null` meaning SecVault holds no evidence of a measurement. The renderer
// is forbidden from drawing the third as the second.

const FRESH_AFTER_DAYS = 7; // matches coverageRegister's STALE_AFTER_DAYS

// Reachability verdicts, worst first. ⛔ `unknown` is NOT the bottom of this
// list — it is off it. A device nothing has polled is not "less reachable"
// than one failing every poll; it is a device we have not asked.
const REACHABILITY = {
  FAILING: 'failing',
  DEGRADED: 'degraded',
  FLAKY: 'flaky',
  HEALTHY: 'healthy',
  UNKNOWN: 'unknown',
};

function ageInDays(ts, now) {
  if (!ts) return null;
  const t = new Date(ts).getTime();
  if (!Number.isFinite(t)) return null;
  const ms = now.getTime() - t;
  // ⛔ A NEGATIVE AGE IS A CLOCK DISAGREEMENT, NOT FRESHNESS. Same call
  // vpn_sessions makes on a negative duration: it is evidence the device's or
  // the server's clock is wrong, and reporting it as "collected 0 days ago"
  // would present that fault as a healthy reading.
  if (ms < 0) return null;
  return ms / 86400000;
}

/**
 * One freshness verdict, used for both config collection and CVE assessment.
 *
 * ⛔ FOUR STATES. "never" and "stale" send an operator to completely different
 * places — a credential/reachability problem versus a job that stopped
 * running — and collapsing them loses which one you have. `unknown` is the
 * clock-disagreement case above.
 */
function collectionFreshness(ts, now, afterDays = FRESH_AFTER_DAYS) {
  if (!ts) return { state: 'never', at: null, ageDays: null };
  const age = ageInDays(ts, now);
  if (age === null) return { state: 'unknown', at: ts, ageDays: null };
  return {
    state: age > afterDays ? 'stale' : 'fresh',
    at: ts,
    ageDays: age,
  };
}

/**
 * A posture figure that may not have been measured.
 *
 * ⛔ `measured` IS SUPPLIED BY THE CALLER AND IS NOT DERIVED FROM `n > 0`.
 * Deriving it would make every genuine zero indistinguishable from an absent
 * measurement, which is the exact substitution this whole file exists to
 * refuse.
 */
function postureFigure(n, measured, reason) {
  if (!measured) return { value: null, measured: false, reason: reason || null };
  const v = Number(n);
  return { value: Number.isFinite(v) ? v : 0, measured: true, reason: null };
}

/**
 * The facts a device-context header shows.
 *
 * @param {object} row  a devices row joined with the per-device aggregates
 *                      loadDeviceContext selects; see its query.
 * @param {{now?: Date}} opts
 */
function deviceContextFacts(row, opts = {}) {
  const r = row || {};
  const now = opts.now instanceof Date ? opts.now : new Date();

  // ⛔ THE BAND COMES FROM THE SAME FUNCTION /devices USES. Re-deriving a
  // reachability verdict here from the same history rows would be a second
  // implementation of one judgement, and the two would eventually disagree
  // about the same device on two pages — which is exactly what happened with
  // HA status (one page drew a red Degraded badge, the other ordinary body
  // text, over one dataset).
  const reachability = {
    band: r.pollBand || REACHABILITY.UNKNOWN,
    health: r.pollHealth || null,
  };

  const collected = collectionFreshness(r.last_collected_at, now);
  let assessed = collectionFreshness(r.last_cve_assessed_at, now);

  // ⛔ EITHER SIGNAL IS SUFFICIENT, matching computeTiles' own OR. A device
  // holding assessment rows HAS been assessed even if the stamp predates the
  // column; a device with a stamp and no rows has been assessed and found to
  // match nothing. Requiring both would report an assessed fleet as uncovered.
  const cveMeasured = Boolean(r.last_cve_assessed_at) || (r.assessment_count || 0) > 0;

  // ⛔ "NEVER" MAY NOT BE ASSERTED FROM THE ABSENCE OF THE STAMP WHILE THE ROWS
  // ARE RIGHT THERE. `cveMeasured` above deliberately ORs the two signals,
  // because assessment rows "can only exist because a match ran" — and
  // `assessed` used only the timestamp. So a firewall holding assessment rows
  // whose per-device stamp was never written rendered "⚠ Assessed never", with
  // a hover reading "SecVault has no record of this ever happening", directly
  // beside a "Patch now" figure that is measurable ONLY BECAUSE that record
  // exists. The two halves of one strip contradicted each other.
  //
  // ⛔ IT IS REACHABLE, not hypothetical: deviceInventory.js records that
  // `last_cve_assessed_at` is NULL on every already-deployed row until the
  // matcher next runs, and the column is stamped only on a COMPLETED match, so
  // a match that errored part-way lands here too.
  //
  // ⛔ `unknown` RATHER THAN A GUESSED AGE. We know it happened; we do not know
  // when, and inventing a date would be the failed-read-as-a-fact rule wearing
  // a timestamp. The amber "never"/"stale" in this strip is the cue that sends
  // an operator to re-collect, so pointing it at the wrong job is the cost.
  if (!r.last_cve_assessed_at && (r.assessment_count || 0) > 0) {
    assessed = {
      state: 'unknown',
      at: null,
      ageDays: null,
      reason: 'This firewall holds CVE assessment rows, so a match has run — but no '
        + 'completed-match timestamp was recorded, so SecVault cannot say when.',
    };
  }
  const rulesMeasured = Boolean(r.last_rules_collected_at) || (r.rule_count || 0) > 0;
  // ⛔ Findings are only measurable once a ruleset exists to analyse. Zero
  // findings on a device with no rules is arithmetic, not hygiene.
  const findingsMeasured = rulesMeasured && (r.analysis_run_count || 0) > 0;
  const complianceMeasured = r.compliance_pct !== null && r.compliance_pct !== undefined;
  // ⛔ `< 2`, not `=== 0`: a diff needs a PREDECESSOR, so a device with
  // exactly one snapshot has been collected from and still cannot produce one.
  const driftMeasured = (r.config_snapshot_count || 0) >= 2;

  const posture = {
    patchNow: postureFigure(r.patch_now_count, cveMeasured, 'No completed CVE assessment on record'),
    criticalCves: postureFigure(r.critical_cve_count, cveMeasured, 'No completed CVE assessment on record'),
    openFindings: postureFigure(
      r.open_findings,
      findingsMeasured,
      rulesMeasured ? 'Rule analysis has not run on this device' : 'No ruleset collected'
    ),
    rules: postureFigure(r.rule_count, rulesMeasured, 'No ruleset collected'),
    compliancePct: postureFigure(r.compliance_pct, complianceMeasured, 'No compliance check is answerable here'),
    openDiffs: postureFigure(r.open_diffs, driftMeasured, 'Fewer than two config snapshots to compare'),
  };

  // What SecVault can and cannot see about this firewall, as named gaps rather
  // than one coverage percentage. ⛔ A single percentage would cover four
  // different problems with four different first steps.
  const gaps = [];
  if (!r.version_string) gaps.push({ key: 'version', label: 'No firmware version collected — CVE matching cannot begin' });
  if (!rulesMeasured) gaps.push({ key: 'rules', label: 'No ruleset collected' });
  if (!cveMeasured) gaps.push({ key: 'cve', label: 'Never assessed for CVEs' });
  if (collected.state === 'never') gaps.push({ key: 'config', label: 'Never collected from' });
  else if (collected.state === 'stale') gaps.push({ key: 'config-stale', label: `Last collected over ${FRESH_AFTER_DAYS} days ago` });
  if (reachability.band === REACHABILITY.FAILING) gaps.push({ key: 'reach', label: 'Every poll in the last 3 days failed' });
  else if (reachability.band === REACHABILITY.UNKNOWN) gaps.push({ key: 'reach-unknown', label: 'Not polled — reachability unobserved' });

  return {
    id: r.id || null,
    name: r.name || null,
    vendor: r.vendor || null,
    model: r.model || null,
    serial: r.serial || null,
    version: r.version_string || null,
    site: r.site || null,
    address: r.mgmt_ip || r.smc_host || null,
    criticality: r.asset_criticality || null,
    ha: r.ha_enabled === null || r.ha_enabled === undefined
      ? null
      : { enabled: r.ha_enabled, mode: r.ha_mode || null, localState: r.ha_local_state || null },
    reachability,
    collected,
    assessed,
    posture,
    gaps,
    staleAfterDays: FRESH_AFTER_DAYS,
  };
}

/**
 * Load one device's context.
 *
 * ⛔ ITS OWN QUERY, NOT `getDeviceRows` FILTERED. Three reasons, and the
 * second is the one that matters:
 *   1. getDeviceRows loads the WHOLE fleet with eleven lateral joins. This
 *      header renders on six routes; paying a fleet query for one device on
 *      every one of them is a cost nobody asked for.
 *   2. ⛔ getDeviceRows carries `WHERE d.active = true`. A DEACTIVATED device's
 *      pages are still reachable and must still state which firewall they
 *      belong to — filtering that query by id would return no row and the
 *      header would silently vanish on exactly the devices whose history
 *      somebody is most likely to be reading.
 *   3. It selects only what the header shows, so the two can't drift into
 *      each other's business.
 *
 * ⛔ IT NEVER THROWS. A context header is chrome on somebody else's page; a
 * failed aggregate must not take down the ruleset they came to read. It
 * returns `null`, and the renderer falls back to the identity it was handed
 * directly — which is strictly better than an error page, and honest, because
 * a header with no posture figures claims nothing.
 */
async function loadDeviceContext(pool, deviceId, opts = {}) {
  if (!pool || !deviceId) return null;
  try {
    const { rows } = await pool.query(
      `SELECT d.id, d.name, d.vendor, d.site, d.mgmt_ip, d.smc_host, d.asset_criticality,
              d.last_connectivity_ok, d.last_connectivity_checked_at, d.last_collected_at,
              d.last_cve_assessed_at, d.last_rules_collected_at,
              dv.version_string, dv.model, dv.serial,
              COALESCE(band.patch_now_count, 0)::int    AS patch_now_count,
              COALESCE(band.critical_cve_count, 0)::int AS critical_cve_count,
              COALESCE(band.assessment_count, 0)::int   AS assessment_count,
              COALESCE(rules.rule_count, 0)::int        AS rule_count,
              COALESCE(fnd.critical_findings, 0)::int   AS critical_findings,
              COALESCE(fnd.high_findings, 0)::int       AS high_findings,
              COALESCE(fnd.open_findings, 0)::int       AS open_findings,
              COALESCE(hist.analysis_run_count, 0)::int AS analysis_run_count,
              comp.score_pct                           AS compliance_pct,
              ha.enabled AS ha_enabled, ha.mode AS ha_mode, ha.local_state AS ha_local_state,
              COALESCE(drift.open_diffs, 0)::int        AS open_diffs,
              COALESCE(cfg.config_snapshot_count, 0)::int AS config_snapshot_count
         FROM devices d
         LEFT JOIN LATERAL (
           SELECT version_string, model, serial FROM device_versions
            WHERE device_versions.device_id = d.id
            ORDER BY collected_at DESC LIMIT 1
         ) dv ON true
         LEFT JOIN LATERAL (
           SELECT COUNT(*) FILTER (WHERE dca.priority_band = 'patch_now') AS patch_now_count,
                  COUNT(*) FILTER (WHERE a.cvss_score >= 9.0)             AS critical_cve_count,
                  COUNT(*)                                               AS assessment_count
             FROM device_cve_assessments dca
             JOIN advisories a ON a.id = dca.advisory_id
            WHERE dca.device_id = d.id
         ) band ON true
         LEFT JOIN LATERAL (
           SELECT COUNT(*) AS rule_count FROM firewall_rules
            WHERE firewall_rules.device_id = d.id
         ) rules ON true
         LEFT JOIN LATERAL (
           -- ⛔ open_findings IS EVERY SEVERITY, AND IT HAS TO BE, BECAUSE THE
           -- FIGURE IS LABELLED "Open findings" AND LINKS TO THE UNFILTERED
           -- FINDINGS TAB. It used to be critical + high only, which made a
           -- firewall whose findings are all medium/info report a MEASURED
           -- ZERO -- no em-dash, no hue, no named gap -- on all six of its
           -- pages, directly above a link listing every one of them.
           --
           -- ⛔ THAT WAS THE COMMON CASE, NOT A CORNER: ruleAnalysis.js emits
           -- medium for EIGHT of its thirteen finding types and info for a
           -- ninth, so only four can ever reach this tile. unused -- 185 live
           -- on the reference fleet -- is one of the eight. /devices banded
           -- such a firewall medium from the same rows, so two surfaces gave
           -- opposite verdicts on one dataset.
           --
           -- critical/high are kept projected: they are what the risk BAND is
           -- built from, and summing here rather than widening those two keeps
           -- the band's own meaning untouched.
           SELECT COUNT(*) FILTER (WHERE severity = 'critical') AS critical_findings,
                  COUNT(*) FILTER (WHERE severity = 'high')     AS high_findings,
                  COUNT(*)                                      AS open_findings
             FROM rule_analysis_results
            WHERE rule_analysis_results.device_id = d.id
         ) fnd ON true
         LEFT JOIN LATERAL (
           -- ⛔ EVIDENCE THAT ANALYSIS RAN, which a finding COUNT cannot
           -- supply: a device analysed and found clean holds zero findings,
           -- exactly like one never analysed. device_risk_history gets a row
           -- every time runAnalysisForDevice() completes, so it separates the
           -- two. Without it a clean device would render its findings figure
           -- as "not measured" for ever.
           SELECT COUNT(*) AS analysis_run_count FROM device_risk_history
            WHERE device_risk_history.device_id = d.id
         ) hist ON true
         LEFT JOIN LATERAL (
           SELECT CASE
                    WHEN COUNT(*) FILTER (WHERE status IN ('pass','fail','warning')) = 0 THEN NULL
                    ELSE ROUND(100.0 * COUNT(*) FILTER (WHERE status = 'pass')
                               / COUNT(*) FILTER (WHERE status IN ('pass','fail','warning')))
                  END AS score_pct
             FROM audit_findings WHERE audit_findings.device_id = d.id
         ) comp ON true
         LEFT JOIN device_ha_status ha ON ha.device_id = d.id
         LEFT JOIN LATERAL (
           SELECT COUNT(*) AS open_diffs FROM config_diffs
            WHERE config_diffs.device_id = d.id AND acknowledged_at IS NULL
         ) drift ON true
         LEFT JOIN LATERAL (
           SELECT COALESCE(SUM(COALESCE(observation_count, 1)), 0) AS config_snapshot_count
             FROM device_configs WHERE device_configs.device_id = d.id
         ) cfg ON true
        WHERE d.id = $1::uuid`,
      [deviceId]
    );
    if (!rows.length) return null;
    const row = rows[0];

    // Reachability, from the same engine /devices uses.
    let pollBand = REACHABILITY.UNKNOWN;
    let pollHealth = null;
    try {
      const { getDevicePollHealth, pollHealthBand } = require('./engines/connectivityHistory');
      const map = await getDevicePollHealth(pool, { days: 3 });
      pollHealth = map.get(deviceId) || null;
      pollBand = pollHealthBand(pollHealth);
    } catch (_err) {
      // ⛔ STAYS `unknown`. A failed read of the poll history is not a passing
      // device, and it is not a failing one either.
      pollBand = REACHABILITY.UNKNOWN;
    }

    return deviceContextFacts({ ...row, pollBand, pollHealth }, opts);
  } catch (_err) {
    return null;
  }
}

// ⛔ EVERY EXPORTED NAME IS NAMESPACED, AND THAT IS NOT STYLE. The first
// draft exported `figure`, `freshness` and `REACH`. tests/importIntegrity.test.js
// treats any name a lib/ module exports as a helper a page must import if it
// mentions it — and `figure` appears as ordinary PROSE in 32 other files,
// `freshness` in 13. Adding the export turned a two-year-old JSX sentence in
// components/analysis/ChangeOutcomeBoard.js ("so it is a figure and not a
// verdict") into a build failure in a file this change never touched. The
// guard's own header records the same thing happening to `source`. Exempting
// it would have been the wrong fix: the hazard is the generic name.
module.exports = {
  deviceContextFacts,
  loadDeviceContext,
  collectionFreshness,
  postureFigure,
  deviceContextAgeInDays: ageInDays,
  REACHABILITY,
  FRESH_AFTER_DAYS,
};
