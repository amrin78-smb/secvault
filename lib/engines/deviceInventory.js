// lib/engines/deviceInventory.js
//
// One query behind the Devices page: per-device posture (security score, risk
// band, CVE bands, rule count, support expiry, HA, drift) plus the fleet tiles
// above the table.
//
// CommonJS — consumed by the Devices page server component.
//
// ⛔ SCORE POLARITY, again. Two 0-100 numbers meet here and move in OPPOSITE
// directions: riskScore.js is higher-is-WORSE, securityScore.js is
// higher-is-BETTER. The Devices page shows the security score as the NUMBER and
// the risk band only as its COLOUR, deliberately — displaying both as figures
// side by side is a reliable way to get one read as the other. The single
// inversion still lives in securityScore.js's hygieneSubscore; nothing here
// re-derives it.

'use strict';

const { computeRiskScoreFromCounts } = require('./riskScore');
const { computeSecurityScore, securityScoreBand } = require('./securityScore');

// Accepted ?sort= values. ⛔ These were ORDER BY fragments in the first cut,
// which was actively misleading: sorting happens in JS (score and risk are
// DERIVED, not columns), the query has no ORDER BY at all, and two of the
// fragments named columns — security_sort, risk_sort — that never existed.
// Anyone reaching for them would have written a query that fails at runtime.
// A plain key set is what this actually is. The raw query param is only ever
// used as a lookup here; it is NEVER interpolated into SQL.
const SORT_OPTIONS = {
  name: true,
  score: true,
  risk: true,
  cve_count: true,
  rules: true,
  last_collected: true,
  vendor: true,
  site: true,
};

/**
 * Raw per-device rows. Everything here is a real column or a real aggregate —
 * no derived posture yet, that happens in JS so it reuses the same engines the
 * rest of the app uses rather than re-implementing them in SQL.
 */
async function getDeviceRows(pool) {
  const { rows } = await pool.query(
    `SELECT d.id, d.name, d.vendor, d.site, d.mgmt_ip, d.smc_host, d.asset_criticality,
            d.last_connectivity_ok, d.last_connectivity_checked_at, d.last_collected_at,
            dv.version_string,
            COALESCE(band.patch_now_count, 0)::int  AS patch_now_count,
            COALESCE(band.scheduled_count, 0)::int  AS scheduled_count,
            COALESCE(band.monitor_count, 0)::int    AS monitor_count,
            COALESCE(band.critical_cve_count, 0)::int AS critical_cve_count,
            COALESCE(rules.rule_count, 0)::int      AS rule_count,
            COALESCE(rules.enabled_count, 0)::int   AS enabled_rule_count,
            COALESCE(fnd.critical_findings, 0)::int AS critical_findings,
            COALESCE(fnd.high_findings, 0)::int     AS high_findings,
            COALESCE(fnd.medium_findings, 0)::int   AS medium_findings,
            COALESCE(fnd.info_findings, 0)::int     AS info_findings,
            comp.score_pct                          AS compliance_pct,
            ha.enabled       AS ha_enabled,
            ha.mode          AS ha_mode,
            ha.local_state   AS ha_local_state,
            ha.peer_connection_status AS ha_peer_status,
            lic.expired_count,
            lic.soonest_future_expiry,
            lic.unknown_expiry_count,
            COALESCE(drift.open_diffs, 0)::int AS open_diffs
       FROM devices d
       LEFT JOIN LATERAL (
         SELECT version_string FROM device_versions
          WHERE device_versions.device_id = d.id
          ORDER BY collected_at DESC LIMIT 1
       ) dv ON true
       LEFT JOIN LATERAL (
         -- CVSS lives on the advisories table, NOT on the assessment row: the
         -- assessment records SecVault's own judgement (band/applicability),
         -- the advisory records the CVE's published severity. Join for it.
         -- (No backticks in this comment -- it sits inside a template literal.)
         SELECT COUNT(*) FILTER (WHERE dca.priority_band = 'patch_now')  AS patch_now_count,
                COUNT(*) FILTER (WHERE dca.priority_band = 'scheduled')  AS scheduled_count,
                COUNT(*) FILTER (WHERE dca.priority_band = 'monitor')    AS monitor_count,
                COUNT(*) FILTER (WHERE a.cvss_score >= 9.0)              AS critical_cve_count
           FROM device_cve_assessments dca
           JOIN advisories a ON a.id = dca.advisory_id
          WHERE dca.device_id = d.id
       ) band ON true
       LEFT JOIN LATERAL (
         SELECT COUNT(*) AS rule_count, COUNT(*) FILTER (WHERE enabled) AS enabled_count
           FROM firewall_rules WHERE firewall_rules.device_id = d.id
       ) rules ON true
       LEFT JOIN LATERAL (
         SELECT COUNT(*) FILTER (WHERE severity = 'critical') AS critical_findings,
                COUNT(*) FILTER (WHERE severity = 'high')     AS high_findings,
                COUNT(*) FILTER (WHERE severity = 'medium')   AS medium_findings,
                COUNT(*) FILTER (WHERE severity = 'info')     AS info_findings
           FROM rule_analysis_results WHERE rule_analysis_results.device_id = d.id
       ) fnd ON true
       LEFT JOIN LATERAL (
         -- Same denominator rule as the compliance engine: 'na' is EXCLUDED,
         -- and the result is NULL (not 0) when nothing is measurable.
         SELECT CASE
                  WHEN COUNT(*) FILTER (WHERE status IN ('pass','fail','warning')) = 0 THEN NULL
                  ELSE ROUND(100.0 * COUNT(*) FILTER (WHERE status = 'pass')
                             / COUNT(*) FILTER (WHERE status IN ('pass','fail','warning')))
                END AS score_pct
           FROM audit_findings WHERE audit_findings.device_id = d.id
       ) comp ON true
       LEFT JOIN device_ha_status ha ON ha.device_id = d.id
       LEFT JOIN LATERAL (
         -- ⛔ Support expiry is TRI-STATE (see CLAUDE.md's lifecycle section):
         -- a NULL expires_at means PERPETUAL when expires_raw is 'Never' and
         -- UNKNOWN otherwise. Count the unknowns separately instead of letting
         -- them vanish into "no expiry", which would read as "fine".
         -- ⛔ NOT plain MIN(expires_at): that returns the OLDEST licence, which
         -- on a real device is one that lapsed years ago (HRIS's earliest is
         -- 2021-12-24). As a "supported until" column that reads as the current
         -- support date and is badly wrong. Split the three states apart:
         --   expired_count       - licences already past their date (act now)
         --   soonest_future_expiry - the next one to lapse (plan for it)
         --   unknown_expiry_count  - vendor string did not parse; NOT "fine"
         -- A perpetual licence (NULL date + raw 'Never') is correctly none of
         -- these and simply does not appear.
         SELECT COUNT(*) FILTER (WHERE expires_at < CURRENT_DATE)::int AS expired_count,
                MIN(expires_at) FILTER (WHERE expires_at >= CURRENT_DATE) AS soonest_future_expiry,
                COUNT(*) FILTER (
                  WHERE expires_at IS NULL AND COALESCE(expires_raw, '') NOT ILIKE 'never'
                )::int AS unknown_expiry_count
           FROM device_licenses WHERE device_licenses.device_id = d.id
       ) lic ON true
       LEFT JOIN LATERAL (
         SELECT COUNT(*) AS open_diffs
           FROM config_diffs
          WHERE config_diffs.device_id = d.id AND acknowledged_at IS NULL
       ) drift ON true
      WHERE d.active = true`
  );
  return rows;
}

/**
 * Adds derived posture to each row, reusing the shared engines.
 * ⛔ The per-device security score uses the SAME composition as the fleet score
 * (vulnerability / hygiene / compliance, unmeasurable components dropped from
 * the denominator) so a device's tile and the dashboard's tile can never
 * disagree about what the number means. For one device, "devices with patch_now"
 * is simply 0 or 1.
 */
function decorate(row) {
  const risk = computeRiskScoreFromCounts({
    critical: row.critical_findings,
    high: row.high_findings,
    medium: row.medium_findings,
    info: row.info_findings,
  });
  const analysed =
    row.critical_findings + row.high_findings + row.medium_findings + row.info_findings > 0;

  const security = computeSecurityScore({
    activeDevices: 1,
    devicesWithPatchNow: row.patch_now_count > 0 ? 1 : 0,
    devicesWithScheduled: row.patch_now_count > 0 ? 0 : row.scheduled_count > 0 ? 1 : 0,
    // No analysis rows at all -> pass [] so hygiene reports "not measurable"
    // rather than a confident 100 ("clean ruleset") it hasn't earned.
    deviceRiskScores: analysed ? [risk.score] : [],
    fleetCompliancePct: row.compliance_pct === null ? null : Number(row.compliance_pct),
  });

  return {
    ...row,
    riskScore: analysed ? risk.score : null,
    riskBand: analysed ? risk.band : null,
    securityScore: security.score,
    securityBand: securityScoreBand(security.score),
    securityComponents: security.components,
    compliancePct: row.compliance_pct === null ? null : Number(row.compliance_pct),
  };
}

// Sort keys that depend on derived values can't be done in SQL, so they're
// applied after decoration. Everything else is already ordered by the query.
function applyDerivedSort(rows, sortKey) {
  if (sortKey === 'score') {
    // Worst first — that is what an operator opening this page is looking for.
    // Nulls last: "not measurable" is not "worst".
    return [...rows].sort((a, b) => {
      if (a.securityScore === b.securityScore) return a.name.localeCompare(b.name);
      if (a.securityScore === null) return 1;
      if (b.securityScore === null) return -1;
      return a.securityScore - b.securityScore;
    });
  }
  if (sortKey === 'risk') {
    return [...rows].sort((a, b) => {
      if (a.riskScore === b.riskScore) return a.name.localeCompare(b.name);
      if (a.riskScore === null) return 1;
      if (b.riskScore === null) return -1;
      return b.riskScore - a.riskScore;
    });
  }
  return rows;
}

const SQL_SORTABLE = new Set(['name', 'cve_count', 'rules', 'last_collected', 'vendor', 'site']);

function sortRows(rows, sortKey) {
  if (SQL_SORTABLE.has(sortKey)) {
    // Cheap in-JS equivalents of the SQL orderings, so one code path sorts
    // everything and the page never mixes SQL and JS ordering rules.
    const by = {
      name: (a, b) => a.name.localeCompare(b.name),
      vendor: (a, b) => a.vendor.localeCompare(b.vendor) || a.name.localeCompare(b.name),
      site: (a, b) => (a.site || '￿').localeCompare(b.site || '￿') || a.name.localeCompare(b.name),
      rules: (a, b) => b.rule_count - a.rule_count || a.name.localeCompare(b.name),
      cve_count: (a, b) =>
        b.patch_now_count - a.patch_now_count ||
        b.scheduled_count - a.scheduled_count ||
        a.name.localeCompare(b.name),
      last_collected: (a, b) =>
        new Date(b.last_collected_at || 0) - new Date(a.last_collected_at || 0) ||
        a.name.localeCompare(b.name),
    };
    return [...rows].sort(by[sortKey]);
  }
  return applyDerivedSort(rows, sortKey);
}

/**
 * Fleet tiles above the table. Every figure is a count of the rows actually
 * shown, so the tiles and the table can never disagree.
 *
 * ⛔ Deliberately NOT included: an "Unsupported OS / EOL" tile. SecVault
 * collects no vendor OS end-of-life dates and no feed supplies them, so that
 * number cannot be produced. Support-CONTRACT expiry (below) is a different,
 * real fact and is what the Support column shows.
 */
function computeTiles(rows) {
  const now = Date.now();
  const soon = now + 90 * 86400000; // 90 days
  return {
    total: rows.length,
    online: rows.filter((r) => r.last_connectivity_ok === true).length,
    neverChecked: rows.filter((r) => r.last_connectivity_ok === null).length,
    criticalCves: rows.reduce((n, r) => n + r.critical_cve_count, 0),
    criticalCveDevices: rows.filter((r) => r.critical_cve_count > 0).length,
    patchNow: rows.reduce((n, r) => n + r.patch_now_count, 0),
    patchNowDevices: rows.filter((r) => r.patch_now_count > 0).length,
    supportExpired: rows.filter((r) => (r.expired_count || 0) > 0).length,
    supportExpiring: rows.filter(
      (r) =>
        (r.expired_count || 0) === 0 &&
        r.soonest_future_expiry &&
        new Date(r.soonest_future_expiry).getTime() <= soon
    ).length,
    supportUnknown: rows.filter((r) => (r.unknown_expiry_count || 0) > 0).length,
    driftDevices: rows.filter((r) => r.open_diffs > 0).length,
  };
}

async function getDeviceInventory(pool, { sort } = {}) {
  const raw = await getDeviceRows(pool);
  const decorated = raw.map(decorate);
  const sortKey = SORT_OPTIONS[sort] ? sort : 'name';
  return { rows: sortRows(decorated, sortKey), tiles: computeTiles(decorated), sortKey };
}

module.exports = {
  getDeviceInventory,
  SORT_OPTIONS,
  decorate,
  computeTiles,
};
