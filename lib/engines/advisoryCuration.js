// lib/engines/advisoryCuration.js
//
// The curation surface for advisory_conditions.
//
// ── WHY THIS EXISTS ───────────────────────────────────────────────────────
// `advisory_conditions` was EMPTY on this fleet — zero rows — and that is not
// a bug, it is un-done work. CLAUDE.md is explicit that conditions are DATA,
// curated per advisory, not code. The consequence of leaving them empty is not
// neutral: with no condition rows an advisory's `config_applies` resolves to
// 'unknown', which lands on decision rule 5 and files it as `scheduled`. On
// this fleet that is 152 of 155 assessments sitting in one band — a queue with
// no prioritisation left in it.
//
// ⛔ THIS FILE DOES NOT DECIDE ANYTHING. It only EXTRACTS what the vendor and
// CISA already published, so a human can make the call quickly. Deriving a
// predicate from advisory prose would be exactly the "documentation lies" trap
// CLAUDE.md warns about — an advisory saying "affects the management
// interface" does not tell you which config path on which vendor proves it,
// and a wrong condition silently changes a CVE's priority band.
//
// A worked example of why the human is needed: CVE-2026-24858 is KEV-listed
// with CVSS 9.4 and its description names FortiAnalyzer, FortiManager and
// FortiWeb. This fleet runs FortiGate. Whether it applies at all is a
// judgement no text-matching rule should be trusted to make.

'use strict';

function firstString(...vals) {
  for (const v of vals) {
    if (typeof v === 'string' && v.trim() !== '') return v.trim();
  }
  return null;
}

function asArray(v) {
  return Array.isArray(v) ? v : [];
}

/**
 * Pull the human-readable facts out of a stored CVE Record (5.x) payload.
 *
 * ⛔ Every field is null/empty when the record does not carry it. Nothing here
 * is inferred, defaulted or summarised — a curator reading a blank field must
 * know the advisory was silent, not that this function gave up.
 *
 * @param {object|null} rawData `advisories.raw_data`
 * @returns {{description, affectedProducts, cwes, references, solution,
 *            ssvcExploitation, ssvcAutomatable, ssvcTechnicalImpact}}
 */
function extractCveRecord(rawData) {
  const empty = {
    description: null,
    affectedProducts: [],
    cwes: [],
    references: [],
    solution: null,
    ssvcExploitation: null,
    ssvcAutomatable: null,
    ssvcTechnicalImpact: null,
  };
  if (!rawData || typeof rawData !== 'object') return empty;

  const containers = rawData.containers || {};
  const cna = containers.cna || {};

  const description = firstString(
    asArray(cna.descriptions).find((d) => d && d.lang && String(d.lang).startsWith('en'))?.value,
    asArray(cna.descriptions)[0]?.value
  );

  // A CVE Record lists every affected product line, which is precisely the
  // fact that decides whether an advisory touches THIS fleet at all.
  const affectedProducts = [];
  for (const a of asArray(cna.affected)) {
    if (!a || typeof a !== 'object') continue;
    const product = firstString(a.product, a.packageName);
    if (!product) continue;
    // ⛔ `lessThan` is EXCLUSIVE and `lessThanOrEqual` is INCLUSIVE, and
    // collapsing them presented an exclusive bound as inclusive — CLAUDE.md's
    // own Operational-Notes footgun, verbatim. Live: CVE-2026-0285 carries
    // {version: "12.1.0", lessThan: "12.1.8"} and its own changes[] marks
    // 12.1.8 UNAFFECTED, but this rendered "12.1.0 to 12.1.8", so a curator
    // reading it against a 12.1.8 device would conclude it was in range and
    // write a condition wrong in the ESCALATING direction. 10 of the assessed
    // advisories carry both keys, and firstString() silently discarded one.
    const versions = asArray(a.versions)
      .filter((v) => v && v.version)
      .map((v) => {
        const parts = [];
        const lt = firstString(v.lessThan);
        const lte = firstString(v.lessThanOrEqual);
        if (lt) parts.push(`${v.version} to <${lt}`);
        if (lte) parts.push(`${v.version} to ${lte} (inclusive)`);
        if (parts.length === 0) return String(v.version);
        return parts.join(' / ');
      });
    affectedProducts.push({
      vendor: firstString(a.vendor),
      product,
      versions,
    });
  }

  const cwes = [];
  for (const pt of asArray(cna.problemTypes)) {
    for (const d of asArray(pt && pt.descriptions)) {
      const v = firstString(d && d.value, d && d.description);
      if (v) cwes.push(v);
    }
  }

  const references = asArray(cna.references)
    .map((r) => firstString(r && r.url))
    .filter(Boolean);

  const solution = firstString(asArray(cna.solutions)[0]?.value);

  // CISA's ADP enrichment. `Exploitation: active` is a strong, independent
  // signal and is worth putting in front of the curator — but it is CISA's
  // assessment of the CVE in the world, NOT of this fleet, which is the whole
  // reason a per-device condition is still needed.
  let ssvcExploitation = null;
  let ssvcAutomatable = null;
  let ssvcTechnicalImpact = null;
  for (const adp of asArray(containers.adp)) {
    for (const m of asArray(adp && adp.metrics)) {
      const opts = asArray(m && m.other && m.other.content && m.other.content.options);
      for (const o of opts) {
        if (!o || typeof o !== 'object') continue;
        if (o.Exploitation) ssvcExploitation = String(o.Exploitation);
        if (o.Automatable) ssvcAutomatable = String(o.Automatable);
        if (o['Technical Impact']) ssvcTechnicalImpact = String(o['Technical Impact']);
      }
    }
  }

  return {
    description,
    affectedProducts,
    cwes,
    references,
    solution,
    ssvcExploitation,
    ssvcAutomatable,
    ssvcTechnicalImpact,
  };
}

/**
 * The curation worklist: every advisory that is actually assessed against a
 * device, with how much it matters and whether anyone has curated it yet.
 *
 * ⛔ Only advisories with at least one assessment. Curating an advisory that
 * touches no device is busywork, and a worklist padded with them hides the
 * ones that matter.
 *
 * pool is always a parameter (CLAUDE.md).
 */
async function getCurationWorklist(pool) {
  const { rows } = await pool.query(
    `SELECT a.id, a.cve_id, a.vendor, a.cvss_score, a.kev_listed, a.published_at,
            a.raw_data,
            count(DISTINCT dca.device_id)::int AS devices,
            count(DISTINCT dca.id) FILTER (WHERE dca.version_affected)::int AS version_affected,
            count(DISTINCT dca.priority_band) FILTER (WHERE dca.priority_band = 'patch_now')::int AS any_patch_now,
            (SELECT count(*) FROM advisory_conditions ac WHERE ac.advisory_id = a.id)::int AS conditions
       FROM advisories a
       JOIN device_cve_assessments dca ON dca.advisory_id = a.id
      GROUP BY a.id
      ORDER BY a.kev_listed DESC,
               (SELECT count(*) FROM advisory_conditions ac WHERE ac.advisory_id = a.id) ASC,
               a.cvss_score DESC NULLS LAST,
               a.cve_id ASC`
  );

  return rows.map((r) => {
    const record = extractCveRecord(r.raw_data);
    return {
      id: r.id,
      cveId: r.cve_id,
      vendor: r.vendor,
      // ⛔ null, never 0. An advisory with no published score is not a
      // zero-severity advisory, and sorting it as one would bury it.
      cvssScore: r.cvss_score === null ? null : Number(r.cvss_score),
      kevListed: r.kev_listed === true,
      publishedAt: r.published_at,
      devices: Number(r.devices),
      versionAffected: Number(r.version_affected),
      anyPatchNow: Number(r.any_patch_now) > 0,
      conditions: Number(r.conditions),
      ...record,
    };
  });
}

/**
 * Fleet-level curation coverage, for the page header.
 *
 * ⛔ `pct` is null rather than 0 when there is nothing to curate — "0% curated"
 * and "nothing needs curating" are different states and must not look alike.
 */
function summarizeWorklist(items) {
  const list = Array.isArray(items) ? items : [];
  const total = list.length;
  const curated = list.filter((a) => a.conditions > 0).length;
  const uncuratedKev = list.filter((a) => a.conditions === 0 && a.kevListed).length;
  const assessments = list.reduce((n, a) => n + a.versionAffected, 0);
  return {
    total,
    curated,
    uncurated: total - curated,
    uncuratedKev,
    assessments,
    pct: total > 0 ? Math.round((curated / total) * 100) : null,
  };
}

module.exports = {
  extractCveRecord,
  getCurationWorklist,
  summarizeWorklist,
};
