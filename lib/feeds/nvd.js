// lib/feeds/nvd.js
// NVD API 2.0 client — per-vendor CPE queries for all Tier 1 vendors.
// CommonJS ONLY — this file is `require()`d by services/engine-worker.js (plain node).

// node-fetch@2's package.json declares BOTH "main" (CJS) and "module" (ESM)
// fields; Next.js's webpack bundler resolves "module" even for this plain
// require() when this file runs inside an API route's bundle (app/api/feeds/sync),
// so the raw result is the ESM namespace object, not the callable function --
// confirmed live via lib/adapters/forcepoint/smc.js hitting the identical bug
// ("typeof fetch === 'object'", every call failing instantly with a minified
// "X is not a function" before any real network attempt). A plain `node`
// invocation (this file also runs under services/engine-worker.js) does not
// hit this, which is why it wasn't caught outside the actual Next.js runtime.
const fetchModule = require('node-fetch');
const fetch = fetchModule.default || fetchModule;

const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RESULTS_PER_PAGE = 200;

// ────────────────────────────────────────────────────────────────────────
// VENDOR_CPES — vendor slug (must match devices.vendor EXACTLY) → array of
// CPE virtualMatchString patterns queried against NVD.
//
// Every string below was LIVE-VERIFIED (2026-07-15) against the real NVD CPE
// dictionary (https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=...)
// per CLAUDE.md's "verify against live responses" rule. Dictionary hit counts
// per vendor:product prefix are recorded next to each string. Do NOT add new
// strings without repeating that verification — invented CPE strings silently
// return zero results forever.
// ────────────────────────────────────────────────────────────────────────
const VENDOR_CPES = {
  // Pre-7.1 NGFW branding, and the 7.1+ FlexEdge SD-WAN rebrand. Query both, dedupe by cve_id.
  // See CLAUDE.md "Forcepoint CVE Data" / "Known Issues > NVD CPE Matching" — vendors are
  // inconsistent about updating CVE records after a rebrand, so some 7.1+ CVEs may still
  // only carry the NGFW CPE string. Querying both is required, not optional.
  // (These two are frozen — verified during the MVP build; see verification note below.)
  forcepoint: [
    'cpe:2.3:a:forcepoint:next_generation_firewall:*:*:*:*:*:*:*:*', // pre-7.1
    'cpe:2.3:a:forcepoint:flexedge_secure_sd-wan:*:*:*:*:*:*:*:*', // 7.1+ rebrand
  ],

  // Dictionary: 270 entries for o:fortinet:fortios. Spot-checked end-to-end:
  // cves/2.0?virtualMatchString=<this> → HTTP 200, totalResults=276 real CVEs.
  fortinet: ['cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*'],

  // Dictionary: 779 entries for o:paloaltonetworks:pan-os (keyword "pan-os").
  paloalto: ['cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*'],

  // Dictionary (keyword "cisco adaptive security appliance"): NVD is split between
  // part=o (940 entries) and part=a (680 entries) for the SAME product string —
  // older ASA CVEs were filed as applications, newer as OS. Query both, dedupe.
  cisco_asa: [
    'cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*',
    'cpe:2.3:a:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*',
  ],

  // Dictionary (keywords "check point gaia" / "check point quantum"):
  //   o:checkpoint:gaia_os (60), o:checkpoint:gaia_embedded (21 — Quantum Spark OS),
  //   o:checkpoint:quantum_security_gateway_firmware (4), o:checkpoint:quantum_spark_firmware (4).
  checkpoint: [
    'cpe:2.3:o:checkpoint:gaia_os:*:*:*:*:*:*:*:*',
    'cpe:2.3:o:checkpoint:gaia_embedded:*:*:*:*:*:*:*:*',
    'cpe:2.3:o:checkpoint:quantum_security_gateway_firmware:*:*:*:*:*:*:*:*',
    'cpe:2.3:o:checkpoint:quantum_spark_firmware:*:*:*:*:*:*:*:*',
  ],

  // Dictionary (keyword "sangfor"): only 3 entries total —
  // a:sangfor:next-gen_application_firewall (2, the NGAF firewall) and
  // a:sangfor:vdi_client (1, not a firewall — excluded). Sangfor's NVD coverage
  // is extremely sparse; expect few/zero advisories from this feed.
  sangfor: ['cpe:2.3:a:sangfor:next-gen_application_firewall:*:*:*:*:*:*:*:*'],
};

// Human-readable label per slug — used only for the synthesized advisory title.
const VENDOR_LABELS = {
  forcepoint: 'Forcepoint',
  fortinet: 'Fortinet',
  paloalto: 'Palo Alto Networks',
  cisco_asa: 'Cisco ASA',
  checkpoint: 'Check Point',
  sangfor: 'Sangfor',
};

// ────────────────────────────────────────────────────────────────────────
// LIVE VERIFICATION NOTE (MVP build, reconfirmed 2026-07-15) — per CLAUDE.md's
// rule to never trust vendor/API docs blindly, this was tested against the real
// NVD API 2.0 endpoint before writing this parser:
//
//   curl "...cves/2.0?cpeName=cpe:2.3:a:forcepoint:next_generation_firewall:*:*:*:*:*:*:*:*"
//     -> HTTP 404
//   curl "...cves/2.0?cpeName=cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"   (fully-versioned CPE)
//     -> HTTP 200
//   curl "...cves/2.0?virtualMatchString=cpe:2.3:a:forcepoint:next_generation_firewall:*:*:*:*:*:*:*:*"
//     -> HTTP 200, 3 real CVE records returned (CVE-2019-6143, CVE-2021-41530, CVE-2025-12690)
//   curl "...cves/2.0?virtualMatchString=cpe:2.3:a:forcepoint:flexedge_secure_sd-wan:*:*:*:*:*:*:*:*"
//     -> HTTP 200, 0 results (product string not yet present in NVD's CPE dictionary —
//       confirms CLAUDE.md's note that FlexEdge CVEs may still only carry the NGFW CPE)
//   node fetch "...cves/2.0?virtualMatchString=cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*&resultsPerPage=5"
//     -> HTTP 200, totalResults=276 (CVE-2005-4570, CVE-2005-3057, ... — plausible FortiOS CVEs)
//
// Conclusion: `cpeName` only accepts a FULLY-VERSIONED CPE (exact product+version) and
// returns 404 for a wildcard/version-less CPE like the strings we need.
// `virtualMatchString` is the correct parameter for wildcard CPE matching against a
// product line. Using `cpeName` as literally documented in some NVD guides would have
// made every sync run fail outright (404) for every query. This file therefore uses
// `virtualMatchString`, not `cpeName`. NEVER revert to `cpeName`.
// ────────────────────────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// One shared throttle across ALL vendors in a run — NVD rate limits by source IP,
// not by query, so the 6s (or 1.2s with API key) spacing must span vendor loops.
function makeThrottle() {
  const delayMs = process.env.NVD_API_KEY ? 1200 : 6000;
  let lastRequestAt = 0;
  return async function throttle() {
    const wait = lastRequestAt + delayMs - Date.now();
    if (wait > 0) await sleep(wait);
    lastRequestAt = Date.now();
  };
}

function buildUrl(cpeString, startIndex, resultsPerPage) {
  const params = new URLSearchParams({
    virtualMatchString: cpeString,
    resultsPerPage: String(resultsPerPage),
    startIndex: String(startIndex),
  });
  return `${NVD_BASE_URL}?${params.toString()}`;
}

async function fetchPage(cpeString, startIndex, resultsPerPage) {
  const url = buildUrl(cpeString, startIndex, resultsPerPage);
  const headers = {};
  if (process.env.NVD_API_KEY) {
    headers.apiKey = process.env.NVD_API_KEY;
  }
  const res = await fetch(url, { headers });
  if (!res.ok) {
    const err = new Error(`NVD request failed: HTTP ${res.status} for ${url}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

function pickDescription(descriptions) {
  if (!Array.isArray(descriptions) || descriptions.length === 0) return null;
  const en = descriptions.find((d) => d && d.lang === 'en');
  return (en || descriptions[0]).value || null;
}

function pickCvss(metrics) {
  if (!metrics) return { score: null, vector: null };
  const data =
    (metrics.cvssMetricV31 && metrics.cvssMetricV31[0] && metrics.cvssMetricV31[0].cvssData) ||
    (metrics.cvssMetricV30 && metrics.cvssMetricV30[0] && metrics.cvssMetricV30[0].cvssData) ||
    (metrics.cvssMetricV2 && metrics.cvssMetricV2[0] && metrics.cvssMetricV2[0].cvssData) ||
    null;
  return {
    score: data && typeof data.baseScore === 'number' ? data.baseScore : null,
    vector: data && data.vectorString ? data.vectorString : null,
  };
}

// "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*" → "cpe:2.3:o:fortinet:fortios:"
// (the part:vendor:product prefix, used to test whether a configuration cpeMatch
// entry belongs to the current vendor's product line).
function cpePrefixes(cpeStrings) {
  return cpeStrings.map((s) => s.replace(/(:\*)+$/, ':'));
}

function matchesAnyPrefix(criteria, prefixes) {
  if (!criteria || typeof criteria !== 'string') return false;
  return prefixes.some((p) => criteria.startsWith(p));
}

// cpe 2.3 URI: cpe:2.3:a:<vendor>:<product>:<version>:... — index 5 (0-based) is version.
function extractVersionFromCriteria(criteria) {
  if (!criteria || typeof criteria !== 'string') return null;
  const parts = criteria.split(':');
  const version = parts[5];
  return version && version !== '*' && version !== '-' ? version : null;
}

// versionEndIncluding = affects UP TO AND INCLUDING that version.
// versionEndExcluding = affects UP TO BUT NOT INCLUDING that version (i.e. that version is fixed).
// Getting these backwards marks patched devices as vulnerable — see CLAUDE.md Known Issues.
//
// vendorPrefixes filter: a CVE's `configurations` can list cpeMatch entries for MANY
// products (e.g. a shared library CVE affecting both FortiOS and PAN-OS). Only entries
// whose criteria matches the CURRENT vendor's CPE prefixes are extracted — otherwise
// another vendor's version ranges would pollute this vendor's applicability data.
function extractAffectedRanges(configurations, vendorPrefixes) {
  const ranges = [];
  for (const config of configurations || []) {
    for (const node of (config && config.nodes) || []) {
      for (const match of (node && node.cpeMatch) || []) {
        if (
          match &&
          match.vulnerable === true &&
          matchesAnyPrefix(match.criteria, vendorPrefixes)
        ) {
          ranges.push({
            min: match.versionStartIncluding != null ? match.versionStartIncluding : null,
            max:
              match.versionEndIncluding != null
                ? match.versionEndIncluding
                : match.versionEndExcluding != null
                ? match.versionEndExcluding
                : null,
            exclude_fixed: !!match.versionEndExcluding,
            vulnerable: true,
          });
        }
      }
    }
  }
  return ranges;
}

function extractFixedVersions(configurations, vendorPrefixes) {
  const versions = new Set();
  for (const config of configurations || []) {
    for (const node of (config && config.nodes) || []) {
      for (const match of (node && node.cpeMatch) || []) {
        if (
          match &&
          match.vulnerable === false &&
          matchesAnyPrefix(match.criteria, vendorPrefixes)
        ) {
          const v =
            match.versionStartIncluding ||
            match.versionEndIncluding ||
            match.versionEndExcluding ||
            extractVersionFromCriteria(match.criteria);
          if (v) versions.add(v);
        }
      }
    }
  }
  return Array.from(versions);
}

function normalizeCveItem(cve, vendorSlug, vendorPrefixes) {
  const { score, vector } = pickCvss(cve.metrics);
  const label = VENDOR_LABELS[vendorSlug] || vendorSlug;
  return {
    cve_id: cve.id,
    vendor: vendorSlug,
    // NVD has no title field for CVE records — synthesize one.
    title: `${label} — ${cve.id}`,
    description: pickDescription(cve.descriptions),
    cvss_score: score,
    cvss_vector: vector,
    published_at: cve.published || null,
    affected_version_ranges: extractAffectedRanges(cve.configurations, vendorPrefixes),
    fixed_in_versions: extractFixedVersions(cve.configurations, vendorPrefixes),
    advisory_url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    raw_data: cve,
  };
}

// Upsert one advisory. Returns true if the row was newly inserted, false if it already
// existed and was updated. Never touches kev_listed/kev_date — those belong to kev.js.
//
// KNOWN CROSS-VENDOR LIMITATION: advisories.cve_id is UNIQUE and the row holds ONE
// vendor. A CVE shared by multiple vendors (e.g. a common-library CVE) stays with
// whichever vendor upserted it FIRST — the ON CONFLICT clause deliberately keeps
// `vendor = advisories.vendor` (never EXCLUDED.vendor). The vendor-specific fields
// (title, affected_version_ranges, fixed_in_versions) are likewise only overwritten
// when the upserting vendor matches the row's existing vendor, so a later vendor's
// sync can refresh the vendor-neutral NVD data (cvss, description, raw_data) without
// clobbering the owning vendor's version-range data.
async function upsertAdvisory(pool, rec) {
  const result = await pool.query(
    `INSERT INTO advisories (
       cve_id, vendor, title, description, cvss_score, cvss_vector,
       published_at, affected_version_ranges, fixed_in_versions, advisory_url, raw_data,
       updated_at
     ) VALUES (
       $1, $2, $3, $4, $5, $6,
       $7::timestamptz, $8::jsonb, $9::jsonb, $10, $11::jsonb,
       now()
     )
     ON CONFLICT (cve_id) DO UPDATE SET
       vendor = advisories.vendor,
       title = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.title ELSE advisories.title END,
       description = EXCLUDED.description,
       cvss_score = EXCLUDED.cvss_score,
       cvss_vector = EXCLUDED.cvss_vector,
       published_at = EXCLUDED.published_at,
       affected_version_ranges = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.affected_version_ranges ELSE advisories.affected_version_ranges END,
       fixed_in_versions = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.fixed_in_versions ELSE advisories.fixed_in_versions END,
       advisory_url = EXCLUDED.advisory_url,
       raw_data = EXCLUDED.raw_data,
       updated_at = now()
     RETURNING (xmax = 0) AS inserted`,
    [
      rec.cve_id,
      rec.vendor,
      rec.title,
      rec.description,
      rec.cvss_score,
      rec.cvss_vector,
      rec.published_at,
      JSON.stringify(rec.affected_version_ranges),
      JSON.stringify(rec.fixed_in_versions),
      rec.advisory_url,
      JSON.stringify(rec.raw_data),
    ]
  );
  return result.rows[0].inserted === true;
}

// Fetch + upsert all CVEs for ONE vendor slug (all its CPE strings, paginated,
// rate-limited via the shared `throttle`, deduped by cve_id across CPE strings
// WITHIN the vendor). Never lets one bad page or one malformed CVE abort the run.
async function fetchCvesForVendor(pool, vendorSlug, throttle) {
  const errors = [];
  const cveMap = new Map();

  const cpeStrings = VENDOR_CPES[vendorSlug] || [];
  if (cpeStrings.length === 0) {
    console.warn(
      `[NVD] vendor "${vendorSlug}" has no verified CPE strings in VENDOR_CPES — skipping (no advisories will be pulled for it)`
    );
    return { inserted: 0, updated: 0, errors };
  }
  const vendorPrefixes = cpePrefixes(cpeStrings);

  for (const cpeString of cpeStrings) {
    let startIndex = 0;
    let totalResults = 1; // dummy value so the loop runs at least once
    while (startIndex < totalResults) {
      await throttle();

      let data = null;
      try {
        data = await fetchPage(cpeString, startIndex, RESULTS_PER_PAGE);
      } catch (err) {
        if (err.status === 429) {
          // Rate limited — back off 30s and retry once (see CLAUDE.md "NVD Rate Limiting").
          errors.push({
            cve_id: null,
            message: `NVD rate limited (HTTP 429) for ${cpeString} startIndex=${startIndex}; backing off 30s and retrying once`,
          });
          await sleep(30000);
          await throttle();
          try {
            data = await fetchPage(cpeString, startIndex, RESULTS_PER_PAGE);
          } catch (err2) {
            errors.push({
              cve_id: null,
              message: `NVD request failed again after retry for ${cpeString} startIndex=${startIndex}: ${err2.message}`,
            });
            break; // give up on this CPE string's remaining pages, but keep the run alive
          }
        } else if (err.status === 403) {
          // API key problem — retrying won't help; log and skip this CPE string.
          errors.push({
            cve_id: null,
            message: `NVD returned HTTP 403 (API key issue?) for ${cpeString} startIndex=${startIndex}; skipping`,
          });
          break;
        } else {
          errors.push({
            cve_id: null,
            message: `NVD request failed for ${cpeString} startIndex=${startIndex}: ${err.message}`,
          });
          break;
        }
      }

      if (!data) break;

      totalResults = typeof data.totalResults === 'number' ? data.totalResults : 0;
      const vulnerabilities = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];

      for (const entry of vulnerabilities) {
        const cve = entry && entry.cve;
        if (!cve || !cve.id) continue;
        try {
          const rec = normalizeCveItem(cve, vendorSlug, vendorPrefixes);
          cveMap.set(rec.cve_id, rec);
        } catch (e) {
          errors.push({ cve_id: cve.id || null, message: e.message });
        }
      }

      if (vulnerabilities.length === 0) break; // avoid an infinite loop on an unexpectedly empty page
      const pageSize =
        typeof data.resultsPerPage === 'number' && data.resultsPerPage > 0
          ? data.resultsPerPage
          : RESULTS_PER_PAGE;
      startIndex += vulnerabilities.length || pageSize;
    }
  }

  let inserted = 0;
  let updated = 0;
  for (const rec of cveMap.values()) {
    try {
      const wasInserted = await upsertAdvisory(pool, rec);
      if (wasInserted) inserted++;
      else updated++;
    } catch (e) {
      errors.push({ cve_id: rec.cve_id, message: e.message });
    }
  }

  return { inserted, updated, errors };
}

/**
 * Fetch all Tier 1 vendor CVEs from NVD (every vendor in VENDOR_CPES, every CPE
 * string, paginated, rate-limited) and upsert them into the `advisories` table.
 * One vendor's failure never aborts the others — each vendor runs in its own
 * try/catch and failures are recorded in `errors` (with a `vendor` field).
 * @param {import('pg').Pool} pool
 * @returns {Promise<{inserted: number, updated: number,
 *   errors: Array<{vendor?: string, cve_id: string|null, message: string}>,
 *   byVendor: Object<string, {inserted: number, updated: number}>}>}
 */
async function fetchAndUpsertVendorCves(pool) {
  const throttle = makeThrottle();
  const errors = [];
  const byVendor = {};
  let inserted = 0;
  let updated = 0;

  for (const vendorSlug of Object.keys(VENDOR_CPES)) {
    try {
      const result = await fetchCvesForVendor(pool, vendorSlug, throttle);
      byVendor[vendorSlug] = { inserted: result.inserted, updated: result.updated };
      inserted += result.inserted;
      updated += result.updated;
      for (const e of result.errors) {
        errors.push({ vendor: vendorSlug, cve_id: e.cve_id, message: e.message });
      }
    } catch (err) {
      byVendor[vendorSlug] = { inserted: 0, updated: 0 };
      errors.push({
        vendor: vendorSlug,
        cve_id: null,
        message: `vendor sync failed: ${err.message}`,
      });
    }
  }

  return { inserted, updated, errors, byVendor };
}

/**
 * @deprecated Back-compat wrapper — runs the NVD sync for the `forcepoint` vendor
 * ONLY. New code should use fetchAndUpsertVendorCves(pool), which covers all
 * Tier 1 vendors. Kept so any older caller keeps its original
 * {inserted, updated, errors} return shape.
 * @param {import('pg').Pool} pool
 * @returns {Promise<{inserted: number, updated: number, errors: Array<{cve_id: string|null, message: string}>}>}
 */
async function fetchAndUpsertForcepointCves(pool) {
  const throttle = makeThrottle();
  return fetchCvesForVendor(pool, 'forcepoint', throttle);
}

module.exports = { fetchAndUpsertVendorCves, fetchAndUpsertForcepointCves, VENDOR_CPES };
