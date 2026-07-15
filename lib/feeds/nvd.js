// lib/feeds/nvd.js
// NVD API 2.0 client — dual-CPE query for Forcepoint (pre/post v7.1 rebrand).
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

// Pre-7.1 NGFW branding, and the 7.1+ FlexEdge SD-WAN rebrand. Query both, dedupe by cve_id.
// See CLAUDE.md "Forcepoint CVE Data" / "Known Issues > NVD CPE Matching" — vendors are
// inconsistent about updating CVE records after a rebrand, so some 7.1+ CVEs may still
// only carry the NGFW CPE string. Querying both is required, not optional.
const CPE_STRINGS = [
  'cpe:2.3:a:forcepoint:next_generation_firewall:*:*:*:*:*:*:*:*', // pre-7.1
  'cpe:2.3:a:forcepoint:flexedge_secure_sd-wan:*:*:*:*:*:*:*:*', // 7.1+ rebrand
];

// ────────────────────────────────────────────────────────────────────────
// LIVE VERIFICATION NOTE (2026-07-15) — per CLAUDE.md's rule to never trust
// vendor/API docs blindly, this was tested against the real NVD API 2.0
// endpoint before writing this parser:
//
//   curl "...cves/2.0?cpeName=cpe:2.3:a:forcepoint:next_generation_firewall:*:*:*:*:*:*:*:*"
//     -> HTTP 404
//   curl "...cves/2.0?cpeName=cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"   (fully-versioned CPE)
//     -> HTTP 200
//   curl "...cves/2.0?virtualMatchString=cpe:2.3:a:forcepoint:next_generation_firewall:*:*:*:*:*:*:*:*"
//     -> HTTP 200, 3 real CVE records returned (CVE-2019-6143, CVE-2021-41530, CVE-2025-12690)
//   curl "...cves/2.0?virtualMatchString=cpe:2.3:a:forcepoint:flexedge_secure_sd-wan:*:*:*:*:*:*:*:*"
///    -> HTTP 200, 0 results (product string not yet present in NVD's CPE dictionary —
//       confirms CLAUDE.md's note that FlexEdge CVEs may still only carry the NGFW CPE)
//
// Conclusion: `cpeName` only accepts a FULLY-VERSIONED CPE (exact product+version) and
// returns 404 for a wildcard/version-less CPE like the two Forcepoint strings we need.
// `virtualMatchString` is the correct parameter for wildcard CPE matching against a
// product line. Using `cpeName` as literally documented in some NVD guides would have
// made every sync run fail outright (404) for both queries. This file therefore uses
// `virtualMatchString`, not `cpeName`.
// ────────────────────────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
function extractAffectedRanges(configurations) {
  const ranges = [];
  for (const config of configurations || []) {
    for (const node of (config && config.nodes) || []) {
      for (const match of (node && node.cpeMatch) || []) {
        if (match && match.vulnerable === true) {
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

function extractFixedVersions(configurations) {
  const versions = new Set();
  for (const config of configurations || []) {
    for (const node of (config && config.nodes) || []) {
      for (const match of (node && node.cpeMatch) || []) {
        if (match && match.vulnerable === false) {
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

function normalizeCveItem(cve) {
  const { score, vector } = pickCvss(cve.metrics);
  return {
    cve_id: cve.id,
    vendor: 'forcepoint',
    // NVD has no title field for CVE records — synthesize one.
    title: `Forcepoint — ${cve.id}`,
    description: pickDescription(cve.descriptions),
    cvss_score: score,
    cvss_vector: vector,
    published_at: cve.published || null,
    affected_version_ranges: extractAffectedRanges(cve.configurations),
    fixed_in_versions: extractFixedVersions(cve.configurations),
    advisory_url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    raw_data: cve,
  };
}

// Upsert one advisory. Returns true if the row was newly inserted, false if it already
// existed and was updated. Never touches kev_listed/kev_date — those belong to kev.js.
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
       vendor = EXCLUDED.vendor,
       title = EXCLUDED.title,
       description = EXCLUDED.description,
       cvss_score = EXCLUDED.cvss_score,
       cvss_vector = EXCLUDED.cvss_vector,
       published_at = EXCLUDED.published_at,
       affected_version_ranges = EXCLUDED.affected_version_ranges,
       fixed_in_versions = EXCLUDED.fixed_in_versions,
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

/**
 * Fetch all Forcepoint CVEs from NVD (both CPE strings, paginated, rate-limited) and
 * upsert them into the `advisories` table.
 * Never lets one bad page or one malformed CVE abort the whole run.
 * @param {import('pg').Pool} pool
 * @returns {Promise<{inserted: number, updated: number, errors: Array<{cve_id: string|null, message: string}>}>}
 */
async function fetchAndUpsertForcepointCves(pool) {
  const errors = [];
  const cveMap = new Map();

  const delayMs = process.env.NVD_API_KEY ? 1200 : 6000;
  let lastRequestAt = 0;
  async function throttle() {
    const wait = lastRequestAt + delayMs - Date.now();
    if (wait > 0) await sleep(wait);
    lastRequestAt = Date.now();
  }

  for (const cpeString of CPE_STRINGS) {
    let startIndex = 0;
    let totalResults = 1; // dummy value so the loop runs at least once
    while (startIndex < totalResults) {
      await throttle();

      let data = null;
      try {
        data = await fetchPage(cpeString, startIndex, RESULTS_PER_PAGE);
      } catch (err) {
        if (err.status === 403 || err.status === 429) {
          errors.push({
            cve_id: null,
            message: `NVD rate limited (HTTP ${err.status}) for ${cpeString} startIndex=${startIndex}; backing off 30s and retrying once`,
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
          const rec = normalizeCveItem(cve);
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

module.exports = { fetchAndUpsertForcepointCves };
