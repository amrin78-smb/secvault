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

// No previous timeout was set here — node-fetch@2 defaults to NO timeout at all,
// so a request that never gets a response (e.g. a firewall silently dropping
// packets instead of actively refusing the connection) hangs indefinitely rather
// than failing. A single stalled request can make a sync that should take ~1-2
// minutes look hung for 7+ minutes. `timeout` is node-fetch@2's socket-inactivity
// timeout (ms) — it aborts and rejects with a FetchError (type 'request-timeout')
// if the socket goes quiet for this long, at connect OR during the response.
const FETCH_TIMEOUT_MS = 20000;

async function fetchPage(cpeString, startIndex, resultsPerPage) {
  const url = buildUrl(cpeString, startIndex, resultsPerPage);
  const headers = {};
  if (process.env.NVD_API_KEY) {
    headers.apiKey = process.env.NVD_API_KEY;
  }
  const res = await fetch(url, { headers, timeout: FETCH_TIMEOUT_MS });
  if (!res.ok) {
    const err = new Error(`NVD request failed: HTTP ${res.status} for ${url}`);
    err.status = res.status;
    throw err;
  }
  try {
    return await res.json();
  } catch (parseErr) {
    // res.ok was true -- NVD responded, so it IS reachable -- but the body failed to
    // parse (truncated/corrupted JSON). This must NOT be mistaken for the "NVD
    // unreachable" case: a bare SyntaxError from .json() has no `.status`, which would
    // otherwise satisfy the same `err.status == null` check used below to trigger the
    // CIRCL fallback (see tryCirclFallback's callers). Mark it explicitly so callers can
    // tell a genuine network-level failure (fetch() itself throwing) apart from a
    // reachable-but-malformed response, and treat the latter as a generic NVD error
    // (log and skip that CPE string) rather than a reachability problem.
    const err = new Error(`NVD response body could not be parsed as JSON for ${url}: ${parseErr.message}`);
    err.nvdJsonParseError = true;
    throw err;
  }
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

// ────────────────────────────────────────────────────────────────────────
// CIRCL fallback (vulnerability.circl.lu "Vulnerability-Lookup" project) —
// used ONLY when an NVD request fails with a network-level error (timeout,
// DNS failure, connection refused/reset — i.e. fetch() itself throws, so
// `err.status` is undefined). NVD remains primary; CIRCL is never consulted
// when NVD responds at all (including 429/403/5xx — those are NVD-reachable
// failures, not reachability problems, so no fallback is attempted for them).
//
// LIVE-VERIFIED 2026-07-16 against the real API (per CLAUDE.md's "verify
// against live responses" rule) — the account API key surfaced during this
// session is NOT used or required:
//   curl ".../api/vulnerability/search/fortinet/fortios"      -> HTTP 200, no auth header sent
//   curl ".../api/vulnerability/cpesearch/<wildcard fortios cpe>" -> HTTP 200 but returned an
//     unrelated product (FortiPAM) under a FortiOS query — broader/fuzzier matching, NOT used.
//   curl ".../api/vulnerability/search/paloaltonetworks/pan-os?per_page=200" -> server clamped
//     page_size to 100 (not 200) — 100 is this file's CIRCL_PER_PAGE, not a guess.
//   Swagger confirms this endpoint: GET /vulnerability/search/{vendor}/{product}?page&per_page&since
// vendor/product path segments are derived directly from each VENDOR_CPES string
// (cpe:2.3:<part>:<vendor>:<product>:...) — same vendor/product pair CIRCL expects.
//
// Response shape: { results: { nvd: [[id, cveRecord], ...], cvelistv5: [...] }, total_count,
// page_size, page } — cveRecord is CVE Record Format 5.x (MITRE's own schema), NOT NVD API 2.0's
// shape. CVSS lives under containers.cna.metrics[] OR containers.adp[].metrics[] (varies per
// record — scan both), affected-version data under containers.cna.affected[].versions[] with a
// {version, status, lessThan, changes:[...]} shape instead of NVD's clean versionStartIncluding/
// versionEndExcluding. See extractAffectedRangesFromCveRecord for the simplification this implies.
// ────────────────────────────────────────────────────────────────────────
const CIRCL_BASE_URL = 'https://vulnerability.circl.lu/api';
const CIRCL_PER_PAGE = 100; // server-verified max — requesting more (e.g. 200) is silently clamped to this
const CIRCL_MAX_PAGES = 10; // defensive cap (1000 records) — our vendors top out around 460 (5 pages)
const CIRCL_PAGE_DELAY_MS = 500; // polite spacing between pages; CIRCL documents no rate limit, but NVD's own outage is exactly the scenario where hammering a second external API is least appropriate

// "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*" -> { vendor: 'fortinet', product: 'fortios' }
function cpeToVendorProduct(cpeString) {
  const parts = typeof cpeString === 'string' ? cpeString.split(':') : [];
  const vendor = parts[3];
  const product = parts[4];
  if (!vendor || !product) return null;
  return { vendor, product };
}

async function circlFetchPage(vendor, product, page) {
  const url = `${CIRCL_BASE_URL}/vulnerability/search/${encodeURIComponent(vendor)}/${encodeURIComponent(
    product
  )}?page=${page}&per_page=${CIRCL_PER_PAGE}`;
  const res = await fetch(url, { timeout: FETCH_TIMEOUT_MS });
  if (!res.ok) {
    const err = new Error(`CIRCL request failed: HTTP ${res.status} for ${url}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// Fetches every page for one vendor/product pair (capped at CIRCL_MAX_PAGES), deduped by
// cveMetadata.cveId across the "nvd" and "cvelistv5" result buckets CIRCL returns. Returns raw
// CVE Record Format 5.x objects — normalizeCirclRecord() converts them to this file's schema.
async function fetchFromCircl(vendor, product) {
  const records = [];
  const seen = new Set();
  let page = 1;
  let totalCount = null;
  let truncatedByPageCap = false;

  while (true) {
    if (page > CIRCL_MAX_PAGES) {
      truncatedByPageCap = true;
      break;
    }
    if (page > 1) await sleep(CIRCL_PAGE_DELAY_MS);
    const data = await circlFetchPage(vendor, product, page);
    totalCount = typeof data.total_count === 'number' ? data.total_count : records.length;

    // `total_count` counts raw entries across BOTH the "nvd" and "cvelistv5" buckets — the same
    // CVE commonly appears in both, so the deduped record count legitimately ends up well below
    // total_count even when every page has been fetched. sawAnyEntry (not "any NEW entry") is
    // the real continuation signal, matching how fetchPage's NVD pagination above stops on an
    // empty vulnerabilities[] array regardless of dedup — a page that's 100% duplicates of
    // already-seen CVEs should still advance, not be mistaken for "no more pages".
    const sources = (data.results && Object.values(data.results)) || [];
    let sawAnyEntry = false;
    for (const sourceList of sources) {
      if (!Array.isArray(sourceList)) continue;
      for (const entry of sourceList) {
        sawAnyEntry = true;
        const rec = Array.isArray(entry) ? entry[1] : entry;
        const cveId = rec && rec.cveMetadata && rec.cveMetadata.cveId;
        if (!cveId || seen.has(cveId)) continue;
        seen.add(cveId);
        records.push(rec);
      }
    }

    if (!sawAnyEntry) break; // page was genuinely empty — nothing more to fetch
    if (page * CIRCL_PER_PAGE >= totalCount) break; // fetched every page CIRCL says exists
    page++;
  }

  if (truncatedByPageCap) {
    console.warn(
      `[CIRCL fallback] ${vendor}/${product}: stopped after ${CIRCL_MAX_PAGES} pages (${records.length} unique CVE(s) so far) — total_count=${totalCount} suggests more may exist`
    );
  }
  return records;
}

// Scans BOTH containers.cna.metrics and every containers.adp[].metrics entry — CVE Record
// Format 5.x places CVSS data in either location depending on which org submitted it (confirmed
// live: a Fortinet-authored record carried it directly in cna.metrics, while an older Apache
// record only had it in adp[1].metrics). Same V3.1 -> V3.0 -> V2.0 preference order as pickCvss.
function pickCvssFromCveRecord(rec) {
  const cna = rec && rec.containers && rec.containers.cna;
  const adp = (rec && rec.containers && rec.containers.adp) || [];
  const metricSets = [];
  if (cna && Array.isArray(cna.metrics)) metricSets.push(...cna.metrics);
  for (const a of adp) {
    if (a && Array.isArray(a.metrics)) metricSets.push(...a.metrics);
  }
  for (const key of ['cvssV3_1', 'cvssV3_0', 'cvssV2_0']) {
    const found = metricSets.find((m) => m && m[key]);
    if (found) {
      const data = found[key];
      return {
        score: typeof data.baseScore === 'number' ? data.baseScore : null,
        vector: data.vectorString || null,
      };
    }
  }
  return { score: null, vector: null };
}

// Only affected[] entries whose own `cpes` list matches this vendor's CPE prefixes are used —
// same cross-vendor guard as extractAffectedRanges/extractFixedVersions for NVD data, since a
// single CVE Record can list `affected` entries for several sibling products (e.g. a Fortinet CVE
// naming both FortiOS and FortiProxy).
function matchingAffectedEntriesFromCveRecord(rec, vendorPrefixes) {
  const cna = rec && rec.containers && rec.containers.cna;
  const affected = (cna && cna.affected) || [];
  return affected.filter(
    (entry) => entry && Array.isArray(entry.cpes) && entry.cpes.some((c) => matchesAnyPrefix(c, vendorPrefixes))
  );
}

// KNOWN SIMPLIFICATION: CVE Record Format 5.x's affected[].versions[] entries can carry a
// `changes[]` timeline of finer-grained affected/unaffected toggles WITHIN one {version,
// lessThan} range (e.g. patched at an intermediate version, regressed again later). This
// extraction deliberately ignores `changes` and uses only the outer range — versionMatcher.js's
// {min, max, exclude_fixed} model has no representation for a mid-range toggle, and NVD's own
// data (this file's primary source) doesn't need one. Ignoring `changes` can only make a
// CIRCL-sourced range WIDER than the true affected set (a version patched mid-range still reads
// as affected here) — same conservative direction as this app's "unknown treated as applicable"
// tri-state rule elsewhere (CLAUDE.md "Applicability Tri-State Default"), never narrower.
// Strips a trailing wildcard segment CVE-Record version strings can carry
// (e.g. "8.0.*", or a bare "*" for "any version") — parseVersion() expects a
// plain dotted numeric string. Returns null (no bound) when nothing usable
// remains. Same helper as lib/feeds/paloalto.js's copy (duplicated, not
// imported — independent feed files, same established convention as this
// file's own upsertAdvisory being copied rather than shared).
function cleanVersionString(v) {
  if (typeof v !== 'string') return null;
  const cleaned = v.replace(/(\.\*)+$/, '').trim();
  return cleaned === '' || cleaned === '*' ? null : cleaned;
}

// ⛔ Bug fixed 2026-07-17, confirmed live (via lib/feeds/paloalto.js's
// identical extraction against the same CVE Record Format 5.x shape,
// CVE-2020-2021): when a versions[] entry has NEITHER lessThan NOR
// lessThanOrEqual, that means "this entire named branch is affected with no
// further fix" (a real, live-confirmed shape, e.g. an EOL branch) — the
// previous code left `max: null` in that case, which isInRange() treats as
// UNBOUNDED, matching every future version forever. Bound it to the end of
// the STATED branch instead (major[.minor].999), mirroring this app's
// existing "X.Y all versions" -> {min:"X.Y.0", max:"X.Y.999"} convention
// (lib/feeds/fortinet.js) — still conservative/wide within the branch
// actually named (consistent with the KNOWN SIMPLIFICATION below), never
// unbounded. A fully-specified release with no lessThan (3+ real segments)
// bounds to itself — an exact match, not a widened branch.
function boundBranchEnd(versionStr) {
  const cleaned = cleanVersionString(versionStr);
  if (!cleaned) return null;
  const segments = cleaned.split('.').filter(Boolean);
  if (segments.length === 0) return null;
  if (segments.length >= 3) return cleaned;
  return `${segments.join('.')}.999`;
}

function extractAffectedRangesFromCveRecord(rec, vendorPrefixes) {
  const ranges = [];
  for (const entry of matchingAffectedEntriesFromCveRecord(rec, vendorPrefixes)) {
    for (const v of entry.versions || []) {
      if (!v || v.status !== 'affected') continue;
      const max =
        v.lessThan != null ? v.lessThan : v.lessThanOrEqual != null ? v.lessThanOrEqual : boundBranchEnd(v.version);
      ranges.push({
        min: cleanVersionString(v.version),
        max,
        exclude_fixed: v.lessThan != null,
        vulnerable: true,
      });
    }
  }
  return ranges;
}

function extractFixedVersionsFromCveRecord(rec, vendorPrefixes) {
  const versions = new Set();
  for (const entry of matchingAffectedEntriesFromCveRecord(rec, vendorPrefixes)) {
    for (const v of entry.versions || []) {
      if (v && v.status === 'unaffected' && v.version) versions.add(v.version);
    }
  }
  return Array.from(versions);
}

function normalizeCirclRecord(rec, vendorSlug, vendorPrefixes) {
  const cveId = rec && rec.cveMetadata && rec.cveMetadata.cveId;
  if (!cveId) throw new Error('CIRCL record missing cveMetadata.cveId');
  const { score, vector } = pickCvssFromCveRecord(rec);
  const label = VENDOR_LABELS[vendorSlug] || vendorSlug;
  const cna = rec.containers && rec.containers.cna;
  return {
    cve_id: cveId,
    vendor: vendorSlug,
    title: `${label} — ${cveId}`,
    description: pickDescription(cna && cna.descriptions),
    cvss_score: score,
    cvss_vector: vector,
    // ⛔ Bug fixed 2026-07-17, confirmed live (paloalto.js, same endpoint
    // shape, CVE-2026-0300): cveMetadata.datePublished is not reliably
    // present — fall back to containers.cna.datePublic.
    published_at: (rec.cveMetadata && rec.cveMetadata.datePublished) || (cna && cna.datePublic) || null,
    affected_version_ranges: extractAffectedRangesFromCveRecord(rec, vendorPrefixes),
    fixed_in_versions: extractFixedVersionsFromCveRecord(rec, vendorPrefixes),
    // Same nvd.nist.gov detail URL regardless of which backend supplied the data — it's the
    // same real-world CVE either way, and unlike circl.lu this URL format is already relied on
    // elsewhere in this file, so no additional live verification of a circl.lu detail page was needed.
    advisory_url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
    raw_data: rec,
  };
}

// Tracks which source (NVD vs CIRCL) produced each cve_id's current cveMap entry, via a
// non-enumerable-in-spirit `_source` tag on the record (harmless extra property — upsertAdvisory
// reads named fields off `rec` individually, it never serializes the whole object). NVD is the
// primary/preferred source (see CLAUDE.md "Forcepoint CVE Data" / "NVD Fallback — CIRCL"): when a
// vendor has multiple CPE strings and one succeeds via NVD while another falls back to CIRCL
// within the SAME fetchCvesForVendor() run, a CIRCL record must never silently overwrite an
// already-NVD-sourced entry for the same cve_id — CIRCL's affected-range extraction is
// deliberately wider/less precise (see extractAffectedRangesFromCveRecord's "KNOWN
// SIMPLIFICATION" comment above). A CIRCL record filling in a cve_id NVD hasn't seen yet, or an
// NVD record replacing an earlier CIRCL one (e.g. a later CPE string's page succeeds via NVD after
// an earlier one fell back), are both still allowed — only CIRCL-over-NVD is blocked.
function setCveMapEntry(cveMap, rec, source) {
  const existing = cveMap.get(rec.cve_id);
  if (existing && existing._source === 'nvd' && source === 'circl') {
    console.warn(
      `[CIRCL fallback] ${rec.cve_id}: keeping existing NVD-sourced record, ignoring CIRCL duplicate for the same cve_id (NVD is preferred)`
    );
    return;
  }
  rec._source = source;
  cveMap.set(rec.cve_id, rec);
}

// Attempts the CIRCL fallback for the vendor/product pair behind one failed CPE string, merging
// any records it finds into the shared cveMap. `attemptedPairs` is per fetchCvesForVendor() call
// (not global) — it exists only to skip a redundant second CIRCL call when a vendor has more than
// one CPE string mapping to the SAME vendor/product pair (e.g. cisco_asa's o: and a: part variants
// both resolve to cisco/adaptive_security_appliance_software). Never throws — a CIRCL failure is
// just another entry in `errors`, same as an NVD failure.
async function tryCirclFallback(cpeString, vendorSlug, vendorPrefixes, cveMap, errors, attemptedPairs) {
  const vp = cpeToVendorProduct(cpeString);
  if (!vp) {
    errors.push({
      cve_id: null,
      message: `[CIRCL fallback] could not derive vendor/product from CPE string ${cpeString}; skipping`,
    });
    return;
  }
  const pairKey = `${vp.vendor}/${vp.product}`;
  if (attemptedPairs.has(pairKey)) return;
  attemptedPairs.add(pairKey);

  console.warn(`[CIRCL fallback] NVD unreachable for ${cpeString}; querying CIRCL for ${pairKey}`);
  try {
    const records = await fetchFromCircl(vp.vendor, vp.product);
    let added = 0;
    for (const rec of records) {
      try {
        const normalized = normalizeCirclRecord(rec, vendorSlug, vendorPrefixes);
        if (!cveMap.has(normalized.cve_id)) added++;
        setCveMapEntry(cveMap, normalized, 'circl');
      } catch (e) {
        errors.push({
          cve_id: (rec && rec.cveMetadata && rec.cveMetadata.cveId) || null,
          message: `[CIRCL fallback] failed to normalize record: ${e.message}`,
        });
      }
    }
    console.warn(`[CIRCL fallback] ${pairKey}: got ${records.length} record(s) from CIRCL (${added} new)`);
    // Also recorded in `errors` (despite being a success, not a real error) so
    // callers reading the returned/logged errors array -- e.g.
    // lib/feeds/index.js's summarizeCirclUsage(), which the Advisories page's
    // per-source status banner depends on -- can detect "CIRCL was used" even
    // when the rescue fully succeeded. Without this, every `console.warn`-only
    // line here was invisible outside engine.log, and summarizeCirclUsage
    // could only ever detect a FAILED fallback attempt, never a successful
    // one -- the exact case CIRCL exists for. Same "informational, not an
    // error" entry pattern lib/feeds/index.js's runNvdSync already uses for
    // its per-vendor summary line.
    errors.push({
      cve_id: null,
      message: `[CIRCL fallback] ${pairKey}: got ${records.length} record(s) from CIRCL (${added} new) (informational, not an error)`,
    });
  } catch (e) {
    errors.push({
      cve_id: null,
      message: `[CIRCL fallback] CIRCL request also failed for ${pairKey}: ${e.message}`,
    });
  }
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
  const circlAttempted = new Set(); // vendor/product pairs already tried via CIRCL this run

  for (const cpeString of cpeStrings) {
    let startIndex = 0;
    let totalResults = 1; // dummy value so the loop runs at least once
    let cpeSucceeded = true;
    let cpeRecordCount = 0;
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
            cpeSucceeded = false;
            if (err2.status == null && !err2.nvdJsonParseError) {
              await tryCirclFallback(cpeString, vendorSlug, vendorPrefixes, cveMap, errors, circlAttempted);
            }
            break; // give up on this CPE string's remaining pages, but keep the run alive
          }
        } else if (err.status === 403) {
          // API key problem — retrying won't help; log and skip this CPE string.
          errors.push({
            cve_id: null,
            message: `NVD returned HTTP 403 (API key issue?) for ${cpeString} startIndex=${startIndex}; skipping`,
          });
          cpeSucceeded = false;
          break;
        } else if (err.status == null && !err.nvdJsonParseError) {
          // No HTTP status at all -- fetch() itself threw (timeout, DNS failure, connection
          // refused/reset, etc.). This is the "NVD unreachable" case CIRCL exists to cover —
          // an HTTP status (429/403/5xx) means NVD responded, and a JSON-parse failure (see
          // fetchPage's nvdJsonParseError marker) means NVD responded too, just with a corrupted
          // body -- neither of those is a reachability problem, so neither takes this branch.
          //
          // One retry before falling back to CIRCL: a single transient blip (packet loss, a
          // momentary DNS hiccup) shouldn't immediately abandon NVD for the rest of this CPE
          // string's remaining pages, the same way the very first failure used to. Proportionate
          // to the 429 branch's one-retry shape above, but no backoff ladder -- just one short,
          // fixed delay.
          errors.push({
            cve_id: null,
            message: `NVD request failed (network error) for ${cpeString} startIndex=${startIndex}: ${err.message}; retrying once before falling back to CIRCL`,
          });
          await sleep(3000);
          await throttle();
          try {
            data = await fetchPage(cpeString, startIndex, RESULTS_PER_PAGE);
          } catch (err2) {
            errors.push({
              cve_id: null,
              message: `NVD request failed again after retry for ${cpeString} startIndex=${startIndex}: ${err2.message}`,
            });
            cpeSucceeded = false;
            if (err2.status == null && !err2.nvdJsonParseError) {
              await tryCirclFallback(cpeString, vendorSlug, vendorPrefixes, cveMap, errors, circlAttempted);
            }
            break;
          }
        } else if (err.nvdJsonParseError) {
          // NVD responded (res.ok was true in fetchPage) but the body was corrupted/truncated --
          // a generic NVD-side error, not a reachability problem. Log and skip this CPE string's
          // remaining pages, same treatment as the generic HTTP-error branch below; CIRCL is
          // never consulted for this case.
          errors.push({
            cve_id: null,
            message: `NVD response malformed for ${cpeString} startIndex=${startIndex}: ${err.message}`,
          });
          cpeSucceeded = false;
          break;
        } else {
          errors.push({
            cve_id: null,
            message: `NVD request failed for ${cpeString} startIndex=${startIndex}: ${err.message}`,
          });
          cpeSucceeded = false;
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
          setCveMapEntry(cveMap, rec, 'nvd');
          cpeRecordCount++;
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

    if (cpeSucceeded) {
      console.log(`[NVD] ${cpeString}: ${cpeRecordCount} CVE(s)`);
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
