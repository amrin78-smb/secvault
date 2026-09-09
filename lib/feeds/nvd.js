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
const { parseVersion, compareVersions } = require('../engines/versionComparator');
const { categorizeCwes } = require('../engines/vulnerabilityCategory');

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

const WILDCARD_TAIL = /\.?\*+$/;

// ⛔ A CVE-Record 5.x branch bound can carry a WILDCARD: `lessThan: "10.0*"`,
// `lessThan: "6.4.*"`. Unlike the cpeMatch path (which has
// branchRangeFromWildcardCriteria), this path took `max` RAW, and parseVersion
// then read "10.0*" as [10,0,0,0] — collapsing the ceiling onto or below the
// floor. With exclude_fixed the range becomes
// `device >= 10.0.0 AND device < 10.0.0`: UNSATISFIABLE, so the advisory can
// never match any device and the CVE silently vanishes from assessment.
// Live-confirmed: CVE-2021-3050 had all four ranges dead with 0 assessments,
// and CVE-2022-23439 / CVE-2022-35843 each carried dead wildcard ranges.
//
// ⛔ WIDEN, NEVER NARROW — same instinct as branchRangeFromWildcardCriteria and
// as CLAUDE.md's tri-state rule. A wildcard ceiling means "everything in this
// branch", so it expands to the TOP of the branch and the bound becomes
// INCLUSIVE (excludeFixed false). Under-reporting a vulnerable device is by far
// the worse error on a security product.
function expandWildcardMax(rawMax) {
  if (typeof rawMax !== 'string') return { max: rawMax, excludeFixed: true };
  const trimmed = rawMax.trim();
  if (trimmed.indexOf('*') === -1) return { max: trimmed, excludeFixed: true };
  // "10.0*" and "6.4.*" both mean the whole 10.0 / 6.4 branch.
  const branch = trimmed.replace(WILDCARD_TAIL, '');
  if (!branch) return { max: null, excludeFixed: true };
  return { max: branch + '.999', excludeFixed: false };
}

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
  if (!metrics) return { score: null, vector: null, version: null };
  // ⛔ The version is REPORTED, not just used. Two sources exposing different
  // CVSS versions for the same CVE is exactly how the fleet severity
  // histogram came to alternate between two states on identical totals.
  for (const [key, version] of [
    ['cvssMetricV40', '4.0'],
    ['cvssMetricV31', '3.1'],
    ['cvssMetricV30', '3.0'],
    ['cvssMetricV2', '2.0'],
  ]) {
    const entry = metrics[key] && metrics[key][0] && metrics[key][0].cvssData;
    if (!entry) continue;
    return {
      score: typeof entry.baseScore === 'number' ? entry.baseScore : null,
      vector: entry.vectorString || null,
      version,
    };
  }
  return { score: null, vector: null, version: null };
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
//
// ⛔ Bug fixed 2026-07-23, found while investigating repeat "[versionComparator]
// Unparseable version segment" log spam: this used to reject only the exact
// sentinels '*' (no constraint) and '-' (not applicable), so a version segment
// that's PARTIALLY wildcarded — e.g. "10.0.*", seen live for real PAN-OS-branch
// CPE entries — was returned as if it were one specific pinned version. It flows
// straight into extractAffectedRanges' pinnedVersion branch (below) as BOTH min
// AND max with no cleaning step (unlike this same file's OTHER extraction path,
// extractAffectedRangesFromCveRecord, which already runs cleanVersionString/
// looksLikeVersion — this native-NVD-API-2.0 path never did). At match time the
// trailing "*" segment fails to parse in versionComparator.js's tuple parser and
// silently defaults to 0, collapsing "10.0.*" to the single point [10,0,0] for
// BOTH bounds — a device on ANY OTHER build in that same branch (e.g. 10.0.5)
// then reads as OUTSIDE the "range" and is silently never flagged, even though
// the wildcard almost certainly meant "the whole 10.0.x branch is affected".
// Now rejects any version segment containing '*' the same way (returns null);
// extractAffectedRanges below separately expands a rejected wildcard segment
// into a real {min,max} branch range instead of dropping the entry, since
// widening an uncertain bound (not narrowing or discarding it) is this
// codebase's established conservative direction — see boundBranchEnd() in
// lib/feeds/paloalto.js and the "X.Y all versions" convention in
// lib/feeds/fortinet.js for the same interpretation already used elsewhere.
function extractVersionFromCriteria(criteria) {
  if (!criteria || typeof criteria !== 'string') return null;
  const parts = criteria.split(':');
  const version = parts[5];
  return version && version !== '*' && version !== '-' && !version.includes('*') ? version : null;
}

// A wildcarded CPE version segment (e.g. "10.0.*") names a BRANCH, not one
// exact release — expands it to {min: "10.0.0", max: "10.0.999"}, the same
// "whole named branch, still bounded, never unbounded" semantic this codebase
// already uses in lib/feeds/paloalto.js's boundBranchEnd() and lib/feeds/
// fortinet.js's "X.Y all versions" handling. Returns null when the segment
// isn't wildcarded this way, or nothing usable remains once the wildcard
// suffix is stripped (e.g. a bare "*" with no branch prefix at all — already
// excluded upstream by extractVersionFromCriteria, but guarded here too since
// this function can be called independently).
function branchRangeFromWildcardCriteria(criteria) {
  if (!criteria || typeof criteria !== 'string') return null;
  const version = criteria.split(':')[5];
  if (!version || !version.endsWith('.*')) return null;
  const branch = version.slice(0, -2);
  return branch ? { min: `${branch}.0`, max: `${branch}.999` } : null;
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
          const hasRangeField =
            match.versionStartIncluding != null ||
            match.versionEndIncluding != null ||
            match.versionEndExcluding != null;
          // ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep: a `cpeMatch`
          // entry can legitimately be `vulnerable: true` with NONE of the three
          // range fields set — NVD's shape for "this exact CPE version, and only
          // this one, is affected" (`criteria` pins a specific version, no range
          // needed). The old code fell through to {min:null, max:null} for this
          // case, and isInRange() treats a null bound as "no constraint on that
          // side" (by design, for genuinely-unbounded ranges) — so an
          // exact-version CVE silently matched EVERY version of that vendor's
          // product, forever, flipping every device to patch_now/scheduled for a
          // CVE that may only affect one specific old build. extractFixedVersions
          // below already has the correct fallback (extractVersionFromCriteria)
          // for the "fixed" side; this mirrors it for the "vulnerable" side.
          const pinnedVersion = hasRangeField ? null : extractVersionFromCriteria(match.criteria);
          // A wildcarded criteria version ("10.0.*") never satisfies
          // extractVersionFromCriteria above (rejected, not pinned) — check
          // separately for the branch-range interpretation before giving up.
          // See branchRangeFromWildcardCriteria's own header comment.
          const branchRange =
            hasRangeField || pinnedVersion ? null : branchRangeFromWildcardCriteria(match.criteria);
          if (!hasRangeField && !pinnedVersion && !branchRange) {
            // No range fields AND no usable version in criteria (e.g. a bare
            // vendor/product wildcard with no version segment at all) — this is
            // NOT a real "applies to everything" signal, just missing data.
            // Skip rather than emit an unbounded range from nothing.
            continue;
          }
          ranges.push({
            min:
              pinnedVersion ||
              (branchRange ? branchRange.min : null) ||
              (match.versionStartIncluding != null ? match.versionStartIncluding : null),
            max:
              pinnedVersion ||
              (branchRange ? branchRange.max : null) ||
              (match.versionEndIncluding != null
                ? match.versionEndIncluding
                : match.versionEndExcluding != null
                ? match.versionEndExcluding
                : null),
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

// Extracts CWE weakness ids from NVD API 2.0's `weaknesses[]` array
// (`weaknesses[].description[].value`, e.g. "CWE-78"). NVD also uses this
// same field for non-CWE placeholder values ("NVD-CWE-noinfo",
// "NVD-CWE-Other") when a CVE hasn't been mapped to a real weakness yet —
// normalizeCweId() (lib/engines/vulnerabilityCategory.js) filters those out,
// so this function can pass every raw value straight through and let that
// shared normalizer be the single place that knows what a real CWE id looks
// like, rather than duplicating that regex here.
function extractCweIds(cve) {
  const ids = new Set();
  for (const weakness of cve.weaknesses || []) {
    for (const desc of weakness.description || []) {
      if (desc && desc.value) ids.add(desc.value);
    }
  }
  return Array.from(ids);
}

function normalizeCveItem(cve, vendorSlug, vendorPrefixes) {
  const { score, vector, version } = pickCvss(cve.metrics);
  const label = VENDOR_LABELS[vendorSlug] || vendorSlug;
  const cweIds = extractCweIds(cve);
  return {
    cve_id: cve.id,
    vendor: vendorSlug,
    // NVD has no title field for CVE records — synthesize one.
    title: `${label} — ${cve.id}`,
    description: pickDescription(cve.descriptions),
    cvss_score: score,
    cvss_vector: vector,
    // Provenance travels with the score — see the upsert rule.
    cvss_source: 'nvd',
    cvss_version: version,
    published_at: cve.published || null,
    affected_version_ranges: extractAffectedRanges(cve.configurations, vendorPrefixes),
    fixed_in_versions: extractFixedVersions(cve.configurations, vendorPrefixes),
    advisory_url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    raw_data: cve,
    cwe_ids: cweIds,
    vulnerability_category: categorizeCwes(cweIds),
  };
}

// Upsert one advisory. Returns true if the row was newly inserted, false if it already
// existed and was updated. Never touches kev_listed/kev_date — those belong to kev.js.
//
// KNOWN CROSS-VENDOR LIMITATION: advisories.cve_id is UNIQUE and the row holds ONE
// vendor. A CVE shared by multiple vendors (e.g. a common-library CVE) stays with
// whichever vendor upserted it FIRST — the ON CONFLICT clause deliberately keeps
// `vendor = advisories.vendor` (never EXCLUDED.vendor). ⛔ Bug fixed 2026-07-19,
// found in a follow-up bug sweep: EVERY field used to be vendor-ownership-guarded
// like this EXCEPT description/cvss_score/cvss_vector/published_at/advisory_url/
// raw_data, which were unconditionally overwritten with EXCLUDED.* regardless of
// which vendor's sync was running. The original reasoning (see git history) was
// that CVSS/description are "vendor-neutral" NVD data any sync could refresh —
// but a genuine cross-vendor cve_id collision (a shared-library CVE affecting two
// vendors' products, or a different feed source's own scenario-specific take on
// the "same" CVE) could then silently overwrite the OWNING vendor's CVSS score
// and description with an unrelated source's data while leaving that row's
// title/ranges untouched — a corrupted hybrid record with mismatched severity
// and version data. Every column is now guarded the same way, matching this
// codebase's own "when in doubt, be conservative" philosophy elsewhere (the
// Applicability Tri-State Default never defaults to the riskier state either).
// Same fix mirrored in lib/feeds/paloalto.js and lib/feeds/fortinet.js's
// upsertAdvisory (independent copies, this codebase's established convention).
async function upsertAdvisory(pool, rec) {
  const result = await pool.query(
    `INSERT INTO advisories (
       cve_id, vendor, title, description, cvss_score, cvss_vector,
       published_at, affected_version_ranges, fixed_in_versions, advisory_url, raw_data,
       cwe_ids, vulnerability_category, cvss_source, cvss_version, matchability,
       updated_at
     ) VALUES (
       $1, $2, $3, $4, $5, $6,
       $7::timestamptz, $8::jsonb, $9::jsonb, $10, $11::jsonb,
       $12::text[], $13, $14, $15, $16,
       now()
     )
     ON CONFLICT (cve_id) DO UPDATE SET
       vendor = advisories.vendor,
       title = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.title ELSE advisories.title END,
       description = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.description ELSE advisories.description END,
       -- ⛔ NVD OUTRANKS CIRCL, and this is the whole fix.
       --
       -- Both sources feed this same function, and both pick a score with the
       -- cascade v4 > v3.1 > v3.0 > v2 from whatever the record happens to
       -- carry. NVD often exposes only v3.1 for a CVE whose CNA record (which
       -- is what CIRCL returns) also carries v4.0 — different versions, different
       -- numbers, same CVE. Since CIRCL is consulted ONLY when an NVD request
       -- fails at the network level, which day it answered was effectively
       -- random, and the fleet severity histogram alternated between
       -- 15/33/99/21 and 4/11/66/87 on IDENTICAL totals of 168.
       --
       -- So a CIRCL score may only FILL A GAP: it writes where there is no
       -- score yet, and never overwrites one NVD supplied. NVD always wins.
       -- The vendor guard below is unchanged and still applies first — a
       -- different vendor's row is never touched, whatever the source.
       cvss_score = CASE
                    WHEN advisories.vendor <> EXCLUDED.vendor THEN advisories.cvss_score
                    WHEN EXCLUDED.cvss_source = 'circl'
                         AND advisories.cvss_source IS DISTINCT FROM 'circl'
                         AND advisories.cvss_score IS NOT NULL
                      THEN advisories.cvss_score
                    ELSE EXCLUDED.cvss_score END,
       cvss_vector = CASE
                    WHEN advisories.vendor <> EXCLUDED.vendor THEN advisories.cvss_vector
                    WHEN EXCLUDED.cvss_source = 'circl'
                         AND advisories.cvss_source IS DISTINCT FROM 'circl'
                         AND advisories.cvss_score IS NOT NULL
                      THEN advisories.cvss_vector
                    ELSE EXCLUDED.cvss_vector END,
       -- Provenance moves WITH the score, or the pair would disagree.
       cvss_source = CASE
                    WHEN advisories.vendor <> EXCLUDED.vendor THEN advisories.cvss_source
                    WHEN EXCLUDED.cvss_source = 'circl'
                         AND advisories.cvss_source IS DISTINCT FROM 'circl'
                         AND advisories.cvss_score IS NOT NULL
                      THEN advisories.cvss_source
                    ELSE EXCLUDED.cvss_source END,
       cvss_version = CASE
                    WHEN advisories.vendor <> EXCLUDED.vendor THEN advisories.cvss_version
                    WHEN EXCLUDED.cvss_source = 'circl'
                         AND advisories.cvss_source IS DISTINCT FROM 'circl'
                         AND advisories.cvss_score IS NOT NULL
                      THEN advisories.cvss_version
                    ELSE EXCLUDED.cvss_version END,
       published_at = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.published_at ELSE advisories.published_at END,
       affected_version_ranges = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.affected_version_ranges ELSE advisories.affected_version_ranges END,
       fixed_in_versions = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.fixed_in_versions ELSE advisories.fixed_in_versions END,
       advisory_url = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.advisory_url ELSE advisories.advisory_url END,
       raw_data = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.raw_data ELSE advisories.raw_data END,
       cwe_ids = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.cwe_ids ELSE advisories.cwe_ids END,
       vulnerability_category = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.vulnerability_category ELSE advisories.vulnerability_category END,
       -- ⛔ CLEARING A STALE 'unmatchable' IS THE POINT, not bookkeeping. Only records this
       -- file classified 'matched' ever reach an upsert, so the value written here is always
       -- 'matched' — and that is exactly what a row needs when an extraction that failed
       -- yesterday (and was backfilled 'unmatchable' by lib/migrate.js) succeeds today. Without
       -- this, the stale label would keep versionMatcher excluding a row that now has real
       -- ranges, permanently. Vendor-guarded like every other column: a different vendor's row
       -- is never relabelled.
       matchability = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.matchability ELSE advisories.matchability END,
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
      rec.cwe_ids || null,
      rec.vulnerability_category || null,
      rec.cvss_source || null,
      rec.cvss_version || null,
      rec.matchability || null,
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
// record only had it in adp[1].metrics). Preference cascade extended with cvssV4_0 ahead of
// V3.1/V3.0/V2.0 — same reasoning and same key ordering as lib/feeds/paloalto.js's
// pickCvssFromPanOsRecord for this identical CVE Record Format 5.x shape (vendors are actively
// migrating to CVSS v4.0; a record carrying only a v4.0 metric must not fall through to null).
function pickCvssFromCveRecord(rec) {
  const cna = rec && rec.containers && rec.containers.cna;
  const adp = (rec && rec.containers && rec.containers.adp) || [];
  const metricSets = [];
  if (cna && Array.isArray(cna.metrics)) metricSets.push(...cna.metrics);
  for (const a of adp) {
    if (a && Array.isArray(a.metrics)) metricSets.push(...a.metrics);
  }
  for (const [key, version] of [
    ['cvssV4_0', '4.0'],
    ['cvssV3_1', '3.1'],
    ['cvssV3_0', '3.0'],
    ['cvssV2_0', '2.0'],
  ]) {
    const found = metricSets.find((m) => m && m[key]);
    if (found) {
      const data = found[key];
      return {
        score: typeof data.baseScore === 'number' ? data.baseScore : null,
        vector: data.vectorString || null,
        version,
      };
    }
  }
  return { score: null, vector: null, version: null };
}

// Normalizes a CVE-Record identity token (a `vendor`/`product` string, or a CPE vendor/product
// path segment) for loose comparison — lowercases and strips non-alphanumeric characters so
// naming variance (e.g. "next-gen_application_firewall" vs. "Next-Gen Application Firewall")
// doesn't defeat the match.
function normalizeIdentityToken(s) {
  return typeof s === 'string' ? s.toLowerCase().replace(/[^a-z0-9]/g, '') : '';
}

// Same normalization, but keeping the word boundaries: "Cisco Secure Firewall Adaptive
// Security Appliance (ASA) Software" -> ['cisco','secure','firewall','adaptive','security',
// 'appliance','asa','software']. Used by the token-subset half of the product match below,
// which is what survives a vendor inserting extra words INSIDE the product name.
function identityWordTokens(s) {
  return typeof s === 'string' ? s.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean) : [];
}

// CVE Record Format 5.x requires `vendor`/`product` on every affected[] entry, so records that
// genuinely don't know either fill them with a placeholder rather than omitting them. A
// placeholder PRODUCT is not evidence of anything and must never satisfy the product match
// below (that would attach an arbitrary advisory to this vendor's devices); a placeholder
// VENDOR is simply absent information, and the product string stays the discriminator.
const PLACEHOLDER_IDENTITY = new Set(['', 'na', 'notapplicable', 'unknown', 'unspecified', 'all']);

function isPlaceholderIdentity(normalized) {
  return PLACEHOLDER_IDENTITY.has(normalized);
}

// ────────────────────────────────────────────────────────────────────────
// CURATED_PRODUCT_ALIASES — a HUMAN-AUDITABLE alias table, deliberately NOT fuzzy matching.
//
// ⛔ THE RULE: every entry below is one product that two organisations SPELL differently, each
// verified by a person against both spellings' own sources. It is a table precisely so that
// widening the matcher is a reviewable, line-by-line act. Fuzzy string distance (Levenshtein,
// trigram similarity, "close enough") is banned here: it is exactly how another product's
// advisory eventually attaches to a device, which FABRICATES a vulnerability — the opposite
// failure from the empty ranges this whole mechanism exists to fix, and just as bad.
//
// Keyed by the NORMALIZED CPE product token (the value that reaches productMatchesCpeProduct's
// `pair.product`); each alias is an additional accepted spelling of THE SAME PRODUCT, matched
// with the identical two directional rules the primary token gets — never a looser one.
//
// Adding an entry requires, in the commit message or a comment here: the CPE dictionary string,
// the vendor's own record string, and the evidence they are one product.
// ────────────────────────────────────────────────────────────────────────
const CURATED_PRODUCT_ALIASES = {
  // Sangfor NGAF. NVD's CPE dictionary carries `a:sangfor:next-gen_application_firewall`
  // (2 entries, the only firewall CPE Sangfor has — see VENDOR_CPES.sangfor above), while
  // Sangfor's OWN CNA records — all 5 in the live corpus, CVE-2023-30802 … CVE-2023-30806,
  // every one of them vendor "Sangfor", product "Net-Gen Application Firewall", version
  // 8.0.17 — spell it "Net-Gen". Same product (Sangfor NGAF, the firewall this adapter
  // manages): same vendor, same product line, same 8.0.x version scheme as devices.vendor
  // 'sangfor'. The two strings differ by ONE letter, which is why this must be a curated
  // entry and not a distance threshold — 'net-gen' vs 'next-gen' is within one edit of each
  // other AND within one edit of nothing else we would ever want to match.
  nextgenapplicationfirewall: ['net-gen_application_firewall'],
};

// Derives {vendor, product} identity pairs from vendorPrefixes (e.g.
// "cpe:2.3:o:fortinet:fortios:" -> {vendor:'fortinet', product:'fortios'}) — used as the
// vendor/product fallback match below. `productTokens` is the same product split on word
// boundaries instead of collapsed, for the token-subset half of productMatchesCpeProduct().
// `aliases` carries any CURATED_PRODUCT_ALIASES spellings for that same product, pre-normalized
// into exactly the same {norm, tokens} shape so the alias cannot accidentally be matched by a
// looser rule than the primary token is.
function vendorProductPairsFromPrefixes(vendorPrefixes) {
  return vendorPrefixes
    .map((p) => {
      const parts = p.split(':'); // ['cpe','2.3','<part>','<vendor>','<product>','']
      const product = normalizeIdentityToken(parts[4]);
      return {
        vendor: normalizeIdentityToken(parts[3]),
        product,
        productTokens: identityWordTokens(parts[4]),
        aliases: (CURATED_PRODUCT_ALIASES[product] || []).map((alias) => ({
          norm: normalizeIdentityToken(alias),
          tokens: identityWordTokens(alias),
        })),
      };
    })
    .filter((pair) => pair.vendor && pair.product);
}

// ⛔ Loosened 2026-09-09 from EXACT equality to CONTAINMENT — see
// matchingAffectedEntriesFromCveRecord's header for the measured impact.
//
// Real CVE-Record product strings are marketing names, not CPE product tokens: "Fortinet
// FortiOS", "Cisco Secure Firewall Adaptive Security Appliance (ASA) Software", "Forcepoint
// Next Generation Firewall". NONE of those normalize to the CPE product token
// ('fortios' / 'adaptive_security_appliance_software' / 'next_generation_firewall'), so exact
// equality matched essentially nothing and every such record produced ZERO ranges.
//
// Two directional rules, both requiring the CPE product to be ENTIRELY present in the entry's
// product string (never the reverse — a shorter entry string being contained in a longer CPE
// product would let e.g. "Gaia Portal" claim gaia_os):
//   1. containment of the collapsed string  — 'fortinetfortios' ⊃ 'fortios'; also survives
//      pluralisation ('quantumsecuritygateways' ⊃ 'quantumsecuritygateway').
//   2. every CPE product WORD present as a word in the entry — survives words inserted in the
//      middle, which is the only thing that rescues Cisco's "(ASA)" infix.
//
// ⛔ Deliberately still NOT matching, verified against the live corpus: fortianalyzer,
// fortimanager, fortiweb, fortivoice, fortirecorder, fortisandbox, forticlient, fortiproxy-only
// entries (none contains 'fortios'), and Palo Alto's Prisma/Cortex/GlobalProtect siblings.
// Widening past that would attach ANOTHER product's version ranges to this vendor's firewalls —
// a FABRICATED vulnerability, which is the opposite failure and just as bad as the empty ranges
// this fixes.
// ⛔ The alias pass (added 2026-09-09) applies the SAME two rules to a CURATED_PRODUCT_ALIASES
// spelling — never a looser one. It is the only widening in this function that is not derivable
// from the CPE string itself, which is why the alias must come from an audited table rather than
// from string similarity. See CURATED_PRODUCT_ALIASES' own header.
function productMatchesCpeProduct(entryProductNorm, entryTokenSet, pair) {
  if (!entryProductNorm || isPlaceholderIdentity(entryProductNorm)) return false;
  if (entryProductNorm.includes(pair.product)) return true;
  if (pair.productTokens.length > 0 && pair.productTokens.every((token) => entryTokenSet.has(token))) {
    return true;
  }
  for (const alias of pair.aliases || []) {
    if (alias.norm && entryProductNorm.includes(alias.norm)) return true;
    if (alias.tokens.length > 0 && alias.tokens.every((token) => entryTokenSet.has(token))) {
      return true;
    }
  }
  return false;
}

// The vendor field is the WEAK half of this match and is used only to reject an entry that
// plainly belongs to somebody else (a Check Point advisory's bundled 'OpenSSL' entry, a Palo
// Alto advisory's 'The Linux Foundation'/'kernel' entry — both live). It is deliberately
// permissive otherwise: the CIRCL query was already scoped to this vendor/product pair, and
// real records spell the same vendor 'Fortinet' / 'Fortinet, Inc.' / 'n/a' interchangeably.
function vendorCompatible(entryVendorNorm, pairVendor) {
  if (isPlaceholderIdentity(entryVendorNorm)) return true;
  return entryVendorNorm.includes(pairVendor) || pairVendor.includes(entryVendorNorm);
}

// Matches affected[] entries against this vendor's CPE prefixes. Prefers the entry's own `cpes`
// list when present (precise, CPE-exact) — but `cpes` is an optional, NVD-specific enrichment
// that raw CVE List v5 ("cvelistv5") records commonly omit entirely (e.g. a CVE not yet processed
// by NVD's own CPE-matching pipeline). Falls back to the entry's `vendor`/`product` plain strings,
// which CVE Record Format 5.x requires on every affected[] entry, normalized for loose comparison.
// Without this fallback, such an entry is silently dropped, and a CIRCL-sourced advisory with zero
// matching entries ends up with empty affected_version_ranges/fixed_in_versions.
//
// ⛔ FIXED 2026-09-09. That fallback existed but required EXACT normalized equality between the
// record's vendor/product strings and the CPE vendor/product tokens, and real CVE-Record product
// strings never take that form — so it matched almost nothing. Measured live: 100% of the fleet's
// cisco_asa (351), checkpoint (7), sangfor (5) and forcepoint (3) advisories, plus 108 fortinet and
// 121 paloalto rows, carried EMPTY affected_version_ranges. Palo Alto's PSIRT rows survived only
// because those records literally spell the product "PAN-OS".
//
// That mattered far more than it looks, because NVD is unreachable from the reference deployment
// and CIRCL — which feeds THIS extraction path — is the operating source. `versionMatcher.js`'s
// `if (!versionAffected) continue;` cannot tell "no ranges to evaluate" from "ranges evaluated and
// missed", so a failed extraction was stored, and later read, as an affirmative "not affected":
// add a Check Point or ASA device and it gets a `last_cve_assessed_at` stamp, zero assessments,
// and a 100/100 vulnerability sub-score with the coverage signal AGREEING.
//
// See productMatchesCpeProduct()/vendorCompatible() above for the loosened rule and, just as
// importantly, for what it still refuses to match. The second half of the fix is
// classifyCveRecordMatchability() below: an advisory whose own record DECLARES affected versions
// but from which zero ranges could be extracted must not be persisted as a matchable-but-empty row.
function matchingAffectedEntriesFromCveRecord(rec, vendorPrefixes) {
  const cna = rec && rec.containers && rec.containers.cna;
  const affected = (cna && cna.affected) || [];
  const identityPairs = vendorProductPairsFromPrefixes(vendorPrefixes);
  return affected.filter((entry) => {
    if (!entry) return false;
    if (Array.isArray(entry.cpes) && entry.cpes.some((c) => matchesAnyPrefix(c, vendorPrefixes))) return true;
    const entryVendorNorm = normalizeIdentityToken(entry.vendor);
    const entryProductNorm = normalizeIdentityToken(entry.product);
    if (isPlaceholderIdentity(entryProductNorm)) return false;
    const entryTokenSet = new Set(identityWordTokens(entry.product));
    return identityPairs.some(
      (pair) =>
        vendorCompatible(entryVendorNorm, pair.vendor) &&
        productMatchesCpeProduct(entryProductNorm, entryTokenSet, pair)
    );
  });
}

// Does a MATCHING affected[] entry claim that some version of OUR product is affected at all?
// Distinct from "did we extract a range from it": this is the source record's own claim, and it
// is what separates an honest empty result ("this advisory lists our product as unaffected")
// from a failed read ("it says we're affected and we could not parse a single bound").
function declaresAffectedVersions(matchingEntries) {
  for (const entry of matchingEntries) {
    const versions = Array.isArray(entry.versions) ? entry.versions : [];
    if (versions.some((v) => v && v.status === 'affected')) return true;
    // An entry with no versions[] at all leans on defaultStatus — 'affected' there means
    // "every version", which is a declaration of affectedness with no bound we can store.
    if (versions.length === 0 && entry.defaultStatus === 'affected') return true;
  }
  return false;
}

/**
 * Decide whether a CVE-Record-shaped advisory may be persisted for this vendor.
 *
 * ⛔ The whole point: `advisories.affected_version_ranges = []` is READ downstream as "this
 * device is not affected" (versionMatcher.js:63). Storing an empty array because extraction
 * FAILED is CLAUDE.md's "a failed read is NOT a measurement" rule, one layer further in — it
 * manufactures a clean bill of health for a CVE nobody ever actually evaluated. Three outcomes:
 *
 *   'matched'      — ranges extracted; store it.
 *   'other_product'— no affected[] entry belongs to this vendor's product at all (Prisma Access,
 *                    Cortex XDR, FortiManager, an OpenSSL sub-entry). Skip, exactly as
 *                    lib/feeds/paloalto.js's own zero-match skip does — a sibling product's
 *                    advisory must never become this product's advisory row.
 *   'unmatchable'  — our product IS declared affected, but zero ranges survived extraction.
 *                    Skip AND report: an unstored advisory is at least honestly absent, whereas
 *                    a stored empty one is an affirmative, wrong "not affected".
 *
 * @param {object} rec - CVE Record Format 5.x record
 * @param {string[]} vendorPrefixes
 * @param {Array} extractedRanges - what extractAffectedRangesFromCveRecord() produced
 * @returns {{status: 'matched'|'other_product'|'unmatchable', reason: string|null}}
 */
function classifyCveRecordMatchability(rec, vendorPrefixes, extractedRanges) {
  const matchingEntries = matchingAffectedEntriesFromCveRecord(rec, vendorPrefixes);
  if (matchingEntries.length === 0) {
    // ⛔ "No entry matched" has two very different causes and only one of them justifies the
    // quiet skip. A record that names REAL products, none of them ours (Prisma Access, Cortex
    // XDR, FortiManager), is genuinely somebody else's advisory. A record whose affected[] is
    // all placeholders — 166 live cisco_asa rows are literally vendor 'n/a' / product 'n/a',
    // and CIRCL returned them for the ASA product query — identifies NO product at all, so
    // "not ours" would be a claim we cannot support. Report those as unmatchable instead.
    const cna = rec && rec.containers && rec.containers.cna;
    const affected = (cna && cna.affected) || [];
    const anyPlaceholderProduct =
      affected.length === 0 ||
      affected.some((e) => !e || isPlaceholderIdentity(normalizeIdentityToken(e.product)));
    if (!anyPlaceholderProduct) {
      return {
        status: 'other_product',
        reason: "every affected[] entry names a different product than this vendor's",
      };
    }
    return {
      status: 'unmatchable',
      reason:
        'no affected[] entry identifies a product (placeholder vendor/product), so this record ' +
        'can be neither matched to nor excluded from this product',
    };
  }
  if (Array.isArray(extractedRanges) && extractedRanges.length > 0) {
    return { status: 'matched', reason: null };
  }
  if (declaresAffectedVersions(matchingEntries)) {
    const products = matchingEntries
      .map((e) => (e && typeof e.product === 'string' ? e.product : '?'))
      .join(' / ');
    return {
      status: 'unmatchable',
      reason: `record declares affected versions for "${products}" but no version range could be extracted`,
    };
  }
  // Matching entries exist and NONE of them declares an affected version — the source itself
  // says our product is not affected. An empty range list is the honest answer here, not a
  // failed read, so this row is safe to store.
  return { status: 'matched', reason: null };
}

/**
 * The NVD-API-2.0-native counterpart of classifyCveRecordMatchability(), over `configurations`
 * / `nodes[].cpeMatch[]` instead of `containers.cna.affected[]`.
 *
 * ⛔ CHECKED FIRST, NOT ASSUMED (2026-09-09): the question was whether this path already
 * distinguishes "no ranges" from "could not extract". It does NOT. extractAffectedRanges()
 * above has an explicit `continue` for a cpeMatch that is `vulnerable: true` for OUR product
 * but carries no versionStart/End field and no usable version in its `criteria` — its own
 * comment calls that case "NOT a real 'applies to everything' signal, just missing data".
 * Skipping the range there is right; storing the resulting [] is the same failed-read-as-a-fact
 * bug as the CVE-Record path had, because versionMatcher reads [] as "not affected".
 *
 * ⛔ Live impact TODAY is zero and that is not a reason to skip it: every one of the 1,001
 * advisories in the reference deployment is CVE-Record-shaped, because NVD is unreachable from
 * that server and CIRCL is the operating source. This path is what runs on every deployment
 * where NVD IS reachable, so the asymmetry would be invisible exactly where it is untested.
 *
 * Same three outcomes, same meanings, as classifyCveRecordMatchability().
 *
 * @param {object} cve - NVD API 2.0 `vulnerabilities[].cve` object
 * @param {string[]} vendorPrefixes
 * @param {Array} extractedRanges - what extractAffectedRanges() produced
 * @returns {{status: 'matched'|'other_product'|'unmatchable', reason: string|null}}
 */
function classifyNvdNativeMatchability(cve, vendorPrefixes, extractedRanges) {
  const allMatches = [];
  for (const config of (cve && cve.configurations) || []) {
    for (const node of (config && config.nodes) || []) {
      for (const match of (node && node.cpeMatch) || []) {
        if (match) allMatches.push(match);
      }
    }
  }
  const ours = allMatches.filter((m) => matchesAnyPrefix(m.criteria, vendorPrefixes));
  const oursVulnerable = ours.filter((m) => m.vulnerable === true);

  if (Array.isArray(extractedRanges) && extractedRanges.length > 0) {
    return { status: 'matched', reason: null };
  }
  if (oursVulnerable.length > 0) {
    return {
      status: 'unmatchable',
      reason:
        `${oursVulnerable.length} cpeMatch entry(ies) mark this product vulnerable but carry no ` +
        'version bound and no usable version in their criteria — no range could be extracted',
    };
  }
  if (ours.length > 0) {
    // Our product appears, exclusively as `vulnerable: false`. NVD's own applicability
    // statement says this product is not affected — an empty range list is that ANSWER.
    return { status: 'matched', reason: null };
  }
  if (allMatches.length === 0) {
    // No CPE applicability data at all (NVD "Awaiting Analysis"). Defensive: a
    // virtualMatchString query should not return such a record, since that parameter matches
    // against these very statements. It can neither be matched to nor excluded from this
    // product, so it is unmatchable — never "not affected".
    return {
      status: 'unmatchable',
      reason: 'record carries no CPE applicability statement at all (NVD has not analysed it)',
    };
  }
  return {
    status: 'other_product',
    reason: "every cpeMatch entry names a different product than this vendor's",
  };
}

// KNOWN SIMPLIFICATION: CVE Record Format 5.x's affected[].versions[] entries
// can carry a `changes[]` timeline of finer-grained affected/unaffected
// toggles WITHIN one {version, lessThan} range (e.g. patched at an
// intermediate version by one hotfix train, a DIFFERENT train patched at a
// different point). versionMatcher.js's {min, max, exclude_fixed} model has
// no representation for that full timeline — extractAffectedRangesFromCveRecord
// below now DOES read `changes[]` (see its own comment) when there's no
// top-level lessThan/lessThanOrEqual to fall back to, using the HIGHEST
// 'unaffected' point as max, which can still make a range WIDER than the
// true per-train affected set (some intermediate already-patched points get
// counted as "still affected") — same conservative-never-narrower direction
// as this app's "unknown treated as applicable" tri-state rule elsewhere
// (CLAUDE.md "Applicability Tri-State Default").
//
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

// ⛔ Bug fixed 2026-07-17 (third pass), confirmed live via
// lib/feeds/paloalto.js's identical fix: some CIRCL/CVE-Record advisories
// (confirmed: PAN-SA-2023-0004, an informational bulletin) use versions[] to
// describe CONFIGURATION SCENARIOS, not firmware version ranges — e.g. a
// `version` field literally reading "with GlobalProtect app on Windows,
// macOS, and Linux LocalNet: Configurations allowing local network access,
// ServerIP: Gateways with address set as an FQDN". Others carry a bare "All"
// or "". None of these are version numbers; feeding them through
// cleanVersionString/boundBranchEnd produced a meaningless (though
// self-canceling — never falsely matched a real device) range and spammed
// engine.log with "[versionComparator] Unparseable version segment"
// warnings on every sync. Reject anything that doesn't look like a real
// version (short, starts with a digit/optional v) before it reaches
// range/fixed-version extraction.
function looksLikeVersion(cleaned) {
  if (!cleaned) return false;
  if (cleaned.length > 20) return false;
  return /^v?\d/i.test(cleaned);
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

// ────────────────────────────────────────────────────────────────────────
// PROSE VERSION BOUNDS — a CLOSED WHITELIST of three sentence shapes, nothing else.
//
// ⛔ Added 2026-09-09 to fix an UNDER-report, and it must never become an over-report.
// Some CNA records put the bound in the `version` field as English rather than in
// lessThan/lessThanOrEqual: "5.6.7 and below", "6.4.0 - 6.4.6", "5.2 all versions" (live,
// Fortinet and Forcepoint). Those strings are short and start with a digit, so
// looksLikeVersion() accepts them and they became {min:"5.6.7 and below", max:"5.6.7 and
// below"} — parseVersion then reads both bounds as [5,6,7], a self-consistent SINGLE POINT.
// Only a device sitting exactly on 5.6.7 matched, when the source plainly said 5.6.7 AND
// EVERYTHING BELOW. Under-reporting, not a false positive — which is why this was safe to
// leave, and why the fix may only widen toward the source's literal words.
//
// ⛔ THE WHOLE STRING MUST BE ONE OF THESE SHAPES. That anchoring is the safety property, not
// a formality: the same corpus contains "FortiSwitch 7.0.2 and below, 6.4.9 and below, …;
// FortiOS 7.0.2 and below, …" and "FortiGate 6.0.0 through 6.0.4, 5.6.0 through 5.6.7, 5.2 and
// earlier and FortiProxy versions 2.0.0, 1.2.8 and earlier". Pulling a bound out of one of
// THOSE means deciding which clause belongs to which product from prose — i.e. guessing, with
// the failure mode being another product's ceiling applied to this one. Those keep today's
// behaviour (a self-consistent narrow point) and stay honestly under-reported. Never "improve"
// this by relaxing the anchors or splitting on commas.
//
// Returns {min, max} where min may be null (an "and below" claim has no lower bound), or null
// when the string is not one of the three shapes.
function parseProseVersionRange(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.trim().replace(/\.$/, '');
  const V = '\\d+(?:\\.\\d+)*';

  // 1. "<v> and below" / "and earlier" / "and prior" / "and all earlier versions" — an upper
  //    bound with NO floor. boundBranchEnd() puts the ceiling at the end of the named branch
  //    ("5.2" -> 5.2.999, "5.6.7" -> 5.6.7 exactly), the same convention this file already
  //    uses for an unbounded named branch.
  let m = new RegExp(`^v?(${V})\\s+and\\s+(?:all\\s+)?(?:below|earlier|prior)(?:\\s+versions?)?$`, 'i').exec(s);
  if (m) return { min: null, max: boundBranchEnd(m[1]) };

  // 2. "<a> - <b>" / "<a> to <b>" / "<a> through <b>" — both endpoints stated, inclusive.
  m = new RegExp(`^v?(${V})\\s*(?:-|–|—|to|through)\\s*v?(${V})$`, 'i').exec(s);
  if (m) return { min: m[1], max: boundBranchEnd(m[2]) };

  // 3. "<branch> all versions" — the whole named branch, same reading as lib/feeds/fortinet.js's
  //    own "X.Y all versions" convention.
  m = new RegExp(`^v?(${V})\\s+all\\s+versions?$`, 'i').exec(s);
  if (m) return { min: m[1], max: boundBranchEnd(m[1]) };

  return null;
}

// ⛔ Bug fixed 2026-07-17 (second pass — see the identical fix and full
// reasoning in lib/feeds/paloalto.js's highestVersionFromChanges, confirmed
// live via CVE-2026-0257: boundBranchEnd's "3+ segments = bound to self"
// rule turned a genuine open branch like {"version":"11.1.0","status":
// "affected","changes":[{"at":"11.1.13-h5","status":"unaffected"},...]} into
// a single-point range, which would have made an actually-still-vulnerable
// device silently stop matching on the next sync — a false-negative
// regression, not just a missing Fixed-In field). When lessThan/
// lessThanOrEqual are both absent, check `changes[]` for 'unaffected' points
// FIRST and use the HIGHEST one as max; boundBranchEnd is now reached only
// when there is truly nothing (no lessThan, no lessThanOrEqual, no usable
// changes[]) to go on.
function highestVersionFromChanges(changes, vendorSlug) {
  let highest = null;
  let highestTuple = null;
  for (const c of changes || []) {
    if (!c || c.status !== 'unaffected') continue;
    const cleaned = cleanVersionString(c.at);
    if (!cleaned || !looksLikeVersion(cleaned)) continue;
    const tuple = parseVersion(vendorSlug, cleaned);
    if (!highestTuple || compareVersions(tuple, highestTuple) > 0) {
      highest = cleaned;
      highestTuple = tuple;
    }
  }
  return highest;
}

// ⛔ Bug fixed 2026-07-18, confirmed live: see versionComparator.js's
// isSafeOnMatchingTrain/isInRange for the full reasoning (CVE-2026-0257,
// PAN-OS 11.1's `changes[]` timeline naming SIX independent per-hotfix-train
// fix points, not just one). highestVersionFromChanges above keeps only the
// SINGLE HIGHEST 'unaffected' point for the coarse {min,max} range ceiling —
// this sibling function collects EVERY valid 'unaffected' checkpoint from the
// same `changes[]` array (same per-entry validation, unaffected/cleanVersionString/
// looksLikeVersion) so isInRange can also check a device against its OWN
// train's named fix point, not just the overall max. Identical fix and
// reasoning as lib/feeds/paloalto.js's allCheckpointsFromChanges — kept as a
// separate copy here per this file's established "duplicated, not imported"
// convention for feed-file helpers (see cleanVersionString's own comment).
function allCheckpointsFromChanges(changes) {
  const checkpoints = [];
  for (const c of changes || []) {
    if (!c || c.status !== 'unaffected') continue;
    const cleaned = cleanVersionString(c.at);
    if (cleaned && looksLikeVersion(cleaned)) checkpoints.push(cleaned);
  }
  return checkpoints;
}

function extractAffectedRangesFromCveRecord(rec, vendorSlug, vendorPrefixes) {
  const ranges = [];
  for (const entry of matchingAffectedEntriesFromCveRecord(rec, vendorPrefixes)) {
    for (const v of entry.versions || []) {
      if (!v || v.status !== 'affected') continue;
      // A `version` field that is one of parseProseVersionRange()'s three whitelisted English
      // shapes ("5.6.7 and below", "6.4.0 - 6.4.6", "5.2 all versions") carries a REAL bound
      // that cleanVersionString cannot see — read it here rather than let the whole sentence
      // through as both min and max, which collapsed to a single point. Anything else keeps
      // the previous behaviour exactly. See parseProseVersionRange's header for why this is a
      // closed whitelist and must stay one.
      const prose = parseProseVersionRange(v.version);
      const min = prose ? prose.min : cleanVersionString(v.version);
      // A non-version-shaped `version` field (a config-scenario description,
      // "All", or "") means this entry doesn't describe a firmware version
      // range at all — skip it rather than emit a meaningless range.
      // (`min` is legitimately null for a prose "and below" claim, which has no floor.)
      if (!prose && (!min || !looksLikeVersion(min))) continue;
      let max;
      let excludeFixed;
      // ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep: this used to
      // only call allCheckpointsFromChanges() inside the final `else` branch
      // below, i.e. only when NEITHER lessThan NOR lessThanOrEqual was present.
      // A real CVE Record Format entry can legitimately have a top-level
      // lessThan/lessThanOrEqual bound AND a changes[] timeline of per-train
      // fix points at the same time (the top-level bound covering the "main"
      // branch, changes[] naming earlier fix points on other hotfix trains) —
      // in that shape every checkpoint was silently dropped, so
      // isSafeOnMatchingTrain in versionComparator.js had nothing to check a
      // device's own train against even though the source data had it. Now
      // collected unconditionally whenever changes[] is present, independent
      // of which branch below determines max/excludeFixed.
      const safeExactVersions = allCheckpointsFromChanges(v.changes);
      if (v.lessThan != null) {
        const expanded = expandWildcardMax(v.lessThan);
        max = expanded.max;
        excludeFixed = expanded.excludeFixed;
      } else if (v.lessThanOrEqual != null) {
        max = v.lessThanOrEqual;
        excludeFixed = false;
      } else if (prose) {
        // A structured lessThan/lessThanOrEqual always outranks the prose (checked above) —
        // this branch is only reached when the sentence IS the only stated bound.
        max = prose.max;
        excludeFixed = false;
      } else {
        const changesMax = highestVersionFromChanges(v.changes, vendorSlug);
        if (changesMax) {
          max = changesMax;
          excludeFixed = true;
        } else {
          max = boundBranchEnd(v.version);
          excludeFixed = false;
        }
      }
      ranges.push({
        min,
        max,
        exclude_fixed: excludeFixed,
        safe_exact_versions: safeExactVersions,
        vulnerable: true,
      });
    }
  }
  return ranges;
}

// ⛔ Bug fixed 2026-07-17: previously only checked v.status === 'unaffected'
// at the TOP level of a versions[] entry — see paloalto.js's identical fix
// and full reasoning (CVE-2026-0257 has no top-level 'unaffected' entries at
// all; every real fix point lives inside `changes[]`). Now also collects
// every 'unaffected' change point from every entry's `changes[]`.
function extractFixedVersionsFromCveRecord(rec, vendorPrefixes) {
  const versions = new Set();
  for (const entry of matchingAffectedEntriesFromCveRecord(rec, vendorPrefixes)) {
    for (const v of entry.versions || []) {
      if (v && v.status === 'unaffected' && v.version) {
        const cleaned = cleanVersionString(v.version);
        if (cleaned && looksLikeVersion(cleaned)) versions.add(cleaned);
      }
      for (const c of (v && v.changes) || []) {
        if (c && c.status === 'unaffected' && c.at) {
          const cleaned = cleanVersionString(c.at);
          if (cleaned && looksLikeVersion(cleaned)) versions.add(cleaned);
        }
      }
    }
  }
  return Array.from(versions);
}

// CVE Record Format 5.x's weakness field: containers.cna.problemTypes[].descriptions[].cweId
// (an ADP container can carry its own problemTypes too, same as the CVSS
// scan in pickCvssFromCveRecord — scan both, same reasoning: different
// orgs can author either container). cweId is usually already a bare
// "CWE-NNN" string; normalizeCweId() (imported below) is the single place
// that validates/strips that format, so this just collects raw values.
function extractCweIdsFromCveRecord(rec) {
  const ids = new Set();
  const containers = [];
  if (rec.containers && rec.containers.cna) containers.push(rec.containers.cna);
  if (Array.isArray(rec.containers && rec.containers.adp)) containers.push(...rec.containers.adp);
  for (const container of containers) {
    for (const problemType of container.problemTypes || []) {
      for (const desc of problemType.descriptions || []) {
        if (desc && desc.cweId) ids.add(desc.cweId);
      }
    }
  }
  return Array.from(ids);
}

function normalizeCirclRecord(rec, vendorSlug, vendorPrefixes) {
  const cveId = rec && rec.cveMetadata && rec.cveMetadata.cveId;
  if (!cveId) throw new Error('CIRCL record missing cveMetadata.cveId');
  const { score, vector, version } = pickCvssFromCveRecord(rec);
  const label = VENDOR_LABELS[vendorSlug] || vendorSlug;
  const cna = rec.containers && rec.containers.cna;
  const cweIds = extractCweIdsFromCveRecord(rec);
  return {
    cve_id: cveId,
    vendor: vendorSlug,
    title: `${label} — ${cveId}`,
    description: pickDescription(cna && cna.descriptions),
    cvss_score: score,
    cvss_vector: vector,
    // ⛔ CIRCL scores are GAP-FILL ONLY — see the upsert cvss_score rule.
    cvss_source: 'circl',
    cvss_version: version,
    // ⛔ Bug fixed 2026-07-17, confirmed live (paloalto.js, same endpoint
    // shape, CVE-2026-0300): cveMetadata.datePublished is not reliably
    // present — fall back to containers.cna.datePublic.
    published_at: (rec.cveMetadata && rec.cveMetadata.datePublished) || (cna && cna.datePublic) || null,
    affected_version_ranges: extractAffectedRangesFromCveRecord(rec, vendorSlug, vendorPrefixes),
    fixed_in_versions: extractFixedVersionsFromCveRecord(rec, vendorPrefixes),
    // Same nvd.nist.gov detail URL regardless of which backend supplied the data — it's the
    // same real-world CVE either way, and unlike circl.lu this URL format is already relied on
    // elsewhere in this file, so no additional live verification of a circl.lu detail page was needed.
    advisory_url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
    raw_data: rec,
    cwe_ids: cweIds,
    vulnerability_category: categorizeCwes(cweIds),
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
    let otherProduct = 0;
    const unmatchable = [];
    for (const rec of records) {
      try {
        const normalized = normalizeCirclRecord(rec, vendorSlug, vendorPrefixes);
        // ⛔ See classifyCveRecordMatchability(): a record we could not extract a single
        // version bound from must NOT be stored with affected_version_ranges = [], because
        // that array is read downstream as an affirmative "this device is not affected".
        const verdict = classifyCveRecordMatchability(
          rec,
          vendorPrefixes,
          normalized.affected_version_ranges
        );
        if (verdict.status === 'other_product') {
          otherProduct++;
          continue;
        }
        if (verdict.status === 'unmatchable') {
          unmatchable.push(normalized.cve_id);
          console.warn(
            `[CIRCL fallback] ${normalized.cve_id}: NOT STORED for ${vendorSlug} — ${verdict.reason}. ` +
              'Storing it with empty affected_version_ranges would read as "not affected".'
          );
          continue;
        }
        // Records the verdict on the row itself (see upsertAdvisory's `matchability` clause) —
        // only 'matched' ever gets here, and writing it is what clears a stale 'unmatchable'
        // left by an earlier failed extraction of the same CVE.
        normalized.matchability = 'matched';
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
      message: `[CIRCL fallback] ${pairKey}: got ${records.length} record(s) from CIRCL (${added} new, ${otherProduct} for other products) (informational, not an error)`,
    });

    // ⛔ Reported, never silent. These advisories either declare this product affected with no
    // parseable bound, or identify no product at all — either way we could not derive a single
    // version range, so they are deliberately absent from `advisories` rather than present as a
    // confident "not affected". "Cannot be matched" is the honest answer. One aggregate line per
    // vendor/product pair (with the cve ids) so the sync's own feed_sync_log row carries the
    // count — this is the only reporting surface that exists without an advisories schema
    // column, and "cannot be matched" must not degrade into "nothing found".
    if (unmatchable.length > 0) {
      const sample = unmatchable.slice(0, 25).join(', ');
      console.warn(
        `[CIRCL fallback] ${pairKey}: ${unmatchable.length} advisory(ies) declare affected versions but none could be extracted — NOT stored (would read as "not affected")`
      );
      errors.push({
        cve_id: null,
        message:
          `[unmatchable] ${pairKey}: ${unmatchable.length} advisory(ies) could not be matched to this product ` +
          `(affected versions declared but unparseable, or no product identified); not stored rather than stored as "not affected" ` +
          `(informational, not an error). ${sample}${unmatchable.length > 25 ? ', …' : ''}`,
        unmatchable_count: unmatchable.length,
      });
    }
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
  // Same reporting contract as the CIRCL path's own counters, for the NVD-native path — see
  // classifyNvdNativeMatchability() and the aggregate `[unmatchable]` entry pushed below.
  const unmatchableNative = [];
  let otherProductNative = 0;

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
          // ⛔ Identical rule to the CIRCL path above: a record we could not extract a single
          // version bound from must NOT be stored with affected_version_ranges = [], because
          // versionMatcher reads that array as an affirmative "this device is not affected".
          // See classifyNvdNativeMatchability() for why this path needed it too.
          const verdict = classifyNvdNativeMatchability(
            cve,
            vendorPrefixes,
            rec.affected_version_ranges
          );
          if (verdict.status === 'other_product') {
            otherProductNative++;
            continue;
          }
          if (verdict.status === 'unmatchable') {
            unmatchableNative.push(rec.cve_id);
            console.warn(
              `[NVD] ${rec.cve_id}: NOT STORED for ${vendorSlug} — ${verdict.reason}. ` +
                'Storing it with empty affected_version_ranges would read as "not affected".'
            );
            continue;
          }
          rec.matchability = 'matched'; // see the CIRCL path's identical line
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

  // ⛔ Reported, never silent — same contract, and the same words, as the CIRCL path's
  // aggregate entry, so lib/feeds/index.js and feed_sync_log see one uniform `[unmatchable]`
  // marker whichever backend answered. "Cannot be matched" must not degrade into
  // "nothing found".
  if (unmatchableNative.length > 0) {
    const sample = unmatchableNative.slice(0, 25).join(', ');
    console.warn(
      `[NVD] ${vendorSlug}: ${unmatchableNative.length} advisory(ies) mark this product vulnerable but no version range could be extracted — NOT stored (would read as "not affected")`
    );
    errors.push({
      cve_id: null,
      message:
        `[unmatchable] ${vendorSlug}: ${unmatchableNative.length} advisory(ies) could not be matched to this product ` +
        `(marked vulnerable with no extractable version bound, or no CPE applicability statement at all); not stored rather than stored as "not affected" ` +
        `(informational, not an error). ${sample}${unmatchableNative.length > 25 ? ', …' : ''}`,
      unmatchable_count: unmatchableNative.length,
    });
  }
  if (otherProductNative > 0) {
    console.log(`[NVD] ${vendorSlug}: skipped ${otherProductNative} record(s) for other products`);
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

/**
 * Retroactive cleanup for advisories.affected_version_ranges/fixed_in_versions
 * on NVD-native-shaped rows (raw_data.configurations present), for every
 * vendor EXCEPT paloalto -- Palo Alto already gets identical treatment via
 * lib/feeds/paloalto.js's backfillPaloAltoVersionRanges(), which ALSO handles
 * Palo Alto's own PSIRT-sourced CVE-Record-shaped rows (a different raw_data
 * shape this function deliberately does not touch: CVE Record Format 5.x rows
 * -- from Palo Alto/Fortinet's own PSIRT/CSAF feeds, or the CIRCL fallback for
 * ANY vendor -- describe versions via versions[]/lessThan/changes[], not CPE
 * criteria strings, so they were never affected by the wildcard-CPE bug this
 * repairs; see extractVersionFromCriteria's header comment above for that
 * bug's full story).
 *
 * Reuses this file's own extractAffectedRanges()/extractFixedVersions() --
 * already vendor-generic (take vendorPrefixes as a parameter), the same
 * functions a live sync uses today -- so this is pure re-derivation from
 * already-stored raw_data, not a second implementation to keep in sync.
 * Same "widen an uncertain bound, never narrow it" contract as
 * backfillPaloAltoVersionRanges(): only writes a row back when the freshly
 * re-derived ranges actually differ from what's stored. Idempotent, safe to
 * re-run indefinitely; best-effort per row AND overall, same non-fatal
 * contract as every other backfill* function (lib/migrate.js never lets this
 * block startup).
 * @param {import('pg').Pool} pool
 * @returns {Promise<{checked: number, updated: number}>}
 */
async function backfillNvdNativeVersionRanges(pool) {
  const { rows } = await pool.query(
    `SELECT id, vendor, affected_version_ranges, fixed_in_versions, raw_data
       FROM advisories
      WHERE vendor <> 'paloalto' AND raw_data IS NOT NULL`
  );

  let checked = 0;
  let updated = 0;

  for (const row of rows) {
    const rec = row.raw_data;
    // Not NVD-native shape (e.g. a PSIRT/CSAF/CIRCL CVE Record) -- out of
    // scope for this function, skip.
    if (!rec || !Array.isArray(rec.configurations)) continue;

    const cpeStrings = VENDOR_CPES[row.vendor] || [];
    if (cpeStrings.length === 0) continue; // unknown/unconfigured vendor slug -- nothing to re-derive against
    const vendorPrefixes = cpePrefixes(cpeStrings);
    checked++;

    try {
      const freshRanges = extractAffectedRanges(rec.configurations, vendorPrefixes);
      const freshFixed = extractFixedVersions(rec.configurations, vendorPrefixes);

      const currentRangesJson = JSON.stringify(row.affected_version_ranges || []);
      const currentFixedJson = JSON.stringify(row.fixed_in_versions || []);
      const freshRangesJson = JSON.stringify(freshRanges);
      const freshFixedJson = JSON.stringify(freshFixed);

      if (currentRangesJson === freshRangesJson && currentFixedJson === freshFixedJson) {
        continue; // already clean -- nothing to do
      }

      await pool.query(
        `UPDATE advisories SET affected_version_ranges = $1::jsonb, fixed_in_versions = $2::jsonb, updated_at = now()
          WHERE id = $3`,
        [freshRangesJson, freshFixedJson, row.id]
      );
      updated++;
    } catch (err) {
      console.warn(
        `[NVD] Version-range backfill failed for advisory row ${row.id} (vendor=${row.vendor}, non-fatal): ${err.message}`
      );
    }
  }

  return { checked, updated };
}

module.exports = {
  fetchAndUpsertVendorCves,
  fetchAndUpsertForcepointCves,
  VENDOR_CPES,
  backfillNvdNativeVersionRanges,
  // Pure, DB-free, network-free — exported for tests/cveMatchability.test.js, which pins both
  // halves of the 2026-09-09 fix: which product strings this matcher must (and must NOT) match,
  // and that a declared-affected-but-unextractable record is never stored as empty ranges.
  cpePrefixes,
  matchingAffectedEntriesFromCveRecord,
  extractAffectedRangesFromCveRecord,
  extractFixedVersionsFromCveRecord,
  extractAffectedRanges,
  extractFixedVersions,
  classifyCveRecordMatchability,
  classifyNvdNativeMatchability,
  parseProseVersionRange,
  CURATED_PRODUCT_ALIASES,
};
