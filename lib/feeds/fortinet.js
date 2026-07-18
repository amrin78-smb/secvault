// lib/feeds/fortinet.js
// Fortinet PSIRT client — pulls FortiOS advisories from the FortiGuard IR RSS
// feed (discovery), then the OASIS CSAF 2.0 JSON linked from each advisory's
// HTML page (primary structured data), with an HTML-table-scrape fallback for
// the rare advisory that has no CSAF file or whose CSAF fetch/parse fails.
// CommonJS ONLY — this file is `require()`d by services/engine-worker.js
// (plain node) and may also be bundled into a Next.js API route, so it
// follows the exact same conventions as lib/feeds/nvd.js.

// Same node-fetch@2 ESM/CJS require-quirk workaround as nvd.js — Next.js's
// webpack bundler can resolve node-fetch's "module" (ESM) field even for this
// plain require() when this file runs inside an API route's bundle, which
// yields the ESM namespace object instead of the callable function. See
// lib/feeds/nvd.js's identical comment for the confirmed failure mode.
const fetchModule = require('node-fetch');
const fetch = fetchModule.default || fetchModule;
const { XMLParser } = require('fast-xml-parser'); // already a dependency — see package.json
const cheerio = require('cheerio'); // added by this file — HTML-table-scrape fallback ONLY
const { categorizeCwes } = require('../engines/vulnerabilityCategory');

// ────────────────────────────────────────────────────────────────────────
// LIVE-VERIFIED 2026-07-17 (per CLAUDE.md's "verify against live responses,
// never assume" rule — a prior task spec assumed `Accept: application/json`
// content negotiation on the advisory page and RSS at `www.fortiguard.com`;
// both were wrong, corrected below):
//
//   curl "https://www.fortiguard.com/rss/ir.xml"                 -> HTTP 500, NO User-Agent sent
//   curl -A "Mozilla/5.0 ..." "https://www.fortiguard.com/rss/ir.xml"
//     -> HTTP 302 -> https://filestore.fortinet.com/fortiguard/rss/ir.xml -> HTTP 200, real RSS 2.0 XML
//     (node-fetch@2 follows the redirect automatically — confirmed live, no extra code needed)
//   Each <item>: title, link (https://fortiguard.fortinet.com/psirt/FG-IR-YY-NNN — the REAL
//     domain, confirmed live; NOT www.fortiguard.com), description (CDATA HTML with a
//     "CVSSv3 Score: N.N" line, NO cve id), pubDate, guid.
//
//   curl -H "Accept: application/json" "https://fortiguard.fortinet.com/psirt/FG-IR-26-154"
//     -> HTTP 200 but plain HTML anyway (header ignored) — no __NEXT_DATA__ or similar
//     hydration JSON blob present. Confirmed there is no JSON content-negotiation on this page.
//
//   The HTML page DOES contain a link revealing a clean CSAF 2.0 JSON file:
//     <a href="/psirt/csaf/FG-IR-26-154?csaf_url=https://filestore.fortinet.com/fortiguard/psirt/
//        csaf_buffer-overread-in-authd-and-wad-daemon_fg-ir-26-154.json">
//   Hitting the proxy path `/psirt/csaf/{id}` directly (without the query param) returns HTTP 422
//   "Invalid Parameters" — confirmed live. The real data lives at the extracted
//   filestore.fortinet.com URL, fetched directly. Confirmed on two advisories from different years
//   (FG-IR-26-154 or 2026, FG-IR-24-373 for 2024) — the pattern generalizes.
//
//   CSAF JSON shape confirmed live: document.title / document.tracking.{id,initial_release_date,
//   current_release_date}; vulnerabilities[] with cve, title, scores[].{products,cvss_v3},
//   notes[] (category 'summary' has the human summary), product_status.{known_affected,
//   known_not_affected} (free-text strings, inconsistent separators — see parseAffectedEntry
//   below), remediations[], references[]. The SAME cve can appear MORE THAN ONCE in
//   vulnerabilities[] — once per affected product line (confirmed live: CVE-2026-59840 appears
//   once scoped to FortiOS, once scoped to FortiProxy, in the FG-IR-26-154 CSAF file) — this file
//   merges affected_version_ranges/fixed_in_versions across every FortiOS-scoped entry sharing one
//   cve id before building a single output record for that cve.
//
//   HTML fallback structure confirmed live via cheerio (NOT assumed): the advisory page has
//   exactly two <table> elements. Table 1 (class "table table-borderless table-striped
//   table-dark", inside a div.table-responsive) is the affected-versions table — header row
//   ["Version","Affected","Solution"], then one data row per product/branch, e.g.
//   ["FortiOS 7.6", "7.6.0 through 7.6.3", "Upgrade to 7.6.4 or above"] or
//   ["FortiOS 7.2", "7.2 all versions", "Migrate to a fixed release"] or
//   ["FortiOS 8.0", "Not affected", "Not Applicable"]. Table 2 (inside a div.sidebar) is a plain
//   2-column key/value metadata table: rows like ["IR Number","FG-IR-26-154"],
//   ["CVSSv3 Score","4.1"], ["CVE ID","CVE-2025-43892 CVE-2026-59840"] (space-separated when more
//   than one CVE). Both tables are located by their content (header text / presence of a "CVE ID"
//   cell), never by positional index, since a future page redesign could reorder them.
// ────────────────────────────────────────────────────────────────────────

const FORTIGUARD_RSS_URL = 'https://www.fortiguard.com/rss/ir.xml';
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecVault/1.0 (+FortiGuard PSIRT feed client)';
const VENDOR_LABEL = 'Fortinet';

// Same socket-inactivity timeout as nvd.js/paloalto.js (node-fetch@2 has no default timeout —
// see CLAUDE.md "NVD Fallback — CIRCL Vulnerability-Lookup" for the production incident this
// guards against). Applied to every fetch in this file: RSS, advisory HTML, and CSAF JSON.
const FETCH_TIMEOUT_MS = 20000;

// This task's explicit requirement — FortiGuard is rate-sensitive. Applied once per advisory,
// covering the PAIR of fetches (HTML page + CSAF json) as one unit, since both hit
// Fortinet-controlled infrastructure. Sequential for-loop, never Promise.all/parallel.
const ADVISORY_FETCH_DELAY_MS = 1000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchText(url) {
  const res = await fetch(url, { headers: { 'User-Agent': USER_AGENT }, timeout: FETCH_TIMEOUT_MS });
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status} for ${url}`);
    err.status = res.status;
    throw err;
  }
  return res.text();
}

async function fetchJson(url) {
  const res = await fetch(url, { headers: { 'User-Agent': USER_AGENT }, timeout: FETCH_TIMEOUT_MS });
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status} for ${url}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// ────────────────────────────────────────────────────────────────────────
// RSS discovery
// ────────────────────────────────────────────────────────────────────────

async function fetchRssItems() {
  const xml = await fetchText(FORTIGUARD_RSS_URL);
  const parser = new XMLParser({ ignoreAttributes: false, cdataPropName: '__cdata' });
  const parsed = parser.parse(xml);
  const rawItems = (parsed && parsed.rss && parsed.rss.channel && parsed.rss.channel.item) || [];
  // fast-xml-parser returns a bare object (not a 1-element array) when there's exactly one <item>.
  const items = Array.isArray(rawItems) ? rawItems : [rawItems];
  return items
    .map((item) => ({
      title: typeof item.title === 'string' ? item.title : null,
      link: typeof item.link === 'string' ? item.link : null,
      description:
        (item.description && typeof item.description === 'object' && item.description.__cdata) ||
        (typeof item.description === 'string' ? item.description : null),
      pubDate: item.pubDate || null,
    }))
    .filter((item) => !!item.link);
}

function extractFgIrId(link) {
  const m = typeof link === 'string' ? link.match(/FG-IR-\d+-\d+/) : null;
  return m ? m[0] : null;
}

// ────────────────────────────────────────────────────────────────────────
// CSAF primary path
// ────────────────────────────────────────────────────────────────────────

const CSAF_URL_RE = /csaf_url=(https:\/\/filestore\.fortinet\.com\/[^"&]+\.json)/;

function extractCsafUrl(html) {
  const m = typeof html === 'string' ? html.match(CSAF_URL_RE) : null;
  return m ? m[1] : null;
}

// A vulnerabilities[] entry is "FortiOS-scoped" if any of its CVSS scores name FortiOS as the
// affected product, or (fallback, in case scores[] is empty/malformed) its title starts with
// "FortiOS" — confirmed live title shape is "FortiOS - MEDIUM - FG-IR-26-154" vs
// "FortiProxy - MEDIUM - FG-IR-26-154". This is Task requirement #4's vendor filter
// ("only ingest FortiOS advisories, skip FortiProxy/FortiManager/etc").
function isFortiOSScoredEntry(vulnEntry) {
  const scores = Array.isArray(vulnEntry && vulnEntry.scores) ? vulnEntry.scores : [];
  if (scores.some((s) => Array.isArray(s && s.products) && s.products.includes('FortiOS'))) return true;
  if (typeof vulnEntry.title === 'string' && /^FortiOS\b/.test(vulnEntry.title)) return true;
  return false;
}

// "FortiOS >=7.6.0|<=7.6.3" -> { product: 'FortiOS', remainder: '>=7.6.0|<=7.6.3' }
// "FortiOS/ 8.0 all versions" -> { product: 'FortiOS', remainder: '8.0 all versions' }
// "FortiOS-7.6.4" -> { product: 'FortiOS', remainder: '7.6.4' }
// "FortiOS 7.2 all versions" -> { product: 'FortiOS', remainder: '7.2 all versions' }
const PRODUCT_TOKEN_RE = /^([A-Za-z][A-Za-z0-9]*)/;

function extractProductAndRemainder(str) {
  const s = String(str);
  const m = s.match(PRODUCT_TOKEN_RE);
  if (!m) return null;
  const product = m[1];
  const remainder = s.slice(m[0].length).replace(/^[\s/-]+/, '').trim();
  return { product, remainder };
}

// Parses one known_affected/known_not_affected free-text string. Returns:
//   { range: {min,max,exclude_fixed} }  — a vulnerable version range
//   { fixed: 'X.Y.Z' }                  — a single exact fixed version
//   null                                — not a FortiOS entry, or an unrecognized shape (skip)
//
// Per-string product filtering here (rather than filtering whole vulnerabilities[] entries) is
// deliberately MORE precise: a single CSAF file legitimately bundles both FortiOS-relevant and
// FortiProxy-only known_affected/known_not_affected strings for the same product_status block in
// some shapes, and this catches that even though isFortiOSScoredEntry() already filters at the
// entry level as the primary gate.
//
// `status` is REQUIRED — either 'affected' (the string came from product_status.known_affected)
// or 'not_affected' (it came from known_not_affected). See the Pattern 3 comment below for why.
function parseAffectedEntry(str, status) {
  const extracted = extractProductAndRemainder(str);
  if (!extracted || extracted.product !== 'FortiOS') return null;
  const remainder = extracted.remainder;

  // Pattern 1: ">=X.Y.Z|<=A.B.C" (the <= bound is inclusive per the literal operator; a bare '<'
  // with no '=' would mean the max bound is exclusive — tolerated but not seen live).
  const rangeMatch = remainder.match(/^>(=)?\s*([\d.]+)\s*\|\s*<(=)?\s*([\d.]+)/);
  if (rangeMatch) {
    return {
      range: {
        min: rangeMatch[2],
        max: rangeMatch[4],
        exclude_fixed: !rangeMatch[3],
      },
    };
  }

  // Pattern 2: "X.Y all versions" (matches this app's existing Fortinet version-range convention
  // per CLAUDE.md — a whole minor branch expands to {min: X.Y.0, max: X.Y.999}).
  const allVersionsMatch = remainder.match(/^([\d.]+)\s+all\s+versions/i);
  if (allVersionsMatch) {
    const v = allVersionsMatch[1];
    const parts = v.split('.');
    if (parts.length === 2) {
      return { range: { min: `${v}.0`, max: `${v}.999`, exclude_fixed: false } };
    }
    // Already fully-specified or an unusual segment count — treat as an exact single version
    // range rather than guessing at padding.
    return { range: { min: v, max: v, exclude_fixed: false } };
  }

  // Pattern 3: a bare exact version with no range operator and no "all versions" (e.g.
  // "FortiOS-7.6.4"). ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep: this used to
  // unconditionally return `{ fixed: bareMatch[1] }` for a bare version, regardless of which
  // product_status list the string came from. That's only correct for known_not_affected
  // ("upgrade to this version to be fixed"). A bare version listed under known_affected means
  // that EXACT version is vulnerable, not fixed — CSAF genuinely uses this shape for a
  // single-point affected release with no accompanying range operator (confirmed live: FortiGuard
  // advisories can name one specific vulnerable build rather than a "X|Y" range or an
  // "all versions" branch). Filing it into fixedVersions instead of ranges would make
  // versionMatcher.js treat a device running that EXACT vulnerable version as already patched —
  // a silent false-negative, the same class of bug CLAUDE.md's versionEndIncluding/Excluding
  // warning and the tri-state "never default to the safer-looking answer" rule both exist to
  // prevent. Now branches on the caller-supplied `status`: known_not_affected still yields
  // `{ fixed }`; known_affected yields a pinned `{ range: { min: v, max: v, exclude_fixed: false } }`
  // (min===max, same "pinned exact-version range" shape nvd.js's extractAffectedRanges fix uses
  // for an exact-CPE-version cpeMatch entry with no range fields).
  const bareMatch = remainder.match(/^([\d.]+)\s*$/);
  if (bareMatch) {
    const v = bareMatch[1];
    if (status === 'not_affected') return { fixed: v };
    return { range: { min: v, max: v, exclude_fixed: false } };
  }

  return null; // unrecognized shape (e.g. free-text like "Not affected") — skip, don't guess
}

// Merges one vulnerabilities[] entry's product_status data into the accumulator for its cve id.
// known_affected strings become vulnerable ranges (or a bare fixed version, rare but tolerated).
// known_not_affected strings: a bare fixed version (e.g. "FortiOS-7.6.4", meaning "upgrade to this
// version to be fixed") is recorded; an "all versions" entry (meaning "this whole branch was never
// affected") is purely informational and skipped — there is no "definitely not vulnerable range"
// concept in this app's schema, and no action is needed since a genuinely unaffected branch was
// never going to fall inside a vulnerable range in the first place.
function mergeVersionDataFromEntry(vulnEntry, acc) {
  const ps = (vulnEntry && vulnEntry.product_status) || {};
  for (const s of ps.known_affected || []) {
    const parsed = parseAffectedEntry(s, 'affected');
    if (!parsed) continue;
    if (parsed.range) acc.ranges.push({ ...parsed.range, vulnerable: true });
    else if (parsed.fixed) acc.fixedVersions.add(parsed.fixed);
  }
  for (const s of ps.known_not_affected || []) {
    const parsed = parseAffectedEntry(s, 'not_affected');
    if (!parsed) continue;
    if (parsed.fixed) acc.fixedVersions.add(parsed.fixed);
    // parsed.range here means "not affected across this whole branch" — informational, skip.
  }
}

// Scans this entry's scores[] for the FortiOS cvss_v3 block. Multiple entries for the same cve
// (see isFortiOSScoredEntry's comment) are reconciled by the caller taking the MAX score seen
// across all FortiOS-scoped entries for that cve — same conservative direction as this app's other
// "when in doubt, don't underestimate severity" choices (see CLAUDE.md's applicability tri-state
// default and the CIRCL fallback's "can only make a range wider, never narrower" note).
function pickCvssFromCsafEntry(vulnEntry) {
  const scores = Array.isArray(vulnEntry && vulnEntry.scores) ? vulnEntry.scores : [];
  for (const s of scores) {
    const v3 = s && s.cvss_v3;
    if (v3 && typeof v3.baseScore === 'number') {
      return { score: v3.baseScore, vector: v3.vectorString || null };
    }
  }
  return { score: null, vector: null };
}

function pickSummaryFromCsafEntry(vulnEntry) {
  const notes = Array.isArray(vulnEntry && vulnEntry.notes) ? vulnEntry.notes : [];
  const summary = notes.find((n) => n && n.category === 'summary' && n.text);
  return summary ? String(summary.text).trim() : null;
}

// Builds one normalized advisory record PER UNIQUE CVE id found across all FortiOS-scoped
// vulnerabilities[] entries in this CSAF document, merging affected_version_ranges/
// fixed_in_versions across every entry sharing that cve id (see the CVE-2026-59840
// FortiOS+FortiProxy example in the header comment). Returns [] when the document has zero
// FortiOS-scoped entries at all (e.g. a FortiSwitch/FortiManager-only advisory) — the caller
// counts that as `skipped`, a real non-error outcome, never `errors`.
function buildRecordsFromCsaf(csafJson, fgIrId) {
  const doc = (csafJson && csafJson.document) || {};
  const docTitle = doc.title || fgIrId;
  const publishedAt =
    (doc.tracking && (doc.tracking.initial_release_date || doc.tracking.current_release_date)) || null;
  const advisoryUrl = `https://fortiguard.fortinet.com/psirt/${fgIrId}`;

  const groups = new Map(); // cveId -> { ranges: [], fixedVersions: Set, cvss: {score,vector}, summary, cweIds: Set }

  for (const vulnEntry of (csafJson && csafJson.vulnerabilities) || []) {
    const cveId = vulnEntry && vulnEntry.cve;
    if (!cveId) continue;
    if (!isFortiOSScoredEntry(vulnEntry)) continue;

    let group = groups.get(cveId);
    if (!group) {
      group = {
        ranges: [],
        fixedVersions: new Set(),
        cvss: { score: null, vector: null },
        summary: null,
        cweIds: new Set(),
      };
      groups.set(cveId, group);
    }

    mergeVersionDataFromEntry(vulnEntry, group);

    const cvss = pickCvssFromCsafEntry(vulnEntry);
    if (cvss.score !== null && (group.cvss.score === null || cvss.score > group.cvss.score)) {
      group.cvss = cvss;
    }
    if (!group.summary) {
      group.summary = pickSummaryFromCsafEntry(vulnEntry);
    }
    // CSAF 2.0's own schema: vulnerabilities[].cwe is a SINGLE {id, name}
    // object per entry (not an array) — confirmed against the OASIS CSAF
    // 2.0 spec, not guessed. A CVE merged from multiple FortiOS-scoped
    // entries (see this function's own header comment for the
    // CVE-2026-59840 FortiOS+FortiProxy example) could in principle carry a
    // different CWE per entry — collected into a Set per CVE rather than
    // just taking the first, so categorizeCwes() sees all of them.
    if (vulnEntry.cwe && vulnEntry.cwe.id) group.cweIds.add(vulnEntry.cwe.id);
  }

  const records = [];
  for (const [cveId, group] of groups.entries()) {
    const cweIds = Array.from(group.cweIds);
    records.push({
      cve_id: cveId,
      vendor: 'fortinet',
      title: `${VENDOR_LABEL} — ${cveId}`,
      description: group.summary ? `[${fgIrId}] ${group.summary}` : `[${fgIrId}] ${docTitle}`,
      cvss_score: group.cvss.score,
      cvss_vector: group.cvss.vector,
      published_at: publishedAt,
      affected_version_ranges: group.ranges,
      fixed_in_versions: Array.from(group.fixedVersions),
      advisory_url: advisoryUrl,
      raw_data: csafJson,
      cwe_ids: cweIds,
      vulnerability_category: categorizeCwes(cweIds),
    });
  }
  return records;
}

// state.loggedFirstCsaf gates the "log the FULL raw CSAF JSON of the FIRST successfully-fetched
// advisory, before any parsing" requirement (CLAUDE.md's "log raw response on first connect" rule,
// same as every other vendor integration in this codebase) — logged here, before
// buildRecordsFromCsaf() does any extraction.
async function tryCsafPath(fgIrId, html, state) {
  const csafUrl = extractCsafUrl(html);
  if (!csafUrl) {
    throw new Error('no csaf_url found in advisory HTML (advisory may predate CSAF)');
  }
  const csafJson = await fetchJson(csafUrl);
  if (!state.loggedFirstCsaf) {
    console.log('[Fortinet PSIRT Debug] Raw CSAF JSON (first successfully-fetched advisory):', JSON.stringify(csafJson, null, 2));
    state.loggedFirstCsaf = true;
  }
  return buildRecordsFromCsaf(csafJson, fgIrId);
}

// ────────────────────────────────────────────────────────────────────────
// HTML-table-scrape FALLBACK — only reached when the CSAF path throws (no csaf_url link, or the
// CSAF fetch/parse itself failed). Uses the HTML already fetched for the CSAF-url-extraction
// attempt — never re-fetches the advisory page.
// ────────────────────────────────────────────────────────────────────────

function findVersionTable($) {
  return $('table')
    .filter((i, t) => {
      const headerText = $(t).find('tr').first().text();
      return /Version/i.test(headerText) && /Affected/i.test(headerText) && /Solution/i.test(headerText);
    })
    .first();
}

function findMetadataTable($) {
  return $('table')
    .filter((i, t) => $(t).text().includes('CVE ID'))
    .first();
}

// Parses the metadata table's rows into { cveIds: string[], cvssScore: number|null }.
// Row shape confirmed live: [label, value] pairs, e.g. ["CVE ID", "CVE-2025-43892 CVE-2026-59840"]
// (space-separated when more than one CVE), ["CVSSv3 Score", "4.1"].
function parseMetadataTable($, metaTable) {
  let cveIds = [];
  let cvssScore = null;
  metaTable.find('tr').each((i, tr) => {
    const cells = $(tr)
      .find('th,td')
      .map((j, c) => $(c).text().trim())
      .get();
    if (cells.length < 2) return;
    const label = cells[0];
    const value = cells.slice(1).join(' ');
    if (/^CVE ID$/i.test(label)) {
      cveIds = value.match(/CVE-\d{4}-\d{4,}/g) || [];
    } else if (/^CVSSv3 Score$/i.test(label)) {
      const n = parseFloat(value);
      if (!Number.isNaN(n)) cvssScore = n;
    }
  });
  return { cveIds, cvssScore };
}

// Parses the affected-versions table's data rows (header row already excluded by the caller).
// Row shape confirmed live: [product+branch, affected-text, solution-text], e.g.
//   ["FortiOS 7.6", "7.6.0 through 7.6.3", "Upgrade to 7.6.4 or above"]
//   ["FortiOS 7.2", "7.2 all versions", "Migrate to a fixed release"]
//   ["FortiOS 8.0", "Not affected", "Not Applicable"]
// Only FortiOS rows are used (FortiProxy/other-product rows are skipped, same vendor filter as
// the CSAF path). "Not affected" rows contribute no range. The solution text is scanned for an
// explicit "Upgrade to X.Y.Z" instruction to populate fixed_in_versions as a bonus (not required
// by the base row shape, but present in the live data and cheap to extract).
function parseVersionTableRows($, versionTable) {
  const ranges = [];
  const fixedVersions = new Set();

  versionTable
    .find('tr')
    .slice(1) // skip the header row
    .each((i, tr) => {
      const cells = $(tr)
        .find('th,td')
        .map((j, c) => $(c).text().trim())
        .get();
      if (cells.length < 2) return;
      const [productCol, affectedText, solutionText] = cells;

      const productMatch = productCol.match(/^([A-Za-z][A-Za-z0-9]*)\s+([\d.]+)/);
      if (!productMatch || productMatch[1] !== 'FortiOS') return; // FortiProxy/other rows skipped

      if (solutionText) {
        const upgradeMatch = solutionText.match(/upgrade to\s+([\d.]+)/i);
        if (upgradeMatch) fixedVersions.add(upgradeMatch[1]);
      }

      if (!affectedText || /^not affected/i.test(affectedText)) return; // no vulnerable range

      const throughMatch = affectedText.match(/^([\d.]+)\s+through\s+([\d.]+)/i);
      if (throughMatch) {
        ranges.push({ min: throughMatch[1], max: throughMatch[2], exclude_fixed: false, vulnerable: true });
        return;
      }

      const allVersionsMatch = affectedText.match(/^([\d.]+)\s+all\s+versions/i);
      if (allVersionsMatch) {
        const v = allVersionsMatch[1];
        const parts = v.split('.');
        if (parts.length === 2) {
          ranges.push({ min: `${v}.0`, max: `${v}.999`, exclude_fixed: false, vulnerable: true });
        } else {
          ranges.push({ min: v, max: v, exclude_fixed: false, vulnerable: true });
        }
        return;
      }
      // Unrecognized affected-text shape for this row — skip rather than guess.
    });

  return { ranges, fixedVersions };
}

// Builds records from the HTML table when CSAF is unavailable/broken for this advisory. Cannot
// distinguish per-CVE version data the way CSAF can (the table has no CVE-id column), so every CVE
// id found in the metadata table gets the SAME version-range/CVSS data — a known limitation of this
// fallback, acceptable because it's the rare path (CSAF is primary and covers the normal case).
function buildRecordsFromHtmlFallback($, fgIrId, item) {
  const versionTable = findVersionTable($);
  const metaTable = findMetadataTable($);

  if (versionTable.length === 0 && metaTable.length === 0) {
    throw new Error('HTML fallback: neither the affected-versions table nor the metadata table was found');
  }

  let cveIds = [];
  let cvssScore = null;
  if (metaTable.length > 0) {
    const meta = parseMetadataTable($, metaTable);
    cveIds = meta.cveIds;
    cvssScore = meta.cvssScore;
  }

  // Last-resort CVE id source: the RSS item's own description text carries a "CVSSv3 Score: N.N"
  // line but (per the live-verification header comment) no CVE id — this rarely helps, but costs
  // nothing to try before giving up.
  if (cveIds.length === 0 && item && item.description) {
    cveIds = item.description.match(/CVE-\d{4}-\d{4,}/g) || [];
  }

  if (cveIds.length === 0) {
    throw new Error('HTML fallback: no CVE ID(s) could be extracted from the advisory page');
  }

  let ranges = [];
  let fixedVersions = new Set();
  if (versionTable.length > 0) {
    const parsed = parseVersionTableRows($, versionTable);
    ranges = parsed.ranges;
    fixedVersions = parsed.fixedVersions;
  }

  const advisoryUrl = `https://fortiguard.fortinet.com/psirt/${fgIrId}`;
  const publishedAt = (item && item.pubDate) || null;
  const rssTitle = (item && item.title) || fgIrId;
  const fixedVersionsArr = Array.from(fixedVersions);

  return cveIds.map((cveId) => ({
    cve_id: cveId,
    vendor: 'fortinet',
    title: `${VENDOR_LABEL} — ${cveId}`,
    description: `[${fgIrId}] ${rssTitle} (via HTML-table fallback — CSAF unavailable for this advisory)`,
    cvss_score: cvssScore,
    cvss_vector: null, // not available from the HTML table — only a numeric CVSSv3 score is shown
    published_at: publishedAt,
    affected_version_ranges: ranges,
    fixed_in_versions: fixedVersionsArr,
    advisory_url: advisoryUrl,
    raw_data: { source: 'html_fallback', fgIrId, cveIds, cvssScore, versionRanges: ranges, fixedVersions: fixedVersionsArr },
    // No CWE data is available from the HTML table (only CSAF carries it) —
    // explicit [] / categorizeCwes([]) = 'Other', matching this codebase's
    // convention of an honest, explicit "uncategorized" rather than leaving
    // the column NULL (which would look like "not yet computed" instead of
    // "genuinely nothing to categorize"). Self-corrects if this advisory is
    // later ingested via CSAF (a separate feed source), since the CASE WHEN
    // vendor-match guard in upsertAdvisory() lets that later sync overwrite it.
    cwe_ids: [],
    vulnerability_category: categorizeCwes([]),
  }));
}

// ────────────────────────────────────────────────────────────────────────
// Per-advisory orchestration: CSAF primary, HTML-table fallback on any failure. Only throws if
// BOTH paths fail — the caller logs that to errors[] and moves on to the next advisory.
// ────────────────────────────────────────────────────────────────────────

async function processAdvisory(fgIrId, item, state) {
  const html = await fetchText(`https://fortiguard.fortinet.com/psirt/${fgIrId}`);

  try {
    return await tryCsafPath(fgIrId, html, state);
  } catch (csafErr) {
    try {
      const $ = cheerio.load(html);
      return buildRecordsFromHtmlFallback($, fgIrId, item);
    } catch (fallbackErr) {
      throw new Error(
        `CSAF path failed (${csafErr.message}); HTML fallback also failed (${fallbackErr.message})`
      );
    }
  }
}

// ────────────────────────────────────────────────────────────────────────
// Upsert — mirrors lib/feeds/nvd.js's upsertAdvisory almost verbatim (same SQL shape, same
// "don't let a different vendor's upsert steal an existing cve_id row" ON CONFLICT guard), vendor
// literal 'fortinet'. Duplicated rather than imported/shared: nvd.js does not export this function,
// and this file is not permitted to edit nvd.js (sibling agent territory / shared file).
//
// ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep (same fix already applied in nvd.js's
// upsertAdvisory — mirrored here): description/cvss_score/cvss_vector/published_at/advisory_url/
// raw_data were unconditionally overwritten with EXCLUDED.* on every conflict, regardless of which
// vendor's sync produced the incoming row — only title/affected_version_ranges/fixed_in_versions
// were guarded. advisories.cve_id is UNIQUE across ALL vendors (see the KNOWN CROSS-VENDOR
// LIMITATION note in nvd.js), so a genuine cross-vendor cve_id collision (a shared-library CVE, or
// another feed's own scenario-specific take on the "same" CVE id) could silently overwrite the
// OWNING vendor's CVSS score/description/publish date with this Fortinet sync's data while leaving
// that row's title/ranges untouched — a corrupted hybrid record with mismatched severity and
// version data. Every non-key, non-vendor column is now guarded identically, matching nvd.js.
// ────────────────────────────────────────────────────────────────────────
async function upsertAdvisory(pool, rec) {
  const result = await pool.query(
    `INSERT INTO advisories (
       cve_id, vendor, title, description, cvss_score, cvss_vector,
       published_at, affected_version_ranges, fixed_in_versions, advisory_url, raw_data,
       cwe_ids, vulnerability_category,
       updated_at
     ) VALUES (
       $1, $2, $3, $4, $5, $6,
       $7::timestamptz, $8::jsonb, $9::jsonb, $10, $11::jsonb,
       $12::text[], $13,
       now()
     )
     ON CONFLICT (cve_id) DO UPDATE SET
       vendor = advisories.vendor,
       title = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.title ELSE advisories.title END,
       description = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.description ELSE advisories.description END,
       cvss_score = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.cvss_score ELSE advisories.cvss_score END,
       cvss_vector = CASE WHEN advisories.vendor = EXCLUDED.vendor
                    THEN EXCLUDED.cvss_vector ELSE advisories.cvss_vector END,
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
    ]
  );
  return result.rows[0].inserted === true;
}

/**
 * Fetch all FortiOS advisories from the FortiGuard PSIRT RSS feed, resolve each to its CSAF 2.0
 * JSON (falling back to HTML-table-scraping when CSAF is unavailable/broken for a given
 * advisory), and upsert them into the `advisories` table. Rate-limited to one advisory's
 * fetch-pair per second (FortiGuard is rate-sensitive — sequential, never parallel). One
 * advisory's failure never aborts the run.
 * @param {import('pg').Pool} pool
 * @returns {Promise<{inserted: number, updated: number,
 *   errors: Array<{cve_id: string|null, message: string}>, skipped: number}>}
 */
async function fetchAndUpsertFortinetAdvisories(pool) {
  const errors = [];
  let inserted = 0;
  let updated = 0;
  let skipped = 0;
  const state = { loggedFirstCsaf: false };

  let rssItems;
  try {
    rssItems = await fetchRssItems();
  } catch (err) {
    errors.push({ cve_id: null, message: `FortiGuard RSS fetch failed: ${err.message}` });
    return { inserted, updated, errors, skipped };
  }

  for (let i = 0; i < rssItems.length; i++) {
    const item = rssItems[i];
    const fgIrId = extractFgIrId(item.link);
    if (!fgIrId) {
      errors.push({ cve_id: null, message: `Could not extract FG-IR id from RSS <link>: ${item.link}` });
      continue;
    }

    if (i > 0) await sleep(ADVISORY_FETCH_DELAY_MS); // rate limit between advisory fetch-pairs

    let records;
    try {
      records = await processAdvisory(fgIrId, item, state);
    } catch (err) {
      errors.push({ cve_id: null, message: `${fgIrId}: ${err.message}` });
      continue; // never abort the run over one bad advisory
    }

    if (records.length === 0) {
      // Zero FortiOS-scoped vulnerabilities after filtering — a genuinely FortiProxy/
      // FortiManager/etc-only advisory. Real, expected, not an error.
      skipped++;
      continue;
    }

    for (const rec of records) {
      try {
        const wasInserted = await upsertAdvisory(pool, rec);
        if (wasInserted) inserted++;
        else updated++;
      } catch (e) {
        errors.push({ cve_id: rec.cve_id, message: e.message });
      }
    }
  }

  return { inserted, updated, errors, skipped };
}

module.exports = { fetchAndUpsertFortinetAdvisories };
