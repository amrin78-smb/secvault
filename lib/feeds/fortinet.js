// lib/feeds/fortinet.js
// Fortinet PSIRT client — pulls advisories from the FortiGuard IR RSS feed
// (discovery), then the OASIS CSAF 2.0 JSON linked from each advisory's HTML
// page (primary structured data), with an HTML-table-scrape fallback, and — when
// the advisory page is not served to us at all — a DEGRADED path that ingests
// only what the RSS itself genuinely carries.
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
//     "CVSSv3 Score: N.N" line), pubDate, guid.
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

// ────────────────────────────────────────────────────────────────────────
// ⛔ 2026-09-10 — THE ADVISORY PAGES ARE NO LONGER SERVED, AND THE OLD CODE
//    REPORTED THE WRONG REASON FOR THREE WEEKS. Read this before touching
//    anything in this file.
//
// Live-verified from the production server AND from a second network:
//
//   GET https://fortiguard.fortinet.com/psirt/FG-IR-26-165
//     -> HTTP **200**, ~19,700 bytes
//     -> <title>Just a moment</title>
//        "Just a moment — verifying connection security."
//        <altcha-widget challengeurl="/v1/challenge" auto="onload">
//        <input type="hidden" name="screen_id" value="SC-D0ECE72D0916">
//        "Screen ID: SC-D0ECE72D0916"
//
// That is an **altcha proof-of-work bot-protection interstitial**, not an
// advisory. The advisory HTML was never served. A browser User-Agent does not
// help (challenged with and without one). `.well-known/csaf/provider-metadata.json`
// is 404 on fortinet.com, fortiguard.com and fortiguard.fortinet.com;
// `/psirt/csaf/<ID>.json` is 422. **Every** advisory page is challenged, so
// this is a total outage of the advisory-page path, not one bad advisory.
//
// ⛔ The old code fetched that 200-with-a-challenge-body, found no `csaf_url`
// in it, and reported:
//     "no csaf_url found in advisory HTML (advisory may predate CSAF)"
//     "HTML fallback: neither the affected-versions table nor the metadata table was found"
// Both sentences are statements ABOUT AN ADVISORY WE NEVER RECEIVED. That is
// CLAUDE.md's failed-read-as-a-fact rule applied to a DIAGNOSTIC: a confident
// wrong reason, repeated 50x per run for 154 runs, sent the investigation
// looking at Fortinet's CSAF publishing history instead of at the challenge.
// **A response is now CLASSIFIED before it is parsed** (classifyAdvisoryPage),
// and "may predate CSAF" can only be said about a page we have positively
// identified AS an advisory page.
//
// The RSS itself is NOT challenged (HTTP 200, ~38 KB, 50 items, verified the
// same day), which is why the degraded RSS path below exists.
//
// ⛔ What the RSS can and cannot supply — MEASURED over all 50 live items,
//    not assumed:
//      50/50 carry a CVSSv3 score      45/50 carry a CWE id
//       5/50 carry a CVE id            50/50 carry a title + summary + pubDate
//       0/50 carry ANY affected-version information
//    So the degraded path recovers ~10% of items and NEVER a version range.
//
// ⛔ RSS_INSERT_WOULD_SQUAT_CVE_IDS — and that is why the degraded path REPORTS but
// does not STORE. `advisories.cve_id` is UNIQUE and carries exactly ONE vendor (see
// CLAUDE.md: "a CVE affecting two vendors stays with whichever ingested it first").
// A degraded row has no ranges, so it is `unmatchable`, and an unmatchable row produces
// no assessment — measured live: 0. So storing one buys nothing and permanently claims a
// global identifier for the wrong vendor. Live proof that the harm is real: CVE-2022-0778
// is an OpenSSL bug that Fortinet republished as FG-IR-22-059 and that is STILL in the
// current RSS; in this database it belongs to `paloalto`, with 6 real version ranges and
// matchability=matched. This path storing it first would have cost those ranges.
//
// If FortiGuard ever starts publishing FortiOS CVE ids (with ranges) in the RSS, this is
// the decision to revisit — not the parser, which already works.
//    Everything it stores is marked `matchability = 'unmatchable'` — the
//    advisory certainly declares affected versions, we simply could not read
//    them, and CLAUDE.md forbids letting that empty list be scored as
//    "this device is not affected".
// ────────────────────────────────────────────────────────────────────────

const FORTIGUARD_RSS_URL = 'https://www.fortiguard.com/rss/ir.xml';
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecVault/1.0 (+FortiGuard PSIRT feed client)';
const VENDOR_LABEL = 'Fortinet';
const VENDOR_SLUG = 'fortinet';

// Same socket-inactivity timeout as nvd.js/paloalto.js (node-fetch@2 has no default timeout —
// see CLAUDE.md "NVD Fallback — CIRCL Vulnerability-Lookup" for the production incident this
// guards against). Applied to every fetch in this file: RSS, advisory HTML, and CSAF JSON.
const FETCH_TIMEOUT_MS = 20000;

// FortiGuard is rate-sensitive. Applied once per advisory, covering the PAIR of fetches
// (HTML page + CSAF json) as one unit, since both hit Fortinet-controlled infrastructure.
// Sequential for-loop, never Promise.all/parallel.
const ADVISORY_FETCH_DELAY_MS = 1000;

// ⛔ Circuit breaker. When the advisory pages are behind a bot challenge, EVERY page is
// challenged — so probing all 50 costs a wasted minute per run (measured: 63 s) and 50
// pointless requests at a host that has just told us to go away. After this many CONSECUTIVE
// challenges the page probe is suspended for the rest of the run and the remaining items go
// straight to the degraded RSS path. It is deliberately > 1: the challenge could be
// intermittent or per-request, and one unlucky response must not disable a working path.
// The counter RESETS on any successful page fetch, so a partially-challenged run still
// collects every page it can.
const CHALLENGE_CIRCUIT_BREAK = 3;

// ────────────────────────────────────────────────────────────────────────
// Failure taxonomy. ⛔ EVERY value here names WHAT WE OBSERVED, never what we
// inferred about Fortinet's publishing. The distinction that matters most:
//   BOT_CHALLENGE / PAGE_NOT_ADVISORY / PAGE_EMPTY  = we got no advisory at all
//   NO_CSAF_LINK / HTML_TABLES_MISSING / …          = we got a REAL advisory
//                                                     page and could not parse it
// Only the second group may say anything about the advisory's own content.
// ────────────────────────────────────────────────────────────────────────
const REASON = {
  BOT_CHALLENGE: 'bot_challenge',
  PAGE_PROBE_SUSPENDED: 'page_probe_suspended',
  PAGE_HTTP_ERROR: 'page_http_error',
  PAGE_NETWORK_ERROR: 'page_network_error',
  PAGE_NOT_ADVISORY: 'page_not_advisory',
  PAGE_EMPTY: 'page_empty',
  NO_CSAF_LINK: 'no_csaf_link',
  CSAF_FETCH_FAILED: 'csaf_fetch_failed',
  CSAF_PARSE_FAILED: 'csaf_parse_failed',
  HTML_TABLES_MISSING: 'html_tables_missing',
  HTML_NO_CVE_ID: 'html_no_cve_id',
  RSS_NO_CVE_ID: 'rss_no_cve_id',
  RSS_NO_FG_IR_ID: 'rss_no_fg_ir_id',
  UPSERT_FAILED: 'upsert_failed',
  RSS_FETCH_FAILED: 'rss_fetch_failed',
};

function feedError(reason, message) {
  const err = new Error(message);
  err.reason = reason;
  return err;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function advisoryUrlFor(fgIrId) {
  return `https://fortiguard.fortinet.com/psirt/${fgIrId}`;
}

function uniq(arr) {
  return Array.from(new Set(arr));
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

function parseRssXml(xml) {
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

async function fetchRssItems() {
  const xml = await fetchText(FORTIGUARD_RSS_URL);
  return parseRssXml(xml);
}

function extractFgIrId(link) {
  const m = typeof link === 'string' ? link.match(/FG-IR-\d+-\d+/) : null;
  return m ? m[0] : null;
}

// ────────────────────────────────────────────────────────────────────────
// Response classification — runs BEFORE any parsing
//
// ⛔ This is the single most important function in this file. Everything the
// old code got wrong about WHY it was failing came from parsing first and
// explaining afterwards.
// ────────────────────────────────────────────────────────────────────────

// Markers observed live on the FortiGuard interstitial (altcha), plus two
// well-known third-party interstitials that fail in the exact same shape
// (HTTP 200, plausible HTML, zero advisory content) so a future switch of
// bot-protection vendor still produces an honest diagnosis rather than
// silently falling back through to "may predate CSAF" again.
function detectBotChallenge(html) {
  if (typeof html !== 'string' || html === '') return null;
  const head = html.slice(0, 60000);
  const markers = [];
  if (/<altcha-widget/i.test(head)) markers.push('altcha-widget');
  if (/challengeurl\s*=\s*["']\/v1\/challenge["']/i.test(head)) markers.push('challengeurl=/v1/challenge');
  if (/name\s*=\s*["']screen_id["']/i.test(head)) markers.push('screen_id form field');
  if (/<title>\s*Just a moment\s*<\/title>/i.test(head)) markers.push('title "Just a moment"');
  if (/verifying connection security/i.test(head)) markers.push('"verifying connection security"');
  if (/checking that your connection to this site is secure/i.test(head)) markers.push('connection-check banner');
  if (/cf-browser-verification|_cf_chl_opt|__cf_chl_/i.test(head)) markers.push('cloudflare challenge');
  if (/_Incapsula_Resource|Incapsula incident ID/i.test(head)) markers.push('imperva/incapsula');
  if (/px-captcha|_pxhd|perimeterx/i.test(head)) markers.push('perimeterx');
  if (markers.length === 0) return null;
  const idMatch =
    head.match(/name\s*=\s*["']screen_id["']\s+value\s*=\s*["']([^"']+)["']/i) ||
    head.match(/Screen ID:\s*([A-Za-z0-9-]{4,})/);
  return { markers, screenId: idMatch ? idMatch[1] : null };
}

function pageTitle(html) {
  const m = typeof html === 'string' ? html.match(/<title[^>]*>([\s\S]{0,120}?)<\/title>/i) : null;
  return m ? m[1].replace(/\s+/g, ' ').trim() : null;
}

// Positive identification: does this body actually contain a FortiGuard advisory?
// Any ONE of these is decisive — they are structures the challenge page provably
// does not have.
function looksLikeAdvisoryPage(html) {
  if (typeof html !== 'string' || html === '') return false;
  if (CSAF_URL_RE.test(html)) return true;
  if (/>\s*CVE ID\s*</i.test(html)) return true;
  if (/>\s*IR Number\s*</i.test(html)) return true;
  if (/>\s*Affected\s*<[\s\S]{0,200}>\s*Solution\s*</i.test(html)) return true;
  return false;
}

/**
 * @returns {{kind: 'advisory'|'bot_challenge'|'page_not_advisory'|'page_empty',
 *            detail?: string, screenId?: string|null}}
 */
function classifyAdvisoryPage(html) {
  if (typeof html !== 'string' || html.trim() === '') {
    return { kind: REASON.PAGE_EMPTY, detail: 'the advisory URL returned an empty body' };
  }
  // ⛔ Real content wins over challenge markers, never the other way round: an
  // advisory whose prose happened to contain one of those strings must still be
  // parsed. Only a body with NO advisory structure can be called a challenge.
  if (looksLikeAdvisoryPage(html)) return { kind: 'advisory' };

  const challenge = detectBotChallenge(html);
  if (challenge) {
    const idPart = challenge.screenId ? `; Screen ID ${challenge.screenId}` : '';
    return {
      kind: REASON.BOT_CHALLENGE,
      screenId: challenge.screenId,
      detail:
        `FortiGuard served a BOT-PROTECTION INTERSTITIAL instead of the advisory ` +
        `(HTTP 200, ${html.length} bytes; markers: ${challenge.markers.join(', ')}${idPart}). ` +
        `The advisory HTML was never served — nothing is known about this advisory's contents.`,
    };
  }

  return {
    kind: REASON.PAGE_NOT_ADVISORY,
    detail:
      `HTTP 200 but the body is not a FortiGuard advisory page and carries no recognised ` +
      `bot-challenge markers (${html.length} bytes, <title> ${JSON.stringify(pageTitle(html))}). ` +
      `Nothing is known about this advisory's contents.`,
  };
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
// "FortiProxy - MEDIUM - FG-IR-26-154". This is the vendor filter ("only ingest FortiOS
// advisories, skip FortiProxy/FortiManager/etc").
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
//
// ⛔ `acc.declaredAffected` counts FortiOS-scoped known_affected STRINGS THE SOURCE SUPPLIED,
// whether or not we managed to parse them. That count is what tells `matched` (the source
// declared nothing) apart from `unmatchable` (the source declared something and our parser did
// not understand it) — see classifyCsafMatchability. Without it an empty range list is ambiguous,
// which is the exact bug advisories.matchability was added to close.
function mergeVersionDataFromEntry(vulnEntry, acc) {
  const ps = (vulnEntry && vulnEntry.product_status) || {};
  for (const s of ps.known_affected || []) {
    const extracted = extractProductAndRemainder(s);
    if (extracted && extracted.product === 'FortiOS') acc.declaredAffected += 1;
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

// ⛔ Three-way, matching lib/schema.sql's own definition of advisories.matchability:
//   matched      ranges were extracted, OR the source genuinely declared none
//   unmatchable  the source DECLARED affected versions and none could be extracted —
//                an empty list here is a FAILED READ and must never be scored
//                as "this device is not affected"
// (`other_product` is not reachable from here: a document with no FortiOS-scoped entry
// produces no record at all and is counted as `skipped`.)
function classifyCsafMatchability(group) {
  if (group.ranges.length > 0) return 'matched';
  if (group.declaredAffected > 0) return 'unmatchable';
  return 'matched';
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
      return {
        score: v3.baseScore,
        vector: v3.vectorString || null,
        // The scale, recorded rather than assumed — CLAUDE.md's CVSS-provenance rule.
        // CSAF carries it explicitly; the vector string carries it as a prefix; the
        // containing key is literally `cvss_v3`, so '3' is the honest floor, never '3.1'.
        version: cvssVersionFrom(v3.version, v3.vectorString, '3'),
      };
    }
  }
  return { score: null, vector: null, version: null };
}

// '3.1' from an explicit field, else from a "CVSS:3.1/AV:N/..." vector prefix, else the
// caller's floor. Never invents a minor version it did not read somewhere.
function cvssVersionFrom(explicitVersion, vectorString, floor) {
  if (typeof explicitVersion === 'string' && /^\d/.test(explicitVersion.trim())) {
    return explicitVersion.trim();
  }
  const m = typeof vectorString === 'string' ? vectorString.match(/^CVSS:(\d+(?:\.\d+)?)\//i) : null;
  if (m) return m[1];
  return floor || null;
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
  const advisoryUrl = advisoryUrlFor(fgIrId);

  const groups = new Map(); // cveId -> { ranges, fixedVersions, cvss, summary, cweIds, declaredAffected }

  for (const vulnEntry of (csafJson && csafJson.vulnerabilities) || []) {
    const cveId = vulnEntry && vulnEntry.cve;
    if (!cveId) continue;
    if (!isFortiOSScoredEntry(vulnEntry)) continue;

    let group = groups.get(cveId);
    if (!group) {
      group = {
        ranges: [],
        fixedVersions: new Set(),
        cvss: { score: null, vector: null, version: null },
        summary: null,
        cweIds: new Set(),
        declaredAffected: 0,
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
      vendor: VENDOR_SLUG,
      title: `${VENDOR_LABEL} — ${cveId}`,
      description: group.summary ? `[${fgIrId}] ${group.summary}` : `[${fgIrId}] ${docTitle}`,
      cvss_score: group.cvss.score,
      cvss_vector: group.cvss.vector,
      cvss_source: group.cvss.score === null ? null : 'psirt',
      cvss_version: group.cvss.score === null ? null : group.cvss.version,
      published_at: publishedAt,
      affected_version_ranges: group.ranges,
      fixed_in_versions: Array.from(group.fixedVersions),
      advisory_url: advisoryUrl,
      raw_data: csafJson,
      cwe_ids: cweIds,
      vulnerability_category: categorizeCwes(cweIds),
      matchability: classifyCsafMatchability(group),
      source_tier: 'advisory_page',
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
    // ⛔ This sentence is only reachable now that classifyAdvisoryPage() has POSITIVELY
    // identified the body as a real advisory page. It used to be reached by a
    // bot-challenge interstitial, which is how "advisory may predate CSAF" ended up
    // being reported 50 times a run about advisories nobody had ever seen.
    throw feedError(
      REASON.NO_CSAF_LINK,
      'the advisory page was served but contains no csaf_url link (this advisory may predate CSAF)'
    );
  }
  let csafJson;
  try {
    csafJson = await fetchJson(csafUrl);
  } catch (err) {
    throw feedError(REASON.CSAF_FETCH_FAILED, `CSAF JSON fetch failed (${csafUrl}): ${err.message}`);
  }
  if (!state.loggedFirstCsaf) {
    console.log('[Fortinet PSIRT Debug] Raw CSAF JSON (first successfully-fetched advisory):', JSON.stringify(csafJson, null, 2));
    state.loggedFirstCsaf = true;
  }
  try {
    return buildRecordsFromCsaf(csafJson, fgIrId);
  } catch (err) {
    throw feedError(REASON.CSAF_PARSE_FAILED, `CSAF JSON parsed but could not be interpreted: ${err.message}`);
  }
}

// ────────────────────────────────────────────────────────────────────────
// HTML-table-scrape FALLBACK — only reached when the CSAF path throws (no csaf_url link, or the
// CSAF fetch/parse itself failed) AND the page has already been confirmed to be a real advisory
// page. Uses the HTML already fetched — never re-fetches the advisory page.
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
//
// ⛔ `declaredAffected` counts FortiOS rows that STATE a vulnerable version, parsed or not — the
// same matched-vs-unmatchable discriminator the CSAF path keeps.
function parseVersionTableRows($, versionTable) {
  const ranges = [];
  const fixedVersions = new Set();
  let declaredAffected = 0;

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
      declaredAffected += 1;

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
      // Unrecognized affected-text shape for this row — skip rather than guess. It stays counted
      // in declaredAffected, so the record is honestly labelled `unmatchable` rather than
      // presenting an empty range list as an answer.
    });

  return { ranges, fixedVersions, declaredAffected };
}

// Builds records from the HTML table when CSAF is unavailable/broken for this advisory. Cannot
// distinguish per-CVE version data the way CSAF can (the table has no CVE-id column), so every CVE
// id found in the metadata table gets the SAME version-range/CVSS data — a known limitation of this
// fallback, acceptable because it's the rare path (CSAF is primary and covers the normal case).
function buildRecordsFromHtmlFallback($, fgIrId, item) {
  const versionTable = findVersionTable($);
  const metaTable = findMetadataTable($);

  if (versionTable.length === 0 && metaTable.length === 0) {
    throw feedError(
      REASON.HTML_TABLES_MISSING,
      'the advisory page was served but neither the affected-versions table nor the metadata table was found in it (page redesign?)'
    );
  }

  let cveIds = [];
  let cvssScore = null;
  if (metaTable.length > 0) {
    const meta = parseMetadataTable($, metaTable);
    cveIds = meta.cveIds;
    cvssScore = meta.cvssScore;
  }

  // Last-resort CVE id source: the RSS item's own description text. Measured live 2026-09-10,
  // only 5 of 50 items carry one — it rarely helps, but costs nothing to try before giving up.
  if (cveIds.length === 0 && item && item.description) {
    cveIds = item.description.match(/CVE-\d{4}-\d{4,}/g) || [];
  }

  if (cveIds.length === 0) {
    throw feedError(REASON.HTML_NO_CVE_ID, 'no CVE ID could be extracted from the advisory page');
  }

  let ranges = [];
  let fixedVersions = new Set();
  let declaredAffected = 0;
  if (versionTable.length > 0) {
    const parsed = parseVersionTableRows($, versionTable);
    ranges = parsed.ranges;
    fixedVersions = parsed.fixedVersions;
    declaredAffected = parsed.declaredAffected;
  }

  const advisoryUrl = advisoryUrlFor(fgIrId);
  const publishedAt = (item && item.pubDate) || null;
  const rssTitle = (item && item.title) || fgIrId;
  const fixedVersionsArr = Array.from(fixedVersions);
  // No version table at all is itself a failed read of the version data, not a declaration
  // that nothing is affected.
  const matchability = ranges.length > 0 ? 'matched' : (declaredAffected > 0 || versionTable.length === 0) ? 'unmatchable' : 'matched';

  return uniq(cveIds).map((cveId) => ({
    cve_id: cveId,
    vendor: VENDOR_SLUG,
    title: `${VENDOR_LABEL} — ${cveId}`,
    description: `[${fgIrId}] ${rssTitle} (via HTML-table fallback — CSAF unavailable for this advisory)`,
    cvss_score: cvssScore,
    cvss_vector: null, // not available from the HTML table — only a numeric CVSSv3 score is shown
    cvss_source: cvssScore === null ? null : 'psirt',
    cvss_version: cvssScore === null ? null : '3', // the table's own label is "CVSSv3 Score"; no minor version is shown
    published_at: publishedAt,
    affected_version_ranges: ranges,
    fixed_in_versions: fixedVersionsArr,
    advisory_url: advisoryUrl,
    raw_data: { source: 'html_fallback', fgIrId, cveIds, cvssScore, versionRanges: ranges, fixedVersions: fixedVersionsArr },
    // No CWE data is available from the HTML table (only CSAF carries it) —
    // explicit [] / categorizeCwes([]) = 'Other', matching this codebase's
    // convention of an honest, explicit "uncategorized" rather than leaving
    // the column NULL (which would look like "not yet computed" instead of
    // "genuinely nothing to categorize").
    cwe_ids: [],
    vulnerability_category: categorizeCwes([]),
    matchability,
    source_tier: 'advisory_page',
  }));
}

// ────────────────────────────────────────────────────────────────────────
// DEGRADED path — the RSS payload itself
//
// Reached only when the advisory page could not be read. Extracts exactly what the RSS
// genuinely carries and NOTHING more. Measured across all 50 live items on 2026-09-10:
// 50 CVSSv3 scores, 45 CWE ids, 5 CVE ids, 0 affected-version statements of any kind.
//
// ⛔ NO VERSION RANGES ARE INVENTED OR INFERRED. The description prose names products and
// sometimes a CVE, never a version. Every record built here is `matchability:'unmatchable'`
// so versionMatcher skips it AND counts it, instead of an empty range list being read as
// "this device is not affected".
// ────────────────────────────────────────────────────────────────────────

const CVE_ID_RE = /CVE-\d{4}-\d{4,}/g;

function stripHtml(html) {
  return String(html || '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Pure. Extracts from one RSS <item> only what it demonstrably contains.
 * Every field is null/empty when the item did not carry it — no defaults, per CLAUDE.md's
 * "a wrong DEFAULT is a fabricated dataset" rule.
 */
function parseRssItem(item, fgIrId) {
  const text = stripHtml(item && item.description);
  const cveIds = uniq(text.match(CVE_ID_RE) || []);
  const scoreMatch = text.match(/CVSSv([\d.]+)\s*Score:\s*([\d.]+)/i);
  const parsedScore = scoreMatch ? parseFloat(scoreMatch[2]) : NaN;
  const cweIds = uniq(text.match(/CWE-\d+/g) || []);

  // The human summary is the description minus the two boilerplate lines the feed wraps it in.
  const summary =
    text
      .replace(/^CVSSv[\d.]+\s*Score:\s*[\d.]+\s*/i, '')
      .replace(/\s*Revised on \d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?\s*$/i, '')
      .trim() || null;

  return {
    fgIrId: fgIrId || null,
    title: (item && item.title) || null,
    cveIds,
    cvssScore: Number.isNaN(parsedScore) ? null : parsedScore,
    cvssVersion: scoreMatch ? scoreMatch[1] : null,
    cweIds,
    publishedAt: (item && item.pubDate) || null,
    summary,
  };
}

/**
 * Pure. One advisories record per CVE id the RSS item carried. Returns [] when it carried
 * none — the caller records that as an explicit, counted `rss_no_cve_id` non-ingestion.
 *
 * ⛔ NO SYNTHETIC IDENTIFIER. `advisories.cve_id` is NOT NULL UNIQUE and every consumer
 * (KEV cross-reference, versionMatcher, the CVE tables, the fleet counts) reads it as a real
 * CVE. Writing an FG-IR id into that column would fabricate an identifier and put a non-CVE
 * into the product's CVE counts — so an advisory with no CVE id is NOT stored, it is reported.
 */
function buildRecordsFromRss(parsed, reasonDetail) {
  if (!parsed || !Array.isArray(parsed.cveIds) || parsed.cveIds.length === 0) return [];
  const fgIrId = parsed.fgIrId;
  const advisoryUrl = fgIrId ? advisoryUrlFor(fgIrId) : null;
  const prefix = fgIrId ? `[${fgIrId}] ` : '';
  const headline = parsed.title || fgIrId || 'FortiGuard advisory';
  const body = parsed.summary ? ` ${parsed.summary}` : '';

  return parsed.cveIds.map((cveId) => ({
    cve_id: cveId,
    vendor: VENDOR_SLUG,
    title: `${VENDOR_LABEL} — ${cveId}`,
    description:
      `${prefix}${headline}.${body} ` +
      `(DEGRADED INGEST: read from the FortiGuard RSS only — the advisory page was not served, ` +
      `so NO affected-version data is available for this advisory.)`,
    cvss_score: parsed.cvssScore,
    cvss_vector: null, // the RSS publishes a bare score, never a vector
    cvss_source: parsed.cvssScore === null ? null : 'psirt',
    cvss_version: parsed.cvssScore === null ? null : parsed.cvssVersion,
    published_at: parsed.publishedAt,
    // ⛔ Empty because we READ nothing, not because nothing is affected. That is exactly what
    // `matchability:'unmatchable'` below records, and why it must never be softened to 'matched'.
    affected_version_ranges: [],
    fixed_in_versions: [],
    advisory_url: advisoryUrl,
    raw_data: {
      source: 'fortiguard_rss',
      fg_ir_id: fgIrId,
      rss_title: parsed.title,
      rss_summary: parsed.summary,
      rss_pub_date: parsed.publishedAt,
      cvss_score: parsed.cvssScore,
      cwe_ids: parsed.cweIds,
      degraded_reason: reasonDetail || null,
    },
    cwe_ids: parsed.cweIds,
    vulnerability_category: categorizeCwes(parsed.cweIds),
    matchability: 'unmatchable',
    source_tier: 'rss',
  }));
}

// ────────────────────────────────────────────────────────────────────────
// Per-advisory orchestration
// ────────────────────────────────────────────────────────────────────────

async function fetchAdvisoryPage(fgIrId) {
  const url = advisoryUrlFor(fgIrId);
  let res;
  try {
    res = await fetch(url, { headers: { 'User-Agent': USER_AGENT }, timeout: FETCH_TIMEOUT_MS });
  } catch (err) {
    throw feedError(REASON.PAGE_NETWORK_ERROR, `advisory page unreachable: ${err.message}`);
  }
  if (!res.ok) {
    throw feedError(REASON.PAGE_HTTP_ERROR, `advisory page returned HTTP ${res.status}`);
  }
  const html = await res.text();
  const verdict = classifyAdvisoryPage(html);
  if (verdict.kind !== 'advisory') {
    const err = feedError(verdict.kind, verdict.detail);
    err.screenId = verdict.screenId || null;
    throw err;
  }
  return html;
}

// Resolves one advisory from its own page. Throws a reason-tagged error if the page could not be
// obtained OR could not be parsed; the caller decides whether to fall back to the RSS payload.
async function resolveFromAdvisoryPage(fgIrId, item, state) {
  const html = await fetchAdvisoryPage(fgIrId);

  let csafErr;
  try {
    return { via: 'csaf', records: await tryCsafPath(fgIrId, html, state) };
  } catch (err) {
    csafErr = err;
  }

  try {
    const $ = cheerio.load(html);
    return { via: 'html_table', records: buildRecordsFromHtmlFallback($, fgIrId, item) };
  } catch (fallbackErr) {
    const err = feedError(
      fallbackErr.reason || REASON.HTML_TABLES_MISSING,
      `CSAF path failed (${csafErr.message}); HTML-table fallback also failed (${fallbackErr.message})`
    );
    throw err;
  }
}

// ────────────────────────────────────────────────────────────────────────
// Upsert — mirrors lib/feeds/nvd.js's upsertAdvisory (same SQL shape, same cross-vendor guard),
// vendor literal 'fortinet'. Duplicated rather than imported/shared: nvd.js does not export this
// function, and this codebase's convention for feed files is duplicated-not-shared.
//
// ⛔ TWO SOURCE TIERS, ONE STATEMENT. `$17` is `is_degraded`.
//
//   'advisory_page' (CSAF or the HTML tables) — authoritative for this vendor. Behaves exactly
//       as before: within the same vendor, EXCLUDED wins.
//   'rss'          — DEGRADED. **May only FILL A GAP; it may never overwrite anything.** This
//       mirrors nvd.js's CIRCL-may-only-fill-a-gap precedence rule, for the same reason: the
//       degraded source carries no version ranges, a weaker CVSS (bare score, no vector) and no
//       product scope, so letting it write over an NVD/CIRCL-sourced row would replace real data
//       with the absence of data — the failed-read-as-a-fact bug, arriving through the upsert.
//
// ⛔ The single most dangerous clause here is `matchability`. A degraded record carries
// 'unmatchable'; writing that onto a row that ALREADY has real affected_version_ranges would make
// versionMatcher SKIP an advisory it currently matches — silently un-assessing a live CVE. Both
// the ranges guard and the explicit `= 'matched'` guard below exist to stop that, and they are
// deliberately two clauses rather than one.
//
// ⛔ Bug fixed 2026-07-19 and still load-bearing: EVERY non-key column is guarded by
// `advisories.vendor = EXCLUDED.vendor`. advisories.cve_id is UNIQUE across ALL vendors, so
// without it a Fortinet sync could overwrite the owning vendor's CVSS/description/ranges. That
// guard now lives in the statement's WHERE too, so a cross-vendor collision performs no write at
// all and is counted as `unchanged` rather than as a phantom update. (Live example: CVE-2022-0778
// — an OpenSSL CVE that FortiGuard republishes as FG-IR-22-059 — is owned by `paloalto` in this
// deployment, with 6 real version ranges. It must stay that way.)
// ────────────────────────────────────────────────────────────────────────
async function upsertAdvisory(pool, rec) {
  const isDegraded = rec.source_tier === 'rss';
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
       title = CASE WHEN $17::boolean AND advisories.title IS NOT NULL
                    THEN advisories.title ELSE EXCLUDED.title END,
       description = CASE WHEN $17::boolean AND advisories.description IS NOT NULL
                    THEN advisories.description ELSE EXCLUDED.description END,
       cvss_score = CASE WHEN $17::boolean AND advisories.cvss_score IS NOT NULL
                    THEN advisories.cvss_score ELSE EXCLUDED.cvss_score END,
       -- Vector, source and scale move WITH the score, or the four disagree.
       cvss_vector = CASE WHEN $17::boolean AND advisories.cvss_score IS NOT NULL
                    THEN advisories.cvss_vector ELSE EXCLUDED.cvss_vector END,
       cvss_source = CASE WHEN $17::boolean AND advisories.cvss_score IS NOT NULL
                    THEN advisories.cvss_source ELSE EXCLUDED.cvss_source END,
       cvss_version = CASE WHEN $17::boolean AND advisories.cvss_score IS NOT NULL
                    THEN advisories.cvss_version ELSE EXCLUDED.cvss_version END,
       published_at = CASE WHEN $17::boolean AND advisories.published_at IS NOT NULL
                    THEN advisories.published_at ELSE EXCLUDED.published_at END,
       affected_version_ranges = CASE
                    WHEN $17::boolean AND jsonb_typeof(advisories.affected_version_ranges) = 'array'
                         AND jsonb_array_length(advisories.affected_version_ranges) > 0
                      THEN advisories.affected_version_ranges
                    ELSE EXCLUDED.affected_version_ranges END,
       fixed_in_versions = CASE
                    WHEN $17::boolean AND jsonb_typeof(advisories.fixed_in_versions) = 'array'
                         AND jsonb_array_length(advisories.fixed_in_versions) > 0
                      THEN advisories.fixed_in_versions
                    ELSE EXCLUDED.fixed_in_versions END,
       advisory_url = CASE WHEN $17::boolean AND advisories.advisory_url IS NOT NULL
                    THEN advisories.advisory_url ELSE EXCLUDED.advisory_url END,
       raw_data = CASE WHEN $17::boolean AND advisories.raw_data IS NOT NULL
                    THEN advisories.raw_data ELSE EXCLUDED.raw_data END,
       cwe_ids = CASE WHEN $17::boolean AND advisories.cwe_ids IS NOT NULL
                          AND array_length(advisories.cwe_ids, 1) > 0
                    THEN advisories.cwe_ids ELSE EXCLUDED.cwe_ids END,
       vulnerability_category = CASE WHEN $17::boolean AND advisories.vulnerability_category IS NOT NULL
                    THEN advisories.vulnerability_category ELSE EXCLUDED.vulnerability_category END,
       -- ⛔ A degraded record must never relabel a row that has real ranges, and must never
       -- overwrite an existing 'matched'. Clearing a STALE 'unmatchable' when a full ingest
       -- succeeds is the whole point of writing this column on every ingest.
       matchability = CASE
                    WHEN $17::boolean AND jsonb_typeof(advisories.affected_version_ranges) = 'array'
                         AND jsonb_array_length(advisories.affected_version_ranges) > 0
                      THEN advisories.matchability
                    WHEN $17::boolean AND advisories.matchability IS NOT NULL
                      THEN advisories.matchability
                    ELSE EXCLUDED.matchability END,
       updated_at = now()
     WHERE advisories.vendor = EXCLUDED.vendor
       AND (
         NOT $17::boolean
         OR advisories.title IS NULL
         OR advisories.description IS NULL
         OR advisories.cvss_score IS NULL
         OR advisories.published_at IS NULL
         OR advisories.advisory_url IS NULL
         OR advisories.raw_data IS NULL
         OR advisories.matchability IS NULL
         OR advisories.vulnerability_category IS NULL
         OR advisories.cwe_ids IS NULL
         OR array_length(advisories.cwe_ids, 1) IS NULL
       )
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
      isDegraded,
    ]
  );
  // ⛔ Zero rows means the ON CONFLICT ... WHERE declined the update: either another vendor owns
  // this cve_id, or this degraded record had no gap to fill. Both are "left alone", NOT "updated"
  // — reporting them as updates would overstate what the run achieved.
  if (result.rows.length === 0) return 'unchanged';
  return result.rows[0].inserted === true ? 'inserted' : 'updated';
}

// ────────────────────────────────────────────────────────────────────────
// Run summary
//
// ⛔ WHAT `status` MEANS, and why this run does not report `success` while degraded.
// lib/feeds/index.js derives feed_sync_log.status as `errors.length ? 'partial' : 'success'`.
// A run that could not read a single advisory page, and therefore ingested no version data at
// all, is NOT a success — reporting one would be the fabrication this whole file is about. So
// this function still produces a non-empty errors array whenever anything was lost or degraded.
//
// What CHANGED is that `partial` is now LEGIBLE. The old behaviour was 50 identical entries all
// stating the same wrong reason. There is now exactly ONE aggregate entry carrying the counts,
// the per-reason breakdown and the affected FG-IR ids, plus one entry per genuinely-lost row
// (an upsert that threw). A clean run — every advisory page served and parsed — still produces
// an empty errors array and therefore `success`.
// ────────────────────────────────────────────────────────────────────────
function buildRunErrors(summary) {
  const errors = [];
  const {
    rssItemCount,
    resolvedFromPage,
    degraded,
    skipped,
    unresolved,
    pageFailureReasons,
    screenId,
    pageProbeSuspendedAfter,
    upsertErrors,
  } = summary;

  const degradedCount = degraded.length;
  const unresolvedCount = unresolved.length;

  if (degradedCount > 0 || unresolvedCount > 0 || Object.keys(pageFailureReasons).length > 0) {
    const byReason = Object.entries(pageFailureReasons)
      .sort((a, b) => b[1] - a[1])
      .map(([reason, count]) => `${reason}=${count}`)
      .join(', ');

    const parts = [
      `[fortinet-psirt] ${rssItemCount} advisories in the FortiGuard RSS:`,
      `${resolvedFromPage} fully ingested from the advisory page,`,
      // ⛔ These are NOT STORED. This sentence said "ingested … stored" for one deploy
      // while inserted=0/updated=0 — reintroducing, in the summary, exactly the
      // report-something-untrue bug this whole change exists to fix. Say what happened.
      `${degradedCount} recoverable from the RSS but DELIBERATELY NOT STORED (no affected-version data, so they would be unmatchable and would squat the CVE id — see RSS_INSERT_WOULD_SQUAT_CVE_IDS),`,
      `${unresolvedCount} NOT ingested,`,
      `${skipped} skipped (no FortiOS-scoped content).`,
      `Advisory-page failures by reason: ${byReason || 'none'}.`,
    ];
    if (pageFailureReasons[REASON.BOT_CHALLENGE]) {
      parts.push(
        `FortiGuard is answering advisory-page requests with a BOT-PROTECTION INTERSTITIAL` +
          `${screenId ? ` (Screen ID ${screenId})` : ''} — HTTP 200 with no advisory content. ` +
          `This is NOT "the advisory predates CSAF" and NOT a page-redesign: no advisory HTML is reaching SecVault at all.`
      );
    }
    if (pageProbeSuspendedAfter !== null) {
      parts.push(
        `Advisory-page probing was suspended after ${pageProbeSuspendedAfter} consecutive challenges; ` +
          `the remaining items went straight to the degraded RSS path.`
      );
    }
    if (unresolvedCount > 0) {
      parts.push(
        `The ${unresolvedCount} not-ingested advisories carry no CVE ID in the RSS, so they cannot be keyed to a CVE ` +
          `(advisories.cve_id is the row identity — no synthetic identifier is invented).`
      );
    }

    errors.push({
      cve_id: null,
      reason: 'run_summary',
      message: parts.join(' '),
      counts: {
        rss_items: rssItemCount,
        resolved_from_advisory_page: resolvedFromPage,
        degraded_from_rss: degradedCount,
        not_ingested: unresolvedCount,
        skipped_non_fortios: skipped,
      },
      page_failures_by_reason: pageFailureReasons,
      bot_challenge_screen_id: screenId || null,
      degraded_advisories: degraded,
      not_ingested_advisories: unresolved,
    });
  }

  for (const e of upsertErrors) {
    errors.push({ cve_id: e.cve_id, reason: REASON.UPSERT_FAILED, message: `${e.fgIrId}: upsert failed: ${e.message}` });
  }

  return errors;
}

/**
 * Fetch Fortinet advisories from the FortiGuard PSIRT RSS feed, resolve each to its CSAF 2.0 JSON
 * (falling back to HTML-table-scraping, and then to the RSS payload itself when the advisory page
 * is not served at all), and upsert them into `advisories`. Rate-limited to one advisory's
 * fetch-pair per second — FortiGuard is rate-sensitive; sequential, never parallel. One advisory's
 * failure never aborts the run.
 * @param {import('pg').Pool} pool
 * @returns {Promise<{inserted:number, updated:number, unchanged:number, skipped:number,
 *   degraded:number, not_ingested:number, errors:Array<{cve_id:string|null, message:string}>}>}
 */
async function fetchAndUpsertFortinetAdvisories(pool) {
  let inserted = 0;
  let updated = 0;
  let unchanged = 0;
  let skipped = 0;
  let resolvedFromPage = 0;
  const degraded = [];
  const unresolved = [];
  const upsertErrors = [];
  const pageFailureReasons = {};
  let screenId = null;
  let pageProbeSuspendedAfter = null;
  const state = { loggedFirstCsaf: false };

  let rssItems;
  try {
    rssItems = await fetchRssItems();
  } catch (err) {
    // The RSS is the only discovery mechanism; without it the run has no input at all.
    return {
      inserted,
      updated,
      unchanged,
      skipped,
      degraded: 0,
      not_ingested: 0,
      errors: [{ cve_id: null, reason: REASON.RSS_FETCH_FAILED, message: `FortiGuard RSS fetch failed: ${err.message}` }],
    };
  }

  let consecutiveChallenges = 0;
  let pageProbeSuspended = false;
  let pagesAttempted = 0;

  for (const item of rssItems) {
    const fgIrId = extractFgIrId(item.link);
    if (!fgIrId) {
      unresolved.push({ fg_ir_id: null, reason: REASON.RSS_NO_FG_IR_ID, detail: `RSS <link> carries no FG-IR id: ${item.link}` });
      continue;
    }

    let records = null;
    let pageFailure = null;

    if (pageProbeSuspended) {
      pageFailure = {
        reason: REASON.PAGE_PROBE_SUSPENDED,
        message: `advisory page not requested — probing was suspended after ${CHALLENGE_CIRCUIT_BREAK} consecutive bot challenges`,
      };
    } else {
      if (pagesAttempted > 0) await sleep(ADVISORY_FETCH_DELAY_MS); // rate limit between page fetches
      pagesAttempted += 1;
      try {
        const resolved = await resolveFromAdvisoryPage(fgIrId, item, state);
        records = resolved.records;
        consecutiveChallenges = 0;
      } catch (err) {
        pageFailure = { reason: err.reason || REASON.PAGE_NOT_ADVISORY, message: err.message };
        if (err.screenId && !screenId) screenId = err.screenId;
        if (pageFailure.reason === REASON.BOT_CHALLENGE) {
          consecutiveChallenges += 1;
          if (consecutiveChallenges >= CHALLENGE_CIRCUIT_BREAK) {
            pageProbeSuspended = true;
            pageProbeSuspendedAfter = consecutiveChallenges;
          }
        } else {
          consecutiveChallenges = 0;
        }
      }
    }

    if (pageFailure) {
      pageFailureReasons[pageFailure.reason] = (pageFailureReasons[pageFailure.reason] || 0) + 1;
      // DEGRADED FALLBACK — the RSS payload itself.
      const parsed = parseRssItem(item, fgIrId);
      const rssRecords = buildRecordsFromRss(parsed, `${pageFailure.reason}: ${pageFailure.message}`);
      if (rssRecords.length === 0) {
        unresolved.push({
          fg_ir_id: fgIrId,
          reason: REASON.RSS_NO_CVE_ID,
          detail: `${pageFailure.message}; the RSS item carries no CVE ID, so this advisory cannot be keyed to a CVE`,
        });
        continue;
      }
      // ⛔ THE DEGRADED RSS PATH IS PARSED AND REPORTED, BUT NOT STORED. Read the
      // RSS_INSERT_WOULD_SQUAT_CVE_IDS note at the top of this file before changing
      // this. Short version, all measured live on 2026-09-10:
      //   - the RSS yields a CVE id for 5 of 50 items, and ALL FIVE are third-party
      //     component republications (OpenSSH, Linux kernel, Apache), never a FortiOS
      //     advisory. CVE-id and CWE presence are perfectly disjoint across the feed.
      //   - a degraded row carries no version ranges, so it is `unmatchable`, and
      //     `assessments_from_unmatchable` is 0 on the live fleet. It can NEVER
      //     produce an assessment. The benefit of storing it is exactly zero.
      //   - `advisories.cve_id` is UNIQUE with ONE vendor, so storing it SQUATS a
      //     global identifier under the wrong vendor. This is not hypothetical:
      //     CVE-2022-0778 (OpenSSL, republished by Fortinet as FG-IR-22-059 and still
      //     in today’s RSS) is owned by `paloalto` WITH 6 REAL VERSION RANGES and
      //     matchability=matched. Had this path been storing in 2022, Fortinet would
      //     have taken that row first and Palo Alto's real ranges would never have
      //     landed.
      // Zero benefit against a demonstrated, permanent harm. So the items are counted
      // and named in the run summary — the operator still learns exactly what was lost
      // and why — and nothing is written.
      degraded.push({ fg_ir_id: fgIrId, cve_ids: parsed.cveIds, page_failure: pageFailure.reason });
      continue;
    } else if (records && records.length === 0) {
      // Advisory page WAS read and simply has no FortiOS-scoped content (a FortiProxy/
      // FortiManager-only advisory). Real, expected, not an error.
      skipped += 1;
      continue;
    } else {
      resolvedFromPage += 1;
    }

    for (const rec of records) {
      try {
        const outcome = await upsertAdvisory(pool, rec);
        if (outcome === 'inserted') inserted += 1;
        else if (outcome === 'updated') updated += 1;
        else unchanged += 1;
      } catch (e) {
        upsertErrors.push({ cve_id: rec.cve_id, fgIrId, message: e.message });
      }
    }
  }

  const errors = buildRunErrors({
    rssItemCount: rssItems.length,
    resolvedFromPage,
    degraded,
    skipped,
    unresolved,
    pageFailureReasons,
    screenId,
    pageProbeSuspendedAfter,
    upsertErrors,
  });

  return {
    inserted,
    updated,
    unchanged,
    skipped,
    degraded: degraded.length,
    not_ingested: unresolved.length,
    errors,
  };
}

module.exports = {
  fetchAndUpsertFortinetAdvisories,
  // Exported for tests (all pure except fetchRssItems) — see tests/fortinetFeed.test.js.
  REASON,
  detectBotChallenge,
  classifyAdvisoryPage,
  looksLikeAdvisoryPage,
  parseRssXml,
  parseRssItem,
  buildRecordsFromRss,
  buildRecordsFromCsaf,
  buildRunErrors,
  upsertAdvisory,
  extractFgIrId,
  CHALLENGE_CIRCUIT_BREAK,
};
