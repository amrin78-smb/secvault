// lib/feeds/cveorg.js
// CVE.org (MITRE CVE Program) — ENRICHMENT-ONLY feed.
// CommonJS ONLY — this file is `require()`d by services/engine-worker.js (plain node).
//
// ════════════════════════════════════════════════════════════════════════
// ⛔ THE ONE RULE: THIS FEED NEVER INSERTS AN ADVISORY. IT ONLY UPDATES.
//
// `advisories.cve_id` is UNIQUE and each row carries exactly ONE `vendor`, so any feed
// that can INSERT can permanently claim a CVE for the wrong vendor. That harm is
// demonstrated, not theoretical: CVE-2022-0778 is an OpenSSL bug that Fortinet
// republishes, and in this database it belongs to `paloalto` WITH 6 REAL VERSION RANGES —
// whichever feed had inserted it first would have owned it (see .ai-codex/cve-pipeline.md's
// "the degraded RSS path REPORTS but never STORES" section, and .ai-codex/roadmap.md).
//
// CVE.org covers EVERY CVE in existence, so a CVE.org feed with an INSERT in it would
// eventually squat a large fraction of the corpus. Discovery is NVD's and the vendor
// PSIRTs' job. This file contains exactly one write statement and it is an UPDATE
// (ENRICH_SQL, below). There is no `INSERT INTO advisories` anywhere in it, and
// tests/cveorgFeed.test.js greps this source to keep it that way.
// ════════════════════════════════════════════════════════════════════════
//
// ════════════════════════════════════════════════════════════════════════
// LIVE VERIFICATION — run from the reference deployment (192.168.7.69), 2026-09-10,
// per CLAUDE.md's "verify all field names against live responses — documentation lies".
// Nothing below is taken from a doc page.
//
//   HEAD https://cveawg.mitre.org/api/cve/CVE-2024-21762  -> 200, 6665 bytes
//   HEAD https://cveawg.mitre.org/api/cve/CVE-2018-13379  -> 200, 4841 bytes
//   GET  https://cveawg.mitre.org/api/cve/CVE-0000-0000   -> 404
//   GET  https://cveawg.mitre.org/api/cve/PAN-SA-2024-0001-> 400 Bad Request
//   302 further live GETs across the real advisory corpus -> 200, zero failures.
//
// Real response shape (CVE-2024-21762, trimmed):
//   { "dataType":"CVE_RECORD", "dataVersion":"5.2",
//     "cveMetadata":{ "cveId":"CVE-2024-21762", "state":"PUBLISHED",
//                     "assignerShortName":"fortinet", "datePublished":"...", ... },
//     "containers":{
//       "cna":{ "metrics":[{"format":"CVSS","cvssV3_1":{"baseScore":9.6,"vectorString":"CVSS:3.1/..."}}],
//               "problemTypes":[{"descriptions":[{"cweId":"CWE-787","type":"CWE", ...}]}],
//               "affected":[...], "descriptions":[...] },
//       "adp":[ { "metrics":[{"other":{"type":"ssvc",...}},{"other":{"type":"kev",...}}],
//                 "affected":[{"cpes":["cpe:2.3:o:fortinet:fortios:7.4.0:*:..."], ...}] } ] } }
//
// So: this is CVE Record Format 5.x — the SAME schema `lib/feeds/paloalto.js` parses and
// the same schema the CIRCL fallback in `lib/feeds/nvd.js` returns. `Content-Type` is
// `application/json`. One record per request; there is no bulk/filtered query parameter.
//
// ⛔ BULK SOURCE CONSIDERED AND REJECTED, with measurements. `github.com` and
// `api.github.com` both answer 200 from that server, and
// `repos/CVEProject/cvelistV5/releases/latest` (tag `cve_2026-09-10_1500Z`) offers:
//     2026-09-10_all_CVEs_at_midnight.zip.zip   570.9 MB
//     2026-09-10_delta_CVEs_at_1500Z.zip          1.8 MB
// This feed only ever wants a BOUNDED, ALREADY-KNOWN id list (~300 records, ~1.5 MB by the
// per-CVE API). Downloading 570.9 MB every 6 h — or maintaining a local checkout plus delta
// application, on a firewall-management box — to answer the same question is strictly worse.
// The delta zip is small but only carries records CHANGED since the last release, which is
// the wrong axis: our gap rows are OLD records that rarely change. Revisit only if this feed
// ever needs to answer a question about CVEs it does not already have ids for — at which
// point it would no longer be an enrichment feed.
// ════════════════════════════════════════════════════════════════════════
//
// ════════════════════════════════════════════════════════════════════════
// ⛔ MEASURED YIELD ON THE REFERENCE FLEET (2026-09-10) — READ BEFORE EXPECTING RESULTS.
//
// 335 advisories had a CVSS and/or CWE gap (255 with no CVSS at all, 311 with no CWE).
// 33 of them are `PAN-SA-*` ids, not CVE ids (see isCveShapedId below). The remaining 302
// were fetched live from CVE.org. Result:
//
//     CVSS filled:   0 of 255
//     CWE  filled:   4 of 278   (CVE-2017-15944, CVE-2021-3156, CVE-2023-22809, CVE-2024-5535)
//     rejected/disputed: 0      not-found: 0      all 302 state=PUBLISHED
//
// ⛔ That zero is a REAL MEASUREMENT, not a broken probe. Control: 42 of the same 302
// records DO carry a `cvssV3_1` block — every one of them already has a stored score. The
// check was a whole-document regex for /cvssV[0-9_]+/, so it cannot have missed a block by
// walking the JSON wrongly.
//
// WHY: the CIRCL fallback already returns cvelistV5 records — i.e. THE SAME DOCUMENTS
// CVE.org serves. The 255 missing scores are NVD-ANALYST scores that never existed in the
// CVE Record at all (assigners: cisco 157, mitre 53, fortinet 39 — none of which published
// a CVSS block for these). CVE.org is therefore NOT a substitute for NVD's CVSS on this
// corpus, and this feed must not be sold as one.
//
// What it IS good for: newly published CVEs, where the CVE Program's ADP ("Vulnrichment")
// container adds CVSS and CWE within days — which is exactly what the `recent` tier below
// targets — and as an authoritative, independently-reachable second opinion when both NVD
// and CIRCL are unavailable.
// ════════════════════════════════════════════════════════════════════════

// node-fetch@2 exposes both a CJS "main" and an ESM "module" entry; Next.js's bundler
// resolves the latter even for a plain require() inside an API-route bundle, yielding the
// namespace object instead of the callable. Same two-line guard every other feed file here
// uses (see lib/feeds/nvd.js's header for the full incident).
const fetchModule = require('node-fetch');
const fetch = fetchModule.default || fetchModule;
const { categorizeCwes } = require('../engines/vulnerabilityCategory');

const CVEORG_BASE_URL = 'https://cveawg.mitre.org/api/cve';

// Same name, same value, independently defined in each feed file — this codebase's
// established "duplicated, not imported" convention for feed constants (nvd.js:307,
// kev.js:27, paloalto.js:74, fortinet.js:77). node-fetch@2 has NO default timeout.
const FETCH_TIMEOUT_MS = 20000;

// ⛔ POLITENESS. CVE.org publishes no rate limit, which is a reason to be MORE careful, not
// less: an unlimited endpoint is one where a bug costs someone else's service. 250 ms is
// 4 req/s worst case. The live dry run above ran 302 requests at 110 ms with zero failures,
// so 250 ms is deliberately slower than what the service tolerated.
const REQUEST_DELAY_MS = 250;

// Hard ceiling per run, whatever the selection produces. At 250 ms this bounds one run to
// ~40 s of network time.
const MAX_RECORDS_PER_RUN = 150;

// ⛔ SELECTION, TIER 1 — "recent". A CVE Record gains its ADP/Vulnrichment CVSS and CWE in
// the weeks after publication, so a record still inside that window is worth re-asking on
// every run. A 2005 MITRE record with no metrics will not sprout them. 400 days is
// deliberately far wider than the enrichment lag (weeks) because the cost of asking is one
// request and the cost of missing is an unscored CVE.
// Measured on the live corpus: of the 335 gap rows, 2 fall in this tier, 6 within 2 years,
// 39 within 5 years, 288 older. So this tier is nearly empty TODAY and that is the correct,
// honest outcome — it exists to catch tomorrow's gaps, not to churn through yesterday's.
const RECENT_WINDOW_DAYS = 400;

// ⛔ SELECTION, TIER 2 — "backfill", a stateless rotation over the old tail.
//
// The tail must still be re-asked occasionally (a record CAN gain an ADP container later),
// but re-fetching all ~300 of them every 6 h is exactly the hammering this feed must not do —
// 1,200 pointless requests a day to learn nothing. Splitting the tail into buckets by a
// stable hash of the cve_id and doing ONE bucket per run reduces that to ~23 requests/run and
// still sweeps the whole tail every 13 runs (~3 days at the 6 h feed cadence).
//
// ⛔ THE BUCKET COUNT IS PRIME ON PURPOSE. The bucket index advances with wall-clock time
// (there is no column to remember progress in — see the frozen-schema note in the run
// summary). With a composite count, a run cadence sharing a factor with it would visit only
// a subset of buckets FOREVER, silently, and the rows in the other buckets would never be
// re-checked while every log line looked healthy. 13 is prime, so any advance step that is
// not an exact multiple of 13 buckets walks the entire rotation.
const BACKFILL_BUCKETS = 13;
const BACKFILL_BUCKET_PERIOD_MS = 6 * 60 * 60 * 1000; // one bucket per 6 h — the feed cadence

// ⛔ Stop the run after this many CONSECUTIVE network-level failures (fetch() itself threw:
// timeout, DNS, refused). Same reasoning as nvd.js's NVD circuit breaker, and the same
// reason it is NEVER persisted: the block could lift at any moment and the next run must
// re-probe from scratch. Without it, an unreachable CVE.org costs
// MAX_RECORDS_PER_RUN × FETCH_TIMEOUT_MS = up to 50 minutes of sleeping per run.
// An HTTP response of ANY status (404/400/429/5xx) proves the host is up and RESETS the
// streak — it does not merely fail to count.
const UNREACHABLE_STREAK = 4;

// ⛔ `advisories.cve_id` is not guaranteed to hold a CVE id. 59 rows on the live fleet carry
// Palo Alto's own advisory ids (`PAN-SA-2024-0001` …), 33 of them with a CVSS/CWE gap, and
// CVE.org answers 400 Bad Request for every one. Filtering them out in SQL — rather than
// discovering it 33 times over the network — is what keeps a structural fact from being
// reported as 33 request failures. They are COUNTED and reported, never silently dropped:
// "we never asked" and "we asked and got nothing" are different facts.
const CVE_ID_SQL_PATTERN = '^CVE-[0-9]{4}-[0-9]{4,}$';
const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/;

function isCveShapedId(id) {
  return typeof id === 'string' && CVE_ID_RE.test(id);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Mirrors nvd.js's isNetworkLevelFailure(): fetch() threw, so there is no HTTP status.
// Any status at all means the host answered.
function isNetworkLevelFailure(err) {
  return Boolean(err) && err.status == null && !err.cveorgJsonParseError;
}

/**
 * Which backfill bucket this run owns. Stateless by necessity (no column may be added) and
 * deterministic given the clock, so two overlapping runs pick the same bucket instead of
 * doubling the request count.
 */
function currentBackfillBucket(nowMs = Date.now(), buckets = BACKFILL_BUCKETS) {
  return Math.floor(nowMs / BACKFILL_BUCKET_PERIOD_MS) % buckets;
}

// ────────────────────────────────────────────────────────────────────────
// CANDIDATE SELECTION
//
// ⛔ "Advisories that NEED it", never "all 1,004 every 6 hours". A row with both a CVSS and
// a CWE has nothing this feed can add, so asking about it is pure cost. `needs_cvss` /
// `needs_cwe` travel with the row so the run summary can report WHICH gap was filled
// without re-reading the row afterwards.
//
// ⛔ `cvss_score IS NULL` is the gap test, NOT `cvss_score = 0 OR IS NULL`, and the
// difference is not academic — it is the single most tempting wrong turn in this file.
//
// Measured live 2026-09-10: **12 advisories are stored with `cvss_score = 0.0` and a NULL
// `cvss_source`**, all on `paloalto` rows. Three of them are real CVE ids, and CVE.org
// publishes a real score for every one:
//     CVE-2023-44487 (HTTP/2 Rapid Reset)  stored 0.0 — CVE.org cvssV3_1 7.5
//     CVE-2023-4863  (libwebp)             stored 0.0 — CVE.org cvssV3_1 8.8
//     CVE-2022-22963 (Spring Cloud Fn)     stored 0.0 — CVE.org cvssV3_1 9.8
// That is CLAUDE.md's failed-read-as-a-fact bug in `advisories`, with live consequences:
// prioritization.js rule 3 fires at cvss >= 9.0, so CVE-2022-22963 sits in `monitor` on a
// fabricated 0 when its published score is 9.8.
//
// ⛔ AND THIS FEED STILL DOES NOT OVERWRITE THEM. A CVSS base score of 0.0 is a legal,
// publishable value (a vector with no impact scores exactly 0.0), and `cvss_source IS NULL`
// proves nothing — 682 of the 1,004 rows predate that column entirely. So the predicate
// "0.0 with no source is fake" would ALSO condemn a genuine 0.0, which is the same bug
// pointed the other way: guessing that somebody else's stored measurement is not one.
// The correct fix is upstream — stop the producing feed writing 0 for "no score", then
// backfill deliberately in lib/migrate.js, the established pattern for repairing rows
// persisted before a fix (see .ai-codex/gotchas.md's CVE pipeline section). Neither file is
// this one's to change. So they are COUNTED AND REPORTED in the run summary
// (`suspicious_zero_scores`) instead: skip and report, never skip silently.
// ────────────────────────────────────────────────────────────────────────
const SELECT_CANDIDATES_SQL = `
  WITH gaps AS (
    SELECT cve_id,
           vendor,
           published_at,
           (cvss_score IS NULL) AS needs_cvss,
           (cwe_ids IS NULL OR cardinality(cwe_ids) = 0) AS needs_cwe
      FROM advisories
     WHERE (cvss_score IS NULL OR cwe_ids IS NULL OR cardinality(cwe_ids) = 0)
       AND cve_id ~ $1::text
  )
  SELECT cve_id, vendor, needs_cvss, needs_cwe, 0 AS tier
    FROM gaps
   WHERE published_at IS NULL
      OR published_at >= now() - ($2::int * interval '1 day')
  UNION ALL
  SELECT cve_id, vendor, needs_cvss, needs_cwe, 1 AS tier
    FROM gaps
   WHERE published_at IS NOT NULL
     AND published_at < now() - ($2::int * interval '1 day')
     AND ((hashtext(cve_id)::bigint & 2147483647::bigint) % $3::int) = $4::int
   ORDER BY tier, cve_id
   LIMIT $5::int`;

// Counts the gap rows this feed deliberately never asks about, so "0 errors" cannot be
// mistaken for "full coverage".
const COUNT_NON_CVE_GAPS_SQL = `
  SELECT count(*)::int AS n
    FROM advisories
   WHERE (cvss_score IS NULL OR cwe_ids IS NULL OR cardinality(cwe_ids) = 0)
     AND cve_id !~ $1::text`;

// ⛔ REPORT-ONLY. See the long note above SELECT_CANDIDATES_SQL: these rows are NOT candidates
// and this feed will not touch them. Surfacing them is the whole point — a fabricated 0 that
// nobody ever counts is indistinguishable from a real one.
const SUSPICIOUS_ZERO_SCORES_SQL = `
  SELECT cve_id
    FROM advisories
   WHERE cvss_score = 0
     AND cvss_source IS NULL
   ORDER BY cve_id
   LIMIT 50`;

async function selectCandidates(pool, options) {
  const {
    recentWindowDays = RECENT_WINDOW_DAYS,
    buckets = BACKFILL_BUCKETS,
    bucket = currentBackfillBucket(Date.now(), buckets),
    maxRecords = MAX_RECORDS_PER_RUN,
  } = options || {};
  const result = await pool.query(SELECT_CANDIDATES_SQL, [
    CVE_ID_SQL_PATTERN,
    recentWindowDays,
    buckets,
    bucket,
    maxRecords,
  ]);
  return result.rows.map((r) => ({
    cve_id: r.cve_id,
    vendor: r.vendor,
    needs_cvss: r.needs_cvss === true,
    needs_cwe: r.needs_cwe === true,
    tier: r.tier === 0 ? 'recent' : 'backfill',
  }));
}

// ────────────────────────────────────────────────────────────────────────
// FETCH
// ────────────────────────────────────────────────────────────────────────
async function fetchCveRecord(cveId) {
  const url = `${CVEORG_BASE_URL}/${encodeURIComponent(cveId)}`;
  const res = await fetch(url, {
    headers: { Accept: 'application/json' },
    timeout: FETCH_TIMEOUT_MS,
  });
  if (!res.ok) {
    const err = new Error(`CVE.org request failed: HTTP ${res.status} for ${url}`);
    err.status = res.status;
    throw err;
  }
  try {
    return await res.json();
  } catch (parseErr) {
    // The host answered (res.ok) and the body is unusable. A bare SyntaxError has no
    // `.status`, which would otherwise satisfy the reachability test above — mark it so a
    // malformed body can never be mistaken for "CVE.org is unreachable" and trip the
    // circuit breaker. Same marker convention as nvd.js's `nvdJsonParseError`.
    const err = new Error(`CVE.org body could not be parsed as JSON for ${url}: ${parseErr.message}`);
    err.cveorgJsonParseError = true;
    throw err;
  }
}

// ────────────────────────────────────────────────────────────────────────
// RECORD STATE
//
// ⛔ A REJECTED CVE Record is a real, deliberate state, not an error. cveMetadata.state is
// PUBLISHED or REJECTED; a rejection replaces the containers with a `rejectedReasons` block
// carrying no metrics and no weaknesses, so there is nothing to enrich from even if we
// wanted to. THE DECISION: skip it, change nothing, and REPORT it by id.
//
//   • Not enriched — a withdrawn record's contents are not evidence of anything.
//   • Not deleted, and the stored advisory is not touched. Deleting an `advisories` row
//     would cascade `advisory_conditions` and orphan operator-curated data, and it is a
//     different feed's decision besides. This file only ever fills empty fields.
//   • Reported, because "SecVault holds an advisory for a CVE the CVE Program has withdrawn"
//     is exactly the sort of thing an operator should see once rather than never.
//
// Live: 0 of 302 fetched records were REJECTED, so this path is defensive today.
//
// ⛔ DISPUTED is NOT the same as REJECTED and is handled differently. A dispute is carried
// as a `disputed` tag on a still-PUBLISHED record; the CNA's CVSS is still a real published
// number. Refusing it would leave cvss_score NULL, which the priority tree reads as "not
// scored" (defaulting cvssScore to 0 — see prioritization.js) and which therefore SILENTLY
// NARROWS the assessment. This codebase's rule is to widen an uncertain bound, never narrow
// it, so a disputed record IS used for enrichment and the count is reported alongside.
// ────────────────────────────────────────────────────────────────────────
function recordState(rec) {
  const state = rec && rec.cveMetadata && rec.cveMetadata.state;
  return typeof state === 'string' ? state.toUpperCase() : null;
}

function isDisputed(rec) {
  const cna = rec && rec.containers && rec.containers.cna;
  const tags = (cna && cna.tags) || [];
  return Array.isArray(tags) && tags.some((t) => typeof t === 'string' && t.toLowerCase() === 'disputed');
}

// ────────────────────────────────────────────────────────────────────────
// ⛔ CVSS BLOCK SELECTION — a CVE Record can carry SEVERAL, and picking one is a decision.
//
// A record may hold metrics in `containers.cna.metrics[]` AND in every
// `containers.adp[].metrics[]`, each of which is an array whose entries may carry any of
// cvssV4_0 / cvssV3_1 / cvssV3_0 / cvssV2_0 (plus non-CVSS `other` entries: ssvc, kev).
// Taking "the first one found" would make the answer depend on array order, i.e. on nothing.
//
// THE RULE, in order:
//
//   1. CONTAINER FIRST: the CNA container outranks every ADP container.
//      The CNA is the organisation that owns the vulnerability (Fortinet for a FortiOS bug,
//      Cisco for an ASA bug); an ADP container is third-party enrichment layered on top,
//      added precisely BECAUSE the CNA supplied nothing. Live evidence for that direction,
//      both from this corpus: CVE-2024-21762's cna carries cvssV3_1 while its adp entries
//      carry only ssvc/kev — and CVE-2022-0778's cna carries only an `other` metric while
//      the adp supplies the cvssV3_1. ADP fills where the CNA is silent; that is exactly the
//      precedence the code encodes.
//      ⛔ This deliberately differs from nvd.js's pickCvssFromCveRecord(), which flattens
//      cna and adp into ONE list and then sorts only by version — so a v4.0 from an ADP can
//      beat a v3.1 from the CNA there. That is not being "fixed" here (that file is not this
//      one's to change), but this feed writes cvss_source='cveorg' so the two are always
//      distinguishable after the fact.
//
//   2. THEN VERSION, newest first: 4.0 > 3.1 > 3.0 > 2.0. Same cascade as nvd.js's
//      pickCvss()/pickCvssFromCveRecord() and paloalto.js's pickCvssFromPanOsRecord(), so a
//      score from this feed is comparable with the rest of the corpus rather than being a
//      fourth convention. The version chosen is RETURNED and stored in
//      `advisories.cvss_version`, because a bare number cannot explain why it differs from
//      another source's number for the same CVE — the exact failure documented in
//      .ai-codex/cve-pipeline.md's "CVSS provenance" section.
//
//   3. TIES INSIDE ONE CONTAINER AND VERSION: take the first and STOP. Never average, never
//      max. Two assessors' scores averaged is a number neither of them published; a max is a
//      silent editorial choice. One published score, plus the provenance to trace it.
//
// ⛔ NO SCORE ANYWHERE MEANS NULL. Not 0, not a guess from the severity word, not a score
// derived from the vector. A missing score and a score of 0.0 are different facts, and
// prioritization.js reads a null as "no CVSS signal" while it would read a 0 as "harmless".
// ────────────────────────────────────────────────────────────────────────
const CVSS_VERSION_CASCADE = [
  ['cvssV4_0', '4.0'],
  ['cvssV3_1', '3.1'],
  ['cvssV3_0', '3.0'],
  ['cvssV2_0', '2.0'],
];

function pickCvssFromMetricSets(metricSets, container) {
  for (const [key, version] of CVSS_VERSION_CASCADE) {
    for (const m of metricSets) {
      const data = m && m[key];
      if (!data) continue;
      if (typeof data.baseScore !== 'number' || !Number.isFinite(data.baseScore)) continue;
      return {
        score: data.baseScore,
        vector: typeof data.vectorString === 'string' ? data.vectorString : null,
        version,
        container,
      };
    }
  }
  return null;
}

/**
 * @param {object} rec CVE Record Format 5.x
 * @returns {{score:number|null, vector:string|null, version:string|null, container:string|null}}
 */
function pickCvssFromCveRecord(rec) {
  const containers = (rec && rec.containers) || {};
  const cna = containers.cna;
  const cnaMetrics = cna && Array.isArray(cna.metrics) ? cna.metrics : [];
  const fromCna = pickCvssFromMetricSets(cnaMetrics, 'cna');
  if (fromCna) return fromCna;

  const adpContainers = Array.isArray(containers.adp) ? containers.adp : [];
  const adpMetrics = [];
  for (const a of adpContainers) {
    if (a && Array.isArray(a.metrics)) adpMetrics.push(...a.metrics);
  }
  const fromAdp = pickCvssFromMetricSets(adpMetrics, 'adp');
  if (fromAdp) return fromAdp;

  return { score: null, vector: null, version: null, container: null };
}

// CWE ids live at containers.cna.problemTypes[].descriptions[].cweId and, when the CNA gave
// none, at the same path inside an ADP container (live: all 4 fillable rows on this fleet
// came from one or the other — CVE-2017-15944 CWE-119+CWE-20, CVE-2021-3156 CWE-193,
// CVE-2023-22809 CWE-269, CVE-2024-5535 CWE-125). CNA first, same precedence and same reason
// as the CVSS rule above; ADP ids are appended only when the CNA supplied none, so a
// third-party mapping never dilutes the assigner's own.
//
// Raw values pass straight through to categorizeCwes(), whose normalizeCweId() is the ONE
// place that knows what a real CWE id looks like (it also filters NVD's non-CWE
// placeholders). Duplicating that regex here is how the two would drift.
function collectCweIds(container) {
  const ids = [];
  for (const pt of (container && container.problemTypes) || []) {
    for (const d of (pt && pt.descriptions) || []) {
      if (d && typeof d.cweId === 'string' && d.cweId && !ids.includes(d.cweId)) ids.push(d.cweId);
    }
  }
  return ids;
}

function extractCweIdsFromCveRecord(rec) {
  const containers = (rec && rec.containers) || {};
  const fromCna = collectCweIds(containers.cna);
  if (fromCna.length > 0) return fromCna;
  const ids = [];
  for (const a of Array.isArray(containers.adp) ? containers.adp : []) {
    for (const id of collectCweIds(a)) {
      if (!ids.includes(id)) ids.push(id);
    }
  }
  return ids;
}

// ────────────────────────────────────────────────────────────────────────
// ⛔ THE ONLY WRITE IN THIS FILE. AN UPDATE. GAP-FILL ONLY.
//
// Modelled directly on lib/feeds/nvd.js's upsert, where a CIRCL score "may only FILL A GAP:
// it writes where there is no score yet, and never overwrites one NVD supplied". The same
// discipline, one notch stricter, because CVE.org is weaker still for firewall purposes:
//
//   • A vendor PSIRT knows its own product's affected versions and publishes its own CVSS.
//     Those are STRONGER than a generic CVE Record for deciding whether THIS firewall is
//     exposed. This statement therefore cannot touch vendor-owned data at all: `vendor`,
//     `title`, `description`, `affected_version_ranges`, `fixed_in_versions`,
//     `advisory_url`, `raw_data`, `matchability`, `kev_listed` and `published_at` do not
//     appear in the SET list. They cannot be clobbered because they are not written.
//
//   • ⛔ `description`/`title` in particular are NOT written even when NULL. CLAUDE.md's
//     framing: a vendor's advisory prose is what a firewall operator can act on ("upgrade to
//     FortiOS 7.4.3 or above"), while the CVE Record's is a generic weakness statement.
//     Overwriting the actionable one with the generic one is a downgrade dressed as a fill,
//     and filling an empty one silently mixes registries in a column the UI renders as
//     "the vendor's description". If that is ever wanted it should be a separate, argued
//     change with its own column or its own justification — not a side effect of enrichment.
//
//   • CVSS and CWE ARE written, but ONLY into a genuinely empty field. The guard is
//     `advisories.cvss_score IS NULL` / `cwe_ids IS NULL OR cardinality = 0`, evaluated on
//     the PRE-UPDATE row (every SET expression in one UPDATE sees the old values), so the
//     four CVSS columns move together atomically or not at all — a score kept from one
//     source beside a vector taken from another is a record that contradicts itself, which
//     is worse than either alone.
//
//   • The WHERE clause repeats the same gap test, so a row with nothing to fill is not
//     touched at ALL — no write, no `updated_at` bump, and rowCount reports honestly how
//     many rows genuinely changed.
//
//   • `cvss_source = 'cveorg'` travels WITH the score, exactly as 'circl' does today, so a
//     later reader can always tell where a number came from. (schema.sql's comment on that
//     column reads `nvd | circl | psirt`; it is a comment, not a CHECK constraint — it wants
//     'cveorg' appending, in the file that owns it.)
//
//   • NO VENDOR GUARD IS NEEDED, and that is not an oversight. nvd.js's
//     `CASE WHEN advisories.vendor = EXCLUDED.vendor` exists because an INSERT ... ON
//     CONFLICT arriving from vendor B could overwrite vendor A's row. This statement cannot
//     insert, cannot change `vendor`, and writes only CVE-level facts: a CVSS base score and
//     a CWE mapping belong to the CVE itself, not to whichever vendor's sync happened to
//     claim the row first. They are correct for the row regardless of which vendor owns it.
// ────────────────────────────────────────────────────────────────────────
const ENRICH_SQL = `
  UPDATE advisories SET
    cvss_score = CASE
      WHEN advisories.cvss_score IS NULL AND $2::numeric IS NOT NULL
        THEN $2::numeric ELSE advisories.cvss_score END,
    cvss_vector = CASE
      WHEN advisories.cvss_score IS NULL AND $2::numeric IS NOT NULL
        THEN $3::text ELSE advisories.cvss_vector END,
    cvss_source = CASE
      WHEN advisories.cvss_score IS NULL AND $2::numeric IS NOT NULL
        THEN 'cveorg' ELSE advisories.cvss_source END,
    cvss_version = CASE
      WHEN advisories.cvss_score IS NULL AND $2::numeric IS NOT NULL
        THEN $4::text ELSE advisories.cvss_version END,
    cwe_ids = CASE
      WHEN (advisories.cwe_ids IS NULL OR cardinality(advisories.cwe_ids) = 0)
           AND $5::text[] IS NOT NULL
        THEN $5::text[] ELSE advisories.cwe_ids END,
    vulnerability_category = CASE
      WHEN (advisories.cwe_ids IS NULL OR cardinality(advisories.cwe_ids) = 0)
           AND $5::text[] IS NOT NULL
        THEN $6::text ELSE advisories.vulnerability_category END,
    updated_at = now()
  WHERE advisories.cve_id = $1::text
    AND ( (advisories.cvss_score IS NULL AND $2::numeric IS NOT NULL)
       OR ((advisories.cwe_ids IS NULL OR cardinality(advisories.cwe_ids) = 0)
           AND $5::text[] IS NOT NULL) )
  RETURNING advisories.cve_id`;

/**
 * Applies one record's enrichment. Returns what actually changed.
 *
 * `vulnerability_category` moves WITH cwe_ids and only with it: a row holding
 * `cwe_ids = ['CWE-193']` beside `vulnerability_category = 'Other'` would contradict itself,
 * since 'Other' is categorizeCwes()'s honest "no confident bucket" answer for an EMPTY list.
 * Recomputing it is required for the pair to stay consistent, not an extra liberty.
 */
async function enrichAdvisory(pool, candidate, cvss, cweIds) {
  const category = cweIds && cweIds.length > 0 ? categorizeCwes(cweIds) : null;
  const result = await pool.query(ENRICH_SQL, [
    candidate.cve_id,
    cvss && typeof cvss.score === 'number' ? cvss.score : null,
    cvss ? cvss.vector : null,
    cvss ? cvss.version : null,
    cweIds && cweIds.length > 0 ? cweIds : null,
    category,
  ]);
  const changed = result.rowCount > 0;
  return {
    changed,
    // Derived from the gap flags SELECTed with the candidate rather than from RETURNING,
    // because RETURNING shows the POST-update row and cannot say which half of it moved.
    filledCvss: changed && candidate.needs_cvss && !!(cvss && typeof cvss.score === 'number'),
    filledCwe: changed && candidate.needs_cwe && !!(cweIds && cweIds.length > 0),
  };
}

/**
 * Enrich existing advisories from CVE.org. NEVER inserts.
 *
 * @param {import('pg').Pool} pool
 * @param {object} [options] in-process overrides — deliberately NOT env vars. Every value
 *   here is a politeness/safety bound rather than a deployment tuning knob (same reasoning
 *   as lib/engines/configRetention.js's MIN_KEEP_* floors), and this feed introduces no new
 *   `.env.local` entries.
 * @returns {Promise<{inserted:number, updated:number, skipped:number, examined:number,
 *                    summary:object, errors:Array<{cve_id:string|null,message:string}>}>}
 *   `inserted` is ALWAYS 0 — structurally, there is no INSERT in this file. It is returned
 *   so the shape matches every other feed's and lib/feeds/index.js's existing wrapper can
 *   log it unchanged.
 *
 * ⛔ NOTE FOR THE WRAPPER IN lib/feeds/index.js: `errors` contains REAL errors only. The
 * run's informational counters are in `summary`, NOT in `errors`, because
 * `status = result.errors.length > 0 ? 'partial' : 'success'` there would otherwise paint
 * every healthy run 'partial'. runNvdSync() already handles exactly this by deciding status
 * from the real errors and only THEN appending its informational entry to the logged jsonb —
 * do the same with `summary`.
 */
async function fetchAndEnrichFromCveOrg(pool, options) {
  const opts = options || {};
  const requestDelayMs = opts.requestDelayMs != null ? opts.requestDelayMs : REQUEST_DELAY_MS;
  const unreachableStreak = Math.max(1, opts.unreachableStreak || UNREACHABLE_STREAK);

  const errors = [];
  const summary = {
    examined: 0,
    filled_cvss: 0,
    filled_cwe: 0,
    no_data_at_cveorg: 0,
    rejected: [],
    disputed: [],
    not_found: [],
    skipped_non_cve_id: 0,
    // Report-only, never candidates — see SUSPICIOUS_ZERO_SCORES_SQL.
    suspicious_zero_scores: [],
    tiers: { recent: 0, backfill: 0 },
    backfill_bucket: null,
    backfill_buckets: opts.buckets || BACKFILL_BUCKETS,
    unreachable: false,
  };

  let candidates;
  try {
    const buckets = opts.buckets || BACKFILL_BUCKETS;
    const bucket = opts.bucket != null ? opts.bucket : currentBackfillBucket(Date.now(), buckets);
    summary.backfill_bucket = bucket;
    candidates = await selectCandidates(pool, { ...opts, buckets, bucket });
  } catch (err) {
    errors.push({ cve_id: null, message: `candidate selection failed: ${err.message}` });
    return { inserted: 0, updated: 0, skipped: 0, examined: 0, summary, errors };
  }

  // Reported, not silently dropped — "we never asked about these" is a fact the operator
  // needs in order to read `updated: 0` correctly.
  try {
    const nonCve = await pool.query(COUNT_NON_CVE_GAPS_SQL, [CVE_ID_SQL_PATTERN]);
    summary.skipped_non_cve_id = (nonCve.rows[0] && nonCve.rows[0].n) || 0;
  } catch (err) {
    errors.push({ cve_id: null, message: `non-CVE-id gap count failed: ${err.message}` });
  }

  try {
    const zeros = await pool.query(SUSPICIOUS_ZERO_SCORES_SQL);
    summary.suspicious_zero_scores = zeros.rows.map((r) => r.cve_id);
  } catch (err) {
    errors.push({ cve_id: null, message: `suspicious-zero scan failed: ${err.message}` });
  }

  let updated = 0;
  let skipped = 0;
  let consecutiveNetworkFailures = 0;

  for (const candidate of candidates) {
    // Defence in depth: the SQL pattern already excludes these, so reaching here means the
    // two definitions drifted. Never send a known-bad id at the network.
    if (!isCveShapedId(candidate.cve_id)) {
      skipped += 1;
      continue;
    }

    if (summary.examined > 0 && requestDelayMs > 0) await sleep(requestDelayMs);
    summary.examined += 1;
    summary.tiers[candidate.tier] += 1;

    let rec;
    try {
      rec = await fetchCveRecord(candidate.cve_id);
      consecutiveNetworkFailures = 0; // any HTTP answer proves the host is up
    } catch (err) {
      if (err.status === 404) {
        // The CVE Program does not have this id. Not an error in the "something broke"
        // sense, and emphatically not a reason to change the stored row.
        consecutiveNetworkFailures = 0;
        summary.not_found.push(candidate.cve_id);
        skipped += 1;
        continue;
      }
      if (err.status != null || err.cveorgJsonParseError) {
        consecutiveNetworkFailures = 0;
        errors.push({ cve_id: candidate.cve_id, message: err.message });
        skipped += 1;
        continue;
      }
      // Network-level: no response at all.
      consecutiveNetworkFailures += 1;
      errors.push({ cve_id: candidate.cve_id, message: err.message });
      skipped += 1;
      if (isNetworkLevelFailure(err) && consecutiveNetworkFailures >= unreachableStreak) {
        summary.unreachable = true;
        errors.push({
          cve_id: null,
          message:
            `[CVE.org unreachable] ${consecutiveNetworkFailures} consecutive network-level failures ` +
            '(no HTTP response at all) — abandoning the rest of this run rather than spending ' +
            `${FETCH_TIMEOUT_MS}ms per remaining candidate. Re-probed from scratch on the next run; ` +
            'nothing about this is persisted.',
        });
        break;
      }
      continue;
    }

    const state = recordState(rec);
    if (state && state !== 'PUBLISHED') {
      // See recordState()'s header: skip, touch nothing, report by id.
      summary.rejected.push(`${candidate.cve_id} (${state})`);
      skipped += 1;
      continue;
    }
    if (isDisputed(rec)) summary.disputed.push(candidate.cve_id);

    const cvss = pickCvssFromCveRecord(rec);
    const cweIds = extractCweIdsFromCveRecord(rec);
    const haveCvss = typeof cvss.score === 'number';

    // ⛔ Nothing to give is NOT a failure and NOT a zero. The record simply carries no CVSS
    // and no CWE — the overwhelmingly common outcome on this corpus (255 of 255 gap rows).
    // The stored NULL stays NULL, which is the honest value.
    if ((!haveCvss || !candidate.needs_cvss) && (cweIds.length === 0 || !candidate.needs_cwe)) {
      summary.no_data_at_cveorg += 1;
      skipped += 1;
      continue;
    }

    try {
      const res = await enrichAdvisory(
        pool,
        candidate,
        haveCvss ? cvss : null,
        cweIds.length > 0 ? cweIds : null
      );
      if (res.changed) {
        updated += 1;
        if (res.filledCvss) summary.filled_cvss += 1;
        if (res.filledCwe) summary.filled_cwe += 1;
      } else {
        // Another writer filled the gap between the SELECT and this UPDATE. The guard did
        // its job; nothing was clobbered.
        skipped += 1;
      }
    } catch (err) {
      errors.push({ cve_id: candidate.cve_id, message: `enrich failed: ${err.message}` });
      skipped += 1;
    }
  }

  return { inserted: 0, updated, skipped, examined: summary.examined, summary, errors };
}

module.exports = {
  fetchAndEnrichFromCveOrg,
  // Exported for tests and for anyone auditing the rules above.
  pickCvssFromCveRecord,
  extractCweIdsFromCveRecord,
  isCveShapedId,
  recordState,
  isDisputed,
  currentBackfillBucket,
  selectCandidates,
  enrichAdvisory,
  ENRICH_SQL,
  SELECT_CANDIDATES_SQL,
  COUNT_NON_CVE_GAPS_SQL,
  SUSPICIOUS_ZERO_SCORES_SQL,
  CVEORG_BASE_URL,
  FETCH_TIMEOUT_MS,
  RECENT_WINDOW_DAYS,
  BACKFILL_BUCKETS,
  MAX_RECORDS_PER_RUN,
};
