// lib/feeds/paloalto.js
// Palo Alto Networks PSIRT client — pulls PAN-OS advisories from the beta
// bulk-advisories endpoint. CommonJS ONLY — this file is `require()`d by
// services/engine-worker.js (plain node) and may also be bundled into a
// Next.js API route, so it follows the exact same conventions as lib/feeds/nvd.js.

// Same node-fetch@2 ESM/CJS require-quirk workaround as nvd.js — Next.js's
// webpack bundler can resolve node-fetch's "module" (ESM) field even for this
// plain require() when this file runs inside an API route's bundle, which
// yields the ESM namespace object instead of the callable function. See
// lib/feeds/nvd.js's identical comment for the confirmed failure mode.
const fetchModule = require('node-fetch');
const fetch = fetchModule.default || fetchModule;

// ────────────────────────────────────────────────────────────────────────
// ENDPOINT — live-verified 2026-07-16/17 via curl per CLAUDE.md's "verify
// against live responses, never assume" rule. Do NOT switch to `/json` or
// `/json?product=PAN-OS` or `/json/{id}` — see the task notes this file was
// built from for the full comparison. Summary of why this one endpoint is
// the sole source:
//   - `/json?product=PAN-OS` -> HTTP 200 but only 25 items (recent bulletins
//     only, not the full history), fragile parallel-array version ranges,
//     no clean CVSS vector (missing Scope component). NOT used.
//   - `/api/v1/products/PAN-OS/advisories` -> HTTP 200, ~4.3MB, 346
//     advisories in ONE call, `{success: true, data: [...]}` where every
//     entry is a full CVE Record Format 5.x object (`dataType:
//     "CVE_RECORD"`, `cveMetadata: {cveId, state}`,
//     `containers.cna: {title, descriptions, affected[], metrics[],
//     references[]}`) — the SAME shape lib/feeds/nvd.js's CIRCL fallback
//     already parses (pickCvssFromCveRecord /
//     matchingAffectedEntriesFromCveRecord /
//     extractAffectedRangesFromCveRecord / extractFixedVersionsFromCveRecord).
//     This file mirrors that logic rather than inventing new logic.
//   - `cveMetadata.cveId` is usually `CVE-YYYY-NNNNN` but 59/346 live entries
//     were `PAN-SA-YYYY-NNNN` (informational bulletins, no CVE assigned) —
//     stored as-is in the `cve_id` column, which is just a unique text key
//     elsewhere in this app, not format-validated.
//   - `containers.cna.affected[]` entries carry a `product` field (e.g.
//     "PAN-OS", "Cloud NGFW", "Prisma Access") — filtered to
//     `product === 'PAN-OS'` (exact, case-sensitive, confirmed live) instead
//     of nvd.js's CPE-prefix matching, since this endpoint is already
//     PAN-OS-scoped but individual CVEs can still list sibling products that
//     must be excluded.
//   - Every filtered affected entry's `versions[]` has
//     `{status: 'affected'|'unaffected', version, lessThan, versionType,
//     changes?}` — confirmed live that 0/346 entries have zero usable PAN-OS
//     versions data.
//   - `containers.cna.metrics[]` mixes `cvssV4_0`, `cvssV3_1`, `cvssV3_0`
//     across different advisories (Palo Alto has been migrating to CVSS
//     v4.0). Multiple metrics entries can exist for the SAME CVE representing
//     different deployment "scenarios" (confirmed live on CVE-2026-0279, 3
//     scenarios, all v4.0) — the FIRST entry matching the version preference
//     cascade wins, never the highest baseScore (a scenario-specific
//     narrative isn't the general-case recommendation). This endpoint has no
//     `adp[]` array (confirmed live) — only `cna.metrics`.
//   - `containers.cna.references[0].url` is a clean advisory URL
//     (`https://security.paloaltonetworks.com/CVE-XXXX-XXXXX`) — used
//     directly, never constructed from the CVE id alone (falls back to a
//     constructed URL only if references[] is somehow empty).
//   - `containers.cna.title` is a real vendor-authored title — used directly.
//   - No pagination (`{success, data}` only, confirmed) — the complete PAN-OS
//     advisory history in one call.
// ────────────────────────────────────────────────────────────────────────
const PALOALTO_ADVISORIES_URL = 'https://security.paloaltonetworks.com/api/v1/products/PAN-OS/advisories';
const VENDOR_LABEL = 'Palo Alto Networks';

// Same socket-inactivity timeout as nvd.js (see CLAUDE.md "NVD Fallback —
// CIRCL Vulnerability-Lookup" for why this exists at all: node-fetch@2 has no
// default timeout, so a silently-dropped connection hangs indefinitely
// instead of failing). Applied here even though this is a single bulk call,
// not N per-advisory requests, per CLAUDE.md's blanket timeout rule.
const FETCH_TIMEOUT_MS = 20000;

function pickDescription(descriptions) {
  if (!Array.isArray(descriptions) || descriptions.length === 0) return null;
  const en = descriptions.find((d) => d && d.lang === 'en');
  return (en || descriptions[0]).value || null;
}

// Scans containers.cna.metrics ONLY (this endpoint has no adp[] array,
// confirmed live — unlike nvd.js's CIRCL records, which scan both cna and
// adp). Preference cascade extended with cvssV4_0 ahead of V3.1/V3.0 since
// Palo Alto's live data mixes all three across different advisories.
function pickCvssFromPanOsRecord(rec) {
  const cna = rec && rec.containers && rec.containers.cna;
  const metricSets = cna && Array.isArray(cna.metrics) ? cna.metrics : [];
  for (const key of ['cvssV4_0', 'cvssV3_1', 'cvssV3_0']) {
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

// Only affected[] entries whose `product` is exactly 'PAN-OS' are used — a
// single CVE Record here can list sibling products (Cloud NGFW, Prisma
// Access) that must never contribute PAN-OS version-range data. Same
// cross-product guard purpose as nvd.js's matchingAffectedEntriesFromCveRecord,
// just keyed on `product` instead of a CPE-prefix match (this endpoint is
// already PAN-OS-scoped at the top level, but not per-affected-entry).
function matchingPanOsAffectedEntries(rec) {
  const cna = rec && rec.containers && rec.containers.cna;
  const affected = cna && Array.isArray(cna.affected) ? cna.affected : [];
  return affected.filter((entry) => entry && entry.product === 'PAN-OS');
}

// Same {min, max, exclude_fixed, vulnerable} shape and the same KNOWN
// SIMPLIFICATION as nvd.js's extractAffectedRangesFromCveRecord: a
// versions[] entry's `changes[]` timeline (mid-range affected/unaffected
// toggles) is deliberately ignored — versionMatcher.js's range model has no
// representation for it, and ignoring it can only make a range WIDER than
// the true affected set, never narrower (same conservative direction as the
// "unknown treated as applicable" tri-state rule in CLAUDE.md).
function extractAffectedRanges(matchingEntries) {
  const ranges = [];
  for (const entry of matchingEntries) {
    for (const v of entry.versions || []) {
      if (!v || v.status !== 'affected') continue;
      const max = v.lessThan != null ? v.lessThan : v.lessThanOrEqual != null ? v.lessThanOrEqual : null;
      ranges.push({
        min: v.version != null && v.version !== '*' ? v.version : null,
        max,
        exclude_fixed: v.lessThan != null,
        vulnerable: true,
      });
    }
  }
  return ranges;
}

function extractFixedVersions(matchingEntries) {
  const versions = new Set();
  for (const entry of matchingEntries) {
    for (const v of entry.versions || []) {
      if (v && v.status === 'unaffected' && v.version) versions.add(v.version);
    }
  }
  return Array.from(versions);
}

function normalizePaloAltoRecord(rec, matchingEntries) {
  const cveId = rec && rec.cveMetadata && rec.cveMetadata.cveId;
  if (!cveId) throw new Error('Palo Alto PSIRT record missing cveMetadata.cveId');
  const cna = rec.containers && rec.containers.cna;
  const { score, vector } = pickCvssFromPanOsRecord(rec);
  const title = (cna && cna.title) || `${VENDOR_LABEL} — ${cveId}`;
  const advisoryUrl =
    (cna && Array.isArray(cna.references) && cna.references[0] && cna.references[0].url) ||
    `https://security.paloaltonetworks.com/${cveId}`;
  return {
    cve_id: cveId,
    vendor: 'paloalto',
    title,
    description: pickDescription(cna && cna.descriptions),
    cvss_score: score,
    cvss_vector: vector,
    published_at: (rec.cveMetadata && rec.cveMetadata.datePublished) || null,
    affected_version_ranges: extractAffectedRanges(matchingEntries),
    fixed_in_versions: extractFixedVersions(matchingEntries),
    advisory_url: advisoryUrl,
    raw_data: rec,
  };
}

// Upsert one advisory. Copied almost verbatim from lib/feeds/nvd.js's
// upsertAdvisory — same ON CONFLICT (cve_id) DO UPDATE shape, same
// "never let a different vendor's upsert steal an existing row, or clobber
// vendor-owned fields" guard (vendor / title / affected_version_ranges /
// fixed_in_versions only overwritten when the upserting vendor already owns
// the row). Vendor here is always the literal string 'paloalto'. Never
// touches kev_listed/kev_date — those belong to kev.js.
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

async function fetchPaloAltoAdvisories() {
  const res = await fetch(PALOALTO_ADVISORIES_URL, { timeout: FETCH_TIMEOUT_MS });
  if (!res.ok) {
    const err = new Error(`Palo Alto PSIRT request failed: HTTP ${res.status} for ${PALOALTO_ADVISORIES_URL}`);
    err.status = res.status;
    throw err;
  }
  try {
    return await res.json();
  } catch (parseErr) {
    throw new Error(
      `Palo Alto PSIRT response body could not be parsed as JSON for ${PALOALTO_ADVISORIES_URL}: ${parseErr.message}`
    );
  }
}

/**
 * Fetch all PAN-OS advisories from the Palo Alto PSIRT beta bulk-advisories
 * endpoint and upsert them into the `advisories` table. A reachability/shape
 * failure (non-2xx, malformed JSON, missing success:true / data[]) THROWS —
 * that is a genuine sync failure, not "zero advisories". One bad entry inside
 * an otherwise-good response never aborts the run; it is caught, recorded in
 * `errors`, and the loop continues.
 * @param {import('pg').Pool} pool
 * @returns {Promise<{inserted: number, updated: number, skipped: number,
 *   errors: Array<{cve_id: string|null, message: string}>}>}
 */
async function fetchAndUpsertPaloAltoAdvisories(pool) {
  const body = await fetchPaloAltoAdvisories();
  if (!body || body.success !== true || !Array.isArray(body.data)) {
    throw new Error(
      `Palo Alto PSIRT response missing success:true / data[] — unexpected shape for ${PALOALTO_ADVISORIES_URL}`
    );
  }

  if (body.data.length > 0) {
    // Per CLAUDE.md's "log raw response on first connect" rule — logged on
    // every call (not just a one-time first-ever-call check), same convention
    // as nvd.js's [SMC Debug]-style prefixes, so a future person can
    // re-verify the live shape against production reality at any time.
    console.log('[PaloAlto PSIRT Debug] first advisory entry:', JSON.stringify(body.data[0], null, 2));
  }

  let inserted = 0;
  let updated = 0;
  let skipped = 0;
  const errors = [];

  for (const rec of body.data) {
    const cveId = (rec && rec.cveMetadata && rec.cveMetadata.cveId) || null;
    try {
      const matchingEntries = matchingPanOsAffectedEntries(rec);
      if (matchingEntries.length === 0) {
        // Advisory affects only sibling products (Cloud NGFW, Prisma Access,
        // etc.), never PAN-OS itself — must not become a PAN-OS advisory row.
        skipped++;
        continue;
      }
      const normalized = normalizePaloAltoRecord(rec, matchingEntries);
      const wasInserted = await upsertAdvisory(pool, normalized);
      if (wasInserted) inserted++;
      else updated++;
    } catch (e) {
      errors.push({ cve_id: cveId, message: e.message });
    }
  }

  return { inserted, updated, skipped, errors };
}

module.exports = { fetchAndUpsertPaloAltoAdvisories };
