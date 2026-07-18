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
const { parseVersion, compareVersions } = require('../engines/versionComparator');
const { categorizeCwes } = require('../engines/vulnerabilityCategory');

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

// Strips a trailing wildcard segment PAN-OS/CVE-Record version strings can
// carry (e.g. "8.0.*", or a bare "*" for "any version") — parseVersion()
// (lib/engines/versionComparator.js) expects a plain dotted numeric string;
// feeding it a literal "*" or "8.0.*" produces an unpredictable tuple rather
// than a clean [8,0,...]. Returns null (no bound) when nothing usable remains.
function cleanVersionString(v) {
  if (typeof v !== 'string') return null;
  const cleaned = v.replace(/(\.\*)+$/, '').trim();
  return cleaned === '' || cleaned === '*' ? null : cleaned;
}

// ⛔ Bug fixed 2026-07-17 (third pass), confirmed live: PAN-SA-2023-0004 (an
// informational bulletin, not a numbered CVE) uses versions[] to describe
// CONFIGURATION SCENARIOS, not firmware version ranges — its entries'
// `version` field literally reads e.g. "with GlobalProtect app on Windows,
// macOS, and Linux LocalNet: Configurations allowing local network access,
// ServerIP: Gateways with address set as an FQDN" (confirmed via the live
// beta API). Other advisories carry a bare "All" or "" in the same field.
// None of these are version numbers, but cleanVersionString/boundBranchEnd
// happily "cleaned" and bounded them anyway — every real device tuple then
// compares unequal to the resulting [0,0,0,0]-parsing garbage range, so this
// never falsely flagged a device (confirmed: the range self-cancels), but it
// silently stored a meaningless affected_version_ranges entry and spammed
// engine.log with "[versionComparator] Unparseable version segment" warnings
// on every sync. A real version string in this domain is always short and
// starts with a digit (optionally a leading v/V, e.g. "8.0.*", "11.1.13-h5",
// "v9.1.3"); a scenario description is long prose starting with a lowercase
// word. Reject anything that doesn't look like a real version BEFORE it
// reaches range/fixed-version extraction, rather than let it silently
// degrade into an inert-but-meaningless entry.
function looksLikeVersion(cleaned) {
  if (!cleaned) return false;
  if (cleaned.length > 20) return false;
  return /^v?\d/i.test(cleaned);
}

// Last-resort bound for a versions[] entry with NEITHER lessThan/
// lessThanOrEqual NOR any usable changes[] data (see extractAffectedRanges
// below — this is only reached when there is truly no fix information at
// all, e.g. CVE-2020-2021's PAN-OS 8.0 branch: {"version":"8.0.*",
// "status":"affected"}, no upper-bound field, no changes array, EOL). Bounds
// to the end of the STATED branch (major[.minor].999), mirroring this app's
// existing "X.Y all versions" -> {min:"X.Y.0", max:"X.Y.999"} convention
// (lib/feeds/fortinet.js) — conservative/wide within the branch actually
// named, never unbounded (the original bug this replaced: max:null, matching
// every future version forever). A fully-specified release with no other
// info (3+ real segments) bounds to itself, the least-presumptuous read of a
// single named version in complete isolation.
function boundBranchEnd(versionStr) {
  const cleaned = cleanVersionString(versionStr);
  if (!cleaned) return null;
  const segments = cleaned.split('.').filter(Boolean);
  if (segments.length === 0) return null;
  if (segments.length >= 3) return cleaned;
  return `${segments.join('.')}.999`;
}

// ⛔ Bug fixed 2026-07-17 (second pass — the first pass's boundBranchEnd
// fallback above, live-verified correct for CVE-2020-2021's "no info at all"
// shape, turned out to be a REGRESSION for a different, equally real shape:
// CVE-2026-0257's PAN-OS 11.1 branch is {"version":"11.1.0","status":
// "affected", "changes":[{"at":"11.1.15","status":"unaffected"},
// {"at":"11.1.13-h5","status":"unaffected"}, ...]} — no top-level lessThan,
// but the ACTUAL fix boundary is very much known, just encoded per-hotfix-
// train inside `changes[]` instead. boundBranchEnd's "3+ segments = bound to
// self" rule turned "11.1.0" into the single point {min:"11.1.0",
// max:"11.1.0"} — which would have made PAN-OS 11.1.13-h5 (a REAL,
// currently-unpatched version for a REAL currently-active CVE) silently stop
// matching on the next re-sync. Confirmed live before shipping: this would
// have been a false-negative regression, not just a missing Fixed-In field.
//
// Fixed: when lessThan/lessThanOrEqual are both absent, check `changes[]`
// for 'unaffected' entries FIRST — the range's max becomes the HIGHEST such
// version (conservative/wide: this can include some intermediate hotfix
// points that were independently already patched as "still affected", same
// documented direction as ignoring the fine-grained per-train timeline
// entirely — see the KNOWN SIMPLIFICATION note on extractFixedVersions
// below). boundBranchEnd is now reached only when there is truly nothing —
// no lessThan, no lessThanOrEqual, no changes[] — left at all.
function highestVersionFromChanges(changes) {
  let highest = null;
  let highestTuple = null;
  for (const c of changes || []) {
    if (!c || c.status !== 'unaffected') continue;
    const cleaned = cleanVersionString(c.at);
    if (!cleaned || !looksLikeVersion(cleaned)) continue;
    const tuple = parseVersion('paloalto', cleaned);
    if (!highestTuple || compareVersions(tuple, highestTuple) > 0) {
      highest = cleaned;
      highestTuple = tuple;
    }
  }
  return highest;
}

// ⛔ Bug fixed 2026-07-17 (fourth pass), confirmed live: CVE-2026-0257's
// 11.1 branch changes[] names SIX independent per-hotfix-train fix points
// (11.1.15, 11.1.13-h5, 11.1.10-h25, 11.1.7-h6, 11.1.6-h32, 11.1.4-h33), but
// highestVersionFromChanges above only ever kept the single highest
// (11.1.15) as the range's overall `max`. A device sitting exactly on its
// OWN train's named fix point (e.g. 11.1.13-h5) is numerically below that
// overall max, so it still read as "in range" and was flagged Patch Now —
// even though Palo Alto's own advisory says that exact version is NOT
// impacted. A single {min,max} range cannot represent "vulnerable UNLESS
// you're on train X at hotfix>=Y, OR train A at hotfix>=B, OR ...", so every
// named checkpoint is now collected here (not just the highest) and carried
// on the range as `safe_exact_versions`, for
// lib/engines/versionComparator.js's isInRange() to check explicitly via its
// new `safeCheckpoints` param — see that function's JSDoc for the matching
// semantics ("same major.minor.patch train, hotfix at or above the
// checkpoint's"). Reuses the exact same per-entry validation
// highestVersionFromChanges already applies (status === 'unaffected',
// cleanVersionString, looksLikeVersion).
function allCheckpointsFromChanges(changes) {
  const checkpoints = [];
  for (const c of changes || []) {
    if (!c || c.status !== 'unaffected') continue;
    const cleaned = cleanVersionString(c.at);
    if (cleaned && looksLikeVersion(cleaned)) checkpoints.push(cleaned);
  }
  return checkpoints;
}

function extractAffectedRanges(matchingEntries) {
  const ranges = [];
  for (const entry of matchingEntries) {
    for (const v of entry.versions || []) {
      if (!v || v.status !== 'affected') continue;
      const min = cleanVersionString(v.version);
      // A non-version-shaped `version` field (a config-scenario description,
      // "All", or "") means this entry doesn't describe a firmware version
      // range at all — skip it entirely rather than emit a meaningless
      // {min: <garbage>, max: <garbage>.999} range that would only ever
      // match a device also parsing to [0,0,0,0].
      if (!min || !looksLikeVersion(min)) continue;
      let max;
      let excludeFixed;
      // ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep: this used to
      // only call allCheckpointsFromChanges() inside the changesMax branch
      // below, i.e. only when NEITHER lessThan NOR lessThanOrEqual was
      // present. A real CVE Record Format entry can legitimately have a
      // top-level lessThan/lessThanOrEqual bound AND a changes[] timeline of
      // per-train fix points at the same time (the top-level bound covering
      // the "main" branch, changes[] naming earlier fix points on other
      // hotfix trains) — in that shape every checkpoint was silently
      // dropped, so isSafeOnMatchingTrain in versionComparator.js had
      // nothing to check a device's own train against even though the
      // source data had it. Now collected unconditionally whenever
      // changes[] is present, independent of which branch below determines
      // max/excludeFixed. Identical fix applied to lib/feeds/nvd.js's
      // extractAffectedRangesFromCveRecord — see that function's comment.
      const safeExactVersions = allCheckpointsFromChanges(v.changes);
      if (v.lessThan != null) {
        max = v.lessThan;
        excludeFixed = true;
      } else if (v.lessThanOrEqual != null) {
        max = v.lessThanOrEqual;
        excludeFixed = false;
      } else {
        const changesMax = highestVersionFromChanges(v.changes);
        if (changesMax) {
          max = changesMax;
          excludeFixed = true; // an 'unaffected' change point is itself the first-fixed version
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

// KNOWN SIMPLIFICATION (unchanged from before, now also applies to the
// changes[]-derived candidates below): a versions[] entry's `changes[]`
// timeline can encode finer-grained per-hotfix-train affected/unaffected
// toggles than a flat {min,max} range can represent (e.g. patched at an
// intermediate point, a DIFFERENT train patched at a different point). This
// can only make a range WIDER than the true affected set, never narrower —
// same conservative direction as the "unknown treated as applicable"
// tri-state rule in CLAUDE.md.
//
// ⛔ Bug fixed 2026-07-17: previously only checked v.status === 'unaffected'
// at the TOP level of a versions[] entry — but CVE-2026-0257's shape (see
// above) has NO top-level 'unaffected' entries at all; every real fix point
// lives inside `changes[]`. That's why "Fixed In" showed "—" for this CVE
// even though the advisory clearly names several fixed releases. Now also
// collects every 'unaffected' change point from every entry's `changes[]` —
// versionMatcher.js's existing "nearest fix strictly above the device's
// current version" logic already handles a flat pool of candidates spanning
// multiple branches correctly (same as it always has for top-level
// 'unaffected' entries from other CVEs), so no changes needed there.
function extractFixedVersions(matchingEntries) {
  const versions = new Set();
  for (const entry of matchingEntries) {
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

// Same CVE Record Format 5.x weakness field as lib/feeds/nvd.js's
// extractCweIdsFromCveRecord() — independent copy, this codebase's
// established "duplicate small per-feed logic, don't share a module across
// feeds/*.js" convention (see the sibling upsertAdvisory comment below for
// why the same choice was made there).
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

function normalizePaloAltoRecord(rec, matchingEntries) {
  const cveId = rec && rec.cveMetadata && rec.cveMetadata.cveId;
  if (!cveId) throw new Error('Palo Alto PSIRT record missing cveMetadata.cveId');
  const cna = rec.containers && rec.containers.cna;
  const { score, vector } = pickCvssFromPanOsRecord(rec);
  const title = (cna && cna.title) || `${VENDOR_LABEL} — ${cveId}`;
  const advisoryUrl =
    (cna && Array.isArray(cna.references) && cna.references[0] && cna.references[0].url) ||
    `https://security.paloaltonetworks.com/${cveId}`;
  const cweIds = extractCweIdsFromCveRecord(rec);
  return {
    cve_id: cveId,
    vendor: 'paloalto',
    title,
    description: pickDescription(cna && cna.descriptions),
    cvss_score: score,
    cvss_vector: vector,
    // ⛔ Bug fixed 2026-07-17, confirmed live against CVE-2026-0300:
    // cveMetadata.datePublished is NOT reliably present on this endpoint —
    // that record's cveMetadata only has {cveId, assignerOrgId, serial,
    // state}, no date field at all — while containers.cna.datePublic is
    // present and correct on the same record. Fall back to it.
    published_at: (rec.cveMetadata && rec.cveMetadata.datePublished) || (cna && cna.datePublic) || null,
    affected_version_ranges: extractAffectedRanges(matchingEntries),
    fixed_in_versions: extractFixedVersions(matchingEntries),
    advisory_url: advisoryUrl,
    raw_data: rec,
    cwe_ids: cweIds,
    vulnerability_category: categorizeCwes(cweIds),
  };
}

// Upsert one advisory. Copied almost verbatim from lib/feeds/nvd.js's
// upsertAdvisory — same ON CONFLICT (cve_id) DO UPDATE shape, same
// "never let a different vendor's upsert steal an existing row, or clobber
// vendor-owned fields" guard. Vendor here is always the literal string
// 'paloalto'. Never touches kev_listed/kev_date — those belong to kev.js.
//
// ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep (identical bug and
// fix as lib/feeds/nvd.js's upsertAdvisory): description/cvss_score/
// cvss_vector/published_at/advisory_url/raw_data used to be unconditionally
// overwritten with EXCLUDED.* regardless of which vendor's sync was running,
// while title/affected_version_ranges/fixed_in_versions were already
// correctly guarded. A genuine cross-vendor cve_id collision (a
// shared-library CVE affecting two vendors' products, or a different feed
// source's own scenario-specific take on the "same" CVE) could silently
// overwrite the OWNING vendor's CVSS score and description with this feed's
// unrelated data while leaving that row's title/ranges untouched — a
// corrupted hybrid record with mismatched severity and version data. Every
// column is now guarded the same way, matching this codebase's own "when in
// doubt, be conservative" philosophy elsewhere.
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
