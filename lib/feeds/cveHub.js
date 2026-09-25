// lib/feeds/cveHub.js
// Central CVE feed consumer — pulls the signed advisory corpus from nocvault-eol.
// CommonJS ONLY — required by services/engine-worker.js under plain node.
//
// ⛔ WHY THIS EXISTS, AND WHY IT IS NOT A CONVENIENCE. Measured 2026-09-18 on the
// reference deployment: this server CANNOT REACH NVD AT ALL. The sites use
// internal public IP ranges that OVERLAP NVD's own address space, so traffic to
// services.nvd.nist.gov routes to an internal host. No firewall rule fixes that —
// you cannot permit egress to a range your own network claims. Every NVD call
// fails, every string falls through to the CIRCL fallback, and CIRCL's records
// carry no parseable version bounds:
//
//   vendor      usable ranges via CIRCL     usable from NVD
//   cisco_asa   70 / 353  (20%)             332 / 369  (90%)
//   checkpoint   0 /   7  ( 0%)              68 /  80  (85%)
//
// Fleet-wide, 439 of 1,006 advisories here can never match a device. Both columns
// were scored with THIS repo's own extractor, so the difference is the data
// source and nothing else. The hub can reach NVD; this server can reach the hub
// (eol_catalogue pulled 2,770 rows on schedule while every NVD call failed).

const crypto = require('crypto');

const DEFAULT_HUB_URL = 'https://nocvault-eol.netlify.app';
const FETCH_TIMEOUT_MS = 60000;

// ⛔ THE HUB PUBLISHES EVERY 6 HOURS, SO A DAY OF SILENCE IS FOUR MISSED RUNS.
// This is a reporting threshold, not a safety floor, and it is deliberately
// generous: a stale feed is still VALID data (the advisories did not become
// wrong), so crossing it reports, never refuses.
const STALE_AFTER_MS = 24 * 60 * 60 * 1000;

// ⛔ PINNED IN SOURCE, NEVER FETCHED AT VERIFICATION TIME. The hub also serves
// this key at /api/v1/cve-feed/pubkey, and reading it from there at runtime
// would verify NOTHING — whoever could swap the feed could swap the key with it.
// The repository is the trusted channel; this constant is the trust anchor.
// CVE_HUB_PUBLIC_KEY overrides it only for a customer running their own hub.
const FEED_PUBLIC_KEY_SPKI_B64 =
  'MCowBQYDK2VwAyEAI+nk9JoWunzPTASALa5PLWwcLe9NNWRrZ72tMY8ZU2k=';

function hubUrl() {
  return (process.env.CVE_HUB_URL || DEFAULT_HUB_URL).replace(/\/+$/, '');
}

function publicKey() {
  const b64 = (process.env.CVE_HUB_PUBLIC_KEY || FEED_PUBLIC_KEY_SPKI_B64).trim();
  return crypto.createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });
}

/**
 * How old is the hub's last SUCCESSFUL INGEST?
 *
 * ⛔ THIS IS THE WHOLE POINT OF THE CONSUMER HAVING A HEALTH OPINION AT ALL.
 * Without it, a hub that stopped publishing is invisible here: this feed would
 * fetch the same feed_version every six hours, verify its signature perfectly,
 * apply nothing, and log `success` for ever — a green signal over a corpus that
 * stopped moving. That is this codebase's most-repeated bug, introduced by the
 * very feed added to fix it.
 *
 * ⛔ IT READS checked_at, NOT generated_at. The hub's publish is idempotent, so
 * generated_at only advances when the CORPUS CHANGES — on a quiet week a dead
 * hub and a healthy one are indistinguishable by that field. checked_at is when
 * the hub last completed an ingest target, so it advances on every healthy run
 * and stops when the hub does.
 *
 * ⛔ A MISSING OR UNPARSEABLE VALUE IS `unknown`, NEVER `fresh`. An absent
 * header is exactly what an old hub build serves, and reading that as healthy
 * would be a failed read recorded as an affirmative value.
 *
 * @returns {{state:'fresh'|'stale'|'unknown', ageMs:number|null, checkedAt:string|null, reason:string}}
 */
function feedFreshness(checkedAtRaw, nowMs) {
  if (!checkedAtRaw || typeof checkedAtRaw !== 'string' || !checkedAtRaw.trim()) {
    return {
      state: 'unknown', ageMs: null, checkedAt: null,
      reason: 'the hub did not report when it last ingested (no checked_at), '
        + 'so the age of this corpus cannot be established',
    };
  }
  const t = Date.parse(checkedAtRaw);
  if (!Number.isFinite(t)) {
    return {
      state: 'unknown', ageMs: null, checkedAt: checkedAtRaw,
      reason: `the hub reported an unparseable checked_at (${checkedAtRaw})`,
    };
  }
  // ⛔ AN OFFSETLESS TIMESTAMP IS AN UNESTABLISHED AGE, NOT A MEASUREMENT.
  // Date.parse treats an ISO date-time with no Z and no offset as SERVER-LOCAL,
  // so west of UTC a stale feed reads younger than it is: a hub last ingesting
  // at 02:00Z, served offsetless and parsed at UTC-5, appears 5 hours fresher
  // and a 27-hour-old corpus passes the 24-hour threshold. The reference
  // deployment is UTC+7 and biased the other way, which is exactly why this
  // would not have been caught here.
  if (!/([Zz]|[+-]\d{2}:?\d{2})$/.test(checkedAtRaw.trim())) {
    return {
      state: 'unknown', ageMs: null, checkedAt: checkedAtRaw,
      reason: `the hub reported checked_at without a timezone offset (${checkedAtRaw}), `
        + 'so its age cannot be established -- it would be read in this server local time '
        + 'and silently shift by the offset between the two machines',
    };
  }
  const ageMs = nowMs - t;
  // ⛔ A checked_at in the FUTURE is not fresh, it is a clock disagreement, and
  // reporting it as healthy would hide the very skew that makes the age
  // meaningless. Same call vpn_sessions makes on a negative duration.
  if (ageMs < -5 * 60 * 1000) {
    return {
      state: 'unknown', ageMs, checkedAt: checkedAtRaw,
      reason: `the hub reports it last ingested in the FUTURE (${checkedAtRaw}); `
        + 'this server and the hub disagree about the time, so the age is not a measurement',
    };
  }
  if (ageMs > STALE_AFTER_MS) {
    const hours = Math.round(ageMs / 3600000);
    return {
      state: 'stale', ageMs, checkedAt: checkedAtRaw,
      reason: `the hub last ingested ${hours}h ago (threshold `
        + `${Math.round(STALE_AFTER_MS / 3600000)}h). The advisories applied are still valid, but the `
        + 'hub has stopped collecting new ones — check its scheduled ingest.',
    };
  }
  return { state: 'fresh', ageMs, checkedAt: checkedAtRaw, reason: '' };
}

/**
 * The error entries a freshness verdict contributes, if any.
 *
 * ⛔ SEPARATED OUT SO IT CAN BE TESTED BY BEHAVIOUR RATHER THAN BY SHAPE. The
 * first version of this lived inline and was "pinned" by a test that asserted
 * the errors.push(...) LINE existed in the source — which kept passing when the
 * surrounding condition was disabled. A test that cannot fail is worse than no
 * test: the code reads as covered.
 *
 * Returning a non-empty array is what makes the sync report `partial` instead of
 * `success`, and therefore what makes a frozen hub visible at all.
 */
function freshnessErrors(freshness) {
  // the ABSENT VERDICT IS A PROBLEM, NOT A PASS. feedFreshness always returns an
  // object today, so this is defensive - but defaulting a missing verdict to
  // "fine" is exactly the failed-read-as-a-fact rule, and the defensive branch
  // is where that mistake survives review.
  if (!freshness) {
    return [{
      cve_id: null,
      message: '[central CVE feed unknown] no freshness verdict was produced for this run, '
        + 'so the age of the corpus is unestablished',
    }];
  }
  if (freshness.state === 'fresh') return [];
  return [{
    cve_id: null,
    message: `[central CVE feed ${freshness.state}] ${freshness.reason}`,
  }];
}

/**
 * Is this a real, usable set of version ranges?
 *
 * ⛔ THE WHOLE CONSUMER TURNS ON THIS PREDICATE. An empty
 * affected_version_ranges means two OPPOSITE things — "this product is not
 * affected" and "no range could be extracted" — and versionMatcher treats an
 * empty array as the former. So "does the hub have something better" is never
 * decided on array length alone.
 */
function hasRanges(v) {
  return Array.isArray(v) && v.length > 0;
}

/**
 * ⛔ matchability MUST BE 'matched', not merely a non-empty array. An
 * 'unmatchable' hub row with an incidentally-populated array would otherwise be
 * allowed to overwrite a good local one — importing a known-bad extraction over
 * a known-good one, which is worse than not running at all.
 */
function hubIsBetter(local, remote) {
  if (!remote || remote.matchability !== 'matched') return false;
  if (!hasRanges(remote.affected_version_ranges)) return false;
  // ⛔ ONLY A KNOWN-BLANK ARRAY IS REPAIRABLE. `!hasRanges()` was true for an
  // UNKNOWN shape too — a jsonb object, a string, an absent key — and the
  // UPDATE then raised "cannot get array length of a non-array", which landed
  // in stats.errors, flipped the whole sync to partial, and (via hubDelivered)
  // silently re-enabled the doomed local NVD sync every cycle. An unrecognised
  // shape is NOT a gap we may fill; it is a row we do not understand.
  const localRanges = local ? local.affected_version_ranges : undefined;
  const blank = localRanges === null || localRanges === undefined
    || (Array.isArray(localRanges) && localRanges.length === 0);
  if (blank) return true;

  // ⛔ A NON-EMPTY LOCAL ROW CAN STILL BE THE WORSE ONE, and gating repair
  // solely on "ours is blank" meant we refused the hub's better data for ever.
  //
  // Measured 2026-09-25 on CVE-2026-24858 (KEV, CVSS 9.8 at NVD, live on three
  // FortiGates): the local row came from the FortiGuard CSAF feed in July and
  // reads `{min: 7.4.0, max: 7.4.10, exclude_fixed: false}` — a prose range
  // decremented to an inclusive bound, which MATCHES correctly and carries no
  // fix version. The hub's row, extracted from NVD's `versionEndExcluding`,
  // reads `{min: 7.4.0, max: 7.4.11, exclude_fixed: true}` — the same coverage
  // PLUS the remediation target. Because ours was not blank we kept the poorer
  // one indefinitely, and the fleet's only urgent CVE had nothing to upgrade to.
  //
  // ⛔ STRICTLY MORE INFORMATIVE, NEVER MERELY DIFFERENT. Two conditions, both
  // required:
  //   1. the hub states a fix boundary (`exclude_fixed: true`) somewhere and we
  //      state none at all — so this can only ever ADD knowledge, never trade
  //      one opinion for another;
  //   2. the hub has AT LEAST AS MANY ranges as we do — so a hub row covering
  //      fewer branches cannot narrow our coverage while claiming to improve it.
  // Rules 3, 4 and 5 are untouched: an unmatchable or rangeless remote was
  // already refused above, a vendor conflict never reaches here, and the
  // fixed_in_versions half of the UPDATE keeps its own empty-value guard.
  const hasFixBoundary = (ranges) => Array.isArray(ranges)
    && ranges.some((r) => r && r.exclude_fixed === true && r.max);
  if (hasFixBoundary(local.affected_version_ranges)) return false;
  if (!hasFixBoundary(remote.affected_version_ranges)) return false;
  return remote.affected_version_ranges.length >= localRanges.length;
}

async function fetchWithTimeout(url, headers) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { headers, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetch the signed feed and verify it.
 *
 * ⛔ VERIFICATION FAILS CLOSED AND THROWS. A feed whose signature does not
 * verify is not "a feed we are unsure about" — it is not the publisher's feed,
 * and applying it would write unverified advisory data into the table that
 * drives the priority decision tree. Degrading to "import it anyway" would make
 * the signature decorative.
 *
 * ⛔ VERIFY THE EXACT BYTES RECEIVED, then parse. Verifying a re-serialised
 * object would check our own JSON.stringify output rather than the publisher's,
 * and the two differ (key order, spacing) for identical data.
 */
async function fetchSignedFeed(licenseKey) {
  // ⛔ accept-encoding MUST BE SENT EXPLICITLY — node's fetch does not negotiate
  // compression on its own. The feed is 3.3 MB raw and 173 KB gzipped (5%),
  // measured; omitting this header costs a 20x download on a link this product
  // often shares with a syslog stream.
  const res = await fetchWithTimeout(`${hubUrl()}/api/v1/cve-feed`, {
    'x-license-key': licenseKey,
    'accept-encoding': 'gzip',
  });
  if (!res.ok) {
    const err = new Error(`CVE hub responded HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  const signature = res.headers.get('x-feed-signature');
  const expectedSha = res.headers.get('x-feed-sha256');
  const checkedAt = res.headers.get('x-feed-checked-at');
  const body = Buffer.from(await res.arrayBuffer());

  if (!signature) {
    throw new Error('CVE hub response carried no X-Feed-Signature — refusing to import');
  }

  const sha256 = crypto.createHash('sha256').update(body).digest('hex');
  // ⛔ Hex case is not part of the value. digest('hex') is lowercase; a publisher
  // emitting uppercase would fail a valid feed permanently, and the error
  // ("header ABC…, computed abc…") is one glance from being missed.
  if (expectedSha && sha256 !== String(expectedSha).trim().toLowerCase()) {
    throw new Error(`CVE feed sha256 mismatch: header ${expectedSha}, computed ${sha256}`);
  }
  const verified = crypto.verify(null, body, publicKey(), Buffer.from(signature, 'base64'));
  if (!verified) {
    throw new Error('CVE feed Ed25519 signature did NOT verify — refusing to import');
  }

  let feed;
  try {
    feed = JSON.parse(body.toString('utf8'));
  } catch (err) {
    throw new Error(`CVE feed body verified but did not parse: ${err.message}`);
  }
  if (!feed || !Array.isArray(feed.advisories)) {
    throw new Error('CVE feed verified but carried no advisories array');
  }
  // ⛔ A VERIFIED-BUT-EMPTY FEED IS REFUSED. A publisher bug that emitted zero
  // rows would otherwise be a correctly-signed instruction to change nothing,
  // reported as a clean success — indistinguishable from a healthy run.
  if (feed.advisories.length === 0) {
    throw new Error(
      'CVE feed verified but contained 0 advisories — refusing (publisher fault, not an empty world)'
    );
  }
  return { feed, sha256, checkedAt };
}

/**
 * Apply the verified feed.
 *
 * The five rules, each decided on measurement rather than judgement (collision
 * report against this fleet, 2026-09-18: 909 distinct CVEs, 74 absent, 835
 * present with the SAME vendor, 0 with a different vendor, 365 repairable, 1
 * that would degrade):
 *
 *   1. INSERT when the CVE is absent.
 *   2. REPAIR ranges only when ours are empty and the hub's are real.
 *   3. NEVER replace a non-empty range with an empty one. Not a preference —
 *      there is exactly 1 live case, and one is enough: it would turn a matched
 *      advisory into an unmatchable one and the device would silently stop being
 *      flagged.
 *   4. NEVER change an existing row's vendor. advisories.cve_id is UNIQUE with a
 *      single vendor, so a re-attribution is permanent and silent.
 *   5. For a CVE the hub holds under TWO vendors (1 case: CVE-2004-0112,
 *      checkpoint+forcepoint), keep whichever we already have; if we have
 *      neither, take the alphabetically-first so the choice is deterministic
 *      rather than dependent on row order.
 */
async function applyFeed(pool, feed) {
  const stats = {
    inserted: 0, repaired: 0, updated: 0, unchanged: 0,
    degradeRefused: 0, vendorConflict: 0, multiVendorCollapsed: 0,
    // ⛔ A DROPPED ROW IS COUNTED. Advisories missing cve_id or vendor were
    // skipped with a bare `continue`, so a feed whose every row was malformed
    // returned all-zero stats with NO errors — and hubDelivered then read that
    // as "the hub supplied the corpus" and skipped the local NVD sync. Green
    // for ever, over nothing.
    skippedUnusable: 0,
    errors: [],
  };

  // Rule 5: collapse multi-vendor CVEs deterministically before anything else.
  const byCve = new Map();
  for (const a of feed.advisories) {
    if (!a || !a.cve_id || !a.vendor) { stats.skippedUnusable++; continue; }
    if (!byCve.has(a.cve_id)) byCve.set(a.cve_id, []);
    byCve.get(a.cve_id).push(a);
  }

  const existing = new Map();
  const { rows } = await pool.query(
    'SELECT cve_id, vendor, affected_version_ranges, matchability FROM advisories'
  );
  for (const r of rows) existing.set(r.cve_id, r);

  for (const [cveId, candidates] of byCve) {
    try {
      const local = existing.get(cveId);
      let remote;
      if (candidates.length === 1) {
        remote = candidates[0];
      } else {
        stats.multiVendorCollapsed++;
        remote = (local && candidates.find((c) => c.vendor === local.vendor))
          || [...candidates].sort((a, b) => a.vendor.localeCompare(b.vendor))[0];
      }

      if (!local) {
        // Rule 1.
        const res = await pool.query(
          `INSERT INTO advisories (
             cve_id, vendor, title, description, cvss_score, cvss_vector,
             published_at, affected_version_ranges, fixed_in_versions, advisory_url,
             raw_data, cwe_ids, cvss_source, cvss_version, matchability, updated_at
           ) VALUES (
             $1, $2, $3, $4, $5, $6,
             $7::timestamptz, $8::jsonb, $9::jsonb, $10,
             $11::jsonb, $12::text[], $13, $14, $15, now()
           )
           ON CONFLICT (cve_id) DO NOTHING`,
          [
            remote.cve_id, remote.vendor, remote.title, remote.description,
            remote.cvss_score, remote.cvss_vector, remote.published_at,
            JSON.stringify(remote.affected_version_ranges || []),
            JSON.stringify(remote.fixed_in_versions || []),
            remote.advisory_url,
            // ⛔ Provenance, not the record. The hub deliberately does not ship
            // raw_data (~84% of each row and nothing reads it), so storing a
            // fabricated stand-in would be worse than storing what we know.
            JSON.stringify({ source: 'cve_hub', feed_version: feed.feed_version }),
            remote.cwe_ids || null, remote.cvss_source, remote.cvss_version,
            remote.matchability || null,
          ]
        );
        // ⛔ COUNT WHAT THE DATABASE DID, NOT WHAT WE ASKED IT TO DO.
        // `ON CONFLICT DO NOTHING` can write nothing — when the snapshot read
        // at the top of this function is stale against a concurrent sync, for
        // instance — and incrementing regardless reports inserts that never
        // happened into feed_sync_log.
        stats.inserted += Number(res && res.rowCount) || 0;
        continue;
      }

      // Rule 4: a row held under a different vendor is never touched, either way.
      if (local.vendor !== remote.vendor) {
        stats.vendorConflict++;
        continue;
      }

      // Rules 2 and 3.
      if (hubIsBetter(local, remote)) {
        await pool.query(
          `UPDATE advisories
              SET affected_version_ranges = $2::jsonb,
                  -- RULE 3 APPLIES TO THIS COLUMN TOO, AND COALESCE DID NOT
                  -- ENFORCE IT. An empty array is TRUTHY in JS, so an empty hub
                  -- value was serialised to the two-character string and
                  -- COALESCE returned it -- the guard only ever protected
                  -- against OUR OWN null, and this column is NOT NULL DEFAULT
                  -- empty-array, so it never fired at all. A local row carrying
                  -- real fixed versions from the Fortinet CSAF feed would be
                  -- blanked by a hub row that has none, flipping
                  -- is_fixed_recommended and silently moving a CVSS>=7 advisory
                  -- from scheduled to monitor.
                  fixed_in_versions = CASE
                    WHEN $3::jsonb IS NOT NULL
                     AND jsonb_typeof($3::jsonb) = 'array'
                     AND jsonb_array_length($3::jsonb) > 0
                      THEN $3::jsonb
                    ELSE fixed_in_versions END,
                  matchability = $4,
                  updated_at = now()
            WHERE cve_id = $1
              AND vendor = $5
              -- ⛔ RULE 3, EXPRESSED IN THE STATEMENT AS WELL AS IN THE
              -- PREDICATE ABOVE. The JS guard already decided this, but a repair
              -- that overwrites real ranges is the one outcome that must be
              -- IMPOSSIBLE rather than merely unreached — the same doubling
              -- config retention uses for its delete protections.
              -- The second disjunct is the one that fires: the column is
              -- NOT NULL DEFAULT '[]'::jsonb (lib/schema.sql), so the IS NULL
              -- test cannot be true today. It is kept deliberately -- if the
              -- column is ever made nullable, jsonb_array_length(NULL) is NULL
              -- and this WHERE would stop matching a blank row silently, which
              -- is the direction that loses repairs. Named here because a clause
              -- that cannot fire reads as protection it is not providing.
              AND (affected_version_ranges IS NULL
                   OR jsonb_array_length(affected_version_ranges) = 0)`,
          [
            cveId,
            JSON.stringify(remote.affected_version_ranges),
            remote.fixed_in_versions ? JSON.stringify(remote.fixed_in_versions) : null,
            remote.matchability,
            local.vendor,
          ]
        );
        stats.repaired++;
      } else if (
        hasRanges(local.affected_version_ranges)
        && !hasRanges(remote.affected_version_ranges)
      ) {
        stats.degradeRefused++;
      } else {
        stats.unchanged++;
      }
    } catch (err) {
      stats.errors.push({ cve_id: cveId, message: err.message });
    }
  }

  stats.updated = stats.repaired;
  return stats;
}

/**
 * Entry point, matching the shape every other feed module returns.
 *
 * ⛔ NOT CONFIGURED IS NOT AN ERROR. Without a licence key this returns notRun
 * with a reason and the orchestrator logs `skipped` — a feed that simply stops
 * appearing is indistinguishable from one that silently broke.
 */
async function fetchAndUpsertHubAdvisories(pool) {
  const licenseKey = (process.env.CVE_HUB_LICENSE_KEY || '').trim();
  if (!licenseKey) {
    return {
      inserted: 0, updated: 0, repaired: 0, errors: [], notRun: true,
      reason: 'CVE_HUB_LICENSE_KEY is not set — the central CVE feed is not configured',
    };
  }

  const { feed, sha256, checkedAt } = await fetchSignedFeed(licenseKey);

  // ⛔ FRESHNESS IS JUDGED BEFORE THE APPLY, AND NEVER BLOCKS IT. A stale feed
  // is still VALID data — the advisories did not become wrong because the hub
  // stopped collecting new ones — so refusing it would throw away good
  // information to protest a different problem. It is REPORTED instead, and the
  // orchestrator turns that into a `partial` so it reaches the status banner.
  const freshness = feedFreshness(checkedAt, Date.now());
  const stats = await applyFeed(pool, feed);

  // ⛔ A STALE OR UNKNOWN AGE IS PUSHED INTO `errors`, which is what makes the
  // sync report `partial` rather than `success`. Counting it anywhere else would
  // leave the one visible signal green while the corpus silently froze.
  const errors = [...(stats.errors || []), ...freshnessErrors(freshness)];

  return {
    ...stats,
    errors,
    feed_version: feed.feed_version,
    feed_sha256: sha256,
    feed_rows: feed.advisories.length,
    freshness: freshness.state,
    checked_at: freshness.checkedAt,
    age_hours: freshness.ageMs === null ? null : Math.round(freshness.ageMs / 3600000),
  };
}

module.exports = {
  fetchAndUpsertHubAdvisories,
  // exported for tests — all pure, no pool, no network
  hasRanges,
  hubIsBetter,
  applyFeed,
  // ⛔ EXPORTED SO THE SIGNATURE CHECK CAN BE TESTED BY BEHAVIOUR. It was
  // covered only by a test asserting its error STRINGS appear in the source,
  // which kept passing with verification disabled entirely.
  fetchSignedFeed,
  feedFreshness,
  freshnessErrors,
  STALE_AFTER_MS,
  FEED_PUBLIC_KEY_SPKI_B64,
};
