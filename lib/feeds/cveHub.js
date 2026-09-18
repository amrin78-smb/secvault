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
  return !hasRanges(local && local.affected_version_ranges);
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
  const body = Buffer.from(await res.arrayBuffer());

  if (!signature) {
    throw new Error('CVE hub response carried no X-Feed-Signature — refusing to import');
  }

  const sha256 = crypto.createHash('sha256').update(body).digest('hex');
  if (expectedSha && sha256 !== expectedSha) {
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
  return { feed, sha256 };
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
    errors: [],
  };

  // Rule 5: collapse multi-vendor CVEs deterministically before anything else.
  const byCve = new Map();
  for (const a of feed.advisories) {
    if (!a || !a.cve_id || !a.vendor) continue;
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
        await pool.query(
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
        stats.inserted++;
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
                  fixed_in_versions = COALESCE($3::jsonb, fixed_in_versions),
                  matchability = $4,
                  updated_at = now()
            WHERE cve_id = $1
              AND vendor = $5
              -- ⛔ RULE 3, EXPRESSED IN THE STATEMENT AS WELL AS IN THE
              -- PREDICATE ABOVE. The JS guard already decided this, but a repair
              -- that overwrites real ranges is the one outcome that must be
              -- IMPOSSIBLE rather than merely unreached — the same doubling
              -- config retention uses for its delete protections.
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

  const { feed, sha256 } = await fetchSignedFeed(licenseKey);
  const stats = await applyFeed(pool, feed);
  return {
    ...stats,
    feed_version: feed.feed_version,
    feed_sha256: sha256,
    feed_rows: feed.advisories.length,
  };
}

module.exports = {
  fetchAndUpsertHubAdvisories,
  // exported for tests — all pure, no pool, no network
  hasRanges,
  hubIsBetter,
  applyFeed,
  FEED_PUBLIC_KEY_SPKI_B64,
};
