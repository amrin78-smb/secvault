// lib/feeds/kev.js
// CISA Known Exploited Vulnerabilities (KEV) catalog ingestion.
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

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

// Live-verified 2026-07-15 via `curl` against the real feed. Top-level shape:
//   { title, catalogVersion, dateReleased, count, vulnerabilities: [...] }
// Each entry: { cveID, vendorProject, product, vulnerabilityName, dateAdded ("YYYY-MM-DD"),
//               shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes, cwes }
// Note the capitalization: `cveID` (not `cveId`), and `dateAdded` is a date-only string.

/**
 * Cross-reference the CISA KEV catalog against the `advisories` table.
 * @param {import('pg').Pool} pool
 * @returns {Promise<{marked_kev: number, unmarked_kev: number, errors: Array<{cve_id: string|null, message: string}>}>}
 */
async function syncKev(pool) {
  const errors = [];
  let marked_kev = 0;
  let unmarked_kev = 0;

  let data;
  try {
    const res = await fetch(KEV_URL);
    if (!res.ok) {
      throw new Error(`CISA KEV request failed: HTTP ${res.status}`);
    }
    data = await res.json();
  } catch (err) {
    errors.push({ cve_id: null, message: `Failed to download CISA KEV feed: ${err.message}` });
    return { marked_kev, unmarked_kev, errors };
  }

  const vulnerabilities = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
  const kevIds = [];
  for (const v of vulnerabilities) {
    if (v && typeof v.cveID === 'string' && v.cveID) kevIds.push(v.cveID);
  }

  for (const v of vulnerabilities) {
    if (!v || !v.cveID) continue;
    try {
      const result = await pool.query(
        `UPDATE advisories
         SET kev_listed = true, kev_date = $1::timestamptz, updated_at = now()
         WHERE cve_id = $2`,
        [v.dateAdded || null, v.cveID]
      );
      marked_kev += result.rowCount;
    } catch (err) {
      errors.push({ cve_id: v.cveID, message: err.message });
    }
  }

  // Safety guard: if the feed parsed but produced zero cve ids (unexpected/malformed
  // response), skip the "unmark" step rather than wiping kev_listed off every advisory —
  // `cve_id != ALL($1::text[])` with an empty array would match every row.
  if (kevIds.length === 0) {
    errors.push({
      cve_id: null,
      message: 'CISA KEV feed parsed but contained zero cve ids; skipping unmark step to avoid clearing kev_listed on every advisory',
    });
    return { marked_kev, unmarked_kev, errors };
  }

  try {
    const result = await pool.query(
      `UPDATE advisories
       SET kev_listed = false, updated_at = now()
       WHERE kev_listed = true AND cve_id != ALL($1::text[])`,
      [kevIds]
    );
    unmarked_kev = result.rowCount;
  } catch (err) {
    errors.push({ cve_id: null, message: `Failed to unmark stale KEV entries: ${err.message}` });
  }

  return { marked_kev, unmarked_kev, errors };
}

module.exports = { syncKev };
