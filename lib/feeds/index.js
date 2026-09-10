// lib/feeds/index.js
// Feed orchestrator — runs NVD + KEV syncs, logging each to feed_sync_log.
// CommonJS ONLY — this file is `require()`d by services/engine-worker.js (plain node).

const { fetchAndUpsertVendorCves } = require('./nvd');
const { syncKev } = require('./kev');
const { fetchAndUpsertEpssScores } = require('./epss');
const { fetchAndEnrichFromCveOrg } = require('./cveorg');
const { fetchAndUpsertPaloAltoAdvisories } = require('./paloalto');
// Sibling agent's Fortinet feed module — its own fetchAndUpsertFortinetAdvisories(pool)
// returns {inserted, updated, errors, skipped}, matching the same shape
// fetchAndUpsertPaloAltoAdvisories does. Log-wrapping lives here (index.js), not in the
// feed module, per this file's established runNvdSync/runKevSync pattern.
const { fetchAndUpsertFortinetAdvisories } = require('./fortinet');

async function logSyncStart(pool, feedName) {
  const result = await pool.query(
    `INSERT INTO feed_sync_log (feed_name, status, started_at) VALUES ($1, 'partial', now()) RETURNING id`,
    [feedName]
  );
  return result.rows[0].id;
}

async function logSyncFinish(pool, logId, { status, inserted, updated, errors, durationMs }) {
  await pool.query(
    `UPDATE feed_sync_log
     SET status = $1, inserted = $2, updated = $3, errors = $4::jsonb, duration_ms = $5, finished_at = now()
     WHERE id = $6`,
    [status, inserted || 0, updated || 0, JSON.stringify(errors || []), durationMs, logId]
  );
}

// One feed's failure must never prevent the other from running — everything in here,
// including the log-row bookkeeping itself, is wrapped so a DB hiccup on logging can't
// mask (or crash out of) the underlying sync attempt.
async function runNvdSync(pool) {
  const startedAt = Date.now();
  let logId = null;
  try {
    logId = await logSyncStart(pool, 'nvd');
    const result = await fetchAndUpsertVendorCves(pool);
    // Status is decided from the REAL errors only — the per-vendor summary entry
    // appended below is informational and must not flip a clean run to 'partial'.
    const status = result.errors && result.errors.length > 0 ? 'partial' : 'success';
    if (logId) {
      // feed_sync_log has no dedicated detail column, so the per-vendor
      // inserted/updated breakdown rides along in the errors jsonb as one
      // clearly-marked non-error summary entry (same array shape as before).
      const errorsForLog = [
        ...(result.errors || []),
        {
          cve_id: null,
          message: 'per-vendor summary (informational, not an error)',
          by_vendor: result.byVendor || {},
        },
      ];
      await logSyncFinish(pool, logId, {
        status,
        inserted: result.inserted,
        updated: result.updated,
        errors: errorsForLog,
        durationMs: Date.now() - startedAt,
      });
    }
    return result;
  } catch (err) {
    if (logId) {
      try {
        await logSyncFinish(pool, logId, {
          status: 'error',
          inserted: 0,
          updated: 0,
          errors: [{ cve_id: null, message: err.message }],
          durationMs: Date.now() - startedAt,
        });
      } catch (_) {
        // logging failure must not mask the original error
      }
    }
    return { inserted: 0, updated: 0, errors: [{ cve_id: null, message: err.message }], byVendor: {} };
  }
}

// feed_sync_log has no KEV-specific columns, so marked_kev/unmarked_kev are recorded
// via the generic inserted/updated columns (marked -> inserted, unmarked -> updated).
async function runKevSync(pool) {
  const startedAt = Date.now();
  let logId = null;
  try {
    logId = await logSyncStart(pool, 'kev');
    const result = await syncKev(pool);
    const status = result.errors && result.errors.length > 0 ? 'partial' : 'success';
    if (logId) {
      await logSyncFinish(pool, logId, {
        status,
        inserted: result.marked_kev,
        updated: result.unmarked_kev,
        errors: result.errors,
        durationMs: Date.now() - startedAt,
      });
    }
    return result;
  } catch (err) {
    if (logId) {
      try {
        await logSyncFinish(pool, logId, {
          status: 'error',
          inserted: 0,
          updated: 0,
          errors: [{ cve_id: null, message: err.message }],
          durationMs: Date.now() - startedAt,
        });
      } catch (_) {
        // logging failure must not mask the original error
      }
    }
    return { marked_kev: 0, unmarked_kev: 0, errors: [{ cve_id: null, message: err.message }] };
  }
}

// Same logSyncStart/logSyncFinish + try/catch shape as runNvdSync/runKevSync
// above, minus the byVendor summary trick (not needed — this is a single-vendor
// feed, unlike NVD's multi-vendor sweep).
async function runPaloAltoPsirtSync(pool) {
  const startedAt = Date.now();
  let logId = null;
  try {
    logId = await logSyncStart(pool, 'paloalto_psirt');
    const result = await fetchAndUpsertPaloAltoAdvisories(pool);
    const status = result.errors && result.errors.length > 0 ? 'partial' : 'success';
    if (logId) {
      await logSyncFinish(pool, logId, {
        status,
        inserted: result.inserted,
        updated: result.updated,
        errors: result.errors,
        durationMs: Date.now() - startedAt,
      });
    }
    return result;
  } catch (err) {
    if (logId) {
      try {
        await logSyncFinish(pool, logId, {
          status: 'error',
          inserted: 0,
          updated: 0,
          errors: [{ cve_id: null, message: err.message }],
          durationMs: Date.now() - startedAt,
        });
      } catch (_) {
        // logging failure must not mask the original error
      }
    }
    return { inserted: 0, updated: 0, skipped: 0, errors: [{ cve_id: null, message: err.message }] };
  }
}

// Same shape as runPaloAltoPsirtSync — wraps the sibling Fortinet feed
// module's fetchAndUpsertFortinetAdvisories(pool) with the same
// logSyncStart/logSyncFinish bookkeeping. The Fortinet module itself does NOT
// do its own log-wrapping, matching this file's established convention that
// log-wrapping lives in index.js, not in the individual feed module.
async function runFortinetPsirtSync(pool) {
  const startedAt = Date.now();
  let logId = null;
  try {
    logId = await logSyncStart(pool, 'fortinet_psirt');
    const result = await fetchAndUpsertFortinetAdvisories(pool);
    const status = result.errors && result.errors.length > 0 ? 'partial' : 'success';
    if (logId) {
      await logSyncFinish(pool, logId, {
        status,
        inserted: result.inserted,
        updated: result.updated,
        errors: result.errors,
        durationMs: Date.now() - startedAt,
      });
    }
    return result;
  } catch (err) {
    if (logId) {
      try {
        await logSyncFinish(pool, logId, {
          status: 'error',
          inserted: 0,
          updated: 0,
          errors: [{ cve_id: null, message: err.message }],
          durationMs: Date.now() - startedAt,
        });
      } catch (_) {
        // logging failure must not mask the original error
      }
    }
    return { inserted: 0, updated: 0, skipped: 0, errors: [{ cve_id: null, message: err.message }] };
  }
}

// CIRCL is an in-band fallback INSIDE runNvdSync/fetchCvesForVendor (nvd.js),
// not an independently-scheduled sync — it has no top-level "run" of its own
// and therefore gets no logSyncStart(pool, 'circl') call (that would
// misrepresent it as a real independent feed run). Every time nvd.js's
// tryCirclFallback runs, it pushes an error-array entry whose `message`
// starts with the literal prefix "[CIRCL fallback]" — this just scans the
// errors array runNvdSync already returns/logs for that prefix, so a status
// consumer can tell "was CIRCL used in the most recent NVD sync" without
// nvd.js needing any change at all.
function summarizeCirclUsage(nvdErrors) {
  const circlEntries = (nvdErrors || []).filter(
    (e) => e && typeof e.message === 'string' && e.message.startsWith('[CIRCL fallback]')
  );
  return { used: circlEntries.length > 0, eventCount: circlEntries.length };
}

/**
 * Run all feed syncs. Each is independently isolated — a failure in one never
 * prevents the others from running. Run SEQUENTIALLY, in this exact order
 * (nvd -> paloalto_psirt -> fortinet_psirt -> kev), to avoid rate-limit
 * issues from running multiple external feed syncs concurrently.
 * @param {import('pg').Pool} pool
 */
// EPSS (FIRST.org exploit probability).
//
// ⛔ ENRICHMENT-ONLY: this feed may UPDATE an existing advisory and may NEVER
// INSERT one. `advisories.cve_id` is UNIQUE and carries exactly ONE vendor, so an
// inserting feed can permanently claim a CVE for the wrong vendor — and EPSS
// covers ~371,000 CVEs against the ~1,000 this product tracks, so inserting would
// also flood it with vulnerabilities belonging to no firewall. `inserted` is a
// structural 0. See .ai-codex/roadmap.md for the underlying schema risk.
//
// ⛔ Runs LAST, after every discovery feed, because it enriches whatever they
// just landed. A CVE ingested this cycle should get its score this cycle.
async function runEpssSync(pool) {
  const startedAt = Date.now();
  let logId = null;
  try {
    logId = await logSyncStart(pool, 'epss');
    const result = await fetchAndUpsertEpssScores(pool);

    // ⛔ STATUS IS DECIDED FROM result.errors ALONE, BEFORE the informational
    // summary is appended. index.js derives `partial` from a non-empty errors
    // array, so appending the summary first would make every successful run
    // report as degraded — the same shape as runNvdSync.
    const status = result.errors && result.errors.length > 0 ? 'partial' : 'success';
    const errorsForLog = [
      ...(result.errors || []),
      {
        cve_id: null,
        message: 'EPSS summary (informational, not an error)',
        ...(result.summary || {}),
      },
    ];

    if (logId) {
      await logSyncFinish(pool, logId, {
        status,
        inserted: 0, // structural invariant: enrichment-only
        updated: result.updated,
        errors: errorsForLog,
        durationMs: Date.now() - startedAt,
      });
    }
    return result;
  } catch (err) {
    if (logId) {
      try {
        await logSyncFinish(pool, logId, {
          status: 'error',
          inserted: 0,
          updated: 0,
          errors: [{ cve_id: null, message: err.message }],
          durationMs: Date.now() - startedAt,
        });
      } catch (_) {
        // logging failure must not mask the original error
      }
    }
    return { inserted: 0, updated: 0, errors: [{ cve_id: null, message: err.message }] };
  }
}

// CVE.org (MITRE CVE Program, CVE Record Format 5.2).
//
// ⛔ ENRICHMENT-ONLY, same contract as EPSS: it may UPDATE an existing advisory
// and may NEVER INSERT one, so it cannot squat a cve_id for the wrong vendor.
// `inserted` is a structural 0.
//
// ⛔ IT DOES NOT REPLACE NVD, and the measurement says so: on this corpus it
// filled 0 of the 255 missing CVSS scores. CIRCL already returns cvelistV5
// records — literally the documents CVE.org serves — and those 255 are
// NVD-ANALYST scores that never existed in the CVE Record at all. Its value here
// is forward-looking (ADP/Vulnrichment on newly published CVEs), CWEs, and
// reachability insurance while NVD is blocked. See .ai-codex/cve-pipeline.md.
async function runCveOrgSync(pool) {
  const startedAt = Date.now();
  let logId = null;
  try {
    logId = await logSyncStart(pool, 'cveorg');
    const result = await fetchAndEnrichFromCveOrg(pool);

    // ⛔ Status from result.errors ALONE, before the summary is appended — the
    // run counters live in `summary`, and folding them into `errors` first would
    // paint every healthy run `partial`. Same shape as runNvdSync/runEpssSync.
    const status = result.errors && result.errors.length > 0 ? 'partial' : 'success';
    const errorsForLog = [
      ...(result.errors || []),
      {
        cve_id: null,
        message: 'CVE.org summary (informational, not an error)',
        ...(result.summary || {}),
      },
    ];

    if (logId) {
      await logSyncFinish(pool, logId, {
        status,
        inserted: 0, // structural invariant: enrichment-only
        updated: result.updated,
        errors: errorsForLog,
        durationMs: Date.now() - startedAt,
      });
    }
    return result;
  } catch (err) {
    if (logId) {
      try {
        await logSyncFinish(pool, logId, {
          status: 'error',
          inserted: 0,
          updated: 0,
          errors: [{ cve_id: null, message: err.message }],
          durationMs: Date.now() - startedAt,
        });
      } catch (_) {
        // logging failure must not mask the original error
      }
    }
    return { inserted: 0, updated: 0, errors: [{ cve_id: null, message: err.message }] };
  }
}

async function runFullSync(pool) {
  let nvd;
  try {
    nvd = await runNvdSync(pool);
  } catch (err) {
    nvd = { inserted: 0, updated: 0, errors: [{ cve_id: null, message: err.message }], byVendor: {} };
  }

  let paloalto_psirt;
  try {
    paloalto_psirt = await runPaloAltoPsirtSync(pool);
  } catch (err) {
    paloalto_psirt = { inserted: 0, updated: 0, skipped: 0, errors: [{ cve_id: null, message: err.message }] };
  }

  let fortinet_psirt;
  try {
    fortinet_psirt = await runFortinetPsirtSync(pool);
  } catch (err) {
    fortinet_psirt = { inserted: 0, updated: 0, skipped: 0, errors: [{ cve_id: null, message: err.message }] };
  }

  let kev;
  try {
    kev = await runKevSync(pool);
  } catch (err) {
    kev = { marked_kev: 0, unmarked_kev: 0, errors: [{ cve_id: null, message: err.message }] };
  }

  // Enrichment feeds run after every discovery feed. CVE.org first, then EPSS:
  // CVE.org can fill a CVSS/CWE gap, and EPSS is keyed only by cve_id, so the
  // order costs nothing and keeps "enrich the record, then score it" readable.
  let cveorg;
  try {
    cveorg = await runCveOrgSync(pool);
  } catch (err) {
    cveorg = { inserted: 0, updated: 0, errors: [{ cve_id: null, message: err.message }] };
  }

  // Last on purpose — it enriches whatever the discovery feeds just landed.
  let epss;
  try {
    epss = await runEpssSync(pool);
  } catch (err) {
    epss = { inserted: 0, updated: 0, errors: [{ cve_id: null, message: err.message }] };
  }

  return { nvd, paloalto_psirt, fortinet_psirt, kev, cveorg, epss };
}

/**
 * @param {import('pg').Pool} pool
 * @returns {Promise<Array<object>>} last 10 feed_sync_log rows, most recent first
 */
async function getLastSyncStatus(pool) {
  const result = await pool.query(
    `SELECT * FROM feed_sync_log ORDER BY started_at DESC LIMIT 10`
  );
  return result.rows;
}

// One most-recent row per feed_name, for a per-source status view (e.g. an
// "Advisories" page banner showing "NVD: success 2h ago / Palo Alto: never
// run / ..."). A source with no rows yet (a feed that hasn't run since this
// feed was added) returns null for that key — callers must treat null as
// "not yet run", not crash on missing fields.
async function getFeedStatusBySource(pool) {
  const feedNames = ['nvd', 'paloalto_psirt', 'fortinet_psirt', 'kev', 'cveorg', 'epss'];
  const result = await pool.query(
    `SELECT DISTINCT ON (feed_name)
       feed_name, status, started_at, finished_at, inserted, updated, errors
     FROM feed_sync_log
     WHERE feed_name = ANY($1)
     ORDER BY feed_name, started_at DESC`,
    [feedNames]
  );

  const bySource = {
    nvd: null, paloalto_psirt: null, fortinet_psirt: null, kev: null, cveorg: null, epss: null,
  };
  for (const row of result.rows) {
    bySource[row.feed_name] = row;
  }

  if (bySource.nvd) {
    bySource.nvd = { ...bySource.nvd, circl: summarizeCirclUsage(bySource.nvd.errors) };
  }

  return bySource;
}

module.exports = {
  runFullSync,
  getLastSyncStatus,
  getFeedStatusBySource,
  summarizeCirclUsage,
};
