// lib/feeds/index.js
// Feed orchestrator — runs NVD + KEV syncs, logging each to feed_sync_log.
// CommonJS ONLY — this file is `require()`d by services/engine-worker.js (plain node).

const { fetchAndUpsertVendorCves } = require('./nvd');
const { syncKev } = require('./kev');
const { fetchAndUpsertEpssScores } = require('./epss');
const { fetchAndEnrichFromCveOrg } = require('./cveorg');
const { syncCloudApps } = require('./cloudApps');
const {
  registerVendorPsirt, inventoryVendors, planVendorPsirts, SKIPPED,
} = require('./vendorPsirt');
const { fetchAndUpsertPaloAltoAdvisories } = require('./paloalto');
// Sibling agent's Fortinet feed module — its own fetchAndUpsertFortinetAdvisories(pool)
// returns {inserted, updated, errors, skipped}, matching the same shape
// fetchAndUpsertPaloAltoAdvisories does. Log-wrapping lives here (index.js), not in the
// feed module, per this file's established runNvdSync/runKevSync pattern.
const { fetchAndUpsertFortinetAdvisories } = require('./fortinet');
// Central CVE feed (nocvault-eol). Log-wrapping lives here, same as every other
// feed module — see runNvdSync.
const { fetchAndUpsertHubAdvisories } = require('./cveHub');

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

/**
 * Refresh the published cloud/SaaS address catalogue.
 *
 * ⛔ NOT A CVE FEED, and deliberately grouped with them anyway: it is an
 * outbound fetch on the same cadence, and giving it its own cron would mean a
 * second schedule to reason about for no benefit. It runs LAST so a slow
 * publisher can never delay the advisory feeds, which are what the priority
 * tree depends on.
 *
 * ⛔ ITS FAILURE IS NOT THE CYCLE'S FAILURE. Nothing about naming a rule should
 * be able to stop CVE ingestion, and an install with no outbound access is
 * expected to fail this one on every run while the rest may still work through
 * a proxy.
 */
async function runCloudAppsSync(pool) {
  const startedAt = Date.now();
  let logId = null;
  try {
    logId = await logSyncStart(pool, 'cloud_apps');
    const result = await syncCloudApps(pool);
    // ⛔ 'partial' when ANY source failed, never 'success'. Three publishers
    // answering and one refusing is a catalogue with a hole in it, and the
    // status is the only place that hole is visible.
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
      await logSyncFinish(pool, logId, {
        status: 'failed',
        inserted: 0,
        updated: 0,
        errors: [{ provider: null, message: err.message }],
        durationMs: Date.now() - startedAt,
      });
    }
    throw err;
  }
}

// ⛔ REGISTERED HERE, AFTER THE RUNNERS EXIST. Each entry is keyed by the
// `devices.vendor` slug exactly, because that key is what gets compared against
// the inventory — a near-miss spelling would silently mean "never run".
registerVendorPsirt('paloalto', 'paloalto_psirt', runPaloAltoPsirtSync);
registerVendorPsirt('fortinet', 'fortinet_psirt', runFortinetPsirtSync);

/**
 * Record that a feed was deliberately not fetched.
 *
 * ⛔ A SKIPPED RUN IS WRITTEN DOWN. A feed that simply stops appearing in
 * feed_sync_log is indistinguishable from one that silently broke, and the
 * dashboard's freshness strip would show a stale timestamp forever with no
 * explanation. The reason is stored with it so the row answers "why" without
 * anyone reading this file.
 */
async function logSkipped(pool, feedName, reason) {
  try {
    const id = await logSyncStart(pool, feedName);
    if (id) {
      await logSyncFinish(pool, id, {
        status: SKIPPED,
        inserted: 0,
        updated: 0,
        errors: [{ cve_id: null, message: reason }],
        durationMs: 0,
      });
    }
  } catch (_err) {
    // ⛔ Never let bookkeeping break a sync cycle. Losing the audit row is a
    // smaller harm than failing the run that was about to happen anyway.
  }
}

/**
 * Central CVE feed from nocvault-eol.
 *
 * ⛔ IT RUNS FIRST, BEFORE NVD, AND THE ORDER IS THE WHOLE ATTRIBUTION RULE.
 * advisories.cve_id is UNIQUE and carries exactly ONE vendor, so whichever feed
 * lands a CVE first owns it permanently. The hub is the only source on this
 * network with NVD-grade version ranges (the local NVD path cannot reach NIST at
 * all — the sites use internal public IP ranges that overlap NVD's own address
 * space), so it must not be left to pick up whatever CIRCL claimed first.
 *
 * ⛔ IT IS A DISCOVERY FEED, NOT AN ENRICHMENT ONE — it inserts. That is the
 * opposite of cveorg/epss and is why it does not run at the end with them.
 *
 * ⛔ ITS FAILURE IS ISOLATED LIKE EVERY OTHER FEED. If the hub is unreachable
 * the local NVD path still runs immediately afterwards and CIRCL still backs it
 * up; a central feed that could block local discovery would be a worse position
 * than not having one.
 */
async function runCveHubSync(pool) {
  const startedAt = Date.now();
  let logId = null;
  try {
    logId = await logSyncStart(pool, 'cve_hub');
    const result = await fetchAndUpsertHubAdvisories(pool);

    // Not configured is not a failure — it is logged as skipped, with the reason.
    if (result.notRun) {
      if (logId) {
        await logSyncFinish(pool, logId, {
          status: 'skipped', inserted: 0, updated: 0,
          errors: [{ cve_id: null, message: result.reason }],
          durationMs: Date.now() - startedAt,
        });
      }
      return result;
    }

    const status = result.errors && result.errors.length > 0 ? 'partial' : 'success';
    if (logId) {
      // Same convention as runNvdSync: the summary rides along in the errors
      // jsonb as one clearly-marked non-error entry, because feed_sync_log has
      // no detail column. ⛔ degrade_refused and vendor_conflict are RECORDED,
      // not just counted in memory — they are the two outcomes where the feed
      // deliberately did nothing, and a silent no-op is indistinguishable from
      // a feed that never saw the row.
      const errorsForLog = [
        ...(result.errors || []),
        {
          cve_id: null,
          message: 'central CVE feed summary (informational, not an error)',
          feed_version: result.feed_version,
          feed_rows: result.feed_rows,
          inserted: result.inserted,
          repaired: result.repaired,
          unchanged: result.unchanged,
          degrade_refused: result.degradeRefused,
          vendor_conflict: result.vendorConflict,
          multi_vendor_collapsed: result.multiVendorCollapsed,
        },
      ];
      await logSyncFinish(pool, logId, {
        status,
        inserted: result.inserted,
        updated: result.repaired,
        errors: errorsForLog,
        durationMs: Date.now() - startedAt,
      });
    }
    return result;
  } catch (err) {
    if (logId) {
      await logSyncFinish(pool, logId, {
        status: 'failed', inserted: 0, updated: 0,
        errors: [{ cve_id: null, message: err.message }],
        durationMs: Date.now() - startedAt,
      });
    }
    throw err;
  }
}

async function runFullSync(pool) {
  // ⛔ ONE inventory read for the whole cycle, and its FAILURE means every
  // vendor feed runs (see planVendorPsirts). A database hiccup must never
  // quietly switch off CVE discovery — that leaves the product not doing its
  // main job while every signal still looks healthy.
  const inventory = await inventoryVendors(pool);
  const psirtPlan = new Map(
    planVendorPsirts(inventory).map((p) => [p.vendor, p])
  );
  // ⛔ FIRST. See runCveHubSync — cve_id is UNIQUE with one vendor, so feed
  // order IS the attribution rule, and the hub is the only source here with
  // usable version ranges.
  let cve_hub;
  try {
    cve_hub = await runCveHubSync(pool);
  } catch (err) {
    cve_hub = { inserted: 0, updated: 0, repaired: 0, errors: [{ cve_id: null, message: err.message }] };
  }

  // ⛔ THE LOCAL NVD PATH IS SKIPPED ONLY WHEN THE HUB ACTUALLY DELIVERED THIS
  // CYCLE — never on a config flag saying "we use the hub now".
  //
  // On a site whose egress cannot reach NVD (internal public ranges overlapping
  // NVD's own address space) this sync can never succeed: it spends ~2 minutes
  // on requests guaranteed to time out and then reports 'partial' for ever. A
  // permanent amber chip for a system working exactly as designed teaches an
  // operator to ignore the chip that matters — the same reason the vendor-PSIRT
  // gate writes 'skipped' rather than letting a feed quietly stop appearing.
  //
  // ⛔ THE CONDITION IS THE WHOLE SAFETY OF IT. `hubDelivered` requires a
  // VERIFIED, NON-EMPTY corpus from this cycle. If the hub is unconfigured,
  // unreachable, or returned errors, NVD runs exactly as before with CIRCL
  // behind it — so the day the hub breaks, discovery does not silently stop
  // while every signal stays green.
  //
  // ⛔ Note what this also skips: CIRCL, which only runs inside runNvdSync as
  // NVD's network-failure fallback. Those advisories are almost all
  // 'unmatchable' (CIRCL publishes no parseable version bounds), so the loss is
  // small — but it IS a loss, and it is the reason this is gated on the hub
  // having delivered rather than on the hub merely being configured.
  // ⛔ A STALE HUB IS NOT A DELIVERING HUB, and this falls out of the error test
  // deliberately rather than by accident. cveHub pushes its freshness verdict
  // into `errors`, so a corpus the hub has stopped refreshing makes hubDelivered
  // FALSE and the local NVD path runs again with CIRCL behind it. On this site
  // that attempt will still fail — but it will fail LOUDLY, and CIRCL may still
  // land something, which is strictly better than quietly trusting a frozen
  // central feed because it happened to verify.
  const hubDelivered = !!(
    cve_hub
    && !cve_hub.notRun
    && (!cve_hub.errors || cve_hub.errors.length === 0)
    && Number(cve_hub.feed_rows) > 0
  );

  let nvd;
  if (hubDelivered) {
    const reason =
      `central CVE feed supplied the corpus this cycle (${cve_hub.feed_rows} advisories, `
      + `feed ${cve_hub.feed_version}), so the direct NVD sync was not run`;
    await logSkipped(pool, 'nvd', reason);
    nvd = { inserted: 0, updated: 0, errors: [], byVendor: {}, notRun: true, reason };
  } else {
    try {
      nvd = await runNvdSync(pool);
    } catch (err) {
      nvd = { inserted: 0, updated: 0, errors: [{ cve_id: null, message: err.message }], byVendor: {} };
    }
  }

  let paloalto_psirt;
  const paPlan = psirtPlan.get('paloalto');
  if (paPlan && !paPlan.shouldRun) {
    await logSkipped(pool, paPlan.feedName, paPlan.reason);
    paloalto_psirt = { inserted: 0, updated: 0, skipped: 0, errors: [], notRun: true, reason: paPlan.reason };
  } else {
    try {
      paloalto_psirt = await runPaloAltoPsirtSync(pool);
    } catch (err) {
      paloalto_psirt = { inserted: 0, updated: 0, skipped: 0, errors: [{ cve_id: null, message: err.message }] };
    }
  }

  let fortinet_psirt;
  const ftPlan = psirtPlan.get('fortinet');
  if (ftPlan && !ftPlan.shouldRun) {
    await logSkipped(pool, ftPlan.feedName, ftPlan.reason);
    fortinet_psirt = { inserted: 0, updated: 0, skipped: 0, errors: [], notRun: true, reason: ftPlan.reason };
  } else {
    try {
      fortinet_psirt = await runFortinetPsirtSync(pool);
    } catch (err) {
      fortinet_psirt = { inserted: 0, updated: 0, skipped: 0, errors: [{ cve_id: null, message: err.message }] };
    }
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

  // Last of all — see runCloudAppsSync. A publisher being unreachable leaves
  // the previous catalogue in place rather than emptying it, so this failing
  // costs freshness, never coverage.
  let cloud_apps;
  try {
    cloud_apps = await runCloudAppsSync(pool);
  } catch (err) {
    cloud_apps = { results: [], inserted: 0, updated: 0, errors: [{ provider: null, message: err.message }] };
  }

  return { cve_hub, nvd, paloalto_psirt, fortinet_psirt, kev, cveorg, epss, cloud_apps };
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
  const feedNames = ['cve_hub', 'nvd', 'paloalto_psirt', 'fortinet_psirt', 'kev', 'cveorg', 'epss', 'cloud_apps'];
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
  runCloudAppsSync,
  runFullSync,
  getLastSyncStatus,
  getFeedStatusBySource,
  summarizeCirclUsage,
};
