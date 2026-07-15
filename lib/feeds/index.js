// lib/feeds/index.js
// Feed orchestrator — runs NVD + KEV syncs, logging each to feed_sync_log.
// CommonJS ONLY — this file is `require()`d by services/engine-worker.js (plain node).

const { fetchAndUpsertVendorCves } = require('./nvd');
const { syncKev } = require('./kev');

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

/**
 * Run both feed syncs. Each is independently isolated — a failure in one never
 * prevents the other from running.
 * @param {import('pg').Pool} pool
 */
async function runFullSync(pool) {
  let nvd;
  try {
    nvd = await runNvdSync(pool);
  } catch (err) {
    nvd = { inserted: 0, updated: 0, errors: [{ cve_id: null, message: err.message }], byVendor: {} };
  }

  let kev;
  try {
    kev = await runKevSync(pool);
  } catch (err) {
    kev = { marked_kev: 0, unmarked_kev: 0, errors: [{ cve_id: null, message: err.message }] };
  }

  return { nvd, kev };
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

module.exports = { runFullSync, getLastSyncStatus };
