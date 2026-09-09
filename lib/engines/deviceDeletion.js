// lib/engines/deviceDeletion.js
//
// Deleting a device, staged so that it can actually finish and so that log
// ingestion is not held hostage while it runs.
//
// ⛔ WHY THIS FILE EXISTS. Both problems were hit live on 2026-09-09 and both
// are reproduced from app-error.log / pg_locks, not inferred:
//
// 1. THE OLD DELETE COULD NEVER SUCCEED. `DELETE FROM devices WHERE id = $1`
//    fired every ON DELETE SET NULL FK, including this one:
//
//      UPDATE ONLY "syslog_rollup_hourly" SET "device_id" = NULL WHERE $1 = "device_id"
//      ERROR 23505  unique_violation
//      constraint: uq_syslog_rollup_hourly
//      detail: Key (bucket_hour, source_ip, device_id, vendor, action, severity, log_class)
//              = (2026-09-09 10:00, 10.204.6.1, null, fortinet, blocked, 4, utm) already exists
//
//    Two deliberate, individually correct decisions are mutually incompatible:
//    the FK is SET NULL, and the unique key is UNIQUE NULLS NOT DISTINCT (the
//    choice CLAUDE.md documents precisely so grouping keys can stay honestly
//    nullable rather than carrying 'unknown' sentinel strings). A device_id
//    NULL row for that same bucket ALREADY EXISTS — written from events that
//    arrived before the sender was matched to a device — so NULLing collides
//    with it. Every attempt rolled the whole four-minute transaction back.
//    The delete was not slow. It was IMPOSSIBLE.
//
// 2. WHILE FAILING, IT BLOCKED INGESTION. The same transaction rewrote every
//    `syslog_events` row the device owned — 3,352,437 rows across 47 GB of
//    partitions for one device — holding an exclusive lock on the `devices`
//    row throughout. The collector needs a KEY SHARE lock on that same row to
//    INSERT any event for the device, so `INSERT INTO syslog_events` was seen
//    waiting on the DELETE in pg_locks. Four minutes of deaf collector, then a
//    rollback, then nothing to show for it.
//
// ─────────────────────────────────────────────────────────────────────────
// THE ORDER, AND WHY EACH STAGE MUST PRECEDE THE NEXT
//
//   Stage 1 — DELETE the derived hourly rollup rows, in bounded batches, each
//             its own transaction.
//             ⛔ DELETE, never NULL. Two reasons, and the second is the one
//             that matters even if 23505 did not exist:
//               a) it is what makes the collision impossible — there is no
//                  NULLing left for the FK to do at stage 3;
//               b) NULLing would MERGE this device's traffic into the
//                  "unmatched sender" bucket, which is the exact population
//                  `discovered_devices` reads to find unmanaged firewalls.
//                  A deleted device's history would resurface as a phantom
//                  unmanaged device. Rollups are DERIVED aggregates,
//                  reconstructible from raw events by rollups.js; a rollup row
//                  for a device that no longer exists is not a fact anyone
//                  needs.
//             This also empties the ON DELETE CASCADE rollups ahead of time,
//             which is what keeps stage 3's lock window short.
//
//   Stage 2 — Batch-NULL `syslog_events.device_id`, bounded batches with a
//             short pause between them.
//             ⛔ The raw events are FORENSIC EVIDENCE and are NOT deleted. The
//             device record goes; the logs stay. NULL is exactly right here
//             and cannot collide: `syslog_events` has no unique constraint at
//             all beyond its PRIMARY KEY (received_at, id), verified against
//             the live database — device_id appears in no unique index.
//             Setting a FK column to NULL takes no lock on `devices`, so the
//             collector keeps inserting throughout this stage. The pause exists
//             so the per-batch row locks and the WAL burst never queue up
//             behind ingest for long.
//
//   Stage 3 — DELETE the device row, in ONE short transaction.
//             By now every large child population is already gone or already
//             unlinked, so the exclusive lock on the `devices` row is held for
//             milliseconds instead of four minutes.
//
// ⛔ HOW STAGE 3 MAKES 23505 IMPOSSIBLE BY CONSTRUCTION, not by luck. Stage 1
// runs minutes before stage 3, and the collector's rollup sweep runs every few
// minutes — so a fresh `syslog_rollup_hourly` row for this device can appear in
// the gap and re-arm the exact same collision. Stage 3 therefore, inside one
// transaction and in this order:
//     SELECT ... FROM devices WHERE id = $1 FOR UPDATE
//     DELETE FROM syslog_rollup_hourly WHERE device_id = $1
//     DELETE FROM devices WHERE id = $1
// FOR UPDATE conflicts with the FOR KEY SHARE lock that any INSERT/UPDATE
// referencing this device must take, so from that moment nothing new can
// reference the device. The mop-up DELETE then removes anything that landed in
// the gap, and only then does the device row go. There is no window in which a
// referencing rollup row can exist when the SET NULL fires.
//
// ⛔ RESUMABLE AND IDEMPOTENT. Every stage is `WHERE device_id = $1` and
// converges to zero rows, so re-running a failed job re-does only what is left.
// Stage 3 finding the device already absent is reported as such — the desired
// end state, reached by an earlier attempt — never as a fresh deletion.
//
// ⛔ NEVER REPORTS SUCCESS IT DID NOT OBSERVE. A stage that throws aborts the
// job with a message that names the stage AND states exactly what had already
// completed, so a partial delete reads as a partial delete. The engine never
// swallows an error to reach the end of the function.
//
// The table names below are hardcoded module constants, never anything derived
// from a request; every VALUE is parameterized. SQL cannot parameterize an
// identifier, so a constant list is the only way to express "these eleven
// tables" — that is why the list is frozen and why adding to it is a code
// change, not configuration.
//
// CommonJS — services/engine-worker.js require()s this under plain node.

'use strict';

// ── The derived hourly rollups, ALL of them ───────────────────────────────
// Ten of these eleven are ON DELETE CASCADE and would clean themselves up at
// stage 3; only `syslog_rollup_hourly` is SET NULL and only it can raise
// 23505. They are all listed anyway, deliberately: emptying them in bounded
// batches BEFORE the device row goes is what keeps stage 3's exclusive lock on
// the `devices` row short, which is problem 2 above. A cascade that deletes
// 256,000 rows while holding that lock is the same outage in a different
// costume.
//
// ⛔ `syslog_rollup_hourly` is FIRST on purpose. It is the one that can fail
// the whole delete, so it is the one that gets done while there is the most
// time left to notice.
const ROLLUP_TABLES = [
  'syslog_rollup_hourly',
  'syslog_rule_hits_hourly',
  'syslog_talker_hourly',
  'syslog_app_hourly',
  'syslog_blocked_dst_hourly',
  'syslog_device_inbound_hourly',
  'syslog_country_hourly',
  'syslog_user_hourly',
  'syslog_urlcat_hourly',
  'syslog_vpn_auth_hourly',
  'syslog_threat_hourly',
];

// ⛔ The ONE table whose FK is SET NULL *and* whose unique key is NULLS NOT
// DISTINCT — i.e. the one that produced the 23505. Named separately because
// stage 3's in-transaction mop-up must target exactly it, and because a future
// table joining this club needs to be added here as well as above.
const COLLIDING_ROLLUP_TABLE = 'syslog_rollup_hourly';

const DEFAULTS = {
  // Bounded so no single statement can take a long lock or a long WAL burst.
  // Rollup populations measured live are hundreds to tens of thousands of rows
  // per device, so these finish in a handful of iterations.
  rollupBatchSize: 5000,
  // Raw events are the big one (3.35M for a single device, measured). Batches
  // are larger because each row change is tiny, and the pause below is what
  // actually yields to the collector.
  eventBatchSize: 20000,
  eventPauseMs: 200,
  // A hard stop on the loop so a bug that fails to make progress cannot spin
  // forever against production. Generous: 3.35M events / 20k = 168 iterations.
  maxBatchesPerTable: 5000,
  // Exact COUNT(*) on syslog_events for one device does NOT complete in 8
  // seconds on this fleet (measured 2026-09-09 against the busiest device, 20.8M
  // events). The job may spend longer than a page load can; the UI must not.
  exactCountTimeoutMs: 60000,
};

/** Thrown by runDeviceDeleteJob. `.summary` carries what HAD completed. */
class DeviceDeleteError extends Error {
  constructor(message, { stage, summary, cause } = {}) {
    super(message);
    this.name = 'DeviceDeleteError';
    this.stage = stage || null;
    this.summary = summary || null;
    if (cause) this.cause = cause;
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function toCount(value) {
  if (value === null || value === undefined) return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

// ──────────────────────────────────────────────────────────────────────────
// Sizing — what the operator is told BEFORE they commit
// ──────────────────────────────────────────────────────────────────────────

/**
 * Exact per-table counts of the derived rollup rows that will be DELETED.
 *
 * These are small and indexed, so an exact answer is affordable and the
 * operator gets a real number rather than an estimate. A table that fails to
 * count (most plausibly because it has not been migrated onto this server yet)
 * records `null` for itself and sets `partial` — ⛔ never 0, which would read
 * as "nothing to delete here" and understate an irreversible action.
 */
async function countRollupRows(pool, deviceId) {
  const perTable = {};
  let total = 0;
  let partial = false;
  for (const table of ROLLUP_TABLES) {
    try {
      const { rows } = await pool.query(
        `SELECT count(*)::bigint AS n FROM ${table} WHERE device_id = $1`,
        [deviceId]
      );
      const n = toCount(rows && rows[0] ? rows[0].n : null);
      perTable[table] = n;
      if (n === null) partial = true;
      else total += n;
    } catch (err) {
      perTable[table] = null;
      partial = true;
    }
  }
  return { total: partial ? null : total, countedTotal: total, perTable, partial };
}

/**
 * How many raw syslog events this device owns.
 *
 * ⛔ TRI-STATE, and the `exact` flag is load-bearing. An exact COUNT(*) over the
 * partitioned raw table was measured at OVER 8 SECONDS (statement timeout, did
 * not complete) for a device with 20.8M events, so:
 *   - `exact: true`  — a real COUNT(*) came back inside the budget.
 *   - `exact: false` — derived by summing `syslog_rollup_hourly.event_count`,
 *                      which is the aggregate of the same events. It covers ALL
 *                      history while the raw table keeps ~30 days, so it is an
 *                      UPPER bound, not a measurement. Every caller must render
 *                      it as approximate.
 *   - `value: null`  — neither worked. NOT zero. "We could not count this" is
 *                      not "there is nothing to count".
 *
 * `timeoutMs <= 0` skips the exact attempt entirely — what a page render passes,
 * because no dialog may stall eight seconds on a count.
 */
async function countSyslogEvents(pool, deviceId, options = {}) {
  const timeoutMs = options.timeoutMs === undefined ? DEFAULTS.exactCountTimeoutMs : options.timeoutMs;

  if (timeoutMs > 0 && typeof pool.connect === 'function') {
    let client;
    try {
      client = await pool.connect();
      await client.query('BEGIN');
      // SET LOCAL so the budget dies with the transaction and can never leak
      // onto the next borrower of this pooled connection.
      await client.query(`SET LOCAL statement_timeout = ${Number(timeoutMs) | 0}`);
      const { rows } = await client.query(
        'SELECT count(*)::bigint AS n FROM syslog_events WHERE device_id = $1',
        [deviceId]
      );
      await client.query('COMMIT');
      const n = toCount(rows && rows[0] ? rows[0].n : null);
      if (n !== null) return { value: n, exact: true, source: 'syslog_events' };
    } catch (err) {
      try {
        if (client) await client.query('ROLLBACK');
      } catch (_) {
        /* the transaction is already gone; the fallback below is what matters */
      }
    } finally {
      if (client && typeof client.release === 'function') client.release();
    }
  }

  try {
    const { rows } = await pool.query(
      `SELECT sum(event_count)::bigint AS n FROM ${COLLIDING_ROLLUP_TABLE} WHERE device_id = $1`,
      [deviceId]
    );
    const n = toCount(rows && rows[0] ? rows[0].n : null);
    // sum() over zero rows is NULL, which genuinely means "no rollup coverage",
    // so it stays null rather than becoming 0.
    if (n !== null) return { value: n, exact: false, source: COLLIDING_ROLLUP_TABLE };
  } catch (err) {
    /* fall through to unknown */
  }

  return { value: null, exact: false, source: null };
}

/**
 * Everything the confirm dialog must state before an irreversible action.
 * Never throws: a sizing failure must not stop an operator from being able to
 * delete a device, it must only stop us claiming a size we do not have.
 */
async function estimateDeleteImpact(pool, deviceId, options = {}) {
  const [rollupRows, syslogEvents] = await Promise.all([
    countRollupRows(pool, deviceId).catch(() => ({
      total: null,
      countedTotal: 0,
      perTable: {},
      partial: true,
    })),
    countSyslogEvents(pool, deviceId, {
      // Default for a UI caller: do not attempt the exact count.
      timeoutMs: options.exactCountTimeoutMs === undefined ? 0 : options.exactCountTimeoutMs,
    }).catch(() => ({ value: null, exact: false, source: null })),
  ]);
  return { rollupRows, syslogEvents };
}

// ──────────────────────────────────────────────────────────────────────────
// The stages
// ──────────────────────────────────────────────────────────────────────────

/**
 * Stage 1 — delete this device's rows from one derived rollup table, in
 * bounded batches. Returns the number of rows deleted.
 *
 * Every rollup here has an `id BIGSERIAL PRIMARY KEY`, so the batch is bounded
 * by selecting ids rather than by a LIMIT on the DELETE (which PostgreSQL does
 * not support).
 */
async function deleteRollupRows(pool, table, deviceId, batchSize, maxBatches, onBatch) {
  let deleted = 0;
  for (let i = 0; i < maxBatches; i += 1) {
    const { rowCount } = await pool.query(
      `DELETE FROM ${table}
             WHERE id IN (SELECT id FROM ${table} WHERE device_id = $1 ORDER BY id LIMIT $2)`,
      [deviceId, batchSize]
    );
    const n = rowCount || 0;
    deleted += n;
    if (onBatch) await onBatch(deleted);
    if (n < batchSize) return deleted;
  }
  throw new Error(
    `${table}: still returning full batches after ${maxBatches} iterations — stopped rather than looping against production`
  );
}

/**
 * Stage 2 — unlink raw events from the device, in bounded batches.
 *
 * ⛔ UPDATE, not DELETE. See the header: the logs outlive the device record.
 */
async function unlinkSyslogEvents(pool, deviceId, opts) {
  const { batchSize, pauseMs, maxBatches, onBatch } = opts;
  let updated = 0;
  for (let i = 0; i < maxBatches; i += 1) {
    const { rowCount } = await pool.query(
      `WITH batch AS (
           SELECT received_at, id FROM syslog_events WHERE device_id = $1 LIMIT $2
       )
       UPDATE syslog_events e
          SET device_id = NULL
         FROM batch b
        WHERE e.received_at = b.received_at AND e.id = b.id`,
      [deviceId, batchSize]
    );
    const n = rowCount || 0;
    updated += n;
    if (onBatch) await onBatch(updated);
    if (n < batchSize) return updated;
    // Yield. Each batch is its own transaction, so this is the window in which
    // the collector's inserts and the rollup sweep get the disk to themselves.
    if (pauseMs > 0) await sleep(pauseMs);
  }
  throw new Error(
    `syslog_events: still returning full batches after ${maxBatches} iterations — stopped rather than looping against production`
  );
}

/**
 * Stage 3 — the device row itself, in one short transaction that closes the
 * 23505 window for good. See the header for why the three statements are in
 * this order and why FOR UPDATE is not optional.
 *
 * Returns { deleted: boolean, moppedUp: number }. `deleted:false` means the row
 * was ALREADY gone — the end state we wanted, reached by an earlier attempt.
 * It is reported as such and never dressed up as a fresh deletion.
 */
async function deleteDeviceRow(pool, deviceId) {
  if (typeof pool.connect !== 'function') {
    throw new Error('deleteDeviceRow requires a pool that can check out a client (pool.connect)');
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // 1. Take the exclusive row lock FIRST. FOR UPDATE conflicts with the FOR
    //    KEY SHARE that any new referencing insert must take, so from here
    //    nothing can add a row pointing at this device.
    const locked = await client.query('SELECT id FROM devices WHERE id = $1 FOR UPDATE', [deviceId]);
    if (locked.rowCount === 0) {
      await client.query('COMMIT');
      return { deleted: false, moppedUp: 0 };
    }
    // 2. Mop up anything that landed in the gap since stage 1. This is the
    //    statement that makes the unique violation impossible rather than
    //    unlikely.
    const mop = await client.query(`DELETE FROM ${COLLIDING_ROLLUP_TABLE} WHERE device_id = $1`, [
      deviceId,
    ]);
    // 3. Only now the device row. Remaining cascades are small by construction.
    const del = await client.query('DELETE FROM devices WHERE id = $1', [deviceId]);
    await client.query('COMMIT');
    return { deleted: (del.rowCount || 0) > 0, moppedUp: mop.rowCount || 0 };
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (_) {
      /* the connection is already broken; the original error is the one to report */
    }
    throw err;
  } finally {
    if (typeof client.release === 'function') client.release();
  }
}

// ──────────────────────────────────────────────────────────────────────────
// The job
// ──────────────────────────────────────────────────────────────────────────

function describeSummary(summary) {
  const parts = [];
  parts.push(
    summary.rollupRowsDeleted === null
      ? 'rollup rows: not reached'
      : `${summary.rollupRowsDeleted.toLocaleString('en-US')} rollup rows deleted`
  );
  parts.push(
    summary.eventsUnlinked === null
      ? 'raw events: not reached'
      : `${summary.eventsUnlinked.toLocaleString('en-US')} raw events unlinked (kept)`
  );
  if (summary.deviceRowDeleted === true) parts.push('device row deleted');
  else if (summary.deviceRowDeleted === false) parts.push('device row was already absent');
  else parts.push('device row: not reached');
  return parts.join('; ');
}

/**
 * Run a `device_delete` job to completion.
 *
 * ⛔ THIS IS THE INTEGRATION SEAM for services/engine-worker.js. The worker
 * claims the job (backgroundJobs.claimNextJob), calls this, and then — and only
 * then — writes the terminal status itself:
 *
 *   const job = await claimNextJob(pool, ['device_delete']);
 *   try {
 *     const summary = await runDeviceDeleteJob(pool, job, {
 *       onProgress: (p) => reportProgress(pool, job.id, p),
 *     });
 *     await finishJob(pool, job.id, 'succeeded', { detail: summary.detail });
 *   } catch (err) {
 *     await finishJob(pool, job.id, 'failed', { error: err.message });
 *   }
 *
 * This engine deliberately does NOT call finishJob itself: the worker owns the
 * claim, so the worker owns the close-out, and nothing else may write
 * 'succeeded'. `err.message` on failure already names the stage AND states what
 * had completed, so even the naive catch above is truthful about a partial
 * delete.
 *
 * @param {object} pool     pg pool (needs .query and .connect)
 * @param {object} job      the claimed background_jobs row ({ id, device_id })
 * @param {object} options  { onProgress({current,total,detail}), ...batch overrides }
 * @returns {Promise<object>} summary
 * @throws {DeviceDeleteError} with .stage and .summary on any stage failure
 */
async function runDeviceDeleteJob(pool, job, options = {}) {
  const deviceId = job && (job.device_id || job.deviceId);
  if (!deviceId) throw new Error('runDeviceDeleteJob: job has no device_id');

  const cfg = { ...DEFAULTS, ...options };
  const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
  const report = async (payload) => {
    if (!onProgress) return;
    // ⛔ A progress-reporting failure must never fail a delete that is working.
    try {
      await onProgress(payload);
    } catch (_) {
      /* progress is a courtesy; the work is the contract */
    }
  };

  const summary = {
    deviceId,
    rollupRowsDeleted: null,
    rollupPerTable: {},
    eventsUnlinked: null,
    deviceRowDeleted: null,
    moppedUpRollupRows: 0,
    eventTotal: null,
    eventTotalExact: false,
    detail: null,
  };

  // ── Stage 1 ──────────────────────────────────────────────────────────────
  await report({ current: null, total: null, detail: 'Removing derived rollup data…' });
  let rollupDeleted = 0;
  for (const table of ROLLUP_TABLES) {
    // ⛔ Partial progress within a table counts. If the sixth table throws
    // halfway, the five before it and that table's own completed batches are
    // already committed, and the failure message has to say so.
    let inTable = 0;
    try {
      const n = await deleteRollupRows(
        pool,
        table,
        deviceId,
        cfg.rollupBatchSize,
        cfg.maxBatchesPerTable,
        (done) => {
          inTable = done;
          summary.rollupRowsDeleted = rollupDeleted + done;
        }
      );
      summary.rollupPerTable[table] = n;
      rollupDeleted += n;
      summary.rollupRowsDeleted = rollupDeleted;
      await report({
        current: null,
        total: null,
        detail: `Removing derived rollup data… ${rollupDeleted.toLocaleString('en-US')} rows removed`,
      });
    } catch (err) {
      summary.rollupPerTable[table] = inTable;
      summary.rollupRowsDeleted = rollupDeleted + inTable;
      summary.detail = describeSummary(summary);
      throw new DeviceDeleteError(
        `Delete stopped while clearing ${table}: ${err.message}. The device was NOT deleted. Completed so far — ${summary.detail}. Re-running the delete resumes from here.`,
        { stage: 'rollups', summary, cause: err }
      );
    }
  }

  // ── Stage 2 ──────────────────────────────────────────────────────────────
  // Size it first so the progress bar can be real. ⛔ A total we could not
  // measure stays NULL — backgroundJobs.reportProgress treats NULL as "not
  // known yet", and a bar that renders unknown as 0/0 reads as finished.
  const counted = await countSyslogEvents(pool, deviceId, { timeoutMs: cfg.exactCountTimeoutMs }).catch(
    () => ({ value: null, exact: false, source: null })
  );
  summary.eventTotal = counted.value;
  summary.eventTotalExact = counted.exact;
  const total = counted.exact ? counted.value : null;
  await report({
    current: 0,
    total,
    detail: counted.exact
      ? `Unlinking ${counted.value.toLocaleString('en-US')} raw syslog events (the events are kept)…`
      : 'Unlinking raw syslog events (the events are kept; the exact total could not be counted cheaply)…',
  });

  try {
    summary.eventsUnlinked = 0;
    summary.eventsUnlinked = await unlinkSyslogEvents(pool, deviceId, {
      batchSize: cfg.eventBatchSize,
      pauseMs: cfg.eventPauseMs,
      maxBatches: cfg.maxBatchesPerTable,
      onBatch: async (done) => {
        // Each batch is its own committed transaction, so this count is a fact
        // on disk, not an intention — it stays in the summary even if a later
        // batch throws.
        summary.eventsUnlinked = done;
        await report({
          current: done,
          total,
          detail: `Unlinking raw syslog events… ${done.toLocaleString('en-US')} done (the events are kept)`,
        });
      },
    });
  } catch (err) {
    summary.detail = describeSummary(summary);
    throw new DeviceDeleteError(
      `Delete stopped while unlinking raw syslog events: ${err.message}. The device was NOT deleted and its remaining events still point at it. Completed so far — ${summary.detail}. Re-running the delete resumes from here.`,
      { stage: 'events', summary, cause: err }
    );
  }

  // ── Stage 3 ──────────────────────────────────────────────────────────────
  await report({ current: null, total, detail: 'Removing the device record…' });
  try {
    const result = await deleteDeviceRow(pool, deviceId);
    summary.deviceRowDeleted = result.deleted;
    summary.moppedUpRollupRows = result.moppedUp;
  } catch (err) {
    summary.detail = describeSummary(summary);
    throw new DeviceDeleteError(
      `Delete stopped while removing the device record: ${err.message}. Its syslog history has already been cleared, but the device record REMAINS. Completed so far — ${summary.detail}. Re-running the delete finishes the job.`,
      { stage: 'device', summary, cause: err }
    );
  }

  summary.detail = describeSummary(summary);
  return summary;
}

module.exports = {
  ROLLUP_TABLES,
  COLLIDING_ROLLUP_TABLE,
  DEFAULTS,
  DeviceDeleteError,
  countRollupRows,
  countSyslogEvents,
  estimateDeleteImpact,
  deleteRollupRows,
  unlinkSyslogEvents,
  deleteDeviceRow,
  describeSummary,
  runDeviceDeleteJob,
};
