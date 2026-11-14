// lib/engines/backgroundJobs.js
//
// Work that must not run on the request path. The API enqueues,
// services/engine-worker.js executes, the UI polls.
//
// ⛔ WHY THIS EXISTS, both reasons measured on the live fleet 2026-09-09:
//
// 1. DELETE. Removing a device rewrites every syslog row it owns — 3,352,437
//    rows across 47 GB of partitions for one device — and holds an exclusive
//    row lock on `devices` throughout. The COLLECTOR needs a KEY SHARE lock on
//    that same row to insert ANY event for the device, so a synchronous delete
//    stalls log ingestion. The operator meanwhile sees a button that does
//    nothing for four minutes.
// 2. COLLECT. collectAndStore runs getVersion + getRules + getConfig in
//    sequence, each to its own adapter timeout (PAN-OS budgets 120s for
//    getConfig alone). A live Collect Now took 111 seconds.
//
// ⛔ THE WORKER RUNS THESE, NOT THE APP. A deploy restarts SecVault-App at any
// moment, and a half-finished delete owned by a dead HTTP request is precisely
// the state nothing can report on afterwards. The engine is also where every
// other long job already lives.
//
// CommonJS — required by services/engine-worker.js under plain node.

'use strict';

const JOB_TYPES = new Set(['device_delete', 'device_collect']);
const TERMINAL = new Set(['succeeded', 'failed', 'cancelled']);

// A job whose worker died leaves a row saying 'running' forever. Reaped to
// 'failed' with a reason at engine startup and periodically.
// ⛔ Never reaped to 'succeeded'. "The process that was doing this disappeared"
// is not evidence the work completed — it is the absence of evidence either
// way, and this is a delete.
const STALE_RUNNING_MINUTES = 30;

/**
 * Queue a job. Returns the existing live job instead of creating a second one.
 *
 * ⛔ Deduplication is a PARTIAL UNIQUE INDEX in the schema, not a check here.
 * On 2026-09-09 an operator clicked Delete twice; the second DELETE queued
 * behind the first and both were doomed. An app-level "is one already running?"
 * read is racy by construction — two requests can both read "no" before either
 * writes. The index is what actually holds.
 */
async function enqueueJob(pool, { jobType, deviceId, requestedBy, detail }) {
  if (!JOB_TYPES.has(jobType)) throw new Error(`Unknown job type: ${jobType}`);
  if (!deviceId) throw new Error('deviceId is required');

  const { rows } = await pool.query(
    `INSERT INTO background_jobs (job_type, device_id, requested_by, detail, status)
          VALUES ($1, $2, $3, $4, 'queued')
     ON CONFLICT (job_type, device_id) WHERE status IN ('queued', 'running')
     DO NOTHING
       RETURNING *`,
    [jobType, deviceId, requestedBy || null, detail || null]
  );
  if (rows.length > 0) return { job: rows[0], created: true };

  // Lost the race, or one was already live — hand back the incumbent so the
  // caller can poll it rather than reporting a spurious failure.
  const { rows: existing } = await pool.query(
    `SELECT * FROM background_jobs
      WHERE job_type = $1 AND device_id = $2 AND status IN ('queued', 'running')
      ORDER BY created_at DESC LIMIT 1`,
    [jobType, deviceId]
  );
  return { job: existing[0] || null, created: false };
}

/**
 * Atomically claim the oldest queued job. Returns null when there is nothing
 * to do.
 *
 * ⛔ The UPDATE ... WHERE id = (SELECT ... FOR UPDATE SKIP LOCKED) form is the
 * claim; two workers must never run the same delete.
 */
async function claimNextJob(pool, jobTypes) {
  const types = Array.isArray(jobTypes) && jobTypes.length ? jobTypes : [...JOB_TYPES];
  const { rows } = await pool.query(
    `UPDATE background_jobs
        SET status = 'running', started_at = now()
      WHERE id = (
            SELECT id FROM background_jobs
             WHERE status = 'queued' AND job_type = ANY($1::text[])
             ORDER BY created_at
             FOR UPDATE SKIP LOCKED
             LIMIT 1)
      RETURNING *`,
    [types]
  );
  return rows[0] || null;
}

/**
 * Report progress. Both counts are nullable and stay that way.
 *
 * ⛔ `total` NULL means the size is NOT KNOWN YET, never zero. A progress bar
 * that renders unknown as 0/0 reads as finished — the failed-read-as-a-fact
 * rule applied to a progress indicator.
 */
async function reportProgress(pool, jobId, { current, total, detail }) {
  // ⛔ `progress_at` IS WHAT MAKES THE REAPER HONEST. It used to key on
  // `started_at`, so a job reporting progress every batch was still declared
  // failed at 30 minutes — see reapStaleJobs below for the measurement.
  const { rowCount } = await pool.query(
    `UPDATE background_jobs
        SET progress_current = COALESCE($2::bigint, progress_current),
            progress_total   = COALESCE($3::bigint, progress_total),
            detail           = COALESCE($4, detail),
            progress_at      = now()
      WHERE id = $1 AND status = 'running'`,
    [
      jobId,
      current === null || current === undefined ? null : String(current),
      total === null || total === undefined ? null : String(total),
      detail || null,
    ]
  );
  // ⛔ RETURNED, NOT SWALLOWED. `AND status = 'running'` means a job that has
  // already been reaped silently discards every later update — the UI freezes
  // on a `failed` row while the work carries on. The guard is right (nothing
  // should resurrect a terminal row by writing progress to it) but a write that
  // did not land must not report success: this codebase's own rule. Callers can
  // now see it; `applied: false` means "this job is no longer running".
  return { applied: rowCount > 0 };
}

/**
 * Close a job out. `status` must be stated explicitly by the caller.
 *
 * ⛔ A JOB THAT WAS ALREADY REAPED KEEPS THAT ON ITS RECORD. There was no
 * terminal-status guard at all: `WHERE id = $1` overwrote a reaped `failed`
 * with a later `succeeded` and left nothing to say the row had ever been
 * declared dead, so the one trace of a reaper that fired wrongly was erased by
 * the work finishing.
 *
 * ⛔ IT STILL WRITES THE NEW STATUS, AND REFUSING WOULD BE THE WORSE BUG. The
 * reap says "whether the work completed is unknown — re-run it to be sure"; a
 * worker then reporting a real result IS the evidence the reap did not have, so
 * the result must win. What may not happen is the overwrite being SILENT, so
 * the previous terminal verdict is appended to `detail` and `reaped` is
 * returned. Preserve the history, not the guess.
 */
async function finishJob(pool, jobId, status, { error, detail } = {}) {
  if (!TERMINAL.has(status)) throw new Error(`Not a terminal status: ${status}`);
  // The CTE captures the status BEFORE the write, in the same statement, so
  // there is no check-then-act window. FOR UPDATE because the reaper may be
  // writing the same row.
  const { rows } = await pool.query(
    `WITH prev AS (
         SELECT id, status AS old_status FROM background_jobs WHERE id = $1 FOR UPDATE
     )
     UPDATE background_jobs j
        SET status = $2, finished_at = now(), error = $3,
            detail = CASE
              WHEN p.old_status IN ('succeeded', 'failed', 'cancelled')
                THEN COALESCE(COALESCE($4, j.detail) || ' ', '')
                     || '(This job had already been recorded as ' || p.old_status
                     || ' before the worker reported a result. The result above is what the '
                     || 'worker actually returned; it arrived after that earlier verdict.)'
              ELSE COALESCE($4, j.detail)
            END
       FROM prev p
      WHERE j.id = p.id
      RETURNING j.*, p.old_status AS previous_status`,
    [jobId, status, error || null, detail || null]
  );
  return rows[0] || null;
}

/**
 * Mark jobs whose worker vanished as failed.
 *
 * ⛔ 'failed' with an explicit reason, never 'succeeded' and never left
 * 'running'. A stuck 'running' row is indistinguishable from work in progress,
 * so the UI would spin forever; a silent 'succeeded' on a DELETE would claim a
 * device was removed when it may not have been.
 */
async function reapStaleJobs(pool, minutes) {
  const mins = Number.isFinite(Number(minutes)) ? Number(minutes) : STALE_RUNNING_MINUTES;
  const { rows } = await pool.query(
    `UPDATE background_jobs
        SET status = 'failed', finished_at = now(),
            error = 'The worker running this job stopped reporting progress before it reported '
                 || 'a result. Whether the work completed is unknown — re-run it to be sure.'
      WHERE status = 'running'
        -- LAST PROGRESS, NOT START TIME: a job working perfectly and
        -- reporting every batch was declared failed on a fixed clock from the
        -- moment it began. COALESCE falls back to started_at for a job that has
        -- not reported yet -- the only case where the start IS the last sign of
        -- life. (No backticks in here: this sits inside a JS template literal
        -- and one would terminate the string.)
        AND COALESCE(progress_at, started_at) < now() - ($1::int * interval '1 minute')
      RETURNING id, job_type, device_id, progress_current, progress_at`,
    [mins]
  );
  return rows;
}

async function getJob(pool, jobId) {
  const { rows } = await pool.query('SELECT * FROM background_jobs WHERE id = $1', [jobId]);
  return rows[0] || null;
}

/** The live (queued/running) job for a device, if any — what the UI polls. */
async function getLiveJobForDevice(pool, deviceId, jobType) {
  const { rows } = await pool.query(
    `SELECT * FROM background_jobs
      WHERE device_id = $1
        AND ($2::text IS NULL OR job_type = $2)
        AND status IN ('queued', 'running')
      ORDER BY created_at DESC LIMIT 1`,
    [deviceId, jobType || null]
  );
  return rows[0] || null;
}

/** Most recent job of a type for a device, live or finished. */
async function getLatestJobForDevice(pool, deviceId, jobType) {
  const { rows } = await pool.query(
    `SELECT * FROM background_jobs
      WHERE device_id = $1 AND ($2::text IS NULL OR job_type = $2)
      ORDER BY created_at DESC LIMIT 1`,
    [deviceId, jobType || null]
  );
  return rows[0] || null;
}

/**
 * Recent jobs across the whole fleet, newest first — the job centre's feed.
 *
 * ⛔ THIS IS THE ONLY WAY TO SEE A JOB YOU DID NOT JUST START. Until now the
 * only reads were by job id or by DEVICE id, so a collect or a delete was
 * visible on exactly one page: the one that started it. Navigate away and the
 * job continued with nothing in the product able to tell you how it ended —
 * including when it FAILED, which is the case that matters.
 *
 * ⛔ LIVE JOBS FIRST, THEN RECENT HISTORY, in one query rather than two. Two
 * queries can disagree: a job finishing between them appears in neither list
 * or in both, and "in neither" is a job that silently vanishes from a panel
 * whose whole purpose is not losing track of it.
 *
 * ⛔ THE DEVICE NAME IS LEFT-JOINED, NOT REQUIRED. `background_jobs.device_id`
 * is ON DELETE SET NULL, and a completed DELETE job is precisely the case
 * where the device is gone — the one job you most want to still see.
 */
async function listRecentJobs(pool, { limit = 20 } = {}) {
  // ⛔ A NEGATIVE LIMIT FALLS BACK TO THE DEFAULT, NOT TO 1. `Number(-5) || 20`
  // is -5 (truthy), so the old `Math.max(..., 1)` turned it into ONE row — a
  // list of one job presented as "recent background jobs", which is a truncated
  // list that looks complete, the more insidious failure this codebase names.
  // Not reachable today (the route hardcodes 20), which is exactly when a sharp
  // edge is cheapest to remove.
  const asked = Number(limit);
  const n = Math.min(Number.isFinite(asked) && asked >= 1 ? Math.floor(asked) : 20, 100);
  const { rows } = await pool.query(
    `SELECT j.id, j.job_type, j.device_id, j.status, j.progress_current,
            j.progress_total, j.detail, j.error, j.requested_by,
            j.created_at, j.started_at, j.finished_at,
            d.name AS device_name
       FROM background_jobs j
       LEFT JOIN devices d ON d.id = j.device_id
      ORDER BY (j.status IN ('queued', 'running')) DESC, j.created_at DESC
      LIMIT $1`,
    [n]
  );
  return rows;
}

module.exports = {
  JOB_TYPES,
  TERMINAL,
  STALE_RUNNING_MINUTES,
  enqueueJob,
  claimNextJob,
  reportProgress,
  finishJob,
  reapStaleJobs,
  getJob,
  getLiveJobForDevice,
  getLatestJobForDevice,
  listRecentJobs,
};
