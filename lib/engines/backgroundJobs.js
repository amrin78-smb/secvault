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
  await pool.query(
    `UPDATE background_jobs
        SET progress_current = COALESCE($2::bigint, progress_current),
            progress_total   = COALESCE($3::bigint, progress_total),
            detail           = COALESCE($4, detail)
      WHERE id = $1 AND status = 'running'`,
    [
      jobId,
      current === null || current === undefined ? null : String(current),
      total === null || total === undefined ? null : String(total),
      detail || null,
    ]
  );
}

/** Close a job out. `status` must be stated explicitly by the caller. */
async function finishJob(pool, jobId, status, { error, detail } = {}) {
  if (!TERMINAL.has(status)) throw new Error(`Not a terminal status: ${status}`);
  const { rows } = await pool.query(
    `UPDATE background_jobs
        SET status = $2, finished_at = now(),
            error = $3, detail = COALESCE($4, detail)
      WHERE id = $1
      RETURNING *`,
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
            error = 'The worker running this job stopped before it reported a result. '
                 || 'Whether the work completed is unknown — re-run it to be sure.'
      WHERE status = 'running'
        AND started_at < now() - ($1::int * interval '1 minute')
      RETURNING id, job_type, device_id`,
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
};
