import { getServerSession } from 'next-auth/next';
import { pool } from '../../../../lib/db';
import { authOptions } from '../../auth/[...nextauth]/route';
import { isValidUuid } from '../../../../lib/apiUtils';
import { getJob, TERMINAL } from '../../../../lib/engines/backgroundJobs';

export const dynamic = 'force-dynamic';

// GET /api/jobs/[id] — status of one background job, polled by the UI while a
// Collect Now (or a device delete) runs in services/engine-worker.js.
//
// ⛔ NOT ADMIN-GATED, deliberately. CLAUDE.md's RBAC rule gates MUTATIONS of
// shared system state; this is a read of a status row and gates nothing. It is
// still AUTHENTICATED — job rows carry device ids and operator names.

// ⛔ TRI-STATE, and the single most important line in this file.
// progress_current/progress_total are BIGINT and NULLABLE, and pg returns
// BIGINT as a STRING. NULL means "the size is not known", NEVER zero — a
// progress bar rendering unknown as 0/0 reads as finished. So this maps
// null/undefined to null and never to 0; `Number(v) || 0` here would be the
// failed-read-as-a-fact bug applied to a progress indicator.
function numOrNull(value) {
  if (value === null || value === undefined) return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

// A finished job's structured result is carried in `detail` as JSON, because
// background_jobs has no JSON column and the collect result is TRI-STATE:
// rulesCount is null when the rule pull FAILED and a number (including a
// genuine 0) when it succeeded. JSON is what carries that null across the wire
// intact — a rendered sentence could not be re-read, and anything that reduced
// it to "a count" would report a failed pull as "0 rules".
//
// Progress updates from a job that writes plain text (a delete's onProgress,
// say) are NOT JSON, so a non-JSON detail is passed through as a message.
function normalizeDetail(detail) {
  if (typeof detail !== 'string' || detail.trim() === '') {
    return { message: null, result: null };
  }
  const trimmed = detail.trim();
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return {
          message: typeof parsed.message === 'string' ? parsed.message : null,
          result: parsed,
        };
      }
    } catch (err) {
      // Not JSON after all — fall through and treat it as plain progress text.
    }
  }
  return { message: detail, result: null };
}

export async function GET(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { id } = params;
  if (!isValidUuid(id)) {
    return Response.json({ error: 'Invalid job id' }, { status: 400 });
  }

  let job;
  try {
    job = await getJob(pool, id);
  } catch (err) {
    // ⛔ A failed READ of the status is not a failed JOB. The client must render
    // this as "status unknown", never as "the collect failed" — the work may
    // well be running perfectly.
    return Response.json({ error: `Could not read job status: ${err.message}` }, { status: 500 });
  }

  if (!job) {
    return Response.json({ error: 'Job not found' }, { status: 404 });
  }

  const { message, result } = normalizeDetail(job.detail);

  return Response.json({
    id: job.id,
    jobType: job.job_type,
    deviceId: job.device_id,
    status: job.status,
    // queued and running are NOT terminal, and neither is a success.
    terminal: TERMINAL.has(job.status),
    progressCurrent: numOrNull(job.progress_current),
    progressTotal: numOrNull(job.progress_total),
    message,
    result,
    error: job.error || null,
    requestedBy: job.requested_by || null,
    createdAt: job.created_at,
    startedAt: job.started_at,
    finishedAt: job.finished_at,
  });
}
