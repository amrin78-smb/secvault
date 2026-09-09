import { pool } from '../../../../../lib/db';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../../lib/rbac';
import { enqueueJob } from '../../../../../lib/engines/backgroundJobs';

export const dynamic = 'force-dynamic';

// POST /api/devices/[id]/collect — ENQUEUE an on-demand version + rules + config
// pull for a single device. Returns immediately with a job id.
//
// ⛔ THIS ROUTE NO LONGER COLLECTS ANYTHING, and that is the point. It used to
// `await collectAndStore(device, pool)` inline. collectAndStore runs getVersion
// + getRules + getConfig in sequence, each to its own adapter timeout (PAN-OS
// budgets 120s for getConfig alone). On 2026-09-09 a live Collect Now against a
// FortiGate ran 09:24:00–09:25:51 — 111 seconds — and this handler held the
// HTTP request open for every one of them, while the operator reported the app
// unusable. The collection itself was correct (38 rules, 44 licences, a config,
// a version); the 111-second FOREGROUND REQUEST was the bug. The exact
// client-side blocking mechanism was never conclusively proven — the server
// answered other requests in 20–90ms throughout and Postgres had zero locks and
// zero blocked queries — which is precisely why the fix is to remove the class
// of problem rather than to tune the symptom.
//
// services/engine-worker.js executes the job; the UI polls GET /api/jobs/[id].
//
// ⛔ A QUEUED JOB IS NOT A SUCCESSFUL COLLECT. The response deliberately carries
// no `ok`, no `rulesCount` and no `errors` — there is nothing measured yet, and
// a caller that read a 202 as "collected" would be inventing a result. The only
// truthful facts available here are the job id and its status.
export async function POST(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  const { id } = params;

  // ⛔ Added 2026-07-19, found in a follow-up bug sweep: a malformed id must
  // never reach pool.query() and leak a raw Postgres "invalid input syntax
  // for type uuid" 500 — same guard already applied to several sibling
  // devices/[id]/* routes, missed here.
  if (!isValidUuid(id)) {
    return Response.json({ error: 'Invalid device id' }, { status: 400 });
  }

  const deviceResult = await pool.query('SELECT id, name FROM devices WHERE id = $1', [id]);
  if (deviceResult.rows.length === 0) {
    return Response.json({ error: 'Device not found' }, { status: 404 });
  }

  try {
    // ⛔ Deduplication is the partial unique index in lib/schema.sql, not a
    // check here — enqueueJob hands back the INCUMBENT job when one is already
    // live for this (type, device), so a double-click follows the running
    // collect instead of reporting a spurious failure or starting a second SSH
    // session against the same firewall.
    const { job, created } = await enqueueJob(pool, {
      jobType: 'device_collect',
      deviceId: id,
      requestedBy: session?.user?.name || session?.user?.email || session?.user?.id || null,
      detail: JSON.stringify({ message: 'Queued — waiting for the collector to pick it up.' }),
    });

    if (!job) {
      return Response.json(
        { error: 'Could not queue the collect. Nothing was collected — try again.' },
        { status: 500 }
      );
    }

    return Response.json(
      {
        jobId: job.id,
        jobType: job.job_type,
        // 'queued' or, when we joined an already-live job, possibly 'running'.
        status: job.status,
        // false => an identical collect was already in flight and this request
        // attached to it rather than starting a second one.
        created,
        pollUrl: `/api/jobs/${job.id}`,
      },
      { status: 202 }
    );
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
