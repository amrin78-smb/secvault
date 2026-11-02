import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../auth/[...nextauth]/route';
import { pool } from '../../../lib/db';
import { listRecentJobs } from '../../../lib/engines/backgroundJobs';

export const dynamic = 'force-dynamic';

// GET /api/jobs — recent background jobs across the fleet, for the header's
// job panel.
//
// ⛔ AUTHENTICATED, NOT CAPABILITY-GATED, and that is a deliberate match to
// what it exposes: a job type, a device NAME, a status and a progress count.
// Every one of those is already visible to any signed-in user on the device
// page that started the job. Gating it on `manage_devices` would hide a
// FAILED collection from the operator watching the fleet, which is the person
// this panel exists for.
//
// ⛔ A SCOPED ACCOUNT IS REFUSED BY middleware.js, via the device-scope
// register — this route reads device names across the whole fleet, so it is
// classified `blocked` rather than made scope-aware. That is the register's
// default-deny rule working as designed: partial coverage degrades to LESS
// access, never more.
export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  try {
    const jobs = await listRecentJobs(pool, { limit: 20 });
    return NextResponse.json({
      jobs,
      // ⛔ COUNTED SERVER-SIDE from the same rows the client is handed, so the
      // badge and the list can never disagree. A client re-deriving it would
      // be a second implementation of one number.
      live: jobs.filter((j) => j.status === 'queued' || j.status === 'running').length,
    });
  } catch (err) {
    // ⛔ 503 AND NO `jobs` KEY, never `{jobs: []}`. An empty array is
    // indistinguishable from "nothing is running", and the panel would render
    // a confident all-clear over a database it could not read — the
    // failed-read-as-a-fact rule, aimed at the one surface whose job is to
    // say whether work is still outstanding.
    return NextResponse.json({ error: 'Could not read the job list' }, { status: 503 });
  }
}
