import { pool } from '../../../../lib/db';
import { runFullSync } from '../../../../lib/feeds';

export const dynamic = 'force-dynamic';

// Phase 1+2: synchronous await is acceptable here — a full sync (two NVD CPE queries
// against a small Forcepoint result set, plus one KEV JSON download) completes well
// within a normal request lifetime. A future phase could turn this into a
// fire-and-forget background job (return a job id immediately, let SecVault-Engine's
// scheduled worker or a queue do the actual work, and poll /api/feeds/status) if sync
// duration grows — e.g. once more vendors/feeds are added.
export async function POST(request) {
  try {
    const result = await runFullSync(pool);
    return Response.json(result);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
