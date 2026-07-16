import { pool } from '../../../../lib/db';
import { runFullSync } from '../../../../lib/feeds';

export const dynamic = 'force-dynamic';

// Phase 1+2: synchronous await is acceptable here — a full sync (one NVD CPE query per
// vendor across all 6 Tier 1 vendors, plus one KEV JSON download) still completes well
// within a normal request lifetime given today's fleet size. A future phase could turn
// this into a fire-and-forget background job (return a job id immediately, let
// SecVault-Engine's scheduled worker or a queue do the actual work, and poll
// /api/feeds/status) if sync duration grows — e.g. once the fleet grows much larger,
// not specifically tied to vendor count (NVD sync already loops all 6 vendors today).
export async function POST(request) {
  try {
    const result = await runFullSync(pool);
    return Response.json(result);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
