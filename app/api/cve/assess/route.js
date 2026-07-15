import { pool } from '../../../../lib/db';
import { runMatchForAllDevices } from '../../../../lib/engines/versionMatcher';

export const dynamic = 'force-dynamic';

// Phase 1+2: synchronous await is acceptable here -- see app/api/feeds/sync/route.js
// for the same reasoning (small Forcepoint-only fleet, request completes well within
// a normal request lifetime).
export async function POST(request) {
  try {
    const result = await runMatchForAllDevices(pool);
    return Response.json(result);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
