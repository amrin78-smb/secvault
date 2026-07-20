import { pool } from '../../../../lib/db';
import { runAnalysisForAllDevices } from '../../../../lib/engines/ruleAnalysis';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../lib/rbac';

export const dynamic = 'force-dynamic';

// POST /api/analysis/run
// Re-runs rule analysis for every active device. Synchronous await is acceptable
// here for the same reasoning as /api/cve/assess (fleet size, not vendor count, is
// what would eventually force this to a background job).
export async function POST(request) {
  try {
    const session = await getServerSession(authOptions);
    if (!isAdmin(session)) {
      return forbiddenResponse();
    }

    const result = await runAnalysisForAllDevices(pool);
    return Response.json(result);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
