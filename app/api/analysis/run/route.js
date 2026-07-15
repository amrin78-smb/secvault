import { pool } from '../../../../lib/db';
import { runAnalysisForAllDevices } from '../../../../lib/engines/ruleAnalysis';

export const dynamic = 'force-dynamic';

// POST /api/analysis/run
// Re-runs rule analysis for every active device. Synchronous await is acceptable
// here for the same reasoning as /api/cve/assess (small Forcepoint-only fleet).
export async function POST(request) {
  try {
    const result = await runAnalysisForAllDevices(pool);
    return Response.json(result);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
