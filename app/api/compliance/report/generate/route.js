import { NextResponse } from 'next/server';
import { pool } from '../../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../../lib/rbac';
import { dispatchMonthlyReport } from '../../../../../lib/engines/complianceReport';

export const dynamic = 'force-dynamic';

// POST /api/compliance/report/generate — admin-gated manual trigger for the
// SAME generate -> email every matching notification_channels row -> write
// compliance_report_log flow services/engine-worker.js's scheduled monthly
// job uses (see lib/engines/complianceReport.js's dispatchMonthlyReport —
// one shared code path, not a second implementation). Still respects the
// per-calendar-month idempotency check; this is an "ops send it now" and
// "test the pipeline" tool, not a way to force a second send this month.
export async function POST() {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  try {
    const result = await dispatchMonthlyReport(pool);
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to generate/send compliance report' },
      { status: 500 }
    );
  }
}
