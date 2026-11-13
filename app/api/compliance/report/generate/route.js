import { NextResponse } from 'next/server';
import { pool } from '../../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { can, MANAGE_SETTINGS, forbiddenResponse } from '../../../../../lib/rbac';
import { dispatchMonthlyReport } from '../../../../../lib/engines/complianceReport';

export const dynamic = 'force-dynamic';

// POST /api/compliance/report/generate — manual trigger for the SAME
// generate -> email every matching notification_channels row -> write
// compliance_report_log flow services/engine-worker.js's scheduled monthly
// job uses (see lib/engines/complianceReport.js's dispatchMonthlyReport —
// one shared code path, not a second implementation). Still respects the
// per-calendar-month idempotency check; this is an "ops send it now" and
// "test the pipeline" tool, not a way to force a second send this month.
//
// ⛔ `manage_settings`, NOT `operate` — RAISED 2026-11-13, AND THE COMMENT HERE
// CALLED IT "admin-gated" WHILE IT WAS OPEN TO EVERY ROLE. `operate` means
// acknowledge findings, run analyses and collections, raise and verify rule
// change requests — all of which act INSIDE the product. This one MAILS a
// fleet-wide compliance PDF to a recipient list that only `manage_settings`
// can read or configure, and CLAUDE.md gates `GET /api/reports/schedules` on
// exactly that capability for exactly that reason: "a schedule names the
// recipients of fleet-wide security documents … that is installation
// configuration". If merely READING the recipient list needs
// `manage_settings`, triggering a SEND to it cannot need less.
//
// ⛔ It also closes the slot question without a schema change. A manual run
// CONSUMES the month (the partial unique index on compliance_report_log allows
// one success per calendar month), so an operator pressing this early in the
// month decided when the organisation's audit document was cut — from data as
// of that moment — and the scheduled job then found the month already claimed
// and did nothing. That is a coherent trade when the person pressing it is the
// one who configured the recipients and the cadence; it was not when it was
// anyone with a login. Splitting the slot into scheduled-vs-manual was the
// alternative and is REFUSED: it means a column plus a rebuilt partial unique
// index on a live table, so that recipients could receive the audit PDF twice
// — and reportSchedule.js's own rule is that a late report is fixed by the
// next tick while a duplicated audit PDF cannot be unsent.
//
// ⛔ No UI calls this route, so nothing on screen became stricter than its API.
export async function POST() {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) {
    return forbiddenResponse(MANAGE_SETTINGS);
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
