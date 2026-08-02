import { pool } from '../../../../../lib/db';
import { generateReportPdf } from '../../../../../lib/engines/complianceReport';

export const dynamic = 'force-dynamic';

// GET /api/compliance/report/pdf — on-demand fleet compliance PDF download.
// Ungated (no isAdmin check) — matches this app's "GET routes are never
// gated" RBAC convention; the underlying compliance data is already
// viewer-readable via GET /api/compliance/fleet and /[deviceId]. Pure
// synchronous render-and-return: does NOT write to compliance_report_log
// and does NOT email anyone (same "test-send doesn't touch the dispatch
// log" precedent as /api/notification-channels/[id]/test) — that write/send
// path belongs only to the scheduled job and POST /generate below.
//
// Accepted cost: one headless-Chromium render per request, same tradeoff
// class this app already accepts elsewhere for O(n²) rule-shadow analysis
// with no enforced throttle.
export async function GET() {
  try {
    const pdfBuffer = await generateReportPdf(pool);
    return new Response(pdfBuffer, {
      status: 200,
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': 'attachment; filename="secvault-compliance-report.pdf"',
      },
    });
  } catch (err) {
    return Response.json({ error: err.message || 'Failed to generate compliance report' }, { status: 500 });
  }
}
