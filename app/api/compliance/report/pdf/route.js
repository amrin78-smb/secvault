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
// ⛔ STALE COMMENT CORRECTED. This said "one headless-Chromium render per
// request", which has not been true since the puppeteer-core implementation was
// replaced by pdfkit — precisely because Chromium would not launch under the
// NSSM service account. There is NO browser in this path. The cost is a
// synchronous pdfkit render.
//
// This route predates lib/reports/catalogue.js and is kept so the existing
// /compliance download link keeps working. /api/reports/compliance-fleet/pdf
// serves the same report through the registry.

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
