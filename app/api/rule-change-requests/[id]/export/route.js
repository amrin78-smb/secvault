import { getServerSession } from 'next-auth/next';
import { pool } from '../../../../../lib/db';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { isValidUuid } from '../../../../../lib/apiUtils';
import {
  generateRequestCsv,
  generateRequestPdf,
} from '../../../../../lib/engines/ruleChangeRequestReport';

export const dynamic = 'force-dynamic';

// GET /api/rule-change-requests/[id]/export?format=pdf|csv
//
// The change-request DOCUMENT — the artefact that leaves SecVault and is read
// by a change board, a vendor or a NOC engineer with no account here. Both
// formats come from one data build (lib/engines/ruleChangeRequestReport.js), so
// the PDF a reviewer signs and the CSV a spreadsheet imports can never disagree
// about the evidence.
//
// ⛔ NOT ADMIN-GATED, but it DOES require a session. Same reading as
// GET /api/compliance/report/pdf: exporting is a pure read of already-collected
// data and persists nothing, and CLAUDE.md's RBAC rule gates MUTATIONS of
// shared state. A viewer who can see the request on screen can print it. What
// this route must not be is anonymous — it names firewalls, management IPs and
// rule names, so the session check is explicit here rather than left entirely
// to middleware.js.
//
// ⛔ Renders live rather than caching. The verification outcomes change with
// every successful rules collection, and a cached document that still says
// "pending" after the change was confirmed is worse than a slow one.
export async function GET(request, { params }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = params;
    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid request id' }, { status: 400 });
    }

    const format = (new URL(request.url).searchParams.get('format') || 'pdf').toLowerCase();
    if (format !== 'pdf' && format !== 'csv') {
      return Response.json({ error: "format must be 'pdf' or 'csv'" }, { status: 400 });
    }

    // Short, stable, filesystem-safe — the reference the reviewer quotes back.
    const ref = id.slice(0, 8);

    if (format === 'csv') {
      const csv = await generateRequestCsv(pool, id);
      if (csv === null) {
        return Response.json({ error: 'Request not found' }, { status: 404 });
      }
      return new Response(csv, {
        status: 200,
        headers: {
          // charset matters: rule names carry non-ASCII from vendor configs.
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': `attachment; filename="secvault-rule-change-request-${ref}.csv"`,
          'Cache-Control': 'no-store',
        },
      });
    }

    const pdf = await generateRequestPdf(pool, id);
    if (pdf === null) {
      return Response.json({ error: 'Request not found' }, { status: 404 });
    }
    return new Response(pdf, {
      status: 200,
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="secvault-rule-change-request-${ref}.pdf"`,
        'Cache-Control': 'no-store',
      },
    });
  } catch (err) {
    return Response.json(
      { error: err.message || 'Failed to export rule change request' },
      { status: 500 }
    );
  }
}
