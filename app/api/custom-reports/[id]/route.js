import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { pool } from '../../../../lib/db';
import { can, OPERATE, MANAGE_SETTINGS, forbiddenResponse } from '../../../../lib/rbac';
import { isValidUuid } from '../../../../lib/apiUtils';
import {
  getCustomReport,
  updateCustomReport,
  deleteCustomReport,
} from '../../../../lib/reports/customReportData';
import {
  requiredCapability,
} from '../../../../lib/reports/customReport';

export const dynamic = 'force-dynamic';

// /api/custom-reports/[id] — one saved definition.
//
// ⛔ THE CAPABILITY SPLIT IS THE SAME AS THE COLLECTION ROUTE'S: reading is the
// catalogue entry's own capability, writing is manage_settings, because the row
// belongs to the installation rather than to the session. See
// app/api/custom-reports/route.js's header for the full argument.
//
// ⛔ A MALFORMED ID IS A 400, NOT A 500 AND NOT A 404. An unparseable id would
// otherwise reach a `::uuid` cast and come back as a database error that reads
// as the feature being broken.

export async function GET(_request, { params }) {
  const session = await getServerSession(authOptions);
  // ⛔ `OPERATE` SPELLED OUT, NOT read through the catalogue entry. It IS the
  // same capability the custom-report entry declares (its floor, shared with
  // the section registry as CUSTOM_REPORT_CAPABILITY) and a test pins the two
  // equal — but tests/rbac.test.js scans every route for the capability it
  // names, and a constant that is not one of rbac's own is invisible to that
  // scan and unreadable to a reviewer. A route must say what it enforces.
  if (!can(session, OPERATE)) {
    return forbiddenResponse(OPERATE);
  }
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Not a valid custom report id.' }, { status: 400 });
  }
  try {
    const report = await getCustomReport(pool, params.id);
    if (!report) {
      return NextResponse.json({ error: 'No such custom report.' }, { status: 404 });
    }
    return NextResponse.json({ report });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to read the custom report' },
      { status: 500 }
    );
  }
}

// PUT body: any of { name, subtitle, sections } — absent keys are left alone.
export async function PUT(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) {
    return forbiddenResponse(MANAGE_SETTINGS);
  }
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Not a valid custom report id.' }, { status: 400 });
  }
  const body = await request.json().catch(() => ({}));

  // ⛔ THE SAME "you cannot save what you could not download" GATE AS THE POST.
  // Checked only when the patch actually changes the selection: a rename must
  // not be refused on the strength of a section the session was already allowed
  // to keep.
  if (body && Array.isArray(body.sections)) {
    const need = requiredCapability(body.sections);
    if (!can(session, need)) return forbiddenResponse(need);
  }

  try {
    const result = await updateCustomReport(pool, params.id, body);
    if (!result.ok) {
      const missing = result.errors.some((e) => /no longer exists/.test(e));
      return NextResponse.json(
        { error: result.errors.join(' '), errors: result.errors },
        { status: missing ? 404 : 400 }
      );
    }
    return NextResponse.json({ report: result.report });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to update the custom report' },
      { status: 500 }
    );
  }
}

export async function DELETE(_request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) {
    return forbiddenResponse(MANAGE_SETTINGS);
  }
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Not a valid custom report id.' }, { status: 400 });
  }
  try {
    const removed = await deleteCustomReport(pool, params.id);
    if (!removed) {
      // ⛔ A DELETE THAT REMOVED NOTHING SAYS SO. Reporting success would leave
      // an operator believing they had tidied up a definition that is still
      // being downloaded by somebody else.
      return NextResponse.json({ error: 'No such custom report.' }, { status: 404 });
    }
    return NextResponse.json({ deleted: true });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to delete the custom report' },
      { status: 500 }
    );
  }
}
