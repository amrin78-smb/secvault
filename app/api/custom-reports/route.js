import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../auth/[...nextauth]/route';
import { pool } from '../../../lib/db';
import { can, OPERATE, MANAGE_SETTINGS, forbiddenResponse } from '../../../lib/rbac';
import {
  listCustomReports,
  createCustomReport,
} from '../../../lib/reports/customReportData';
import {
  requiredCapability,
  clientSafeSections,
} from '../../../lib/reports/customReport';
import { capabilitiesOf } from '../../../lib/rbac';

export const dynamic = 'force-dynamic';

// /api/custom-reports — the saved definitions behind the Custom Report entry in
// lib/reports/catalogue.js.
//
// ⛔ TWO CAPABILITIES, AND THE SPLIT IS THE SAME ONE /reports ALREADY MAKES.
// Reading a definition, and downloading the document it produces, are gated on
// the catalogue entry's own capability (`operate`, which every assignable role
// holds) — so every role can USE what an administrator defined. CREATING,
// EDITING or DELETING one is manage_settings, exactly as
// /api/reports/schedules is, because a custom report is INSTALLATION-WIDE
// SHARED STATE: it is a template for an audit artefact that leaves the
// building, and if two people can hold different definitions under the name
// "Quarterly Board Pack" then the same title means two different documents and
// the cover page cannot say whose version it is. That is the
// mislabelled-artefact failure this product refuses everywhere else.
//
// ⛔ NOT A SAVED VIEW, AND THE DIFFERENCE IS WHY THIS IS GATED AT ALL.
// saved_views is one person's filter: it changes no shared meaning, nobody else
// ever sees it, and CLAUDE.md names it as a documented exception to the
// mutating-route rule for exactly that reason. This row belongs to the
// installation, which is the other side of that same rule.
//
// ⛔ THERE IS NO PDF ROUTE HERE. The document is downloaded through
// GET /api/reports/custom-report/pdf?id=<definition id>, which resolves this
// report through the registry like every other report, enforces the entry's own
// capability, validates the id and 404s an unknown one. A second download path
// would be a second copy of all four of those gates.

/** The session's own name, for provenance — never taken from the body. */
function actorOf(session) {
  return (session && session.user && (session.user.name || session.user.email)) || null;
}

export async function GET() {
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
  try {
    const reports = await listCustomReports(pool);
    return NextResponse.json({
      reports,
      // The registry travels with the list so the builder needs no second copy
      // of it, and each section is marked with whether THIS session could
      // download a report containing it.
      sections: clientSafeSections(capabilitiesOf(session)),
    });
  } catch (err) {
    // ⛔ A 500 WITH THE REASON, never `{reports: []}`. An empty list is a claim
    // that nothing has been defined, and a panel rendering it over a failed
    // read would invite an operator to create a duplicate of a report that
    // already exists.
    return NextResponse.json(
      { error: err.message || 'Failed to list custom reports' },
      { status: 500 }
    );
  }
}

// POST body: { name, subtitle?, sections: string[] }
export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) {
    return forbiddenResponse(MANAGE_SETTINGS);
  }
  const body = await request.json().catch(() => ({}));

  // ⛔ YOU CANNOT SAVE A REPORT YOU COULD NOT DOWNLOAD. The required capability
  // is the strictest among the chosen sections; a section nobody with this
  // session's capabilities could read would otherwise be saved into a
  // definition that answers 403 to its own author, which reads as the product
  // being broken. No registered section exceeds the floor today, so this admits
  // every manage_settings holder — it is in the path because a guard added
  // after the section that needs it is a guard someone forgets.
  const need = requiredCapability(Array.isArray(body && body.sections) ? body.sections : []);
  if (!can(session, need)) return forbiddenResponse(need);

  try {
    const result = await createCustomReport(pool, body, actorOf(session));
    if (!result.ok) {
      // Every refusal is a sentence naming what to change, not a constraint
      // violation — the empty-selection rule lives in a CHECK as well, and a
      // raw "custom_reports_sections_chk" tells an operator nothing.
      return NextResponse.json(
        { error: result.errors.join(' '), errors: result.errors },
        { status: 400 }
      );
    }
    return NextResponse.json({ report: result.report }, { status: 201 });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to create custom report' },
      { status: 500 }
    );
  }
}
