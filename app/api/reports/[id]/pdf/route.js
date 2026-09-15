import { getServerSession } from 'next-auth';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { pool } from '../../../../../lib/db';
import { can, forbiddenResponse } from '../../../../../lib/rbac';
import { reportById } from '../../../../../lib/reports/catalogue';
import { isValidUuid } from '../../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// GET /api/reports/[id]/pdf — download any catalogued report as a PDF.
//
// ⛔ THE CAPABILITY COMES FROM THE CATALOGUE, AND IS ENFORCED HERE.
// lib/reports/catalogue.js declares a `capability` per report; that entry is
// DATA and cannot deny anything. This route is the only thing standing between
// a URL and the file. The catalogue's own filter (`visibleReports`) exists for
// discovery — so an operator is not shown a download they cannot fetch — and is
// explicitly not a boundary.
//
// Today every assignable role holds `operate`, so this gate admits every
// authenticated user and denies one with no role (which is how lib/rbac.js
// fails closed). It is not decoration: Phase D adds a VPN report that names
// individual people and must carry `view_identity`, and the mechanism has to
// already be in the path rather than be retrofitted around one report. A guard
// added late is a guard someone forgets.
//
// ⛔ NOT a violation of "GET routes are never gated". That convention has two
// documented exceptions, both about personal data, and this route is the
// delivery mechanism for a report class that will include one. Gating on a
// capability every role already holds costs nothing and means the identity
// report cannot ship without a boundary.

export async function GET(request, { params }) {
  const entry = reportById(params.id);

  // ⛔ An unknown id is 404, NOT a 500 and NOT an empty PDF. A zero-byte
  // "report" is the kind of confident-looking artefact this product exists to
  // refuse — someone would file it.
  if (!entry) {
    return Response.json({ error: `No such report: ${params.id}` }, { status: 404 });
  }

  const session = await getServerSession(authOptions);
  if (entry.capability && !can(session, entry.capability)) {
    return forbiddenResponse(entry.capability);
  }

  const { searchParams } = new URL(request.url);
  const deviceId = searchParams.get('deviceId');
  const entityId = searchParams.get('id');

  // ⛔ Validate the scope parameters the entry actually declares, and refuse
  // rather than silently widening. A `device`-scoped report handed no deviceId
  // must not quietly render the whole fleet under a title that says otherwise —
  // that is a mislabelled document, which on an audit artefact is worse than an
  // error page.
  if (entry.scope === 'device') {
    if (!deviceId || !isValidUuid(deviceId)) {
      return Response.json(
        { error: 'This report is scoped to one firewall and needs a valid deviceId.' },
        { status: 400 }
      );
    }
  }

  // ⛔ A SUPPLIED deviceId IS VALIDATED WHATEVER THE SCOPE. A fleet report may
  // accept an OPTIONAL device filter (`optionalDevice`), and without this a
  // malformed one would flow straight into a query — either erroring as a 500
  // that looks like the report is broken, or worse, matching nothing and
  // rendering a fleet-titled document with empty sections. An unparseable
  // filter is a bad request, not an empty result.
  if (deviceId && !isValidUuid(deviceId)) {
    return Response.json({ error: 'deviceId is not a valid identifier.' }, { status: 400 });
  }
  if (entry.scope === 'entity') {
    if (!entityId || !isValidUuid(entityId)) {
      return Response.json(
        { error: 'This report is scoped to a single record and needs a valid id.' },
        { status: 400 }
      );
    }
  }

  try {
    const build = entry.builder();
    // The two entity/device builders take their id as the second positional
    // argument; fleet builders take an options object. Both shapes also receive
    // the options object, so a builder can read scope parameters either way.
    const opts = { deviceId: deviceId || null };
    const buffer = entry.scope === 'entity'
      ? await build(pool, entityId, opts)
      : await build(pool, opts);

    if (!buffer) {
      return Response.json({ error: 'That record does not exist.' }, { status: 404 });
    }

    const stamp = new Date().toISOString().slice(0, 10);
    const filename = `secvault-${entry.id}-${stamp}.pdf`;

    return new Response(buffer, {
      status: 200,
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="${filename}"`,
        // ⛔ A report is a point-in-time measurement. A cached copy served days
        // later carries a cover page asserting a generation time it does not
        // have, which is precisely the stale-evidence problem the whole product
        // is built to avoid.
        'Cache-Control': 'no-store, must-revalidate',
      },
    });
  } catch (err) {
    // ⛔ The error is returned, not swallowed into an empty 200. An operator who
    // downloads a broken file learns nothing; one who reads "the compliance
    // query failed" knows what to fix.
    return Response.json(
      { error: err.message || `Failed to generate ${entry.name}` },
      { status: 500 }
    );
  }
}
