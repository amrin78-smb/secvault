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

  // ⛔ FAILS CLOSED ON A REGISTRY THAT DID NOT DECLARE ONE. This used to read
  // `entry.capability && !can(...)`, so an entry that simply forgot its
  // `capability` line was served to every authenticated session — an omission
  // in DATA silently disabling the only boundary in the path. lib/rbac.js
  // denies an undefined capability, so calling can() unconditionally turns that
  // omission into a visible 403 rather than an invisible hole. Every registered
  // entry declares one today and a test pins that; this is what happens the day
  // one does not.
  const session = await getServerSession(authOptions);
  if (!can(session, entry.capability)) {
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

  // ⛔ AND A REPORT THAT CANNOT NARROW REFUSES A deviceId RATHER THAN IGNORING
  // IT. Only a `device`-scoped report, or one declaring `optionalDevice`, reads
  // the filter — every other builder drops it on the floor. Accepting it anyway
  // answered "the compliance posture of THIS firewall" with the whole-fleet
  // document, which is the same mislabelled artefact the parameter allow-list
  // below exists to prevent, arriving through a different query key. An
  // unusable filter is a bad request, not a silent widening.
  const takesDevice = entry.scope === 'device' || entry.optionalDevice === true;
  if (deviceId && !takesDevice) {
    return Response.json(
      { error: `${entry.name} is not scoped to a single firewall; remove deviceId.` },
      { status: 400 }
    );
  }
  if (entry.scope === 'entity') {
    if (!entityId || !isValidUuid(entityId)) {
      return Response.json(
        { error: 'This report is scoped to a single record and needs a valid id.' },
        { status: 400 }
      );
    }
  }

  // ⛔ EVERY DECLARED PARAMETER IS ALLOW-LISTED AGAINST ITS OWN CHOICES, and a
  // value that is not on the list is a 400 rather than being dropped. Dropping
  // it would silently widen the report — a request for the PCI document
  // answered with the whole-fleet document, under a filename saying PCI. That
  // is a mislabelled audit artefact, which is strictly worse than an error.
  //
  // Because the accepted set is a literal in the catalogue, nothing an operator
  // can type reaches a builder or a query. The engine validates again on its
  // own, so this is the first of two gates, not the only one.
  const declared = Array.isArray(entry.params) ? entry.params : [];
  const paramValues = {};
  for (const p of declared) {
    const raw = searchParams.get(p.key);
    // Absent or empty means "unscoped", which is every report's default and is
    // not an error — the picker's empty option is a real choice, not a blank.
    if (raw === null || raw === '') continue;
    const allowed = Array.isArray(p.choices) ? p.choices : [];
    if (!allowed.some((c) => c.value === raw)) {
      return Response.json(
        { error: `${raw} is not a valid ${p.label || p.key} for this report.` },
        { status: 400 }
      );
    }
    paramValues[p.key] = raw;
  }

  try {
    const build = entry.builder();
    // The two entity/device builders take their id as the second positional
    // argument; fleet builders take an options object. Both shapes also receive
    // the options object, so a builder can read scope parameters either way.
    const opts = { deviceId: deviceId || null, ...paramValues };
    const buffer = entry.scope === 'entity'
      ? await build(pool, entityId, opts)
      : await build(pool, opts);

    if (!buffer) {
      return Response.json({ error: 'That record does not exist.' }, { status: 404 });
    }

    const stamp = new Date().toISOString().slice(0, 10);
    const scopeSuffix = Object.values(paramValues)
      .map((v) => String(v).toLowerCase().replace(/[^a-z0-9]+/g, '-'))
      .filter(Boolean)
      .join('-');
    const filename = `secvault-${entry.id}${scopeSuffix ? `-${scopeSuffix}` : ''}-${stamp}.pdf`;

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
