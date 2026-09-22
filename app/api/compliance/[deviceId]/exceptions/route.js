import { pool } from '../../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { logActivity } from '../../../../../lib/activityLog';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { can, OPERATE, forbiddenResponse } from '../../../../../lib/rbac';
import {
  getExceptionView,
  createException,
  describeException,
  ExceptionRequestError,
} from '../../../../../lib/engines/complianceExceptions';

export const dynamic = 'force-dynamic';

// GET  /api/compliance/[deviceId]/exceptions — the exceptions, their read-time
//      states, the failing checks still available to accept, and the counts.
// POST /api/compliance/[deviceId]/exceptions — record one.
//
// ── ⛔ WHY `OPERATE` AND NOT `MANAGE_SETTINGS` ──────────────────────────────
//
// Both were live candidates. OPERATE, for three reasons that all come from
// CLAUDE.md's own rules rather than from taste:
//
// 1. THE CLOSEST EXISTING ANALOGUE IS ALREADY `operate`. CLAUDE.md defines
//    `operate` as "acknowledge findings/alerts/diffs, run analyses and
//    collections, raise and verify rule change requests", and the Operator
//    role description says so in as many words. A compliance exception is the
//    same act as a finding acknowledgement — a recorded operator judgement
//    about a finding the engines produced — one table over. Splitting two
//    near-identical decisions across two capabilities is how a permission
//    system grows the holes nobody can see, which is exactly the failure mode
//    lib/rbac.js's header warns about.
//
// 2. SEGMENTATION AND APPLICATION INTENT SET THE PRECEDENT, AND IT IS RECENT
//    AND EXPLICIT: "Mutating routes are gated on OPERATE, not MANAGE_DEVICES:
//    declaring intent changes no device, no rule and no score." An exception
//    changes no device, no rule and — by the contract in lib/schema.sql's own
//    comment — NO SCORE.
//
// 3. ⛔ THE GATE IS ONLY SAFE AT `operate` BECAUSE OF THAT LAST CLAUSE, AND
//    THIS IS THE LOAD-BEARING PART OF THE DECISION. The authority that would
//    justify escalating to MANAGE_SETTINGS is "can make the compliance number
//    go up" — a commercial/political power, the same reasoning that keeps
//    MANAGE_LICENSE out of `admin`. An exception cannot do that: the headline
//    score is computed as if no exception existed, so the worst an operator can
//    do here is add an annotation beside a failure that remains a failure. If
//    anybody ever makes an exception move a score, THIS GATE MUST BE REVISITED
//    IN THE SAME COMMIT — the capability changes meaning at that moment.
//
// MANAGE_SETTINGS was refused because it means "change application settings,
// including notification channels" — system configuration. An exception is not
// configuration; it is a per-device operational record with a device_id, and
// filing it under the settings capability would also lock out the Operator
// role, the only role whose entire job description is acting on findings.
//
// ⛔ The GET is NOT gated, per CLAUDE.md: GET routes are never gated except the
// two documented personal-data exceptions (log search, VPN identity). An
// exception names a SecVault operator, not an end user, and the same names are
// already readable through the activity log.

function actorOf(session) {
  // ⛔ THE ONLY SOURCE OF `accepted_by`. It is read from the session and never
  // from the request body — the same rule saved views follow for `user_id`. A
  // body-supplied owner would let any caller attribute a risk acceptance to a
  // colleague, and `accepted_by` is the one column an auditor actually reads.
  const name = session && session.user && session.user.name;
  return typeof name === 'string' && name.trim() ? name.trim() : null;
}

export async function GET(_request, { params }) {
  const { deviceId } = params;
  if (!isValidUuid(deviceId)) {
    return Response.json({ error: 'Invalid device id' }, { status: 400 });
  }

  const session = await getServerSession(authOptions);
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  try {
    // ⛔ `new Date()` is passed in rather than read inside the engine, so the
    // expiry evaluation is the same injectable read-time computation the tests
    // pin. There is no cron job and no stored state.
    const view = await getExceptionView(pool, deviceId, new Date());
    return Response.json({ deviceId, ...view });
  } catch (err) {
    return Response.json({ error: err.message || 'Failed to load exceptions' }, { status: 500 });
  }
}

export async function POST(request, { params }) {
  const { deviceId } = params;
  if (!isValidUuid(deviceId)) {
    return Response.json({ error: 'Invalid device id' }, { status: 400 });
  }

  const session = await getServerSession(authOptions);
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!can(session, OPERATE)) return forbiddenResponse(OPERATE);

  const acceptedBy = actorOf(session);
  if (!acceptedBy) {
    return Response.json(
      {
        error:
          'SecVault could not determine who is accepting this risk, so the exception '
          + 'was not recorded. An exception must name the person who accepted it.',
      },
      { status: 400 }
    );
  }

  let body;
  try {
    body = await request.json();
  } catch (_err) {
    return Response.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  try {
    const row = await createException(
      pool,
      {
        deviceId,
        checkSlug: body.checkSlug,
        reason: body.reason,
        compensatingControl: body.compensatingControl,
        // ⛔ NOT body.acceptedBy. There is deliberately no such field, and a
        // caller that sends one is ignored rather than honoured.
        acceptedBy,
        expiresAt: body.expiresAt,
      },
      new Date()
    );

    try {
      await logActivity(pool, {
        actor: acceptedBy,
        action: 'accept_compliance_exception',
        deviceId,
        detail: `${row.check_slug} accepted until ${new Date(row.expires_at).toISOString().slice(0, 10)}`,
      });
    } catch (auditErr) {
      // Best-effort, same idiom as the sibling /run route: a logging problem
      // must never turn a successful write into a reported failure.
      console.warn(`[compliance exceptions] Failed to record activity log: ${auditErr.message}`);
    }

    return Response.json({ exception: describeException(row, new Date()) }, { status: 201 });
  } catch (err) {
    // ⛔ Only an ExceptionRequestError becomes a 4xx. Everything else is a 500 —
    // dressing an unexpected fault up as "bad input" would have the operator
    // correcting a form that was never the problem.
    if (err instanceof ExceptionRequestError) {
      return Response.json({ error: err.message }, { status: err.status || 400 });
    }
    return Response.json({ error: err.message || 'Failed to record exception' }, { status: 500 });
  }
}
