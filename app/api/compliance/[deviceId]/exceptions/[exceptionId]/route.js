import { pool } from '../../../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../../auth/[...nextauth]/route';
import { logActivity } from '../../../../../../lib/activityLog';
import { isValidUuid } from '../../../../../../lib/apiUtils';
import { can, OPERATE, forbiddenResponse } from '../../../../../../lib/rbac';
import {
  revokeException,
  describeException,
  ExceptionRequestError,
} from '../../../../../../lib/engines/complianceExceptions';

export const dynamic = 'force-dynamic';

// DELETE /api/compliance/[deviceId]/exceptions/[exceptionId] — REVOKE.
//
// ⛔ THE VERB IS DELETE; THE OPERATION IS NOT. `revokeException` stamps
// `revoked_at`/`revoked_by` and keeps the row, because the audit trail of who
// accepted what and who later withdrew it is the durable value here. A real
// DELETE would let an exception be recorded, relied on for months, and then
// erased without trace. The partial unique index is partial for precisely this
// reason — see lib/schema.sql's comment.
//
// ⛔ Gated on OPERATE, the same capability as the create — see ../route.js for
// the full justification. Revoking only ever REMOVES an accepted label from a
// failing check, so it moves the picture in the conservative direction; gating
// it more strictly than the create would leave an operator able to record an
// exception they could not withdraw.

function actorOf(session) {
  // From the SESSION, never the request body — same rule as `accepted_by`.
  const name = session && session.user && session.user.name;
  return typeof name === 'string' && name.trim() ? name.trim() : null;
}

export async function DELETE(_request, { params }) {
  const { deviceId, exceptionId } = params;
  if (!isValidUuid(deviceId)) {
    return Response.json({ error: 'Invalid device id' }, { status: 400 });
  }
  // ⛔ Guarded before the query: compliance_exceptions.id is UUID-typed, and a
  // hand-edited path segment would otherwise reach Postgres as a raw "invalid
  // input syntax for type uuid" 500.
  if (!isValidUuid(exceptionId)) {
    return Response.json({ error: 'Invalid exception id' }, { status: 400 });
  }

  const session = await getServerSession(authOptions);
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  if (!can(session, OPERATE)) return forbiddenResponse(OPERATE);

  const revokedBy = actorOf(session);
  if (!revokedBy) {
    return Response.json(
      {
        error:
          'SecVault could not determine who is revoking this exception, so it was left '
          + 'in place. A revocation must name the person who made it.',
      },
      { status: 400 }
    );
  }

  try {
    // ⛔ Scoped by device_id INSIDE the SQL, not here — the same call the saved
    // views delete makes about ownership. A mis-addressed id cannot revoke
    // another device's recorded decision, and no future caller can forget the
    // condition.
    const row = await revokeException(pool, { exceptionId, deviceId, revokedBy });
    if (!row) {
      // Covers both "no such exception" and "already revoked". They are not
      // distinguished on purpose: the second is not an error the operator needs
      // to act on, and re-stamping a fresh revocation time over the real one
      // would falsify the trail.
      return Response.json(
        { error: 'No live exception with that id on this device.' },
        { status: 404 }
      );
    }

    try {
      await logActivity(pool, {
        actor: revokedBy,
        action: 'revoke_compliance_exception',
        deviceId,
        detail: `${row.check_slug} exception revoked`,
      });
    } catch (auditErr) {
      console.warn(`[compliance exceptions] Failed to record activity log: ${auditErr.message}`);
    }

    return Response.json({ exception: describeException(row, new Date()) });
  } catch (err) {
    if (err instanceof ExceptionRequestError) {
      return Response.json({ error: err.message }, { status: err.status || 400 });
    }
    return Response.json({ error: err.message || 'Failed to revoke exception' }, { status: 500 });
  }
}
