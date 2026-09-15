import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../../auth/[...nextauth]/route';
import { pool } from '../../../../../../lib/db';
import { isValidUuid } from '../../../../../../lib/apiUtils';
import { can, forbiddenResponse, OPERATE } from '../../../../../../lib/rbac';
import { updateFlow, deleteFlow } from '../../../../../../lib/engines/applicationViewData';
import { logActivity } from '../../../../../../lib/activityLog';

export const dynamic = 'force-dynamic';

// One declared flow.
//
// ⛔ OWNERSHIP IS PROVEN, NOT ASSUMED. updateFlow/deleteFlow key on the flow id
// ALONE, so trusting the flowId would let a request addressed to application A
// edit or delete a flow belonging to application B — silently, and with a 200.
// Every handler here confirms the row's application_id matches the [id] in the
// URL before touching it, and a mismatch is a 404 (the flow does not exist
// *here*, which is the only thing this URL can honestly answer).

async function findOwnedFlow(applicationId, flowId) {
  const { rows } = await pool.query(
    'SELECT id FROM application_flows WHERE id = $1::uuid AND application_id = $2::uuid',
    [flowId, applicationId]
  );
  return rows.length > 0;
}

function badIds(params) {
  if (!isValidUuid(params.id)) return 'Invalid application id';
  if (!isValidUuid(params.flowId)) return 'Invalid flow id';
  return null;
}

export async function PUT(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, OPERATE)) return forbiddenResponse(OPERATE);

  const invalid = badIds(params);
  if (invalid) return NextResponse.json({ error: invalid }, { status: 400 });

  const body = await request.json().catch(() => ({}));

  try {
    if (!(await findOwnedFlow(params.id, params.flowId))) {
      return NextResponse.json({ error: 'Flow not found' }, { status: 404 });
    }

    const result = await updateFlow(pool, params.flowId, body);
    if (!result.ok) {
      // updateFlow answers 'No such flow.' when the row vanished between the
      // ownership check and the UPDATE. That is a 404, not a validation
      // failure — everything else it refuses is the engine's own parse reason
      // and is returned verbatim, because it names the field that is wrong.
      const status = result.reason === 'No such flow.' ? 404 : 400;
      return NextResponse.json({ error: result.reason }, { status });
    }

    try {
      await logActivity(pool, {
        actor: (session.user && session.user.name) || 'unknown',
        action: 'application_flow_updated',
        detail: `${result.flow.src} -> ${result.flow.dst} ${result.flow.protocol}`,
      });
    } catch (e) { /* the audit line is not worth failing the write for */ }

    return NextResponse.json({ flow: result.flow });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

export async function DELETE(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, OPERATE)) return forbiddenResponse(OPERATE);

  const invalid = badIds(params);
  if (invalid) return NextResponse.json({ error: invalid }, { status: 400 });

  try {
    if (!(await findOwnedFlow(params.id, params.flowId))) {
      return NextResponse.json({ error: 'Flow not found' }, { status: 404 });
    }

    const removed = await deleteFlow(pool, params.flowId);
    if (!removed) {
      return NextResponse.json({ error: 'Flow not found' }, { status: 404 });
    }

    try {
      await logActivity(pool, {
        actor: (session.user && session.user.name) || 'unknown',
        action: 'application_flow_deleted',
        detail: `Deleted flow ${params.flowId}`,
      });
    } catch (e) { /* the audit line is not worth failing the write for */ }

    return NextResponse.json({ ok: true });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
