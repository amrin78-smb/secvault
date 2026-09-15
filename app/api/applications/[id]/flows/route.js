import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { pool } from '../../../../../lib/db';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { can, forbiddenResponse, OPERATE } from '../../../../../lib/rbac';
import { addFlow } from '../../../../../lib/engines/applicationViewData';
import { logActivity } from '../../../../../lib/activityLog';

export const dynamic = 'force-dynamic';

// Declare a flow an application needs (or must never have).
//
// ⛔ THE PARENT IS VERIFIED TO EXIST FIRST. application_flows.application_id is
// a FK, so a flow against a missing application would fail as a 500 from the
// constraint — but the caller's mistake is that the application is not there,
// and that is what they need told. The check also keeps the 404 honest for the
// PUT/DELETE siblings, which use the same parent id to prove ownership.
//
// ⛔ A REFUSED FLOW RETURNS THE ENGINE'S OWN REASON, VERBATIM. addFlow
// validates with normaliseFlow — the SAME parser that will later evaluate the
// flow — so the reason names the field that is wrong ("Source "10.0.0.300" is
// not a valid address or CIDR."). Replacing that with "invalid input" throws
// away the only part of the error that makes it fixable, and the flow cannot be
// stored and left broken: an unparseable flow can never produce a verdict, so
// accepting it would put a permanently unanswerable row in the operator's list.

async function applicationExists(id) {
  const { rows } = await pool.query('SELECT id FROM applications WHERE id = $1::uuid', [id]);
  return rows.length > 0;
}

export async function POST(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, OPERATE)) return forbiddenResponse(OPERATE);

  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid application id' }, { status: 400 });
  }

  const body = await request.json().catch(() => ({}));

  try {
    if (!(await applicationExists(params.id))) {
      return NextResponse.json({ error: 'Application not found' }, { status: 404 });
    }

    const result = await addFlow(pool, params.id, body);
    if (!result.ok) {
      return NextResponse.json({ error: result.reason }, { status: 400 });
    }

    try {
      await logActivity(pool, {
        actor: (session.user && session.user.name) || 'unknown',
        action: 'application_flow_added',
        detail: `${result.flow.src} -> ${result.flow.dst} ${result.flow.protocol}`
          + `${result.flow.port_start === null ? '' : `/${result.flow.port_start}`}`
          + ` must ${result.flow.expectation === 'deny' ? 'NOT be reachable' : 'be reachable'}`,
      });
    } catch (e) { /* the audit line is not worth failing the write for */ }

    return NextResponse.json({ flow: result.flow }, { status: 201 });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
