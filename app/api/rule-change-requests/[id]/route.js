import { getServerSession } from 'next-auth/next';
import { pool } from '../../../../lib/db';
import { authOptions } from '../../auth/[...nextauth]/route';
import { isValidUuid } from '../../../../lib/apiUtils';
import { isAdmin, forbiddenResponse } from '../../../../lib/rbac';
import { logActivity } from '../../../../lib/activityLog';
import { submitRequest, abandonRequest, getRequest } from '../../../../lib/engines/ruleChangeRequests';

export const dynamic = 'force-dynamic';

// One rule change request.
//
// GET   -> the request plus its items (each item's outcome + verified_at)
// PATCH -> { action: 'submit' | 'abandon', note? }
//
// ⛔ THE ONLY TWO ACTIONS ARE `submit` AND `abandon`, AND THAT IS THE FEATURE.
// There is no "mark as done", no `action: 'verify'`, and no way to write
// `status = 'verified'` from an HTTP request at all. A request becomes verified
// because verifyRequestsForDevice() compared the re-collected RULESET against
// the requested rules and found them gone — a measurement, not a claim. A
// button that let an operator assert completion would make this feature
// indistinguishable from a spreadsheet, which is precisely what it exists to
// replace (lib/engines/ruleChangeRequests.js, header).
//
// ⛔ Equally, there is no endpoint that clears `unverifiable`. That outcome
// means no rules pull has succeeded since submission, so nothing can be
// concluded; the fix is a successful collection, not an API call.
//
// GET is ungated (read-only, same as every other GET in this app). PATCH
// mutates shared state another operator acts on, so it is admin-gated.

export async function GET(request, { params }) {
  try {
    const { id } = params;
    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid request id' }, { status: 400 });
    }
    const found = await getRequest(pool, id);
    if (!found) {
      return Response.json({ error: 'Request not found' }, { status: 404 });
    }
    return Response.json(found);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}

export async function PATCH(request, { params }) {
  try {
    const { id } = params;
    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid request id' }, { status: 400 });
    }

    const session = await getServerSession(authOptions);
    if (!isAdmin(session)) {
      return forbiddenResponse();
    }

    const body = await request.json().catch(() => ({}));
    const action = typeof body.action === 'string' ? body.action : '';
    const note = typeof body.note === 'string' && body.note.trim() !== '' ? body.note.trim() : null;

    if (action !== 'submit' && action !== 'abandon') {
      return Response.json(
        { error: "action must be 'submit' or 'abandon' — a request is never marked complete by hand" },
        { status: 400 }
      );
    }

    const existing = await getRequest(pool, id);
    if (!existing) {
      return Response.json({ error: 'Request not found' }, { status: 404 });
    }

    let updated;
    try {
      updated =
        action === 'submit'
          ? await submitRequest(pool, id)
          : await abandonRequest(pool, id, note);
    } catch (err) {
      // "Only a draft request can be submitted" / "Only a draft or submitted
      // request can be abandoned" are both state conflicts, not server faults.
      return Response.json({ error: err.message }, { status: 409 });
    }

    try {
      await logActivity(pool, {
        actor: (session && session.user && session.user.name) || 'unknown',
        action: action === 'submit' ? 'submit_rule_change_request' : 'abandon_rule_change_request',
        deviceId: updated.device_id,
        detail: `"${updated.title}" -> ${updated.status}`,
      });
    } catch (auditErr) {
      console.warn(`[rule-change-request route] Failed to record activity log: ${auditErr.message}`);
    }

    return Response.json(updated);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
