import { getServerSession } from 'next-auth/next';
import { pool } from '../../../../lib/db';
import { authOptions } from '../../auth/[...nextauth]/route';
import { isValidUuid } from '../../../../lib/apiUtils';
import { can, OPERATE, MANAGE_DEVICES, forbiddenResponse } from '../../../../lib/rbac';
import { logActivity } from '../../../../lib/activityLog';
import {
  submitRequest,
  abandonRequest,
  approveRequest,
  rejectRequest,
  getRequest,
} from '../../../../lib/engines/ruleChangeRequests';

export const dynamic = 'force-dynamic';

// One rule change request.
//
// GET   -> the request plus its items (each item's outcome + verified_at)
// PATCH -> { action: 'submit' | 'abandon' | 'approve' | 'reject', note?, reason? }
//
// ⛔ NO ACTION HERE CAN PRODUCE A `verified`. There is no "mark as done", no
// `action: 'verify'`, and no way to write `status = 'verified'` from an HTTP
// request at all — including via an approval. A request becomes verified
// because verifyRequestsForDevice() compared the re-collected RULESET against
// the requested rules and found them gone — a measurement, not a claim. A
// button that let an operator assert completion would make this feature
// indistinguishable from a spreadsheet, which is precisely what it exists to
// replace (lib/engines/ruleChangeRequests.js, header). An APPROVAL is a human
// authorising a change, not evidence it happened: it writes `approval_state`
// and nothing else, and the request it approves is still a draft afterwards.
//
// ⛔ APPROVE/REJECT NEED `manage_devices`, NOT `operate`, AND THE ARGUMENT IS
// THIS. `operate` is explicitly "acknowledge findings, run analyses and
// collections, RAISE AND VERIFY rule change requests" — raising one changes no
// device. Approving one is the gate that says a change may now be made to a
// production firewall's ruleset, which is the same authority `manage_devices`
// already carries ("add/edit/delete firewalls, rotate their credentials").
// Gating approval on `operate` would mean every account that can raise a
// request can approve one, i.e. the step would gate nothing at all and would
// still read as a control on screen and in the exported document — a boundary
// somebody believes in that is not there. So: an Operator raises, an
// Admin or Super Admin approves.
//
// ⛔ OPERATE IS STILL THE FLOOR FOR EVERY ACTION, checked once below, with the
// stricter capability layered on top of it for the two decision actions. That
// is deliberate: touching a change request at all is operational work, and a
// session with neither capability gets one consistent refusal.
//
// ⛔ SELF-APPROVAL IS REFUSED IN THE ENGINE, not here, and the refusal is a 409
// rather than a 403: the caller HAS the capability, so naming a capability they
// already hold would be actively misleading. It is a conflict about this
// resource and this actor. The UI disables the control with the same reason —
// equal to the API, never stricter than it.
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
    if (!can(session, OPERATE)) {
      return forbiddenResponse(OPERATE);
    }

    const body = await request.json().catch(() => ({}));
    const action = typeof body.action === 'string' ? body.action : '';
    const note = typeof body.note === 'string' && body.note.trim() !== '' ? body.note.trim() : null;
    const reason = typeof body.reason === 'string' && body.reason.trim() !== ''
      ? body.reason.trim()
      : null;

    // ⛔ THE ACTOR COMES FROM THE SESSION, NEVER FROM THE BODY. It is what gets
    // stored as the approver and what the self-approval refusal compares
    // against, so a body-supplied name would let a requester approve their own
    // change by typing somebody else's.
    const actor = (session && session.user && session.user.name) || null;

    // ⛔ A CLOSED SET, WRITTEN OUT. Four actions, each spelled, so a grep for
    // what this route accepts finds the whole answer — and so that adding a
    // fifth is a deliberate edit here rather than a new key in a map somebody
    // extends without reading this header. NONE of them can produce a
    // `verified`.
    if (action !== 'submit' && action !== 'abandon' && action !== 'approve' && action !== 'reject') {
      return Response.json(
        {
          error: "action must be 'submit', 'abandon', 'approve' or 'reject' — a request is never "
            + 'marked complete by hand',
        },
        { status: 400 }
      );
    }

    const existing = await getRequest(pool, id);
    if (!existing) {
      return Response.json({ error: 'Request not found' }, { status: 404 });
    }

    // ── the two DECISION actions, gated stricter ───────────────────────────
    if (action === 'approve' || action === 'reject') {
      if (!can(session, MANAGE_DEVICES)) {
        return forbiddenResponse(MANAGE_DEVICES);
      }
      let decided;
      try {
        decided = action === 'approve'
          ? await approveRequest(pool, id, { decidedBy: actor })
          : await rejectRequest(pool, id, { decidedBy: actor, reason });
      } catch (err) {
        // Every refusal from those two is a conflict about THIS request and
        // THIS actor — wrong state, no reason given, or the requester trying to
        // approve their own ask. None of them is a server fault, and none of
        // them is a missing capability.
        return Response.json({ error: err.message }, { status: 409 });
      }

      try {
        await logActivity(pool, {
          actor: actor || 'unknown',
          action: action === 'approve'
            ? 'approve_rule_change_request'
            : 'reject_rule_change_request',
          deviceId: decided.device_id,
          detail: `"${decided.title}" -> approval ${decided.approval_state}`
            + (decided.rejected_reason ? `: ${decided.rejected_reason}` : ''),
        });
      } catch (auditErr) {
        console.warn(`[rule-change-request route] Failed to record activity log: ${auditErr.message}`);
      }

      return Response.json(decided);
    }

    // Only the two OPERATE-level transitions are left.
    let updated;
    try {
      updated =
        action === 'submit'
          ? await submitRequest(pool, id)
          : await abandonRequest(pool, id, note);
    } catch (err) {
      // "Only a draft request can be submitted" / "Only a draft or submitted
      // request can be abandoned" / "waiting for approval" are all state
      // conflicts, not server faults.
      return Response.json({ error: err.message }, { status: 409 });
    }

    try {
      await logActivity(pool, {
        actor: actor || 'unknown',
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
