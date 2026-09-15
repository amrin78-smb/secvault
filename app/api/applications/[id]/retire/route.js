import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { pool } from '../../../../../lib/db';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { can, forbiddenResponse, OPERATE } from '../../../../../lib/rbac';
import {
  planApplicationRetirement,
  retireApplication,
} from '../../../../../lib/engines/applicationRetire';
import { logActivity } from '../../../../../lib/activityLog';

export const dynamic = 'force-dynamic';

// Retiring a declared application into a rule change request.
//
// POST (default)              -> { mode: 'plan', plan }        computes, writes nothing
// POST { confirm: true }      -> { mode: 'submitted', ... }    raises the requests
//
// ⛔ TWO STEPS, DELIBERATELY. The proposal names firewall rules for deletion, so
// the operator sees the proposed list AND the withheld list with reasons before
// anything is raised. A one-click action whose effect is a surprise is worse
// than two clicks here.
//
// ⛔ THE PLAN IS A POST AND IS STILL GATED. It persists nothing — by the rule
// this product applies to /api/devices/[id]/access-path it could have been
// ungated — but it is the first half of one action whose second half raises
// change requests, and splitting the boundary across the two halves would leave
// a gate that reads as stricter than it is. OPERATE is the capability the
// existing cleanup loop already requires to raise a request.
//
// ⛔ THE CALLER'S RULE IDS ARE NEVER TRUSTED. `expect` can only NARROW what the
// engine itself recomputed: anything newly proposed since the operator looked is
// reported as drift and nothing is submitted. Taking a list of rules from a
// request body would let a caller nominate rules the engine never proposed.
//
// ⛔ NOTHING IS DELETED HERE AND NO STATUS IS CHANGED. This raises requests; the
// rules go when a human edits the firewall, and the existing loop proves it
// against the next collected ruleset. The application's own `status` is left
// exactly as the operator set it — this action is evidence for a decision, not
// the decision.

function windowDaysFrom(body) {
  const raw = body && body.days;
  if (raw === null || raw === undefined || String(raw).trim() === '') return undefined;
  if (!/^\d+$/.test(String(raw).trim())) return undefined;
  const n = Number(String(raw).trim());
  return Number.isSafeInteger(n) && n > 0 ? n : undefined;
}

export async function POST(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, OPERATE)) return forbiddenResponse(OPERATE);

  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid application id' }, { status: 400 });
  }

  const body = await request.json().catch(() => ({}));
  const windowDays = windowDaysFrom(body);
  const confirm = body && body.confirm === true;
  const expect = Array.isArray(body && body.expect)
    ? body.expect.filter((v) => typeof v === 'string' && v.trim() !== '').map((v) => v.trim())
    : undefined;

  try {
    if (!confirm) {
      const plan = await planApplicationRetirement(pool, params.id, { windowDays });
      if (!plan) return NextResponse.json({ error: 'Application not found' }, { status: 404 });
      // ⛔ `plan` carries `proposed` AND `withheld` AND `notes`, and every one of
      // them is returned. Dropping the withheld half here would hand the UI a
      // shorter list that looks complete — the failed-read-as-a-fact bug wearing
      // a retirement screen.
      return NextResponse.json({ mode: 'plan', plan });
    }

    const createdBy = (session && session.user && session.user.name) || null;
    const result = await retireApplication(pool, params.id, {
      windowDays,
      createdBy,
      expect,
      note: typeof body.note === 'string' && body.note.trim() !== '' ? body.note.trim() : undefined,
    });
    if (!result) return NextResponse.json({ error: 'Application not found' }, { status: 404 });

    if (result.drifted) {
      // A conflict, not a server failure: what the operator reviewed is no
      // longer what the engine proposes.
      return NextResponse.json({ mode: 'drifted', ...result }, { status: 409 });
    }

    if (result.requests.length > 0) {
      try {
        await logActivity(pool, {
          actor: createdBy || 'unknown',
          action: 'application_retirement_requested',
          detail:
            `Retiring "${(result.plan.application && result.plan.application.name) || params.id}": `
            + `${result.submitted} rule(s) proposed for removal across `
            + `${result.requests.length} firewall(s)`,
        });
      } catch (e) { /* the audit line is not worth failing the write for */ }
    }

    // ⛔ A PARTIAL RESULT IS STILL A 200 WITH ITS FAILURES NAMED, never a bare
    // success. `ok:false` with a populated `failures[]` is how one firewall
    // rejecting its request stays visible to an operator who was otherwise told
    // the work was raised.
    return NextResponse.json({ mode: 'submitted', ...result });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
