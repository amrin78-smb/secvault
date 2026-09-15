import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { pool } from '../../../../lib/db';
import { isValidUuid } from '../../../../lib/apiUtils';
import { can, forbiddenResponse, OPERATE } from '../../../../lib/rbac';
import {
  evaluateApplication,
  updateApplication,
  deleteApplication,
} from '../../../../lib/engines/applicationViewData';
import { logActivity } from '../../../../lib/activityLog';

export const dynamic = 'force-dynamic';

// One declared application: its flows evaluated against the live rulebase.
//
// ⛔ EVERY ID IS UUID-CHECKED BEFORE IT REACHES A QUERY. `applications.id` is a
// UUID column, so a malformed segment would otherwise surface as Postgres's
// "invalid input syntax for type uuid" — a 500 that reads like a broken server
// for what is a malformed request. It must also never be allowed to look like
// an empty result, which reads as "no such application" and is a different,
// wrong, answer.
//
// ⛔ Mutations are gated on OPERATE (see the note in ../route.js); GET is not.

function windowDaysFrom(searchParams) {
  const raw = searchParams.get('days');
  if (raw === null || raw.trim() === '') return undefined;
  if (!/^\d+$/.test(raw.trim())) return undefined;
  const n = Number(raw.trim());
  return Number.isSafeInteger(n) && n > 0 ? n : undefined;
}

export async function GET(request, { params }) {
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid application id' }, { status: 400 });
  }
  const { searchParams } = new URL(request.url);
  const windowDays = windowDaysFrom(searchParams);

  try {
    const result = await evaluateApplication(pool, params.id, { windowDays });
    if (!result) {
      return NextResponse.json({ error: 'Application not found' }, { status: 404 });
    }
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

export async function PUT(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, OPERATE)) return forbiddenResponse(OPERATE);

  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid application id' }, { status: 400 });
  }

  const body = await request.json().catch(() => ({}));
  if (body.name !== undefined && String(body.name).trim() === '') {
    return NextResponse.json({ error: 'name cannot be empty' }, { status: 400 });
  }

  try {
    const application = await updateApplication(pool, params.id, body);
    if (!application) {
      return NextResponse.json({ error: 'Application not found' }, { status: 404 });
    }

    try {
      await logActivity(pool, {
        actor: (session.user && session.user.name) || 'unknown',
        action: 'application_updated',
        detail: `Updated application "${application.name}"`,
      });
    } catch (e) { /* the audit line is not worth failing the write for */ }

    return NextResponse.json({ application });
  } catch (err) {
    if (err && err.code === '23505') {
      return NextResponse.json(
        { error: 'Another application already has that name.' },
        { status: 409 }
      );
    }
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

export async function DELETE(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, OPERATE)) return forbiddenResponse(OPERATE);

  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid application id' }, { status: 400 });
  }

  try {
    // application_flows is ON DELETE CASCADE, so the declaration goes with it.
    const removed = await deleteApplication(pool, params.id);
    if (!removed) {
      return NextResponse.json({ error: 'Application not found' }, { status: 404 });
    }

    try {
      await logActivity(pool, {
        actor: (session.user && session.user.name) || 'unknown',
        action: 'application_deleted',
        detail: `Deleted application ${params.id}`,
      });
    } catch (e) { /* the audit line is not worth failing the write for */ }

    return NextResponse.json({ ok: true });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
