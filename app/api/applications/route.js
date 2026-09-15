import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../auth/[...nextauth]/route';
import { pool } from '../../../lib/db';
import { can, forbiddenResponse, OPERATE } from '../../../lib/rbac';
import {
  evaluateAllApplications,
  createApplication,
} from '../../../lib/engines/applicationViewData';
import { logActivity } from '../../../lib/activityLog';

export const dynamic = 'force-dynamic';

// Declared applications, each evaluated against the live rulebase.
//
// ⛔ GET IS UNGATED, like every other read in this app that is not personal
// data. The mutating handlers are gated on OPERATE rather than MANAGE_DEVICES,
// for the same reason /api/segmentation's are: declaring that an application
// exists and which flows it needs changes no device, no rule and no score. An
// operator who cannot record the map they work to cannot do the job the role
// exists for.
//
// ⛔ THERE IS DELIBERATELY NO RECOMPUTE/REFRESH ENDPOINT. Nothing here is
// stored, so there is nothing to recompute — every GET evaluates the current
// rulebase and the current traffic window. Offering a "refresh" would imply a
// cached verdict exists, which is exactly the staleness this feature is built
// to beat.

// `?days=` — a positive whole number or nothing.
//
// ⛔ A JUNK VALUE IS IGNORED, NOT REFUSED. The engine owns the default window
// (applicationViewData.DEFAULT_WINDOW_DAYS) and ALWAYS reports the window it
// actually used back in `windowDays`/`coverage.windowDays`. So an unusable
// `days` costs the caller nothing and the response can never state a span the
// evidence does not cover — which is the failure this guard exists to prevent,
// not the presence of a bad query string.
function windowDaysFrom(searchParams) {
  const raw = searchParams.get('days');
  if (raw === null || raw.trim() === '') return undefined;
  if (!/^\d+$/.test(raw.trim())) return undefined;
  const n = Number(raw.trim());
  return Number.isSafeInteger(n) && n > 0 ? n : undefined;
}

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const windowDays = windowDaysFrom(searchParams);

  try {
    // evaluateAllApplications isolates each of its own sources and reports a
    // failure in `errors` rather than contributing zero rows silently. A throw
    // out of it is therefore a real fault and is surfaced as one — never an
    // empty 200, which would read as "no applications declared".
    const result = await evaluateAllApplications(pool, { windowDays });
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!can(session, OPERATE)) return forbiddenResponse(OPERATE);

  const body = await request.json().catch(() => ({}));
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (!name) {
    return NextResponse.json({ error: 'name is required' }, { status: 400 });
  }

  try {
    const application = await createApplication(
      pool,
      { ...body, name },
      (session.user && session.user.name) || null
    );

    try {
      await logActivity(pool, {
        actor: (session.user && session.user.name) || 'unknown',
        action: 'application_created',
        detail: `Declared application "${application.name}"`,
      });
    } catch (e) { /* the audit line is not worth failing the write for */ }

    return NextResponse.json({ application }, { status: 201 });
  } catch (err) {
    // applications.name is UNIQUE. A duplicate is the caller's mistake and is
    // named as such — a bare 500 would send them looking for a server fault.
    if (err && err.code === '23505') {
      return NextResponse.json(
        { error: `An application named "${name}" already exists.` },
        { status: 409 }
      );
    }
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
