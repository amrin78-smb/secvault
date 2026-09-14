import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '../auth/[...nextauth]/route';
import { pool } from '../../../lib/db';
import { can, forbiddenResponse, OPERATE } from '../../../lib/rbac';
import {
  evaluateSegmentation,
  listFleetZones,
  upsertIntent,
  deleteIntent,
  parseWindowDaysParam,
} from '../../../lib/engines/segmentationData';
import { logActivity } from '../../../lib/activityLog';

export const dynamic = 'force-dynamic';

// Declared segmentation intent.
//
// ⛔ GET is ungated like every other read in this app. The mutating handlers are
// gated on OPERATE rather than MANAGE_DEVICES: declaring what SHOULD be true
// between two zones is analysis, not administration — it changes no device, no
// rule and no score, and an operator who cannot record the policy they are
// working to cannot do the job the role exists for.

// ⛔ `days` IS VALIDATED HERE AND RESOLVED EXACTLY ONCE.
//
// `Number.parseInt` + `Number.isFinite` accepted `-5`, `0`, `1e9` and `7abc`.
// A negative or absurd window is not a request this route can honour, and the
// old code did not reject it — it forwarded it, the evidence layer silently
// clamped it to something sane, and the page then printed the number that was
// ASKED FOR next to a measurement taken over a different span: "Evaluated over
// -5 days against 1,757 rules". Garbage in, confident-looking prose out.
//
// So: nonsense is REFUSED with a 400 (the caller gets told, rather than getting
// a plausible page built on a request nobody honoured), and a merely
// out-of-range value is clamped by resolveWindowDays with the ACTUAL window
// returned in `windowDays` and the request echoed in `requestedWindowDays`.
// The response never states a span the evidence does not cover.
//
// The validator itself lives in segmentationData.js: a Next.js route module may
// only export HTTP handlers, so a rule that has to be tested cannot live here.
export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const parsed = parseWindowDaysParam(searchParams.get('days'));
  if (!parsed.ok) return NextResponse.json({ error: parsed.error }, { status: 400 });

  try {
    const [result, zones] = await Promise.all([
      evaluateSegmentation(pool, { windowDays: parsed.days }),
      listFleetZones(pool),
    ]);
    return NextResponse.json({ ...result, zones });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!can(session, OPERATE)) return forbiddenResponse(OPERATE);

  const body = await request.json().catch(() => ({}));
  try {
    const saved = await upsertIntent(pool, {
      sourceZone: body.sourceZone,
      destZone: body.destZone,
      expectation: body.expectation,
      note: body.note,
      createdBy: (session.user && session.user.name) || null,
    });

    try {
      await logActivity(pool, {
        actor: (session.user && session.user.name) || 'unknown',
        action: 'segmentation_intent_set',
        detail: `${saved.sourceZone} -> ${saved.destZone} must ${saved.expectation === 'deny' ? 'NOT be reachable' : 'be reachable'}`,
      });
    } catch (e) { /* the audit line is not worth failing the write for */ }

    return NextResponse.json({ ok: true, intent: saved });
  } catch (err) {
    // upsertIntent throws only on input it refuses, so this is a 400 not a 500.
    return NextResponse.json({ error: err.message }, { status: 400 });
  }
}

export async function DELETE(request) {
  const session = await getServerSession(authOptions);
  if (!can(session, OPERATE)) return forbiddenResponse(OPERATE);

  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id');
  if (!id) return NextResponse.json({ error: 'id is required' }, { status: 400 });

  try {
    const result = await deleteIntent(pool, id);
    return NextResponse.json({ ok: true, ...result });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
