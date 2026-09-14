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

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const days = Number.parseInt(searchParams.get('days') || '', 10);

  try {
    const [result, zones] = await Promise.all([
      evaluateSegmentation(pool, { windowDays: Number.isFinite(days) ? days : undefined }),
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
