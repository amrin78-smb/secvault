import { NextResponse } from 'next/server';
import { pool } from '../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { deleteSavedView } from '../../../../lib/savedViews';
import { ownerOf, OWNER_STATES } from '../../../../lib/sessionOwner';

export const dynamic = 'force-dynamic';

// See ../route.js for why saved views are not admin-gated, and for the full ⛔
// block on why the OWNER IS DECIDED BY PROVIDER AND NEVER BY THE SHAPE OF THE
// ID: an Entra `oid` is a GUID, so the shape test that used to live here read
// an Entra session as a local account.
//
// ⛔ THE RULE NOW LIVES IN lib/sessionOwner.js. This file and ../route.js each
// carried their own copy of it under a comment reading "change both in the
// same commit" — a hope, not an invariant. A fourth provider added to one copy
// and missed in the other would give an account that can CREATE saved views
// and never delete one, told by a 500 that it is a fault rather than a
// limitation. A third copy in /api/mfa was still deciding on the id's SHAPE,
// which an Entra GUID defeats, and that one was live.
// DELETE /api/saved-views/<id>
export async function DELETE(_request, { params }) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const owner = ownerOf(session);
  // A directory account cannot own a view, so it cannot be holding one to
  // delete — a limitation to explain, with a 400.
  if (owner.state === OWNER_STATES.NON_OWNING) {
    return NextResponse.json(
      {
        error: 'Saved views need a local SecVault account. This session is authenticated '
          + 'through a directory, which has no SecVault user record to attach views to.',
      },
      { status: 400 }
    );
  }
  // ⛔ A SESSION WE CANNOT ATTRIBUTE IS A FAULT, NOT A BAD REQUEST, and it must
  // never be answered by deleting something: `deleteSavedView` is owner-scoped
  // in its own SQL, and an owner id we are not sure of has no business being
  // bound into it.
  if (owner.state !== OWNER_STATES.OWNER) {
    console.warn(`[saved-views] refused a delete for an unidentifiable session (provider `
      + `'${owner.provider}')`);
    return NextResponse.json(
      {
        error: 'The account behind this session could not be identified, so no saved view was '
          + 'deleted. This is a fault, not a permission — report it rather than requesting access.',
      },
      { status: 500 }
    );
  }
  const userId = owner.userId;

  try {
    // ⛔ Ownership is enforced in the DELETE's own WHERE clause
    // (lib/savedViews.js), not here. A shared view is visible to everyone and
    // must still only be removable by the person who made it; putting that
    // condition in the SQL means no future caller can forget it.
    //
    // A miss returns 404 rather than 403 on purpose: distinguishing "this view
    // does not exist" from "this view is not yours" would confirm the existence
    // of another user's private view to anyone who guessed an id.
    const ok = await deleteSavedView(pool, userId, params.id);
    if (!ok) return NextResponse.json({ error: 'View not found' }, { status: 404 });
    return NextResponse.json({ ok: true });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to delete view' }, { status: 500 });
  }
}
