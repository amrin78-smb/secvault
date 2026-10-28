import { NextResponse } from 'next/server';
import { pool } from '../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { deleteSavedView } from '../../../../lib/savedViews';

export const dynamic = 'force-dynamic';

// See ../route.js for why saved views are not admin-gated, and for the full ⛔
// block on why the OWNER IS DECIDED BY PROVIDER AND NEVER BY THE SHAPE OF THE
// ID: an Entra `oid` is a GUID, so the shape test that used to live here read
// an Entra session as a local account.
//
// ⛔ DUPLICATED FROM ../route.js, DELIBERATELY — two route files, one rule. If
// either copy changes, change both in the same commit.
const OWNING_PROVIDERS = new Set(['local']);
const NON_OWNING_PROVIDERS = new Set(['ldap', 'entra']);
const LOCAL_ID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const OWNER_STATES = { OWNER: 'owner', NON_OWNING: 'non-owning', UNKNOWN: 'unknown' };

function ownerOf(session) {
  const id = session?.user?.id;
  const provider = session?.user?.provider;
  if (typeof provider !== 'string' || provider === '') {
    return { state: OWNER_STATES.UNKNOWN, userId: null, provider: null };
  }
  if (typeof id !== 'string' || id === '') {
    return { state: OWNER_STATES.UNKNOWN, userId: null, provider };
  }
  if (NON_OWNING_PROVIDERS.has(provider)) {
    return { state: OWNER_STATES.NON_OWNING, userId: null, provider };
  }
  if (!OWNING_PROVIDERS.has(provider)) {
    return { state: OWNER_STATES.UNKNOWN, userId: null, provider };
  }
  if (!LOCAL_ID_SHAPE.test(id)) {
    return { state: OWNER_STATES.UNKNOWN, userId: null, provider };
  }
  return { state: OWNER_STATES.OWNER, userId: id, provider };
}

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
