import { NextResponse } from 'next/server';
import { pool } from '../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { deleteSavedView } from '../../../../lib/savedViews';

export const dynamic = 'force-dynamic';

// See ../route.js for why saved views are not admin-gated.
function ownerIdOf(session) {
  const id = session?.user?.id;
  if (typeof id !== 'string') return null;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id) ? id : null;
}

// DELETE /api/saved-views/<id>
export async function DELETE(_request, { params }) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const userId = ownerIdOf(session);
  if (!userId) return NextResponse.json({ error: 'Saved views need a local SecVault account.' }, { status: 400 });

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
