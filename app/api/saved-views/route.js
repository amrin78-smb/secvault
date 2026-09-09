import { NextResponse } from 'next/server';
import { pool } from '../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../auth/[...nextauth]/route';
import { listSavedViews, saveView } from '../../../lib/savedViews';

export const dynamic = 'force-dynamic';

// Saved table views — a named filter/column/sort state, per user.
//
// ⛔ NOT ADMIN-GATED, and that is a deliberate reading of CLAUDE.md's RBAC
// rule rather than an oversight. The rule gates MUTATIONS OF SHARED SYSTEM
// STATE; a viewer changing their own password is already the documented
// exception. A saved view is exactly that class of thing: it is this user's
// own bookmark, it changes no device, no assessment and no score, and a
// read-only operator who cannot save the filter they use every morning is
// being denied the feature for no security benefit.
//
// What DOES the security work here is that `user_id` comes from the SESSION
// and never from the request body, and that the delete is scoped to the owner
// inside the SQL. A viewer cannot reach another user's private view, and
// cannot delete a shared one they do not own.

// A session that cannot own rows. See the session callback in the auth route:
// an LDAP session authenticates fine but has no `users` row, so it has no UUID
// to key saved_views by.
function ownerIdOf(session) {
  const id = session?.user?.id;
  // A local-provider id is a UUID; an LDAP id is a bare username. Checking the
  // SHAPE rather than trusting `provider` means a future third provider cannot
  // silently produce a foreign-key violation at write time.
  if (typeof id !== 'string') return null;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id) ? id : null;
}

const NO_OWNER = {
  error:
    'Saved views need a local SecVault account. This session is authenticated '
    + 'through LDAP, which has no user record to attach views to.',
};

// GET /api/saved-views?scope=devices
export async function GET(request) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const userId = ownerIdOf(session);
  // ⛔ Not an error for a read: an LDAP user simply has no views. Returning an
  // empty list lets the page render normally rather than showing a failure for
  // a feature they were never offered.
  if (!userId) return NextResponse.json({ views: [], canSave: false });

  const scope = new URL(request.url).searchParams.get('scope');
  try {
    const views = await listSavedViews(pool, userId, scope);
    return NextResponse.json({ views, canSave: true });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to list saved views' }, { status: 500 });
  }
}

// POST /api/saved-views — create or update by (scope, name)
export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const userId = ownerIdOf(session);
  if (!userId) return NextResponse.json(NO_OWNER, { status: 400 });

  let body;
  try {
    body = await request.json();
  } catch (_err) {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  try {
    const view = await saveView(pool, userId, {
      scope: body.scope,
      name: body.name,
      query: body.query,
      shared: body.shared,
      isDefault: body.isDefault,
    });
    return NextResponse.json({ view });
  } catch (err) {
    // The validators in lib/savedViews.js throw on a bad name/scope/query, and
    // those are the operator's mistakes to see, not 500s.
    return NextResponse.json({ error: err.message || 'Failed to save view' }, { status: 400 });
  }
}
