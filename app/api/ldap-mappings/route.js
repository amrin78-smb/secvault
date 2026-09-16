import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { pool } from '../../../lib/db';
import { authOptions } from '../auth/[...nextauth]/route';
import { can, MANAGE_USERS, forbiddenResponse } from '../../../lib/rbac';
import * as ldapRoles from '../../../lib/ldapRoles';

export const dynamic = 'force-dynamic';

// ⛔ GATED ON MANAGE_USERS, NOT MANAGE_SETTINGS — so super_admin only.
//
// A mapping here says "everyone in this directory group administers the
// firewall platform". That is the same authority as creating an account, and
// reaching it through a group is not a lesser act than reaching it through the
// Users panel — it is a larger one, because the membership is maintained
// somewhere SecVault cannot see. It belongs with whoever can also create
// accounts, never with every administrator.

function ldapConfigured() {
  return !!(process.env.LDAP_URL || '').trim();
}

/**
 * List the mappings, plus the state the panel must warn about.
 */
export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session || !session.user) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }
  if (!can(session, MANAGE_USERS)) return forbiddenResponse(MANAGE_USERS);

  try {
    const mappings = await ldapRoles.loadMappings(pool);
    return NextResponse.json({
      mappings,
      ldapConfigured: ldapConfigured(),
      // ⛔ THE PANEL MUST BE ABLE TO SAY THIS OUT LOUD. Zero mappings with LDAP
      // switched on means every person who can bind to the directory is an
      // Administrator of this platform right now. That is the state the product
      // shipped in for its whole life, and it is not discoverable from a table
      // that simply looks empty.
      legacyModeActive: ldapConfigured() && mappings.length === 0,
      // A service account is what makes group membership readable at all; the
      // direct-bind fallback cannot search, so it can never map anyone.
      bindAccountConfigured: !!(process.env.LDAP_BIND_DN || '').trim(),
    });
  } catch (err) {
    return NextResponse.json(
      { error: 'The LDAP role mappings could not be read: ' + (err.message || String(err)) },
      { status: 500 }
    );
  }
}

/** Add or update a mapping. */
export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!session || !session.user) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }
  if (!can(session, MANAGE_USERS)) return forbiddenResponse(MANAGE_USERS);

  const body = await request.json().catch(() => ({}));
  const groupDn = typeof body.groupDn === 'string' ? body.groupDn.trim() : '';
  const role = typeof body.role === 'string' ? body.role.trim() : '';
  const description = typeof body.description === 'string' ? body.description.trim() : '';

  if (!groupDn) {
    return NextResponse.json({ error: 'A group DN is required.' }, { status: 400 });
  }
  // ⛔ VALIDATED HERE AS WELL AS IN THE LIB. A role string that is not
  // assignable would store cleanly, display cleanly, and grant NOTHING — the
  // user would authenticate and then be refused by every page, with the mapping
  // looking perfectly healthy on screen.
  if (!ldapRoles.isMappableRole(role)) {
    return NextResponse.json(
      { error: `'${role}' is not an assignable role.` },
      { status: 400 }
    );
  }
  // A DN has at least one `attr=value` component. This is a typo guard, not a
  // schema check — the directory is the authority on whether the group exists.
  if (!/=/.test(groupDn)) {
    return NextResponse.json(
      {
        error: 'That does not look like a group DN. It should be the full distinguished name, '
          + 'e.g. CN=Firewall Admins,OU=Groups,DC=example,DC=com',
      },
      { status: 400 }
    );
  }

  try {
    const saved = await ldapRoles.upsertMapping(pool, { groupDn, role, description });
    const mappings = await ldapRoles.loadMappings(pool);
    return NextResponse.json({
      ok: true,
      mapping: saved,
      // ⛔ Told at the moment it stops being true, because the FIRST mapping
      // changes the behaviour of every other directory user on the next login:
      // legacy mode ends and anyone outside a mapped group is refused.
      legacyModeEnded: mappings.length === 1,
    });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || String(err) },
      { status: 500 }
    );
  }
}

/** Remove a mapping. */
export async function DELETE(request) {
  const session = await getServerSession(authOptions);
  if (!session || !session.user) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }
  if (!can(session, MANAGE_USERS)) return forbiddenResponse(MANAGE_USERS);

  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id');
  if (!id) return NextResponse.json({ error: 'id is required' }, { status: 400 });

  try {
    const removed = await ldapRoles.deleteMapping(pool, id);
    if (!removed) return NextResponse.json({ error: 'No such mapping.' }, { status: 404 });
    const mappings = await ldapRoles.loadMappings(pool);
    return NextResponse.json({
      ok: true,
      // ⛔ REMOVING THE LAST MAPPING RE-OPENS LEGACY MODE, which is a far bigger
      // change than "one row deleted" — the whole directory becomes
      // Administrators again on their next login. Saying so here is what stops
      // that being discovered months later.
      legacyModeReopened: mappings.length === 0 && ldapConfigured(),
    });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || String(err) },
      { status: 500 }
    );
  }
}
