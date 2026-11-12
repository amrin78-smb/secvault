import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { getServerSession } from 'next-auth/next';
import { pool } from '../../../../lib/db';
import { authOptions } from '../../auth/[...nextauth]/route';
import { can, MANAGE_USERS, forbiddenResponse, ASSIGNABLE_ROLES, OPERATOR_ROLE, SUPER_ADMIN_ROLE, isAssignableRole } from '../../../../lib/rbac';
import { isValidUuid } from '../../../../lib/apiUtils';
import { scopeAssignmentRefusal } from '../../../../lib/deviceScope';

export const dynamic = 'force-dynamic';

// ⛔ Sourced from lib/rbac.js rather than re-listed here. A role this file
// accepted but the capability matrix did not recognise would be stored on a
// real account and then grant nothing, which reads as a broken login rather
// than a rejected input.
const VALID_ROLES = new Set(ASSIGNABLE_ROLES);

// Shared guard: the app must never end up with zero admin users (would
// lock every session out of every write action with no recovery path
// short of a direct DB edit). Used by both the role-change and delete
// paths below.
async function wouldRemoveLastAdmin(pool, userId, { targetRole } = {}) {
  const { rows } = await pool.query(
    // ⛔ SUPER_ADMIN, not admin. Only super_admin holds MANAGE_USERS, so
    // deleting or demoting the last one leaves an installation in which NOBODY
    // can ever create or change a user account again — recoverable only by a
    // direct database edit. The guard follows the capability, not the word.
    "SELECT id, role FROM users WHERE role = 'super_admin'"
  );
  const remainingAdmins = rows.filter((r) => {
    if (r.id !== userId) return true;
    // If this IS the target user, they still count only if the requested change
    // LEAVES THEM A SUPER ADMIN.
    //
    // ⛔ This read `targetRole === ADMIN_ROLE`, which was wrong twice over: the
    // identifier was never imported (so every role change and every
    // super_admin deletion threw ReferenceError and 500'd — the guard has never
    // once executed), and the comparison itself named the wrong role. Demoting
    // the last super_admin to `admin` would have counted them as still holding
    // the role. The comment directly above already stated the correct rule; the
    // code did the opposite.
    return targetRole === SUPER_ADMIN_ROLE;
  });
  return remainingAdmins.length === 0;
}

export async function PUT(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_USERS)) {
    return forbiddenResponse(MANAGE_USERS);
  }
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid user id' }, { status: 400 });
  }

  const body = await request.json().catch(() => ({}));
  const nextRole = body?.role;
  const nextPassword = typeof body?.password === 'string' ? body.password : null;

  const existing = await pool.query('SELECT id, username, role FROM users WHERE id = $1', [params.id]);
  if (existing.rows.length === 0) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  // ⛔ VALIDATE EVERYTHING BEFORE THE FIRST WRITE.
  //
  // This used to apply the role change and only THEN check the password
  // length, so `{role:'viewer', password:'short'}` COMMITTED the demotion and
  // then returned 400. The UI reported failure while the account had already
  // been demoted; the admin retried and never learned the role had changed.
  // Same discipline app/api/settings/route.js already documents for its own
  // mixed password/setting request.
  if (nextRole !== undefined) {
    if (!VALID_ROLES.has(nextRole)) {
      return NextResponse.json({ error: `role must be one of: ${[...VALID_ROLES].join(', ')}` }, { status: 400 });
    }
  }
  if (nextPassword !== null && nextPassword.length < 8) {
    return NextResponse.json({ error: 'Password must be at least 8 characters' }, { status: 400 });
  }
  // Last-admin check is a DB read, so it stays with the other validations but
  // must run after the cheap ones.
  // ⛔ Runs whenever the new role is anything OTHER than super_admin — which
  // includes `admin`. Reading `!== ADMIN_ROLE` here skipped the check on
  // exactly the demotion most likely to be attempted, leaving an installation
  // where nobody holds MANAGE_USERS and no account can ever be changed again
  // without a direct database edit.
  if (nextRole !== undefined && nextRole !== SUPER_ADMIN_ROLE) {
    if (await wouldRemoveLastAdmin(pool, params.id, { targetRole: nextRole })) {
      return NextResponse.json(
        { error: 'Cannot change role — this is the last remaining Super Admin account' },
        { status: 400 }
      );
    }
  }

  // ⛔ THE SAME LOCKOUT `scopeAssignmentRefusal` PREVENTS, REACHED FROM THE OTHER
  // SIDE. That guard refuses SCOPING an account that already holds
  // MANAGE_USERS, because /api/users/[id]/device-scope is itself a `blocked`
  // surface — so a scoped holder is 403'd by middleware on the only endpoint
  // that can undo it. Until 2026-11-13 it had exactly ONE call site (the scope
  // route), and PROMOTING an already-scoped account into MANAGE_USERS reached
  // the identical end state with nothing consulted: scope an operator to two
  // firewalls, promote them to super_admin, and both calls are accepted.
  //
  // ⛔ IT HIDES BECAUSE THE COMMON PROMOTION IS SAFE. `admin` does not hold
  // MANAGE_USERS and is scopable by design, so only the super_admin promotion
  // trips it — and if that account is then the last Super Admin, recovery is a
  // direct database edit. Exactly what the last-super_admin guard above exists
  // to prevent, and the same authority.
  //
  // ⛔ A FAILED SCOPE READ REFUSES THE PROMOTION. `loadScopeForUser` returning
  // `unknown` means we do not know whether this account carries scope rows, and
  // proceeding on "probably none" is how the lockout happens. Refusing costs a
  // retry; guessing costs a database edit.
  if (nextRole !== undefined) {
    let scopedDeviceIds;
    try {
      // ⛔ A COUNT, NOT THE IDS, AND THAT IS DELIBERATE TWICE OVER. The guard
      // reads only the LENGTH, and the refusal sentence quotes only a number —
      // so the identities are not needed. Selecting `device_id` here instead
      // put this route into the device-data register (`DEVICE_RE` in
      // tests/deviceScopeCoverage.test.js matches the column name), which
      // would have forced it from `no-device-data` to `blocked`. That is not a
      // free reclassification: `/api/users/[id]` is the route by which a
      // legacy already-scoped Super Admin can demote itself to `admin` — a
      // role that IS scopable — and blocking it would remove that recovery
      // while adding no protection, because a scoped account can never hold
      // `manage_users` to reach this route in the first place.
      const held = await pool.query(
        'SELECT count(*)::int AS scoped FROM user_device_scopes WHERE user_id = $1',
        [params.id]
      );
      const scopedCount = held.rows.length ? held.rows[0].scoped : 0;
      scopedDeviceIds = new Array(scopedCount).fill(1);
    } catch (err) {
      return NextResponse.json(
        {
          error: 'Could not read this account’s device scope, so the role change was not applied. '
            + 'An account that can manage users may not be restricted to specific firewalls, and '
            + 'without that read we cannot tell whether this one is. Try again.',
        },
        { status: 503 }
      );
    }
    const lockout = scopeAssignmentRefusal(nextRole, scopedDeviceIds);
    if (lockout) {
      return NextResponse.json(
        {
          error: `${lockout} This account is currently restricted to ${scopedDeviceIds.length} `
            + 'firewall(s); clear its device scope first.',
        },
        { status: 409 }
      );
    }
  }

  // Every check has passed; the writes below cannot be rejected halfway.
  if (nextRole !== undefined) {
    await pool.query('UPDATE users SET role = $1, updated_at = now() WHERE id = $2', [nextRole, params.id]);
  }
  if (nextPassword !== null) {
    const hash = await bcrypt.hash(nextPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2', [hash, params.id]);
  }

  const result = await pool.query(
    'SELECT id, username, role, created_at, updated_at FROM users WHERE id = $1',
    [params.id]
  );
  return NextResponse.json({ user: result.rows[0] });
}

export async function DELETE(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_USERS)) {
    return forbiddenResponse(MANAGE_USERS);
  }
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid user id' }, { status: 400 });
  }

  const existing = await pool.query('SELECT id, username FROM users WHERE id = $1', [params.id]);
  if (existing.rows.length === 0) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  if (session.user?.name === existing.rows[0].username) {
    return NextResponse.json({ error: 'Cannot delete your own account while logged in' }, { status: 400 });
  }

  if (await wouldRemoveLastAdmin(pool, params.id, { targetRole: null })) {
    return NextResponse.json(
      { error: 'Cannot delete — this is the last remaining Super Admin account' },
      { status: 400 }
    );
  }

  await pool.query('DELETE FROM users WHERE id = $1', [params.id]);
  return NextResponse.json({ ok: true });
}
