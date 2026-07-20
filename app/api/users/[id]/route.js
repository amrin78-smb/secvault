import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { getServerSession } from 'next-auth/next';
import { pool } from '../../../../lib/db';
import { authOptions } from '../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse, ADMIN_ROLE, VIEWER_ROLE } from '../../../../lib/rbac';
import { isValidUuid } from '../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

const VALID_ROLES = new Set([ADMIN_ROLE, VIEWER_ROLE]);

// Shared guard: the app must never end up with zero admin users (would
// lock every session out of every write action with no recovery path
// short of a direct DB edit). Used by both the role-change and delete
// paths below.
async function wouldRemoveLastAdmin(pool, userId, { targetRole } = {}) {
  const { rows } = await pool.query(
    "SELECT id, role FROM users WHERE role = 'admin'"
  );
  const remainingAdmins = rows.filter((r) => {
    if (r.id !== userId) return true;
    // If this IS the target user, they still count as admin only if the
    // requested change keeps them admin.
    return targetRole === ADMIN_ROLE;
  });
  return remainingAdmins.length === 0;
}

export async function PUT(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid user id' }, { status: 400 });
  }

  const body = await request.json();
  const nextRole = body?.role;
  const nextPassword = typeof body?.password === 'string' ? body.password : null;

  const existing = await pool.query('SELECT id, username, role FROM users WHERE id = $1', [params.id]);
  if (existing.rows.length === 0) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  if (nextRole !== undefined) {
    if (!VALID_ROLES.has(nextRole)) {
      return NextResponse.json({ error: `role must be one of: ${[...VALID_ROLES].join(', ')}` }, { status: 400 });
    }
    if (nextRole !== ADMIN_ROLE && (await wouldRemoveLastAdmin(pool, params.id, { targetRole: nextRole }))) {
      return NextResponse.json(
        { error: 'Cannot change role — this is the last remaining admin account' },
        { status: 400 }
      );
    }
    await pool.query('UPDATE users SET role = $1, updated_at = now() WHERE id = $2', [nextRole, params.id]);
  }

  if (nextPassword !== null) {
    if (nextPassword.length < 8) {
      return NextResponse.json({ error: 'Password must be at least 8 characters' }, { status: 400 });
    }
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
  if (!isAdmin(session)) {
    return forbiddenResponse();
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
      { error: 'Cannot delete — this is the last remaining admin account' },
      { status: 400 }
    );
  }

  await pool.query('DELETE FROM users WHERE id = $1', [params.id]);
  return NextResponse.json({ ok: true });
}
