import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { pool } from '../../../../../lib/db';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { can, forbiddenResponse, MANAGE_USERS } from '../../../../../lib/rbac';
import * as mfa from '../../../../../lib/mfa';
import { logActivity } from '../../../../../lib/activityLog';

export const dynamic = 'force-dynamic';

// Administrative MFA control over ANOTHER account — the second of the three
// documented ways back in after a lost authenticator (recovery codes first, the
// offline script last).
//
// ⛔ MANAGE_USERS, so Super Admin only. Resetting someone's second factor is
// exactly as powerful as resetting their password: it removes an authentication
// requirement from an account you do not own. It belongs with user management,
// not with "administers the fleet".

export async function GET(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_USERS)) return forbiddenResponse(MANAGE_USERS);
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid user id' }, { status: 400 });
  }
  return NextResponse.json(await mfa.getStatus(pool, params.id));
}

/** Require (or stop requiring) MFA on an account. */
export async function PUT(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_USERS)) return forbiddenResponse(MANAGE_USERS);
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid user id' }, { status: 400 });
  }

  const body = await request.json().catch(() => ({}));
  if (typeof body.required !== 'boolean') {
    return NextResponse.json({ error: 'required must be true or false' }, { status: 400 });
  }

  const target = await pool.query('SELECT username FROM users WHERE id = $1', [params.id]);
  if (target.rows.length === 0) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  await mfa.setRequired(pool, params.id, body.required);

  try {
    await logActivity(pool, {
      actor: session.user.name || 'unknown',
      action: body.required ? 'mfa_required' : 'mfa_requirement_removed',
      detail: `MFA requirement ${body.required ? 'set' : 'removed'} for '${target.rows[0].username}'`,
    });
  } catch (err) {
    console.warn(`[users mfa route] activity log failed: ${err.message}`);
  }

  return NextResponse.json({ ok: true, required: body.required });
}

/**
 * Reset another account's MFA — the "they lost their phone" path.
 *
 * ⛔ A SUPER ADMIN MAY NOT RESET THEIR OWN. Not because it is dangerous, but
 * because it is pointless and misleading: to reach this route they are already
 * authenticated, so it would simply strip their own second factor with one
 * click from an unlocked browser. Their own path is DELETE /api/mfa, which
 * requires a current code. Self-service and administration stay separate.
 */
export async function DELETE(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_USERS)) return forbiddenResponse(MANAGE_USERS);
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid user id' }, { status: 400 });
  }

  if (session.user && session.user.id === params.id) {
    return NextResponse.json(
      {
        error:
          'Use your own security settings to change your MFA — that path requires a current code. '
          + 'This action is for resetting someone else\'s lost authenticator.',
      },
      { status: 400 }
    );
  }

  const target = await pool.query('SELECT username FROM users WHERE id = $1', [params.id]);
  if (target.rows.length === 0) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  const result = await mfa.resetFor(pool, params.id);

  try {
    await logActivity(pool, {
      actor: session.user.name || 'unknown',
      action: 'mfa_reset',
      detail: `MFA reset for '${target.rows[0].username}' — they must enrol a new device`,
    });
  } catch (err) {
    console.warn(`[users mfa route] activity log failed: ${err.message}`);
  }

  return NextResponse.json({ ok: true, reset: result.reset });
}
