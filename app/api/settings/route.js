import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { getServerSession } from 'next-auth/next';
import { pool } from '../../../lib/db';
import { authOptions } from '../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../lib/rbac';

export const dynamic = 'force-dynamic';

// Keys that must never be returned over the API.
const HIDDEN_KEYS = new Set(['admin_password_hash']);

export async function GET() {
  const result = await pool.query('SELECT key, value FROM settings', []);

  const settings = {};
  for (const row of result.rows) {
    if (HIDDEN_KEYS.has(row.key)) continue;
    settings[row.key] = row.value;
  }

  return NextResponse.json(settings);
}

export async function PUT(request) {
  const body = await request.json();

  const {
    feed_poll_interval_hours: feedPollIntervalHours,
    current_password: currentPassword,
    new_password: newPassword,
  } = body || {};

  const session = await getServerSession(authOptions);
  if (!session || !session.user) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }

  // Authorize every requested change BEFORE performing any DB write, so a
  // request combining a self-service password change with an admin-only
  // field can never partially commit (password changed) while still
  // reporting 403 for the whole call. Feed poll interval is a global app
  // setting, admin-only.
  if (feedPollIntervalHours !== undefined && feedPollIntervalHours !== null) {
    if (!isAdmin(session)) {
      return forbiddenResponse();
    }
  }

  // Handle password change first, if requested. Changing YOUR OWN password
  // is allowed for any authenticated user (admin or viewer), not gated on
  // isAdmin() — this is self-service account management, not an
  // administrative action. RBAC: identity now lives in the `users` table,
  // not the old global settings.admin_password_hash single-identity row —
  // see lib/schema.sql / lib/migrate.js's seedUsers().
  if (newPassword) {
    if (!currentPassword) {
      return NextResponse.json(
        { error: 'current_password is required to set a new password' },
        { status: 400 }
      );
    }

    if (newPassword.length < 8) {
      return NextResponse.json(
        { error: 'New password must be at least 8 characters' },
        { status: 400 }
      );
    }

    const userResult = await pool.query(
      'SELECT id, password_hash FROM users WHERE username = $1',
      [session.user.name]
    );
    const storedUser = userResult.rows[0];
    if (!storedUser) {
      // LDAP-bound sessions have no row in `users` — their password lives
      // in LDAP/AD, not here, so there is nothing local to change.
      return NextResponse.json(
        { error: 'Password changes are only available for local accounts' },
        { status: 400 }
      );
    }

    const valid = await bcrypt.compare(currentPassword, storedUser.password_hash);
    if (!valid) {
      return NextResponse.json({ error: 'Current password is incorrect' }, { status: 400 });
    }

    const newHash = await bcrypt.hash(newPassword, 10);

    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2',
      [newHash, storedUser.id]
    );
  }

  // Handle feed poll interval update, if provided. Admin check already
  // performed above, before any write occurred.
  if (feedPollIntervalHours !== undefined && feedPollIntervalHours !== null) {
    await pool.query(
      `INSERT INTO settings (key, value, updated_at)
       VALUES ('feed_poll_interval_hours', $1, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [String(feedPollIntervalHours)]
    );
  }

  return NextResponse.json({ ok: true });
}
