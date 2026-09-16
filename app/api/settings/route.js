import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { getServerSession } from 'next-auth/next';
import { pool } from '../../../lib/db';
import { authOptions } from '../auth/[...nextauth]/route';
import { can, MANAGE_SETTINGS, forbiddenResponse } from '../../../lib/rbac';
import { licenceBlockForWrite } from '../../../lib/productLicenseData';

export const dynamic = 'force-dynamic';

// Keys that must never be returned over the API.
//
// ⛔ `product_license_key` is here because NOTHING NEEDS IT BACK. The licence
// verdict is served by /api/license, which returns what the UI renders and
// never the key itself; handing the raw key to every signed-in session through
// the generic settings endpoint would put a commercial credential in browser
// network logs for no purpose. It is not a secret the way the password hash is
// — it names one machine and one expiry — which is exactly why it is easy to
// leave lying around.
const HIDDEN_KEYS = new Set(['admin_password_hash', 'product_license_key']);

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
  const body = await request.json().catch(() => ({}));

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
    if (!can(session, MANAGE_SETTINGS)) {
      return forbiddenResponse(MANAGE_SETTINGS);
    }
    // ⛔ INSIDE THIS BRANCH, NOT AT THE TOP OF THE HANDLER. The licence gate
    // covers the ADMIN setting only; the self-service password change below is
    // deliberately left reachable in every licence state. Refusing to let
    // someone change their own password because an invoice is late would make a
    // billing state into an account-security problem, on a security product.
    const licenceBlock = await licenceBlockForWrite(pool);
    if (licenceBlock) return NextResponse.json(licenceBlock.body, { status: licenceBlock.status });
    // ⛔ VALIDATE. Confirmed live: settings.feed_poll_interval_hours holds an
    // EMPTY STRING in production, because a blank form field arrives as '' —
    // which is neither undefined nor null, so it passed this guard and was
    // stored via String(''). The engine worker then warns
    // 'value "" is not a valid integer between 1 and 24 — falling back to 6'
    // on EVERY startup, and the configured interval silently does nothing.
    // Reject it here rather than persist a value the reader must reject.
    const parsed = Number.parseInt(feedPollIntervalHours, 10);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > 24) {
      return NextResponse.json(
        { error: 'feed_poll_interval_hours must be a whole number between 1 and 24' },
        { status: 400 }
      );
    }
  }

  // Handle password change first, if requested. Changing YOUR OWN password
  // is allowed for ANY authenticated user regardless of role — including an
  // operator — and is deliberately not gated on a capability: this is
  // self-service account management, not an
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
      [String(Number.parseInt(feedPollIntervalHours, 10))]
    );
  }

  return NextResponse.json({ ok: true });
}
