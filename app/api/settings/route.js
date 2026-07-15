import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { pool } from '../../../lib/db';

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

  // Handle password change first, if requested.
  if (newPassword) {
    if (!currentPassword) {
      return NextResponse.json(
        { error: 'current_password is required to set a new password' },
        { status: 400 }
      );
    }

    const hashResult = await pool.query(
      "SELECT value FROM settings WHERE key = 'admin_password_hash'",
      []
    );

    const storedHash = hashResult.rows.length > 0 ? hashResult.rows[0].value : null;
    if (!storedHash) {
      return NextResponse.json(
        { error: 'No admin password is currently configured' },
        { status: 400 }
      );
    }

    const valid = await bcrypt.compare(currentPassword, storedHash);
    if (!valid) {
      return NextResponse.json({ error: 'Current password is incorrect' }, { status: 400 });
    }

    const newHash = await bcrypt.hash(newPassword, 10);

    await pool.query(
      `INSERT INTO settings (key, value, updated_at)
       VALUES ('admin_password_hash', $1, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [newHash]
    );
  }

  // Handle feed poll interval update, if provided.
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
