import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { getServerSession } from 'next-auth/next';
import { pool } from '../../../lib/db';
import { authOptions } from '../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse, ADMIN_ROLE, VIEWER_ROLE } from '../../../lib/rbac';

export const dynamic = 'force-dynamic';

const VALID_ROLES = new Set([ADMIN_ROLE, VIEWER_ROLE]);

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  const result = await pool.query(
    'SELECT id, username, role, created_at, updated_at FROM users ORDER BY username'
  );
  return NextResponse.json({ users: result.rows });
}

export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  const body = await request.json();
  const username = typeof body?.username === 'string' ? body.username.trim() : '';
  const password = typeof body?.password === 'string' ? body.password : '';
  const role = VALID_ROLES.has(body?.role) ? body.role : VIEWER_ROLE;

  if (!username) {
    return NextResponse.json({ error: 'username is required' }, { status: 400 });
  }
  if (password.length < 8) {
    return NextResponse.json({ error: 'Password must be at least 8 characters' }, { status: 400 });
  }

  const existing = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
  if (existing.rows.length > 0) {
    return NextResponse.json({ error: 'A user with that username already exists' }, { status: 409 });
  }

  const hash = await bcrypt.hash(password, 10);
  const result = await pool.query(
    `INSERT INTO users (username, password_hash, role)
     VALUES ($1, $2, $3)
     RETURNING id, username, role, created_at, updated_at`,
    [username, hash, role]
  );

  return NextResponse.json({ user: result.rows[0] }, { status: 201 });
}
