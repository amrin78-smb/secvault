import { NextResponse } from 'next/server';
import { pool } from '../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../lib/rbac';
import { listProfiles, createProfile, buildProfilePlaintext } from '../../../lib/credentialProfiles';
import { CREDENTIAL_TYPES } from '../../../components/devices/vendorMeta';

export const dynamic = 'force-dynamic';

// GET /api/credential-profiles — list saved connection profiles (metadata
// only — id/name/credential_type/username/timestamps, never the encrypted
// secret). Admin-gated like GET /api/users: a profile is only ever consumed
// from an already admin-only flow (Add Device, credential rotation), so
// there is no viewer-facing use for this list — same "err toward the
// credential-adjacent default" posture as every other secret-bearing
// management surface in this app.
export async function GET() {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }
  try {
    const profiles = await listProfiles(pool);
    return NextResponse.json({ profiles });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to list credential profiles' },
      { status: 500 }
    );
  }
}

// POST /api/credential-profiles — create a new profile. Body:
//   { name, credential_type, auth_mode?, secret?, username?, password?, enable_password? }
// Mirrors buildCredentialPlaintext's shape rules (components/devices/vendorMeta.js),
// keyed by credential_type instead of vendor+method (see
// lib/credentialProfiles.js's buildProfilePlaintext comment for why that's
// a deliberately separate function):
//   credential_type 'smc_api'  → `secret` (raw string, e.g. Forcepoint SMC API key)
//   credential_type 'rest_api' → `secret` (api key) OR `username`+`password` (auth_mode: 'userpass')
//   credential_type 'ssh'      → `username`+`password`(+`enable_password`?)
// The plaintext is built here server-side (never trusted pre-built from the
// client) so a profile's stored shape can never disagree with its declared
// credential_type.
export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  const body = await request.json().catch(() => ({}));
  const { name, credential_type, auth_mode, secret, username, password, enable_password } = body || {};

  const trimmedName = typeof name === 'string' ? name.trim() : '';
  if (!trimmedName) {
    return NextResponse.json({ error: 'name is required' }, { status: 400 });
  }
  if (!CREDENTIAL_TYPES.includes(credential_type)) {
    return NextResponse.json(
      { error: `credential_type must be one of: ${CREDENTIAL_TYPES.join(', ')}` },
      { status: 400 }
    );
  }

  const plaintext = buildProfilePlaintext(credential_type, {
    authMode: auth_mode,
    secret,
    username,
    password,
    enablePassword: enable_password,
  });
  if (!plaintext) {
    return NextResponse.json({ error: 'No usable credential fields provided' }, { status: 400 });
  }

  try {
    const dupe = await pool.query('SELECT id FROM credential_profiles WHERE name = $1', [trimmedName]);
    if (dupe.rows.length > 0) {
      return NextResponse.json({ error: 'A profile with that name already exists' }, { status: 409 });
    }
    const profile = await createProfile(
      { name: trimmedName, credentialType: credential_type, plaintext },
      pool
    );
    return NextResponse.json({ profile }, { status: 201 });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to create credential profile' },
      { status: 500 }
    );
  }
}
