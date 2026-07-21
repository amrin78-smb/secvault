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
//   { name, credential_type, auth_mode?, secret?, username?, password?, enable_password?,
//     snmp_version?, auth_protocol?, auth_password?, priv_protocol?, priv_password?, insecure_ack? }
// Mirrors buildCredentialPlaintext's shape rules (components/devices/vendorMeta.js),
// keyed by credential_type instead of vendor+method (see
// lib/credentialProfiles.js's buildProfilePlaintext comment for why that's
// a deliberately separate function):
//   credential_type 'smc_api'  → `secret` (raw string, e.g. Forcepoint SMC API key)
//   credential_type 'rest_api' → `secret` (api key) OR `username`+`password` (auth_mode: 'userpass')
//   credential_type 'ssh'      → `username`+`password`(+`enable_password`?)
//   credential_type 'snmp'     → `snmp_version` 'v1'|'v2c'|'v3'; v3: `username`+optional
//                                auth/priv fields; v1/v2c: `secret` as the community string
// The plaintext is built here server-side (never trusted pre-built from the
// client) so a profile's stored shape can never disagree with its declared
// credential_type.
//
// SNMP-specific security gate (see CLAUDE.md's SNMP Monitoring section):
// v1/v2c carries its community string in CLEARTEXT on the wire — a real,
// novel risk class for this app (SSH/HTTPS are both encrypted transports).
// Creating a v1/v2c profile requires `insecure_ack: true` in the same
// request; v3 never needs it. Checked server-side, not just hidden behind a
// UI checkbox, so a direct API call can't silently bypass the warning.
export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  const body = await request.json().catch(() => ({}));
  const {
    name,
    credential_type,
    auth_mode,
    secret,
    username,
    password,
    enable_password,
    snmp_version,
    auth_protocol,
    auth_password,
    priv_protocol,
    priv_password,
    insecure_ack,
  } = body || {};

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
  if (credential_type === 'snmp' && snmp_version !== 'v3' && !insecure_ack) {
    return NextResponse.json(
      {
        error:
          'SNMPv1/v2c sends the community string in cleartext on the wire. Set insecure_ack to confirm you understand the risk, or use SNMPv3 instead.',
      },
      { status: 400 }
    );
  }

  const plaintext = buildProfilePlaintext(credential_type, {
    authMode: auth_mode,
    secret,
    username,
    password,
    enablePassword: enable_password,
    snmpVersion: snmp_version,
    authProtocol: auth_protocol,
    authPassword: auth_password,
    privProtocol: priv_protocol,
    privPassword: priv_password,
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
