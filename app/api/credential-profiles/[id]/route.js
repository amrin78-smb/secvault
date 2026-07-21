import { NextResponse } from 'next/server';
import { pool } from '../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../lib/rbac';
import { isValidUuid } from '../../../../lib/apiUtils';
import { getProfileMeta, updateProfile, deleteProfile, buildProfilePlaintext } from '../../../../lib/credentialProfiles';

export const dynamic = 'force-dynamic';

// PUT /api/credential-profiles/[id] — rename and/or rotate the stored
// secret. Body: { name?, auth_mode?, secret?, username?, password?, enable_password? }.
// Rotation is DETECTED (any secret-bearing field present), not an explicit
// flag — `name`-only bodies rename without touching the secret, matching
// PUT /api/users/[id]'s "role and/or password, either optional" shape.
//
// credential_type is immutable — see lib/credentialProfiles.js's
// updateProfile comment. A shape change means creating a new profile.
export async function PUT(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid profile id' }, { status: 400 });
  }

  const existing = await getProfileMeta(params.id, pool);
  if (!existing) {
    return NextResponse.json({ error: 'Credential profile not found' }, { status: 404 });
  }

  const body = await request.json().catch(() => ({}));
  const {
    name,
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

  const trimmedName = typeof name === 'string' ? name.trim() : undefined;
  if (trimmedName !== undefined && !trimmedName) {
    return NextResponse.json({ error: 'name cannot be empty' }, { status: 400 });
  }

  const rotating = Boolean(secret || (username && password) || (existing.credential_type === 'snmp' && username));
  let plaintext;
  if (rotating) {
    // Same cleartext-on-the-wire gate as POST above — a v1/v2c profile's
    // secret rotation is just as exposed as its initial creation.
    if (existing.credential_type === 'snmp' && snmp_version !== 'v3' && !insecure_ack) {
      return NextResponse.json(
        {
          error:
            'SNMPv1/v2c sends the community string in cleartext on the wire. Set insecure_ack to confirm you understand the risk, or use SNMPv3 instead.',
        },
        { status: 400 }
      );
    }
    plaintext = buildProfilePlaintext(existing.credential_type, {
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
  }

  if (trimmedName === undefined && plaintext === undefined) {
    return NextResponse.json({ error: 'Nothing to update' }, { status: 400 });
  }

  try {
    if (trimmedName !== undefined && trimmedName !== existing.name) {
      const dupe = await pool.query('SELECT id FROM credential_profiles WHERE name = $1 AND id <> $2', [
        trimmedName,
        params.id,
      ]);
      if (dupe.rows.length > 0) {
        return NextResponse.json({ error: 'A profile with that name already exists' }, { status: 409 });
      }
    }
    const profile = await updateProfile(params.id, { name: trimmedName, plaintext }, pool);
    return NextResponse.json({ profile });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to update credential profile' },
      { status: 500 }
    );
  }
}

// DELETE — no cascade concerns: applying a profile copies its plaintext
// into the consuming device's own device_credentials row at that moment
// (see schema.sql's credential_profiles comment), so deleting a profile
// never affects any device that already used it.
export async function DELETE(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid profile id' }, { status: 400 });
  }

  const existing = await getProfileMeta(params.id, pool);
  if (!existing) {
    return NextResponse.json({ error: 'Credential profile not found' }, { status: 404 });
  }

  try {
    await deleteProfile(params.id, pool);
    return NextResponse.json({ ok: true });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to delete credential profile' },
      { status: 500 }
    );
  }
}
