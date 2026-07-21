// lib/credentialProfiles.js
//
// Reusable named credential bundles ("connection profiles") — see
// lib/schema.sql's credential_profiles table comment for the full design
// rationale (not vendor-scoped, no FK to devices, plaintext copied at
// apply-time not referenced live). CommonJS, required directly by
// app/api/credential-profiles/** and app/api/devices/** route files
// (Next.js interops module.exports transparently via `import`, same
// convention as every other lib/*.js file in this app).
//
// credStore.js's encrypt/decrypt are reused directly — its
// getCredential/setCredential are device_id-scoped and don't apply here.
//
// ⛔ NEVER return `encrypted_data`/`iv`, or a decrypted plaintext, from any
// function here except getProfilePlaintext — which exists ONLY for
// server-side use (copying a profile's secret into a device's own
// device_credentials row). Every other function here returns metadata-only
// rows that are safe to hand straight to NextResponse.json.

'use strict';

const { encrypt, decrypt } = require('./credStore');

// Pulls a non-secret username out of a credential plaintext for display
// purposes only — NEVER the password/api_key/enable_password. Best-effort:
// any parse failure (malformed JSON, a 'secret'-shape raw string with no
// JSON structure at all) yields null rather than throwing — this is
// cosmetic, not load-bearing, and must never block a profile create/update
// over a display nicety.
function deriveDisplayUsername(plaintext) {
  if (typeof plaintext !== 'string') return null;
  const trimmed = plaintext.trim();
  if (!trimmed.startsWith('{')) return null; // 'secret' shape, or a bare API token
  try {
    const obj = JSON.parse(trimmed);
    return obj && typeof obj.username === 'string' && obj.username !== '' ? obj.username : null;
  } catch (_err) {
    return null;
  }
}

// Builds credential-profile plaintext directly from a credentialType (not a
// vendor+method pair — profiles are shape-scoped, not vendor-scoped; see
// the schema.sql table comment for why that's safe). Mirrors
// components/devices/vendorMeta.js's buildCredentialPlaintext shape rules
// exactly (same JSON keys, same RAW-string special case for 'smc_api') but
// is deliberately a SEPARATE small function rather than a shared import —
// buildCredentialPlaintext resolves its shape from VENDOR_META[vendor][method],
// which a profile (no vendor) has no way to supply. Returns null when the
// supplied fields don't produce a usable credential for that type.
// snmpVersion/authProtocol/authPassword/privProtocol/privPassword are only
// meaningful for credentialType === 'snmp' — see lib/adapters/
// snmpCredential.js's parseSnmpCredential for the exact stored shape this
// must match. `secret` doubles as the v1/v2c COMMUNITY STRING for this type
// (same "generic secret slot" reuse this function already does for
// smc_api's raw key / rest_api's api_key) — kept as `secret` rather than a
// new param so the SNMP credential form can reuse the same field name/state
// shape as every other credential type in this app.
function buildProfilePlaintext(
  credentialType,
  { authMode, secret, username, password, enablePassword, snmpVersion, authProtocol, authPassword, privProtocol, privPassword } = {}
) {
  if (credentialType === 'smc_api') {
    return secret ? secret : null;
  }
  if (credentialType === 'rest_api') {
    if (authMode === 'userpass') {
      return username && password ? JSON.stringify({ username, password }) : null;
    }
    return secret ? JSON.stringify({ api_key: secret }) : null;
  }
  if (credentialType === 'ssh') {
    if (!username || !password) return null;
    const obj = { username, password };
    if (enablePassword) obj.enable_password = enablePassword;
    return JSON.stringify(obj);
  }
  if (credentialType === 'snmp') {
    if (snmpVersion === 'v3') {
      if (!username) return null;
      return JSON.stringify({
        version: 'v3',
        username,
        authProtocol: authProtocol || null,
        authPassword: authPassword || null,
        privProtocol: privProtocol || null,
        privPassword: privPassword || null,
      });
    }
    if (!secret) return null;
    return JSON.stringify({ version: snmpVersion === 'v1' ? 'v1' : 'v2c', community: secret });
  }
  return null;
}

// Metadata only — never encrypted_data/iv. Safe to return to the browser.
async function listProfiles(pool) {
  if (!pool) throw new Error('listProfiles requires pool parameter');
  const { rows } = await pool.query(
    `SELECT id, name, credential_type, username, created_at, updated_at
     FROM credential_profiles ORDER BY name ASC`
  );
  return rows;
}

async function getProfileMeta(id, pool) {
  if (!pool) throw new Error('getProfileMeta requires pool parameter');
  const { rows } = await pool.query(
    `SELECT id, name, credential_type, username, created_at, updated_at
     FROM credential_profiles WHERE id = $1`,
    [id]
  );
  return rows[0] || null;
}

// Decrypts a profile's plaintext for SERVER-SIDE use only (copying it into
// a device's own device_credentials row via credStore.setCredential) — the
// plaintext itself must never leave this process. Returns null when the
// profile doesn't exist.
async function getProfilePlaintext(id, pool) {
  if (!pool) throw new Error('getProfilePlaintext requires pool parameter');
  const { rows } = await pool.query(
    'SELECT credential_type, encrypted_data, iv FROM credential_profiles WHERE id = $1',
    [id]
  );
  if (rows.length === 0) return null;
  const { credential_type, encrypted_data, iv } = rows[0];
  return { credentialType: credential_type, plaintext: decrypt(encrypted_data, iv) };
}

async function createProfile({ name, credentialType, plaintext }, pool) {
  if (!pool) throw new Error('createProfile requires pool parameter');
  const { encrypted, iv } = encrypt(plaintext);
  const username = deriveDisplayUsername(plaintext);
  const { rows } = await pool.query(
    `INSERT INTO credential_profiles (name, credential_type, username, encrypted_data, iv)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id, name, credential_type, username, created_at, updated_at`,
    [name, credentialType, username, encrypted, iv]
  );
  return rows[0];
}

// `name` and/or `plaintext` may each be omitted (rename-only, rotate-only,
// or both — undefined means "leave alone", distinct from an empty string).
// credential_type is immutable once created — a shape change means a
// different profile, not an edit, mirroring how a single device's own
// credential rotation never changes credential_type either.
async function updateProfile(id, { name, plaintext }, pool) {
  if (!pool) throw new Error('updateProfile requires pool parameter');
  const sets = [];
  const values = [];
  let i = 1;
  if (name !== undefined) {
    sets.push(`name = $${i++}`);
    values.push(name);
  }
  if (plaintext !== undefined) {
    const { encrypted, iv } = encrypt(plaintext);
    sets.push(`encrypted_data = $${i++}`, `iv = $${i++}`, `username = $${i++}`);
    values.push(encrypted, iv, deriveDisplayUsername(plaintext));
  }
  if (sets.length === 0) {
    return getProfileMeta(id, pool);
  }
  sets.push('updated_at = now()');
  values.push(id);
  const { rows } = await pool.query(
    `UPDATE credential_profiles SET ${sets.join(', ')} WHERE id = $${i}
     RETURNING id, name, credential_type, username, created_at, updated_at`,
    values
  );
  return rows[0] || null;
}

async function deleteProfile(id, pool) {
  if (!pool) throw new Error('deleteProfile requires pool parameter');
  await pool.query('DELETE FROM credential_profiles WHERE id = $1', [id]);
}

module.exports = {
  deriveDisplayUsername,
  buildProfilePlaintext,
  listProfiles,
  getProfileMeta,
  getProfilePlaintext,
  createProfile,
  updateProfile,
  deleteProfile,
};
