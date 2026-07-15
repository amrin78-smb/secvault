import { NextResponse } from 'next/server';
import { pool } from '../../../../lib/db';
import { setCredential } from '../../../../lib/credStore';
import { VENDOR_META, VENDOR_SLUGS, CREDENTIAL_TYPES } from '../../../../components/devices/vendorMeta';

export const dynamic = 'force-dynamic';

// Whitelist of devices-table columns that PUT is allowed to update — keeps the
// dynamically-built SET clause safe even though column names are interpolated
// (values themselves are always parameterized).
// NOTE: mgmt_method is intentionally NOT in this list — it is always derived
// server-side from the vendor slug, never trusted from the client.
const UPDATABLE_FIELDS = [
  'name',
  'vendor',
  'mgmt_ip',
  'mgmt_port',
  'smc_host',
  'smc_port',
  'allow_self_signed_ssl',
  'site',
  'asset_criticality',
  'active',
];

// Coerces a client-supplied port to a valid integer, or null. Never throws —
// mgmt_port / smc_port are nullable and old rows may not have them at all.
function coercePort(value) {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

export async function GET(request, { params }) {
  try {
    const result = await pool.query('SELECT * FROM devices WHERE id = $1', [params.id]);
    if (result.rows.length === 0) {
      return NextResponse.json({ error: 'Device not found' }, { status: 404 });
    }
    return NextResponse.json(result.rows[0]);
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to load device' }, { status: 500 });
  }
}

// PUT /api/devices/[id] — updates device fields. Credentials are routed through
// credStore.setCredential rather than written to the devices table — the devices
// table must never hold plaintext credentials, and plaintext is never echoed back
// in the response or logged.
//
// Credential inputs:
//   { credential, credential_type }  — generic path (credential_type validated
//                                      against CREDENTIAL_TYPES)
//   { smc_api_key }                  — legacy Forcepoint-only field, kept for
//                                      backward compatibility (maps to 'smc_api')
export async function PUT(request, { params }) {
  const body = await request.json().catch(() => ({}));
  const { smc_api_key, credential, credential_type, mgmt_method: _ignored, ...rest } = body || {};

  // Validate vendor (if being updated) and derive mgmt_method from it server-side.
  if (rest.vendor !== undefined) {
    const meta = VENDOR_META[rest.vendor];
    if (!meta) {
      return NextResponse.json(
        { error: `vendor must be one of: ${VENDOR_SLUGS.join(', ')}` },
        { status: 400 }
      );
    }
    rest.mgmt_method = meta.mgmtMethod;
  }

  if (rest.mgmt_port !== undefined) rest.mgmt_port = coercePort(rest.mgmt_port);
  if (rest.smc_port !== undefined) rest.smc_port = coercePort(rest.smc_port);

  // Resolve credential to store — validated before any write happens.
  let credPlaintext = null;
  let credType = null;
  if (credential) {
    if (!CREDENTIAL_TYPES.includes(credential_type)) {
      return NextResponse.json(
        { error: `credential_type must be one of: ${CREDENTIAL_TYPES.join(', ')}` },
        { status: 400 }
      );
    }
    credPlaintext = credential;
    credType = credential_type;
  } else if (smc_api_key) {
    credPlaintext = smc_api_key;
    credType = 'smc_api';
  }

  try {
    if (credPlaintext) {
      await setCredential(params.id, credType, credPlaintext, pool);
    }

    const updates = Object.keys(rest).filter(
      (key) => UPDATABLE_FIELDS.includes(key) || key === 'mgmt_method'
    );

    if (updates.length > 0) {
      const setClauses = updates.map((key, i) => `${key} = $${i + 2}`);
      const values = updates.map((key) => rest[key]);
      await pool.query(
        `UPDATE devices SET ${setClauses.join(', ')}, updated_at = now() WHERE id = $1`,
        [params.id, ...values]
      );
    } else if (credPlaintext) {
      await pool.query('UPDATE devices SET updated_at = now() WHERE id = $1', [params.id]);
    }

    const result = await pool.query('SELECT * FROM devices WHERE id = $1', [params.id]);
    if (result.rows.length === 0) {
      return NextResponse.json({ error: 'Device not found' }, { status: 404 });
    }
    return NextResponse.json(result.rows[0]);
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to update device' }, { status: 500 });
  }
}

// DELETE /api/devices/[id] — related rows (device_versions, device_credentials,
// firewall_rules, device_cve_assessments, ...) cascade via ON DELETE CASCADE in schema.sql.
export async function DELETE(request, { params }) {
  try {
    await pool.query('DELETE FROM devices WHERE id = $1', [params.id]);
    return NextResponse.json({ ok: true });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to delete device' }, { status: 500 });
  }
}
