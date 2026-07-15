import { NextResponse } from 'next/server';
import { pool } from '../../../lib/db';
import { setCredential } from '../../../lib/credStore';
import { VENDOR_META, VENDOR_SLUGS, CREDENTIAL_TYPES } from '../../../components/devices/vendorMeta';

export const dynamic = 'force-dynamic';

// Coerces a client-supplied port to a valid integer, or null. Never throws —
// mgmt_port / smc_port are nullable and old rows may not have them at all.
function coercePort(value) {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

// GET /api/devices — list all devices with their latest known version attached.
export async function GET() {
  try {
    const result = await pool.query(
      `SELECT d.*, dv.version_string, dv.model, dv.collected_at AS version_collected_at
       FROM devices d
       LEFT JOIN LATERAL (
         SELECT version_string, model, collected_at
         FROM device_versions
         WHERE device_versions.device_id = d.id
         ORDER BY collected_at DESC
         LIMIT 1
       ) dv ON true
       ORDER BY d.name ASC`
    );
    return NextResponse.json(result.rows);
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to list devices' }, { status: 500 });
  }
}

// POST /api/devices — create a device. Credentials (if provided) are NEVER written
// to the devices table — they are routed through credStore.setCredential into the
// separately-encrypted device_credentials table, and never echoed back or logged.
//
// mgmt_method is derived server-side from the vendor slug (VENDOR_META) — any
// client-supplied mgmt_method is ignored.
export async function POST(request) {
  const body = await request.json().catch(() => ({}));
  const {
    name,
    vendor,
    smc_host,
    smc_port,
    mgmt_ip,
    mgmt_port,
    allow_self_signed_ssl,
    site,
    asset_criticality,
    smc_api_key,
    credential,
    credential_type,
  } = body || {};

  const vendorSlug = vendor || 'forcepoint';
  const meta = VENDOR_META[vendorSlug];
  if (!meta) {
    return NextResponse.json(
      { error: `vendor must be one of: ${VENDOR_SLUGS.join(', ')}` },
      { status: 400 }
    );
  }

  if (!name) {
    return NextResponse.json({ error: 'name is required' }, { status: 400 });
  }
  if (meta.connection === 'smc' && !smc_host) {
    return NextResponse.json({ error: 'name and smc_host are required' }, { status: 400 });
  }
  if (meta.connection === 'mgmt' && !mgmt_ip) {
    return NextResponse.json({ error: `mgmt_ip is required for vendor '${vendorSlug}'` }, { status: 400 });
  }

  // Resolve the credential to store (validated BEFORE the insert so a bad
  // credential_type can never leave a half-created device behind).
  // `credential` + `credential_type` is the generic path; `smc_api_key` is the
  // original Forcepoint-only field, kept for backward compatibility.
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

  // Forcepoint keeps its historical default SMC port; other vendors store null
  // unless the client supplied a port explicitly.
  const smcPortValue =
    meta.connection === 'smc' ? coercePort(smc_port) ?? meta.defaultPort : coercePort(smc_port);
  const mgmtPortValue = coercePort(mgmt_port);

  try {
    const result = await pool.query(
      `INSERT INTO devices
        (name, vendor, mgmt_method, smc_host, smc_port, mgmt_ip, mgmt_port, allow_self_signed_ssl, site, asset_criticality)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, true), $9, COALESCE($10, 'medium'))
       RETURNING *`,
      [
        name,
        vendorSlug,
        meta.mgmtMethod,
        smc_host || null,
        smcPortValue,
        mgmt_ip || null,
        mgmtPortValue,
        allow_self_signed_ssl ?? null,
        site || null,
        asset_criticality || null,
      ]
    );
    const device = result.rows[0];

    if (credPlaintext) {
      await setCredential(device.id, credType, credPlaintext, pool);
    }

    return NextResponse.json(device, { status: 201 });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to create device' }, { status: 500 });
  }
}
