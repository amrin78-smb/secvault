import { NextResponse } from 'next/server';
import { pool } from '../../../lib/db';
import { setCredential } from '../../../lib/credStore';

export const dynamic = 'force-dynamic';

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

// POST /api/devices — create a device. The SMC API key (if provided) is NEVER written
// to the devices table — it is routed through credStore.setCredential into the
// separately-encrypted device_credentials table.
export async function POST(request) {
  const body = await request.json().catch(() => ({}));
  const {
    name,
    vendor,
    mgmt_method,
    smc_host,
    smc_port,
    allow_self_signed_ssl,
    site,
    asset_criticality,
    smc_api_key,
  } = body || {};

  if (!name || !smc_host) {
    return NextResponse.json({ error: 'name and smc_host are required' }, { status: 400 });
  }

  try {
    const result = await pool.query(
      `INSERT INTO devices
        (name, vendor, mgmt_method, smc_host, smc_port, allow_self_signed_ssl, site, asset_criticality)
       VALUES
        ($1, COALESCE($2, 'forcepoint'), COALESCE($3, 'smc'), $4, COALESCE($5, 8082), COALESCE($6, true), $7, COALESCE($8, 'medium'))
       RETURNING *`,
      [
        name,
        vendor || null,
        mgmt_method || null,
        smc_host,
        smc_port ?? null,
        allow_self_signed_ssl ?? null,
        site || null,
        asset_criticality || null,
      ]
    );
    const device = result.rows[0];

    if (smc_api_key) {
      await setCredential(device.id, 'smc_api', smc_api_key, pool);
    }

    return NextResponse.json(device, { status: 201 });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to create device' }, { status: 500 });
  }
}
