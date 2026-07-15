import { NextResponse } from 'next/server';
import { pool } from '../../../../lib/db';
import { setCredential } from '../../../../lib/credStore';

export const dynamic = 'force-dynamic';

// Whitelist of devices-table columns that PUT is allowed to update — keeps the
// dynamically-built SET clause safe even though column names are interpolated
// (values themselves are always parameterized).
const UPDATABLE_FIELDS = [
  'name',
  'vendor',
  'mgmt_method',
  'mgmt_ip',
  'smc_host',
  'smc_port',
  'allow_self_signed_ssl',
  'site',
  'asset_criticality',
  'active',
];

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

// PUT /api/devices/[id] — updates device fields. If the body includes `smc_api_key`,
// it is routed through credStore.setCredential rather than written to the devices
// table — the devices table must never hold plaintext credentials.
export async function PUT(request, { params }) {
  const body = await request.json().catch(() => ({}));
  const { smc_api_key, ...rest } = body || {};

  try {
    if (smc_api_key) {
      await setCredential(params.id, 'smc_api', smc_api_key, pool);
    }

    const updates = Object.keys(rest).filter((key) => UPDATABLE_FIELDS.includes(key));

    if (updates.length > 0) {
      const setClauses = updates.map((key, i) => `${key} = $${i + 2}`);
      const values = updates.map((key) => rest[key]);
      await pool.query(
        `UPDATE devices SET ${setClauses.join(', ')}, updated_at = now() WHERE id = $1`,
        [params.id, ...values]
      );
    } else if (smc_api_key) {
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
