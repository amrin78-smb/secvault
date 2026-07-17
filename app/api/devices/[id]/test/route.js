import { pool } from '../../../../../lib/db';
import { getAdapter } from '../../../../../lib/adapters';
import { isValidUuid } from '../../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// POST /api/devices/[id]/test — test connectivity to an already-saved device,
// any supported vendor.
export async function POST(request, { params }) {
  const { id } = params;

  if (!isValidUuid(id)) {
    return Response.json({ error: 'Invalid device id' }, { status: 400 });
  }

  const deviceResult = await pool.query('SELECT * FROM devices WHERE id = $1', [id]);
  if (deviceResult.rows.length === 0) {
    return Response.json({ error: 'Device not found' }, { status: 404 });
  }

  const device = deviceResult.rows[0];

  try {
    // testConnectivity() must always receive `pool` via the adapter constructor —
    // see CLAUDE.md's Pool Warning. Never construct an adapter without { pool }.
    const adapter = getAdapter(device, pool);
    const result = await adapter.testConnectivity();

    // Persist the outcome so the device list/detail StatusDot reflects reality.
    await pool.query(
      'UPDATE devices SET last_connectivity_ok = $1, last_connectivity_checked_at = now(), updated_at = now() WHERE id = $2',
      [result.ok === true, id]
    );

    return Response.json(result);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
