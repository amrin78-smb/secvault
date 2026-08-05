import { pool } from '../../../../../lib/db';
import { recordConnectivity } from '../../../../../lib/engines/connectivityHistory';
import { getAdapter } from '../../../../../lib/adapters';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../../lib/rbac';

export const dynamic = 'force-dynamic';

// POST /api/devices/[id]/test — test connectivity to an already-saved device,
// any supported vendor.
export async function POST(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

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
    // Append to the reachability log as well — the UPDATE above overwrites the
    // single current value and keeps no history. Never throws (see the engine).
    await recordConnectivity(pool, id, {
      reachable: result.ok === true,
      latencyMs: result.latency_ms,
      source: 'test',
      message: result.ok === true ? null : result.message,
    });

    return Response.json(result);
  } catch (err) {
    await recordConnectivity(pool, id, { reachable: false, source: 'test', message: err.message });
    return Response.json({ error: err.message }, { status: 500 });
  }
}
