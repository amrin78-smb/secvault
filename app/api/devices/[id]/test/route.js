import { pool } from '../../../../../lib/db';
import { ForcepointAdapter } from '../../../../../lib/adapters/forcepoint';

export const dynamic = 'force-dynamic';

// POST /api/devices/[id]/test — test connectivity to an already-saved device's SMC.
export async function POST(request, { params }) {
  const { id } = params;

  const deviceResult = await pool.query('SELECT * FROM devices WHERE id = $1', [id]);
  if (deviceResult.rows.length === 0) {
    return Response.json({ error: 'Device not found' }, { status: 404 });
  }

  const device = deviceResult.rows[0];

  // testConnectivity() must always receive `pool` via the adapter constructor — see
  // CLAUDE.md's Pool Warning. Never construct this adapter without { pool }.
  const adapter = new ForcepointAdapter({ device, pool });
  const result = await adapter.testConnectivity();

  return Response.json(result);
}
