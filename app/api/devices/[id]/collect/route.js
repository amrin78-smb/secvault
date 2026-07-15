import { pool } from '../../../../../lib/db';
import { collectAndStore } from '../../../../../lib/adapters';

export const dynamic = 'force-dynamic';

// POST /api/devices/[id]/collect — on-demand version + rules + config pull for a
// single device, any supported vendor. The same collectAndStore(device, pool)
// function is also invoked by services/engine-worker.js on the scheduled pull job.
export async function POST(request, { params }) {
  const { id } = params;

  const deviceResult = await pool.query('SELECT * FROM devices WHERE id = $1', [id]);
  if (deviceResult.rows.length === 0) {
    return Response.json({ error: 'Device not found' }, { status: 404 });
  }

  const device = deviceResult.rows[0];

  try {
    const result = await collectAndStore(device, pool);
    return Response.json(result);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
