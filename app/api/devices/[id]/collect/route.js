import { pool } from '../../../../../lib/db';
import { collectAndStore } from '../../../../../lib/adapters';
import { isValidUuid } from '../../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// POST /api/devices/[id]/collect — on-demand version + rules + config pull for a
// single device, any supported vendor. The same collectAndStore(device, pool)
// function is also invoked by services/engine-worker.js on the scheduled pull job.
export async function POST(request, { params }) {
  const { id } = params;

  // ⛔ Added 2026-07-19, found in a follow-up bug sweep: a malformed id must
  // never reach pool.query() and leak a raw Postgres "invalid input syntax
  // for type uuid" 500 — same guard already applied to several sibling
  // devices/[id]/* routes, missed here.
  if (!isValidUuid(id)) {
    return Response.json({ error: 'Invalid device id' }, { status: 400 });
  }

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
