import { pool } from '../../../../../lib/db';

export const dynamic = 'force-dynamic';

// GET /api/devices/[id]/diffs
// Lists config change diffs for one device, newest first. The full diff jsonb is
// intentionally excluded here (it can be large) — fetch a single diff by id for it.
export async function GET(request, { params }) {
  try {
    const { id } = params;

    const { rows } = await pool.query(
      `SELECT id, change_summary, detected_at, acknowledged_at, acknowledged_by
       FROM config_diffs
       WHERE device_id = $1
       ORDER BY detected_at DESC
       LIMIT 100`,
      [id]
    );

    return Response.json({ diffs: rows });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
