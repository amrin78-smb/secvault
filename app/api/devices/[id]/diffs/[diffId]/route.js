import { pool } from '../../../../../../lib/db';

export const dynamic = 'force-dynamic';

// GET /api/devices/[id]/diffs/[diffId]
// Returns the full diff row, including the diff jsonb payload.
export async function GET(request, { params }) {
  try {
    const { id, diffId } = params;

    const { rows } = await pool.query(
      `SELECT * FROM config_diffs WHERE id = $1 AND device_id = $2`,
      [diffId, id]
    );

    if (rows.length === 0) {
      return Response.json({ error: 'Diff not found' }, { status: 404 });
    }

    return Response.json(rows[0]);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}

// PUT /api/devices/[id]/diffs/[diffId]
// Acknowledges a config change. Body is optional: { acknowledged_by } (default 'admin').
export async function PUT(request, { params }) {
  try {
    const { id, diffId } = params;

    let body = {};
    try {
      body = await request.json();
    } catch {
      // No/invalid JSON body — acknowledge with defaults.
    }
    const acknowledgedBy = (body && body.acknowledged_by) || 'admin';

    const { rows } = await pool.query(
      `UPDATE config_diffs
       SET acknowledged_at = now(), acknowledged_by = $1
       WHERE id = $2 AND device_id = $3
       RETURNING *`,
      [acknowledgedBy, diffId, id]
    );

    if (rows.length === 0) {
      return Response.json({ error: 'Diff not found' }, { status: 404 });
    }

    return Response.json(rows[0]);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
