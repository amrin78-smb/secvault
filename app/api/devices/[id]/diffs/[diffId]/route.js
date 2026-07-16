import { pool } from '../../../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../../auth/[...nextauth]/route';
import { logActivity } from '../../../../../../lib/activityLog';

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
// Acknowledges a config change. `acknowledged_by` is derived from the logged-in
// session — never trust a client-supplied "who did this" value now that it
// feeds the Phase 4 audit trail (activity_log).
export async function PUT(request, { params }) {
  try {
    const { id, diffId } = params;

    // Resolved defensively: acknowledgedBy feeds the PRIMARY update below, not
    // just the audit trail, so a getServerSession hiccup must degrade to
    // 'unknown' rather than abort the whole acknowledge action.
    let acknowledgedBy = 'unknown';
    try {
      const session = await getServerSession(authOptions);
      acknowledgedBy = (session && session.user && session.user.name) || 'unknown';
    } catch (sessionErr) {
      console.warn(`[diffs route] Failed to resolve session actor: ${sessionErr.message}`);
    }

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

    await logActivity(pool, {
      actor: acknowledgedBy,
      action: 'acknowledge_config_diff',
      deviceId: id,
      detail: `Config diff ${diffId} acknowledged`,
    });

    return Response.json(rows[0]);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
