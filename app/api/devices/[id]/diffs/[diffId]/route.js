import { pool } from '../../../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../../auth/[...nextauth]/route';
import { logActivity } from '../../../../../../lib/activityLog';
import { isValidUuid } from '../../../../../../lib/apiUtils';
import { isAdmin, forbiddenResponse } from '../../../../../../lib/rbac';
import { classifyDiff } from '../../../../../../lib/engines/configDiff';

export const dynamic = 'force-dynamic';

// GET /api/devices/[id]/diffs/[diffId]
// Returns the full diff row, including the diff jsonb payload.
export async function GET(request, { params }) {
  try {
    const { id, diffId } = params;

    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid device id' }, { status: 400 });
    }
    if (!isValidUuid(diffId)) {
      return Response.json({ error: 'Invalid diff id' }, { status: 400 });
    }

    const { rows } = await pool.query(
      `SELECT * FROM config_diffs WHERE id = $1 AND device_id = $2`,
      [diffId, id]
    );

    if (rows.length === 0) {
      return Response.json({ error: 'Diff not found' }, { status: 404 });
    }

    // classified is a presentation-layer grouping of the same raw `diff` --
    // see lib/engines/configDiff.js's classifyDiff() block comment. Additive
    // only: `diff` stays in the response unchanged, for any existing/future
    // consumer that wants the raw shape.
    const classified = classifyDiff(rows[0].diff);

    return Response.json({ ...rows[0], classified });
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

    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid device id' }, { status: 400 });
    }
    if (!isValidUuid(diffId)) {
      return Response.json({ error: 'Invalid diff id' }, { status: 400 });
    }

    // Resolved defensively (own try/catch, separate from the route's outer
    // one): unlike the diffs/findings/cve ack routes, THIS route's resolved
    // actor also feeds the PRIMARY update below (acknowledged_by), not just
    // the audit trail, so a getServerSession hiccup must degrade to
    // 'unknown' rather than abort the whole acknowledge action — see
    // CLAUDE.md's "Risk Trend + Audit/Tracking" section for why this one
    // route is the exception. The RBAC admin check below still runs first
    // and fails closed (session resolution failure -> forbidden), since
    // that's a security gate, not an audit-label nicety.
    let session = null;
    let acknowledgedBy = 'unknown';
    try {
      session = await getServerSession(authOptions);
      acknowledgedBy = (session && session.user && session.user.name) || 'unknown';
    } catch (sessionErr) {
      console.warn(`[diffs route] Failed to resolve session actor: ${sessionErr.message}`);
    }

    if (!isAdmin(session)) {
      return forbiddenResponse();
    }

    const body = await request.json().catch(() => ({}));
    const note = typeof body?.note === 'string' && body.note.trim() ? body.note.trim() : null;

    const { rows } = await pool.query(
      `UPDATE config_diffs
       SET acknowledged_at = now(), acknowledged_by = $1, acknowledged_note = $2
       WHERE id = $3 AND device_id = $4
       RETURNING *`,
      [acknowledgedBy, note, diffId, id]
    );

    if (rows.length === 0) {
      return Response.json({ error: 'Diff not found' }, { status: 404 });
    }

    await logActivity(pool, {
      actor: acknowledgedBy,
      action: 'acknowledge_config_diff',
      deviceId: id,
      detail: note ? `Config diff ${diffId} acknowledged — ${note}` : `Config diff ${diffId} acknowledged`,
    });

    return Response.json(rows[0]);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
