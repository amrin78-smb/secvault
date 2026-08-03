import { pool } from '../../../../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../../../auth/[...nextauth]/route';
import { logActivity } from '../../../../../../../lib/activityLog';
import { isValidUuid } from '../../../../../../../lib/apiUtils';
import { isAdmin, forbiddenResponse } from '../../../../../../../lib/rbac';

export const dynamic = 'force-dynamic';

// PUT /api/devices/[id]/configs/[configId]/baseline
//
// Marks one device_configs snapshot as that device's known-good baseline, the
// anchor the Changes page's "Baseline Drift" card diffs the latest config
// against. Body `{ baseline: false }` clears the device's baseline instead
// (leaving the device with none, which the page renders as "no baseline set"
// guidance rather than an error).
//
// At most one baseline per device is enforced by a PARTIAL UNIQUE INDEX
// (idx_device_configs_one_baseline_per_device, lib/schema.sql) -- a real DB
// guarantee, not app logic. That's exactly why the clear below must run BEFORE
// the set, inside the same transaction: setting first would collide with the
// still-set previous baseline and be rejected.
export async function PUT(request, { params }) {
  try {
    const { id, configId } = params;

    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid device id' }, { status: 400 });
    }
    if (!isValidUuid(configId)) {
      return Response.json({ error: 'Invalid config id' }, { status: 400 });
    }

    // Security gate first, and it fails closed -- a session-resolution error
    // means not-admin, never admin. (Unlike the diffs acknowledge route, the
    // resolved actor here only feeds the audit trail, not the primary write,
    // so there's no reason to degrade it to 'unknown' and continue.)
    const session = await getServerSession(authOptions);
    if (!isAdmin(session)) {
      return forbiddenResponse();
    }
    const actor = (session && session.user && session.user.name) || 'unknown';

    const body = await request.json().catch(() => ({}));
    // Only an explicit `false` clears; anything else (including a missing
    // body) means "make this one the baseline", which is the overwhelmingly
    // common call.
    const setBaseline = body?.baseline !== false;

    const client = await pool.connect();
    let updatedRow = null;
    try {
      await client.query('BEGIN');

      await client.query(
        'UPDATE device_configs SET is_baseline = false WHERE device_id = $1 AND is_baseline',
        [id]
      );

      if (setBaseline) {
        const { rows } = await client.query(
          `UPDATE device_configs
           SET is_baseline = true
           WHERE id = $1 AND device_id = $2
           RETURNING id, device_id, collected_at, is_baseline`,
          [configId, id]
        );
        if (rows.length === 0) {
          // Config snapshot doesn't exist (or belongs to another device) --
          // roll back so the clear above doesn't silently strip an existing
          // baseline as a side effect of a bad request.
          await client.query('ROLLBACK');
          return Response.json({ error: 'Config version not found' }, { status: 404 });
        }
        updatedRow = rows[0];
      }

      await client.query('COMMIT');
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackErr) {
        // ignore — the client is being released either way
      }
      throw err;
    } finally {
      client.release();
    }

    await logActivity(pool, {
      actor,
      action: 'set_config_baseline',
      deviceId: id,
      detail: setBaseline
        ? `Config version ${configId} set as baseline`
        : 'Config baseline cleared',
    });

    return Response.json({ ok: true, baseline: updatedRow });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
