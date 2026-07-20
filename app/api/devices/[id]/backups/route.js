import { pool } from '../../../../../lib/db';
import { createBackup } from '../../../../../lib/engines/configDiff';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../../lib/rbac';

export const dynamic = 'force-dynamic';

const ALLOWED_LABELS = ['manual', 'pre-change'];

// GET /api/devices/[id]/backups
// Lists config backups for one device, newest first. config_raw itself is not
// returned here (can be large) — only its size; download a single backup for it.
export async function GET(request, { params }) {
  try {
    const { id } = params;

    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid device id' }, { status: 400 });
    }

    const { rows } = await pool.query(
      `SELECT id, label, backed_up_at, octet_length(config_raw) AS size_bytes
       FROM config_backups
       WHERE device_id = $1
       ORDER BY backed_up_at DESC
       LIMIT 100`,
      [id]
    );

    return Response.json({ backups: rows });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}

// POST /api/devices/[id]/backups
// Creates a labeled backup from the device's latest collected config.
// Body is optional: { label } — 'manual' (default) or 'pre-change'.
export async function POST(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  try {
    const { id } = params;

    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid device id' }, { status: 400 });
    }

    let body = {};
    try {
      body = await request.json();
    } catch {
      // No/invalid JSON body — use defaults.
    }
    const label = (body && body.label) || 'manual';

    if (!ALLOWED_LABELS.includes(label)) {
      return Response.json(
        { error: `label must be one of: ${ALLOWED_LABELS.join(', ')}` },
        { status: 400 }
      );
    }

    const { backupId } = await createBackup(id, label, pool);
    if (!backupId) {
      return Response.json({ error: 'No collected config to back up yet' }, { status: 400 });
    }

    const { rows } = await pool.query(
      `SELECT id, label, backed_up_at, octet_length(config_raw) AS size_bytes
       FROM config_backups
       WHERE id = $1 AND device_id = $2`,
      [backupId, id]
    );

    return Response.json(rows[0] || { id: backupId, label }, { status: 201 });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
