import { pool } from '../../../../../../lib/db';
import { isValidUuid } from '../../../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// GET /api/devices/[id]/backups/[backupId]
// Downloads the raw config text of one backup as a plain-text attachment.
export async function GET(request, { params }) {
  try {
    const { id, backupId } = params;

    if (!isValidUuid(id) || !isValidUuid(backupId)) {
      return Response.json({ error: 'Invalid device or backup id' }, { status: 400 });
    }

    const { rows } = await pool.query(
      `SELECT config_raw FROM config_backups WHERE id = $1 AND device_id = $2`,
      [backupId, id]
    );

    if (rows.length === 0) {
      return Response.json({ error: 'Backup not found' }, { status: 404 });
    }

    return new Response(rows[0].config_raw ?? '', {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': `attachment; filename="secvault-config-${id}-${backupId}.txt"`,
      },
    });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}

// DELETE /api/devices/[id]/backups/[backupId]
// Removes one backup row.
export async function DELETE(request, { params }) {
  try {
    const { id, backupId } = params;

    if (!isValidUuid(id) || !isValidUuid(backupId)) {
      return Response.json({ error: 'Invalid device or backup id' }, { status: 400 });
    }

    const { rows } = await pool.query(
      `DELETE FROM config_backups WHERE id = $1 AND device_id = $2 RETURNING id`,
      [backupId, id]
    );

    if (rows.length === 0) {
      return Response.json({ error: 'Backup not found' }, { status: 404 });
    }

    return Response.json({ ok: true, id: rows[0].id });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
