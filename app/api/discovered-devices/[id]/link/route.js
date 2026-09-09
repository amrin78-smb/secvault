import { NextResponse } from 'next/server';
import { pool } from '../../../../../lib/db';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../../lib/rbac';

export const dynamic = 'force-dynamic';

// Link a discovered sender to an EXISTING device as an additional syslog
// source — the HA-passive-peer case, which is 5 of the 8 senders on this fleet.
//
// ⛔ This writes device_syslog_sources, NEVER devices.mgmt_ip. That column is
// what every adapter opens SSH/HTTPS to; pointing it at a passive HA unit would
// break collection on a device that is currently working.
//
// ⛔ Genuinely mutating and persistent, so admin-gated — it does not qualify for
// the "non-mutating POST treated like a GET" exemption that
// /api/devices/[id]/access-path uses.
export async function POST(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) return forbiddenResponse();

  const { id } = params;
  if (!isValidUuid(id)) {
    return NextResponse.json({ error: 'Invalid discovered-device id' }, { status: 400 });
  }

  let body;
  try {
    body = await request.json();
  } catch (_err) {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const deviceId = body?.device_id;
  if (!isValidUuid(deviceId)) {
    return NextResponse.json({ error: 'A valid device_id is required' }, { status: 400 });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: found } = await client.query(
      'SELECT id, source_ip, status FROM discovered_devices WHERE id = $1 FOR UPDATE',
      [id]
    );
    if (found.length === 0) {
      await client.query('ROLLBACK');
      return NextResponse.json({ error: 'Discovered sender not found' }, { status: 404 });
    }
    // ⛔ Idempotence. A double-submit must not create a second alias row.
    if (found[0].status !== 'new') {
      await client.query('ROLLBACK');
      return NextResponse.json(
        { error: `This sender has already been ${found[0].status}` },
        { status: 409 }
      );
    }

    const { rows: dev } = await client.query('SELECT id, name FROM devices WHERE id = $1', [
      deviceId,
    ]);
    if (dev.length === 0) {
      await client.query('ROLLBACK');
      return NextResponse.json({ error: 'Target device not found' }, { status: 404 });
    }

    await client.query(
      `INSERT INTO device_syslog_sources (device_id, source_ip, note, created_by)
       VALUES ($1, $2::inet, $3, $4)
       ON CONFLICT (source_ip) DO NOTHING`,
      [deviceId, String(found[0].source_ip).replace(/\/\d+$/, ''), body?.note || null,
        session?.user?.name || session?.user?.email || null]
    );

    await client.query(
      `UPDATE discovered_devices
          SET status = 'linked', linked_device_id = $1, decision_note = $2,
              decided_by = $3, decided_at = now(), updated_at = now()
        WHERE id = $4`,
      [deviceId, body?.note || null,
        session?.user?.name || session?.user?.email || null, id]
    );

    await client.query('COMMIT');
    return NextResponse.json({ ok: true, linkedTo: dev[0].name });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    return NextResponse.json({ error: err.message }, { status: 500 });
  } finally {
    client.release();
  }
}
