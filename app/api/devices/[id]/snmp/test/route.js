import { pool } from '../../../../../../lib/db';
import { getAdapter } from '../../../../../../lib/adapters';
import { isValidUuid } from '../../../../../../lib/apiUtils';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../../../lib/rbac';

export const dynamic = 'force-dynamic';

// POST /api/devices/[id]/snmp/test — test the ALREADY-SAVED SNMP credential
// (device_credentials credential_type='snmp') + device.snmp_host/snmp_port
// against the live device, right after configuring it, rather than waiting
// up to SNMP_POLL_INTERVAL_MINUTES for the next scheduled poll to find out
// whether it actually works. Mirrors POST /api/devices/[id]/test's shape
// ({ok, message}) — same "test an already-stored credential" convention,
// not a client-supplied one (the SNMP credential form has no separate
// pre-save test-before-commit flow the way Forcepoint's SMC form does; you
// save first, then test what was saved).
//
// On success, ALSO inserts a snmp_metric_snapshots row — identical to what
// services/engine-worker.js's snmp-poll job does on its own schedule. A
// real metrics fetch just happened; discarding it would be wasteful and
// would leave the trend chart looking unchanged right after a successful
// test, which reads as "did that actually do anything?" On failure, no row
// is inserted — same "only a successful poll writes a row" discipline as
// the scheduled job.
export async function POST(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  const { id } = params;
  if (!isValidUuid(id)) {
    return Response.json({ error: 'Invalid device id' }, { status: 400 });
  }

  const deviceResult = await pool.query('SELECT * FROM devices WHERE id = $1', [id]);
  if (deviceResult.rows.length === 0) {
    return Response.json({ error: 'Device not found' }, { status: 404 });
  }
  const device = deviceResult.rows[0];

  let adapter;
  try {
    // getSnmpMetrics() must always receive `pool` via the adapter
    // constructor — see CLAUDE.md's Pool Warning.
    adapter = getAdapter(device, pool);
  } catch (err) {
    return Response.json({ ok: false, message: err.message }, { status: 200 });
  }

  if (typeof adapter.getSnmpMetrics !== 'function') {
    return Response.json(
      { ok: false, message: `SNMP monitoring is not yet implemented for vendor "${device.vendor}".` },
      { status: 200 }
    );
  }

  try {
    const metrics = await adapter.getSnmpMetrics();
    await pool.query(
      `INSERT INTO snmp_metric_snapshots (device_id, cpu_percent, memory_percent, session_count, uptime_seconds, raw)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
      [
        device.id,
        metrics.cpuPercent ?? null,
        metrics.memoryPercent ?? null,
        metrics.sessionCount ?? null,
        metrics.uptimeSeconds ?? null,
        JSON.stringify(metrics.raw || null),
      ]
    );
    return Response.json({
      ok: true,
      message: `Connected via SNMP to ${metrics.targetHost}.`,
      metrics: {
        cpuPercent: metrics.cpuPercent,
        memoryPercent: metrics.memoryPercent,
        sessionCount: metrics.sessionCount,
        uptimeSeconds: metrics.uptimeSeconds,
      },
    });
  } catch (err) {
    // err.message is credential-safe by construction — every adapter's
    // getSnmpMetrics()/parseSnmpCredential() never embeds the secret in a
    // thrown error (same discipline as every other adapter error path).
    return Response.json({ ok: false, message: err.message }, { status: 200 });
  }
}
