import { pool } from '../../../../../lib/db';
import { summarizeVpnConfig } from '../../../../../lib/engines/vpnSummary';
import { isValidUuid } from '../../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// GET /api/devices/[id]/vpn — same duplicated-query convention as
// app/(dashboard)/devices/[id]/vpn/page.js's own render (this app's
// established "server components query the DB directly, API routes exist
// for CSV export / any future client-side consumer" pattern).
// ?format=csv exports the session-poll history (the only genuinely
// tabular/time-series part of this page — the VPN config summary itself is
// a handful of key/value fields, not a rows-and-columns export candidate).

async function getDevice(dbPool, id) {
  const result = await dbPool.query('SELECT id, name, vendor FROM devices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

async function getLatestConfigParsed(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT config_parsed, collected_at
     FROM device_configs
     WHERE device_id = $1
     ORDER BY collected_at DESC
     LIMIT 1`,
    [deviceId]
  );
  return result.rows[0] || null;
}

async function getVpnSessionHistory(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT active_session_count, sampled_at
     FROM vpn_session_snapshots
     WHERE device_id = $1
     ORDER BY sampled_at ASC`,
    [deviceId]
  );
  return result.rows;
}

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const str = typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/[",\n\r]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function buildCsv(rows) {
  const headers = ['Sampled At', 'Active Session Count'];
  const lines = [headers.join(',')];
  for (const r of rows) {
    lines.push([csvEscape(r.sampled_at), csvEscape(r.active_session_count)].join(','));
  }
  return lines.join('\r\n');
}

export async function GET(request, { params }) {
  try {
    const { id } = params;

    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid device id' }, { status: 400 });
    }

    const device = await getDevice(pool, id);
    if (!device) {
      return Response.json({ error: 'Device not found' }, { status: 404 });
    }

    const sessionHistory = await getVpnSessionHistory(pool, id);

    const { searchParams } = new URL(request.url);
    if (searchParams.get('format') === 'csv') {
      const csv = buildCsv(sessionHistory);
      return new Response(csv, {
        status: 200,
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': `attachment; filename="vpn-sessions-${device.id}.csv"`,
        },
      });
    }

    const configRow = await getLatestConfigParsed(pool, id);
    const summary = summarizeVpnConfig(device.vendor, configRow ? configRow.config_parsed : null);

    return Response.json({
      deviceId: device.id,
      deviceName: device.name,
      vendor: device.vendor,
      lastConfigAt: configRow ? configRow.collected_at : null,
      summary,
      sessionHistory,
    });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
