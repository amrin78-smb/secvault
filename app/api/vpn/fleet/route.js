import { pool } from '../../../../lib/db';
import { summarizeVpnConfig } from '../../../../lib/engines/vpnSummary';

export const dynamic = 'force-dynamic';

// GET /api/vpn/fleet — same duplicated-query convention as
// app/(dashboard)/vpn/page.js's own getFleetVpnStatus() (this app's
// established "server components query the DB directly, API routes exist
// for CSV export / any future client-side consumer" pattern — see
// CLAUDE.md's Alerts/Compliance sections for the same tradeoff documented
// elsewhere). ?format=csv mirrors the pattern already used by
// GET /api/devices/[id]/rules and the Compliance/Rule-Analysis routes.

async function getFleetVpnStatus(dbPool) {
  const { rows: devices } = await dbPool.query(
    `SELECT id AS device_id, name AS device_name, vendor
     FROM devices
     WHERE active = true
     ORDER BY name ASC`
  );

  const deviceIds = devices.map((d) => d.device_id);

  const { rows: configRows } = await dbPool.query(
    `SELECT DISTINCT ON (device_id) device_id, config_parsed, collected_at
     FROM device_configs
     WHERE device_id = ANY($1::uuid[])
     ORDER BY device_id, collected_at DESC`,
    [deviceIds]
  );
  const configByDevice = new Map(configRows.map((r) => [r.device_id, r]));

  const { rows: sessionRows } = await dbPool.query(
    `SELECT DISTINCT ON (device_id) device_id, active_session_count, sampled_at
     FROM vpn_session_snapshots
     WHERE device_id = ANY($1::uuid[])
     ORDER BY device_id, sampled_at DESC`,
    [deviceIds]
  );
  const sessionByDevice = new Map(sessionRows.map((r) => [r.device_id, r]));

  return devices.map((d) => {
    const configRow = configByDevice.get(d.device_id);
    const summary = summarizeVpnConfig(d.vendor, configRow ? configRow.config_parsed : null);
    const session = sessionByDevice.get(d.device_id);
    return {
      deviceId: d.device_id,
      deviceName: d.device_name,
      vendor: d.vendor,
      supported: summary.supported,
      hasConfig: summary.hasConfig,
      enabled: summary.enabled !== undefined ? summary.enabled : null,
      lastConfigAt: configRow ? configRow.collected_at : null,
      activeSessionCount: session ? session.active_session_count : null,
      sessionSampledAt: session ? session.sampled_at : null,
    };
  });
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
  const headers = [
    'Device',
    'Vendor',
    'VPN Supported',
    'Has VPN Config',
    'Enabled',
    'Config As Of',
    'Active Sessions',
    'Sessions Sampled At',
  ];
  const lines = [headers.join(',')];
  for (const r of rows) {
    lines.push(
      [
        csvEscape(r.deviceName),
        csvEscape(r.vendor),
        csvEscape(r.supported),
        csvEscape(r.hasConfig),
        csvEscape(r.enabled),
        csvEscape(r.lastConfigAt),
        csvEscape(r.activeSessionCount),
        csvEscape(r.sessionSampledAt),
      ].join(',')
    );
  }
  return lines.join('\r\n');
}

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const format = searchParams.get('format');

    const devices = await getFleetVpnStatus(pool);

    if (format === 'csv') {
      const csv = buildCsv(devices);
      return new Response(csv, {
        status: 200,
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': 'attachment; filename="vpn-fleet.csv"',
        },
      });
    }

    return Response.json({ devices });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
