import { pool } from '../../../../lib/db';
import { summarizeVpnConfig } from '../../../../lib/engines/vpnSummary';
// ⛔ THE SHARED ESCAPE, NOT A LOCAL ONE (migrated 2026-09-25). This route
// carried its own `csvEscape` that predated lib/csv.js: it quoted
// CONDITIONALLY -- only on /[",\n\r]/ -- and neutralised NOTHING, so a cell
// beginning `=`, `+`, `-` or `@` was written raw and EXECUTED as a formula
// when the export was opened in Excel, LibreOffice or Sheets.
// ⛔ Do not reintroduce a local copy. Two files deciding independently how to
// neutralise a spreadsheet formula would eventually disagree, and the one that
// disagreed quietly would be the one writing the document that executes.
// ⛔ `Device` and `Vendor` are the cells at risk: a device name is typed by
// an operator and a vendor slug is stored beside it. Verified against the
// migration fixture: a device named `=cmd|'/c calc'!A1` went into the
// document RAW AND UNQUOTED.
import { csvRow, csvDocument } from '../../../../lib/csv';

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

// ⛔ PRESERVED FROM THE ESCAPE THIS ROUTE USED TO CARRY -- NOT AN ADDITION.
// That function ran JSON.stringify over anything whose `typeof` was 'object',
// and a TIMESTAMPTZ column arrives from pg as a JS Date, so every timestamp in
// this export has always been written as a JSON date literal with its own
// quotes included. lib/csv.js does a bare String(), which would silently
// rewrite every timestamp in the file into Date#toString in the SERVER's local
// zone. Keeping the transform at the call site keeps the column byte-identical;
// only the encoding changes.
// ⛔ The sibling SNMP export never had this branch and so already writes the
// local-zone form. That inconsistency is PRE-EXISTING and is deliberately left
// alone here: changing a timestamp format is a data decision, not part of a
// formula-injection fix.
function cell(value) {
  if (value === null || value === undefined) return '';
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

// ⛔ COLUMNS AND THEIR ORDER ARE UNCHANGED BY THE MIGRATION -- only the
// encoding is: every cell is now quoted, a leading =/+/-/@ is neutralised, and
// the document ends with a CRLF. The header still goes out on zero rows.
function buildCsv(rows) {
  const out = [
    csvRow([
      'Device',
      'Vendor',
      'VPN Supported',
      'Has VPN Config',
      'Enabled',
      'Config As Of',
      'Active Sessions',
      'Sessions Sampled At',
    ]),
  ];
  for (const r of rows) {
    out.push(
      csvRow([
        cell(r.deviceName),
        cell(r.vendor),
        cell(r.supported),
        cell(r.hasConfig),
        cell(r.enabled),
        cell(r.lastConfigAt),
        cell(r.activeSessionCount),
        cell(r.sessionSampledAt),
      ])
    );
  }
  return csvDocument(out);
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
