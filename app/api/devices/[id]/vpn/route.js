import { pool } from '../../../../../lib/db';
import { summarizeVpnConfig } from '../../../../../lib/engines/vpnSummary';
import { isValidUuid } from '../../../../../lib/apiUtils';
// ⛔ THE SHARED ESCAPE, NOT A LOCAL ONE (migrated 2026-09-25). This route
// carried its own `csvEscape` that predated lib/csv.js: it quoted
// CONDITIONALLY -- only on /[",\n\r]/ -- and neutralised NOTHING, so a cell
// beginning `=`, `+`, `-` or `@` was written raw and EXECUTED as a formula
// when the export was opened in Excel, LibreOffice or Sheets.
// ⛔ Do not reintroduce a local copy. Two files deciding independently how to
// neutralise a spreadsheet formula would eventually disagree, and the one that
// disagreed quietly would be the one writing the document that executes.
// ⛔ THIS EXPORT IS NOT CURRENTLY EXPLOITABLE, AND IT IS MIGRATED ANYWAY.
// It emits a session count and a timestamp, so nothing an attacker writes
// reaches a cell TODAY. That is a property of today's query, not of the
// escaping: the defective function was the same one, and the next column
// added here -- a username, a client string, an assigned IP -- would have
// inherited it silently.
import { csvRow, csvDocument } from '../../../../../lib/csv';

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
// the document ends with a CRLF. The counts themselves are untouched.
function buildCsv(rows) {
  const out = [csvRow(['Sampled At', 'Active Session Count'])];
  for (const r of rows) {
    out.push(csvRow([cell(r.sampled_at), cell(r.active_session_count)]));
  }
  return csvDocument(out);
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
