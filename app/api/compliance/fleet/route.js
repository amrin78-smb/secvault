import { pool } from '../../../../lib/db';

export const dynamic = 'force-dynamic';

// ⛔ BUG FIXED 2026-07-18, found in a bug-sweep pass: this list had drifted
// out of step with components/compliance/ComplianceMatrix.js's real STANDARDS
// export (which gained 'SANS') — both page.js server components import from
// ComplianceMatrix.js correctly and were never affected, but this route's
// own buildStandardStats() silently dropped every SANS-tagged finding via
// its `if (!stats[standard]) continue` guard, so the JSON this route returns
// had no SANS key at all. Kept as a literal array, not an import, per this
// file's own established "duplicated query/shape, not shared" convention —
// just now back in sync. Watch for this drifting again if a standard is
// ever added/removed.
const STANDARDS = ['PCI_DSS', 'ISO_27001', 'CIS_V8', 'NIST', 'SANS'];

function emptyStandardStats() {
  const stats = {};
  for (const standard of STANDARDS) {
    stats[standard] = { pass: 0, fail: 0, warning: 0, na: 0, total: 0, scorePct: null };
  }
  return stats;
}

function finalizeScorePct(stats) {
  for (const standard of STANDARDS) {
    const s = stats[standard];
    const denom = s.pass + s.fail + s.warning;
    s.scorePct = denom > 0 ? Math.round((100 * s.pass) / denom) : null;
  }
}

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const str = typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/[",\n\r]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

// Matches the formatLastRun/formatDateTime convention already used in
// components/compliance/ComplianceMatrix.js.
function formatLastRun(lastRunAt) {
  if (!lastRunAt) return '';
  return new Date(lastRunAt).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function buildCsv(rows) {
  const headers = ['Device', 'Vendor', 'Last Run', 'PCI DSS %', 'ISO 27001 %', 'CIS v8 %', 'NIST %'];
  const lines = [headers.join(',')];
  for (const r of rows) {
    lines.push(
      [
        csvEscape(r.deviceName),
        csvEscape(r.vendor),
        csvEscape(formatLastRun(r.lastRunAt)),
        csvEscape(r.standards.PCI_DSS.scorePct),
        csvEscape(r.standards.ISO_27001.scorePct),
        csvEscape(r.standards.CIS_V8.scorePct),
        csvEscape(r.standards.NIST.scorePct),
      ].join(',')
    );
  }
  return lines.join('\r\n');
}

// GET /api/compliance/fleet
// One row per active device (WHERE active = true — same convention as
// app/(dashboard)/alerts/page.js's getDevices), each with the same
// per-standard scorePct breakdown as GET /api/compliance/[deviceId].
export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const format = searchParams.get('format');

    const { rows: devices } = await pool.query(
      'SELECT id, name, vendor FROM devices WHERE active = true ORDER BY name ASC'
    );

    const { rows: findingRows } = await pool.query(
      `SELECT af.device_id, af.status, ac.standards
       FROM audit_findings af
       JOIN audit_checks ac ON ac.id = af.check_id
       JOIN devices d ON d.id = af.device_id
       WHERE d.active = true`
    );

    const { rows: lastRunRows } = await pool.query(
      `SELECT af.device_id, MAX(af.detected_at) AS last_run_at
       FROM audit_findings af
       JOIN devices d ON d.id = af.device_id
       WHERE d.active = true
       GROUP BY af.device_id`
    );
    const lastRunByDevice = new Map(lastRunRows.map((r) => [r.device_id, r.last_run_at]));

    const statsByDevice = new Map();
    for (const device of devices) {
      statsByDevice.set(device.id, emptyStandardStats());
    }

    for (const row of findingRows) {
      const stats = statsByDevice.get(row.device_id);
      if (!stats) continue; // defensive — should always exist given the WHERE d.active=true join above
      const standardsForRow = Array.isArray(row.standards) ? row.standards : [];
      for (const standard of standardsForRow) {
        if (!stats[standard]) continue;
        stats[standard].total += 1;
        if (row.status === 'pass') stats[standard].pass += 1;
        else if (row.status === 'fail') stats[standard].fail += 1;
        else if (row.status === 'warning') stats[standard].warning += 1;
        else if (row.status === 'na') stats[standard].na += 1;
      }
    }

    const result = devices.map((device) => {
      const stats = statsByDevice.get(device.id);
      finalizeScorePct(stats);
      return {
        deviceId: device.id,
        deviceName: device.name,
        vendor: device.vendor,
        lastRunAt: lastRunByDevice.get(device.id) || null,
        standards: stats,
      };
    });

    if (format === 'csv') {
      const csv = buildCsv(result);
      return new Response(csv, {
        status: 200,
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': 'attachment; filename="compliance-fleet.csv"',
        },
      });
    }

    return Response.json({ devices: result });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
