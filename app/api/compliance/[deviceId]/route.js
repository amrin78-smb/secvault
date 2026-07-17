import { pool } from '../../../../lib/db';
import { isValidUuid } from '../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

const STANDARDS = ['PCI_DSS', 'ISO_27001', 'CIS_V8', 'NIST'];

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const str = typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/[",\n\r]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function buildCsv(rows) {
  const headers = ['Check Name', 'Severity', 'Standards', 'Status', 'Detail', 'Remediation'];
  const lines = [headers.join(',')];
  for (const r of rows) {
    lines.push(
      [
        csvEscape(r.name),
        csvEscape(r.severity),
        csvEscape(Array.isArray(r.standards) ? r.standards.join('; ') : r.standards),
        csvEscape(r.status),
        csvEscape(r.detail),
        csvEscape(r.remediation_guidance),
      ].join(',')
    );
  }
  return lines.join('\r\n');
}

// Sanitizes user-entered device data (device.name) before it lands in an HTTP
// header (Content-Disposition filename) — strips anything that isn't
// alphanumeric/dash/underscore/space.
function sanitizeForFilename(value) {
  return String(value || '').replace(/[^a-zA-Z0-9\- _]/g, '');
}

// scorePct = round(100 * pass / (pass + fail + warning)), EXCLUDING 'na' from
// the denominator (an inapplicable check shouldn't count against the score).
// Divide-by-zero guarded: all-na or zero-checks -> scorePct: null.
function buildStandardStats(rows) {
  const stats = {};
  for (const standard of STANDARDS) {
    stats[standard] = { pass: 0, fail: 0, warning: 0, na: 0, total: 0, scorePct: null };
  }

  for (const row of rows) {
    const standardsForRow = Array.isArray(row.standards) ? row.standards : [];
    for (const standard of standardsForRow) {
      if (!stats[standard]) continue; // ignore any standard outside the known 4 (e.g. 'CUSTOM')
      stats[standard].total += 1;
      if (row.status === 'pass') stats[standard].pass += 1;
      else if (row.status === 'fail') stats[standard].fail += 1;
      else if (row.status === 'warning') stats[standard].warning += 1;
      else if (row.status === 'na') stats[standard].na += 1;
    }
  }

  for (const standard of STANDARDS) {
    const s = stats[standard];
    const denom = s.pass + s.fail + s.warning;
    s.scorePct = denom > 0 ? Math.round((100 * s.pass) / denom) : null;
  }

  return stats;
}

// GET /api/compliance/[deviceId]
// Latest compliance findings for one device, with a per-standard pass/fail/
// warning/na breakdown + scorePct. A device that has never been audited
// returns lastRunAt: null, empty standards (all zeros), empty findings —
// 404 is reserved for a device that doesn't exist at all.
export async function GET(request, { params }) {
  try {
    const { deviceId } = params;
    const { searchParams } = new URL(request.url);
    const format = searchParams.get('format');

    if (!isValidUuid(deviceId)) {
      return Response.json({ error: 'Invalid device id' }, { status: 400 });
    }

    const { rows: deviceRows } = await pool.query(
      'SELECT id, name, vendor FROM devices WHERE id = $1',
      [deviceId]
    );
    if (deviceRows.length === 0) {
      return Response.json({ error: 'Device not found' }, { status: 404 });
    }
    const device = deviceRows[0];

    const { rows: findingRows } = await pool.query(
      `SELECT af.id, af.check_id, ac.check_id AS check_slug, ac.name, ac.standards,
              ac.severity, af.status, af.detail, ac.remediation_guidance, af.detected_at
       FROM audit_findings af
       JOIN audit_checks ac ON ac.id = af.check_id
       WHERE af.device_id = $1
       ORDER BY
         CASE af.status WHEN 'fail' THEN 0 WHEN 'warning' THEN 1 WHEN 'pass' THEN 2 ELSE 3 END,
         CASE ac.severity
           WHEN 'critical' THEN 0
           WHEN 'high' THEN 1
           WHEN 'medium' THEN 2
           WHEN 'low' THEN 3
           ELSE 4
         END,
         ac.name`,
      [deviceId]
    );

    if (format === 'csv') {
      const csv = buildCsv(findingRows);
      const filenameBase = sanitizeForFilename(device.name) || deviceId;
      return new Response(csv, {
        status: 200,
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': `attachment; filename="compliance-${filenameBase}.csv"`,
        },
      });
    }

    const { rows: lastRunRows } = await pool.query(
      'SELECT MAX(detected_at) AS last_run_at FROM audit_findings WHERE device_id = $1',
      [deviceId]
    );
    const lastRunAt = lastRunRows[0] && lastRunRows[0].last_run_at ? lastRunRows[0].last_run_at : null;

    const standards = buildStandardStats(
      findingRows.map((r) => ({ standards: r.standards, status: r.status }))
    );

    return Response.json({
      deviceId: device.id,
      deviceName: device.name,
      vendor: device.vendor,
      lastRunAt,
      standards,
      findings: findingRows.map((r) => ({
        id: r.id,
        checkId: r.check_id,
        checkSlug: r.check_slug,
        name: r.name,
        severity: r.severity,
        standards: r.standards,
        status: r.status,
        detail: r.detail,
        remediationGuidance: r.remediation_guidance,
        detectedAt: r.detected_at,
      })),
    });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
