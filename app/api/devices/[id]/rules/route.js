import { NextResponse } from 'next/server';
import { pool } from '../../../../../lib/db';
import { isValidUuid } from '../../../../../lib/apiUtils';
// ⛔ THE SHARED ESCAPE, NOT A LOCAL ONE (migrated 2026-09-25). This route
// carried its own `csvEscape` that predated lib/csv.js: it quoted
// CONDITIONALLY and neutralised NOTHING, so a cell beginning `=`, `+`, `-` or
// `@` was EXECUTED as a formula when the export was opened in Excel,
// LibreOffice or Sheets.
// ⛔ THIS IS THE LARGEST EXPORT IN THE PRODUCT and the most exposed one. It
// emits the WHOLE ruleset, `comment` included — free text an administrator
// types into the firewall, i.e. a value that originates entirely outside
// SecVault. Live proof from the fixture used to verify this migration: the
// old escape wrote `=cmd|'/c calc'!A1` into the document raw AND unquoted,
// because the value contains no comma, quote or newline and so failed the
// conditional-quoting test. A firewall rule comment was a direct path to code
// running on an operator's workstation.
// ⛔ Do not reintroduce a local copy. Two files deciding independently how to
// neutralise a spreadsheet formula would eventually disagree, and the one that
// disagreed quietly would be the one writing the document that executes.
import { csvRow, csvDocument } from '../../../../../lib/csv';

export const dynamic = 'force-dynamic';

// Builds a parameterized WHERE clause + params array for the shared filter set used by
// both the JSON listing and the CSV export. Never interpolates raw query-param values
// into SQL — every filter value goes in as a bound parameter.
// ⛔ Extended 2026-07-19: `action` now accepts a comma-separated list (e.g.
// `action=deny,drop,reject`), matched via `= ANY($N::text[])` — see the
// identical comment in the sibling page's own buildFilters() (this file's
// established convention is duplicating this helper across page + API route
// rather than sharing it, since Next.js page/route files aren't importable
// modules for each other). Also added `nat=true`/`nat=false`.
function buildFilters(deviceId, searchParams) {
  const conditions = ['device_id = $1'];
  const params = [deviceId];

  const action = searchParams.get('action');
  if (action) {
    const actions = action.split(',').map((a) => a.trim()).filter(Boolean);
    if (actions.length > 0) {
      params.push(actions);
      conditions.push(`action = ANY($${params.length}::text[])`);
    }
  }

  const enabled = searchParams.get('enabled');
  if (enabled === 'true' || enabled === 'false') {
    params.push(enabled === 'true');
    conditions.push(`enabled = $${params.length}`);
  }

  const nat = searchParams.get('nat');
  if (nat === 'true' || nat === 'false') {
    params.push(nat === 'true');
    conditions.push(`nat_enabled = $${params.length}`);
  }

  const zone = searchParams.get('zone');
  if (zone) {
    params.push(JSON.stringify([zone]));
    const idx = params.length;
    conditions.push(`(src_zones @> $${idx}::jsonb OR dst_zones @> $${idx}::jsonb)`);
  }

  const search = searchParams.get('search');
  if (search) {
    params.push(`%${search}%`);
    const idx = params.length;
    conditions.push(
      `(rule_name ILIKE $${idx} OR src_addresses::text ILIKE $${idx} OR dst_addresses::text ILIKE $${idx} OR services::text ILIKE $${idx})`
    );
  }

  return { where: `WHERE ${conditions.join(' AND ')}`, params };
}

// ⛔ THE ONE TRANSFORMATION THE OLD LOCAL ESCAPE DID THAT THE SHARED ONE DOES
// NOT, AND IT IS LOAD-BEARING HERE. `csvEscape` in lib/csv.js does a bare
// `String(value)`. SIX of this export's fourteen columns are JSONB —
// src_zones, dst_zones, src_addresses, dst_addresses, services, applications —
// and node-postgres hands JSONB back ALREADY PARSED, as real JS arrays. The
// old escape carried `typeof value === 'object' ? JSON.stringify(value) : …`,
// so `["10.0.0.0/8","192.168.1.1","SRV-WEB"]` is what the customer's file has
// always contained. Passing the array straight to the shared escape instead
// would render it `10.0.0.0/8,192.168.1.1,SRV-WEB` — commas inside a cell,
// harmless only because the shared escape now always quotes — and any JSONB
// value that is an OBJECT rather than an array would become `[object Object]`.
// Either way the product's biggest export silently changes shape.
// ⛔ So the transformation stays HERE, at the call site, and a STRING is what
// reaches csvRow. The null check comes FIRST because `typeof null === 'object'`
// and JSON.stringify(null) is the four-character string `"null"`, not an empty
// cell — which is `hit_count`'s NOT-MEASURED NULL rendered as a fact.
function cell(value) {
  if (value === null || value === undefined) return '';
  return typeof value === 'object' ? JSON.stringify(value) : value;
}

// ⛔ THE COLUMNS AND THEIR ORDER ARE UNCHANGED BY THE ESCAPE MIGRATION, and
// deliberately so: this is the export customers save, script against and hand
// to auditors. Only the ENCODING of a cell changed — every cell is now quoted
// (the shared escape always quotes, because deciding per value whether it
// contains a separator shifts every column after the one call you get wrong)
// and a leading formula character is prefixed with an apostrophe.
function buildCsv(rows) {
  const headers = [
    '#',
    'Name',
    'Enabled',
    'Action',
    'Src Zones',
    'Dst Zones',
    'Src Addresses',
    'Dst Addresses',
    'Services',
    'Comment',
    'Applications',
    'Schedule',
    'Log Enabled',
    'Hit Count',
  ];
  // The header goes through csvRow too, matching every other export in this
  // repo: one escape for the whole document means no row can be encoded by a
  // different set of rules than the row above it.
  const lines = [csvRow(headers)];
  for (const r of rows) {
    lines.push(
      csvRow([
        cell(r.sequence_number),
        cell(r.rule_name),
        cell(r.enabled),
        cell(r.action),
        cell(r.src_zones),
        cell(r.dst_zones),
        cell(r.src_addresses),
        cell(r.dst_addresses),
        cell(r.services),
        cell(r.comment),
        cell(r.applications),
        cell(r.schedule),
        cell(r.log_enabled),
        cell(r.hit_count),
      ])
    );
  }
  // ⛔ No BOM: this export has never carried one, and adding it is a separate,
  // visible decision (see lib/csv.js for why it is opt-in per caller). A
  // filter that matches no rules still gets its header row — "the export is
  // broken" and "no rule matched this filter" must never look the same.
  return csvDocument(lines);
}

// GET /api/devices/[id]/rules — JSON list (paginated) by default; ?format=csv streams a
// full (unpaginated) CSV export honoring the same filters.
export async function GET(request, { params }) {
  const deviceId = params.id;

  if (!isValidUuid(deviceId)) {
    return NextResponse.json({ error: 'Invalid device id' }, { status: 400 });
  }

  const { searchParams } = new URL(request.url);
  const format = searchParams.get('format');
  const { where, params: sqlParams } = buildFilters(deviceId, searchParams);

  try {
    if (format === 'csv') {
      const result = await pool.query(
        `SELECT sequence_number, rule_name, enabled, action, src_zones, dst_zones,
                src_addresses, dst_addresses, services, comment, applications, schedule,
                log_enabled, hit_count
         FROM firewall_rules
         ${where}
         ORDER BY sequence_number ASC NULLS LAST`,
        sqlParams
      );
      const csv = buildCsv(result.rows);
      return new Response(csv, {
        status: 200,
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': 'attachment; filename="device-rules.csv"',
        },
      });
    }

    const page = Math.max(1, parseInt(searchParams.get('page') || '1', 10) || 1);
    const pageSize = 50;
    const offset = (page - 1) * pageSize;

    const limitIdx = sqlParams.length + 1;
    const offsetIdx = sqlParams.length + 2;
    const result = await pool.query(
      `SELECT *
       FROM firewall_rules
       ${where}
       ORDER BY sequence_number ASC NULLS LAST
       LIMIT $${limitIdx} OFFSET $${offsetIdx}`,
      [...sqlParams, pageSize, offset]
    );

    const countResult = await pool.query(
      `SELECT COUNT(*)::int AS total FROM firewall_rules ${where}`,
      sqlParams
    );

    return NextResponse.json({
      rows: result.rows,
      page,
      pageSize,
      total: countResult.rows[0]?.total ?? 0,
    });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to load rules' }, { status: 500 });
  }
}
