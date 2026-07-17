import { NextResponse } from 'next/server';
import { pool } from '../../../../../lib/db';

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
    '#',
    'Name',
    'Enabled',
    'Action',
    'Src Zones',
    'Dst Zones',
    'Src Addresses',
    'Dst Addresses',
    'Services',
    'Log Enabled',
    'Hit Count',
  ];
  const lines = [headers.join(',')];
  for (const r of rows) {
    lines.push(
      [
        csvEscape(r.sequence_number),
        csvEscape(r.rule_name),
        csvEscape(r.enabled),
        csvEscape(r.action),
        csvEscape(r.src_zones),
        csvEscape(r.dst_zones),
        csvEscape(r.src_addresses),
        csvEscape(r.dst_addresses),
        csvEscape(r.services),
        csvEscape(r.log_enabled),
        csvEscape(r.hit_count),
      ].join(',')
    );
  }
  return lines.join('\r\n');
}

// GET /api/devices/[id]/rules — JSON list (paginated) by default; ?format=csv streams a
// full (unpaginated) CSV export honoring the same filters.
export async function GET(request, { params }) {
  const deviceId = params.id;
  const { searchParams } = new URL(request.url);
  const format = searchParams.get('format');
  const { where, params: sqlParams } = buildFilters(deviceId, searchParams);

  try {
    if (format === 'csv') {
      const result = await pool.query(
        `SELECT sequence_number, rule_name, enabled, action, src_zones, dst_zones,
                src_addresses, dst_addresses, services, log_enabled, hit_count
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
