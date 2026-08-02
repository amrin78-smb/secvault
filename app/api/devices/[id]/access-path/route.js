import { NextResponse } from 'next/server';
import { pool } from '../../../../../lib/db';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { queryAccessPath } from '../../../../../lib/engines/objectResolver';

export const dynamic = 'force-dynamic';

// POST /api/devices/[id]/access-path
// Body: { srcIp, dstIp, protocol?, port? }
// A pure, read-only computation over this device's already-collected
// firewall_rules + network_objects -- no persistence, nothing written.
// Deliberately NOT admin-gated (no isAdmin/forbiddenResponse call): this is
// not a mutating route (CLAUDE.md's RBAC rule is scoped to "every mutating
// (POST/PUT/DELETE/PATCH) route"), and every other analysis view (Reachability,
// Risky Rules, etc) already renders identically for both admin and viewer --
// gating this one POST would make it the sole read-only view a viewer can't
// use, an inconsistency with no real security benefit since the data it
// queries is already fully viewer-readable via those other tabs.
export async function POST(request, { params }) {
  const deviceId = params.id;

  if (!isValidUuid(deviceId)) {
    return NextResponse.json({ error: 'Invalid device id' }, { status: 400 });
  }

  let body = {};
  try {
    body = await request.json();
  } catch {
    // Falls through to the srcIp/dstIp check below.
  }

  const { srcIp, dstIp, protocol, port } = body || {};
  if (!srcIp || !dstIp) {
    return NextResponse.json({ error: 'srcIp and dstIp are required' }, { status: 400 });
  }

  try {
    const deviceResult = await pool.query('SELECT id, vendor FROM devices WHERE id = $1', [deviceId]);
    if (deviceResult.rows.length === 0) {
      return NextResponse.json({ error: 'Device not found' }, { status: 404 });
    }

    const [rulesResult, objectsResult] = await Promise.all([
      pool.query(
        `SELECT id, rule_name, rule_id_vendor, sequence_number, action, enabled,
                src_addresses, dst_addresses, services, log_enabled
         FROM firewall_rules WHERE device_id = $1`,
        [deviceId]
      ),
      pool.query(
        `SELECT object_type, name, value, members FROM network_objects WHERE device_id = $1`,
        [deviceId]
      ),
    ]);

    if (rulesResult.rows.length === 0) {
      return NextResponse.json({
        verdict: 'unspecified',
        matchedRule: null,
        hasCaveat: false,
        walk: [],
        note: 'No rules collected yet for this device.',
      });
    }

    const result = queryAccessPath(rulesResult.rows, objectsResult.rows, { srcIp, dstIp, protocol, port });

    // Sangfor's getObjects() is a deliberate stub (always returns no
    // objects) -- surface this explicitly rather than let a viewer
    // misread a query result that could only ever match on literal IPs/
    // ports typed directly into a rule, never a resolved object.
    const note =
      objectsResult.rows.length === 0
        ? 'No address/service object data is available for this device — only literal IP/port values typed directly into rules could be resolved.'
        : undefined;

    return NextResponse.json({ ...result, note });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Access path query failed' }, { status: 400 });
  }
}
