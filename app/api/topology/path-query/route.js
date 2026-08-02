import { NextResponse } from 'next/server';
import { pool } from '../../../../lib/db';
import { simulateMultiHopPath } from '../../../../lib/engines/topology';

export const dynamic = 'force-dynamic';

// Groups DB rows into a Map<deviceId, row[]>, keyed by the given column --
// the shape every fleetData.*ByDevice field in lib/engines/topology.js
// expects, so this route's only job is "load everything, bucket it, hand it
// to the pure engine."
function groupByDeviceId(rows, column) {
  const map = new Map();
  for (const row of rows) {
    const key = row[column];
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(row);
  }
  return map;
}

// POST /api/topology/path-query
// Body: { srcIp, dstIp, protocol?, port? }
// A pure, read-only, fleet-wide computation over already-collected
// firewall_rules/network_objects/device_interfaces/device_routes/nat_rules
// -- no persistence, nothing written. Deliberately NOT admin-gated, same
// reasoning as the sibling per-device app/api/devices/[id]/access-path
// route this mirrors: CLAUDE.md's RBAC rule only scopes mutating
// (POST/PUT/DELETE/PATCH) routes, and every other read-only analysis view
// already renders identically for admin and viewer.
export async function POST(request) {
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

  // DB loading and engine execution are wrapped SEPARATELY so a genuine
  // input-validation failure (invalid IP, thrown by simulateMultiHopPath)
  // reports 400 while an unexpected failure (DB unreachable, etc) reports
  // 500 -- distinct outcomes the sibling access-path route doesn't need to
  // separate (its single catch only ever sees validation errors, since it
  // has no fleet-wide query fan-out to fail independently).
  let fleetData;
  try {
    const devicesResult = await pool.query('SELECT id, name FROM devices WHERE active = true');
    const devices = devicesResult.rows;

    if (devices.length === 0) {
      return NextResponse.json({
        finalVerdict: 'unspecified',
        hops: [],
        note: 'No active devices are known to SecVault.',
      });
    }

    const deviceIds = devices.map((d) => d.id);

    const [rulesResult, objectsResult, interfacesResult, routesResult, natRulesResult] = await Promise.all([
      pool.query(
        `SELECT device_id, id, rule_name, rule_id_vendor, sequence_number, action, enabled,
                src_addresses, dst_addresses, services, log_enabled
         FROM firewall_rules WHERE device_id = ANY($1::uuid[])`,
        [deviceIds]
      ),
      pool.query(
        `SELECT device_id, object_type, name, value, members
         FROM network_objects WHERE device_id = ANY($1::uuid[])`,
        [deviceIds]
      ),
      pool.query(
        `SELECT device_id, interface_name, ip_address, zone, vdom, enabled
         FROM device_interfaces WHERE device_id = ANY($1::uuid[])`,
        [deviceIds]
      ),
      pool.query(
        `SELECT device_id, destination_cidr, next_hop_ip, interface_name, protocol, metric, vdom
         FROM device_routes WHERE device_id = ANY($1::uuid[])`,
        [deviceIds]
      ),
      pool.query(
        `SELECT device_id, id, sequence_number, enabled, nat_type,
                original_src_addresses, original_dst_addresses, original_services,
                translated_src_addresses, translated_dst_addresses, translated_services
         FROM nat_rules WHERE device_id = ANY($1::uuid[])`,
        [deviceIds]
      ),
    ]);

    fleetData = {
      devices,
      rulesByDevice: groupByDeviceId(rulesResult.rows, 'device_id'),
      objectsByDevice: groupByDeviceId(objectsResult.rows, 'device_id'),
      interfacesByDevice: groupByDeviceId(interfacesResult.rows, 'device_id'),
      routesByDevice: groupByDeviceId(routesResult.rows, 'device_id'),
      natRulesByDevice: groupByDeviceId(natRulesResult.rows, 'device_id'),
    };
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to load fleet data' }, { status: 500 });
  }

  try {
    const result = simulateMultiHopPath(fleetData, { srcIp, dstIp, protocol, port });
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Invalid topology path query' }, { status: 400 });
  }
}
