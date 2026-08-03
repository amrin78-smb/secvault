import { NextResponse } from 'next/server';
import { pool } from '../../../../lib/db';
import { buildFleetTopologyGraph } from '../../../../lib/engines/topology';

export const dynamic = 'force-dynamic';

// GET /api/topology/graph
// Fleet-wide adjacency graph (every active device as a node, every inferred
// device-to-device link as one deduped edge — 'subnet' or 'vpn', see
// lib/engines/topology.js's buildFleetTopologyGraph()) — distinct from
// POST /api/topology/path-query, which answers one specific src/dst query.
// Powers components/topology/FleetMap.js's visual diagram; kept as its own
// JSON route (not folded into the page) for API consistency with
// path-query and any future external consumer. Ungated (GET, auth only) —
// same convention as every other read view.
export async function GET() {
  try {
    const devicesResult = await pool.query('SELECT id, name, vendor FROM devices WHERE active = true');
    const devices = devicesResult.rows;

    if (devices.length === 0) {
      return NextResponse.json({ nodes: [], edges: [] });
    }

    const deviceIds = devices.map((d) => d.id);
    const interfacesResult = await pool.query(
      `SELECT device_id, interface_name, ip_address, enabled
       FROM device_interfaces WHERE device_id = ANY($1::uuid[])`,
      [deviceIds]
    );

    const interfacesByDevice = new Map();
    for (const row of interfacesResult.rows) {
      if (!interfacesByDevice.has(row.device_id)) interfacesByDevice.set(row.device_id, []);
      interfacesByDevice.get(row.device_id).push(row);
    }

    const tunnelsResult = await pool.query(
      `SELECT device_id, name, peer, status
       FROM vpn_ipsec_tunnels WHERE device_id = ANY($1::uuid[])`,
      [deviceIds]
    );
    const vpnTunnelsByDevice = new Map();
    for (const row of tunnelsResult.rows) {
      if (!vpnTunnelsByDevice.has(row.device_id)) vpnTunnelsByDevice.set(row.device_id, []);
      vpnTunnelsByDevice.get(row.device_id).push(row);
    }

    const graph = buildFleetTopologyGraph(devices, interfacesByDevice, vpnTunnelsByDevice);
    return NextResponse.json(graph);
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to build fleet topology graph' }, { status: 500 });
  }
}
