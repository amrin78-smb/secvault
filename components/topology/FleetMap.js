import { pool } from '../../lib/db';
const { buildFleetTopologyGraph } = require('../../lib/engines/topology');
const { parseCidrOrIp } = require('../../lib/engines/cidrUtils');
import Card, { CardBody } from '../ui/Card';
import EmptyState from '../ui/EmptyState';

// Fleet-wide visual map — every active device as a node, every inferred
// device-to-device link (shared subnet, per lib/engines/topology.js's
// buildAdjacencyGraph()) as a line. Async server component, does its own
// pool.query — same "server component queries the DB directly" convention
// as ReachabilityTab.js/ObjectsTab.js on the per-device analysis page. Do
// not add 'use client'.
//
// Hand-rolled inline SVG, circular layout: nodes placed evenly around a
// circle, sorted by name for a stable/deterministic render. No physics/
// force-directed simulation — unnecessary at this fleet's device count and
// this codebase has no diagramming library to lean on (recharts is
// charts-only).
//
// Click-through (added 2026-08-03): a node with hasInterfaceData:true is
// wrapped in a plain SVG <a> to /topology?view=query&srcIp=<ip> — no client
// JS needed, same "a normal link over client JS when one suffices" instinct
// as this app's CSV-download <a> tags elsewhere. The pre-filled IP is that
// device's first interface (sorted by name) whose address parses cleanly —
// a reasonable default, not a claim it's "the right" source; the user can
// edit it before submitting, same as any other pre-filled form field.

const VENDOR_COLOR = {
  paloalto: '#fa582d',
  fortinet: '#ee3124',
  cisco_asa: '#1ba1e2',
  checkpoint: '#e4032e',
  sangfor: '#0a5eb0',
  forcepoint: '#5e2d91',
};
const DEFAULT_VENDOR_COLOR = '#64748b';

const VIEWBOX_SIZE = 640;
const CENTER = VIEWBOX_SIZE / 2;
const RADIUS = 250;
const NODE_R = 10;

function layoutNodes(nodes) {
  const sorted = nodes.slice().sort((a, b) => a.name.localeCompare(b.name));
  const n = sorted.length;
  return sorted.map((node, i) => {
    const angle = n <= 1 ? 0 : (2 * Math.PI * i) / n - Math.PI / 2;
    const x = n <= 1 ? CENTER : CENTER + RADIUS * Math.cos(angle);
    const y = n <= 1 ? CENTER : CENTER + RADIUS * Math.sin(angle);
    return { ...node, x, y };
  });
}

async function getFleetGraph(dbPool) {
  const devicesResult = await dbPool.query('SELECT id, name, vendor FROM devices WHERE active = true');
  const devices = devicesResult.rows;
  if (devices.length === 0) return { nodes: [], edges: [], interfacesByDevice: new Map() };

  const deviceIds = devices.map((d) => d.id);
  const interfacesResult = await dbPool.query(
    `SELECT device_id, interface_name, ip_address, enabled
     FROM device_interfaces WHERE device_id = ANY($1::uuid[])`,
    [deviceIds]
  );
  const interfacesByDevice = new Map();
  for (const row of interfacesResult.rows) {
    if (!interfacesByDevice.has(row.device_id)) interfacesByDevice.set(row.device_id, []);
    interfacesByDevice.get(row.device_id).push(row);
  }

  const graph = buildFleetTopologyGraph(devices, interfacesByDevice);
  return { ...graph, interfacesByDevice };
}

// First interface (sorted by name, matching the diagram's own node-sort
// convention) whose ip_address parses as a real IPv4/CIDR — the bare IP
// (prefix stripped) becomes the pre-filled Path Query source. Returns null
// if the device has no interfaces or none parse (never guesses).
function representativeIp(interfaces) {
  if (!Array.isArray(interfaces) || interfaces.length === 0) return null;
  const sorted = interfaces.slice().sort((a, b) => a.interface_name.localeCompare(b.interface_name));
  for (const iface of sorted) {
    const parsed = parseCidrOrIp(iface.ip_address);
    if (parsed === null) continue;
    return iface.ip_address.split('/')[0];
  }
  return null;
}

export default async function FleetMap() {
  const { nodes, edges, interfacesByDevice } = await getFleetGraph(pool);

  if (nodes.length === 0) {
    return <EmptyState message="No active devices to map yet." />;
  }

  const positioned = layoutNodes(nodes).map((node) => ({
    ...node,
    srcIp: node.hasInterfaceData ? representativeIp(interfacesByDevice.get(node.id)) : null,
  }));
  const byId = new Map(positioned.map((n) => [n.id, n]));
  const uncollectedCount = positioned.filter((n) => !n.hasInterfaceData).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', margin: 0 }}>
        Every active device, and every link inferred from a shared subnet between two devices&apos; collected
        interfaces. Dashed, muted devices have no interface data collected yet — Cisco ASA/Check Point/Sangfor/
        Forcepoint, or a Palo Alto/Fortinet device not yet collected (Phase 1 covers those two vendors&apos; SSH
        transport only).
        {uncollectedCount > 0 && ` ${uncollectedCount} of ${positioned.length} devices shown have no interface data yet.`}{' '}
        Click a solid device to query a path starting there.
      </p>

      <Card>
        <CardBody>
          <div style={{ overflowX: 'auto' }}>
            <svg
              viewBox={`0 0 ${VIEWBOX_SIZE} ${VIEWBOX_SIZE}`}
              width="100%"
              style={{ maxWidth: VIEWBOX_SIZE, display: 'block', margin: '0 auto' }}
              role="img"
              aria-label="Fleet topology map"
            >
              {edges.map((edge, i) => {
                const a = byId.get(edge.sourceDeviceId);
                const b = byId.get(edge.targetDeviceId);
                if (!a || !b) return null;
                return (
                  <line
                    key={i}
                    x1={a.x}
                    y1={a.y}
                    x2={b.x}
                    y2={b.y}
                    stroke="var(--border)"
                    strokeWidth={2}
                  >
                    {/* ⛔ react-dom's server renderer special-cases <title>
                        (SVG or HTML) to accept only ONE text-node child --
                        multiple mixed string/expression children silently
                        render empty on the server, then mismatch on
                        hydration (React error #418). Always pass a single
                        pre-concatenated template-literal string here. */}
                    <title>{`${a.name} (${edge.sourceInterface}) <-> ${b.name} (${edge.targetInterface})`}</title>
                  </line>
                );
              })}

              {positioned.map((node) => {
                const color = VENDOR_COLOR[node.vendor] || DEFAULT_VENDOR_COLOR;
                const labelY = node.y + (node.y >= CENTER ? 22 : -16);
                const titleText = node.srcIp
                  ? `${node.name} (${node.vendor}) - click to query a path from ${node.srcIp}`
                  : `${node.name} (${node.vendor})${node.hasInterfaceData ? '' : ' - no interface data collected'}`;
                const content = (
                  <g key={node.srcIp ? undefined : node.id}>
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={NODE_R}
                      fill={node.hasInterfaceData ? color : 'var(--bg-primary)'}
                      stroke={color}
                      strokeWidth={2}
                      strokeDasharray={node.hasInterfaceData ? undefined : '3,3'}
                      opacity={node.hasInterfaceData ? 1 : 0.6}
                    >
                      {/* Same single-string-child requirement as the edge
                          <title> above. */}
                      <title>{titleText}</title>
                    </circle>
                    <text
                      x={node.x}
                      y={labelY}
                      textAnchor="middle"
                      fontSize={11}
                      fill={node.srcIp ? 'var(--primary)' : 'var(--text-primary)'}
                    >
                      {node.name}
                    </text>
                  </g>
                );

                // Click-through: only a device with a resolvable IP becomes
                // a link (plain SVG <a>, no client JS) -- a device with no
                // interface data has nothing useful to pre-fill and stays
                // non-interactive, matching its already-muted visual state.
                return node.srcIp ? (
                  <a key={node.id} href={`/topology?view=query&srcIp=${encodeURIComponent(node.srcIp)}`} style={{ cursor: 'pointer' }}>
                    {content}
                  </a>
                ) : (
                  content
                );
              })}
            </svg>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
