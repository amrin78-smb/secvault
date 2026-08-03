import { pool } from '../../lib/db';
const { buildFleetTopologyGraph } = require('../../lib/engines/topology');
const { parseCidrOrIp } = require('../../lib/engines/cidrUtils');
import Card, { CardBody } from '../ui/Card';
import EmptyState from '../ui/EmptyState';

// Fleet-wide visual map — every active device as a node, every inferred
// device-to-device link as a line. TWO independent edge kinds, per
// lib/engines/topology.js's buildFleetTopologyGraph(): 'subnet' (shared
// subnet between two devices' collected interfaces, buildAdjacencyGraph())
// and 'vpn' (a device's IPsec tunnel peer gateway IP matching another
// device's own interface IP, buildVpnEdges() — added 2026-08-03 after
// several Fortinet branches showed no lines at all; their site-to-site
// tunnels use UNNUMBERED interfaces with no subnet to match on, so the VPN
// peer-IP signal is the only way those real links become visible). Async
// server component, does its own pool.query — same "server component
// queries the DB directly" convention as ReachabilityTab.js/ObjectsTab.js
// on the per-device analysis page. Do not add 'use client'.
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

// Deliberately NOT each vendor's real brand color (Palo Alto/Fortinet/Check
// Point are all red-orange in real life, Cisco/Sangfor are both blue) —
// three vendors of near-identical hue were indistinguishable as small map
// dots (found live: this fleet's Fortinet and Palo Alto devices, the two
// most common vendors here, were the worst offenders). Chosen instead for
// maximum pairwise hue separation across all six, spaced around the color
// wheel, with Fortinet and Palo Alto specifically placed as far apart as
// possible since they're this fleet's two actual vendors today.
const VENDOR_COLOR = {
  paloalto: '#f97316',
  fortinet: '#0ea5e9',
  cisco_asa: '#1d4ed8',
  checkpoint: '#dc2626',
  sangfor: '#7c3aed',
  forcepoint: '#db2777',
};
const VENDOR_LABEL = {
  paloalto: 'Palo Alto',
  fortinet: 'Fortinet',
  cisco_asa: 'Cisco ASA',
  checkpoint: 'Check Point',
  sangfor: 'Sangfor',
  forcepoint: 'Forcepoint',
};
const DEFAULT_VENDOR_COLOR = '#64748b';

// Small inline SVG swatches for the legend — a line sample for edge types, a
// dot sample for node vendor/collection-state — so the legend visually
// matches exactly what's drawn on the map itself, rather than describing it
// in prose alone.
function LineSwatch({ color, dashed }) {
  return (
    <svg width={22} height={10} aria-hidden="true">
      <line x1={1} y1={5} x2={21} y2={5} stroke={color} strokeWidth={dashed ? 1.5 : 2} strokeDasharray={dashed ? '5 3' : undefined} opacity={dashed ? 0.75 : 1} />
    </svg>
  );
}

function DotSwatch({ color, muted }) {
  return (
    <svg width={14} height={14} aria-hidden="true">
      <circle cx={7} cy={7} r={6} fill={muted ? 'var(--bg-primary)' : color} stroke={color} strokeWidth={2} strokeDasharray={muted ? '3,3' : undefined} opacity={muted ? 0.6 : 1} />
    </svg>
  );
}

function LegendItem({ swatch, label }) {
  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      {swatch}
      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>{label}</span>
    </div>
  );
}

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

  const tunnelsResult = await dbPool.query(
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
  const presentVendors = [...new Set(positioned.map((n) => n.vendor))].sort(
    (a, b) => (VENDOR_LABEL[a] || a).localeCompare(VENDOR_LABEL[b] || b)
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', margin: 0 }}>
        Every active device, plus every inferred link between them — see the legend below for what each line and
        dot style means.
        {uncollectedCount > 0 && ` ${uncollectedCount} of ${positioned.length} devices shown have no interface data yet.`}{' '}
        Click a solid device to query a path starting there.
      </p>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px 20px', padding: '10px 14px', background: 'var(--surface-subtle)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
        <LegendItem swatch={<LineSwatch color="var(--border)" />} label="Shared subnet" />
        <LegendItem swatch={<LineSwatch color="var(--primary)" dashed />} label="VPN tunnel (active)" />
        <LegendItem swatch={<DotSwatch color="var(--text-secondary)" />} label="Interface data collected" />
        <LegendItem swatch={<DotSwatch color="var(--text-secondary)" muted />} label="Not yet collected" />
        {presentVendors.map((vendor) => (
          <LegendItem
            key={vendor}
            swatch={<DotSwatch color={VENDOR_COLOR[vendor] || DEFAULT_VENDOR_COLOR} />}
            label={VENDOR_LABEL[vendor] || vendor}
          />
        ))}
      </div>

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
                const isVpn = edge.type === 'vpn';
                // Array order is already subnet-edges-then-vpn-edges (see
                // buildFleetTopologyGraph()), so VPN lines naturally paint
                // on top of any subnet line for the same pair — no sort
                // needed here.
                const titleText = isVpn
                  ? `${a.name} VPN: "${edge.tunnelName}" (${edge.status}) <-> ${b.name}`
                  : `${a.name} (${edge.sourceInterface}) <-> ${b.name} (${edge.targetInterface})`;
                return (
                  <line
                    key={i}
                    x1={a.x}
                    y1={a.y}
                    x2={b.x}
                    y2={b.y}
                    stroke={isVpn ? 'var(--primary)' : 'var(--border)'}
                    strokeWidth={isVpn ? 1.5 : 2}
                    strokeDasharray={isVpn ? '5 3' : undefined}
                    opacity={isVpn ? 0.75 : 1}
                  >
                    {/* ⛔ react-dom's server renderer special-cases <title>
                        (SVG or HTML) to accept only ONE text-node child --
                        multiple mixed string/expression children silently
                        render empty on the server, then mismatch on
                        hydration (React error #418). Always pass a single
                        pre-concatenated template-literal string here. */}
                    <title>{titleText}</title>
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
