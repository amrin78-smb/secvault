// tests/topologyAdjacency.test.js
//
// ⛔ WHY THIS EXISTS. `buildAdjacencyGraph()` decided two firewalls shared a
// link if their interface RANGES overlapped at all. `parseCidrOrIp()` masks
// host bits off by design, so the interface's own address was thrown away
// before the comparison ever happened, and two things that are not links
// became links:
//
//   - the SAME HOST ADDRESS on two devices. `10.254.254.1/24` is held
//     simultaneously by IDC FW, SMT, TUM(TUTH1) and TUFF(TUTH3) on the live
//     fleet, and `192.168.100.254/24` by HRIS and OKF(F2). That is an IP
//     conflict or a copy-pasted branch template — it is physically impossible
//     on one link, and it was the STRONGEST adjacency evidence available.
//   - a PREFIX MISMATCH. A /30 point-to-point tunnel nested inside an
//     unrelated device's /24 overlaps it numerically and shares nothing.
//
// Measured live: 68 cross-device interface pairs, of which 10 were same-host,
// 47 were prefix-mismatched, and only 11 were plausible — 84% false, 136
// directed links where ~22 were credible.
//
// ⛔ THE DAMAGE IS NOT COSMETIC. `simulateMultiHopPath()` takes `neighbors[0]`,
// so a phantom neighbour makes the simulator evaluate the WRONG FIREWALL'S
// RULESET and return a confident allow/deny for a hop that does not exist; and
// the Fleet Map dedupes by device pair first-wins, so a phantom edge claimed
// the pair key and DISPLACED the genuine tunnel link from the diagram
// (it drew IDC FW[ha1-a] — PAKFood[tunnel.3], an HA sync interface, and never
// drew the real tunnel.40 — tunnel.3).
//
// ⛔ THE OTHER DIRECTION IS EQUALLY WRONG, which is why half the cases below
// assert an edge SURVIVES. Deleting a real link silently truncates a path
// query — the same class of wrong answer, wearing different clothes. The four
// known-good /30 tunnel pairs from the live fleet are pinned by name.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parseInterfaceAddress,
  interfacesAreAdjacent,
  buildAdjacencyGraph,
  buildFleetTopologyGraph,
  simulateMultiHopPath,
} = require('../lib/engines/topology');

// ───────────────────────────── helpers ─────────────────────────────

const iface = (name, ip, extra = {}) => ({ interface_name: name, ip_address: ip, ...extra });

// deviceId -> rows, in insertion order (the order that decides neighbors[0]).
const ifaceMap = (obj) => new Map(Object.entries(obj));

// Pairs, deduped and undirected, as `dev/iface <-> dev/iface` strings — the
// shape the live verification counted (68 before, 11 after).
function undirectedPairs(graph) {
  const out = new Set();
  for (const [key, neighbors] of graph) {
    for (const n of neighbors) out.add([key, `${n.deviceId}::${n.interfaceName}`].sort().join(' <-> '));
  }
  return out;
}

// ─────────────────── the address parse keeps BOTH halves ───────────────────

test('an interface address keeps its host as well as its masked network', () => {
  const a = parseInterfaceAddress('10.254.254.233/30');
  assert.equal(a.prefixLen, 30);
  // Host bits survive: .233 and .234 share a network and differ as hosts.
  const b = parseInterfaceAddress('10.254.254.234/30');
  assert.equal(a.network, b.network);
  assert.notEqual(a.host, b.host);
});

test("the literal 'N/A' is an ABSENT address, not an address", () => {
  // 95 of 241 live device_interfaces rows (39%, 10 devices) store this
  // sentinel where NULL belongs — a vendor saying "no address" recorded as if
  // it were one. It must never reach the adjacency test.
  for (const v of ['N/A', 'n/a', '', '   ', null, undefined, 0, {}, 'unassigned']) {
    assert.equal(parseInterfaceAddress(v), null, String(v));
  }
});

// ───────────────────────────── the predicate ─────────────────────────────

const at = (deviceId, name, ip) => ({ deviceId, interfaceName: name, ...parseInterfaceAddress(ip) });

test('an IDENTICAL host address on two devices is an IP conflict, never adjacency', () => {
  // The live case: 10.254.254.1/24 on four different devices at once.
  assert.equal(interfacesAreAdjacent(at('idc', 'e1', '10.254.254.1/24'), at('smt', 'e1', '10.254.254.1/24')), false);
  assert.equal(
    interfacesAreAdjacent(at('hris', 'e2', '192.168.100.254/24'), at('okf', 'e2', '192.168.100.254/24')),
    false
  );
});

test('a /30 nested inside an unrelated /24 is not a shared link', () => {
  assert.equal(
    interfacesAreAdjacent(at('idc', 'tunnel.40', '10.254.254.233/30'), at('tum', 'ethernet1/7', '10.254.254.1/24')),
    false
  );
});

test('a genuine point-to-point /30 pair IS adjacent', () => {
  assert.equal(
    interfacesAreAdjacent(at('idc', 'tunnel.40', '10.254.254.233/30'), at('pak', 'tunnel.3', '10.254.254.234/30')),
    true
  );
});

test('two different hosts on one shared /24 are adjacent', () => {
  assert.equal(interfacesAreAdjacent(at('a', 'e1', '10.9.9.1/24'), at('b', 'e1', '10.9.9.2/24')), true);
});

test('two interfaces on the SAME device are never adjacent to each other', () => {
  assert.equal(interfacesAreAdjacent(at('a', 'e1', '10.9.9.1/24'), at('a', 'e2', '10.9.9.2/24')), false);
});

// ─────────────────────────── the graph, end to end ───────────────────────────

// A miniature of the live fleet: one device holding both a real /30 tunnel and
// the copy-pasted 10.254.254.1/24 template address, plus the two devices that
// share each of those with it.
const FLEET_IFACES = ifaceMap({
  idc: [
    iface('ethernet1/1', '192.168.50.1/24'),
    iface('ha1-a', '10.254.254.1/24'), // template address, three other devices hold it too
    iface('tunnel.40', '10.254.254.233/30'),
    iface('tunnel.44', '10.254.254.245/30'),
    iface('tunnel.24', '10.254.254.209/30'),
    iface('dead0', 'N/A'), // the live sentinel
    iface('shut0', '10.254.254.253/30', { enabled: false }),
  ],
  tum: [iface('ethernet1/7', '10.254.254.1/24')], // FIRST in insertion order, on purpose
  smt: [iface('port1', '10.254.254.1/24')],
  pak: [iface('tunnel.3', '10.254.254.234/30'), iface('ethernet1/2', '172.20.5.1/24')],
  hris: [iface('tunnel.1', '10.254.254.246/30'), iface('port2', '192.168.100.254/24')],
  tug: [iface('tunnel.2', '10.254.254.210/30')],
  okf: [iface('port2', '192.168.100.254/24')],
  tfmmh: [iface('tunnel.9', '10.254.254.221/30')],
  tfmrn: [iface('tunnel.9', '10.254.254.222/30')],
  shutpeer: [iface('tunnel.99', '10.254.254.254/30')],
});

test('the four known-good /30 tunnel pairs all survive', () => {
  const pairs = undirectedPairs(buildAdjacencyGraph(FLEET_IFACES));
  for (const p of [
    'idc::tunnel.40 <-> pak::tunnel.3',
    'hris::tunnel.1 <-> idc::tunnel.44',
    'idc::tunnel.24 <-> tug::tunnel.2',
    'tfmmh::tunnel.9 <-> tfmrn::tunnel.9',
  ]) {
    assert.ok(pairs.has(p), `${p} must still be a link (removing a real edge truncates path queries)`);
  }
});

test('the shared template address links nothing, in any direction', () => {
  const graph = buildAdjacencyGraph(FLEET_IFACES);
  for (const key of ['idc::ha1-a', 'tum::ethernet1/7', 'smt::port1', 'hris::port2', 'okf::port2']) {
    assert.equal(graph.get(key), undefined, `${key} holds a duplicated address, which is not a link`);
  }
});

test('only the genuine pairs remain — no prefix-mismatch or same-host links', () => {
  assert.deepEqual(
    [...undirectedPairs(buildAdjacencyGraph(FLEET_IFACES))].sort(),
    [
      'hris::tunnel.1 <-> idc::tunnel.44',
      'idc::tunnel.24 <-> tug::tunnel.2',
      'idc::tunnel.40 <-> pak::tunnel.3',
      'tfmmh::tunnel.9 <-> tfmrn::tunnel.9',
    ]
  );
});

test('a disabled interface carries no traffic and forms no link', () => {
  // idc::shut0 (10.254.254.253/30) would otherwise pair with shutpeer.
  assert.equal(buildAdjacencyGraph(FLEET_IFACES).get('idc::shut0'), undefined);
  assert.equal(buildAdjacencyGraph(FLEET_IFACES).get('shutpeer::tunnel.99'), undefined);
});

// ───────────────────── the consequence: the simulator ─────────────────────

const RULES = {
  idc: [{ rule_name: 'allow-all', sequence_number: 1, enabled: true, action: 'allow', src_addresses: ['any'], dst_addresses: ['any'], services: ['any'] }],
  pak: [{ rule_name: 'allow-all', sequence_number: 1, enabled: true, action: 'allow', src_addresses: ['any'], dst_addresses: ['any'], services: ['any'] }],
  // The phantom neighbour denies everything — so if the simulator ever crosses
  // to it again, the assertion below fails loudly instead of silently.
  tum: [{ rule_name: 'deny-all', sequence_number: 1, enabled: true, action: 'deny', src_addresses: ['any'], dst_addresses: ['any'], services: ['any'] }],
};

const FLEET = {
  devices: [
    { id: 'idc', name: 'IDC FW' },
    { id: 'tum', name: 'TUM(TUTH1)' },
    { id: 'smt', name: 'SMT' },
    { id: 'pak', name: 'PAKFood' },
    { id: 'hris', name: 'HRIS' },
    { id: 'tug', name: 'TUG' },
    { id: 'okf', name: 'OKF(F2)' },
    { id: 'tfmmh', name: 'TFM-MH' },
    { id: 'tfmrn', name: 'TFM-RN' },
    { id: 'shutpeer', name: 'ShutPeer' },
  ],
  interfacesByDevice: FLEET_IFACES,
  rulesByDevice: new Map(Object.entries(RULES)),
  objectsByDevice: new Map(),
  routesByDevice: new Map([
    ['idc', [{ destination_cidr: '172.20.5.0/24', next_hop_ip: '10.254.254.234', interface_name: 'tunnel.40' }]],
    ['pak', [{ destination_cidr: '172.20.5.0/24', next_hop_ip: null, interface_name: 'ethernet1/2' }]],
  ]),
  natRulesByDevice: new Map(),
};

test("neighbors[0] for the /30 tunnel is the real peer, not the address-conflict device", () => {
  const neighbors = buildAdjacencyGraph(FLEET_IFACES).get('idc::tunnel.40');
  assert.deepEqual(neighbors, [{ deviceId: 'pak', interfaceName: 'tunnel.3' }]);
});

test('the second hop is the real peer device, not the phantom whose ruleset denies', () => {
  const r = simulateMultiHopPath(FLEET, { srcIp: '192.168.50.10', dstIp: '172.20.5.10', protocol: 'tcp', port: 443 });
  assert.deepEqual(r.hops.map((h) => h.deviceId), ['idc', 'pak']);
  assert.equal(r.finalVerdict, 'allow');
});

test('a device that no rule decides stays UNSPECIFIED, never deny', () => {
  // There is no default/implicit-policy data anywhere in this codebase, for
  // any vendor, so "no rule matched" must never be rendered as a block.
  const fleet = { ...FLEET, rulesByDevice: new Map() };
  const r = simulateMultiHopPath(fleet, { srcIp: '192.168.50.10', dstIp: '172.20.5.10' });
  assert.equal(r.finalVerdict, 'unspecified');
  assert.ok(r.hops.every((h) => h.verdict !== 'deny'));
});

test("a source only reachable via an 'N/A' interface finds no entry device", () => {
  const fleet = {
    ...FLEET,
    interfacesByDevice: ifaceMap({ x: [iface('dead0', 'N/A')] }),
    rulesByDevice: new Map(),
    routesByDevice: new Map(),
  };
  const r = simulateMultiHopPath(fleet, { srcIp: '192.168.50.10', dstIp: '172.20.5.10' });
  assert.equal(r.finalVerdict, 'unspecified');
  assert.deepEqual(r.hops, []);
  assert.match(r.note, /not on any known device/i);
});

// ───────────────────────────── the Fleet Map ─────────────────────────────

test('the map draws the real tunnel link, which a phantom edge used to displace', () => {
  const { edges } = buildFleetTopologyGraph(FLEET.devices, FLEET_IFACES);
  const subnet = edges.filter((e) => e.type === 'subnet');
  const idcPak = subnet.find(
    (e) =>
      [e.sourceDeviceId, e.targetDeviceId].sort().join('|') === 'idc|pak'
  );
  assert.ok(idcPak, 'IDC FW <-> PAKFood must still be drawn');
  assert.deepEqual([idcPak.sourceInterface, idcPak.targetInterface].sort(), ['tunnel.3', 'tunnel.40']);
  // And no edge to a device that only ever shared the duplicated address.
  assert.equal(subnet.some((e) => e.sourceDeviceId === 'tum' || e.targetDeviceId === 'tum'), false);
  assert.equal(subnet.length, 4);
});

test('VPN edges stay VISUAL-ONLY and never enter the path-simulation graph', () => {
  const tunnels = new Map([['idc', [{ name: 'to-pak', peer: '172.20.5.1', status: 'up' }]]]);
  const { edges } = buildFleetTopologyGraph(FLEET.devices, FLEET_IFACES, tunnels);
  assert.ok(edges.some((e) => e.type === 'vpn' && e.targetDeviceId === 'pak'));
  // The adjacency graph the simulator walks knows nothing about tunnels: a
  // peer gateway IP does not say what is routable THROUGH the tunnel, so the
  // pair set must be identical with and without them.
  assert.deepEqual(
    [...undirectedPairs(buildAdjacencyGraph(FLEET_IFACES))].sort(),
    [
      'hris::tunnel.1 <-> idc::tunnel.44',
      'idc::tunnel.24 <-> tug::tunnel.2',
      'idc::tunnel.40 <-> pak::tunnel.3',
      'tfmmh::tunnel.9 <-> tfmrn::tunnel.9',
    ]
  );
});
