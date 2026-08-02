// lib/engines/topology.js
//
// Phase 1 of a multi-hop, cross-device network path simulator (Tufin/
// AlgoSec-style): given a source IP and destination IP, walk across
// MULTIPLE firewalls in turn -- evaluating each device's own rules via
// lib/engines/objectResolver.js's already-shipped, UNCHANGED
// queryAccessPath(), and crossing to the next device only where their
// interfaces' subnets actually overlap (i.e. they share a broadcast
// domain/link). Everything in this codebase up to now (objectResolver.js,
// reachabilityMatrix.js) is deliberately single-device -- this module is the
// first thing that adds cross-device topology, and it does so ADDITIVELY:
// no per-device rule/object evaluation logic is duplicated or modified here,
// only routed BETWEEN devices.
//
// Pure functions, no DB access -- same "load everything up front, pass it
// in" convention as objectResolver.js/ruleAnalysis.js. The one exception
// noted in objectResolver.js's own header (an orchestrator that touches the
// DB) does NOT apply here either: simulateMultiHopPath() takes a fully
// pre-loaded `fleetData` bundle and returns a plain result object, so the
// route handler (app/api/topology/path-query/route.js) owns all querying.
// This keeps the whole engine testable with hand-built fixtures and no
// Postgres, the same way this codebase already verified objectResolver.js
// before ever touching a live device.
//
// Tri-state / "never guess" discipline carries over unchanged: an
// unresolved NAT translation is flagged (natUnresolved), a route that
// dead-ends is reported with a note rather than silently upgraded to a
// confident verdict, and a path that leaves SecVault's managed fleet says so
// explicitly instead of pretending the destination was reached.
//
// CommonJS only, matching every other lib/engines/*.js file.

'use strict';

const { parseCidrOrIp, rangeContains, rangeOverlaps, cidrToRange } = require('./cidrUtils');
const { resolveAddressField, matchesAddress, queryAccessPath } = require('./objectResolver');

// Defensive hop cap -- guards against a routing loop between misconfigured
// devices (e.g. two devices each routing the destination back toward the
// other) hanging the request forever. Same philosophy as objectResolver.js's
// MAX_GROUP_DEPTH guarding against a cyclic address/service group.
const MAX_HOPS = 25;

// ─────────────────────────────────────────
// Small local helpers
// ─────────────────────────────────────────

// Defensive Map coercion -- every fleetData.*ByDevice value is documented as
// a Map, but a missing/malformed one should degrade to "no data" rather than
// throw partway through a fleet-wide computation.
function toDeviceMap(map) {
  return map instanceof Map ? map : new Map();
}

// address/address_group lookup map for one device's network_objects rows --
// deliberately duplicated from objectResolver.js's own (unexported)
// buildObjectMap() rather than reaching into that module's internals. Same
// "small per-file helpers are duplicated, not imported" convention
// objectResolver.js's own header comment states it inherited from
// reachabilityMatrix.js.
function buildAddressObjectMap(objects) {
  const map = new Map();
  for (const obj of Array.isArray(objects) ? objects : []) {
    if ((obj.object_type === 'address' || obj.object_type === 'address_group') && obj.name) {
      map.set(obj.name, obj);
    }
  }
  return map;
}

// Same null-handling sort comparator objectResolver.js's queryAccessPath()
// already uses internally for firewall_rules -- copied here (not imported,
// it's not exported) so nat_rules sort identically: ascending
// sequence_number, nulls last.
function bySequenceNumberAscNullsLast(a, b) {
  const aSeq = a.sequence_number;
  const bSeq = b.sequence_number;
  if (aSeq === null || aSeq === undefined) return bSeq === null || bSeq === undefined ? 0 : 1;
  if (bSeq === null || bSeq === undefined) return -1;
  return aSeq - bSeq;
}

// Finds the first entry in a NAT translated-address field (JSONB array of
// strings, same shape as firewall_rules.src_addresses) that parses as a bare
// IPv4 /32 literal. Translated addresses are expected to be concrete literals
// (a NAT translates to ONE specific address per session), never an object
// name or a range -- so unlike resolveAddressField, this deliberately does
// NOT expand object names or CIDR ranges; a non-literal entry here is not
// "unresolved," it's simply not a usable translation target and is skipped.
function findFirstLiteralIp(fieldValue) {
  if (!Array.isArray(fieldValue)) return null;
  for (const entry of fieldValue) {
    const raw = typeof entry === 'string' ? entry.trim() : null;
    if (!raw) continue;
    const parsed = parseCidrOrIp(raw);
    if (parsed !== null && parsed.prefixLen === 32) return raw;
  }
  return null;
}

// nat_rules has no name/label column (see lib/schema.sql) -- synthesize a
// human-readable identifier from what the row actually has, for the API
// response's natRuleName field.
function describeNatRule(rule) {
  const type = rule.nat_type || 'nat';
  const seq = rule.sequence_number !== null && rule.sequence_number !== undefined ? `#${rule.sequence_number}` : '(no sequence)';
  return `${type} ${seq}`;
}

// ─────────────────────────────────────────
// 1. Adjacency graph
// ─────────────────────────────────────────

/**
 * Two interfaces on DIFFERENT devices whose address ranges overlap are
 * "adjacent" -- they sit on the same shared link/subnet, so traffic can
 * cross from one device to the other there. Built once per query over every
 * device's device_interfaces rows.
 *
 * Deliberately O(n^2) over the total interface count across the fleet, same
 * accepted-tradeoff precedent as ruleAnalysis.js's O(n^2) shadow analysis
 * (CLAUDE.md's Operational Notes) -- fleet interface counts are orders of
 * magnitude smaller than per-device rule counts, so this has never needed a
 * cap.
 *
 * @param {Map<string, object[]>} interfacesByDevice - deviceId -> that
 *   device's device_interfaces rows.
 * @returns {Map<string, {deviceId:string, interfaceName:string}[]>} keyed by
 *   `${deviceId}::${interfaceName}` -> the OTHER side(s) of that link. An
 *   array, not a single value -- more than two devices can theoretically
 *   share one broadcast subnet, so this never assumes exactly one neighbor.
 */
function buildAdjacencyGraph(interfacesByDevice) {
  const entries = [];
  for (const [deviceId, interfaces] of toDeviceMap(interfacesByDevice)) {
    for (const iface of Array.isArray(interfaces) ? interfaces : []) {
      if (iface.enabled === false) continue; // a disabled interface carries no live traffic
      const cidr = parseCidrOrIp(iface.ip_address);
      if (cidr === null) continue; // unparseable/missing -- skip, never throw (per spec)
      entries.push({
        deviceId,
        interfaceName: iface.interface_name,
        range: cidrToRange(cidr),
      });
    }
  }

  const graph = new Map();
  const link = (from, to) => {
    const key = `${from.deviceId}::${from.interfaceName}`;
    if (!graph.has(key)) graph.set(key, []);
    graph.get(key).push({ deviceId: to.deviceId, interfaceName: to.interfaceName });
  };

  for (let i = 0; i < entries.length; i++) {
    for (let j = i + 1; j < entries.length; j++) {
      const a = entries[i];
      const b = entries[j];
      if (a.deviceId === b.deviceId) continue; // only cross-device links count
      if (!rangeOverlaps(a.range, b.range)) continue;
      link(a, b);
      link(b, a);
    }
  }

  return graph;
}

// ─────────────────────────────────────────
// 2. Route resolution
// ─────────────────────────────────────────

/**
 * Longest-prefix-match route lookup for one device, same semantics as real
 * IP routing: among every device_routes row whose destination_cidr contains
 * destIpUint32, the MOST SPECIFIC (highest prefixLen) wins.
 *
 * @param {object[]} routes - device_routes rows for ONE device.
 * @param {number} destIpUint32 - already-parsed destination address.
 * @returns {{nextHopIp: string|null, interfaceName: string|null} | null}
 *   null = no route at all. A non-null result with nextHopIp === null means
 *   a directly-connected/local route -- callers MUST distinguish this from
 *   "has a next hop," never collapse it.
 */
function resolveRoute(routes, destIpUint32) {
  let best = null; // {prefixLen, nextHopIp, interfaceName}
  const point = { start: destIpUint32, end: destIpUint32 };

  for (const route of Array.isArray(routes) ? routes : []) {
    const cidr = parseCidrOrIp(route.destination_cidr);
    if (cidr === null) continue; // unparseable -- skip, never throw
    const range = cidrToRange(cidr);
    if (!rangeContains(range, point)) continue;
    if (best === null || cidr.prefixLen > best.prefixLen) {
      best = {
        prefixLen: cidr.prefixLen,
        nextHopIp: route.next_hop_ip === undefined ? null : route.next_hop_ip,
        interfaceName: route.interface_name,
      };
    }
  }

  if (best === null) return null;
  return { nextHopIp: best.nextHopIp, interfaceName: best.interfaceName };
}

// ─────────────────────────────────────────
// 3. NAT translation
// ─────────────────────────────────────────

/**
 * Walks one device's nat_rules (enabled, sequence_number order) looking for
 * the first rule whose original_src_addresses/original_dst_addresses could
 * plausibly apply to srcIp/dstIp -- reusing objectResolver's
 * resolveAddressField/matchesAddress UNCHANGED against nat_rules rows (same
 * shape as firewall_rules.src_addresses/dst_addresses, see lib/schema.sql).
 * Same forgiving-but-flagged philosophy as queryAccessPath: both 'match' and
 * 'unresolved' count as "this rule could apply," never silently skipped.
 *
 * @param {object[]} natRules - nat_rules rows for ONE device.
 * @param {Map<string,object>} addressObjectsByName - from
 *   buildAddressObjectMap(), same device.
 * @param {string} srcIp - bare IPv4 literal.
 * @param {string} dstIp - bare IPv4 literal.
 * @returns {{srcIp:string, dstIp:string, natApplied:boolean,
 *   natRuleName:string|null, natUnresolved:boolean}}
 */
function applyNat(natRules, addressObjectsByName, srcIp, dstIp) {
  const srcParsed = parseCidrOrIp(srcIp);
  const dstParsed = parseCidrOrIp(dstIp);
  if (srcParsed === null || dstParsed === null) {
    // Should not happen -- callers always pass validated /32 literals -- but
    // NAT evaluation is meaningless without them, so leave unchanged rather
    // than guess.
    return { srcIp, dstIp, natApplied: false, natRuleName: null, natUnresolved: false };
  }

  const sorted = (Array.isArray(natRules) ? natRules : [])
    .filter((r) => r.enabled !== false)
    .slice()
    .sort(bySequenceNumberAscNullsLast);

  for (const rule of sorted) {
    const srcResolved = resolveAddressField(rule.original_src_addresses, addressObjectsByName);
    const dstResolved = resolveAddressField(rule.original_dst_addresses, addressObjectsByName);
    const srcResult = matchesAddress(srcResolved, srcParsed.network);
    const dstResult = matchesAddress(dstResolved, dstParsed.network);

    if (srcResult === 'no-match' || dstResult === 'no-match') continue; // definitively excluded

    // This rule could apply -- take it (first non-excluded rule wins, same
    // discipline queryAccessPath already uses for firewall_rules).
    let newSrcIp = srcIp;
    let newDstIp = dstIp;
    let unresolved = false;

    if (rule.nat_type === 'source') {
      const lit = findFirstLiteralIp(rule.translated_src_addresses);
      if (lit !== null) newSrcIp = lit;
      else unresolved = true;
    } else if (rule.nat_type === 'destination') {
      const lit = findFirstLiteralIp(rule.translated_dst_addresses);
      if (lit !== null) newDstIp = lit;
      else unresolved = true;
    } else if (rule.nat_type === 'static') {
      const srcLit = findFirstLiteralIp(rule.translated_src_addresses);
      const dstLit = findFirstLiteralIp(rule.translated_dst_addresses);
      if (srcLit !== null) newSrcIp = srcLit;
      else unresolved = true;
      if (dstLit !== null) newDstIp = dstLit;
      else unresolved = true;
    } else {
      // Unrecognized nat_type -- not one of the three documented values, so
      // this rule can't be interpreted; don't guess a translation, try the
      // next rule instead of stopping the whole walk.
      continue;
    }

    return {
      srcIp: newSrcIp,
      dstIp: newDstIp,
      natApplied: true,
      natRuleName: describeNatRule(rule),
      natUnresolved: unresolved,
    };
  }

  return { srcIp, dstIp, natApplied: false, natRuleName: null, natUnresolved: false };
}

// ─────────────────────────────────────────
// 4. Multi-hop orchestrator
// ─────────────────────────────────────────

/**
 * Simulates srcIp -> dstIp traffic across the whole fleet: find the entry
 * device (whose interface subnet contains srcIp), evaluate its rules via
 * objectResolver.queryAccessPath() UNCHANGED, apply any NAT translation,
 * resolve the route for the (possibly-translated) destination, and cross to
 * the next device only where an adjacency link exists -- repeating until a
 * deny, a dead end, the fleet boundary, or MAX_HOPS is reached.
 *
 * @param {{
 *   devices: {id:string,name:string}[],
 *   rulesByDevice: Map<string,object[]>,
 *   objectsByDevice: Map<string,object[]>,
 *   interfacesByDevice: Map<string,object[]>,
 *   routesByDevice: Map<string,object[]>,
 *   natRulesByDevice: Map<string,object[]>,
 * }} fleetData - fully pre-loaded; this function never touches the DB.
 * @param {{srcIp:string, dstIp:string, protocol?:string, port?:number}} query
 * @returns {{
 *   finalVerdict: string,
 *   hops: {deviceId:string, deviceName:string|null, verdict:string,
 *     matchedRule:object|null, hasCaveat:boolean, natApplied:boolean,
 *     natRuleName:string|null}[],
 *   note?: string,
 * }}
 */
function simulateMultiHopPath(fleetData, query) {
  const srcParsed = parseCidrOrIp(query && query.srcIp);
  const dstParsed = parseCidrOrIp(query && query.dstIp);
  if (srcParsed === null || srcParsed.prefixLen !== 32) {
    throw new Error('srcIp must be a single valid IPv4 address');
  }
  if (dstParsed === null || dstParsed.prefixLen !== 32) {
    throw new Error('dstIp must be a single valid IPv4 address');
  }

  const devices = Array.isArray(fleetData && fleetData.devices) ? fleetData.devices : [];
  const deviceNameById = new Map(devices.map((d) => [d.id, d.name]));

  const interfacesByDevice = toDeviceMap(fleetData && fleetData.interfacesByDevice);
  const rulesByDevice = toDeviceMap(fleetData && fleetData.rulesByDevice);
  const objectsByDevice = toDeviceMap(fleetData && fleetData.objectsByDevice);
  const routesByDevice = toDeviceMap(fleetData && fleetData.routesByDevice);
  const natRulesByDevice = toDeviceMap(fleetData && fleetData.natRulesByDevice);

  const graph = buildAdjacencyGraph(interfacesByDevice);

  // Find the entry device -- never guess a starting device.
  let entryDeviceId = null;
  for (const [deviceId, interfaces] of interfacesByDevice) {
    for (const iface of Array.isArray(interfaces) ? interfaces : []) {
      if (iface.enabled === false) continue;
      const cidr = parseCidrOrIp(iface.ip_address);
      if (cidr === null) continue;
      const range = cidrToRange(cidr);
      if (rangeContains(range, { start: srcParsed.network, end: srcParsed.network })) {
        entryDeviceId = deviceId;
        break;
      }
    }
    if (entryDeviceId !== null) break;
  }

  if (entryDeviceId === null) {
    return {
      finalVerdict: 'unspecified',
      hops: [],
      note: "Source IP is not on any known device's interface subnet.",
    };
  }

  let currentDeviceId = entryDeviceId;
  let currentSrcIp = query.srcIp;
  let currentDstIp = query.dstIp;
  const hops = [];
  let finalVerdict = 'unspecified';

  for (let i = 0; i < MAX_HOPS; i++) {
    const rules = rulesByDevice.get(currentDeviceId) || [];
    const objects = objectsByDevice.get(currentDeviceId) || [];

    const result = queryAccessPath(rules, objects, {
      srcIp: currentSrcIp,
      dstIp: currentDstIp,
      protocol: query.protocol,
      port: query.port,
    });

    const hop = {
      deviceId: currentDeviceId,
      deviceName: deviceNameById.get(currentDeviceId) || null,
      verdict: result.verdict,
      matchedRule: result.matchedRule,
      hasCaveat: result.hasCaveat,
      natApplied: false,
      natRuleName: null,
    };
    hops.push(hop);
    finalVerdict = result.verdict;

    if (result.verdict === 'deny') {
      return { finalVerdict, hops };
    }

    // Apply NAT for the NEXT hop's evaluation.
    const natRules = natRulesByDevice.get(currentDeviceId) || [];
    const addressObjectsByName = buildAddressObjectMap(objects);
    const natResult = applyNat(natRules, addressObjectsByName, currentSrcIp, currentDstIp);
    if (natResult.natApplied) {
      hop.natApplied = true;
      hop.natRuleName = natResult.natRuleName;
    }
    currentSrcIp = natResult.srcIp;
    currentDstIp = natResult.dstIp;

    const currentDstParsed = parseCidrOrIp(currentDstIp);
    if (currentDstParsed === null) {
      // Should not happen -- applyNat only ever produces a validated /32
      // literal or leaves the previous (already-validated) value unchanged.
      // Defensive stop rather than crash.
      return {
        finalVerdict,
        hops,
        note: 'Destination address became unparseable after NAT translation.',
      };
    }

    const routes = routesByDevice.get(currentDeviceId) || [];
    const route = resolveRoute(routes, currentDstParsed.network);

    if (route === null) {
      // This device is the last one we know anything about -- keep the
      // verdict as already reported, never silently upgrade to 'allow'.
      return {
        finalVerdict,
        hops,
        note: 'No route to the destination is known beyond this device.',
      };
    }

    if (route.nextHopIp === null) {
      // Directly connected -- destination is on this device's own local
      // network, so this device is the last hop, successfully.
      return { finalVerdict, hops };
    }

    const egressKey = `${currentDeviceId}::${route.interfaceName}`;
    const neighbors = graph.get(egressKey);
    if (!neighbors || neighbors.length === 0) {
      // Egress interface's subnet isn't shared with any other known device
      // -- traffic leaves SecVault's managed fleet from here.
      return {
        finalVerdict,
        hops,
        note: "Path continues beyond SecVault's managed fleet from this point.",
      };
    }

    currentDeviceId = neighbors[0].deviceId;
  }

  return {
    finalVerdict,
    hops,
    note: `Hop limit (${MAX_HOPS}) reached without resolving the path -- likely a routing loop between devices.`,
  };
}

module.exports = {
  buildAdjacencyGraph,
  resolveRoute,
  applyNat,
  simulateMultiHopPath,
};
