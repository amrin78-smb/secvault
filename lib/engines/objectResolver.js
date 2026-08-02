// lib/engines/objectResolver.js
//
// Resolves firewall_rules address/service field entries -- which are almost
// always OBJECT NAMES (e.g. "LAN-subnet", "HTTPS-svc"), sometimes a literal
// IP/CIDR typed directly into a rule -- down to real IP ranges and
// protocol/port values, by looking them up in a device's own
// network_objects rows and recursively expanding address_group/
// service_group membership. Nothing else in this codebase does this today:
// lib/engines/ruleAnalysis.js's fieldCovers()/fieldEquals() only compare
// address-list VALUES as strings/sets, and lib/engines/cidrUtils.js only
// upgrades a literal IP/CIDR typed directly into a rule (Palo Alto only) --
// neither ever follows an object NAME to its network_objects row.
//
// Built for lib/engines/objectResolver.js's one consumer,
// queryAccessPath() below (used by app/api/devices/[id]/access-path/route.js)
// -- a per-device, config-only "what does this ruleset do with this
// specific IP/port pair" query. Deliberately single-device, same scope
// limit lib/engines/reachabilityMatrix.js's header comment already states
// for the existing zone-level reachability tool -- this module resolves
// OBJECTS more precisely than that tool does, but does not add any
// cross-device topology SecVault has no data for.
//
// Pure functions, no DB access -- same convention as reachabilityMatrix.js/
// ruleAnalysis.js. Callers load a device's network_objects rows once and
// pass them in (matches this codebase's existing "load all objects for the
// device up front" convention, see CLAUDE.md's Operational Notes on
// address/service object resolution).
//
// Tri-state discipline throughout: every resolved field can produce
// 'match' | 'no-match' | 'unresolved' -- an object this module could not
// resolve (an FQDN, a name with no matching network_objects row, a value
// shape it doesn't recognize) NEVER silently counts as a non-match. Same
// "unknown must never silently become no" rule CLAUDE.md states for the
// CVE/compliance applicability engines.
//
// CommonJS only, matching every other lib/engines/*.js file.

'use strict';

const { parseCidrOrIp, parseIpRange, rangeContains, cidrToRange } = require('./cidrUtils');

// ─────────────────────────────────────────
// Small pure helpers (deliberately duplicated from reachabilityMatrix.js /
// ruleAnalysis.js, not imported -- this codebase's own established
// convention for small per-file helpers, see reachabilityMatrix.js's own
// header comment on this exact point).
// ─────────────────────────────────────────

const ANY_ALIASES = new Set(['any', 'all', 'any4', 'any6']);
const ALLOW_ACTIONS = new Set(['allow', 'permit', 'accept']);
const DENY_ACTIONS = new Set(['deny', 'drop', 'reject', 'block']);

function normItem(item) {
  return String(item).trim().toLowerCase();
}

function normList(list) {
  if (!Array.isArray(list)) return [];
  return list.map(normItem).filter((s) => s.length > 0);
}

function isAnyField(list) {
  if (list === null || list === undefined) return true;
  if (!Array.isArray(list)) return false;
  const norm = normList(list);
  if (norm.length === 0) return true;
  return norm.some((s) => ANY_ALIASES.has(s));
}

function actionCategory(rule) {
  const a = rule && rule.action ? String(rule.action).trim().toLowerCase() : '';
  if (ALLOW_ACTIONS.has(a)) return 'allow';
  if (DENY_ACTIONS.has(a)) return 'deny';
  return a || 'unspecified';
}

// A raw rule row carries collection-internal fields (raw_rule, collected_at,
// etc) we never want to hand back to an API response -- this trims to what
// the UI actually renders (deciding rule identity + the fields that were
// actually evaluated).
function summarizeRule(rule) {
  return {
    id: rule.id,
    ruleName: rule.rule_name,
    ruleIdVendor: rule.rule_id_vendor,
    sequenceNumber: rule.sequence_number,
    action: rule.action,
    srcAddresses: rule.src_addresses,
    dstAddresses: rule.dst_addresses,
    services: rule.services,
    logEnabled: rule.log_enabled,
  };
}

// ─────────────────────────────────────────
// Object lookup maps
// ─────────────────────────────────────────

// Builds a name -> row Map restricted to the given object_type(s) --
// address and service objects are resolved through SEPARATE maps even
// though both live in the same network_objects table, so a same-named
// address object and service object (unlikely, but not impossible across
// independently-configured firewalls) can never cross-resolve into the
// wrong field type.
function buildObjectMap(objects, types) {
  const map = new Map();
  const typeSet = new Set(types);
  for (const obj of Array.isArray(objects) ? objects : []) {
    if (typeSet.has(obj.object_type) && obj.name) {
      map.set(obj.name, obj);
    }
  }
  return map;
}

// ─────────────────────────────────────────
// Address resolution
// ─────────────────────────────────────────

const MAX_GROUP_DEPTH = 50; // defensive cap beyond the cycle guard below --
// guards against a pathologically long (non-cyclic) group chain, not just a
// true cycle.

// True if str contains at least one letter -- used only to distinguish "an
// FQDN we can't resolve" from "a value shape we don't recognize at all"
// when neither CIDR nor range parsing succeeds. This is a labeling
// distinction for the UI (two different caveat messages), not a
// correctness-affecting one -- both outcomes are 'unresolved' either way.
function looksLikeFqdn(str) {
  return typeof str === 'string' && /[a-zA-Z]/.test(str);
}

function resolveAddressEntry(entry, objectsByName, visited, depth, acc) {
  const raw = typeof entry === 'string' ? entry.trim() : String(entry);
  if (!raw) return;

  // Literal IP/CIDR typed directly into the rule (the one case
  // cidrUtils.js already handled before this module existed).
  const cidr = parseCidrOrIp(raw);
  if (cidr !== null) {
    acc.ranges.push(cidrToRange(cidr));
    return;
  }
  // Literal "start-end" range typed directly into the rule.
  const range = parseIpRange(raw);
  if (range !== null) {
    acc.ranges.push(range);
    return;
  }

  // Not a literal -- must be an object name.
  const obj = objectsByName.get(raw);
  if (!obj) {
    acc.unresolvedNames.push(raw);
    return;
  }

  if (obj.object_type === 'address_group') {
    if (visited.has(obj.name) || depth >= MAX_GROUP_DEPTH) {
      // Cycle (or pathological depth) -- stop expanding this branch rather
      // than recursing forever. Not counted as unresolved: the group ITSELF
      // resolved fine, we just refuse to walk back into where we've been.
      return;
    }
    const nextVisited = new Set(visited);
    nextVisited.add(obj.name);
    const members = Array.isArray(obj.members) ? obj.members : [];
    for (const member of members) {
      resolveAddressEntry(member, objectsByName, nextVisited, depth + 1, acc);
    }
    return;
  }

  if (obj.object_type === 'address') {
    const value = obj.value;
    const valueCidr = typeof value === 'string' ? parseCidrOrIp(value) : null;
    if (valueCidr !== null) {
      acc.ranges.push(cidrToRange(valueCidr));
      return;
    }
    const valueRange = typeof value === 'string' ? parseIpRange(value) : null;
    if (valueRange !== null) {
      acc.ranges.push(valueRange);
      return;
    }
    if (looksLikeFqdn(value)) {
      acc.unresolvedFqdns.push(value);
    } else {
      // A value shape this module doesn't recognize (e.g. a vendor's raw
      // "ip mask" fallback string) -- unresolved, not silently ignored.
      acc.unresolvedNames.push(`${raw} (unparseable value: ${value})`);
    }
    return;
  }

  // A name that resolved to an object of an unexpected type (e.g. a
  // service object referenced from an address field -- a real data
  // inconsistency, not something to guess through).
  acc.unresolvedNames.push(raw);
}

/**
 * @param {string[]} fieldValues - rule.src_addresses or rule.dst_addresses.
 * @param {Map<string, object>} addressObjectsByName - from buildObjectMap()
 *   restricted to ['address', 'address_group'].
 * @returns {{
 *   ranges: {start:number,end:number}[],
 *   unresolvedFqdns: string[],
 *   unresolvedNames: string[],
 *   isAny: boolean,
 * }}
 */
function resolveAddressField(fieldValues, addressObjectsByName) {
  if (isAnyField(fieldValues)) {
    return { ranges: [], unresolvedFqdns: [], unresolvedNames: [], isAny: true };
  }
  const acc = { ranges: [], unresolvedFqdns: [], unresolvedNames: [] };
  for (const entry of fieldValues) {
    resolveAddressEntry(entry, addressObjectsByName, new Set(), 0, acc);
  }
  return { ...acc, isAny: false };
}

/**
 * @param {{ranges,unresolvedFqdns,unresolvedNames,isAny}} resolved
 * @param {number} queryIpUint32 - a single IPv4 address, already parsed
 *   (parseCidrOrIp(...).network on a /32).
 * @returns {'match' | 'no-match' | 'unresolved'}
 */
function matchesAddress(resolved, queryIpUint32) {
  if (resolved.isAny) return 'match';
  const point = { start: queryIpUint32, end: queryIpUint32 };
  for (const range of resolved.ranges) {
    if (rangeContains(range, point)) return 'match';
  }
  if (resolved.unresolvedFqdns.length > 0 || resolved.unresolvedNames.length > 0) {
    return 'unresolved';
  }
  return 'no-match';
}

// ─────────────────────────────────────────
// Service resolution
// ─────────────────────────────────────────

// Parses one service VALUE string (from a leaf service object's `value`,
// or a literal typed directly into a rule) into protocol/port entries.
// Handles every shape confirmed live across the six vendor parsers:
//   "tcp/443"                 -> [{proto:'tcp', portStart:443, portEnd:443}]
//   "tcp/8000-9000"           -> [{proto:'tcp', portStart:8000, portEnd:9000}]
//   "tcp/443,udp/123"         -> two entries (Fortinet's combined form)
//   "icmp" / "all"            -> [{proto:'icmp', portStart:null, portEnd:null}]
// Returns null (never a partial result) if ANY comma-segment fails to
// parse -- a value that's half-understood is treated as fully unresolved,
// same "don't guess" discipline as the rest of this module.
function parseServiceValue(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  const segments = value.split(',').map((s) => s.trim()).filter(Boolean);
  if (segments.length === 0) return null;

  const entries = [];
  for (const segment of segments) {
    const slashIdx = segment.indexOf('/');
    if (slashIdx === -1) {
      // Protocol-only, no port (e.g. "icmp", "all").
      const proto = segment.toLowerCase();
      if (!/^[a-z0-9]+$/.test(proto)) return null;
      entries.push({ proto, portStart: null, portEnd: null });
      continue;
    }
    const proto = segment.slice(0, slashIdx).trim().toLowerCase();
    const portPart = segment.slice(slashIdx + 1).trim();
    if (!/^[a-z0-9]+$/.test(proto) || !portPart) return null;

    let portStart;
    let portEnd;
    const dashIdx = portPart.indexOf('-');
    if (dashIdx === -1) {
      if (!/^\d{1,5}$/.test(portPart)) return null;
      portStart = portEnd = parseInt(portPart, 10);
    } else {
      const startStr = portPart.slice(0, dashIdx);
      const endStr = portPart.slice(dashIdx + 1);
      if (!/^\d{1,5}$/.test(startStr) || !/^\d{1,5}$/.test(endStr)) return null;
      portStart = parseInt(startStr, 10);
      portEnd = parseInt(endStr, 10);
    }
    if (portStart < 0 || portEnd > 65535 || portStart > portEnd) return null;
    entries.push({ proto, portStart, portEnd });
  }
  return entries;
}

function resolveServiceEntry(entry, objectsByName, visited, depth, acc) {
  const raw = typeof entry === 'string' ? entry.trim() : String(entry);
  if (!raw) return;

  // Object-name lookup FIRST, unlike resolveAddressEntry's literal-first
  // order -- an IP-shaped address literal ("10.0.0.5") never collides with
  // a real object name in practice (confirmed precedent: Palo Alto rules
  // can embed a literal IP directly, and address object names don't look
  // like IPs). Services are different: a bare object name like "HTTPS" is
  // indistinguishable in shape from a bare protocol keyword like "icmp" --
  // parsing the raw entry as a literal FIRST would silently misread the
  // object name "HTTPS" as protocol "https" with no port, the wrong
  // answer. Only fall back to literal parsing when no object matches.
  const obj = objectsByName.get(raw);
  if (!obj) {
    const literalParsed = parseServiceValue(raw);
    if (literalParsed !== null) {
      acc.protocols.push(...literalParsed);
      return;
    }
    acc.unresolvedNames.push(raw);
    return;
  }

  if (obj.object_type === 'service_group') {
    if (visited.has(obj.name) || depth >= MAX_GROUP_DEPTH) {
      return;
    }
    const nextVisited = new Set(visited);
    nextVisited.add(obj.name);
    const members = Array.isArray(obj.members) ? obj.members : [];
    for (const member of members) {
      resolveServiceEntry(member, objectsByName, nextVisited, depth + 1, acc);
    }
    return;
  }

  if (obj.object_type === 'service') {
    const parsed = parseServiceValue(obj.value);
    if (parsed !== null) {
      acc.protocols.push(...parsed);
    } else {
      acc.unresolvedNames.push(`${raw} (unparseable value: ${obj.value})`);
    }
    return;
  }

  acc.unresolvedNames.push(raw);
}

/**
 * @param {string[]} fieldValues - rule.services.
 * @param {Map<string, object>} serviceObjectsByName - from buildObjectMap()
 *   restricted to ['service', 'service_group'].
 * @returns {{
 *   protocols: {proto:string, portStart:number|null, portEnd:number|null}[],
 *   unresolvedNames: string[],
 *   isAny: boolean,
 * }}
 */
function resolveServiceField(fieldValues, serviceObjectsByName) {
  if (isAnyField(fieldValues)) {
    return { protocols: [], unresolvedNames: [], isAny: true };
  }
  const acc = { protocols: [], unresolvedNames: [] };
  for (const entry of fieldValues) {
    resolveServiceEntry(entry, serviceObjectsByName, new Set(), 0, acc);
  }
  return { ...acc, isAny: false };
}

/**
 * @param {{protocols,unresolvedNames,isAny}} resolved
 * @param {string|undefined} queryProto - lowercase 'tcp'/'udp'/'icmp'/etc,
 *   or undefined if the query doesn't care about protocol/port at all.
 * @param {number|undefined} queryPort
 * @returns {'match' | 'no-match' | 'unresolved'}
 */
function matchesService(resolved, queryProto, queryPort) {
  // Query didn't specify protocol/port at all -- an address-only query
  // ("can this host reach this host, at all") never lets the service field
  // exclude a rule.
  if (queryProto === undefined && queryPort === undefined) return 'match';
  if (resolved.isAny) return 'match';

  const normProto = queryProto ? String(queryProto).trim().toLowerCase() : undefined;
  for (const p of resolved.protocols) {
    const protoMatches =
      normProto === undefined || p.proto === 'ip' || p.proto === 'any' || p.proto === 'all' || p.proto === normProto;
    if (!protoMatches) continue;
    if (p.portStart === null) {
      // Protocol-only entry (e.g. "icmp") -- no port to compare against.
      return 'match';
    }
    if (queryPort === undefined || (queryPort >= p.portStart && queryPort <= p.portEnd)) {
      return 'match';
    }
  }
  if (resolved.unresolvedNames.length > 0) return 'unresolved';
  return 'no-match';
}

// ─────────────────────────────────────────
// Main query
// ─────────────────────────────────────────

/**
 * Walks a device's own enabled rules, in sequence_number order (same
 * ordering convention as reachabilityMatrix.js's computeZoneReachability),
 * resolving each rule's address/service fields and testing them against
 * the query. The FIRST rule that is not definitively excluded (i.e. none
 * of src/dst/service resolved to a clean 'no-match') decides the verdict
 * -- including a rule whose match involved an 'unresolved' object, which
 * still "wins" but is flagged with hasCaveat:true, since skipping past an
 * uncertain rule to find a cleaner one further down would silently hide
 * the fact that an earlier rule might already have decided this traffic.
 *
 * If no rule ever stops being excluded, the verdict is 'unspecified' --
 * NEVER 'deny' -- because no default/implicit-policy data exists anywhere
 * in this codebase (see this module's header comment / the approved plan's
 * research notes).
 *
 * @param {object[]} rules - firewall_rules rows for one device.
 * @param {object[]} objects - network_objects rows for the same device.
 * @param {{srcIp:string, dstIp:string, protocol?:string, port?:number}} query
 * @returns {{
 *   verdict: 'allow'|'deny'|'unspecified'|string,
 *   matchedRule: object|null,
 *   hasCaveat: boolean,
 *   walk: {rule:object, srcResult:string, dstResult:string, svcResult:string, decided:boolean}[],
 * }}
 */
function queryAccessPath(rules, objects, query) {
  const srcParsed = parseCidrOrIp(query && query.srcIp);
  const dstParsed = parseCidrOrIp(query && query.dstIp);
  if (srcParsed === null || srcParsed.prefixLen !== 32) {
    throw new Error('srcIp must be a single valid IPv4 address');
  }
  if (dstParsed === null || dstParsed.prefixLen !== 32) {
    throw new Error('dstIp must be a single valid IPv4 address');
  }
  const queryPort =
    query && query.port !== undefined && query.port !== null && query.port !== '' ? Number(query.port) : undefined;
  if (queryPort !== undefined && (!Number.isInteger(queryPort) || queryPort < 0 || queryPort > 65535)) {
    throw new Error('port must be an integer 0-65535');
  }
  const queryProto = query && query.protocol ? String(query.protocol).trim().toLowerCase() : undefined;

  const addressObjectsByName = buildObjectMap(objects, ['address', 'address_group']);
  const serviceObjectsByName = buildObjectMap(objects, ['service', 'service_group']);

  const enabledRules = (Array.isArray(rules) ? rules : [])
    .filter((r) => r.enabled !== false)
    .slice()
    .sort((a, b) => {
      const aSeq = a.sequence_number;
      const bSeq = b.sequence_number;
      if (aSeq === null || aSeq === undefined) return bSeq === null || bSeq === undefined ? 0 : 1;
      if (bSeq === null || bSeq === undefined) return -1;
      return aSeq - bSeq;
    });

  const walk = [];
  let matchedRule = null;
  let verdict = 'unspecified';
  let hasCaveat = false;

  for (const rule of enabledRules) {
    const srcResolved = resolveAddressField(rule.src_addresses, addressObjectsByName);
    const dstResolved = resolveAddressField(rule.dst_addresses, addressObjectsByName);
    const svcResolved = resolveServiceField(rule.services, serviceObjectsByName);

    const srcResult = matchesAddress(srcResolved, srcParsed.network);
    const dstResult = matchesAddress(dstResolved, dstParsed.network);
    const svcResult = matchesService(svcResolved, queryProto, queryPort);

    const excluded = srcResult === 'no-match' || dstResult === 'no-match' || svcResult === 'no-match';
    const anyRelevant = srcResult !== 'no-match' || dstResult !== 'no-match' || svcResult !== 'no-match';

    if (excluded) {
      if (anyRelevant) {
        walk.push({ rule: summarizeRule(rule), srcResult, dstResult, svcResult, decided: false });
      }
      continue;
    }

    matchedRule = rule;
    verdict = actionCategory(rule);
    hasCaveat = srcResult === 'unresolved' || dstResult === 'unresolved' || svcResult === 'unresolved';
    walk.push({ rule: summarizeRule(rule), srcResult, dstResult, svcResult, decided: true });
    break;
  }

  return {
    verdict: matchedRule ? verdict : 'unspecified',
    matchedRule: matchedRule ? summarizeRule(matchedRule) : null,
    hasCaveat,
    walk,
  };
}

module.exports = {
  resolveAddressField,
  resolveServiceField,
  matchesAddress,
  matchesService,
  queryAccessPath,
};
