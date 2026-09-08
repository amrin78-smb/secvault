// lib/engines/exposure.js
//
// Internet Exposure & Attack Surface.
//
// ── WHAT QUESTION THIS ANSWERS ────────────────────────────────────────────
// Not "is this rule risky" (ruleAnalysis.js already scores hygiene) but:
// WHAT IS REACHABLE FROM THE INTERNET, THROUGH WHICH RULE, TO WHICH INTERNAL
// HOST — and was it actually reached?
//
// The path this reconstructs is the firewall-scoped part of the roadmap's
// attack graph:
//
//     Internet -> public IP:port -> [DNAT] -> internal host:port
//                       ^ permitted by rule N
//
// ⛔ SCOPE HONESTY. The roadmap's full graph continues into applications,
// identities and databases. SecVault has no asset, identity or data-store
// inventory, so this file stops at the internal host address and says so.
// Extending the drawn path past the last thing actually collected would be
// inventing the most security-critical half of the answer.
//
// ── THE THREE-STATE OBSERVATION, WHICH IS THE POINT ───────────────────────
// Every path carries `observation`:
//
//   'observed'     syslog shows ALLOWED traffic from a PUBLIC source arriving
//                  at this public address on this port. The exposure is real
//                  and in use.
//   'not_observed' we have syslog coverage for this device across the window
//                  and saw none. A real measurement.
//   'unmeasured'   no syslog coverage, or no collected interfaces. NOT SAFE —
//                  we simply were not listening.
//
// ⛔ `not_observed` must never be rendered as "closed" and `unmeasured` must
// never be rendered as either. This is the same discipline as `hit_count` and
// `log_hit`: our inability to measure is not a fact about the device.
//
// ⛔ An UNOBSERVED path is still an exposure. Nothing here may filter a path
// out because no traffic was seen — an unused open door is still open, and
// treating quiet as closed is precisely how a forgotten vendor rule survives
// an audit.

'use strict';

const {
  buildObjectMap,
  resolveAddressField,
  resolveServiceField,
} = require('./objectResolver');

// ─────────────────────────────────────────
// Address helpers (IPv4 only — see note)
// ─────────────────────────────────────────
//
// ⛔ IPv4 only, deliberately and explicitly. Every vendor parser in this
// codebase emits IPv4 and no live device in the fleet has been verified to
// emit IPv6 rule/NAT data. A v6 literal is reported as UNPARSEABLE rather
// than silently skipped, so a future v6 estate shows up as a coverage gap
// instead of as a clean bill of health.
const DOTTED_QUAD = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function ipToUint32(ip) {
  const m = DOTTED_QUAD.exec(String(ip).trim());
  if (!m) return null;
  let out = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (!Number.isInteger(o) || o < 0 || o > 255) return null;
    out = out * 256 + o;
  }
  return out >>> 0;
}

// RFC1918 + loopback + link-local + CGNAT + this-host + multicast/reserved.
// "Public" here means "routable from the internet", the conservative reading.
const PRIVATE_RANGES = [
  ['10.0.0.0', 8],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['100.64.0.0', 10],
  ['0.0.0.0', 8],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

function isPublicIp(ip) {
  const u = ipToUint32(ip);
  if (u === null) return false;
  for (const [base, bits] of PRIVATE_RANGES) {
    const b = ipToUint32(base);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if ((u & mask) >>> 0 === (b & mask) >>> 0) return false;
  }
  return true;
}

// `device_interfaces.ip_address` is TEXT carrying a prefix ("27.254.29.130/24")
// and, on some live rows, the literal sentinel "N/A".
//
// ⛔ "N/A" is a fabricated value where NULL belongs — the pattern CLAUDE.md
// bans. It is filtered here rather than "handled", and anything that is not a
// clean dotted quad is dropped rather than guessed at.
function publicInterfaceIps(interfaces) {
  const out = [];
  for (const i of Array.isArray(interfaces) ? interfaces : []) {
    if (!i || typeof i.ip_address !== 'string') continue;
    const host = i.ip_address.split('/')[0].trim();
    if (!DOTTED_QUAD.test(host)) continue;
    if (!isPublicIp(host)) continue;
    out.push({ ip: host, interfaceName: i.interface_name || null, zone: i.zone || null });
  }
  // Stable, de-duplicated by IP.
  const seen = new Set();
  return out.filter((x) => (seen.has(x.ip) ? false : (seen.add(x.ip), true)));
}

// ─────────────────────────────────────────
// Rule helpers
// ─────────────────────────────────────────

const ALLOW_ACTIONS = new Set(['allow', 'accept', 'permit']);

/**
 * The names by which this device's rules refer to its INTERNET-FACING side.
 *
 * ⛔ WHY THIS EXISTS — it is the difference between a report and a fiction.
 * Without a direction test, `src_addresses:['any']` on an internal rule reads
 * as "reachable from the entire internet" and `dst_addresses:['any']` on an
 * outbound rule matches every public face. Measured on the live fleet, that
 * made 257 of 403 reported paths (64%) false positives, ALL of them at the
 * maximum score, so they outranked the genuine ones: TSR-TL's entire reported
 * exposure was five internal-to-internal rules (`internal5 -> internal3`),
 * while TUG's one real internet-facing camera forward ranked below them.
 *
 * Both vendor shapes are covered, because both appear in `src_zones`:
 *   Palo Alto  the interface's ZONE  (WAN1, Untrust)
 *   Fortinet   the interface NAME    (wan2) — FortiOS policies name interfaces
 *
 * Returns an empty set when the device has no collected public interface, in
 * which case direction is UNVERIFIABLE and the caller must say so rather than
 * assume either answer.
 */
function externalZoneIds(interfaces) {
  const ids = new Set();
  for (const i of Array.isArray(interfaces) ? interfaces : []) {
    if (!i || typeof i.ip_address !== 'string') continue;
    const host = i.ip_address.split('/')[0].trim();
    if (!DOTTED_QUAD.test(host) || !isPublicIp(host)) continue;
    if (i.zone) ids.add(String(i.zone).trim().toLowerCase());
    if (i.interface_name) ids.add(String(i.interface_name).trim().toLowerCase());
  }
  return ids;
}

const ANY_ZONE = new Set(['any', 'all', '']);

/**
 * Can traffic matching this rule have ARRIVED from the internet?
 *
 * @returns {'inbound'|'internal'|'unverified'}
 *   inbound     the rule's source side includes an internet-facing zone
 *   internal    it definitively does not — not an internet exposure
 *   unverified  no usable zone data; we cannot tell, and must not pretend to
 */
function ruleDirection(rule, externalIds) {
  if (externalIds.size === 0) return 'unverified';
  const zones = asList(rule.src_zones)
    .map((z) => String(z).trim().toLowerCase())
    .filter((z) => z !== '');
  if (zones.length === 0) return 'unverified';
  // An explicit "any" zone genuinely includes the external one.
  if (zones.some((z) => ANY_ZONE.has(z))) return 'inbound';
  return zones.some((z) => externalIds.has(z)) ? 'inbound' : 'internal';
}

function isAllowRule(rule) {
  return ALLOW_ACTIONS.has(String(rule && rule.action ? rule.action : '').toLowerCase());
}

function asList(v) {
  if (Array.isArray(v)) return v;
  if (v === null || v === undefined || v === '') return [];
  return [v];
}

// Every port a resolved service field opens, as printable ranges. `isAny`
// stays distinguishable from "no ports" — an any-service rule is the broadest
// exposure there is and must not render the same as an unresolved one.
function describeService(resolvedService) {
  if (resolvedService.isAny) return { label: 'any', ports: [], isAny: true, unresolved: false };
  const ports = [];
  for (const p of resolvedService.protocols || []) {
    ports.push({
      proto: p.proto || null,
      portStart: p.portStart === undefined ? null : p.portStart,
      portEnd: p.portEnd === undefined ? null : p.portEnd,
    });
  }
  const unresolved = (resolvedService.unresolvedNames || []).length > 0;
  const label =
    ports.length === 0
      ? unresolved
        ? 'unresolved'
        : 'none'
      : ports
          .map((p) =>
            p.portStart === null
              ? p.proto || 'any'
              : p.portStart === p.portEnd
                ? `${p.proto || 'any'}/${p.portStart}`
                : `${p.proto || 'any'}/${p.portStart}-${p.portEnd}`
          )
          .join(', ');
  return { label, ports, isAny: false, unresolved };
}

// ─────────────────────────────────────────
// DNAT
// ─────────────────────────────────────────

/**
 * Destination-NAT entries that publish a PUBLIC address to an internal host.
 *
 * ⛔ Only `nat_type = 'destination'`. A source-NAT row describes outbound
 * translation and is not an inbound exposure; counting it would inflate the
 * attack surface with every device's normal internet egress.
 */
function buildDnatMap(natRules, addressObjects) {
  const map = new Map(); // public ip -> [{internalIp, natRule}]
  for (const n of Array.isArray(natRules) ? natRules : []) {
    if (!n || n.enabled === false) continue;
    if (String(n.nat_type || '').toLowerCase() !== 'destination') continue;

    const origin = resolveAddressField(asList(n.original_dst_addresses), addressObjects);
    const target = resolveAddressField(asList(n.translated_dst_addresses), addressObjects);

    // Literal public addresses on the ORIGINAL side are the published face.
    const publics = [];
    for (const e of asList(n.original_dst_addresses)) {
      const s = String(e).split('/')[0].trim();
      if (DOTTED_QUAD.test(s) && isPublicIp(s)) publics.push(s);
    }
    if (publics.length === 0) continue;

    // The internal side may be a literal or an object name; keep it as text
    // when it does not resolve rather than dropping the exposure entirely.
    const internals = [];
    for (const e of asList(n.translated_dst_addresses)) {
      internals.push(String(e).split('/')[0].trim());
    }

    for (const p of publics) {
      if (!map.has(p)) map.set(p, []);
      map.get(p).push({
        internal: internals.length > 0 ? internals : null,
        internalResolved: (target.ranges || []).length > 0,
        natRuleSeq: n.sequence_number === undefined ? null : n.sequence_number,
        originIsAny: origin.isAny === true,
      });
    }
  }
  return map;
}

// ─────────────────────────────────────────
// Explainable severity
// ─────────────────────────────────────────
//
// ⛔ Every point carries a REASON string (roadmap §17: "every risk point
// should have a reason and an evidence trail"). The number is never shown
// without them, and this function is pure so the reasons are reproducible.
//
// ⛔ Observation only ever ADDS. An unobserved path is never scored DOWN for
// being quiet — see the file header.
function scoreExposure(path) {
  const reasons = [];
  let score = 0;

  if (path.directionVerified === false) {
    // ⛔ Reported, but NOT claimed as confirmed. Zone data was unavailable for
    // this device, so we cannot say the rule's source side faces the internet.
    reasons.push(
      'Direction UNVERIFIED — no public-interface zone data was collected for this device, so ' +
        'SecVault cannot confirm this rule faces the internet. Shown because under-reporting ' +
        'exposure is the more dangerous error.'
    );
  }

  if (path.sourceIsAny) {
    score += 40;
    reasons.push(
      path.directionVerified === false
        ? 'Source address is ANY.'
        : 'Source is ANY — reachable from the entire internet.'
    );
  } else {
    score += 15;
    reasons.push('Source is restricted to specific ranges, but still includes public space.');
  }

  if (path.service.isAny) {
    score += 25;
    reasons.push('Service is ANY — every port on this address is published.');
  } else if (path.service.unresolved) {
    score += 10;
    reasons.push('Service could not be fully resolved — the true port range may be wider.');
  }

  if (path.internal) {
    score += 15;
    reasons.push(
      `Destination NAT publishes this address to internal host ${path.internal.join(', ')}.`
    );
  }

  if (!path.logEnabled) {
    score += 10;
    reasons.push('Rule has logging disabled — traffic across this path is not recorded.');
  }

  if (path.observation === 'observed') {
    score += 20;
    // ⛔ ADDRESS-LEVEL wording, deliberately. The evidence is matched on
    // (public address, port) and cannot name which rule carried the traffic,
    // so claiming it arrived "across this path" would overstate what the
    // rollup can prove when several rules publish the same address.
    reasons.push(
      `Traffic from ${path.evidence.sources} distinct public source(s) was ALLOWED to this ` +
        `address on this port (${path.evidence.events} events, last ${path.evidence.lastSeen}).`
    );
  } else if (path.observation === 'unmeasured') {
    // ⛔ No score movement. Not knowing is not evidence in either direction,
    // and adding points for it would let a logging gap masquerade as risk.
    reasons.push(
      path.unmeasuredReason === 'service-unresolved'
        ? "The rule's service could not be resolved to a port range, so no traffic could be " +
          'matched against it — UNMEASURED, not unused.'
        : 'No inbound-traffic coverage for this device in the window — this path is UNMEASURED, ' +
          'not unused.'
    );
  } else {
    reasons.push(
      'No matching traffic observed in the window. The path is still open; it is simply unused.'
    );
  }

  const severity = score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low';
  return { score: Math.min(score, 100), severity, reasons };
}

// ─────────────────────────────────────────
// Path construction (pure)
// ─────────────────────────────────────────

/**
 * Build the exposure paths for ONE device from already-loaded data.
 *
 * Pure and synchronous so it can be unit-tested without a database, per
 * tests/README.md's "engines take data in and return data out".
 *
 * @returns {{paths: Array, publicIps: Array, unresolvedRules: number}}
 */
function buildExposurePaths({ rules, objects, natRules, interfaces }) {
  const addressObjects = buildObjectMap(objects, ['address', 'address_group']);
  const serviceObjects = buildObjectMap(objects, ['service', 'service_group']);

  const publicIps = publicInterfaceIps(interfaces);
  const dnat = buildDnatMap(natRules, addressObjects);

  // The set of addresses that represent "the internet-facing face of this
  // device": its own public interface addresses plus anything published by a
  // destination-NAT rule.
  const faces = new Map();
  for (const p of publicIps) faces.set(p.ip, { ip: p.ip, via: 'interface', interface: p });
  for (const ip of dnat.keys()) {
    if (!faces.has(ip)) faces.set(ip, { ip, via: 'nat', interface: null });
  }

  const externalIds = externalZoneIds(interfaces);

  const paths = [];
  let unresolvedRules = 0;
  let internalRulesExcluded = 0;

  for (const rule of Array.isArray(rules) ? rules : []) {
    if (!rule || rule.enabled === false) continue;
    if (!isAllowRule(rule)) continue;

    // ⛔ DIRECTION FIRST. A rule whose source side cannot be the internet is
    // not an internet exposure, however broad its address or service fields.
    const direction = ruleDirection(rule, externalIds);
    if (direction === 'internal') {
      internalRulesExcluded++;
      continue;
    }

    const src = resolveAddressField(asList(rule.src_addresses), addressObjects);
    const dst = resolveAddressField(asList(rule.dst_addresses), addressObjects);
    const svc = resolveServiceField(asList(rule.services), serviceObjects);

    // A rule only creates INTERNET exposure if its source can be public.
    // `isAny` obviously qualifies. Otherwise the source must include at least
    // one public range.
    let sourceIsAny = src.isAny === true;
    let sourceHasPublic = sourceIsAny;
    if (!sourceIsAny) {
      for (const r of src.ranges || []) {
        // A range is "public" if either endpoint is outside private space.
        if (!rangeIsWhollyPrivate(r)) {
          sourceHasPublic = true;
          break;
        }
      }
    }
    if (!sourceHasPublic) continue;

    if ((src.unresolvedNames || []).length > 0 || (src.unresolvedFqdns || []).length > 0) {
      unresolvedRules++;
    }

    const service = describeService(svc);

    for (const face of faces.values()) {
      const u = ipToUint32(face.ip);
      if (u === null) continue;

      // Does this rule's destination cover the public face?
      let covers = dst.isAny === true;
      if (!covers) {
        for (const r of dst.ranges || []) {
          if (u >= r.start && u <= r.end) {
            covers = true;
            break;
          }
        }
      }
      // A DNAT'd address is frequently written into the rule as its INTERNAL
      // address instead of its public one (Fortinet VIPs behave this way), so
      // also match the rule against the internal target.
      const nats = dnat.get(face.ip) || [];
      if (!covers) {
        for (const n of nats) {
          for (const iip of n.internal || []) {
            const iu = ipToUint32(iip);
            if (iu === null) continue;
            for (const r of dst.ranges || []) {
              if (iu >= r.start && iu <= r.end) {
                covers = true;
                break;
              }
            }
            if (covers) break;
          }
          if (covers) break;
        }
      }
      if (!covers) continue;

      // ⛔ De-duplicated. buildDnatMap holds one entry per NAT RULE, and a
      // device commonly forwards several ports of one public address to the
      // same internal host — live, TUG's five DNAT rules on 147.50.33.118
      // produced "10.248.32.9, 10.248.32.9, 10.248.32.9, 10.248.32.10,
      // 10.248.32.204". Beyond the cosmetics, the repeated entry made the
      // page claim all three hosts were reachable on ANY port when the device
      // forwards only :9001 and :37777 to the last two.
      const internalAll = nats.length > 0 ? nats.flatMap((n) => n.internal || []) : [];
      const internal = Array.from(new Set(internalAll));

      paths.push({
        publicIp: face.ip,
        via: face.via,
        interfaceName: face.interface ? face.interface.interfaceName : null,
        zone: face.interface ? face.interface.zone : null,
        // ⛔ Carried so the UI can distinguish a verified internet-facing path
        // from one on a device whose zone data we could not collect. An
        // unverified path is still REPORTED — under-reporting exposure is the
        // more dangerous direction — but it must not claim to be confirmed.
        directionVerified: direction === 'inbound',
        internal: internal.length > 0 ? internal : null,
        ruleName: rule.rule_name || rule.rule_id_vendor || null,
        ruleSequence: rule.sequence_number === undefined ? null : rule.sequence_number,
        vdom: rule.vdom || null,
        sourceIsAny,
        service,
        logEnabled: rule.log_enabled === true,
        // filled in by attachObservations()
        observation: 'unmeasured',
        evidence: null,
      });
    }
  }

  return { paths, publicIps, unresolvedRules, internalRulesExcluded, externalIds: Array.from(externalIds) };
}

function rangeIsWhollyPrivate(range) {
  for (const [base, bits] of PRIVATE_RANGES) {
    const b = ipToUint32(base);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const start = (b & mask) >>> 0;
    const end = (start + (bits === 32 ? 0 : ~mask >>> 0)) >>> 0;
    if (range.start >= start && range.end <= end) return true;
  }
  return false;
}

module.exports = {
  externalZoneIds,
  ruleDirection,
  ipToUint32,
  isPublicIp,
  publicInterfaceIps,
  buildDnatMap,
  describeService,
  scoreExposure,
  buildExposurePaths,
  rangeIsWhollyPrivate,
};
