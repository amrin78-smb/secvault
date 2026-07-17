// lib/engines/cidrUtils.js
//
// IPv4 literal / CIDR parsing and containment/equality comparison, used by
// lib/engines/ruleAnalysis.js to upgrade address-list comparison from pure
// string equality to real subnet math -- but ONLY for address-list items
// that are genuine IPv4 literals typed directly into a rule (this happens
// on Palo Alto, both SSH and XML/API transports, where an admin can type
// "10.0.0.0/24" straight into a rule instead of referencing an address
// object). Most address-list items across all Tier 1 vendors are unresolved
// object names (e.g. "LAN-subnet") or the wildcard "any" -- this module
// must never claim a match for those, so every function here returns a
// distinct `null` sentinel (never `false`) when either input isn't a
// parseable IPv4 literal/CIDR, so callers can fall back to string equality
// instead of silently treating "not comparable" as "not equal"/"doesn't
// contain". Same "deliberately conservative, don't guess" philosophy as
// fieldCovers()'s existing comments in ruleAnalysis.js.
//
// IPv6 is explicitly OUT OF SCOPE (any string containing ':' returns null
// from parseCidrOrIp, never attempted) -- an accepted limitation, not a
// bug. Every Tier 1 vendor ruleset in this codebase is overwhelmingly
// IPv4, and this module is a bounded, additive enhancement, not a general
// network library.

'use strict';

// Matches strings that look like they were MEANT to be an IPv4 literal or
// CIDR (only digits, dots, and an optional "/digits" suffix) but that may
// still fail strict validation below (bad octet, bad prefix, wrong octet
// count, etc). Used only to decide whether a parse failure is "subtly
// malformed IP-shaped input worth a warning" vs. "this was never an IP to
// begin with" (an address-object name, "any", IPv6, garbage) -- the vast
// majority of inputs are the latter and must NOT warn on every call.
const IP_SHAPED = /^[0-9]+(\.[0-9]+)*(\/[0-9]+)?$/;

/**
 * Converts a validated 4-element octet array to an unsigned 32-bit integer.
 * @param {number[]} octets - exactly 4 integers, each already known 0-255.
 * @returns {number} unsigned 32-bit integer (`>>> 0` keeps it unsigned --
 *   plain bitwise ops on values >= 2^31 go negative in JS otherwise).
 */
function octetsToUint32(octets) {
  return (
    ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>>
    0
  );
}

/**
 * Builds a /prefixLen network mask as an unsigned 32-bit integer.
 * @param {number} prefixLen - integer 0-32, already validated by the caller.
 * @returns {number}
 */
function maskForPrefixLen(prefixLen) {
  if (prefixLen === 0) {
    // `0xFFFFFFFF << 32` is a no-op in JS (shift amount is taken mod 32,
    // so shifting by 32 is the same as shifting by 0) -- must special-case
    // /0 rather than let the general shift below silently produce the
    // wrong (all-ones) mask.
    return 0;
  }
  return (0xffffffff << (32 - prefixLen)) >>> 0;
}

/**
 * Parses a single address-field string as an IPv4 literal or CIDR.
 * Accepts "10.0.0.5" (bare IP, treated as /32) and "10.0.0.0/24" (CIDR).
 * Host bits are masked off by the prefix length (so "10.0.0.5/24" normalizes
 * to network 10.0.0.0/24, same as "10.0.0.0/24") -- this is deliberate:
 * an admin typing host bits into what's meant to be a network/prefix literal
 * is a plausible real-world typo, and normalizing avoids a false inequality.
 * Returns null for anything else: IPv6 (contains ':'), an address-object
 * name, "any"/"all", octets out of 0-255 range, a prefix length outside
 * 0-32, garbage. IPv6 is explicitly OUT OF SCOPE for this module (return
 * null, don't attempt to parse) -- documented as an accepted limitation,
 * not a bug: most Tier-1 vendor rulesets in this codebase are IPv4-heavy,
 * and this is a bounded, additive enhancement -- see fieldCovers()'s
 * existing "deliberately conservative to avoid false shadows" philosophy in
 * lib/engines/ruleAnalysis.js's own comments.
 * @param {string} str
 * @returns {{network: number, prefixLen: number} | null} network is the
 *   masked address as an unsigned 32-bit integer (use `>>> 0` to keep it
 *   unsigned in JS, since plain bitwise ops on values >= 2^31 go negative).
 */
function parseCidrOrIp(str) {
  if (typeof str !== 'string') {
    return null;
  }
  const trimmed = str.trim();
  if (trimmed === '' || trimmed.indexOf(':') !== -1) {
    // Empty string or IPv6 (colon present) -- neither is IP-shaped in the
    // sense this module cares about; no warning, these are expected misses.
    return null;
  }

  const looksIpShaped = IP_SHAPED.test(trimmed);

  const slashParts = trimmed.split('/');
  if (slashParts.length > 2) {
    return warnIfIpShaped(trimmed, looksIpShaped);
  }

  const ipPart = slashParts[0];
  const prefixPart = slashParts.length === 2 ? slashParts[1] : null;

  const octetStrs = ipPart.split('.');
  if (octetStrs.length !== 4) {
    return warnIfIpShaped(trimmed, looksIpShaped);
  }

  const octets = [];
  for (const octetStr of octetStrs) {
    if (!/^\d{1,3}$/.test(octetStr)) {
      return warnIfIpShaped(trimmed, looksIpShaped);
    }
    const n = parseInt(octetStr, 10);
    if (n < 0 || n > 255) {
      return warnIfIpShaped(trimmed, looksIpShaped);
    }
    octets.push(n);
  }

  let prefixLen = 32;
  if (prefixPart !== null) {
    if (!/^\d{1,2}$/.test(prefixPart)) {
      return warnIfIpShaped(trimmed, looksIpShaped);
    }
    const p = parseInt(prefixPart, 10);
    if (p < 0 || p > 32) {
      return warnIfIpShaped(trimmed, looksIpShaped);
    }
    prefixLen = p;
  }

  const address = octetsToUint32(octets);
  const network = (address & maskForPrefixLen(prefixLen)) >>> 0;

  return { network, prefixLen };
}

/**
 * Emits a console.warn only when the rejected input looked like it was
 * meant to be an IPv4 literal/CIDR (digits/dots/slash only) but failed
 * validation -- e.g. a bad octet or an out-of-range prefix length. Silent
 * for anything else (address-object names, "any"/"all", IPv6, arbitrary
 * garbage), since those are the overwhelming majority of non-matches and
 * are not malformed IPs, just not IPs at all.
 * @returns {null}
 */
function warnIfIpShaped(trimmed, looksIpShaped) {
  if (looksIpShaped) {
    console.warn(
      `[cidrUtils] "${trimmed}" looks like an IPv4 literal/CIDR but failed to parse (bad octet, octet count, or prefix length) - treating as not comparable`
    );
  }
  return null;
}

/**
 * True if outerStr's address range fully contains innerStr's address range
 * (outerStr covers innerStr) -- e.g. "10.0.0.0/16" contains "10.0.5.0/24".
 * Returns null (NOT false) when either string doesn't parse as an IPv4
 * literal/CIDR -- callers MUST treat null as "not comparable this way,
 * fall back to whatever else you were doing (e.g. string equality)", never
 * as a negative containment result.
 * @param {string} outerStr
 * @param {string} innerStr
 * @returns {boolean | null}
 */
function cidrContains(outerStr, innerStr) {
  const outer = parseCidrOrIp(outerStr);
  const inner = parseCidrOrIp(innerStr);
  if (outer === null || inner === null) {
    return null;
  }
  if (outer.prefixLen > inner.prefixLen) {
    // Outer is a smaller (more specific) range than inner -- a smaller
    // range can never contain a bigger one.
    return false;
  }
  const innerMaskedToOuter = (inner.network & maskForPrefixLen(outer.prefixLen)) >>> 0;
  return innerMaskedToOuter === outer.network;
}

/**
 * True if aStr and bStr denote the exact same address range after masking
 * (e.g. "10.0.0.5/24" equals "10.0.0.0/24"). Returns null when either
 * string doesn't parse as an IPv4 literal/CIDR, same "not comparable, don't
 * treat as false" contract as cidrContains.
 * @param {string} aStr
 * @param {string} bStr
 * @returns {boolean | null}
 */
function cidrEquals(aStr, bStr) {
  const a = parseCidrOrIp(aStr);
  const b = parseCidrOrIp(bStr);
  if (a === null || b === null) {
    return null;
  }
  return a.prefixLen === b.prefixLen && a.network === b.network;
}

module.exports = { parseCidrOrIp, cidrContains, cidrEquals };
