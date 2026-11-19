// lib/syslog/sonicos.js
//
// The SonicOS "Enhanced Syslog" grammar: header stripping, a quote-aware
// key=value tokenizer, and the compound `src=`/`dst=` splitter.
//
// Kept out of vendorParsers.js for the same reason junos.js and cef.js are: the
// tokenizer is NOT the loose key=value grammar the other vendors share — it has
// single-quoted values, multi-space separators and a compound address field
// whose mis-split silently fabricates IP addresses.
//
// ⛔ EVERY RULE HERE WAS MEASURED against 220 real (anonymised) SonicOS lines:
// 55 keys, 44 message ids, 431 address occurrences in 8 distinct shapes. Full
// analysis: secvault-lab/findings/SONICWALL-SYSLOG.md.
//
// ⛔ THE CORPUS IS THIRD-PARTY AND ANONYMISED — Elastic's own integration
// fixtures, not our capture of a live appliance, and no SonicWall device has
// ever been connected to SecVault. Syntax in 220 real lines is strong evidence;
// what a key MEANS on a firmware nobody here has seen is not settled by it.

'use strict';

const net = require('node:net');

// ⛔ `id=` IS THE BODY ANCHOR, NOT A DEVICE IDENTITY. SonicOS emits the literal
// string `id=firewall` on 217 of 220 lines (the other 3 are an anonymiser's
// redaction), so it is a CONSTANT and Elastic's mapping of it to
// `observer.name` yields "firewall" on every event it has ever indexed.
//
// ⛔ It is still the right anchor, because the body may start at byte 0 or may
// follow an RFC 3164 header, and three header shapes were observed. Finding the
// first `id=` at a token boundary and discarding what precedes it handles all of
// them without a header grammar. ⛔ A parser that VALIDATES `id=firewall` would
// reject lines on the strength of a redaction — anchor on the key, never its value.
const BODY_ANCHOR_RE = /(?:^|\s)id=/;

/** Strip any syslog header, returning the key=value body. */
function sonicosBody(message) {
  if (typeof message !== 'string') return null;
  const m = BODY_ANCHOR_RE.exec(message);
  if (!m) return null;
  return message.slice(m.index + (m[0][0] === ' ' ? 1 : 0));
}

// ⛔ BOTH QUOTE CHARACTERS ARE REAL. `appName='General UDP'` arrives in SINGLE
// quotes while every other quoted value uses double. A tokenizer that knows only
// `"` reads `appName='General` and leaves `UDP'` as a stray token.
//
// ⛔ MULTI-SPACE SEPARATORS ARE REAL TOO (measured: 3 instances of two spaces
// between pairs), so the separator is `\s+` and never a single space.
//
// ⛔ A DUPLICATE KEY IS RECORDED, NOT SILENTLY DROPPED. One corpus line carries
// `msg=` twice. FIRST WINS — matching Elastic — and the loser is preserved under
// `$dup:<key>` so the collision is visible rather than invented away.
function parseSonicosKv(body) {
  const out = {};
  if (typeof body !== 'string') return out;
  let i = 0;
  const n = body.length;
  while (i < n) {
    while (i < n && /\s/.test(body[i])) i += 1;
    if (i >= n) break;
    let key = '';
    while (i < n && body[i] !== '=' && !/\s/.test(body[i])) { key += body[i]; i += 1; }
    if (i >= n || body[i] !== '=') {
      // A bare token with no '='. Not a pair; skip it rather than inventing one.
      continue;
    }
    i += 1; // past '='
    let val = '';
    const q = body[i];
    if (q === '"' || q === "'") {
      i += 1;
      // ⛔ Strip only the MATCHING quote pair and preserve interior whitespace —
      // `msg="Possible TCP Flood on IF X1 - src: 82.98.136.100:80"` is one value.
      while (i < n && body[i] !== q) { val += body[i]; i += 1; }
      if (i < n) i += 1; // past the closing quote
    } else {
      while (i < n && !/\s/.test(body[i])) { val += body[i]; i += 1; }
    }
    if (!key) continue;
    if (Object.prototype.hasOwnProperty.call(out, key)) {
      if (!out[`$dup:${key}`]) out[`$dup:${key}`] = val;
      continue; // first wins
    }
    out[key] = val;
  }
  return out;
}

// ---------------------------------------------------------------------------
// The compound address field
// ---------------------------------------------------------------------------
//
//   src=<IP>[:<PORT>[:<INTERFACE>[:<HOSTNAME>]]]
//
// ⛔ EIGHT SHAPES WERE MEASURED over 431 occurrences, and BOTH the IP slot and
// the PORT slot can be EMPTY: `:28503:WAN:SOURCEHOST` and `::LAN:DSTHOST` are
// real. An empty IP slot means the address is IPv6 and arrives in the parallel
// `srcV6=`/`dstV6=` key instead — SonicOS NEVER puts a colon-bearing IPv6 in
// this field, because the field is itself colon-delimited.
//
// ⛔ A NAIVE split(':') IS CORRECT FOR THIS CORPUS BY LUCK, and the three
// validations below are what make it correct by construction. The decisive one
// is the INTERFACE pattern: a compressed IPv6 `::1` splits to ['', '', '1'],
// which has an empty IP, an empty port and a part[2] that would be read as an
// interface named "1". Only `^[A-Za-z]` refuses it. Measured: all 11 distinct
// interface names start with a letter and none is all-digits.
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IFACE_RE = /^[A-Za-z][A-Za-z0-9_-]*$/;

function validIpv4(s) {
  const m = IPV4_RE.exec(s);
  return m !== null && m.slice(1).every((o) => {
    const n = Number(o);
    // ⛔ Reject a leading zero: `010.1.1.1` is read as OCTAL by some resolvers,
    // so accepting it stores an address that means something else elsewhere —
    // the trap lib/consoleUrl.js already carries.
    return String(n) === o && n >= 0 && n <= 255;
  });
}

function validPort(s) {
  if (!/^\d{1,5}$/.test(s)) return false;
  const n = Number(s);
  return n >= 0 && n <= 65535;
}

/**
 * Split a SonicOS compound address.
 *
 * ⛔ REFUSES rather than guessing. A shape this does not recognise returns
 * `{ok:false}` with the raw value, and the caller records it unparsed — the
 * failed-read rule. Silently assigning `parts[0]` as an address is the bug: on
 * `fe80::1` that would store an "IP" of `fe80`.
 *
 * @returns {{ok:true, ip, port, iface, host}|{ok:false, reason, raw}}
 */
function splitSonicosAddress(value) {
  if (typeof value !== 'string' || value === '') return { ok: false, reason: 'empty', raw: value };
  // ⛔ AN IPv6 LITERAL IS REFUSED OUTRIGHT, BEFORE THE POSITIONAL SPLIT. The
  // interface pattern below is documented as "the one that catches a
  // compressed IPv6" — and it only catches the forms whose third colon-group
  // is not letter-led. `::1` is caught because part[2] is `1`; `::ffff:10.0.0.96`
  // is NOT, and returned ok:true with **iface: 'ffff'** and host '10.0.0.96',
  // putting a non-existent interface name into every interface rollup with no
  // `$badSrc` recorded to show a refusal had happened.
  //
  // ⛔ MEASURED FREE ON THE CORPUS: `net.isIPv6()` is false for all 431 real
  // compound addresses — including `::LAN:DSTHOST` and `:28503:WAN:SOURCEHOST`,
  // which are this grammar's empty-IP forms and not addresses — and true for
  // every leaking form. The findings document lists "whether src=/dst= can
  // ever carry an IPv6 directly" as UNVERIFIED, and this refusal path is what
  // is supposed to hold when that firmware arrives.
  if (net.isIPv6(value)) return { ok: false, reason: 'ipv6_literal', raw: value };

  const parts = value.split(':');
  // ⛔ An 8-group IPv6 yields 8 parts; anything past 4 is not this grammar.
  if (parts.length > 4) return { ok: false, reason: 'too_many_parts', raw: value };

  const rawIp = parts[0] === undefined || parts[0] === '' ? null : parts[0];
  if (rawIp !== null && !validIpv4(rawIp)) return { ok: false, reason: 'bad_ip', raw: value };

  const rawPort = parts[1] === undefined || parts[1] === '' ? null : parts[1];
  if (rawPort !== null && !validPort(rawPort)) return { ok: false, reason: 'bad_port', raw: value };

  const rawIface = parts[2] === undefined || parts[2] === '' ? null : parts[2];
  if (rawIface !== null && !IFACE_RE.test(rawIface)) return { ok: false, reason: 'bad_interface', raw: value };

  const rawHost = parts[3] === undefined || parts[3] === '' ? null : parts[3];

  return {
    ok: true,
    ip: rawIp,
    // ⛔ An EMPTY port slot is NOT port 0. 16 corpus occurrences carry
    // `ip::iface`, and writing 0 there is a measured value that never happened.
    port: rawPort === null ? null : Number(rawPort),
    iface: rawIface,
    host: rawHost,
  };
}

// ⛔ THE NAT FIELDS ARE A DIFFERENT GRAMMAR and must not go through the splitter
// above: `natSrc=`/`natDst=` are `ip:port` or a bare `ip` with NO interface and
// NO hostname slot, and the `*V6` variants BRACKET an address that carries a
// port (`[2a02:cf40::1]:1234`). Running them through the 4-part rule would read
// a port as an interface.
function splitSonicosNat(value) {
  if (typeof value !== 'string' || value === '') return { ok: false, reason: 'empty', raw: value };
  const bracket = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(value);
  if (bracket) {
    // ⛔ BOTH HALVES VALIDATED. `\d{1,5}` admits 99999, and the bracket body
    // was never checked at all — so `[a]:1` returned ok:true with ip 'a'.
    if (!net.isIP(bracket[1])) return { ok: false, reason: 'bad_ip', raw: value };
    if (bracket[2] !== undefined && !validPort(bracket[2])) {
      return { ok: false, reason: 'bad_port', raw: value };
    }
    return { ok: true, ip: bracket[1], port: bracket[2] === undefined ? null : Number(bracket[2]) };
  }
  const parts = value.split(':');
  if (parts.length === 1) {
    return validIpv4(parts[0])
      ? { ok: true, ip: parts[0], port: null }
      // A bare non-IPv4 token here is either a bare IPv6 or junk; it is passed
      // back unparsed rather than guessed at.
      : { ok: false, reason: 'not_ipv4', raw: value };
  }
  if (parts.length === 2 && validIpv4(parts[0]) && validPort(parts[1])) {
    return { ok: true, ip: parts[0], port: Number(parts[1]) };
  }
  // ⛔ Elastic's grok accepts `ip::port` (an empty middle slot) on these fields.
  // We have no sample, so it is handled but recorded as such by the caller.
  if (parts.length === 3 && validIpv4(parts[0]) && parts[1] === '' && validPort(parts[2])) {
    return { ok: true, ip: parts[0], port: Number(parts[2]) };
  }
  return { ok: false, reason: 'unrecognised', raw: value };
}

module.exports = {
  BODY_ANCHOR_RE,
  IFACE_RE,
  sonicosBody,
  parseSonicosKv,
  splitSonicosAddress,
  splitSonicosNat,
  validIpv4,
  validPort,
};
