'use strict';
//
// lib/consoleUrl.js — what address is this console reached on?
//
// ⛔ WHY THIS IS NOT JUST A TEXT BOX. NextAuth builds its callback from
// NEXTAUTH_URL. Point it at a name the browser is not using and every sign-in
// bounces silently back to the login page — no error in the UI, none in the
// browser console, and the operator CANNOT LOG IN TO UNDO IT. The recovery is
// editing .env.local on the server and restarting the service.
//
// That is the whole reason this file is pure and separately tested: the
// validation is the safety mechanism, not decoration around a write.
//
// ⛔ THE SCHEME MUST FOLLOW THE TRANSPORT. lib/tlsConfig.js already refuses to
// let those disagree and server.js logs loudly when they do; this refuses to
// CREATE the disagreement in the first place, which is the cheaper place to
// catch it.

const PORT_MIN = 1;
const PORT_MAX = 65535;

// Deliberately narrow: a hostname or an IPv4 literal. Not a URL with a path,
// not a userinfo section, not an IPv6 literal — none of which NEXTAUTH_URL
// should carry here, and each of which would parse "successfully" into
// something that then fails only at sign-in.
const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$/;
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isIpv4(host) {
  const m = IPV4_RE.exec(host);
  return !!m && m.slice(1).every((o) => o.length <= 3 && Number(o) >= 0 && Number(o) <= 255);
}

/**
 * The host EXACTLY AS TYPED, pulled out of the raw string without a URL parse.
 *
 * ⛔ THIS EXISTS BECAUSE `new URL()` REWRITES HOSTS SILENTLY, AND EVERY GUARD
 * IN THIS FILE RAN ON THE REWRITTEN VALUE. `IPV4_RE`/`isIpv4` and `HOST_RE`
 * were applied to `parsed.hostname`, so the typed text never reached a check:
 * `http://192.168.010.1:3010` was ACCEPTED and saved as `192.168.8.1` — a
 * leading zero makes WHATWG read the octet as OCTAL. Measured 2026-11-14 by
 * calling the real validator, which returned `{ok:true, url:
 * 'http://192.168.8.1:3010'}` with no warning naming the change.
 *
 * ⛔ A BETTER `IPV4_RE` IS NOT THE FIX, which is why this compares strings
 * instead. The same rewrite arrives by at least four routes — octal
 * (`192.168.010.1`), all-octal (`0300.0250.0.1`), bare decimal
 * (`3232235777` → 192.168.1.1, which `HOST_RE` happily accepts because it is
 * all alphanumerics) and short form (`192.168.1` → 192.168.0.1) — plus IDN
 * punycode for any non-ASCII name. Enumerating the forms is a losing game;
 * refusing ANY disagreement between what was typed and what was parsed is not.
 *
 * ⛔ NO URL PARSE IN HERE, deliberately: parsing is the thing being checked, so
 * using it to produce the comparison value would compare the parser with
 * itself. IPv6 needs no bracket handling because `HOST_RE` refuses it outright
 * (see its own comment), and this returns the bracketed literal unchanged so
 * that refusal still fires.
 */
function typedHostOf(raw) {
  const sep = raw.indexOf('://');
  if (sep === -1) return '';
  const authority = raw.slice(sep + 3).split(/[/?#]/)[0];
  const at = authority.lastIndexOf('@');
  const hostAndPort = at === -1 ? authority : authority.slice(at + 1);
  if (hostAndPort.startsWith('[')) {
    const close = hostAndPort.indexOf(']');
    return close === -1 ? hostAndPort : hostAndPort.slice(0, close + 1);
  }
  const colon = hostAndPort.indexOf(':');
  return colon === -1 ? hostAndPort : hostAndPort.slice(0, colon);
}

/**
 * Validate and normalise a proposed console address.
 *
 * @param {string} input          what the operator typed
 * @param {{tlsActive: boolean}} ctx
 * @returns {{ok:true, url:string, scheme:string, host:string, port:number|null, warnings:string[]}
 *          |{ok:false, error:string}}
 */
function validateConsoleUrl(input, ctx = {}) {
  const raw = String(input == null ? '' : input).trim();
  if (!raw) return { ok: false, error: 'Enter the address this console is reached on.' };

  // ⛔ THE COMMONEST MISTAKE IS OMITTING THE SCHEME, and it produces the most
  // confusing error: `new URL('host:3010')` parses "host" as the SCHEME and
  // succeeds, so the operator is told their hostname is an unsupported
  // protocol. Caught before parsing, where the advice can be useful.
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) {
    return {
      ok: false,
      error: 'Include the scheme, for example https://secvault.example.com:3010',
    };
  }

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return {
      ok: false,
      error: 'That address could not be parsed. Check the host and port, for example '
        + 'https://secvault.example.com:3010',
    };
  }

  const scheme = parsed.protocol.replace(':', '').toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    return { ok: false, error: `Only http and https are supported, not "${scheme}".` };
  }

  // ⛔ A PATH IS SILENTLY FATAL. NextAuth appends /api/auth/... to this value,
  // so a trailing path segment produces callback URLs that 404 — and the only
  // symptom is that sign-in does not work.
  if (parsed.pathname && parsed.pathname !== '/') {
    return { ok: false, error: 'Give the address only — no path after the host and port.' };
  }
  if (parsed.search || parsed.hash) {
    return { ok: false, error: 'Give the address only — no query string or fragment.' };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, error: 'Remove the username and password from the address.' };
  }

  const host = parsed.hostname;
  if (!host) return { ok: false, error: 'The address has no host.' };

  // ⛔ REFUSE A SILENT REWRITE, BEFORE ANY OTHER HOST CHECK. Everything below
  // validates `parsed.hostname`; if that is not what the operator typed, the
  // checks are being applied to an address nobody asked for. Case is the one
  // difference allowed — hostnames are case-insensitive and lowercasing them
  // changes no destination.
  //
  // ⛔ THIS FIELD IS WHERE A WRONG ADDRESS COSTS THE MOST. It becomes
  // NEXTAUTH_URL, the lockout guard (`hostPointsHere`) resolves whatever is
  // stored here, and a mistake locks the operator out of the console they
  // would use to fix it. Saving a DIFFERENT address from the one typed, with
  // no error, is the worst available outcome in this file.
  const typedHost = typedHostOf(raw);
  if (typedHost && typedHost.toLowerCase() !== host.toLowerCase()) {
    return {
      ok: false,
      error: `That address was read as "${host}", not "${typedHost}" as typed. `
        + 'Leading zeros, a missing octet or a non-ASCII name are each rewritten '
        + 'to a different address. Enter the address exactly as the browser uses it.',
    };
  }

  if (!isIpv4(host) && !HOST_RE.test(host)) {
    return { ok: false, error: `"${host}" is not a valid hostname.` };
  }

  let port = null;
  if (parsed.port !== '') {
    port = Number(parsed.port);
    if (!Number.isInteger(port) || port < PORT_MIN || port > PORT_MAX) {
      return { ok: false, error: `Port ${parsed.port} is out of range.` };
    }
  }

  // ⛔ SCHEME vs TRANSPORT. This is the disagreement that breaks sign-in with no
  // visible error, and it is refused rather than warned about: an operator who
  // is told "this may not work" and proceeds is locked out just as thoroughly.
  if (ctx.tlsActive === true && scheme === 'http') {
    return {
      ok: false,
      error: 'TLS is active on this server, so the address must be https:// — with http:// the '
        + 'sign-in cookie is issued for an origin the browser is not on, and every login silently fails.',
    };
  }
  if (ctx.tlsActive === false && scheme === 'https') {
    return {
      ok: false,
      error: 'TLS is NOT active on this server, so the address must be http:// — install a '
        + 'certificate first, then change this.',
    };
  }

  const warnings = [];
  if (isIpv4(host)) {
    warnings.push(
      'This is an IP address. A certificate must carry it as an IP SAN, which public CAs do not '
      + 'issue for private addresses — a hostname is usually the better choice.'
    );
  }
  if (host === 'localhost' || host === '127.0.0.1') {
    warnings.push('Only this machine can reach localhost. Anyone signing in from elsewhere will fail.');
  }

  const url = `${scheme}://${host}${port === null ? '' : `:${port}`}`;
  return { ok: true, url, scheme, host, port, warnings };
}

/**
 * Does the proposed host actually point at this server?
 *
 * ⛔ THE LOCKOUT GUARD. Everything above is shape; this is the only check that
 * can tell "secvault.example.com" from a name nobody has created yet, and
 * setting the second one is exactly how an administrator locks themselves out
 * of a security platform with no way back through the UI.
 *
 * ⛔ IT FAILS OPEN ON A RESOLVER ERROR, AND SAYS SO. An internal DNS name may be
 * resolvable from every workstation and not from this host, and refusing a
 * correct address because our own resolver is unhappy would be its own kind of
 * lockout. Unresolvable is reported as a WARNING the operator must read, never
 * as a silent pass.
 */
async function hostPointsHere(host, { lookup, localAddresses }) {
  if (isIpv4(host)) {
    return localAddresses.includes(host)
      ? { resolved: true, pointsHere: true, addresses: [host] }
      : { resolved: true, pointsHere: false, addresses: [host] };
  }
  try {
    const records = await lookup(host);
    const addresses = (records || []).map((r) => (typeof r === 'string' ? r : r.address)).filter(Boolean);
    if (addresses.length === 0) return { resolved: false, pointsHere: null, addresses: [], error: 'no addresses' };
    return {
      resolved: true,
      pointsHere: addresses.some((a) => localAddresses.includes(a)),
      addresses,
    };
  } catch (err) {
    return { resolved: false, pointsHere: null, addresses: [], error: err.message };
  }
}

module.exports = { validateConsoleUrl, hostPointsHere, isIpv4, typedHostOf };
