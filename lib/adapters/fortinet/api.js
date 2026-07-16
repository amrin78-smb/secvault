// lib/adapters/fortinet/api.js
// CommonJS ONLY — required by lib/adapters/fortinet/index.js, which in turn is
// required by services/engine-worker.js (plain node, CommonJS).
//
// Low-level FortiOS REST API client. Pure HTTP — no DB access, no credStore access here.
// See CLAUDE.md "External API Integrations" before changing anything in this file:
//   - NEVER assume field names from documentation alone. FortiOS monitor/cmdb response
//     shapes vary between 6.x and 7.x firmware — log raw responses on first integration
//     test (done in index.js) and keep every field access defensive in parser.js.
//   - Most FortiGate mgmt interfaces use self-signed certs — accept them by default.
//
// Auth — TWO modes, selected by index.js from the stored credential shape:
//   1. API token  → `Authorization: Bearer <token>` (stateless; the original path,
//                   unchanged).
//   2. Session    → POST /logincheck with username=/secretkey= form fields, then every
//                   request carries the returned session cookies, and every NON-GET
//                   request additionally carries `X-CSRFTOKEN` (FortiOS rejects
//                   state-changing requests without it). The session MUST be closed via
//                   POST /logout — a FortiGate has a finite admin-session cap, and a
//                   session leaked per collect will eventually lock out real admins.
//                   index.js owns the try/finally that guarantees this.
//
// ⚠️ The session-login path is DOC-DERIVED and has NOT been verified against a live
// FortiGate (CLAUDE.md: documentation lies — verify field names against live responses).
// It is written to fail LOUDLY rather than silently: /logincheck answers HTTP 200 even
// for a rejected login, so success is determined by the presence of a real CSRF cookie,
// never by the status code. See loginSession() below.
//
// ⛔ NEVER log or echo the API token, the password, or the session cookie VALUES. Errors
// from this module surface both in engine.log and in the /api/devices/[id]/test HTTP
// response body. Session cookies are bearer credentials — logging them is as bad as
// logging the password.

const https = require('https');
// node-fetch@2's package.json declares BOTH "main" (CJS, lib/index.js) and
// "module" (ESM, lib/index.mjs). Next.js's webpack bundler resolves the
// "module" field even for this plain `require()` call, so the raw result is
// the ESM namespace object -- the actual function lives at `.default` -- not
// the callable function itself. Confirmed live (Forcepoint SMC adapter,
// commit b48ef44): `typeof require('node-fetch')` was 'object' inside a built
// Next.js API route, causing every request to fail instantly with a minified
// "X is not a function" before any real network attempt. A plain
// `node script.js` run does NOT hit this, which is why it was only caught in
// the actual Next.js runtime. Never simplify this back to a bare require.
const fetchModule = require('node-fetch');
const fetch = fetchModule.default || fetchModule;

// Per-request timeout. FortiGate monitor endpoints on a healthy box respond in
// well under a second; 15s covers slow WAN links without hanging a collect job.
const REQUEST_TIMEOUT_MS = 15000;

let loggedFirstLoginResponse = false;

// conn shape used throughout this module (built by index.js's _getConn()):
//   {
//     host, port, allowSelfSignedSsl,
//     token,                 // API-token mode
//     username, password,    // session mode (never logged)
//     session,               // session mode, after loginSession(): { cookieHeader, csrfToken }
//   }

function baseUrl(conn) {
  return `https://${conn.host}:${conn.port || 443}`;
}

// FortiOS scopes cmdb/monitor reads to ONE VDOM per request. Without ?vdom=<name>
// you silently get the admin's default VDOM only — an incomplete ruleset that the
// rule-analysis engine would treat as complete. See index.js getRules().
function withVdom(path, vdom) {
  if (vdom === null || vdom === undefined || vdom === '') return path;
  const sep = String(path).includes('?') ? '&' : '?';
  return `${path}${sep}vdom=${encodeURIComponent(vdom)}`;
}

// Builds the auth headers for one request. Session mode wins when a session is
// present, otherwise the Bearer token path (unchanged from the token-only build).
function authHeaders(conn, method) {
  const headers = { Accept: 'application/json' };

  if (conn && conn.session && conn.session.cookieHeader) {
    headers.Cookie = conn.session.cookieHeader;
    // FortiOS requires the CSRF token on every state-changing request. GETs are
    // authenticated by the session cookie alone.
    if (method !== 'GET' && conn.session.csrfToken) {
      headers['X-CSRFTOKEN'] = conn.session.csrfToken;
    }
    return headers;
  }

  if (conn && conn.token) {
    headers.Authorization = `Bearer ${conn.token}`;
    return headers;
  }

  throw new Error(
    'FortiGate request has no usable authentication — no API token and no active session. ' +
      'Save an API token, or a username/password, for this device.'
  );
}

// Single low-level fetch. Returns { response, bodyText } and never inspects
// status — callers map failures to messages (loginSession needs the raw
// response headers, so it cannot go through fortiRequest's error mapping).
async function rawFetch(conn, path, { method = 'GET', formBody = null, vdom = null } = {}) {
  const target = withVdom(path, vdom);
  const url = String(target).startsWith('http') ? target : `${baseUrl(conn)}${target}`;

  // Default: accept self-signed certs unless explicitly told not to
  // (same pattern as lib/adapters/forcepoint/smc.js).
  const agent = new https.Agent({ rejectUnauthorized: (conn || {}).allowSelfSignedSsl === false });

  const headers = authHeaders(conn, method);
  const init = {
    method,
    agent,
    timeout: REQUEST_TIMEOUT_MS, // node-fetch@2 native per-request timeout
    headers,
    // Manual redirects on purpose: an expired/invalid session makes FortiOS 302 to
    // the login page. Following it would return login HTML with HTTP 200 and the
    // caller would report a confusing "non-JSON response" instead of "session
    // rejected". A redirect IS the error signal here.
    redirect: 'manual',
  };

  if (formBody !== null) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    init.body = formBody;
  }

  let response;
  try {
    response = await fetch(url, init);
  } catch (err) {
    throw new Error(`FortiGate request failed (${url}): ${err.message}`);
  }

  const bodyText = await response.text();
  return { response, bodyText, url };
}

// conn shape: see the comment block above.
async function fortiRequest(conn, path, { rawText = false, method = 'GET', formBody = null, vdom = null } = {}) {
  const { response, bodyText } = await rawFetch(conn, path, { method, formBody, vdom });
  const shownPath = withVdom(path, vdom);

  if (response.status >= 300 && response.status < 400) {
    // Only reachable in session mode (a Bearer request is never redirected to login).
    throw new Error(
      `FortiGate redirected ${shownPath} to the login page (HTTP ${response.status}) — ` +
        'the admin session was rejected or expired.'
    );
  }

  if (!response.ok) {
    const status = response.status;
    const snippet = bodyText ? bodyText.slice(0, 300) : '(empty body)';
    if (status === 401) {
      throw new Error(
        'FortiGate authentication failed (HTTP 401) — invalid or expired REST API token / admin session'
      );
    }
    if (status === 403) {
      throw new Error(
        `FortiGate access denied (HTTP 403) for ${shownPath} — the admin profile lacks permission for this endpoint or VDOM`
      );
    }
    if (status === 404) {
      throw new Error(`FortiGate endpoint not found (HTTP 404): ${shownPath}`);
    }
    throw new Error(`FortiGate request failed with HTTP ${status} (${shownPath}): ${snippet}`);
  }

  if (rawText) {
    return bodyText;
  }

  try {
    return JSON.parse(bodyText);
  } catch (_err) {
    const snippet = bodyText ? bodyText.slice(0, 300) : '(empty body)';
    throw new Error(`FortiGate returned a non-JSON response for ${shownPath}: ${snippet}`);
  }
}

// --- Session auth (username + password) --------------------------------------------

// Collects Set-Cookie headers into a Map(name → value). node-fetch@2 exposes the
// unfolded list via headers.raw(); the .get() fallback exists only so this keeps
// working if the fetch implementation is ever swapped.
function parseSetCookies(response) {
  let list = [];
  try {
    const raw = typeof response.headers.raw === 'function' ? response.headers.raw()['set-cookie'] : null;
    if (Array.isArray(raw)) {
      list = raw;
    } else {
      const single = response.headers.get('set-cookie');
      if (single) list = [single];
    }
  } catch (_err) {
    list = [];
  }

  const cookies = new Map();
  for (const line of list) {
    const first = String(line).split(';')[0];
    const eq = first.indexOf('=');
    if (eq <= 0) continue;
    const name = first.slice(0, eq).trim();
    const value = first.slice(eq + 1).trim();
    if (name) cookies.set(name, value);
  }
  return cookies;
}

// FortiOS names the CSRF cookie `ccsrftoken`, or `ccsrftoken_<port>` when the admin
// GUI runs on a non-standard port. The value arrives wrapped in double quotes, which
// must be stripped before it goes in the X-CSRFTOKEN header.
// DOC-DERIVED — verify against a live device (see the [Fortinet Debug] log below).
function extractCsrfToken(cookies) {
  for (const [name, value] of cookies.entries()) {
    if (/^ccsrftoken/i.test(name)) {
      const unquoted = String(value).replace(/^"+|"+$/g, '').trim();
      // A rejected login can still set ccsrftoken="0" — that is NOT a usable token.
      if (unquoted && unquoted !== '0') return unquoted;
    }
  }
  return null;
}

// `\n0\n` style body codes returned by /logincheck when ajax=1 is sent.
// DOC/community-derived; used only to produce a BETTER error message. The
// authoritative success signal is the CSRF cookie, never this code.
function describeLoginCode(bodyText) {
  const code = String(bodyText || '').trim().charAt(0);
  if (code === '0') return 'invalid username or password';
  if (code === '2') return 'the account must change its password before it can be used';
  if (code === '3') return 'the account is locked out or logins are rate-limited';
  return null;
}

/**
 * Opens a FortiOS admin session with username + password.
 *
 * ⚠️ DOC-DERIVED, not live-verified: /logincheck answers HTTP 200 for BOTH a
 * successful and a rejected login, so status is useless as a success signal. Success
 * is defined here as "FortiOS handed us a usable ccsrftoken cookie" — if it did not,
 * we throw. That is the fail-loud behaviour CLAUDE.md demands: a wrong assumption here
 * produces a clear error, never a silent empty ruleset.
 *
 * @param {object} conn — must carry host/port/username/password/allowSelfSignedSsl
 * @returns {Promise<{cookieHeader: string, csrfToken: string}>}
 */
async function loginSession(conn) {
  if (!conn || !conn.username || conn.password === null || conn.password === undefined) {
    throw new Error('FortiGate session login requires both a username and a password');
  }

  // `ajax=1` makes FortiOS answer with a short status code instead of an HTML/JS
  // redirect page. Both forms still set the same cookies.
  const formBody =
    `username=${encodeURIComponent(conn.username)}` +
    `&secretkey=${encodeURIComponent(conn.password)}` +
    '&ajax=1';

  // conn without token/session — authHeaders() would throw. /logincheck is the one
  // unauthenticated endpoint, so give it a token-bearing shim that is never used.
  const loginConn = { ...conn, token: 'unauthenticated-login', session: null };

  const { response, bodyText } = await rawFetch(loginConn, '/logincheck', {
    method: 'POST',
    formBody,
  });

  const cookies = parseSetCookies(response);
  const csrfToken = extractCsrfToken(cookies);

  if (!loggedFirstLoginResponse) {
    // Per CLAUDE.md: log the raw response shape on first use so the doc-derived
    // assumptions above can be checked against a real FortiGate.
    // ⛔ Cookie VALUES are deliberately omitted — a FortiOS session cookie is a
    // bearer credential, and this line lands in engine.log on disk. Names, status
    // and body length are enough to diagnose a shape mismatch.
    console.log(
      '[Fortinet Debug] /logincheck response — HTTP status:',
      response.status,
      '| Set-Cookie names:',
      JSON.stringify(Array.from(cookies.keys())),
      '| CSRF token found:',
      csrfToken ? 'yes' : 'no',
      '| body length:',
      String(bodyText || '').length,
      '| body first char:',
      JSON.stringify(String(bodyText || '').trim().charAt(0))
    );
    loggedFirstLoginResponse = true;
  }

  if (cookies.size === 0) {
    throw new Error(
      `FortiGate session login failed — POST /logincheck (HTTP ${response.status}) returned no cookies at all. ` +
        'This endpoint/field-name mapping is doc-derived and unverified against live firmware: check the ' +
        '[Fortinet Debug] /logincheck line in the logs, then fix lib/adapters/fortinet/api.js. ' +
        'Refusing to continue with an unauthenticated session.'
    );
  }

  if (!csrfToken) {
    const reason = describeLoginCode(bodyText);
    throw new Error(
      `FortiGate session login failed — ${reason || 'FortiOS returned no usable ccsrftoken cookie'}. ` +
        'Check the username/password, and that the admin account is permitted to log in from this host ' +
        "(FortiOS admin accounts have a 'trusted hosts' allowlist). " +
        'Cookie names received: ' +
        JSON.stringify(Array.from(cookies.keys())) +
        '.'
    );
  }

  const cookieHeader = Array.from(cookies.entries())
    .map(([name, value]) => `${name}=${value}`)
    .join('; ');

  return { cookieHeader, csrfToken };
}

/**
 * Closes the admin session opened by loginSession().
 *
 * MUST be called for every successful login (index.js wraps every session-mode
 * operation in try/finally). A FortiGate caps concurrent admin sessions; leaking one
 * per collect is a real operational failure, not a tidiness issue.
 *
 * @param {object} conn — must carry .session
 */
async function logoutSession(conn) {
  if (!conn || !conn.session) return;
  // POST + X-CSRFTOKEN: /logout is state-changing, so it needs the CSRF header —
  // authHeaders() adds it automatically for non-GET requests.
  await fortiRequest(conn, '/logout', { method: 'POST', rawText: true });
}

// --- Monitor API (runtime state) ---------------------------------------------------

// GET /api/v2/monitor/system/status — connectivity check + version/serial/hostname/model.
async function getSystemStatus(conn) {
  return fortiRequest(conn, '/api/v2/monitor/system/status');
}

// GET /api/v2/monitor/system/firmware — running + available firmware.
// results.current typically carries { version: "v7.4.3", build: 2573, ... }.
async function getFirmware(conn) {
  return fortiRequest(conn, '/api/v2/monitor/system/firmware');
}

// GET /api/v2/monitor/firewall/policy?vdom=<name> — per-policy runtime stats. FortiGate
// is one of the few vendors that exposes real hit counts (hit_count / bytes keyed by
// policyid). NOTE policyid is only unique WITHIN a VDOM — callers must keep each VDOM's
// stats with that VDOM's policies, never merge them into one index.
async function getPolicyStats(conn, vdom = null) {
  return fortiRequest(conn, '/api/v2/monitor/firewall/policy', { vdom });
}

// GET /api/v2/monitor/system/config/backup?scope=global — full raw text config.
// May 403 on tokens whose admin profile lacks backup permission — callers must
// treat this endpoint as best-effort.
//
// SECURITY: the returned text is a FortiOS full configuration — it carries admin
// password hashes, `set psksecret`, private keys and SNMP communities. It MUST be
// redacted before it is returned from getConfig() (CLAUDE.md "Stored configs are
// REDACTED"). index.js does this via cliParser.redactConfig().
async function getConfigBackup(conn) {
  return fortiRequest(conn, '/api/v2/monitor/system/config/backup?scope=global', {
    rawText: true,
  });
}

// --- CMDB API (configuration objects) ----------------------------------------------

// GET /api/v2/cmdb/system/vdom — the VDOM table. On a box without multi-VDOM enabled
// this normally still returns the implicit single 'root' VDOM; on older firmware, or
// for an admin scoped to one VDOM, it may 403/404 or return only that VDOM. Callers
// MUST treat failure as "assume single implicit VDOM", never as a hard error.
async function getVdoms(conn) {
  return fortiRequest(conn, '/api/v2/cmdb/system/vdom');
}

// GET /api/v2/cmdb/firewall/policy?vdom=<name> — the IPv4 policy table (results array)
// for ONE VDOM. Omitting vdom returns only the admin's default VDOM.
async function getFirewallPolicies(conn, vdom = null) {
  return fortiRequest(conn, '/api/v2/cmdb/firewall/policy', { vdom });
}

// GET /api/v2/cmdb/system/global — global system settings.
async function getSystemGlobal(conn) {
  return fortiRequest(conn, '/api/v2/cmdb/system/global');
}

// GET /api/v2/cmdb/system/interface — interface configuration.
async function getInterfaces(conn) {
  return fortiRequest(conn, '/api/v2/cmdb/system/interface');
}

// GET /api/v2/cmdb/vpn.ssl/settings — SSL-VPN settings (key CVE surface on FortiOS).
async function getSslVpnSettings(conn) {
  return fortiRequest(conn, '/api/v2/cmdb/vpn.ssl/settings');
}

// GET /api/v2/cmdb/system/snmp/sysinfo — SNMP agent settings.
async function getSnmpSysinfo(conn) {
  return fortiRequest(conn, '/api/v2/cmdb/system/snmp/sysinfo');
}

// GET /api/v2/cmdb/system/admin — local administrator accounts.
async function getAdmins(conn) {
  return fortiRequest(conn, '/api/v2/cmdb/system/admin');
}

module.exports = {
  fortiRequest,
  loginSession,
  logoutSession,
  getSystemStatus,
  getFirmware,
  getPolicyStats,
  getConfigBackup,
  getVdoms,
  getFirewallPolicies,
  getSystemGlobal,
  getInterfaces,
  getSslVpnSettings,
  getSnmpSysinfo,
  getAdmins,
  // exported for testing / reuse, not part of the documented contract
  withVdom,
  extractCsrfToken,
  parseSetCookies,
};
