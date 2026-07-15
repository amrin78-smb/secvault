// lib/adapters/checkpoint/api.js
// CommonJS ONLY — required by lib/adapters/checkpoint/index.js, which in turn is
// required by services/engine-worker.js (plain node, CommonJS).
//
// Low-level Check Point Management API client. Pure HTTP — no DB access, no
// credStore access here.
//
// Check Point Management API basics:
//   - Base URL: https://<mgmt_ip>:<mgmt_port || 443>/web_api/
//   - ALL calls are POST with JSON bodies (even "show-*" reads).
//   - Login: POST login with {user, password} OR {'api-key': ...} → response.sid
//   - Every subsequent call sends header `X-chkp-sid: <sid>`.
//   - ALWAYS POST logout when done (sessions are limited on the management
//     server) — withSession() guarantees this in a finally block.
//   - Most management servers use self-signed certs — accept them by default.
//   - NEVER assume field names from documentation alone (CLAUDE.md "External
//     API Integrations") — first-connect paths log raw responses in index.js.

const https = require('https');
// node-fetch@2's package.json declares BOTH "main" (CJS, lib/index.js) and
// "module" (ESM, lib/index.mjs). Next.js's webpack bundler resolves the
// "module" field even for this plain `require()` call, so the raw result is
// the ESM namespace object -- the actual function lives at `.default` -- not
// the callable function itself. Confirmed live: `typeof require('node-fetch')`
// was 'object' inside a built Next.js API route, causing every SMC request to
// fail instantly with a minified "X is not a function" (X = whatever the
// bundler renamed this variable to), before any real network attempt. A plain
// `node script.js` run of this exact file does NOT hit this (require resolves
// "main" correctly there), which is why it wasn't caught outside the actual
// Next.js runtime.
const fetchModule = require('node-fetch');
const fetch = fetchModule.default || fetchModule;

const REQUEST_TIMEOUT_MS = 15000;

// conn shape used throughout this module:
//   { host, port, credentials, allowSelfSignedSsl }
// credentials is either { username, password } or { apiKey } (built by
// index.js from the decrypted credStore JSON).

// Internal shared POST. `sid` is optional — omitted only for the login call.
async function rawPost(conn, command, body, sid) {
  const url = `https://${conn.host}:${conn.port}/web_api/${command}`;

  // Default: accept self-signed certs unless explicitly told not to
  // (same pattern as lib/adapters/forcepoint/smc.js).
  const agent = new https.Agent({ rejectUnauthorized: conn.allowSelfSignedSsl === false });

  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  if (sid) {
    headers['X-chkp-sid'] = sid;
  }

  let response;
  try {
    response = await fetch(url, {
      method: 'POST',
      agent,
      timeout: REQUEST_TIMEOUT_MS,
      headers,
      body: JSON.stringify(body || {}),
    });
  } catch (err) {
    throw new Error(`Check Point API request failed (${command} @ ${url}): ${err.message}`);
  }

  const bodyText = await response.text();
  let parsed = null;
  if (bodyText) {
    try {
      parsed = JSON.parse(bodyText);
    } catch (_err) {
      // Non-JSON body — leave parsed as null, fall through to status handling.
      parsed = null;
    }
  }

  if (!response.ok) {
    // Check Point error bodies carry structured `code` + `message` fields —
    // surface them so failures are meaningful, not just an HTTP status.
    let detail;
    if (parsed && (parsed.message || parsed.code)) {
      detail = [parsed.code, parsed.message].filter(Boolean).join(': ');
    } else {
      detail = bodyText ? bodyText.slice(0, 300) : '(empty body)';
    }

    if (response.status === 401 || (parsed && parsed.code === 'err_login_failed')) {
      throw new Error(`Check Point authentication failed — ${detail}`);
    }
    if (response.status === 403) {
      throw new Error(`Check Point API '${command}' forbidden (check API permissions) — ${detail}`);
    }
    throw new Error(`Check Point API '${command}' failed with status ${response.status}: ${detail}`);
  }

  return parsed;
}

// POST login → sid. Accepts either credential shape; throws a clear error if
// neither is usable or the response has no sid.
async function login(conn) {
  const creds = (conn && conn.credentials) || {};

  let body;
  if (creds.apiKey) {
    body = { 'api-key': creds.apiKey };
  } else if (creds.username) {
    body = { user: creds.username, password: creds.password || '' };
  } else {
    throw new Error(
      'No usable Check Point credential — expected {"username","password"} or {"api_key"} JSON in credStore'
    );
  }

  const result = await rawPost(conn, 'login', body);
  if (!result || typeof result.sid !== 'string' || result.sid.length === 0) {
    throw new Error(
      'Check Point login succeeded (HTTP 200) but response contained no sid — raw keys: ' +
        JSON.stringify(result && typeof result === 'object' ? Object.keys(result) : result)
    );
  }
  return result.sid;
}

// POST logout for an active session. Never throws — logout failure must never
// mask the real error from the work done inside the session.
async function logout(session) {
  try {
    await rawPost(session.conn, 'logout', {}, session.sid);
  } catch (err) {
    console.warn(`[CheckPoint API] logout failed (session may expire on its own): ${err.message}`);
  }
}

// Low-level session-scoped request helper.
// session shape: { conn, sid, request } (built by withSession).
async function cpRequest(session, command, body) {
  return rawPost(session.conn, command, body || {}, session.sid);
}

// Session lifecycle helper: logs in, runs the callback with the session,
// ALWAYS logs out in a finally block (Check Point management sessions are a
// limited resource — leaking them locks out subsequent API logins).
//
// Usage: await withSession(conn, async (session) => { ... session.request(cmd, body) ... })
async function withSession(conn, fn) {
  const sid = await login(conn);
  const session = { conn, sid };
  session.request = (command, body) => cpRequest(session, command, body);
  try {
    return await fn(session);
  } finally {
    await logout(session);
  }
}

module.exports = {
  cpRequest,
  login,
  logout,
  withSession,
};
