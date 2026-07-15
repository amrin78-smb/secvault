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
// Auth: FortiOS REST API access token, sent as `Authorization: Bearer <token>`.

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

// conn shape used throughout this module (built by index.js's _getConn()):
//   { host, port, token, allowSelfSignedSsl }
async function fortiRequest(conn, path, { rawText = false } = {}) {
  const { host, port, token, allowSelfSignedSsl } = conn || {};
  const url = String(path).startsWith('http')
    ? path
    : `https://${host}:${port || 443}${path}`;

  // Default: accept self-signed certs unless explicitly told not to
  // (same pattern as lib/adapters/forcepoint/smc.js).
  const agent = new https.Agent({ rejectUnauthorized: allowSelfSignedSsl === false });

  let response;
  try {
    response = await fetch(url, {
      method: 'GET',
      agent,
      timeout: REQUEST_TIMEOUT_MS, // node-fetch@2 native per-request timeout
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
      },
    });
  } catch (err) {
    throw new Error(`FortiGate request failed (${url}): ${err.message}`);
  }

  const bodyText = await response.text();

  if (!response.ok) {
    const status = response.status;
    const snippet = bodyText ? bodyText.slice(0, 300) : '(empty body)';
    if (status === 401) {
      throw new Error(
        'FortiGate authentication failed (HTTP 401) — invalid or expired REST API token'
      );
    }
    if (status === 403) {
      throw new Error(
        `FortiGate access denied (HTTP 403) for ${path} — the API token's admin profile lacks permission for this endpoint`
      );
    }
    if (status === 404) {
      throw new Error(`FortiGate endpoint not found (HTTP 404): ${path}`);
    }
    throw new Error(`FortiGate request failed with HTTP ${status} (${path}): ${snippet}`);
  }

  if (rawText) {
    return bodyText;
  }

  try {
    return JSON.parse(bodyText);
  } catch (_err) {
    const snippet = bodyText ? bodyText.slice(0, 300) : '(empty body)';
    throw new Error(`FortiGate returned a non-JSON response for ${path}: ${snippet}`);
  }
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

// GET /api/v2/monitor/firewall/policy — per-policy runtime stats. FortiGate is one of
// the few vendors that exposes real hit counts (hit_count / bytes keyed by policyid).
async function getPolicyStats(conn) {
  return fortiRequest(conn, '/api/v2/monitor/firewall/policy');
}

// GET /api/v2/monitor/system/config/backup?scope=global — full raw text config.
// May 403 on tokens whose admin profile lacks backup permission — callers must
// treat this endpoint as best-effort.
async function getConfigBackup(conn) {
  return fortiRequest(conn, '/api/v2/monitor/system/config/backup?scope=global', {
    rawText: true,
  });
}

// --- CMDB API (configuration objects) ----------------------------------------------

// GET /api/v2/cmdb/firewall/policy — the full IPv4 policy table (results array).
async function getFirewallPolicies(conn) {
  return fortiRequest(conn, '/api/v2/cmdb/firewall/policy');
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
  getSystemStatus,
  getFirmware,
  getPolicyStats,
  getConfigBackup,
  getFirewallPolicies,
  getSystemGlobal,
  getInterfaces,
  getSslVpnSettings,
  getSnmpSysinfo,
  getAdmins,
};
