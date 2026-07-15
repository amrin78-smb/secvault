// lib/adapters/paloalto/api.js
// CommonJS ONLY — required by lib/adapters/paloalto/index.js, which in turn is
// required by services/engine-worker.js (plain node, CommonJS).
//
// Low-level PAN-OS XML API client. Pure HTTP — no DB access, no credStore access here.
// Per CLAUDE.md "External API Integrations": the MVP was built without a live PAN-OS
// device — index.js logs raw responses on first-connect paths so field mappings in
// parser.js can be verified against a real firewall on first integration test.
//
// PAN-OS XML API basics:
//   - Single endpoint: https://<mgmt_ip>:<port>/api/ — operation selected via query params.
//   - Auth: API key passed as the `key` query parameter (URL-encoded).
//   - Every response is XML: <response status="success|error">...</response>.
//     status="error" carries the failure text in <msg> (string, <line> child, or a
//     list of <line> children depending on the error) — always surface it.

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

const { XMLParser } = require('fast-xml-parser');

const REQUEST_TIMEOUT_MS = 15000;

// Phase 1+2 assumes a single-vsys firewall on the default vsys. Multi-vsys support
// (enumerating /config/devices/entry/vsys/entry and pulling each rulebase) is a
// future enhancement — would need a per-device vsys setting or a vsys discovery call.
const DEFAULT_VSYS = 'vsys1';

const SECURITY_RULES_XPATH =
  "/config/devices/entry[@name='localhost.localdomain']" +
  `/vsys/entry[@name='${DEFAULT_VSYS}']/rulebase/security/rules`;

// One parser instance for the whole module — fast-xml-parser's parse() is stateless.
// ignoreAttributes: false + attributeNamePrefix '@_' so rule names (<entry name="...">)
// and response status (<response status="...">) survive parsing as '@_name'/'@_status'.
const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
});

// PAN-OS error <msg> bodies vary: a bare string, { line: 'text' }, { line: [...] },
// or nested objects with '#text'. Recursively flatten to a human-readable string.
// Never throws; returns null when nothing readable is found.
function extractErrorMessage(msg) {
  if (msg === null || msg === undefined) return null;
  if (typeof msg === 'string' || typeof msg === 'number' || typeof msg === 'boolean') {
    const s = String(msg).trim();
    return s.length > 0 ? s : null;
  }
  if (Array.isArray(msg)) {
    const parts = msg.map(extractErrorMessage).filter((p) => p !== null);
    return parts.length > 0 ? parts.join('; ') : null;
  }
  if (typeof msg === 'object') {
    if (msg.line !== undefined) return extractErrorMessage(msg.line);
    if (msg['#text'] !== undefined) return extractErrorMessage(msg['#text']);
    try {
      return JSON.stringify(msg).slice(0, 300);
    } catch (_err) {
      return null;
    }
  }
  return null;
}

// Strips the API key from any string that might end up in a thrown error message
// (node-fetch error messages embed the full request URL, key included).
function redactKey(text, apiKey) {
  if (!text) return text;
  let out = String(text);
  if (apiKey) {
    out = out.split(apiKey).join('***');
    // The key travels URL-encoded in the query string — redact that form too.
    out = out.split(encodeURIComponent(apiKey)).join('***');
  }
  return out;
}

// conn shape used throughout this module: { host, port, apiKey, allowSelfSignedSsl }.
// params: query params for the single /api/ endpoint (e.g. { type: 'op', cmd: '...' });
// the key param is appended here — callers never handle the key directly.
// Returns { raw: <full response XML string>, response: <parsed <response> node>,
//           result: <parsed <result> node or null> }.
async function panRequest(conn, params) {
  const { host, port, apiKey, allowSelfSignedSsl } = conn || {};
  if (!host) {
    throw new Error('PAN-OS API request failed: no management IP/host configured for device');
  }
  if (!apiKey) {
    throw new Error('PAN-OS API request failed: no API key provided');
  }

  const effectivePort = port || 443;
  // URLSearchParams URL-encodes every value, including the API key.
  const query = new URLSearchParams({ ...params, key: apiKey });
  const url = `https://${host}:${effectivePort}/api/?${query.toString()}`;
  const endpointLabel = `https://${host}:${effectivePort}/api/ (type=${params && params.type ? params.type : '?'})`;

  // Default: accept self-signed certs unless explicitly told not to — same pattern
  // as the Forcepoint SMC client (most firewall mgmt interfaces are self-signed).
  const agent = new https.Agent({ rejectUnauthorized: allowSelfSignedSsl === false });

  let response;
  try {
    response = await fetch(url, {
      method: 'GET',
      agent,
      timeout: REQUEST_TIMEOUT_MS,
      headers: { Accept: 'application/xml' },
    });
  } catch (err) {
    throw new Error(`PAN-OS API request failed (${endpointLabel}): ${redactKey(err.message, apiKey)}`);
  }

  const rawXml = await response.text();

  let doc = null;
  try {
    doc = xmlParser.parse(rawXml);
  } catch (_err) {
    doc = null; // Non-XML body — fall through to status handling below.
  }

  const responseNode = doc && typeof doc === 'object' ? doc.response : null;

  // PAN-OS signals application-level failures via <response status="error"> — often
  // alongside a non-2xx HTTP status (e.g. 403 for a bad key). Check the XML status
  // first so the thrown error carries the firewall's own message, not just an HTTP code.
  if (responseNode && String(responseNode['@_status']).toLowerCase() === 'error') {
    const msg =
      extractErrorMessage(responseNode.msg !== undefined ? responseNode.msg : responseNode.result) ||
      `error code ${responseNode['@_code'] !== undefined ? responseNode['@_code'] : 'unknown'}`;
    throw new Error(`PAN-OS API error (${endpointLabel}): ${redactKey(msg, apiKey)}`);
  }

  if (!response.ok) {
    const snippet = rawXml ? rawXml.slice(0, 300) : '(empty body)';
    throw new Error(
      `PAN-OS API request failed with HTTP ${response.status} (${endpointLabel}): ${redactKey(snippet, apiKey)}`
    );
  }

  if (!responseNode || typeof responseNode !== 'object') {
    const snippet = rawXml ? rawXml.slice(0, 300) : '(empty body)';
    throw new Error(
      `PAN-OS API returned an unexpected non-XML/unwrapped body (${endpointLabel}): ${redactKey(snippet, apiKey)}`
    );
  }

  return {
    raw: rawXml,
    response: responseNode,
    result: responseNode.result !== undefined ? responseNode.result : null,
  };
}

// op: show system info — connectivity check + version/model source.
// Returns the parsed <result> node ({ system: { 'sw-version': ..., model: ..., ... } }).
async function showSystemInfo(conn) {
  const { result } = await panRequest(conn, {
    type: 'op',
    cmd: '<show><system><info></info></system></show>',
  });
  return result;
}

// config get: security rulebase for the default vsys.
// Returns the parsed <result> node ({ rules: { entry: <object or array> } }).
async function getSecurityRules(conn) {
  const { result } = await panRequest(conn, {
    type: 'config',
    action: 'get',
    xpath: SECURITY_RULES_XPATH,
  });
  return result;
}

// op: show config running — full running config snapshot.
// Returns { raw: <full response XML string>, result: <parsed <result> node, whose
// .config child is the config tree root> }.
async function showRunningConfig(conn) {
  const { raw, result } = await panRequest(conn, {
    type: 'op',
    cmd: '<show><config><running></running></config></show>',
  });
  return { raw, result };
}

module.exports = {
  panRequest,
  showSystemInfo,
  getSecurityRules,
  showRunningConfig,
  DEFAULT_VSYS,
  SECURITY_RULES_XPATH,
};
