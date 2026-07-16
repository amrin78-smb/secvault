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
//   - PAN-OS natively mints an API key from a username+password:
//       GET /api/?type=keygen&user=<user>&password=<pass>
//       → <response status="success"><result><key>...</key></result></response>
//     This is a first-class PAN-OS auth mode, not a shim.
//   - Every response is XML: <response status="success|error">...</response>.
//     status="error" carries the failure text in <msg> (string, <line> child, or a
//     list of <line> children depending on the error) — always surface it.
//
// ⛔ SECURITY — READ BEFORE TOUCHING ANY ERROR PATH IN THIS FILE.
// PAN-OS passes secrets as URL QUERY PARAMS: the API key as `key=`, and — on the
// keygen call — the operator's PASSWORD as `password=`. node-fetch@2 embeds the
// FULL request URL in its error messages (both connect errors and body-read
// errors), and adapter errors surface in BOTH engine.log and the
// /api/devices/[id]/test HTTP response body. A raw error string escaping this
// module is therefore a credential disclosure. This has already happened once in
// this exact file (body-read errors leaked ?...&key=<APIKEY>) and was fixed.
// EVERY string that leaves this module as an error MUST pass through
// redactSecrets() with the relevant secrets. On the keygen path the response body
// itself IS a credential (it contains the freshly minted key), so it is NEVER
// echoed into an error message at all.

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

// Short op calls (`show system info`, keygen) — these answer in well under a second
// on a healthy device; the budget is for a slow/lossy WAN, not for a big payload.
// Raised from the original 15s: node-fetch's `timeout` covers the BODY read too, so
// this value doubles as a payload budget. A longer timeout can only make a working
// call keep working — it never breaks one.
const REQUEST_TIMEOUT_MS = 30000;

// `show config running` returns the entire running config (multi-MB on a large
// firewall). 15s was demonstrably too tight for that over a WAN — the body-read
// would time out and the pull would look like a device failure.
const CONFIG_REQUEST_TIMEOUT_MS = 120000;

// The default single-vsys rulebase location.
//
// NOTE on 'localhost.localdomain': that is PAN-OS's FIXED internal name for the
// device entry in the config tree — it is not the hostname and does not change when
// the device is renamed. It is correct for a standalone firewall. What it does NOT
// cover is a multi-vsys device (vsys2, vsys3, ...), where this xpath resolves to
// nothing and PAN-OS answers `<response status="success"><result/></response>` —
// indistinguishable from "the rulebase is empty" unless we look wider. Hence the
// any-vsys fallback below, used by index.js only when this xpath yields zero rules.
const DEFAULT_VSYS = 'vsys1';

const SECURITY_RULES_XPATH =
  "/config/devices/entry[@name='localhost.localdomain']" +
  `/vsys/entry[@name='${DEFAULT_VSYS}']/rulebase/security/rules`;

// Predicate-free xpath: every device entry, every vsys. Used ONLY as a fallback
// when SECURITY_RULES_XPATH returns nothing, so it cannot regress the working
// single-vsys path. The response shape for a multi-node match is not verified
// against a live device — parser.parseRulesDeep() deep-walks the result for
// security rulebases rather than assuming a shape.
const SECURITY_RULES_XPATH_ANY_VSYS = '/config/devices/entry/vsys/entry/rulebase/security/rules';

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
    // Bad-credential keygen replies nest one level deeper:
    //   <response status="error" code="403"><result><msg>Invalid credentials.</msg></result></response>
    // so the caller passes result and the readable text is at result.msg.
    if (msg.msg !== undefined) return extractErrorMessage(msg.msg);
    if (msg['#text'] !== undefined) return extractErrorMessage(msg['#text']);
    try {
      return JSON.stringify(msg).slice(0, 300);
    } catch (_err) {
      return null;
    }
  }
  return null;
}

// Every wire form one secret can take in an error string.
//
// A secret reaches an error message via the request URL, so it may appear
// percent-/form-encoded rather than literally. URLSearchParams (used to build the
// URL below) serializes as application/x-www-form-urlencoded, which is NOT the same
// as encodeURIComponent: space becomes '+' not '%20', and !'()~ get escaped. PAN-OS
// API keys are base64 so those forms usually coincide — but a human-chosen PASSWORD
// routinely contains spaces and punctuation, where they very much do not. Redaction
// must not depend on the two forms coinciding.
//
// Empty/non-string secrets are skipped: ''.split('') would splice the redaction
// marker between every character of the message. parseApiCredential() accepts an
// empty password (a stored {"username":"u","password":""}), so this guard is
// reachable, not theoretical.
function secretForms(secret) {
  if (typeof secret !== 'string' || secret === '') return [];
  const forms = new Set([secret]);
  try {
    forms.add(new URLSearchParams({ k: secret }).toString().slice(2));
  } catch (_err) {
    /* non-encodable — the literal form below still applies */
  }
  try {
    forms.add(encodeURIComponent(secret));
  } catch (_err) {
    /* lone surrogate etc. — ignore */
  }
  return Array.from(forms).filter((f) => typeof f === 'string' && f !== '');
}

// Scrubs the VALUE of every secret-bearing query parameter, keyed on the parameter
// NAME rather than on the secret's text.
//
// This is the load-bearing defence, and it is deliberately independent of
// secretForms() above. Literal matching can only redact encodings we predicted; if
// node-fetch (or WHATWG URL normalisation inside it) ever re-encodes the query
// differently from how URLSearchParams wrote it, a literal match silently misses
// and the secret ships. Anchoring on `key=` / `password=` / `user=` cannot miss,
// because the parameter name is ours and is not subject to re-encoding.
//
// The value charset is bounded by the x-www-form-urlencoded serializer to
// [A-Za-z0-9*-._+%], so stopping at &, whitespace, quotes, <>, ) or ] can never
// truncate a value early and leave a tail of it exposed.
function scrubUrlSecretParams(text) {
  return String(text).replace(/([?&](?:key|password|user)=)[^&\s"'<>)\]]*/gi, '$1***');
}

// Redacts every given secret from any string that might end up in a thrown error
// message (node-fetch error messages embed the full request URL, secrets included).
// EVERY error string leaving this module must pass through this — see the SECURITY
// block at the top of the file.
function redactSecrets(text, secrets) {
  if (!text) return text;
  let out = scrubUrlSecretParams(text);
  for (const secret of Array.isArray(secrets) ? secrets : [secrets]) {
    for (const form of secretForms(secret)) {
      out = out.split(form).join('***');
    }
  }
  return out;
}

// Back-compat alias for the single-secret (API key) case.
function redactKey(text, apiKey) {
  return redactSecrets(text, [apiKey]);
}

// The shared, hardened request core. Both the API-key path (panRequest) and the
// keygen path (generateApiKey) go through this — there is exactly ONE place where a
// PAN-OS error string is built, so the redaction rules cannot drift apart between
// the two.
//
// @param {{host, port, allowSelfSignedSsl}} conn
// @param {object} params  query params for the single /api/ endpoint. Whatever the
//                         caller puts here (key=, password=) is URL-encoded and sent.
// @param {{secrets: string[], timeoutMs?: number, echoBody?: boolean}} opts
//   secrets   — every secret present in `params`; redacted from every error string.
//   echoBody  — when false, response bodies are NEVER quoted in an error message.
//               Used by keygen, whose response body IS a credential.
// Returns { raw, response: <parsed <response> node>, result: <parsed <result> or null> }.
async function panFetchXml(conn, params, opts) {
  const { host, port, allowSelfSignedSsl } = conn || {};
  const { secrets = [], timeoutMs = REQUEST_TIMEOUT_MS, echoBody = true } = opts || {};

  const effectivePort = port || 443;
  // URLSearchParams URL-encodes every value, secrets included.
  const query = new URLSearchParams(params);
  const url = `https://${host}:${effectivePort}/api/?${query.toString()}`;
  // The label is built from non-secret parts only — never from `url`.
  const endpointLabel = `https://${host}:${effectivePort}/api/ (type=${params && params.type ? params.type : '?'})`;

  // Every error message in this function funnels through here. No `throw new
  // Error(...)` below may interpolate an unsanitised string.
  const safe = (text) => redactSecrets(text, secrets);
  // Response-body snippet for diagnostics — withheld entirely when the body itself
  // is a credential (keygen).
  const bodySnippet = (rawXml) => {
    if (!echoBody) return '(response body withheld — it contains the generated API key)';
    return safe(rawXml ? rawXml.slice(0, 300) : '(empty body)');
  };

  // Default: accept self-signed certs unless explicitly told not to — same pattern
  // as the Forcepoint SMC client (most firewall mgmt interfaces are self-signed).
  const agent = new https.Agent({ rejectUnauthorized: allowSelfSignedSsl === false });

  let response;
  try {
    response = await fetch(url, {
      method: 'GET',
      agent,
      timeout: timeoutMs,
      headers: { Accept: 'application/xml' },
    });
  } catch (err) {
    // node-fetch FetchError: "request to <full url> failed, reason: connect ECONNREFUSED ..."
    throw new Error(`PAN-OS API request failed (${endpointLabel}): ${safe(err.message)}`);
  }

  // Reading the body is a SEPARATE failure domain from the fetch() call above and
  // needs its own redaction. node-fetch@2 embeds the full request URL — secrets and
  // all — in body-read errors:
  //   "Response timeout while trying to fetch <url> (over 30000ms)"  (body-timeout;
  //      the `timeout` option covers the body read too, which is why
  //      showRunningConfig() below raises it — a multi-MB config over a slow WAN
  //      genuinely exceeds the short-call budget)
  //   "Invalid response body while trying to fetch <url>: ..."       (system)
  //   "Could not create Buffer from response body for <url>: ..."    (system)
  // Left unwrapped, those propagate verbatim into engine.log and into the
  // /api/devices/[id]/test JSON response.
  let rawXml;
  try {
    rawXml = await response.text();
  } catch (err) {
    throw new Error(
      `PAN-OS API response body could not be read (${endpointLabel}): ${safe(err.message)}`
    );
  }

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
    // The firewall's OWN error text. Redacted too: PAN-OS echoes parts of the
    // request in some error bodies, so it is not safe to assume this is secret-free.
    const msg =
      extractErrorMessage(responseNode.msg !== undefined ? responseNode.msg : responseNode.result) ||
      `error code ${responseNode['@_code'] !== undefined ? responseNode['@_code'] : 'unknown'}`;
    throw new Error(`PAN-OS API error (${endpointLabel}): ${safe(msg)}`);
  }

  if (!response.ok) {
    throw new Error(
      `PAN-OS API request failed with HTTP ${response.status} (${endpointLabel}): ${bodySnippet(rawXml)}`
    );
  }

  if (!responseNode || typeof responseNode !== 'object') {
    throw new Error(
      `PAN-OS API returned an unexpected non-XML/unwrapped body (${endpointLabel}): ${bodySnippet(rawXml)}`
    );
  }

  return {
    raw: rawXml,
    response: responseNode,
    result: responseNode.result !== undefined ? responseNode.result : null,
  };
}

// conn shape used throughout this module: { host, port, apiKey, allowSelfSignedSsl }.
// params: query params for the single /api/ endpoint (e.g. { type: 'op', cmd: '...' });
// the key param is appended here — callers never handle the key directly.
// Returns { raw, response, result }.
async function panRequest(conn, params, { timeoutMs } = {}) {
  const { host, apiKey } = conn || {};
  if (!host) {
    throw new Error('PAN-OS API request failed: no management IP/host configured for device');
  }
  if (!apiKey) {
    throw new Error('PAN-OS API request failed: no API key provided');
  }

  return panFetchXml(conn, { ...params, key: apiKey }, {
    secrets: [apiKey],
    timeoutMs,
    echoBody: true,
  });
}

// Converts a username+password into a PAN-OS API key:
//   GET /api/?type=keygen&user=<user>&password=<pass>
//   → <response status="success"><result><key>...</key></result></response>
//
// ⛔ The PASSWORD travels in the URL query string, and the RESPONSE BODY is itself a
// credential. Both are handled accordingly:
//   - every error string is redacted with the password as a secret (literal forms +
//     the `password=` query-param scrub, see redactSecrets);
//   - echoBody:false means no response body is ever quoted into an error, so the
//     minted key cannot leak through the "unexpected body" / HTTP-status paths;
//   - the returned key is never logged here — callers hold it in memory only.
//
// conn: { host, port, username, password, allowSelfSignedSsl }
// → the API key string.
async function generateApiKey(conn) {
  const { host, port, username, password } = conn || {};
  if (!host) {
    throw new Error('PAN-OS keygen failed: no management IP/host configured for device');
  }
  if (!username) {
    throw new Error('PAN-OS keygen failed: no username provided');
  }
  if (typeof password !== 'string') {
    throw new Error('PAN-OS keygen failed: no password provided');
  }

  const endpointLabel = `https://${host}:${port || 443}/api/ (type=keygen)`;

  const { result } = await panFetchXml(
    conn,
    { type: 'keygen', user: username, password },
    // NOTE: username is in `secrets` as well. It is not a secret, but it costs
    // nothing and keeps an account name out of the /test HTTP response body.
    { secrets: [password, username], timeoutMs: REQUEST_TIMEOUT_MS, echoBody: false }
  );

  // <result><key>...</key></result>. fast-xml-parser gives a bare string here, or
  // { '#text': ... } if PAN-OS ever adds attributes to <key>; a fully numeric key
  // would parse as a number, hence String().
  const keyNode = result && typeof result === 'object' ? result.key : null;
  const rawKey =
    keyNode !== null && keyNode !== undefined && typeof keyNode === 'object'
      ? keyNode['#text']
      : keyNode;
  const key = rawKey === null || rawKey === undefined ? '' : String(rawKey).trim();

  if (!key) {
    // No body echo — see above. Report the SHAPE only.
    throw new Error(
      `PAN-OS keygen returned success but no <key> element (${endpointLabel}). ` +
        'The response body is withheld because it may contain a credential. ' +
        'Verify that this host is a PAN-OS firewall management interface and that ' +
        'the account is permitted XML API access.'
    );
  }

  return key;
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

// config get: security rulebase across EVERY device entry and EVERY vsys.
// Fallback only — see SECURITY_RULES_XPATH_ANY_VSYS. Feed the result to
// parser.parseRulesDeep(), not parser.parseRules(): the shape of a multi-node xpath
// match is not verified against live hardware.
async function getSecurityRulesAnyVsys(conn) {
  const { result } = await panRequest(conn, {
    type: 'config',
    action: 'get',
    xpath: SECURITY_RULES_XPATH_ANY_VSYS,
  });
  return result;
}

// op: show config running — full running config snapshot.
// Returns { raw: <full response XML string>, result: <parsed <result> node, whose
// .config child is the config tree root> }.
// Uses the long timeout: this is the one call whose body is genuinely large.
async function showRunningConfig(conn) {
  const { raw, result } = await panRequest(
    conn,
    { type: 'op', cmd: '<show><config><running></running></config></show>' },
    { timeoutMs: CONFIG_REQUEST_TIMEOUT_MS }
  );
  return { raw, result };
}

module.exports = {
  panRequest,
  generateApiKey,
  showSystemInfo,
  getSecurityRules,
  getSecurityRulesAnyVsys,
  showRunningConfig,
  DEFAULT_VSYS,
  SECURITY_RULES_XPATH,
  SECURITY_RULES_XPATH_ANY_VSYS,
  // exported for testing / reuse, not part of the documented contract
  redactSecrets,
  redactKey,
  extractErrorMessage,
};
