// lib/adapters/sophos/api.js
// CommonJS ONLY — required by ./index.js, which services/engine-worker.js
// require()s under plain node.
//
// Low-level Sophos SFOS XML API client. Pure HTTP — no DB, no credStore here.
//
// ⛔ EVERY SHAPE BELOW WAS READ OFF A LIVE APPLIANCE (SFOS 22.0.3
// MR-3-Build576, 2026-11-19), not from Sophos documentation. Entity names were
// discovered by PROBING 38 candidates and recording which answered — 24 are
// real, 11 return code 529. Evidence: secvault-lab/findings/API-SHAPES.md.
//
// SFOS XML API basics:
//   - Single endpoint: https://<host>:4444/webconsole/APIController?reqxml=<xml>
//   - ⛔ THE CREDENTIALS TRAVEL INSIDE THE REQUEST BODY, not in a header:
//       <Request><Login><Username>..</Username><Password>..</Password></Login>
//         <Get><FirewallRule/></Get></Request>
//   - Every response is XML: <Response APIVersion=".." IPS_CAT_VER=".." ..>
//
// ⛔ SECURITY — READ BEFORE TOUCHING ANY ERROR PATH IN THIS FILE.
// Because the password is inside `reqxml`, it is inside the REQUEST URL. This
// is the same hazard lib/adapters/paloalto/api.js documents and has already
// been burned by once: node-fetch@2 embeds the full request URL in its error
// messages, and adapter errors surface in BOTH engine.log and the
// /api/devices/[id]/test HTTP response body. A raw error string escaping this
// module is therefore a credential disclosure. EVERY string that leaves here
// passes through redactSecrets().
//
// ⛔ GET is used because GET is what was VERIFIED against the live appliance.
// POST with a form body would keep the secret out of the URL entirely and is
// the better shape — but it is UNVERIFIED, and this file's whole discipline is
// that an unverified assumption about a device is worth less than a measured
// one plus a guard. If POST is ever confirmed, move to it and this comment
// becomes the reason why.

const https = require('https');
// See the long note in paloalto/api.js: Next.js's bundler resolves node-fetch's
// "module" field even for a plain require(), so the callable lives at .default.
const fetchModule = require('node-fetch');
const fetch = fetchModule.default || fetchModule;
const { XMLParser } = require('fast-xml-parser');

const REQUEST_TIMEOUT_MS = 30000;
// `<Get><ApplicationFilterPolicy/></Get>` measured at 305 KB on a DEFAULT
// appliance with nothing configured. node-fetch's timeout covers the body read,
// so a config pull needs its own budget.
const CONFIG_REQUEST_TIMEOUT_MS = 120000;

const DEFAULT_PORT = 4444;

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  // ⛔ A single <FirewallRule> must still arrive as an ARRAY. fast-xml-parser
  // collapses a one-element list to a bare object by default, and a rulebase
  // with exactly one rule is a real, common state on a new appliance — code
  // that then iterates it would read its KEYS as rules.
  isArray: (name, jpath) => /^Response\.[A-Za-z]+$/.test(jpath) && name !== 'Login',
});

function secretForms(secret) {
  if (typeof secret !== 'string' || secret === '') return [];
  const forms = new Set([secret, encodeURIComponent(secret)]);
  // XML-escaped, because the secret is embedded in an XML document before it
  // is URL-encoded — a password containing & or < appears in a third form.
  forms.add(secret.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'));
  return [...forms].filter((f) => f.length >= 3);
}

/**
 * ⛔ Strips both the named secrets AND the whole reqxml parameter.
 *
 * The parameter scrub is the belt-and-braces half and it matters: it removes
 * the credential even for a password this function was not told about, which is
 * the case that bites — an error thrown from a path where the caller forgot to
 * pass the secret through.
 */
function redactSecrets(text, secrets) {
  if (!text) return text;
  let out = String(text).replace(/([?&]reqxml=)[^\s&]*/gi, '$1***');
  // The whole XML body, in case it reaches an error unencoded.
  out = out.replace(/<Password>[\s\S]*?<\/Password>/gi, '<Password>***</Password>');
  for (const secret of Array.isArray(secrets) ? secrets : [secrets]) {
    for (const form of secretForms(secret)) out = out.split(form).join('***');
  }
  return out;
}

function xmlEscape(v) {
  return String(v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function buildRequest({ username, password, inner }) {
  return '<Request>'
    + `<Login><Username>${xmlEscape(username)}</Username>`
    + `<Password>${xmlEscape(password)}</Password></Login>`
    + inner
    + '</Request>';
}

/**
 * ⛔ THREE RESPONSE SHAPES, AND ONLY ONE IS AN ERROR. The discriminator is the
 * PRESENCE OF A `code` ATTRIBUTE, which is subtle and load-bearing:
 *
 *   1. ERROR          <Status code="529">Input request module is Invalid</Status>
 *   2. GENUINE EMPTY  <Status>No. of records Zero.</Status>     <- NO code attribute
 *   3. DATA           <FirewallRule>...</FirewallRule>
 *
 * Shape 2 is a real, empty ruleset. Shape 1 is a failed read. Collapsing them
 * is precisely the getRules()-must-throw-never-return-[] boundary: an error
 * read as an empty list makes collectAndStore DELETE a device's real rulebase.
 */
const EMPTY_RECORDSET = /no\.?\s*of\s*records\s*zero/i;

function statusOf(node) {
  if (!node || typeof node !== 'object') return null;
  let st = node.Status;
  if (st === undefined || st === null) return null;
  // ⛔ The isArray rule above wraps every direct child of <Response> in an
  // array, INCLUDING <Status>. Without this unwrap the most likely real-world
  // first failure — code 532, "You need to enable the API Configuration",
  // which is what a freshly installed appliance returns — was reported as
  // "returned no Login block" instead of naming the cause the operator has to
  // fix. It still threw, so nothing unsafe followed; it simply sent them
  // looking in the wrong place.
  if (Array.isArray(st)) {
    if (st.length === 0) return null;
    st = st[0];
  }
  if (typeof st === 'object' && !Array.isArray(st)) {
    const code = st['@_code'];
    const text = st['#text'] !== undefined ? String(st['#text']) : '';
    return { code: code === undefined ? null : String(code), text };
  }
  return { code: null, text: String(st) };
}

/** True when the node is the device saying "this collection is empty". */
function isEmptyRecordset(node) {
  const st = statusOf(node);
  return Boolean(st && st.code === null && EMPTY_RECORDSET.test(st.text));
}

/**
 * ⛔ A PER-ENTITY FAILURE NESTS INSIDE A SUCCESSFUL LOGIN, so status must be
 * checked at BOTH levels — verified live:
 *
 *   <Login><status>Authentication Successful</status></Login>
 *   <Licence><Status code="529">Input request module is Invalid</Status></Licence>
 *
 * ...and the whole thing arrives as HTTP 200. An adapter checking only the HTTP
 * code reads this as success and then parses zero rules out of it.
 */
function assertLogin(response) {
  const login = response && response.Login;
  const text = login && (login.status !== undefined ? String(login.status) : '');
  if (!login) {
    const st = statusOf(response);
    if (st && st.code) throw new Error(`SFOS API refused the request (code ${st.code}): ${st.text}`);
    throw new Error('SFOS API returned no Login block — the response was not recognised.');
  }
  if (!/successful/i.test(text)) {
    // ⛔ Never echo the credential, and never echo the request. The device's own
    // wording is enough to tell an operator what to fix.
    throw new Error(`SFOS API authentication failed: ${text || 'no reason given'}`);
  }
}

/**
 * Fetch one entity.
 * @returns {{ records: object[], empty: boolean, apiVersion: string|null, ipsCatVer: string|null }}
 *   `empty: true` means the DEVICE said the collection is empty — a measurement.
 *   An error throws. The two are never conflated.
 */
/**
 * ⛔ EXTRACTED SO IT CAN BE EXERCISED. Every decision that distinguishes a
 * failed read from an empty collection lives here, in a pure function that
 * takes already-parsed XML — because the only place this is dangerous is
 * exactly the place a live test cannot easily reach. This repo has twice
 * watched a guard that could only be asserted against its own source text pass
 * over an inverted condition.
 *
 * @returns {{ records: object[], empty: boolean, apiVersion: string|null, ipsCatVer: string|null }}
 *   `empty: true` means the DEVICE said the collection is empty — a
 *   measurement. A failed read THROWS. The two are never conflated.
 */
function interpretResponse(body, entity) {
  const response = body && body.Response;
  if (!response) throw new Error('SFOS API returned no <Response> element.');
  assertLogin(response);

  const apiVersion = response['@_APIVersion'] !== undefined ? String(response['@_APIVersion']) : null;
  const ipsCatVer = response['@_IPS_CAT_VER'] !== undefined ? String(response['@_IPS_CAT_VER']) : null;

  const node = response[entity];
  if (node === undefined || node === null) {
    // ⛔ The entity was not echoed back at all. That is NOT an empty
    // collection — it is a read that did not happen, and it must never become
    // []. collectAndStore DELETEs a device's firewall_rules before reinserting.
    const st = statusOf(response);
    throw new Error(
      `SFOS API returned no <${entity}> element${st && st.code ? ` (code ${st.code}: ${st.text})` : ''}.`
    );
  }

  const list = Array.isArray(node) ? node : [node];

  for (const item of list) {
    const st = statusOf(item);
    if (st && st.code) {
      throw new Error(`SFOS API could not read ${entity} (code ${st.code}): ${st.text}`);
    }
  }
  if (list.length === 1 && isEmptyRecordset(list[0])) {
    return { records: [], empty: true, apiVersion, ipsCatVer };
  }
  return { records: list, empty: false, apiVersion, ipsCatVer };
}

/** Parse a raw SFOS XML response body. Exposed so tests start from BYTES. */
function parseXml(text) {
  return xmlParser.parse(text);
}

async function getEntity(conn, entity, { timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
  const reqxml = buildRequest({
    username: conn.username,
    password: conn.password,
    inner: `<Get><${entity}/></Get>`,
  });
  return interpretResponse(await request(conn, reqxml, timeoutMs), entity);
}

async function request(conn, reqxml, timeoutMs) {
  const port = conn.port || DEFAULT_PORT;
  const base = `https://${conn.host}:${port}/webconsole/APIController`;
  const url = `${base}?reqxml=${encodeURIComponent(reqxml)}`;
  const agent = new https.Agent({
    // CLAUDE.md: `rejectUnauthorized: allowSelfSignedSsl === false`, used
    // identically by every vendor adapter. Backwards here starts failing TLS on
    // every self-signed appliance, which is all of them by default.
    rejectUnauthorized: conn.allowSelfSignedSsl === false,
  });

  let res;
  try {
    res = await fetch(url, { method: 'GET', agent, timeout: timeoutMs });
  } catch (err) {
    throw new Error(`SFOS API request failed: ${redactSecrets(err.message, [conn.password])}`);
  }
  if (!res.ok) {
    throw new Error(`SFOS API returned HTTP ${res.status} ${redactSecrets(res.statusText, [conn.password])}`);
  }

  let text;
  try {
    text = await res.text();
  } catch (err) {
    throw new Error(`SFOS API response could not be read: ${redactSecrets(err.message, [conn.password])}`);
  }

  try {
    return xmlParser.parse(text);
  } catch (err) {
    // ⛔ The body is redacted too: on an unexpected failure the appliance can
    // echo the request back, and the request contains the password.
    throw new Error(
      `SFOS API response was not valid XML: ${redactSecrets(err.message, [conn.password])}`
    );
  }
}

module.exports = {
  getEntity,
  interpretResponse,
  parseXml,
  assertLogin,
  redactSecrets,
  buildRequest,
  statusOf,
  isEmptyRecordset,
  xmlEscape,
  DEFAULT_PORT,
  REQUEST_TIMEOUT_MS,
  CONFIG_REQUEST_TIMEOUT_MS,
};
