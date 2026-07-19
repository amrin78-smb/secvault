// lib/adapters/forcepoint/smc.js
// CommonJS ONLY — required by lib/adapters/forcepoint/index.js, which in turn is
// required by services/engine-worker.js (plain node, CommonJS).
//
// Low-level SMC REST API client. Pure HTTP — no DB access, no credStore access here.
// See CLAUDE.md "Forcepoint SMC Integration" before changing anything in this file:
//   - NEVER SSH directly to Forcepoint engines. SMC REST API only, on :8082 by default.
//   - NEVER construct SMC URLs from element IDs. Always follow HATEOAS `href` values.
//   - NEVER assume SMC field names. Field names for engine version differ between
//     SMC 6.x and 7.x — log raw responses on first integration test.
//   - Most SMC instances use self-signed certs — accept them by default.

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

// Engine list is capped to mirror the same defensive cap CLAUDE.md documents for rule
// analysis (large environments have been seen with 50+ engines; cap prevents runaway
// pagination against a misbehaving or huge SMC instance).
const MAX_ENGINES = 100;

// Per-request timeout, matching the pattern every other adapter already uses
// (fortinet/checkpoint: 15000ms; paloalto: 30000/120000ms for its one large
// payload). Before this, smcRequest had NO timeout at all — a black-holed
// connection (packets silently dropped, as opposed to an actively refused one)
// falls back entirely on the OS's own TCP timeout, which can run for minutes.
// Test Connectivity / Collect Now surface this as a raw, un-enhanced form
// submission with zero pending UI (see DeviceActions.js), so an unbounded wait
// here reads to the user as "the whole app froze". node-fetch's `timeout`
// option covers connect AND body read, so this also bounds a slow/huge engine
// or rule-object list, not just a dead TCP handshake.
const REQUEST_TIMEOUT_MS = 15000;

let loggedFirstEngineElement = false;
let loggedFirstNetworkElement = false;
let loggedFirstServiceElement = false;

// conn shape used throughout this module: { smcHost, smcPort, apiKey, allowSelfSignedSsl }
async function smcRequest({ smcHost, smcPort, apiKey, allowSelfSignedSsl, path, method = 'GET' }) {
  const url = String(path).startsWith('http') ? path : `https://${smcHost}:${smcPort}${path}`;

  // Default: accept self-signed certs unless explicitly told not to.
  const agent = new https.Agent({ rejectUnauthorized: allowSelfSignedSsl === false });

  let response;
  try {
    response = await fetch(url, {
      method,
      agent,
      timeout: REQUEST_TIMEOUT_MS,
      headers: {
        'SMC-API-KEY': apiKey,
        Accept: 'application/json',
      },
    });
  } catch (err) {
    throw new Error(`SMC request failed (${url}): ${err.message}`);
  }

  const bodyText = await response.text();
  let body = null;
  if (bodyText) {
    try {
      body = JSON.parse(bodyText);
    } catch (_err) {
      // Non-JSON body — leave body as null, fall through to status handling below.
      body = null;
    }
  }

  if (!response.ok) {
    const status = response.status;
    if (status === 401) {
      throw new Error('SMC authentication failed — invalid API key');
    }
    if (status === 404) {
      throw new Error('SMC element not found');
    }
    if (status === 503) {
      throw new Error('SMC unavailable');
    }
    const snippet = bodyText ? bodyText.slice(0, 300) : '(empty body)';
    throw new Error(`SMC request failed with status ${status}: ${snippet}`);
  }

  return body;
}

// GET /api/ — connectivity + API version info.
async function getApiInfo(conn) {
  return smcRequest({ ...conn, path: '/api/' });
}

// Generic HATEOAS href follower.
async function getElement(conn, href) {
  return smcRequest({ ...conn, path: href });
}

// Follows paging.next hrefs, accumulating `result` entries, up to `cap` total.
// `cap` of 0/undefined means no cap.
async function fetchAllPages(conn, initialPath, { cap } = {}) {
  const items = [];
  let path = initialPath;
  let cappedWarned = false;

  while (path) {
    const page = await smcRequest({ ...conn, path });
    const pageItems = (page && page.result) || [];
    for (const item of pageItems) {
      if (cap && items.length >= cap) {
        if (!cappedWarned) {
          console.warn(
            `[SMC] Result list capped at ${cap} entries — environment has more than the cap allows.`
          );
          cappedWarned = true;
        }
        break;
      }
      items.push(item);
    }

    if (cap && items.length >= cap) break;

    const next = page && page.paging && page.paging.next;
    path = next || null;
  }

  return items;
}

// GET /api/elements/engines — follow pagination, cap at MAX_ENGINES, and fetch full
// element data for any summary-only entries (list responses often only carry
// name/type/href — full fields require following the href).
async function getEngines(conn) {
  const summaries = await fetchAllPages(conn, '/api/elements/engines', { cap: MAX_ENGINES });

  const engines = [];
  for (const summary of summaries) {
    let engineElement = summary;

    // Summary-only entry: only has a handful of fields plus an href. Fetch full element.
    const hasOnlySummaryFields =
      summary &&
      summary.href &&
      Object.keys(summary).filter((k) => k !== 'href' && k !== 'name' && k !== 'type').length === 0;

    if (hasOnlySummaryFields || (summary && summary.href && !summary.software_version && !summary.dynamic_package)) {
      try {
        engineElement = await getElement(conn, summary.href);
      } catch (err) {
        console.warn(`[SMC] Failed to fetch full engine element for ${summary.href}: ${err.message}`);
        engineElement = summary;
      }
    }

    if (!loggedFirstEngineElement) {
      // Per CLAUDE.md: field names for engine software version vary between SMC 6.x
      // and 7.x. Always log the raw element the first time we fetch one so parser.js
      // field mappings can be verified/adjusted against the live system. Logged
      // unconditionally here (not just on the href-follow path above) so a live SMC
      // whose list response already returns complete elements inline still gets this
      // mandatory first-connect verification log.
      console.log('[SMC Debug] Engine element:', JSON.stringify(engineElement, null, 2));
      loggedFirstEngineElement = true;
    }

    engines.push(engineElement);
  }

  return engines;
}

// Dual-purpose, matching how index.js's getRules() needs to use it:
//   - getPolicy(conn, href)  -> follow the HATEOAS href to a specific full policy element
//   - getPolicy(conn)        -> no href known yet; list /api/elements/fw_policy
//                               (paginated, same paging.next handling as getEngines)
//                               so the caller can pick an entry and follow its href.
async function getPolicy(conn, policyHref) {
  if (policyHref) {
    return getElement(conn, policyHref);
  }
  return fetchAllPages(conn, '/api/elements/fw_policy');
}

async function getNetworkElements(conn) {
  const elements = await fetchAllPages(conn, '/api/elements/network_elements');

  if (!loggedFirstNetworkElement && elements.length > 0) {
    // Per CLAUDE.md's "Live SMC field verification still pending" — the
    // network_elements sub-type shapes (host/network/address_range/group) used by
    // parser.parseAddressObjects() are doc-derived, never live-verified. Log the
    // first raw element the same way getEngines() already does for engine elements,
    // so the real field names can be confirmed/corrected on first live connect.
    console.log('[SMC Debug] network_elements sample:', JSON.stringify(elements[0], null, 2));
    loggedFirstNetworkElement = true;
  }

  return elements;
}

async function getServiceElements(conn) {
  const elements = await fetchAllPages(conn, '/api/elements/service_elements');

  if (!loggedFirstServiceElement && elements.length > 0) {
    // Same first-use verification convention as getNetworkElements() above, for
    // parser.parseServiceObjectCatalog()'s tcp_service/udp_service/service_group
    // classification.
    console.log('[SMC Debug] service_elements sample:', JSON.stringify(elements[0], null, 2));
    loggedFirstServiceElement = true;
  }

  return elements;
}

module.exports = {
  smcRequest,
  getApiInfo,
  getElement,
  getEngines,
  getPolicy,
  getNetworkElements,
  getServiceElements,
};
