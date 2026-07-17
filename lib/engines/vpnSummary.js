// lib/engines/vpnSummary.js
//
// Vendor-agnostic VPN config summary, read from device_configs.config_parsed
// -- NOT vendor-specific adapter code. Each vendor's config_parsed shape is
// wildly different (curated named sections for Fortinet, a hand-picked flat
// object for Cisco ASA/Sangfor, the full raw config tree for Palo Alto), so
// this is a single place that knows how to interpret each one for VPN
// purposes, kept separate from the adapters themselves (which only ever
// collect/store data -- see CLAUDE.md "Adapters implement ONLY the
// FirewallAdapter interface" for the same boundary applied to the shared
// collectAndStore pipeline).
//
// Pure, no DB, no I/O -- CommonJS, required by both API routes and server
// component pages.

'use strict';

// ---------------------------------------------------------------------------
// Fortinet — ssl_vpn is a flat {key: value} settings object, always present
// as its own top-level config_parsed key on BOTH transports (see
// lib/adapters/fortinet/{cliParser,index}.js's getConfig()). 'source-
// interface' presence is used as the "actively bound to a listening
// interface" signal -- the same field the fortinet-sslvpn-not-wan-exposed
// compliance check (lib/auditChecksSeed.js) already relies on as grounded/
// real, rather than inventing a separate enabled/disabled heuristic this
// module isn't confident about.
// ---------------------------------------------------------------------------
function summarizeFortinet(configParsed) {
  const sslVpn = configParsed && configParsed.ssl_vpn;
  if (!sslVpn || typeof sslVpn !== 'object' || Object.keys(sslVpn).length === 0) {
    return { supported: true, hasConfig: false, fields: {} };
  }
  return {
    supported: true,
    hasConfig: true,
    sourceInterface: sslVpn['source-interface'] || null,
    port: sslVpn.port || null,
    idleTimeout: sslVpn['idle-timeout'] || null,
    minTlsVersion: sslVpn['ssl-min-proto-ver'] || null,
    fields: sslVpn,
  };
}

// ---------------------------------------------------------------------------
// Cisco ASA — parsed.webvpn.{enabled, enabled_interface}, a real boolean
// built by lib/adapters/cisco_asa/parser.js's minimal WebVPN detection
// (2026-07-19). No further fields modeled -- see that file's own comment
// for why tunnel-group/group-policy/anyconnect-image parsing is explicitly
// out of scope for now.
// ---------------------------------------------------------------------------
function summarizeCiscoAsa(configParsed) {
  const webvpn = configParsed && configParsed.webvpn;
  if (!webvpn) return { supported: true, hasConfig: false, fields: {} };
  return {
    supported: true,
    hasConfig: true,
    enabled: !!webvpn.enabled,
    sourceInterface: webvpn.enabled_interface || null,
    fields: webvpn,
  };
}

// ---------------------------------------------------------------------------
// Sangfor — parsed.sections.ssl_vpn.enabled is a TRI-STATE (true/false/null)
// -- see lib/adapters/sangfor/parser.js's own extensive low-confidence
// caveat (2026-07-19, doc-derived, never live-verified for this vendor --
// this codebase's least-verified adapter, per CLAUDE.md's Live Validation
// Status). null MUST render as "unknown", never coerced to false.
// ---------------------------------------------------------------------------
function summarizeSangfor(configParsed) {
  const sections = configParsed && configParsed.sections;
  const sslVpn = sections && sections.ssl_vpn;
  if (!sslVpn || sslVpn.enabled === undefined) {
    return { supported: true, hasConfig: false, fields: {}, lowConfidence: true };
  }
  return {
    supported: true,
    hasConfig: true,
    enabled: sslVpn.enabled, // true | false | null
    fields: sslVpn,
    lowConfidence: true, // always flagged for this vendor -- see parser.js's own caveat
  };
}

// ---------------------------------------------------------------------------
// Palo Alto (both SSH and XML/API transports) — the FULL config tree is
// already present in config_parsed: SSH under `.tree` (a brace-tree Node,
// {settings, blocks: {name: Node}, entries: [Node]} -- see
// lib/adapters/paloalto/sshParser.js's parseConfig()), XML/API spread
// directly at the top level (the raw parsed <config> tree -- see
// lib/adapters/paloalto/parser.js's parseConfig()). NEITHER transport
// needed an adapter change for this feature -- GlobalProtect config was
// already being collected, just never surfaced anywhere.
//
// No single fixed predicate path reliably finds it, though: PAN-OS config
// nesting varies (single-vsys root, vsys.entry, shared, Panorama pre/post-
// rulebase) -- the exact same structural variability CLAUDE.md documents
// findSecurityRulesContainers() having to search deep for security rules,
// for the identical reason. So this does a bounded deep search for a key
// whose name contains "global-protect"/"globalprotect" (case-insensitive),
// rather than assuming one exact path. This is a UI-layer concern, free to
// search deeply -- the compliance predicate engine (evaluatePredicate(),
// exactly one fixed dot-path per check) could NOT do this safely, which is
// why no Palo Alto GlobalProtect compliance check was added alongside this
// -- a deliberate, documented scope decision (see CLAUDE.md), not an
// oversight.
// ---------------------------------------------------------------------------
const GLOBAL_PROTECT_PATTERN = /global.?protect/i;
const MAX_SEARCH_DEPTH = 8;

function deepFindKeyByPattern(obj, pattern, path, depth) {
  if (!obj || typeof obj !== 'object' || depth > MAX_SEARCH_DEPTH) return null;
  for (const [key, value] of Object.entries(obj)) {
    if (pattern.test(key)) {
      return { path: path ? `${path}.${key}` : key, value };
    }
  }
  for (const [key, value] of Object.entries(obj)) {
    if (value && typeof value === 'object') {
      const found = deepFindKeyByPattern(value, pattern, path ? `${path}.${key}` : key, depth + 1);
      if (found) return found;
    }
  }
  return null;
}

// settings {key: string[]} → {key: string|string[]} — same "unwrap single-
// token arrays" convention as lib/adapters/fortinet/cliParser.js's
// flattenSettings(), applied here to a Palo Alto brace-tree Node instead.
function flattenNodeSettings(node) {
  if (!node || typeof node !== 'object' || !node.settings) return {};
  const out = {};
  for (const [key, tokens] of Object.entries(node.settings)) {
    out[key] = Array.isArray(tokens) ? (tokens.length === 1 ? tokens[0] : tokens) : tokens;
  }
  return out;
}

function deepFindBlockInTree(node, pattern, path, depth) {
  if (!node || typeof node !== 'object' || depth > MAX_SEARCH_DEPTH) return null;
  for (const [name, child] of Object.entries(node.blocks || {})) {
    if (pattern.test(name)) return { path: path ? `${path}.${name}` : name, node: child };
  }
  for (const [name, child] of Object.entries(node.blocks || {})) {
    const found = deepFindBlockInTree(child, pattern, path ? `${path}.${name}` : name, depth + 1);
    if (found) return found;
  }
  for (const entry of node.entries || []) {
    const found = deepFindBlockInTree(entry, pattern, path, depth + 1);
    if (found) return found;
  }
  return null;
}

function summarizePaloAlto(configParsed) {
  if (!configParsed || typeof configParsed !== 'object') {
    return { supported: true, hasConfig: false, fields: {} };
  }

  // SSH transport: search the brace-tree's .blocks (Node shape), not plain
  // object walking -- .settings/.entries aren't meaningful search targets
  // for finding a BLOCK by name.
  if (configParsed.tree && typeof configParsed.tree === 'object') {
    const found = deepFindBlockInTree(configParsed.tree, GLOBAL_PROTECT_PATTERN, '', 0);
    if (found) {
      return { supported: true, hasConfig: true, foundAt: found.path, fields: flattenNodeSettings(found.node) };
    }
    return { supported: true, hasConfig: false, fields: {} };
  }

  // XML/API transport: configParsed itself is (roughly) the raw parsed
  // tree -- generic object/array deep search for the same key pattern.
  const found = deepFindKeyByPattern(configParsed, GLOBAL_PROTECT_PATTERN, '', 0);
  if (found) {
    return { supported: true, hasConfig: true, foundAt: found.path, fields: found.value };
  }
  return { supported: true, hasConfig: false, fields: {} };
}

// ---------------------------------------------------------------------------
// Dispatch — any vendor not listed here (e.g. Check Point) has no VPN config
// collection at all yet: `supported: false` renders distinctly in the UI
// from `supported: true, hasConfig: false` ("collected, and it's genuinely
// empty") -- the two are different facts and must not look the same.
// ---------------------------------------------------------------------------
const SUMMARIZERS = {
  fortinet: summarizeFortinet,
  cisco_asa: summarizeCiscoAsa,
  sangfor: summarizeSangfor,
  paloalto: summarizePaloAlto,
};

/**
 * @param {string} vendor
 * @param {object|null} configParsed - device_configs.config_parsed (latest row)
 * @returns {{supported: boolean, hasConfig: boolean, enabled?: boolean|null,
 *   sourceInterface?: string|null, port?: string|null, idleTimeout?: string|null,
 *   minTlsVersion?: string|null, foundAt?: string, fields: object,
 *   lowConfidence?: boolean, error?: boolean}}
 */
function summarizeVpnConfig(vendor, configParsed) {
  const fn = SUMMARIZERS[vendor];
  if (!fn) return { supported: false, hasConfig: false, fields: {} };
  try {
    return fn(configParsed);
  } catch (err) {
    // Never let a malformed/unexpected config_parsed shape throw up into an
    // API route or page render -- degrade to "collected but unreadable",
    // same "never let 'unknown' collapse into a confident wrong answer,
    // but also never crash the page" discipline used throughout this app.
    console.warn(`[vpnSummary] Failed to summarize VPN config for vendor "${vendor}": ${err.message}`);
    return { supported: true, hasConfig: false, fields: {}, error: true };
  }
}

module.exports = { summarizeVpnConfig };
