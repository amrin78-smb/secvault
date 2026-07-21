// lib/engines/snmpConfigDetection.js
//
// Vendor-agnostic "does this device's already-collected config show SNMP
// enabled?" detector — presence/enabled-STATE only, never the actual
// community string or SNMPv3 credentials. Mirrors lib/engines/vpnSummary.js's
// shape and conventions exactly (pure, no DB, no I/O, one summarizer
// function per vendor, dispatched by vendor slug) — same architectural
// family as that file and lib/engines/adminAccountSummary.js: read-only
// interpretation of device_configs.config_parsed, kept out of the adapters
// themselves.
//
// Why this is safe to build at all: for both vendors below, the actual
// SNMP secret is either never collected in the first place (Fortinet only
// ever fetches the global agent status object, never the separate
// community-string table) or is ALREADY redacted to '<redacted>' before
// config_parsed is ever built (Palo Alto — both transports construct
// `parsed` FROM the already-redacted raw text/response, see
// lib/adapters/paloalto/index.js's `parser.parseConfig(redactedConfigResult,
// ...)` and CLAUDE.md's "Security note for parseConfig()"). This module
// never needs its own redaction pass because there is nothing left to leak
// by the time it runs — it was NOT built by loosening any existing secret
// boundary.
//
// CommonJS, required by server component pages (same convention as
// vpnSummary.js).

'use strict';

const MAX_SEARCH_DEPTH = 8;

// Same bounded deep-search helper as vpnSummary.js's GlobalProtect
// detection (duplicated, not imported — that file documents its own reason
// for existing independently per format/vendor; this one is small enough
// that duplicating it here is simpler than adding a shared-helpers module
// for one function).
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

// ---------------------------------------------------------------------------
// Fortinet — config_parsed.snmp is `system snmp sysinfo`'s flattened
// settings object, already collected on BOTH transports with no new adapter
// work (REST: api.getSnmpSysinfo(); SSH: cliParser.js's
// settingsOfFirst('system snmp sysinfo')) — see lib/adapters/fortinet/
// index.js's getConfig() `sections` array. `status` is FortiOS's own bare
// 'enable'/'disable' vocabulary, the same convention already confirmed live
// for other Fortinet sections (CLAUDE.md's Compliance Engine notes on
// fortinet-logging-enabled etc.) — doc-derived for THIS specific field,
// flagged accordingly, but the vocabulary itself is grounded.
//
// This adapter never fetches the separate `system snmp community` table
// (the actual secret) — only this global agent-status object — so there is
// nothing secret-shaped in `fields` to worry about.
// ---------------------------------------------------------------------------
function detectFortinet(configParsed) {
  const snmp = configParsed && configParsed.snmp;
  if (!snmp || typeof snmp !== 'object' || Object.keys(snmp).length === 0) {
    return { supported: true, hasConfig: false, enabled: null, fields: {} };
  }
  const status = typeof snmp.status === 'string' ? snmp.status.toLowerCase() : null;
  const enabled = status === 'enable' ? true : status === 'disable' ? false : null;
  return { supported: true, hasConfig: true, enabled, foundAt: 'snmp.status', fields: snmp };
}

// ---------------------------------------------------------------------------
// Palo Alto (both SSH and XML/API transports) — the real PAN-OS path is
// `deviceconfig system snmp-setting ...`, confirmed via this codebase's OWN
// existing secret-redaction lists (lib/adapters/paloalto/parser.js's
// SECRET_TAGS and sshParser.js's SECRET_TOKENS both already target
// `snmp-community-string` at exactly this path — not a fresh guess for this
// feature). Uses the same bounded deep-search + root-resolution
// (SSH: `.tree`; XML/API: spread at top level) as vpnSummary.js's
// GlobalProtect detection, for the identical "PAN-OS config nesting varies
// by platform/Panorama-vs-standalone" reason documented there — a fixed
// dot-path is not safe here even though the canonical block NAME is known.
//
// PAN-OS has no single explicit enable/disable toggle for SNMP the way
// FortiOS's `status` field is — the snmp-setting block's mere PRESENCE
// (with a version/community configured under it) is the closest available
// signal. Reported as `enabled: null` (genuinely not modeled) rather than
// guessing `true`, with `hasConfig: true` carrying the real "something is
// configured here" fact — same tri-state honesty this app applies
// everywhere else (see CLAUDE.md's applicability tri-state rule).
// `lowConfidence: true` always, matching this vendor's SNMP-metrics
// treatment elsewhere in this app.
// ---------------------------------------------------------------------------
const PALOALTO_SNMP_PATTERN = /snmp-setting/i;

function detectPaloAlto(configParsed) {
  if (!configParsed || typeof configParsed !== 'object') {
    return { supported: true, hasConfig: false, enabled: null, fields: {} };
  }
  const root = configParsed.tree && typeof configParsed.tree === 'object' ? configParsed.tree : configParsed;
  const found = deepFindKeyByPattern(root, PALOALTO_SNMP_PATTERN, '', 0);
  if (!found) {
    return { supported: true, hasConfig: false, enabled: null, fields: {} };
  }
  return {
    supported: true,
    hasConfig: true,
    enabled: null,
    foundAt: found.path,
    fields: found.value,
    lowConfidence: true,
  };
}

// ---------------------------------------------------------------------------
// Dispatch — any vendor not listed here (Cisco ASA, Check Point, Forcepoint,
// Sangfor as of 2026-07-21) has no SNMP config-presence detection yet:
// `supported: false` renders distinctly from `supported: true, hasConfig:
// false` ("checked, and it's genuinely not there") — same distinction
// vpnSummary.js already makes. A natural per-vendor follow-up, not built now.
// ---------------------------------------------------------------------------
const DETECTORS = {
  fortinet: detectFortinet,
  paloalto: detectPaloAlto,
};

/**
 * @param {string} vendor
 * @param {object|null} configParsed - device_configs.config_parsed (latest row)
 * @returns {{supported: boolean, hasConfig: boolean, enabled: boolean|null,
 *   foundAt?: string, fields: object, lowConfidence?: boolean, error?: boolean}}
 */
function detectSnmpConfig(vendor, configParsed) {
  const fn = DETECTORS[vendor];
  if (!fn) return { supported: false, hasConfig: false, enabled: null, fields: {} };
  try {
    return fn(configParsed);
  } catch (err) {
    // Never let a malformed/unexpected config_parsed shape throw up into a
    // page render — degrade to "checked, nothing usable found", same
    // discipline as vpnSummary.js's own try/catch.
    console.warn(`[snmpConfigDetection] Failed to detect SNMP config for vendor "${vendor}": ${err.message}`);
    return { supported: true, hasConfig: false, enabled: null, fields: {}, error: true };
  }
}

// Convenience predicate for UI call sites: "should we show the 'looks
// already enabled, want to set up monitoring?' nudge?" — true when a
// config section was found AND it isn't explicitly reporting disabled
// (Fortinet's enabled === false case). Palo Alto's permanently-null
// `enabled` still counts as a positive signal here, since `hasConfig: true`
// already means a real snmp-setting block was found.
function looksConfigured(detected) {
  return Boolean(detected && detected.hasConfig && detected.enabled !== false);
}

module.exports = { detectSnmpConfig, looksConfigured };
