// lib/adapters/paloalto/index.js
// CommonJS ONLY — required (via the adapter registry) by services/engine-worker.js
// (plain node, CommonJS).
//
// Palo Alto PAN-OS adapter — talks to the firewall's XML API on the management
// interface (https://<mgmt_ip>:<port>/api/, key auth via `key` query param).
//
// Two auth modes, both first-class (see parseApiCredential in ../credentials.js for
// the stored plaintext forms):
//   - api_key            → used directly.
//   - username+password  → exchanged for an API key via PAN-OS's own
//                          ?type=keygen endpoint, then used identically. This is
//                          NOT a shim: keygen is how PAN-OS itself issues keys.
//   - a bare non-JSON string → legacy raw API key (backward compat, still works).
//
// See CLAUDE.md — in particular the Pool Warning: testConnectivity() and any function
// touching credStore/DB must always receive and use `this.pool`, even though it looks
// like a pure connectivity check. Removing pool builds clean and breaks silently at
// runtime.

const { FirewallAdapter } = require('../interface');
const credStore = require('../../credStore');
const { parseApiCredential } = require('../credentials');
const api = require('./api');
const parser = require('./parser');
const { PaloaltoSshAdapter } = require('./ssh');
const { getLatestConfigParsed } = require('../../engines/applicability');

// Per CLAUDE.md "External API Integrations": log the raw response the first time we
// see one so parser.js field mappings can be verified against the live device
// (the MVP was built without a live PAN-OS firewall).
let loggedFirstSystemInfo = false;

class PaloaltoAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
    // Keygen result cache, for the LIFE OF THIS ADAPTER INSTANCE only.
    //
    // collectAndStore() builds one adapter per device per collect and then calls
    // getVersion/getRules/getConfig on it — each of which calls _getConn(). Without
    // this, a single collect would hit ?type=keygen four times, putting the
    // password on the wire four times over.
    //
    // NOT persisted, deliberately: credStore/device_credentials is the only
    // credential store in this app (CLAUDE.md Security). The key dies with the
    // instance; the next collect mints a fresh one.
    this._apiKey = null;
    this._apiKeyPromise = null;
  }

  // Resolves the API key for this device: returned as-is when one is stored, or
  // minted from username+password via PAN-OS keygen.
  //
  // The in-flight PROMISE is cached, not just the result — getVersion/getRules/
  // getConfig can overlap, and caching only the resolved value would still allow
  // concurrent callers to each fire their own keygen. A failure clears the cache so
  // the next attempt retries rather than replaying a stale rejection.
  async _resolveApiKey() {
    if (this._apiKey) return this._apiKey;
    if (this._apiKeyPromise) return this._apiKeyPromise;

    this._apiKeyPromise = (async () => {
      const plaintext = await credStore.getCredential(this.device.id, 'rest_api', this.pool);
      if (!plaintext) {
        throw new Error(
          `No PAN-OS API credential found for device ${this.device.id} — save credentials before connecting.`
        );
      }

      // Never surfaces the plaintext in its errors — see ../credentials.js.
      const { apiKey, username, password } = parseApiCredential(plaintext, 'PAN-OS device');

      if (apiKey) return apiKey;

      // username+password → keygen. api.generateApiKey() redacts the password from
      // every error string it can throw and never echoes the response body (which
      // contains the minted key). Nothing about the password is logged here either.
      return api.generateApiKey({
        host: this.device.mgmt_ip,
        port: this.device.mgmt_port || 443,
        username,
        password,
        allowSelfSignedSsl: this.device.allow_self_signed_ssl !== false,
      });
    })();

    try {
      this._apiKey = await this._apiKeyPromise;
      return this._apiKey;
    } catch (err) {
      this._apiKeyPromise = null;
      throw err;
    }
  }

  // Builds the PAN-OS connection descriptor, decrypting the stored credential via
  // credStore. Always uses this.pool — never omit it (CLAUDE.md Pool Warning).
  async _getConn() {
    const apiKey = await this._resolveApiKey();

    return {
      host: this.device.mgmt_ip,
      port: this.device.mgmt_port || 443,
      apiKey,
      allowSelfSignedSsl: this.device.allow_self_signed_ssl !== false,
    };
  }

  // → { ok: bool, latency_ms, message } — must never throw.
  async testConnectivity() {
    const startedAt = Date.now();
    try {
      const conn = await this._getConn();
      await api.showSystemInfo(conn);
      return { ok: true, latency_ms: Date.now() - startedAt, message: 'Connected' };
    } catch (err) {
      return { ok: false, latency_ms: null, message: err.message };
    }
  }

  // → { version_string, version_tuple, build, model }
  async getVersion() {
    const conn = await this._getConn();
    const systemInfoResult = await api.showSystemInfo(conn);

    if (!loggedFirstSystemInfo) {
      // First-connect verification aid: field names must be checked against the live
      // device before trusting parser.js mappings (CLAUDE.md: documentation lies).
      console.log(
        '[PaloAlto Debug] show system info result:',
        JSON.stringify(systemInfoResult, null, 2)
      );
      loggedFirstSystemInfo = true;
    }

    return parser.parseSystemInfo(systemInfoResult);
  }

  // → NormalizedRule[]
  async getRules() {
    const conn = await this._getConn();
    const rulesResult = await api.getSecurityRules(conn);
    const rules = parser.parseRules(rulesResult);
    if (rules.length > 0) return rules;

    // Zero rules from the default single-vsys xpath is AMBIGUOUS: either the
    // rulebase really is empty, or this is a multi-vsys device whose rules live
    // under vsys2/vsys3/... — where the xpath resolves to nothing and PAN-OS
    // answers `<response status="success"><result/></response>`, which presents as
    // "this device has no rules" while collectAndStore DELETEs the real ruleset.
    //
    // So before accepting "no rules", look across every vsys. This runs ONLY when
    // the primary path already found nothing, so it cannot regress the working
    // single-vsys case — the cost of a genuinely empty rulebase is one extra
    // config-get that also returns nothing.
    let fallbackRules = [];
    try {
      const anyVsysResult = await api.getSecurityRulesAnyVsys(conn);
      fallbackRules = parser.parseRulesDeep(anyVsysResult);
    } catch (err) {
      // The primary call already succeeded, so the device is reachable — a failing
      // fallback probe is diagnostic noise, not a reason to fail the pull.
      console.warn(
        `[PaloAlto] Any-vsys rule fallback failed for device ${this.device.id}: ${err.message}`
      );
      return rules;
    }

    if (fallbackRules.length > 0) {
      console.warn(
        `[PaloAlto] Device ${this.device.id}: no rules at the default vsys ` +
          `(${api.DEFAULT_VSYS}) but ${fallbackRules.length} found across all vsys — this looks ` +
          'like a multi-vsys firewall. Rules from every vsys are being stored together; ' +
          'per-vsys separation would need a per-device vsys setting.'
      );
      return fallbackRules;
    }

    return rules;
  }

  // → { raw: string, parsed: object }
  // raw = the full `show config running` response XML string;
  // parsed = the config tree (rooted at the <config> element) with the parsed
  // `show system info` result merged in under parsed.system_info — this structure
  // feeds the Phase 6 dot-path predicate engine.
  async getConfig() {
    const conn = await this._getConn();
    const { raw, result: configResult } = await api.showRunningConfig(conn);

    // Best-effort: the config snapshot is still useful without system info, so a
    // failed info call is logged, not fatal.
    let systemInfoResult = null;
    try {
      systemInfoResult = await api.showSystemInfo(conn);
    } catch (err) {
      console.warn(
        `[PaloAlto] Failed to fetch system info for config snapshot on device ${this.device.id}: ${err.message}`
      );
    }

    // ⛔ SECURITY — CLAUDE.md: "Any NEW adapter that returns a raw text config MUST
    // redact before returning it from getConfig()." Found missing entirely in a
    // full-app audit (2026-07-16) — this transport is Palo Alto's DEFAULT
    // mgmt_method, so every Palo Alto device added the default way had its full
    // config (phash hashes, IKE pre-shared keys, SNMPv3 secrets) stored verbatim.
    // Both `raw` (the XML string) and the object tree feeding `parsed` are
    // redacted — device_configs/config_backups are GRANT SELECT'd to
    // claude_readonly/nocvault_readonly, the same roles device_credentials is
    // barred from. Nothing downstream redacts.
    const redactedRaw = parser.redactConfigXml(raw);
    const redactedConfigResult = parser.redactConfigTree(configResult);

    return {
      raw: redactedRaw,
      parsed: parser.parseConfig(redactedConfigResult, systemInfoResult),
    };
  }

  // OPTIONAL — FirewallAdapter's getObjects() (see interface.js for the exact
  // contract). Deliberately does NOT make a new device call: by the time
  // collectAndStore() reaches this step, THIS pull's device_configs.config_parsed
  // row (built by getConfig() above) is already committed — and the XML/API
  // transport's parseConfig() already spreads the ENTIRE PAN-OS config tree at
  // the top level, which contains every address/address-group/service/
  // service-group definition. Reading it back via getLatestConfigParsed() is
  // cheaper and avoids a redundant live pull. Never throws — an unreadable or
  // missing config degrades to all-empty arrays, same as parser.extractObjects()'s
  // own no-tree case.
  async getObjects() {
    const configParsed = await getLatestConfigParsed(this.device.id, this.pool);
    if (!configParsed || typeof configParsed !== 'object') {
      return { addresses: [], addressGroups: [], services: [], serviceGroups: [] };
    }
    return parser.extractObjects(configParsed);
  }
}

// PaloaltoSshAdapter is re-exported here (not defined here) so the registry's
// `const { PaloaltoAdapter, PaloaltoSshAdapter } = require('./paloalto');` resolves.
// Both names are load-bearing — lib/adapters/index.js destructures them at require
// time, so a rename breaks the app on startup, not at first use.
module.exports = { PaloaltoAdapter, PaloaltoSshAdapter };
