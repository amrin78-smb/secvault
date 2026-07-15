// lib/adapters/paloalto/index.js
// CommonJS ONLY — required (via the adapter registry) by services/engine-worker.js
// (plain node, CommonJS).
//
// Palo Alto PAN-OS adapter — talks to the firewall's XML API on the management
// interface (https://<mgmt_ip>:<port>/api/, key auth via `key` query param).
//
// See CLAUDE.md — in particular the Pool Warning: testConnectivity() and any function
// touching credStore/DB must always receive and use `this.pool`, even though it looks
// like a pure connectivity check. Removing pool builds clean and breaks silently at
// runtime.

const { FirewallAdapter } = require('../interface');
const credStore = require('../../credStore');
const api = require('./api');
const parser = require('./parser');

// Per CLAUDE.md "External API Integrations": log the raw response the first time we
// see one so parser.js field mappings can be verified against the live device
// (the MVP was built without a live PAN-OS firewall).
let loggedFirstSystemInfo = false;

class PaloaltoAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
  }

  // Builds the PAN-OS connection descriptor, decrypting the stored API key via
  // credStore. Always uses this.pool — never omit it (CLAUDE.md Pool Warning).
  async _getConn() {
    const apiKey = await credStore.getCredential(this.device.id, 'rest_api', this.pool);
    if (!apiKey) {
      throw new Error(
        `No PAN-OS API key credential found for device ${this.device.id} — save credentials before connecting.`
      );
    }

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
    return parser.parseRules(rulesResult);
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

    return {
      raw,
      parsed: parser.parseConfig(configResult, systemInfoResult),
    };
  }
}

module.exports = { PaloaltoAdapter };
