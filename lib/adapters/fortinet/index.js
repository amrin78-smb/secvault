// lib/adapters/fortinet/index.js
// CommonJS ONLY — services/engine-worker.js (plain node) requires adapter modules.
//
// Fortinet FortiGate adapter. Talks to the FortiOS REST API directly on the device's
// management interface (https://<mgmt_ip>:<mgmt_port||443>) using a REST API access
// token (`Authorization: Bearer <token>`).
//
// See CLAUDE.md "External API Integrations" and the Pool Warning: testConnectivity()
// and any function touching credStore/DB must always receive and use `this.pool`,
// even though it looks like a pure connectivity check.
//
// ⚠️ No live FortiGate was available during this build. All monitor/cmdb field names
// are the documented FortiOS 7.x shapes and MUST be verified against a real device on
// first connect — raw responses are logged once via '[Fortinet Debug]' below for
// exactly that purpose. parser.js is defensive on every field.

const { FirewallAdapter } = require('../interface');
const credStore = require('../../credStore');
const api = require('./api');
const parser = require('./parser');

let loggedFirstVersionResponses = false;
let loggedFirstPolicyEntry = false;

class FortinetAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
  }

  // Builds the FortiOS connection descriptor, decrypting the stored REST API access
  // token via credStore. Always uses this.pool — never omit it (CLAUDE.md Pool Warning).
  async _getConn() {
    const token = await credStore.getCredential(this.device.id, 'rest_api', this.pool);
    if (!token) {
      throw new Error(
        `No REST API token credential found for device ${this.device.id} — save credentials before connecting.`
      );
    }

    return {
      host: this.device.mgmt_ip,
      port: this.device.mgmt_port || 443,
      token,
      allowSelfSignedSsl: this.device.allow_self_signed_ssl !== false,
    };
  }

  // → { ok: bool, latency_ms, message } — must never throw.
  async testConnectivity() {
    const startedAt = Date.now();
    try {
      const conn = await this._getConn();
      await api.getSystemStatus(conn);
      return { ok: true, latency_ms: Date.now() - startedAt, message: 'Connected' };
    } catch (err) {
      return { ok: false, latency_ms: null, message: err.message };
    }
  }

  // → { version_string, version_tuple, build, model }
  // Primary source: /api/v2/monitor/system/firmware (results.current.version/.build).
  // Fallback: /api/v2/monitor/system/status (version, serial, hostname, model fields).
  async getVersion() {
    const conn = await this._getConn();

    let firmwareBody = null;
    try {
      firmwareBody = await api.getFirmware(conn);
    } catch (err) {
      console.warn(
        `[Fortinet] firmware endpoint failed for device ${this.device.id} — falling back to system status: ${err.message}`
      );
    }

    let statusBody = null;
    try {
      statusBody = await api.getSystemStatus(conn);
    } catch (err) {
      console.warn(
        `[Fortinet] system status endpoint failed for device ${this.device.id}: ${err.message}`
      );
    }

    if (!firmwareBody && !statusBody) {
      throw new Error(
        'Unable to determine FortiGate version — both /monitor/system/firmware and /monitor/system/status failed'
      );
    }

    if (!loggedFirstVersionResponses) {
      // Per CLAUDE.md: never assume vendor field names from documentation. Log the full
      // raw responses the first time so parser.js field mappings can be verified and
      // adjusted against the live system.
      console.log('[Fortinet Debug] Raw firmware response:', JSON.stringify(firmwareBody, null, 2));
      console.log('[Fortinet Debug] Raw system status response:', JSON.stringify(statusBody, null, 2));
      loggedFirstVersionResponses = true;
    }

    return parser.parseVersionInfo(firmwareBody, statusBody);
  }

  // → NormalizedRule[]
  // Policy table from /api/v2/cmdb/firewall/policy; real per-policy hit counts merged
  // in from /api/v2/monitor/firewall/policy (best-effort — FortiGate is one of the few
  // vendors exposing genuine hit counts, but the monitor call must never break the
  // rule pull; hit counts default to 0 if unavailable).
  async getRules() {
    const conn = await this._getConn();

    const policyBody = await api.getFirewallPolicies(conn);
    const policies = parser.extractResults(policyBody);
    if (!Array.isArray(policies)) {
      console.warn(
        '[Fortinet] cmdb firewall/policy response had no results array — field names may differ on this firmware. Raw keys: ' +
          JSON.stringify(policyBody && typeof policyBody === 'object' ? Object.keys(policyBody) : null)
      );
      return [];
    }

    if (!loggedFirstPolicyEntry && policies.length > 0) {
      console.log('[Fortinet Debug] Raw first policy entry:', JSON.stringify(policies[0], null, 2));
      loggedFirstPolicyEntry = true;
    }

    let statsResults = [];
    try {
      const statsBody = await api.getPolicyStats(conn);
      const extracted = parser.extractResults(statsBody);
      statsResults = Array.isArray(extracted) ? extracted : [];
    } catch (err) {
      console.warn(
        `[Fortinet] policy hit-count monitor call failed for device ${this.device.id} — hit counts default to 0: ${err.message}`
      );
      statsResults = [];
    }

    return parser.parsePolicies(policies, statsResults);
  }

  // → { raw: string, parsed: object }
  // raw: full text config from /monitor/system/config/backup?scope=global (may 403 on
  // tokens without backup permission — falls back to the JSON of `parsed`).
  // parsed: flat, predictably-keyed object assembled from cmdb endpoints — these keys
  // ({global, interfaces, ssl_vpn, snmp, admins}) feed the Phase 6 applicability
  // predicate engine's dot-path lookups. Keep the structure flat and predictable.
  async getConfig() {
    const conn = await this._getConn();

    const sections = [
      ['global', api.getSystemGlobal],
      ['interfaces', api.getInterfaces],
      ['ssl_vpn', api.getSslVpnSettings],
      ['snmp', api.getSnmpSysinfo],
      ['admins', api.getAdmins],
    ];

    const parsed = {};
    for (const [key, fetchFn] of sections) {
      try {
        parsed[key] = parser.extractResults(await fetchFn(conn));
      } catch (err) {
        console.warn(
          `[Fortinet] config section '${key}' fetch failed for device ${this.device.id}: ${err.message}`
        );
        parsed[key] = null;
      }
    }

    let raw = null;
    try {
      raw = await api.getConfigBackup(conn);
    } catch (err) {
      console.warn(
        `[Fortinet] config backup fetch failed for device ${this.device.id} (token may lack backup permission) — using parsed JSON as raw: ${err.message}`
      );
      raw = null;
    }

    if (typeof raw !== 'string' || raw.length === 0) {
      raw = JSON.stringify(parsed);
    }

    return { raw, parsed };
  }
}

module.exports = { FortinetAdapter };
