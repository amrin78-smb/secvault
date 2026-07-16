// lib/adapters/fortinet/index.js
// CommonJS ONLY — services/engine-worker.js (plain node) requires adapter modules.
//
// Fortinet FortiGate adapters. Two transports, dispatched by devices.mgmt_method in
// lib/adapters/index.js:
//   - FortinetAdapter    (mgmt_method 'api') — FortiOS REST API, this file
//   - FortinetSshAdapter (mgmt_method 'ssh') — FortiOS CLI over SSH, ./ssh.js
// Both names are imported by the frozen dispatcher; do not rename either.
//
// This file is the REST transport: https://<mgmt_ip>:<mgmt_port||443>, authenticating
// EITHER with a REST API access token (`Authorization: Bearer <token>`) OR with an
// admin username + password via a FortiOS session login. Which one is used depends on
// the stored credential's shape — see _getConn().
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
const { parseApiCredential } = require('../credentials');
const api = require('./api');
const parser = require('./parser');
const cliParser = require('./cliParser');
const { FortinetSshAdapter } = require('./ssh');

let loggedFirstVersionResponses = false;
let loggedFirstPolicyEntry = false;
let loggedFirstVdomResponse = false;

class FortinetAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
  }

  // Builds the FortiOS connection descriptor, decrypting the stored credential via
  // credStore. Always uses this.pool — never omit it (CLAUDE.md Pool Warning).
  //
  // parseApiCredential handles all three stored forms (see lib/adapters/credentials.js):
  //   {"api_key":"..."}                      → token auth
  //   {"username":"...","password":"..."}    → session auth
  //   a bare non-JSON string                 → token auth (LEGACY raw token; devices
  //                                            added before access-method selection
  //                                            existed must keep working untouched)
  async _getConn() {
    const plaintext = await credStore.getCredential(this.device.id, 'rest_api', this.pool);
    if (!plaintext) {
      throw new Error(
        `No REST API credential found for device ${this.device.id} — save credentials before connecting.`
      );
    }

    // Throws a secret-free, actionable error when the stored credential is unusable.
    const { apiKey, username, password } = parseApiCredential(plaintext, 'FortiGate');

    return {
      host: this.device.mgmt_ip,
      port: this.device.mgmt_port || 443,
      token: apiKey,
      username,
      password,
      session: null,
      authMode: apiKey ? 'token' : 'session',
      allowSelfSignedSsl: this.device.allow_self_signed_ssl !== false,
    };
  }

  /**
   * Runs `fn(conn)` with a usable, authenticated conn.
   *
   * Token auth: passes the conn straight through — the original stateless path,
   * unchanged.
   *
   * Session auth: logs in first, and ALWAYS logs out afterwards via try/finally,
   * including on every error path. This is not tidiness — a FortiGate caps concurrent
   * admin sessions, so one session leaked per collect cycle eventually locks real
   * admins out of the appliance. A logout failure is logged but never masks the real
   * error from `fn`.
   */
  async _withSession(fn) {
    const conn = await this._getConn();

    if (conn.authMode === 'token') {
      return fn(conn);
    }

    const session = await api.loginSession(conn);
    const sessionConn = { ...conn, session };

    try {
      return await fn(sessionConn);
    } finally {
      try {
        await api.logoutSession(sessionConn);
      } catch (err) {
        // Never rethrow from finally: that would replace the real failure with a
        // logout error. The session lingers until FortiOS times it out.
        console.warn(
          `[Fortinet] Session logout failed for device ${this.device.id} — the admin session ` +
            `will linger until it times out: ${err.message}`
        );
      }
    }
  }

  // → { ok: bool, latency_ms, message } — must never throw.
  async testConnectivity() {
    const startedAt = Date.now();
    try {
      await this._withSession(async (conn) => api.getSystemStatus(conn));
      return { ok: true, latency_ms: Date.now() - startedAt, message: 'Connected' };
    } catch (err) {
      // err.message is credential-safe by construction: api.js and credentials.js
      // never put the token, password or session cookie into an error. This message
      // is returned in the /api/devices/[id]/test HTTP response body.
      return { ok: false, latency_ms: null, message: err.message };
    }
  }

  // → { version_string, version_tuple, build, model }
  // Primary source: /api/v2/monitor/system/firmware (results.current.version/.build).
  // Fallback: /api/v2/monitor/system/status (version, serial, hostname, model fields).
  async getVersion() {
    return this._withSession(async (conn) => {
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
    });
  }

  /**
   * Lists the device's VDOMs.
   *
   * @returns {Promise<string[]|null>} VDOM names, or NULL meaning "could not
   *   enumerate — assume a single implicit VDOM". NULL is the safe, pre-existing
   *   behaviour and must never be treated as "this box has no VDOMs".
   */
  async _discoverVdoms(conn) {
    try {
      const body = await api.getVdoms(conn);

      if (!loggedFirstVdomResponse) {
        console.log('[Fortinet Debug] Raw cmdb/system/vdom response:', JSON.stringify(body, null, 2));
        loggedFirstVdomResponse = true;
      }

      return parser.parseVdomNames(body);
    } catch (err) {
      // Older firmware, a VDOM-scoped admin profile, or VDOMs simply not enabled.
      // Fall back to the single implicit VDOM rather than hard-failing a box that
      // has always worked.
      console.warn(
        `[Fortinet] VDOM enumeration failed for device ${this.device.id} — assuming a single ` +
          `implicit VDOM (the pre-VDOM behaviour): ${err.message}`
      );
      return null;
    }
  }

  // Pulls one VDOM's policy table (vdom = null → the admin's default/implicit VDOM).
  // THROWS on anything that is not a usable policy table — see getRules().
  async _getRulesForVdom(conn, vdom, sequenceStart, prefixRuleName) {
    const where = vdom ? ` for VDOM "${vdom}"` : '';

    const policyBody = await api.getFirewallPolicies(conn, vdom);
    const policies = parser.extractResults(policyBody);

    if (!Array.isArray(policies)) {
      // Previously this returned [] — a false success. collectAndStore would then
      // DELETE every stored rule for the device and report rulesCount: 0.
      throw new Error(
        `FortiGate cmdb firewall/policy response${where} had no results array — field names may ` +
          'differ on this firmware. Raw keys: ' +
          JSON.stringify(
            policyBody && typeof policyBody === 'object' ? Object.keys(policyBody) : null
          ) +
          '. Not treating this as "zero rules" — existing rules are left untouched. Check the ' +
          '[Fortinet Debug] logs and adjust lib/adapters/fortinet/parser.js.'
      );
    }

    if (!loggedFirstPolicyEntry && policies.length > 0) {
      console.log('[Fortinet Debug] Raw first policy entry:', JSON.stringify(policies[0], null, 2));
      loggedFirstPolicyEntry = true;
    }

    // Hit counts are best-effort enrichment: FortiGate is one of the few vendors that
    // exposes genuine per-policy counters, but a monitor failure must never break the
    // rule pull — hit counts just default to 0.
    //
    // Fetched PER VDOM and kept with that VDOM's policies: FortiOS policyid is only
    // unique within a VDOM, so merging every VDOM's stats into one index would
    // attribute one VDOM's traffic to another VDOM's policy of the same id.
    let statsResults = [];
    try {
      const statsBody = await api.getPolicyStats(conn, vdom);
      const extracted = parser.extractResults(statsBody);
      statsResults = Array.isArray(extracted) ? extracted : [];
    } catch (err) {
      console.warn(
        `[Fortinet] policy hit-count monitor call${where} failed for device ${this.device.id} — hit counts default to 0: ${err.message}`
      );
      statsResults = [];
    }

    return parser.parsePolicies(policies, statsResults, { vdom, prefixRuleName, sequenceStart });
  }

  // → NormalizedRule[]
  //
  // VDOM completeness: without a `vdom` query param FortiOS returns ONLY the admin's
  // default VDOM, so on a multi-VDOM box this used to hand the rule-analysis engine a
  // partial ruleset that it treated as complete (producing wrong "unused rule"
  // findings). Rules are now collected from EVERY VDOM.
  //
  // ⛔ If one VDOM's rules cannot be fetched, the WHOLE call throws — it does not
  // return the other VDOMs' rules. collectAndStore() (lib/adapters/index.js) awaits
  // getRules() and only THEN opens a transaction that DELETEs every firewall_rules row
  // for this device before reinserting. So:
  //   throw  → the DELETE never runs; the previous complete ruleset survives and the
  //            error is surfaced in engine.log and the /test response.
  //   partial→ the real rules of the failed VDOM are deleted and never reinserted, the
  //            Phase 5 findings are rewritten from the partial set, and the whole thing
  //            reports success. That is strictly worse than a visible failure, and is
  //            exactly the bug this change exists to fix.
  async getRules() {
    return this._withSession(async (conn) => {
      const vdoms = await this._discoverVdoms(conn);

      // No VDOM info, or exactly one VDOM → keep the original implicit-VDOM request
      // (no `vdom` param). With a single VDOM the admin's default VDOM IS that VDOM,
      // so the implicit result is already complete — and this keeps single-VDOM and
      // legacy boxes on the exact code path that already works. No hard fail.
      if (!vdoms || vdoms.length <= 1) {
        return this._getRulesForVdom(conn, null, 0, false);
      }

      console.log(
        `[Fortinet] Device ${this.device.id} has ${vdoms.length} VDOMs; collecting rules from all ` +
          `of them: ${vdoms.join(', ')}`
      );

      const allRules = [];
      for (const vdom of vdoms) {
        // No try/catch on purpose — a failure here must fail getRules() entirely.
        const rules = await this._getRulesForVdom(
          conn,
          vdom,
          allRules.length,
          // Multi-VDOM only: the VDOM goes in raw_rule (durable, machine-readable) AND
          // as a "[vdom] " rule_name prefix (human-facing). firewall_rules has no vdom
          // column, and its `tags` column is NOT in collectAndStore's INSERT list, so a
          // tags entry would be silently dropped — the prefix is the only visible option.
          true
        );
        allRules.push(...rules);
      }

      return allRules;
    });
  }

  // → { raw: string, parsed: object }
  // raw: full text config from /monitor/system/config/backup?scope=global, REDACTED
  // (may 403 on tokens without backup permission — falls back to the JSON of `parsed`).
  // parsed: flat, predictably-keyed object assembled from cmdb endpoints — these keys
  // ({global, interfaces, ssl_vpn, snmp, admins}) feed the Phase 6 applicability
  // predicate engine's dot-path lookups. Keep the structure flat and predictable.
  async getConfig() {
    return this._withSession(async (conn) => {
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
          // redactSecretFields: defence in depth. `parsed` lands in
          // device_configs.config_parsed, which is readable by the claude_readonly /
          // nocvault_readonly roles, and it is NOT verified whether FortiOS blanks
          // secret fields on a cmdb GET (system/admin in particular). Fail closed.
          parsed[key] = parser.redactSecretFields(parser.extractResults(await fetchFn(conn)));
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
      } else {
        // SECURITY: /monitor/system/config/backup returns a FortiOS full configuration
        // — admin password hashes (`set passwd ENC ...`), `set psksecret`, PEM private
        // keys, SNMP communities. It is persisted verbatim into
        // device_configs.config_raw, copied into config_backups, served by the backup
        // download route, and BOTH tables are GRANT SELECT'd to claude_readonly /
        // nocvault_readonly — the roles CLAUDE.md bars from device_credentials.
        // Nothing downstream redacts, so redact here before it leaves the adapter.
        // (CLAUDE.md "Stored configs are REDACTED" / "Any NEW adapter that returns a
        // raw text config MUST redact before returning it from getConfig()".)
        raw = cliParser.redactConfig(raw);
      }

      return { raw, parsed };
    });
  }
}

module.exports = { FortinetAdapter, FortinetSshAdapter };
