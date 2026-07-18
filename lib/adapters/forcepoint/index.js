// lib/adapters/forcepoint/index.js
// CommonJS ONLY — required (via lib/adapters/index.js) by services/engine-worker.js
// under plain node.
//
// This module implements ONLY the FirewallAdapter interface. The shared collect
// pipeline (device_versions / firewall_rules / device_configs persistence plus
// the Phase 5/6 hooks) lives in lib/adapters/index.js — do not add storage
// logic here.
//
// See CLAUDE.md "Forcepoint SMC Integration" — in particular the Pool Warning:
// testConnectivity() and any function touching credStore/DB must always receive and
// use the `pool` parameter, even though it looks like a pure connectivity check.

const { FirewallAdapter } = require('../interface');
const credStore = require('../../credStore');
const smc = require('./smc');
const parser = require('./parser');

class ForcepointAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
  }

  // Builds the SMC connection descriptor, decrypting the stored API key via credStore.
  // Always uses this.pool — never omit it (CLAUDE.md Pool Warning).
  async _getConn() {
    const apiKey = await credStore.getCredential(this.device.id, 'smc_api', this.pool);
    if (!apiKey) {
      throw new Error(
        `No SMC API key credential found for device ${this.device.id} — save credentials before connecting.`
      );
    }

    return {
      smcHost: this.device.smc_host,
      smcPort: this.device.smc_port || 8082,
      apiKey,
      allowSelfSignedSsl: this.device.allow_self_signed_ssl !== false,
    };
  }

  // → { ok: bool, latency_ms, message } — must never throw.
  async testConnectivity() {
    const startedAt = Date.now();
    try {
      const conn = await this._getConn();
      await smc.getApiInfo(conn);
      return { ok: true, latency_ms: Date.now() - startedAt, message: 'Connected' };
    } catch (err) {
      return { ok: false, latency_ms: null, message: err.message };
    }
  }

  // Resolves the ONE engine element on this SMC server that IS this device — see
  // CLAUDE.md Bug 1 / parser.findEngineByIdentity. smc.getEngines(conn) returns EVERY
  // engine on the whole SMC server unfiltered; a positional engines[0] pick silently
  // collapses every device pointed at this smc_host onto whichever engine happens to be
  // first in the listing. THROWS (naming the candidate engine names found on the
  // server) rather than falling back to any positional pick — mirrors
  // lib/adapters/checkpoint/index.js's gateway-identity resolution: storing nothing is
  // recoverable, storing the wrong engine's data silently is not.
  async _resolveEngine(conn) {
    const engines = await smc.getEngines(conn);
    const engine = parser.findEngineByIdentity(engines, this.device);
    if (!engine) {
      throw new Error(
        `No engine on SMC ${conn.smcHost} matches device "${this.device.name}" by name ` +
          `(candidates found on the server: ${parser.describeEngineCandidates(engines)}). Refusing ` +
          'to guess — collecting another engine\'s version/rules/config would silently report the ' +
          'wrong physical firewall\'s data for this device. Fix: make the SecVault device name ' +
          'exactly match the engine element\'s name on the SMC server, then re-run the collection.'
      );
    }
    return engine;
  }

  // → { version_string, version_tuple, model }
  async getVersion() {
    const conn = await this._getConn();
    const engine = await this._resolveEngine(conn);
    return parser.parseEngineVersion(engine);
  }

  // → NormalizedRule[]
  async getRules() {
    const conn = await this._getConn();
    const engine = await this._resolveEngine(conn);

    // Best-effort: follow a policy reference on the engine element if present.
    // Field names for the assigned policy reference are not guaranteed consistent
    // across SMC versions — check a few known candidates defensively.
    let policyHref =
      (engine.fw_policy && (engine.fw_policy.href || engine.fw_policy)) ||
      (engine.policy && (engine.policy.href || engine.policy)) ||
      null;

    if (policyHref && typeof policyHref !== 'string') {
      policyHref = null;
    }

    // ⛔ MUST THROW, not fall back to a positional pick — see CLAUDE.md Bug 2. When the
    // matched engine element doesn't expose a fw_policy/policy href (a real
    // possibility: these field names are doc-derived, never live-verified — see
    // CLAUDE.md "Live Validation Status"), the previous code fetched the FIRST policy
    // on the ENTIRE SMC server and stored it as this device's ruleset — completely
    // unrelated to the actual device. No ruleset is safer than the wrong one.
    if (!policyHref) {
      throw new Error(
        `Forcepoint rule collection failed for device ${this.device.id} ("${this.device.name}") — ` +
          'no policy reference (checked fw_policy, policy) was found on the matched engine element ' +
          `(raw keys present: ${JSON.stringify(Object.keys(engine || {}))}). Refusing to fall back to ` +
          "a positionally-picked policy from the server's full policy list — that could silently " +
          "store an unrelated device's ruleset. Fix: verify the policy-reference field name for this " +
          'SMC version (see CLAUDE.md "SMC API" Field Name Verification / [SMC Debug] log) and update ' +
          "this adapter, or confirm the engine has a policy assigned in SMC."
      );
    }

    let policyElement;
    try {
      policyElement = await smc.getPolicy(conn, policyHref);
    } catch (err) {
      // ⛔ MUST THROW, not swallow to null — found in a full-app audit
      // (2026-07-16). parser.parsePolicy(null, ...) returns [], and
      // collectAndStore DELETEs the device's real firewall_rules before
      // reinserting whatever getRules() returns. A transient SMC failure here
      // (timeout, 503, auth error, unexpected href/field shape on this SMC
      // version) must never be mistaken for "this device genuinely has zero
      // rules" — the same class of bug already fixed in Fortinet/Sangfor
      // ("getRules() must THROW on a retrieval failure — never return []").
      throw new Error(
        `Forcepoint rule collection failed — could not resolve the assigned policy for ` +
          `device ${this.device.id}: ${err.message}`
      );
    }

    const [networkElements, serviceElements] = await Promise.all([
      smc.getNetworkElements(conn).catch((err) => {
        console.warn(`[Forcepoint] Failed to fetch network elements: ${err.message}`);
        return [];
      }),
      smc.getServiceElements(conn).catch((err) => {
        console.warn(`[Forcepoint] Failed to fetch service elements: ${err.message}`);
        return [];
      }),
    ]);

    return parser.parsePolicy(policyElement, networkElements, serviceElements);
  }

  // → { raw: string, parsed: object }
  async getConfig() {
    const conn = await this._getConn();
    const engine = await this._resolveEngine(conn);

    // Re-fetch the engine's full element via its own href to make sure we have the
    // complete, current element (getEngines() may already have done this, but the
    // href is always authoritative per HATEOAS — never assume the cached copy is fresh).
    let fullEngineElement = engine;
    if (engine.href) {
      try {
        fullEngineElement = await smc.getElement(conn, engine.href);
      } catch (err) {
        console.warn(
          `[Forcepoint] Failed to re-fetch full engine element for device ${this.device.id}: ${err.message}`
        );
        fullEngineElement = engine;
      }
    }

    // ⛔ Redact before storing — see CLAUDE.md Bug 3. device_configs.config_raw/
    // config_parsed are GRANT SELECT'd to claude_readonly/nocvault_readonly, the same
    // roles CLAUDE.md bars from device_credentials; every other adapter in this
    // codebase redacts before persisting, this one previously didn't at all.
    const redactedElement = parser.redactEngineElement(fullEngineElement);
    return parser.parseConfig(redactedElement);
  }

  // OPTIONAL — see lib/adapters/interface.js's getObjects() contract comment.
  // → { addresses, addressGroups, services, serviceGroups }
  //
  // Deliberately does NOT call _resolveEngine() — unlike getVersion()/getRules()/
  // getConfig(), SMC's object catalog (network_elements/service_elements) is
  // SERVER-WIDE, not scoped to one engine, so there is no per-engine identity to
  // resolve here (see CLAUDE.md's Forcepoint bug-sweep paragraph for why identity
  // matching matters for the other three methods).
  //
  // Also deliberately different from getRules()'s fail-loud philosophy: a partial
  // object catalog (e.g. addresses collected, service objects failed) still feeds
  // lib/engines/objectUsage.js's unused/duplicate-object matching usefully — there
  // is no destructive DELETE-then-nothing consequence here the way an empty
  // getRules() result has for firewall_rules. Each of the two underlying SMC
  // fetches (network_elements / service_elements) is isolated in its own
  // try/catch, degrading its pair of output arrays to [] independently rather
  // than throwing the whole method.
  async getObjects() {
    const conn = await this._getConn();

    let addresses = [];
    let addressGroups = [];
    try {
      const networkElements = await smc.getNetworkElements(conn);
      ({ addresses, addressGroups } = parser.parseAddressObjects(networkElements));
    } catch (err) {
      console.warn(
        `[Forcepoint] getObjects: failed to fetch/parse network elements for device ${this.device.id}: ${err.message}`
      );
    }

    let services = [];
    let serviceGroups = [];
    try {
      const serviceElements = await smc.getServiceElements(conn);
      ({ services, serviceGroups } = parser.parseServiceObjectCatalog(serviceElements));
    } catch (err) {
      console.warn(
        `[Forcepoint] getObjects: failed to fetch/parse service elements for device ${this.device.id}: ${err.message}`
      );
    }

    return { addresses, addressGroups, services, serviceGroups };
  }
}

module.exports = { ForcepointAdapter };
