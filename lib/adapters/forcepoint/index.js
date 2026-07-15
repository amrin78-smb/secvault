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

  // → { version_string, version_tuple, model }
  async getVersion() {
    const conn = await this._getConn();
    const engines = await smc.getEngines(conn);

    // Phase 1+2 assumes one primary engine per device row. Supporting multiple engines
    // (e.g. a cluster) per device is a future enhancement — would require either a
    // separate engines table or a device-to-engine mapping.
    const primaryEngine = engines[0];
    if (!primaryEngine) {
      throw new Error('No engines found for this device in SMC');
    }

    return parser.parseEngineVersion(primaryEngine);
  }

  // → NormalizedRule[]
  async getRules() {
    const conn = await this._getConn();
    const engines = await smc.getEngines(conn);
    const primaryEngine = engines[0];
    if (!primaryEngine) {
      throw new Error('No engines found for this device in SMC');
    }

    // Best-effort: follow a policy reference on the engine element if present.
    // Field names for the assigned policy reference are not guaranteed consistent
    // across SMC versions — check a few known candidates defensively.
    let policyHref =
      (primaryEngine.fw_policy && (primaryEngine.fw_policy.href || primaryEngine.fw_policy)) ||
      (primaryEngine.policy && (primaryEngine.policy.href || primaryEngine.policy)) ||
      null;

    if (policyHref && typeof policyHref !== 'string') {
      policyHref = null;
    }

    let policyElement = null;
    try {
      if (policyHref) {
        policyElement = await smc.getPolicy(conn, policyHref);
      } else {
        // No policy reference found on the engine element — fall back to the global
        // policy list and take the first entry.
        const policies = await smc.getPolicy(conn);
        const first = Array.isArray(policies) ? policies[0] : null;
        if (first && first.href) {
          policyElement = await smc.getPolicy(conn, first.href);
        } else {
          policyElement = first;
        }
      }
    } catch (err) {
      console.warn(`[Forcepoint] Failed to fetch policy for device ${this.device.id}: ${err.message}`);
      policyElement = null;
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
    const engines = await smc.getEngines(conn);
    const primaryEngine = engines[0];
    if (!primaryEngine) {
      throw new Error('No engines found for this device in SMC');
    }

    // Re-fetch the primary engine's full element via its own href to make sure we have
    // the complete, current element (getEngines() may already have done this, but the
    // href is always authoritative per HATEOAS — never assume the cached copy is fresh).
    let fullEngineElement = primaryEngine;
    if (primaryEngine.href) {
      try {
        fullEngineElement = await smc.getElement(conn, primaryEngine.href);
      } catch (err) {
        console.warn(
          `[Forcepoint] Failed to re-fetch full engine element for device ${this.device.id}: ${err.message}`
        );
        fullEngineElement = primaryEngine;
      }
    }

    return parser.parseConfig(fullEngineElement);
  }
}

module.exports = { ForcepointAdapter };
