// lib/adapters/forcepoint/index.js
// CommonJS ONLY — services/engine-worker.js (plain node) requires collectAndStore
// from this file for the scheduled daily config/rule pull job.
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

// Module-level function (not a class method) — called both by this workstream's own
// /collect route AND services/engine-worker.js's scheduled daily pull job. Signature
// must stay exactly (device, pool).
async function collectAndStore(device, pool) {
  const adapter = new ForcepointAdapter({ device, pool });

  const result = {
    version: null,
    rulesCount: null,
    configCollected: false,
    errors: [],
  };

  // Each collect step is isolated in its own try/catch so one failing step never
  // prevents the others from completing.

  try {
    const version = await adapter.getVersion();
    await pool.query(
      `INSERT INTO device_versions (device_id, version_string, version_tuple, build, model)
       VALUES ($1, $2, $3::jsonb, $4, $5)`,
      [
        device.id,
        version.version_string,
        JSON.stringify(version.version_tuple),
        version.build || null,
        version.model || null,
      ]
    );
    result.version = version;
  } catch (err) {
    result.errors.push(`version: ${err.message}`);
  }

  try {
    const rules = await adapter.getRules();
    await pool.query('DELETE FROM firewall_rules WHERE device_id = $1', [device.id]);

    for (const rule of rules) {
      await pool.query(
        `INSERT INTO firewall_rules (
           device_id, rule_name, rule_id_vendor, sequence_number, enabled, action,
           src_zones, dst_zones, src_addresses, dst_addresses, services, applications,
           schedule, expiry_date, log_enabled, comment, hit_count, raw_rule
         ) VALUES (
           $1, $2, $3, $4, $5, $6,
           $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb, $12::jsonb,
           $13, $14, $15, $16, $17, $18::jsonb
         )`,
        [
          device.id,
          rule.rule_name,
          rule.rule_id_vendor,
          rule.sequence_number,
          rule.enabled,
          rule.action,
          JSON.stringify(rule.src_zones || []),
          JSON.stringify(rule.dst_zones || []),
          JSON.stringify(rule.src_addresses || []),
          JSON.stringify(rule.dst_addresses || []),
          JSON.stringify(rule.services || []),
          JSON.stringify(rule.applications || []),
          rule.schedule,
          rule.expiry_date,
          rule.log_enabled,
          rule.comment,
          rule.hit_count || 0,
          JSON.stringify(rule.raw_rule || null),
        ]
      );
    }

    result.rulesCount = rules.length;
  } catch (err) {
    result.errors.push(`rules: ${err.message}`);
  }

  try {
    const config = await adapter.getConfig();
    await pool.query(
      `INSERT INTO device_configs (device_id, config_raw, config_parsed)
       VALUES ($1, $2, $3::jsonb)`,
      [device.id, config.raw, JSON.stringify(config.parsed)]
    );
    result.configCollected = true;
  } catch (err) {
    result.errors.push(`config: ${err.message}`);
  }

  try {
    await pool.query(
      'UPDATE devices SET last_collected_at = now(), updated_at = now() WHERE id = $1',
      [device.id]
    );
  } catch (err) {
    result.errors.push(`last_collected_at update: ${err.message}`);
  }

  return result;
}

module.exports = { ForcepointAdapter, collectAndStore };
