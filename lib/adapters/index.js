// lib/adapters/index.js
// Vendor dispatch + the shared collect pipeline.
//
// CommonJS ONLY — services/engine-worker.js (plain node) requires collectAndStore
// from this file for the scheduled daily config/rule pull job, and the
// /api/devices/[id]/collect and /test routes import it for on-demand actions.
//
// Adapters implement ONLY the FirewallAdapter interface (testConnectivity,
// getVersion, getRules, getConfig). Everything about persisting the results —
// device_versions, firewall_rules, device_configs, the Phase 5 rule analysis
// and Phase 6 config diff/backup hooks — lives HERE, once, so a new vendor is
// "add an adapter folder + a comparator entry", never a copy of the pipeline.
//
// See CLAUDE.md Pool Warning: every adapter is constructed with { device, pool }
// and must use this.pool for all credStore access.

'use strict';

const { ForcepointAdapter } = require('./forcepoint');
const { FortinetAdapter } = require('./fortinet');
const { PaloaltoAdapter } = require('./paloalto');
const { CheckpointAdapter } = require('./checkpoint');
const { CiscoAsaAdapter } = require('./cisco_asa');
const { SangforAdapter } = require('./sangfor');
const { runAnalysisForDevice } = require('../engines/ruleAnalysis');
const { detectAndStoreDiff, createBackup } = require('../engines/configDiff');

// Canonical vendor slugs — must match devices.vendor, the versionComparator
// dispatch table, and lib/feeds/nvd.js VENDOR_CPES. Documented in CLAUDE.md.
const ADAPTERS = {
  forcepoint: ForcepointAdapter,
  fortinet: FortinetAdapter,
  paloalto: PaloaltoAdapter,
  checkpoint: CheckpointAdapter,
  cisco_asa: CiscoAsaAdapter,
  sangfor: SangforAdapter,
};

const SUPPORTED_VENDORS = Object.keys(ADAPTERS);

/**
 * @param {object} device - devices row
 * @param {import('pg').Pool} pool
 * @returns {import('./interface').FirewallAdapter}
 */
function getAdapter(device, pool) {
  const AdapterClass = ADAPTERS[device.vendor];
  if (!AdapterClass) {
    throw new Error(
      `Unsupported vendor "${device.vendor}" — supported: ${SUPPORTED_VENDORS.join(', ')}`
    );
  }
  return new AdapterClass({ device, pool });
}

/**
 * Full collect for one device: version + rules + config, then the Phase 5
 * rule analysis and Phase 6 config diff/backup hooks. Each step is isolated
 * in its own try/catch so one failing step never prevents the others.
 *
 * Called by services/engine-worker.js (scheduled pull) and
 * app/api/devices/[id]/collect (on-demand). Signature must stay (device, pool).
 */
async function collectAndStore(device, pool) {
  const adapter = getAdapter(device, pool);

  const result = {
    version: null,
    rulesCount: null,
    configCollected: false,
    configChanged: false,
    analysisFindings: null,
    errors: [],
  };

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

  // Phase 5: rule hygiene analysis runs after every rule pull. Findings are
  // rewritten per device, so running it here keeps them consistent with the
  // freshly reinserted firewall_rules rows (old findings cascade-deleted).
  try {
    const analysis = await runAnalysisForDevice(device.id, pool);
    result.analysisFindings = analysis.findings;
  } catch (err) {
    result.errors.push(`rule analysis: ${err.message}`);
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

  // Phase 6: change tracking runs after every config pull — diff the two most
  // recent snapshots, and keep an 'auto' labeled backup only when something
  // actually changed (avoids duplicating every unchanged daily pull).
  try {
    if (result.configCollected) {
      const diffResult = await detectAndStoreDiff(device.id, pool);
      result.configChanged = diffResult.changed;
      if (diffResult.changed) {
        await createBackup(device.id, 'auto', pool);
      }
    }
  } catch (err) {
    result.errors.push(`config diff: ${err.message}`);
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

module.exports = { getAdapter, collectAndStore, SUPPORTED_VENDORS };
