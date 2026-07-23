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
const { FortinetAdapter, FortinetSshAdapter } = require('./fortinet');
const { PaloaltoAdapter, PaloaltoSshAdapter } = require('./paloalto');
const { CheckpointAdapter } = require('./checkpoint');
const { CiscoAsaAdapter } = require('./cisco_asa');
const { SangforAdapter } = require('./sangfor');
const { runAnalysisForDevice } = require('../engines/ruleAnalysis');
const { detectAndStoreDiff, createBackup } = require('../engines/configDiff');
const { runComplianceAuditForDevice } = require('../engines/configAuditor');
const { storeObjects, runObjectUsageAnalysisForDevice } = require('../engines/objectUsage');

// vendor slug → mgmt_method → adapter class.
//
// Canonical vendor slugs — must match devices.vendor, the versionComparator
// dispatch table, lib/feeds/nvd.js VENDOR_CPES, and VENDOR_META in
// components/devices/vendorMeta.js. Documented in CLAUDE.md.
//
// The inner keys are devices.mgmt_method values and MUST match the
// accessMethods keys declared for that vendor in vendorMeta.js — the form lets
// an operator pick a method, and dispatch here has to honour that pick.
const ADAPTERS = {
  // SMC only, deliberately — CLAUDE.md: NEVER SSH directly to Forcepoint engines.
  forcepoint: { smc: ForcepointAdapter },
  fortinet: { api: FortinetAdapter, ssh: FortinetSshAdapter },
  paloalto: { api: PaloaltoAdapter, ssh: PaloaltoSshAdapter },
  checkpoint: { api: CheckpointAdapter },
  cisco_asa: { ssh: CiscoAsaAdapter },
  sangfor: { ssh: SangforAdapter },
};

// Fallback when devices.mgmt_method is null or unrecognised — e.g. rows created
// before the access-method selector existed, or a vendor changed after the row
// was written.
//
// Duplicated from VENDOR_META[x].defaultAccessMethod rather than imported:
// vendorMeta.js is an ES module (client components import it), and THIS file is
// require()d by services/engine-worker.js under plain node, which cannot
// require ESM. Keep the two in step — same class of cross-registry constraint
// CLAUDE.md already documents for vendor slugs.
const DEFAULT_METHOD = {
  forcepoint: 'smc',
  fortinet: 'api',
  paloalto: 'api',
  checkpoint: 'api',
  cisco_asa: 'ssh',
  sangfor: 'ssh',
};

const SUPPORTED_VENDORS = Object.keys(ADAPTERS);

/**
 * @param {object} device - devices row (uses .vendor and .mgmt_method)
 * @param {import('pg').Pool} pool
 * @returns {import('./interface').FirewallAdapter}
 */
function getAdapter(device, pool) {
  const byMethod = ADAPTERS[device.vendor];
  if (!byMethod) {
    throw new Error(
      `Unsupported vendor "${device.vendor}" — supported: ${SUPPORTED_VENDORS.join(', ')}`
    );
  }

  const requested = device.mgmt_method;
  const method = requested && byMethod[requested] ? requested : DEFAULT_METHOD[device.vendor];
  const AdapterClass = byMethod[method];

  if (!AdapterClass) {
    throw new Error(
      `Vendor "${device.vendor}" has no adapter for access method "${requested || '(none)'}" — ` +
        `supported: ${Object.keys(byMethod).join(', ')}`
    );
  }

  // A stored method the vendor doesn't support is a data problem worth seeing:
  // we still connect (via the default) rather than failing the pull, but silently
  // using a different transport than the operator selected would be misleading.
  if (requested && !byMethod[requested]) {
    console.warn(
      `[adapters] Device ${device.id} (${device.vendor}) has unsupported mgmt_method ` +
        `"${requested}" — falling back to "${method}".`
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
    complianceFindings: null,
    errors: [],
  };

  try {
    const version = await adapter.getVersion();
    await pool.query(
      `INSERT INTO device_versions (device_id, version_string, version_tuple, build, model, serial, hostname)
       VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7)`,
      [
        device.id,
        version.version_string,
        JSON.stringify(version.version_tuple),
        version.build || null,
        version.model || null,
        version.serial || null,
        version.hostname || null,
      ]
    );
    result.version = version;
  } catch (err) {
    result.errors.push(`version: ${err.message}`);
  }

  // The ruleset rewrite (DELETE + reinsert) MUST be atomic. Without a
  // transaction, a failure part-way through the insert loop — e.g. a parser
  // returning undefined for a NOT NULL column like enabled/log_enabled, which
  // pg sends as NULL — leaves the device with a partial (or empty) ruleset that
  // persists until the next successful pull. Phase 5 then analyses that partial
  // set and rewrites the findings from it. A transaction keeps the previous
  // good ruleset intact whenever the new one cannot be stored in full.
  let rulesCollected = false;

  try {
    const rules = await adapter.getRules();
    const client = await pool.connect();

    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM firewall_rules WHERE device_id = $1', [device.id]);

      for (const rule of rules) {
        await client.query(
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

      await client.query('COMMIT');
    } catch (txErr) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackErr) {
        // ignore — the client is being released either way
      }
      throw txErr;
    } finally {
      // ALWAYS release, or the pool leaks a client per failed collect.
      client.release();
    }

    result.rulesCount = rules.length;
    rulesCollected = true;
  } catch (err) {
    result.errors.push(`rules: ${err.message}`);
  }

  // Phase 5: rule hygiene analysis runs after every rule pull. Findings are
  // rewritten per device, so running it here keeps them consistent with the
  // freshly reinserted firewall_rules rows (old findings cascade-deleted).
  //
  // Guarded on the rule pull having actually succeeded — runAnalysisForDevice
  // unconditionally DELETEs this device's rule_analysis_results and reinserts
  // whatever the CURRENT firewall_rules rows imply. Running it after a failed
  // pull would rewrite the findings from a stale ruleset, and (before the
  // transaction above) could wipe every finding for a device whose rules simply
  // failed to collect — a silent "all clear" on an uncollected device. When the
  // pull fails, the previous ruleset and its findings are both left untouched,
  // which keeps them consistent with each other.
  if (rulesCollected) {
    try {
      const analysis = await runAnalysisForDevice(device.id, pool);
      result.analysisFindings = analysis.findings;
    } catch (err) {
      result.errors.push(`rule analysis: ${err.message}`);
    }
  } else {
    result.errors.push(
      'rule analysis: skipped — rule collection failed; previous rules and findings left untouched'
    );
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
      const diffResult = await detectAndStoreDiff(device.id, pool, device.vendor);
      result.configChanged = diffResult.changed;
      if (diffResult.changed) {
        await createBackup(device.id, 'auto', pool);
      }
    }
  } catch (err) {
    result.errors.push(`config diff: ${err.message}`);
  }

  // Phase 7: compliance audit runs after every successful config pull, same
  // trigger condition as the Phase 6 diff/backup block above — it needs the
  // same fresh device_configs.config_parsed row (via getLatestConfigParsed).
  try {
    if (result.configCollected) {
      const audit = await runComplianceAuditForDevice(device.id, pool);
      result.complianceFindings = audit.findings;
    }
  } catch (err) {
    result.errors.push(`compliance audit: ${err.message}`);
  }

  // Network object catalog collection (address/service objects + groups) —
  // OPTIONAL, unlike getRules()/getConfig() above. Most vendor adapters
  // don't implement getObjects() yet (see CLAUDE.md's "Network Object
  // Catalog" section for per-vendor status) — checked the same way
  // getVpnSessionSummary() is checked in services/engine-worker.js, so a
  // vendor without it is simply a no-op here, not a failure. Runs after the
  // config/diff/compliance blocks above (not before, not interleaved with
  // rules) because a getObjects() implementation may itself read back the
  // config JUST persisted above via getLatestConfigParsed() instead of
  // making a second live device call (Palo Alto's full config tree already
  // contains every address/service object — see paloalto/index.js) — that
  // only works if device_configs already has this pull's row by the time
  // getObjects() runs.
  if (typeof adapter.getObjects === 'function') {
    let objectsCollected = false;
    try {
      const objects = await adapter.getObjects();
      await storeObjects(device.id, objects, pool);
      objectsCollected = true;
      result.objectsCollected = true;
    } catch (err) {
      result.errors.push(`objects: ${err.message}`);
    }

    // ⛔ BUG FIXED 2026-07-18, found in a bug-sweep pass: usage analysis
    // used to run unconditionally here, even when the try block above threw
    // and storeObjects() never ran — meaning it would recompute
    // object_analysis_results from a STALE network_objects catalog (whatever
    // survived the LAST successful collect) matched up against this pull's
    // FRESH firewall_rules. Mismatched-freshness inputs can produce actively
    // WRONG verdicts, not just stale ones (e.g. an object renamed on the
    // device: the stale catalog still has the old name, current rules
    // reference the new one, so the old-named object gets a fresh "unused"
    // verdict that misrepresents a rename as an abandonment). This mirrors
    // the exact `rulesCollected` gate already used above for Phase 5 rule
    // analysis, for the identical reason — only recompute findings from
    // inputs that are actually consistent with each other this cycle.
    if (objectsCollected) {
      try {
        const usage = await runObjectUsageAnalysisForDevice(device.id, pool);
        result.objectFindings = usage.findings;
      } catch (err) {
        result.errors.push(`object usage analysis: ${err.message}`);
      }
    } else {
      result.errors.push(
        'object usage analysis: skipped — object collection failed; previous objects and findings left untouched'
      );
    }
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
