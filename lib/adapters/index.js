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
const { detectAndStoreDiff, createBackup, diffConfigs, isEmptyDiff } = require('../engines/configDiff');
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

// Topology data storage (added 2026-08-02, for lib/engines/topology.js) —
// live-snapshot shape, same DELETE+reinsert-in-one-transaction pattern
// lib/engines/objectUsage.js's storeObjects() already uses for
// network_objects. Three separate small functions (not one combined) since
// collectAndStore() below calls each independently, matching each optional
// adapter method's own independent try/catch.

async function storeDeviceInterfaces(deviceId, interfaces, pool) {
  const rows = Array.isArray(interfaces) ? interfaces : [];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM device_interfaces WHERE device_id = $1', [deviceId]);
    for (const iface of rows) {
      if (!iface || !iface.name) continue; // unnamed interface can't be referenced by a route -- skip rather than store junk
      await client.query(
        `INSERT INTO device_interfaces (device_id, interface_name, ip_address, zone, vdom, enabled)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [deviceId, iface.name, iface.ipAddress || null, iface.zone || null, iface.vdom || null, iface.enabled !== false]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (_rollbackErr) {
      // ignore — the client is being released either way
    }
    throw err;
  } finally {
    client.release();
  }
}

// --- Device lifecycle & health stores (added 2026-08-03) -------------------
// All four follow storeDeviceInterfaces()'s transactional DELETE+reinsert
// shape: called ONLY after a successful pull, so a failed poll leaves the
// last-known-good rows intact rather than blanking a device's licence or HA
// state. An empty array legitimately clears (e.g. a device that genuinely
// reports no licences).

async function storeDeviceLicenses(deviceId, licenses, pool) {
  const rows = Array.isArray(licenses) ? licenses : [];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM device_licenses WHERE device_id = $1', [deviceId]);
    for (const lic of rows) {
      if (!lic || !lic.feature) continue; // a licence with no feature name is not usable data
      await client.query(
        `INSERT INTO device_licenses
           (device_id, feature, description, serial, issued_at, expires_at, expires_raw, expired, authcode, raw)
         VALUES ($1, $2, $3, $4, $5::date, $6::date, $7, $8, $9, $10::jsonb)`,
        [
          deviceId,
          lic.feature,
          lic.description || null,
          lic.serial || null,
          lic.issuedAt || null,
          lic.expiresAt || null,
          lic.expiresRaw || null,
          typeof lic.expired === 'boolean' ? lic.expired : null,
          lic.authcode || null,
          JSON.stringify(lic),
        ]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_e) { /* client released either way */ }
    throw err;
  } finally {
    client.release();
  }
}

// One row per device (UNIQUE(device_id)) — upsert rather than DELETE+insert.
async function storeDeviceHaStatus(deviceId, ha, pool) {
  if (!ha || typeof ha !== 'object' || typeof ha.enabled !== 'boolean') return;
  await pool.query(
    `INSERT INTO device_ha_status
       (device_id, enabled, mode, group_id, local_state, peer_state, peer_mgmt_ip, peer_serial,
        peer_connection_status, config_sync_state, last_nonfunctional_reason,
        version_compat_ok, version_compat, raw, collected_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14::jsonb, now())
     ON CONFLICT (device_id) DO UPDATE SET
       enabled = EXCLUDED.enabled, mode = EXCLUDED.mode, group_id = EXCLUDED.group_id,
       local_state = EXCLUDED.local_state, peer_state = EXCLUDED.peer_state,
       peer_mgmt_ip = EXCLUDED.peer_mgmt_ip, peer_serial = EXCLUDED.peer_serial,
       peer_connection_status = EXCLUDED.peer_connection_status,
       config_sync_state = EXCLUDED.config_sync_state,
       last_nonfunctional_reason = EXCLUDED.last_nonfunctional_reason,
       version_compat_ok = EXCLUDED.version_compat_ok,
       version_compat = EXCLUDED.version_compat, raw = EXCLUDED.raw,
       collected_at = now()`,
    [
      deviceId,
      ha.enabled,
      ha.mode || null,
      ha.groupId || null,
      ha.localState || null,
      ha.peerState || null,
      ha.peerMgmtIp || null,
      ha.peerSerial || null,
      ha.peerConnectionStatus || null,
      ha.configSyncState || null,
      ha.lastNonfunctionalReason || null,
      typeof ha.versionCompatOk === 'boolean' ? ha.versionCompatOk : null,
      ha.versionCompat ? JSON.stringify(ha.versionCompat) : null,
      ha.raw ? JSON.stringify(ha.raw) : null,
    ]
  );
}

async function storeDeviceDiskUsage(deviceId, filesystems, pool) {
  const rows = Array.isArray(filesystems) ? filesystems : [];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM device_disk_usage WHERE device_id = $1', [deviceId]);
    for (const fs of rows) {
      if (!fs || !fs.filesystem) continue;
      await client.query(
        `INSERT INTO device_disk_usage
           (device_id, filesystem, mounted_on, size_raw, used_raw, avail_raw, use_percent)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          deviceId,
          fs.filesystem,
          fs.mountedOn || null,
          fs.sizeRaw || null,
          fs.usedRaw || null,
          fs.availRaw || null,
          Number.isFinite(fs.usePercent) ? fs.usePercent : null,
        ]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_e) { /* client released either way */ }
    throw err;
  } finally {
    client.release();
  }
}

async function storeDeviceContentVersions(deviceId, contentVersions, pool) {
  const rows = Array.isArray(contentVersions) ? contentVersions : [];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM device_content_versions WHERE device_id = $1', [deviceId]);
    for (const cv of rows) {
      if (!cv || !cv.component) continue;
      await client.query(
        `INSERT INTO device_content_versions (device_id, component, version, released_at, raw)
         VALUES ($1, $2, $3, $4::timestamptz, $5::jsonb)`,
        [deviceId, cv.component, cv.version || null, cv.releasedAt || null, JSON.stringify(cv)]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_e) { /* client released either way */ }
    throw err;
  } finally {
    client.release();
  }
}

async function storeDeviceRoutes(deviceId, routes, pool) {
  const rows = Array.isArray(routes) ? routes : [];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM device_routes WHERE device_id = $1', [deviceId]);
    for (const route of rows) {
      if (!route || !route.destinationCidr) continue;
      await client.query(
        `INSERT INTO device_routes (device_id, destination_cidr, next_hop_ip, interface_name, protocol, metric, vdom)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          deviceId,
          route.destinationCidr,
          route.nextHopIp || null,
          route.interfaceName || null,
          route.protocol || null,
          route.metric === undefined ? null : route.metric,
          route.vdom || null,
        ]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (_rollbackErr) {
      // ignore
    }
    throw err;
  } finally {
    client.release();
  }
}

async function storeNatRules(deviceId, rules, pool) {
  const rows = Array.isArray(rules) ? rules : [];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM nat_rules WHERE device_id = $1', [deviceId]);
    for (const rule of rows) {
      if (!rule || !rule.natType) continue;
      await client.query(
        `INSERT INTO nat_rules (
           device_id, sequence_number, enabled, nat_type,
           original_src_addresses, original_dst_addresses, original_services,
           translated_src_addresses, translated_dst_addresses, translated_services
         ) VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb)`,
        [
          deviceId,
          rule.sequenceNumber === undefined ? null : rule.sequenceNumber,
          rule.enabled !== false,
          rule.natType,
          rule.originalSrcAddresses ? JSON.stringify(rule.originalSrcAddresses) : null,
          rule.originalDstAddresses ? JSON.stringify(rule.originalDstAddresses) : null,
          rule.originalServices ? JSON.stringify(rule.originalServices) : null,
          rule.translatedSrcAddresses ? JSON.stringify(rule.translatedSrcAddresses) : null,
          rule.translatedDstAddresses ? JSON.stringify(rule.translatedDstAddresses) : null,
          rule.translatedServices ? JSON.stringify(rule.translatedServices) : null,
        ]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (_rollbackErr) {
      // ignore
    }
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Full collect for one device: version + rules + config, then the Phase 5
 * rule analysis and Phase 6 config diff/backup hooks. Each step is isolated
 * in its own try/catch so one failing step never prevents the others.
 *
 * Called by services/engine-worker.js (scheduled pull) and
 * app/api/devices/[id]/collect (on-demand). Signature must stay (device, pool).
 */
// ⛔ A FAILED READ MUST NOT BE PERSISTED AS AN AFFIRMATIVE EMPTY.
//
// Both Palo Alto transports fetch `show system info` best-effort when building
// a config snapshot: a failure is logged and `null` is passed on. Their
// parseConfig() then turns that null into `system_info: {}` — so a transient
// SSH/API hiccup was stored as "this device no longer has a model, serial,
// hostname, IP or MAC". configDiff then correctly reported 12 REMOVALS against
// yesterday's populated object, and 12 ADDITIONS when the next read succeeded.
//
// Observed live on TUG (2 of 96 snapshots): config_raw was byte-identical at
// 151063 bytes on both the "removed" and the "added" day, i.e. the device
// changed nothing. It produced false change alerts on a security product.
//
// Fixed HERE rather than in each adapter so it covers both PA transports and
// any future adapter that merges a best-effort system_info. Same discipline as
// getLicenses/getDiskUsage above: on a read failure the PREVIOUS values are
// kept and the failure is surfaced in result.errors, never asserted as a change.
//
// Deliberately narrow: it only fills an EMPTY/absent system_info from the
// previous snapshot. A populated one is never touched, so a genuine change to
// model/serial/version still diffs normally.
async function preserveSystemInfoOnReadFailure(deviceId, parsed, pool, result) {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return parsed;
  const current = parsed.system_info;
  const currentIsEmpty =
    current === null ||
    current === undefined ||
    (typeof current === 'object' && !Array.isArray(current) && Object.keys(current).length === 0);
  if (!currentIsEmpty) return parsed;

  try {
    const { rows } = await pool.query(
      `SELECT config_parsed FROM device_configs
        WHERE device_id = $1 ORDER BY collected_at DESC LIMIT 1`,
      [deviceId]
    );
    const prev = rows[0] && rows[0].config_parsed && rows[0].config_parsed.system_info;
    if (!prev || typeof prev !== 'object' || Object.keys(prev).length === 0) {
      // No previous value either (e.g. Fortinet, which never populated it before
      // v2.59.0). Nothing to carry forward and nothing to distort — leave as-is.
      return parsed;
    }
    result.errors.push(
      'system info: could not be read this cycle (previous values kept, no false config change recorded)'
    );
    return { ...parsed, system_info: prev };
  } catch (_err) {
    // Never let this lookup break a config store — the snapshot matters more.
    return parsed;
  }
}

// ⛔ THIS EXPRESSION IS DUPLICATED IN lib/schema.sql's one-time content_hash
// backfill AND THE TWO COPIES MUST STAY IN STEP. They differ in exactly one
// respect — this one binds $2/$3, the backfill names config_raw/config_parsed —
// and must agree on everything else: same coalesce, same chr(10) separator,
// same UTF8 encoding, same sha256, same hex. If they drift, a backfilled row
// and a freshly written one holding identical content carry different hashes
// and the column stops meaning anything at all.
// tests/configSnapshotDedupe.test.js normalises the two operand spellings away
// and asserts the remainder is character-for-character equal.
//
// It is computed in SQL rather than in Node on purpose: config_parsed is jsonb,
// and PostgreSQL re-normalises key order and whitespace when it stores one, so
// a sha256 over JSON.stringify() here could never equal a sha256 over the value
// that actually landed in the column. Hashing `config_parsed::text` hashes what
// is really stored — which is also already-redacted text, because every adapter
// redacts before getConfig() returns (CLAUDE.md: "Stored configs are REDACTED").
//
// $2 = config_raw, $3 = config_parsed. Both statements below are written to
// bind those positions; changing either statement's parameter order without
// changing this is a silent corruption, so the positions are named here.
const CONTENT_HASH_SQL = `encode(
      sha256(convert_to(coalesce($2::text, '') || chr(10) || coalesce(($3::jsonb)::text, ''), 'UTF8')),
      'hex')`;

/**
 * Persist one config snapshot for a device, DEDUPED AT WRITE TIME.
 *
 * ⛔ THE PROBLEM. device_configs stored one full snapshot per device per pull
 * whether or not anything had changed — 540 MB of a live database, and 93.3% of
 * consecutive snapshot pairs (measured on the live fleet with the change
 * engine's own emptiness test) were no change at all. configRetention.js bounds
 * that growth from behind; nothing stopped it being created.
 *
 * ⛔ THE OBJECTION THIS IS BUILT AROUND. A stored row is not only a payload, it
 * is EVIDENCE THAT A COLLECTION SUCCEEDED AT TIME T. Just skipping the INSERT
 * would silently destroy that evidence — a successful read recorded as nothing,
 * the exact mirror of this codebase's most-repeated bug (a failed read recorded
 * as a fact). So the evidence is preserved SEPARATELY from the payload: an
 * unchanged pull UPDATEs the surviving row, moving `collected_at` forward to
 * this observation, leaving `first_collected_at` alone and incrementing
 * `observation_count`. Three things are still true after a deduped pull —
 *   - `collected_at` = now(), i.e. "a collection succeeded at time T", exactly
 *     as the newest duplicate row used to assert it;
 *   - `observation_count` = how many successful collections saw this config,
 *     between `first_collected_at` and `collected_at`;
 *   - `device_versions` still gets its own row per pull, untouched by any of
 *     this, so the per-pull collection audit trail keeps FULL granularity
 *     (verified live: 2,149 device_versions rows against 2,160 device_configs).
 *
 * ⛔ THE DEDUPE KEY IS THE CHANGE ENGINE ITSELF, NOT A BYTE HASH. Measured on
 * the live fleet, byte-identical consecutive snapshots are only 2.8%: Palo Alto
 * rewrites config_parsed on nearly every pull (volatile system_info) while its
 * raw text is identical, and Fortinet does the reverse (~412 volatile raw bytes
 * against an identical parsed tree). Deduping on bytes would have saved almost
 * nothing. The condition used instead is literally
 * `isEmptyDiff(diffConfigs(previous, incoming, vendor))` — SecVault's own
 * definition of "nothing changed", volatile-path exclusions and all.
 *
 * ⛔ WHY THAT MAKES CHANGE DETECTION PROVABLY UNAFFECTED. detectAndStoreDiff()
 * compares the two newest rows and writes a config_diffs row (and an 'auto'
 * config_backups row) only when that same diff is non-empty. When this function
 * dedupes, that diff is empty BY CONSTRUCTION, so detectAndStoreDiff() would
 * have returned {changed:false} and written nothing — the caller therefore skips
 * it and the outcome is identical. When this function inserts, nothing about the
 * old path changes at all. And because the UPDATE also refreshes the payload,
 * the row the NEXT real change is diffed against holds exactly the bytes the old
 * code would have left there.
 *
 * ⛔ A BASELINE ROW IS NEVER THE DEDUPE TARGET. device_configs.is_baseline is an
 * operator-designated known-good snapshot (partial unique index, one per device)
 * and the comparison target for drift. Mutating its payload or its timestamps
 * would corrupt the one thing an operator explicitly pinned, so when the newest
 * row is a baseline this INSERTs instead. The guard is expressed twice — once
 * when choosing the target, once in the UPDATE's own WHERE — the same
 * double-expression discipline configRetention.js uses for the same flag.
 *
 * @param {string} deviceId
 * @param {string|null} raw - redacted raw config text
 * @param {object|null} parsed - parsed config tree
 * @param {string|undefined} vendor - device vendor slug, for volatile-path exclusions
 * @param {import('pg').Pool} pool
 * @returns {Promise<{id:string|null, deduped:boolean, observationCount:number|null}>}
 */
async function storeConfigSnapshot(deviceId, raw, parsed, vendor, pool) {
  const parsedJson = JSON.stringify(parsed);

  // Newest row for this device, by the same ordering every other consumer uses.
  const { rows } = await pool.query(
    `SELECT id, config_parsed, is_baseline FROM device_configs
      WHERE device_id = $1 ORDER BY collected_at DESC, id DESC LIMIT 1`,
    [deviceId]
  );
  const previous = rows && rows[0] ? rows[0] : null;

  const targetable =
    previous &&
    previous.is_baseline !== true &&
    previous.config_parsed &&
    typeof previous.config_parsed === 'object';

  if (targetable) {
    let unchanged = false;
    try {
      unchanged = isEmptyDiff(diffConfigs(previous.config_parsed, parsed, vendor));
    } catch (_err) {
      // ⛔ A diff we could not COMPUTE is not a "nothing changed". Failing to
      // answer falls back to storing a new row (the old behaviour), never to
      // collapsing two snapshots that were never actually compared.
      unchanged = false;
    }

    if (unchanged) {
      const updated = await pool.query(
        `UPDATE device_configs
            SET config_raw = $2,
                config_parsed = $3::jsonb,
                content_hash = ${CONTENT_HASH_SQL},
                collected_at = now(),
                observation_count = observation_count + 1
          WHERE id = $1
            AND is_baseline = false
        RETURNING id, observation_count`,
        [previous.id, raw, parsedJson]
      );
      if (updated.rowCount === 1) {
        return {
          id: updated.rows[0].id,
          deduped: true,
          observationCount: Number(updated.rows[0].observation_count) || null,
        };
      }
      // rowCount 0 = the row became a baseline, or was removed, between the two
      // statements. Fall through and INSERT: a lost snapshot is the one outcome
      // worse than a duplicated one.
    }
  }

  const inserted = await pool.query(
    `INSERT INTO device_configs (device_id, config_raw, config_parsed, content_hash)
     VALUES ($1, $2, $3::jsonb, ${CONTENT_HASH_SQL})
     RETURNING id, observation_count`,
    [deviceId, raw, parsedJson]
  );
  const row = inserted.rows && inserted.rows[0] ? inserted.rows[0] : null;
  return {
    id: row ? row.id : null,
    deduped: false,
    observationCount: row ? Number(row.observation_count) || null : null,
  };
}

async function collectAndStore(device, pool) {
  const adapter = getAdapter(device, pool);

  const result = {
    version: null,
    rulesCount: null,
    configCollected: false,
    // True when this pull's config was identical — in the change engine's sense
    // — to the stored one and was folded into it instead of inserting a new
    // row. NOT an error, and NOT a failure to collect. See storeConfigSnapshot().
    configDeduped: false,
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
             schedule, expiry_date, log_enabled, comment, hit_count, raw_rule, vdom
           ) VALUES (
             $1, $2, $3, $4, $5, $6,
             $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb, $12::jsonb,
             $13, $14, $15, $16, $17, $18::jsonb, $19
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
            // ⛔ `|| 0` here would undo the whole point of the tri-state:
            // it turns "not measured" (null/undefined) into the affirmative
            // claim "zero hits". Only a real finite number is stored.
            Number.isFinite(Number(rule.hit_count)) && rule.hit_count !== null ? Number(rule.hit_count) : null,
            JSON.stringify(rule.raw_rule || null),
            rule.vdom || null,
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
    const parsed = await preserveSystemInfoOnReadFailure(device.id, config.parsed, pool, result);
    // Write-time dedupe lives in storeConfigSnapshot() — read its header before
    // changing anything here. configCollected stays TRUE on a deduped pull: the
    // config WAS collected, successfully, and the surviving row records that.
    const stored = await storeConfigSnapshot(device.id, config.raw, parsed, device.vendor, pool);
    result.configCollected = true;
    result.configDeduped = stored.deduped;
    result.configSnapshotId = stored.id;
    result.configObservationCount = stored.observationCount;
  } catch (err) {
    result.errors.push(`config: ${err.message}`);
  }

  // Phase 6: change tracking runs after every config pull — diff the two most
  // recent snapshots, and keep an 'auto' labeled backup only when something
  // actually changed (avoids duplicating every unchanged daily pull).
  //
  // Skipped when the pull was DEDUPED, and that is not a shortcut: the dedupe
  // condition IS "the diff against the previous snapshot is empty", so
  // detectAndStoreDiff() would re-read the same two rows, recompute the same
  // empty diff and return {changed:false} having written nothing. Skipping it is
  // exactly equivalent, and cheaper by one whole config-tree diff. config_diffs
  // and config_backups therefore see the same writes, at the same moments, that
  // they saw before this dedupe existed.
  try {
    if (result.configCollected && !result.configDeduped) {
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

  // Topology data collection (interfaces/routes/NAT) — OPTIONAL, same
  // typeof-check convention as getObjects() above. Phase 1 (2026-08-02):
  // implemented only by paloalto/fortinet (see CLAUDE.md's Topology
  // section). Each of the three methods is checked and stored
  // INDEPENDENTLY — a device may implement some but not all, and one
  // method failing must never block the others.
  //
  // ⛔ These tables DO have destructive-empty risk — the previous comment here
  // claimed otherwise and was wrong. storeDeviceInterfaces/Routes/NatRules all
  // DELETE before reinserting, so an empty array wipes the device. The
  // protection is that each adapter method now THROWS on a transport failure
  // (it used to catch and return []), which lands in the catch below and
  // leaves the existing rows untouched. The Array.isArray guards are a second
  // line of defence against a future adapter returning a non-array.
  if (typeof adapter.getInterfaces === 'function') {
    try {
      const { interfaces } = await adapter.getInterfaces();
      await storeDeviceInterfaces(device.id, interfaces, pool);
      result.interfacesCollected = true;
    } catch (err) {
      result.errors.push(`interfaces: ${err.message}`);
    }
  }
  if (typeof adapter.getRoutingTable === 'function') {
    try {
      const { routes } = await adapter.getRoutingTable();
      await storeDeviceRoutes(device.id, routes, pool);
      result.routesCollected = true;
    } catch (err) {
      result.errors.push(`routes: ${err.message}`);
    }
  }
  if (typeof adapter.getNatRules === 'function') {
    try {
      const { rules } = await adapter.getNatRules();
      await storeNatRules(device.id, rules, pool);
      result.natRulesCollected = true;
    } catch (err) {
      result.errors.push(`nat rules: ${err.message}`);
    }
  }

  // Device lifecycle & health (added 2026-08-03). Same optional-capability
  // gating and independent try/catch as the topology trio above — a vendor or
  // transport that can't report licences must never fail the whole collect.
  if (typeof adapter.getLicenses === 'function') {
    try {
      // ⛔ null = "could not determine". These stores DELETE+reinsert, so
      // passing an empty array through on a transient SSH/API failure would
      // WIPE a device's last-known-good licences and report success — the same
      // destructive-empty trap CLAUDE.md's "getRules() must THROW, never return
      // []" rule exists to prevent. Adapters now return null on failure and an
      // array only when they genuinely read the device.
      const res = await adapter.getLicenses();
      if (res && Array.isArray(res.licenses)) {
        await storeDeviceLicenses(device.id, res.licenses, pool);
        result.licensesCollected = true;
      } else {
        result.errors.push('licenses: could not be read from the device (previous values kept)');
      }
    } catch (err) {
      result.errors.push(`licenses: ${err.message}`);
    }
  }
  if (typeof adapter.getHaStatus === 'function') {
    try {
      const ha = await adapter.getHaStatus();
      // null means "could not determine" — leave the last known row intact
      // rather than overwriting a real HA state with an unknown. A standalone
      // device returns { enabled: false }, which IS stored.
      if (ha) {
        await storeDeviceHaStatus(device.id, ha, pool);
        result.haStatusCollected = true;
      }
    } catch (err) {
      result.errors.push(`ha status: ${err.message}`);
    }
  }
  if (typeof adapter.getDiskUsage === 'function') {
    try {
      // Same destructive-empty guard as getLicenses() above.
      const res = await adapter.getDiskUsage();
      if (res && Array.isArray(res.filesystems)) {
        await storeDeviceDiskUsage(device.id, res.filesystems, pool);
        result.diskUsageCollected = true;
      } else {
        result.errors.push('disk usage: could not be read from the device (previous values kept)');
      }
    } catch (err) {
      result.errors.push(`disk usage: ${err.message}`);
    }
  }
  // Content/signature versions ride along on getVersion()'s already-fetched
  // system info (no extra device command) — stored here rather than in the
  // version block above because they are 1-to-many and land in their own table.
  // ⛔ null (Fortinet's read failed) must NOT reach the store — it DELETEs
  // before reinserting, so an unreadable content-version list would wipe the
  // device's real AV/IPS/App-Control versions and report success. Surface it
  // as an error and keep the previous rows, same as getLicenses/getDiskUsage.
  if (result.version && result.version.contentVersions !== undefined) {
    if (Array.isArray(result.version.contentVersions)) {
      try {
        await storeDeviceContentVersions(device.id, result.version.contentVersions, pool);
        result.contentVersionsCollected = true;
      } catch (err) {
        result.errors.push(`content versions: ${err.message}`);
      }
    } else if (result.version.contentVersions === null) {
      result.errors.push(
        'content versions: could not be read from the device (previous values kept)'
      );
    }
  }

  // ⛔ ONLY stamp last_collected_at when something was ACTUALLY collected.
  //
  // This ran unconditionally, outside every per-capability try/catch, so the
  // column meant "a collection was ATTEMPTED", not "a collection SUCCEEDED".
  // Live consequence: TSR_EKC has been unreachable since 2026-08-06 — 1,002
  // consecutive failed probes, newest config 18.5 days old — and reported
  // last_collected_at of 0.9 HOURS. Every staleness query in the app returned
  // zero rows fleet-wide, which is precisely why a dead firewall stayed
  // invisible while its CVE assessments and compliance score kept being
  // computed from an 18-day-old snapshot.
  //
  // devices.last_connectivity_ok is updated from the same signal: it was
  // written ONLY by the manual "Test connectivity" button, leaving all 16
  // devices 22-40 days stale and TSR_EKC storing `true` while every live probe
  // said false.
  // Uses the flags that actually exist on `result`: rulesCount is null when
  // the rule pull failed and a number (including 0) when it succeeded;
  // version is null on failure. configCollected is a real boolean.
  const collectedSomething =
    result.rulesCount !== null || result.configCollected === true || result.version !== null;
  try {
    if (collectedSomething) {
      await pool.query(
        `UPDATE devices
            SET last_collected_at = now(),
                last_connectivity_ok = true,
                last_connectivity_checked_at = now(),
                updated_at = now()
          WHERE id = $1`,
        [device.id]
      );
    } else {
      // Nothing was collected. Record the failed reachability but deliberately
      // leave last_collected_at ALONE, so it keeps pointing at the last real
      // collection and staleness stays visible.
      await pool.query(
        `UPDATE devices
            SET last_connectivity_ok = false,
                last_connectivity_checked_at = now(),
                updated_at = now()
          WHERE id = $1`,
        [device.id]
      );
      result.errors.push(
        'collection produced nothing — last_collected_at left unchanged so the device reads as stale'
      );
    }
  } catch (err) {
    result.errors.push(`device collection status update: ${err.message}`);
  }

  return result;
}

module.exports = { getAdapter, collectAndStore, storeConfigSnapshot, SUPPORTED_VENDORS };
