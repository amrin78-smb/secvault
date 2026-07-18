// lib/engines/objectUsage.js
//
// Network object catalog usage analysis — "Unused Objects" / "Duplicate
// Objects", the ManageEngine Firewall Analyzer concept this feature mirrors
// (see CLAUDE.md's "Network Object Catalog" section for the full design).
//
// analyzeObjectUsage() is a PURE function (no DB) mirroring
// lib/engines/ruleAnalysis.js's analyzeRules() shape: takes a device's
// network_objects rows + firewall_rules rows, emits findings.
// storeObjects()/runObjectUsageAnalysisForDevice() are the DB-backed
// wrappers used by lib/adapters/index.js's collectAndStore().
//
// CommonJS only — required by lib/adapters/index.js under plain node
// (services/engine-worker.js) AND by Next.js API routes/pages.

'use strict';

function normName(value) {
  return String(value === null || value === undefined ? '' : value)
    .trim()
    .toLowerCase();
}

function labelForType(type) {
  if (type === 'address') return 'Address object';
  if (type === 'address_group') return 'Address group';
  if (type === 'service') return 'Service object';
  if (type === 'service_group') return 'Service group';
  return 'Object';
}

// Every distinct value appearing in a rule's src_addresses/dst_addresses/
// services field, normalized. A rule can reference a literal inline value
// with no backing object at all (e.g. a Palo Alto rule typed directly with
// "10.0.0.0/16") — this function has no way to distinguish that from a real
// object name, and doesn't need to: analyzeObjectUsage() only USES this set
// to look up matches in the device's actual object catalog (byName below),
// so a literal that happens not to match any collected object name simply
// never marks anything used, which is the correct outcome either way.
function collectDirectlyReferencedNames(rules) {
  const names = new Set();
  for (const rule of Array.isArray(rules) ? rules : []) {
    for (const field of [rule.src_addresses, rule.dst_addresses, rule.services]) {
      if (!Array.isArray(field)) continue;
      for (const item of field) {
        if (item === null || item === undefined) continue;
        names.add(normName(item));
      }
    }
  }
  return names;
}

/**
 * @param {Array<{id: string, object_type: string, name: string, value: string|null, members: string[]|null}>} objects
 * @param {Array<{src_addresses: any, dst_addresses: any, services: any}>} rules
 * @returns {Array<{object_id: string, finding_type: 'unused'|'duplicate', detail: string, related_object_ids: string[]}>}
 */
function analyzeObjectUsage(objects, rules) {
  const objectList = Array.isArray(objects) ? objects : [];
  const findings = [];

  const byName = new Map();
  for (const obj of objectList) {
    byName.set(normName(obj.name), obj);
  }

  // Seed with every object directly named by a rule, then transitively
  // expand through group membership (a used group's members are used too,
  // to any nesting depth) — otherwise an address inside a used GROUP would
  // be wrongly flagged unused just because the RULE names the group, not
  // the member. Bounded by objectList.length passes: each pass that changes
  // anything adds at least one name to `used`, so it can never loop longer
  // than there are objects to add.
  const used = new Set();
  for (const name of collectDirectlyReferencedNames(rules)) {
    if (byName.has(name)) used.add(name);
  }
  let changed = true;
  let guard = 0;
  while (changed && guard <= objectList.length) {
    changed = false;
    guard += 1;
    for (const obj of objectList) {
      const key = normName(obj.name);
      if (!used.has(key)) continue;
      if (!Array.isArray(obj.members)) continue;
      for (const member of obj.members) {
        const memberKey = normName(member);
        if (byName.has(memberKey) && !used.has(memberKey)) {
          used.add(memberKey);
          changed = true;
        }
      }
    }
  }

  for (const obj of objectList) {
    if (used.has(normName(obj.name))) continue;
    findings.push({
      object_id: obj.id,
      finding_type: 'unused',
      detail: `${labelForType(obj.object_type)} "${obj.name}" is not referenced by any rule, or by any group that is itself in use, on this device.`,
      related_object_ids: [],
    });
  }

  // Duplicate detection: LEAF objects only (address/service), exact
  // same-type same-value match. Deliberately NOT extended to groups —
  // member-SET equality is a harder bipartite-matching problem once a group
  // has more than one member (which item pairs with which?), same
  // conservative-scope reasoning ruleAnalysis.js's fieldEquals/fieldCovers
  // comment already documents for this codebase: a wrong 'duplicate'
  // finding suggesting an object be merged/deleted is worse than a missed
  // one.
  const byTypeAndValue = new Map();
  for (const obj of objectList) {
    if (obj.object_type !== 'address' && obj.object_type !== 'service') continue;
    if (obj.value === null || obj.value === undefined || obj.value === '') continue;
    const key = `${obj.object_type}|${normName(obj.value)}`;
    if (!byTypeAndValue.has(key)) byTypeAndValue.set(key, []);
    byTypeAndValue.get(key).push(obj);
  }
  for (const group of byTypeAndValue.values()) {
    if (group.length < 2) continue;
    for (const obj of group) {
      const others = group.filter((o) => o.id !== obj.id);
      findings.push({
        object_id: obj.id,
        finding_type: 'duplicate',
        detail: `${labelForType(obj.object_type)} "${obj.name}" has the same value (${obj.value}) as ${others.length} other object(s): ${others.map((o) => o.name).join(', ')}.`,
        related_object_ids: others.map((o) => o.id),
      });
    }
  }

  return findings;
}

// ─────────────────────────────────────────
// DB-backed wrappers
// ─────────────────────────────────────────

/**
 * Rewrite one device's network_objects from a fresh adapter.getObjects()
 * result. DELETE+reinsert, same lifecycle as firewall_rules — safe because
 * runObjectUsageAnalysisForDevice() always reruns immediately after.
 *
 * @param {string} deviceId
 * @param {{addresses?: object[], addressGroups?: object[], services?: object[], serviceGroups?: object[]}} objects
 * @param {import('pg').Pool} pool
 */
async function storeObjects(deviceId, objects, pool) {
  const src = objects || {};
  const rows = [];
  for (const a of src.addresses || []) {
    rows.push({ object_type: 'address', name: a && a.name, value: (a && a.value) ?? null, members: null });
  }
  for (const g of src.addressGroups || []) {
    rows.push({ object_type: 'address_group', name: g && g.name, value: null, members: (g && g.members) || [] });
  }
  for (const s of src.services || []) {
    rows.push({ object_type: 'service', name: s && s.name, value: (s && s.value) ?? null, members: null });
  }
  for (const g of src.serviceGroups || []) {
    rows.push({ object_type: 'service_group', name: g && g.name, value: null, members: (g && g.members) || [] });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM network_objects WHERE device_id = $1', [deviceId]);
    for (const row of rows) {
      if (!row.name) continue; // unnamed object can't be referenced or displayed — skip rather than store junk
      await client.query(
        `INSERT INTO network_objects (device_id, object_type, name, value, members)
         VALUES ($1, $2, $3, $4, $5::jsonb)`,
        [deviceId, row.object_type, row.name, row.value, row.members ? JSON.stringify(row.members) : null]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      // ignore — the client is being released either way
    }
    throw err;
  } finally {
    client.release();
  }

  return { count: rows.filter((r) => r.name).length };
}

/**
 * Run object-usage analysis for one device: load its network_objects +
 * firewall_rules, evaluate, DELETE+reinsert object_analysis_results inside
 * one transaction. A device with zero network_objects (vendor's adapter
 * doesn't implement getObjects(), or the last collect failed before storing
 * any) is a legitimate, common state — clears any stale findings from a
 * PREVIOUS pull and returns cleanly, never an error.
 *
 * @param {string} deviceId
 * @param {import('pg').Pool} pool
 * @returns {Promise<{findings: object[]}>}
 */
async function runObjectUsageAnalysisForDevice(deviceId, pool) {
  const { rows: objectRows } = await pool.query(
    'SELECT id, object_type, name, value, members FROM network_objects WHERE device_id = $1',
    [deviceId]
  );

  if (objectRows.length === 0) {
    await pool.query('DELETE FROM object_analysis_results WHERE device_id = $1', [deviceId]);
    return { findings: [] };
  }

  const { rows: ruleRows } = await pool.query(
    'SELECT src_addresses, dst_addresses, services FROM firewall_rules WHERE device_id = $1',
    [deviceId]
  );

  const findings = analyzeObjectUsage(objectRows, ruleRows);

  const client = await pool.connect();
  let inserted = [];
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM object_analysis_results WHERE device_id = $1', [deviceId]);
    for (const f of findings) {
      const { rows } = await client.query(
        `INSERT INTO object_analysis_results (device_id, object_id, finding_type, detail, related_object_ids)
         VALUES ($1, $2, $3, $4, $5::jsonb)
         RETURNING id, device_id, object_id, finding_type, detail, related_object_ids, analyzed_at`,
        [deviceId, f.object_id, f.finding_type, f.detail, JSON.stringify(f.related_object_ids || [])]
      );
      inserted.push(rows[0]);
    }
    await client.query('COMMIT');
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      // ignore — the client is being released either way
    }
    throw err;
  } finally {
    client.release();
  }

  return { findings: inserted };
}

module.exports = { analyzeObjectUsage, storeObjects, runObjectUsageAnalysisForDevice };
