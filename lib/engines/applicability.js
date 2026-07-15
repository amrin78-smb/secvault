// lib/engines/applicability.js
//
// Phase 6 predicate evaluator for advisory applicability.
//
// CRITICAL SEMANTICS (see CLAUDE.md "Applicability Tri-State Default"):
//   - config_applies is tri-state: 'yes' | 'no' | 'unknown'
//   - when NO advisory_conditions rows exist for an advisory the result is
//     'unknown' — NEVER 'no'
//   - 'unknown' is treated conservatively downstream (prioritization.js);
//     this module only PRODUCES config_applies values, it never changes
//     prioritization semantics.
//
// evaluatePredicate / computeConfigApplies / evaluateConditionsDetailed are
// PURE. DB helpers take `pool` as a parameter per CLAUDE.md.

'use strict';

const TRUTHY_FEATURE_VALUES = ['true', 'enabled', 'yes', '1'];
const FALSY_FEATURE_VALUES = ['false', 'disabled', 'no', '0'];
const PORT_KEY_NAMES = ['port', 'ports', 'listen_port', 'dst_port'];

/**
 * Resolve a dot-notation path (with `[i]` array indices, e.g.
 * `interfaces[2].name`) into a parsed config object. Returns undefined when
 * the path does not resolve.
 */
function getByPath(obj, path) {
  if (obj === null || obj === undefined) return undefined;
  if (typeof path !== 'string' || path === '') return undefined;

  const tokens = [];
  const re = /([^[\].]+)|\[(\d+)\]/g;
  let m;
  while ((m = re.exec(path)) !== null) {
    if (m[1] !== undefined) {
      tokens.push(m[1]);
    } else {
      tokens.push(Number(m[2]));
    }
  }
  if (tokens.length === 0) return undefined;

  let current = obj;
  for (const token of tokens) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return undefined;
    }
    current = current[token];
  }
  return current;
}

/**
 * Deep-scan a parsed config for a key whose name satisfies keyMatch and whose
 * value satisfies valueMatch (either the value itself, or — for array values —
 * any element of the array). Cycle-safe via a visited set (jsonb data cannot
 * contain cycles, but this function must never throw or spin).
 */
function deepScan(node, keyMatch, valueMatch, visited) {
  if (node === null || node === undefined || typeof node !== 'object') return false;
  if (visited.has(node)) return false;
  visited.add(node);

  if (Array.isArray(node)) {
    for (const item of node) {
      if (deepScan(item, keyMatch, valueMatch, visited)) return true;
    }
    return false;
  }

  for (const [key, value] of Object.entries(node)) {
    if (keyMatch(key)) {
      if (valueMatch(value)) return true;
      if (Array.isArray(value) && value.some((v) => valueMatch(v))) return true;
    }
    if (deepScan(value, keyMatch, valueMatch, visited)) return true;
  }
  return false;
}

/**
 * Deep-scan for any string equal (case-insensitive) to `target` anywhere in
 * the subtree, including primitive leaves and array elements.
 */
function subtreeContainsString(node, targetLower, visited) {
  if (typeof node === 'string') {
    return node.toLowerCase() === targetLower;
  }
  if (node === null || node === undefined || typeof node !== 'object') return false;
  if (visited.has(node)) return false;
  visited.add(node);

  if (Array.isArray(node)) {
    return node.some((item) => subtreeContainsString(item, targetLower, visited));
  }
  return Object.values(node).some((value) => subtreeContainsString(value, targetLower, visited));
}

/**
 * Deep-scan for a zone string appearing anywhere under a key containing
 * 'admin' or 'management' (case-insensitive).
 */
function scanAdminZone(node, zoneLower, visited) {
  if (node === null || node === undefined || typeof node !== 'object') return false;
  if (visited.has(node)) return false;
  visited.add(node);

  if (Array.isArray(node)) {
    return node.some((item) => scanAdminZone(item, zoneLower, visited));
  }

  for (const [key, value] of Object.entries(node)) {
    const keyLower = key.toLowerCase();
    if (keyLower.includes('admin') || keyLower.includes('management')) {
      if (subtreeContainsString(value, zoneLower, new Set())) return true;
    }
    if (scanAdminZone(value, zoneLower, visited)) return true;
  }
  return false;
}

/**
 * PURE tri-state predicate evaluator. Never throws — any internal error,
 * unknown predicate type, null config, or malformed predicate config returns
 * 'unknown'.
 *
 * @param {string} predicateType
 * @param {object} predicateConfig - already-parsed jsonb
 * @param {object} configParsed - already-parsed jsonb (device config)
 * @returns {'yes'|'no'|'unknown'}
 */
function evaluatePredicate(predicateType, predicateConfig, configParsed) {
  try {
    if (configParsed === null || configParsed === undefined) return 'unknown';
    if (predicateConfig === null || predicateConfig === undefined || typeof predicateConfig !== 'object') {
      return 'unknown';
    }

    switch (predicateType) {
      case 'config_key_exists': {
        if (typeof predicateConfig.path !== 'string' || predicateConfig.path === '') return 'unknown';
        const value = getByPath(configParsed, predicateConfig.path);
        return value !== undefined ? 'yes' : 'no';
      }

      case 'config_value_equals': {
        if (typeof predicateConfig.path !== 'string' || predicateConfig.path === '') return 'unknown';
        if (predicateConfig.value === undefined) return 'unknown';
        const actual = getByPath(configParsed, predicateConfig.path);
        if (actual === undefined) return 'no';
        return String(actual).toLowerCase() === String(predicateConfig.value).toLowerCase()
          ? 'yes'
          : 'no';
      }

      case 'config_value_matches': {
        if (typeof predicateConfig.path !== 'string' || predicateConfig.path === '') return 'unknown';
        if (typeof predicateConfig.pattern !== 'string') return 'unknown';
        const actual = getByPath(configParsed, predicateConfig.path);
        if (actual === undefined) return 'no';
        let regex;
        try {
          regex = new RegExp(predicateConfig.pattern, 'i');
        } catch (err) {
          return 'unknown'; // invalid regex in curated data
        }
        return regex.test(String(actual)) ? 'yes' : 'no';
      }

      case 'feature_enabled': {
        if (typeof predicateConfig.path !== 'string' || predicateConfig.path === '') return 'unknown';
        const value = getByPath(configParsed, predicateConfig.path);
        if (value === undefined) return 'no';
        const normalized = String(value).toLowerCase();
        if (TRUTHY_FEATURE_VALUES.includes(normalized)) return 'yes';
        if (FALSY_FEATURE_VALUES.includes(normalized)) return 'no';
        return 'unknown';
      }

      case 'port_exposed': {
        const portNum = Number(predicateConfig.port);
        if (!Number.isFinite(portNum)) return 'unknown';
        const keyMatch = (key) => PORT_KEY_NAMES.includes(key.toLowerCase());
        const valueMatch = (v) =>
          (typeof v === 'number' || typeof v === 'string') && Number(v) === portNum;
        const found = deepScan(configParsed, keyMatch, valueMatch, new Set());
        // Absence of evidence is not provable absence for port exposure.
        return found ? 'yes' : 'unknown';
      }

      case 'admin_access_from_zone': {
        if (typeof predicateConfig.zone !== 'string' || predicateConfig.zone === '') return 'unknown';
        const found = scanAdminZone(configParsed, predicateConfig.zone.toLowerCase(), new Set());
        return found ? 'yes' : 'unknown';
      }

      default:
        return 'unknown';
    }
  } catch (err) {
    // The evaluator must never throw — curated predicate data may be
    // malformed; treat any failure conservatively.
    return 'unknown';
  }
}

/**
 * AND-combine a set of advisory_conditions rows against a parsed config.
 *
 * - empty/null conditions → 'unknown' (NEVER 'no' — see CLAUDE.md)
 * - null configParsed → 'unknown'
 * - any condition 'no' → 'no'; else any 'unknown' → 'unknown'; else 'yes'
 *
 * @param {object[]} conditions - advisory_conditions rows (predicate_type, predicate_config already-parsed jsonb)
 * @param {object|null} configParsed
 * @returns {'yes'|'no'|'unknown'}
 */
function computeConfigApplies(conditions, configParsed) {
  if (!Array.isArray(conditions) || conditions.length === 0) return 'unknown';
  if (configParsed === null || configParsed === undefined) return 'unknown';

  let sawUnknown = false;
  for (const condition of conditions) {
    const result = evaluatePredicate(
      condition.predicate_type,
      condition.predicate_config,
      configParsed
    );
    if (result === 'no') return 'no';
    if (result === 'unknown') sawUnknown = true;
  }
  return sawUnknown ? 'unknown' : 'yes';
}

/**
 * Detailed per-condition evaluation for the admin "test predicate against
 * device" UI/API.
 *
 * @param {object[]} conditions - advisory_conditions rows
 * @param {object|null} configParsed
 * @returns {{config_applies: 'yes'|'no'|'unknown', per_condition: {id:string, condition_description:string, predicate_type:string, result:'yes'|'no'|'unknown'}[]}}
 */
function evaluateConditionsDetailed(conditions, configParsed) {
  const rows = Array.isArray(conditions) ? conditions : [];
  const perCondition = rows.map((condition) => ({
    id: condition.id,
    condition_description: condition.condition_description,
    predicate_type: condition.predicate_type,
    result: evaluatePredicate(condition.predicate_type, condition.predicate_config, configParsed),
  }));

  return {
    config_applies: computeConfigApplies(rows, configParsed),
    per_condition: perCondition,
  };
}

/**
 * Latest device_configs.config_parsed for a device, or null when the device
 * has no config snapshot (or the snapshot has no parsed form).
 *
 * @param {string} deviceId
 * @param {import('pg').Pool} pool
 * @returns {Promise<object|null>}
 */
async function getLatestConfigParsed(deviceId, pool) {
  const { rows } = await pool.query(
    'SELECT config_parsed FROM device_configs WHERE device_id = $1 ORDER BY collected_at DESC LIMIT 1',
    [deviceId]
  );
  if (rows.length === 0) return null;
  return rows[0].config_parsed !== undefined && rows[0].config_parsed !== null
    ? rows[0].config_parsed
    : null;
}

/**
 * Load all advisory_conditions rows for a vendor in one query, grouped by
 * advisory_id. Advisories with no rows simply do not appear in the Map —
 * callers must treat a missing key as 'unknown' (NEVER 'no').
 *
 * @param {import('pg').Pool} pool
 * @param {string} vendor
 * @returns {Promise<Map<string, object[]>>}
 */
async function loadConditionsByAdvisory(pool, vendor) {
  const { rows } = await pool.query(
    'SELECT ac.* FROM advisory_conditions ac JOIN advisories a ON a.id = ac.advisory_id WHERE a.vendor = $1',
    [vendor]
  );

  const byAdvisory = new Map();
  for (const row of rows) {
    const key = String(row.advisory_id);
    if (!byAdvisory.has(key)) byAdvisory.set(key, []);
    byAdvisory.get(key).push(row);
  }
  return byAdvisory;
}

/**
 * config_applies for a single device x advisory pair: loads that advisory's
 * conditions and the device's latest parsed config, then AND-combines.
 *
 * @param {string} deviceId
 * @param {string} advisoryId
 * @param {import('pg').Pool} pool
 * @returns {Promise<'yes'|'no'|'unknown'>}
 */
async function getConfigAppliesForDevice(deviceId, advisoryId, pool) {
  const { rows: conditions } = await pool.query(
    'SELECT * FROM advisory_conditions WHERE advisory_id = $1',
    [advisoryId]
  );
  const configParsed = await getLatestConfigParsed(deviceId, pool);
  return computeConfigApplies(conditions, configParsed);
}

module.exports = {
  evaluatePredicate,
  computeConfigApplies,
  evaluateConditionsDetailed,
  getLatestConfigParsed,
  loadConditionsByAdvisory,
  getConfigAppliesForDevice,
};
