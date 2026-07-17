// lib/engines/configDiff.js
//
// Phase 6 config-diff engine: pure deep diff of two parsed config snapshots
// (device_configs.config_parsed jsonb), persistence of detected diffs into
// config_diffs, and labeled snapshot copies into config_backups.
//
// diffConfigs / summarizeDiff / isEmptyDiff are PURE — no DB, no I/O.
// detectAndStoreDiff / createBackup take `pool` as a parameter per CLAUDE.md
// (NEVER omit pool from any function that touches the DB).

'use strict';

const MAX_DIFF_ENTRIES = 500;
const VALID_BACKUP_LABELS = ['auto', 'manual', 'pre-change'];

// ---------------------------------------------------------------------------
// Volatile-path exclusion (change-detection noise suppression)
// ---------------------------------------------------------------------------
//
// Some vendor parsers merge live device TELEMETRY (clock, uptime, auto-updating
// signature/content version stamps) into the same config_parsed tree as the real
// CONFIGURATION (rules, zones, admin settings) — see lib/adapters/paloalto/parser.js
// parseConfig() and lib/adapters/paloalto/sshParser.js parseConfig(), both of which
// merge the FULL `show system info` result under `system_info`. Diffing that
// wholesale produces a "config changed" notification on every single poll, because
// telemetry like the clock is mathematically guaranteed to differ every time —
// noise that buries real changes and defeats the point of this feature.
//
// This registry lists EXACT dot-paths (never fuzzy/regex patterns — each entry
// must be individually grounded in real parser code or a confirmed live log) to
// skip when producing add/remove/modify entries. The exclusion is per-leaf-path,
// not a whole-subtree skip: sibling keys under the same parent object (e.g.
// `system_info.hostname`, `system_info.sw-version`) are NOT excluded and still
// report real, meaningful changes (a firmware upgrade or rename) — see the
// "config change on config diff" CVE re-match hook in lib/adapters/index.js,
// which needs sw-version changes to keep firing.
//
// An absent/missing vendor key means "no exclusions" — never "everything
// excluded". Do not add an entry for a vendor whose config_parsed shape has not
// been verified against real hardware (see CLAUDE.md "Live Validation Status").
const VOLATILE_PATHS_BY_VENDOR = {
  paloalto: new Set([
    'system_info.time', // live device clock -- differs on every poll by definition
    'system_info.uptime', // seconds/days since boot -- always increases
    'system_info.wildfire-version', // WildFire signature content version, auto-updates
    'system_info.url-filtering-version', // URL filtering content version, auto-updates
  ]),
  // Other vendors: no grounded evidence (yet) of a live-telemetry field merged into
  // config_parsed by their parsers — see lib/adapters/{fortinet,cisco_asa,checkpoint,
  // sangfor,forcepoint}. Do not add speculative entries here.
};

function volatilePathsForVendor(vendor) {
  return VOLATILE_PATHS_BY_VENDOR[vendor] || new Set();
}

/**
 * True for plain objects (not arrays, not null).
 */
function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/**
 * JSON-normalize a primitive leaf before comparison: non-finite numbers
 * become null (as JSON.stringify would emit), everything else passes through.
 */
function normalizeLeaf(v) {
  if (typeof v === 'number' && !Number.isFinite(v)) return null;
  return v;
}

/**
 * Build a child path in dot notation. Array indices render as `[i]`
 * (e.g. `interfaces[2].name`).
 */
function childPath(parentPath, key, isIndex) {
  if (isIndex) {
    return `${parentPath}[${key}]`;
  }
  return parentPath === '' ? String(key) : `${parentPath}.${key}`;
}

/**
 * Recursive worker: compares oldVal/newVal at `path`, pushing entries into
 * the shared diff accumulator. `volatilePaths` (a Set of exact dot-paths) is
 * checked before every push — recursion into objects/arrays always happens
 * regardless, so exclusion is strictly per-leaf-path, never a whole-subtree
 * skip (see VOLATILE_PATHS_BY_VENDOR above).
 */
function diffValue(oldVal, newVal, path, acc, volatilePaths) {
  const bothObjects = isPlainObject(oldVal) && isPlainObject(newVal);
  const bothArrays = Array.isArray(oldVal) && Array.isArray(newVal);

  if (bothObjects) {
    const keys = new Set([...Object.keys(oldVal), ...Object.keys(newVal)]);
    for (const key of keys) {
      const p = childPath(path, key, false);
      const inOld = Object.prototype.hasOwnProperty.call(oldVal, key) && oldVal[key] !== undefined;
      const inNew = Object.prototype.hasOwnProperty.call(newVal, key) && newVal[key] !== undefined;
      if (inOld && !inNew) {
        if (!volatilePaths.has(p)) acc.removed.push({ path: p, value: oldVal[key] });
      } else if (!inOld && inNew) {
        if (!volatilePaths.has(p)) acc.added.push({ path: p, value: newVal[key] });
      } else if (inOld && inNew) {
        diffValue(oldVal[key], newVal[key], p, acc, volatilePaths);
      }
    }
    return;
  }

  if (bothArrays) {
    const maxLen = Math.max(oldVal.length, newVal.length);
    for (let i = 0; i < maxLen; i++) {
      const p = childPath(path, i, true);
      if (i >= oldVal.length) {
        if (!volatilePaths.has(p)) acc.added.push({ path: p, value: newVal[i] });
      } else if (i >= newVal.length) {
        if (!volatilePaths.has(p)) acc.removed.push({ path: p, value: oldVal[i] });
      } else {
        diffValue(oldVal[i], newVal[i], p, acc, volatilePaths);
      }
    }
    return;
  }

  // Mixed types (object vs array vs primitive) or two primitive leaves:
  // compare with strict equality after JSON-normalization. Any container
  // type mismatch is always a modification.
  if (isPlainObject(oldVal) || isPlainObject(newVal) || Array.isArray(oldVal) || Array.isArray(newVal)) {
    if (!volatilePaths.has(path)) acc.modified.push({ path, old: oldVal, new: newVal });
    return;
  }

  if (normalizeLeaf(oldVal) !== normalizeLeaf(newVal)) {
    if (!volatilePaths.has(path)) acc.modified.push({ path, old: oldVal, new: newVal });
  }
}

/**
 * PURE deep recursive diff of two plain JSON objects (parsed configs).
 * null/undefined inputs are treated as {}.
 *
 * @param {object|null|undefined} oldParsed
 * @param {object|null|undefined} newParsed
 * @param {string} [vendor] - optional; looks up VOLATILE_PATHS_BY_VENDOR to skip
 *   known-volatile telemetry leaves (device clock, uptime, auto-updating content
 *   version stamps) during diffing. Omitted (existing 2-arg call sites) → no
 *   exclusions, fully backward compatible.
 * @returns {{added: {path:string,value:*}[], removed: {path:string,value:*}[], modified: {path:string,old:*,new:*}[]}}
 */
function diffConfigs(oldParsed, newParsed, vendor) {
  const oldObj = oldParsed === null || oldParsed === undefined ? {} : oldParsed;
  const newObj = newParsed === null || newParsed === undefined ? {} : newParsed;
  const volatilePaths = volatilePathsForVendor(vendor);

  const acc = { added: [], removed: [], modified: [] };
  diffValue(oldObj, newObj, '', acc, volatilePaths);

  const total = acc.added.length + acc.removed.length + acc.modified.length;
  if (total > MAX_DIFF_ENTRIES) {
    let remaining = MAX_DIFF_ENTRIES;
    const added = acc.added.slice(0, remaining);
    remaining -= added.length;
    const removed = acc.removed.slice(0, remaining);
    remaining -= removed.length;
    const modified = acc.modified.slice(0, remaining);
    added.push({ path: '(truncated)', value: `diff exceeded ${MAX_DIFF_ENTRIES} entries` });
    return { added, removed, modified };
  }

  return acc;
}

/**
 * True when the diff contains no changes at all.
 *
 * @param {{added:object[],removed:object[],modified:object[]}} diff
 * @returns {boolean}
 */
function isEmptyDiff(diff) {
  if (!diff) return true;
  const added = Array.isArray(diff.added) ? diff.added : [];
  const removed = Array.isArray(diff.removed) ? diff.removed : [];
  const modified = Array.isArray(diff.modified) ? diff.modified : [];
  return added.length === 0 && removed.length === 0 && modified.length === 0;
}

/**
 * Human-readable one-liner for a diff, e.g.
 * "2 added, 1 removed, 3 modified — e.g. interfaces[2].name, log_server, antivirus.enabled"
 *
 * @param {{added:object[],removed:object[],modified:object[]}} diff
 * @returns {string}
 */
function summarizeDiff(diff) {
  if (isEmptyDiff(diff)) return 'no changes';

  const added = Array.isArray(diff.added) ? diff.added : [];
  const removed = Array.isArray(diff.removed) ? diff.removed : [];
  const modified = Array.isArray(diff.modified) ? diff.modified : [];

  const parts = [];
  if (added.length > 0) parts.push(`${added.length} added`);
  if (removed.length > 0) parts.push(`${removed.length} removed`);
  if (modified.length > 0) parts.push(`${modified.length} modified`);

  const examplePaths = [];
  for (const entry of [...added, ...removed, ...modified]) {
    if (examplePaths.length >= 3) break;
    if (entry.path === '(truncated)') continue;
    examplePaths.push(entry.path);
  }

  let summary = parts.join(', ');
  if (examplePaths.length > 0) {
    summary += ` — e.g. ${examplePaths.join(', ')}`;
  }
  return summary;
}

/**
 * Compare the two most recent device_configs snapshots for a device and, if
 * they differ, persist a config_diffs row.
 *
 * @param {string} deviceId
 * @param {import('pg').Pool} pool
 * @param {string} [vendor] - optional device vendor slug (e.g. 'paloalto'), used to
 *   look up volatile-path exclusions for change-detection noise suppression. Omitted
 *   → no exclusions (backward compatible with any existing 2-arg caller).
 * @returns {Promise<{changed: boolean, diffId: string|null, summary: string|null}>}
 */
async function detectAndStoreDiff(deviceId, pool, vendor) {
  const { rows } = await pool.query(
    'SELECT id, config_parsed, collected_at FROM device_configs WHERE device_id = $1 ORDER BY collected_at DESC LIMIT 2',
    [deviceId]
  );

  if (rows.length < 2) {
    return { changed: false, diffId: null, summary: null };
  }

  // rows[0] = newest snapshot, rows[1] = previous snapshot.
  // config_parsed is jsonb and arrives already-parsed from pg.
  const diff = diffConfigs(rows[1].config_parsed, rows[0].config_parsed, vendor);

  if (isEmptyDiff(diff)) {
    return { changed: false, diffId: null, summary: null };
  }

  const summary = summarizeDiff(diff);
  const { rows: inserted } = await pool.query(
    'INSERT INTO config_diffs (device_id, diff, change_summary) VALUES ($1, $2::jsonb, $3) RETURNING id',
    [deviceId, JSON.stringify(diff), summary]
  );

  return { changed: true, diffId: inserted[0].id, summary };
}

/**
 * Copy the latest device_configs.config_raw into config_backups with the
 * given label ('auto' | 'manual' | 'pre-change'; invalid labels default to
 * 'manual').
 *
 * @param {string} deviceId
 * @param {string} label
 * @param {import('pg').Pool} pool
 * @returns {Promise<{backupId: string|null}>}
 */
async function createBackup(deviceId, label, pool) {
  const safeLabel = VALID_BACKUP_LABELS.includes(label) ? label : 'manual';

  const { rows } = await pool.query(
    'SELECT config_raw FROM device_configs WHERE device_id = $1 ORDER BY collected_at DESC LIMIT 1',
    [deviceId]
  );

  if (rows.length === 0) {
    return { backupId: null };
  }

  const { rows: inserted } = await pool.query(
    'INSERT INTO config_backups (device_id, config_raw, label) VALUES ($1, $2, $3) RETURNING id',
    [deviceId, rows[0].config_raw, safeLabel]
  );

  return { backupId: inserted[0].id };
}

module.exports = {
  diffConfigs,
  summarizeDiff,
  isEmptyDiff,
  detectAndStoreDiff,
  createBackup,
};
