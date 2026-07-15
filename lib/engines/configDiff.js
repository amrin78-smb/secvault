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
 * the shared diff accumulator.
 */
function diffValue(oldVal, newVal, path, acc) {
  const bothObjects = isPlainObject(oldVal) && isPlainObject(newVal);
  const bothArrays = Array.isArray(oldVal) && Array.isArray(newVal);

  if (bothObjects) {
    const keys = new Set([...Object.keys(oldVal), ...Object.keys(newVal)]);
    for (const key of keys) {
      const p = childPath(path, key, false);
      const inOld = Object.prototype.hasOwnProperty.call(oldVal, key) && oldVal[key] !== undefined;
      const inNew = Object.prototype.hasOwnProperty.call(newVal, key) && newVal[key] !== undefined;
      if (inOld && !inNew) {
        acc.removed.push({ path: p, value: oldVal[key] });
      } else if (!inOld && inNew) {
        acc.added.push({ path: p, value: newVal[key] });
      } else if (inOld && inNew) {
        diffValue(oldVal[key], newVal[key], p, acc);
      }
    }
    return;
  }

  if (bothArrays) {
    const maxLen = Math.max(oldVal.length, newVal.length);
    for (let i = 0; i < maxLen; i++) {
      const p = childPath(path, i, true);
      if (i >= oldVal.length) {
        acc.added.push({ path: p, value: newVal[i] });
      } else if (i >= newVal.length) {
        acc.removed.push({ path: p, value: oldVal[i] });
      } else {
        diffValue(oldVal[i], newVal[i], p, acc);
      }
    }
    return;
  }

  // Mixed types (object vs array vs primitive) or two primitive leaves:
  // compare with strict equality after JSON-normalization. Any container
  // type mismatch is always a modification.
  if (isPlainObject(oldVal) || isPlainObject(newVal) || Array.isArray(oldVal) || Array.isArray(newVal)) {
    acc.modified.push({ path, old: oldVal, new: newVal });
    return;
  }

  if (normalizeLeaf(oldVal) !== normalizeLeaf(newVal)) {
    acc.modified.push({ path, old: oldVal, new: newVal });
  }
}

/**
 * PURE deep recursive diff of two plain JSON objects (parsed configs).
 * null/undefined inputs are treated as {}.
 *
 * @param {object|null|undefined} oldParsed
 * @param {object|null|undefined} newParsed
 * @returns {{added: {path:string,value:*}[], removed: {path:string,value:*}[], modified: {path:string,old:*,new:*}[]}}
 */
function diffConfigs(oldParsed, newParsed) {
  const oldObj = oldParsed === null || oldParsed === undefined ? {} : oldParsed;
  const newObj = newParsed === null || newParsed === undefined ? {} : newParsed;

  const acc = { added: [], removed: [], modified: [] };
  diffValue(oldObj, newObj, '', acc);

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
 * @returns {Promise<{changed: boolean, diffId: string|null, summary: string|null}>}
 */
async function detectAndStoreDiff(deviceId, pool) {
  const { rows } = await pool.query(
    'SELECT id, config_parsed, collected_at FROM device_configs WHERE device_id = $1 ORDER BY collected_at DESC LIMIT 2',
    [deviceId]
  );

  if (rows.length < 2) {
    return { changed: false, diffId: null, summary: null };
  }

  // rows[0] = newest snapshot, rows[1] = previous snapshot.
  // config_parsed is jsonb and arrives already-parsed from pg.
  const diff = diffConfigs(rows[1].config_parsed, rows[0].config_parsed);

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
