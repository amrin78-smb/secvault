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
// Volatile-subtree filtering (change-detection noise suppression)
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
// ⛔ v2.2.0 shipped an EXACT-PATH DENYLIST here (4 entries: time, uptime,
// wildfire-version, url-filtering-version). A live user report surfaced a 5th
// noisy field (system_info.wildfire-release-date) that list had missed within
// a day — `show system info` has an entire FAMILY of paired *-version/
// *-release-date content-signature fields (app/av/threat/wildfire/
// url-filtering/global-protect-datafile/global-protect-clientless-vpn/logdb),
// all auto-updating, none admin-configured. Individually discovering and
// denying each one as a user hits it doesn't converge.
//
// Flipped the polarity for this one known-noisy subtree: an ALLOWLIST of the
// handful of `system_info` fields that ARE meaningful (device identity +
// firmware version) — everything else under `system_info` is excluded by
// default, rather than needing to be individually found and denied. Real
// fields like `sw-version` (a genuine firmware upgrade — must keep firing the
// CVE re-match hook in lib/adapters/index.js) and `hostname` (a rename) still
// report correctly; any OTHER `system_info.*` key, present or future, is
// treated as telemetry unless explicitly allowlisted below.
//
// A vendor with no entry here gets NO filtering at all (nothing excluded) —
// do not add one for a vendor whose config_parsed shape has not been
// verified against real hardware (see CLAUDE.md "Live Validation Status").
const MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR = {
  paloalto: {
    system_info: new Set([
      'hostname',
      'sw-version', // real PAN-OS firmware version -- must keep firing the CVE re-match hook
      'model',
      'serial',
      'multi-vsys',
      'operational-mode',
      'ip-address',
      'ipv6-address',
      'mac-address',
      'family',
      'devicename',
      'platform-family',
      'vpn-disable-mode',
    ]),
  },
  // Other vendors: no grounded evidence (yet) of a live-telemetry subtree merged
  // into config_parsed by their parsers — see lib/adapters/{fortinet,cisco_asa,
  // checkpoint,sangfor,forcepoint}. Do not add speculative entries here.
};

/**
 * True when `path` falls inside a registered noisy subtree (e.g.
 * `system_info.*`) for this vendor AND its immediate field name under that
 * subtree root is NOT in the allowlist. A vendor with no registry entry never
 * excludes anything — this only ever narrows what's reported for vendors
 * that have been explicitly, individually opted in above.
 */
function isVolatilePath(path, vendor) {
  const subtrees = vendor ? MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR[vendor] : null;
  if (!subtrees) return false;
  for (const [root, allowedFields] of Object.entries(subtrees)) {
    const prefix = `${root}.`;
    if (path.startsWith(prefix)) {
      const field = path.slice(prefix.length).split(/[.[]/)[0];
      return !allowedFields.has(field);
    }
  }
  return false;
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
 * the shared diff accumulator. `isVolatilePath(p, vendor)` is checked before
 * every push — recursion into objects/arrays always happens regardless, so
 * exclusion is strictly per-leaf-path, never a whole-subtree skip (see
 * MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR above).
 */
function diffValue(oldVal, newVal, path, acc, vendor) {
  const bothObjects = isPlainObject(oldVal) && isPlainObject(newVal);
  const bothArrays = Array.isArray(oldVal) && Array.isArray(newVal);

  if (bothObjects) {
    const keys = new Set([...Object.keys(oldVal), ...Object.keys(newVal)]);
    for (const key of keys) {
      const p = childPath(path, key, false);
      const inOld = Object.prototype.hasOwnProperty.call(oldVal, key) && oldVal[key] !== undefined;
      const inNew = Object.prototype.hasOwnProperty.call(newVal, key) && newVal[key] !== undefined;
      if (inOld && !inNew) {
        if (!isVolatilePath(p, vendor)) acc.removed.push({ path: p, value: oldVal[key] });
      } else if (!inOld && inNew) {
        if (!isVolatilePath(p, vendor)) acc.added.push({ path: p, value: newVal[key] });
      } else if (inOld && inNew) {
        diffValue(oldVal[key], newVal[key], p, acc, vendor);
      }
    }
    return;
  }

  if (bothArrays) {
    const maxLen = Math.max(oldVal.length, newVal.length);
    for (let i = 0; i < maxLen; i++) {
      const p = childPath(path, i, true);
      if (i >= oldVal.length) {
        if (!isVolatilePath(p, vendor)) acc.added.push({ path: p, value: newVal[i] });
      } else if (i >= newVal.length) {
        if (!isVolatilePath(p, vendor)) acc.removed.push({ path: p, value: oldVal[i] });
      } else {
        diffValue(oldVal[i], newVal[i], p, acc, vendor);
      }
    }
    return;
  }

  // Mixed types (object vs array vs primitive) or two primitive leaves:
  // compare with strict equality after JSON-normalization. Any container
  // type mismatch is always a modification.
  if (isPlainObject(oldVal) || isPlainObject(newVal) || Array.isArray(oldVal) || Array.isArray(newVal)) {
    if (!isVolatilePath(path, vendor)) acc.modified.push({ path, old: oldVal, new: newVal });
    return;
  }

  if (normalizeLeaf(oldVal) !== normalizeLeaf(newVal)) {
    if (!isVolatilePath(path, vendor)) acc.modified.push({ path, old: oldVal, new: newVal });
  }
}

/**
 * PURE deep recursive diff of two plain JSON objects (parsed configs).
 * null/undefined inputs are treated as {}.
 *
 * @param {object|null|undefined} oldParsed
 * @param {object|null|undefined} newParsed
 * @param {string} [vendor] - optional; looks up MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR
 *   to skip known-volatile telemetry leaves (device clock, uptime, auto-updating
 *   content version stamps) during diffing. Omitted (existing 2-arg call sites) →
 *   no exclusions, fully backward compatible.
 * @returns {{added: {path:string,value:*}[], removed: {path:string,value:*}[], modified: {path:string,old:*,new:*}[]}}
 */
function diffConfigs(oldParsed, newParsed, vendor) {
  const oldObj = oldParsed === null || oldParsed === undefined ? {} : oldParsed;
  const newObj = newParsed === null || newParsed === undefined ? {} : newParsed;

  const acc = { added: [], removed: [], modified: [] };
  diffValue(oldObj, newObj, '', acc, vendor);

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
