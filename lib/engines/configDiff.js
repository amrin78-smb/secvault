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
 * True when `path` is exactly a registered volatile-subtree root (e.g.
 * `system_info` for paloalto) -- used by diffValue() to detect the
 * whole-subtree-added/removed case, where the entire object appears or
 * disappears between two collects as ONE diff entry rather than being
 * diffed field-by-field. See the isVolatilePath() block comment above:
 * that function only ever matches a nested leaf path like `system_info.time`
 * (prefix + trailing dot), never the bare root itself.
 */
function isRegisteredSubtreeRoot(path, vendor) {
  const subtrees = vendor ? MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR[vendor] : null;
  if (!subtrees) return false;
  return Object.prototype.hasOwnProperty.call(subtrees, path);
}

// ---------------------------------------------------------------------------
// Value-level secret redaction (defense in depth)
// ---------------------------------------------------------------------------
//
// diffConfigs() blindly captures whatever old/new/value it's given for a
// changed leaf -- it has no awareness that a leaf might be a secret. Every
// vendor adapter is responsible for redacting config_parsed BEFORE it's ever
// stored (see each adapter's own redactSecretFields/redactSecrets/
// isSecretKey), so in the normal case this layer should never have anything
// to do. But a real incident (found 2026-07-19, via a live production DB
// check prompted by a user report that the Dashboard's "Config Changes"
// widget looked wrong) proved the assumption alone isn't enough: a Palo Alto
// SSH device's config_parsed briefly held a raw, unredacted certificate
// private-key and several local-admin password hashes before that vendor's
// own redaction was fixed -- and because detectAndStoreDiff() happened to run
// across exactly that transition (old snapshot = raw secret, new snapshot =
// the vendor's own '<redacted>' placeholder), the RAW secret got captured
// into config_diffs.diff's `old` field and persisted there. config_diffs is
// GRANT SELECT'd to claude_readonly/nocvault_readonly -- the exact roles
// CLAUDE.md bars from device_credentials. A per-vendor redaction bug upstream
// must never become a THIRD table's secret-disclosure bug just because the
// diff engine faithfully repeats whatever it's handed -- same "fail closed,
// redact defensively even when it's unverified whether upstream already
// redacted" posture this codebase already applies elsewhere (Check Point's
// and Forcepoint's own getConfig() redaction, added for the identical
// reason). Mirrors lib/adapters/checkpoint/parser.js's and
// lib/adapters/forcepoint/parser.js's identical SECRET_KEY_PATTERN
// convention, widened here to also catch `phash` (Palo Alto's local-admin
// password-hash field name -- the exact field that leaked) and
// `pre[-_]?shared` (a bare `private[-_]?key` check does NOT match
// "pre-shared-key" -- different word entirely, confirmed by testing the
// original pattern against the real leaked path and finding it silently
// missed).
const SECRET_PATH_PATTERN =
  /secret|password|passwd|psk|pre[-_]?shared|private[-_]?key|phash|community|credential|token|api[-_]?key|keytab/i;

// Section/setting NAMES that happen to contain a secret-shaped substring but
// are not themselves credential values -- found live while verifying this
// pattern against real production data: Fortinet's `password_policy` is a
// real, legitimate config_parsed section (CLAUDE.md's Compliance Engine
// section: config system password-policy, holding `minimum-length`/`status`,
// not a credential), and the bare substring match above would otherwise
// redact the WHOLE section wholesale. A small, explicit exception list (not
// a cleverer regex) so a future false positive is a one-line addition here,
// not a fragile regex rewrite -- same instinct as MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR's
// allowlist above, just inverted (a short denylist-of-exceptions is fine
// here because the failure mode of missing one is "over-redact a section",
// a safe direction, unlike the volatile-fields case where under-listing was
// unsafe).
const SECRET_PATH_EXCEPTIONS = new Set(['password_policy', 'password-policy']);

/**
 * True when the LEAF field name of a dot/bracket diff path looks secret-shaped
 * (same "check only the immediate field name, not the whole path" approach
 * isVolatilePath already uses).
 */
function isSecretPath(path) {
  const field = String(path).split(/[.[]/).pop();
  if (SECRET_PATH_EXCEPTIONS.has(field.toLowerCase())) return false;
  return SECRET_PATH_PATTERN.test(field);
}

/**
 * Recursively redacts any secret-shaped KEY found inside a nested
 * object/array value. isSecretPath()/redactSecretEntries() above only ever
 * inspect a diff entry's own top-level path -- for a one-sided added/removed
 * entry, diffValue() never recurses into the subtree it's carrying (see
 * diffValue()'s bothObjects/bothArrays branches), so the whole object lands
 * in `value` unexamined. This walks that carried value on its own, so a
 * secret nested a level or more down (e.g. a newly-added admin user object's
 * `phash` field) still gets caught even though the entry's own path
 * ('mgt-config.users.newadmin') isn't itself secret-shaped. Depth-capped as
 * a defensive guard against pathological/unexpectedly-deep input, not
 * because deep configs are expected.
 */
function deepRedactSecrets(value, depth) {
  if (depth > 25) return value;
  if (Array.isArray(value)) {
    return value.map((v) => deepRedactSecrets(v, depth + 1));
  }
  if (isPlainObject(value)) {
    const out = {};
    for (const key of Object.keys(value)) {
      out[key] = isSecretPath(key) ? '<redacted>' : deepRedactSecrets(value[key], depth + 1);
    }
    return out;
  }
  return value;
}

/**
 * Redacts old/new/value on any diff entry whose path looks secret-shaped,
 * AND deep-redacts any secret-shaped key nested inside a carried
 * object/array value even when the entry's own path isn't secret-shaped
 * (see deepRedactSecrets() above -- covers the whole-subtree added/removed
 * case). Never throws -- a redaction error fails an entry CLOSED (a
 * placeholder string), never leaves the original value in place, matching
 * the fail-closed posture of every other redactor in this codebase.
 */
function redactSecretEntries(entries) {
  return (entries || []).map((e) => {
    try {
      const redacted = { ...e };
      if (isSecretPath(e.path)) {
        if ('value' in redacted) redacted.value = '<redacted>';
        if ('old' in redacted) redacted.old = '<redacted>';
        if ('new' in redacted) redacted.new = '<redacted>';
        return redacted;
      }
      if ('value' in redacted) redacted.value = deepRedactSecrets(redacted.value, 0);
      if ('old' in redacted) redacted.old = deepRedactSecrets(redacted.old, 0);
      if ('new' in redacted) redacted.new = deepRedactSecrets(redacted.new, 0);
      return redacted;
    } catch (_err) {
      return { ...e, value: '<redaction-error>', old: '<redaction-error>', new: '<redaction-error>' };
    }
  });
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
        // A whole-subtree REMOVE that matches a registered volatile-subtree
        // root (e.g. paloalto's `system_info`) is decomposed via a recursive
        // diff against {} instead of captured as one opaque entry --
        // isVolatilePath() only ever matches a nested leaf path (the root's
        // own bare path never matches its own `${root}.` prefix), so without
        // this the whole subtree's noisy fields bypass filtering entirely.
        // See isRegisteredSubtreeRoot()'s comment above.
        if (isPlainObject(oldVal[key]) && isRegisteredSubtreeRoot(p, vendor)) {
          diffValue(oldVal[key], {}, p, acc, vendor);
        } else if (!isVolatilePath(p, vendor)) {
          acc.removed.push({ path: p, value: oldVal[key] });
        }
      } else if (!inOld && inNew) {
        if (isPlainObject(newVal[key]) && isRegisteredSubtreeRoot(p, vendor)) {
          diffValue({}, newVal[key], p, acc, vendor);
        } else if (!isVolatilePath(p, vendor)) {
          acc.added.push({ path: p, value: newVal[key] });
        }
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

  // Defense-in-depth secret redaction -- see the SECRET_PATH_PATTERN block
  // comment above for why this exists even though config_parsed is already
  // supposed to be redacted before it ever reaches this function.
  acc.added = redactSecretEntries(acc.added);
  acc.removed = redactSecretEntries(acc.removed);
  acc.modified = redactSecretEntries(acc.modified);

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
 * Re-applies isVolatilePath AND redactSecretEntries to an already-computed
 * diff object, returning a new {added, removed, modified} with volatile
 * entries stripped and any secret-shaped value redacted. Used by
 * cleanupVolatileConfigDiffs() below to retroactively re-filter EXISTING
 * config_diffs rows through the CURRENT rules, not just new diffs -- this
 * is what actually scrubs an already-persisted raw secret out of the
 * database, not just prevents new ones (see SECRET_PATH_PATTERN's block
 * comment above for the incident this closes).
 */
function filterDiffForCurrentRules(diff, vendor) {
  const filterOne = (list) => redactSecretEntries((list || []).filter((e) => !isVolatilePath(e.path, vendor)));
  return {
    added: filterOne(diff.added),
    removed: filterOne(diff.removed),
    modified: filterOne(diff.modified),
  };
}

/**
 * One-time (but safely re-runnable) retroactive cleanup covering TWO separate historical gaps
 * that both left already-persisted config_diffs rows wrong by CURRENT rules:
 *
 * 1. Noise: MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR above didn't exist yet when the earliest rows
 *    were recorded, so a device with nothing but device-clock/uptime/auto-updating-signature-
 *    version noise between two collects still got a config_diffs row inserted -- visible in the
 *    Dashboard's "Config Changes" widget and the per-device Changes timeline looking exactly
 *    like an admin-made change, which it wasn't.
 * 2. Secret disclosure: SECRET_PATH_PATTERN above didn't exist yet either, so at least one row
 *    captured a raw, unredacted private key and password hashes verbatim (see that block
 *    comment for the full incident) -- a live secret sitting in a table granted to the readonly
 *    diagnostic roles.
 *
 * Re-runs BOTH current rules (filterDiffForCurrentRules = volatile-path filter + secret
 * redaction) against every EXISTING row's stored diff JSON. A row that becomes fully empty
 * after filtering is deleted outright (it was 100% noise). A row that still has real content
 * (e.g. a genuine credential rotation recorded the same day as that day's clock/uptime noise)
 * is UPDATED in place instead -- dropping the noise, redacting any secret value, and
 * re-deriving change_summary from what's left -- never silently discarding a real change just
 * because noise or a secret happened to be sitting next to it in the same row. Compares the
 * full re-filtered object (not just entry counts) against the original, since secret redaction
 * can change a row's CONTENT (a value going from raw to '<redacted>') without changing its
 * entry COUNT at all -- a pure count comparison would silently miss exactly the secret-leak
 * case this migration exists to fix.
 *
 * Best-effort / non-fatal, same reasoning as backfillVulnerabilityCategories() in
 * lib/engines/vulnerabilityCategory.js: a failure here just means some historical noise (or,
 * worse, an unredacted secret) lingers until the next successful migrate run, not a broken
 * feature -- logged loudly by main() either way, never silently swallowed. Safe to re-run
 * indefinitely -- a row with nothing left to change is left untouched.
 */
async function cleanupVolatileConfigDiffs(pool) {
  const { rows } = await pool.query(
    `SELECT cd.id, cd.diff, d.vendor
     FROM config_diffs cd
     JOIN devices d ON d.id = cd.device_id`
  );

  let deleted = 0;
  let updated = 0;

  for (const row of rows) {
    const original = row.diff || {};
    const originalNormalized = {
      added: original.added || [],
      removed: original.removed || [],
      modified: original.modified || [],
    };
    const filtered = filterDiffForCurrentRules(original, row.vendor);
    const filteredCount = filtered.added.length + filtered.removed.length + filtered.modified.length;

    if (JSON.stringify(filtered) === JSON.stringify(originalNormalized)) continue; // nothing to clean up

    if (filteredCount === 0) {
      await pool.query('DELETE FROM config_diffs WHERE id = $1', [row.id]);
      deleted += 1;
    } else {
      const summary = summarizeDiff(filtered);
      await pool.query('UPDATE config_diffs SET diff = $1::jsonb, change_summary = $2 WHERE id = $3', [
        JSON.stringify(filtered),
        summary,
        row.id,
      ]);
      updated += 1;
    }
  }

  return { checked: rows.length, deleted, updated };
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
  filterDiffForCurrentRules,
  cleanupVolatileConfigDiffs,
};
