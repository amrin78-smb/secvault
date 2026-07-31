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
    // `shared.content-preview` (added 2026-07-30, confirmed via Palo Alto's own
    // community/docs, not assumed): PAN-OS stages a preview of pending New/
    // Modified App-ID content there while a downloaded content update hasn't
    // been installed yet, and clears it again once the update is applied or
    // discarded -- system-managed telemetry tied to the automatic content-
    // release cycle, never an admin decision. A real user report showed this
    // firing "1 removed" config-diff alerts across many unrelated devices at
    // similar times, the same noise signature system_info's own filtering was
    // built for. EMPTY allowlist, unlike system_info above -- there is no
    // admin-meaningful field inside this node at all (application/
    // application-type/category/technology only ever describe the pending
    // preview payload itself), so every field under it is excluded, not just
    // an unlisted subset.
    'content-preview': new Set([]),
  },
  // Other vendors: no grounded evidence (yet) of a live-telemetry subtree merged
  // into config_parsed by their parsers — see lib/adapters/{fortinet,cisco_asa,
  // checkpoint,sangfor,forcepoint}. Do not add speculative entries here.
};

// Finds `root` as a distinct path SEGMENT anywhere in `path` (not just at the
// start) -- e.g. `root='content-preview'` matches inside
// `tree.shared.content-preview.application` regardless of how deep
// `content-preview` sits, since its real nesting differs by transport (SSH's
// `tree.shared.*`, XML/API's `devices.entry.vsys.entry.shared.*` or similar).
// `[N]` array-index suffixes are stripped before comparing, same convention
// `stripIndex()` uses elsewhere in this file. Returns the segment's index, or
// -1 if not found. `system_info` also happens to only ever appear at index 0
// in practice (both parsers merge it in at the top of config_parsed, per that
// entry's own comment) -- scanning the whole path instead of just the start
// is a strict broadening of what used to be an exact-prefix-from-root check,
// but a harmless one, since nothing currently produces a `system_info`
// segment anywhere else.
function findSubtreeRootIndex(path, root) {
  const segments = path.split('.');
  for (let i = 0; i < segments.length; i++) {
    if (segments[i].replace(/\[\d+\]$/, '') === root) return i;
  }
  return -1;
}

// Vendor-AGNOSTIC always-noise leaf fields — derived/computed summary values no
// admin edits directly, which only change as a side effect of a real change
// that is itself tracked far more usefully elsewhere. Unlike
// MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR (per-vendor, subtree-scoped), these match
// by LEAF FIELD NAME on EVERY vendor, so a field one brand emits today (or
// another adds tomorrow) is filtered uniformly with no per-vendor entry.
//
// `security_rules_count`: the Palo Alto parser derives it (findSecurityRulesContainers
// in lib/adapters/paloalto/sshParser.js) as a rulebase SIZE summary — it moves
// on every single rule add/remove, duplicating what the per-rule change table
// already reports. A real user report flagged a lone "security_rules_count:
// 51 → 53" row as pure noise. Only Palo Alto emits it today; matching by name
// rather than by vendor means any brand that later adds an equivalent count is
// covered for free.
const UNIVERSAL_VOLATILE_LEAF_FIELDS = new Set(['security_rules_count']);

// True when `path`'s LEAF field name is a vendor-agnostic always-noise field.
// Leaf-name match (last dot/bracket segment), same "check only the immediate
// field name" approach isSecretPath() uses.
function isUniversalVolatileLeaf(path) {
  const field = String(path).split('.').pop().replace(/\[\d+\]$/, '');
  return UNIVERSAL_VOLATILE_LEAF_FIELDS.has(field);
}

/**
 * True when `path` is volatile/noise and should be excluded from a diff. Two
 * independent reasons: (1) its leaf field is a vendor-AGNOSTIC always-noise
 * field (UNIVERSAL_VOLATILE_LEAF_FIELDS, e.g. `security_rules_count`), applied
 * on every vendor including the no-vendor call; or (2) it falls inside a
 * registered per-vendor noisy subtree (e.g. `system_info.*`, `content-preview.*`)
 * AND its immediate field under that root is NOT in the allowlist (an EMPTY
 * allowlist means every field under that root is volatile). A vendor with no
 * registry entry only ever hits reason (1).
 */
function isVolatilePath(path, vendor) {
  if (isUniversalVolatileLeaf(path)) return true;
  const subtrees = vendor ? MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR[vendor] : null;
  if (!subtrees) return false;
  const segments = path.split('.');
  for (const [root, allowedFields] of Object.entries(subtrees)) {
    const idx = findSubtreeRootIndex(path, root);
    if (idx === -1 || idx >= segments.length - 1) continue; // not found, or IS the bare root (see isRegisteredSubtreeRoot)
    const field = segments[idx + 1].replace(/\[\d+\]$/, '');
    return !allowedFields.has(field);
  }
  return false;
}

/**
 * True when `path` IS (ends at) a registered volatile-subtree root (e.g.
 * `system_info`, or `tree.shared.content-preview`) -- used by diffValue() to
 * detect the whole-subtree-added/removed case, where the entire object
 * appears or disappears between two collects as ONE diff entry rather than
 * being diffed field-by-field. See isVolatilePath()'s block comment above:
 * that function only ever matches a nested leaf path (root + a field
 * underneath it), never the bare root itself -- this is the complementary
 * check for exactly that bare-root case, matched by the root being the LAST
 * segment of `path` rather than requiring the whole path to equal it (see
 * findSubtreeRootIndex()'s comment on why this scans instead of anchoring at
 * the start).
 */
function isRegisteredSubtreeRoot(path, vendor) {
  const subtrees = vendor ? MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR[vendor] : null;
  if (!subtrees) return false;
  const segments = path.split('.');
  const lastSegment = segments[segments.length - 1].replace(/\[\d+\]$/, '');
  return Object.prototype.hasOwnProperty.call(subtrees, lastSegment);
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
 * True for a plain primitive leaf (string/number/boolean/null) — NOT an
 * object, NOT an array. Used to decide whether an array qualifies for the
 * LCS-based diff below (diffPrimitiveArrayLCS) vs. falling back to the
 * original positional comparison.
 */
function isPrimitiveArrayElement(v) {
  return !isPlainObject(v) && !Array.isArray(v);
}

/**
 * LCS-based diff for an array where EVERY element on BOTH sides is a plain
 * primitive (string/number/boolean/null) — e.g. a username list, a DNS/NTP
 * server list, a group-membership list. Scoped narrowly and deliberately:
 * see this function's caller (diffValue's bothArrays branch) for why arrays
 * containing any object/array element never reach this path.
 *
 * ⛔ WHY THIS EXISTS: the original positional (index-by-index) comparison
 * treated an array purely by POSITION — removing ONE entry from the middle
 * of a 20-username `local-user-database.user-group.<group>.user` array
 * shifted every subsequent index down by one, so a single real removal was
 * misreported as a dozen separate "modified" entries (`user[18]: satish →
 * sawitree`, `user[19]: sawitree → sopee`, ...) — a real production report
 * against exactly that path shape. An LCS alignment finds the longest run of
 * values common to both arrays (regardless of the position it sits at on
 * either side); anything in the OLD array not part of that common run is a
 * true removal, anything in the NEW array not part of it is a true addition,
 * and everything IN the common run produced NO entry at all — it never
 * "changed", it just shifted position, which is more honest than reporting
 * a "modification" for a value whose identity never actually changed.
 *
 * Standard O(n*m) DP-table LCS — these arrays are realistically tens to low
 * hundreds of entries (user lists, DNS/NTP server lists, group memberships),
 * not large enough to justify a smarter/linear algorithm.
 *
 * Equality uses normalizeLeaf() (same JSON-normalization diffValue's own
 * primitive-leaf comparison already uses below), so e.g. NaN/Infinity
 * compare the same way here as everywhere else in this file.
 *
 * Each produced added/removed entry still goes through isVolatilePath()
 * before being pushed, exactly like every other push site in this function —
 * this is purely a smarter WAY of walking the array, not an exemption from
 * the existing noise-filtering contract. Paths follow the same
 * childPath(path, i, true) convention used elsewhere: the OLD array's index
 * for a removed entry, the NEW array's index for an added entry.
 */
function diffPrimitiveArrayLCS(oldArr, newArr, path, acc, vendor) {
  const n = oldArr.length;
  const m = newArr.length;

  // dp[i][j] = length of the LCS of oldArr[i:] and newArr[j:].
  const dp = new Array(n + 1);
  for (let i = 0; i <= n; i++) dp[i] = new Array(m + 1).fill(0);

  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      if (normalizeLeaf(oldArr[i]) === normalizeLeaf(newArr[j])) {
        dp[i][j] = dp[i + 1][j + 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (normalizeLeaf(oldArr[i]) === normalizeLeaf(newArr[j])) {
      // Part of the common subsequence -- unchanged, just possibly shifted
      // position. No entry pushed at all.
      i += 1;
      j += 1;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      // Skipping oldArr[i] keeps at least as much LCS available as skipping
      // newArr[j] would -- oldArr[i] is not part of the alignment: removed.
      const p = childPath(path, i, true);
      if (!isVolatilePath(p, vendor)) acc.removed.push({ path: p, value: oldArr[i] });
      i += 1;
    } else {
      const p = childPath(path, j, true);
      if (!isVolatilePath(p, vendor)) acc.added.push({ path: p, value: newArr[j] });
      j += 1;
    }
  }
  while (i < n) {
    const p = childPath(path, i, true);
    if (!isVolatilePath(p, vendor)) acc.removed.push({ path: p, value: oldArr[i] });
    i += 1;
  }
  while (j < m) {
    const p = childPath(path, j, true);
    if (!isVolatilePath(p, vendor)) acc.added.push({ path: p, value: newArr[j] });
    j += 1;
  }
}

// ---------------------------------------------------------------------------
// Identity-keyed object-array diff (shift-cascade fix for object arrays)
// ---------------------------------------------------------------------------
//
// ⛔ WHY THIS EXISTS (the object-array analogue of diffPrimitiveArrayLCS above).
// diffValue()'s array branch used to compare an array of OBJECTS purely by
// POSITION (`oldArr[i]` vs `newArr[i]`). For a Palo Alto XML/API rulebase --
// stored as an array of `<entry name="...">` objects (`rulebase.security.rules.
// entry[]`) -- inserting or removing ONE rule near the top shifts every later
// rule down a slot, and the positional comparison then diffs rule N against a
// DIFFERENT rule, reporting each shifted rule's every differing field as a fake
// "modified" entry. A real production report showed one small change rendering
// as 37 added / 38 removed / 152 modified -- almost all shift artifacts. The
// primitive-array LCS fix (2026-07-30) explicitly left object arrays on the
// positional path because they "need an identity field to align by"; PAN-OS
// rule/object/admin entries DO have one (`@_name`), so they can now be aligned
// by identity instead of position.
//
// Aligns by the first ARRAY_IDENTITY_KEYS key present as a UNIQUE scalar on
// EVERY element of BOTH sides. Matched elements are diffed field-by-field
// (real changes only -- a pure reorder with no field change produces NO entry,
// which is the whole point); an element only in old is a real removal, only in
// new a real addition. Paths keep the EXACT same positional `...entry[N]`
// grammar the old branch emitted (matched/added use the element's NEW index,
// removed its OLD index), so classifyPath(), DiffViewer.js's index grouping,
// secret redaction and truncation are all untouched -- only the PAIRING
// changes, killing the cascade. Any array that isn't all-objects-with-a-
// shared-unique-key falls back to the original positional comparison, so no
// other array shape's behavior changes.
//
// Grounded, non-speculative keys only (per CLAUDE.md's "don't add speculative
// entries" discipline): `@_name` = fast-xml-parser's rendering of PAN-OS's
// <entry name="..."> attribute (every XML/API rulebase/object/admin array);
// `name` = the flat cmdb-style object arrays (Fortinet `admins`, Check Point
// `administrators`, Forcepoint `smc_administrators`). No uuid/id guesswork.
const ARRAY_IDENTITY_KEYS = ['@_name', 'name'];

// A type-tagged scalar identity for `el` at `key`, or null when `el` isn't a
// plain object or the value isn't a usable non-empty scalar. The `s:`/`n:`
// prefix keeps a string "5" from colliding with a numeric 5 as a Map key.
function identityValueAt(el, key) {
  if (!isPlainObject(el)) return null;
  const v = el[key];
  if (typeof v === 'string') return v === '' ? null : `s:${v}`;
  if (typeof v === 'number' && Number.isFinite(v)) return `n:${v}`;
  return null;
}

// True when EVERY element on both sides is a plain object carrying a usable,
// UNIQUE identity at `key`. An element missing the key, or a duplicate
// identity within either side (which would make alignment ambiguous), fails
// the check and sends the caller back to the positional comparison.
function arrayKeyableBy(oldArr, newArr, key) {
  const idsUnique = (arr) => {
    const seen = new Set();
    for (const el of arr) {
      const id = identityValueAt(el, key);
      if (id === null || seen.has(id)) return false;
      seen.add(id);
    }
    return true;
  };
  return idsUnique(oldArr) && idsUnique(newArr);
}

// First identity key (in priority order) by which both arrays can be keyed, or
// null if none applies.
function chooseArrayIdentityKey(oldArr, newArr) {
  for (const key of ARRAY_IDENTITY_KEYS) {
    if (arrayKeyableBy(oldArr, newArr, key)) return key;
  }
  return null;
}

// Identity-aligned diff of two object arrays. Caller must already have
// established chooseArrayIdentityKey() returned a non-null `key`.
function diffObjectArrayByIdentity(oldArr, newArr, key, path, acc, vendor) {
  const newById = new Map();
  newArr.forEach((el, idx) => {
    newById.set(identityValueAt(el, key), { el, idx });
  });
  const matched = new Set();

  oldArr.forEach((oldEl, oldIdx) => {
    const id = identityValueAt(oldEl, key);
    const hit = newById.get(id);
    if (hit) {
      matched.add(id);
      // Recurse at the element's CURRENT (new) index so the emitted path
      // reflects where the rule lives now and keeps the `...entry[N]` grammar.
      diffValue(oldEl, hit.el, childPath(path, hit.idx, true), acc, vendor);
    } else {
      const p = childPath(path, oldIdx, true);
      if (!isVolatilePath(p, vendor)) acc.removed.push({ path: p, value: oldEl });
    }
  });

  newArr.forEach((newEl, newIdx) => {
    const id = identityValueAt(newEl, key);
    if (matched.has(id)) return;
    const p = childPath(path, newIdx, true);
    if (!isVolatilePath(p, vendor)) acc.added.push({ path: p, value: newEl });
  });
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
    // 1. Every element on BOTH sides a plain primitive -> LCS diff (see
    //    diffPrimitiveArrayLCS's header comment).
    if (oldVal.every(isPrimitiveArrayElement) && newVal.every(isPrimitiveArrayElement)) {
      diffPrimitiveArrayLCS(oldVal, newVal, path, acc, vendor);
      return;
    }

    // 2. Every element a plain OBJECT sharing a unique identity key
    //    (@_name/name) -> align by identity, not position, to kill the
    //    shift cascade (see diffObjectArrayByIdentity's header comment). Any
    //    array not matching this shape falls through to the positional
    //    comparison below, unchanged.
    const identityKey = chooseArrayIdentityKey(oldVal, newVal);
    if (identityKey !== null) {
      diffObjectArrayByIdentity(oldVal, newVal, identityKey, path, acc, vendor);
      return;
    }

    // 3. Fallback: original positional index-by-index comparison (arrays of
    //    objects with no shared identity key, mixed primitive/object arrays,
    //    arrays of arrays).
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

// A legitimate config path is a short dot/bracket-separated identifier --
// never more than a couple dozen characters in practice. A path anywhere
// near this length is a signal something upstream went wrong (the exact
// class of bug documented under "Palo Alto SSH redaction corrupted the
// config brace structure" in CLAUDE.md: an unterminated quote during
// redaction can make the parser swallow hundreds of characters of raw
// config TEXT -- including literal newlines and brace syntax -- into what
// should have been a single short object key, so the "path" itself, not
// just a value, ends up corrupted). Found live: one production
// config_diffs.change_summary row was 13,647 characters because two of its
// four example paths were themselves ~6,800-character corrupted blobs.
const MAX_EXAMPLE_PATH_LENGTH = 80;

// A real config path is dot/bracket-separated identifiers only -- it never
// legitimately contains whitespace or brace characters. Either one showing
// up is itself proof the "path" is corrupted raw config text, not a
// cosmetic length problem -- truncating it would still show a confusing
// garbage fragment (e.g. "foo.bar { ip-netmask 1.2.3.0/24; } baz-object…"),
// which still reads as if it might be a real (if oddly-formatted) path. An
// honest placeholder is clearer than a truncated one for this case.
const PATH_SHAPE_VIOLATION = /[\s{}]/;

/**
 * Collapses embedded whitespace/newlines (present in a corrupted path, never
 * in a real one) to single spaces, then truncates with an ellipsis past
 * `maxLength` -- or, if the path is shaped nothing like a real dot-path at
 * all (see PATH_SHAPE_VIOLATION), swaps in an honest placeholder instead of
 * a truncated garbage fragment.
 *
 * Two call sites, two different caps -- both bound the DISPLAY string only,
 * never the underlying stored diff entry:
 *  - summarizeDiff()'s "e.g. ..." one-liner (MAX_EXAMPLE_PATH_LENGTH, 80) --
 *    renders unconditionally on the Changes page before a user ever expands
 *    "View diff".
 *  - classifyDiff()'s per-row `path` shown inside an expanded section group
 *    (MAX_ROW_PATH_LENGTH, 200 -- a table/list row has more room than a
 *    packed one-liner). Found live 2026-07-20, same day as the one-liner
 *    fix shipped: classifyDiff() correctly BUCKETS a corrupted path into
 *    the right section (classification runs against the real, untruncated
 *    path -- see classifyDiff() below, this function is never called
 *    before that), but the entry's raw `path` was still handed to the UI
 *    unsanitized, so DiffViewer.js's per-row label rendered the same
 *    ~6,800-character corrupted blob, just one level deeper (inside
 *    "Address Objects" → Show details, instead of the top-level summary).
 *    config_diffs has (at least) THREE independent places a path can
 *    render -- change_summary, classifyDiff()'s section entries, and
 *    classifyDiff()'s ruleChanges ruleName/field -- fixing one is not
 *    fixing the others; see this fact called out explicitly in CLAUDE.md.
 */
function truncatePathForDisplay(path, maxLength) {
  const str = String(path);
  if (PATH_SHAPE_VIOLATION.test(str)) return '(unreadable path — see full diff for details)';
  if (str.length <= maxLength) return str;
  return `${str.slice(0, maxLength)}…`;
}

function sanitizeExamplePath(path) {
  return truncatePathForDisplay(path, MAX_EXAMPLE_PATH_LENGTH);
}

const MAX_ROW_PATH_LENGTH = 200;

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
    examplePaths.push(sanitizeExamplePath(entry.path));
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
 *
 * A whole registered-volatile-subtree-root entry (e.g. `tree.shared.content-preview`
 * or `system_info` captured as ONE object -- either recorded before per-leaf
 * decomposition existed, or when the device vendor wasn't known at compute
 * time) is DECOMPOSED here by re-diffing its value through diffValue() so the
 * CURRENT per-field allowlist applies leaf-by-leaf: `content-preview` (empty
 * allowlist) drops entirely, `system_info` keeps only its allowlisted identity/
 * firmware fields and sheds the embedded telemetry. isVolatilePath() alone
 * can't do this -- it only ever matches a nested leaf path, never the bare
 * root (see isRegisteredSubtreeRoot()'s comment above) -- so without this a
 * historical whole-`content-preview`-object add still renders as a "1 added"
 * noise row forever. Only added/removed roots decompose (a whole-root
 * 'modified' is a rare mismatched-type artifact, left to the leaf filter).
 */
function filterDiffForCurrentRules(diff, vendor) {
  const acc = { added: [], removed: [], modified: [] };
  const collect = (changeType, list) => {
    for (const e of list || []) {
      if (
        (changeType === 'added' || changeType === 'removed') &&
        isPlainObject(e.value) &&
        isRegisteredSubtreeRoot(e.path, vendor)
      ) {
        // Re-decompose against {} in the same direction the entry represents,
        // letting diffValue() apply the current volatile-field allowlist.
        if (changeType === 'added') diffValue({}, e.value, e.path, acc, vendor);
        else diffValue(e.value, {}, e.path, acc, vendor);
        continue;
      }
      if (!isVolatilePath(e.path, vendor)) acc[changeType].push(e);
    }
  };
  collect('added', diff.added);
  collect('removed', diff.removed);
  collect('modified', diff.modified);
  return {
    added: redactSecretEntries(acc.added),
    removed: redactSecretEntries(acc.removed),
    modified: redactSecretEntries(acc.modified),
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

// ---------------------------------------------------------------------------
// Diff classification for display (rule-change table + collapsed sections)
// ---------------------------------------------------------------------------
//
// diffConfigs() above diffs the ENTIRE parsed config tree uniformly -- rules,
// address/service objects, VPN settings, admin config, everything landing in
// the same flat added/removed/modified arrays with raw dot-paths. That's the
// right shape to PERSIST (vendor-agnostic, doesn't need to understand any
// tree shape to compute or store), but a raw path like
// "tree.address.TUMN-2" or "tree.rulebase.security.rules.RuleName.action"
// is meaningless to an operator scanning for "what rule changed" -- a real
// user report (2026-07-20) called this out directly against a 501-entry
// address-object diff rendering as 501 stacked raw JSON rows.
//
// classifyDiff() below is a presentation-layer step: it takes an
// already-computed diff and groups entries into (a) a "Rule Changes" table --
// the thing operators actually care about most, matching ManageEngine
// Firewall Analyzer's change-tracking table (rule name / field / old → new)
// -- and (b) everything else, bucketed by a human-readable section label
// with just a count, not a raw dump. It is PURE and additive: diffConfigs()'s
// own output shape, and everything already persisted in config_diffs.diff,
// is completely unchanged. Called at READ time (the diffs API route), not
// at write time -- so a future improvement to section labeling or rule-path
// detection applies retroactively to every historical row for free, with no
// migration needed.
//
// Rule-path detection is grounded in two REAL, live-verified config_parsed
// shapes (checked directly against production device_configs before writing
// this, not assumed):
//  - Palo Alto SSH (e.g. IDC FW): tree.rulebase.security.rules.<RuleName>.<field>
//    -- the rule NAME is a literal object key / path segment. Directly
//    extractable.
//  - Palo Alto XML/API (e.g. ITC-SLY): devices.entry.vsys.entry.rulebase.
//    security.rules.entry[N].<field> -- rules are an ARRAY of {@_name, ...}
//    objects, so the rule's real name is a SIBLING field inside entry[N],
//    not a path segment. Resolving "entry[3]" to the actual rule name would
//    require looking up the live full tree at diff-render time (a bigger,
//    separate change), not something this diff-entry-only classifier can do
//    safely. Rather than guess or mislabel, an unresolvable indexed-entry
//    path falls through to the generic section bucket instead of being
//    force-fit into the rule table -- same "no ruleset is safer than the
//    wrong one" honesty this codebase already applies elsewhere (see
//    getRules()'s fail-loud contract in CLAUDE.md). Only PAN-OS emits
//    rulebase.security.rules paths in config_parsed at all today --
//    Fortinet's config_parsed is flat settings sections only (see the
//    Compliance Engine section of CLAUDE.md), so every other vendor's rule
//    changes simply never reach this branch, which is correct: those
//    vendors' rule data isn't in config_parsed to begin with.
const RULE_PATH_MARKER = 'rulebase.security.rules.';

// First matching (segment, label) pair wins; segments are matched against
// each dot-path component in order (skipping array-index brackets). A
// generic humanized fallback (titleCase of the first non-wrapper segment)
// covers anything not explicitly listed here -- never silently dropped,
// same "unrecognized still gets an honest bucket" discipline as
// MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR's allowlist above.
const SECTION_LABELS = [
  ['address-group', 'Address Groups'],
  ['address', 'Address Objects'],
  ['service-group', 'Service Groups'],
  ['service', 'Service Objects'],
  ['application-filter-group', 'Application Filter Groups'],
  ['application-filter', 'Application Filters'],
  ['application-group', 'Application Groups'],
  // Local firewall user database (PAN-OS `local-user-database.user`/`.user-group`)
  // -- was falling through to the generic "Other (Local User Database)" bucket.
  ['local-user-database', 'Local Users'],
  // NOTE: `security_rules_count` intentionally has NO label here -- it's now a
  // UNIVERSAL_VOLATILE_LEAF_FIELDS noise field (filtered before it ever reaches
  // a section), so a label would be dead code. See isUniversalVolatileLeaf().
  ['nat', 'NAT Rules'],
  ['pbf', 'Policy-Based Forwarding Rules'],
  ['zone', 'Zones/Interfaces'],
  ['network', 'Network Configuration'],
  ['mgt-config', 'Admin/Management Config'],
  ['admins', 'Admin Accounts'],
  ['usernames', 'Admin Accounts'], // Cisco ASA -- flat array of username strings
  ['administrators', 'Admin Accounts'], // Check Point -- show-administrators
  ['smc_administrators', 'Admin Accounts'], // Forcepoint -- SMC-wide admin list
  ['deviceconfig', 'Device Configuration'],
  ['ssl_vpn', 'VPN Configuration'],
  ['ssl-vpn', 'VPN Configuration'],
  ['vpn', 'VPN Configuration'],
  ['smc_vpn_gateway_configured', 'VPN Configuration'], // Forcepoint -- tri-state gateway-configured signal
  ['snmp', 'SNMP'],
  ['ntp', 'NTP'],
  ['dns', 'DNS'],
  ['log_syslogd', 'Logging'],
  ['password_policy', 'Password Policy'],
  ['fortiguard', 'FortiGuard/Update Settings'],
  ['autoupdate_schedule', 'FortiGuard/Update Settings'],
  ['system_info', 'System Info'],
];

// Wrapper segments carrying no meaning of their own -- skipped when looking
// for the first "real" segment, both for SECTION_LABELS matching and for the
// humanized fallback.
//
// 'shared' is deliberately treated as a wrapper here, NOT a SECTION_LABELS
// entry -- PAN-OS nests real, type-specific objects directly under it
// (shared.address.*, shared.service.*, shared.nat.*; see
// lib/adapters/paloalto/parser.js's own comment on this shape), and
// sectionLabelFor()'s root-to-leaf scan returns on the FIRST matching
// segment. A 'shared' → 'Shared Config' entry in SECTION_LABELS would win
// before the scan ever reaches 'address'/'service'/'nat' underneath it,
// collapsing every shared-scope object change into the generic bucket and
// losing the type-specific breakdown this classifier exists to provide.
// Treating it as a wrapper lets the scan continue past it to the real,
// more specific segment below.
const WRAPPER_SEGMENTS = new Set(['tree', 'devices', 'entry', 'vsys', 'shared']);

// ⛔ Fixed 2026-07-30, found while verifying the new NAT/PBF friendlyDescription
// work: 'rulebase' used to be a normal SECTION_LABELS entry, which broke NAT/PBF
// classification entirely, because sectionLabelFor()'s scan walks path segments
// IN ORDER and returns on the first match anywhere in SECTION_LABELS. A NAT rule's
// path is `...rulebase.nat.rules.<name>...` -- the 'rulebase' segment always
// appears BEFORE 'nat', so it matched first and EVERY NAT/PBF rule change was
// mislabeled "Rules (detail unavailable for this device)" (the label meant for a
// security-rulebase path whose rule name is unresolvable), never reaching the
// correct 'NAT Rules'/'Policy-Based Forwarding Rules' entries below it in the
// path. Moved 'rulebase'/'pre-rulebase'/'post-rulebase' into this SEPARATE
// fallback map, checked only when the main SECTION_LABELS scan finds nothing --
// this preserves the original intent (an unresolvable-index security-rulebase
// path still gets this label instead of a generic "Other (Rulebase)" bucket)
// without letting it shadow the more specific nat/pbf labels underneath it.
// Label for a security-rulebase path whose rule NAME can't be resolved from
// the diff entry alone (the Palo Alto XML/API array-index shape --
// `rulebase.security.rules.entry[N]`, see classifyPath()'s isUnresolvableIndex
// gap). Only ever reached when the earlier SECTION_LABELS scan matched nothing
// (nat/pbf/zone/etc. all win first), so in practice this is exactly the
// SECURITY rulebase -- hence the plain "Security Rules" name.
//
// ⛔ Was "Rules (detail unavailable for this device)" until this indexed-rule
// grouping landed -- that wording is no longer accurate: DiffViewer.js now
// regroups these entries into a readable per-rule table (see
// extractIndexedRuleEntry() above), so per-rule DETAIL *is* available, only
// the rule NAME still isn't. Kept as a stable classification key --
// components/devices/OverviewConfigChangesCard.js's HIGH_IMPACT_LABELS keys
// off this exact string, so both must change together.
const FALLBACK_RULEBASE_LABELS = new Map([
  ['rulebase', 'Security Rules'],
  // Panorama nests the rulebase under 'pre-rulebase'/'post-rulebase' rather
  // than a bare 'rulebase' segment -- RULE_PATH_MARKER's substring match
  // already catches these for the resolvable-rule-name case (see
  // classifyPath() below), but this fallback needs its own entries or an
  // unresolvable-index path under either falls through to the generic
  // "Other (Pre Rulebase)"/"Other (Post Rulebase)" label instead.
  ['pre-rulebase', 'Security Rules'],
  ['post-rulebase', 'Security Rules'],
]);

function stripIndex(segment) {
  return segment.replace(/\[\d+\]$/, '');
}

function titleCase(segment) {
  return String(segment)
    .replace(/[-_]+/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function sectionLabelFor(path) {
  const segments = path.split('.').map(stripIndex).filter(Boolean);
  for (const seg of segments) {
    const lower = seg.toLowerCase();
    const match = SECTION_LABELS.find(([key]) => key === lower);
    if (match) return match[1];
  }
  for (const seg of segments) {
    const fallback = FALLBACK_RULEBASE_LABELS.get(seg.toLowerCase());
    if (fallback) return fallback;
  }
  const firstReal = segments.find((s) => !WRAPPER_SEGMENTS.has(s)) || segments[0] || 'other';
  return `Other (${titleCase(firstReal)})`;
}

// ---------------------------------------------------------------------------
// Indexed (XML/API) rulebase entry grouping
// ---------------------------------------------------------------------------
//
// The Palo Alto XML/API transport stores every rulebase (security/nat/pbf) as
// an ARRAY of `<entry name="...">` objects, so a diff path looks like
// `...rulebase.security.rules.entry[5].log-end` -- `entry[5]` is an opaque
// positional array index, and the rule's real name is a SIBLING `@_name`
// field, not a path segment (see classifyPath()'s isUnresolvableIndex gap and
// the friendlyDescription section's XML/API notes). classifyPath() therefore
// (correctly) refuses to force these into the named Rule Changes table and
// files them under the generic "Security Rules" section instead, where they
// used to render as a flat wall of one `entry[5].log-end: yes` row per changed
// FIELD -- the exact unreadable dump a real user report flagged.
//
// BUT every diff entry that shares one `entry[N]` index describes the SAME
// rule: this diff was computed positionally, so `entry[5]` on the old side and
// `entry[5]` on the new side are the two versions of the rule at position 5.
// Grouping every entry back together by that index restores a per-rule,
// ManageEngine-style "one table per rule, Field/Change/Value rows" view --
// WITHOUT resolving the name (which would need the live full tree, still out
// of scope, same reason as classifyPath()). extractIndexedRuleEntry() below
// pulls the `{index, field}` a display grouper needs off the REAL untruncated
// path; classifyDiff() attaches it to each section entry as `ruleIndex`/
// `ruleField` (both null for any non-indexed-rule path -- e.g. every SSH-
// transport path, whose rule names ARE resolved into the Rule Changes table
// and never reach a section at all). components/config/DiffViewer.js does the
// actual grouping/rendering off those two fields.
//
// Requires the literal `rulebase` segment in the path (only PAN-OS emits it)
// AND the `.rules.entry[N]` shape -- so it never accidentally groups an
// unrelated `entry[N]` array (address objects, admin accounts, ...) whose
// own readability is handled separately by friendlyDescription. The captured
// `field` is the ENTIRE remainder after `entry[N].` (one segment like
// `log-end`, or a deeper path like `profile-setting.profiles`), or null for a
// whole-rule add/remove (the diff path was exactly `...entry[N]`, the whole
// rule object landing as one entry -- that object still carries `@_name`, so
// the display layer can name that specific group).
function extractIndexedRuleEntry(path) {
  if (typeof path !== 'string' || path.indexOf('rulebase') === -1) return null;
  const m = path.match(/\.rules\.entry\[(\d+)\](?:\.(.+))?$/);
  if (!m) return null;
  return { index: Number(m[1]), field: m[2] || null };
}

/**
 * Classifies one diff path into either a rule-table row (kind: 'rule') or a
 * generic section bucket (kind: 'section'). See the block comment above for
 * why only the SSH-transport rule-name shape is resolved directly.
 */
function classifyPath(path) {
  const idx = path.indexOf(RULE_PATH_MARKER);
  if (idx !== -1) {
    const rest = path.slice(idx + RULE_PATH_MARKER.length);
    const parts = rest.split('.').filter(Boolean);
    const ruleNameRaw = parts[0] || '';
    const isUnresolvableIndex = /^entry(\[\d+\])?$/.test(ruleNameRaw);
    if (ruleNameRaw && !isUnresolvableIndex) {
      const ruleName = stripIndex(ruleNameRaw);
      const field = parts.slice(1).join('.') || null;
      return { kind: 'rule', ruleName, field };
    }
  }
  return { kind: 'section', sectionLabel: sectionLabelFor(path) };
}

// ---------------------------------------------------------------------------
// friendlyDescription -- plain-English per-entry descriptions (additive)
// ---------------------------------------------------------------------------
//
// FROZEN CONTRACT: components/config/DiffViewer.js (a separate, parallel
// change) depends on every classifyDiff() entry carrying a `friendlyDescription`
// field -- a short plain-English sentence, or exactly `null` (never omitted,
// never `undefined`) whenever the path shape isn't confidently recognized.
// Every function in this section must NEVER throw -- an unexpected shape
// falls through to null, mirroring classifyPath()'s own "unresolvable falls
// through to the generic bucket" philosophy immediately above.
//
// Originally shipped 2026-07-30 covering two path shapes; extended the same
// day to five, then to nine, all still identified purely by SEGMENT NAME
// (same segment-matching approach sectionLabelFor() already uses: split on
// '.', strip `[N]` index suffixes, look for a recognizable segment) -- NOT
// tied to one transport's path prefix, except where noted:
//   1. local-user-database.user.<username>[...]            (local users)
//      local-user-database.user-group.<groupname>.user[...] (group membership
//      -- the exact shape Task 1's LCS array-diff fix above was written for)
//   2. <address|address-group|service|service-group>.<name>[...] (network
//      objects/groups -- the same four segment names sectionLabelFor()'s
//      SECTION_LABELS already keys off of).
//   3. Admin/user accounts -- Fortinet `admins[N]`, Check Point
//      `administrators[N]`, Forcepoint `smc_administrators[N]` (whole-entry
//      only -- see friendlyDescriptionForAdminAccountArray()'s header comment
//      for why a per-field modify can't resolve an account name from these),
//      Cisco ASA `usernames[N]` (flat string array), Palo Alto
//      `mgt-config.users.<username>[...]` (SSH transport only -- XML/API's
//      opaque `entry[N]` array index falls through to null, same gap as
//      shape 2 above). See friendlyDescriptionForAdminAccount() below.
//   4. VPN configuration -- Fortinet `ssl_vpn.<field>` (flat dict), Palo Alto
//      GlobalProtect (detected by a `global.?protect`-matching segment
//      ANYWHERE in the path, not a fixed nesting -- mirrors
//      lib/engines/vpnSummary.js's own deep-scan approach), Forcepoint's
//      literal top-level `smc_vpn_gateway_configured` tri-state field (an
//      exact whole-path match, not a segment scan -- it isn't nested under a
//      vpn/ssl_vpn segment at all). See friendlyDescriptionForVpnConfig()
//      below.
//   5. NAT rules -- PAN-OS SSH `rulebase.nat.rules.<RuleName>[...]` (same
//      brace-grammar grounding as security rules; doc-derived field names
//      within the rule, not live-verified). See friendlyDescriptionForNatRule().
//   6. PBF rules -- PAN-OS SSH `rulebase.pbf.rules.<RuleName>[...]`, same
//      standing as NAT above. See friendlyDescriptionForPbfRule().
//   7. Zones -- PAN-OS SSH `zone.<ZoneName>[...]`, reusing
//      friendlyDescriptionForNetworkObject() directly (kind='Zone'). See
//      friendlyDescriptionForZone().
//   8. Fortinet flat settings sections -- `snmp`/`ntp`/`dns`/`log_syslogd`/
//      `password_policy`/`fortiguard`/`autoupdate_schedule.<field>`, same
//      flat-dict shape as shape 4's `ssl_vpn`. See
//      friendlyDescriptionForFortinetSection().
//   9. Palo Alto `system_info.<field>` -- gated by the SAME
//      MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR allowlist that already filters
//      this subtree for noise (see that constant above); `sw-version` and
//      `hostname` get dedicated wording, every other allowlisted field a
//      generic fallback. See friendlyDescriptionForSystemInfo().
//
// Grounded directly against lib/adapters/paloalto/parser.js (XML/API
// transport) and lib/adapters/paloalto/sshParser.js (SSH transport) before
// writing this, per CLAUDE.md's "verify against real code" discipline:
//  - SSH (brace tree): a named PAN-OS schema node's block key IS the entry's
//    real name (ruleFromBraceEntry/extractAddressEntriesFromBrace/etc. all
//    rely on exactly this) -- so 'address.WEB-SRV.ip-netmask',
//    'local-user-database.user.jdoe', 'local-user-database.user-group.
//    SSL-GROUP.user' are all real, direct path shapes on this transport.
//  - XML/API: fast-xml-parser turns a repeated <entry name="..."> element
//    into an ARRAY of objects, each with a SIBLING '@_name' attribute, not a
//    literal name path segment (extractAddressEntries()/etc. all read
//    `entry['@_name']`) -- so the equivalent path looks like
//    'address.entry[3].ip-netmask', where 'entry[3]' is an opaque array
//    index, not a name. This is the EXACT SAME limitation classifyPath()
//    above already documents and accepts for rule names on this transport
//    (isUnresolvableIndex) -- resolving it here would need the live full
//    tree, not just this one diff entry, so an 'entry' segment where a name
//    is expected is treated as "can't confidently resolve" and falls
//    through to null, never a guess.
//  - Fortinet's config_parsed is flat, pre-named cmdb sections (confirmed
//    directly against lib/adapters/fortinet/index.js's getConfig() and
//    lib/adapters/fortinet/cliParser.js's parseFullConfiguration(), both
//    transports: global/interfaces/ssl_vpn/snmp/admins/ntp/dns/
//    log_syslogd/password_policy/fortiguard/autoupdate_schedule) -- it can
//    never contain 'local-user-database'/'address'/'address-group'/
//    'service'/'service-group' as a path segment, so this whole section is a
//    structural no-op (always null) for every Fortinet diff entry, by
//    construction, not by an explicit vendor check anywhere below.

const OBJECT_SECTION_KIND = new Map([
  ['address-group', 'Address group'],
  ['address', 'Address object'],
  ['service-group', 'Service group'],
  ['service', 'Service object'],
]);

// Same "opaque XML/API array index, not a real name" check classifyPath()
// already applies to rule names (isUnresolvableIndex) -- stripIndex() has
// already removed any trailing '[N]', so this only needs to check the bare
// segment text.
function isUnresolvableNameSegment(seg) {
  return typeof seg !== 'string' || seg === '' || seg.toLowerCase() === 'entry';
}

// "ip-netmask" -> "ip netmask" -- reuses titleCase() (already used for the
// generic section-label fallback above) but lowercased, since this is meant
// to read naturally INSIDE a sentence ("its ip netmask was changed"), not as
// a standalone heading.
function humanizeFieldForSentence(segment) {
  return titleCase(segment).toLowerCase();
}

// Defensive stringification for a fallback "X changed: old -> new" sentence
// -- values here may already be redacted ('<redacted>'), a plain string, or
// (rarely) something else entirely; never throws.
function formatValueForSentence(v) {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'string') return v;
  try {
    return JSON.stringify(v);
  } catch (_err) {
    return String(v);
  }
}

// True when `field` looks secret-shaped by the SAME pattern/exception list
// isSecretPath() uses for a full path -- used here to decide whether it's
// safe to NAME a changed user field in a sentence, or whether that would be
// a meaningless (or actively risky) "changed from <redacted> to <redacted>"
// statement.
function looksLikeSecretFieldName(field) {
  if (typeof field !== 'string') return true; // fail toward "don't name it"
  if (SECRET_PATH_EXCEPTIONS.has(field.toLowerCase())) return false;
  return SECRET_PATH_PATTERN.test(field);
}

/**
 * local-user-database.* shapes -- see this section's header comment above
 * for the two recognized sub-shapes. `segments` is already stripIndex()'d
 * and non-empty-filtered (see computeFriendlyDescription); `ludIdx` is the
 * index of the 'local-user-database' segment itself. `values` is the raw
 * diff entry ({value} for added/removed, {old,new} for modified).
 */
function friendlyDescriptionForLocalUserDatabase(segments, ludIdx, changeType, values) {
  const rest = segments.slice(ludIdx + 1);
  if (rest.length === 0) return null;

  // Shape: local-user-database.user-group.<groupname>.user[...] -- the
  // array-of-usernames leaf Task 1's LCS fix above exists for.
  if (rest[0].toLowerCase() === 'user-group') {
    const groupName = rest[1];
    const tail = rest.slice(2);
    if (isUnresolvableNameSegment(groupName)) return null;
    if (tail.length !== 1 || tail[0].toLowerCase() !== 'user') return null;

    if (changeType === 'added' && typeof values.value === 'string') {
      return `User "${values.value}" was added to group "${groupName}"`;
    }
    if (changeType === 'removed' && typeof values.value === 'string') {
      return `User "${values.value}" was removed from group "${groupName}"`;
    }
    if (changeType === 'modified') {
      // Should now be rare-to-never post-Task-1 (an all-primitive array only
      // ever produces added/removed) -- kept as an honest fallback in case a
      // mixed-shape array ever lands here instead, and still seen on HISTORICAL
      // rows recorded before that fix. Deliberately does NOT embed the old/new
      // values: DiffViewer.js's DiffModifiedRow already appends ": old → new"
      // after this label, so embedding them here produced a redundant
      // "...membership changed: X → Y: X → Y" line (visible on those historical
      // group-membership cascade rows). Also "Group", not "User" -- groupName
      // is the group, not a user.
      return `Group "${groupName}" membership changed`;
    }
    return null;
  }

  // Shape: local-user-database.user.<username>[...] -- a whole local-user
  // record (nothing after the username) or a specific field within one.
  if (rest[0].toLowerCase() === 'user') {
    const username = rest[1];
    if (isUnresolvableNameSegment(username)) return null;
    const tail = rest.slice(2);

    if (changeType === 'added') return tail.length === 0 ? `Local user "${username}" was added` : null;
    if (changeType === 'removed') return tail.length === 0 ? `Local user "${username}" was removed` : null;
    if (changeType === 'modified') {
      if (tail.length === 1) {
        const field = tail[0];
        const oldRedacted = values.old === '<redacted>';
        const newRedacted = values.new === '<redacted>';
        if (!looksLikeSecretFieldName(field) && !oldRedacted && !newRedacted) {
          return `Local user "${username}"'s ${humanizeFieldForSentence(field)} was changed`;
        }
      }
      // Whole-record modify (tail.length === 0), a secret-shaped/redacted
      // field, or a deeper-than-one-level change -- generic, never a
      // meaningless "changed from <redacted> to <redacted>" statement.
      return `Local user "${username}"'s settings were changed`;
    }
    return null;
  }

  return null;
}

/**
 * <address|address-group|service|service-group>.<name>[...] shapes -- see
 * this section's header comment above. `sectionIdx` is the index in
 * `segments` of the recognized section-key segment itself.
 */
function friendlyDescriptionForNetworkObject(segments, sectionIdx, kind, changeType, values) {
  const name = segments[sectionIdx + 1];
  if (isUnresolvableNameSegment(name)) return null;

  const tail = segments.slice(sectionIdx + 2);

  if (tail.length === 0) {
    if (changeType === 'added') return `${kind} "${name}" was added`;
    if (changeType === 'removed') return `${kind} "${name}" was removed`;
    if (changeType === 'modified') return `${kind} "${name}" was changed`;
    return null;
  }

  if (changeType === 'modified') {
    if (tail.length === 1) {
      return `${kind} "${name}"'s ${humanizeFieldForSentence(tail[0])} was changed`;
    }
    // No clean single-subfield resolution (nested deeper than one level) --
    // still confidently know WHICH object changed, just not which field.
    return `${kind} "${name}" was changed`;
  }

  // added/removed at a depth deeper than the object's own leaf (a field
  // appearing/disappearing on an otherwise pre-existing object) isn't one of
  // the two shapes this function commits to -- leave it null rather than
  // guess at a message.
  return null;
}

// ---------------------------------------------------------------------------
// friendlyDescription -- VPN config + admin/user account shapes (added
// 2026-07-30, extending the local-user-database/network-object shapes above)
// ---------------------------------------------------------------------------
//
// Same discipline as the two shapes above: identify by SEGMENT NAME (or, for
// Forcepoint's one literal top-level field, by exact whole path), never throw,
// never name a secret-shaped or already-`<redacted>` field, fall back to null
// (or a generic-but-accurate sentence) rather than guess at a shape that
// hasn't been confirmed against the real summarizer code. Grounded directly
// against lib/engines/vpnSummary.js and lib/engines/adminAccountSummary.js
// (both read in full before writing this) -- NOT re-derived from field-name
// guesses.

// ---------------------------------------------------------------------------
// VPN configuration
// ---------------------------------------------------------------------------

// Deliberate duplicate of lib/engines/vpnSummary.js's own GLOBAL_PROTECT_PATTERN
// constant -- same "not a shared module, keep every copy in step" convention
// this codebase already uses for SECRET_PATH_PATTERN (see .ai-codex/gotchas.md's
// Redaction rules section). GlobalProtect's real config-tree nesting varies
// by device/vsys/Panorama mode (see vpnSummary.js's own header comment for
// why summarizePaloAlto() does a bounded deep search rather than assuming one
// fixed path) -- this classifier does the SAME deep-scan-by-segment-name
// approach, not a fixed path.
const GLOBAL_PROTECT_PATTERN = /global.?protect/i;

/**
 * Fortinet's configParsed.ssl_vpn -- a flat top-level settings dict (see
 * vpnSummary.js's summarizeFortinet(): 'source-interface', 'port',
 * 'idle-timeout', 'ssl-min-proto-ver', among others). `idx` is the index of
 * the 'ssl_vpn' segment itself in `segments`.
 */
function friendlyDescriptionForFortinetSslVpn(segments, idx, changeType, values) {
  const tail = segments.slice(idx + 1);

  if (tail.length === 0) {
    if (changeType === 'added') return 'SSL VPN configuration was added';
    if (changeType === 'removed') return 'SSL VPN configuration was removed';
    if (changeType === 'modified') return 'SSL VPN configuration was changed';
    return null;
  }

  if (tail.length !== 1) return null; // ssl_vpn is documented flat-only -- deeper nesting is an unrecognized shape, don't guess

  const field = tail[0];
  if (looksLikeSecretFieldName(field)) return 'SSL VPN configuration was changed';

  if (changeType === 'modified') {
    if (values.old === '<redacted>' || values.new === '<redacted>') return 'SSL VPN configuration was changed';
    return `SSL VPN ${humanizeFieldForSentence(field)} was changed to "${formatValueForSentence(values.new)}"`;
  }
  if (changeType === 'added') {
    if (values.value === '<redacted>') return 'SSL VPN configuration was changed';
    return `SSL VPN ${humanizeFieldForSentence(field)} was set to "${formatValueForSentence(values.value)}"`;
  }
  if (changeType === 'removed') {
    return `SSL VPN ${humanizeFieldForSentence(field)} was removed`;
  }
  return null;
}

/**
 * Palo Alto GlobalProtect -- no single fixed path (see vpnSummary.js's
 * GLOBAL_PROTECT_PATTERN deep-scan comment: nesting varies by vsys/Panorama
 * mode). `gpIdx` is the index of the FIRST segment matching
 * GLOBAL_PROTECT_PATTERN. Deliberately conservative: only names a specific
 * sub-field one level below the matched segment; anything deeper, or an
 * unresolvable XML/API array index, still confidently reports "GlobalProtect
 * configuration was changed" rather than guessing at an unverified nesting.
 */
function friendlyDescriptionForGlobalProtect(segments, gpIdx, changeType, values) {
  const tail = segments.slice(gpIdx + 1);

  if (tail.length === 0) {
    if (changeType === 'added') return 'GlobalProtect configuration was added';
    if (changeType === 'removed') return 'GlobalProtect configuration was removed';
    if (changeType === 'modified') return 'GlobalProtect configuration was changed';
    return null;
  }

  if (changeType === 'modified') {
    const field = tail[0];
    if (
      tail.length === 1 &&
      !isUnresolvableNameSegment(field) &&
      !looksLikeSecretFieldName(field) &&
      values.old !== '<redacted>' &&
      values.new !== '<redacted>'
    ) {
      return `GlobalProtect ${humanizeFieldForSentence(field)} was changed`;
    }
    // Nested deeper than one level, an opaque XML/API array index, or a
    // secret-shaped field -- still confidently know GlobalProtect itself
    // changed, just not which field. Generic-but-accurate beats guessing at
    // an unverified sub-shape (this path's nesting is known to vary).
    return 'GlobalProtect configuration was changed';
  }

  // added/removed at a depth below the top level isn't a shape this function
  // commits to -- leave null rather than guess.
  return null;
}

/**
 * Forcepoint's configParsed.smc_vpn_gateway_configured -- a literal TOP-LEVEL
 * key (not nested under a vpn/ssl_vpn segment at all -- see
 * lib/adapters/forcepoint/parser.js's detectVpnGatewayConfigured()), so this
 * is checked by exact whole-path equality by the caller, not a segment scan.
 * Tri-state (true/false/null) -- `null` ("undetected") is never described as
 * a confident state, per this codebase's tri-state discipline (CLAUDE.md).
 */
function friendlyDescriptionForForcepointVpnGateway(changeType, values) {
  let val;
  if (changeType === 'added') val = values.value;
  else if (changeType === 'modified') val = values.new;
  else return null; // 'removed' isn't one of the tri-state transitions this literal field models

  if (val === true) return 'VPN gateway was configured on this engine';
  if (val === false) return 'VPN gateway was unconfigured on this engine';
  return null; // null (undetected) or any other unexpected value -- never a guess
}

/**
 * Dispatches to the three recognized VPN shapes above. `path` is the REAL,
 * untruncated entry path (needed for the Forcepoint exact-match case);
 * `segments` is the same stripIndex()'d/filtered array computeFriendlyDescription()
 * already builds for the other shapes.
 */
function friendlyDescriptionForVpnConfig(path, segments, changeType, values) {
  if (path === 'smc_vpn_gateway_configured') {
    return friendlyDescriptionForForcepointVpnGateway(changeType, values);
  }

  const gpIdx = segments.findIndex((s) => GLOBAL_PROTECT_PATTERN.test(s));
  if (gpIdx !== -1) {
    return friendlyDescriptionForGlobalProtect(segments, gpIdx, changeType, values);
  }

  const sslVpnIdx = segments.findIndex((s) => s.toLowerCase() === 'ssl_vpn');
  if (sslVpnIdx !== -1) {
    return friendlyDescriptionForFortinetSslVpn(segments, sslVpnIdx, changeType, values);
  }

  return null;
}

// ---------------------------------------------------------------------------
// Admin / user account shapes
// ---------------------------------------------------------------------------

// Segment names identifying an ARRAY of admin-account dicts whose per-entry
// identity is a SIBLING `name` field, not a path segment (the array index is
// opaque) -- Fortinet's `admins` (lib/engines/adminAccountSummary.js's
// summarizeFortinet(): [{name, accprofile, 'two-factor', trusthostN, ...}]),
// Check Point's `administrators` (summarizeCheckPoint():
// [{name, permissions_profile, authentication_method, email,
// must_change_password, expiration_date, ...}] -- see
// lib/adapters/checkpoint/parser.js's parseAdministratorObjects()), and
// Forcepoint's `smc_administrators` (summarizeForcepoint(): [{name,
// superuser, enabled}]).
//
// ⛔ Whole-entry added/removed CAN be named (the diff entry's `value` IS the
// full record, including `name`) -- but a per-FIELD modify genuinely CANNOT:
// the array index in the path (`admins[3].accprofile`) carries no identity of
// its own, and a modified-leaf diff entry only ever carries that one field's
// old/new value, never the sibling `name` needed to say WHICH account. This
// is the exact same "can't resolve an opaque array index without the live
// tree" limitation this file already documents and accepts for Palo Alto's
// XML/API rule/object arrays (see isUnresolvableNameSegment's callers above)
// -- so a field-level modify on any of these three sections returns null
// rather than guess, same discipline, not a narrower implementation.
//
// Verified against SECRET_PATH_PATTERN before assuming any of these field
// names are safe to name in a sentence (per this task's own instruction, not
// assumed): `must_change_password` DOES false-positive (contains
// "password") -- looksLikeSecretFieldName() already treats it as
// secret-shaped, so a modify on it silently falls back to the generic
// "...'s settings were changed" sentence rather than naming it, exactly like
// this file's existing `password_policy`-style false positives. Separately,
// Check Point's own redactSecrets() (lib/adapters/checkpoint/parser.js)
// already redacts must_change_password's VALUE to the literal string
// '<redacted>' at the adapter layer for the same keyword-match reason,
// before this even runs -- a real, confirmed over-redaction side effect
// (out of scope to fix here: this file only owns configDiff.js), but it
// means old/new for that field will in practice both already read
// '<redacted>' and never even produce a distinguishable diff. All other
// fields on all three vendors (`name`, `accprofile`, `two-factor`,
// `permissions_profile`, `authentication_method`, `email`,
// `expiration_date`, `superuser`, `enabled`) do NOT match
// SECRET_PATH_PATTERN -- confirmed, not assumed.
const ADMIN_ARRAY_SECTIONS = new Map([
  ['admins', 'Admin account'],
  ['administrators', 'Admin account'],
  ['smc_administrators', 'Admin account'],
]);

function friendlyDescriptionForAdminAccountArray(segments, idx, label, changeType, values) {
  const tail = segments.slice(idx + 1);

  if (tail.length === 0) {
    if (changeType !== 'added' && changeType !== 'removed') return null; // whole-record modify -- rare positional-shift artifact, not confidently nameable
    const record = values.value;
    const name = record && typeof record === 'object' && !Array.isArray(record) && typeof record.name === 'string'
      ? record.name
      : null;
    if (!name) return null;
    return changeType === 'added' ? `${label} "${name}" was added` : `${label} "${name}" was removed`;
  }

  // A field within one entry -- the array index carries no identity (see
  // this section's header comment above). Never guess.
  return null;
}

/**
 * Cisco ASA's configParsed.usernames -- a flat array of plain username
 * STRINGS (lib/engines/adminAccountSummary.js's summarizeCiscoAsa()), never
 * objects. Post-Task-1's LCS array fix, an all-primitive array only ever
 * produces added/removed entries (never a false "modified" cascade), so
 * `changeType === 'modified'` should be unreachable here in practice -- kept
 * as an honest null fallback rather than assumed impossible.
 */
function friendlyDescriptionForCiscoUsernames(segments, idx, changeType, values) {
  if (segments.length !== idx + 1) return null; // usernames is flat -- no sub-path is a recognized shape
  if (changeType === 'added' && typeof values.value === 'string') return `Admin user "${values.value}" was added`;
  if (changeType === 'removed' && typeof values.value === 'string') return `Admin user "${values.value}" was removed`;
  return null;
}

/**
 * Palo Alto's mgt-config.users -- SSH transport: the username IS the literal
 * path segment (mgt-config.users.<username>[...], same "block key IS the
 * identity" convention local-user-database.user.<username> already relies
 * on -- see lib/engines/adminAccountSummary.js's summarizePaloAltoSsh()).
 * XML/API transport: fast-xml-parser turns repeated <entry name="..."> into
 * an array of {@_name, ...} objects (summarizePaloAltoXml()) -- 'entry' is an
 * opaque array index, not a name, the SAME transport gap
 * friendlyDescriptionForNetworkObject() already accepts -- returns null there
 * rather than guess, regardless of whole-entry vs. field-modify.
 *
 * `mgtIdx` is the index of the 'mgt-config' segment. Requires the VERY NEXT
 * segment to be 'users' -- 'mgt-config' alone covers lots of unrelated
 * management settings (hostname, ip-address, ...; already its own
 * SECTION_LABELS "Admin/Management Config" bucket) that must NOT be
 * mislabeled as an admin-account change.
 */
function friendlyDescriptionForPaloAltoAdminUsers(segments, mgtIdx, changeType, values) {
  if (!segments[mgtIdx + 1] || segments[mgtIdx + 1].toLowerCase() !== 'users') return null;

  const rest = segments.slice(mgtIdx + 2);
  if (rest.length === 0) return null; // whole `users` block added/removed -- not one specific account

  const identity = rest[0];
  if (isUnresolvableNameSegment(identity)) return null; // XML/API's opaque 'entry' index -- never guess

  const username = identity;
  const tail = rest.slice(1);

  if (tail.length === 0) {
    if (changeType === 'added') return `Admin account "${username}" was added`;
    if (changeType === 'removed') return `Admin account "${username}" was removed`;
    return null;
  }

  if (changeType === 'modified') {
    if (tail.length === 1) {
      const field = tail[0];
      const oldRedacted = values.old === '<redacted>';
      const newRedacted = values.new === '<redacted>';
      if (!looksLikeSecretFieldName(field) && !oldRedacted && !newRedacted) {
        return `Admin account "${username}"'s ${humanizeFieldForSentence(field)} was changed`;
      }
    }
    return `Admin account "${username}"'s settings were changed`;
  }

  // added/removed at a depth deeper than the user's own leaf -- not one of
  // the two committed shapes, leave null rather than guess.
  return null;
}

/**
 * Dispatches to the five recognized admin/user-account shapes above.
 */
function friendlyDescriptionForAdminAccount(segments, changeType, values) {
  const mgtIdx = segments.findIndex((s) => s.toLowerCase() === 'mgt-config');
  if (mgtIdx !== -1) {
    return friendlyDescriptionForPaloAltoAdminUsers(segments, mgtIdx, changeType, values);
  }

  const usernamesIdx = segments.findIndex((s) => s.toLowerCase() === 'usernames');
  if (usernamesIdx !== -1) {
    return friendlyDescriptionForCiscoUsernames(segments, usernamesIdx, changeType, values);
  }

  for (let i = 0; i < segments.length; i++) {
    const label = ADMIN_ARRAY_SECTIONS.get(segments[i].toLowerCase());
    if (label) {
      return friendlyDescriptionForAdminAccountArray(segments, i, label, changeType, values);
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// NAT / PBF rule shapes (Palo Alto SSH transport only) -- added extending
// the friendlyDescription feature beyond its original 2026-07-30 shapes
// ---------------------------------------------------------------------------
//
// Same brace-tree "block key IS the entry's real name" grounding
// ruleFromBraceEntry() (SSH transport) already relies on for the security
// rulebase, re-confirmed directly against lib/adapters/paloalto/sshParser.js
// before writing this: PAN-OS's NAT and PBF rulebases use the IDENTICAL
// brace grammar (`rulebase { nat { rules { <RuleName> { ... } } } }` /
// `rulebase { pbf { rules { <RuleName> { ... } } } }`) as the security
// rulebase -- a NAT/PBF rule name is just as directly a path segment as a
// security rule name is. Unlike security rules, NAT/PBF entries surface
// through the GENERIC section-entry path (computeFriendlyDescription /
// addToSection), never the separate Rule Changes table --
// classifyPath()'s RULE_PATH_MARKER only ever matches
// 'rulebase.security.rules.' by design (see that constant's own comment) --
// so these dispatch from here, not from friendlyDescriptionForRuleObject()'s
// caller. sshParser.js itself never extracts NAT/PBF rules into any
// NormalizedRule-like shape (only security rules and the four address/
// service object kinds get dedicated extraction) -- the field names below
// are therefore DOC-DERIVED against standard, well-documented PAN-OS
// CLI/XML schema field names, NOT confirmed against any live sample or any
// existing parser code in this codebase, same "doc-derived, not yet
// live-verified" standing CLAUDE.md requires calling out explicitly. If a
// real NAT/PBF sample ever contradicts a field name here, only this block
// needs correcting.
//
// Reuses ruleFieldValuesForSentence()/isRuleFieldEffectivelyAny() (defined
// below, in the Rule Changes table section -- both are hoisted function
// declarations, safe to call from here) rather than duplicating their "omit
// an absent/PAN-OS-default-'any' field" logic, per this task's own
// instruction not to reinvent them.

// Plain-string accessor for a nested translation sub-dict's own leaf value
// (e.g. `interface-address.interface`, `static-ip.translated-address`) --
// deliberately narrower than ruleFieldValuesForSentence() (which also
// accepts arrays): every translation-detail field used below is documented
// as a single scalar, never a list.
function scalarFieldOrNull(v) {
  return typeof v === 'string' && v !== '' ? v : null;
}

// PAN-OS source-translation is a nested dict keyed by the translation TYPE
// ('dynamic-ip-and-port' | 'dynamic-ip' | 'static-ip'), each holding either a
// literal translated-address (scalar or list) or an interface-address
// sub-dict. Only describes the shapes explicitly documented and reasonably
// unambiguous -- an unrecognized type key or a malformed sub-shape returns
// null so the caller omits translation detail rather than guessing wrong
// (per this task's own "omit rather than guess" instruction for NAT).
function describeNatSourceTranslation(xlat) {
  if (!isPlainObject(xlat)) return null;
  try {
    if (isPlainObject(xlat['dynamic-ip-and-port'])) {
      const d = xlat['dynamic-ip-and-port'];
      if (isPlainObject(d['interface-address'])) {
        const iface = scalarFieldOrNull(d['interface-address'].interface);
        return iface ? `translates source to interface "${iface}"` : null;
      }
      const addr = ruleFieldValuesForSentence(d['translated-address']);
      return addr.length > 0 ? `translates source to ${addr.join(', ')} (dynamic IP and port)` : null;
    }
    if (isPlainObject(xlat['dynamic-ip'])) {
      const addr = ruleFieldValuesForSentence(xlat['dynamic-ip']['translated-address']);
      return addr.length > 0 ? `translates source to ${addr.join(', ')} (dynamic IP)` : null;
    }
    if (isPlainObject(xlat['static-ip'])) {
      const addr = scalarFieldOrNull(xlat['static-ip']['translated-address']);
      return addr ? `static NAT translates source to ${addr}` : null;
    }
  } catch (_err) {
    return null;
  }
  return null;
}

// destination-translation is simpler: a flat { 'translated-address', 'translated-port' } dict, no type-keyed sub-shape.
function describeNatDestinationTranslation(xlat) {
  if (!isPlainObject(xlat)) return null;
  try {
    const addr = scalarFieldOrNull(xlat['translated-address']);
    if (!addr) return null;
    const port = scalarFieldOrNull(xlat['translated-port']);
    return port ? `translates destination to ${addr}:${port}` : `translates destination to ${addr}`;
  } catch (_err) {
    return null;
  }
}

/**
 * Whole NAT rule added/removed -> one sentence, same "core fields always
 * named, optional detail omitted when absent or the PAN-OS 'any' no-op
 * default" shape as friendlyDescriptionForRuleObject() (security rules) --
 * NAT rules have no action field (the fact that translation happens at all
 * IS the "action"), so `from`/`to` (zones) anchor the sentence instead, same
 * as security rules' zones.
 */
function friendlyDescriptionForNatRuleObject(rawRule, changeType) {
  if (!isPlainObject(rawRule)) return null;
  if (changeType !== 'added' && changeType !== 'removed') return null;

  try {
    if (looksLikeSecretFieldName('from') || looksLikeSecretFieldName('to')) return null; // defensive only, unreachable in practice
    const fromZones = ruleFieldValuesForSentence(rawRule.from);
    const toZones = ruleFieldValuesForSentence(rawRule.to);
    if (fromZones.length === 0 || toZones.length === 0) return null; // core fields missing -- not confident this is a real NAT rule shape

    const zoneWord = (list) => (list.length > 1 ? 'zones' : 'zone');
    let sentence = `NAT rule from ${zoneWord(fromZones)} "${fromZones.join(', ')}" to ${zoneWord(toZones)} "${toZones.join(', ')}" was ${changeType === 'added' ? 'added' : 'removed'}`;

    const detail = [];
    for (const [field, label] of [
      ['source', 'source'],
      ['destination', 'destination'],
      ['service', 'service'],
    ]) {
      if (looksLikeSecretFieldName(field)) continue; // defensive -- these fields shouldn't structurally carry secrets
      const raw = rawRule[field];
      if (raw === '<redacted>') continue;
      const values = ruleFieldValuesForSentence(raw);
      if (isRuleFieldEffectivelyAny(values)) continue;
      detail.push(`${label} ${values.join(', ')}`);
    }

    const srcXlatDesc =
      rawRule['source-translation'] !== '<redacted>' ? describeNatSourceTranslation(rawRule['source-translation']) : null;
    const dstXlatDesc =
      rawRule['destination-translation'] !== '<redacted>' ? describeNatDestinationTranslation(rawRule['destination-translation']) : null;
    if (srcXlatDesc) detail.push(srcXlatDesc);
    if (dstXlatDesc) detail.push(dstXlatDesc);

    if (detail.length > 0) sentence += ` — ${detail.join(', ')}`;
    return sentence;
  } catch (_err) {
    return null;
  }
}

/**
 * NAT rule dispatch from a section-entry path -- `natIdx` is the index of
 * the 'nat' segment. Requires the very next segment to be 'rules' (mirrors
 * friendlyDescriptionForPaloAltoAdminUsers()'s 'mgt-config' + 'users'
 * requirement) -- a bare 'nat' segment elsewhere isn't confidently this
 * shape.
 */
function friendlyDescriptionForNatRule(segments, natIdx, changeType, values) {
  if (!segments[natIdx + 1] || segments[natIdx + 1].toLowerCase() !== 'rules') return null;
  const ruleName = segments[natIdx + 2];
  if (isUnresolvableNameSegment(ruleName)) return null;
  const tail = segments.slice(natIdx + 3);

  if (tail.length === 0) {
    if (changeType === 'added' || changeType === 'removed') {
      return friendlyDescriptionForNatRuleObject(values.value, changeType);
    }
    if (changeType === 'modified') return `NAT rule "${ruleName}" was changed`;
    return null;
  }

  if (changeType === 'modified') {
    if (tail.length === 1) {
      const field = tail[0];
      if (!looksLikeSecretFieldName(field) && values.old !== '<redacted>' && values.new !== '<redacted>') {
        return `NAT rule "${ruleName}"'s ${humanizeFieldForSentence(field)} was changed`;
      }
    }
    return `NAT rule "${ruleName}" was changed`;
  }

  // added/removed at a depth deeper than the rule's own leaf -- not one of
  // the committed shapes, leave null rather than guess.
  return null;
}

// PBF's "action" is a nested dict keyed by the forwarding verb
// ('forward'/'discard'/'no-pbf'), doc-derived like the NAT translation
// sub-shapes above.
function describePbfAction(actionObj) {
  if (!isPlainObject(actionObj)) return null;
  try {
    if (Object.prototype.hasOwnProperty.call(actionObj, 'discard')) return 'discards matching traffic';
    if (Object.prototype.hasOwnProperty.call(actionObj, 'no-pbf')) return 'exempts matching traffic from policy-based forwarding';
    if (isPlainObject(actionObj.forward)) {
      const egress = scalarFieldOrNull(actionObj.forward['egress-interface']);
      return egress ? `forwards matching traffic via interface "${egress}"` : 'forwards matching traffic';
    }
  } catch (_err) {
    return null;
  }
  return null;
}

/**
 * Whole PBF rule added/removed -> one sentence, same discipline as NAT above.
 */
function friendlyDescriptionForPbfRuleObject(rawRule, changeType) {
  if (!isPlainObject(rawRule)) return null;
  if (changeType !== 'added' && changeType !== 'removed') return null;

  try {
    if (looksLikeSecretFieldName('from')) return null; // defensive only, unreachable in practice
    const fromZones = ruleFieldValuesForSentence(rawRule.from);
    if (fromZones.length === 0) return null; // core field missing -- not confident this is a real PBF rule shape

    const zoneWord = fromZones.length > 1 ? 'zones' : 'zone';
    let sentence = `PBF rule from ${zoneWord} "${fromZones.join(', ')}" was ${changeType === 'added' ? 'added' : 'removed'}`;

    const detail = [];
    for (const [field, label] of [
      ['source', 'source'],
      ['destination', 'destination'],
      ['application', 'application(s):'],
      ['service', 'service'],
    ]) {
      if (looksLikeSecretFieldName(field)) continue;
      const raw = rawRule[field];
      if (raw === '<redacted>') continue;
      const values = ruleFieldValuesForSentence(raw);
      if (isRuleFieldEffectivelyAny(values)) continue;
      detail.push(`${label} ${values.join(', ')}`);
    }

    const actionDesc = rawRule.action !== '<redacted>' ? describePbfAction(rawRule.action) : null;
    if (actionDesc) detail.push(actionDesc);

    if (detail.length > 0) sentence += ` — ${detail.join(', ')}`;
    return sentence;
  } catch (_err) {
    return null;
  }
}

/**
 * PBF rule dispatch from a section-entry path -- same shape as
 * friendlyDescriptionForNatRule() above, just for the 'pbf' segment.
 */
function friendlyDescriptionForPbfRule(segments, pbfIdx, changeType, values) {
  if (!segments[pbfIdx + 1] || segments[pbfIdx + 1].toLowerCase() !== 'rules') return null;
  const ruleName = segments[pbfIdx + 2];
  if (isUnresolvableNameSegment(ruleName)) return null;
  const tail = segments.slice(pbfIdx + 3);

  if (tail.length === 0) {
    if (changeType === 'added' || changeType === 'removed') {
      return friendlyDescriptionForPbfRuleObject(values.value, changeType);
    }
    if (changeType === 'modified') return `PBF rule "${ruleName}" was changed`;
    return null;
  }

  if (changeType === 'modified') {
    if (tail.length === 1) {
      const field = tail[0];
      if (!looksLikeSecretFieldName(field) && values.old !== '<redacted>' && values.new !== '<redacted>') {
        return `PBF rule "${ruleName}"'s ${humanizeFieldForSentence(field)} was changed`;
      }
    }
    return `PBF rule "${ruleName}" was changed`;
  }

  return null;
}

// ---------------------------------------------------------------------------
// Zones (Palo Alto SSH transport only)
// ---------------------------------------------------------------------------
//
// PAN-OS zone config (`zone { <ZoneName> { network { layer3 [...]; } ... } }`)
// is the SAME "block key IS the entry's name" brace shape as the four
// address/service object kinds friendlyDescriptionForNetworkObject() already
// handles -- reused DIRECTLY here (kind='Zone') rather than duplicating its
// add/removed/one-field-deep/deeper logic, per this task's own "reuse
// directly, don't reinvent" instruction.
//
// Deliberately NOT extended to `network.*` interface entries: re-confirmed
// directly against lib/adapters/paloalto/sshParser.js and parser.js before
// deciding this (not assumed) -- NEITHER file has any interface-extraction
// function at all (unlike the dedicated extraction that exists for security
// rules, NAT/PBF's brace grammar above, and the four address/service object
// kinds), so there is no codebase-grounded path shape for "an interface" to
// check against, and `network` is also a much broader root than zones alone
// (routing, DNS settings, virtual routers, interfaces all live under it) --
// a one-level-deep field name there can't be confidently attributed to "an
// interface" specifically without risking a wrong label. Left as today's
// raw-path fallback (null) rather than guess, per this task's own explicit
// permission to do so.
function friendlyDescriptionForZone(segments, zoneIdx, changeType, values) {
  return friendlyDescriptionForNetworkObject(segments, zoneIdx, 'Zone', changeType, values);
}

// ---------------------------------------------------------------------------
// Fortinet flat settings sections (SNMP, NTP, DNS, Logging, Password Policy,
// FortiGuard/Update Settings)
// ---------------------------------------------------------------------------
//
// Same flat {key: value}-per-section shape friendlyDescriptionForFortinetSslVpn()
// above already handles for ssl_vpn -- confirmed directly against
// lib/adapters/fortinet/cliParser.js's parseFullConfiguration() (the
// `ntp`/`dns`/`log_syslogd`/`password_policy`/`fortiguard`/
// `autoupdate_schedule`/`snmp` keys are ALL built via the same flat-only
// `settingsOfFirst()`, never a nested `entriesOfAll()` table -- see that
// file's own header comment) before writing this, not assumed. Kept as a
// SEPARATE function from friendlyDescriptionForFortinetSslVpn (not
// refactored to share one implementation) so the already-shipped VPN
// sentence output can never be affected by this change.
//
// Field names actually exercised elsewhere in this codebase today (grounded
// via lib/auditChecksSeed.js's predicate_config, not guessed here): `ntp.ntpsync`,
// `dns.primary`, `log_syslogd.status`, `password_policy.minimum-length`,
// `autoupdate_schedule.status` -- each individually still doc-derived /
// not-yet-live-verified per that file's own header caveat, but they are this
// codebase's OWN grounded reference, not re-guessed here. `fortiguard` and
// `snmp` have no specific field name grounded anywhere in this codebase, but
// share the identical flat-dict section shape by construction -- any field
// name works generically for these two, exactly like ssl_vpn's own generic
// per-field handling already does for fields auditChecksSeed.js doesn't name
// either (e.g. `source-interface`).
function friendlyDescriptionForFortinetFlatSection(label, segments, idx, changeType, values) {
  const tail = segments.slice(idx + 1);

  if (tail.length === 0) {
    if (changeType === 'added') return `${label} configuration was added`;
    if (changeType === 'removed') return `${label} configuration was removed`;
    if (changeType === 'modified') return `${label} configuration was changed`;
    return null;
  }

  if (tail.length !== 1) return null; // flat single-level dict by construction -- deeper nesting is an unrecognized shape, don't guess

  const field = tail[0];
  if (looksLikeSecretFieldName(field)) return `${label} configuration was changed`;

  if (changeType === 'modified') {
    if (values.old === '<redacted>' || values.new === '<redacted>') return `${label} configuration was changed`;
    return `${label} ${humanizeFieldForSentence(field)} was changed to "${formatValueForSentence(values.new)}"`;
  }
  if (changeType === 'added') {
    if (values.value === '<redacted>') return `${label} configuration was changed`;
    return `${label} ${humanizeFieldForSentence(field)} was set to "${formatValueForSentence(values.value)}"`;
  }
  if (changeType === 'removed') {
    return `${label} ${humanizeFieldForSentence(field)} was removed`;
  }
  return null;
}

const FORTINET_FLAT_SECTIONS = new Map([
  ['snmp', 'SNMP'],
  ['ntp', 'NTP'],
  ['dns', 'DNS'],
  ['log_syslogd', 'Syslog'],
  ['password_policy', 'Password policy'],
  ['fortiguard', 'FortiGuard'],
  ['autoupdate_schedule', 'FortiGuard update schedule'],
]);

function friendlyDescriptionForFortinetSection(segments, changeType, values) {
  for (let i = 0; i < segments.length; i++) {
    const label = FORTINET_FLAT_SECTIONS.get(segments[i].toLowerCase());
    if (label) {
      return friendlyDescriptionForFortinetFlatSection(label, segments, i, changeType, values);
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Palo Alto system_info (device identity + firmware version)
// ---------------------------------------------------------------------------
//
// Grounded directly against MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR.paloalto's
// system_info allowlist above -- isVolatilePath() already guarantees any
// system_info.* diff entry reaching this point has a field name from EXACTLY
// that Set (hostname/sw-version/model/serial/multi-vsys/operational-mode/
// ip-address/ipv6-address/mac-address/family/devicename/platform-family/
// vpn-disable-mode); anything else was already filtered out before
// diffConfigs() ever produced an entry. 'sw-version' gets its own wording
// since it's what triggers the CVE re-match hook (see
// lib/adapters/index.js) -- worth naming clearly; 'hostname' gets its own
// wording since it's the device's real-world identity; every other
// allowlisted field gets a generic-but-accurate fallback (lower-value, same
// "still an honest sentence, just less specific" pattern this feature
// already uses elsewhere, e.g. a whole local-user-record modify).
const SYSTEM_INFO_NAMED_FIELDS = new Set(['sw-version', 'hostname']);

function friendlyDescriptionForSystemInfo(segments, sysIdx, changeType, values) {
  const tail = segments.slice(sysIdx + 1);

  if (tail.length !== 1) {
    // Either the whole system_info object landing as one entry (a rare
    // mismatched-type edge case -- isRegisteredSubtreeRoot() normally
    // decomposes a whole-subtree add/remove into per-leaf entries before
    // this ever runs) or something deeper than one level (not a shape the
    // allowlist above should ever produce) -- generic-but-accurate rather
    // than guess, and only for 'modified' (added/removed at this depth isn't
    // a committed shape).
    if (changeType === 'modified') return 'System info was changed';
    return null;
  }

  const field = tail[0];
  if (looksLikeSecretFieldName(field)) return null; // defensive only -- none of the allowlisted fields are secret-shaped

  if (field === 'sw-version') {
    if (changeType === 'modified') {
      return `Firmware version was changed from "${formatValueForSentence(values.old)}" to "${formatValueForSentence(values.new)}"`;
    }
    if (changeType === 'added') return `Firmware version was set to "${formatValueForSentence(values.value)}"`;
    if (changeType === 'removed') return 'Firmware version info was removed';
    return null;
  }

  if (field === 'hostname') {
    if (changeType === 'modified') {
      if (values.old === null || values.old === undefined || values.old === '') {
        return `Device hostname was set to "${formatValueForSentence(values.new)}"`;
      }
      return `Device was renamed from "${formatValueForSentence(values.old)}" to "${formatValueForSentence(values.new)}"`;
    }
    if (changeType === 'added') return `Device hostname was set to "${formatValueForSentence(values.value)}"`;
    if (changeType === 'removed') return 'Device hostname was removed';
    return null;
  }

  // Any other allowlisted field (model/serial/multi-vsys/operational-mode/
  // ip-address/ipv6-address/mac-address/family/devicename/platform-family/
  // vpn-disable-mode) -- generic-but-accurate, lower-value.
  const humanized = humanizeFieldForSentence(field);
  if (changeType === 'modified') return `System info ${humanized} was changed`;
  if (changeType === 'added') return `System info ${humanized} was set`;
  if (changeType === 'removed') return `System info ${humanized} was removed`;
  return null;
}

/**
 * Best-effort friendly-description resolver for one classifyDiff() entry.
 * See this section's header comment above for the recognized shapes and the
 * frozen-contract requirements. Never throws -- any unexpected input or
 * internal error falls through to null.
 */
function computeFriendlyDescription(path, changeType, values) {
  try {
    if (typeof path !== 'string' || path === '') return null;
    const segments = path.split('.').map(stripIndex).filter(Boolean);
    const safeValues = values && typeof values === 'object' ? values : {};

    const ludIdx = segments.findIndex((s) => s.toLowerCase() === 'local-user-database');
    if (ludIdx !== -1) {
      return friendlyDescriptionForLocalUserDatabase(segments, ludIdx, changeType, safeValues);
    }

    for (let i = 0; i < segments.length; i++) {
      const kind = OBJECT_SECTION_KIND.get(segments[i].toLowerCase());
      if (kind) {
        return friendlyDescriptionForNetworkObject(segments, i, kind, changeType, safeValues);
      }
    }

    const adminDescription = friendlyDescriptionForAdminAccount(segments, changeType, safeValues);
    if (adminDescription !== null) return adminDescription;

    const vpnDescription = friendlyDescriptionForVpnConfig(path, segments, changeType, safeValues);
    if (vpnDescription !== null) return vpnDescription;

    const natIdx = segments.findIndex((s) => s.toLowerCase() === 'nat');
    if (natIdx !== -1) {
      const natDescription = friendlyDescriptionForNatRule(segments, natIdx, changeType, safeValues);
      if (natDescription !== null) return natDescription;
    }

    const pbfIdx = segments.findIndex((s) => s.toLowerCase() === 'pbf');
    if (pbfIdx !== -1) {
      const pbfDescription = friendlyDescriptionForPbfRule(segments, pbfIdx, changeType, safeValues);
      if (pbfDescription !== null) return pbfDescription;
    }

    const zoneIdx = segments.findIndex((s) => s.toLowerCase() === 'zone');
    if (zoneIdx !== -1) {
      const zoneDescription = friendlyDescriptionForZone(segments, zoneIdx, changeType, safeValues);
      if (zoneDescription !== null) return zoneDescription;
    }

    const fortinetSectionDescription = friendlyDescriptionForFortinetSection(segments, changeType, safeValues);
    if (fortinetSectionDescription !== null) return fortinetSectionDescription;

    const sysInfoIdx = segments.findIndex((s) => s.toLowerCase() === 'system_info');
    if (sysInfoIdx !== -1) {
      const sysInfoDescription = friendlyDescriptionForSystemInfo(segments, sysInfoIdx, changeType, safeValues);
      if (sysInfoDescription !== null) return sysInfoDescription;
    }

    // 'network' (Zones/Interfaces' sibling "Network Configuration" bucket)
    // and 'deviceconfig' are deliberately left WITHOUT a dispatch branch here
    // -- see friendlyDescriptionForZone()'s comment above for why `network`
    // interface entries specifically aren't resolvable, and Task 5's own
    // instructions for why `deviceconfig` (a broad, general-purpose PAN-OS
    // settings root spanning system/ntp-servers/dns-setting/service/
    // snmp-setting/session and more, with no single confident one-level-deep
    // identifier pattern) is left as today's raw-path fallback. Both fall
    // through to null below, same as any other unrecognized shape.
    return null;
  } catch (_err) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Rule Changes table -- whole-rule added/removed friendlyDescription
// ---------------------------------------------------------------------------
//
// Task 3a: today, a whole security rule added/removed (the `field === null`
// case in pushRuleChange() below) carries the raw rule dict straight through
// to `value`, rendered as an untranslated ~13-key JSON blob in the UI (a real
// user report: a Palo Alto rule named "Allow-AI_Tools" showing exactly that).
// This builds ONE readable sentence from it instead.
//
// Reachable ONLY from the SSH transport. Re-confirmed directly against
// classifyPath() above before writing this (not assumed): the XML/API
// transport's rule entries are `rulebase.security.rules.entry[N].<field>` --
// `entry`/`entry[N]` matches `isUnresolvableIndex`, so classifyPath() returns
// `kind: 'section'` for those paths and they never reach pushRuleChange() at
// all. Only the SSH transport's `rulebase.security.rules.<RuleName>[...]`
// shape (the rule name is a literal brace-tree block key -- see
// ruleFromBraceEntry() in lib/adapters/paloalto/sshParser.js) ever produces
// `kind: 'rule'` with `field === null` (a whole-rule add/remove, i.e. the
// diff path was exactly the rule's own key, nothing after it).
//
// Field names grounded directly in ruleFromBraceEntry()'s own `a.<field>`
// reads (the raw brace attrs object, `a`, IS what lands in config_parsed --
// this function works on that same raw shape, just without that function's
// NormalizedRule renaming): `to`/`from` (destination/source zone(s) --
// confirmed from that file's own header-comment example, `to any; from
// [DMZ1 DMZ2 DMZ3];`, i.e. `from` = source zone, `to` = destination zone),
// `action` (allow/deny/drop/reset-*), `source`/`destination` (address
// string or array), `service`/`application` (string or array), `category`
// (URL category list) -- PAN-OS's well-documented standard rule-schema
// fields. `source-user`/`source-hip`/`destination-hip`/`log-start`/
// `log-end` are deliberately left OUT of the sentence (almost always "any"/
// default per PAN-OS convention, and the raw diff entry is still available
// as a fallback) to keep the sentence short, not because they're unsafe.
const RULE_OBJECT_DETAIL_FIELDS = [
  ['source', 'source'],
  ['destination', 'destination'],
  ['service', 'service'],
  ['application', 'application(s):'],
  ['category', 'category'],
];

// A field's value is omitted from the sentence when it's absent OR every
// element (string or array) is the PAN-OS no-op/default sentinel "any"
// (case-insensitive) -- don't clutter the sentence with default values.
function ruleFieldValuesForSentence(value) {
  if (value === null || value === undefined) return [];
  if (Array.isArray(value)) return value.filter((v) => typeof v === 'string' || typeof v === 'number').map(String);
  if (typeof value === 'string') return value === '' ? [] : [value];
  if (typeof value === 'number' || typeof value === 'boolean') return [String(value)];
  return []; // an unexpected shape (nested object where a scalar/list was expected) -- omit, don't guess
}

function isRuleFieldEffectivelyAny(values) {
  return values.length === 0 || values.every((v) => v.toLowerCase() === 'any');
}

/**
 * Builds one plain-English sentence for a whole PAN-OS security rule
 * added/removed as one diff entry. `rawRule` is the raw brace-attrs object
 * (see this function's header comment above); `changeType` is 'added' or
 * 'removed' (the only two states pushRuleChange() below calls this for).
 * Never throws -- any unexpected shape falls back to null (today's raw-JSON
 * rendering), same discipline as every other friendlyDescription function in
 * this file.
 */
function friendlyDescriptionForRuleObject(rawRule, changeType) {
  if (!isPlainObject(rawRule)) return null;
  if (changeType !== 'added' && changeType !== 'removed') return null;

  try {
    const actionRaw = typeof rawRule.action === 'string' ? rawRule.action : null;
    if (!actionRaw || looksLikeSecretFieldName('action')) return null;
    const action = actionRaw.toUpperCase();

    // from/to (zones) are always included -- the core of what a rule does --
    // even when the value is "any", unlike the optional detail fields below.
    if (looksLikeSecretFieldName('from') || looksLikeSecretFieldName('to')) return null; // never reachable in practice, defensive only
    const fromZones = ruleFieldValuesForSentence(rawRule.from);
    const toZones = ruleFieldValuesForSentence(rawRule.to);
    if (fromZones.length === 0 || toZones.length === 0) return null; // core fields missing -- not confident this is a real rule shape

    const zoneWord = (list) => (list.length > 1 ? 'zones' : 'zone');
    let sentence = `${action} rule from ${zoneWord(fromZones)} "${fromZones.join(', ')}" to ${zoneWord(toZones)} "${toZones.join(', ')}" was ${changeType === 'added' ? 'added' : 'removed'}`;

    const detail = [];
    for (const [field, label] of RULE_OBJECT_DETAIL_FIELDS) {
      if (looksLikeSecretFieldName(field)) continue; // defensive -- a PAN-OS security rule shouldn't structurally carry a secret-shaped field, but never trust that blindly
      const raw = rawRule[field];
      if (raw === '<redacted>') continue;
      const values = ruleFieldValuesForSentence(raw);
      if (isRuleFieldEffectivelyAny(values)) continue;
      const joined = values.join(', ');
      if (joined === '<redacted>') continue;
      detail.push(`${label} ${joined}`);
    }

    if (detail.length > 0) sentence += ` — ${detail.join(', ')}`;
    return sentence;
  } catch (_err) {
    return null;
  }
}

/**
 * Groups an already-computed diff ({added, removed, modified}) into a
 * "Rule Changes" table plus everything else bucketed by section, for
 * display. Pure, no DB. See the block comment above for the full rationale.
 *
 * `friendlyDescription` (added alongside classifyDiff() itself, see the
 * friendlyDescription section above): a short plain-English sentence
 * describing the change, or exactly `null` when the path shape isn't
 * confidently recognized -- FROZEN CONTRACT, DiffViewer.js depends on this
 * field always being present with this exact name and null-not-omitted
 * semantics. Rule-table rows can now carry a real (non-null) value here too
 * (see friendlyDescriptionForRuleObject() above, added for Task 3a) -- a
 * whole rule added/removed, translated out of its raw brace-attrs shape into
 * one sentence. `fieldLabel` (added for Task 3b) is a SEPARATE field: a
 * humanized version of the raw field name for a per-field rule-table row
 * (`log-end` -> `log end`), `null` for the whole-rule row (where `field`
 * itself is already `null`) -- always present, like `friendlyDescription`,
 * never omitted.
 *
 * @param {{added:object[],removed:object[],modified:object[]}} diff
 * @returns {{
 *   ruleChanges: {ruleName:string, changes: {field:string|null, fieldLabel:string|null, changeType:'added'|'removed'|'modified', friendlyDescription:string|null, value?:*, old?:*, new?:*}[]}[],
 *   sections: {label:string, addedCount:number, removedCount:number, modifiedCount:number, totalCount:number, entries:{changeType:string, path:string, friendlyDescription:string|null, ruleIndex:number|null, ruleField:string|null, value?:*, old?:*, new?:*}[]}[],
 * }}
 *
 * `ruleIndex`/`ruleField` on a section entry (added alongside the indexed-rule
 * grouping, see extractIndexedRuleEntry() above): the positional rule index
 * and in-rule field path for a Palo Alto XML/API `...rules.entry[N].<field>`
 * entry, letting DiffViewer.js regroup the flat per-field rows of the
 * "Security Rules" section into one table per rule. Both null for every other
 * path shape -- always present, never omitted, same null-not-omitted contract
 * as `friendlyDescription`.
 */
function classifyDiff(diff) {
  const added = Array.isArray(diff?.added) ? diff.added : [];
  const removed = Array.isArray(diff?.removed) ? diff.removed : [];
  const modified = Array.isArray(diff?.modified) ? diff.modified : [];

  const ruleChanges = [];
  const sectionMap = new Map(); // label -> { addedCount, removedCount, modifiedCount, entries }

  // `label`/`entry.path` here are for DISPLAY -- classification (which
  // section an entry belongs to) has already happened by the time this
  // runs, against the real untruncated path (see classifyPath() calls
  // below). truncatePathForDisplay() only ever touches what the UI shows,
  // never what was used to decide where it goes.
  function addToSection(label, changeType, entry) {
    if (!sectionMap.has(label)) {
      sectionMap.set(label, { addedCount: 0, removedCount: 0, modifiedCount: 0, entries: [] });
    }
    const bucket = sectionMap.get(label);
    bucket[`${changeType}Count`] += 1;
    // friendlyDescription is computed against the REAL, untruncated
    // entry.path/value/old/new -- same "classify against the real path,
    // truncate only for display" discipline this function's own header
    // comment already documents for `label`/`path`. Never allowed to throw
    // (computeFriendlyDescription already wraps itself; the outer try/catch
    // here is cheap extra insurance against a future change loosening that).
    let friendlyDescription = null;
    try {
      friendlyDescription = computeFriendlyDescription(entry.path, changeType, entry);
    } catch (_err) {
      friendlyDescription = null;
    }
    // Indexed (XML/API) rulebase entries carry the {index, field} a display
    // grouper needs to reassemble a flat pile of `entry[5].log-end` rows back
    // into one per-rule table -- computed against the REAL untruncated
    // entry.path (same "classify/derive against the real path, truncate only
    // for display" discipline as friendlyDescription above). null/null for
    // every other path shape, so DiffViewer.js's grouping is a strict opt-in
    // that leaves all existing section rendering untouched.
    const ruleEntry = extractIndexedRuleEntry(entry.path);
    bucket.entries.push({
      ...entry,
      changeType,
      path: truncatePathForDisplay(entry.path, MAX_ROW_PATH_LENGTH),
      friendlyDescription: friendlyDescription || null,
      ruleIndex: ruleEntry ? ruleEntry.index : null,
      ruleField: ruleEntry ? ruleEntry.field : null,
    });
  }

  // Same display-only truncation for a rule-table row's ruleName/field --
  // both are individual path SEGMENTS (already split apart by classifyPath()),
  // so corruption is far less likely here than in the section-entries case
  // above, but bounded defensively rather than assumed safe.
  //
  // `ruleGroupKey` carries the RAW, pre-truncation ruleName alongside the
  // truncated display value -- the byRule grouping below keys off this, not
  // off the display `ruleName`. Two distinct corrupted rule names both
  // collapse to the identical placeholder ("(unreadable path — see full diff
  // for details)") once truncated for display; grouping on that shared
  // placeholder would silently merge two unrelated rules' field changes into
  // one fake row. Stripped back out before the grouped result is returned,
  // so it never leaks into the public shape.
  function pushRuleChange(ruleName, field, rest) {
    // `field === null` is the whole-rule added/removed case (see
    // classifyPath() above) -- `fieldLabel` has nothing to humanize there,
    // same "null when not applicable" contract as `friendlyDescription`.
    // `PATH_SHAPE_VIOLATION` guards the same corrupted-path case
    // truncatePathForDisplay() already detects -- humanizing a corrupted
    // blob would just read as garbage title-cased, so treat it as
    // unhumanizable too rather than call titleCase() on it.
    const fieldLabel = field === null || PATH_SHAPE_VIOLATION.test(String(field))
      ? null
      : humanizeFieldForSentence(field);

    // Task 3a: a whole-rule added/removed entry can now carry a real
    // friendlyDescription (see friendlyDescriptionForRuleObject() above) --
    // only ever attempted for the `field === null` shape and only for
    // added/removed (that function's own contract); every other rule-table
    // row (any per-field modify, or a whole-rule 'modified' -- structurally
    // possible but not one of the two shapes that function commits to) still
    // has no recognized friendlyDescription shape, same as before this task.
    let friendlyDescription = null;
    if (field === null && (rest.changeType === 'added' || rest.changeType === 'removed')) {
      try {
        friendlyDescription = friendlyDescriptionForRuleObject(rest.value, rest.changeType);
      } catch (_err) {
        friendlyDescription = null;
      }
    }

    ruleChanges.push({
      ruleName: truncatePathForDisplay(ruleName, MAX_ROW_PATH_LENGTH),
      field: field === null ? null : truncatePathForDisplay(field, MAX_ROW_PATH_LENGTH),
      fieldLabel,
      ruleGroupKey: ruleName,
      friendlyDescription: friendlyDescription || null,
      ...rest,
    });
  }

  for (const e of added) {
    if (e.path === '(truncated)') {
      addToSection('Other (Truncated)', 'added', e);
      continue;
    }
    const c = classifyPath(e.path);
    if (c.kind === 'rule') {
      pushRuleChange(c.ruleName, c.field, { changeType: 'added', value: e.value });
    } else {
      addToSection(c.sectionLabel, 'added', e);
    }
  }
  for (const e of removed) {
    const c = classifyPath(e.path);
    if (c.kind === 'rule') {
      pushRuleChange(c.ruleName, c.field, { changeType: 'removed', value: e.value });
    } else {
      addToSection(c.sectionLabel, 'removed', e);
    }
  }
  for (const e of modified) {
    const c = classifyPath(e.path);
    if (c.kind === 'rule') {
      pushRuleChange(c.ruleName, c.field, { changeType: 'modified', old: e.old, new: e.new });
    } else {
      addToSection(c.sectionLabel, 'modified', e);
    }
  }

  // Rule changes grouped by rule name (a single rule edit commonly touches
  // several fields -- one row per field, grouped so the table can show the
  // rule name once with its field-level changes underneath rather than
  // repeating it), ordered by whichever rule has the most changes first.
  //
  // Grouped by the RAW `ruleGroupKey`, not the (possibly-shared) truncated
  // display `ruleName` -- see pushRuleChange()'s comment above. `ruleName`
  // used for the group's own label is still the truncated display value.
  const byRule = new Map();
  for (const rc of ruleChanges) {
    const { ruleGroupKey, ...display } = rc;
    if (!byRule.has(ruleGroupKey)) byRule.set(ruleGroupKey, { ruleName: display.ruleName, changes: [] });
    byRule.get(ruleGroupKey).changes.push(display);
  }
  const ruleChangesGrouped = [...byRule.values()].sort((a, b) => b.changes.length - a.changes.length);

  const sections = [...sectionMap.entries()]
    .map(([label, v]) => ({
      label,
      addedCount: v.addedCount,
      removedCount: v.removedCount,
      modifiedCount: v.modifiedCount,
      totalCount: v.addedCount + v.removedCount + v.modifiedCount,
      entries: v.entries,
    }))
    .sort((a, b) => b.totalCount - a.totalCount);

  return { ruleChanges: ruleChangesGrouped, sections };
}

// A real, well-formed change_summary is always short (a count phrase plus up
// to 3 examples, each now capped at MAX_EXAMPLE_PATH_LENGTH by
// sanitizeExamplePath() above) -- comfortably under 500 characters. Anything
// stored ABOVE this threshold predates the sanitizeExamplePath() fix and is
// a leftover corrupted-path artifact from the SAME brace-corruption bug
// class documented above, not a legitimately long summary.
const OVERSIZED_SUMMARY_THRESHOLD = 500;

/**
 * One-time-but-safely-rerunnable backfill: regenerates change_summary for
 * any config_diffs row whose stored summary is abnormally large (see
 * OVERSIZED_SUMMARY_THRESHOLD above), using the CURRENT summarizeDiff()
 * (which now sanitizes/truncates each example path). The underlying `diff`
 * jsonb is never touched -- only the derived, cached change_summary text is
 * re-derived from it. Same best-effort, non-fatal, safe-to-rerun-forever
 * shape as cleanupVolatileConfigDiffs() above: a row with an
 * already-reasonable summary length is never touched, so re-running this on
 * every migrate.js invocation is cheap.
 */
async function regenerateOversizedChangeSummaries(pool) {
  const { rows } = await pool.query(
    `SELECT id, diff FROM config_diffs WHERE LENGTH(change_summary) > $1`,
    [OVERSIZED_SUMMARY_THRESHOLD]
  );

  let updated = 0;
  for (const row of rows) {
    const summary = summarizeDiff(row.diff || {});
    await pool.query('UPDATE config_diffs SET change_summary = $1 WHERE id = $2', [summary, row.id]);
    updated += 1;
  }

  return { checked: rows.length, updated };
}

// ---------------------------------------------------------------------------
// Historical primitive-array shift-cascade collapse (retroactive fix)
// ---------------------------------------------------------------------------
//
// ⛔ THE PROBLEM (user report): a config_diffs row recorded BEFORE the
// value-based primitive-array diff existed (diffPrimitiveArrayLCS, added when
// this file's array branch went from positional to LCS) shows a set-like
// primitive array (a user-group membership list, DNS/NTP server list) that had
// ONE element inserted/removed as a huge run of "modified" entries -- e.g.
// removing one user from the front of a 246-name SSL-GROUP membership list
// shifted every later name down one slot, so the OLD positional diff reported
// 245 "membership changed: X -> Y" modifications PLUS a mis-identified tail
// "removed" (the last old element, which was NOT the element actually removed).
// Genuinely misleading: it reads as "the whole list changed" when one user
// left, and it names the WRONG user as removed.
//
// New diffs never produce this (the LCS array branch already collapses it), so
// this is purely a HISTORICAL-row problem. Those rows can't be recomputed from
// their source snapshots (long rotated out of device_configs), BUT the stored
// entries themselves carry everything needed: for one array path, the modified
// entries give old[i]/new[i], and the tail add/remove gives the extra element.
// Reconstruct the changed REGION of the array from those entries (ordered by
// index) and re-diff it with LCS -- yielding the true added/removed and NO
// modified. For a set-like primitive array this is strictly more correct
// regardless of whether it was a shift or a genuine in-place change (position
// is meaningless for a set; "value X replaced Y at slot 3" and "Y removed, X
// added" are the same fact).
//
// Conservative gates: only collapses an array path with >= CASCADE_MIN_MODIFIED
// primitive modified entries (a clear cascade, not a one-off edit) AND whose
// touched indices form a CONTIGUOUS range (so the reconstructed region has no
// gap an unchanged-in-place element would leave); anything else is left exactly
// as stored. Pure + deterministic (unit-tested); applied to stored rows by the
// migration below.
const CASCADE_MIN_MODIFIED = 3;
const ARRAY_INDEX_PATH_RE = /^(.*)\[(\d+)\]$/;

/**
 * Standard LCS diff of two primitive arrays, returning the concrete removed and
 * added VALUES (not paths). Mirrors diffPrimitiveArrayLCS's alignment, using
 * the same normalizeLeaf() equality, but shaped for reconstruction rather than
 * accumulator pushes.
 */
function lcsPrimitiveDiff(oldArr, newArr) {
  const n = oldArr.length;
  const m = newArr.length;
  const dp = new Array(n + 1);
  for (let i = 0; i <= n; i++) dp[i] = new Array(m + 1).fill(0);
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] =
        normalizeLeaf(oldArr[i]) === normalizeLeaf(newArr[j])
          ? dp[i + 1][j + 1] + 1
          : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const removed = [];
  const added = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (normalizeLeaf(oldArr[i]) === normalizeLeaf(newArr[j])) {
      i += 1;
      j += 1;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      removed.push(oldArr[i]);
      i += 1;
    } else {
      added.push(newArr[j]);
      j += 1;
    }
  }
  while (i < n) removed.push(oldArr[i++]);
  while (j < m) added.push(newArr[j++]);
  return { removed, added };
}

/**
 * PURE. Returns a new diff with any primitive-array positional-shift cascade
 * collapsed to its true added/removed (and no modified). Returns the diff
 * effectively unchanged (normalized shape) when there's nothing to collapse.
 * See the block comment above for the full rationale and the conservative
 * gates.
 */
function collapsePrimitiveArrayShifts(diff) {
  const added = Array.isArray(diff.added) ? diff.added : [];
  const removed = Array.isArray(diff.removed) ? diff.removed : [];
  const modified = Array.isArray(diff.modified) ? diff.modified : [];

  const modCount = new Map();
  for (const e of modified) {
    const mm = ARRAY_INDEX_PATH_RE.exec(e.path || '');
    if (mm && isPrimitiveArrayElement(e.old) && isPrimitiveArrayElement(e.new)) {
      modCount.set(mm[1], (modCount.get(mm[1]) || 0) + 1);
    }
  }
  const cascadePaths = new Set();
  for (const [p, c] of modCount) if (c >= CASCADE_MIN_MODIFIED) cascadePaths.add(p);
  if (cascadePaths.size === 0) return { added, removed, modified };

  const out = { added: [], removed: [], modified: [] };
  const slotsByPath = new Map(); // arrPath -> Map(index -> {old?, new?, hasOld, hasNew})
  const slotFor = (p, idx) => {
    let g = slotsByPath.get(p);
    if (!g) {
      g = new Map();
      slotsByPath.set(p, g);
    }
    let s = g.get(idx);
    if (!s) {
      s = { hasOld: false, hasNew: false };
      g.set(idx, s);
    }
    return s;
  };

  const routeInto = (entry, kind) => {
    const mm = ARRAY_INDEX_PATH_RE.exec(entry.path || '');
    if (!mm || !cascadePaths.has(mm[1])) return false;
    if (kind === 'modified') {
      if (!isPrimitiveArrayElement(entry.old) || !isPrimitiveArrayElement(entry.new)) return false;
      const s = slotFor(mm[1], Number(mm[2]));
      s.old = entry.old;
      s.new = entry.new;
      s.hasOld = true;
      s.hasNew = true;
      return true;
    }
    if (!isPrimitiveArrayElement(entry.value)) return false;
    const s = slotFor(mm[1], Number(mm[2]));
    if (kind === 'removed') {
      s.old = entry.value;
      s.hasOld = true;
    } else {
      s.new = entry.value;
      s.hasNew = true;
    }
    return true;
  };

  for (const e of modified) if (!routeInto(e, 'modified')) out.modified.push(e);
  for (const e of removed) if (!routeInto(e, 'removed')) out.removed.push(e);
  for (const e of added) if (!routeInto(e, 'added')) out.added.push(e);

  for (const [p, g] of slotsByPath) {
    const indices = [...g.keys()].sort((a, b) => a - b);
    const contiguous = indices.every((v, i) => i === 0 || v === indices[i - 1] + 1);
    if (!contiguous) {
      // Not safely reconstructable -- restore the original entries untouched.
      for (const idx of indices) {
        const s = g.get(idx);
        if (s.hasOld && s.hasNew) out.modified.push({ path: `${p}[${idx}]`, old: s.old, new: s.new });
        else if (s.hasOld) out.removed.push({ path: `${p}[${idx}]`, value: s.old });
        else if (s.hasNew) out.added.push({ path: `${p}[${idx}]`, value: s.new });
      }
      continue;
    }
    const oldArr = [];
    const newArr = [];
    for (const idx of indices) {
      const s = g.get(idx);
      if (s.hasOld) oldArr.push(s.old);
      if (s.hasNew) newArr.push(s.new);
    }
    const base = indices[0];
    const { removed: remVals, added: addVals } = lcsPrimitiveDiff(oldArr, newArr);
    let idx = base;
    for (const v of remVals) out.removed.push({ path: `${p}[${idx++}]`, value: v });
    for (const v of addVals) out.added.push({ path: `${p}[${idx++}]`, value: v });
  }

  return out;
}

/**
 * One-time (safely re-runnable) retroactive fix: collapses primitive-array
 * shift cascades in EXISTING config_diffs rows (see collapsePrimitiveArrayShifts()
 * above) and re-derives change_summary from the collapsed diff, so the row
 * header, summary text, and expanded detail all agree. Idempotent -- a row with
 * no cascade (including one already collapsed) is left untouched, since a
 * collapsed row has no modified cascade left to match. Best-effort/non-fatal,
 * same shape as cleanupVolatileConfigDiffs()/regenerateOversizedChangeSummaries().
 */
async function collapseHistoricalArrayShiftCascades(pool) {
  const { rows } = await pool.query(`SELECT id, diff FROM config_diffs`);

  let updated = 0;
  for (const row of rows) {
    const original = row.diff || {};
    let collapsed;
    try {
      collapsed = collapsePrimitiveArrayShifts(original);
    } catch (_err) {
      continue; // never let one malformed row abort the migration
    }
    const originalNormalized = {
      added: original.added || [],
      removed: original.removed || [],
      modified: original.modified || [],
    };
    if (JSON.stringify(collapsed) === JSON.stringify(originalNormalized)) continue;

    const summary = summarizeDiff(collapsed);
    await pool.query('UPDATE config_diffs SET diff = $1::jsonb, change_summary = $2 WHERE id = $3', [
      JSON.stringify(collapsed),
      summary,
      row.id,
    ]);
    updated += 1;
  }

  return { checked: rows.length, updated };
}

module.exports = {
  diffConfigs,
  summarizeDiff,
  isEmptyDiff,
  detectAndStoreDiff,
  createBackup,
  filterDiffForCurrentRules,
  cleanupVolatileConfigDiffs,
  classifyDiff,
  regenerateOversizedChangeSummaries,
  collapsePrimitiveArrayShifts,
  collapseHistoricalArrayShiftCascades,
};
