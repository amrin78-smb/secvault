'use strict';

// lib/engines/ruleConsolidationData.js
//
// The database half of rule consolidation: loads a device's (or the fleet's)
// `firewall_rules` and `network_objects` rows and hands them to the pure
// engine. No judgement lives here.
//
// ⛔ SPLIT FROM ruleConsolidation.js DELIBERATELY, the same split
// segmentationData.js makes for segmentation.js. That file is pure — canonical
// keys, interference, verdicts, no pool — which is what lets its 48 tests drive
// every branch with literal rules. This file is the plumbing. Keeping the
// judgement out of the plumbing is what makes the judgement testable.
//
// ── ⛔ AN EMPTY RESULT AND A FAILED READ MUST NOT LOOK ALIKE ───────────────
//
// This is the whole reason this file returns a shape rather than an array.
// "No consolidation candidates on this firewall" is a real, good answer — two
// live devices genuinely have none. "We could not read the rules" is not an
// answer at all, and rendering it as the first one tells an operator their
// ruleset is already tidy at exactly the moment SecVault cannot see it. So:
//
//   ok: true  + groups: []   -> nothing to consolidate, measured.
//   ok: false + groups: null -> NOTHING WAS MEASURED. Never `[]` here; an
//                               empty array is a claim, and a caller that
//                               forgets to check `ok` would render it as one.
//
// ⛔ AND "NO RULES COLLECTED" IS A THIRD STATE. A firewall whose ruleset has
// never been pulled produces zero rows, zero groups, and reads as the tidiest
// firewall on the fleet — this codebase's signature bug pointed at a cleanup
// screen. `coverage.rulesCollected` is what separates it from a device that
// really has nothing to merge, and it is derived from
// `devices.last_rules_collected_at` (stamped ONLY when getRules() succeeded),
// not from the row count alone.
//
// ── ⛔ THE OBJECT CATALOGUE IS A COVERAGE FACT, NOT AN OPTIONAL EXTRA ──────
//
// Every object NAME an unread catalogue cannot resolve falls to `unknown` in
// dimensionOverlap, and the verdict falls CLOSED to `needs_review`. So a
// missing catalogue can never manufacture a `safe_to_merge` — it can only make
// the review pile look like a POLICY problem when it is really a COLLECTION
// one. Three live devices carry zero `network_objects` rows, so this is the
// common case, not a corner, and it is reported rather than absorbed:
//
//   'available'      rows were read
//   'none_collected' the read worked and returned nothing
//   'unreadable'     the read FAILED — objectCount is null, never 0
//
// ⛔ An object-read failure does NOT fail the whole answer, because the rule
// rows are still worth analysing and the verdicts they produce are still
// conservative. It is disclosed instead.

const {
  findConsolidationGroups,
  summariseConsolidation,
  MERGE_CLAIM,
  VERDICTS,
} = require('./ruleConsolidation');

// ⛔ EVERY COLUMN THE ENGINE KEYS ON, NAMED HERE SO A TEST CAN PIN IT AGAINST
// THE SQL BELOW. A column silently dropped from the SELECT does not crash: it
// arrives as `undefined`, canonicalises to the empty string, and two rules that
// differ in it key TOGETHER. `log_enabled` is the cheapest example — merging a
// logged rule with an unlogged one changes what the firewall records, and
// omitting the column would propose exactly that with no error anywhere.
//
// ⛔ `raw_rule` IS ON THIS LIST AND MUST STAY. It is the ONLY input to
// hasNegationMarker(), the engine's single guard against a negated address
// field — and a negated field inverts the extent the disjointness check reads,
// so without it a "these never overlap" conclusion is exactly backwards. Drop
// the column and that guard cannot fire, which is this codebase's most-named
// defect. It is also the most expensive column here; that cost is the price of
// the guard, not an oversight.
const RULE_COLUMNS = Object.freeze([
  'id',
  'device_id',
  'rule_name',
  'rule_id_vendor',
  'sequence_number',
  'enabled',
  'action',
  'src_zones',
  'dst_zones',
  'src_addresses',
  'dst_addresses',
  'services',
  'applications',
  'schedule',
  'expiry_date',
  'log_enabled',
  'nat_enabled',
  'comment',
  'tags',
  'hit_count',
  'raw_rule',
  'vdom',
]);

// ⛔ ORDERED BY sequence_number. findConsolidationGroups documents its input as
// "already ordered by sequence_number" and re-sorts each group itself, so this
// is belt and braces — but `NULLS LAST` is not: a NULL sequence number is a
// rule the engine cannot position, and sorting those to the front would put the
// unplaceable rows at the top of every debug dump of this query.
const RULES_SQL = `
  SELECT fr.id, fr.device_id, fr.rule_name, fr.rule_id_vendor, fr.sequence_number,
         fr.enabled, fr.action, fr.src_zones, fr.dst_zones, fr.src_addresses,
         fr.dst_addresses, fr.services, fr.applications, fr.schedule, fr.expiry_date,
         fr.log_enabled, fr.nat_enabled, fr.comment, fr.tags, fr.hit_count,
         fr.raw_rule, fr.vdom
    FROM firewall_rules fr
   WHERE fr.device_id = $1
   ORDER BY fr.sequence_number NULLS LAST, fr.id`;

const FLEET_RULES_SQL = `
  SELECT fr.id, fr.device_id, fr.rule_name, fr.rule_id_vendor, fr.sequence_number,
         fr.enabled, fr.action, fr.src_zones, fr.dst_zones, fr.src_addresses,
         fr.dst_addresses, fr.services, fr.applications, fr.schedule, fr.expiry_date,
         fr.log_enabled, fr.nat_enabled, fr.comment, fr.tags, fr.hit_count,
         fr.raw_rule, fr.vdom
    FROM firewall_rules fr
    JOIN devices d ON d.id = fr.device_id
   WHERE d.active = true
   ORDER BY fr.device_id, fr.sequence_number NULLS LAST, fr.id`;

// ⛔ `value` AND `members` BOTH, and both are load-bearing: buildObjectMap keeps
// the whole row, resolveAddressField reads `value` on a leaf and `members` on a
// group. A catalogue loaded without `members` resolves every group to nothing,
// which is indistinguishable from a catalogue that was never collected.
const OBJECTS_SQL = `
  SELECT no.id, no.device_id, no.object_type, no.name, no.value, no.members
    FROM network_objects no
   WHERE no.device_id = $1`;

const FLEET_OBJECTS_SQL = `
  SELECT no.id, no.device_id, no.object_type, no.name, no.value, no.members
    FROM network_objects no
    JOIN devices d ON d.id = no.device_id
   WHERE d.active = true`;

const DEVICE_SQL = `
  SELECT d.id, d.name, d.vendor, d.active, d.last_rules_collected_at
    FROM devices d
   WHERE d.id = $1`;

const FLEET_DEVICES_SQL = `
  SELECT d.id, d.name, d.vendor, d.last_rules_collected_at
    FROM devices d
   WHERE d.active = true
   ORDER BY d.name`;

const OBJECT_COVERAGE = Object.freeze({
  AVAILABLE: 'available',
  NONE: 'none_collected',
  UNREADABLE: 'unreadable',
});

/** An error's message, never the object — these travel into a rendered caveat. */
function messageOf(err) {
  if (!err) return 'unknown error';
  return err.message ? String(err.message) : String(err);
}

/**
 * Which of the three object-catalogue states applies.
 *
 * ⛔ PURE, AND EXPORTED, so the distinction the UI draws is pinned by a test
 * rather than re-derived from `count > 0` at a render site. A failed read has
 * `count: null`, and `null` must never fall into the same branch as `0`: one
 * says the firewall defines no objects, the other says we do not know what it
 * defines.
 */
function objectCoverageState({ read, count }) {
  if (read !== true) return OBJECT_COVERAGE.UNREADABLE;
  if (count === null || count === undefined || !Number.isFinite(Number(count))) {
    return OBJECT_COVERAGE.UNREADABLE;
  }
  return Number(count) > 0 ? OBJECT_COVERAGE.AVAILABLE : OBJECT_COVERAGE.NONE;
}

/**
 * Per-rule coverage counters, computed from the rows already in hand rather
 * than from a second COUNT query.
 *
 * ⛔ `rulesWithoutSequence` IS REPORTED EVEN THOUGH IT IS ZERO ON THIS FLEET.
 * findConsolidationGroups silently EXCLUDES an enabled rule with no
 * sequence_number from grouping — correctly, since no merge involving it could
 * ever be checked — and an exclusion nobody counts is a candidate set that
 * looks complete. This is the number that makes that exclusion visible on the
 * collection that goes wrong later.
 */
function ruleCoverage(rows) {
  const list = Array.isArray(rows) ? rows : [];
  const enabled = list.filter((r) => r && r.enabled !== false);
  const withoutSeq = enabled.filter(
    (r) => r.sequence_number === null || r.sequence_number === undefined || r.sequence_number === ''
  );
  return {
    ruleCount: list.length,
    enabledRuleCount: enabled.length,
    disabledRuleCount: list.length - enabled.length,
    rulesWithoutSequence: withoutSeq.length,
    groupableRuleCount: enabled.length - withoutSeq.length,
  };
}

async function loadDeviceRules(pool, deviceId) {
  const { rows } = await pool.query(RULES_SQL, [deviceId]);
  return rows;
}

async function loadDeviceObjects(pool, deviceId) {
  const { rows } = await pool.query(OBJECTS_SQL, [deviceId]);
  return rows;
}

async function loadFleetRules(pool) {
  const { rows } = await pool.query(FLEET_RULES_SQL);
  return rows;
}

async function loadFleetObjects(pool) {
  const { rows } = await pool.query(FLEET_OBJECTS_SQL);
  return rows;
}

/** Group object rows into the `{deviceId: rows}` shape the engine's opts take. */
function groupObjectsByDevice(rows) {
  const out = {};
  for (const o of Array.isArray(rows) ? rows : []) {
    if (!o || !o.device_id) continue;
    if (!out[o.device_id]) out[o.device_id] = [];
    out[o.device_id].push(o);
  }
  return out;
}

/**
 * ⛔ The object catalogue is loaded in its OWN try, so its failure degrades the
 * answer instead of destroying it. Returns `{rows, read, count, error}` with
 * `count: null` — never 0 — when the read failed.
 */
async function loadObjectsTolerantly(load) {
  try {
    const rows = await load();
    const list = Array.isArray(rows) ? rows : [];
    return { rows: list, read: true, count: list.length, error: null };
  } catch (err) {
    return { rows: [], read: false, count: null, error: messageOf(err) };
  }
}

/**
 * One firewall's consolidation candidates.
 *
 * @param {object} pool      pg pool — a PARAMETER, never instantiated here.
 * @param {string} deviceId
 * @returns {Promise<object>} see the header for the ok/groups contract.
 */
async function getDeviceConsolidation(pool, deviceId) {
  // Started before the rules so the two round trips overlap; awaited after, so
  // a rules failure still reports the catalogue state it did manage to read.
  const objectsPromise = loadObjectsTolerantly(() => loadDeviceObjects(pool, deviceId));

  let deviceRow = null;
  let ruleRows = null;
  try {
    const [deviceResult, rules] = await Promise.all([
      pool.query(DEVICE_SQL, [deviceId]),
      loadDeviceRules(pool, deviceId),
    ]);
    deviceRow = (deviceResult && deviceResult.rows && deviceResult.rows[0]) || null;
    ruleRows = rules;
  } catch (err) {
    const objects = await objectsPromise;
    // ⛔ groups AND summary are null, not [] and not a zeroed summary. A caller
    // that renders either without checking `ok` would be publishing a
    // measurement nobody took.
    return {
      ok: false,
      error: messageOf(err),
      deviceId,
      deviceName: null,
      groups: null,
      summary: null,
      claim: MERGE_CLAIM,
      coverage: {
        rulesCollected: null,
        lastRulesCollectedAt: null,
        ruleCount: null,
        enabledRuleCount: null,
        disabledRuleCount: null,
        rulesWithoutSequence: null,
        groupableRuleCount: null,
        objectCount: objects.count,
        objectCoverage: objectCoverageState({ read: objects.read, count: objects.count }),
        objectError: objects.error,
      },
    };
  }

  const objects = await objectsPromise;
  const groups = findConsolidationGroups(ruleRows, { objects: objects.rows });
  const counts = ruleCoverage(ruleRows);

  return {
    ok: true,
    error: null,
    deviceId,
    deviceName: deviceRow ? deviceRow.name : null,
    groups,
    summary: summariseConsolidation(groups),
    claim: MERGE_CLAIM,
    coverage: {
      // ⛔ The TIMESTAMP decides this, not the row count. `last_rules_collected_at`
      // is stamped only when getRules() succeeded, so it is the one field that
      // separates "collected, and there are none to merge" from "never read".
      rulesCollected: Boolean(deviceRow && deviceRow.last_rules_collected_at)
        || counts.ruleCount > 0,
      lastRulesCollectedAt: deviceRow ? deviceRow.last_rules_collected_at || null : null,
      ...counts,
      objectCount: objects.count,
      objectCoverage: objectCoverageState({ read: objects.read, count: objects.count }),
      objectError: objects.error,
    },
  };
}

/**
 * The whole active fleet, in one pass.
 *
 * ⛔ `objectsByDeviceId`, never the `objects` shorthand. That shorthand applies
 * only when every rule belongs to one device; handing one firewall's catalogue
 * to another's rules resolves a name that device never defined, which is an
 * address invented for a firewall that does not have it — deciding a firewall
 * change on a fabricated measurement.
 */
async function getFleetConsolidation(pool) {
  const objectsPromise = loadObjectsTolerantly(() => loadFleetObjects(pool));

  let deviceRows = [];
  let ruleRows = null;
  try {
    const [devices, rules] = await Promise.all([
      pool.query(FLEET_DEVICES_SQL),
      loadFleetRules(pool),
    ]);
    deviceRows = (devices && devices.rows) || [];
    ruleRows = rules;
  } catch (err) {
    const objects = await objectsPromise;
    return {
      ok: false,
      error: messageOf(err),
      groups: null,
      summary: null,
      byDevice: null,
      claim: MERGE_CLAIM,
      coverage: {
        activeDeviceCount: null,
        devicesWithoutRules: null,
        ruleCount: null,
        enabledRuleCount: null,
        disabledRuleCount: null,
        rulesWithoutSequence: null,
        groupableRuleCount: null,
        objectCount: objects.count,
        objectCoverage: objectCoverageState({ read: objects.read, count: objects.count }),
        objectError: objects.error,
      },
    };
  }

  const objects = await objectsPromise;
  const byDeviceId = groupObjectsByDevice(objects.rows);
  const groups = findConsolidationGroups(ruleRows, { objectsByDeviceId: byDeviceId });
  const counts = ruleCoverage(ruleRows);

  const rulesPerDevice = new Map();
  for (const r of ruleRows) {
    rulesPerDevice.set(r.device_id, (rulesPerDevice.get(r.device_id) || 0) + 1);
  }

  // ⛔ ONE ROW PER ACTIVE DEVICE, including the ones with no groups and the
  // ones with no rules. A device that drops out of the list because it produced
  // nothing reads as a firewall with nothing to do.
  const byDevice = deviceRows.map((d) => {
    const mine = groups.filter((g) => g.deviceId === d.id);
    return {
      deviceId: d.id,
      deviceName: d.name,
      vendor: d.vendor,
      ruleCount: rulesPerDevice.get(d.id) || 0,
      rulesCollected: Boolean(d.last_rules_collected_at) || (rulesPerDevice.get(d.id) || 0) > 0,
      objectCount: Array.isArray(byDeviceId[d.id]) ? byDeviceId[d.id].length : 0,
      summary: summariseConsolidation(mine),
    };
  });

  return {
    ok: true,
    error: null,
    groups,
    summary: summariseConsolidation(groups),
    byDevice,
    claim: MERGE_CLAIM,
    coverage: {
      activeDeviceCount: deviceRows.length,
      devicesWithoutRules: deviceRows
        .filter((d) => !rulesPerDevice.has(d.id))
        .map((d) => d.name || d.id),
      ...counts,
      objectCount: objects.count,
      objectCoverage: objectCoverageState({ read: objects.read, count: objects.count }),
      objectError: objects.error,
    },
  };
}

module.exports = {
  getDeviceConsolidation,
  getFleetConsolidation,
  loadDeviceRules,
  loadDeviceObjects,
  loadFleetRules,
  loadFleetObjects,
  groupObjectsByDevice,
  objectCoverageState,
  ruleCoverage,
  OBJECT_COVERAGE,
  RULE_COLUMNS,
  RULES_SQL,
  FLEET_RULES_SQL,
  OBJECTS_SQL,
  FLEET_OBJECTS_SQL,
  DEVICE_SQL,
  FLEET_DEVICES_SQL,
  // Re-exported so a caller never has to reach past this module for the one
  // claim the engine makes — and never restates it in its own words.
  MERGE_CLAIM,
  VERDICTS,
};
