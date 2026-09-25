'use strict';
// tests/ruleConsolidationData.test.js
//
// Pins lib/engines/ruleConsolidationData.js — the PLUMBING half of rule
// consolidation. lib/engines/ruleConsolidation.js (the judgement) is pinned
// separately by tests/ruleConsolidation.test.js and is not re-tested here.
//
// ⛔ THE CENTRE OF THIS FILE IS "WE COULD NOT MEASURE THIS", per tests/README.md.
// Three separate failures all end as an empty-looking screen on a CLEANUP tab,
// and each one, rendered as the honest answer, tells an operator their rulebase
// is already tidy:
//
//   1. the rules query THREW          -> ok:false, groups NULL (never [])
//   2. the ruleset was never collected -> coverage.rulesCollected false
//   3. the object catalogue is missing -> objectCoverage, and count NULL not 0
//
// The third is the subtle one: an unresolved object name falls CLOSED in the
// engine, so a missing catalogue cannot manufacture an ordering-checked
// verdict — it can only make the review pile look like a POLICY problem when it
// is really a COLLECTION one. Three live firewalls carry zero network_objects
// rows, so that is the common case, not a corner.
//
// ⛔ NO DATABASE. Every test hands a stub that RECORDS the statements and params
// it was given and returns canned rows — the convention configRetention.test.js
// established and upgradePlanData.test.js follows. SQL assertions match a
// meaningful FRAGMENT, never a whole string, so a reformat is a one-line update
// while a removed guarantee still fails loudly.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  getDeviceConsolidation,
  getFleetConsolidation,
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
  MERGE_CLAIM,
  VERDICTS,
} = require('../lib/engines/ruleConsolidationData');

const ENGINE = require('../lib/engines/ruleConsolidation');

// --------------------------------------------------------------------------
// Stub pool
// --------------------------------------------------------------------------

function classify(sql) {
  const s = String(sql);
  if (/FROM\s+network_objects/i.test(s)) return 'objects';
  if (/FROM\s+firewall_rules/i.test(s)) return 'rules';
  if (/d\.id\s*=\s*\$1/.test(s)) return 'device';
  return 'devices';
}

/**
 * @param {object} rowsFor  {device, devices, rules, objects} -> canned rows
 * @param {string[]} [fail] kinds whose query THROWS
 */
function stubPool(rowsFor, fail = []) {
  const calls = [];
  const failures = new Set(fail);
  return {
    calls,
    kinds: () => calls.map((c) => c.kind),
    async query(sql, params) {
      const kind = classify(sql);
      calls.push({ kind, sql: String(sql), params });
      if (failures.has(kind)) throw new Error(`stub failure: ${kind}`);
      const rows = (rowsFor[kind] || []).map((r) => ({ ...r }));
      return { rows, rowCount: rows.length };
    },
  };
}

// --------------------------------------------------------------------------
// Fixtures — two rules identical except in destination, one rule between them.
// --------------------------------------------------------------------------

const DEV = 'dev-1';

function rule(over = {}) {
  return {
    id: `r-${over.sequence_number || 0}`,
    device_id: DEV,
    rule_name: `rule-${over.sequence_number || 0}`,
    rule_id_vendor: String(over.sequence_number || 0),
    sequence_number: 1,
    enabled: true,
    action: 'allow',
    src_zones: ['trust'],
    dst_zones: ['untrust'],
    src_addresses: ['10.1.1.0/24'],
    dst_addresses: ['10.2.2.0/24'],
    services: ['tcp/443'],
    applications: null,
    schedule: null,
    expiry_date: null,
    log_enabled: true,
    nat_enabled: false,
    comment: null,
    tags: null,
    hit_count: null,
    raw_rule: null,
    vdom: null,
    ...over,
  };
}

// A group of two (positions 1 and 3) differing only in destination, with one
// enabled rule at position 2 between them. Whether that rule interferes depends
// entirely on what `GRP` resolves to — which is the whole point of the object
// catalogue being a coverage fact rather than an optional extra.
function threeRules() {
  return [
    rule({ sequence_number: 1, dst_addresses: ['10.2.2.0/24'] }),
    rule({
      sequence_number: 2,
      rule_name: 'between',
      action: 'deny',
      dst_addresses: ['GRP'],
    }),
    rule({ sequence_number: 3, dst_addresses: ['10.3.3.0/24'] }),
  ];
}

const DEVICE_ROW = {
  id: DEV,
  name: 'edge-fw-01',
  vendor: 'paloalto',
  active: true,
  last_rules_collected_at: '2026-09-25T02:00:00.000Z',
};

// GRP resolves somewhere neither member touches, so the intervening rule is
// provably disjoint and the group clears.
const DISJOINT_OBJECT = {
  id: 'o-1',
  device_id: DEV,
  object_type: 'address',
  name: 'GRP',
  value: '192.168.99.0/24',
  members: null,
};

// ══════════════════════════════════════════════════════════════════════════
// 1. ⛔ A FAILED READ AND AN EMPTY RESULT MUST NOT LOOK ALIKE
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ a failed read is reported, never rendered as "nothing to consolidate"', () => {
  it('a throwing rules query returns ok:false with groups NULL — not an empty array', async () => {
    const pool = stubPool({ device: [DEVICE_ROW], objects: [] }, ['rules']);
    const r = await getDeviceConsolidation(pool, DEV);

    assert.equal(r.ok, false);
    // ⛔ strictly null. `[]` here is a CLAIM — "this firewall has no candidates" —
    // and a caller that forgot to check `ok` would publish it as one.
    assert.strictEqual(r.groups, null, 'groups must be null on a failed read, never []');
    assert.strictEqual(r.summary, null, 'a zeroed summary is a measurement nobody took');
    assert.notDeepEqual(r.groups, []);
    assert.match(r.error, /stub failure/);
  });

  it('a throwing DEVICE query fails the whole answer too', async () => {
    const pool = stubPool({ rules: threeRules(), objects: [] }, ['device']);
    const r = await getDeviceConsolidation(pool, DEV);
    assert.equal(r.ok, false);
    assert.strictEqual(r.groups, null);
  });

  it('every coverage counter is NULL on a failed read, never 0', async () => {
    const pool = stubPool({ device: [DEVICE_ROW], objects: [] }, ['rules']);
    const { coverage } = await getDeviceConsolidation(pool, DEV);
    for (const key of [
      'rulesCollected',
      'ruleCount',
      'enabledRuleCount',
      'disabledRuleCount',
      'rulesWithoutSequence',
      'groupableRuleCount',
    ]) {
      assert.strictEqual(coverage[key], null, `${key} must be null, not 0/false, on a failed read`);
    }
  });

  it('a genuinely empty firewall is ok:true with an EMPTY ARRAY and a real summary', async () => {
    const pool = stubPool({ device: [DEVICE_ROW], rules: [], objects: [] });
    const r = await getDeviceConsolidation(pool, DEV);

    assert.equal(r.ok, true);
    assert.deepEqual(r.groups, []);
    assert.equal(r.summary.groups, 0);
    assert.equal(r.summary.removableRows, 0);
    assert.equal(r.error, null);
  });

  it('the two states are distinguishable by `ok` alone — the field a renderer must branch on', async () => {
    const failed = await getDeviceConsolidation(
      stubPool({ device: [DEVICE_ROW], objects: [] }, ['rules']),
      DEV
    );
    const empty = await getDeviceConsolidation(
      stubPool({ device: [DEVICE_ROW], rules: [], objects: [] }),
      DEV
    );
    assert.notEqual(failed.ok, empty.ok);
    assert.notEqual(Array.isArray(failed.groups), Array.isArray(empty.groups));
  });

  it('the fleet read fails the same way', async () => {
    const r = await getFleetConsolidation(stubPool({ objects: [] }, ['rules']));
    assert.equal(r.ok, false);
    assert.strictEqual(r.groups, null);
    assert.strictEqual(r.summary, null);
    assert.strictEqual(r.byDevice, null);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 2. ⛔ "NEVER COLLECTED" IS A THIRD STATE
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ a firewall with no collected ruleset is not a firewall with nothing to merge', () => {
  it('no rows AND no last_rules_collected_at means the ruleset was never read', async () => {
    const pool = stubPool({
      device: [{ ...DEVICE_ROW, last_rules_collected_at: null }],
      rules: [],
      objects: [],
    });
    const r = await getDeviceConsolidation(pool, DEV);
    assert.equal(r.ok, true);
    assert.equal(r.coverage.rulesCollected, false);
  });

  it('⛔ the TIMESTAMP decides it, not the row count — a collected, empty rulebase is collected', async () => {
    // last_rules_collected_at is stamped only when getRules() succeeded, which
    // is the one field that separates the two.
    const pool = stubPool({ device: [DEVICE_ROW], rules: [], objects: [] });
    const r = await getDeviceConsolidation(pool, DEV);
    assert.equal(r.coverage.rulesCollected, true);
    assert.equal(r.coverage.ruleCount, 0);
  });

  it('rows present with no timestamp still counts as collected', async () => {
    const pool = stubPool({
      device: [{ ...DEVICE_ROW, last_rules_collected_at: null }],
      rules: threeRules(),
      objects: [],
    });
    const r = await getDeviceConsolidation(pool, DEV);
    assert.equal(r.coverage.rulesCollected, true);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 3. ⛔ THE OBJECT CATALOGUE IS A COVERAGE FACT
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ the object catalogue has THREE states and a failed read is not an empty one', () => {
  it('objectCoverageState never confuses a null count with a zero one', () => {
    assert.equal(objectCoverageState({ read: true, count: 7 }), OBJECT_COVERAGE.AVAILABLE);
    assert.equal(objectCoverageState({ read: true, count: 0 }), OBJECT_COVERAGE.NONE);
    // ⛔ null is "we do not know what this firewall defines", 0 is "it defines
    // nothing". Collapsing them hides a read failure inside a real answer.
    assert.equal(objectCoverageState({ read: true, count: null }), OBJECT_COVERAGE.UNREADABLE);
    assert.equal(objectCoverageState({ read: false, count: null }), OBJECT_COVERAGE.UNREADABLE);
    assert.equal(objectCoverageState({ read: false, count: 12 }), OBJECT_COVERAGE.UNREADABLE);
    assert.equal(objectCoverageState({}), OBJECT_COVERAGE.UNREADABLE);
  });

  it('a failing object query DEGRADES the answer — it does not destroy it', async () => {
    const pool = stubPool({ device: [DEVICE_ROW], rules: threeRules() }, ['objects']);
    const r = await getDeviceConsolidation(pool, DEV);

    assert.equal(r.ok, true, 'the rules were read; the answer still stands');
    assert.ok(Array.isArray(r.groups));
    assert.equal(r.coverage.objectCoverage, OBJECT_COVERAGE.UNREADABLE);
    // ⛔ null, never 0 — 0 would read as "this firewall defines no objects".
    assert.strictEqual(r.coverage.objectCount, null);
    assert.match(r.coverage.objectError, /stub failure/);
  });

  it('the catalogue state is still reported when the RULES read failed', async () => {
    const pool = stubPool({ device: [DEVICE_ROW], objects: [DISJOINT_OBJECT] }, ['rules']);
    const r = await getDeviceConsolidation(pool, DEV);
    assert.equal(r.ok, false);
    assert.equal(r.coverage.objectCoverage, OBJECT_COVERAGE.AVAILABLE);
  });

  it('an empty catalogue reports `none_collected`, distinct from `unreadable`', async () => {
    const pool = stubPool({ device: [DEVICE_ROW], rules: threeRules(), objects: [] });
    const r = await getDeviceConsolidation(pool, DEV);
    assert.equal(r.coverage.objectCoverage, OBJECT_COVERAGE.NONE);
    assert.strictEqual(r.coverage.objectCount, 0);
    assert.equal(r.coverage.objectError, null);
  });

  it('⛔ a missing catalogue can only make a verdict MORE conservative, never less', async () => {
    const withObjects = await getDeviceConsolidation(
      stubPool({ device: [DEVICE_ROW], rules: threeRules(), objects: [DISJOINT_OBJECT] }),
      DEV
    );
    const without = await getDeviceConsolidation(
      stubPool({ device: [DEVICE_ROW], rules: threeRules(), objects: [] }),
      DEV
    );

    assert.equal(withObjects.groups.length, 1, 'fixture should produce exactly one group');
    assert.equal(withObjects.groups[0].verdict, VERDICTS.SAFE);
    assert.equal(without.groups.length, 1);
    assert.equal(
      without.groups[0].verdict,
      VERDICTS.REVIEW,
      'an unresolvable object name must fall CLOSED, not open'
    );
    assert.ok(without.groups[0].undetermined.length > 0, 'and it must say why');
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 4. ⛔ THE COLUMNS THE ENGINE KEYS ON
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ every column the engine keys on is actually selected', () => {
  it('RULE_COLUMNS covers every SET_FIELD, SCALAR_FIELD and identity field', () => {
    for (const f of [...ENGINE.SET_FIELDS, ...ENGINE.SCALAR_FIELDS]) {
      assert.ok(RULE_COLUMNS.includes(f), `${f} is keyed on but not in RULE_COLUMNS`);
    }
    for (const f of ['id', 'device_id', 'vdom', 'sequence_number', 'enabled']) {
      assert.ok(RULE_COLUMNS.includes(f), `${f} missing from RULE_COLUMNS`);
    }
  });

  it('both rule statements select every one of them', () => {
    for (const col of RULE_COLUMNS) {
      assert.match(RULES_SQL, new RegExp(`\\bfr\\.${col}\\b`), `RULES_SQL drops ${col}`);
      assert.match(FLEET_RULES_SQL, new RegExp(`\\bfr\\.${col}\\b`), `FLEET_RULES_SQL drops ${col}`);
    }
  });

  it('⛔ raw_rule is selected — it is the ONLY input to the negation guard', () => {
    // hasNegationMarker() reads raw_rule and nothing else. Drop the column and
    // that guard cannot fire, and a "these never overlap" conclusion computed
    // from a NEGATED field is exactly backwards.
    assert.ok(RULE_COLUMNS.includes('raw_rule'));
    assert.match(RULES_SQL, /fr\.raw_rule/);
    assert.match(FLEET_RULES_SQL, /fr\.raw_rule/);
  });

  it('⛔ a dropped column does not crash — it silently merges rules that differ', () => {
    // Stated as a behaviour so the reason for the assertions above is testable
    // rather than only documented: two rules differing ONLY in log_enabled are
    // not one rule, and a SELECT without that column makes them look like one.
    const differing = [
      rule({ sequence_number: 1, dst_addresses: ['10.2.2.0/24'], log_enabled: true }),
      rule({ sequence_number: 2, dst_addresses: ['10.3.3.0/24'], log_enabled: false }),
    ];
    assert.equal(ENGINE.findConsolidationGroups(differing).length, 0);

    const stripped = differing.map(({ log_enabled: _drop, ...rest }) => rest);
    assert.equal(
      ENGINE.findConsolidationGroups(stripped).length,
      1,
      'without the column the engine cannot tell them apart — hence the SELECT test above'
    );
  });

  it('the object statements select value AND members', () => {
    for (const sql of [OBJECTS_SQL, FLEET_OBJECTS_SQL]) {
      assert.match(sql, /no\.object_type/);
      assert.match(sql, /no\.name/);
      assert.match(sql, /no\.value/);
      // Without `members` every address_group resolves to nothing, which is
      // indistinguishable from a catalogue that was never collected.
      assert.match(sql, /no\.members/);
    }
  });

  it('rules are ordered with NULLS LAST', () => {
    assert.match(RULES_SQL, /ORDER BY[\s\S]*NULLS LAST/i);
    assert.match(FLEET_RULES_SQL, /ORDER BY[\s\S]*NULLS LAST/i);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 5. ⛔ PARAMETERISED QUERIES ONLY
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ no value is ever interpolated into SQL', () => {
  it('not one exported statement carries a template placeholder', () => {
    for (const [name, sql] of Object.entries({
      RULES_SQL,
      FLEET_RULES_SQL,
      OBJECTS_SQL,
      FLEET_OBJECTS_SQL,
      DEVICE_SQL,
      FLEET_DEVICES_SQL,
    })) {
      assert.equal(/\$\{/.test(sql), false, `${name} interpolates a value into SQL`);
    }
  });

  it('every per-device statement is handed its id as a parameter', async () => {
    const pool = stubPool({ device: [DEVICE_ROW], rules: threeRules(), objects: [] });
    await getDeviceConsolidation(pool, DEV);
    const scoped = pool.calls.filter((c) => /\$1/.test(c.sql));
    assert.ok(scoped.length >= 3, 'expected the device, rules and objects reads to be scoped');
    for (const c of scoped) assert.deepEqual(c.params, [DEV]);
  });

  it('the fleet statements take no parameters and filter on d.active', async () => {
    await getFleetConsolidation(stubPool({ devices: [], rules: [], objects: [] }));
    for (const sql of [FLEET_RULES_SQL, FLEET_OBJECTS_SQL, FLEET_DEVICES_SQL]) {
      assert.equal(/\$1/.test(sql), false);
      assert.match(sql, /d\.active\s*=\s*true/);
    }
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 6. Coverage counters
// ══════════════════════════════════════════════════════════════════════════

describe('rule coverage counters', () => {
  it('counts enabled, disabled and unplaceable rules apart', () => {
    const rows = [
      rule({ sequence_number: 1 }),
      rule({ sequence_number: 2, enabled: false }),
      rule({ sequence_number: null, id: 'r-x' }),
    ];
    const c = ruleCoverage(rows);
    assert.equal(c.ruleCount, 3);
    assert.equal(c.enabledRuleCount, 2);
    assert.equal(c.disabledRuleCount, 1);
    assert.equal(c.rulesWithoutSequence, 1);
    assert.equal(c.groupableRuleCount, 1);
  });

  it('⛔ an enabled rule with NO position is counted, because the engine silently drops it', async () => {
    // findConsolidationGroups excludes it from grouping — correctly, no merge
    // involving it could be checked — and an exclusion nobody counts turns a
    // partial candidate set into one that looks complete.
    const rows = [...threeRules(), rule({ id: 'r-nopos', sequence_number: null })];
    const pool = stubPool({ device: [DEVICE_ROW], rules: rows, objects: [DISJOINT_OBJECT] });
    const r = await getDeviceConsolidation(pool, DEV);
    assert.equal(r.coverage.rulesWithoutSequence, 1);
    assert.equal(r.coverage.groupableRuleCount, 3);
  });

  it('a non-array is 0 everywhere rather than a crash', () => {
    const c = ruleCoverage(null);
    assert.equal(c.ruleCount, 0);
    assert.equal(c.groupableRuleCount, 0);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 7. ⛔ ONE FIREWALL'S OBJECTS MAY NEVER RESOLVE ANOTHER'S RULES
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ the fleet read keys objects per device', () => {
  it('a name defined on one firewall does not resolve on another', async () => {
    const other = 'dev-2';
    const rulesA = threeRules();
    const rulesB = threeRules().map((r) => ({
      ...r,
      id: `b-${r.sequence_number}`,
      device_id: other,
    }));

    const r = await getFleetConsolidation(
      stubPool({
        devices: [
          { id: DEV, name: 'has-catalogue', vendor: 'paloalto', last_rules_collected_at: 'x' },
          { id: other, name: 'no-catalogue', vendor: 'paloalto', last_rules_collected_at: 'x' },
        ],
        rules: [...rulesA, ...rulesB],
        // GRP exists ONLY on dev-1.
        objects: [DISJOINT_OBJECT],
      })
    );

    assert.equal(r.ok, true);
    const a = r.groups.filter((g) => g.deviceId === DEV);
    const b = r.groups.filter((g) => g.deviceId === other);
    assert.equal(a.length, 1);
    assert.equal(b.length, 1);
    assert.equal(a[0].verdict, VERDICTS.SAFE, 'dev-1 defines GRP and its group clears');
    assert.equal(
      b[0].verdict,
      VERDICTS.REVIEW,
      'dev-2 does not define GRP; borrowing dev-1 catalogue would invent an address it has not got'
    );
  });

  it('groupObjectsByDevice buckets by device_id and drops nothing else', () => {
    const grouped = groupObjectsByDevice([
      { device_id: 'a', name: 'x' },
      { device_id: 'b', name: 'y' },
      { device_id: 'a', name: 'z' },
      null,
      { name: 'orphan' },
    ]);
    assert.equal(grouped.a.length, 2);
    assert.equal(grouped.b.length, 1);
    assert.equal(Object.keys(grouped).length, 2);
  });

  it('⛔ every ACTIVE device appears in byDevice, including one with no rules at all', async () => {
    const r = await getFleetConsolidation(
      stubPool({
        devices: [
          { id: DEV, name: 'busy', vendor: 'paloalto', last_rules_collected_at: 'x' },
          { id: 'quiet', name: 'never-collected', vendor: 'fortinet', last_rules_collected_at: null },
        ],
        rules: threeRules(),
        objects: [DISJOINT_OBJECT],
      })
    );
    assert.equal(r.byDevice.length, 2);
    const quiet = r.byDevice.find((d) => d.deviceName === 'never-collected');
    // A device that dropped out of the list because it produced nothing would
    // read as a firewall with nothing to do.
    assert.ok(quiet, 'a device with no rules must still appear');
    assert.equal(quiet.rulesCollected, false);
    assert.equal(quiet.summary.groups, 0);
    assert.deepEqual(r.coverage.devicesWithoutRules, ['never-collected']);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 8. The claim travels with the data
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ the one claim is re-exported, never restated', () => {
  it('MERGE_CLAIM is the engine constant, byte for byte', () => {
    assert.equal(MERGE_CLAIM, ENGINE.MERGE_CLAIM);
    assert.match(MERGE_CLAIM, /proposal/i);
  });

  it('it rides on every successful result, and on every failed one', async () => {
    const ok = await getDeviceConsolidation(
      stubPool({ device: [DEVICE_ROW], rules: [], objects: [] }),
      DEV
    );
    const bad = await getDeviceConsolidation(
      stubPool({ device: [DEVICE_ROW], objects: [] }, ['rules']),
      DEV
    );
    assert.equal(ok.claim, ENGINE.MERGE_CLAIM);
    assert.equal(bad.claim, ENGINE.MERGE_CLAIM);
  });

  it('VERDICTS is re-exported unchanged, so a caller never spells a slug itself', () => {
    assert.deepEqual(VERDICTS, ENGINE.VERDICTS);
  });
});
