// tests/objectUsage.test.js
//
// Pins lib/engines/objectUsage.js.
//
// This engine's output is a LIST OF OBJECTS TO DELETE, which makes every
// false 'unused' finding actively dangerous — not merely noisy. Two classes
// of bug live here and both are pinned below:
//
//   1. A REFERENCE SURFACE THE ENGINE CANNOT SEE. Until 2026-09-25 the engine
//      took firewall_rules as its only surface and never looked at nat_rules.
//      Measured on the live fleet: 11 objects across 6 Palo Altos were
//      reported unused while a NAT rule actually referenced them.
//   2. A FAILED READ RECORDED AS A FACT. "We could not read nat_rules"
//      collapsing into "NAT references nothing" produces a LONGER delete
//      list, confidently. Per tests/README.md, the "we could not measure
//      this" case is the one that regresses silently, so it gets its own
//      section (D) and is asserted from both the pure function and the
//      pool-taking wrapper.
//
// Plus the 2026-07-18 namespace-partitioning fix, which NAT re-opens: NAT has
// four address columns and two service columns, and merging them would
// recreate that bug one table over.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  analyzeObjectUsage,
  runObjectUsageAnalysisForDevice,
  NAT_ADDRESS_FIELDS,
  NAT_SERVICE_FIELDS,
} = require('../lib/engines/objectUsage');

// --------------------------------------------------------------------------
// Fixtures + helpers
// --------------------------------------------------------------------------

const addr = (id, name, value = null) => ({ id, object_type: 'address', name, value, members: null });
const addrGroup = (id, name, members) => ({ id, object_type: 'address_group', name, value: null, members });
const svc = (id, name, value = null) => ({ id, object_type: 'service', name, value, members: null });
const svcGroup = (id, name, members) => ({ id, object_type: 'service_group', name, value: null, members });

// A nat_rules row as the DB hands it back: every name-bearing column present,
// null unless the test sets it (a source-NAT rule really does carry a null
// translated_dst_addresses on the live fleet).
function natRow(overrides = {}) {
  return {
    original_src_addresses: null,
    original_dst_addresses: null,
    original_services: null,
    translated_src_addresses: null,
    translated_dst_addresses: null,
    translated_services: null,
    ...overrides,
  };
}

const rule = (overrides = {}) => ({ src_addresses: null, dst_addresses: null, services: null, ...overrides });

const unusedIds = (findings) =>
  findings.filter((f) => f.finding_type === 'unused').map((f) => f.object_id).sort();

const isUnused = (findings, id) => findings.some((f) => f.finding_type === 'unused' && f.object_id === id);

// Stub pool. Records every {sql, params} handed to query(), on the pool AND
// on any client taken from connect(). `handler(sql, params)` may return a
// result object, or an Error instance meaning "reject with this".
function stubPool(handler) {
  const calls = [];
  const released = [];
  const run = (sql, params) => {
    calls.push({ sql: String(sql), params });
    const result = handler ? handler(String(sql), params) : undefined;
    if (result instanceof Error) return Promise.reject(result);
    return Promise.resolve(result === undefined ? { rows: [], rowCount: 0 } : result);
  };
  return {
    calls,
    released,
    connectCount: 0,
    query: run,
    connect() {
      this.connectCount += 1;
      return Promise.resolve({
        query: run,
        release: () => released.push(true),
      });
    },
  };
}

const sqlFor = (pool, table) =>
  pool.calls.filter((c) => new RegExp(`\\b${table}\\b`, 'i').test(c.sql));

// --------------------------------------------------------------------------
// A. nat_rules is a reference surface — all six columns
// --------------------------------------------------------------------------

describe('objectUsage: nat_rules is a reference surface', () => {
  it('an object referenced by nothing at all is still reported unused (baseline)', () => {
    const objects = [addr('o1', 'srv-web')];
    const findings = analyzeObjectUsage(objects, [], []);
    assert.deepEqual(unusedIds(findings), ['o1']);
  });

  for (const field of NAT_ADDRESS_FIELDS) {
    it(`an address object named ONLY in nat_rules.${field} is not unused`, () => {
      const objects = [addr('o1', 'srv-web', '10.1.1.5/32'), addr('o2', 'orphan', '10.9.9.9/32')];
      const natRules = [natRow({ [field]: ['srv-web'] })];
      const findings = analyzeObjectUsage(objects, [], natRules);
      assert.equal(isUnused(findings, 'o1'), false, `${field} did not count as a reference`);
      // The control: the untouched object must STILL be reported, otherwise
      // the test would pass on an engine that simply stopped reporting.
      assert.equal(isUnused(findings, 'o2'), true);
    });
  }

  for (const field of NAT_SERVICE_FIELDS) {
    it(`a service object named ONLY in nat_rules.${field} is not unused`, () => {
      const objects = [svc('s1', 'tcp-8443', 'tcp/8443'), svc('s2', 'orphan-svc', 'tcp/1')];
      const natRules = [natRow({ [field]: ['tcp-8443'] })];
      const findings = analyzeObjectUsage(objects, [], natRules);
      assert.equal(isUnused(findings, 's1'), false, `${field} did not count as a reference`);
      assert.equal(isUnused(findings, 's2'), true);
    });
  }

  it('an object used ONLY as a translation target is in use — the post-NAT side counts', () => {
    // The tempting half-fix is to read only the `original_*` columns, on the
    // reasoning that they are what traffic is "matched" against. An object
    // that exists solely as the translated address is exactly as load-bearing:
    // delete it and the translation breaks.
    const objects = [addr('o1', 'inside-web-server', '10.248.32.9/32')];
    const natRules = [
      natRow({ original_dst_addresses: ['147.50.33.118'], translated_dst_addresses: ['inside-web-server'] }),
    ];
    assert.deepEqual(unusedIds(analyzeObjectUsage(objects, [], natRules)), []);
  });

  it('a DISABLED NAT rule still counts as a reference', () => {
    // Same treatment firewall rules have always had (the engine never filters
    // on `enabled`): the object is still named in the running config, and
    // ignoring disabled rules could only ever LENGTHEN the delete list.
    const objects = [addr('o1', 'srv-web')];
    const natRules = [natRow({ enabled: false, original_src_addresses: ['srv-web'] })];
    assert.deepEqual(unusedIds(analyzeObjectUsage(objects, [], natRules)), []);
  });

  it('null / absent / non-array NAT columns contribute nothing and do not throw', () => {
    const objects = [addr('o1', 'srv-web')];
    const natRules = [
      natRow(),
      {}, // a row with no name columns at all
      natRow({ original_src_addresses: 'srv-web' }), // a string, not an array: not a reference
      natRow({ original_dst_addresses: [null, undefined] }),
    ];
    assert.deepEqual(unusedIds(analyzeObjectUsage(objects, [], natRules)), ['o1']);
  });

  it('a null or non-object NAT row is skipped rather than crashing the analysis', () => {
    const objects = [addr('o1', 'srv-web')];
    const natRules = [null, undefined, 42, natRow({ original_src_addresses: ['srv-web'] })];
    assert.deepEqual(unusedIds(analyzeObjectUsage(objects, [], natRules)), []);
  });

  it('NAT names are matched case- and whitespace-insensitively, as rule names already are', () => {
    const objects = [addr('o1', 'SRV-Web')];
    const natRules = [natRow({ translated_src_addresses: ['  srv-web  '] })];
    assert.deepEqual(unusedIds(analyzeObjectUsage(objects, [], natRules)), []);
  });

  it('a NAT literal that matches no collected object marks nothing used', () => {
    // Live fleet: NAT rows routinely carry bare public IPs ("147.50.33.118")
    // rather than object names. Those must not accidentally credit anything.
    const objects = [addr('o1', 'srv-web')];
    const natRules = [natRow({ original_dst_addresses: ['147.50.33.118'], translated_dst_addresses: ['10.248.32.9'] })];
    assert.deepEqual(unusedIds(analyzeObjectUsage(objects, [], natRules)), ['o1']);
  });

  it('rules and NAT are ADDITIVE surfaces — neither replaces the other', () => {
    const objects = [addr('o1', 'by-rule'), addr('o2', 'by-nat'), addr('o3', 'by-neither')];
    const findings = analyzeObjectUsage(
      objects,
      [rule({ src_addresses: ['by-rule'] })],
      [natRow({ translated_dst_addresses: ['by-nat'] })]
    );
    assert.deepEqual(unusedIds(findings), ['o3']);
  });
});

// --------------------------------------------------------------------------
// B. Namespace partitioning across NAT — the 2026-07-18 bug must not return
// --------------------------------------------------------------------------

describe('objectUsage: address and service namespaces stay separate across NAT fields', () => {
  it('a NAT SERVICE field naming "dns" does not credit an address object named "DNS"', () => {
    const objects = [addr('a1', 'DNS', '8.8.8.8/32'), svc('s1', 'dns', 'udp/53')];
    const findings = analyzeObjectUsage(objects, [], [natRow({ original_services: ['dns'] })]);
    assert.equal(isUnused(findings, 's1'), false, 'the service named by the NAT service field should be in use');
    assert.equal(
      isUnused(findings, 'a1'),
      true,
      'the address object named "DNS" is genuinely unreferenced — crediting it would suppress a real finding'
    );
  });

  it('a NAT ADDRESS field naming "dns" does not credit a service object named "dns"', () => {
    const objects = [addr('a1', 'DNS', '8.8.8.8/32'), svc('s1', 'dns', 'udp/53')];
    const findings = analyzeObjectUsage(objects, [], [natRow({ translated_dst_addresses: ['DNS'] })]);
    assert.equal(isUnused(findings, 'a1'), false);
    assert.equal(isUnused(findings, 's1'), true);
  });

  it('every NAT address column is address-namespace and every NAT service column is service-namespace', () => {
    // Exhaustive over all six columns, both directions, so a future edit that
    // moves one column into the wrong list fails here rather than in the field.
    for (const field of NAT_ADDRESS_FIELDS) {
      const objects = [addr('a1', 'shared'), svc('s1', 'shared')];
      const findings = analyzeObjectUsage(objects, [], [natRow({ [field]: ['shared'] })]);
      assert.equal(isUnused(findings, 'a1'), false, `${field} should feed the address namespace`);
      assert.equal(isUnused(findings, 's1'), true, `${field} must NOT feed the service namespace`);
    }
    for (const field of NAT_SERVICE_FIELDS) {
      const objects = [addr('a1', 'shared'), svc('s1', 'shared')];
      const findings = analyzeObjectUsage(objects, [], [natRow({ [field]: ['shared'] })]);
      assert.equal(isUnused(findings, 's1'), false, `${field} should feed the service namespace`);
      assert.equal(isUnused(findings, 'a1'), true, `${field} must NOT feed the address namespace`);
    }
  });

  it('a NAT address field does not credit an address GROUP that only shares a name with a service group', () => {
    const objects = [
      addrGroup('ag1', 'web', ['a1-member']),
      addr('a1', 'a1-member'),
      svcGroup('sg1', 'web', ['s1-member']),
      svc('s1', 's1-member'),
    ];
    const findings = analyzeObjectUsage(objects, [], [natRow({ original_dst_addresses: ['web'] })]);
    assert.deepEqual(unusedIds(findings), ['s1', 'sg1']);
  });
});

// --------------------------------------------------------------------------
// C. Group closure runs AFTER the NAT seed
// --------------------------------------------------------------------------

describe('objectUsage: NAT-derived names expand transitively through groups', () => {
  it('an address GROUP referenced only by a NAT rule makes its members used', () => {
    const objects = [addrGroup('g1', 'dmz-servers', ['web1', 'web2']), addr('a1', 'web1'), addr('a2', 'web2')];
    const natRules = [natRow({ original_dst_addresses: ['dmz-servers'] })];
    assert.deepEqual(unusedIds(analyzeObjectUsage(objects, [], natRules)), []);
  });

  it('closure through a NAT-referenced group is TRANSITIVE (nested groups, both levels)', () => {
    // Two levels deep proves the seed happens BEFORE the while(changed) walk
    // rather than after it: a seed applied afterwards would credit the outer
    // group only and leave every member on the delete-me list.
    const objects = [
      addrGroup('g1', 'outer', ['inner']),
      addrGroup('g2', 'inner', ['leaf']),
      addr('a1', 'leaf'),
      addr('a2', 'untouched'),
    ];
    const natRules = [natRow({ translated_src_addresses: ['outer'] })];
    assert.deepEqual(unusedIds(analyzeObjectUsage(objects, [], natRules)), ['a2']);
  });

  it('a service GROUP referenced only by a NAT service field makes its members used', () => {
    const objects = [svcGroup('g1', 'web-ports', ['tcp-80', 'tcp-443']), svc('s1', 'tcp-80'), svc('s2', 'tcp-443')];
    const natRules = [natRow({ translated_services: ['web-ports'] })];
    assert.deepEqual(unusedIds(analyzeObjectUsage(objects, [], natRules)), []);
  });

  it('a group cycle between NAT-referenced groups terminates', () => {
    const objects = [addrGroup('g1', 'a', ['b']), addrGroup('g2', 'b', ['a'])];
    assert.deepEqual(unusedIds(analyzeObjectUsage(objects, [], [natRow({ original_src_addresses: ['a'] })])), []);
  });
});

// --------------------------------------------------------------------------
// D. ⛔ A FAILED NAT READ MUST NOT WIDEN THE UNUSED LIST
// --------------------------------------------------------------------------

describe('objectUsage: a failed NAT read never produces a longer unused list', () => {
  const objects = [addr('o1', 'nat-only'), addr('o2', 'genuinely-unused')];
  const natRules = [natRow({ translated_dst_addresses: ['nat-only'] })];

  it('the true answer with NAT read successfully is ONE unused object', () => {
    assert.deepEqual(unusedIds(analyzeObjectUsage(objects, [], natRules)), ['o2']);
  });

  it('the longer list is reachable ONLY by positively asserting there are no NAT rules', () => {
    // `[]` is a claim — "this device has no NAT rules" — and on a device that
    // really has none it is correct, so it legitimately yields the longer list.
    assert.deepEqual(unusedIds(analyzeObjectUsage(objects, [], [])), ['o1', 'o2']);
  });

  for (const [label, value] of [
    ['undefined (the argument was simply not passed)', undefined],
    ['null', null],
    ['false', false],
    ['0', 0],
    ['an empty string', ''],
    ['a query result object rather than its rows', { rows: [] }],
    ['a string', 'no nat rules'],
  ]) {
    it(`throws rather than degrading to "no NAT rules" when natRules is ${label}`, () => {
      assert.throws(
        () => analyzeObjectUsage(objects, [], value),
        /natRules must be an array/,
        'an unreadable NAT result must not be silently treated as an empty one'
      );
    });
  }

  it('no non-array input can ever yield the longer list — it throws or nothing', () => {
    // The property, stated directly: there is no value other than a real
    // array for which this function returns findings at all. A future
    // "tolerant" default (`natRules = []`) breaks this test.
    for (const value of [undefined, null, false, 0, '', {}, 'x', 123, new Set(), { length: 0 }]) {
      let returned = null;
      try {
        returned = analyzeObjectUsage(objects, [], value);
      } catch (err) {
        assert.match(err.message, /natRules must be an array/);
        continue;
      }
      assert.fail(`analyzeObjectUsage accepted ${String(value)} and returned ${JSON.stringify(unusedIds(returned))}`);
    }
  });

  it('the wrapper propagates a failed nat_rules read and writes NOTHING', async () => {
    // The whole point of aborting: object_analysis_results is DELETE+reinsert,
    // so a run that proceeded on a failed NAT read would first DELETE the
    // previous (correct) findings and then insert the wider, wrong list.
    const boom = new Error('connection terminated unexpectedly');
    const pool = stubPool((sql) => {
      if (/FROM network_objects/i.test(sql)) return { rows: [addr('o1', 'nat-only')], rowCount: 1 };
      if (/FROM firewall_rules/i.test(sql)) return { rows: [], rowCount: 0 };
      if (/FROM nat_rules/i.test(sql)) return boom;
      return { rows: [], rowCount: 0 };
    });

    await assert.rejects(() => runObjectUsageAnalysisForDevice('dev-1', pool), /connection terminated/);

    assert.equal(pool.connectCount, 0, 'no transaction should have been opened');
    assert.equal(
      pool.calls.some((c) => /DELETE\s+FROM\s+object_analysis_results/i.test(c.sql)),
      false,
      'the previous pull findings must be left untouched'
    );
    assert.equal(
      pool.calls.some((c) => /INSERT\s+INTO\s+object_analysis_results/i.test(c.sql)),
      false
    );
  });

  it('the wrapper does not swallow the NAT failure into an empty finding set', async () => {
    const pool = stubPool((sql) => {
      if (/FROM network_objects/i.test(sql)) return { rows: [addr('o1', 'nat-only')], rowCount: 1 };
      if (/FROM nat_rules/i.test(sql)) return new Error('nat read failed');
      return { rows: [], rowCount: 0 };
    });
    let result;
    try {
      result = await runObjectUsageAnalysisForDevice('dev-1', pool);
    } catch (err) {
      assert.match(err.message, /nat read failed/);
      return;
    }
    assert.fail(`expected a throw; got a result instead: ${JSON.stringify(result)}`);
  });
});

// --------------------------------------------------------------------------
// E. Zero NAT rows is a genuine zero — distinguishable from a failed read
// --------------------------------------------------------------------------

describe('objectUsage: zero NAT rows is distinguishable from a failed NAT read', () => {
  function poolForNat(natResult) {
    return stubPool((sql) => {
      if (/FROM network_objects/i.test(sql)) {
        return { rows: [addr('o1', 'orphan'), addr('o2', 'nat-only')], rowCount: 2 };
      }
      if (/FROM firewall_rules/i.test(sql)) return { rows: [], rowCount: 0 };
      if (/FROM nat_rules/i.test(sql)) return natResult;
      if (/INSERT INTO object_analysis_results/i.test(sql)) return { rows: [{ id: 'f' }], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    });
  }

  it('a device with no NAT rows analyses normally and WRITES results', async () => {
    // Only some vendors/transports collect NAT at all, so this is the
    // ordinary case for most of the fleet — it must not look like a failure.
    const pool = poolForNat({ rows: [], rowCount: 0 });
    const { findings } = await runObjectUsageAnalysisForDevice('dev-1', pool);
    assert.equal(findings.length, 2, 'both objects are genuinely unused when there really is no NAT');
    assert.equal(pool.connectCount, 1);
    assert.ok(pool.calls.some((c) => /DELETE\s+FROM\s+object_analysis_results/i.test(c.sql)));
  });

  it('a device WITH NAT rows shortens the list rather than lengthening it', async () => {
    const pool = poolForNat({ rows: [natRow({ original_src_addresses: ['nat-only'] })], rowCount: 1 });
    const { findings } = await runObjectUsageAnalysisForDevice('dev-1', pool);
    assert.equal(findings.length, 1);
  });

  it('the failed read and the empty read take visibly different paths', async () => {
    const ok = poolForNat({ rows: [], rowCount: 0 });
    await runObjectUsageAnalysisForDevice('dev-1', ok);

    const failed = poolForNat(new Error('nat unreadable'));
    await assert.rejects(() => runObjectUsageAnalysisForDevice('dev-1', failed));

    assert.equal(ok.connectCount, 1, 'the genuine zero commits a transaction');
    assert.equal(failed.connectCount, 0, 'the failed read never reaches one');
  });

  it('queries nat_rules with a parameterized device_id and selects all six name-bearing columns', async () => {
    const pool = poolForNat({ rows: [], rowCount: 0 });
    await runObjectUsageAnalysisForDevice('dev-1', pool);
    const [natCall] = sqlFor(pool, 'nat_rules');
    assert.ok(natCall, 'expected a SELECT against nat_rules');
    assert.deepEqual(natCall.params, ['dev-1']);
    assert.match(natCall.sql, /WHERE device_id = \$1/i, 'device_id must be parameterized, never interpolated');
    for (const col of [...NAT_ADDRESS_FIELDS, ...NAT_SERVICE_FIELDS]) {
      assert.match(natCall.sql, new RegExp(`\\b${col}\\b`), `nat_rules SELECT is missing ${col}`);
    }
  });

  it('a device with no collected objects clears its findings without reading any surface', async () => {
    // Pre-existing behaviour, retained: no catalog means no object can be
    // reported unused, so neither firewall_rules nor nat_rules is consulted.
    const pool = stubPool(() => ({ rows: [], rowCount: 0 }));
    const { findings } = await runObjectUsageAnalysisForDevice('dev-1', pool);
    assert.deepEqual(findings, []);
    assert.equal(sqlFor(pool, 'nat_rules').length, 0);
    assert.equal(sqlFor(pool, 'firewall_rules').length, 0);
    assert.ok(pool.calls.some((c) => /DELETE\s+FROM\s+object_analysis_results/i.test(c.sql)));
  });
});

// --------------------------------------------------------------------------
// F. Everything the engine already did still holds
// --------------------------------------------------------------------------

describe('objectUsage: pre-existing behaviour is unchanged', () => {
  it('the 2026-07-18 namespace fix still holds for FIREWALL rule fields', () => {
    const objects = [addr('a1', 'DNS', '8.8.8.8/32'), svc('s1', 'dns', 'udp/53')];
    const findings = analyzeObjectUsage(objects, [rule({ services: ['DNS'] })], []);
    assert.equal(isUnused(findings, 's1'), false);
    assert.equal(isUnused(findings, 'a1'), true, 'a service reference must never credit a same-named address object');
  });

  it('group closure through a firewall rule still works transitively', () => {
    const objects = [addrGroup('g1', 'outer', ['inner']), addrGroup('g2', 'inner', ['leaf']), addr('a1', 'leaf')];
    assert.deepEqual(unusedIds(analyzeObjectUsage(objects, [rule({ dst_addresses: ['outer'] })], [])), []);
  });

  it('duplicates are detected on same-type same-value leaf objects', () => {
    const objects = [addr('a1', 'web-1', '10.0.0.1/32'), addr('a2', 'web-one', '10.0.0.1/32')];
    const dupes = analyzeObjectUsage(objects, [], []).filter((f) => f.finding_type === 'duplicate');
    assert.equal(dupes.length, 2);
    assert.deepEqual(dupes[0].related_object_ids, ['a2']);
    assert.deepEqual(dupes[1].related_object_ids, ['a1']);
  });

  it('duplicate detection is independent of NAT — an in-use duplicate is still a duplicate', () => {
    const objects = [addr('a1', 'web-1', '10.0.0.1/32'), addr('a2', 'web-one', '10.0.0.1/32')];
    const natRules = [natRow({ translated_dst_addresses: ['web-1', 'web-one'] })];
    const findings = analyzeObjectUsage(objects, [], natRules);
    assert.deepEqual(unusedIds(findings), [], 'both are referenced by NAT');
    assert.equal(findings.filter((f) => f.finding_type === 'duplicate').length, 2);
  });

  it('an address and a service holding the same value are NOT duplicates of each other', () => {
    const objects = [addr('a1', 'x', 'tcp/53'), svc('s1', 'y', 'tcp/53')];
    assert.equal(analyzeObjectUsage(objects, [], []).filter((f) => f.finding_type === 'duplicate').length, 0);
  });

  it('groups are never reported as duplicates, however identical their members', () => {
    const objects = [addrGroup('g1', 'a', ['m']), addrGroup('g2', 'b', ['m']), addr('a1', 'm')];
    assert.equal(analyzeObjectUsage(objects, [], []).filter((f) => f.finding_type === 'duplicate').length, 0);
  });

  it('objects with a null/empty value are never duplicates of each other', () => {
    const objects = [addr('a1', 'x', null), addr('a2', 'y', null), addr('a3', 'z', '')];
    assert.equal(analyzeObjectUsage(objects, [], []).filter((f) => f.finding_type === 'duplicate').length, 0);
  });

  it('a non-array objects argument yields no findings rather than throwing', () => {
    assert.deepEqual(analyzeObjectUsage(null, [], []), []);
    assert.deepEqual(analyzeObjectUsage(undefined, [], []), []);
  });

  it('a non-array rules argument keeps its historical tolerance', () => {
    // Deliberate asymmetry with natRules: `rules` has legacy callers, and its
    // failed-read protection is that the wrapper's own SELECT throws.
    assert.deepEqual(unusedIds(analyzeObjectUsage([addr('o1', 'x')], null, [])), ['o1']);
  });

  it('the finding shape written to object_analysis_results is unchanged', () => {
    const findings = analyzeObjectUsage([addr('o1', 'x')], [], []);
    assert.deepEqual(Object.keys(findings[0]).sort(), [
      'detail',
      'finding_type',
      'object_id',
      'related_object_ids',
    ]);
    assert.deepEqual(findings[0].related_object_ids, []);
  });

  it('the unused detail text names NAT among the surfaces that were checked', () => {
    // The text is what an operator reads immediately before deleting the
    // object; claiming only "any rule" would understate what was measured.
    const [finding] = analyzeObjectUsage([addr('o1', 'x')], [], []);
    assert.match(finding.detail, /NAT rule/i);
  });
});

// --------------------------------------------------------------------------
// G. Schema-drift gate — a seventh NAT column must not become invisible
// --------------------------------------------------------------------------

describe('objectUsage: the NAT field lists cover every name-bearing nat_rules column', () => {
  it('matches lib/schema.sql exactly', () => {
    const schema = fs.readFileSync(path.join(__dirname, '..', 'lib', 'schema.sql'), 'utf8');
    const block = schema.match(/CREATE TABLE IF NOT EXISTS nat_rules\s*\(([\s\S]*?)\n\);/);
    assert.ok(block, 'could not find the nat_rules CREATE TABLE in lib/schema.sql');

    const columns = block[1]
      .split('\n')
      .map((line) => line.replace(/--.*$/, '').trim())
      .map((line) => (line.match(/^([a-z_][a-z0-9_]*)\s+/i) || [])[1])
      .filter(Boolean)
      .filter((name) => /_(addresses|services)$/.test(name));

    assert.ok(columns.length > 0, 'the nat_rules parse found no name-bearing columns — the regex has drifted');
    assert.deepEqual(
      columns.slice().sort(),
      [...NAT_ADDRESS_FIELDS, ...NAT_SERVICE_FIELDS].slice().sort(),
      'a nat_rules column naming objects exists that objectUsage.js does not read — it is silently invisible ' +
        'to the unused-object analysis, which is how objects NAT depends on get recommended for deletion'
    );

    // And each is on the side its NAME says it is on.
    assert.deepEqual(NAT_ADDRESS_FIELDS.filter((f) => !/_addresses$/.test(f)), []);
    assert.deepEqual(NAT_SERVICE_FIELDS.filter((f) => !/_services$/.test(f)), []);
  });
});
