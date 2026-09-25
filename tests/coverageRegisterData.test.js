'use strict';

// tests/coverageRegisterData.test.js — pins lib/engines/coverageRegisterData.js,
// the plumbing half of the A2 blind-spot register.
//
// WHY THIS FILE EXISTS: this is the page whose entire job is to name what
// SecVault CANNOT measure. A failed read here does not merely lose information
// — it asserts the exact opposite of the truth, on the one page a reader
// consults to decide how much to trust everything else in the product. An
// empty register reads as "we can see everything". So the "we could not
// measure this" case is the centre of this file, per tests/README.md: the
// throwing query, the NULL count, and the difference between a measured zero
// and an unreadable one.
//
// ⛔ NO DATABASE. `getCoverageRegister(pool, opts)` only ever calls
// `pool.query(sql, params)`, so every test hands it a stub that RECORDS the
// statement and params it was given and returns canned rows (the convention
// configRetention.test.js established and upgradePlanData.test.js follows).
// That gives two independent things to pin: the SQL it builds, and how it
// interprets what comes back.
//
// SQL assertions match a meaningful FRAGMENT, never a whole string, so a
// legitimate reformat is a one-line test update while a REMOVED guarantee
// still fails loudly.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const dataModule = require('../lib/engines/coverageRegisterData');
const { getCoverageRegister } = dataModule;
const { STATE, SOURCES } = require('../lib/engines/coverageRegister');

const MODULE_PATH = path.join(__dirname, '..', 'lib', 'engines', 'coverageRegisterData.js');
const SRC = fs.readFileSync(MODULE_PATH, 'utf8');

// ⛔ EVERY 'must NOT contain' ASSERTION BELOW RUNS AGAINST SOURCE WITH COMMENTS
// REMOVED. This repo has been bitten three separate times by a source scan
// satisfied by the very comment explaining the thing it was hunting — and the
// module under test deliberately documents, in prose, the table it must never
// query. Stripping is crude on purpose and only ever feeds a doesNotMatch,
// where over-removal can lose coverage but can never invent a failure.
const BLOCK_COMMENT = new RegExp('/\\*[\\s\\S]*?\\*/', 'g');
const LINE_COMMENT = new RegExp('(^|[\\s{(;,])//[^\\n]*', 'g');
const stripComments = (src) =>
  String(src).replace(BLOCK_COMMENT, ' ').replace(LINE_COMMENT, '$1 ');

const CODE = stripComments(SRC);

// --------------------------------------------------------------------------
// Stub pool
// --------------------------------------------------------------------------

/**
 * @param {object[]|Error} result rows to return, or an Error to throw.
 */
function stubPool(result) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql: String(sql), params });
      if (result instanceof Error) throw result;
      const rows = (result || []).map((r) => ({ ...r }));
      return { rows, rowCount: rows.length };
    },
  };
}

// ⛔ COUNTS ARE STRINGS AND AGES ARE NUMBERS, exactly as `pg` hands them back:
// `count(*)` is bigint (string, so 2^53 cannot be silently truncated) while the
// `::int` age expressions arrive as real numbers. The fixture keeps that mix so
// a coercion that only works for one of them fails here.
const row = (over = {}) => ({
  id: 'd-ok',
  name: 'IDC FW',
  vendor: 'paloalto',
  last_rules_collected_at: '2026-09-25T00:00:00Z',
  version_rows: '3',
  interfaces: '72',
  rules: '721',
  rules_unmeasured: '0',
  log_buckets: '2009',
  obj_refs: '878',
  obj_unresolvable: '0',
  config_age_days: 0,
  analysis_age_days: 1,
  rule_findings: '377',
  ...over,
});

// The three live shapes measured on the reference fleet 2026-09-25, the ones
// that drove the feature. Same fixtures as the pure engine's own test.
const PAKFOOD = () => row({
  id: 'd-pak', name: 'PAKFood', log_buckets: '0', obj_refs: '77', obj_unresolvable: '77',
});
const TSR_EKM = () => row({
  id: 'd-ekm', name: 'TSR_EKM', vendor: 'fortinet', rules: '78', rules_unmeasured: '78',
});
const TSR_EKC = () => row({
  id: 'd-ekc',
  name: 'TSR_EKC',
  vendor: 'fortinet',
  last_rules_collected_at: null,
  rules: '0',
  rules_unmeasured: '0',
  obj_refs: '0',
  obj_unresolvable: '0',
  analysis_age_days: 49,
  rule_findings: '22',
});

const byName = (entries, name) => entries.find((e) => e.deviceName === name);
const cellFor = (entry, key) => entry.cells.find((c) => c.key === key);

// --------------------------------------------------------------------------
// ⛔ The reason this file exists: a broken read must never look like a clean one
// --------------------------------------------------------------------------

describe('a query that throws', () => {
  it('reports a failure and returns NO entries — never a clean-looking empty register', async () => {
    const pool = stubPool(new Error('relation "syslog_rollup_hourly" does not exist'));
    const out = await getCoverageRegister(pool);

    assert.deepEqual(out.entries, [], 'a partial register that looks complete is the bug');
    assert.equal(out.failures.length, 1, 'the failure is part of the ANSWER, not a log line');
    assert.equal(typeof out.failures[0].source, 'string');
    assert.match(out.failures[0].error, /does not exist/);
  });

  it('does not throw out of getCoverageRegister — the caller gets a labelled result', async () => {
    const pool = stubPool(new Error('connection terminated unexpectedly'));
    const out = await getCoverageRegister(pool);
    assert.ok(out && typeof out === 'object');
    assert.equal(out.summary.devices, 0);
    assert.equal(out.summary.devicesWithGaps, 0);
    // ⛔ THE TRAP: every total above is 0, which on this page reads as "no
    // blind spots". `failures` is the only thing distinguishing it from a
    // genuinely clean fleet, so it must be non-empty and the caller must lead
    // with it.
    assert.ok(out.failures.length > 0, 'zero totals must never stand alone');
  });

  it('a healthy fleet reports NO failures, so a non-empty failures list means something', async () => {
    const pool = stubPool([row()]);
    const out = await getCoverageRegister(pool);
    assert.deepEqual(out.failures, []);
  });

  it('a thrown non-Error still produces a readable failure', async () => {
    const pool = {
      calls: [],
      // eslint-disable-next-line prefer-promise-reject-errors
      async query() { throw 'string thrown by a driver'; },
    };
    const out = await getCoverageRegister(pool);
    assert.equal(out.entries.length, 0);
    assert.equal(out.failures.length, 1);
    assert.match(out.failures[0].error, /string thrown/);
  });
});

// --------------------------------------------------------------------------
// ⛔ An unreadable count is NOT a measured zero
// --------------------------------------------------------------------------

describe('a NULL count stays unreadable', () => {
  it('a NULL syslog count is ABSENT-but-UNCERTAIN, never "this firewall sends no syslog"', async () => {
    const pool = stubPool([row({ log_buckets: null })]);
    const { entries, summary } = await getCoverageRegister(pool);
    const c = cellFor(entries[0], 'syslog');

    assert.equal(c.state, STATE.ABSENT);
    assert.equal(c.certain, false, 'we could not even check — that is not a measured zero');
    assert.match(c.detail, /could not be read/i);
    assert.doesNotMatch(c.detail, /sends no syslog/i, 'an unread count must not assert a fact');
    assert.equal(summary.devicesWithUnreadableChecks, 1);
  });

  it('a MEASURED zero is certain, and reads differently from the unreadable one', async () => {
    const pool = stubPool([row({ log_buckets: '0' })]);
    const { entries, summary } = await getCoverageRegister(pool);
    const c = cellFor(entries[0], 'syslog');

    assert.equal(c.state, STATE.ABSENT);
    assert.equal(c.certain, true, 'a measured zero is certain — we DID check');
    assert.match(c.detail, /sends no syslog/i);
    assert.equal(summary.devicesWithUnreadableChecks, 0);
  });

  it('a NULL rule count does not become 0 rules collected', async () => {
    const pool = stubPool([row({ rules: null, rules_unmeasured: null })]);
    const { entries } = await getCoverageRegister(pool);
    const c = cellFor(entries[0], 'ruleset');
    assert.equal(c.certain, false);
    assert.match(c.detail, /could not be read/i);
    assert.doesNotMatch(c.detail, /No firewall rules have been collected/i);
  });

  it('an undefined column (a row shape that changed) is unreadable, not zero', async () => {
    // A renamed column arrives as `undefined`, which `Number()` also turns
    // into NaN and a lazy guard turns into 0.
    const base = row();
    delete base.log_buckets;
    const pool = stubPool([base]);
    const { entries } = await getCoverageRegister(pool);
    assert.equal(cellFor(entries[0], 'syslog').certain, false);
  });

  it('a NULL config age is "no configuration collected", and a real 0 is not', async () => {
    const pool = stubPool([row({ config_age_days: null }), row({ id: 'd2', name: 'fresh', config_age_days: 0 })]);
    const { entries } = await getCoverageRegister(pool);
    assert.equal(cellFor(byName(entries, 'IDC FW'), 'config').state, STATE.ABSENT);
    assert.equal(cellFor(byName(entries, 'fresh'), 'config').state, STATE.MEASURED);
  });

  it('a NULL last_rules_collected_at is passed through as null, never invented', async () => {
    const pool = stubPool([TSR_EKC()]);
    const { entries } = await getCoverageRegister(pool);
    assert.equal(entries[0].staleFindings.neverCollected, true);
  });
});

// --------------------------------------------------------------------------
// The three live shapes
// --------------------------------------------------------------------------

describe('the live fleet shapes', () => {
  it('a fully-collected firewall is fullyCovered and withholds nothing', async () => {
    const pool = stubPool([row()]);
    const { entries, summary } = await getCoverageRegister(pool);

    assert.equal(entries.length, 1);
    assert.equal(entries[0].deviceId, 'd-ok');
    assert.equal(entries[0].deviceName, 'IDC FW');
    assert.equal(entries[0].vendor, 'paloalto');
    assert.equal(entries[0].fullyCovered, true);
    assert.equal(entries[0].gapCount, 0);
    assert.equal(entries[0].answersWithheld, 0);
    assert.equal(entries[0].staleFindings, null);
    assert.equal(summary.devicesFullyCovered, 1);
    assert.equal(summary.devicesWithGaps, 0);
  });

  it('PAKFood: zero syslog buckets, while every other source is present', async () => {
    const pool = stubPool([PAKFOOD()]);
    const { entries, summary } = await getCoverageRegister(pool);
    const e = entries[0];

    assert.equal(e.fullyCovered, false, 'it renders as fully assessed everywhere else');
    assert.equal(cellFor(e, 'syslog').state, STATE.ABSENT);
    assert.deepEqual(cellFor(e, 'syslog').gates, SOURCES.syslog.gates);
    // 77 of 77 object references unresolvable, live.
    assert.equal(cellFor(e, 'objects').state, STATE.ABSENT);
    assert.ok(e.blockedEngines.some((g) => /log_hit/.test(g)));
    assert.equal(summary.gapsBySource.syslog, 1);
  });

  it('TSR_EKM: 78 of 78 rules with no hit count is ABSENT rule usage, not zero hits', async () => {
    const pool = stubPool([TSR_EKM()]);
    const { entries } = await getCoverageRegister(pool);
    const c = cellFor(entries[0], 'ruleUsage');

    assert.equal(c.state, STATE.ABSENT);
    assert.match(c.detail, /78 of 78/);
    assert.match(c.detail, /cleanup will refuse/i);
    // The ruleset itself WAS collected — only its usage is unmeasured.
    assert.equal(cellFor(entries[0], 'ruleset').state, STATE.MEASURED);
  });

  it('TSR_EKC: 49-day-old analysis with rule collection that never succeeded', async () => {
    const pool = stubPool([TSR_EKC()]);
    const { entries, summary } = await getCoverageRegister(pool);
    const e = entries[0];

    assert.ok(e.staleFindings, 'stale findings render as current answers unless the register says so');
    assert.equal(e.staleFindings.ageDays, 49);
    assert.equal(e.staleFindings.findingCount, 22);
    assert.equal(e.staleFindings.neverCollected, true);
    assert.match(e.staleFindings.detail, /never succeeded/i);
    assert.equal(e.fullyCovered, false);
    assert.equal(summary.devicesWithStaleFindings, 1);
  });

  it('a partial hit-count gap is PARTIAL, not ABSENT', async () => {
    const pool = stubPool([row({ rules: '100', rules_unmeasured: '40' })]);
    const { entries } = await getCoverageRegister(pool);
    assert.equal(cellFor(entries[0], 'ruleUsage').state, STATE.PARTIAL);
  });
});

// --------------------------------------------------------------------------
// Ranking — by consequence, and stale first
// --------------------------------------------------------------------------

describe('ranking', () => {
  it('entries come back RANKED: stale findings first, then by answers withheld', async () => {
    // Deliberately supplied in the SQL's own `ORDER BY d.name` order, which is
    // alphabetical and is NOT the answer: IDC FW, PAKFood, TSR_EKC.
    const pool = stubPool([row(), PAKFOOD(), TSR_EKC()]);
    const { entries } = await getCoverageRegister(pool);

    assert.equal(entries.length, 3);
    assert.equal(entries[0].deviceName, 'TSR_EKC', 'stale evidence outranks a pure gap');
    assert.equal(entries[1].deviceName, 'PAKFood');
    assert.equal(entries[2].deviceName, 'IDC FW', 'the fully-covered firewall ranks last');
  });

  it('between two gap-only firewalls, the one withholding more answers comes first', async () => {
    const oneGap = row({ id: 'd-a', name: 'one-gap', log_buckets: '0' });
    const manyGaps = row({
      id: 'd-b', name: 'many-gaps', log_buckets: '0', interfaces: '0', version_rows: '0',
      obj_refs: '77', obj_unresolvable: '77',
    });
    const { entries } = await getCoverageRegister(stubPool([oneGap, manyGaps]));

    assert.equal(entries[0].deviceName, 'many-gaps');
    assert.ok(entries[0].answersWithheld > entries[1].answersWithheld);
  });

  it('does not re-sort the engine\'s ranking in this file', () => {
    assert.ok(/rankRegister\(/.test(CODE), 'the engine ranks; this file must not');
    assert.ok(!/\.sort\(/.test(CODE), 'a second sort here would eventually disagree with the engine');
  });
});

// --------------------------------------------------------------------------
// The statement it builds
// --------------------------------------------------------------------------

describe('the SQL', () => {
  const sqlOf = async (opts) => {
    const pool = stubPool([row()]);
    await getCoverageRegister(pool, opts);
    return pool.calls[0];
  };

  it('⛔ NEVER touches the raw syslog event table (comments stripped first)', () => {
    // ~28M rows/day in daily partitions, with the collector inserting at
    // ~1,000 rows/sec. The rollup answers this register's only syslog
    // question at low cardinality. The module explains this IN PROSE, which
    // is exactly why the scan runs on stripped source.
    assert.ok(/syslog_events/.test(SRC), 'the module should still explain the rule in a comment');
    assert.ok(
      !/syslog_events/.test(CODE),
      'the raw event table must never be queried from this register'
    );
    assert.ok(/syslog_rollup_hourly/.test(CODE), 'the rollup is what it counts');
  });

  it('issues exactly ONE statement — no per-device query', async () => {
    const pool = stubPool([row(), PAKFOOD(), TSR_EKM()]);
    await getCoverageRegister(pool);
    assert.equal(pool.calls.length, 1);
  });

  it('uses a bound parameter for deviceIds — no interpolation anywhere', async () => {
    const call = await sqlOf({ deviceIds: ['d-ok', 'd-pak'] });
    assert.ok(!/\$\{/.test(call.sql), 'no string interpolation in SQL, ever');
    assert.ok(!/d-ok/.test(call.sql), 'an id must never appear in the statement text');
    assert.match(call.sql, /\$1::uuid\[\]/, 'explicitly cast, per CLAUDE.md');
    assert.match(call.sql, /=\s*ANY\(\$1::uuid\[\]\)/);
    assert.deepEqual(call.params, [['d-ok', 'd-pak']]);
  });

  it('omitting deviceIds means the WHOLE active fleet — the parameter is null, not []', async () => {
    const call = await sqlOf(undefined);
    assert.deepEqual(call.params, [null]);
    assert.match(call.sql, /\$1::uuid\[\]\s+IS\s+NULL/i, 'null must widen, not match nothing');
  });

  it('an EMPTY list means NO devices, and is never quietly widened to the fleet', async () => {
    const call = await sqlOf({ deviceIds: [] });
    assert.deepEqual(call.params, [[]]);
  });

  it('junk entries are dropped rather than sent to the database', async () => {
    const call = await sqlOf({ deviceIds: ['a', '', null, 7, 'b'] });
    assert.deepEqual(call.params, [['a', 'b']]);
  });

  it('is driven FROM devices, so a firewall with no evidence still gets a row', async () => {
    const call = await sqlOf();
    assert.match(call.sql, /FROM\s+devices\s+d/i);
    assert.match(call.sql, /WHERE\s+d\.active/i);
  });

  it('reads rule_analysis_results.analyzed_at — the column that exists', async () => {
    // ⛔ VERIFIED against lib/schema.sql: rule_analysis_results declares
    // `analyzed_at TIMESTAMPTZ NOT NULL DEFAULT now()` and has NO `created_at`.
    // The wrong name does not degrade gracefully — the statement throws and the
    // whole register comes back empty.
    const call = await sqlOf();
    assert.match(call.sql, /max\(rr\.analyzed_at\)/i);
    assert.ok(!/rr\.created_at/i.test(call.sql), 'rule_analysis_results has no created_at');
  });

  it('counts unmeasured rules as hit_count IS NULL, the tri-state\'s third state', async () => {
    const call = await sqlOf();
    assert.match(call.sql, /hit_count\s+IS\s+NULL/i);
  });

  it('stores nothing — no INSERT, UPDATE or DELETE anywhere in this engine', () => {
    // A stored register goes stale against the very collection it indexes.
    assert.ok(!/\bINSERT\s+INTO\b/i.test(CODE), 'read time only');
    assert.ok(!/\bUPDATE\s+\w+\s+SET\b/i.test(CODE), 'read time only');
    assert.ok(!/\bDELETE\s+FROM\b/i.test(CODE), 'read time only');
  });

  it('pool is a PARAMETER — the module never imports or instantiates one', () => {
    assert.ok(
      !/require\(['"][^'"]*\bdb['"]\)/.test(CODE) && !/new\s+Pool\b/.test(CODE),
      'CLAUDE.md: never instantiate or import a pool here'
    );
  });
});

// --------------------------------------------------------------------------
// The contract
// --------------------------------------------------------------------------

describe('the exported contract', () => {
  it('exports exactly getCoverageRegister', () => {
    assert.deepEqual(Object.keys(dataModule), ['getCoverageRegister']);
    assert.equal(typeof getCoverageRegister, 'function');
  });

  it('returns entries, summary, failures and generatedAt', async () => {
    const out = await getCoverageRegister(stubPool([row()]));
    assert.deepEqual(Object.keys(out).sort(), ['entries', 'failures', 'generatedAt', 'summary']);
  });

  it('generatedAt is injectable, so the timestamp is pinnable', async () => {
    const out = await getCoverageRegister(stubPool([row()]), { now: '2026-09-25T08:30:00.000Z' });
    assert.equal(out.generatedAt, '2026-09-25T08:30:00.000Z');
  });

  it('generatedAt defaults to now, and is still present on a failure', async () => {
    const before = Date.now();
    const out = await getCoverageRegister(stubPool(new Error('nope')));
    const t = Date.parse(out.generatedAt);
    assert.ok(t >= before && t <= Date.now());
  });

  it('an empty fleet returns no entries and no failures — and devices: 0 says so', async () => {
    const { entries, summary, failures } = await getCoverageRegister(stubPool([]));
    assert.deepEqual(entries, []);
    assert.deepEqual(failures, []);
    assert.equal(summary.devices, 0);
    // ⛔ Identical totals to the throwing case above. `failures` is the ONLY
    // thing that separates "no firewalls" from "we could not look", which is
    // why the caller must read it first.
    assert.equal(summary.devicesWithGaps, 0);
  });

  it('carries the pure engine\'s summary through unchanged', async () => {
    const { summary } = await getCoverageRegister(stubPool([row(), PAKFOOD(), TSR_EKC()]));
    assert.equal(summary.devices, 3);
    assert.equal(summary.devicesFullyCovered, 1);
    assert.equal(summary.devicesWithGaps, 2);
    assert.equal(summary.devicesWithStaleFindings, 1);
    assert.ok(Array.isArray(summary.blockedEngines));
    assert.ok(summary.blockedEngines.length > 0);
  });

  it('tolerates a driver result with no rows array rather than throwing', async () => {
    const pool = { calls: [], async query() { return {}; } };
    const out = await getCoverageRegister(pool);
    assert.deepEqual(out.entries, []);
    assert.deepEqual(out.failures, []);
  });
});
