'use strict';

// tests/fleetConformanceData.test.js — pins lib/engines/fleetConformanceData.js,
// the plumbing half of "which firewall is configured unlike its peers".
//
// The pure engine is pinned separately by tests/fleetConformance.test.js. What
// is tested here is only what the PLUMBING can get wrong, and there are two
// things in that set that matter more than the rest:
//
//   1. ⛔ A FAILED READ THAT LOOKS LIKE A CLEAN FLEET. An empty board reads as
//      "every firewall agrees with its peers". A query that throws produces
//      exactly that shape, so the distinction between "nothing differs" and
//      "nothing could be read" is the centre of this file, per tests/README.md.
//
//   2. ⛔ A FAILED READ THAT BECOMES A FINDING. The engine has a documented
//      exclusion for a firewall with no parsed configuration, and it names and
//      counts it. If the configuration statement throws and the device roster
//      is still handed through, every firewall on the fleet is excluded for
//      `no_parsed_config` and the board reports — with counts and names — that
//      SecVault has collected nothing from any of them. That is the same bug
//      wearing a confident face, and it is asserted below.
//
// ⛔ NO DATABASE. `getFleetConformance(pool, opts)` only ever calls
// `pool.query(sql, params)`, so every test hands it a stub that RECORDS the
// statement and params it was given and returns canned rows — the convention
// configRetention.test.js established and coverageRegisterData.test.js follows.
// That gives two independent things to pin: the SQL it builds, and how it
// interprets what comes back.
//
// SQL assertions match a meaningful FRAGMENT, never a whole string, so a
// legitimate reformat is a one-line test update while a REMOVED guarantee still
// fails loudly.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { getFleetConformance } = require('../lib/engines/fleetConformanceData');
const {
  CONFORMANCE_CLAIM,
  STATUS,
  EXCLUSION,
} = require('../lib/engines/fleetConformance');

const MODULE_PATH = path.join(__dirname, '..', 'lib', 'engines', 'fleetConformanceData.js');
const RAW_SRC = fs.readFileSync(MODULE_PATH, 'utf8');

// ⛔ EVERY 'does NOT contain' ASSERTION BELOW RUNS AGAINST SOURCE WITH COMMENTS
// REMOVED. This repo has been bitten repeatedly by a source scan satisfied by
// the very comment explaining the thing it was hunting — and the module under
// test deliberately spells out, in prose, the vocabulary it refuses to emit.
// The stripper is PROVEN by its own test further down rather than assumed.
const BLOCK_COMMENT = new RegExp('/\\*[\\s\\S]*?\\*/', 'g');
const LINE_COMMENT = new RegExp('(^|[\\s{(;,])//[^\\n]*', 'g');
const stripComments = (src) =>
  String(src).replace(BLOCK_COMMENT, ' ').replace(LINE_COMMENT, '$1 ');

const CODE = stripComments(RAW_SRC);

// ── the stub pool ──────────────────────────────────────────────────────────

/**
 * ⛔ THE STUB ROUTES ON THE STATEMENT. This layer issues TWO queries, and a
 * stub that returned the same canned rows to both would feed device rows to the
 * configuration reader without throwing — every merge assertion below would
 * then be measuring the stub.
 *
 * ⛔ ORDER IS LOAD-BEARING: the configuration statement also NAMES `devices` in
 * its join, so it has to be recognised FIRST, by the one table only it has.
 *
 * @param {object} spec
 * @param {object[]|Error} [spec.fleet]   rows for the device roster
 * @param {object[]|Error} [spec.configs] rows for the latest-config statement
 */
function stubPool(spec = {}) {
  const calls = [];
  const give = (v) => {
    if (v instanceof Error) throw v;
    if (v === undefined) return { rows: [], rowCount: 0 };
    const rows = (v || []).map((r) => ({ ...r }));
    return { rows, rowCount: rows.length };
  };
  return {
    calls,
    async query(sql, params) {
      const text = String(sql);
      calls.push({ sql: text, params });
      if (/FROM\s+device_configs\s+c\b/i.test(text)) return give(spec.configs);
      if (/FROM\s+devices\s+d\b/i.test(text)) return give(spec.fleet);
      return give([]);
    },
  };
}

const sqlFor = (pool, re) => (pool.calls.find((c) => re.test(c.sql)) || {}).sql || '';
const fleetCall = (pool) => pool.calls.find((c) => /FROM\s+devices\s+d\b/i.test(c.sql) && !/device_configs/i.test(c.sql));
const configCall = (pool) => pool.calls.find((c) => /FROM\s+device_configs\s+c\b/i.test(c.sql));

// ── fixtures ───────────────────────────────────────────────────────────────

const AT = '2026-09-25T12:00:00.000Z';

const device = (id, name, vendor, mgmt_method) => ({ id, name, vendor, mgmt_method });
const config = (device_id, config_parsed, collected_at = AT) => ({ device_id, config_parsed, collected_at });

/**
 * The live shape, reduced: five FortiGates over SSH where ONE reports a
 * different value on two settings, and one lone Palo Alto over SSH — a cohort
 * of one, which is `insufficient_cohort` and yields nothing.
 *
 * ⛔ The odd firewall here is the HARDENED one (`5022`, not the default SSH
 * port), exactly as on the reference fleet. It is the minority and it is the
 * only one not on the default. Nothing in this layer may describe it as
 * anything but different.
 */
const FIVE_FORTINETS = [
  device('f1', 'OKF(F2)', 'fortinet', 'ssh'),
  device('f2', 'TSR-TL', 'fortinet', 'ssh'),
  device('f3', 'Vietnam-YCC', 'fortinet', 'ssh'),
  device('f4', 'HRIS', 'fortinet', 'ssh'),
  device('f5', 'PAKFood', 'fortinet', 'ssh'),
];

const fortinetConfig = (odd) => ({
  dns: { protocol: odd ? 'cleartext' : 'dot' },
  global: { 'admin-ssh-port': odd ? '5022' : '22', 'admin-https-redirect': odd ? 'disable' : 'enable' },
});

const FIVE_CONFIGS = [
  config('f1', fortinetConfig(true)),
  config('f2', fortinetConfig(false)),
  config('f3', fortinetConfig(false)),
  config('f4', fortinetConfig(false)),
  config('f5', fortinetConfig(false)),
];

const TUG = device('p1', 'TUG', 'paloalto', 'ssh');
const TUG_CONFIG = config('p1', { tree: { hostname: 'TUG' }, sw_version: '11.1.2' });

const cohortNamed = (out, key) => out.cohorts.find((c) => c.cohortKey === key);

// ────────────────────────────────────────────────────────────────────────────
// 1. The exported signature
// ────────────────────────────────────────────────────────────────────────────

describe('getFleetConformance — shape', () => {
  it('returns cohorts, summary, failures, generatedAt and the claim', async () => {
    const pool = stubPool({ fleet: FIVE_FORTINETS, configs: FIVE_CONFIGS });
    const out = await getFleetConformance(pool);
    assert.deepEqual(Object.keys(out).sort(), ['claim', 'cohorts', 'failures', 'generatedAt', 'summary']);
    assert.ok(Array.isArray(out.cohorts));
    assert.ok(Array.isArray(out.failures));
    assert.equal(typeof out.summary, 'object');
    assert.equal(typeof out.generatedAt, 'string');
  });

  it('⛔ carries the engine’s claim verbatim, never a local rewording', async () => {
    const pool = stubPool({ fleet: FIVE_FORTINETS, configs: FIVE_CONFIGS });
    const out = await getFleetConformance(pool);
    assert.equal(out.claim, CONFORMANCE_CLAIM);
    // ⛔ And the claim is not duplicated in this file's own source: a second
    // copy would drift from the one the engine's tests pin.
    assert.doesNotMatch(CODE, /may be the only one/i);
  });

  it('the injected clock pins generatedAt rather than the moment the suite ran', async () => {
    const pool = stubPool({ fleet: [], configs: [] });
    const out = await getFleetConformance(pool, { now: AT });
    assert.equal(out.generatedAt, AT);
  });

  it('survives a JSON round trip, as a route would send it', async () => {
    const pool = stubPool({ fleet: [...FIVE_FORTINETS, TUG], configs: [...FIVE_CONFIGS, TUG_CONFIG] });
    const out = JSON.parse(JSON.stringify(await getFleetConformance(pool, { now: AT })));
    assert.equal(out.claim, CONFORMANCE_CLAIM);
    assert.equal(cohortNamed(out, 'fortinet/ssh').status, STATUS.MEASURED);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 2. The statements
// ────────────────────────────────────────────────────────────────────────────

describe('the SQL', () => {
  it('issues exactly two statements and no more', async () => {
    const pool = stubPool({ fleet: FIVE_FORTINETS, configs: FIVE_CONFIGS });
    await getFleetConformance(pool);
    assert.equal(pool.calls.length, 2);
  });

  it('⛔ drives the roster from devices, so a firewall with no config is still seen', async () => {
    const pool = stubPool({ fleet: FIVE_FORTINETS, configs: FIVE_CONFIGS });
    await getFleetConformance(pool);
    const sql = fleetCall(pool).sql;
    assert.match(sql, /FROM\s+devices\s+d/i);
    assert.match(sql, /WHERE\s+d\.active/i);
    assert.doesNotMatch(sql, /device_configs/i);
  });

  it('⛔ takes the NEWEST parsed config per device, via DISTINCT ON with a matching ORDER BY', async () => {
    const pool = stubPool({ fleet: FIVE_FORTINETS, configs: FIVE_CONFIGS });
    await getFleetConformance(pool);
    const sql = configCall(pool).sql;
    assert.match(sql, /DISTINCT\s+ON\s*\(\s*c\.device_id\s*\)/i);
    // ⛔ The leading ORDER BY column has to be the DISTINCT ON column or
    // PostgreSQL refuses the statement; the second column is what makes the
    // surviving row the newest one rather than an arbitrary one.
    assert.match(sql, /ORDER\s+BY\s+c\.device_id\s*,\s*c\.collected_at\s+DESC/i);
    assert.match(sql, /c\.config_parsed\s+IS\s+NOT\s+NULL/i);
    assert.match(sql, /d\.active/i);
  });

  it('⛔ fetches the large payload exactly once, and only where it is used', async () => {
    // `config_parsed` is the cost of this page — ~5 MB across the live fleet,
    // with one firewall at ~1,160 kB. It belongs in ONE statement's select
    // list and in no other.
    const pool = stubPool({ fleet: FIVE_FORTINETS, configs: FIVE_CONFIGS });
    await getFleetConformance(pool);
    const cfg = configCall(pool).sql;
    const selectList = cfg.slice(cfg.search(/SELECT/i), cfg.search(/\bFROM\b/i));
    assert.equal((selectList.match(/config_parsed/g) || []).length, 1, 'the payload is selected twice');
    assert.doesNotMatch(fleetCall(pool).sql, /config_parsed/, 'the roster statement fetches the payload too');
    // ⛔ And the RAW text config is never fetched at all: it is a redacted blob
    // this comparison cannot address by path, and it is larger than the parsed
    // form it sits beside.
    assert.equal((CODE.match(/config_raw/g) || []).length, 0, 'the raw config is fetched');
  });

  it('⛔ is parameterised — no interpolation reaches either statement', () => {
    // Both statements are template literals, so the check is that neither
    // carries a substitution at all.
    const templates = CODE.match(/`[^`]*SELECT[^`]*`/g) || [];
    assert.ok(templates.length >= 2, 'expected both statements to be found');
    for (const t of templates) {
      assert.doesNotMatch(t, /\$\{/, 'a statement interpolates a value');
    }
    assert.match(CODE, /\$1::uuid\[\]/);
  });

  it('⛔ never names the raw syslog table', () => {
    // ~28M rows/day in daily partitions with no index that would serve this.
    assert.doesNotMatch(CODE, /syslog_events/);
  });

  it('⛔ takes its pool as a parameter and never builds one', () => {
    assert.doesNotMatch(CODE, /new\s+Pool/);
    assert.doesNotMatch(CODE, /require\(['"]pg['"]\)/);
    assert.match(CODE, /function\s+getFleetConformance\s*\(\s*pool/);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 3. deviceIds — "no filter" and "no devices" are opposite instructions
// ────────────────────────────────────────────────────────────────────────────

describe('deviceIds', () => {
  const paramsOf = (pool) => pool.calls.map((c) => c.params[0]);

  it('omitted means the whole active fleet — a NULL parameter, not an empty array', async () => {
    const pool = stubPool({ fleet: [], configs: [] });
    await getFleetConformance(pool);
    assert.deepEqual(paramsOf(pool), [null, null]);
  });

  it('⛔ an EMPTY array means no devices, and is passed through as one', async () => {
    const pool = stubPool({ fleet: [], configs: [] });
    await getFleetConformance(pool, { deviceIds: [] });
    assert.deepEqual(paramsOf(pool), [[], []]);
  });

  it('a list is passed to BOTH statements, so the payload fetch is scoped too', async () => {
    const pool = stubPool({ fleet: [], configs: [] });
    await getFleetConformance(pool, { deviceIds: ['f1', 'f2'] });
    assert.deepEqual(paramsOf(pool), [['f1', 'f2'], ['f1', 'f2']]);
  });

  it('a non-array or a non-string member cannot reach the statement', async () => {
    const pool = stubPool({ fleet: [], configs: [] });
    await getFleetConformance(pool, { deviceIds: 'f1' });
    assert.deepEqual(paramsOf(pool), [null, null]);

    const pool2 = stubPool({ fleet: [], configs: [] });
    await getFleetConformance(pool2, { deviceIds: ['f1', 7, null, '', { id: 'x' }] });
    assert.deepEqual(paramsOf(pool2), [['f1'], ['f1']]);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 4. The merge, and the engine's judgement arriving intact
// ────────────────────────────────────────────────────────────────────────────

describe('the engine’s answer arrives intact', () => {
  it('one cohort per (vendor, mgmt_method), and a lone firewall is its own', async () => {
    const pool = stubPool({
      fleet: [...FIVE_FORTINETS, TUG],
      configs: [...FIVE_CONFIGS, TUG_CONFIG],
    });
    const out = await getFleetConformance(pool, { now: AT });
    assert.deepEqual(out.cohorts.map((c) => c.cohortKey), ['fortinet/ssh', 'paloalto/ssh']);
    assert.equal(cohortNamed(out, 'fortinet/ssh').status, STATUS.MEASURED);
    assert.equal(cohortNamed(out, 'paloalto/ssh').status, STATUS.INSUFFICIENT_COHORT);
  });

  it('⛔ a cohort of one is insufficient_cohort WITH its limit sentence, never an empty measured one', async () => {
    const pool = stubPool({ fleet: [TUG], configs: [TUG_CONFIG] });
    const out = await getFleetConformance(pool, { now: AT });
    const c = cohortNamed(out, 'paloalto/ssh');
    assert.equal(c.status, STATUS.INSUFFICIENT_COHORT);
    assert.match(c.limit, /Nothing was compared/);
    assert.equal(out.summary.insufficientCohorts.length, 1);
    assert.equal(out.summary.devicesCompared, 0);
    assert.equal(out.summary.devicesInUnreportableCohorts, 1);
  });

  it('the value deviations the engine finds reach the caller, with both sides named', async () => {
    const pool = stubPool({ fleet: FIVE_FORTINETS, configs: FIVE_CONFIGS });
    const out = await getFleetConformance(pool, { now: AT });
    const c = cohortNamed(out, 'fortinet/ssh');
    assert.equal(c.valueDeviations.length, 3);
    const ports = c.valueDeviations.find((d) => d.path === 'global.admin-ssh-port');
    assert.equal(ports.summary, '1 of 5 differ');
    assert.match(ports.statement, /"22"/);
    assert.match(ports.statement, /"5022"/);
    assert.match(ports.statement, /OKF\(F2\)/);
    assert.equal(out.summary.devices[0].deviceName, 'OKF(F2)');
    assert.equal(out.summary.devices[0].valueMinorityCount, 3);
  });

  it('⛔ VALUE and PRESENCE stay separate all the way through this layer', async () => {
    // One firewall lacks a setting the other four report, and one reports a
    // different value. Two facts, two lists, and no third number anywhere.
    const fleet = FIVE_FORTINETS;
    const configs = [
      config('f1', { dns: { protocol: 'cleartext' } }),
      config('f2', { dns: { protocol: 'dot', 'server-hostname': 'a' } }),
      config('f3', { dns: { protocol: 'dot', 'server-hostname': 'a' } }),
      config('f4', { dns: { protocol: 'dot', 'server-hostname': 'a' } }),
      config('f5', { dns: { protocol: 'dot', 'server-hostname': 'a' } }),
    ];
    const out = await getFleetConformance(stubPool({ fleet, configs }), { now: AT });
    const c = cohortNamed(out, 'fortinet/ssh');
    assert.equal(c.valueDeviations.length, 1);
    assert.equal(c.presenceDeviations.length, 1);
    assert.equal(out.summary.valueDeviations, 1);
    assert.equal(out.summary.presenceDeviations, 1);
    // ⛔ No summed figure exists to be read as a total.
    const json = JSON.stringify(out.summary);
    assert.doesNotMatch(json, /"(deviations|totalDeviations|allDeviations)"/);
  });

  it('⛔ a firewall with NO config row is excluded and COUNTED, never dropped', async () => {
    // The whole reason the roster is driven from `devices`. A firewall SecVault
    // cannot read agrees with nothing and differs from nothing; uncounted, it
    // is the best-behaved member of its cohort.
    const pool = stubPool({
      fleet: [...FIVE_FORTINETS, device('f6', 'DARK', 'fortinet', 'ssh')],
      configs: FIVE_CONFIGS,
    });
    const out = await getFleetConformance(pool, { now: AT });
    const c = cohortNamed(out, 'fortinet/ssh');
    assert.equal(c.comparableCount, 5);
    assert.equal(c.excludedCount, 1);
    assert.equal(c.excluded[0].deviceName, 'DARK');
    assert.equal(c.excluded[0].reason, EXCLUSION.NO_CONFIG);
    assert.equal(out.summary.devicesExcluded, 1);
    assert.equal(out.summary.excluded[0].cohortKey, 'fortinet/ssh');
  });

  it('a firewall with no vendor or no access method is held and reported, not dropped', async () => {
    const pool = stubPool({
      fleet: [...FIVE_FORTINETS, device('x1', 'NOKEY', null, null)],
      configs: [...FIVE_CONFIGS, config('x1', { a: { b: 1 } })],
    });
    const out = await getFleetConformance(pool, { now: AT });
    assert.equal(out.summary.devicesExcluded, 1);
    assert.equal(out.summary.excluded[0].reason, EXCLUSION.NO_COHORT_KEY);
  });

  it('⛔ an empty parsed config is excluded as unusable, not read as agreement', async () => {
    const pool = stubPool({
      fleet: FIVE_FORTINETS,
      configs: [config('f1', {}), ...FIVE_CONFIGS.slice(1)],
    });
    const out = await getFleetConformance(pool, { now: AT });
    const c = cohortNamed(out, 'fortinet/ssh');
    assert.equal(c.excludedCount, 1);
    assert.equal(c.excluded[0].reason, EXCLUSION.UNUSABLE_CONFIG);
  });

  it('a config row for a device that is not in the roster is simply unused', async () => {
    const pool = stubPool({
      fleet: FIVE_FORTINETS,
      configs: [...FIVE_CONFIGS, config('ghost', { a: { b: 1 } })],
    });
    const out = await getFleetConformance(pool, { now: AT });
    assert.equal(out.summary.devicesCompared, 5);
    assert.equal(out.summary.devicesExcluded, 0);
  });

  it('⛔ the FIRST row per device wins, which is the newest one the ORDER BY put first', async () => {
    const pool = stubPool({
      fleet: [FIVE_FORTINETS[0], FIVE_FORTINETS[1], FIVE_FORTINETS[2]],
      configs: [
        config('f1', { dns: { protocol: 'new' } }, '2026-09-25T12:00:00.000Z'),
        config('f1', { dns: { protocol: 'old' } }, '2020-01-01T00:00:00.000Z'),
        config('f2', { dns: { protocol: 'new' } }),
        config('f3', { dns: { protocol: 'new' } }),
      ],
    });
    const out = await getFleetConformance(pool, { now: AT });
    const c = cohortNamed(out, 'fortinet/ssh');
    // Three firewalls all reporting the same value: compared, and no split of
    // three can reach the minority threshold.
    assert.equal(c.comparableCount, 3);
    assert.equal(c.status, STATUS.THRESHOLD_UNREACHABLE);
    assert.match(c.limit, /larger cohort/i);
  });

  it('tolerates a driver that returns no rows array at all', async () => {
    const pool = {
      calls: [],
      async query(sql, params) { this.calls.push({ sql, params }); return undefined; },
    };
    const out = await getFleetConformance(pool, { now: AT });
    assert.deepEqual(out.failures, []);
    assert.deepEqual(out.cohorts, []);
    assert.equal(out.summary.devicesCompared, 0);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 5. ⛔ A FAILED READ IS NOT A CLEAN FLEET — the case that regresses silently
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ a failed read reports itself, and never as agreement', () => {
  it('the roster statement throwing produces EMPTY cohorts WITH a named failure', async () => {
    const pool = stubPool({ fleet: new Error('roster is down'), configs: FIVE_CONFIGS });
    const out = await getFleetConformance(pool, { now: AT });
    assert.deepEqual(out.cohorts, []);
    assert.equal(out.failures.length, 1);
    assert.equal(out.failures[0].source, 'conformance_fleet');
    assert.match(out.failures[0].error, /roster is down/);
  });

  it('the configuration statement throwing produces EMPTY cohorts WITH a named failure', async () => {
    const pool = stubPool({ fleet: FIVE_FORTINETS, configs: new Error('payload is down') });
    const out = await getFleetConformance(pool, { now: AT });
    assert.deepEqual(out.cohorts, []);
    assert.equal(out.failures.length, 1);
    assert.equal(out.failures[0].source, 'conformance_configs');
    assert.match(out.failures[0].error, /payload is down/);
  });

  it('⛔ AND A BROKEN CONFIG READ MANUFACTURES NO EXCLUSIONS', async () => {
    // This is the dangerous half. With the roster still handed through, every
    // firewall would arrive with a null config and the engine would faithfully
    // report the whole fleet as having no collected configuration — a named,
    // counted, entirely fabricated finding that looks exactly like a
    // measurement. A count of 0 here beside a populated `failures` is the
    // honest shape.
    const pool = stubPool({ fleet: FIVE_FORTINETS, configs: new Error('payload is down') });
    const out = await getFleetConformance(pool, { now: AT });
    assert.equal(out.summary.devicesExcluded, 0);
    assert.deepEqual(out.summary.excluded, []);
    assert.equal(out.summary.devicesCompared, 0);
    assert.ok(out.failures.length > 0, 'the answer has to say why it is empty');
  });

  it('both statements throwing name both reads, never one', async () => {
    const pool = stubPool({ fleet: new Error('a'), configs: new Error('b') });
    const out = await getFleetConformance(pool, { now: AT });
    assert.deepEqual(out.failures.map((f) => f.source).sort(), ['conformance_configs', 'conformance_fleet']);
  });

  it('a thrown non-Error still reads as something', async () => {
    const pool = {
      calls: [],
      async query() { throw 'a string was thrown'; },
    };
    const out = await getFleetConformance(pool, { now: AT });
    assert.equal(out.failures.length, 2);
    for (const f of out.failures) assert.match(f.error, /a string was thrown/);
  });

  it('⛔ AN EMPTY FLEET AND A BROKEN READ ARE DISTINGUISHABLE, which is the whole point', async () => {
    const clean = await getFleetConformance(stubPool({ fleet: [], configs: [] }), { now: AT });
    const broken = await getFleetConformance(
      stubPool({ fleet: new Error('down'), configs: [] }),
      { now: AT },
    );
    // Identical everywhere a count is read…
    assert.deepEqual(clean.cohorts, broken.cohorts);
    assert.equal(clean.summary.valueDeviations, broken.summary.valueDeviations);
    assert.equal(clean.summary.devicesCompared, broken.summary.devicesCompared);
    // …and `failures` is the ONLY thing that tells them apart, which is why a
    // caller reads it first and withholds every count while it is non-empty.
    assert.deepEqual(clean.failures, []);
    assert.equal(broken.failures.length, 1);
  });

  it('⛔ a fleet that genuinely agrees still reports no failures, so the two can never be confused', async () => {
    const configs = FIVE_FORTINETS.map((d) => config(d.id, { dns: { protocol: 'dot' } }));
    const out = await getFleetConformance(stubPool({ fleet: FIVE_FORTINETS, configs }), { now: AT });
    assert.deepEqual(out.failures, []);
    assert.equal(out.summary.valueDeviations, 0);
    assert.equal(out.summary.presenceDeviations, 0);
    // ⛔ And it is a MEASURED zero: the cohort was compared and says so.
    assert.equal(cohortNamed(out, 'fortinet/ssh').status, STATUS.MEASURED);
    assert.ok(cohortNamed(out, 'fortinet/ssh').comparedPaths > 0);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 6. ⛔ NO JUDGEMENT IS RE-IMPLEMENTED HERE
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ the engine owns every decision', () => {
  it('this layer holds no threshold, no minority rule and no depth of its own', () => {
    for (const bad of [/MINORITY/, /minorityCeiling/, /0\.25/, /MAX_DEPTH\s*=/, /maxDepth\s*:/]) {
      assert.doesNotMatch(CODE, bad, `a policy leaked into the plumbing: ${bad}`);
    }
  });

  it('it does not sort or filter the engine’s output', () => {
    assert.doesNotMatch(CODE, /cohorts\.sort/);
    assert.doesNotMatch(CODE, /\.valueDeviations\b/);
    assert.doesNotMatch(CODE, /\.presenceDeviations\b/);
  });

  it('it calls the three engine entry points and nothing else', () => {
    assert.match(CODE, /buildCohorts\(/);
    assert.match(CODE, /findDeviations\)/);
    assert.match(CODE, /summariseConformance\(/);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 7. ⛔ MAJORITY IS NOT CORRECTNESS — the vocabulary of judgement is absent
// ────────────────────────────────────────────────────────────────────────────

const FORBIDDEN = [
  /\bmisconfig\w*/i,
  /\bwrong\b/i,
  /\bincorrect\w*/i,
  /\bnon-?compliant\b/i,
  /\bcompliant\b/i,
  /\bviolat\w*/i,
  /\bshould\b/i,
  /\bmust\b/i,
  /\bfix(es|ed|ing)?\b/i,
  /\bremediat\w*/i,
  /\bfault\w*/i,
  /\bbad\b/i,
  /\binvalid\b/i,
  /\bbreach\w*/i,
];

function everyString(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => everyString(v, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => everyString(v, out));
  return out;
}

describe('⛔ nothing this layer emits reads as a verdict', () => {
  it('no string in a full answer carries the vocabulary of judgement', async () => {
    const pool = stubPool({
      fleet: [...FIVE_FORTINETS, TUG, device('f6', 'DARK', 'fortinet', 'ssh'), device('x1', 'NOKEY', null, null)],
      configs: [...FIVE_CONFIGS, TUG_CONFIG, config('x1', { a: { b: 1 } })],
    });
    const out = await getFleetConformance(pool, { now: AT });
    const strings = everyString(out);
    assert.ok(strings.length > 40, `expected the states to produce prose, got ${strings.length}`);
    for (const s of strings) {
      for (const bad of FORBIDDEN) {
        assert.doesNotMatch(s, bad, `emitted string carries ${bad}: ${s}`);
      }
    }
  });

  it('⛔ and no string LITERAL in the source carries it either — comments stripped FIRST', () => {
    for (const bad of FORBIDDEN) {
      const hit = CODE.match(new RegExp(bad.source, 'gi'));
      assert.equal(hit, null, `source (comments stripped) carries ${bad}: ${hit}`);
    }
  });

  it('⛔ the stripper is proven, not assumed', () => {
    // The module header explains the refusal by naming the reading it refuses,
    // in as many words. Without a working stripper the scan above would go red
    // on that comment rather than green on nothing — and this is what makes
    // that impossible to mistake for the scan being pointless.
    assert.match(RAW_SRC, /misconfigured/i);
    assert.match(RAW_SRC, /\bwrong\b/i);
    assert.doesNotMatch(CODE, /misconfigured/i);
    assert.doesNotMatch(CODE, /\bwrong\b/i);
  });

  it('⛔ no score, no grade, no band and no percentage', async () => {
    const pool = stubPool({ fleet: [...FIVE_FORTINETS, TUG], configs: [...FIVE_CONFIGS, TUG_CONFIG] });
    const json = JSON.stringify(await getFleetConformance(pool, { now: AT }));
    assert.doesNotMatch(json, /"score/i);
    assert.doesNotMatch(json, /"(grade|band|rating|health|conformance_?pct)"/i);
    // ⛔ A conformance percentage would be a correctness claim by arithmetic:
    // it asks what share of a fleet is "right", which is the one question this
    // engine cannot answer.
    assert.doesNotMatch(json, /%/);
    assert.doesNotMatch(CODE, /\bpct\b|percent/i);
  });
});
