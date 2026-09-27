'use strict';

// tests/changeOutcomeData.test.js — pins lib/engines/changeOutcomeData.js, the
// plumbing half of A7 ("what followed a configuration change").
//
// WHY THIS FILE EXISTS: the engine it feeds answers a question whose common
// honest answer is "nothing distinguishable". That makes a SHORT or EMPTY answer
// indistinguishable from the real result, so the case at the centre of this file
// is the one tests/README.md names: the failed read. A throwing query here must
// never produce the same shape as a firewall nobody has touched, and it must
// never produce the same shape as a fleet whose changes were all quiet.
//
// ⛔ NO DATABASE. `getChangeOutcomes(pool, opts)` only ever calls
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

const dataModule = require('../lib/engines/changeOutcomeData');
const { getChangeOutcomes, getDeviceChangeOutcome } = dataModule;
const { VERDICTS, DEFAULT_WINDOW_HOURS } = require('../lib/engines/changeOutcome');

const MODULE_PATH = path.join(__dirname, '..', 'lib', 'engines', 'changeOutcomeData.js');
const SRC = fs.readFileSync(MODULE_PATH, 'utf8');

// ⛔ EVERY 'must NOT contain' ASSERTION BELOW RUNS AGAINST SOURCE WITH COMMENTS
// REMOVED. This repo has been bitten more than once by a source scan satisfied
// by the very comment explaining the thing it was hunting — and the module under
// test documents, in prose, the table it must never query. Stripping is crude on
// purpose and only ever feeds a doesNotMatch, where over-removal can lose
// coverage but can never invent a failure.
const BLOCK_COMMENT = new RegExp('/\\*[\\s\\S]*?\\*/', 'g');
const LINE_COMMENT = new RegExp('(^|[\\s{(;,])//[^\\n]*', 'g');
const stripComments = (src) =>
  String(src).replace(BLOCK_COMMENT, ' ').replace(LINE_COMMENT, '$1 ');

const CODE = stripComments(SRC);

// ⛔ The causal vocabulary this feature may never use. Co-occurrence, never
// causation: a firewall change and a traffic movement are two facts in sequence.
const CAUSAL = [
  /\bcaused\b/i,
  /\bbecause\b/i,
  /\bdue to\b/i,
  /\bresulted in\b/i,
  /impact/i,
  /\bled to\b/i,
  /\bbroke\b/i,
];

// ⛔ The scoring vocabulary. There is no score, no grade, no share of changes
// marked as fine, and no risk number anywhere in this feature.
const SCORING = [/score/i, /grade/i, /\brisk/i, /\bsafe/i, /percent/i];

// --------------------------------------------------------------------------
// Stub pool
// --------------------------------------------------------------------------

/**
 * ⛔ THE STUB ROUTES ON THE STATEMENT, AND THE ORDER IS LOAD-BEARING. The
 * changes statement JOINs `devices d`, so a route keyed on that phrase would
 * hand the device fixture to the changes query and every verdict assertion
 * below would be measuring the stub. `config_diffs` is checked first (only the
 * changes statement has it), then `date_trunc` (only the series statement has
 * it), and only then the driver.
 *
 * An unrouted statement returns NO rows deliberately: a query this file has not
 * thought about must read as "nothing there" rather than inherit another
 * source's fixture.
 *
 * @param {object} fixtures
 * @param {object[]|Error} [fixtures.devices]
 * @param {object[]|Error} [fixtures.series]
 * @param {object[]|Error} [fixtures.changes]
 */
function stubPool(fixtures = {}) {
  const calls = [];
  const give = (v) => {
    if (v instanceof Error) throw v;
    const rows = (v || []).map((r) => ({ ...r }));
    return { rows, rowCount: rows.length };
  };
  return {
    calls,
    async query(sql, params) {
      const text = String(sql);
      calls.push({ sql: text, params });
      if (/config_diffs/.test(text)) return give(fixtures.changes);
      if (/date_trunc/.test(text)) return give(fixtures.series);
      if (/FROM\s+devices\s+d\b/i.test(text)) return give(fixtures.devices);
      return give([]);
    },
  };
}

const sqlFor = (pool, re) => {
  const hit = pool.calls.find((c) => re.test(c.sql));
  assert.ok(hit, `expected a statement matching ${re}`);
  return hit;
};

// --------------------------------------------------------------------------
// Fixtures
// --------------------------------------------------------------------------

const DEV = { id: 'dev-1', name: 'TSR-TL', vendor: 'fortinet' };
const QUIET = { id: 'dev-2', name: 'PAKFood', vendor: 'fortinet' };

const NOW = '2026-09-27T09:00:00.000Z';

/**
 * 21 consecutive days whose volume alternates, so the band is real but tight.
 * ⛔ 21 days gives 20 day-pairs, comfortably over MIN_BASELINE_PAIRS — a series
 * one pair short would make every assertion below read `insufficient_baseline`
 * for a reason that has nothing to do with what is being tested.
 *
 * Event counts arrive as STRINGS, which is what node-postgres does with a
 * `bigint` sum. That is deliberate: a test using numbers would not exercise the
 * one conversion this module owns.
 */
function series(deviceId) {
  const rows = [];
  for (let i = 1; i <= 21; i += 1) {
    const day = `2026-09-${String(i).padStart(2, '0')}T00:00:00.000Z`;
    rows.push({ device_id: deviceId, day, events: String(i % 2 === 0 ? 1100 : 1000) });
  }
  return rows;
}

const change = (over = {}) => ({
  id: 'chg-1',
  device_id: DEV.id,
  detected_at: '2026-09-10T12:00:00.000Z',
  change_summary: '3 rules modified',
  before_events: '1000',
  after_events: '1040',
  ...over,
});

// --------------------------------------------------------------------------

describe('changeOutcomeData — the statements it builds', () => {
  it('drives from devices, reads the hourly rollup, and reads config_diffs', async () => {
    const pool = stubPool({ devices: [DEV], series: series(DEV.id), changes: [change()] });
    await getChangeOutcomes(pool, { now: NOW });

    assert.equal(pool.calls.length, 3, 'three statements, one per source');
    assert.match(sqlFor(pool, /FROM\s+devices\s+d/i).sql, /d\.active/);
    assert.match(sqlFor(pool, /date_trunc/).sql, /syslog_rollup_hourly/);
    assert.match(sqlFor(pool, /date_trunc/).sql, /sum\(s\.event_count\)/);
    const changes = sqlFor(pool, /config_diffs/).sql;
    assert.match(changes, /cd\.change_summary/);
    assert.match(changes, /cd\.detected_at/);
    assert.match(changes, /syslog_rollup_hourly/);
  });

  it('⛔ never names the raw syslog event table, and the comment stripper is proven', () => {
    // The stripper is PROVEN before it is trusted: the module's own prose uses a
    // banned word, so a scan that read comments would report a false hit here.
    assert.match(SRC, /because/, 'expected the prose to carry a word the scan bans');
    assert.doesNotMatch(CODE, /because/, 'the stripper must remove that prose');
    assert.doesNotMatch(CODE, /syslog_events/);
  });

  it('⛔ has no `changes` column on config_diffs — the column does not exist', () => {
    assert.doesNotMatch(CODE, /cd\.changes\b/);
  });

  it('⛔ every statement is a named constant, never an interpolated template', () => {
    const named = CODE.match(/pool\.query\(\s*[A-Z_]+_SQL\s*,/g) || [];
    assert.equal(named.length, 3);
    assert.doesNotMatch(CODE, /pool\.query\(\s*`/, 'no inline SQL template literal');
    assert.doesNotMatch(CODE, /pool\.query\(\s*['"]/, 'no inline SQL string');
  });

  it('⛔ never instantiates a Pool — it takes one as a parameter', () => {
    assert.doesNotMatch(CODE, /new\s+Pool\b/);
    assert.doesNotMatch(CODE, /require\(['"]pg['"]\)/);
  });

  it('uses no causal or scoring vocabulary in any string it emits', () => {
    for (const re of CAUSAL) assert.doesNotMatch(CODE, re, `causal vocabulary: ${re}`);
    for (const re of SCORING) assert.doesNotMatch(CODE, re, `scoring vocabulary: ${re}`);
  });
});

describe('changeOutcomeData — the window parameter', () => {
  const windowParam = async (windowHours) => {
    const pool = stubPool({ devices: [DEV], series: series(DEV.id), changes: [change()] });
    const answer = await getChangeOutcomes(pool, { windowHours, now: NOW });
    return { param: sqlFor(pool, /config_diffs/).params[1], answer };
  };

  it('defaults to the engine default and passes it as a parameter', async () => {
    const { param, answer } = await windowParam(undefined);
    assert.equal(param, DEFAULT_WINDOW_HOURS);
    assert.equal(answer.windowHours, DEFAULT_WINDOW_HOURS);
  });

  it('is applied as an interval multiplier, not string-built', () => {
    assert.match(CODE, /\$2::int \* interval '1 hour'/);
  });

  it('accepts a value inside the bound', async () => {
    const { param, answer } = await windowParam(48);
    assert.equal(param, 48);
    assert.equal(answer.windowHours, 48);
  });

  it('⛔ falls back to the default for anything outside the bound or unparseable', async () => {
    for (const bad of [0, -12, 1000, 'sideways', null, {}, NaN]) {
      const { param } = await windowParam(bad);
      assert.equal(param, DEFAULT_WINDOW_HOURS, `rejected: ${String(bad)}`);
    }
  });
});

describe('changeOutcomeData — the deviceIds asymmetry', () => {
  it('no filter passes null, so the statement covers the active fleet', async () => {
    const pool = stubPool({ devices: [DEV], series: series(DEV.id), changes: [change()] });
    await getChangeOutcomes(pool, { now: NOW });
    assert.equal(sqlFor(pool, /FROM\s+devices\s+d/i).params[0], null);
  });

  it('⛔ an EMPTY list means no firewalls, issues no query, and is NOT a failure', async () => {
    const pool = stubPool({ devices: [DEV], series: series(DEV.id), changes: [change()] });
    const answer = await getChangeOutcomes(pool, { deviceIds: [], now: NOW });
    assert.equal(pool.calls.length, 0);
    assert.deepEqual(answer.devices, []);
    assert.deepEqual(answer.failures, []);
    assert.equal(answer.summary.changes, 0);
  });

  it('a populated list is passed through as a uuid[] parameter', async () => {
    const pool = stubPool({ devices: [DEV], series: series(DEV.id), changes: [change()] });
    await getChangeOutcomes(pool, { deviceIds: [DEV.id], now: NOW });
    for (const re of [/FROM\s+devices\s+d/i, /date_trunc/, /config_diffs/]) {
      assert.deepEqual(sqlFor(pool, re).params[0], [DEV.id]);
    }
  });
});

describe('changeOutcomeData — what it does with what comes back', () => {
  it('a judged change carries its verdict and the basis it was judged on', async () => {
    const pool = stubPool({ devices: [DEV], series: series(DEV.id), changes: [change()] });
    const answer = await getChangeOutcomes(pool, { now: NOW });

    assert.equal(answer.devices.length, 1);
    const d = answer.devices[0];
    assert.equal(d.deviceId, DEV.id);
    assert.equal(d.deviceName, 'TSR-TL');
    assert.equal(d.changeCount, 1);
    const c = d.changes[0];
    assert.equal(c.verdict, VERDICTS.INDISTINGUISHABLE);
    assert.equal(c.summary, '3 rules modified');
    assert.ok(typeof c.largerThanDays === 'number');
    assert.ok(typeof c.ordinaryDays === 'number');
    assert.ok(d.baseline.usable);
    assert.ok(d.baseline.bandPct > 0);
  });

  it('a movement outside the band reports exceeded_normal_variation', async () => {
    const pool = stubPool({
      devices: [DEV],
      series: series(DEV.id),
      changes: [change({ after_events: '9000' })],
    });
    const answer = await getChangeOutcomes(pool, { now: NOW });
    assert.equal(answer.devices[0].changes[0].verdict, VERDICTS.EXCEEDED);
    assert.equal(answer.summary.byVerdict[VERDICTS.EXCEEDED], 1);
  });

  it('⛔ a window reaching outside the collected period is window_incomplete', async () => {
    const pool = stubPool({
      devices: [DEV],
      series: series(DEV.id),
      // Six hours into the first collected day: the 24h "before" window lies in
      // hours SecVault was not collecting, which is the +814% artefact the
      // engine's own header records.
      changes: [change({ detected_at: '2026-09-01T06:00:00.000Z', after_events: '9000' })],
    });
    const answer = await getChangeOutcomes(pool, { now: NOW });
    const c = answer.devices[0].changes[0];
    assert.equal(c.verdict, VERDICTS.WINDOW_INCOMPLETE);
    assert.equal(c.windowComplete, false);
    assert.equal(c.deltaPct, null, 'no delta is published for an incomplete window');
  });

  it('⛔ a NULL side of the window is no_traffic_window, never a delta', async () => {
    const pool = stubPool({
      devices: [DEV],
      series: series(DEV.id),
      changes: [change({ before_events: null })],
    });
    const answer = await getChangeOutcomes(pool, { now: NOW });
    const c = answer.devices[0].changes[0];
    assert.equal(c.verdict, VERDICTS.NO_TRAFFIC_WINDOW);
    assert.equal(c.deltaPct, null);
  });

  it('⛔ a firewall sending no syslog gets a row and insufficient_baseline', async () => {
    // PAKFood, live: it sends nothing, so no band can be built. It must still
    // appear — dropping it would make the firewall whose verdicts are least
    // trustworthy the one nobody sees.
    const pool = stubPool({
      devices: [DEV, QUIET],
      series: series(DEV.id),
      changes: [change(), change({ id: 'chg-2', device_id: QUIET.id })],
    });
    const answer = await getChangeOutcomes(pool, { now: NOW });
    assert.equal(answer.devices.length, 2);
    const quiet = answer.devices.find((d) => d.deviceId === QUIET.id);
    assert.equal(quiet.baseline.usable, false);
    assert.equal(quiet.baseline.reason, VERDICTS.INSUFFICIENT_BASELINE);
    // ⛔ THE DEVICE-LEVEL STATE AND THE PER-CHANGE VERDICT ARE DIFFERENT FACTS,
    // and this is the live shape. With no series at all there is no observed
    // period either, so the engine — which tests the WINDOW before the traffic —
    // reports `window_incomplete` per change while the firewall itself carries
    // `insufficient_baseline`. A view that rendered only the per-change verdict
    // would never say that this firewall has no band, so both are pinned.
    assert.equal(quiet.changes[0].verdict, VERDICTS.WINDOW_INCOMPLETE);
    assert.equal(quiet.observedFrom, null);
    assert.equal(answer.summary.devicesWithUsableBaseline, 1);
    assert.equal(answer.summary.devicesWithoutBaseline, 1);
  });

  it('a firewall with no change at all is reported with no change, not dropped', async () => {
    const pool = stubPool({ devices: [DEV], series: series(DEV.id), changes: [] });
    const answer = await getChangeOutcomes(pool, { now: NOW });
    assert.equal(answer.devices.length, 1);
    assert.equal(answer.devices[0].changeCount, 0);
    assert.equal(answer.summary.changes, 0);
    assert.deepEqual(answer.failures, []);
  });

  it('carries the engine claim through and stamps the injected clock', async () => {
    const pool = stubPool({ devices: [DEV], series: series(DEV.id), changes: [change()] });
    const answer = await getChangeOutcomes(pool, { now: NOW });
    assert.equal(answer.generatedAt, NOW);
    assert.match(answer.summary.claim, /two facts in sequence/);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// ⛔ THE CASE THAT REGRESSES SILENTLY
// ──────────────────────────────────────────────────────────────────────────

describe('changeOutcomeData — a failed read is its own answer', () => {
  const broken = new Error('relation does not exist');

  it('reports which source failed, one entry per source', async () => {
    for (const [key, source] of [
      ['devices', 'devices'],
      ['series', 'traffic_series'],
      ['changes', 'config_changes'],
    ]) {
      const fixtures = { devices: [DEV], series: series(DEV.id), changes: [change()] };
      fixtures[key] = broken;
      const answer = await getChangeOutcomes(stubPool(fixtures), { now: NOW });
      assert.equal(answer.failures.length, 1, `one failure for ${source}`);
      assert.equal(answer.failures[0].source, source);
      assert.match(answer.failures[0].error, /relation does not exist/);
    }
  });

  it('⛔ assesses NOTHING while any source is missing', async () => {
    const answer = await getChangeOutcomes(
      stubPool({ devices: [DEV], series: broken, changes: [change()] }),
      { now: NOW },
    );
    assert.deepEqual(answer.devices, []);
    // ⛔ Assessing on a partial read would report `insufficient_baseline` for
    // every firewall, which is a claim about that firewall's history rather than
    // about our failed read.
    assert.equal(answer.summary.devicesWithoutBaseline, 0);
    assert.equal(answer.summary.changes, 0);
  });

  it('⛔ a broken read, an empty fleet, and a fleet with nothing exceeded are THREE distinct answers', async () => {
    const brokenAnswer = await getChangeOutcomes(
      stubPool({ devices: broken, series: series(DEV.id), changes: [change()] }),
      { now: NOW },
    );
    const noChanges = await getChangeOutcomes(
      stubPool({ devices: [DEV], series: series(DEV.id), changes: [] }),
      { now: NOW },
    );
    const nothingExceeded = await getChangeOutcomes(
      stubPool({ devices: [DEV], series: series(DEV.id), changes: [change()] }),
      { now: NOW },
    );

    // 1. The broken read is the ONLY one carrying a failure.
    assert.equal(brokenAnswer.failures.length, 1);
    assert.deepEqual(noChanges.failures, []);
    assert.deepEqual(nothingExceeded.failures, []);

    // 2. "No changes" still names the firewall; the broken read names nothing.
    assert.equal(brokenAnswer.devices.length, 0);
    assert.equal(noChanges.devices.length, 1);
    assert.equal(nothingExceeded.devices.length, 1);

    // 3. "Nothing exceeded" is a MEASUREMENT: a judged change with a zero
    //    exceeded count. The other two judged nothing at all, and the three
    //    must not collapse onto the same shape.
    const judged = (a) => (a.summary.byVerdict[VERDICTS.INDISTINGUISHABLE] || 0)
      + (a.summary.byVerdict[VERDICTS.EXCEEDED] || 0);
    assert.equal(judged(nothingExceeded), 1);
    assert.equal(judged(noChanges), 0);
    assert.equal(judged(brokenAnswer), 0);
    assert.equal(nothingExceeded.summary.byVerdict[VERDICTS.EXCEEDED], 0);
  });
});

describe('getDeviceChangeOutcome', () => {
  it('scopes every statement to the one firewall and returns it directly', async () => {
    const pool = stubPool({ devices: [DEV], series: series(DEV.id), changes: [change()] });
    const answer = await getDeviceChangeOutcome(pool, DEV.id, { now: NOW });
    assert.equal(answer.device.deviceId, DEV.id);
    assert.deepEqual(sqlFor(pool, /config_diffs/).params[0], [DEV.id]);
  });

  it('⛔ a missing id is a FAILURE, and issues no query at all', async () => {
    for (const bad of [undefined, null, '', 0, {}]) {
      const pool = stubPool({ devices: [DEV], series: series(DEV.id), changes: [change()] });
      const answer = await getDeviceChangeOutcome(pool, bad, { now: NOW });
      // ⛔ The dangerous alternative is a bare `undefined` reaching the
      // statements, which this module defines as THE WHOLE FLEET — another
      // firewall's changes printed under this one's name.
      assert.equal(pool.calls.length, 0, `no query for ${String(bad)}`);
      assert.equal(answer.device, null);
      assert.equal(answer.failures.length, 1);
      assert.equal(answer.failures[0].source, 'device');
    }
  });

  it('returns null for a firewall the driver did not list, without inventing one', async () => {
    const pool = stubPool({ devices: [], series: [], changes: [] });
    const answer = await getDeviceChangeOutcome(pool, 'dev-missing', { now: NOW });
    assert.equal(answer.device, null);
    assert.deepEqual(answer.failures, []);
  });
});
