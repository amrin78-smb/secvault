'use strict';
// Pins the two things the 2026-09-09 wide-sweep investigation added: the sweep
// reports where its own time went, and the window scan is planned with seq
// scans penalised.
//
// ⛔ WHY A TEST FOR A LOG LINE. The wide sweep took ~900s per pass and overran
// its cycle for weeks. The only symptom was `rollup skipped - previous sweep
// still running`, which names no pass, so the investigation had to profile the
// live database from scratch to learn that the MAJORITY of the time was the
// temp-table build and not any of the ten aggregations. That is the same class
// of blind spot the row COUNTS were already derived to avoid — a sweep that
// commits successfully while something inside it silently degrades. Timing is
// derived from the same list as the counts precisely so an eleventh rollup
// cannot be added without reporting both.
//
// ⛔ WHY A TEST FOR A PLANNER HINT. Measured live over a 3-hour window
// (14,187,569 rows): the build took 167,925 ms as a Seq Scan reading all
// 1,881,660 pages of the daily partition, and 30,314 ms as a Bitmap Heap Scan
// reading the 588,017 that actually hold the window. Whole sweep 268,531 ms ->
// 135,085 ms. That gain is invisible in every unit-testable output — same rows,
// same counts, same numbers — so nothing but this test stops it being tidied
// away as a stray SET.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  recomputeWindow,
  WINDOW_TEMP,
  SEQSCAN_OFF,
  SEQSCAN_ON,
} = require('../lib/syslog/rollups');

const FROM = new Date('2026-09-08T10:00:00Z');
const TO = new Date('2026-09-08T14:00:00Z');

// Same stub as tests/rollups.test.js: records the SQL, touches no database.
function stubPool(behaviour) {
  const calls = [];
  const client = {
    query: async (sql, params) => {
      const trimmed = String(sql).trim();
      calls.push({ sql: trimmed, params });
      if (typeof behaviour === 'function') return behaviour(trimmed);
      return { rowCount: 1, rows: [] };
    },
    release: () => { calls.push({ sql: '__released__' }); },
  };
  return { calls, connect: async () => client };
}

describe('rollups: the sweep reports where its own time went', () => {
  it('⛔ times EVERY pass, derived from the same list as the row counts', async () => {
    const pool = stubPool();
    const r = await recomputeWindow(pool, FROM, TO);
    assert.equal(r.ok, true);
    const passes = Object.keys(r).filter((k) => k.endsWith('Rows'));
    assert.ok(passes.length >= 10, 'sanity: every rollup returns a row count');
    for (const k of passes) {
      const name = k.slice(0, -4);
      assert.equal(
        typeof r.timings[name], 'number',
        `${name} reports a row count but no duration — a pass that silently `
        + 'slows down is exactly what the 900s sweep looked like'
      );
    }
  });

  it('⛔ times the temp-table BUILD separately, because that is the majority of it', async () => {
    // Measured live: build 167,925ms of a 268,531ms 3h sweep (63%). No log
    // line reported it at all, so the cost was attributed to "the rollups".
    const pool = stubPool();
    const r = await recomputeWindow(pool, FROM, TO);
    for (const k of ['build', 'analyze', 'deletes']) {
      assert.equal(typeof r.timings[k], 'number', `the shared prologue must report ${k}`);
    }
  });

  it('still returns the timings it managed to collect when a pass fails', async () => {
    // recomputeWindow never throws; a failed sweep is where the timings are
    // most wanted, so they must survive the failure path.
    const pool = stubPool((sql) => {
      if (sql.startsWith('INSERT INTO syslog_rollup_hourly')) throw new Error('boom');
      return { rowCount: 0, rows: [] };
    });
    const r = await recomputeWindow(pool, FROM, TO);
    assert.equal(r.ok, false);
    assert.equal(typeof r.timings.build, 'number');
  });
});

describe('rollups: the window scan penalises seq scans, and ONLY the window scan', () => {
  it('⛔ is SET LOCAL, so it cannot outlive the transaction onto a pooled client', () => {
    // A plain SET would ride the connection back into the pool and re-plan
    // every later query on it — the same class of bug as a leaked temp table.
    assert.match(SEQSCAN_OFF, /^SET LOCAL enable_seqscan\s*=\s*off$/);
    assert.match(SEQSCAN_ON, /^SET LOCAL enable_seqscan\s*=\s*on$/);
  });

  it('⛔ wraps the CREATE TEMP TABLE and nothing else', async () => {
    const pool = stubPool();
    await recomputeWindow(pool, FROM, TO);
    const sqls = pool.calls.map((c) => c.sql);
    const off = sqls.indexOf(SEQSCAN_OFF);
    const build = sqls.findIndex((s) => s.startsWith('CREATE TEMP TABLE rollup_src'));
    const on = sqls.indexOf(SEQSCAN_ON);
    const firstInsert = sqls.findIndex((s) => s.startsWith('INSERT INTO syslog_'));
    const firstDelete = sqls.findIndex((s) => s.startsWith('DELETE FROM syslog_'));
    assert.ok(off >= 0 && on >= 0, 'the hint must be applied and then restored');
    assert.ok(off < build, 'the hint must be set BEFORE the scan it was measured against');
    assert.ok(on > build, 'and restored after it');
    // ⛔ The ten passes aggregate rollup_src, which has NO indexes, and the
    // inbound pass joins tiny tables where a seq scan is genuinely correct.
    // Leaving the hint set would mis-plan those for no measured gain.
    assert.ok(on < firstInsert, 'no rollup pass may run with seq scans penalised');
    assert.ok(on < firstDelete, 'no DELETE may run with seq scans penalised');
  });

  it('⛔ the hint carries no window parameters — the window still lives in ONE statement', async () => {
    // tests/rollups.test.js counts the statements carrying [from, to]. A hint
    // that took parameters would be a second place the window could diverge.
    const pool = stubPool();
    await recomputeWindow(pool, FROM, TO);
    for (const c of pool.calls.filter((x) => x.sql.startsWith('SET LOCAL'))) {
      assert.equal(c.params, undefined);
    }
    assert.match(WINDOW_TEMP, /received_at >= \$1 AND received_at < \$2/);
  });
});
