'use strict';
// Pins the rollup sweep-window arithmetic and the never-throws contract.
//
// ⛔ The window maths is the whole correctness story here. LogVault shipped a
// 2-hour recompute window and it silently and PERMANENTLY under-counted: an
// event that lands late (DB outage, ingest backpressure, or just the collector
// being down during a deploy — all routine) belongs to a bucket that has
// already scrolled out of the window, so that bucket was never revisited and
// the rollup was wrong forever, with no error anywhere. These tests pin the
// properties that stop that recurring.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  floorHour,
  sweepWindow,
  recomputeWindow,
  runRollupMaintenance,
  HOURLY_INSERT,
  RULE_INSERT,
} = require('../lib/syslog/rollups');

const NOW = new Date('2026-09-08T14:37:12.500Z');

describe('rollups: bucket boundaries are UTC hours', () => {
  it('floors to the start of the UTC hour', () => {
    assert.equal(floorHour(NOW).toISOString(), '2026-09-08T14:00:00.000Z');
  });

  it('is already floored for an exact hour', () => {
    const exact = new Date('2026-09-08T14:00:00.000Z');
    assert.equal(floorHour(exact).getTime(), exact.getTime());
  });
});

describe('rollups: sweepWindow', () => {
  it('⛔ includes the IN-PROGRESS hour, or the current hour is never populated', () => {
    // `to` must be the start of the NEXT hour. If it were the current hour,
    // the hour in progress would stay empty until it happened to roll over
    // between two cycles.
    const { to } = sweepWindow(NOW, 3);
    assert.equal(to.toISOString(), '2026-09-08T15:00:00.000Z');
  });

  it('covers the WHOLE earliest hour, not a partial one', () => {
    // A 3-hour lookback must start far enough back that the oldest hour is
    // fully re-aggregated; a partial bucket would be written as if complete.
    const { from, to } = sweepWindow(NOW, 3);
    assert.equal(from.toISOString(), '2026-09-08T11:00:00.000Z');
    const spanHours = (to - from) / 3600000;
    assert.equal(spanHours, 4, '3 requested hours + the in-progress one');
  });

  it('a WIDE window genuinely reaches back further than a recent one', () => {
    const recent = sweepWindow(NOW, 3);
    const wide = sweepWindow(NOW, 24);
    assert.ok(wide.from < recent.from, 'the wide sweep must cover strictly more history');
    assert.equal(wide.to.getTime(), recent.to.getTime(), 'both end at the same boundary');
    assert.equal((wide.to - wide.from) / 3600000, 25);
  });

  it('crosses a day boundary correctly', () => {
    const justAfterMidnight = new Date('2026-09-09T00:10:00Z');
    const { from, to } = sweepWindow(justAfterMidnight, 3);
    assert.equal(to.toISOString(), '2026-09-09T01:00:00.000Z');
    assert.equal(from.toISOString(), '2026-09-08T21:00:00.000Z');
  });

  it('never produces an inverted or empty window, whatever it is handed', () => {
    for (const h of [0, -5, null, undefined, NaN, 'x', 1.7]) {
      const { from, to } = sweepWindow(NOW, h);
      assert.ok(to > from, `hours=${JSON.stringify(h)} must still yield a forward window`);
    }
  });
});

describe('rollups: the SQL aggregates honestly', () => {
  it('⛔ sums byte counts rather than coalescing them to 0', () => {
    // sum() over all-NULL yields NULL, which is correct: a vendor that never
    // reports bytes must stay UNMEASURED, not aggregate to a confident zero.
    // A COALESCE(...,0) here would fabricate traffic volume.
    assert.match(HOURLY_INSERT, /sum\(bytes_sent\)/);
    assert.doesNotMatch(HOURLY_INSERT, /coalesce\s*\(\s*sum\(bytes_sent\)\s*,\s*0\s*\)/i);
    assert.match(RULE_INSERT, /sum\(bytes_sent\)/);
    assert.doesNotMatch(RULE_INSERT, /coalesce\s*\(\s*sum\(bytes_sent\)\s*,\s*0\s*\)/i);
  });

  it('only rolls up rows that actually identify a rule', () => {
    // A NULL-rule bucket would read like a real rule in the hit-count view.
    assert.match(RULE_INSERT, /rule_id IS NOT NULL OR rule_uuid IS NOT NULL OR rule_name IS NOT NULL/);
  });

  it('counts events rather than trusting a stored counter', () => {
    assert.match(HOURLY_INSERT, /count\(\*\)/);
    assert.match(RULE_INSERT, /count\(\*\)/);
  });
});

// A stub pool that records the SQL it is handed. No database is touched.
//
// NOTE: the SQL constants are template literals that begin with a newline and
// indentation, so `behaviour` is given the TRIMMED text. Passing the raw string
// meant every `startsWith('INSERT ...')` silently matched nothing and the
// failure-path tests passed vacuously — the stub, not the code, was wrong.
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

describe('rollups: recomputeWindow never throws and is DELETE-then-INSERT', () => {
  it('deletes the bucket range before inserting it, inside a transaction', async () => {
    const pool = stubPool();
    const r = await recomputeWindow(pool, new Date('2026-09-08T10:00:00Z'), new Date('2026-09-08T14:00:00Z'));
    assert.equal(r.ok, true);
    const sqls = pool.calls.map((c) => c.sql);
    const firstDelete = sqls.findIndex((s) => s.startsWith('DELETE FROM syslog_rollup_hourly'));
    const firstInsert = sqls.findIndex((s) => s.startsWith('INSERT INTO syslog_rollup_hourly'));
    assert.ok(firstDelete >= 0 && firstInsert >= 0);
    assert.ok(firstDelete < firstInsert, 'the bucket must be cleared before it is rebuilt');
    assert.ok(sqls.includes('BEGIN'), 'a reader must never see a bucket mid-rebuild');
    assert.ok(sqls.includes('COMMIT'));
  });

  it('rebuilds BOTH rollups from the same window', async () => {
    const pool = stubPool();
    await recomputeWindow(pool, new Date('2026-09-08T10:00:00Z'), new Date('2026-09-08T14:00:00Z'));
    const sqls = pool.calls.map((c) => c.sql).join('\n');
    assert.match(sqls, /INSERT INTO syslog_rollup_hourly/);
    assert.match(sqls, /INSERT INTO syslog_rule_hits_hourly/);
  });

  it('⛔ returns the error instead of throwing — one bad sweep must not kill the collector', async () => {
    const pool = stubPool((sql) => {
      if (String(sql).startsWith('INSERT INTO syslog_rollup_hourly')) throw new Error('deadlock detected');
      return { rowCount: 0, rows: [] };
    });
    const r = await recomputeWindow(pool, new Date('2026-09-08T10:00:00Z'), new Date('2026-09-08T14:00:00Z'));
    assert.equal(r.ok, false);
    assert.match(r.error, /deadlock/);
  });

  it('rolls back rather than leaving a bucket deleted-but-not-rebuilt', async () => {
    const pool = stubPool((sql) => {
      if (String(sql).startsWith('INSERT INTO syslog_rollup_hourly')) throw new Error('boom');
      return { rowCount: 0, rows: [] };
    });
    await recomputeWindow(pool, new Date('2026-09-08T10:00:00Z'), new Date('2026-09-08T14:00:00Z'));
    assert.ok(pool.calls.some((c) => c.sql === 'ROLLBACK'), 'a failed rebuild must not leave the hour empty');
  });

  it('always releases the client, even on failure', async () => {
    const pool = stubPool(() => { throw new Error('nope'); });
    await recomputeWindow(pool, new Date(), new Date());
    assert.ok(pool.calls.some((c) => c.sql === '__released__'), 'a leaked client would exhaust the pool');
  });

  it('handles a missing pool without throwing', async () => {
    const r = await recomputeWindow(null, new Date(), new Date());
    assert.equal(r.ok, false);
    assert.match(r.error, /no pool/);
  });
});

describe('rollups: runRollupMaintenance tiers', () => {
  it('labels the tier and uses the wider lookback when wide', async () => {
    const pool = stubPool();
    const wide = await runRollupMaintenance(pool, { now: NOW, wide: true, lookbackHours: 24, recentHours: 3 });
    const recent = await runRollupMaintenance(pool, { now: NOW, wide: false, lookbackHours: 24, recentHours: 3 });
    assert.equal(wide.tier, 'wide');
    assert.equal(wide.hours, 24);
    assert.equal(recent.tier, 'recent');
    assert.equal(recent.hours, 3);
    assert.ok(wide.from < recent.from, 'the wide tier must actually reach back further');
  });
});
