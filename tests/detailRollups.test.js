'use strict';
// Pins the three DETAIL rollups (per-host / per-application / blocked
// destination) added 2026-09-08, and their bounded retention.
//
// These are separate from tests/rollups.test.js because they answer a different
// question. The two permanent rollups are about arithmetic correctness over a
// window; these are about CARDINALITY and HONESTY:
//
//   - they are keyed on high-cardinality values (a host, an application), so
//     they must be trimmed, and the trim must not silently fail;
//   - they rank things, so a byte total that is "unmeasurable" must not be
//     aggregated into a confident zero — that would sort the vendors which do
//     not report bytes to the bottom of a "top talkers by volume" list and read
//     as "quiet" when the truth is "we cannot tell".

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  recomputeWindow,
  trimDetailRollups,
  TALKER_INSERT,
  APP_INSERT,
  BLOCKED_INSERT,
} = require('../lib/syslog/rollups');

const FROM = new Date('2026-09-08T10:00:00Z');
const TO = new Date('2026-09-08T14:00:00Z');

// Mirrors tests/rollups.test.js's stub: the SQL constants are template literals
// that begin with a newline, so the stub hands `behaviour` the TRIMMED text.
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

describe('detail rollups: byte totals stay tri-state', () => {
  it('⛔ sums bytes only WHERE bytes_summable', () => {
    // Without the FILTER these tables would add FortiOS running cumulative
    // session counters together — the same bug that reported a single device
    // at 50,565 GB in two hours.
    for (const [name, sql] of [['talker', TALKER_INSERT], ['app', APP_INSERT]]) {
      assert.match(sql, /sum\(bytes_sent\) FILTER \(WHERE bytes_summable\)/, name);
      assert.match(sql, /sum\(bytes_received\) FILTER \(WHERE bytes_summable\)/, name);
    }
  });

  it('⛔ never coalesces an unmeasurable byte total to 0', () => {
    for (const [name, sql] of [['talker', TALKER_INSERT], ['app', APP_INSERT]]) {
      assert.doesNotMatch(sql, /coalesce\s*\(\s*sum\(bytes_/i, name);
    }
  });

  it('the blocked-destination rollup carries no byte columns at all', () => {
    // It answers "how often", not "how much" — a byte column there would be a
    // number nobody could interpret.
    assert.doesNotMatch(BLOCKED_INSERT, /bytes_/);
    assert.match(BLOCKED_INSERT, /count\(\*\)/);
  });
});

describe('detail rollups: each excludes rows it cannot describe', () => {
  it('the host rollup requires a real source address', () => {
    // A traffic log with no src_ip is still a real event, but grouping it
    // would create a NULL-host row that ranks like a real host.
    assert.match(TALKER_INSERT, /(WHERE|AND) src_ip IS NOT NULL/);
  });

  it('the application rollup requires an application OR a protocol', () => {
    assert.match(APP_INSERT, /application IS NOT NULL OR protocol IS NOT NULL/);
  });

  it('⛔ the blocked-destination rollup stores ONLY denied traffic', () => {
    // This is what bounds the table. Storing every destination would make it
    // the largest table in the database — measured 15,546 distinct
    // destinations in ten minutes, an unbounded internet long tail.
    assert.match(BLOCKED_INSERT, /action IN \('deny','drop','reset-both','block'\)/);
    assert.match(BLOCKED_INSERT, /(WHERE|AND) dst_ip IS NOT NULL/);
  });

  it('the host rollup counts denies alongside events', () => {
    assert.match(TALKER_INSERT, /count\(\*\) FILTER \(WHERE action IN/);
  });
});

describe('detail rollups: rebuilt in the same window as the permanent ones', () => {
  it('recomputeWindow DELETEs then INSERTs all five rollups', async () => {
    const pool = stubPool();
    const r = await recomputeWindow(pool, FROM, TO);
    assert.equal(r.ok, true);
    const sqls = pool.calls.map((c) => c.sql);
    for (const t of [
      'syslog_rollup_hourly',
      'syslog_rule_hits_hourly',
      'syslog_talker_hourly',
      'syslog_app_hourly',
      'syslog_blocked_dst_hourly',
    ]) {
      const del = sqls.findIndex((s) => s.startsWith(`DELETE FROM ${t}`));
      const ins = sqls.findIndex((s) => s.startsWith(`INSERT INTO ${t}`));
      assert.ok(del >= 0, `${t} must be cleared`);
      assert.ok(ins >= 0, `${t} must be rebuilt`);
      assert.ok(del < ins, `${t} must be cleared BEFORE it is rebuilt`);
    }
  });

  it('⛔ every detail rollup reads the SAME materialized window', async () => {
    // A rollup rebuilt over a different range than the DELETE that preceded
    // it is exactly the bug that took down syslog_rule_hits_daily. Since
    // 2026-09-08 that is structurally impossible: the window is scanned once
    // into a temp table and no INSERT mentions received_at at all.
    const pool = stubPool();
    await recomputeWindow(pool, FROM, TO);
    const sqls = pool.calls.map((c) => c.sql);
    assert.ok(sqls.some((s) => s.startsWith('CREATE TEMP TABLE rollup_src')));
    for (const sql of [TALKER_INSERT, APP_INSERT, BLOCKED_INSERT]) {
      assert.match(sql, /FROM rollup_src/);
      assert.doesNotMatch(sql, /FROM syslog_events/);
      assert.doesNotMatch(sql, /received_at/);
    }
    // The DELETEs still take the bounds, and they must all agree.
    const windowed = pool.calls.filter((c) => Array.isArray(c.params) && c.params.length === 2);
    assert.equal(windowed.length, 6, 'one temp-table scan + five DELETEs');
    for (const c of windowed) {
      assert.equal(c.params[0].getTime(), FROM.getTime());
      assert.equal(c.params[1].getTime(), TO.getTime());
    }
  });

  it('reports a row count for each detail rollup', async () => {
    const pool = stubPool(() => ({ rowCount: 7, rows: [] }));
    const r = await recomputeWindow(pool, FROM, TO);
    assert.equal(r.talkerRows, 7);
    assert.equal(r.appRows, 7);
    assert.equal(r.blockedRows, 7);
  });

  it('⛔ a failing detail rollup is returned, not thrown, and rolls back', async () => {
    const pool = stubPool((sql) => {
      if (sql.startsWith('INSERT INTO syslog_talker_hourly')) throw new Error('out of disk');
      return { rowCount: 0, rows: [] };
    });
    const r = await recomputeWindow(pool, FROM, TO);
    assert.equal(r.ok, false);
    assert.match(r.error, /out of disk/);
    assert.ok(pool.calls.some((c) => c.sql === 'ROLLBACK'));
    assert.ok(pool.calls.some((c) => c.sql === '__released__'), 'a leaked client exhausts the pool');
  });
});

describe('detail rollups: retention', () => {
  function trimPool(behaviour) {
    const calls = [];
    return {
      calls,
      query: async (sql, params) => {
        calls.push({ sql: String(sql).trim(), params });
        if (typeof behaviour === 'function') return behaviour(String(sql));
        return { rowCount: 3 };
      },
    };
  }

  it('trims all three tables by bucket_hour', async () => {
    const pool = trimPool();
    const out = await trimDetailRollups(pool, 30);
    assert.equal(out.days, 30);
    assert.deepEqual(Object.keys(out.deleted).sort(), [
      'syslog_app_hourly', 'syslog_blocked_dst_hourly', 'syslog_talker_hourly',
    ]);
    for (const c of pool.calls) {
      assert.match(c.sql, /^DELETE FROM syslog_/);
      assert.match(c.sql, /bucket_hour </);
      assert.deepEqual(c.params, [30]);
    }
  });

  it('⛔ passes the day count as a BOUND PARAMETER, never interpolated', async () => {
    // Table names are a fixed literal list; the only variable is the day
    // count, and it is bound. CLAUDE.md: no string interpolation in SQL, ever.
    const pool = trimPool();
    await trimDetailRollups(pool, 45);
    for (const c of pool.calls) {
      assert.doesNotMatch(c.sql, /45/, 'the day count must not appear in the SQL text');
      assert.deepEqual(c.params, [45]);
    }
  });

  it('falls back to 30 days rather than deleting everything on junk input', async () => {
    // ⛔ A retention of 0 or NaN interpolated into an interval would delete the
    // whole table. Every unusable value resolves to the documented default.
    for (const bad of [0, -1, null, undefined, NaN, 'x', {}]) {
      const pool = trimPool();
      const out = await trimDetailRollups(pool, bad);
      assert.equal(out.days, 30, `retention=${JSON.stringify(bad)}`);
      assert.deepEqual(pool.calls[0].params, [30]);
    }
  });

  it('⛔ reports a failure instead of throwing OR swallowing it', async () => {
    // Never throws: the caller is a timer inside the collector. But the error
    // must come back — a silently un-trimmed high-cardinality table is how a
    // disk fills up with every health signal still green.
    const pool = trimPool((sql) => {
      if (sql.includes('syslog_app_hourly')) throw new Error('permission denied');
      return { rowCount: 1 };
    });
    const out = await trimDetailRollups(pool, 30);
    assert.match(out.error, /syslog_app_hourly: permission denied/);
    // The other two still ran — one bad table must not stop the sweep.
    assert.equal(out.deleted.syslog_talker_hourly, 1);
    assert.equal(out.deleted.syslog_blocked_dst_hourly, 1);
  });

  it('handles a missing pool without throwing', async () => {
    const out = await trimDetailRollups(null, 30);
    assert.match(out.error, /no pool/);
  });
});
