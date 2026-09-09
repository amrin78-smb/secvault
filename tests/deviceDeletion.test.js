'use strict';
// Pins lib/engines/deviceDeletion.js.
//
// WHY THIS FILE EXISTS: on 2026-09-09 device delete was found to be
// PERMANENTLY BROKEN for any device with syslog history. Two independent
// problems, both reproduced from production:
//
//   1. `DELETE FROM devices` fired the ON DELETE SET NULL FK on
//      `syslog_rollup_hourly`, whose unique key is UNIQUE NULLS NOT DISTINCT,
//      and collided (23505) with the already-present unmatched-sender row for
//      the same bucket. It could never succeed, only roll back after ~4 min.
//   2. While failing it rewrote 3,352,437 `syslog_events` rows holding an
//      exclusive lock on the `devices` row — the same row the collector needs a
//      KEY SHARE lock on to insert ANY event — so ingestion stalled behind it.
//
// The fix is an ORDER, not a patch, so most of what is worth pinning is the
// order and the shape of the SQL rather than a return value. These tests
// therefore assert on the statements the engine BUILDS as well as on how it
// interprets what comes back — the same approach configRetention.test.js takes,
// and for the same reason: a protection that is silently removed must fail a
// build, not a production delete.
//
// ⛔ NO DATABASE. Every test hands the engine a stub pool that records the
// statements it was given and returns canned rowCounts.
//
// ⛔ The failure paths matter more than the happy one here. A delete that half
// works and reports "succeeded" is the failed-read-as-a-fact rule at its most
// expensive, so every stage has a test for what its failure LOOKS like.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  ROLLUP_TABLES,
  COLLIDING_ROLLUP_TABLE,
  DEFAULTS,
  DeviceDeleteError,
  countRollupRows,
  countSyslogEvents,
  estimateDeleteImpact,
  deleteRollupRows,
  unlinkSyslogEvents,
  deleteDeviceRow,
  describeSummary,
  runDeviceDeleteJob,
} = require('../lib/engines/deviceDeletion');

const DEVICE = '710506de-d602-459e-8fa1-40b7a318dcd4';
const JOB = { id: 'job-1', device_id: DEVICE };

// --------------------------------------------------------------------------
// Stub pool
// --------------------------------------------------------------------------
//
// `respond(sql, params, callIndex)` returns { rowCount, rows } or throws.
// Every statement (including the dedicated-client ones) is appended to
// `pool.statements` in order, which is what the ordering assertions read.

function makePool(respond) {
  const statements = [];
  const query = async (sql, params) => {
    const text = String(sql);
    statements.push({ sql: text, params: params || [] });
    const result = respond ? respond(text, params || [], statements.length - 1) : undefined;
    if (result === undefined) return { rowCount: 0, rows: [] };
    return { rowCount: 0, rows: [], ...result };
  };
  let released = 0;
  const pool = {
    statements,
    query,
    releases: () => released,
    connect: async () => ({
      query,
      release: () => {
        released += 1;
      },
    }),
  };
  return pool;
}

const sqlsOf = (pool) => pool.statements.map((s) => s.sql);
const firstIndex = (pool, re) => sqlsOf(pool).findIndex((s) => re.test(s));
const lastIndex = (pool, re) => {
  const all = sqlsOf(pool);
  for (let i = all.length - 1; i >= 0; i -= 1) if (re.test(all[i])) return i;
  return -1;
};
const countMatching = (pool, re) => sqlsOf(pool).filter((s) => re.test(s)).length;

// A pool where the device exists but every child population is already drained
// — the cheapest happy path, and also the shape of a re-run after a previous
// attempt got as far as clearing the syslog history.
const emptyPool = () =>
  makePool((sql) => {
    if (/FOR UPDATE/i.test(sql)) return { rowCount: 1, rows: [{ id: DEVICE }] };
    if (/^DELETE FROM devices/i.test(sql.trim())) return { rowCount: 1, rows: [] };
    return { rowCount: 0, rows: [{ n: '0' }] };
  });

// --------------------------------------------------------------------------
describe('the order of the three stages', () => {
  it('deletes rollups, then unlinks raw events, then deletes the device row', async () => {
    const pool = emptyPool();
    await runDeviceDeleteJob(pool, JOB, { eventPauseMs: 0 });

    const rollup = firstIndex(pool, /DELETE FROM syslog_rollup_hourly/i);
    const events = firstIndex(pool, /UPDATE syslog_events/i);
    const device = lastIndex(pool, /DELETE FROM devices/i);

    assert.ok(rollup >= 0, 'a rollup delete must be issued');
    assert.ok(events >= 0, 'the raw-event unlink must be issued');
    assert.ok(device >= 0, 'the device row must be deleted');
    // Rollups first: that is what leaves the SET NULL FK with nothing to do.
    assert.ok(rollup < events, 'rollups must be cleared before the raw events are touched');
    // The device row LAST: it is the row whose exclusive lock blocks ingestion.
    assert.ok(events < device, 'the device row must go after the raw events are unlinked');
  });

  it('never issues the DELETE FROM devices when an earlier stage failed', async () => {
    const pool = makePool((sql) => {
      if (/DELETE FROM syslog_talker_hourly/i.test(sql)) throw new Error('disk full');
      return { rowCount: 0, rows: [] };
    });
    await assert.rejects(() => runDeviceDeleteJob(pool, JOB, { eventPauseMs: 0 }), DeviceDeleteError);
    assert.equal(countMatching(pool, /DELETE FROM devices/i), 0);
  });
});

// --------------------------------------------------------------------------
describe('23505 is impossible by construction, not by luck', () => {
  it('DELETEs the colliding rollup rather than NULLing them', async () => {
    const pool = emptyPool();
    await runDeviceDeleteJob(pool, JOB, { eventPauseMs: 0 });
    // The whole bug was an UPDATE ... SET device_id = NULL on this table.
    // ⛔ If this assertion ever has to be relaxed, the 23505 is back.
    const nulled = sqlsOf(pool).filter(
      (s) => new RegExp(`UPDATE[\\s\\S]*${COLLIDING_ROLLUP_TABLE}[\\s\\S]*device_id\\s*=\\s*NULL`, 'i').test(s)
    );
    assert.deepEqual(nulled, [], 'the colliding rollup must never be NULLed, only deleted');
    assert.ok(countMatching(pool, new RegExp(`DELETE FROM ${COLLIDING_ROLLUP_TABLE}`, 'i')) >= 1);
  });

  it('re-clears the colliding rollup INSIDE the same transaction as the device delete, after taking FOR UPDATE', async () => {
    // Stage 1 runs minutes before stage 3 and the rollup sweep runs every few
    // minutes, so a fresh row can appear in the gap and re-arm the collision.
    // FOR UPDATE conflicts with the FOR KEY SHARE any new referencing write must
    // take, so nothing can be added once it is held; the mop-up then removes
    // whatever landed before it.
    const pool = emptyPool();
    await runDeviceDeleteJob(pool, JOB, { eventPauseMs: 0 });

    const begin = lastIndex(pool, /^BEGIN$/i);
    const forUpdate = lastIndex(pool, /FROM devices WHERE id = \$1 FOR UPDATE/i);
    const mop = lastIndex(pool, new RegExp(`DELETE FROM ${COLLIDING_ROLLUP_TABLE}`, 'i'));
    const del = lastIndex(pool, /DELETE FROM devices/i);
    const commit = lastIndex(pool, /^COMMIT$/i);

    assert.ok(begin >= 0 && forUpdate > begin, 'the row lock must be taken inside the transaction');
    assert.ok(mop > forUpdate, 'the mop-up must happen AFTER the lock, or new rows can still arrive');
    assert.ok(del > mop, 'the device row must go after the mop-up');
    assert.ok(commit > del, 'and it must all be one committed transaction');
  });

  it('rolls the stage-3 transaction back and releases the client when the device delete fails', async () => {
    const pool = makePool((sql) => {
      if (/^DELETE FROM devices/i.test(sql)) throw new Error('deadlock detected');
      return { rowCount: 1, rows: [{ id: DEVICE }] };
    });
    await assert.rejects(
      () => deleteDeviceRow(pool, DEVICE),
      (err) => /deadlock detected/.test(err.message)
    );
    assert.ok(firstIndex(pool, /^ROLLBACK$/i) >= 0, 'a failed stage 3 must roll back');
    assert.equal(pool.releases(), 1, 'the pooled client must always be released');
  });
});

// --------------------------------------------------------------------------
describe('raw events are evidence — kept, never deleted', () => {
  it('unlinks syslog_events with an UPDATE and never a DELETE', async () => {
    const pool = emptyPool();
    await runDeviceDeleteJob(pool, JOB, { eventPauseMs: 0 });
    assert.equal(
      countMatching(pool, /DELETE FROM syslog_events/i),
      0,
      'the device record goes, the forensic log evidence stays'
    );
    assert.ok(countMatching(pool, /UPDATE syslog_events[\s\S]*device_id = NULL/i) >= 1);
  });

  it('sets device_id NULL — safe because syslog_events has no unique constraint to collide with', async () => {
    // Pinned against schema.sql so this stays true if someone adds one.
    const schema = fs.readFileSync(path.join(__dirname, '..', 'lib', 'schema.sql'), 'utf8');
    const uniques = schema.match(/CREATE UNIQUE INDEX[^;]*ON\s+syslog_events\b[^;]*;/gi) || [];
    assert.deepEqual(
      uniques,
      [],
      'a unique index on syslog_events would make the NULL-unlink collide the same way the rollup did'
    );
  });
});

// --------------------------------------------------------------------------
describe('every syslog rollup is covered, and the list cannot silently drift', () => {
  const schema = fs.readFileSync(path.join(__dirname, '..', 'lib', 'schema.sql'), 'utf8');

  it('ROLLUP_TABLES lists every syslog_*_hourly table in schema.sql', () => {
    const declared = new Set();
    for (const m of schema.matchAll(/CREATE TABLE IF NOT EXISTS\s+(syslog_[a-z0-9_]*_hourly)\b/gi)) {
      declared.add(m[1].toLowerCase());
    }
    assert.ok(declared.size > 0, 'the schema parse must find something, or this test proves nothing');
    const missing = [...declared].filter((t) => !ROLLUP_TABLES.includes(t));
    assert.deepEqual(
      missing,
      [],
      'a new hourly rollup left out of ROLLUP_TABLES cascades during stage 3 while the devices row lock is held — the outage this engine exists to prevent'
    );
  });

  it('the colliding table is cleared first, because it is the one that can fail the whole delete', () => {
    assert.equal(ROLLUP_TABLES[0], COLLIDING_ROLLUP_TABLE);
  });

  it('no OTHER table combines ON DELETE SET NULL with a NULLS NOT DISTINCT unique on device_id', () => {
    // ⛔ This is the general shape of the bug, not the specific instance. Any
    // table that joins this club acquires the same undeleteable-device problem
    // and must be handled here. Conservative: only tables whose CREATE TABLE
    // body this can parse are considered.
    const offenders = [];
    for (const m of schema.matchAll(/CREATE TABLE IF NOT EXISTS\s+([a-z_][a-z0-9_]*)\s*\(([\s\S]*?)\n\)[^;]*;/gi)) {
      const table = m[1].toLowerCase();
      const body = m[2];
      const setNullOnDevice = /device_id[^,]*REFERENCES\s+devices\s*\(id\)\s*ON DELETE SET NULL/i.test(body);
      if (!setNullOnDevice) continue;
      // The unique key may be declared inline or added by a later ALTER.
      // ⛔ Bounded to a SINGLE statement ([^;]*). A cross-statement regex ran
      // happily from one table's ALTER all the way to a LATER table's
      // constraint and reported syslog_events — which has no unique key at all
      // — as an offender. A lint that cries wolf gets deleted.
      const alters =
        schema.match(
          new RegExp(`ALTER TABLE ${table}\\s+ADD CONSTRAINT[^;]*UNIQUE NULLS NOT DISTINCT[^;]*;`, 'gi')
        ) || [];
      const nndBlobs = [
        ...(body.match(/UNIQUE NULLS NOT DISTINCT[\s\S]*?\)/gi) || []),
        ...alters,
      ];
      if (nndBlobs.some((b) => /\bdevice_id\b/.test(b))) offenders.push(table);
    }
    assert.deepEqual(
      offenders,
      [COLLIDING_ROLLUP_TABLE],
      `tables with SET NULL + NULLS NOT DISTINCT on device_id must all be handled by deviceDeletion.js; unhandled: ${offenders.join(', ')}`
    );
  });
});

// --------------------------------------------------------------------------
describe('batches are bounded and the loop cannot run away', () => {
  it('passes the configured batch size as a LIMIT parameter, never an unbounded statement', async () => {
    const pool = emptyPool();
    await runDeviceDeleteJob(pool, JOB, { rollupBatchSize: 111, eventBatchSize: 222, eventPauseMs: 0 });
    const rollup = pool.statements.find((s) => /DELETE FROM syslog_rollup_hourly/i.test(s.sql));
    const events = pool.statements.find((s) => /UPDATE syslog_events/i.test(s.sql));
    assert.match(rollup.sql, /LIMIT \$2/);
    assert.deepEqual(rollup.params, [DEVICE, 111]);
    assert.match(events.sql, /LIMIT \$2/);
    assert.deepEqual(events.params, [DEVICE, 222]);
  });

  it('stops looping as soon as a batch comes back short', async () => {
    let calls = 0;
    const pool = makePool((sql) => {
      if (/DELETE FROM syslog_rollup_hourly/i.test(sql)) {
        calls += 1;
        return { rowCount: calls < 3 ? 10 : 4 };
      }
      return { rowCount: 0, rows: [] };
    });
    const deleted = await deleteRollupRows(pool, 'syslog_rollup_hourly', DEVICE, 10, 100);
    assert.equal(deleted, 24);
    assert.equal(calls, 3, 'a short batch means the table is drained — stop, do not probe again');
  });

  it('throws rather than spinning forever when batches never shorten', async () => {
    const pool = makePool(() => ({ rowCount: 10 }));
    await assert.rejects(
      () => deleteRollupRows(pool, 'syslog_talker_hourly', DEVICE, 10, 5),
      /after 5 iterations/
    );
    assert.equal(countMatching(pool, /DELETE FROM syslog_talker_hourly/i), 5);
  });

  it('pauses between raw-event batches so ingestion is never queued behind it for long', async () => {
    let calls = 0;
    const pool = makePool(() => {
      calls += 1;
      return { rowCount: calls < 2 ? 5 : 1 };
    });
    const started = Date.now();
    const n = await unlinkSyslogEvents(pool, DEVICE, {
      batchSize: 5,
      pauseMs: 30,
      maxBatches: 10,
    });
    assert.equal(n, 6);
    assert.ok(Date.now() - started >= 25, 'the yield between batches is what keeps the collector alive');
  });

  it('has bounded defaults, not "no limit"', () => {
    assert.ok(DEFAULTS.rollupBatchSize > 0 && DEFAULTS.rollupBatchSize <= 50000);
    assert.ok(DEFAULTS.eventBatchSize > 0 && DEFAULTS.eventBatchSize <= 100000);
    assert.ok(DEFAULTS.maxBatchesPerTable > 0);
  });
});

// --------------------------------------------------------------------------
describe('resumable and idempotent', () => {
  it('a re-run against an already-clean device succeeds without claiming a fresh deletion', async () => {
    // Stage 3's FOR UPDATE finds no row: the device is already gone, which is
    // the end state we wanted — reached by an earlier attempt.
    const pool = makePool((sql) => {
      if (/FOR UPDATE/i.test(sql)) return { rowCount: 0, rows: [] };
      return { rowCount: 0, rows: [] };
    });
    const summary = await runDeviceDeleteJob(pool, JOB, { eventPauseMs: 0 });
    assert.equal(summary.deviceRowDeleted, false);
    assert.match(describeSummary(summary), /device row was already absent/);
    // ⛔ And it must not have tried to delete a row it never locked.
    assert.equal(countMatching(pool, /^DELETE FROM devices/i), 0);
    assert.ok(lastIndex(pool, /^COMMIT$/i) >= 0, 'the no-op transaction still commits cleanly');
  });

  it('every stage is scoped to this device only', async () => {
    const pool = emptyPool();
    await runDeviceDeleteJob(pool, JOB, { eventPauseMs: 0 });
    const mutating = pool.statements.filter((s) => /^(DELETE|UPDATE|WITH)/i.test(s.sql.trim()));
    assert.ok(mutating.length > 0);
    for (const s of mutating) {
      assert.match(s.sql, /device_id = \$1|WHERE id = \$1/, `unscoped mutation: ${s.sql}`);
      assert.equal(s.params[0], DEVICE);
    }
  });
});

// --------------------------------------------------------------------------
describe('a failure is reported as a failure, and says what already happened', () => {
  it('names the stage, states the completed work, and says the device was NOT deleted', async () => {
    const pool = makePool((sql) => {
      if (/DELETE FROM syslog_rollup_hourly/i.test(sql)) return { rowCount: 3 };
      if (/DELETE FROM syslog_rule_hits_hourly/i.test(sql)) throw new Error('connection reset');
      return { rowCount: 0, rows: [] };
    });
    await assert.rejects(
      () => runDeviceDeleteJob(pool, JOB, { rollupBatchSize: 10, eventPauseMs: 0 }),
      (err) => {
        assert.ok(err instanceof DeviceDeleteError);
        assert.equal(err.stage, 'rollups');
        assert.match(err.message, /syslog_rule_hits_hourly/);
        assert.match(err.message, /connection reset/);
        assert.match(err.message, /was NOT deleted/);
        // ⛔ The work that DID land must be stated. "It failed" without a
        // partial-progress statement is what makes an operator re-run blind.
        assert.match(err.message, /3 rollup rows deleted/);
        assert.match(err.message, /resumes/);
        assert.equal(err.summary.rollupRowsDeleted, 3);
        return true;
      }
    );
  });

  it('reports committed raw-event batches when a later batch fails', async () => {
    let calls = 0;
    const pool = makePool((sql) => {
      if (/UPDATE syslog_events/i.test(sql)) {
        calls += 1;
        if (calls === 3) throw new Error('server closed the connection');
        return { rowCount: 5 };
      }
      return { rowCount: 0, rows: [{ n: null }] };
    });
    await assert.rejects(
      () => runDeviceDeleteJob(pool, JOB, { eventBatchSize: 5, eventPauseMs: 0 }),
      (err) => {
        assert.equal(err.stage, 'events');
        // Two batches of five committed before the third threw; each batch is
        // its own transaction, so those ten rows are a fact on disk.
        assert.equal(err.summary.eventsUnlinked, 10);
        assert.match(err.message, /10 raw events unlinked \(kept\)/);
        assert.match(err.message, /still point at it/);
        return true;
      }
    );
    assert.equal(countMatching(pool, /^DELETE FROM devices/i), 0);
  });

  it('says the device record REMAINS when only stage 3 failed', async () => {
    const pool = makePool((sql) => {
      if (/^DELETE FROM devices/i.test(sql)) throw new Error('lock timeout');
      if (/FOR UPDATE/i.test(sql)) return { rowCount: 1, rows: [{ id: DEVICE }] };
      return { rowCount: 0, rows: [] };
    });
    await assert.rejects(
      () => runDeviceDeleteJob(pool, JOB, { eventPauseMs: 0 }),
      (err) => {
        assert.equal(err.stage, 'device');
        assert.match(err.message, /device record REMAINS/);
        assert.equal(err.summary.deviceRowDeleted, null);
        return true;
      }
    );
  });

  it('refuses a job with no device_id rather than deleting something arbitrary', async () => {
    await assert.rejects(() => runDeviceDeleteJob(emptyPool(), { id: 'x' }, {}), /no device_id/);
  });

  it('a progress-reporting failure never fails a delete that is working', async () => {
    const pool = emptyPool();
    const summary = await runDeviceDeleteJob(pool, JOB, {
      eventPauseMs: 0,
      onProgress: async () => {
        throw new Error('background_jobs is unreachable');
      },
    });
    assert.equal(summary.deviceRowDeleted, true);
  });
});

// --------------------------------------------------------------------------
describe('sizing is tri-state — "we could not count it" is never zero', () => {
  it('returns an exact count when the raw table answers inside the budget', async () => {
    const pool = makePool((sql) => {
      if (/FROM syslog_events/i.test(sql)) return { rows: [{ n: '3352437' }] };
      return { rows: [] };
    });
    const r = await countSyslogEvents(pool, DEVICE, { timeoutMs: 1000 });
    assert.deepEqual(r, { value: 3352437, exact: true, source: 'syslog_events' });
  });

  it('falls back to the rollup sum and LABELS it inexact when the exact count times out', async () => {
    // Measured live: COUNT(*) on syslog_events for the busiest device did not
    // complete in 8s. The fallback covers all history while the raw table keeps
    // ~30 days, so it is an upper bound and must never be shown as a measurement.
    const pool = makePool((sql) => {
      if (/FROM syslog_events/i.test(sql)) {
        const e = new Error('canceling statement due to statement timeout');
        e.code = '57014';
        throw e;
      }
      if (/FROM syslog_rollup_hourly/i.test(sql)) return { rows: [{ n: '20809660' }] };
      return { rows: [] };
    });
    const r = await countSyslogEvents(pool, DEVICE, { timeoutMs: 1000 });
    assert.equal(r.value, 20809660);
    assert.equal(r.exact, false);
    assert.equal(r.source, 'syslog_rollup_hourly');
  });

  it('returns null, NOT 0, when nothing can answer', async () => {
    const pool = makePool(() => {
      throw new Error('relation does not exist');
    });
    const r = await countSyslogEvents(pool, DEVICE, { timeoutMs: 0 });
    assert.equal(r.value, null, '0 here would read as "this device has no logs" — the opposite of the truth');
    assert.equal(r.exact, false);
  });

  it('treats an empty rollup sum (SQL NULL) as unknown, not as zero', async () => {
    const pool = makePool(() => ({ rows: [{ n: null }] }));
    const r = await countSyslogEvents(pool, DEVICE, { timeoutMs: 0 });
    assert.equal(r.value, null);
  });

  it('skips the expensive exact count entirely when the budget is zero', async () => {
    const pool = makePool(() => ({ rows: [{ n: '5' }] }));
    await countSyslogEvents(pool, DEVICE, { timeoutMs: 0 });
    assert.equal(countMatching(pool, /FROM syslog_events/i), 0, 'a page render must never pay for this');
  });

  it('marks the rollup count partial (total null) when a table cannot be counted', async () => {
    const pool = makePool((sql) => {
      if (/FROM syslog_threat_hourly/i.test(sql)) throw new Error('permission denied');
      return { rows: [{ n: '7' }] };
    });
    const r = await countRollupRows(pool, DEVICE);
    assert.equal(r.partial, true);
    assert.equal(r.total, null, 'an incomplete total must not masquerade as a complete one');
    assert.equal(r.perTable.syslog_threat_hourly, null);
    assert.ok(r.countedTotal > 0, 'what WAS counted is still reported, as a floor');
  });

  it('estimateDeleteImpact never throws, so a sizing failure cannot block the page', async () => {
    const pool = makePool(() => {
      throw new Error('database is starting up');
    });
    const impact = await estimateDeleteImpact(pool, DEVICE);
    assert.equal(impact.rollupRows.total, null);
    assert.equal(impact.syslogEvents.value, null);
  });
});

// --------------------------------------------------------------------------
describe('progress reporting stays honest', () => {
  it('reports a NULL total when the size is not exactly known', async () => {
    const seen = [];
    const pool = makePool((sql) => {
      if (/count\(\*\)[\s\S]*FROM syslog_events/i.test(sql)) throw new Error('too slow');
      if (/sum\(event_count\)/i.test(sql)) return { rows: [{ n: '999' }] };
      if (/FOR UPDATE/i.test(sql)) return { rowCount: 1, rows: [{ id: DEVICE }] };
      return { rowCount: 0, rows: [] };
    });
    await runDeviceDeleteJob(pool, JOB, { eventPauseMs: 0, onProgress: (p) => seen.push(p) });
    const withTotals = seen.filter((p) => p.total !== null && p.total !== undefined);
    assert.deepEqual(
      withTotals,
      [],
      'an approximate size must never be published as progress_total — a bar drawn against a guess is a fabricated measurement'
    );
    assert.ok(seen.some((p) => /could not be counted cheaply/.test(String(p.detail))));
  });

  it('publishes a real total when the exact count succeeded', async () => {
    const seen = [];
    const pool = makePool((sql) => {
      if (/count\(\*\)[\s\S]*FROM syslog_events/i.test(sql)) return { rows: [{ n: '40' }] };
      if (/UPDATE syslog_events/i.test(sql)) return { rowCount: 0 };
      return { rowCount: 0, rows: [] };
    });
    await runDeviceDeleteJob(pool, JOB, { eventPauseMs: 0, onProgress: (p) => seen.push(p) });
    assert.ok(seen.some((p) => p.total === 40));
  });
});
