'use strict';
// Pins lib/backfillLedger.js — the one-shot gate that took `node lib/migrate.js`
// from 601-823 seconds (84% of every deploy) down to the schema work alone.
//
// ⛔ THE RISK THIS INTRODUCES, stated plainly, because it is worse than the
// slowness it fixes: a gate that skips a repair which has NOT actually run
// leaves broken data in place permanently and silently. On this codebase that
// data includes PAN-OS secrets sitting in plaintext in device_configs. So the
// three properties below are not hygiene, they are the whole safety argument:
//
//   1. A FAILED run is never recorded, so it retries next deploy. Every one of
//      these backfills is deliberately non-fatal — a data repair must not block
//      the deploy shipping the forward-looking parser fix — which makes silent
//      failure entirely possible, and marking a failed repair complete would be
//      this codebase's oldest bug applied to its own maintenance.
//   2. A CHANGED repair re-runs, via the revision. The PAN-OS re-redaction
//      shipped twice (the first pass was XML-only and missed 343 rows stored in
//      CLI brace grammar). Keying on name alone would mean the corrected pass
//      never ran on exactly the installs holding the broken data.
//   3. An UNREADABLE ledger fails OPEN — run the repair again. Re-running is
//      idempotent and costs minutes; skipping wrongly leaves secrets exposed.
//      This is the one place in this codebase where fail-open is correct, and
//      it is correct because the failure modes are asymmetric.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { isDone, markDone, runOnce, ensureLedger } = require('../lib/backfillLedger');

// A stub pool that records SQL and can be told to fail.
function stubPool(opts = {}) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      if (opts.throwOn && sql.includes(opts.throwOn)) throw new Error('db is down');
      if (/^\s*SELECT 1 FROM/.test(sql)) {
        return { rows: opts.recorded ? [{ '?column?': 1 }] : [] };
      }
      return { rows: [] };
    },
  };
}

describe('the gate', () => {
  it('runs a repair that has never completed', async () => {
    const pool = stubPool({ recorded: false });
    let ran = false;
    const r = await runOnce(pool, 'thing', 1, async () => { ran = true; return 'did 5 rows'; });
    assert.equal(ran, true);
    assert.equal(r.ran, true);
  });

  it('skips one that has', async () => {
    const pool = stubPool({ recorded: true });
    let ran = false;
    const r = await runOnce(pool, 'thing', 1, async () => { ran = true; });
    assert.equal(ran, false);
    assert.equal(r.ran, false);
  });

  it('records completion with the name AND revision', async () => {
    const pool = stubPool({ recorded: false });
    await runOnce(pool, 'thing', 3, async () => 'ok');
    const insert = pool.calls.find((c) => /INSERT INTO/.test(c.sql));
    assert.ok(insert, 'completion must be written');
    assert.equal(insert.params[0], 'thing');
    assert.equal(insert.params[1], 3);
  });
});

describe('⛔ a failed repair is never marked complete', () => {
  it('does not record when the repair throws', async () => {
    const pool = stubPool({ recorded: false });
    const r = await runOnce(pool, 'thing', 1, async () => { throw new Error('boom'); });
    assert.equal(r.failed, true);
    assert.equal(
      pool.calls.some((c) => /INSERT INTO/.test(c.sql)), false,
      'a throw must leave the ledger untouched so the next deploy retries'
    );
  });

  it('a throw is contained — migrate is never failed by a data repair', async () => {
    const pool = stubPool({ recorded: false });
    await assert.doesNotReject(() => runOnce(pool, 'thing', 1, async () => { throw new Error('boom'); }));
  });
});

describe('⛔ the revision is what makes a FIXED repair re-run', () => {
  it('a bumped revision is a different marker, so the repair runs again', async () => {
    // The live precedent: the PAN-OS re-redaction shipped twice because the
    // first pass was XML-only. Keying on name alone would have meant the
    // corrected pass never ran where it was needed.
    const seen = [];
    const pool = {
      async query(sql, params) {
        if (/^\s*SELECT 1 FROM/.test(sql)) {
          // rev 1 recorded, rev 2 not.
          return { rows: params[1] === 1 ? [{ x: 1 }] : [] };
        }
        if (/INSERT INTO/.test(sql)) seen.push(params[1]);
        return { rows: [] };
      },
    };
    const old = await runOnce(pool, 'redaction', 1, async () => 'should not run');
    const fixed = await runOnce(pool, 'redaction', 2, async () => 'runs');
    assert.equal(old.ran, false, 'the already-completed revision is skipped');
    assert.equal(fixed.ran, true, 'the bumped revision runs');
    assert.deepEqual(seen, [2]);
  });
});

describe('⛔ an unreadable ledger fails OPEN', () => {
  it('treats a read failure as "not done" and runs the repair', async () => {
    // Asymmetric failure modes: re-running is idempotent and costs minutes;
    // skipping wrongly leaves plaintext secrets in the database.
    const pool = stubPool({ throwOn: 'SELECT 1 FROM' });
    assert.equal(await isDone(pool, 'thing', 1), false);
  });

  it('a write failure never fails the migration', async () => {
    const pool = stubPool({ throwOn: 'INSERT INTO' });
    await assert.doesNotReject(() => markDone(pool, 'thing', 1, 10, 'x'));
  });
});

describe('the ledger table', () => {
  it('is created idempotently and is keyed on (name, revision)', async () => {
    const pool = stubPool();
    await ensureLedger(pool);
    const sql = pool.calls[0].sql;
    assert.match(sql, /CREATE TABLE IF NOT EXISTS/);
    assert.match(sql, /UNIQUE \(name, revision\)/);
  });
});

describe('⛔ migrate gates DATA repairs only, never the schema', () => {
  it('runSchema is not behind the ledger', () => {
    // The schema migration is how a new table or column reaches an existing
    // install. It is idempotent by construction and cheap, and gating it would
    // mean a future column silently never lands.
    const src = require('fs').readFileSync(require.resolve('../lib/migrate.js'), 'utf8');
    const schemaCall = src.indexOf('await runSchema(pool)');
    assert.ok(schemaCall > 0, 'runSchema must still be called');
    const gateBefore = src.lastIndexOf('isDone(pool', schemaCall);
    const mainStart = src.indexOf('async function main()');
    assert.ok(
      gateBefore < mainStart,
      'runSchema must not sit behind an isDone() gate'
    );
  });

  it('every gated backfill passes a numeric revision', () => {
    const src = require('fs').readFileSync(require.resolve('../lib/migrate.js'), 'utf8');
    const gates = [...src.matchAll(/isDone\(pool, '([a-z0-9-]+)', (\d+)\)/g)];
    assert.ok(gates.length >= 7, `expected the expensive backfills to be gated, found ${gates.length}`);
    for (const [, name, rev] of gates) {
      assert.ok(Number(rev) >= 1, `${name} needs a revision >= 1`);
    }
    // ⛔ Each marker name is used once. A name reused for a DIFFERENT repair
    // would make the second one silently skip on every install that ran the first.
    const names = gates.map((g) => g[1]);
    assert.equal(new Set(names).size, names.length, 'marker names must be unique');
  });

  it('every gate has a matching markDone with the SAME name and revision', () => {
    // A gate without its write runs the repair on every deploy forever (the bug
    // this replaces); a write without its gate is dead bookkeeping.
    const src = require('fs').readFileSync(require.resolve('../lib/migrate.js'), 'utf8');
    const gates = [...src.matchAll(/isDone\(pool, '([a-z0-9-]+)', (\d+)\)/g)].map((g) => `${g[1]}@${g[2]}`);
    const marks = [...src.matchAll(/markDone\(pool, '([a-z0-9-]+)', (\d+)/g)].map((g) => `${g[1]}@${g[2]}`);
    for (const g of gates) assert.ok(marks.includes(g), `${g} is gated but never recorded`);
  });
});
