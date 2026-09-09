'use strict';
// tests/actionClassification.test.js
//
// Pins the ONE action vocabulary (lib/syslog/actions.js) and the two things
// that went wrong with it, both found 2026-09-09:
//
//   1. `timeout` was in DENIED_ACTIONS. It is a FortiOS session-TEARDOWN verb
//      of the same family as close/client-rst/server-rst — the session was
//      created, SNAT was applied, packets were forwarded, and then it went
//      idle. Measured live: ~213,000 sessions/day, 5.2% of the fleet's entire
//      "denied" total, recorded as blocks. Worse than the headline number,
//      `syslog_device_inbound_hourly.allowed` was set FALSE for a service that
//      HAD been reached, so lib/engines/logHit.js (which filters on
//      `allowed IS TRUE`) could never fire on it.
//
//   2. lib/engines/logHit.js kept its OWN copy of both lists — the fifth copy
//      in this codebase's history — and it had already drifted: actions.js had
//      `drop-packet` (1,737 live PAN threat events/24h) and logHit.js did not,
//      so classifyAction('drop-packet') answered 'blocked' in one file and
//      'unknown' in the other.
//
// Per tests/README.md, the case that matters most here is neither the allow
// nor the deny: it is the verb in NEITHER list, which must stay `unknown`. A
// blocked/allowed default is the failed-read-as-a-fact bug wearing a vendor's
// vocabulary — an unrecognised verb that resolves to `blocked` inflates every
// denied figure, and one that resolves to `allowed` can manufacture a
// `patch_now` through decision rule 2.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const actions = require('../lib/syslog/actions');
const logHit = require('../lib/engines/logHit');
const { classifyAction, ALLOWED_ACTIONS, DENIED_ACTIONS, ALLOWED_SQL, DENIED_SQL } = actions;

// ⛔ THE FIXTURE. A real captured line from the live fleet, not a constructed
// example and not vendor documentation. It is a FortiOS forward-traffic log:
// an ALLOW policy matched (policyid/policyname), a session existed for 25
// seconds, source NAT was applied, and 260 bytes in 5 packets were forwarded.
// Nothing about it is a refusal.
const CAPTURED_TIMEOUT_LINE =
  'type="traffic" subtype="forward" action="timeout" policyid=7 policytype="policy" ' +
  'policyname="chotruycap" trandisp="snat" transip=123.25.240.15 ' +
  'duration=25 sentbyte=260 rcvdbyte=0 sentpkt=5';

function fieldOf(line, key) {
  const m = new RegExp(`${key}=("([^"]*)"|([^\\s]+))`).exec(line);
  if (!m) return null;
  return m[2] !== undefined ? m[2] : m[3];
}

describe('the captured `timeout` line', () => {
  it('is a forwarded session, not a refusal', () => {
    // Guard the fixture itself: if someone edits the line, these are the
    // properties that make the verdict below correct.
    assert.equal(fieldOf(CAPTURED_TIMEOUT_LINE, 'action'), 'timeout');
    assert.equal(fieldOf(CAPTURED_TIMEOUT_LINE, 'policyid'), '7');
    assert.equal(fieldOf(CAPTURED_TIMEOUT_LINE, 'trandisp'), 'snat');
    assert.ok(Number(fieldOf(CAPTURED_TIMEOUT_LINE, 'sentbyte')) > 0);
    assert.ok(Number(fieldOf(CAPTURED_TIMEOUT_LINE, 'duration')) > 0);
  });

  it('⛔ classifies as ALLOWED — it was in DENIED_ACTIONS until 2026-09-09', () => {
    assert.equal(classifyAction(fieldOf(CAPTURED_TIMEOUT_LINE, 'action')), 'allowed');
    assert.ok(ALLOWED_ACTIONS.has('timeout'));
    assert.ok(!DENIED_ACTIONS.has('timeout'), 'timeout must not be in both sets');
  });

  it('⛔ is gone from the generated deny SQL and present in the allow SQL', () => {
    // The SQL fragments are what the ten rollup passes actually substitute, so
    // a fix that only moved the JS Set would leave every stored number wrong.
    assert.ok(!DENIED_SQL.includes("'timeout'"));
    assert.ok(ALLOWED_SQL.includes("'timeout'"));
  });
});

describe('the FortiOS session-teardown family', () => {
  it('every teardown verb means the session existed', () => {
    for (const a of ['allow', 'accept', 'permit', 'start', 'close', 'client-rst', 'server-rst', 'timeout']) {
      assert.equal(classifyAction(a), 'allowed', a);
    }
  });

  it('⛔ Palo Alto reset-both is NOT swept up with them', () => {
    // It looks like the same family — a connection torn down — but it is the
    // IPS resetting both ends, i.e. a block. 973,973 events in the last 24h on
    // this fleet, so getting it wrong the other way is just as expensive.
    assert.equal(classifyAction('reset-both'), 'blocked');
    assert.ok(DENIED_ACTIONS.has('reset-both'));
    assert.ok(!ALLOWED_ACTIONS.has('reset-both'));
  });

  it('the remaining live deny verbs are unchanged by the timeout fix', () => {
    for (const a of ['deny', 'drop', 'drop-packet', 'blocked', 'block-url', 'reset-client', 'reset-server']) {
      assert.equal(classifyAction(a), 'blocked', a);
    }
  });
});

describe('⛔ three states, never two', () => {
  it('a verb in neither list is unknown', () => {
    // Real, high-volume live verbs that belong to neither vocabulary, plus
    // non-strings. None of them may fire either way.
    for (const a of ['ssl-login-fail', 'alert', 'dns', 'negotiate', 'ip-conn', 'analytics',
      'some-verb-a-vendor-invents-in-2027', '', '   ', null, undefined, 42, {}]) {
      assert.equal(classifyAction(a), 'unknown', String(a));
    }
  });

  it('the two sets are disjoint, so no verb can be both', () => {
    for (const a of ALLOWED_ACTIONS) {
      assert.ok(!DENIED_ACTIONS.has(a), `${a} is in both sets`);
    }
  });

  it('case and padding do not change the verdict', () => {
    assert.equal(classifyAction('  TIMEOUT '), 'allowed');
    assert.equal(classifyAction('Reset-Both'), 'blocked');
  });
});

describe('⛔ ONE vocabulary — logHit.js no longer keeps its own copy', () => {
  it('logHit re-exports the SAME Set objects, not equal-looking copies', () => {
    // Identity, not deep-equality. Two Sets that happen to agree today are
    // exactly what drifted last time; sharing the object makes drift
    // impossible rather than merely unlikely.
    assert.equal(logHit.ALLOWED_ACTIONS, actions.ALLOWED_ACTIONS);
    assert.equal(logHit.BLOCKED_ACTIONS, actions.DENIED_ACTIONS);
    assert.equal(logHit.classifyAction, actions.classifyAction);
  });

  it('⛔ the drift that existed: drop-packet now agrees in both files', () => {
    assert.equal(logHit.classifyAction('drop-packet'), 'blocked');
    assert.equal(actions.classifyAction('drop-packet'), 'blocked');
  });

  it('logHit agrees with actions on every verb either file knows', () => {
    for (const a of [...ALLOWED_ACTIONS, ...DENIED_ACTIONS, 'unheard-of']) {
      assert.equal(logHit.classifyAction(a), classifyAction(a), a);
    }
  });

  it('lib/engines/logHit.js declares no action list of its own', () => {
    const src = require('node:fs').readFileSync(
      require('node:path').join(__dirname, '..', 'lib', 'engines', 'logHit.js'),
      'utf8'
    );
    assert.ok(
      !/(const|let|var)\s+(ALLOWED|BLOCKED|DENIED)_ACTIONS\s*=\s*new Set/.test(src),
      'logHit.js must import the vocabulary, never redeclare it'
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────
// The repair path: fixing the classifier only fixes NEW data.
// ─────────────────────────────────────────────────────────────────────────

const { repairRange, floorHour, addHours } = require('../lib/syslog/rollups');

// A stub pool that answers the partition catalogue query and records every
// recompute window it was asked for. Nothing here talks to a database.
function makeRepairPool(partitionDays, opts = {}) {
  const windows = [];
  const failAfter = opts.failAfter === undefined ? Infinity : opts.failAfter;
  let recomputes = 0;
  return {
    windows,
    async connect() {
      return {
        async query(sql, params) {
          const text = String(sql).trim();
          if (text.startsWith('CREATE TEMP TABLE')) {
            recomputes += 1;
            windows.push({ from: params[0], to: params[1] });
            if (recomputes > failAfter) throw new Error('slice blew up');
          }
          return { rowCount: 0, rows: [] };
        },
        release() {},
      };
    },
    async query(sql) {
      if (String(sql).includes('pg_inherits')) {
        return { rows: partitionDays.map((d) => ({ name: `syslog_events_${d}` })) };
      }
      return { rowCount: 0, rows: [] };
    },
  };
}

const NOW = new Date('2026-09-09T12:00:00Z');

describe('repairRange: bounded, resumable, and clamped to the raw window', () => {
  it('is BOUNDED — one invocation never exceeds maxHours', () => {
    // Without a bound, a 30-day repair is one uninterruptible run against a
    // host taking ~1,400 inserts/sec.
    const pool = makeRepairPool(['20260901', '20260902', '20260909']);
    return repairRange(pool, {
      from: addHours(NOW, -24 * 8),
      to: NOW,
      maxHours: 6,
      sliceHours: 3,
    }).then((r) => {
      assert.equal(r.ok, true);
      assert.equal(r.done, false, 'a bounded run over a wider range is not done');
      const covered = (r.to.getTime() - r.nextTo.getTime()) / 3600000;
      assert.equal(covered, 6);
      assert.equal(pool.windows.length, 2);
    });
  });

  it('is RESUMABLE — feeding nextTo back in continues without a gap', async () => {
    const days = ['20260901', '20260909'];
    const first = await repairRange(makeRepairPool(days), {
      from: addHours(NOW, -24), to: NOW, maxHours: 6, sliceHours: 3,
    });
    const pool2 = makeRepairPool(days);
    const second = await repairRange(pool2, {
      from: addHours(NOW, -24), to: first.nextTo, maxHours: 6, sliceHours: 3,
    });
    // No gap and no overlap-induced hole: the second run starts exactly where
    // the first stopped, and every bucket between them is covered.
    assert.equal(second.to.getTime(), first.nextTo.getTime());
    assert.ok(second.nextTo < first.nextTo);
    assert.equal(pool2.windows[0].to.getTime(), first.nextTo.getTime());
  });

  it('⛔ NEVER touches a bucket the raw window no longer covers', async () => {
    // THE IMPORTANT ONE. recomputeWindow is DELETE-then-INSERT-from-raw, so
    // repairing a bucket whose daily partition has been dropped DELETES a
    // correct permanent rollup row and inserts nothing. A 5% over-count is
    // recoverable; a deleted rollup with no surviving raw evidence is not.
    const pool = makeRepairPool(['20260908', '20260909']);
    const requestedFrom = new Date('2026-08-01T00:00:00Z');
    const r = await repairRange(pool, {
      from: requestedFrom, to: NOW, maxHours: 24 * 7, sliceHours: 6,
    });
    assert.equal(r.ok, true);
    assert.equal(r.rawFloor.toISOString(), '2026-09-08T00:00:00.000Z');
    assert.equal(r.from.toISOString(), '2026-09-08T00:00:00.000Z');
    assert.equal(r.unrecoverableFrom.toISOString(), requestedFrom.toISOString());
    assert.equal(r.unrecoverableTo.toISOString(), '2026-09-08T00:00:00.000Z');
    for (const w of pool.windows) {
      assert.ok(w.from >= r.rawFloor, `slice ${w.from.toISOString()} reached past the raw floor`);
    }
  });

  it('⛔ refuses entirely when there are no raw partitions at all', async () => {
    // "We cannot measure this" — not "there is nothing to repair". Proceeding
    // would delete every targeted bucket.
    const pool = makeRepairPool([]);
    const r = await repairRange(pool, { from: addHours(NOW, -24), to: NOW });
    assert.equal(r.ok, false);
    assert.match(r.error, /refusing to repair/);
    assert.equal(pool.windows.length, 0);
  });

  it('⛔ stops at the first failed slice and resumes from THAT slice', async () => {
    // Grinding on past an error yields a cursor that silently skips a hole.
    const pool = makeRepairPool(['20260901', '20260909'], { failAfter: 1 });
    const r = await repairRange(pool, {
      from: addHours(NOW, -24), to: NOW, maxHours: 12, sliceHours: 3,
    });
    assert.equal(r.ok, false);
    assert.equal(r.slicesFailed, 1);
    // nextTo is the top of the slice that FAILED, so resuming retries it.
    assert.equal(r.nextTo.getTime(), addHours(floorHour(NOW), -3).getTime());
  });

  it('reports done once the whole requested range is covered', async () => {
    const pool = makeRepairPool(['20260901', '20260909']);
    const r = await repairRange(pool, {
      from: addHours(NOW, -6), to: NOW, maxHours: 24, sliceHours: 3,
    });
    assert.equal(r.ok, true);
    assert.equal(r.done, true);
    assert.equal(r.nextTo.getTime(), r.from.getTime());
  });

  it('is idempotent by construction — every slice is a whole-bucket rebuild', async () => {
    const a = makeRepairPool(['20260901', '20260909']);
    const b = makeRepairPool(['20260901', '20260909']);
    const o = { from: addHours(NOW, -6), to: NOW, maxHours: 24, sliceHours: 3 };
    await repairRange(a, o);
    await repairRange(b, o);
    assert.deepEqual(
      a.windows.map((w) => [w.from.toISOString(), w.to.toISOString()]),
      b.windows.map((w) => [w.from.toISOString(), w.to.toISOString()])
    );
  });
});
