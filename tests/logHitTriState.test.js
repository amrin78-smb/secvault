// tests/logHitTriState.test.js
//
// `device_cve_assessments.log_hit` became genuinely TRI-STATE on 2026-09-09
// (BOOLEAN, no NOT NULL, no DEFAULT). This file pins the three states end to
// end, plus the two rules that must survive them.
//
// ⛔ WHY THIS EXISTS. lib/engines/logHit.js has always documented two cases
// that must "write NOTHING rather than false" — a device with no syslog
// coverage in the window, and a device with no collected device_interfaces
// rows (without which traffic TO the device cannot be told from traffic
// THROUGH it). Neither was representable: the column was NOT NULL DEFAULT
// false, so every row was born `false` and "never measured" and "measured,
// not reached" were the SAME STORED VALUE. That is CLAUDE.md's own
// failed-read-as-a-fact rule — hit_count's old `DEFAULT 0`, one table over.
//
// The silent half of the bug lived in the update guard:
//
//     if (value === (r.log_hit === true)) continue;
//
// which collapses the stored value to a boolean, so a NULL intent reads as
// "already false" and the write is skipped. Per tests/README.md the case that
// regresses silently is the "we could not measure this" one, so it is the case
// most heavily covered below — including the two transitions the old guard got
// wrong (null -> false, and true -> null).
//
// ⛔ NOTHING HERE CHANGES WHAT `true` MEANS. CLAUDE.md's "What log_hit MEANS"
// still governs: a curated port_exposed condition, traffic arriving at one of
// the device's OWN interface addresses on that port, from a PUBLIC source, and
// ALLOWED. The rejected "a threat signature fired on this device" definition
// stays rejected. Only the storage of an UNMEASURED result changed.
//
// No database and no device: the pool is a stub that returns canned rows and
// records the SQL it was handed.

'use strict';

const { test, describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { persistLogHit, runLogHitCorrelation } = require('../lib/engines/logHit');
const { computePriority } = require('../lib/engines/prioritization');
const { isCapabilityUnavailable } = require('../lib/adapters/interface');
const { FortinetSshAdapter } = require('../lib/adapters/fortinet/ssh');

const REPO = path.join(__dirname, '..');
const ADV = '11111111-1111-1111-1111-111111111111';
const DEV = '22222222-2222-2222-2222-222222222222';

function makePool(handlers) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      for (const [pattern, rows] of handlers) {
        if (sql.includes(pattern)) return { rows: typeof rows === 'function' ? rows(params) : rows };
      }
      return { rows: [] };
    },
  };
}

// A fleet of exactly one device with exactly one curated advisory. Each
// override below is the single fact that decides which of the three states the
// run should produce.
function handlers(overrides = {}) {
  return [
    ['FROM advisory_conditions', overrides.conditions ?? [{ advisory_id: ADV, port: '10443' }]],
    ['FROM device_interfaces', overrides.interfaces ?? [{ device_id: DEV, ip: '27.254.29.130' }]],
    [
      'FROM device_cve_assessments',
      overrides.assessments ?? [{ id: 'a1', device_id: DEV, advisory_id: ADV, log_hit: null }],
    ],
    ['LIMIT 1', overrides.coverage ?? [{ n: 1 }]],
    ['GROUP BY dst_port', overrides.reached ?? []],
  ];
}

const REACHED = [{ dst_port: 10443, events: '412', sources: 37, last_seen: new Date(0) }];

function writes(pool) {
  return pool.calls.filter((c) => c.sql.includes('SET log_hit'));
}

// ───────────────── the three states, written end to end ─────────────────

describe('log_hit is written as three distinct states', () => {
  it('TRUE — measured, and the service was reached', async () => {
    const pool = makePool(handlers({ reached: REACHED }));
    const s = await runLogHitCorrelation(pool);

    assert.equal(s.setTrue, 1);
    assert.equal(s.setFalse, 0);
    assert.equal(s.setUnmeasured, 0);
    assert.equal(writes(pool).length, 1);
    assert.equal(writes(pool)[0].params[0], true);
  });

  it('FALSE — MEASURED, and not reached (both gates passed first)', async () => {
    // Coverage exists and the device's own addresses are known, so "nothing
    // arrived" is a real observation rather than an absence of one.
    const pool = makePool(
      handlers({ assessments: [{ id: 'a1', device_id: DEV, advisory_id: ADV, log_hit: true }] })
    );
    const s = await runLogHitCorrelation(pool);

    assert.equal(s.setFalse, 1);
    assert.equal(s.setUnmeasured, 0);
    assert.equal(writes(pool)[0].params[0], false);
  });

  it('NULL — no syslog coverage in the window is UNMEASURED, never a clean bill', async () => {
    // ⛔ "We were not listening" must not be recorded as "nothing reached it",
    // and leaving a previous run's `true` standing says exactly that with a
    // rule that outranks CVSS 9.0.
    const pool = makePool(
      handlers({
        coverage: [],
        assessments: [{ id: 'a1', device_id: DEV, advisory_id: ADV, log_hit: true }],
      })
    );
    const s = await runLogHitCorrelation(pool);

    assert.equal(s.devicesSkippedNoCoverage, 1);
    assert.equal(s.setUnmeasured, 1);
    assert.equal(s.setFalse, 0, 'an unmeasured device must never be written false');
    assert.equal(writes(pool).length, 1);
    assert.equal(writes(pool)[0].params[0], null);
  });

  it('NULL — no collected interfaces is UNMEASURED, and this is the pair the old guard dropped', async () => {
    // false -> null. Under `value === (r.log_hit === true)` the NULL intent
    // compared equal to the stored `false` and the write was skipped, so a
    // fabricated `false` survived every subsequent run.
    const pool = makePool(
      handlers({
        interfaces: [],
        assessments: [{ id: 'a1', device_id: DEV, advisory_id: ADV, log_hit: false }],
      })
    );
    const s = await runLogHitCorrelation(pool);

    assert.equal(s.devicesSkippedNoInterfaces, 1);
    assert.equal(s.setUnmeasured, 1);
    assert.equal(writes(pool).length, 1);
    assert.equal(writes(pool)[0].params[0], null);
  });

  it('null -> false is a real transition (we started measuring)', async () => {
    const pool = makePool(handlers()); // stored null, covered, nothing reached
    const s = await runLogHitCorrelation(pool);

    assert.equal(s.setFalse, 1);
    assert.equal(writes(pool)[0].params[0], false);
  });

  it('an already-unmeasured row is not rewritten on a skip', async () => {
    // Idempotence: the skip expresses an intent, it does not churn the table.
    const pool = makePool(handlers({ coverage: [] }));
    const s = await runLogHitCorrelation(pool);

    assert.equal(s.devicesSkippedNoCoverage, 1);
    assert.equal(s.setUnmeasured, 0);
    assert.equal(writes(pool).length, 0);
  });

  it('withdrawing a stale true re-derives the priority band', async () => {
    // log_hit feeds rule 2, so true -> null DE-ESCALATES and the band must be
    // recomputed — otherwise the row keeps a patch_now earned by evidence we
    // can no longer stand behind.
    const pool = makePool(
      handlers({
        coverage: [],
        assessments: [{ id: 'a1', device_id: DEV, advisory_id: ADV, log_hit: true }],
      })
    );
    const s = await runLogHitCorrelation(pool);

    assert.equal(s.setUnmeasured, 1);
    assert.equal(s.reprioritized, 1);
    assert.ok(pool.calls.some((c) => c.sql.includes('SET priority_band')));
  });
});

// ─────────────────── the guard itself, all nine pairs ───────────────────

test('the update guard is a three-way identity, not a boolean collapse', async () => {
  const STATES = [true, false, null];
  for (const current of STATES) {
    for (const intended of STATES) {
      const pool = makePool([]);
      const wrote = await persistLogHit(pool, { id: 'a1', log_hit: current }, intended);
      const expected = current !== intended;
      assert.equal(wrote, expected, `${String(current)} -> ${String(intended)}`);
      assert.equal(pool.calls.length, expected ? 1 : 0);
      if (expected) assert.equal(pool.calls[0].params[0], intended);
    }
  }
});

test('an undefined stored value is UNMEASURED, not false', async () => {
  // A row assembled without the column selected must not be mistaken for a
  // measurement — the same reason NULL exists.
  const pool = makePool([]);
  assert.equal(await persistLogHit(pool, { id: 'a1' }, null), false);
  assert.equal(await persistLogHit(pool, { id: 'a1' }, false), true);
});

// ───────────── NULL must never escalate, and never be rendered ─────────────

describe('a tri-state log_hit against the priority tree', () => {
  const device = { asset_criticality: 'normal' };
  const base = {
    kev_listed: false,
    version_affected: true,
    config_applies: 'yes',
    is_fixed_recommended: true,
  };

  it('NULL cannot fire rule 2', () => {
    // ⛔ Rule 2 sits ABOVE CVSS 9.0. An unmeasured device must not be able to
    // manufacture a patch_now — NULL behaves exactly as false did.
    assert.equal(computePriority({ ...base, log_hit: null }, device, 5.0), 'monitor');
    assert.equal(computePriority({ ...base, log_hit: false }, device, 5.0), 'monitor');
    assert.equal(computePriority({ ...base, log_hit: true }, device, 5.0), 'patch_now');
  });

  it('NULL cannot fire rule 2 even where false would also have been declined', () => {
    // config_applies='no' is the one place rule 2 is gated; check NULL does not
    // sneak past it either, at a CVSS that cannot escalate on its own.
    assert.equal(
      computePriority({ ...base, config_applies: 'no', log_hit: null }, device, 5.0),
      'monitor'
    );
  });

  it('NULL does not disturb the bands the other rules produce', () => {
    assert.equal(
      computePriority({ ...base, kev_listed: true, log_hit: null }, device, 0),
      'patch_now'
    );
    assert.equal(
      computePriority({ ...base, config_applies: 'unknown', log_hit: null }, device, 0),
      'scheduled'
    );
  });

  it('undefined (a row selected without the column) also declines', () => {
    assert.equal(computePriority({ ...base }, device, 5.0), 'monitor');
  });
});

test('rule 2 tests === true, never truthiness or !== false', () => {
  // A source-level pin: `log_hit !== false` or a bare truthiness check would
  // let NULL escalate, and the resulting patch_now looks identical to a real
  // one in every UI.
  const src = fs.readFileSync(path.join(REPO, 'lib/engines/prioritization.js'), 'utf8');
  assert.ok(/log_hit === true/.test(src), 'rule 2 must compare identity against true');
  assert.ok(!/log_hit\s*!==\s*false/.test(src));
  assert.ok(!/if\s*\(\s*log_hit\s*&&/.test(src));
});

test('no UI renders log_hit, so nothing can render NULL as "not reachable"', () => {
  // ⛔ A TRIPWIRE, and it passes trivially today because no page or component
  // touches this column. `false` means "not observed", NOT "not exploitable",
  // and NULL means we never looked — absence of an observation is not evidence
  // of absence, exactly as with hit_count. The first surface to display this
  // must distinguish all three, so this fails the moment one appears without
  // acknowledging null.
  const offenders = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
        walk(p);
      } else if (/\.(js|jsx)$/.test(e.name)) {
        const src = fs.readFileSync(p, 'utf8');
        if (/log_hit|logHit/.test(src) && !/null/.test(src)) offenders.push(p);
      }
    }
  };
  for (const dir of ['app', 'components']) walk(path.join(REPO, dir));
  assert.deepEqual(
    offenders,
    [],
    'a surface reads log_hit without mentioning null — it must handle UNMEASURED, ' +
      'and must not render false/NULL as "not reachable"'
  );
});

// ── Fortinet SSH getPerformanceMetrics: unreadable metric != down device ──
//
// Landed in the same pass and covered here rather than left unpinned. The
// throw converted below sits AFTER a RESOLVED _run(): connect, login and
// command all succeeded and the output is the device's own reply, so only the
// METRIC READING failed. This is the fleet's densest heartbeat, so filing that
// as `reachable: false` outweighs every other connectivity source.

describe('Fortinet SSH getPerformanceMetrics', () => {
  const DEVICE = { id: 'dev-1', name: 'TEST-FW', mgmt_ip: '10.0.0.1', vendor: 'fortinet' };
  const POOL = { query: async () => ({ rows: [], rowCount: 0 }) };
  const adapter = () => new FortinetSshAdapter({ device: DEVICE, pool: POOL });

  async function rejection(fn) {
    try {
      const v = await fn();
      assert.fail(`expected a rejection, got ${JSON.stringify(v)}`);
    } catch (err) {
      if (err instanceof assert.AssertionError) throw err;
      return err;
    }
  }

  it('an unparsable reading is a reached device, not a down one', async () => {
    const a = adapter();
    a._run = async () => [
      { command: 'get system performance status', output: '\ncommand parse error\n' },
    ];
    const err = await rejection(() => a.getPerformanceMetrics());
    // ⛔ By FLAG, never instanceof: interface.js loads through several paths and
    // an instanceof across two module instances silently fails CLOSED to
    // "unreachable", quietly restoring the bug.
    assert.equal(isCapabilityUnavailable(err), true, err.message);
    assert.equal(err.deviceWasReached, true);
    assert.equal(err.capability, 'performance_metrics');
  });

  it('⛔ NEGATIVE: an SSH transport failure stays plain and keeps counting against the device', async () => {
    const a = adapter();
    a._run = async () => {
      throw new Error('connect ETIMEDOUT 10.0.0.1:22');
    };
    const err = await rejection(() => a.getPerformanceMetrics());
    assert.equal(isCapabilityUnavailable(err), false, err.message);
    assert.ok(err instanceof Error);
  });
});
