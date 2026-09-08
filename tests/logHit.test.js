// tests/logHit.test.js
//
// `log_hit` feeds decision rule 2, which sits ABOVE CVSS 9.0 in the priority
// tree. A false positive here promotes an advisory to `patch_now` with the
// same confidence as "known exploited in the wild", so most of what is pinned
// below is the engine DECLINING to fire.
//
// Per tests/README.md, every case here includes the "we could not measure
// this" variant, because that is the one that regresses silently.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  classifyAction,
  getCuratedPorts,
  getDeviceInterfaceIps,
  runLogHitCorrelation,
} = require('../lib/engines/logHit');

// ── A stub pool: returns canned rows and records the SQL it was handed. ──
function makePool(handlers) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      for (const [pattern, rows] of handlers) {
        if (sql.includes(pattern)) {
          return { rows: typeof rows === 'function' ? rows(params) : rows };
        }
      }
      return { rows: [] };
    },
  };
}

const ADV = '11111111-1111-1111-1111-111111111111';
const DEV = '22222222-2222-2222-2222-222222222222';

function baseHandlers(overrides = {}) {
  return [
    ['FROM advisory_conditions', overrides.conditions ?? [{ advisory_id: ADV, port: '10443' }]],
    ['FROM device_interfaces', overrides.interfaces ?? [{ device_id: DEV, ip: '27.254.29.130' }]],
    [
      'FROM device_cve_assessments',
      overrides.assessments ?? [{ id: 'a1', device_id: DEV, advisory_id: ADV, log_hit: false }],
    ],
    ['LIMIT 1', overrides.coverage ?? [{ '?column?': 1 }]],
    ['GROUP BY dst_port', overrides.reached ?? []],
  ];
}

// ─────────────────────────── classifyAction ───────────────────────────

test('classifyAction: a session that existed and closed counts as reached', () => {
  // The live-verified case: FortiGate SSL-VPN on 10443 is logged `close` /
  // `client-rst`, never `allow`. Reading only `allow` as reached would miss
  // the most exposed service on the fleet.
  for (const a of ['allow', 'accept', 'close', 'client-rst', 'server-rst']) {
    assert.equal(classifyAction(a), 'allowed', a);
  }
});

test('classifyAction: reset-both is a block, not a teardown', () => {
  // Palo Alto's IPS resetting both ends looks like Fortinet's session-end
  // actions but means the opposite.
  assert.equal(classifyAction('reset-both'), 'blocked');
  for (const a of ['deny', 'drop', 'block-url']) {
    assert.equal(classifyAction(a), 'blocked', a);
  }
});

test('classifyAction: an unrecognised action is unknown, never allowed', () => {
  // ⛔ THE IMPORTANT ONE. An action string from a vendor this engine has never
  // seen must not be able to manufacture a patch_now.
  for (const a of ['weird-vendor-verb', '', '   ', null, undefined, 42, {}]) {
    assert.equal(classifyAction(a), 'unknown', String(a));
  }
});

test('classifyAction: case and padding do not change the verdict', () => {
  assert.equal(classifyAction('  ALLOW '), 'allowed');
  assert.equal(classifyAction('Deny'), 'blocked');
});

// ─────────────────────────── getCuratedPorts ──────────────────────────

test('getCuratedPorts: rejects out-of-range and non-numeric ports', () => {
  const pool = makePool([
    [
      'FROM advisory_conditions',
      [
        { advisory_id: ADV, port: '443' },
        { advisory_id: ADV, port: '0' },
        { advisory_id: ADV, port: '70000' },
        { advisory_id: ADV, port: 'https' },
        { advisory_id: ADV, port: null },
        { advisory_id: ADV, port: '8.5' },
      ],
    ],
  ]);
  return getCuratedPorts(pool).then((m) => {
    assert.deepEqual(Array.from(m.get(ADV)), [443]);
  });
});

test('getDeviceInterfaceIps: strips the prefix length', async () => {
  const pool = makePool([['FROM device_interfaces', [{ device_id: DEV, ip: '10.150.1.4' }]]]);
  const m = await getDeviceInterfaceIps(pool);
  assert.deepEqual(Array.from(m.get(DEV)), ['10.150.1.4']);
});

// ──────────────────── runLogHitCorrelation: firing ────────────────────

test('fires when a curated port is reached from a public source', async () => {
  const pool = makePool(
    baseHandlers({
      reached: [{ dst_port: 10443, events: '412', sources: 37, last_seen: new Date(0) }],
    })
  );
  const s = await runLogHitCorrelation(pool);
  assert.equal(s.setTrue, 1);
  assert.equal(s.hits[0].port, 10443);
  assert.equal(s.hits[0].sources, 37);
  const wrote = pool.calls.find((c) => c.sql.includes('SET log_hit'));
  assert.equal(wrote.params[0], true);
});

test('the reach query restricts to the public-source ranges', async () => {
  const pool = makePool(baseHandlers());
  await runLogHitCorrelation(pool);
  const q = pool.calls.find((c) => c.sql.includes('GROUP BY dst_port'));
  // If this filter is ever dropped, internal admin traffic to a management
  // port would escalate every curated advisory on the device.
  for (const cidr of ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10']) {
    assert.ok(q.sql.includes(cidr), 'missing ' + cidr);
  }
});

test('timestamp parameters are cast explicitly', async () => {
  const pool = makePool(baseHandlers());
  await runLogHitCorrelation(pool);
  for (const c of pool.calls.filter((x) => x.sql.includes('received_at >='))) {
    assert.ok(c.sql.includes('::timestamptz'), 'uncast timestamp param');
  }
});

// ──────────────── runLogHitCorrelation: declining to fire ─────────────

test('no curated conditions means no work and no syslog scan at all', async () => {
  const pool = makePool(baseHandlers({ conditions: [] }));
  const s = await runLogHitCorrelation(pool);
  assert.equal(s.curatedAdvisories, 0);
  assert.equal(s.setTrue, 0);
  assert.ok(!pool.calls.some((c) => c.sql.includes('syslog_events')));
});

test('a device with no syslog coverage is SKIPPED, not written false', async () => {
  // ⛔ The failed-read-as-a-fact case. "We were not listening" must never be
  // recorded as "nothing reached it".
  const pool = makePool(
    baseHandlers({
      coverage: [],
      assessments: [{ id: 'a1', device_id: DEV, advisory_id: ADV, log_hit: true }],
    })
  );
  const s = await runLogHitCorrelation(pool);
  assert.equal(s.devicesSkippedNoCoverage, 1);
  assert.equal(s.setFalse, 0);
  assert.ok(!pool.calls.some((c) => c.sql.includes('SET log_hit')));
});

test('a device with no collected interfaces is SKIPPED, not written false', async () => {
  // Without the device's own addresses we cannot tell traffic TO it from
  // traffic THROUGH it, so there is no measurement to record either way.
  const pool = makePool(
    baseHandlers({
      interfaces: [],
      assessments: [{ id: 'a1', device_id: DEV, advisory_id: ADV, log_hit: true }],
    })
  );
  const s = await runLogHitCorrelation(pool);
  assert.equal(s.devicesSkippedNoInterfaces, 1);
  assert.equal(s.setFalse, 0);
  assert.ok(!pool.calls.some((c) => c.sql.includes('SET log_hit')));
});

test('a covered device with no reach clears a stale true', async () => {
  // The rolling-window counterpart: coverage exists, nothing was reached, so
  // `false` here is a real measurement rather than an absence.
  const pool = makePool(
    baseHandlers({
      assessments: [{ id: 'a1', device_id: DEV, advisory_id: ADV, log_hit: true }],
      reached: [],
    })
  );
  const s = await runLogHitCorrelation(pool);
  assert.equal(s.setFalse, 1);
  assert.equal(pool.calls.find((c) => c.sql.includes('SET log_hit')).params[0], false);
});

test('an unchanged value is not rewritten', async () => {
  const pool = makePool(baseHandlers({ reached: [] }));
  const s = await runLogHitCorrelation(pool);
  assert.equal(s.setTrue, 0);
  assert.equal(s.setFalse, 0);
  assert.ok(!pool.calls.some((c) => c.sql.includes('SET log_hit')));
});

test('a hit on any one of several curated ports is enough', async () => {
  const pool = makePool(
    baseHandlers({
      conditions: [
        { advisory_id: ADV, port: '443' },
        { advisory_id: ADV, port: '10443' },
      ],
      reached: [{ dst_port: 10443, events: '5', sources: 2, last_seen: new Date(0) }],
    })
  );
  const s = await runLogHitCorrelation(pool);
  assert.equal(s.setTrue, 1);
});

// ───────────────────────────── robustness ─────────────────────────────

test('never throws — a DB failure is reported in the summary', async () => {
  const pool = {
    async query() {
      throw new Error('connection reset');
    },
  };
  const s = await runLogHitCorrelation(pool);
  assert.ok(Array.isArray(s.errors) && s.errors.length > 0);
  assert.equal(s.setTrue, 0);
});

test('a per-device failure does not abort the other devices', async () => {
  const DEV2 = '33333333-3333-3333-3333-333333333333';
  let n = 0;
  const pool = {
    calls: [],
    async query(sql, params) {
      this.calls.push({ sql, params });
      if (sql.includes('FROM advisory_conditions')) return { rows: [{ advisory_id: ADV, port: '10443' }] };
      if (sql.includes('FROM device_interfaces')) {
        return { rows: [{ device_id: DEV, ip: '1.1.1.1' }, { device_id: DEV2, ip: '2.2.2.2' }] };
      }
      if (sql.includes('FROM device_cve_assessments')) {
        return {
          rows: [
            { id: 'a1', device_id: DEV, advisory_id: ADV, log_hit: false },
            { id: 'a2', device_id: DEV2, advisory_id: ADV, log_hit: false },
          ],
        };
      }
      if (sql.includes('LIMIT 1')) {
        n++;
        if (n === 1) throw new Error('partition missing');
        return { rows: [{ '?column?': 1 }] };
      }
      if (sql.includes('GROUP BY dst_port')) {
        return { rows: [{ dst_port: 10443, events: '9', sources: 3, last_seen: new Date(0) }] };
      }
      return { rows: [] };
    },
  };
  const s = await runLogHitCorrelation(pool);
  assert.equal(s.errors.length, 1);
  assert.equal(s.setTrue, 1, 'the healthy device was still processed');
});

test('lookback is clamped to a sane window', async () => {
  for (const [given, want] of [[0, 7], [-5, 7], [NaN, 7], [500, 90], [14, 14]]) {
    const s = await runLogHitCorrelation(makePool(baseHandlers({ conditions: [] })), {
      lookbackDays: given,
    });
    assert.equal(s.lookbackDays, want, 'lookbackDays=' + given);
  }
});
