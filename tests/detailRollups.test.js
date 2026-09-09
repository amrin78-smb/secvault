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
    // ⛔ The deny vocabulary now comes from the SHARED set (lib/syslog/
    // actions.js) rather than a literal. There were four divergent lists and
    // the narrowest drove every dashboard number: measured live, the old
    // 4-verb literal missed 6.8% of blocks fleet-wide and 24% on URL-category
    // rows, because `block-url` — the only URL-filtering block verb PAN-OS
    // emits — was absent. `block` itself never appears on this fleet at all.
    assert.match(BLOCKED_INSERT, /lower\(action\) IN \(/);
    assert.ok(BLOCKED_INSERT.includes("'block-url'"), 'block-url must be counted as a block');
    assert.ok(BLOCKED_INSERT.includes("'deny'") && BLOCKED_INSERT.includes("'drop'"));
    assert.match(BLOCKED_INSERT, /(WHERE|AND) dst_ip IS NOT NULL/);
  });

  it('the host rollup counts denies alongside events', () => {
    assert.match(TALKER_INSERT, /count\(\*\) FILTER \(WHERE lower\(action\) IN \(/);
    assert.ok(TALKER_INSERT.includes("'block-url'"));
  });

  it('⛔ every rollup uses the SAME deny vocabulary', () => {
    // Four divergent copies is how this went wrong. Pin that they agree.
    const { DENIED_SQL } = require('../lib/syslog/actions');
    for (const [name, sql] of [
      ['BLOCKED_INSERT', BLOCKED_INSERT],
      ['TALKER_INSERT', TALKER_INSERT],
    ]) {
      assert.ok(sql.includes(DENIED_SQL), `${name} must use the shared deny list`);
    }
    // And that the list is a directly substitutable SQL fragment — a bare
    // comma list produced `IN 'deny','drop'`, a syntax error that would abort
    // the whole nine-rollup sweep transaction.
    assert.ok(DENIED_SQL.startsWith('(') && DENIED_SQL.endsWith(')'));
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
    assert.equal(windowed.length, 11, 'one temp-table scan + one DELETE per rollup');
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

  it('trims every detail rollup by bucket_hour', async () => {
    const pool = trimPool();
    const out = await trimDetailRollups(pool, 30);
    assert.equal(out.days, 30);
    // ⛔ Every DETAIL rollup must be trimmed. One missing from this list is a
    // table that grows forever while the log still reports success.
    // syslog_threat_hourly added 2026-09-09: it was the omission this comment
    // warns about, measured at 119,404 rows / 70 MB in 27 hours (~22 GB/year)
    // with nothing anywhere deleting a row from it.
    assert.deepEqual(Object.keys(out.deleted).sort(), [
      'syslog_app_hourly', 'syslog_blocked_dst_hourly', 'syslog_country_hourly',
      'syslog_device_inbound_hourly', 'syslog_talker_hourly', 'syslog_threat_hourly',
      'syslog_urlcat_hourly', 'syslog_user_hourly', 'syslog_vpn_auth_hourly',
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

// ─────────────────────────────────────────────────────────────────────────
// syslog_device_inbound_hourly — the Internet Exposure / log_hit input
// ─────────────────────────────────────────────────────────────────────────
//
// This rollup exists because the same question against raw syslog_events took
// OVER TWO MINUTES for one device-day (measured 2026-09-08). Both
// lib/engines/exposureQuery.js and lib/engines/logHit.js depend on it, and
// both delegate their "was the source public / was the traffic allowed"
// decision to it. That makes the classification below load-bearing for a CVE
// priority band, so it is pinned here rather than only in the engines.

const { INBOUND_INSERT } = require('../lib/syslog/rollups');

it('inbound rollup: guards the inet cast BEFORE casting', () => {
  // ⛔ device_interfaces.ip_address is TEXT and carries the literal 'N/A' on
  // live rows. Casting that raises "invalid input syntax for type inet",
  // which would abort the sweep TRANSACTION and take the other seven rollups
  // down with it. The regex must be applied before the cast.
  const guardPos = INBOUND_INSERT.indexOf('~ ');
  const castPos = INBOUND_INSERT.indexOf("split_part(ip_address, '/', 1)::inet");
  assert.ok(guardPos > -1, 'no regex guard present');
  assert.ok(castPos > -1, 'no inet cast present');
  assert.ok(
    /split_part\(ip_address, '\/', 1\) ~ /.test(INBOUND_INSERT),
    'the cast must be guarded by a dotted-quad regex on the same expression'
  );
});

it('inbound rollup: bounded to the devices own published addresses', () => {
  // ⛔ Without the devip join this aggregates every destination on the
  // internet — unbounded cardinality, the same trap syslog_blocked_dst_hourly
  // avoids by only storing blocked destinations.
  assert.ok(INBOUND_INSERT.includes('devip'), 'must join the bounded address set');
  assert.ok(
    /\) devip ON devip\.device_id = s\.device_id AND devip\.ip = s\.dst_ip/.test(INBOUND_INSERT),
    'must join on BOTH device and address — device alone would store all traffic'
  );
  assert.ok(INBOUND_INSERT.includes('nat_rules'), 'must include NAT-published addresses');
  assert.ok(
    /lower\(n\.nat_type\) = 'destination'/.test(INBOUND_INSERT),
    'only destination NAT publishes an inbound address'
  );
});

it('inbound rollup: classifies actions three ways, never two', () => {
  // The allowed list must contain Fortinet's session-END actions: a session
  // that existed and closed WAS reached. FortiGate SSL-VPN on 10443 is logged
  // `close`, never `allow`.
  for (const a of ['allow', 'accept', 'close', 'client-rst', 'server-rst']) {
    assert.ok(INBOUND_INSERT.includes(`'${a}'`), 'allowed action missing: ' + a);
  }
  // Palo Alto's reset-both is a BLOCK despite resembling the above.
  assert.ok(INBOUND_INSERT.includes("'reset-both'"), 'reset-both must be classified as blocked');
  // ⛔ The third state. An action in neither list must land on NULL, never be
  // folded into allowed — NULL is what keeps an unknown vendor verb from
  // escalating a CVE to patch_now.
  assert.ok(/ELSE NULL/.test(INBOUND_INSERT), 'unknown actions must resolve to NULL');
});

it('inbound rollup: public-source determination covers every private range', () => {
  // This is where the exposure engines' "from the internet" guarantee actually
  // lives now. If a range is dropped here, internal traffic starts counting as
  // an internet-sourced hit in BOTH engines at once.
  for (const cidr of [
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10',
  ]) {
    assert.ok(INBOUND_INSERT.includes(cidr), 'missing private range: ' + cidr);
  }
  // A NULL source must stay NULL rather than counting as public.
  assert.ok(/s\.src_ip IS NULL THEN NULL/.test(INBOUND_INSERT));
});

// ─────────────────────────────────────────────────────────────────────────
// The UI must use the SAME action vocabulary as the rollups (added 2026-09-09)
// ─────────────────────────────────────────────────────────────────────────
//
// Two UI files carried their OWN deny lists — the fifth and sixth copies — and
// both were wrong, in opposite directions:
//
//   components/logs/LogResults.js     anything not in its list rendered as a
//                                     GREEN "success" badge, so ~78,000 blocked
//                                     events and ~290,000 unclassifiable ones
//                                     were shown to the reader as allowed.
//   components/dashboard/SyslogWidgets.js
//                                     listed client-rst/server-rst as DENIED,
//                                     but those are Fortinet SESSION-END verbs
//                                     meaning the session existed and was
//                                     permitted.
//
// This pins the vocabulary itself so a seventh copy has something to fail
// against.

const { classifyAction: uiClassify } = require('../lib/syslog/actions');

it('⛔ verbs seen live on this fleet classify correctly', () => {
  // Every one of these was measured in the live rollups.
  // ⛔ `timeout` MOVED SIDES on 2026-09-09 — it is a FortiOS session-teardown
  // verb, not a refusal, and asserting it as a block here was pinning the bug.
  // See tests/actionClassification.test.js for the captured line and the live
  // measurements.
  for (const a of ['allow', 'accept', 'close', 'client-rst', 'server-rst', 'timeout']) {
    assert.equal(uiClassify(a), 'allowed', a);
  }
  for (const a of ['deny', 'drop', 'blocked', 'block-url', 'reset-both']) {
    assert.equal(uiClassify(a), 'blocked', a);
  }
});

it('⛔ an unclassifiable verb is UNKNOWN — never allowed, never blocked', () => {
  // These are real, high-volume live verbs that belong to neither vocabulary.
  // Folding them into "allowed" is what made a failed VPN login look like a
  // permitted session.
  for (const a of ['ssl-login-fail', 'alert', 'dns', 'negotiate', 'ip-conn', 'analytics']) {
    assert.equal(uiClassify(a), 'unknown', a);
  }
});

it('the fleet does not emit reset-client/reset-server — client-rst/server-rst do', () => {
  // The old UI list was written from documentation rather than captured logs.
  // Keep both spellings classified so neither can silently become "allowed",
  // but the ones that actually occur are the -rst forms.
  assert.equal(uiClassify('client-rst'), 'allowed');
  assert.equal(uiClassify('reset-client'), 'blocked');
});
