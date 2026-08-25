'use strict';
// Pins lib/engines/configRetention.js — the ONLY engine in SecVault that
// DELETES production data.
//
// WHY THIS FILE EXISTS: retention shipped 2026-08-25 to bound `device_configs`
// (449 MB of a 529 MB database, ~9.5 MB/day, no retention of any kind). The
// job is safe only because of four protections that CLAUDE.md requires to be
// expressed TWICE each — once in the classification query, once in the DELETE
// predicate — precisely so a single careless edit cannot be the only thing
// standing between a retention run and a data-loss incident. A test that only
// checked "does it delete?" would happily pass while a protection was quietly
// removed, so these tests assert on the SQL the engine BUILDS as well as on
// how it interprets results.
//
// ⛔ NO DATABASE. `runConfigRetention(pool, options)` only ever calls
// `pool.query(sql, params)`, so every test hands it a stub that records the
// statements it was given and returns canned rows. That gives two independent
// things to pin: the SQL/params the engine constructs, and its interpretation
// of whatever comes back.
//
// SQL assertions match a meaningful FRAGMENT, never a whole string, and each
// says in a comment which protection the fragment stands for — a legitimate
// reformat is then a one-line test update, while a REMOVED protection still
// fails loudly.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  runConfigRetention,
  formatRetentionSummary,
  DEFAULT_CONFIG_RETENTION_DAYS,
  DEFAULT_BACKUP_RETENTION_DAYS,
  MIN_KEEP_CONFIGS,
  MIN_KEEP_BACKUPS,
  DEFAULT_MAX_ROWS_PER_RUN,
  AUTO_BACKUP_LABEL,
} = require('../lib/engines/configRetention');

// --------------------------------------------------------------------------
// Stub pool + helpers
// --------------------------------------------------------------------------

// Default canned classification: one row per bucket, so every branch of the
// summary's bucket-accumulator is exercised on a normal run.
const CANNED_BUCKETS = [
  { bucket: 'protected', rows: 4 },
  { bucket: 'newest', rows: 3 },
  { bucket: 'min_keep', rows: 20 },
  { bucket: 'within_window', rows: 100 },
  { bucket: 'deletable', rows: 7 },
];

const isDeleteStatement = (sql) => /\bDELETE\s+FROM\b/i.test(String(sql));
const isNameLookup = (sql) => /FROM\s+devices\s+WHERE/i.test(String(sql));

function cannedResult(sql) {
  if (isDeleteStatement(sql)) return { rows: [{ device_id: 'dev-1' }, { device_id: 'dev-1' }], rowCount: 2 };
  if (isNameLookup(sql)) return { rows: [{ id: 'dev-1', name: 'edge-fw-01' }], rowCount: 1 };
  return { rows: CANNED_BUCKETS.map((b) => ({ ...b })), rowCount: CANNED_BUCKETS.length };
}

// Records every {sql, params} it is handed. `handler` may return a result
// object, or an Error instance meaning "reject with this".
function stubPool(handler) {
  const calls = [];
  return {
    calls,
    query(sql, params) {
      calls.push({ sql: String(sql), params });
      const result = handler ? handler(String(sql), params, calls.length) : undefined;
      if (result instanceof Error) return Promise.reject(result);
      return Promise.resolve(result === undefined ? cannedResult(sql) : result);
    },
  };
}

function classifyCall(pool, table) {
  const call = pool.calls.find(
    (c) => new RegExp(`\\b${table}\\b`).test(c.sql) && !isDeleteStatement(c.sql) && /GROUP BY/i.test(c.sql)
  );
  assert.ok(call, `expected a classification query against ${table}`);
  return call;
}

function deleteCall(pool, table) {
  const call = pool.calls.find((c) => new RegExp(`DELETE\\s+FROM\\s+${table}\\b`, 'i').test(c.sql));
  assert.ok(call, `expected a DELETE against ${table}`);
  return call;
}

// The victims CTE is the inner half of the DELETE; the outer DELETE ... USING
// is the second, redundant half. Splitting them lets a test prove a protection
// appears in BOTH halves rather than once anywhere in the statement.
function splitDelete(sql) {
  const idx = sql.search(/\bDELETE\s+FROM\b/i);
  assert.ok(idx > -1, 'expected a DELETE keyword');
  return { victims: sql.slice(0, idx), outer: sql.slice(idx) };
}

// --------------------------------------------------------------------------
// A. The four protections, asserted against the SQL the engine actually builds
// --------------------------------------------------------------------------

describe('configRetention: protection 1 — an is_baseline row is never deleted, at any age', () => {
  it('classifies baseline rows into a protected bucket that is not the delete target', async () => {
    const pool = stubPool();
    await runConfigRetention(pool);
    const sql = classifyCall(pool, 'device_configs').sql;
    // `is_baseline IS NOT FALSE` (not `= true`) so a NULL counts as PROTECTED.
    assert.match(sql, /is_baseline\s+IS\s+NOT\s+FALSE/i, 'classify lost its is_baseline guard');
    assert.match(sql, /WHEN\s+is_protected\s+THEN\s+'protected'/i, 'protected must be the FIRST bucket tested');
    // Order matters: protected is evaluated before the age/window branches, so
    // no baseline row can ever fall through into 'deletable'.
    assert.ok(
      sql.indexOf("'protected'") < sql.indexOf("'deletable'"),
      'the protected branch must precede the deletable branch in the CASE'
    );
  });

  it('guards is_baseline TWICE inside the DELETE — once in victims, once on the outer statement', async () => {
    const pool = stubPool();
    await runConfigRetention(pool);
    const { victims, outer } = splitDelete(deleteCall(pool, 'device_configs').sql);
    // Half one: victims selects only rows whose is_protected (is_baseline IS
    // NOT FALSE) is false.
    assert.match(victims, /is_baseline\s+IS\s+NOT\s+FALSE/i, 'victims CTE lost its is_baseline computation');
    assert.match(victims, /is_protected\s*=\s*false/i, 'victims CTE lost its is_protected = false filter');
    // Half two: the DELETE itself re-tests the real column, so a row must fail
    // the baseline test twice to be removed.
    assert.match(outer, /is_baseline\s+IS\s+FALSE/i, 'the outer DELETE lost its redundant is_baseline guard');
  });
});

describe('configRetention: protection 2 — the newest row per device is never deleted, at any age', () => {
  it('classifies rn = 1 as newest, ahead of every age-based branch', async () => {
    const pool = stubPool();
    await runConfigRetention(pool);
    for (const table of ['device_configs', 'config_backups']) {
      const sql = classifyCall(pool, table).sql;
      assert.match(sql, /row_number\(\)\s+OVER\s+\(PARTITION BY device_id/i, `${table}: lost its per-device ranking`);
      assert.match(sql, /WHEN\s+rn\s*=\s*1\s+THEN\s+'newest'/i, `${table}: lost its newest-per-device bucket`);
      assert.ok(
        sql.indexOf("'newest'") < sql.indexOf("'within_window'"),
        `${table}: newest must be tested before any age branch`
      );
    }
  });

  it('restates rn > 1 in the DELETE so the guard does not depend on the minKeep variable', async () => {
    const pool = stubPool();
    await runConfigRetention(pool);
    for (const table of ['device_configs', 'config_backups']) {
      const { victims } = splitDelete(deleteCall(pool, table).sql);
      // `rn > $2` already implies this because minKeep is clamped to >= 1, but
      // the literal `rn > 1` is restated on purpose: "never delete a device's
      // newest row" must not be contingent on the value of a bind parameter.
      assert.match(victims, /rn\s*>\s*1\b/, `${table}: the literal rn > 1 guard was removed`);
      assert.match(victims, /rn\s*>\s*\$2/, `${table}: the minKeep-derived rank guard was removed`);
    }
  });

  it('ranks rows identically in the classify and the DELETE, so "kept" is derived from the delete logic', async () => {
    const pool = stubPool();
    await runConfigRetention(pool);
    const windows = [
      ['device_configs', /PARTITION BY device_id\s+ORDER BY collected_at DESC, id DESC/i],
      ['config_backups', /PARTITION BY device_id\s+ORDER BY backed_up_at DESC, id DESC/i],
    ];
    for (const [table, windowRe] of windows) {
      assert.match(classifyCall(pool, table).sql, windowRe, `${table}: classify window drifted`);
      assert.match(deleteCall(pool, table).sql, windowRe, `${table}: DELETE window drifted from classify`);
    }
  });
});

describe('configRetention: protection 3 — a per-device minimum count survives regardless of age', () => {
  it('keeps the documented floors as exported constants (10 configs / 5 backups)', () => {
    // Constants, not env vars, on purpose: safety floors are not tuning knobs.
    assert.equal(MIN_KEEP_CONFIGS, 10);
    assert.equal(MIN_KEEP_BACKUPS, 5);
  });

  it('classifies the first N rows per device as min_keep, ahead of the age branch', async () => {
    const pool = stubPool();
    await runConfigRetention(pool);
    for (const table of ['device_configs', 'config_backups']) {
      const sql = classifyCall(pool, table).sql;
      assert.match(sql, /WHEN\s+rn\s*<=\s*\$2\s+THEN\s+'min_keep'/i, `${table}: lost its min-keep bucket`);
      assert.ok(
        sql.indexOf("'min_keep'") < sql.indexOf("'within_window'"),
        `${table}: min-keep must be tested before the age window`
      );
    }
  });

  it('passes the SAME minKeep bind value to the classify and the DELETE', async () => {
    const pool = stubPool();
    await runConfigRetention(pool);
    // If these ever diverge, the "kept" count reported to the operator stops
    // describing what the DELETE actually spared.
    assert.equal(classifyCall(pool, 'device_configs').params[1], MIN_KEEP_CONFIGS);
    assert.equal(deleteCall(pool, 'device_configs').params[1], MIN_KEEP_CONFIGS);
    assert.equal(classifyCall(pool, 'config_backups').params[1], MIN_KEEP_BACKUPS);
    assert.equal(deleteCall(pool, 'config_backups').params[1], MIN_KEEP_BACKUPS);
  });

  it('is not reachable from the environment — MIN_KEEP_* cannot be lowered by an env var', async () => {
    const saved = { c: process.env.MIN_KEEP_CONFIGS, b: process.env.MIN_KEEP_BACKUPS };
    process.env.MIN_KEEP_CONFIGS = '0';
    process.env.MIN_KEEP_BACKUPS = '0';
    try {
      const pool = stubPool();
      await runConfigRetention(pool);
      assert.equal(deleteCall(pool, 'device_configs').params[1], MIN_KEEP_CONFIGS);
      assert.equal(deleteCall(pool, 'config_backups').params[1], MIN_KEEP_BACKUPS);
    } finally {
      if (saved.c === undefined) delete process.env.MIN_KEEP_CONFIGS;
      else process.env.MIN_KEEP_CONFIGS = saved.c;
      if (saved.b === undefined) delete process.env.MIN_KEEP_BACKUPS;
      else process.env.MIN_KEEP_BACKUPS = saved.b;
    }
  });
});

describe("configRetention: protection 4 — a config_backups row not labelled 'auto' is never deleted", () => {
  it("treats any label distinct from 'auto' (including NULL) as operator-created and protected", async () => {
    const pool = stubPool();
    await runConfigRetention(pool);
    const call = classifyCall(pool, 'config_backups');
    // IS DISTINCT FROM, not <>, so a NULL label is protected rather than
    // silently NULL-ing out of the comparison and becoming deletable.
    assert.match(call.sql, /label\s+IS\s+DISTINCT\s+FROM\s+\$3/i, 'classify lost its label guard');
    assert.match(call.sql, /WHEN\s+is_protected\s+THEN\s+'protected'/i);
    assert.equal(AUTO_BACKUP_LABEL, 'auto');
    assert.equal(call.params[2], AUTO_BACKUP_LABEL, "the 'auto' label must be a bind parameter, not interpolated");
  });

  it('guards the label TWICE inside the DELETE — once in victims, once on the outer statement', async () => {
    const pool = stubPool();
    await runConfigRetention(pool);
    const call = deleteCall(pool, 'config_backups');
    const { victims, outer } = splitDelete(call.sql);
    assert.match(victims, /label\s+IS\s+DISTINCT\s+FROM\s+\$4/i, 'victims CTE lost its label computation');
    assert.match(victims, /is_protected\s*=\s*false/i, 'victims CTE lost its is_protected = false filter');
    assert.match(outer, /label\s+IS\s+NOT\s+DISTINCT\s+FROM\s+\$4/i, 'the outer DELETE lost its redundant label guard');
    assert.equal(call.params[3], AUTO_BACKUP_LABEL);
  });

  it('does not apply the label guard to device_configs (that table has no label column)', async () => {
    const pool = stubPool();
    await runConfigRetention(pool);
    assert.doesNotMatch(deleteCall(pool, 'device_configs').sql, /\blabel\b/i);
  });
});

describe('configRetention: the two retention windows stay separate and parameterized', () => {
  it('uses the long backup window and the short config window, never one shared value', async () => {
    const pool = stubPool();
    await runConfigRetention(pool);
    assert.equal(DEFAULT_CONFIG_RETENTION_DAYS, 60);
    assert.equal(DEFAULT_BACKUP_RETENTION_DAYS, 365);
    // Every config_backups row is a distinct moment of real change; applying
    // the 60d config window here would destroy the long-term change record.
    assert.equal(deleteCall(pool, 'device_configs').params[0], '60');
    assert.equal(deleteCall(pool, 'config_backups').params[0], '365');
  });

  it('binds the day counts as parameters instead of interpolating them into the SQL', async () => {
    const pool = stubPool();
    await runConfigRetention(pool, { configRetentionDays: 4242, backupRetentionDays: 9797 });
    for (const call of pool.calls) {
      assert.doesNotMatch(call.sql, /4242|9797/, 'a day count was interpolated into the SQL text');
    }
    assert.match(deleteCall(pool, 'device_configs').sql, /\(\$1 \|\| ' days'\)::interval/);
    assert.equal(deleteCall(pool, 'device_configs').params[0], '4242');
    assert.equal(deleteCall(pool, 'config_backups').params[0], '9797');
  });

  it('caps rows removed per run so a backlog drains over several runs, not one huge transaction', async () => {
    const pool = stubPool();
    await runConfigRetention(pool);
    assert.equal(DEFAULT_MAX_ROWS_PER_RUN, 5000);
    for (const table of ['device_configs', 'config_backups']) {
      const call = deleteCall(pool, table);
      assert.match(call.sql, /LIMIT \$3/, `${table}: lost its per-run LIMIT`);
      // Oldest-first, so when the cap bites it always removes the oldest rows;
      // id breaks ties so repeat runs are deterministic.
      assert.match(call.sql, /ORDER BY ts ASC, id ASC/i, `${table}: victims ordering is no longer oldest-first`);
      assert.equal(call.params[2], DEFAULT_MAX_ROWS_PER_RUN);
    }
  });
});

// --------------------------------------------------------------------------
// B. Clamping — the safety floors hold under hostile input
// --------------------------------------------------------------------------

describe('configRetention: minKeep clamps to >= 1 so protection 2 survives a hostile caller', () => {
  // 0 and negatives would otherwise make `rn > $2` true for rn = 1 — i.e. the
  // newest row per device would become deletable by the first half of the
  // DELETE. (The literal `rn > 1` is the second half that still catches it;
  // the clamp is what stops the situation arising at all.)
  const hostile = [
    ['zero', 0],
    ['a negative', -5],
    ['null', null],
    ['undefined', undefined],
    ['NaN', NaN],
    ['a non-numeric string', 'lots'],
    ['an empty string', ''],
    ['a boolean', true],
    ['an object', {}],
  ];

  for (const [label, value] of hostile) {
    it(`falls back to the documented floors when minKeep is ${label}`, async () => {
      const pool = stubPool();
      await runConfigRetention(pool, { minKeepConfigs: value, minKeepBackups: value });
      const cfgDelete = deleteCall(pool, 'device_configs');
      const bakDelete = deleteCall(pool, 'config_backups');
      assert.equal(cfgDelete.params[1], MIN_KEEP_CONFIGS, `device_configs minKeep was not clamped for ${label}`);
      assert.equal(bakDelete.params[1], MIN_KEEP_BACKUPS, `config_backups minKeep was not clamped for ${label}`);
      // The property that actually matters, independent of the constants.
      assert.ok(cfgDelete.params[1] >= 1);
      assert.ok(bakDelete.params[1] >= 1);
      // The classify must see the same clamped value or the reported "kept"
      // number stops matching what the DELETE spared.
      assert.equal(classifyCall(pool, 'device_configs').params[1], MIN_KEEP_CONFIGS);
      assert.equal(classifyCall(pool, 'config_backups').params[1], MIN_KEEP_BACKUPS);
    });

    it(`falls back to the documented retention windows when the day count is ${label}`, async () => {
      const pool = stubPool();
      await runConfigRetention(pool, { configRetentionDays: value, backupRetentionDays: value });
      // A 0/negative window would mean "delete everything older than now".
      assert.equal(deleteCall(pool, 'device_configs').params[0], String(DEFAULT_CONFIG_RETENTION_DAYS));
      assert.equal(deleteCall(pool, 'config_backups').params[0], String(DEFAULT_BACKUP_RETENTION_DAYS));
    });

    it(`falls back to the documented per-run cap when maxRowsPerRun is ${label}`, async () => {
      const pool = stubPool();
      await runConfigRetention(pool, { maxRowsPerRun: value });
      assert.equal(deleteCall(pool, 'device_configs').params[2], DEFAULT_MAX_ROWS_PER_RUN);
      assert.equal(deleteCall(pool, 'config_backups').params[2], DEFAULT_MAX_ROWS_PER_RUN);
    });
  }

  it('accepts a legitimate explicit override rather than ignoring every caller value', async () => {
    const pool = stubPool();
    await runConfigRetention(pool, {
      configRetentionDays: 30,
      backupRetentionDays: 90,
      minKeepConfigs: 25,
      minKeepBackups: 12,
      maxRowsPerRun: 100,
    });
    assert.deepEqual(deleteCall(pool, 'device_configs').params, ['30', 25, 100]);
    assert.deepEqual(deleteCall(pool, 'config_backups').params, ['90', 12, 100, 'auto']);
  });

  it('never reports a minKeep below 1 in the summary it hands the operator', async () => {
    const pool = stubPool();
    const summary = await runConfigRetention(pool, { minKeepConfigs: -1, minKeepBackups: 0 });
    assert.ok(summary.deviceConfigs.minKeepPerDevice >= 1);
    assert.ok(summary.configBackups.minKeepPerDevice >= 1);
    assert.equal(summary.deviceConfigs.minKeepPerDevice, MIN_KEEP_CONFIGS);
    assert.equal(summary.configBackups.minKeepPerDevice, MIN_KEEP_BACKUPS);
  });
});

// --------------------------------------------------------------------------
// C. ⛔ NEVER THROWS
// --------------------------------------------------------------------------

describe('configRetention: never throws — it runs inside the engine service alongside other jobs', () => {
  it('resolves with the error in the summary when pool.query REJECTS', async () => {
    const pool = stubPool(() => new Error('connection terminated unexpectedly'));
    const summary = await runConfigRetention(pool);
    assert.match(summary.deviceConfigs.error, /connection terminated/);
    assert.match(summary.configBackups.error, /connection terminated/);
    assert.equal(summary.deviceConfigs.deleted, 0);
    assert.equal(summary.configBackups.deleted, 0);
  });

  it('resolves when pool.query THROWS SYNCHRONOUSLY (not every driver rejects)', async () => {
    const calls = [];
    const pool = {
      calls,
      query(sql, params) {
        calls.push({ sql: String(sql), params });
        throw new TypeError('pool is closed');
      },
    };
    const summary = await runConfigRetention(pool);
    assert.match(summary.deviceConfigs.error, /pool is closed/);
    assert.match(summary.configBackups.error, /pool is closed/);
  });

  it('resolves with a "no pool supplied" summary when pool is null', async () => {
    const summary = await runConfigRetention(null);
    assert.equal(summary.deviceConfigs.error, 'no pool supplied');
    assert.equal(summary.configBackups.error, 'no pool supplied');
    assert.equal(summary.deviceConfigs.deleted, 0);
    assert.equal(summary.configBackups.deleted, 0);
  });

  it('resolves when pool is undefined and no options are passed at all', async () => {
    const summary = await runConfigRetention(undefined);
    assert.equal(summary.deviceConfigs.error, 'no pool supplied');
    assert.equal(summary.configBackups.error, 'no pool supplied');
    // The windows it WOULD have used are still reported, so the log line is
    // still diagnostic rather than blank.
    assert.equal(summary.deviceConfigs.retentionDays, DEFAULT_CONFIG_RETENTION_DAYS);
    assert.equal(summary.configBackups.retentionDays, DEFAULT_BACKUP_RETENTION_DAYS);
  });

  it('resolves when pool has no query method at all', async () => {
    const summary = await runConfigRetention({});
    assert.ok(summary.deviceConfigs.error, 'expected an error, not a silent success');
    assert.ok(summary.configBackups.error);
  });

  it('resolves when a null options object is passed instead of an object', async () => {
    const pool = stubPool();
    const summary = await runConfigRetention(pool, null);
    assert.equal(summary.deviceConfigs.error, null);
    assert.equal(summary.deviceConfigs.retentionDays, DEFAULT_CONFIG_RETENTION_DAYS);
  });

  const malformed = [
    ['a result with no rows property', { rowCount: 0 }],
    ['a result whose rows is not an array', { rows: 42, rowCount: 0 }],
    ['a result whose rows is null', { rows: null, rowCount: 0 }],
    ['no result object at all', null],
  ];
  for (const [label, result] of malformed) {
    it(`resolves rather than rejecting on ${label}`, async () => {
      const pool = stubPool((sql) => (isDeleteStatement(sql) || isNameLookup(sql) ? cannedResult(sql) : result));
      const summary = await runConfigRetention(pool);
      assert.ok(summary.deviceConfigs.error, `${label}: expected the failure to be reported, not thrown`);
      assert.ok(summary.configBackups.error);
      assert.equal(typeof summary.durationMs, 'number');
    });
  }

  it('resolves when the DELETE returns a rowCount but no RETURNING rows', async () => {
    const pool = stubPool((sql) => (isDeleteStatement(sql) ? { rowCount: 3 } : undefined));
    const summary = await runConfigRetention(pool);
    assert.ok(summary.deviceConfigs.error, 'a malformed DELETE result must surface as an error, not a throw');
  });

  it('still processes config_backups when device_configs fails — that isolation is the point', async () => {
    const pool = stubPool((sql) => {
      if (/\bdevice_configs\b/.test(sql)) return new Error('deadlock detected');
      return undefined;
    });
    const summary = await runConfigRetention(pool);
    assert.match(summary.deviceConfigs.error, /deadlock detected/);
    assert.equal(summary.configBackups.error, null, 'config_backups must not be skipped by the other table failing');
    assert.equal(summary.configBackups.deleted, 2);
    assert.ok(
      pool.calls.some((c) => /DELETE\s+FROM\s+config_backups/i.test(c.sql)),
      'the second table must still have had its DELETE issued'
    );
  });

  it('still processes device_configs when config_backups fails', async () => {
    const pool = stubPool((sql) => {
      if (/\bconfig_backups\b/.test(sql)) return new Error('relation does not exist');
      return undefined;
    });
    const summary = await runConfigRetention(pool);
    assert.equal(summary.deviceConfigs.error, null);
    assert.equal(summary.deviceConfigs.deleted, 2);
    assert.match(summary.configBackups.error, /relation does not exist/);
  });

  it('degrades a failed device-name lookup to ids instead of failing the run', async () => {
    // Names are cosmetic. A device row vanishing between the DELETE and the
    // lookup must never turn a completed retention run into a reported failure.
    const pool = stubPool((sql) => (isNameLookup(sql) ? new Error('name lookup blew up') : undefined));
    const summary = await runConfigRetention(pool);
    assert.equal(summary.deviceConfigs.error, null, 'a cosmetic lookup failure must not fail the table');
    assert.equal(summary.deviceConfigs.deleted, 2);
    assert.deepEqual(summary.deviceConfigs.perDevice, [{ deviceId: 'dev-1', name: 'dev-1', deleted: 2 }]);
  });
});

// --------------------------------------------------------------------------
// D. dryRun issues NO DELETE at all
// --------------------------------------------------------------------------

describe('configRetention: dryRun is provably read-only', () => {
  it('issues not one statement containing DELETE', async () => {
    const pool = stubPool();
    const summary = await runConfigRetention(pool, { dryRun: true });
    assert.equal(summary.dryRun, true);
    const offenders = pool.calls.filter((c) => /\bDELETE\b/i.test(c.sql));
    assert.deepEqual(
      offenders.map((c) => c.sql),
      [],
      'dryRun is the mode used to verify retention against production before arming the job'
    );
  });

  it('issues exactly the two classification queries and nothing else', async () => {
    const pool = stubPool();
    await runConfigRetention(pool, { dryRun: true });
    assert.equal(pool.calls.length, 2);
    assert.ok(/\bdevice_configs\b/.test(pool.calls[0].sql));
    assert.ok(/\bconfig_backups\b/.test(pool.calls[1].sql));
  });

  it('reports what it WOULD delete and nothing as actually deleted', async () => {
    const pool = stubPool();
    const summary = await runConfigRetention(pool, { dryRun: true });
    assert.equal(summary.deviceConfigs.wouldDelete, 7);
    assert.equal(summary.deviceConfigs.deleted, 0);
    assert.equal(summary.deviceConfigs.devices, 0);
    assert.deepEqual(summary.deviceConfigs.perDevice, []);
  });

  it('honours the STRING spellings of dryRun, because env vars have no booleans', async () => {
    // ⛔ Changed 2026-08-25. This was `=== true`, so `dryRun: 'true'` -- the
    // only thing an env var or JSON config can hold -- ran the job FOR REAL.
    // On the one engine that destroys data, misreading an explicit request
    // for a rehearsal as permission to delete is the wrong way to be wrong.
    for (const affirmative of [true, 'true', 'TRUE', ' yes ', '1', 'on']) {
      const pool = stubPool();
      const summary = await runConfigRetention(pool, { dryRun: affirmative });
      assert.equal(summary.dryRun, true, `dryRun: ${JSON.stringify(affirmative)} must disarm the job`);
      assert.ok(
        !pool.calls.some((c) => isDeleteStatement(c.sql)),
        `dryRun: ${JSON.stringify(affirmative)} must issue no DELETE`
      );
    }
  });

  it('stays ARMED for an unrecognised dryRun value, so a typo cannot silently disable cleanup', async () => {
    // The default direction is deliberately the opposite of the rule above:
    // an affirmative we recognise disarms, anything else leaves the
    // scheduled job doing its job.
    for (const junk of ['nope', 'false', 0, 1, {}, null, undefined]) {
      const pool = stubPool();
      const summary = await runConfigRetention(pool, { dryRun: junk });
      assert.equal(summary.dryRun, false, `dryRun: ${JSON.stringify(junk)} must not disarm the job`);
      assert.ok(pool.calls.some((c) => isDeleteStatement(c.sql)));
    }
  });

  it('flags capped in dryRun when more rows are eligible than one run may remove', async () => {
    const pool = stubPool((sql) =>
      isDeleteStatement(sql) ? cannedResult(sql) : { rows: [{ bucket: 'deletable', rows: 12000 }], rowCount: 1 }
    );
    const summary = await runConfigRetention(pool, { dryRun: true, maxRowsPerRun: 5000 });
    assert.equal(summary.deviceConfigs.wouldDelete, 12000);
    assert.equal(summary.deviceConfigs.capped, true);
  });
});

// --------------------------------------------------------------------------
// E. formatRetentionSummary is pure and reports what was KEPT
// --------------------------------------------------------------------------

function tableSummary(overrides) {
  return Object.assign(
    {
      retentionDays: 60,
      minKeepPerDevice: 10,
      totalRows: 1300,
      devices: 2,
      deleted: 66,
      wouldDelete: 66,
      capped: false,
      kept: { baseline: 4, newestPerDevice: 3, minKeep: 20, withinWindow: 1207, total: 1234 },
      perDevice: [{ deviceId: 'dev-1', name: 'edge-fw-01', deleted: 66 }],
      error: null,
    },
    overrides
  );
}

describe('formatRetentionSummary: an operator must be able to tell retention from data loss', () => {
  it('reports what was KEPT, broken down by which protection kept it', () => {
    const [line] = formatRetentionSummary({
      dryRun: false,
      deviceConfigs: tableSummary(),
      configBackups: null,
    });
    assert.match(line, /kept 1234 of 1300/, 'the kept total is the whole point of this line');
    assert.match(line, /4 baseline/, 'protection 1 must be attributed by name');
    assert.match(line, /3 newest-per-device/, 'protection 2 must be attributed by name');
    assert.match(line, /20 within min-keep 10/, 'protection 3 must be attributed by name');
    assert.match(line, /1207 within 60d window/);
  });

  it("names the backups table's protection as operator-labelled, not baseline", () => {
    const lines = formatRetentionSummary({
      dryRun: false,
      deviceConfigs: null,
      configBackups: tableSummary({ retentionDays: 365, minKeepPerDevice: 5, perDevice: [] }),
    });
    assert.match(lines[0], /^config_backups:/);
    assert.match(lines[0], /4 operator-labelled/, 'protection 4 must be attributed by name');
  });

  it('reports the per-run cap rather than silently understating what remains', () => {
    const [line] = formatRetentionSummary({
      dryRun: false,
      deviceConfigs: tableSummary({ deleted: 5000, wouldDelete: 12000, capped: true, perDevice: [] }),
      configBackups: null,
    });
    // Without this, "deleted 5000" reads like the whole job was done.
    assert.match(line, /capped at 12000 eligible/);
    assert.match(line, /remainder next run/);
  });

  it('says nothing was deleted when a table errored having removed nothing', () => {
    const [line] = formatRetentionSummary({
      dryRun: false,
      deviceConfigs: tableSummary({ error: 'deadlock detected', deleted: 0 }),
      configBackups: null,
    });
    assert.match(line, /FAILED/);
    assert.match(line, /deadlock detected/);
    assert.match(line, /nothing deleted from this table/);
  });

  it('does NOT claim a clean run when the failure came AFTER rows were deleted', () => {
    // ⛔ Changed 2026-08-25. `summary.deleted` is assigned from rowCount
    // BEFORE the RETURNING rows are tallied, so a throw in between left a
    // summary carrying both a real deletion count and an error -- and the
    // error branch printed "nothing deleted from this table" over the top of
    // it. Understating what a destructive job actually did is the worst
    // direction for this log line to be wrong.
    const [line] = formatRetentionSummary({
      dryRun: false,
      deviceConfigs: tableSummary({ error: 'connection terminated', deleted: 412 }),
      configBackups: null,
    });
    assert.match(line, /FAILED/);
    assert.match(line, /412/, "the operator must be told rows were already removed");
    assert.doesNotMatch(line, /nothing deleted from this table/);
  });

  it('phrases a dry run as "would delete", never as a completed deletion', () => {
    const [line] = formatRetentionSummary({
      dryRun: true,
      deviceConfigs: tableSummary({ deleted: 0, perDevice: [] }),
      configBackups: null,
    });
    assert.match(line, /would delete 66 row\(s\)/);
    assert.doesNotMatch(line, /^device_configs: deleted/);
  });

  it('truncates the per-device breakdown but says how many were hidden', () => {
    const perDevice = Array.from({ length: 25 }, (_, i) => ({
      deviceId: `dev-${i}`,
      name: `fw-${i}`,
      deleted: 25 - i,
    }));
    const lines = formatRetentionSummary({
      dryRun: false,
      deviceConfigs: tableSummary({ perDevice }),
      configBackups: null,
    });
    assert.equal(lines.length, 2);
    assert.match(lines[1], /\+5 more/, 'a truncated list must state what it truncated');
  });

  it('does not throw or mutate its input, and is stable across repeated calls', () => {
    const summary = { dryRun: false, deviceConfigs: tableSummary(), configBackups: tableSummary() };
    const before = JSON.stringify(summary);
    const first = formatRetentionSummary(summary);
    const second = formatRetentionSummary(summary);
    assert.deepEqual(first, second);
    assert.equal(JSON.stringify(summary), before, 'the formatter must be pure');
  });

  it('handles a missing summary and missing tables without throwing', () => {
    assert.deepEqual(formatRetentionSummary(null), ['config retention produced no summary.']);
    assert.deepEqual(formatRetentionSummary(undefined), ['config retention produced no summary.']);
    assert.deepEqual(formatRetentionSummary({ dryRun: false }), []);
  });
});

// --------------------------------------------------------------------------
// F. Idempotency of interpretation
// --------------------------------------------------------------------------

describe('configRetention: a second run over an already-trimmed fleet is a clean no-op', () => {
  const nothingLeft = [
    { bucket: 'protected', rows: 4 },
    { bucket: 'newest', rows: 3 },
    { bucket: 'min_keep', rows: 20 },
    { bucket: 'within_window', rows: 100 },
  ];

  it('reports zero deletions, zero eligible and no error', async () => {
    const pool = stubPool((sql) => {
      if (isDeleteStatement(sql)) return { rows: [], rowCount: 0 };
      if (isNameLookup(sql)) return { rows: [], rowCount: 0 };
      return { rows: nothingLeft.map((b) => ({ ...b })), rowCount: nothingLeft.length };
    });
    const summary = await runConfigRetention(pool);
    for (const table of ['deviceConfigs', 'configBackups']) {
      const t = summary[table];
      assert.equal(t.error, null, `${table}: a no-op run must not report an error`);
      assert.equal(t.deleted, 0);
      assert.equal(t.wouldDelete, 0);
      assert.equal(t.devices, 0);
      assert.equal(t.capped, false);
      assert.deepEqual(t.perDevice, []);
    }
  });

  it('accounts for every row: kept.total + wouldDelete == totalRows', async () => {
    const pool = stubPool();
    const summary = await runConfigRetention(pool);
    const t = summary.deviceConfigs;
    // 4 + 3 + 20 + 100 kept, 7 deletable, 134 total. If a future bucket name is
    // added to the SQL and not to the accumulator, this is what catches it.
    assert.equal(t.totalRows, 134);
    assert.equal(t.kept.total, 127);
    assert.equal(t.wouldDelete, 7);
    assert.equal(t.kept.total + t.wouldDelete, t.totalRows);
  });

  it('does not skip the device-name lookup for the ids it actually deleted', async () => {
    const pool = stubPool();
    const summary = await runConfigRetention(pool);
    assert.equal(summary.deviceConfigs.devices, 1);
    assert.deepEqual(summary.deviceConfigs.perDevice, [{ deviceId: 'dev-1', name: 'edge-fw-01', deleted: 2 }]);
    const lookup = pool.calls.find((c) => isNameLookup(c.sql));
    assert.ok(lookup, 'expected a name lookup');
    assert.deepEqual(lookup.params, [['dev-1']], 'ids must be bound as an array parameter, not interpolated');
  });
});
