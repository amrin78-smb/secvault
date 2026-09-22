// tests/dbCheckHarness.test.js
//
// The PURE half of scripts/dbCheck.js, fed the shapes a live run never
// produces.
//
// ⛔ WHY A TEST FOR A TEST TOOL. `npm run dbcheck` talks to a production
// database, so on this fleet it has only ever returned green. A harness that
// has never gone red proves nothing: the whole value of the tool is in the
// branches a healthy fleet does not exercise — the wrong column name, the
// swallowed error, the permission refusal, the function that resolves without
// issuing a statement. Every one of those is reproduced here from synthetic
// input, exactly as tests/smokeHarness.test.js feeds `pageVerdict` the
// v2.120.0 blank-page shape.
//
// ⛔ THIS FILE TOUCHES NO DATABASE and must never be made to. `require`ing
// scripts/dbCheck.js opens no socket (its `main()` is behind
// `require.main === module`), which tests/moduleLoad.test.js' rule already
// depends on elsewhere in this repo.
//
// ⛔ AND IT PINS THE GUARDS, NOT JUST THE REPORT. The read-only name guard and
// the statement guard are the only things standing between this tool and a
// write against a live security database; a regression in either must fail a
// build rather than be discovered by its consequences.

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const dc = require('../scripts/dbCheck.js');

// ── 0. the ROLE assertion ──────────────────────────────────────────────────

test('⛔ the role guard refuses the APPLICATION role — guard 1 was never enforced', () => {
  // ⛔ THE LIVE SHAPE. `DBCHECK_URL` overrides the connection string and
  // `current_user` was printed and never checked, so an operator chasing a
  // missing grant types `DBCHECK_URL=$DATABASE_URL npm run dbcheck` and every
  // registered function runs as the table OWNER against production.
  const v = dc.assertReadOnlyRole({
    user: 'secvault_user', superuser: false, writableTables: 78, writableSample: 'advisories, devices',
  });
  assert.equal(v.ok, false);
  assert.match(v.reason, /INSERT\/UPDATE\/DELETE on 78 table\(s\)/);
  assert.match(v.reason, /DBCHECK_URL/, 'the message must say what to do next');
});

test('the role guard refuses a superuser', () => {
  const v = dc.assertReadOnlyRole({ user: 'postgres', superuser: true, writableTables: 0 });
  assert.equal(v.ok, false);
  assert.match(v.reason, /SUPERUSER/);
});

test('⛔ an UNKNOWN privilege answer is refused, not read as "may write nothing"', () => {
  // ⛔ `Number(null)` is 0 and 0 is finite, so a bare Number.isFinite guard
  // would turn "we could not read this" into a clean bill of health — the
  // same substitution CLAUDE.md names over the licence guard's maxDevices,
  // here on the check that decides whether this tool may talk to production.
  for (const w of [
    { user: 'x', superuser: false, writableTables: null },
    { user: 'x', superuser: false, writableTables: undefined },
    { user: 'x', superuser: false, writableTables: '' },
    { user: 'x', superuser: false, writableTables: 'lots' },
  ]) {
    const v = dc.assertReadOnlyRole(w);
    assert.equal(v.ok, false, `${JSON.stringify(w)} must be refused`);
    assert.match(v.reason, /UNKNOWN/);
  }
  // and an unknown SUPERUSER answer is refused for the same reason
  assert.equal(dc.assertReadOnlyRole({ user: 'x', superuser: null, writableTables: 0 }).ok, false);
  assert.equal(dc.assertReadOnlyRole({ user: '', superuser: false, writableTables: 0 }).ok, false);
  assert.equal(dc.assertReadOnlyRole(null).ok, false);
});

test('and the real diagnostics role passes', () => {
  const v = dc.assertReadOnlyRole({ user: 'claude_readonly', superuser: false, writableTables: 0 });
  assert.equal(v.ok, true);
  assert.equal(v.user, 'claude_readonly');
});

// ── 1. the read-only NAME guard ────────────────────────────────────────────

test('name guard accepts the read verbs this repo actually uses', () => {
  for (const name of [
    'getLastSyncs', 'listIntents', 'loadFleet', 'buildRuleHygieneData',
    'computeFleetExposure', 'gatherWorkQueue', 'queryAccessPath',
    'summariseCloudUsage', 'evaluateSegmentation', 'correlateDeviceRules',
    'searchEvents', 'windowCoverage', 'standardCoverage',
  ]) {
    assert.equal(dc.checkReadOnlyName(name).ok, true, `${name} should be accepted`);
  }
});

test('name guard refuses every writer name that exists in lib/', () => {
  // Real exports from this repo. Each one would mutate a production database.
  for (const name of [
    'storeVpnSessions', 'saveView', 'runComplianceAuditForDevice',
    'collectAndStore', 'dispatchNotification', 'trimDetailRollups',
    'dropOldPartitions', 'createApplication', 'updateFlow', 'deleteIntent',
    'setCredential', 'enqueueJob', 'claimNextJob', 'finishJob', 'reapStaleJobs',
    'activateLicense', 'clearLicense', 'recordConnectivity', 'seedAuditChecks',
    'generateReportPdf', 'verifyRequestsForDevice', 'submitRequest',
  ]) {
    const v = dc.checkReadOnlyName(name);
    assert.equal(v.ok, false, `${name} must be refused`);
    assert.match(v.reason, /names a write|not a known read verb/);
  }
});

test('name guard FAILS CLOSED on a verb it has never seen', () => {
  // ⛔ The branch that earns the guard its place. A new export called
  // `refreshFoo` or `rebuildBar` is refused until a human reads it — the cost
  // of a wrong "allow" here is a write against a live security database.
  for (const name of ['refreshCache', 'rebuildIndex', 'touchRow', 'mangleThings']) {
    const v = dc.checkReadOnlyName(name);
    assert.equal(v.ok, false, `${name} must fail closed`);
    assert.match(v.reason, /not a known read verb/);
  }
});

test('name guard refuses a name it cannot read at all', () => {
  for (const name of ['', null, undefined, 'GetThings', '_getThings', '123']) {
    assert.equal(dc.checkReadOnlyName(name).ok, false, `${JSON.stringify(name)} must be refused`);
  }
});

test('assertReadOnlyRegistry throws and names every offender, rather than skipping them', () => {
  // ⛔ A skipped entry is a silently shorter report, and a shorter report looks
  // complete. So this throws.
  assert.throws(
    () => dc.assertReadOnlyRegistry([
      { mod: 'lib/a.js', fn: 'getThings' },
      { mod: 'lib/b.js', fn: 'storeThings' },
      { mod: 'lib/c.js', fn: 'deleteThings' },
    ]),
    (err) => {
      assert.match(err.message, /2 registered function\(s\) may write/);
      assert.match(err.message, /lib\/b\.js/);
      assert.match(err.message, /lib\/c\.js/);
      assert.doesNotMatch(err.message, /lib\/a\.js/);
      return true;
    }
  );
});

test('the shipped registry passes its own guard', () => {
  assert.doesNotThrow(() => dc.assertReadOnlyRegistry(dc.REGISTRY));
  assert.ok(dc.REGISTRY.length > 80, 'the registry should cover the product, not a sample');
});

test('every registry entry is well formed, so a typo cannot silently skip a check', () => {
  for (const e of dc.REGISTRY) {
    assert.equal(typeof e.mod, 'string', `${JSON.stringify(e)} needs a module path`);
    assert.match(e.mod, /^lib\//, `${e.mod} must live under lib/`);
    assert.equal(typeof e.fn, 'string');
    assert.equal(typeof e.args, 'function', `${e.fn} needs an args builder`);
    assert.equal(typeof e.spec, 'object', `${e.fn} needs a shape spec`);
    // args() must not throw on a context with nothing in it but the fields the
    // runner always supplies — a throwing args builder would abort the sweep.
    const ctx = {
      now: new Date(),
      deviceId: '00000000-0000-0000-0000-000000000000',
      deviceIds: [],
      window: { from: new Date(0), to: new Date(1), clamped: false },
      window20: { from: new Date(0), to: new Date(1), clamped: false },
    };
    assert.doesNotThrow(() => e.args(ctx), `${e.fn}'s args builder threw`);
    assert.ok(Array.isArray(e.args(ctx)), `${e.fn}'s args builder must return an array`);
  }
});

test('the registry has no duplicate entries', () => {
  const seen = new Set();
  for (const e of dc.REGISTRY) {
    const key = `${e.mod}#${e.fn}`;
    assert.equal(seen.has(key), false, `${key} is registered twice`);
    seen.add(key);
  }
});

// ── 2. the STATEMENT guard ─────────────────────────────────────────────────

test('statement guard admits the reads this tool legitimately issues', () => {
  for (const sql of [
    'SELECT 1',
    '  \n  SELECT a FROM b',
    '-- a leading comment\nSELECT a FROM b',
    '/* block */ SELECT a FROM b',
    'WITH t AS (SELECT 1) SELECT * FROM t',
    'SHOW statement_timeout',
    'EXPLAIN SELECT 1',
    'BEGIN',
    'COMMIT',
    'ROLLBACK',
    // lib/syslog/logSearch.js does exactly this, on a dedicated client, and it
    // is the right thing for it to do.
    'SET LOCAL statement_timeout = 10000',
  ]) {
    assert.equal(dc.guardStatement(sql).ok, true, `${sql} should be admitted`);
  }
});

test('statement guard refuses every write shape', () => {
  const cases = [
    ['INSERT INTO settings (key) VALUES ($1)', /INSERT statement/],
    ['UPDATE devices SET active = false', /UPDATE statement/],
    ['DELETE FROM advisories', /DELETE statement/],
    ['TRUNCATE syslog_events', /TRUNCATE statement/],
    ['DROP TABLE devices', /DROP statement/],
    ['ALTER TABLE devices ADD COLUMN x TEXT', /ALTER statement/],
    ['CREATE TABLE t (a int)', /CREATE statement/],
    ['GRANT SELECT ON t TO claude_readonly', /GRANT statement/],
    ['COPY t FROM STDIN', /COPY statement/],
    ['CALL do_something()', /CALL statement/],
    ['DO $$ BEGIN END $$', /DO statement/],
    ['VACUUM FULL syslog_events', /VACUUM statement/],
    ['', /empty statement/],
  ];
  for (const [sql, re] of cases) {
    const v = dc.guardStatement(sql);
    assert.equal(v.ok, false, `${sql} must be refused`);
    assert.match(v.reason, re);
  }
});

test('statement guard refuses a READ-NAMED WRITER — the reason guard 2 exists', () => {
  // ⛔ THE CONCRETE CASE. lib/productLicenseData.js's `resolveInstallDate`
  // begins with "resolve", which IS a read verb, and it INSERTs into
  // `settings`. The name guard passes it. The statement guard is what stops
  // it, which is why both exist and why neither is redundant.
  assert.equal(dc.checkReadOnlyName('resolveInstallDate').ok, true);
  const v = dc.guardStatement(
    'INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING'
  );
  assert.equal(v.ok, false);
  assert.match(v.reason, /INSERT statement/);
});

test('statement guard refuses a data-modifying CTE', () => {
  for (const sql of [
    'WITH d AS (DELETE FROM advisories RETURNING id) SELECT * FROM d',
    'WITH u AS (UPDATE devices SET active = false RETURNING id) SELECT * FROM u',
    'WITH i AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM i',
  ]) {
    const v = dc.guardStatement(sql);
    assert.equal(v.ok, false, `${sql} must be refused`);
    assert.match(v.reason, /data-modifying CTE/);
  }
});

test('statement guard does not mistake the WORD "delete" in a literal for a write', () => {
  // A refusal here would be a false alarm, and a false alarm trains the next
  // person to delete the guard.
  const v = dc.guardStatement("WITH t AS (SELECT 'delete' AS verb) SELECT * FROM t");
  assert.equal(v.ok, true);
});

test('statement guard refuses SET ROLE / SET SESSION AUTHORIZATION', () => {
  for (const sql of ['SET ROLE secvault_user', 'SET SESSION AUTHORIZATION secvault_user']) {
    const v = dc.guardStatement(sql);
    assert.equal(v.ok, false);
    assert.match(v.reason, /change who this is/);
  }
});

test('statement guard refuses an UNBOUNDED read of syslog_events', () => {
  // ⛔ ~28M rows/day, and a careless scan evicts the buffer cache out from
  // under an ingest running at ~1,000 inserts/sec.
  const bad = dc.guardStatement('SELECT count(*) FROM syslog_events');
  assert.equal(bad.ok, false);
  assert.match(bad.reason, /no received_at bound/);

  const alsoBad = dc.guardStatement('SELECT src_ip FROM syslog_events WHERE device_id = $1');
  assert.equal(alsoBad.ok, false);

  const good = dc.guardStatement(
    "SELECT id FROM syslog_events WHERE received_at >= now() - interval '20 minutes' LIMIT 5"
  );
  assert.equal(good.ok, true);
});

test('⛔ statement guard reads EVERY statement, not just the leading verb', () => {
  // ⛔ node-pg sends a multi-statement string as a simple query whenever no
  // parameter array is passed, and PostgreSQL executes all of it. So
  // `SELECT 1; DELETE FROM advisories` was a WRITE that returned ok from a
  // guard reading only the first word. No registered function does this
  // today; the guard's job is to survive the day one does.
  for (const [sql, re] of [
    ['SELECT 1; DELETE FROM advisories', /DELETE statement/],
    ['SELECT 1; INSERT INTO settings (key) VALUES ($1)', /INSERT statement/],
    ['BEGIN; UPDATE devices SET active = false; COMMIT', /UPDATE statement/],
    ['SELECT 1;\n  -- a comment\n  DROP TABLE devices', /DROP statement/],
    ['SELECT 1; WITH d AS (DELETE FROM advisories RETURNING id) SELECT * FROM d', /data-modifying CTE/],
  ]) {
    const v = dc.guardStatement(sql);
    assert.equal(v.ok, false, `${sql} must be refused`);
    assert.match(v.reason, re);
    assert.match(v.reason, /statement \d+ of \d+/, 'the message must say WHICH statement objected');
  }
});

test('a genuinely chained pair of READS is still admitted, and a trailing semicolon is not a statement', () => {
  // A refusal here would be a false alarm, and a false alarm trains the next
  // person to delete the guard.
  assert.equal(dc.guardStatement('SELECT 1; SELECT 2').ok, true);
  assert.equal(dc.guardStatement('SELECT 1;').ok, true);
  assert.equal(dc.guardStatement('BEGIN; SELECT 1; COMMIT').ok, true);
});

test('a semicolon INSIDE a literal does not fake a statement break', () => {
  const v = dc.guardStatement("SELECT * FROM t WHERE msg = 'a; DELETE FROM advisories'");
  assert.equal(v.ok, true);
  assert.equal(v.statements, 1);
});

test('splitStatements keeps dollar-quoted blocks and doubled quotes whole', () => {
  assert.equal(dc.splitStatements("SELECT $$a;b$$ AS x").length, 1);
  assert.equal(dc.splitStatements("SELECT 'it''s; fine' AS x").length, 1);
  assert.equal(dc.splitStatements('SELECT 1 /* ; */ ; SELECT 2').length, 2);
});

test('⛔ a syslog_events read must be BOUNDED, not merely mention the column', () => {
  // ⛔ THE OLD TEST WAS A SUBSTRING MATCH ON THE WHOLE STATEMENT, so this —
  // a full scan of every retained partition against a live ingest — passed,
  // under a comment claiming "an entirely unbounded read is refused outright".
  const bad = dc.guardStatement('SELECT received_at, src_ip FROM syslog_events');
  assert.equal(bad.ok, false);
  assert.match(bad.reason, /no received_at bound/);
  assert.match(bad.reason, /naming the column is not bounding it/);

  // an upper bound alone is not a bound: it scans everything behind it
  assert.equal(dc.guardStatement('SELECT id FROM syslog_events WHERE received_at < $1').ok, false);
  // ORDER BY is not a predicate either
  assert.equal(dc.guardStatement('SELECT id FROM syslog_events ORDER BY received_at DESC LIMIT 5').ok, false);
  // and neither is reading a partition by name
  assert.equal(dc.guardStatement('SELECT id FROM syslog_events_20260922 LIMIT 5').ok, false);
});

test('and every shape this product actually uses is still admitted', () => {
  // Each of these is a live query from the registry's own modules; a false
  // refusal here would take the raw-table readers out of the sweep entirely.
  for (const sql of [
    "SELECT id FROM syslog_events WHERE received_at >= now() - interval '20 minutes' LIMIT 5",
    "SELECT e.received_at FROM syslog_events e WHERE e.received_at >= now() - ($1::int * interval '1 hour') AND e.log_class = 'vpn'",
    'SELECT id FROM syslog_events WHERE received_at >= $1 AND received_at < $2 ORDER BY received_at DESC',
    "SELECT id FROM syslog_events WHERE received_at BETWEEN $1 AND $2",
    'SELECT id FROM syslog_events WHERE $1 <= received_at',
    // serverHealth counts partitions by NAME, in a literal — it reads no rows
    "SELECT tablename FROM pg_tables WHERE tablename ~ '^syslog_events_[0-9]{8}$'",
  ]) {
    assert.equal(dc.guardStatement(sql).ok, true, `${sql} should be admitted`);
  }
});

test('statement guard accepts an object-form query, as pg does', () => {
  assert.equal(dc.guardStatement({ text: 'SELECT 1', values: [] }).ok, true);
  assert.equal(dc.guardStatement({ text: 'DELETE FROM t' }).ok, false);
});

// ── 3. error classification ────────────────────────────────────────────────

test('a wrong column name is a FAILURE and the message says what is wrong', () => {
  // ⛔ THE v2.86.1 SHAPE, exactly: `feed_sync_log.completed_at` does not exist.
  const v = dc.classifyError({
    code: '42703',
    message: 'column f.completed_at does not exist',
  });
  assert.equal(v.state, 'fail');
  assert.match(v.reason, /names a column that does not exist/);
  assert.match(v.reason, /completed_at/);
});

test('every class-42 defect code is classified as a failure, not swallowed', () => {
  for (const code of Object.keys(dc.DEFECT_CODES)) {
    const v = dc.classifyError({ code, message: 'boom' });
    assert.equal(v.state, 'fail', `${code} must fail`);
  }
});

test('the missing ::timestamptz cast has its own message', () => {
  const v = dc.classifyError({
    code: '42P18',
    message: 'could not determine data type of parameter $1',
  });
  assert.equal(v.state, 'fail');
  assert.match(v.reason, /::timestamptz/);
});

test('a permission error on a DELIBERATELY denied table is `blocked`, never `ok`', () => {
  for (const table of dc.EXPECTED_UNREADABLE) {
    const v = dc.classifyError({
      code: '42501',
      message: `permission denied for table ${table}`,
    });
    assert.equal(v.state, 'blocked', `${table} should be blocked`);
    assert.notEqual(v.state, 'ok');
    // ⛔ The message must say BOTH facts: the grants policy held, AND the query
    // was not verified. Collapsing the second into a pass is the
    // failed-read-as-a-fact bug applied to this tool's own reporting.
    assert.match(v.reason, /deliberately denied/);
    assert.match(v.reason, /NOT verified/);
  }
});

test('device_credentials specifically is blocked, not failed — the grants policy working', () => {
  const v = dc.classifyError({ code: '42501', message: 'permission denied for table device_credentials' });
  assert.equal(v.state, 'blocked');
});

test('a permission error on ANY OTHER table is a FAILURE — a missing per-table GRANT', () => {
  const v = dc.classifyError({ code: '42501', message: 'permission denied for table firewall_rules' });
  assert.equal(v.state, 'fail');
  assert.match(v.reason, /missing per-table GRANT SELECT/);
});

test('a statement timeout is a failure with its own wording', () => {
  const v = dc.classifyError({ code: '57014', message: 'canceling statement due to statement timeout' });
  assert.equal(v.state, 'fail');
  assert.match(v.reason, /statement timeout/);
});

test('an UNRECOGNISED rejection is a failure — not evidence that things are fine', () => {
  for (const err of [
    { code: 'XX000', message: 'internal error' },
    { message: 'something threw with no code' },
    new Error('a plain Error'),
  ]) {
    assert.equal(dc.classifyError(err).state, 'fail');
  }
});

// ── 4. shape assertions ────────────────────────────────────────────────────

test('an array spec rejects a non-array', () => {
  const { problems } = dc.checkShape({ a: 1 }, { array: true });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /callers iterate it as an array/);
});

test('rowKeys catches a renamed column in the rows that came back', () => {
  const { problems } = dc.checkShape(
    [{ feed_name: 'nvd', status: 'ok', started_at: 1, completed_at: 2 }],
    { array: true, rowKeys: ['feed_name', 'status', 'started_at', 'finished_at'] }
  );
  assert.equal(problems.length, 1);
  assert.match(problems[0], /missing finished_at/);
  // the message must also show what IS there, or the reader cannot act on it
  assert.match(problems[0], /completed_at/);
});

test('rowKeys on an EMPTY array is UNVERIFIED, never ok', () => {
  // ⛔ An empty table proves nothing about the column names a row would have
  // carried. An assertion that passes because there was nothing to check is
  // this codebase's signature bug wearing a test's clothes.
  const { problems, unverified } = dc.checkShape([], { array: true, rowKeys: ['id'] });
  assert.deepEqual(problems, []);
  assert.equal(unverified.length, 1);
  assert.match(unverified[0], /not verified/);
});

test('an object spec catches a missing key and names the keys present', () => {
  const { problems } = dc.checkShape(
    { windowDays: 1, intents: [], summary: {} },
    { object: ['results', 'rulesCollected'] }
  );
  assert.equal(problems.length, 1);
  assert.match(problems[0], /missing results, rulesCollected/);
  assert.match(problems[0], /windowDays/);
});

test('a key PRESENT AND UNDEFINED is reported separately — the worse case', () => {
  // ⛔ `'k' in obj` is true, so every reader destructures a confident
  // undefined and no error is raised anywhere. This is the 2026-09-21 shape
  // (a `sum(...) FILTER (...)` the caller believed was a real zero) and it is
  // why "did not throw" is not the whole check.
  const { problems } = dc.checkShape({ total: undefined }, { object: ['total'] });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /present but undefined/);
});

test('null is a failure unless the spec permits it, and a permitted null is UNVERIFIED', () => {
  const strict = dc.checkShape(null, { object: ['a'] });
  assert.equal(strict.problems.length, 1);
  assert.match(strict.problems[0], /no caller handles/);

  const lenient = dc.checkShape(null, { nullable: true, object: ['a'] });
  assert.deepEqual(lenient.problems, []);
  assert.equal(lenient.unverified.length, 1);
  assert.match(lenient.unverified[0], /not verified/);
});

test('undefined is always a failure', () => {
  assert.equal(dc.checkShape(undefined, {}).problems.length, 1);
});

// ── 5. the swallowed-error harvest ─────────────────────────────────────────

test('harvests gatherWorkQueue\'s per-source failure', () => {
  // ⛔ THE MOST IMPORTANT CHECK IN THE TOOL. gatherWorkQueue isolates every
  // source, so a broken query RESOLVES and contributes zero items. A checker
  // that only asked "did it throw" would report green over a page rendering a
  // named gap where a table should be.
  const found = dc.harvestSwallowedErrors({
    items: [],
    sources: [
      { key: 'cve', ok: true, count: 1 },
      { key: 'rule_cleanup', ok: false, error: 'operator does not exist: text = uuid' },
    ],
  });
  assert.equal(found.length, 1);
  assert.match(found[0], /rule_cleanup/);
  assert.match(found[0], /text = uuid/);
});

test('harvests errors, sectionErrors and failures alike', () => {
  assert.equal(dc.harvestSwallowedErrors({ errors: [{ message: 'a' }] }).length, 1);
  assert.equal(dc.harvestSwallowedErrors({ sectionErrors: [{ section: 's', message: 'b' }] }).length, 1);
  assert.equal(dc.harvestSwallowedErrors({ failures: [{ name: 'n', message: 'c' }] }).length, 1);
  assert.equal(
    dc.harvestSwallowedErrors({ errors: ['a'], sectionErrors: ['b'], failures: ['c'] }).length,
    3
  );
});

test('harvests gatherExecutiveSummary\'s keyed sections', () => {
  const found = dc.harvestSwallowedErrors({
    sections: {
      headline: { ok: true, value: {} },
      compliance: { ok: false, error: 'relation "audit_findings" does not exist' },
    },
  });
  assert.equal(found.length, 1);
  assert.match(found[0], /compliance/);
});

test('a source reporting ok:false with NO message is still harvested', () => {
  const found = dc.harvestSwallowedErrors({ sources: [{ key: 'x', ok: false }] });
  assert.equal(found.length, 1);
  assert.match(found[0], /no message/);
});

test('⛔ harvests an ARRAY-shaped result — the blind spot that hid getServiceLiveness', () => {
  // ⛔ THE LIVE SHAPE. serverHealth.getServiceLiveness returns
  // [{name, lastSeen, ageSeconds, error?}] and catches PER ELEMENT. Rename a
  // column on feed_sync_log or syslog_ingest_stats and both its queries throw,
  // both are caught, the array is the right length, its spec ({}) is
  // satisfied — and this tool reported `ok` for the function whose whole job
  // is saying whether the Engine and the Collector are alive.
  const found = dc.harvestSwallowedErrors([
    { name: 'Engine (feeds, matching, retention)', lastSeen: null, ageSeconds: null, error: 'column "started_at" does not exist' },
    { name: 'Collector (syslog ingest)', lastSeen: new Date(), ageSeconds: 4 },
  ]);
  assert.equal(found.length, 1);
  assert.match(found[0], /Engine/);
  assert.match(found[0], /started_at/);
});

test('an array element reporting ok:false is harvested even with no message', () => {
  const found = dc.harvestSwallowedErrors([{ key: 'cve', ok: false }, { key: 'rules', ok: true }]);
  assert.equal(found.length, 1);
  assert.match(found[0], /cve/);
  assert.match(found[0], /no message/);
});

test('⛔ but a DATABASE ROW carrying an `error` COLUMN is not a swallowed error', () => {
  // background_jobs.error and compliance_report_log.error are facts about a
  // JOB, not about our query. Harvesting them would be a false alarm, and a
  // false alarm is what trains the next person to delete the check. Every such
  // row carries its primary key; a status-report element does not.
  assert.deepEqual(
    dc.harvestSwallowedErrors([{ id: 'b3f0…', job_type: 'collect', status: 'failed', error: 'the firewall refused the connection' }]),
    []
  );
  assert.deepEqual(dc.harvestSwallowedErrors([{ id: 'x', period: '2026-09', status: 'error', error: 'smtp refused' }]), []);
});

test('an array of ordinary rows harvests nothing', () => {
  assert.deepEqual(dc.harvestSwallowedErrors([{ feed_name: 'nvd', status: 'success' }]), []);
  assert.deepEqual(dc.harvestSwallowedErrors([]), []);
  assert.deepEqual(dc.harvestSwallowedErrors([null, 'text', 42]), []);
});

test('a clean result harvests nothing', () => {
  assert.deepEqual(dc.harvestSwallowedErrors({ errors: [], sectionErrors: [], failures: [] }), []);
  assert.deepEqual(dc.harvestSwallowedErrors({ sources: [{ key: 'a', ok: true }] }), []);
  assert.deepEqual(dc.harvestSwallowedErrors(null), []);
  assert.deepEqual(dc.harvestSwallowedErrors('not an object'), []);
});

test('truncation is DISCLOSED, not failed', () => {
  const notes = dc.harvestTruncation({
    sources: [{ key: 'compliance', ok: true, count: 50, truncatedFrom: 74 }],
  });
  assert.equal(notes.length, 1);
  assert.match(notes[0], /50 of 74/);
});

// ── 6. composition ─────────────────────────────────────────────────────────

const OK_RESULT = { name: 'x.y', ms: 5, value: { a: 1 }, spec: { object: ['a'] }, statements: 1 };

test('a clean read is ok', () => {
  const r = dc.classifyResult(OK_RESULT);
  assert.equal(r.state, 'ok');
  assert.equal(r.reason, null);
});

test('a swallowed error beats a passing shape', () => {
  // ⛔ The shape is perfect and the result is wrong. This ordering is the whole
  // point: `{items: [], sources: [...]}` satisfies every structural
  // assertion.
  const r = dc.classifyResult({
    name: 'workQueueData.gatherWorkQueue',
    ms: 10,
    value: { items: [], sources: [{ key: 'cve', ok: false, error: 'column x does not exist' }] },
    spec: { object: ['items', 'sources'] },
    statements: 12,
  });
  assert.equal(r.state, 'fail');
  assert.match(r.reason, /swallowed error/);
  assert.match(r.reason, /column x does not exist/);
});

test('a function that issued NO statement is blocked, not ok', () => {
  // ⛔ The guard-that-cannot-fire pattern inside this tool's own output. A
  // short-circuiting reader (windowAppBytes handed no summable device ids)
  // resolves with a valid shape and verifies nothing.
  const r = dc.classifyResult({ ...OK_RESULT, statements: 0 });
  assert.equal(r.state, 'blocked');
  assert.match(r.reason, /without issuing a single statement/);
  assert.match(r.reason, /NO SQL was verified/);
});

test('an error outranks everything and is classified, not merely recorded', () => {
  const r = dc.classifyResult({
    name: 'x.y',
    ms: 3,
    error: { code: '42703', message: 'column q does not exist' },
    spec: { object: ['a'] },
    statements: 1,
  });
  assert.equal(r.state, 'fail');
  assert.match(r.reason, /names a column that does not exist/);
});

test('notes survive onto a failing result — a gap does not stop mattering', () => {
  const r = dc.classifyResult({
    name: 'x.y',
    ms: 3,
    value: { rows: [], sources: [{ key: 'a', ok: true, count: 50, truncatedFrom: 74 }] },
    spec: { array: true, rowKeys: ['id'] },
    statements: 1,
  });
  assert.equal(r.state, 'fail'); // an object where an array was expected
  assert.ok(r.notes.some((n) => /50 of 74/.test(n)));
});

// ── 7. the closing verdict ─────────────────────────────────────────────────

const EMPTY_SCHEMA = { missingTables: [], missingColumns: [] };

test('a fully clean run is ok and exits 0', () => {
  const v = dc.summariseRun(
    [{ state: 'ok', notes: [] }, { state: 'ok', notes: [] }],
    EMPTY_SCHEMA
  );
  assert.equal(v.tone, 'ok');
  assert.equal(v.exitCode, 0);
  assert.match(v.sentence, /returned the expected shape/);
});

test('⛔ AN ALL-CLEAR IS FORBIDDEN WHILE ANYTHING IS BLOCKED', () => {
  // The rule lib/answers.js enforces product-wide: a clean result over
  // incomplete coverage is `unknown`, never `ok`.
  const v = dc.summariseRun(
    [{ state: 'ok', notes: [] }, { state: 'blocked', notes: [] }],
    EMPTY_SCHEMA
  );
  assert.equal(v.tone, 'unknown');
  assert.notEqual(v.tone, 'ok');
  assert.match(v.sentence, /NOT an all-clear/);
  // ⛔ AND IT STILL EXITS 0. `blocked` is the grants policy working; failing the
  // run on it would make the only way to a green sweep granting a readonly role
  // access to device_credentials.
  assert.equal(v.exitCode, 0);
});

test('⛔ AN ALL-CLEAR IS FORBIDDEN WHILE A SHAPE IS UNVERIFIED', () => {
  const v = dc.summariseRun(
    [{ state: 'ok', notes: ['returned 0 rows, so its row shape was not verified'] }],
    EMPTY_SCHEMA
  );
  assert.equal(v.tone, 'unknown');
  assert.equal(v.unverified, 1);
  assert.match(v.sentence, /NOT an all-clear/);
});

test('one failure fails the run', () => {
  const v = dc.summariseRun(
    [{ state: 'ok', notes: [] }, { state: 'fail', notes: [] }],
    EMPTY_SCHEMA
  );
  assert.equal(v.tone, 'fail');
  assert.equal(v.exitCode, 1);
  assert.match(v.sentence, /1 read\(s\) failed/);
});

test('a schema gap fails the run even when every read passed', () => {
  const v = dc.summariseRun(
    [{ state: 'ok', notes: [] }],
    { missingTables: ['compliance_exceptions'], missingColumns: [] }
  );
  assert.equal(v.exitCode, 1);
  assert.equal(v.schemaProblems, 1);
  assert.match(v.sentence, /missing from the live database/);
  assert.doesNotMatch(v.sentence, /0 read/);
});

test('⛔ A CREDENTIAL EXPOSURE REACHES THE CLOSING SENTENCE, AND LEADS IT', () => {
  // ⛔ THE DEFECT: `deniedNowReadable` — a blanket GRANT SELECT ON ALL TABLES
  // having made device_credentials readable by the diagnostics role — was
  // counted for the exit code and left OUT of the verdict, so the last and
  // loudest line of that run read "All 104 reads executed and returned the
  // expected shape…". The most serious finding this tool can make was the one
  // finding its own summary did not mention.
  const v = dc.summariseRun(
    [{ state: 'ok', notes: [] }],
    EMPTY_SCHEMA,
    { missingGrants: [], deniedNowReadable: ['device_credentials', 'user_mfa'] }
  );
  assert.equal(v.exitCode, 1);
  assert.equal(v.tone, 'fail');
  assert.match(v.sentence, /device_credentials/);
  assert.match(v.sentence, /credential-exposure regression/);
  assert.doesNotMatch(v.sentence, /returned the expected shape/);
  // and it comes FIRST — nothing in this report outranks it
  assert.ok(v.sentence.indexOf('READABLE') < 40, `exposure must lead the sentence: ${v.sentence}`);
});

test('a missing per-table GRANT also reaches the verdict, and names the table', () => {
  const v = dc.summariseRun(
    [{ state: 'ok', notes: [] }],
    EMPTY_SCHEMA,
    { missingGrants: ['compliance_exceptions'], deniedNowReadable: [] }
  );
  assert.equal(v.exitCode, 1);
  assert.equal(v.grantProblems, 1);
  assert.match(v.sentence, /compliance_exceptions/);
});

test('and a clean grants audit says so rather than staying silent about it', () => {
  const v = dc.summariseRun([{ state: 'ok', notes: [] }], EMPTY_SCHEMA, { missingGrants: [], deniedNowReadable: [] });
  assert.equal(v.tone, 'ok');
  assert.equal(v.grantProblems, 0);
  assert.match(v.sentence, /every grant is as lib\/schema-grants\.sql declares it/);
});

// ── 8. the schema parse and diff ───────────────────────────────────────────

test('parses a CREATE TABLE body, skipping table-level constraints', () => {
  const t = dc.parseSchemaSql(`
CREATE TABLE IF NOT EXISTS widgets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,           -- a trailing comment
  ratio NUMERIC(5,2),
  UNIQUE (name),
  CONSTRAINT chk CHECK (ratio > 0)
);
`);
  assert.deepEqual([...t.get('widgets')].sort(), ['id', 'name', 'ratio']);
});

test('a PARTITION BY table does not swallow the next table', () => {
  // ⛔ The exact trap tests/sqlColumns.test.js documents: syslog_events ends
  // `) PARTITION BY RANGE (received_at);`, and a `\n);` pattern reads the
  // following table's body as part of it.
  const t = dc.parseSchemaSql(`
CREATE TABLE IF NOT EXISTS events (
  id BIGSERIAL,
  received_at TIMESTAMPTZ NOT NULL
) PARTITION BY RANGE (received_at);

CREATE TABLE IF NOT EXISTS later (
  other TEXT
);
`);
  assert.deepEqual([...t.get('events')].sort(), ['id', 'received_at']);
  assert.deepEqual([...t.get('later')], ['other']);
  assert.equal(t.get('events').has('other'), false);
});

test('⛔ ALTER TABLE … ADD COLUMN is collected — the whole point of the check', () => {
  // `CREATE TABLE IF NOT EXISTS` guards the TABLE only, so a column added to an
  // existing table's CREATE body never reaches a deployed server. Both
  // spellings have to be diffed or the trap is invisible.
  const t = dc.parseSchemaSql(`
CREATE TABLE IF NOT EXISTS d (
  id UUID PRIMARY KEY
);
ALTER TABLE d ADD COLUMN IF NOT EXISTS serial TEXT;
ALTER TABLE IF EXISTS d ADD COLUMN hostname TEXT;
ALTER TABLE brand_new ADD COLUMN IF NOT EXISTS only_column TEXT;
`);
  assert.deepEqual([...t.get('d')].sort(), ['hostname', 'id', 'serial']);
  assert.deepEqual([...t.get('brand_new')], ['only_column']);
});

test('diffSchema reports a declared table missing from the live database', () => {
  const declared = new Map([['a', new Set(['x'])], ['b', new Set(['y'])]]);
  const live = new Map([['a', new Set(['x'])]]);
  const d = dc.diffSchema(declared, live);
  assert.deepEqual(d.missingTables, ['b']);
  assert.deepEqual(d.missingColumns, []);
});

test('diffSchema reports a declared COLUMN missing from an existing table', () => {
  const declared = new Map([['a', new Set(['x', 'y'])]]);
  const live = new Map([['a', new Set(['x'])]]);
  const d = dc.diffSchema(declared, live);
  assert.deepEqual(d.missingTables, []);
  assert.deepEqual(d.missingColumns, ['a.y']);
});

test('an UNDECLARED live table is informational, and partitions are ignored', () => {
  // ⛔ Failing on this would train the next person to delete the check, which
  // costs more than the coverage it gives up.
  const declared = new Map([['syslog_events', new Set(['id'])]]);
  const live = new Map([
    ['syslog_events', new Set(['id'])],
    ['syslog_events_20260922', new Set(['id'])],
    ['data_backfills', new Set(['name'])],
  ]);
  const d = dc.diffSchema(declared, live);
  assert.deepEqual(d.missingTables, []);
  assert.deepEqual(d.undeclaredTables, ['data_backfills']);
});

test('the real lib/schema.sql parses into the table count schema.md claims', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const sql = fs.readFileSync(path.join(__dirname, '..', 'lib', 'schema.sql'), 'utf8');
  const t = dc.parseSchemaSql(sql);
  assert.ok(t.size >= 60, `expected at least 60 tables, parsed ${t.size}`);
  // Spot-check the two shapes most likely to break the parser.
  assert.ok(t.get('syslog_events').has('received_at'), 'the partitioned table must parse');
  assert.ok(t.get('firewall_rules').has('hit_count'), 'hit_count must be found');
  assert.ok(t.get('device_versions').has('serial'), 'an ALTER-added column must be found');
});

// ── 9. plumbing ────────────────────────────────────────────────────────────

test('entryName is stable and derived from the module path', () => {
  assert.equal(dc.entryName({ mod: 'lib/syslog/trafficStats.js', fn: 'getTopHosts' }), 'trafficStats.getTopHosts');
});

test('the raw-table window this tool asks for is 20 minutes or less', () => {
  assert.ok(dc.RAW_WINDOW_MINUTES <= 20, 'the raw syslog_events window must stay narrow');
});

test('the deliberately-denied table list holds every secret-bearing table', () => {
  // A table dropped from this list would start reporting its (correct)
  // permission refusal as a FAILURE, which is a false alarm; a table wrongly
  // ADDED would turn a real missing grant into a blocked line nobody chases.
  for (const t of ['device_credentials', 'credential_profiles', 'notification_channels', 'user_mfa', 'settings', 'users']) {
    assert.ok(dc.EXPECTED_UNREADABLE.includes(t), `${t} must be on the deliberately-denied list`);
  }
});

test('requiring the script opens no socket and runs nothing', () => {
  // It is guarded by `require.main === module`; without that, merely requiring
  // it here would connect to a production database from `npm test` — which is
  // the one thing CLAUDE.md forbids the test suite to do.
  const src = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'scripts', 'dbCheck.js'),
    'utf8'
  );
  assert.match(src, /if \(require\.main === module\)/);
  // and the pool is only constructed inside main()
  assert.doesNotMatch(src, /^const pool = new Pool/m);
});

test('no registry entry names a function this repo does not export', () => {
  // ⛔ A stale registry is a silently shorter sweep. The live runner reports it
  // too, but it would only be seen by someone who ran the tool against a
  // database; this catches it in `npm test`, where a rename is made.
  const path = require('node:path');
  const stale = [];
  for (const e of dc.REGISTRY) {
    let mod;
    try {
      mod = require(path.join(__dirname, '..', e.mod));
    } catch (err) {
      stale.push(`${e.mod} could not be required: ${err.message}`);
      continue;
    }
    if (typeof mod[e.fn] !== 'function') stale.push(`${e.mod} does not export ${e.fn}`);
  }
  assert.deepEqual(stale, []);
});
