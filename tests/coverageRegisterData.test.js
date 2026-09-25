'use strict';

// tests/coverageRegisterData.test.js — pins lib/engines/coverageRegisterData.js,
// the plumbing half of the A2 blind-spot register.
//
// WHY THIS FILE EXISTS: this is the page whose entire job is to name what
// SecVault CANNOT measure. A failed read here does not merely lose information
// — it asserts the exact opposite of the truth, on the one page a reader
// consults to decide how much to trust everything else in the product. An
// empty register reads as "we can see everything". So the "we could not
// measure this" case is the centre of this file, per tests/README.md: the
// throwing query, the NULL count, and the difference between a measured zero
// and an unreadable one.
//
// ⛔ NO DATABASE. `getCoverageRegister(pool, opts)` only ever calls
// `pool.query(sql, params)`, so every test hands it a stub that RECORDS the
// statement and params it was given and returns canned rows (the convention
// configRetention.test.js established and upgradePlanData.test.js follows).
// That gives two independent things to pin: the SQL it builds, and how it
// interprets what comes back.
//
// SQL assertions match a meaningful FRAGMENT, never a whole string, so a
// legitimate reformat is a one-line test update while a REMOVED guarantee
// still fails loudly.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const dataModule = require('../lib/engines/coverageRegisterData');
const { getCoverageRegister } = dataModule;
const { STATE, SOURCES } = require('../lib/engines/coverageRegister');

const MODULE_PATH = path.join(__dirname, '..', 'lib', 'engines', 'coverageRegisterData.js');
const SRC = fs.readFileSync(MODULE_PATH, 'utf8');

// ⛔ EVERY 'must NOT contain' ASSERTION BELOW RUNS AGAINST SOURCE WITH COMMENTS
// REMOVED. This repo has been bitten three separate times by a source scan
// satisfied by the very comment explaining the thing it was hunting — and the
// module under test deliberately documents, in prose, the table it must never
// query. Stripping is crude on purpose and only ever feeds a doesNotMatch,
// where over-removal can lose coverage but can never invent a failure.
const BLOCK_COMMENT = new RegExp('/\\*[\\s\\S]*?\\*/', 'g');
const LINE_COMMENT = new RegExp('(^|[\\s{(;,])//[^\\n]*', 'g');
const stripComments = (src) =>
  String(src).replace(BLOCK_COMMENT, ' ').replace(LINE_COMMENT, '$1 ');

const CODE = stripComments(SRC);

// --------------------------------------------------------------------------
// Stub pool
// --------------------------------------------------------------------------

/**
 * ⛔ THE STUB ROUTES ON THE STATEMENT, and it has to since A3: the register is
 * no longer one query. A stub that returned the same canned rows to every
 * `pool.query` fed register rows to the log-coverage reader and to
 * `getLoggedRuleHits`, which did not throw — it quietly produced garbage grades
 * — so every log-evidence assertion below would have been measuring the stub.
 *
 * Unrouted statements return NO rows, deliberately: a query this file has not
 * thought about must read as "nothing there" rather than inherit another
 * source's fixture.
 *
 * @param {object[]|Error} result register rows, or an Error to throw.
 * @param {object} [extra]
 * @param {object[]|Error} [extra.coverage]  rows for getDeviceLogCoverage
 * @param {object|Error} [extra.hits]  deviceId → rows for getLoggedRuleHits
 * @param {object[]|Error} [extra.nullRules]  rows for the hit_count IS NULL fetch
 */
function stubPool(result, extra = {}) {
  const calls = [];
  const give = (v) => {
    if (v instanceof Error) throw v;
    const rows = (v || []).map((r) => ({ ...r }));
    return { rows, rowCount: rows.length };
  };
  return {
    calls,
    async query(sql, params) {
      const text = String(sql);
      calls.push({ sql: text, params });
      // ⛔ ORDER IS LOAD-BEARING. The register statement itself NAMES
      // `syslog_rollup_hourly` and `firewall_rules` in its subqueries, so it
      // has to be recognised FIRST — by the one thing only it has, its
      // `FROM devices d` driver. Matching on a table name alone routed the
      // register's own query to the coverage fixture and made every failure
      // test below pass for the wrong reason.
      if (/FROM\s+devices\s+d\b/i.test(text)) return give(result);
      if (/hours_with_events/i.test(text)) return give(extra.coverage);
      if (/syslog_rule_hits_hourly/.test(text)) {
        if (extra.hits instanceof Error) throw extra.hits;
        return give((extra.hits || {})[params && params[0]]);
      }
      if (/FROM\s+firewall_rules/i.test(text)) return give(extra.nullRules);
      return give([]);
    },
  };
}

// ── log-evidence fixtures ────────────────────────────────────────────────
//
// The clock every log-evidence test pins, so the 30-day window and the history
// test are deterministic rather than being whatever the suite ran at.
const AT = '2026-09-25T12:00:00.000Z';

/**
 * A firewall that logged EVERY hour of the window, on an installation with
 * years of history — i.e. one whose silence about a rule IS evidence. That is
 * what lets a rule absent from the logs certify as a measured zero; drop either
 * field and `enrichRulesWithLogEvidence` correctly refuses to certify anything.
 */
const fullCoverage = (deviceId) => ({
  device_id: deviceId,
  hours_with_events: 720,
  first_seen: '2026-08-26T00:00:00.000Z',
  last_seen: AT,
  events: '1000000',
  first_bucket: '2025-01-01T00:00:00.000Z',
});

/**
 * A firewall SecVault has not been listening to long enough for silence to
 * mean anything. ⛔ This is the LIVE shape — the rollup began the day the
 * collector shipped — and it is why "some answered" is the common case: a rule
 * the logs MATCHED is still answered, while a rule absent from them is not.
 */
const thinCoverage = (deviceId) => ({
  device_id: deviceId,
  hours_with_events: 400,
  first_seen: '2026-09-08T00:00:00.000Z',
  last_seen: AT,
  events: '500000',
  first_bucket: '2026-09-08T00:00:00.000Z',
});

const nullRule = (deviceId, over = {}) => ({
  device_id: deviceId,
  rule_id_vendor: null,
  rule_name: null,
  log_enabled: true,
  hit_count: null,
  ...over,
});

const loggedHit = (over = {}) => ({
  rule_id: null,
  rule_name: null,
  hits: '1234',
  first_hit: '2026-09-10T00:00:00.000Z',
  last_hit: AT,
  ...over,
});

// ⛔ COUNTS ARE STRINGS AND AGES ARE NUMBERS, exactly as `pg` hands them back:
// `count(*)` is bigint (string, so 2^53 cannot be silently truncated) while the
// `::int` age expressions arrive as real numbers. The fixture keeps that mix so
// a coercion that only works for one of them fails here.
const row = (over = {}) => ({
  id: 'd-ok',
  name: 'IDC FW',
  vendor: 'paloalto',
  last_rules_collected_at: '2026-09-25T00:00:00Z',
  version_rows: '3',
  interfaces: '72',
  rules: '721',
  rules_unmeasured: '0',
  log_buckets: '2009',
  obj_refs: '878',
  obj_unresolvable: '0',
  config_age_days: 0,
  analysis_age_days: 1,
  rule_findings: '377',
  ...over,
});

// The three live shapes measured on the reference fleet 2026-09-25, the ones
// that drove the feature. Same fixtures as the pure engine's own test.
const PAKFOOD = () => row({
  id: 'd-pak', name: 'PAKFood', log_buckets: '0', obj_refs: '77', obj_unresolvable: '77',
});
const TSR_EKM = () => row({
  id: 'd-ekm', name: 'TSR_EKM', vendor: 'fortinet', rules: '78', rules_unmeasured: '78',
});
const TSR_EKC = () => row({
  id: 'd-ekc',
  name: 'TSR_EKC',
  vendor: 'fortinet',
  last_rules_collected_at: null,
  rules: '0',
  rules_unmeasured: '0',
  obj_refs: '0',
  obj_unresolvable: '0',
  analysis_age_days: 49,
  rule_findings: '22',
});

const byName = (entries, name) => entries.find((e) => e.deviceName === name);
const cellFor = (entry, key) => entry.cells.find((c) => c.key === key);

// --------------------------------------------------------------------------
// ⛔ The reason this file exists: a broken read must never look like a clean one
// --------------------------------------------------------------------------

describe('a query that throws', () => {
  it('reports a failure and returns NO entries — never a clean-looking empty register', async () => {
    const pool = stubPool(new Error('relation "syslog_rollup_hourly" does not exist'));
    const out = await getCoverageRegister(pool);

    assert.deepEqual(out.entries, [], 'a partial register that looks complete is the bug');
    assert.equal(out.failures.length, 1, 'the failure is part of the ANSWER, not a log line');
    assert.equal(typeof out.failures[0].source, 'string');
    assert.match(out.failures[0].error, /does not exist/);
  });

  it('does not throw out of getCoverageRegister — the caller gets a labelled result', async () => {
    const pool = stubPool(new Error('connection terminated unexpectedly'));
    const out = await getCoverageRegister(pool);
    assert.ok(out && typeof out === 'object');
    assert.equal(out.summary.devices, 0);
    assert.equal(out.summary.devicesWithGaps, 0);
    // ⛔ THE TRAP: every total above is 0, which on this page reads as "no
    // blind spots". `failures` is the only thing distinguishing it from a
    // genuinely clean fleet, so it must be non-empty and the caller must lead
    // with it.
    assert.ok(out.failures.length > 0, 'zero totals must never stand alone');
  });

  it('a healthy fleet reports NO failures, so a non-empty failures list means something', async () => {
    const pool = stubPool([row()]);
    const out = await getCoverageRegister(pool);
    assert.deepEqual(out.failures, []);
  });

  it('a thrown non-Error still produces a readable failure', async () => {
    const pool = {
      calls: [],
      // eslint-disable-next-line prefer-promise-reject-errors
      async query() { throw 'string thrown by a driver'; },
    };
    const out = await getCoverageRegister(pool);
    assert.equal(out.entries.length, 0);
    assert.equal(out.failures.length, 1);
    assert.match(out.failures[0].error, /string thrown/);
  });
});

// --------------------------------------------------------------------------
// ⛔ An unreadable count is NOT a measured zero
// --------------------------------------------------------------------------

describe('a NULL count stays unreadable', () => {
  it('a NULL syslog count is ABSENT-but-UNCERTAIN, never "this firewall sends no syslog"', async () => {
    const pool = stubPool([row({ log_buckets: null })]);
    const { entries, summary } = await getCoverageRegister(pool);
    const c = cellFor(entries[0], 'syslog');

    assert.equal(c.state, STATE.ABSENT);
    assert.equal(c.certain, false, 'we could not even check — that is not a measured zero');
    assert.match(c.detail, /could not be read/i);
    assert.doesNotMatch(c.detail, /sends no syslog/i, 'an unread count must not assert a fact');
    assert.equal(summary.devicesWithUnreadableChecks, 1);
  });

  it('a MEASURED zero is certain, and reads differently from the unreadable one', async () => {
    const pool = stubPool([row({ log_buckets: '0' })]);
    const { entries, summary } = await getCoverageRegister(pool);
    const c = cellFor(entries[0], 'syslog');

    assert.equal(c.state, STATE.ABSENT);
    assert.equal(c.certain, true, 'a measured zero is certain — we DID check');
    assert.match(c.detail, /sends no syslog/i);
    assert.equal(summary.devicesWithUnreadableChecks, 0);
  });

  it('a NULL rule count does not become 0 rules collected', async () => {
    const pool = stubPool([row({ rules: null, rules_unmeasured: null })]);
    const { entries } = await getCoverageRegister(pool);
    const c = cellFor(entries[0], 'ruleset');
    assert.equal(c.certain, false);
    assert.match(c.detail, /could not be read/i);
    assert.doesNotMatch(c.detail, /No firewall rules have been collected/i);
  });

  it('an undefined column (a row shape that changed) is unreadable, not zero', async () => {
    // A renamed column arrives as `undefined`, which `Number()` also turns
    // into NaN and a lazy guard turns into 0.
    const base = row();
    delete base.log_buckets;
    const pool = stubPool([base]);
    const { entries } = await getCoverageRegister(pool);
    assert.equal(cellFor(entries[0], 'syslog').certain, false);
  });

  it('a NULL config age is "no configuration collected", and a real 0 is not', async () => {
    const pool = stubPool([row({ config_age_days: null }), row({ id: 'd2', name: 'fresh', config_age_days: 0 })]);
    const { entries } = await getCoverageRegister(pool);
    assert.equal(cellFor(byName(entries, 'IDC FW'), 'config').state, STATE.ABSENT);
    assert.equal(cellFor(byName(entries, 'fresh'), 'config').state, STATE.MEASURED);
  });

  it('a NULL last_rules_collected_at is passed through as null, never invented', async () => {
    const pool = stubPool([TSR_EKC()]);
    const { entries } = await getCoverageRegister(pool);
    assert.equal(entries[0].staleFindings.neverCollected, true);
  });
});

// --------------------------------------------------------------------------
// The three live shapes
// --------------------------------------------------------------------------

describe('the live fleet shapes', () => {
  it('a fully-collected firewall is fullyCovered and withholds nothing', async () => {
    const pool = stubPool([row()]);
    const { entries, summary } = await getCoverageRegister(pool);

    assert.equal(entries.length, 1);
    assert.equal(entries[0].deviceId, 'd-ok');
    assert.equal(entries[0].deviceName, 'IDC FW');
    assert.equal(entries[0].vendor, 'paloalto');
    assert.equal(entries[0].fullyCovered, true);
    assert.equal(entries[0].gapCount, 0);
    assert.equal(entries[0].answersWithheld, 0);
    assert.equal(entries[0].staleFindings, null);
    assert.equal(summary.devicesFullyCovered, 1);
    assert.equal(summary.devicesWithGaps, 0);
  });

  it('PAKFood: zero syslog buckets, while every other source is present', async () => {
    const pool = stubPool([PAKFOOD()]);
    const { entries, summary } = await getCoverageRegister(pool);
    const e = entries[0];

    assert.equal(e.fullyCovered, false, 'it renders as fully assessed everywhere else');
    assert.equal(cellFor(e, 'syslog').state, STATE.ABSENT);
    assert.deepEqual(cellFor(e, 'syslog').gates, SOURCES.syslog.gates);
    // 77 of 77 object references unresolvable, live.
    assert.equal(cellFor(e, 'objects').state, STATE.ABSENT);
    assert.ok(e.blockedEngines.some((g) => /log_hit/.test(g)));
    assert.equal(summary.gapsBySource.syslog, 1);
  });

  it('TSR_EKM: 78 of 78 rules with no hit count is ABSENT rule usage, not zero hits', async () => {
    const pool = stubPool([TSR_EKM()]);
    const { entries } = await getCoverageRegister(pool);
    const c = cellFor(entries[0], 'ruleUsage');

    assert.equal(c.state, STATE.ABSENT);
    assert.match(c.detail, /78 of 78/);
    assert.match(c.detail, /cleanup will refuse/i);
    // The ruleset itself WAS collected — only its usage is unmeasured.
    assert.equal(cellFor(entries[0], 'ruleset').state, STATE.MEASURED);
  });

  it('TSR_EKC: 49-day-old analysis with rule collection that never succeeded', async () => {
    const pool = stubPool([TSR_EKC()]);
    const { entries, summary } = await getCoverageRegister(pool);
    const e = entries[0];

    assert.ok(e.staleFindings, 'stale findings render as current answers unless the register says so');
    assert.equal(e.staleFindings.ageDays, 49);
    assert.equal(e.staleFindings.findingCount, 22);
    assert.equal(e.staleFindings.neverCollected, true);
    assert.match(e.staleFindings.detail, /never succeeded/i);
    assert.equal(e.fullyCovered, false);
    assert.equal(summary.devicesWithStaleFindings, 1);
  });

  it('a partial hit-count gap is PARTIAL, not ABSENT', async () => {
    const pool = stubPool([row({ rules: '100', rules_unmeasured: '40' })]);
    const { entries } = await getCoverageRegister(pool);
    assert.equal(cellFor(entries[0], 'ruleUsage').state, STATE.PARTIAL);
  });
});

// --------------------------------------------------------------------------
// ⛔ A3 — the gap was OVERSTATED: logs answer 84 of the 235 unmeasured rules
// --------------------------------------------------------------------------
//
// `hit_count IS NULL` alone said "we cannot see this rule's usage". Live, the
// firewall's OWN LOGS answer 84 of those: 54 by the vendor's rule ID (Fortinet)
// and 30 by NAME only (Palo Alto, whose rollup rows carry no rule id at all).
// The register has to say so — a blind-spot list that names firewalls it CAN
// see teaches an operator to discount the ones it cannot.

describe('log-derived rule usage', () => {
  // A Fortinet whose logs carry rule IDs and answer all three of its
  // unmeasurable rules.
  const allAnswered = () => stubPool(
    [row({ id: 'd-ekm', name: 'TSR_EKM', vendor: 'fortinet', rules: '3', rules_unmeasured: '3' })],
    {
      coverage: [thinCoverage('d-ekm')],
      nullRules: [
        nullRule('d-ekm', { rule_id_vendor: '11', rule_name: 'to-wan' }),
        nullRule('d-ekm', { rule_id_vendor: '12', rule_name: 'to-dmz' }),
        nullRule('d-ekm', { rule_id_vendor: '13', rule_name: 'to-lan' }),
      ],
      hits: {
        'd-ekm': [
          loggedHit({ rule_id: '11', rule_name: 'to-wan' }),
          loggedHit({ rule_id: '12', rule_name: 'to-dmz' }),
          loggedHit({ rule_id: '13', rule_name: 'to-lan' }),
        ],
      },
    },
  );

  it('every unmeasured rule answered from logs is PARTIAL, never ABSENT', async () => {
    const { entries } = await getCoverageRegister(allAnswered(), { now: AT });
    const c = cellFor(entries[0], 'ruleUsage');

    assert.equal(c.state, STATE.PARTIAL, 'the gap is real but smaller than absent');
    assert.equal(c.certain, true);
    assert.match(c.detail, /logs answer all 3/i);
    assert.doesNotMatch(c.detail, /refuse every rule on this firewall/i,
      'cleanup will NOT refuse rules the logs answered by ID');
  });

  it('the per-device counts are exposed for a renderer', async () => {
    const { entries } = await getCoverageRegister(allAnswered(), { now: AT });
    // Surfaced through the engine input; the cell is what a page renders, but
    // the counts must be derivable and must agree with it.
    assert.match(cellFor(entries[0], 'ruleUsage').detail, /3 of 3 rules report no hit count/);
  });

  it('SOME answered is PARTIAL and the detail names both numbers', async () => {
    // ⛔ THE LIVE SHAPE. Thin history means a rule ABSENT from the logs
    // certifies nothing, while a rule the logs MATCHED is still answered.
    const pool = stubPool(
      [row({ id: 'd-ekm', name: 'TSR_EKM', vendor: 'fortinet', rules: '10', rules_unmeasured: '4' })],
      {
        coverage: [thinCoverage('d-ekm')],
        nullRules: [
          nullRule('d-ekm', { rule_id_vendor: '11', rule_name: 'to-wan' }),
          nullRule('d-ekm', { rule_id_vendor: '12', rule_name: 'to-dmz' }),
          nullRule('d-ekm', { rule_id_vendor: '13', rule_name: 'quiet-a' }),
          nullRule('d-ekm', { rule_id_vendor: '14', rule_name: 'quiet-b' }),
        ],
        hits: { 'd-ekm': [loggedHit({ rule_id: '11' }), loggedHit({ rule_id: '12' })] },
      },
    );
    const { entries } = await getCoverageRegister(pool, { now: AT });
    const c = cellFor(entries[0], 'ruleUsage');

    assert.equal(c.state, STATE.PARTIAL);
    assert.match(c.detail, /4 of 10 rules report no hit count/);
    assert.match(c.detail, /answer 2/);
    assert.match(c.detail, /leaving 2 with no usage evidence at all/i);
  });

  it('NONE answered leaves the cell exactly as it was', async () => {
    const pool = stubPool([TSR_EKM()], {
      coverage: [thinCoverage('d-ekm')],
      nullRules: [nullRule('d-ekm', { rule_id_vendor: '11' })],
      hits: { 'd-ekm': [] },
    });
    const { entries } = await getCoverageRegister(pool, { now: AT });
    const c = cellFor(entries[0], 'ruleUsage');

    assert.equal(c.state, STATE.ABSENT);
    assert.equal(c.certain, true, 'we DID check the logs; they answer none of them');
    assert.match(c.detail, /78 of 78/);
    assert.match(c.detail, /cleanup will refuse/i);
  });

  it('⛔ AN UNREADABLE LOG-EVIDENCE COUNT LEAVES THE CELL WORSE AND UNCERTAIN', async () => {
    // The one that regresses silently: a failed read that quietly improved the
    // picture would report a blind spot as covered, on the page whose entire
    // job is to name blind spots.
    const pool = stubPool([TSR_EKM()], {
      coverage: [thinCoverage('d-ekm')],
      nullRules: [nullRule('d-ekm', { rule_id_vendor: '11' })],
      hits: new Error('canceling statement due to statement timeout'),
    });
    const { entries, summary, failures } = await getCoverageRegister(pool, { now: AT });
    const c = cellFor(entries[0], 'ruleUsage');

    assert.equal(c.state, STATE.ABSENT, 'it must stay at its WORSE state');
    assert.equal(c.certain, false, 'and say we could not even check');
    assert.match(c.detail, /could not be read/i);
    assert.match(c.detail, /overstate/i);
    assert.equal(summary.devicesWithUnreadableChecks, 1);
    // ⛔ And it lands in failures, never silently reducing the register.
    assert.equal(failures.length, 1);
    assert.match(failures[0].source, /rule_log_evidence/);
    assert.match(failures[0].error, /statement timeout/);
  });

  it('a failed SHARED read leaves every affected firewall uncertain, and the counts stand', async () => {
    const pool = stubPool(
      [row(), TSR_EKM()],
      { coverage: new Error('relation "syslog_rollup_hourly" does not exist') },
    );
    const { entries, failures } = await getCoverageRegister(pool, { now: AT });

    assert.equal(entries.length, 2, 'the register itself is still built');
    assert.equal(cellFor(byName(entries, 'TSR_EKM'), 'ruleUsage').certain, false);
    // The firewall that reports its own hit counts is untouched by this failure.
    assert.equal(cellFor(byName(entries, 'IDC FW'), 'ruleUsage').state, STATE.MEASURED);
    assert.equal(cellFor(byName(entries, 'IDC FW'), 'ruleUsage').certain, true);
    assert.deepEqual(failures.map((f) => f.source), ['rule_log_evidence']);
  });

  it('one unreadable firewall does not blank the other', async () => {
    const pool = stubPool(
      [
        row({ id: 'd-a', name: 'Alpha', vendor: 'fortinet', rules: '2', rules_unmeasured: '2' }),
        row({ id: 'd-b', name: 'Bravo', vendor: 'fortinet', rules: '2', rules_unmeasured: '2' }),
      ],
      {
        coverage: [thinCoverage('d-a'), thinCoverage('d-b')],
        nullRules: [
          nullRule('d-a', { rule_id_vendor: '1' }), nullRule('d-a', { rule_id_vendor: '2' }),
          nullRule('d-b', { rule_id_vendor: '1' }), nullRule('d-b', { rule_id_vendor: '2' }),
        ],
        hits: {
          'd-a': [loggedHit({ rule_id: '1' }), loggedHit({ rule_id: '2' })],
          'd-b': new Error('connection terminated unexpectedly'),
        },
      },
    );
    const { entries, failures } = await getCoverageRegister(pool, { now: AT });

    assert.equal(cellFor(byName(entries, 'Alpha'), 'ruleUsage').state, STATE.PARTIAL);
    assert.equal(cellFor(byName(entries, 'Alpha'), 'ruleUsage').certain, true);
    // Bravo stays at its worse state and says it could not be checked — it is
    // never handed Alpha's answer, and never a zero it did not earn.
    assert.equal(cellFor(byName(entries, 'Bravo'), 'ruleUsage').state, STATE.ABSENT);
    assert.equal(cellFor(byName(entries, 'Bravo'), 'ruleUsage').certain, false);
    assert.equal(failures.length, 1);
    assert.match(failures[0].source, /rule_log_evidence:Bravo/);
  });

  it('good coverage with no logged hits certifies a measured zero — at NAME grade only', async () => {
    // ⛔ The engine's own conservatism, pinned here because it is the case a
    // reader is most likely to expect the opposite of: when the logs carry no
    // rule IDs AT ALL there was no ID to have searched by, so even a Fortinet
    // rule that HAS a vendor id certifies only at name grade — and therefore
    // still may not be removed.
    const pool = stubPool(
      [row({ id: 'd-q', name: 'Quiet', vendor: 'fortinet', rules: '2', rules_unmeasured: '2' })],
      {
        coverage: [fullCoverage('d-q')],
        nullRules: [
          nullRule('d-q', { rule_id_vendor: '1', rule_name: 'a' }),
          nullRule('d-q', { rule_id_vendor: '2', rule_name: 'b' }),
        ],
        hits: { 'd-q': [] },
      },
    );
    const { entries } = await getCoverageRegister(pool, { now: AT });
    const c = cellFor(entries[0], 'ruleUsage');

    assert.equal(c.state, STATE.PARTIAL, 'a certified silence IS an answer');
    assert.match(c.detail, /logs answer all 2/i);
    assert.match(c.detail, /NAME only/);
    assert.match(c.detail, /never authorise removing a rule/i);
  });

  // ── ID grade vs NAME grade ─────────────────────────────────────────────

  it('a Palo Alto answered by NAME is reported as name-grade, never as removable', async () => {
    // ⛔ LIVE: every Palo Alto rollup row carries a NULL rule_id — names only.
    const pool = stubPool(
      [row({ id: 'd-pa', name: 'ITC-SLY', vendor: 'paloalto', rules: '2', rules_unmeasured: '2' })],
      {
        coverage: [thinCoverage('d-pa')],
        nullRules: [
          nullRule('d-pa', { rule_name: 'allow-web' }),
          nullRule('d-pa', { rule_name: 'allow-dns' }),
        ],
        hits: {
          'd-pa': [
            loggedHit({ rule_id: null, rule_name: 'allow-web' }),
            loggedHit({ rule_id: null, rule_name: 'allow-dns' }),
          ],
        },
      },
    );
    const { entries } = await getCoverageRegister(pool, { now: AT });
    const c = cellFor(entries[0], 'ruleUsage');

    assert.equal(c.state, STATE.PARTIAL);
    assert.match(c.detail, /NAME only/);
    assert.match(c.detail, /never authorise removing a rule/i);
    assert.match(c.detail, /renamed rule reads as unused/i);
    assert.match(c.detail, /cleanup will refuse all 2/i,
      'name-grade evidence buys an operator nothing at the cleanup step');
  });

  it('a Fortinet answered by rule ID is reported as exact and as removable', async () => {
    const { entries } = await getCoverageRegister(allAnswered(), { now: AT });
    const c = cellFor(entries[0], 'ruleUsage');
    assert.match(c.detail, /rule ID, which is exact/i);
    assert.match(c.detail, /cleanup will accept them/i);
    assert.doesNotMatch(c.detail, /NAME only/);
  });

  it('a mixed fleet keeps the two grades apart in one detail', async () => {
    const pool = stubPool(
      [row({ id: 'd-mx', name: 'Mixed', vendor: 'fortinet', rules: '3', rules_unmeasured: '3' })],
      {
        coverage: [thinCoverage('d-mx')],
        nullRules: [
          nullRule('d-mx', { rule_id_vendor: '11', rule_name: 'by-id' }),
          // No vendor id on the rule, so only its NAME can be looked up.
          nullRule('d-mx', { rule_name: 'by-name' }),
          nullRule('d-mx', { rule_id_vendor: '99', rule_name: 'silent' }),
        ],
        hits: {
          'd-mx': [
            loggedHit({ rule_id: '11', rule_name: 'by-id' }),
            loggedHit({ rule_id: null, rule_name: 'by-name' }),
          ],
        },
      },
    );
    const { entries } = await getCoverageRegister(pool, { now: AT });
    const c = cellFor(entries[0], 'ruleUsage');

    assert.match(c.detail, /1 are matched by the vendor's own rule ID/);
    assert.match(c.detail, /1 by rule NAME only/);
    assert.match(c.detail, /never authorise removing a rule/i);
    assert.match(c.detail, /refuse the other 2/i, 'the name-grade one and the unanswered one');
  });

  // ── the things it must not do ──────────────────────────────────────────

  it('a firewall reporting all its hit counts stays MEASURED and costs no query', async () => {
    const pool = stubPool([row()]);
    const { entries } = await getCoverageRegister(pool, { now: AT });
    assert.equal(cellFor(entries[0], 'ruleUsage').state, STATE.MEASURED);
    assert.equal(pool.calls.length, 1);
  });

  it('an UNREADABLE rule count is never paired with a confident log verdict', async () => {
    // Nothing can improve a gap we could not measure in the first place, and no
    // log query is issued for it.
    const pool = stubPool([row({ rules: null, rules_unmeasured: null })]);
    const { entries } = await getCoverageRegister(pool, { now: AT });
    assert.equal(cellFor(entries[0], 'ruleset').certain, false);
    assert.equal(cellFor(entries[0], 'ruleUsage'), undefined, 'no cell without a rule count');
    assert.equal(pool.calls.length, 1);
  });

  it('log evidence can never promote the cell to MEASURED', async () => {
    // ⛔ A bounded-window observation is not the device's own lifetime counter.
    const { entries } = await getCoverageRegister(allAnswered(), { now: AT });
    const c = cellFor(entries[0], 'ruleUsage');
    assert.notEqual(c.state, STATE.MEASURED);
    assert.ok(c.weight > 0, 'a log-answered firewall is still a partial blind spot');
    assert.deepEqual(c.gates, SOURCES.ruleUsage.gates);
  });
});

// --------------------------------------------------------------------------
// Ranking — by consequence, and stale first
// --------------------------------------------------------------------------

describe('ranking', () => {
  it('entries come back RANKED: stale findings first, then by answers withheld', async () => {
    // Deliberately supplied in the SQL's own `ORDER BY d.name` order, which is
    // alphabetical and is NOT the answer: IDC FW, PAKFood, TSR_EKC.
    const pool = stubPool([row(), PAKFOOD(), TSR_EKC()]);
    const { entries } = await getCoverageRegister(pool);

    assert.equal(entries.length, 3);
    assert.equal(entries[0].deviceName, 'TSR_EKC', 'stale evidence outranks a pure gap');
    assert.equal(entries[1].deviceName, 'PAKFood');
    assert.equal(entries[2].deviceName, 'IDC FW', 'the fully-covered firewall ranks last');
  });

  it('between two gap-only firewalls, the one withholding more answers comes first', async () => {
    const oneGap = row({ id: 'd-a', name: 'one-gap', log_buckets: '0' });
    const manyGaps = row({
      id: 'd-b', name: 'many-gaps', log_buckets: '0', interfaces: '0', version_rows: '0',
      obj_refs: '77', obj_unresolvable: '77',
    });
    const { entries } = await getCoverageRegister(stubPool([oneGap, manyGaps]));

    assert.equal(entries[0].deviceName, 'many-gaps');
    assert.ok(entries[0].answersWithheld > entries[1].answersWithheld);
  });

  it('does not re-sort the engine\'s ranking in this file', () => {
    assert.ok(/rankRegister\(/.test(CODE), 'the engine ranks; this file must not');
    assert.ok(!/\.sort\(/.test(CODE), 'a second sort here would eventually disagree with the engine');
  });
});

// --------------------------------------------------------------------------
// The statement it builds
// --------------------------------------------------------------------------

describe('the SQL', () => {
  const sqlOf = async (opts) => {
    const pool = stubPool([row()]);
    await getCoverageRegister(pool, opts);
    return pool.calls[0];
  };

  it('⛔ NEVER touches the raw syslog event table (comments stripped first)', () => {
    // ~28M rows/day in daily partitions, with the collector inserting at
    // ~1,000 rows/sec. The rollup answers this register's only syslog
    // question at low cardinality. The module explains this IN PROSE, which
    // is exactly why the scan runs on stripped source.
    assert.ok(/syslog_events/.test(SRC), 'the module should still explain the rule in a comment');
    assert.ok(
      !/syslog_events/.test(CODE),
      'the raw event table must never be queried from this register'
    );
    assert.ok(/syslog_rollup_hourly/.test(CODE), 'the rollup is what it counts');
  });

  it('issues exactly ONE statement when every firewall reports its hit counts', async () => {
    // ⛔ The counts themselves are, and must stay, a single statement. The
    // log-evidence source below is the ONLY thing that may add queries, and it
    // adds none at all when there is nothing for it to answer.
    const pool = stubPool([row(), PAKFOOD(), row({ id: 'd-3', name: 'Third' })]);
    await getCoverageRegister(pool);
    assert.equal(pool.calls.length, 1);
  });

  it('the log-evidence fetch is BOUNDED to firewalls with an unmeasured rule', async () => {
    // Two healthy firewalls and one that cannot report hit counts: the extra
    // cost is two shared statements plus ONE per affected firewall, never one
    // per firewall on the fleet.
    const pool = stubPool(
      [row(), row({ id: 'd-3', name: 'Third' }), TSR_EKM()],
      { coverage: [thinCoverage('d-ekm')], nullRules: [nullRule('d-ekm')] },
    );
    await getCoverageRegister(pool, { now: AT });

    const hitCalls = pool.calls.filter((c) => /syslog_rule_hits_hourly/.test(c.sql));
    assert.equal(hitCalls.length, 1, 'only the firewall with unmeasured rules is visited');
    assert.equal(hitCalls[0].params[0], 'd-ekm');
    assert.equal(pool.calls.length, 4, 'register + coverage + rules + one per affected firewall');
  });

  it('the unmeasured-rule fetch is parameterised and selects the tri-state\'s third state', async () => {
    const pool = stubPool([TSR_EKM()], {
      coverage: [thinCoverage('d-ekm')], nullRules: [nullRule('d-ekm')],
    });
    await getCoverageRegister(pool, { now: AT });
    // ⛔ `rule_id_vendor` is the discriminator: the REGISTER statement also
    // names firewall_rules and also tests `hit_count IS NULL`, so matching on
    // either would assert against the wrong query.
    const call = pool.calls.find((c) => /rule_id_vendor/.test(c.sql));

    assert.match(call.sql, /hit_count\s+IS\s+NULL/i);
    assert.match(call.sql, /=\s*ANY\(\$1::uuid\[\]\)/);
    assert.ok(!/\$\{/.test(call.sql), 'no string interpolation in SQL, ever');
    assert.ok(!/d-ekm/.test(call.sql), 'an id must never appear in the statement text');
    assert.deepEqual(call.params, [['d-ekm']]);
  });

  it('⛔ does not re-implement the grading in SQL — it selects inputs and calls the engine', () => {
    // ⛔ Two files deciding "is this rule in use" would eventually disagree, and
    // the wrong one would be recommending that rules be deleted from a
    // firewall. The grade is ruleHitCorrelation.js's answer and this file only
    // ever COUNTS it.
    assert.ok(/require\(['"]\.\/ruleHitCorrelation['"]\)/.test(CODE),
      'the correlation engine must be imported, not reproduced');
    assert.ok(/enrichRulesWithLogEvidence\(/.test(CODE), 'the engine does the grading');
    assert.ok(!/syslog_rule_hits_hourly/.test(CODE),
      'the rollup belongs to the correlation engine, not to this file');
  });

  it('the unmeasured-rule statement decides nothing — no CASE, no join, no aggregate', async () => {
    const pool = stubPool([TSR_EKM()], {
      coverage: [thinCoverage('d-ekm')], nullRules: [nullRule('d-ekm')],
    });
    await getCoverageRegister(pool, { now: AT });
    const sql = pool.calls.find((c) => /rule_id_vendor/.test(c.sql)).sql;

    assert.ok(!/\bCASE\b/i.test(sql), 'a CASE here would be a second grader');
    assert.ok(!/\bJOIN\b/i.test(sql), 'joining the rollup here would reproduce the engine');
    assert.ok(!/\bcount\(|\bsum\(/i.test(sql), 'this statement counts nothing — the engine grades');
  });

  it('uses a bound parameter for deviceIds — no interpolation anywhere', async () => {
    const call = await sqlOf({ deviceIds: ['d-ok', 'd-pak'] });
    assert.ok(!/\$\{/.test(call.sql), 'no string interpolation in SQL, ever');
    assert.ok(!/d-ok/.test(call.sql), 'an id must never appear in the statement text');
    assert.match(call.sql, /\$1::uuid\[\]/, 'explicitly cast, per CLAUDE.md');
    assert.match(call.sql, /=\s*ANY\(\$1::uuid\[\]\)/);
    assert.deepEqual(call.params, [['d-ok', 'd-pak']]);
  });

  it('omitting deviceIds means the WHOLE active fleet — the parameter is null, not []', async () => {
    const call = await sqlOf(undefined);
    assert.deepEqual(call.params, [null]);
    assert.match(call.sql, /\$1::uuid\[\]\s+IS\s+NULL/i, 'null must widen, not match nothing');
  });

  it('an EMPTY list means NO devices, and is never quietly widened to the fleet', async () => {
    const call = await sqlOf({ deviceIds: [] });
    assert.deepEqual(call.params, [[]]);
  });

  it('junk entries are dropped rather than sent to the database', async () => {
    const call = await sqlOf({ deviceIds: ['a', '', null, 7, 'b'] });
    assert.deepEqual(call.params, [['a', 'b']]);
  });

  it('is driven FROM devices, so a firewall with no evidence still gets a row', async () => {
    const call = await sqlOf();
    assert.match(call.sql, /FROM\s+devices\s+d/i);
    assert.match(call.sql, /WHERE\s+d\.active/i);
  });

  it('reads rule_analysis_results.analyzed_at — the column that exists', async () => {
    // ⛔ VERIFIED against lib/schema.sql: rule_analysis_results declares
    // `analyzed_at TIMESTAMPTZ NOT NULL DEFAULT now()` and has NO `created_at`.
    // The wrong name does not degrade gracefully — the statement throws and the
    // whole register comes back empty.
    const call = await sqlOf();
    assert.match(call.sql, /max\(rr\.analyzed_at\)/i);
    assert.ok(!/rr\.created_at/i.test(call.sql), 'rule_analysis_results has no created_at');
  });

  it('counts unmeasured rules as hit_count IS NULL, the tri-state\'s third state', async () => {
    const call = await sqlOf();
    assert.match(call.sql, /hit_count\s+IS\s+NULL/i);
  });

  it('stores nothing — no INSERT, UPDATE or DELETE anywhere in this engine', () => {
    // A stored register goes stale against the very collection it indexes.
    assert.ok(!/\bINSERT\s+INTO\b/i.test(CODE), 'read time only');
    assert.ok(!/\bUPDATE\s+\w+\s+SET\b/i.test(CODE), 'read time only');
    assert.ok(!/\bDELETE\s+FROM\b/i.test(CODE), 'read time only');
  });

  it('pool is a PARAMETER — the module never imports or instantiates one', () => {
    assert.ok(
      !/require\(['"][^'"]*\bdb['"]\)/.test(CODE) && !/new\s+Pool\b/.test(CODE),
      'CLAUDE.md: never instantiate or import a pool here'
    );
  });
});

// --------------------------------------------------------------------------
// The contract
// --------------------------------------------------------------------------

describe('the exported contract', () => {
  it('exports exactly getCoverageRegister', () => {
    assert.deepEqual(Object.keys(dataModule), ['getCoverageRegister']);
    assert.equal(typeof getCoverageRegister, 'function');
  });

  it('returns entries, summary, failures and generatedAt', async () => {
    const out = await getCoverageRegister(stubPool([row()]));
    assert.deepEqual(Object.keys(out).sort(), ['entries', 'failures', 'generatedAt', 'summary']);
  });

  it('generatedAt is injectable, so the timestamp is pinnable', async () => {
    const out = await getCoverageRegister(stubPool([row()]), { now: '2026-09-25T08:30:00.000Z' });
    assert.equal(out.generatedAt, '2026-09-25T08:30:00.000Z');
  });

  it('generatedAt defaults to now, and is still present on a failure', async () => {
    const before = Date.now();
    const out = await getCoverageRegister(stubPool(new Error('nope')));
    const t = Date.parse(out.generatedAt);
    assert.ok(t >= before && t <= Date.now());
  });

  it('an empty fleet returns no entries and no failures — and devices: 0 says so', async () => {
    const { entries, summary, failures } = await getCoverageRegister(stubPool([]));
    assert.deepEqual(entries, []);
    assert.deepEqual(failures, []);
    assert.equal(summary.devices, 0);
    // ⛔ Identical totals to the throwing case above. `failures` is the ONLY
    // thing that separates "no firewalls" from "we could not look", which is
    // why the caller must read it first.
    assert.equal(summary.devicesWithGaps, 0);
  });

  it('carries the pure engine\'s summary through unchanged', async () => {
    const { summary } = await getCoverageRegister(stubPool([row(), PAKFOOD(), TSR_EKC()]));
    assert.equal(summary.devices, 3);
    assert.equal(summary.devicesFullyCovered, 1);
    assert.equal(summary.devicesWithGaps, 2);
    assert.equal(summary.devicesWithStaleFindings, 1);
    assert.ok(Array.isArray(summary.blockedEngines));
    assert.ok(summary.blockedEngines.length > 0);
  });

  it('tolerates a driver result with no rows array rather than throwing', async () => {
    const pool = { calls: [], async query() { return {}; } };
    const out = await getCoverageRegister(pool);
    assert.deepEqual(out.entries, []);
    assert.deepEqual(out.failures, []);
  });
});
