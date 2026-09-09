'use strict';
// Pins how lib/adapters/index.js's collectAndStore() wires the rule-cleanup
// loop's VERIFY half: the devices.last_rules_collected_at stamp, and the
// verifyRequestsForDevice() call that reads it.
//
// WHY THIS FILE EXISTS. Listing removable rules is what ManageEngine Firewall
// Analyzer already does. Stating whether the rules ACTUALLY WENT is the whole
// differentiator, and that claim rests on one timestamp being honest.
//
// ⛔ THE CASE THAT MATTERS IS THE FAILED PULL. getRules() throws on a retrieval
// failure and never returns [] — precisely so a failed pull cannot be mistaken
// for an empty ruleset. If the stamp were written anyway, verifyRequestsForDevice
// would judge this device against a timestamp newer than the request's
// submitted_at, find the requested rules absent from a ruleset it never
// re-read, and report every one of them as REMOVED. A collection outage would
// become a fabricated success — the same failed-read-recorded-as-a-fact bug
// this codebase keeps rediscovering (hit_count DEFAULT 0, getRules() -> []),
// this time with an operator acting on the result. It builds clean and produces
// a plausible number, so nothing but a test catches it.
//
// ⛔ NO DATABASE. collectAndStore only ever calls pool.query()/pool.connect(),
// so every test hands it a stub that records the statements it was given and
// returns canned rows. verifyRequestsForDevice is the REAL engine — the point
// under test is the wiring between them (does the stamp precede the read), and
// stubbing the engine would test nothing.
//
// The adapter is injected by monkey-patching CiscoAsaAdapter's prototype before
// collectAndStore constructs it (collectAndStore picks its own adapter from the
// frozen ADAPTERS dispatch table, so there is no seam to inject through).
// Restored in after().

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { collectAndStore } = require('../lib/adapters/index.js');
const { CiscoAsaAdapter } = require('../lib/adapters/cisco_asa');

const DEVICE = { id: 'dev-1', name: 'TEST-ASA', vendor: 'cisco_asa', mgmt_method: 'ssh' };

const SUBMITTED_AT = new Date('2026-09-01T10:00:00Z');
const STAMPED_AT = new Date('2026-09-02T10:00:00Z'); // strictly after SUBMITTED_AT

// --------------------------------------------------------------------------
// SQL predicates. The stamp write and the verifier's read both mention
// last_rules_collected_at, so they are told apart by statement type, never by
// the column name alone.
// --------------------------------------------------------------------------
const isStampWrite = (sql) =>
  /UPDATE\s+devices/i.test(sql) && /SET[\s\S]*last_rules_collected_at\s*=\s*now\(\)/i.test(sql);
const isVerifierDeviceRead = (sql) =>
  /SELECT\s+last_rules_collected_at\s+FROM\s+devices/i.test(sql);
const isVerifierItemRead = (sql) => /FROM\s+rule_change_request_items/i.test(sql);
const isItemOutcomeWrite = (sql) => /UPDATE\s+rule_change_request_items/i.test(sql);
const isLiveRulesRead = (sql) =>
  /SELECT\s+rule_id_vendor\s+FROM\s+firewall_rules/i.test(sql);

/**
 * @param {object} [opts]
 * @param {Array}  [opts.pendingItems]  rows the verifier's item query returns
 * @param {Array}  [opts.liveRules]     rows the verifier's firewall_rules query returns
 * @param {boolean}[opts.failItemRead]  make the verifier's item query reject
 */
function stubPool(opts = {}) {
  const calls = [];
  // Simulates the real column: null until collectAndStore stamps it.
  const device = { last_rules_collected_at: null };

  async function query(sql, params) {
    const text = String(sql);
    calls.push({ sql: text, params });

    if (isStampWrite(text)) {
      device.last_rules_collected_at = STAMPED_AT;
      return { rows: [], rowCount: 1 };
    }
    if (isVerifierDeviceRead(text)) {
      return { rows: [{ last_rules_collected_at: device.last_rules_collected_at }], rowCount: 1 };
    }
    if (isVerifierItemRead(text)) {
      if (opts.failItemRead) throw new Error('relation "rule_change_request_items" does not exist');
      const rows = opts.pendingItems || [];
      return { rows, rowCount: rows.length };
    }
    if (isLiveRulesRead(text)) {
      const rows = opts.liveRules || [];
      return { rows, rowCount: rows.length };
    }
    // Everything else (device_versions, the ruleset rewrite, rule analysis,
    // the final last_collected_at update...) is not what this file pins.
    return { rows: [], rowCount: 0 };
  }

  return {
    calls,
    device,
    query,
    async connect() {
      return { query, release() {} };
    },
    indexOf(pred) {
      return calls.findIndex((c) => pred(c.sql));
    },
    find(pred) {
      return calls.find((c) => pred(c.sql));
    },
    count(pred) {
      return calls.filter((c) => pred(c.sql)).length;
    },
  };
}

// --------------------------------------------------------------------------
// Adapter injection
// --------------------------------------------------------------------------
const RULES_FAILURE = new Error('SSH session closed before the ruleset was read');
const saved = {};

function patchAdapter({ rules }) {
  CiscoAsaAdapter.prototype.getVersion = async () => {
    throw new Error('not under test');
  };
  CiscoAsaAdapter.prototype.getConfig = async () => {
    throw new Error('not under test');
  };
  CiscoAsaAdapter.prototype.getObjects = async () => {
    throw new Error('not under test');
  };
  CiscoAsaAdapter.prototype.getRules = async () => {
    if (rules === 'throw') throw RULES_FAILURE;
    return rules;
  };
}

before(() => {
  for (const m of ['getVersion', 'getConfig', 'getObjects', 'getRules']) {
    saved[m] = CiscoAsaAdapter.prototype[m];
  }
});

after(() => {
  for (const m of Object.keys(saved)) CiscoAsaAdapter.prototype[m] = saved[m];
});

const ONE_RULE = [
  {
    rule_name: 'kept',
    rule_id_vendor: 'RULE-KEPT',
    sequence_number: 1,
    enabled: true,
    action: 'allow',
    log_enabled: true,
    hit_count: 5,
  },
];

describe('collectAndStore: devices.last_rules_collected_at', () => {
  it('is NOT stamped when getRules() throws — a failed pull is not a measurement', async () => {
    patchAdapter({ rules: 'throw' });
    const pool = stubPool();

    const result = await collectAndStore(DEVICE, pool);

    assert.equal(
      pool.count(isStampWrite),
      0,
      'last_rules_collected_at must never be stamped after a failed rules pull'
    );
    assert.equal(pool.device.last_rules_collected_at, null);
    assert.equal(result.rulesCount, null);
    assert.ok(
      result.errors.some((e) => e.startsWith('rules:')),
      'the rules failure is reported, not swallowed'
    );
  });

  it('does not run verification at all when the rules pull failed', async () => {
    patchAdapter({ rules: 'throw' });
    const pool = stubPool({
      pendingItems: [{ id: 'item-1', rule_id_vendor: 'RULE-GONE', submitted_at: SUBMITTED_AT }],
      liveRules: [],
    });

    const result = await collectAndStore(DEVICE, pool);

    // firewall_rules still holds the PREVIOUS pull's ruleset here. Asking it
    // whether a rule is absent would answer from stale data against a stale
    // stamp — the outage-as-success bug.
    assert.equal(pool.count(isVerifierDeviceRead), 0, 'verifier must not read the stamp');
    assert.equal(pool.count(isItemOutcomeWrite), 0, 'no item outcome may be written');
    assert.equal(
      result.ruleChangeVerification,
      null,
      '"we did not look" must stay null, never a zeroed summary that reads as "nothing found"'
    );
  });

  it('is stamped after a successful rules pull, and STRICTLY BEFORE the verifier reads it', async () => {
    patchAdapter({ rules: ONE_RULE });
    const pool = stubPool();

    await collectAndStore(DEVICE, pool);

    const stampAt = pool.indexOf(isStampWrite);
    const readAt = pool.indexOf(isVerifierDeviceRead);
    assert.ok(stampAt >= 0, 'the stamp is written on a successful pull');
    assert.ok(readAt >= 0, 'verification ran');
    assert.ok(
      stampAt < readAt,
      'the stamp must precede the read, or verification judges this pull by the previous pull'
    );
    assert.equal(pool.device.last_rules_collected_at, STAMPED_AT);
  });

  it('stamps only after the ruleset transaction COMMITted', async () => {
    patchAdapter({ rules: ONE_RULE });
    const pool = stubPool();

    await collectAndStore(DEVICE, pool);

    const commitAt = pool.indexOf((sql) => /^\s*COMMIT\s*$/i.test(sql));
    const stampAt = pool.indexOf(isStampWrite);
    assert.ok(commitAt >= 0, 'the ruleset rewrite committed');
    assert.ok(
      commitAt < stampAt,
      'a stamp written before COMMIT could survive a rolled-back ruleset'
    );
  });
});

describe('collectAndStore: rule-cleanup verification', () => {
  it('reports a requested rule as removed once a pull has succeeded after submission', async () => {
    patchAdapter({ rules: ONE_RULE });
    const pool = stubPool({
      pendingItems: [{ id: 'item-1', rule_id_vendor: 'RULE-GONE', submitted_at: SUBMITTED_AT }],
      liveRules: [{ rule_id_vendor: 'RULE-KEPT' }],
    });

    const result = await collectAndStore(DEVICE, pool);

    assert.deepEqual(
      {
        checked: result.ruleChangeVerification.checked,
        removed: result.ruleChangeVerification.removed,
        stillPresent: result.ruleChangeVerification.stillPresent,
        unverifiable: result.ruleChangeVerification.unverifiable,
        error: result.ruleChangeVerification.error,
      },
      { checked: 1, removed: 1, stillPresent: 0, unverifiable: 0, error: null }
    );
  });

  it('a verification failure never breaks the collection run or loses the ruleset', async () => {
    patchAdapter({ rules: ONE_RULE });
    const pool = stubPool({ failItemRead: true });

    const result = await collectAndStore(DEVICE, pool);

    assert.equal(result.rulesCount, 1, 'the ruleset was still collected and stored');
    assert.ok(pool.find(isStampWrite), 'and still stamped');
    assert.ok(
      result.errors.some((e) => e.startsWith('rule change verification:')),
      'the verification problem is surfaced as a partial error'
    );
  });
});
