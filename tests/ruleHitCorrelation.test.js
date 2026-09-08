'use strict';
// Phase 8b — log evidence as rule usage.
//
// ⛔ THE WHOLE FILE IS ABOUT ONE QUESTION: when is "this rule appears in no
// log" a MEASURED ZERO, and when is it just an absence of measurement?
//
// Getting that wrong recreates the single most expensive bug in this codebase.
// `hit_count` was NOT NULL DEFAULT 0 until 2026-08-25, so every vendor that
// could not read hit counts asserted "zero hits" and ruleAnalysis turned that
// into 1,278 fabricated `unused` findings. Log evidence is a second chance to
// make exactly the same mistake from the other direction, and these tests are
// what stop it.
//
// A zero is only real when ALL THREE hold:
//   1. the device was logging throughout the window
//   2. the rule has logging enabled (otherwise it CANNOT appear in a log)
//   3. the window is long enough to mean anything

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  enrichRulesWithLogEvidence,
  getDeviceLogCoverage,
  getLoggedRuleHits,
  MIN_WINDOW_HOURS,
  MIN_COVERAGE_RATIO,
} = require('../lib/engines/ruleHitCorrelation');

const GOOD_COVERAGE = { hoursWithEvents: 700, windowHours: 720, ratio: 0.97, covered: true };
const GAPPY_COVERAGE = { hoursWithEvents: 400, windowHours: 720, ratio: 0.56, covered: false };
const SHORT_COVERAGE = { hoursWithEvents: 6, windowHours: 720, ratio: 0.008, covered: false };

function rule(over) {
  return Object.assign(
    { id: 'r1', rule_name: 'Allow_Web', rule_id_vendor: '21', hit_count: null, log_enabled: true },
    over
  );
}

describe('⛔ a logged zero is only a measurement when it can be one', () => {
  it('is a MEASURED ZERO when the device was logging and the rule logs', () => {
    const [r] = enrichRulesWithLogEvidence([rule()], GOOD_COVERAGE, { byVendorId: new Map(), byName: new Map() });
    assert.equal(r.logEvidence, 'measured-zero');
    assert.equal(r.loggedHits, 0);
    assert.equal(r.effectiveHitCount, 0);
    assert.equal(r.hitCountSource, 'logs');
  });

  it('⛔ is NOT a measurement when the rule has logging DISABLED', () => {
    // The rule cannot appear in a log however much traffic it passes. Its
    // absence measures the logging setting, not the traffic — and SecVault
    // already reports that separately as a log_disabled finding.
    const [r] = enrichRulesWithLogEvidence(
      [rule({ log_enabled: false })], GOOD_COVERAGE, { byVendorId: new Map(), byName: new Map() }
    );
    assert.equal(r.logEvidence, 'rule-logging-disabled');
    assert.equal(r.loggedHits, null, 'must stay null, never 0');
    assert.equal(r.effectiveHitCount, null);
    assert.equal(r.hitCountSource, null);
  });

  it('⛔ is NOT a measurement when the device had logging GAPS', () => {
    // Zero logged hits then measures the collector, not the rule.
    const [r] = enrichRulesWithLogEvidence([rule()], GAPPY_COVERAGE, { byVendorId: new Map(), byName: new Map() });
    assert.equal(r.logEvidence, 'no-coverage');
    assert.equal(r.loggedHits, null);
    assert.equal(r.effectiveHitCount, null);
  });

  it('⛔ is NOT a measurement when the window is too SHORT', () => {
    // A rule idle for six hours is not unused.
    const [r] = enrichRulesWithLogEvidence([rule()], SHORT_COVERAGE, { byVendorId: new Map(), byName: new Map() });
    assert.equal(r.logEvidence, 'window-too-short');
    assert.equal(r.loggedHits, null);
  });

  it('⛔ is NOT a measurement when there is no coverage record at all', () => {
    const [r] = enrichRulesWithLogEvidence([rule()], null, { byVendorId: new Map(), byName: new Map() });
    assert.equal(r.loggedHits, null);
    assert.notEqual(r.logEvidence, 'measured-zero');
  });
});

describe('matching a log identity to a rule', () => {
  it('prefers the vendor rule id, which is exact', () => {
    const byVendorId = new Map([['21', { hits: 5000, lastHit: new Date('2026-09-08T10:00:00Z') }]]);
    const byName = new Map([['Allow_Web', { hits: 9, lastHit: new Date('2026-09-01T00:00:00Z') }]]);
    const [r] = enrichRulesWithLogEvidence([rule()], GOOD_COVERAGE, { byVendorId, byName });
    assert.equal(r.loggedHits, 5000, 'the id match wins over the name match');
    assert.equal(r.logEvidence, 'hits');
  });

  it('falls back to the rule name when the vendor supplies no id', () => {
    // Palo Alto carries no rule id in its logs at all — only the name.
    const byName = new Map([['Allow_Web', { hits: 77, lastHit: null }]]);
    const [r] = enrichRulesWithLogEvidence(
      [rule({ rule_id_vendor: null })], GOOD_COVERAGE, { byVendorId: new Map(), byName }
    );
    assert.equal(r.loggedHits, 77);
  });

  it('⛔ the DEVICE\'s own hit count always wins over the logged one', () => {
    // They measure different things: the device reports over the rule's
    // lifetime, logs only over the retention window. Where the device can
    // answer, its answer is the better one.
    const byVendorId = new Map([['21', { hits: 5000, lastHit: null }]]);
    const [r] = enrichRulesWithLogEvidence(
      [rule({ hit_count: 12 })], GOOD_COVERAGE, { byVendorId, byName: new Map() }
    );
    assert.equal(r.effectiveHitCount, 12);
    assert.equal(r.hitCountSource, 'device');
    assert.equal(r.loggedHits, 5000, 'the logged count is still reported alongside');
  });

  it('a device zero stays a device zero', () => {
    const [r] = enrichRulesWithLogEvidence(
      [rule({ hit_count: 0 })], GOOD_COVERAGE, { byVendorId: new Map(), byName: new Map() }
    );
    assert.equal(r.effectiveHitCount, 0);
    assert.equal(r.hitCountSource, 'device');
  });
});

describe('⛔ Fortinet\'s implicit deny must never be matched to a real rule', () => {
  it('drops policyid 0 with an empty name', async () => {
    // Measured live: policyid=0 with no name carries 84,449 hits on one device.
    // It is the implicit deny, not a configured rule, and attaching that count
    // to whichever real rule shares the key would be a large, confident lie.
    const pool = {
      query: async () => ({
        rows: [
          { rule_id: '0', rule_name: '', hits: '84449', first_hit: null, last_hit: null },
          { rule_id: '7', rule_name: 'chotruycap', hits: '559280', first_hit: null, last_hit: null },
        ],
      }),
    };
    const { byVendorId, byName } = await getLoggedRuleHits(pool, 'dev-1', 30, new Date());
    assert.equal(byVendorId.has('0'), false, 'the implicit deny must not be indexed');
    assert.equal(byName.has(''), false);
    assert.equal(byVendorId.get('7').hits, 559280, 'real rules still land');
  });
});

describe('device log coverage', () => {
  function coveragePool(hoursWithEvents) {
    return {
      query: async () => ({
        rows: [{
          device_id: 'dev-1',
          hours_with_events: hoursWithEvents,
          first_seen: new Date('2026-08-09T00:00:00Z'),
          last_seen: new Date('2026-09-08T00:00:00Z'),
          events: '1000000',
        }],
      }),
    };
  }

  it('marks a densely-logging device as covered', async () => {
    const m = await getDeviceLogCoverage(coveragePool(700), 30, new Date());
    assert.equal(m.get('dev-1').covered, true);
  });

  it('⛔ requires BOTH a long enough window and a high enough ratio', async () => {
    // A device logging densely for two hours has a tiny ratio over 30 days and
    // must not qualify; a device with a long span but a big outage must not
    // either. Two conditions, because either alone can be satisfied wrongly.
    assert.equal((await getDeviceLogCoverage(coveragePool(2), 30, new Date())).get('dev-1').covered, false);
    assert.equal((await getDeviceLogCoverage(coveragePool(400), 30, new Date())).get('dev-1').covered, false);
    assert.ok(MIN_WINDOW_HOURS >= 24, 'a window under a day cannot support an unused claim');
    assert.ok(MIN_COVERAGE_RATIO >= 0.9);
  });

  it('a device absent from the rollup is simply absent, not covered', async () => {
    const m = await getDeviceLogCoverage({ query: async () => ({ rows: [] }) }, 30, new Date());
    assert.equal(m.get('dev-1'), undefined);
    // And an undefined coverage must never enrich into a measured zero.
    const [r] = enrichRulesWithLogEvidence([rule()], m.get('dev-1') || null, { byVendorId: new Map(), byName: new Map() });
    assert.equal(r.loggedHits, null);
  });
});
