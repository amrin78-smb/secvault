'use strict';
// tests/ruleRiskByTraffic.test.js
//
// ⛔ THIS REPORT'S OUTPUT IS A LIST OF FIREWALL RULES SOMEONE MIGHT DELETE, so
// every wrong answer it can give is expensive in a way a wrong dashboard number
// is not. Three failure modes are pinned here, and all three produce a document
// that renders perfectly:
//
//   1. RANKING ON THE WRONG UNIT. `effectiveHitCount` prefers the DEVICE's own
//      counter, which is cumulative since an unknown per-device reset date.
//      Measured live 2026-09-21 it ran 33x-1,076x the same rule's 30-day logged
//      count, and one rule showed 4.0 BILLION lifetime hits against ZERO logged
//      hits in the window. Summing those into "traffic in this window" mixes two
//      measurements and states the result as one.
//   2. AN UNMEASURED RULE FALLING INTO "CARRIED NOTHING". That manufactures a
//      deletion candidate out of a collector gap.
//   3. AN EMPTY CLEANUP LIST READ AS AN ALL-CLEAR. Zero candidates out of zero
//      answerable rules is a coverage gap; zero out of a thousand is good news.
//      Live, a 30-day window on this fleet produces the first and looks like the
//      second.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  buildRuleRiskData, headlineSentence, worstFinding,
  RISK_FINDINGS, CONCENTRATION_TARGET, MAX_BUSIEST,
} = require('../lib/reports/ruleRiskByTraffic');

const DEV = '11111111-1111-4111-8111-111111111111';

/**
 * A pool stub that answers the four queries buildRuleRiskData issues, routed by
 * the table each one names. Shapes match the live columns.
 */
function stubPool({ rollupHours = 169, rules = [], hits = [], findings = [], devices, throwOn = null }) {
  const devs = devices || [{ id: DEV, name: 'FW1', vendor: 'paloalto', mgmt_method: 'api' }];
  return {
    queries: [],
    async query(sql, params) {
      this.queries.push(sql);
      if (/FROM devices/.test(sql)) {
        if (params && params.length && sql.includes('$1::uuid')) {
          return { rows: devs.filter((d) => d.id === params[0]) };
        }
        return { rows: devs };
      }
      if (/FROM syslog_rollup_hourly/.test(sql)) {
        return {
          rows: devs.map((d) => ({
            device_id: d.id,
            // first_bucket: how far back the rollup goes. A window longer
            // than this can never certify a measured zero.
            first_bucket: new Date(Date.now() - 400 * 24 * 3600 * 1000),
            hours_with_events: rollupHours,
            first_seen: new Date(), last_seen: new Date(), events: 1000,
          })),
        };
      }
      if (/FROM firewall_rules/.test(sql)) {
        if (throwOn && params[0] === throwOn) throw new Error('collection failed');
        return { rows: rules.filter((r) => r.device_id === params[0]) };
      }
      if (/FROM syslog_rule_hits_hourly/.test(sql)) {
        return { rows: hits.filter((h) => h.device_id === params[0]) };
      }
      if (/FROM rule_analysis_results/.test(sql)) {
        return { rows: findings.filter((f) => f.device_id === params[0]) };
      }
      throw new Error(`unstubbed query: ${sql.slice(0, 60)}`);
    },
  };
}

const rule = (over = {}) => ({
  device_id: DEV, id: 'r1', rule_name: 'R1', rule_id_vendor: '1',
  action: 'allow', enabled: true, log_enabled: true, hit_count: null,
  src_zones: [], dst_zones: [], ...over,
});
const hit = (over = {}) => ({
  device_id: DEV, rule_id: '1', rule_name: 'R1', hits: '100',
  first_hit: new Date(), last_hit: new Date(), ...over,
});
const finding = (over = {}) => ({
  device_id: DEV, rule_id: 'r1', finding_type: 'overly_permissive',
  severity: 'medium', detail: 'd', ...over,
});

describe('⛔ the ranked unit is LOGGED hits, never the device counter', () => {
  it('ranks on logged hits and keeps the device counter as separate context', async () => {
    const pool = stubPool({
      rules: [
        rule({ id: 'a', rule_name: 'A', rule_id_vendor: '1', hit_count: 4000000000 }),
        rule({ id: 'b', rule_name: 'B', rule_id_vendor: '2', hit_count: 5 }),
      ],
      hits: [hit({ rule_id: '1', rule_name: 'A', hits: '10' }),
        hit({ rule_id: '2', rule_name: 'B', hits: '900' })],
    });
    const d = await buildRuleRiskData(pool, { days: 7 });

    // ⛔ B outranks A. Under the old measure A's 4-billion lifetime counter put
    // it first on evidence that says nothing about this window. And the Pareto
    // cut then stops at B alone, because 900 of 910 is already 99% — the list
    // ends where the traffic does, which is the whole point of the cut.
    assert.equal(d.busiest.length, 1);
    assert.equal(d.busiest[0].name, 'B');
    assert.equal(d.busiest[0].windowHits, 900);

    // A is still MEASURED and still carries its counter — it just is not busy.
    assert.equal(d.totals.measured, 2);
    const a = d.coverage[0];
    assert.equal(a.measured, 2, 'both rules were answerable');

    // ⛔ AND IT IS NEVER SUMMED. The total is 910, not 4,000,000,005.
    assert.equal(d.totals.traffic, 910);
  });

  it('a rule the device never counted still ranks, on its logged hits', async () => {
    // Every Fortinet is this case: no device counter at all.
    const pool = stubPool({
      rules: [rule({ id: 'a', rule_name: 'A', rule_id_vendor: '1', hit_count: null })],
      hits: [hit({ rule_id: '1', rule_name: 'A', hits: '500' })],
    });
    const d = await buildRuleRiskData(pool, { days: 7 });
    assert.equal(d.busiest.length, 1);
    assert.equal(d.busiest[0].windowHits, 500);
    assert.equal(d.busiest[0].lifetimeHits, null, 'unknown, not zero');
  });
});

describe('⛔ an unmeasured rule is in neither list', () => {
  it('a rule whose firewall was not logging throughout is unmeasured, not idle', async () => {
    // 10 hours of events over a 7-day window: below MIN_COVERAGE_RATIO.
    const pool = stubPool({
      rollupHours: 10,
      rules: [rule({ id: 'a', rule_name: 'A', rule_id_vendor: '1' })],
      hits: [],
      findings: [finding({ rule_id: 'a' })],
    });
    const d = await buildRuleRiskData(pool, { days: 7 });

    assert.equal(d.totals.measured, 0);
    assert.equal(d.totals.unmeasured, 1);
    assert.equal(d.busiest.length, 0, 'not in the busiest list');
    assert.equal(d.cleanupCandidates.length, 0, 'and NOT a deletion candidate');
    assert.equal(d.cleanupMeasurable, 0);
    assert.ok(d.unmeasuredByReason['no-coverage'] > 0
      || d.unmeasuredByReason['window-too-short'] > 0, 'with a stated reason');
  });

  it('a rule with logging switched off is unmeasured with its own reason', async () => {
    const pool = stubPool({
      rules: [rule({ id: 'a', rule_name: 'A', rule_id_vendor: '1', log_enabled: false })],
      hits: [],
    });
    const d = await buildRuleRiskData(pool, { days: 7 });
    assert.equal(d.unmeasuredByReason['rule-logging-disabled'], 1);
    assert.equal(d.busiest.length, 0);
  });
});

describe('⛔ a cleanup candidate needs a MEASURED zero', () => {
  it('a covered firewall with no logged hits yields a candidate', async () => {
    const pool = stubPool({
      rules: [rule({ id: 'a', rule_name: 'A', rule_id_vendor: '1', hit_count: 0 })],
      hits: [],
      findings: [finding({ rule_id: 'a', finding_type: 'any_any', severity: 'critical' })],
    });
    const d = await buildRuleRiskData(pool, { days: 7 });
    assert.equal(d.cleanupCandidates.length, 1);
    assert.equal(d.cleanupCandidates[0].worst.type, 'any_any');
    // ⛔ The device's own zero is a SECOND, longer claim and is flagged apart.
    assert.equal(d.cleanupCandidates[0].deviceAgreesZero, true);
  });

  it('and reports it as NOT agreeing when the firewall supplied no counter', async () => {
    const pool = stubPool({
      rules: [rule({ id: 'a', rule_name: 'A', rule_id_vendor: '1', hit_count: null })],
      hits: [],
      findings: [finding({ rule_id: 'a' })],
    });
    const d = await buildRuleRiskData(pool, { days: 7 });
    assert.equal(d.cleanupCandidates[0].deviceAgreesZero, false,
      'absence of a counter is not agreement');
  });

  it('a rule with no finding is not a candidate, however idle', async () => {
    const pool = stubPool({
      rules: [rule({ id: 'a', rule_name: 'A', rule_id_vendor: '1' })],
      hits: [], findings: [],
    });
    const d = await buildRuleRiskData(pool, { days: 7 });
    assert.equal(d.cleanupCandidates.length, 0);
    assert.equal(d.cleanupMeasurable, 1, 'but it WAS answerable — the denominator holds');
  });
});

describe('⛔ risk means dangerous, and three types are excluded on purpose', () => {
  it('worstFinding returns the most severe RISK finding and ignores the rest', () => {
    const f = worstFinding([
      { type: 'correlation', severity: 'critical' },
      { type: 'overly_permissive', severity: 'medium' },
      { type: 'any_any', severity: 'critical' },
    ]);
    assert.equal(f.type, 'any_any', 'critical correlation must not outrank a real risk finding');
  });

  it('returns null when only excluded types are present', () => {
    assert.equal(worstFinding([
      { type: 'unused', severity: 'critical' },
      { type: 'reorder_candidate', severity: 'high' },
      { type: 'correlation', severity: 'high' },
    ]), null);
  });

  it('the exclusions are pinned, because each would be wrong in a different way', () => {
    // `unused` is self-contradictory in a table of the busiest rules;
    // `correlation` is a merge suggestion; `reorder_candidate` is performance,
    // and being busy is its whole argument.
    for (const t of ['unused', 'correlation', 'reorder_candidate']) {
      assert.equal(RISK_FINDINGS.has(t), false, `${t} must not be a risk finding`);
    }
    for (const t of ['any_any', 'overly_permissive', 'risky_service', 'external_exposure',
      'shadow', 'redundant', 'generalization', 'log_disabled', 'expiring_soon']) {
      assert.equal(RISK_FINDINGS.has(t), true, `${t} is a risk finding`);
    }
  });
});

describe('⛔ the headline names its denominator, its cap and its coverage', () => {
  const base = (over = {}) => ({
    windowDays: 7,
    totals: { enabled: 100, measured: 90, unmeasured: 10 },
    concentration: { rules: 5, share: 0.81, capped: false, rankedTotal: 40 },
    busiestWithRisk: [{}, {}],
    windowCoverage: { sufficient: true, historyHours: 300, shorterWindowSuggested: null },
    ...over,
  });

  it('states the unmeasured count beside the share', () => {
    const s = headlineSentence(base());
    assert.match(s, /5 rules carry 81% of the traffic/);
    assert.match(s, /2 of them carry a hygiene finding/);
    assert.match(s, /10 of 100 enabled rules could not be measured/);
  });

  it('⛔ says so when the list stopped at the cap rather than at the data', () => {
    const s = headlineSentence(base({
      concentration: { rules: 25, share: 0.65, capped: true, rankedTotal: 278 },
    }));
    assert.match(s, /stops at 25 because that is this report's limit/);
    assert.match(s, /278 rules carried traffic/);
  });

  it('⛔ the coverage failure OUTRANKS everything and forbids a cleanup reading', () => {
    const s = headlineSentence(base({
      windowDays: 30,
      windowCoverage: { sufficient: false, historyHours: 313, shorterWindowSuggested: 7 },
      totals: { enabled: 1283, measured: 278, unmeasured: 1005 },
    }));
    assert.match(s, /^No firewall logged to SecVault throughout the last 30 days/);
    assert.match(s, /nothing here may be read as a cleanup list/);
    assert.match(s, /about 13 days of log history/);
    assert.match(s, /ask for a 7-day window instead/);
    // it must NOT lead with a confident concentration claim
    assert.doesNotMatch(s.split('.')[0], /carry \d+% of the traffic/);
  });

  it('nothing measurable at all is stated as a gap, not as a quiet rulebase', () => {
    const s = headlineSentence(base({ totals: { enabled: 100, measured: 0, unmeasured: 100 } }));
    assert.match(s, /gap in evidence, not a quiet rulebase/);
  });

  it('no enabled rules is its own sentence', () => {
    const s = headlineSentence(base({ totals: { enabled: 0, measured: 0, unmeasured: 0 } }));
    assert.match(s, /nothing to weigh/);
  });
});

describe('⛔ a firewall that cannot be read is a named gap', () => {
  it('reports the failure and keeps the rest of the document', async () => {
    const other = '22222222-2222-4222-8222-222222222222';
    const pool = stubPool({
      devices: [
        { id: DEV, name: 'FW1', vendor: 'paloalto', mgmt_method: 'api' },
        { id: other, name: 'FW2', vendor: 'fortinet', mgmt_method: 'ssh' },
      ],
      rules: [rule({ id: 'a', rule_name: 'A', rule_id_vendor: '1' })],
      hits: [hit({ rule_id: '1', rule_name: 'A', hits: '7' })],
      throwOn: other,
    });
    const d = await buildRuleRiskData(pool, { days: 7 });
    assert.equal(d.failures.length, 1);
    assert.equal(d.failures[0].device, 'FW2');
    assert.equal(d.totals.devices, 2);
    assert.equal(d.totals.devicesRead, 1, 'the denominator discloses the gap');
    assert.equal(d.busiest.length, 1, 'and the readable firewall still reports');
  });

  it('a device-scoped report for a device that does not exist returns null', async () => {
    const pool = stubPool({ devices: [] });
    const d = await buildRuleRiskData(pool, { deviceId: DEV });
    assert.equal(d, null, 'so the route can 404 rather than title a document after nothing');
  });
});

describe('⛔ the window default is the one that can answer', () => {
  it('defaults to 7 days, and only 7 or 30 are accepted', async () => {
    const pool = stubPool({ rules: [], hits: [] });
    assert.equal((await buildRuleRiskData(pool, {})).windowDays, 7);
    assert.equal((await buildRuleRiskData(pool, { days: 30 })).windowDays, 30);
    assert.equal((await buildRuleRiskData(pool, { days: 999 })).windowDays, 7,
      'an unsupported window falls back rather than being passed through');
  });

  it('the Pareto target and the cap are what the document says they are', () => {
    assert.equal(CONCENTRATION_TARGET, 0.8);
    assert.equal(MAX_BUSIEST, 25);
  });
});
