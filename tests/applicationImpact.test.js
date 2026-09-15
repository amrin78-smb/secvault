'use strict';
// Pins lib/engines/applicationImpact.js — the reverse index behind
// "3 applications depend on this rule" on the Cleanup tab.
//
// ⛔ WHAT THESE TESTS ARE FOR. This module's output sits beside a delete
// button, so every failure mode here has the same shape: an absence rendered as
// an affirmative "safe". There are four distinct ways to arrive at a zero —
//
//   1. no declared flow uses this rule          (a real measurement)
//   2. nothing is declared at all               (a blank map, not a clean one)
//   3. the flow's evaluation was unverified     (unknowable, not zero)
//   4. the evaluation itself failed             (nothing was read)
//
// — and only the first is news. The tests below assert that the other three are
// STRUCTURALLY different objects, not merely differently worded, because a
// renderer only ever compares values.
//
// ⛔ The evaluated inputs are produced by the REAL evaluateFlow(), not by
// hand-written `permittedBy` fixtures. Hand-written ones would pass forever
// after applicationView.js changed the shape it emits, and this module would be
// silently reading `undefined` for every rule — reporting zero dependants for
// the entire fleet.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  IMPACT,
  IMPACT_CLAIM,
  IMPACT_CAVEAT,
  buildImpactIndex,
  impactForRule,
  serialiseImpactIndex,
  getImpactIndex,
} = require('../lib/engines/applicationImpact');

const { evaluateFlow } = require('../lib/engines/applicationViewData');

// ── fixtures ────────────────────────────────────────────────────────────────

function rule(o) {
  return {
    id: o.id,
    rule_id_vendor: o.vendorId === undefined ? o.id : o.vendorId,
    rule_name: o.name || null,
    action: o.action || 'allow',
    enabled: o.enabled !== false,
    sequence_number: o.seq,
    src_addresses: o.src,
    dst_addresses: o.dst,
    services: o.svc,
    hit_count: o.hit_count === undefined ? null : o.hit_count,
  };
}

/** A fleet in the shape loadFleet() returns, minus the DB. */
function fleetOf(devices, { devicesWithoutRules = [] } = {}) {
  return {
    devices: devices.map((d) => ({
      id: d.id,
      name: d.name,
      vendor: 'fortinet',
      rules: d.rules,
      objects: d.objects || [],
      hasRules: d.rules.length > 0,
    })),
    windowDays: 30,
    activeDeviceCount: devices.length + devicesWithoutRules.length,
    devicesWithRules: devices.length,
    devicesWithoutRules,
  };
}

function flowRow(o) {
  return {
    id: o.id,
    application_id: o.applicationId,
    src: o.src,
    dst: o.dst,
    protocol: o.protocol || 'tcp',
    port_start: o.port === undefined ? null : o.port,
    port_end: o.port === undefined ? null : o.port,
    expectation: o.expectation || 'allow',
  };
}

/** `[{application, flows}]`, exactly as evaluateAllApplications returns it. */
function declared(apps, fleet) {
  return apps.map((a) => ({
    application: { id: a.id, name: a.name, criticality: a.criticality || 'normal' },
    flows: a.flows.map((f) => evaluateFlow(f, fleet)),
  }));
}

// A flow whose declared destination is one host on 443.
const WEB = (id, applicationId) => flowRow({
  id, applicationId, src: '10.1.0.0/24', dst: '10.2.0.5', port: 443,
});

// ── 1. the headline figure ──────────────────────────────────────────────────

describe('a rule the declaration depends on', () => {
  it('reports BOTH applications when two of them need the same rule', () => {
    // The literal feature request: an operator on the Cleanup tab must be able
    // to see that more than one business owner is behind a single rule.
    const fleet = fleetOf([{
      id: 'dev-1',
      name: 'FW-CORE',
      rules: [
        rule({ id: 'r-shared', vendorId: '17', name: 'permit-web', seq: 1,
          src: ['any'], dst: ['any'], svc: ['tcp/443'] }),
      ],
    }]);

    const index = buildImpactIndex(declared([
      { id: 'app-a', name: 'SAP Fiori', flows: [WEB('f1', 'app-a')] },
      { id: 'app-b', name: 'Payroll', criticality: 'critical', flows: [WEB('f2', 'app-b')] },
    ], fleet));

    const impact = impactForRule(index, { deviceId: 'dev-1', ruleIdVendor: '17' });

    assert.equal(impact.applicationCount, 2);
    assert.deepEqual(impact.applications.map((a) => a.name).sort(), ['Payroll', 'SAP Fiori']);
    // Both flows have exactly this one rule behind them fleet-wide.
    assert.equal(impact.onlySupportCount, 2);
    assert.equal(impact.impact, IMPACT.BREAKS);
    assert.equal(impact.dependentFlowCount, 2);
  });

  it('is reachable by the vendor rule id AND by the internal rule uuid', () => {
    // The Cleanup tab keys on rule_id_vendor (the only identity that survives a
    // ruleset DELETE+reinsert); applicationView emits the internal uuid as
    // deviceRuleId. Both have to land on the same answer or the figure silently
    // disappears from the one screen it was built for.
    const fleet = fleetOf([{
      id: 'dev-1', name: 'FW-CORE',
      rules: [rule({ id: 'uuid-1', vendorId: '17', seq: 1, src: ['any'], dst: ['any'], svc: ['any'] })],
    }]);
    const index = buildImpactIndex(declared(
      [{ id: 'app-a', name: 'SAP Fiori', flows: [WEB('f1', 'app-a')] }], fleet
    ));

    const byVendor = impactForRule(index, { deviceId: 'dev-1', ruleIdVendor: '17' });
    const byUuid = impactForRule(index, { deviceRuleId: 'uuid-1' });
    assert.equal(byVendor.onlySupportCount, 1);
    assert.equal(byUuid, byVendor, 'the two lookups must return the SAME object, not two shapes');
  });
});

// ── 2. "only support" is computed, never assumed ────────────────────────────

describe('⛔ only-support is computed against the whole fleet, not assumed', () => {
  // Five rules that between them tile the declared source /24 — so all five
  // really do permit part of the flow. (Five IDENTICAL rules would not: the
  // evaluator walks in sequence order, so rules 2-5 would be shadowed and would
  // never claim any volume. That is correct firewall semantics and the reason
  // this fixture is built out of adjacent ranges.)
  const FIVE = [
    rule({ id: 'r1', vendorId: '1', seq: 1, src: ['10.1.0.0/25'], dst: ['10.2.0.5'], svc: ['tcp/443'] }),
    rule({ id: 'r2', vendorId: '2', seq: 2, src: ['10.1.0.128/26'], dst: ['10.2.0.5'], svc: ['tcp/443'] }),
    rule({ id: 'r3', vendorId: '3', seq: 3, src: ['10.1.0.192/27'], dst: ['10.2.0.5'], svc: ['tcp/443'] }),
    rule({ id: 'r4', vendorId: '4', seq: 4, src: ['10.1.0.224/28'], dst: ['10.2.0.5'], svc: ['tcp/443'] }),
    rule({ id: 'r5', vendorId: '5', seq: 5, src: ['10.1.0.240/28'], dst: ['10.2.0.5'], svc: ['tcp/443'] }),
  ];

  it('five permitting rules: removing ONE breaks nothing — each is SHARED', () => {
    const fleet = fleetOf([{ id: 'dev-1', name: 'FW-CORE', rules: FIVE }]);
    const index = buildImpactIndex(declared(
      [{ id: 'app-a', name: 'SAP Fiori', flows: [WEB('f1', 'app-a')] }], fleet
    ));

    assert.equal(index.rules.length, 5, 'all five rules must appear as permitters');
    for (const vendorId of ['1', '2', '3', '4', '5']) {
      const impact = impactForRule(index, { deviceId: 'dev-1', ruleIdVendor: vendorId });
      assert.equal(impact.impact, IMPACT.SHARED, `rule ${vendorId} should be shared`);
      // ⛔ THE ASSERTION THE FEATURE TURNS ON. Removing this rule leaves the
      // flow with four other rules permitting it, so the claim "N declared
      // flows would have nothing permitting them" is ZERO — not one.
      assert.equal(impact.onlySupportCount, 0);
      assert.equal(impact.sharedCount, 1);
      assert.equal(impact.applicationCount, 1);
    }
    assert.equal(index.rulesBreakingSomething, 0);
  });

  it('the LAST remaining permitting rule IS only-support', () => {
    // The same declaration, evaluated against a rulebase where four of the five
    // have already gone.
    const fleet = fleetOf([{ id: 'dev-1', name: 'FW-CORE', rules: [FIVE[0]] }]);
    const index = buildImpactIndex(declared(
      [{ id: 'app-a', name: 'SAP Fiori', flows: [WEB('f1', 'app-a')] }], fleet
    ));

    const impact = impactForRule(index, { deviceId: 'dev-1', ruleIdVendor: '1' });
    assert.equal(impact.impact, IMPACT.BREAKS);
    assert.equal(impact.onlySupportCount, 1);
    assert.equal(impact.sharedCount, 0);
    assert.equal(index.rulesBreakingSomething, 1);
  });

  it('two rules on DIFFERENT firewalls still count as two supports', () => {
    // ⛔ "Nothing permits it" has to mean nothing ANYWHERE. A flow permitted by
    // one rule on each of two firewalls is not broken by losing either, and
    // computing support per-device would report both as breaking.
    const fleet = fleetOf([
      { id: 'dev-1', name: 'FW-A', rules: [rule({ id: 'a', vendorId: '1', seq: 1, src: ['any'], dst: ['any'], svc: ['any'] })] },
      { id: 'dev-2', name: 'FW-B', rules: [rule({ id: 'b', vendorId: '1', seq: 1, src: ['any'], dst: ['any'], svc: ['any'] })] },
    ]);
    const index = buildImpactIndex(declared(
      [{ id: 'app-a', name: 'SAP Fiori', flows: [WEB('f1', 'app-a')] }], fleet
    ));

    // Same vendor id on both devices — the key must be per-device or these two
    // collapse into one answer.
    const a = impactForRule(index, { deviceId: 'dev-1', ruleIdVendor: '1' });
    const b = impactForRule(index, { deviceId: 'dev-2', ruleIdVendor: '1' });
    assert.notEqual(a, b, 'two devices, two distinct answers');
    assert.equal(a.impact, IMPACT.SHARED);
    assert.equal(b.impact, IMPACT.SHARED);
    assert.equal(a.onlySupportCount, 0);
    assert.equal(b.onlySupportCount, 0);
  });
});

// ── 3. ⛔ unknown is not zero ───────────────────────────────────────────────

describe('⛔ an unverified evaluation yields UNKNOWN impact, never zero', () => {
  function unverifiedIndex() {
    // An active firewall whose ruleset was never collected makes every flow
    // unverified — the commonest real cause on this fleet, and the one that
    // would otherwise let a deletion be authorised from missing data.
    const fleet = fleetOf(
      [{
        id: 'dev-1', name: 'FW-CORE',
        rules: [rule({ id: 'r1', vendorId: '17', seq: 1, src: ['any'], dst: ['any'], svc: ['tcp/443'] })],
      }],
      { devicesWithoutRules: ['FW-BRANCH'] }
    );
    return buildImpactIndex(declared(
      [{ id: 'app-a', name: 'SAP Fiori', flows: [WEB('f1', 'app-a')] }], fleet
    ));
  }

  it('the flow is carried as unknown, not as a proven break and not as nothing', () => {
    const index = unverifiedIndex();
    assert.equal(index.unverifiedFlowCount, 1);

    const impact = impactForRule(index, { deviceId: 'dev-1', ruleIdVendor: '17' });
    assert.equal(impact.impact, IMPACT.UNKNOWN);
    assert.equal(impact.unknownCount, 1);
    // ⛔ NOT folded into the headline number in EITHER direction: adding it
    // would fabricate breakage, dropping it would fabricate safety.
    assert.equal(impact.onlySupportCount, 0);
    assert.equal(impact.sharedCount, 0);
    // The application is still named — the operator must know WHO is behind the
    // rule even when the verdict cannot be settled.
    assert.equal(impact.applicationCount, 1);
  });

  it('⛔ is NOT equal to the answer for a rule nothing declared depends on', () => {
    // The whole point. Both end up with onlySupportCount === 0, and a renderer
    // that only reads that number would draw them identically. They must differ
    // structurally so it cannot.
    const unknown = impactForRule(unverifiedIndex(), { deviceId: 'dev-1', ruleIdVendor: '17' });

    const cleanFleet = fleetOf([{
      id: 'dev-1', name: 'FW-CORE',
      rules: [
        rule({ id: 'r1', vendorId: '17', seq: 1, src: ['any'], dst: ['any'], svc: ['tcp/443'] }),
        rule({ id: 'r2', vendorId: '99', seq: 2, src: ['any'], dst: ['any'], svc: ['tcp/8080'] }),
      ],
    }]);
    const cleanIndex = buildImpactIndex(declared(
      [{ id: 'app-a', name: 'SAP Fiori', flows: [WEB('f1', 'app-a')] }], cleanFleet
    ));
    const zero = impactForRule(cleanIndex, { deviceId: 'dev-1', ruleIdVendor: '99' });

    assert.equal(zero.impact, IMPACT.NONE);
    assert.equal(zero.onlySupportCount, 0);
    assert.equal(unknown.onlySupportCount, 0);
    assert.notDeepStrictEqual(
      { impact: unknown.impact, unknownCount: unknown.unknownCount, apps: unknown.applicationCount },
      { impact: zero.impact, unknownCount: zero.unknownCount, apps: zero.applicationCount },
      'unknown impact and zero impact must not be the same value'
    );
    assert.notEqual(unknown.impact, zero.impact);
  });

  it('an unresolvable object on another rule also poisons the answer', () => {
    // The second source of unverified: a rule referencing an address group this
    // device never reported. Its true extent is unknowable, so it may itself be
    // permitting the flow without ever appearing as a permitter.
    const fleet = fleetOf([{
      id: 'dev-1', name: 'FW-CORE',
      rules: [
        rule({ id: 'r0', vendorId: '1', action: 'deny', seq: 1,
          src: ['10.9.9.0/24', 'GRP-NEVER-COLLECTED'], dst: ['any'], svc: ['tcp/443'] }),
        rule({ id: 'r1', vendorId: '17', seq: 2, src: ['any'], dst: ['any'], svc: ['tcp/443'] }),
      ],
    }]);
    const index = buildImpactIndex(declared(
      [{ id: 'app-a', name: 'SAP Fiori', flows: [WEB('f1', 'app-a')] }], fleet
    ));
    const impact = impactForRule(index, { deviceId: 'dev-1', ruleIdVendor: '17' });
    assert.equal(impact.impact, IMPACT.UNKNOWN);
    assert.equal(impact.unknownCount, 1);
    assert.equal(impact.onlySupportCount, 0);
  });
});

// ── 4. ⛔ an empty declaration is not an all-clear ──────────────────────────

describe('⛔ with nothing declared, zero means nothing', () => {
  it('every rule reports zero dependants AND the index says the map is empty', () => {
    const index = buildImpactIndex([]);

    assert.equal(index.declarationEmpty, true);
    assert.equal(index.flowCount, 0);
    assert.equal(index.rules.length, 0);

    const impact = impactForRule(index, { deviceId: 'dev-1', ruleIdVendor: 'anything' });
    assert.equal(impact.onlySupportCount, 0);
    assert.equal(impact.applicationCount, 0);
    // ⛔ THE FLAG A CALLER CANNOT MISS. It rides on the per-rule answer, not
    // only on the index, because a table cell is handed one rule's result and
    // nothing else. Without it, a blank declaration renders as a fleet-wide
    // "no application depends on this" — an empty map turned into a deletion
    // licence for 1,760 rules.
    assert.equal(impact.declarationEmpty, true);
    assert.equal(impact.caveat, IMPACT_CAVEAT);
  });

  it('a FOUND rule carries the same flags as a missing one', () => {
    // Two code paths produce an answer — a finalised entry and the absent-rule
    // fallback — and the honesty flags have to be on BOTH. A caller cannot be
    // expected to know which path it got, and a table cell holds one result and
    // nothing else. (Found by a mutation sweep: hardcoding the flag on the
    // finalised path went unnoticed because only the absent path was asserted.)
    const fleet = fleetOf([{
      id: 'dev-1', name: 'FW-CORE',
      rules: [rule({ id: 'r1', vendorId: '17', seq: 1, src: ['any'], dst: ['any'], svc: ['any'] })],
    }]);
    const index = buildImpactIndex(declared(
      [{ id: 'app-a', name: 'SAP Fiori', flows: [WEB('f1', 'app-a')] }], fleet
    ));
    const found = impactForRule(index, { deviceId: 'dev-1', ruleIdVendor: '17' });
    const missing = impactForRule(index, { deviceId: 'dev-1', ruleIdVendor: 'no-such-rule' });

    for (const [label, answer] of [['found', found], ['missing', missing]]) {
      for (const field of ['declarationEmpty', 'available', 'claim', 'caveat', 'impact']) {
        assert.ok(field in answer, `the ${label} answer dropped ${field}`);
      }
      assert.equal(answer.declarationEmpty, index.declarationEmpty, `${label}: flag disagrees with the index`);
      assert.equal(answer.available, index.available, `${label}: availability disagrees with the index`);
    }
  });

  it('an application declared with no flows is still an empty declaration', () => {
    const index = buildImpactIndex([
      { application: { id: 'app-a', name: 'SAP Fiori' }, flows: [] },
    ]);
    assert.equal(index.applicationCount, 1);
    assert.equal(index.declarationEmpty, true, 'a named application with no flows declares nothing');
  });

  it('⛔ declarationEmpty is FALSE, not true, when the evaluation failed', () => {
    // A failure must never be able to print the reassuring "nothing is declared
    // yet" copy. Nothing was read, so nothing is known about the declaration.
    const failed = buildImpactIndex([], {
      available: false, errors: [{ source: 'application_impact', error: 'boom' }],
    });
    failed.declarationEmpty = false; // what getImpactIndex's catch does
    const impact = impactForRule(failed, { deviceId: 'd', ruleIdVendor: '1' });
    assert.equal(impact.impact, IMPACT.UNKNOWN);
    assert.equal(impact.available, false);
    // ⛔ NULL, not 0. There is no measurement behind this at all.
    assert.equal(impact.onlySupportCount, null);
    assert.equal(impact.declarationEmpty, false);
  });

  it('an isolated source failure inside the evaluation makes the whole index unavailable', () => {
    // evaluateAllApplications isolates its sources; if application_flows could
    // not be read it returns applications with no flows and an error. Treating
    // that as "nothing is declared" would report every rule as unused by
    // everything — a fleet-wide safe-to-delete computed from a failed query.
    const index = buildImpactIndex(
      [{ application: { id: 'a', name: 'SAP' }, flows: [] }],
      { available: false, errors: [{ source: 'application_flows', error: 'boom' }] }
    );
    assert.equal(index.available, false);
    assert.equal(impactForRule(index, { ruleIdVendor: 'x' }).impact, IMPACT.UNKNOWN);
  });
});

// ── 5. a deny-expectation flow is not a dependency ──────────────────────────

describe('⛔ a rule permitting a DENY-expectation flow is not a dependant', () => {
  it('counts as a violation the removal would fix, never as an application that needs it', () => {
    const fleet = fleetOf([{
      id: 'dev-1', name: 'FW-CORE',
      rules: [rule({ id: 'r1', vendorId: '17', seq: 1, src: ['any'], dst: ['any'], svc: ['tcp/443'] })],
    }]);
    const index = buildImpactIndex(declared([{
      id: 'app-a',
      name: 'SAP Fiori',
      flows: [flowRow({
        id: 'f1', applicationId: 'app-a', src: '10.1.0.0/24', dst: '10.2.0.5',
        port: 443, expectation: 'deny',
      })],
    }], fleet));

    const impact = impactForRule(index, { deviceId: 'dev-1', ruleIdVendor: '17' });
    assert.equal(impact.violationCount, 1);
    // Removing it breaks nothing and serves nobody — it removes a permission
    // the operator declared should not exist.
    assert.equal(impact.onlySupportCount, 0);
    assert.equal(impact.applicationCount, 0);
    assert.equal(impact.impact, IMPACT.NONE);
    assert.equal(index.denyFlowCount, 1);
  });
});

// ── 6. the claim itself ────────────────────────────────────────────────────

describe('⛔ the claim may not grow', () => {
  it('says exactly what was computed and no more', () => {
    assert.equal(
      IMPACT_CLAIM,
      'Removing this rule would leave N declared flows with nothing permitting them.'
    );
    // Nothing in the wording may promise reachability, safety, or usage.
    for (const forbidden of [/safe/i, /reachab/i, /unused/i, /guarantee/i]) {
      assert.equal(forbidden.test(IMPACT_CLAIM), false, `claim must not say ${forbidden}`);
    }
    assert.match(IMPACT_CAVEAT, /not proven safe to remove/);
  });

  it('the claim and the caveat travel on every answer, not just on the index', () => {
    const index = buildImpactIndex([]);
    const impact = impactForRule(index, { ruleIdVendor: 'x' });
    assert.equal(impact.claim, IMPACT_CLAIM);
    assert.equal(impact.caveat, IMPACT_CAVEAT);
  });
});

// ── 7. serialisation ───────────────────────────────────────────────────────

describe('the JSON shape a route returns', () => {
  it('carries the flags beside the numbers and survives JSON.stringify', () => {
    const fleet = fleetOf([{
      id: 'dev-1', name: 'FW-CORE',
      rules: [rule({ id: 'r1', vendorId: '17', seq: 1, src: ['any'], dst: ['any'], svc: ['any'] })],
    }]);
    const index = buildImpactIndex(declared(
      [{ id: 'app-a', name: 'SAP Fiori', flows: [WEB('f1', 'app-a')] }], fleet
    ));
    const body = JSON.parse(JSON.stringify(serialiseImpactIndex(index)));
    assert.equal(body.claim, IMPACT_CLAIM);
    assert.equal(body.caveat, IMPACT_CAVEAT);
    assert.equal(body.declarationEmpty, false);
    assert.equal(body.available, true);
    assert.equal(body.rules.length, 1);
    assert.equal(body.rules[0].onlySupportCount, 1);
  });

  it('a deviceId filter narrows the LIST but not the computation', () => {
    // ⛔ Support is counted before the filter. Narrowing must never be able to
    // turn a shared permission into a breaking one.
    const fleet = fleetOf([
      { id: 'dev-1', name: 'FW-A', rules: [rule({ id: 'a', vendorId: '1', seq: 1, src: ['any'], dst: ['any'], svc: ['any'] })] },
      { id: 'dev-2', name: 'FW-B', rules: [rule({ id: 'b', vendorId: '1', seq: 1, src: ['any'], dst: ['any'], svc: ['any'] })] },
    ]);
    const index = buildImpactIndex(declared(
      [{ id: 'app-a', name: 'SAP Fiori', flows: [WEB('f1', 'app-a')] }], fleet
    ));
    const body = serialiseImpactIndex(index, { deviceId: 'dev-1' });
    assert.equal(body.rules.length, 1);
    assert.equal(body.rules[0].deviceId, 'dev-1');
    assert.equal(body.rules[0].onlySupportCount, 0, 'still shared — the other firewall also permits it');
  });
});

// ── 8. the plumbing: cost guard and never-throws ────────────────────────────

function stubPool(handlers) {
  const seen = [];
  return {
    seen,
    async query(sql, params) {
      seen.push(sql);
      for (const [re, answer] of handlers) {
        if (re.test(sql)) {
          if (typeof answer === 'function') return answer(sql, params);
          return answer;
        }
      }
      return { rows: [] };
    },
  };
}

describe('getImpactIndex', () => {
  it('⛔ a COUNT stands in front of the whole-fleet load', async () => {
    // loadFleet is ~750ms plus an evaluation of every flow against every
    // device. With nothing declared there is nothing to invert, and paying that
    // to find out would tax every operator for a feature nobody here uses yet.
    const pool = stubPool([[/count\(\*\)::int AS n FROM application_flows/, { rows: [{ n: 0 }] }]]);
    const index = await getImpactIndex(pool);
    assert.equal(index.declarationEmpty, true);
    assert.equal(index.probe, 'no_flows_declared');
    assert.equal(pool.seen.length, 1, 'the fleet must not be loaded at all');
  });

  it('⛔ the probe FAILS OPEN — an unreadable count is not "nothing declared"', async () => {
    const pool = {
      seen: [],
      async query(sql) {
        this.seen.push(sql);
        if (/count\(\*\)::int AS n FROM application_flows/.test(sql)) throw new Error('no such table');
        return { rows: [] };
      },
    };
    const index = await getImpactIndex(pool);
    assert.equal(index.probe, 'probe_failed_open');
    assert.ok(pool.seen.length > 1, 'it must go on to do the real evaluation');
  });

  it('⛔ never throws — a failure comes back as unavailable, not as a zero', async () => {
    const pool = {
      async query(sql) {
        if (/count\(\*\)::int AS n FROM application_flows/.test(sql)) return { rows: [{ n: 2 }] };
        throw new Error('database is on fire');
      },
    };
    const index = await getImpactIndex(pool);
    assert.equal(index.available, false);
    assert.equal(index.declarationEmpty, false);
    const impact = impactForRule(index, { deviceId: 'd', ruleIdVendor: '1' });
    assert.equal(impact.impact, IMPACT.UNKNOWN);
    assert.equal(impact.onlySupportCount, null);
  });

  it('⛔ an UNEXPECTED throw is caught too, not only an isolated source failure', async () => {
    // evaluateAllApplications isolates its own sources, so the common failure
    // arrives as {errors} rather than as a throw — which means the catch inside
    // getImpactIndex is reached only by something nobody predicted, and is
    // exactly the path least likely to be exercised. This drives it: a query
    // answering with a non-array `rows` blows up in the engine's own final map,
    // outside every try it owns.
    const pool = {
      async query(sql) {
        if (/count\(\*\)::int AS n FROM application_flows/.test(sql)) return { rows: [{ n: 2 }] };
        if (/FROM applications a/.test(sql)) return { rows: 'not-an-array' };
        return { rows: [] };
      },
    };
    const index = await getImpactIndex(pool);
    assert.equal(index.probe, 'failed');
    assert.equal(index.available, false);
    assert.equal(index.declarationEmpty, false);
    assert.equal(index.errors[0].source, 'application_impact');
    assert.equal(impactForRule(index, { ruleIdVendor: '1' }).onlySupportCount, null);
  });
});

// ── 9. the HTTP surface ────────────────────────────────────────────────────

describe('⛔ app/api/applications/impact/route.js', () => {
  const ROOT = path.join(__dirname, '..');
  const FILE = path.join(ROOT, 'app', 'api', 'applications', 'impact', 'route.js');
  const raw = fs.readFileSync(FILE, 'utf8');
  const src = raw
    .split('\n')
    .filter((l) => !l.trim().startsWith('//') && !l.trim().startsWith('*') && !l.trim().startsWith('/*'))
    .join('\n');

  it('exposes GET and no mutating verb at all', () => {
    assert.match(src, /export async function GET\s*\(/);
    for (const verb of ['POST', 'PUT', 'DELETE', 'PATCH']) {
      assert.equal(
        new RegExp(`export async function ${verb}\\s*\\(`).test(src), false,
        `${verb} exists — it would have to be gated on OPERATE`
      );
    }
  });

  it('is UNGATED, because it computes and persists nothing', () => {
    // The rule in this product is about PERSISTENCE, not about the HTTP verb:
    // a read that stores nothing is treated like a GET. This route writes no
    // table, so gating it would only make the UI stricter than its own data.
    assert.equal(/forbiddenResponse/.test(src), false);
    assert.equal(/can\(session/.test(src), false);
    assert.equal(/isAdmin/.test(src), false);
  });

  it('⛔ writes nothing — the justification for being ungated, asserted', () => {
    assert.equal(/\bINSERT\b|\bUPDATE\b|\bDELETE\s+FROM\b/i.test(src), false);
    assert.equal(/createApplication|updateApplication|deleteApplication|addFlow|updateFlow|deleteFlow/.test(src), false);
  });

  it('exports dynamic = force-dynamic, or the build prerenders it against the DB', () => {
    assert.match(src, /export const dynamic = 'force-dynamic'/);
  });

  it('calls the engine rather than re-deriving anything', () => {
    assert.match(src, /getImpactIndex\(/);
    assert.match(src, /serialiseImpactIndex\(/);
    assert.equal(/evaluateFlowOnDevice|permittedBy/.test(src), false,
      'the route must not evaluate flows itself');
  });
});
