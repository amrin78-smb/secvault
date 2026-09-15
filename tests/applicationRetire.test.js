'use strict';
// Pins lib/engines/applicationRetire.js and app/api/applications/[id]/retire.
//
// ⛔ WHAT THESE TESTS ARE FOR. Retiring an application proposes FIREWALL RULES
// FOR DELETION, and the existing cleanup loop will then confirm a deletion as a
// SUCCESS. So the dangerous failure here is not a crash — it is a confident,
// plausible proposal to delete a rule something else still depends on. Every
// section below pins one of the refusals that stops that:
//
//   1. a rule two applications claim is never proposed
//   2. a rule whose usage was never measured is REFUSED, not warned about
//   3. an unverified evaluation cannot authorise a deletion
//   4. an empty proposal always says WHY it is empty
//
// Per tests/README.md: the "we could not measure this" case is the one that
// regresses silently, because the wrong answer is a plausible list rather than
// an exception. Each of those has a positive control beside it — a rule that IS
// proposed — so no refusal can pass by refusing everything.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const engine = require('../lib/engines/applicationRetire');
const { REASONS, NOTES, planRetirement, retireApplication } = engine;
const { can, OPERATE } = require('../lib/rbac');

const ROOT = path.join(__dirname, '..');
const ROUTE = path.join(ROOT, 'app', 'api', 'applications', '[id]', 'retire', 'route.js');

// ── fixtures ───────────────────────────────────────────────────────────────

function rule(o) {
  const hits = o.hits === undefined ? null : o.hits;
  return {
    id: o.id,
    device_id: o.deviceId || 'dev-1',
    rule_id_vendor: o.vendorId === undefined ? o.id : o.vendorId,
    rule_name: o.name || o.id,
    sequence_number: o.seq === undefined ? 1 : o.seq,
    enabled: o.enabled !== false,
    action: o.action || 'allow',
    src_addresses: o.src || ['any'],
    dst_addresses: o.dst || ['10.1.0.10'],
    services: o.svc || ['tcp/443'],
    log_enabled: true,
    hit_count: hits,
    // ruleHitCorrelation's tri-state, exactly as loadFleet would have attached
    // it: a number, a measured 0, or null meaning nothing could report one.
    effectiveHitCount: hits,
  };
}

function device(o) {
  const rules = o.rules || [];
  return {
    id: o.id,
    name: o.name || o.id,
    vendor: 'paloalto',
    rules,
    objects: [],
    hasRules: rules.length > 0,
  };
}

function fleetOf(devices, opts = {}) {
  const without = opts.devicesWithoutRules || [];
  return {
    devices,
    windowDays: 30,
    activeDeviceCount: devices.length + without.length,
    devicesWithRules: devices.length,
    devicesWithoutRules: without,
  };
}

let flowSeq = 0;
function flow(o) {
  flowSeq += 1;
  return {
    id: o.id || `flow-${flowSeq}`,
    src: o.src || 'any',
    dst: o.dst || '10.1.0.10',
    protocol: o.protocol || 'tcp',
    port_start: o.port === undefined ? 443 : o.port,
    port_end: o.port === undefined ? 443 : o.port,
    expectation: o.expectation || 'allow',
  };
}

function app(id, name, flows, status) {
  return { application: { id, name, status: status || 'active' }, flows: flows || [] };
}

/** The cleanup engine's verdict for a device: these vendor ids are offered. */
function candidates(deviceId, eligibleIds, withheldEntries) {
  return new Map([[deviceId, {
    eligible: (eligibleIds || []).map((id) => ({
      ruleIdVendor: id, findingType: 'unused', severity: 'medium', hitCount: 0,
    })),
    withheld: withheldEntries || [],
  }]]);
}

/** The ordinary case: one app, one rule serving it, everything measurable. */
function simple(overrides = {}) {
  const r = rule(Object.assign({ id: 'r1', hits: 0 }, overrides.rule || {}));
  const fleet = fleetOf([device({ id: 'dev-1', name: 'FW-1', rules: [r] })]);
  const apps = [app('app-1', 'Payroll', [flow({})])].concat(overrides.apps || []);
  return {
    fleet,
    applications: apps,
    targetApplicationId: 'app-1',
    candidatesByDevice: overrides.candidatesByDevice !== undefined
      ? overrides.candidatesByDevice
      : candidates('dev-1', ['r1']),
  };
}

const vendorIdsOf = (list) => list.map((x) => x.ruleIdVendor);

// ── 1. "only it claims it" ─────────────────────────────────────────────────

describe('⛔ only rules this application ALONE claims are proposed', () => {
  it('proposes a rule that serves this application and nothing else', () => {
    // POSITIVE CONTROL. Without it every refusal below could pass by refusing
    // everything, which is the one way this feature can be useless and green.
    const plan = planRetirement(simple());
    assert.deepEqual(vendorIdsOf(plan.proposed), ['r1']);
    assert.equal(plan.withheld.length, 0);
    assert.deepEqual(plan.byDevice, [{ deviceId: 'dev-1', deviceName: 'FW-1', ruleIdVendors: ['r1'] }]);
    assert.equal(plan.summary.claimedRules, 1);
  });

  it('⛔ NEVER proposes a rule a second application also claims', () => {
    // The whole safety property. This rule permits Payroll's flow AND the HR
    // portal's; deleting it because Payroll was decommissioned breaks HR, and
    // the verify loop would then report that breakage as a successful cleanup.
    const plan = planRetirement(simple({
      apps: [app('app-2', 'HR Portal', [flow({ dst: '10.1.0.10', port: 443 })])],
    }));

    assert.equal(plan.proposed.length, 0);
    // Asserted directly, not only through the count: a later refactor that
    // proposed it under a different shape must still fail here.
    assert.equal(plan.proposed.some((p) => p.ruleIdVendor === 'r1'), false);

    assert.equal(plan.withheld.length, 1);
    assert.equal(plan.withheld[0].reasonCode, REASONS.ALSO_CLAIMED);
    assert.deepEqual(plan.withheld[0].alsoClaimedBy, ['HR Portal']);
    assert.match(plan.withheld[0].reason, /HR Portal/);
  });

  it('a rule permitting another application’s DENY flow is still a claim', () => {
    // That rule is the other application's violation. Deleting it as a side
    // effect of retiring an unrelated system is not this feature's call, and
    // counting claims broadly is the safe direction — it withholds more.
    const plan = planRetirement(simple({
      apps: [app('app-2', 'Lab', [flow({ dst: '10.1.0.10', port: 443, expectation: 'deny' })])],
    }));
    assert.equal(plan.proposed.length, 0);
    assert.equal(plan.withheld[0].reasonCode, REASONS.ALSO_CLAIMED);
  });

  it('a RETIRED other application still counts as a claimant', () => {
    // Its status is a label someone typed, not evidence its traffic stopped.
    const plan = planRetirement(simple({
      apps: [app('app-2', 'Old ERP', [flow({ dst: '10.1.0.10', port: 443 })], 'retired')],
    }));
    assert.equal(plan.proposed.length, 0);
    assert.equal(plan.withheld[0].reasonCode, REASONS.ALSO_CLAIMED);
  });

  it('does not propose a rule that permits only this application’s DENY flow', () => {
    // A rule permitting a flow the operator declared must never happen is a
    // violation to review, not plumbing to delete.
    const base = simple();
    base.applications = [app('app-1', 'Payroll', [flow({ expectation: 'deny' })])];
    const plan = planRetirement(base);
    assert.equal(plan.proposed.length, 0);
    assert.equal(plan.withheld.length, 0);
    assert.equal(plan.notes[0].code, NOTES.NO_ALLOW_FLOWS);
  });

  it('never proposes a rule no application claims — that is coverage, not a to-do list', () => {
    // An unclaimed rule is a gap in the DECLARATION, not evidence about the
    // rule. With nothing declared, every rule on a fleet is unclaimed.
    const r1 = rule({ id: 'r1', hits: 0 });
    const unrelated = rule({ id: 'r9', hits: 0, dst: ['10.9.9.9'], seq: 2 });
    const plan = planRetirement({
      fleet: fleetOf([device({ id: 'dev-1', name: 'FW-1', rules: [r1, unrelated] })]),
      applications: [app('app-1', 'Payroll', [flow({})])],
      targetApplicationId: 'app-1',
      candidatesByDevice: candidates('dev-1', ['r1', 'r9']),
    });
    assert.deepEqual(vendorIdsOf(plan.proposed), ['r1']);
    assert.equal(vendorIdsOf(plan.withheld).includes('r9'), false);
  });
});

// ── 2. unmeasured usage ────────────────────────────────────────────────────

describe('⛔ an unmeasured hit count is REFUSED, not warned about', () => {
  it('withholds a rule whose effectiveHitCount is null, and says so', () => {
    const plan = planRetirement(simple({ rule: { hits: undefined } }));
    assert.equal(plan.proposed.length, 0);
    assert.equal(plan.withheld.length, 1);

    const w = plan.withheld[0];
    assert.equal(w.reasonCode, REASONS.USAGE_NOT_MEASURED);
    assert.match(w.reason, /never measured/i);
    // ⛔ The reason must say this is NOT evidence the rule is unused. "We cannot
    // tell whether this rule is used" read as "it is unused" is the bug the
    // whole refusal exists for.
    assert.match(w.reason, /not evidence/i);
    // ⛔ And the count stays null on the withheld row. Defaulting it to 0 here
    // would reintroduce the very claim the refusal makes.
    assert.equal(w.effectiveHitCount, null);
  });

  it('a MEASURED ZERO is not the same thing and IS proposed', () => {
    // 0 is the evidence this feature runs on; null is the absence of it. A
    // refusal that cannot tell them apart refuses everything.
    const plan = planRetirement(simple({ rule: { hits: 0 } }));
    assert.deepEqual(vendorIdsOf(plan.proposed), ['r1']);
  });

  it('a rule with real traffic is proposed too — retiring is not a usage question', () => {
    // The application is being decommissioned; a busy rule serving only it is
    // exactly what should go. Usage is refused only when it was never MEASURED.
    const plan = planRetirement(simple({ rule: { hits: 918273 } }));
    assert.deepEqual(vendorIdsOf(plan.proposed), ['r1']);
  });
});

// ── 3. unverified evaluation ───────────────────────────────────────────────

describe('⛔ an unverified evaluation cannot authorise a deletion', () => {
  it('withholds every rule on a device whose rulebase references an unresolved object', () => {
    // A rule naming an FQDN or an object the device never reported could cover
    // any part of any flow — including another application's. So "only this one
    // claims it" was not established on that device, for any rule on it.
    const served = rule({ id: 'r1', hits: 0, seq: 2 });
    const opaque = rule({ id: 'r-fqdn', hits: 0, seq: 1, src: ['some-group-we-never-collected'] });
    const plan = planRetirement({
      fleet: fleetOf([device({ id: 'dev-1', name: 'FW-1', rules: [opaque, served] })]),
      applications: [app('app-1', 'Payroll', [flow({})])],
      targetApplicationId: 'app-1',
      candidatesByDevice: candidates('dev-1', ['r1', 'r-fqdn']),
    });

    assert.equal(plan.proposed.length, 0);
    const w = plan.withheld.find((x) => x.ruleIdVendor === 'r1');
    assert.ok(w, 'the served rule was neither proposed nor withheld — it vanished');
    assert.equal(w.reasonCode, REASONS.UNVERIFIED);
    // ⛔ An unverified answer must always say WHY. A flag with no reason beside
    // it reads as a rendering glitch and gets ignored.
    assert.ok(w.unverifiedReasons.length > 0);
    assert.match(w.unverifiedReasons.join(' '), /FW-1/);
    assert.equal(plan.summary.taintedDeviceCount, 1);
  });

  it('withholds when ANOTHER application’s flow was the unverified one', () => {
    // The risk runs the other way round too: if we could not fully evaluate
    // what the other application depends on, we cannot say this rule is not it.
    const served = rule({ id: 'r1', hits: 0, seq: 2 });
    const opaque = rule({ id: 'r2', hits: 0, seq: 1, dst: ['a-name-with-no-object'], svc: ['tcp/9999'] });
    const plan = planRetirement({
      fleet: fleetOf([device({ id: 'dev-1', name: 'FW-1', rules: [opaque, served] })]),
      applications: [
        app('app-1', 'Payroll', [flow({})]),
        app('app-2', 'Lab', [flow({ dst: '10.4.4.4', port: 9999 })]),
      ],
      targetApplicationId: 'app-1',
      candidatesByDevice: candidates('dev-1', ['r1']),
    });
    assert.equal(plan.proposed.length, 0);
    assert.equal(plan.withheld[0].reasonCode, REASONS.UNVERIFIED);
  });

  it('⛔ a firewall with NO collected ruleset withholds everything, fleet-wide', () => {
    // It hosts no rule we could propose, but its absence says the rulebase is
    // not fully known — and this action rests on a claim about the WHOLE
    // rulebase. A fleet whose rulesets were never pulled must not report a
    // confident deletion list computed entirely from missing data.
    const plan = planRetirement(Object.assign(simple(), {
      fleet: fleetOf(
        [device({ id: 'dev-1', name: 'FW-1', rules: [rule({ id: 'r1', hits: 0 })] })],
        { devicesWithoutRules: ['FW-2'] }
      ),
    }));
    assert.equal(plan.proposed.length, 0);
    assert.equal(plan.withheld[0].reasonCode, REASONS.UNVERIFIED);
    assert.match(plan.summary.globalTaints.join(' '), /FW-2/);
  });

  it('⛔ an unreadable flow on ANY application withholds everything, fleet-wide', () => {
    // A flow that cannot be parsed could claim any rule anywhere. That is an
    // absence of evidence about everything, not evidence of nothing.
    const plan = planRetirement(simple({
      apps: [app('app-2', 'Broken', [{ id: 'f-bad', src: '10.0.0.300', dst: 'any', protocol: 'tcp', expectation: 'allow' }])],
    }));
    assert.equal(plan.proposed.length, 0);
    assert.equal(plan.withheld[0].reasonCode, REASONS.UNVERIFIED);
    assert.match(plan.summary.globalTaints.join(' '), /Broken/);
  });
});

// ── 4. the existing cleanup machinery decides eligibility ──────────────────

describe('⛔ the existing cleanup engine’s refusals are honoured verbatim', () => {
  it('repeats the cleanup engine’s own sentence when it withheld the rule', () => {
    // Two engines wording the same refusal differently is how the two start
    // disagreeing — and createRequest re-checks server-side anyway, so
    // proposing it would produce a request that fails at submission.
    const said = 'Hit count was never measured for this rule — this vendor or transport cannot report one.';
    const plan = planRetirement(simple({
      candidatesByDevice: candidates('dev-1', [], [{ ruleIdVendor: 'r1', reason: said }]),
    }));
    assert.equal(plan.proposed.length, 0);
    assert.equal(plan.withheld[0].reasonCode, REASONS.CLEANUP_WITHHELD);
    assert.equal(plan.withheld[0].reason, said);
  });

  it('withholds a rule the analyser has not independently flagged as removable', () => {
    const plan = planRetirement(simple({ candidatesByDevice: candidates('dev-1', []) }));
    assert.equal(plan.proposed.length, 0);
    assert.equal(plan.withheld[0].reasonCode, REASONS.NOT_CLEANUP_ELIGIBLE);
  });

  it('⛔ NO ANSWER from the cleanup engine is not a yes', () => {
    // A device whose findings could not be read is a failed read, and a failed
    // read may never authorise a deletion.
    const plan = planRetirement(simple({ candidatesByDevice: new Map() }));
    assert.equal(plan.proposed.length, 0);
    assert.equal(plan.withheld[0].reasonCode, REASONS.NOT_CLEANUP_ELIGIBLE);
    assert.match(plan.withheld[0].reason, /could not read/i);
  });

  it('withholds a rule with no vendor identifier — it could never be verified afterwards', () => {
    // firewall_rules is DELETEd and reinserted on every pull, so without
    // rule_id_vendor a request sits unverifiable forever, which looks like
    // progress and is not.
    const plan = planRetirement(simple({ rule: { vendorId: null, hits: 0 } }));
    assert.equal(plan.proposed.length, 0);
    assert.equal(plan.withheld[0].reasonCode, REASONS.NO_VENDOR_ID);
  });
});

// ── 5. an empty proposal always says why ───────────────────────────────────

describe('⛔ an empty proposal is explained, never returned bare', () => {
  it('an application claiming nothing yields an empty proposal and a reason, not an error', () => {
    const plan = planRetirement({
      fleet: fleetOf([device({ id: 'dev-1', name: 'FW-1', rules: [rule({ id: 'r1', hits: 0, dst: ['10.9.9.9'] })] })]),
      applications: [app('app-1', 'Payroll', [flow({ dst: '10.1.0.10' })])],
      targetApplicationId: 'app-1',
      candidatesByDevice: candidates('dev-1', ['r1']),
    });
    assert.deepEqual(plan.proposed, []);
    assert.deepEqual(plan.withheld, []);
    assert.equal(plan.notes.length, 1);
    assert.equal(plan.notes[0].code, NOTES.NOTHING_CLAIMED);
    // ⛔ And it must not read as a guarantee: it is a statement about the rules
    // SecVault has collected.
    assert.match(plan.notes[0].text, /collected/i);
  });

  it('an application with NO FLOWS is a different fact and says so', () => {
    const base = simple();
    base.applications = [app('app-1', 'Payroll', [])];
    const plan = planRetirement(base);
    assert.equal(plan.notes[0].code, NOTES.NO_FLOWS);
    assert.equal(plan.proposed.length, 0);
  });

  it('everything withheld is a THIRD fact, and names the count', () => {
    const plan = planRetirement(simple({ rule: { hits: undefined } }));
    assert.equal(plan.notes[0].code, NOTES.ALL_WITHHELD);
    assert.match(plan.notes[0].text, /1 rule/);
  });

  it('a proposal that succeeded carries no note to explain away', () => {
    assert.deepEqual(planRetirement(simple()).notes, []);
  });

  it('an unknown application id returns null rather than throwing or inventing a plan', () => {
    const base = simple();
    base.targetApplicationId = 'app-does-not-exist';
    assert.equal(planRetirement(base), null);
  });
});

// ── 6. it goes through the EXISTING request machinery ──────────────────────

/**
 * A stub pool: answers each query by shape and records every statement it was
 * handed, so a test can assert what the engine did AND what it did not do.
 */
function stubPool(opts = {}) {
  const statements = [];
  const answer = (text) => {
    if (/FROM applications a/.test(text)) {
      return { rows: [{ id: 'app-1', name: 'Payroll', status: 'retiring', flow_count: 1 }] };
    }
    if (/FROM application_flows/.test(text)) {
      return {
        rows: [{
          id: 'f1', application_id: 'app-1', src: 'any', dst: '10.1.0.10',
          protocol: 'tcp', port_start: 443, port_end: 443, expectation: 'allow', note: null,
        }],
      };
    }
    if (/FROM firewall_rules fr/.test(text)) {
      return { rows: [Object.assign(rule({ id: 'r1', hits: 0 }), { vdom: null })] };
    }
    if (/FROM devices WHERE active/.test(text)) {
      return { rows: [{ id: 'dev-1', name: 'FW-1', vendor: 'paloalto' }] };
    }
    if (/FROM rule_analysis_results/.test(text)) {
      return {
        rows: [{
          rule_id_vendor: 'r1', finding_type: 'unused', severity: 'medium', detail: 'no traffic',
          rule_name: 'r1', hit_count: 0, enabled: true, log_enabled: true, ack_status: null,
        }],
      };
    }
    if (/INSERT INTO rule_change_requests/.test(text)) {
      return { rows: [{ id: 'req-1', device_id: 'dev-1', title: 'Retire Payroll', status: 'draft' }] };
    }
    if (/UPDATE rule_change_requests/.test(text)) {
      if (opts.refuseSubmit) return { rows: [] };
      return { rows: [{ id: 'req-1', device_id: 'dev-1', status: 'submitted' }] };
    }
    return { rows: [] };
  };
  const query = async (text) => { statements.push(String(text)); return answer(String(text)); };
  return {
    statements,
    query,
    connect: async () => ({ query, release: () => {} }),
  };
}

describe('⛔ retiring produces a REQUEST — it deletes nothing and verifies nothing', () => {
  it('creates and submits one request per device, through the existing engine', async () => {
    const pool = stubPool();
    const result = await retireApplication(pool, 'app-1', { createdBy: 'tester' });

    assert.equal(result.ok, true);
    assert.equal(result.requests.length, 1);
    assert.equal(result.requests[0].requestId, 'req-1');
    assert.equal(result.requests[0].status, 'submitted');
    assert.equal(result.submitted, 1);

    const all = pool.statements.join('\n');
    assert.match(all, /INSERT INTO rule_change_requests/);
    assert.match(all, /INSERT INTO rule_change_request_items/);
    // submitRequest, not a hand-rolled status write.
    assert.match(all, /UPDATE rule_change_requests[\s\S]*status = 'submitted'/);
  });

  it('⛔ issues no DELETE and no rule write of any kind', async () => {
    // Retiring must not change the firewall or its stored ruleset. The rules go
    // when a human edits the device; SecVault only asks, and later checks.
    const pool = stubPool();
    await retireApplication(pool, 'app-1', { createdBy: 'tester' });
    for (const s of pool.statements) {
      assert.equal(/DELETE\s+FROM/i.test(s), false, `a DELETE was issued: ${s}`);
      assert.equal(/UPDATE\s+firewall_rules/i.test(s), false, `a rule was written: ${s}`);
      assert.equal(/UPDATE\s+applications/i.test(s), false,
        `the application's own status was changed as a side effect: ${s}`);
    }
  });

  it('⛔ writes no verification of its own — that belongs to one engine only', () => {
    // A second verifier would eventually disagree with the first, and the wrong
    // one would be the one reporting a deletion as done.
    const src = fs.readFileSync(path.join(ROOT, 'lib', 'engines', 'applicationRetire.js'), 'utf8');
    assert.equal(/SET\s+outcome/i.test(src), false, 'this file verifies request items itself');
    assert.equal(/last_rules_collected_at/.test(src), false,
      'this file re-implements the verification precondition');
    assert.match(src, /require\('\.\/ruleChangeRequests'\)/);
  });

  it('⛔ refuses to submit anything the reviewer was not shown', async () => {
    // A confirmation screen that can be overtaken by a re-collection between
    // display and click is not a confirmation.
    const pool = stubPool();
    const result = await retireApplication(pool, 'app-1', { createdBy: 'tester', expect: [] });
    assert.equal(result.ok, false);
    assert.equal(result.drifted, true);
    assert.deepEqual(result.added, ['r1']);
    assert.equal(result.requests.length, 0);
    assert.equal(pool.statements.some((s) => /INSERT INTO rule_change_requests/.test(s)), false,
      'a request was raised despite the drift');
  });

  it('submits when the reviewed list matches', async () => {
    const pool = stubPool();
    const result = await retireApplication(pool, 'app-1', { createdBy: 'tester', expect: ['r1'] });
    assert.equal(result.ok, true);
    assert.equal(result.submitted, 1);
  });

  it('⛔ a device whose request failed is NAMED, not silently dropped', async () => {
    // An operator told "done" while one firewall was skipped never looks again.
    const pool = stubPool({ refuseSubmit: true });
    const result = await retireApplication(pool, 'app-1', { createdBy: 'tester' });
    assert.equal(result.ok, false);
    assert.equal(result.failures.length, 1);
    assert.equal(result.failures[0].deviceName, 'FW-1');
    assert.match(result.failures[0].error, /draft/);
  });

  it('an unknown application id is null from the plumbing too', async () => {
    const pool = stubPool();
    assert.equal(await retireApplication(pool, 'app-nope', {}), null);
  });
});

// ── 7. the route ───────────────────────────────────────────────────────────

describe('⛔ POST /api/applications/[id]/retire', () => {
  const src = fs.readFileSync(ROUTE, 'utf8');
  const code = src.split('\n')
    .filter((l) => !l.trim().startsWith('//') && !l.trim().startsWith('*') && !l.trim().startsWith('/*'))
    .join('\n');

  it('gates on OPERATE, and refuses by naming the capability', () => {
    assert.match(code, /can\(session,\s*OPERATE\)/);
    assert.match(code, /forbiddenResponse\(OPERATE\)/);
    assert.match(code, /getServerSession\(authOptions\)/);
  });

  it('⛔ gates BEFORE it computes anything', () => {
    const gate = code.search(/can\(session,\s*OPERATE\)/);
    const work = code.search(/planApplicationRetirement\(|retireApplication\(/);
    assert.ok(gate > -1 && work > -1 && gate < work,
      'the capability check runs after the work — by then the proposal has been built');
  });

  it('the capability really does exclude an unauthenticated caller', () => {
    // Pinned against rbac itself, so the gate above cannot be satisfied by a
    // capability that no longer means anything.
    assert.equal(can(null, OPERATE), false);
    assert.equal(can({ user: { role: 'operator' } }, OPERATE), true);
  });

  it('404s an unknown application id, and 400s a malformed one', () => {
    assert.match(code, /isValidUuid\(params\.id\)/);
    assert.match(code, /Invalid application id[\s\S]*status: 400/);
    assert.match(code, /Application not found[\s\S]*status: 404/);
    const guard = code.search(/isValidUuid\(params\.id\)/);
    const work = code.search(/planApplicationRetirement\(|retireApplication\(/);
    assert.ok(guard < work, 'the id reaches the engine before it is validated');
  });

  it('⛔ submits only on an explicit confirm — the plan writes nothing', () => {
    assert.match(code, /confirm\s*===\s*true/);
    const plan = code.search(/planApplicationRetirement\(/);
    const submit = code.search(/retireApplication\(/);
    assert.ok(plan > -1 && submit > -1 && plan < submit);
  });

  it('⛔ returns the WITHHELD half, not just the proposal', () => {
    // The route hands back the engine's whole plan object. A route that picked
    // `proposed` out of it would give the UI a shorter list that looks
    // complete — which is the bug this feature is built to refuse.
    assert.match(code, /mode:\s*'plan',\s*plan/);
    assert.equal(/plan\.proposed\s*\}/.test(code), false, 'the route narrows the plan');
  });

  it('is force-dynamic and exposes no GET', () => {
    assert.match(code, /export const dynamic = 'force-dynamic'/);
    assert.equal(/export async function GET/.test(code), false);
  });

  it('surfaces a thrown failure rather than an empty success', () => {
    assert.match(code, /catch\s*\(\s*err\s*\)/);
    assert.match(code, /error:\s*err\.message/);
    assert.match(code, /status: 500/);
  });
});
