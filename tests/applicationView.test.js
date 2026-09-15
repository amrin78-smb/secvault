'use strict';
// Pins lib/engines/applicationView.js — the application view's pure evaluator.
//
// ⛔ WHAT THESE TESTS ARE FOR. Almost every bug this codebase has found is one
// class: a failed or partial read recorded as an affirmative value. This engine
// has three places that can happen, and each has its own section below:
//
//   1. A flow declared over a SUBNET PAIR answered by sampling one address.
//   2. A partial deny reported as a whole deny (or vice versa).
//   3. "No rule decides this" reported as "this is blocked".
//
// The volume arithmetic is exact on purpose — BigInt, no floats — so a test can
// assert that allow + deny + unspecified == the declared flow, every time. A
// model that loses or invents volume is one that is quietly guessing.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const av = require('../lib/engines/applicationView');
const {
  VERDICTS, USED, parseCidr, normaliseFlow, boxVolume, intersectBox, subtractBox,
  evaluateFlowOnDevice, aggregateFlow, usedVerdict, flowFinding, rangeToString,
} = av;

// The plumbing half, for the one thing that cannot be tested without it: the
// traffic window this engine REPORTS has to be the window it MEASURED, and only
// the data layer knows what it handed the evidence queries.
const { loadFleet, resolveWindowDays } = require('../lib/engines/applicationViewData');

// ── helpers ────────────────────────────────────────────────────────────────

function rule(o) {
  return {
    id: o.id || o.rule_id,
    rule_id: o.rule_id,
    name: o.name || null,
    action: o.action,
    enabled: o.enabled !== false,
    sequence_number: o.seq,
    src_addresses: o.src,
    dst_addresses: o.dst,
    services: o.svc,
    hit_count: o.hit_count === undefined ? null : o.hit_count,
  };
}

function flowOf(o) {
  const n = normaliseFlow({
    src: o.src, dst: o.dst, protocol: o.protocol || 'tcp',
    port_start: o.port === undefined ? null : o.port,
    port_end: o.portEnd === undefined ? (o.port === undefined ? null : o.port) : o.portEnd,
  });
  assert.equal(n.ok, true, n.reason);
  return n;
}

/** The invariant that makes every other assertion trustworthy. */
function assertReconciles(r) {
  assert.equal(
    (r.allowVolume + r.denyVolume + r.unspecifiedVolume) === r.total, true,
    `volumes do not reconcile: ${r.allowVolume} + ${r.denyVolume} + ${r.unspecifiedVolume} != ${r.total}`
  );
}

// ── 1. Address parsing ─────────────────────────────────────────────────────

describe('parseCidr', () => {
  it('parses a bare address as a /32', () => {
    assert.deepEqual(parseCidr('10.0.0.1'), { start: 167772161, end: 167772161 });
  });

  it('parses a prefix and normalises to the network address', () => {
    // .5 inside a /24 must yield the whole /24, not a range starting at .5 —
    // otherwise a flow declared "10.1.0.5/24" silently covers the wrong hosts.
    assert.deepEqual(parseCidr('10.1.0.5/24'), parseCidr('10.1.0.0/24'));
    const r = parseCidr('10.1.0.0/24');
    assert.equal(r.end - r.start + 1, 256);
  });

  it('treats "any" and 0.0.0.0/0 as the whole space', () => {
    assert.deepEqual(parseCidr('any'), { start: 0, end: 4294967295 });
    assert.deepEqual(parseCidr('0.0.0.0/0'), { start: 0, end: 4294967295 });
  });

  it('⛔ returns null rather than guessing at anything malformed', () => {
    // A flow an operator typed wrongly must surface as a data problem they can
    // fix. Coercing it to 0.0.0.0 or to a /32 would evaluate a DIFFERENT flow
    // from the one declared and report the answer as if it were theirs.
    for (const bad of ['', '10.0.0', '10.0.0.256', '10.0.0.1/33', '10.0.0.1/x',
      'notanip', '10.0.0.1-10.0.0.5', null, undefined, 42]) {
      assert.equal(parseCidr(bad), null, `accepted ${JSON.stringify(bad)}`);
    }
  });

  it('round-trips through rangeToString', () => {
    assert.equal(rangeToString(parseCidr('10.0.0.1')), '10.0.0.1');
    assert.equal(rangeToString(parseCidr('any')), 'any');
    assert.equal(rangeToString({ start: 167772161, end: 167772165 }), '10.0.0.1-10.0.0.5');
  });
});

describe('normaliseFlow', () => {
  it('a flow with no ports covers every port of its protocol', () => {
    const n = normaliseFlow({ src: '10.0.0.1', dst: '10.0.0.2', protocol: 'tcp' });
    assert.equal(n.ok, true);
    assert.equal(n.box.p0, 0);
    assert.equal(n.box.p1, 65535);
  });

  it('a single port becomes a one-wide range', () => {
    const n = normaliseFlow({ src: '10.0.0.1', dst: '10.0.0.2', port_start: 443 });
    assert.equal(n.box.p0, 443);
    assert.equal(n.box.p1, 443);
  });

  it('⛔ refuses bad input with a REASON rather than throwing', () => {
    // A 500 tells the operator the feature is broken; a reason tells them which
    // field to fix.
    const bad = normaliseFlow({ src: 'nope', dst: '10.0.0.1' });
    assert.equal(bad.ok, false);
    assert.match(bad.reason, /Source/);
    const backwards = normaliseFlow({ src: '10.0.0.1', dst: '10.0.0.2', port_start: 900, port_end: 100 });
    assert.equal(backwards.ok, false);
    assert.match(backwards.reason, /starts after it ends/);
    const oob = normaliseFlow({ src: '10.0.0.1', dst: '10.0.0.2', port_start: 0, port_end: 70000 });
    assert.equal(oob.ok, false);
  });
});

// ── 2. Box arithmetic — the invariant everything else rests on ─────────────

describe('box arithmetic', () => {
  it('subtract partitions exactly: cut + remainder == original', () => {
    const box = av.makeBox(0, 100, 0, 100, 0, 100);
    const cut = av.makeBox(10, 20, 30, 40, 50, 60);
    const rem = subtractBox(box, cut);
    const sum = rem.reduce((a, b) => a + boxVolume(b), 0n) + boxVolume(cut);
    assert.equal(sum, boxVolume(box), 'subtraction lost or invented volume');
  });

  it('the remainder pieces are disjoint from each other', () => {
    const box = av.makeBox(0, 50, 0, 50, 0, 50);
    const rem = subtractBox(box, av.makeBox(10, 20, 10, 20, 10, 20));
    for (let i = 0; i < rem.length; i++) {
      for (let j = i + 1; j < rem.length; j++) {
        assert.equal(intersectBox(rem[i], rem[j]), null,
          'two remainder boxes overlap — volume would be double-counted');
      }
    }
  });

  it('a cut equal to the box leaves nothing', () => {
    const box = av.makeBox(0, 10, 0, 10, 0, 10);
    assert.deepEqual(subtractBox(box, box), []);
  });

  it('non-overlapping boxes do not intersect', () => {
    assert.equal(intersectBox(av.makeBox(0, 5, 0, 5, 0, 5), av.makeBox(6, 9, 0, 5, 0, 5)), null);
  });
});

// ── 3. THE CASE THIS ENGINE EXISTS FOR ────────────────────────────────────

describe('⛔ partial coverage is not a whole answer', () => {
  // The motivating example, quoted in the engine's own header. A per-dimension
  // evaluator calls rule 1 "relevant", sees a deny, and reports the flow
  // BLOCKED — when 254 of its 255 source addresses are permitted. On a `deny`
  // expectation that is a hole reported as closed: a false assurance.
  const flow = flowOf({ src: '10.1.0.0/24', dst: 'any', port: 443 });
  const rules = [
    rule({ rule_id: '1', name: 'deny-one', action: 'deny', seq: 1, src: ['10.1.0.5'], dst: ['any'], svc: ['tcp/443'] }),
    rule({ rule_id: '2', name: 'allow-subnet', action: 'allow', seq: 2, src: ['10.1.0.0/24'], dst: ['any'], svc: ['tcp/443'] }),
  ];

  it('reports partially_permitted, NOT blocked', () => {
    const r = evaluateFlowOnDevice(flow, rules, []);
    assert.equal(r.verdict, VERDICTS.PARTIAL);
    assert.notEqual(r.verdict, VERDICTS.BLOCKED);
  });

  it('quantifies it exactly — 254 of 256 source addresses', () => {
    const r = evaluateFlowOnDevice(flow, rules, []);
    assertReconciles(r);
    const perAddress = boxVolume(av.makeBox(0, 0, flow.box.d0, flow.box.d1, flow.box.p0, flow.box.p1));
    assert.equal(r.denyVolume, perAddress * 1n, 'the deny should cover exactly one address');
    assert.equal(r.allowVolume, perAddress * 255n, 'the allow should cover the remaining 255');
  });

  it('surfaces it as a VIOLATION on a deny expectation', () => {
    // The whole point: something reaches what must not be reached.
    const agg = aggregateFlow([{ device: { id: 'd', name: 'FW' }, result: evaluateFlowOnDevice(flow, rules, []) }]);
    assert.equal(flowFinding('deny', agg).state, 'violation');
  });

  it('and as a PARTIAL break on an allow expectation', () => {
    const agg = aggregateFlow([{ device: { id: 'd', name: 'FW' }, result: evaluateFlowOnDevice(flow, rules, []) }]);
    assert.equal(flowFinding('allow', agg).state, 'partial');
  });

  it('rule ORDER decides: the same two rules reversed permit everything', () => {
    const reversed = [
      rule({ rule_id: '2', action: 'allow', seq: 1, src: ['10.1.0.0/24'], dst: ['any'], svc: ['tcp/443'] }),
      rule({ rule_id: '1', action: 'deny', seq: 2, src: ['10.1.0.5'], dst: ['any'], svc: ['tcp/443'] }),
    ];
    const r = evaluateFlowOnDevice(flow, reversed, []);
    assert.equal(r.verdict, VERDICTS.PERMITTED);
    assert.equal(r.denyVolume, 0n, 'a shadowed deny must claim nothing');
    assertReconciles(r);
  });
});

// ── 4. The straightforward verdicts ───────────────────────────────────────

describe('whole-flow verdicts', () => {
  const flow = flowOf({ src: '10.1.0.0/24', dst: '10.2.0.0/24', port: 1521 });

  it('an exactly-matching allow is permitted', () => {
    const r = evaluateFlowOnDevice(flow, [
      rule({ rule_id: '1', action: 'accept', seq: 1, src: ['10.1.0.0/24'], dst: ['10.2.0.0/24'], svc: ['tcp/1521'] }),
    ], []);
    assert.equal(r.verdict, VERDICTS.PERMITTED);
    assert.equal(r.unspecifiedVolume, 0n);
    assert.equal(r.permittingRules.length, 1);
    assertReconciles(r);
  });

  it('a wider allow still permits the whole flow', () => {
    const r = evaluateFlowOnDevice(flow, [
      rule({ rule_id: '1', action: 'allow', seq: 1, src: ['any'], dst: ['any'], svc: ['any'] }),
    ], []);
    assert.equal(r.verdict, VERDICTS.PERMITTED);
  });

  it('an exactly-matching deny blocks it', () => {
    const r = evaluateFlowOnDevice(flow, [
      rule({ rule_id: '1', action: 'drop', seq: 1, src: ['10.1.0.0/24'], dst: ['10.2.0.0/24'], svc: ['tcp/1521'] }),
    ], []);
    assert.equal(r.verdict, VERDICTS.BLOCKED);
    assertReconciles(r);
  });

  it('⛔ a rulebase that says nothing is UNSPECIFIED, never blocked', () => {
    // No implicit-policy data exists anywhere in this codebase, for any vendor.
    // "No rule decides this" and "this is denied" are different statements and
    // collapsing them would assert a default-deny nobody measured.
    const r = evaluateFlowOnDevice(flow, [
      rule({ rule_id: '1', action: 'allow', seq: 1, src: ['192.168.1.0/24'], dst: ['192.168.2.0/24'], svc: ['tcp/80'] }),
    ], []);
    assert.equal(r.verdict, VERDICTS.UNSPECIFIED);
    assert.notEqual(r.verdict, VERDICTS.BLOCKED);
    assert.equal(r.unspecifiedVolume, r.total);
  });

  it('an empty rulebase is UNSPECIFIED, never blocked', () => {
    const r = evaluateFlowOnDevice(flow, [], []);
    assert.equal(r.verdict, VERDICTS.UNSPECIFIED);
    assert.equal(r.allowVolume, 0n);
    assert.equal(r.denyVolume, 0n);
  });

  it('a disabled rule decides nothing', () => {
    const r = evaluateFlowOnDevice(flow, [
      rule({ rule_id: '1', action: 'allow', enabled: false, seq: 1, src: ['any'], dst: ['any'], svc: ['any'] }),
    ], []);
    assert.equal(r.verdict, VERDICTS.UNSPECIFIED);
  });

  it('the wrong protocol does not match', () => {
    const udp = flowOf({ src: '10.1.0.0/24', dst: '10.2.0.0/24', port: 1521, protocol: 'udp' });
    const r = evaluateFlowOnDevice(udp, [
      rule({ rule_id: '1', action: 'allow', seq: 1, src: ['any'], dst: ['any'], svc: ['tcp/1521'] }),
    ], []);
    assert.equal(r.verdict, VERDICTS.UNSPECIFIED);
  });

  it('⛔ an UNRECOGNISED action decides nothing and is counted', () => {
    // An unknown vendor verb must never be able to manufacture a verdict —
    // the same rule log_hit follows for its action lists.
    const r = evaluateFlowOnDevice(flow, [
      rule({ rule_id: '1', action: 'inspect-and-ponder', seq: 1, src: ['any'], dst: ['any'], svc: ['any'] }),
    ], []);
    assert.equal(r.verdict, VERDICTS.UNSPECIFIED);
    assert.equal(r.unrecognisedActionCount, 1);
  });

  it('⛔ a NULL sequence number sorts LAST, not first', () => {
    // A rule whose position we do not know must not be assumed to sit at the
    // top of the policy, where it would shadow everything beneath it.
    const r = evaluateFlowOnDevice(flow, [
      rule({ rule_id: 'unknown-pos', action: 'deny', seq: null, src: ['any'], dst: ['any'], svc: ['any'] }),
      rule({ rule_id: 'known', action: 'allow', seq: 1, src: ['any'], dst: ['any'], svc: ['any'] }),
    ], []);
    assert.equal(r.verdict, VERDICTS.PERMITTED, 'the positioned allow should have decided first');
  });
});

// ── 5. ⛔ "We could not measure this" — required by CLAUDE.md ──────────────

describe('⛔ unverifiable inputs never produce a settled answer', () => {
  const flow = flowOf({ src: '10.1.0.0/24', dst: '10.2.0.0/24', port: 443 });

  it('an unresolved object name makes the result unverified', () => {
    // The rule references something this device never reported, so how much of
    // the flow it really covers is unknown. The answer must carry that.
    const r = evaluateFlowOnDevice(flow, [
      rule({ rule_id: '1', action: 'allow', seq: 1, src: ['GRP-NOT-COLLECTED'], dst: ['10.2.0.0/24'], svc: ['tcp/443'] }),
    ], []);
    assert.equal(r.unverified, true);
    assert.equal(r.unresolvedRuleCount, 1);
    assert.ok(r.unverifiedReasons.length > 0, 'an unverified result must say why');
  });

  it('an FQDN is unresolved, not a non-match', () => {
    const r = evaluateFlowOnDevice(flow, [
      rule({ rule_id: '1', action: 'deny', seq: 1, src: ['any'], dst: ['files.example.com'], svc: ['tcp/443'] }),
    ], []);
    assert.equal(r.unverified, true);
  });

  it('⛔ a clean rulebase is NOT unverified — the flag must discriminate', () => {
    // A flag that is always on carries no information and trains the reader to
    // ignore it, which is worse than not having it.
    const r = evaluateFlowOnDevice(flow, [
      rule({ rule_id: '1', action: 'allow', seq: 1, src: ['10.1.0.0/24'], dst: ['10.2.0.0/24'], svc: ['tcp/443'] }),
    ], []);
    assert.equal(r.unverified, false);
    assert.deepEqual(r.unverifiedReasons, []);
  });

  it('⛔ a fleet with uncollected rulesets is unverified, NEVER "blocked"', () => {
    // Otherwise a fleet whose rules were never pulled reports every flow as
    // safely unreachable — a perfect result computed entirely from missing data.
    const r = evaluateFlowOnDevice(flow, [], []);
    const agg = aggregateFlow([{ device: { id: 'd', name: 'FW' }, result: r }], { devicesWithoutRules: 3 });
    assert.equal(agg.unverified, true);
    assert.notEqual(agg.verdict, VERDICTS.BLOCKED);
    assert.ok(agg.unverifiedReasons.some((x) => /no collected ruleset/.test(x)));
  });

  it('a permitted-but-unverified allow flow is not reported as a clean pass', () => {
    const r = evaluateFlowOnDevice(flow, [
      rule({ rule_id: '1', action: 'allow', seq: 1, src: ['10.1.0.0/24'], dst: ['10.2.0.0/24'], svc: ['SVC-UNKNOWN'] }),
    ], []);
    const agg = aggregateFlow([{ device: { id: 'd', name: 'FW' }, result: r }]);
    if (agg.verdict === VERDICTS.PERMITTED) {
      assert.equal(flowFinding('allow', agg).state, 'ok_unverified');
      assert.notEqual(flowFinding('allow', agg).state, 'ok');
    }
  });
});

// ── 6. Fleet aggregation ──────────────────────────────────────────────────

describe('⛔ volumes are never unioned across devices', () => {
  const flow = flowOf({ src: '10.1.0.0/24', dst: 'any', port: 80 });

  it('two firewalls each permitting half does NOT make a permitted flow', () => {
    // They are different firewalls, probably on different paths. Summing them
    // would invent a reachability that exists on neither.
    const halfA = evaluateFlowOnDevice(flow, [
      rule({ rule_id: 'a', action: 'allow', seq: 1, src: ['10.1.0.0/25'], dst: ['any'], svc: ['tcp/80'] }),
    ], []);
    const halfB = evaluateFlowOnDevice(flow, [
      rule({ rule_id: 'b', action: 'allow', seq: 1, src: ['10.1.0.128/25'], dst: ['any'], svc: ['tcp/80'] }),
    ], []);
    const agg = aggregateFlow([
      { device: { id: 'a', name: 'FW-A' }, result: halfA },
      { device: { id: 'b', name: 'FW-B' }, result: halfB },
    ]);
    assert.equal(agg.verdict, VERDICTS.PARTIAL);
    assert.notEqual(agg.verdict, VERDICTS.PERMITTED);
    assert.equal(agg.permittedPct, 50);
  });

  it('one device permitting it all is enough for the fleet answer', () => {
    const full = evaluateFlowOnDevice(flow, [
      rule({ rule_id: 'a', action: 'allow', seq: 1, src: ['any'], dst: ['any'], svc: ['any'] }),
    ], []);
    const none = evaluateFlowOnDevice(flow, [], []);
    const agg = aggregateFlow([
      { device: { id: 'a', name: 'FW-A' }, result: none },
      { device: { id: 'b', name: 'FW-B' }, result: full },
    ]);
    assert.equal(agg.verdict, VERDICTS.PERMITTED);
    assert.equal(agg.permittedBy.length, 1);
    assert.equal(agg.permittedBy[0].deviceName, 'FW-B');
  });

  it('names which firewall permits it, so the finding is actionable', () => {
    const r = evaluateFlowOnDevice(flow, [
      rule({ rule_id: 'r7', name: 'allow-web', action: 'allow', seq: 1, src: ['any'], dst: ['any'], svc: ['tcp/80'] }),
    ], []);
    const agg = aggregateFlow([{ device: { id: 'a', name: 'FW-A' }, result: r }]);
    assert.equal(agg.permittedBy[0].rules[0].ruleId, 'r7');
    assert.equal(agg.permittedBy[0].rules[0].name, 'allow-web');
  });

  it('no devices evaluated at all is unspecified, not permitted', () => {
    const agg = aggregateFlow([]);
    assert.equal(agg.verdict, VERDICTS.UNSPECIFIED);
    assert.equal(agg.permittedBy.length, 0);
  });
});

// ── 7. The USED axis ──────────────────────────────────────────────────────

describe('⛔ usedVerdict speaks about RULES, not flows', () => {
  // ⛔ It consumes ruleHitCorrelation's OWN tri-state (`effectiveHitCount`:
  // a real count, a measured 0, or NULL meaning not measurable) rather than a
  // second vocabulary for the same three states.

  it('any rule with measured hits makes it rule-active', () => {
    assert.equal(usedVerdict([{ effectiveHitCount: 0 }, { effectiveHitCount: 42 }]), USED.ACTIVE);
  });

  it('all rules measured-zero makes it rule-idle', () => {
    assert.equal(usedVerdict([{ effectiveHitCount: 0 }, { effectiveHitCount: 0 }]), USED.IDLE);
  });

  it('⛔ ONE unmeasurable rule makes the whole thing unknown', () => {
    // That rule might be the one carrying the traffic. Fortinet over SSH
    // reports no hit counts at all, so this is the common case here, and
    // claiming "idle" would be the strongest possible wrong answer: it is the
    // claim a deletion gets justified by.
    assert.equal(usedVerdict([{ effectiveHitCount: 42 }, { effectiveHitCount: null }]), USED.UNKNOWN);
    assert.equal(usedVerdict([{ effectiveHitCount: 0 }, { effectiveHitCount: null }]), USED.UNKNOWN);
  });

  it('⛔ a NULL count is never read as a zero', () => {
    // The distinction this whole product is built on: "the device reported no
    // hits" and "the device cannot report hits" are different facts.
    assert.notEqual(usedVerdict([{ effectiveHitCount: null }]), USED.IDLE);
    assert.equal(usedVerdict([{ effectiveHitCount: null }]), USED.UNKNOWN);
    assert.equal(usedVerdict([{ effectiveHitCount: 0 }]), USED.IDLE);
  });

  it('a missing or malformed evidence entry is unknown, not idle', () => {
    assert.equal(usedVerdict([null]), USED.UNKNOWN);
    assert.equal(usedVerdict([{}]), USED.UNKNOWN);
  });

  it('no permitting rules at all is unknown, not idle', () => {
    // Nothing permits the flow, so there is no usage question to answer yet.
    assert.equal(usedVerdict([]), USED.UNKNOWN);
    assert.equal(usedVerdict(undefined), USED.UNKNOWN);
  });
});

// ── 8. Expectation → finding ──────────────────────────────────────────────

describe('flowFinding', () => {
  const agg = (verdict, unverified = false) => ({ verdict, unverified, permittedBy: [], blockedBy: [] });

  it('an allow flow nothing permits is a BROKEN APPLICATION', () => {
    assert.equal(flowFinding('allow', agg(VERDICTS.UNSPECIFIED)).state, 'unspecified');
    assert.equal(flowFinding('allow', agg(VERDICTS.BLOCKED)).state, 'broken');
  });

  it('a deny flow something permits is a VIOLATION', () => {
    assert.equal(flowFinding('deny', agg(VERDICTS.PERMITTED)).state, 'violation');
    assert.equal(flowFinding('deny', agg(VERDICTS.PARTIAL)).state, 'violation');
  });

  it('⛔ an unspecified deny flow is NOT a pass', () => {
    // Nothing permits it and nothing denies it. That holds only until someone
    // adds a rule, and this product has no implicit-policy data to say what
    // happens to unmatched traffic. Rendering it green would be inventing a
    // default-deny nobody measured.
    const f = flowFinding('deny', agg(VERDICTS.UNSPECIFIED));
    assert.equal(f.state, 'unspecified');
    assert.notEqual(f.state, 'ok');
  });

  it('⛔ an unverified result never reads as a clean pass, either way', () => {
    assert.equal(flowFinding('allow', agg(VERDICTS.PERMITTED, true)).state, 'ok_unverified');
    assert.equal(flowFinding('deny', agg(VERDICTS.BLOCKED, true)).state, 'ok_unverified');
    assert.equal(flowFinding('allow', agg(VERDICTS.PERMITTED, false)).state, 'ok');
    assert.equal(flowFinding('deny', agg(VERDICTS.BLOCKED, false)).state, 'ok');
  });

  it('an unrecognised expectation is treated as allow, not silently dropped', () => {
    assert.equal(flowFinding(undefined, agg(VERDICTS.PERMITTED)).state, 'ok');
  });
});

// ── 9. The cap ────────────────────────────────────────────────────────────

describe('⛔ the fragmentation cap refuses rather than approximates', () => {
  it('a pathological rulebase yields unspecified + truncated, not a partial answer', () => {
    // ⛔ The addresses must be DISTINCT and NON-ADJACENT, and getting that wrong
    // is why this test failed on its first run against a correct engine:
    // modulo arithmetic collided 6,000 rules down to 3,072 distinct addresses,
    // which sits under the cap. Adjacent addresses are no good either — denying
    // .0 then .1 just moves the remaining box's lower bound instead of
    // splitting it. Every other address in the /16 fragments it properly.
    const flow = flowOf({ src: '10.0.0.0/16', dst: 'any', port: 443 });
    const rules = [];
    for (let i = 0; i < 6000; i++) {
      const offset = i * 2; // 0, 2, 4 ... 11998 — inside the /16, never adjacent
      rules.push(rule({
        rule_id: String(i), action: 'deny', seq: i,
        src: [`10.0.${Math.floor(offset / 256)}.${offset % 256}`],
        dst: ['any'], svc: ['tcp/443'],
      }));
    }
    const r = evaluateFlowOnDevice(flow, rules, []);
    assert.equal(r.truncated, true);
    assert.equal(r.unverified, true);
    assert.equal(r.verdict, VERDICTS.UNSPECIFIED);
    assert.ok(r.unverifiedReasons.some((x) => /incomplete rather than approximate/.test(x)));
  });

  it('a normal rulebase is nowhere near the cap', () => {
    const flow = flowOf({ src: '10.1.0.0/24', dst: '10.2.0.0/24', port: 443 });
    const rules = [];
    for (let i = 0; i < 300; i++) {
      rules.push(rule({
        rule_id: String(i), action: 'allow', seq: i,
        src: [`192.168.${i % 256}.0/24`], dst: ['any'], svc: ['tcp/80'],
      }));
    }
    const r = evaluateFlowOnDevice(flow, rules, []);
    assert.equal(r.truncated, false);
    assertReconciles(r);
  });
});

// ── 10. Object resolution is borrowed, not reimplemented ──────────────────

describe('group expansion comes from objectResolver, unchanged', () => {
  it('a rule naming an address group is expanded through network_objects', () => {
    // Proves this engine is resolving via the shared resolver rather than
    // carrying its own (inevitably diverging) copy of group expansion.
    const flow = flowOf({ src: '10.5.0.10', dst: '10.9.0.10', port: 22 });
    const objects = [
      { object_type: 'address', name: 'host-a', value: '10.5.0.10' },
      { object_type: 'address_group', name: 'admins', value: null, members: ['host-a'] },
      { object_type: 'service', name: 'SSH', value: 'tcp/22' },
    ];
    const r = evaluateFlowOnDevice(flow, [
      rule({ rule_id: '1', action: 'allow', seq: 1, src: ['admins'], dst: ['any'], svc: ['SSH'] }),
    ], objects);
    assert.equal(r.verdict, VERDICTS.PERMITTED);
    assert.equal(r.unverified, false, 'a fully-resolvable group must not read as unverified');
  });
});

// ── 11. ⛔ The cap refuses — without manufacturing the opposite claim ──────

describe('⛔ truncation states what was proven and refuses the rest', () => {
  // ⛔ THE BUG THIS PINS. The cap used to force the verdict to `unspecified`,
  // and `unspecified` is NOT a neutral "unknown" here — flowFinding renders it
  // as "Nothing permits this" / "Nothing permits it, and nothing denies it".
  // So a device that had already matched a rule permitting exactly half the
  // flow, named that rule, and reported permittedPct 50, printed the headline
  // "Nothing permits this" above it. On a `deny` expectation that turned a
  // demonstrated VIOLATION into "nothing permits it" — a hole reported as
  // closed, which this engine's own header names as the dangerous direction.
  //
  // Claimed volume is claimed by rules that really matched, in order, before
  // the walk stopped. It is proven wherever the walk ended; the REFUSAL is
  // carried by truncated/unverified/the reason, not by a wrong verdict.
  function fragmentingRulebase() {
    const rules = [
      rule({
        rule_id: 'allow-half', name: 'allow-half', action: 'allow', seq: 0,
        src: ['10.0.0.0/17'], dst: ['any'], svc: ['tcp/443'], hit_count: 5,
      }),
    ];
    // Distinct, non-adjacent, and in the half the allow did NOT claim — denies
    // inside the allowed half are simply shadowed and fragment nothing.
    for (let i = 0; i < 6000; i++) {
      const off = i * 2;
      rules.push(rule({
        rule_id: 'd' + i, action: 'deny', seq: i + 1,
        src: ['10.0.' + (128 + Math.floor(off / 256)) + '.' + (off % 256)],
        dst: ['any'], svc: ['tcp/443'],
      }));
    }
    return rules;
  }

  const capFlow = flowOf({ src: '10.0.0.0/16', dst: 'any', port: 443 });

  // Walking 6,000 rules to the cap costs ~2s, and nothing here mutates the
  // result, so each of the two rulebases is evaluated ONCE and shared.
  let withAllow = null;
  let denyOnly = null;
  const truncated = () => {
    if (!withAllow) withAllow = evaluateFlowOnDevice(capFlow, fragmentingRulebase(), []);
    return withAllow;
  };
  const truncatedDenyOnly = () => {
    if (!denyOnly) denyOnly = evaluateFlowOnDevice(capFlow, fragmentingRulebase().slice(1), []);
    return denyOnly;
  };

  it('still reports itself truncated, unverified, and says why', () => {
    const r = truncated();
    assert.equal(r.truncated, true, 'this rulebase must actually hit the cap');
    assert.equal(r.unverified, true);
    assert.ok(r.unverifiedReasons.some((x) => /incomplete rather than approximate/.test(x)));
    assertReconciles(r);
  });

  it('⛔ does NOT report "nothing permits this" about a rule it just named', () => {
    const r = truncated();
    assert.ok(r.allowVolume > 0n, 'the allow rule claimed real volume');
    assert.equal(r.permittingRules.length, 1);
    assert.notEqual(r.verdict, VERDICTS.UNSPECIFIED,
      'a named permitting rule and "nothing permits this" cannot both be true');
    assert.equal(r.verdict, VERDICTS.PARTIAL);
  });

  it('⛔ and a deny expectation still sees the VIOLATION', () => {
    const agg = aggregateFlow([{ device: { id: 'd', name: 'FW' }, result: truncated() }]);
    assert.equal(agg.permittedBy.length, 1, 'the permitting rule is reported');
    assert.equal(flowFinding('deny', agg).state, 'violation');
    assert.equal(flowFinding('allow', agg).state, 'partial');
  });

  it('⛔ a truncated walk can never be dressed as a WHOLE answer', () => {
    // The cap only fires while undecided boxes remain, so unspecifiedVolume is
    // non-zero and neither side can reach `total`. That invariant is what makes
    // reporting the proven part safe.
    const r = truncated();
    assert.ok(r.unspecifiedVolume > 0n);
    assert.notEqual(r.verdict, VERDICTS.PERMITTED);
    assert.notEqual(r.verdict, VERDICTS.BLOCKED);
  });

  it('a cap hit with nothing permitted is still unspecified, not blocked', () => {
    // All-deny fragmentation: nothing was proven either way, so the refusal is
    // the whole answer.
    const r = truncatedDenyOnly();
    assert.equal(r.truncated, true);
    assert.equal(r.allowVolume, 0n);
    assert.equal(r.verdict, VERDICTS.UNSPECIFIED);
    assert.notEqual(r.verdict, VERDICTS.BLOCKED);
  });
});

// ── 12. ⛔ Nothing measured is not a measurement ───────────────────────────

describe('⛔ an answer over zero firewalls is never settled', () => {
  it('no device evaluated at all is UNVERIFIED, with a reason', () => {
    // A fresh install has no active devices. `devicesWithoutRules` is 0 and no
    // device reports itself unverified, so this came back as a SETTLED
    // "Nothing permits this" computed over nothing at all — the same shape as a
    // fleet whose rulesets were never pulled reporting perfect segmentation.
    const agg = aggregateFlow([]);
    assert.equal(agg.verdict, VERDICTS.UNSPECIFIED);
    assert.equal(agg.evaluatedDeviceCount, 0);
    assert.equal(agg.unverified, true);
    assert.ok(agg.unverifiedReasons.length > 0, 'an unverified answer must say why');
    assert.ok(agg.unverifiedReasons.some((x) => /No firewall was evaluated/.test(x)));
  });

  it('and neither expectation reads as a clean pass', () => {
    const agg = aggregateFlow([]);
    assert.notEqual(flowFinding('allow', agg).state, 'ok');
    assert.notEqual(flowFinding('deny', agg).state, 'ok');
  });

  it('⛔ but one real device still discriminates — the flag is not always on', () => {
    const f = flowOf({ src: '10.1.0.0/24', dst: '10.2.0.0/24', port: 443 });
    const r = evaluateFlowOnDevice(f, [
      rule({ rule_id: '1', action: 'allow', seq: 1, src: ['10.1.0.0/24'], dst: ['10.2.0.0/24'], svc: ['tcp/443'] }),
    ], []);
    const agg = aggregateFlow([{ device: { id: 'd', name: 'FW' }, result: r }]);
    assert.equal(agg.unverified, false);
    assert.deepEqual(agg.unverifiedReasons, []);
  });
});

// ── 13. Randomised property sweep over the box arithmetic ─────────────────

describe('⛔ the box arithmetic, by PROPERTY rather than by example', () => {
  // ⛔ WHY A GENERATOR AND NOT MORE EXAMPLES. Every other test here is a case
  // someone thought of. The decomposition's failure modes — a piece counted
  // twice, a sliver lost, a later rule re-claiming space an earlier one already
  // took — are invisible in any single example that happens to come out right,
  // and all produce a plausible number rather than a crash.
  //
  // The oracle is deliberately stupid: decide every point in an 8x8x8 universe
  // individually, first matching enabled rule in sequence order wins, and
  // compare the three totals. A fixed seed keeps a failure reproducible.
  let seed = 2026091501;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  const ri = (n) => Math.floor(rnd() * n);
  const N = 8;

  function field(base) {
    const lits = [];
    const set = new Set();
    const k = 1 + ri(3);
    for (let i = 0; i < k; i++) {
      if (rnd() < 0.1) {
        lits.push('any');
        for (let j = 0; j < N; j++) set.add(j);
        continue;
      }
      const a = ri(N);
      const b = ri(N);
      const lo = Math.min(a, b);
      const hi = Math.max(a, b);
      if (base === null) {
        lits.push(lo === hi ? 'tcp/' + lo : 'tcp/' + lo + '-' + hi);
      } else {
        const ip = (o) => '10.0.' + base + '.' + o;
        lits.push(lo === hi ? ip(lo) : ip(lo) + '-' + ip(hi));
      }
      for (let j = lo; j <= hi; j++) set.add(j);
    }
    return { lits, set, any: lits.includes('any') };
  }

  it('matches a point-by-point oracle over 400 generated rulebases', () => {
    const f = flowOf({ src: '10.0.0.0/29', dst: '10.0.1.0/29', port: 0, portEnd: N - 1 });
    for (let trial = 0; trial < 400; trial++) {
      const rules = [];
      const meta = [];
      const n = 1 + ri(6);
      for (let i = 0; i < n; i++) {
        const s = field(0);
        const d = field(1);
        const p = field(null);
        const roll = rnd();
        // Includes an unrecognised verb and disabled rules: both must decide
        // nothing, and "decides nothing" is exactly what quietly leaks volume.
        const action = roll < 0.45 ? 'allow' : (roll < 0.88 ? 'deny' : 'inspect-and-ponder');
        const enabled = rnd() > 0.1;
        const seqNo = rnd() < 0.1 ? null : i;
        meta.push({ s, d, p, action, enabled, seq: seqNo });
        rules.push(rule({
          rule_id: 'r' + i, action, enabled, seq: seqNo,
          src: s.lits, dst: d.lits, svc: p.lits,
        }));
      }

      const r = evaluateFlowOnDevice(f, rules, []);
      assertReconciles(r);

      const ordered = meta.filter((m) => m.enabled).slice().sort((a, b) => {
        if (a.seq === null) return b.seq === null ? 0 : 1;
        if (b.seq === null) return -1;
        return a.seq - b.seq;
      });
      let allow = 0n;
      let deny = 0n;
      let unspec = 0n;
      for (let si = 0; si < N; si++) {
        for (let di = 0; di < N; di++) {
          for (let pi = 0; pi < N; pi++) {
            let decided = null;
            for (const m of ordered) {
              if (m.action !== 'allow' && m.action !== 'deny') continue;
              if (!(m.s.any || m.s.set.has(si))) continue;
              if (!(m.d.any || m.d.set.has(di))) continue;
              if (!(m.p.any || m.p.set.has(pi))) continue;
              decided = m.action;
              break;
            }
            if (decided === 'allow') allow += 1n;
            else if (decided === 'deny') deny += 1n;
            else unspec += 1n;
          }
        }
      }
      const shape = () => JSON.stringify(meta.map(
        (m) => [m.action, m.enabled, m.seq, m.s.lits, m.d.lits, m.p.lits]
      ));
      assert.equal(r.allowVolume, allow, 'allow volume disagrees with the oracle: ' + shape());
      assert.equal(r.denyVolume, deny, 'deny volume disagrees with the oracle: ' + shape());
      assert.equal(r.unspecifiedVolume, unspec, 'unspecified volume disagrees with the oracle: ' + shape());
    }
  });

  it('⛔ a later rule can never re-claim space an earlier one already took', () => {
    // Double counting would break reconciliation, so this asserts the stronger
    // property directly: the second, wider rule adds exactly the remainder.
    const f = flowOf({ src: '10.0.0.0/24', dst: 'any', port: 443 });
    const r = evaluateFlowOnDevice(f, [
      rule({ rule_id: '1', action: 'allow', seq: 1, src: ['10.0.0.0/25'], dst: ['any'], svc: ['tcp/443'] }),
      rule({ rule_id: '2', action: 'allow', seq: 2, src: ['10.0.0.0/24'], dst: ['any'], svc: ['tcp/443'] }),
    ], []);
    assert.equal(r.allowVolume, r.total);
    assert.equal(r.permittingRules.length, 2);
    assert.equal(
      BigInt(r.permittingRules[0].volume) + BigInt(r.permittingRules[1].volume), r.total,
      'the two rules must partition the flow, not overlap it'
    );
    assert.equal(BigInt(r.permittingRules[0].volume), BigInt(r.permittingRules[1].volume));
  });

  it('the 2^32 and port boundaries survive the arithmetic', () => {
    // 0.0.0.0, 255.255.255.255, /0 and /32, port 0 and port 65535 — the places
    // a signed shift or an off-by-one shows up as a whole extra address.
    assert.equal(
      boxVolume(av.makeBox(0, 4294967295, 0, 4294967295, 0, 65535)),
      4294967296n * 4294967296n * 65536n
    );
    const whole = flowOf({ src: '0.0.0.0/0', dst: 'any', port: 0, portEnd: 65535 });
    const r = evaluateFlowOnDevice(whole, [
      rule({ rule_id: '1', action: 'allow', seq: 1, src: ['any'], dst: ['any'], svc: ['any'] }),
    ], []);
    assert.equal(r.allowVolume, r.total);
    assertReconciles(r);

    const edge = flowOf({ src: '255.255.255.255', dst: '0.0.0.0', port: 65535 });
    const e = evaluateFlowOnDevice(edge, [
      rule({ rule_id: '1', action: 'deny', seq: 1, src: ['255.255.255.255'], dst: ['0.0.0.0'], svc: ['tcp/65535'] }),
    ], []);
    assert.equal(e.total, 1n);
    assert.equal(e.denyVolume, 1n);
    assert.equal(e.verdict, VERDICTS.BLOCKED);

    const portZero = flowOf({ src: '10.0.0.1', dst: '10.0.0.2', port: 0 });
    const z = evaluateFlowOnDevice(portZero, [
      rule({ rule_id: '1', action: 'allow', seq: 1, src: ['any'], dst: ['any'], svc: ['tcp/0'] }),
    ], []);
    assert.equal(z.verdict, VERDICTS.PERMITTED, 'port 0 is a port, not a missing value');
  });
});

// ── 14. ⛔ The window that is REPORTED is the window that was MEASURED ─────

describe('⛔ loadFleet reports the traffic window it actually used', () => {
  // A stub pool: canned rows, and it RECORDS THE SQL IT WAS HANDED — which is
  // what lets the window reported be compared with the window measured. Same
  // shape tests/segmentation.test.js uses to pin the identical rule there.
  function stubPool(opts) {
    const o = opts || {};
    const calls = [];
    return {
      calls,
      find: (re) => calls.find((c) => re.test(c.sql)),
      async query(sql, params) {
        calls.push({ sql, params });
        if (/FROM firewall_rules/.test(sql)) return { rows: o.rules || [] };
        if (/FROM devices WHERE active/.test(sql)) return { rows: o.devices || [] };
        if (/FROM network_objects/.test(sql)) return { rows: o.objects || [] };
        if (/syslog_rollup_hourly/.test(sql)) return { rows: [] };
        if (/syslog_rule_hits_hourly/.test(sql)) return { rows: [] };
        throw new Error('unexpected SQL in test: ' + sql.slice(0, 80));
      },
    };
  }

  const dbRule = (over) => Object.assign({
    id: 'r1', device_id: 'd1', rule_name: 'r1', rule_id_vendor: '1',
    sequence_number: 1, enabled: true, action: 'allow',
    src_addresses: ['any'], dst_addresses: ['any'], services: ['any'],
    hit_count: 5, log_enabled: true, vdom: null,
  }, over);

  it('clamps to the evidence layer\'s own bounds', () => {
    assert.equal(resolveWindowDays(undefined), 30);
    assert.equal(resolveWindowDays('not-a-number'), 30);
    // ⛔ Number(null) is 0 and 0 IS finite — the trap this guard exists for. A
    // missing value must not be read as a real one; `?days=` absent arrives as
    // null from URLSearchParams.get.
    assert.equal(resolveWindowDays(null), 30);
    assert.equal(resolveWindowDays(''), 30);
    assert.equal(resolveWindowDays(-5), 7, 'floor, never a negative window');
    assert.equal(resolveWindowDays(0), 7);
    assert.equal(resolveWindowDays(3), 7, 'the floor ruleHitCorrelation enforces');
    assert.equal(resolveWindowDays(45), 45);
    assert.equal(resolveWindowDays(99999), 400, 'cap, never a span the evidence cannot cover');
  });

  it('⛔ pins the reported window against the window the evidence query USED', async () => {
    // The two were resolved independently and disagreed: loadFleet reported
    // `days`, ruleHitCorrelation measured clampDays(days). `days=1000` printed
    // a 1,000-day traffic window over at most 400 days of evidence, and
    // `days=null` printed a 1-day window over 7. If clampDays' bounds ever
    // move, this fails rather than the page quietly mislabelling itself.
    const run = async (asked) => {
      const pool = stubPool({ rules: [dbRule()], devices: [{ id: 'd1', name: 'fw-1', vendor: 'fortinet' }] });
      const fleet = await loadFleet(pool, { windowDays: asked, now: new Date('2026-09-14T00:00:00Z') });
      const coverageCall = pool.find(/syslog_rollup_hourly/);
      assert.equal(
        coverageCall.params[1], fleet.windowDays * 24,
        'reported ' + fleet.windowDays + 'd but measured ' + coverageCall.params[1] + 'h for days=' + asked
      );
      const hitsCall = pool.find(/syslog_rule_hits_hourly/);
      assert.equal(hitsCall.params[2], fleet.windowDays, 'the per-rule query must use the same window');
      return fleet.windowDays;
    };
    const got = await Promise.all([run(3), run(-5), run(45), run(undefined), run(null), run(99999)]);
    assert.deepEqual(got, [7, 7, 45, 30, 30, 400]);
  });

  it('a device with no collected rules is NAMED, not omitted', async () => {
    const pool = stubPool({
      rules: [dbRule({ device_id: 'd1' })],
      devices: [{ id: 'd1', name: 'fw-1', vendor: 'fortinet' }, { id: 'd2', name: 'fw-2', vendor: 'paloalto' }],
    });
    const fleet = await loadFleet(pool);
    assert.equal(fleet.activeDeviceCount, 2);
    assert.equal(fleet.devicesWithRules, 1);
    assert.deepEqual(fleet.devicesWithoutRules, ['fw-2']);
  });
});
