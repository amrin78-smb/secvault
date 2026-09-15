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
