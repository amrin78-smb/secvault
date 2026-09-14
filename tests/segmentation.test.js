'use strict';
// Pins lib/engines/segmentation.js — declared segmentation intent, tested as
// "can this reach that" AND "did it" (Phase 3, v2.113.0).
//
// ⛔ THE TWO WAYS THIS CAN LIE, and both are worse than saying nothing:
//
//   1. UNDERSTATING REACHABILITY. `any` is a wildcard and appears 114 times on
//      the live fleet; treating it literally would report a wide-open path as
//      blocked. On a segmentation report that is the dangerous direction — a
//      hole reported as closed is not a missed finding, it is a false
//      assurance.
//   2. CALLING AN UNMEASURED PATH UNUSED. Fortinet over SSH reports no hit
//      counts at all (0 of 180 rules live). If a permitting rule cannot be
//      measured, the pair is UNKNOWN, never "never used" — recommending the
//      removal of a rule that may be carrying production traffic is exactly the
//      mistake every competing tool makes.
//
// The verdict names are asserted literally rather than by severity, because the
// whole value of the feature is that "permitted but unused" and "permitted,
// unmeasurable" are DIFFERENT answers.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  evaluateIntent,
  summarise,
  zoneListMatches,
  trafficEvidence,
  isAllowAction,
  isDenyAction,
  isUnrecognisedAction,
} = require('../lib/engines/segmentation');
const {
  resolveWindowDays,
  parseWindowDaysParam,
  loadFleetRulesWithEvidence,
  evaluateSegmentation,
} = require('../lib/engines/segmentationData');
const fs = require('node:fs');
const path = require('node:path');

const readSrc = (...parts) =>
  fs.readFileSync(path.join(__dirname, '..', ...parts), 'utf8');

// A rule as ruleHitCorrelation hands it over.
const rule = (over) => ({
  device_id: 'd1',
  enabled: true,
  action: 'allow',
  src_zones: ['branch'],
  dst_zones: ['cardholder'],
  rule_name: 'r',
  sequence_number: 1,
  effectiveHitCount: 0,
  logEvidence: 'measured-zero',
  ...over,
});

const DENY_INTENT = { sourceZone: 'branch', destZone: 'cardholder', expectation: 'deny' };
const ALLOW_INTENT = { sourceZone: 'branch', destZone: 'core', expectation: 'allow' };

// ⛔ EVERY NEGATIVE VERDICT NEEDS THIS CONTEXT, and that is the point of it.
// "Nothing permits this path" is a claim about every rule on every firewall, so
// it is only assertable when every active device's ruleset was actually
// collected. Tests that want `ok_blocked` or `expected_allow_missing` must say
// so explicitly; the coverage-gap cases below say the opposite.
const FULL_COVERAGE = { rulesCollected: true, activeDeviceCount: 1, devicesWithRules: 1 };

describe('zone matching', () => {
  it('matches exactly, case-insensitively', () => {
    assert.equal(zoneListMatches(['LAN'], 'lan'), true);
    assert.equal(zoneListMatches(['lan'], 'LAN'), true);
    assert.equal(zoneListMatches(['lan'], 'dmz1'), false);
  });

  it('⛔ treats `any` as a WILDCARD', () => {
    // 114 occurrences live. Matching it literally reports open paths as blocked.
    assert.equal(zoneListMatches(['any'], 'cardholder'), true);
    assert.equal(zoneListMatches(['ANY'], 'anything-at-all'), true);
  });

  it('⛔ treats an EMPTY or absent zone list as unconstrained', () => {
    // A rule with no zone constraint constrains nothing. Reading it as
    // "matches nothing" silently drops real rules from the analysis.
    assert.equal(zoneListMatches([], 'cardholder'), true);
    assert.equal(zoneListMatches(null, 'cardholder'), true);
    assert.equal(zoneListMatches(undefined, 'cardholder'), true);
  });

  it('knows the allow and deny action families', () => {
    for (const a of ['allow', 'accept', 'permit']) assert.equal(isAllowAction(a), true);
    // ⛔ 'block' belongs to the deny family — firewall_rules.action says so.
    for (const d of ['deny', 'drop', 'reject', 'block']) assert.equal(isDenyAction(d), true);
    assert.equal(isAllowAction('deny'), false);
    assert.equal(isDenyAction('allow'), false);
  });
});

describe('⛔ traffic evidence is TRI-STATE', () => {
  it('true when any permitting rule has hits', () => {
    const e = trafficEvidence([rule({ effectiveHitCount: 0 }), rule({ effectiveHitCount: 42 })]);
    assert.equal(e.did, true);
  });

  it('false only when EVERY permitting rule was measured and all were zero', () => {
    const e = trafficEvidence([rule({ effectiveHitCount: 0 }), rule({ effectiveHitCount: 0 })]);
    assert.equal(e.did, false);
    assert.equal(e.measured, 2);
  });

  it('⛔ NULL WINS OVER FALSE — one unmeasured rule makes the pair unknown', () => {
    // The unmeasured rule might be the one carrying the traffic. Collapsing to
    // "no traffic" because the others were quiet is how an in-use path gets
    // recommended for deletion.
    const e = trafficEvidence([
      rule({ effectiveHitCount: 0, logEvidence: 'measured-zero' }),
      rule({ effectiveHitCount: null, logEvidence: 'no-coverage' }),
    ]);
    assert.equal(e.did, null);
    assert.equal(e.unmeasured, 1);
    assert.ok(e.reasons.includes('no-coverage'));
  });

  it('no rules at all is unknown, never false', () => {
    assert.equal(trafficEvidence([]).did, null);
  });
});

describe('deny intent', () => {
  it('⛔ permitted AND used is the worst verdict', () => {
    const r = evaluateIntent(DENY_INTENT, [rule({ effectiveHitCount: 500 })]);
    assert.equal(r.verdict, 'violation_active');
    assert.equal(r.can, true);
    assert.equal(r.did, true);
  });

  it('⛔ permitted but NEVER USED is its own verdict — the cleanup backlog', () => {
    // The cell no competitor can produce: a standing hole with no demonstrated
    // purpose, and the safest possible thing to close.
    const r = evaluateIntent(DENY_INTENT, [rule({ effectiveHitCount: 0 })]);
    assert.equal(r.verdict, 'violation_permitted');
    assert.equal(r.did, false);
  });

  it('⛔ permitted but UNMEASURABLE is NOT reported as unused', () => {
    const r = evaluateIntent(DENY_INTENT, [
      rule({ effectiveHitCount: null, logEvidence: 'no-coverage' }),
    ]);
    assert.equal(r.verdict, 'violation_unverified');
    assert.equal(r.did, null);
    assert.notEqual(r.verdict, 'violation_permitted');
  });

  it('nothing permits it -> blocked as intended', () => {
    const r = evaluateIntent(DENY_INTENT, [rule({ action: 'deny' })]);
    assert.equal(r.verdict, 'ok_blocked');
    assert.equal(r.can, false);
  });

  it('⛔ an any->any ALLOW rule is a violation, not a miss', () => {
    const r = evaluateIntent(DENY_INTENT, [
      rule({ src_zones: ['any'], dst_zones: ['any'], effectiveHitCount: 7 }),
    ]);
    assert.equal(r.verdict, 'violation_active');
  });

  it('a DISABLED permitting rule does not create a violation', () => {
    const r = evaluateIntent(DENY_INTENT, [rule({ enabled: false, effectiveHitCount: 99 })]);
    assert.equal(r.verdict, 'ok_blocked');
  });
});

describe('allow intent', () => {
  const allowRule = (over) => rule({ dst_zones: ['core'], ...over });

  it('permitted and used is fine', () => {
    const r = evaluateIntent(ALLOW_INTENT, [allowRule({ effectiveHitCount: 10 })]);
    assert.equal(r.verdict, 'ok_in_use');
  });

  it('⛔ permitted but never used is a REMOVAL CANDIDATE, not a pass', () => {
    const r = evaluateIntent(ALLOW_INTENT, [allowRule({ effectiveHitCount: 0 })]);
    assert.equal(r.verdict, 'unused_permission');
  });

  it('permitted but unmeasurable is neither', () => {
    const r = evaluateIntent(ALLOW_INTENT, [allowRule({ effectiveHitCount: null, logEvidence: 'no-coverage' })]);
    assert.equal(r.verdict, 'ok_unverified');
  });

  it('⛔ expected to work but nothing permits it is surfaced, not ignored', () => {
    // Either the intent is wrong or a rule is missing. Both need a human.
    const r = evaluateIntent(ALLOW_INTENT, [allowRule({ action: 'deny' })]);
    assert.equal(r.verdict, 'expected_allow_missing');
  });
});

describe('⛔ missing data never becomes a clean result', () => {
  it('no rules collected is UNKNOWN, not "blocked"', () => {
    // A fleet whose rulesets were never pulled would otherwise report every
    // deny-intent as satisfied — a perfect score generated from missing data.
    const r = evaluateIntent(DENY_INTENT, [], { rulesCollected: false });
    assert.equal(r.verdict, 'unknown');
    assert.equal(r.can, null);
    assert.ok(r.evidenceReasons.includes('no-rules-collected'));
  });

  it('an empty rule array is unknown even without the flag', () => {
    assert.equal(evaluateIntent(DENY_INTENT, []).verdict, 'unknown');
  });

  it('the summary counts what could not be measured, separately', () => {
    const results = [
      evaluateIntent(DENY_INTENT, [rule({ effectiveHitCount: 5 })], FULL_COVERAGE),   // active violation
      evaluateIntent(DENY_INTENT, [rule({ effectiveHitCount: null })], FULL_COVERAGE), // unverified
      evaluateIntent(ALLOW_INTENT, [rule({ dst_zones: ['core'], effectiveHitCount: 0 })], FULL_COVERAGE), // unused
      evaluateIntent(DENY_INTENT, [rule({ action: 'deny' })], FULL_COVERAGE),          // correctly blocked
      evaluateIntent(DENY_INTENT, [], { rulesCollected: false }),                      // unknown
    ];
    const s = summarise(results);
    assert.equal(s.total, 5);
    assert.equal(s.violations, 2);
    assert.equal(s.activeViolations, 1);
    assert.equal(s.unusedPermissions, 1);
    assert.equal(s.unknown, 1);
    assert.equal(s.ok, 1);
    assert.equal(s.expectedAllowMissing, 0);

    // ⛔ EXACT, NOT `>= 2`. The old assertion was `assert.ok(s.unmeasurable >= 2)`,
    // which cannot fail however badly the count OVER-counts — and over-counting
    // is the failure that actually shipped: `summarise` once counted every
    // correctly-blocked path as unmeasurable (because `ok_blocked` sets
    // `did: null`), so the page printed "3 of 3 paths could not be measured"
    // over three paths measured perfectly, and made an all-clear unreachable.
    // A lower bound on a count that only ever inflates is not a test.
    assert.equal(s.unmeasurable, 2, 'exactly the unverified and the unknown');
  });
});

describe('examples are capped', () => {
  it('an any->any rule does not return the whole rulebase', () => {
    const many = Array.from({ length: 50 }, (_, i) =>
      rule({ src_zones: ['any'], dst_zones: ['any'], rule_name: 'r' + i }));
    const r = evaluateIntent(DENY_INTENT, many);
    assert.equal(r.permittingRuleCount, 50);
    assert.ok(r.examples.length <= 5, 'examples must be capped for the UI');
  });
});

describe('the segmentation sentence may not claim more than was measured', () => {
  const { buildSegmentationAnswer } = require('../lib/answers');
  const base = { intents: [1], windowDays: 30, rulesWithoutHitData: 0 };

  it('⛔ an EMPTY matrix is unknown, never a pass', () => {
    // Nobody has said what should be segmented. That is the least informed
    // state possible, not a clean one.
    const a = buildSegmentationAnswer({ intents: [], summary: { total: 0 } });
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /No segmentation intent has been declared/);
  });

  it('leads with violations that are actually carrying traffic', () => {
    const a = buildSegmentationAnswer({
      ...base, summary: { total: 9, violations: 3, activeViolations: 1, unusedPermissions: 0, unmeasurable: 0 },
    });
    assert.equal(a.tone, 'critical');
    assert.match(a.sentence, /carrying traffic right now/);
  });

  it('distinguishes a standing hole from an active breach', () => {
    const a = buildSegmentationAnswer({
      ...base, summary: { total: 9, violations: 2, activeViolations: 0, unusedPermissions: 0, unmeasurable: 0 },
    });
    assert.equal(a.tone, 'critical');
    assert.match(a.sentence, /standing holes rather than active breaches/);
  });

  it('⛔ REFUSES an all-clear while any path was unmeasurable', () => {
    const a = buildSegmentationAnswer({
      ...base, rulesWithoutHitData: 232,
      summary: { total: 9, violations: 0, activeViolations: 0, unusedPermissions: 0, unmeasurable: 3 },
    });
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /not every path could be/);
    assert.match(a.coverage, /3 of 9/);
    assert.match(a.coverage, /232 rules cannot report usage/);
  });

  it('allows the all-clear only when everything was measurable', () => {
    const a = buildSegmentationAnswer({
      ...base, summary: { total: 9, violations: 0, activeViolations: 0, unusedPermissions: 0, unmeasurable: 0 },
    });
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
    assert.match(a.sentence, /every one was measurable/);
  });

  it('never throws on a missing or malformed result', () => {
    for (const bad of [null, undefined, {}, { intents: 'x' }]) {
      const a = buildSegmentationAnswer(bad);
      assert.equal(typeof a.sentence, 'string');
      assert.equal(a.tone, 'unknown');
    }
  });
});

describe('⛔ coverage is PER DEVICE — one collected firewall is not a collected fleet', () => {
  // The bug: `rulesCollected` was a single fleet-wide boolean set by
  // `rows.length === 0`. With 1 of 16 devices collected it stayed true, the
  // other 15 were simply absent from the rules array, and every deny-intent
  // whose permitting rule lives on one of them evaluated to `ok_blocked` —
  // "Blocked, as intended", severity ok — from 15 firewalls nobody had read.

  const PARTIAL = {
    rulesCollected: true,
    activeDeviceCount: 16,
    devicesWithRules: 1,
    devicesWithoutRules: Array.from({ length: 15 }, (_, i) => 'fw-' + i),
  };

  it('⛔ refuses "blocked as intended" while any device has no collected ruleset', () => {
    const r = evaluateIntent(DENY_INTENT, [rule({ action: 'deny' })], PARTIAL);
    assert.equal(r.verdict, 'unknown');
    assert.notEqual(r.verdict, 'ok_blocked');
    assert.equal(r.can, null, 'not false — we did not look everywhere');
    assert.equal(r.uncollectedDeviceCount, 15);
    assert.ok(r.evidenceReasons.includes('partial-rule-coverage'));
  });

  it('⛔ refuses "nothing permits it" for an ALLOW intent too', () => {
    // Same claim, opposite intent: `expected_allow_missing` sends someone to add
    // a rule that may already exist on a firewall we never read.
    const r = evaluateIntent(ALLOW_INTENT, [rule({ dst_zones: ['core'], action: 'deny' })], PARTIAL);
    assert.equal(r.verdict, 'unknown');
  });

  it('a POSITIVE finding still stands on partial coverage', () => {
    // One rule proves "something permits this". Incomplete collection cannot
    // make a violation we can SEE disappear — only a negative needs the whole
    // fleet, and suppressing a real violation would be the worse error.
    const r = evaluateIntent(DENY_INTENT, [rule({ effectiveHitCount: 9 })], PARTIAL);
    assert.equal(r.verdict, 'violation_active');
    assert.equal(r.can, true);
  });

  it('full coverage still produces the clean verdict', () => {
    const r = evaluateIntent(DENY_INTENT, [rule({ action: 'deny' })], FULL_COVERAGE);
    assert.equal(r.verdict, 'ok_blocked');
    assert.equal(r.uncollectedDeviceCount, 0);
  });

  it('counts the coverage gap in the summary, separately from other unknowns', () => {
    const s = summarise([
      evaluateIntent(DENY_INTENT, [rule({ action: 'deny' })], PARTIAL),
      evaluateIntent(DENY_INTENT, [rule({ effectiveHitCount: null })], FULL_COVERAGE),
    ]);
    assert.equal(s.unknown, 1);
    assert.equal(s.unmeasurable, 2);
    assert.equal(s.pairsBlockedByUncollectedDevices, 1);
  });
});

describe('⛔ an action verb we cannot read is not a rule we may ignore', () => {
  // `permitting` needs isAllowAction and `denying` needs isDenyAction, so a new
  // vendor verb, null or '' matched NEITHER and vanished. For a deny-intent that
  // produced can=false -> ok_blocked: a rule SecVault could not read, reported as
  // proof the path is CLOSED. A hole reported as closed is a false assurance.

  it('classifies the unreadable verbs', () => {
    for (const a of [null, undefined, '', 'pass', 'redirect', 'reset-both-ish']) {
      assert.equal(isUnrecognisedAction(a), true, String(a));
    }
    for (const a of ['allow', 'accept', 'permit', 'deny', 'drop', 'reject', 'block']) {
      assert.equal(isUnrecognisedAction(a), false, a);
    }
  });

  it('⛔ a pair matched only by unreadable verbs is NOT reported blocked', () => {
    const r = evaluateIntent(DENY_INTENT, [rule({ action: 'tunnel-inspect' })], FULL_COVERAGE);
    assert.equal(r.verdict, 'unknown');
    assert.notEqual(r.verdict, 'ok_blocked');
    assert.equal(r.can, null);
    assert.equal(r.unrecognisedActionRuleCount, 1);
    assert.ok(r.evidenceReasons.includes('unrecognised-action'));
  });

  it('a null action is treated the same as an unknown word', () => {
    // An adapter that could not parse an action returns null. That is a failed
    // read, and a failed read is never a measurement.
    const r = evaluateIntent(DENY_INTENT, [rule({ action: null })], FULL_COVERAGE);
    assert.equal(r.verdict, 'unknown');
  });

  it('⛔ THE OPPOSITE POLICY FROM logHit.js, deliberately', () => {
    // There an unrecognised verb never fires, because a false "allowed" would
    // MANUFACTURE a patch_now. Here an unrecognised verb that counted as nothing
    // MANUFACTURES an all-clear. Both refuse to let an unread value become the
    // reassuring answer; the reassuring answer is simply the other one.
    const { classifyAction } = require('../lib/engines/logHit');
    if (typeof classifyAction === 'function') {
      assert.equal(classifyAction('tunnel-inspect'), 'unknown');
    }
    assert.equal(
      evaluateIntent(DENY_INTENT, [rule({ action: 'tunnel-inspect' })], FULL_COVERAGE).verdict,
      'unknown'
    );
  });

  it('unreadable rules are surfaced as examples, since they ARE the finding', () => {
    const r = evaluateIntent(DENY_INTENT, [rule({ action: 'weird', rule_name: 'odd-1' })], FULL_COVERAGE);
    assert.equal(r.examples.length, 1);
    assert.equal(r.examples[0].ruleName, 'odd-1');
    assert.equal(r.examples[0].action, 'weird');
  });

  it('a readable allow beside an unreadable verb still decides the pair', () => {
    const r = evaluateIntent(DENY_INTENT, [
      rule({ action: 'weird' }),
      rule({ effectiveHitCount: 3 }),
    ], FULL_COVERAGE);
    assert.equal(r.verdict, 'violation_active');
    // Still reported: the operator should go and look at the verb we could not read.
    assert.equal(r.unrecognisedActionRuleCount, 1);
    assert.equal(summarise([r]).pairsWithUnrecognisedActions, 1);
  });
});

// ── the window ──────────────────────────────────────────────────────────────
//
// A stub pool: returns canned rows and RECORDS THE SQL IT WAS HANDED, which is
// what lets the window actually used be compared with the window reported.
function stubPool(opts) {
  const o = opts || {};
  const calls = [];
  return {
    calls,
    find: (re) => calls.find((c) => re.test(c.sql)),
    async query(sql, params) {
      calls.push({ sql, params });
      if (/FROM firewall_rules/.test(sql)) return { rows: o.rules || [] };
      if (/FROM devices\s+WHERE active/.test(sql)) return { rows: o.devices || [] };
      if (/segmentation_intents/.test(sql)) return { rows: o.intents || [] };
      if (/syslog_rollup_hourly/.test(sql)) return { rows: [] };
      if (/syslog_rule_hits_hourly/.test(sql)) return { rows: [] };
      throw new Error('unexpected SQL in test: ' + sql.slice(0, 80));
    },
  };
}

const dbRule = (over) => ({
  id: 'r1',
  device_id: 'd1',
  device_name: 'fw-1',
  rule_name: 'r1',
  rule_id_vendor: '1',
  sequence_number: 1,
  enabled: true,
  action: 'allow',
  src_zones: ['branch'],
  dst_zones: ['cardholder'],
  hit_count: 5,
  log_enabled: true,
  ...over,
});

describe('⛔ the reported window is the window that was MEASURED', () => {
  it('clamps to the evidence layer\'s own bounds', () => {
    assert.equal(resolveWindowDays(undefined), 30);
    assert.equal(resolveWindowDays('not-a-number'), 30);
    assert.equal(resolveWindowDays(-5), 7, 'floor, never a negative window');
    assert.equal(resolveWindowDays(0), 7);
    assert.equal(resolveWindowDays(3), 7, 'the floor ruleHitCorrelation enforces');
    assert.equal(resolveWindowDays(45), 45);
    assert.equal(resolveWindowDays(99999), 400);
  });

  it('refuses nonsense at the boundary rather than coercing it', () => {
    // `?days=-5` used to pass Number.isFinite, be reported as -5, and be measured
    // as 30. Telling the caller no is better than a plausible page built over a
    // window nobody asked for.
    assert.deepEqual(parseWindowDaysParam(null), { ok: true, days: undefined });
    assert.deepEqual(parseWindowDaysParam(''), { ok: true, days: undefined });
    assert.deepEqual(parseWindowDaysParam('45'), { ok: true, days: 45 });
    for (const bad of ['-5', '0', '1.5', '7abc', 'NaN', 'Infinity']) {
      assert.equal(parseWindowDaysParam(bad).ok, false, bad);
    }
  });

  it('⛔ pins resolveWindowDays against the window the evidence query ACTUALLY used', () => {
    // The two used to be resolved independently in two files and could disagree
    // silently. This asserts them equal through a real call: if
    // ruleHitCorrelation's clampDays bounds ever move, this fails rather than
    // the page quietly mislabelling its own measurement.
    const run = async (asked) => {
      const pool = stubPool({ rules: [dbRule()], devices: [{ id: 'd1', name: 'fw-1' }] });
      const fleet = await loadFleetRulesWithEvidence(pool, asked, new Date('2026-09-14T00:00:00Z'));
      const coverageCall = pool.find(/syslog_rollup_hourly/);
      assert.equal(
        coverageCall.params[1], fleet.windowDays * 24,
        `reported ${fleet.windowDays}d but measured ${coverageCall.params[1]}h for days=${asked}`
      );
      return fleet.windowDays;
    };
    return Promise.all([run(3), run(-5), run(45), run(undefined), run(99999)])
      .then(([a, b, c, d, e]) => {
        assert.deepEqual([a, b, c, d, e], [7, 7, 45, 30, 400]);
      });
  });

  it('evaluateSegmentation reports the measured window, not the request', async () => {
    const pool = stubPool({
      rules: [dbRule()],
      devices: [{ id: 'd1', name: 'fw-1' }],
      intents: [{
        id: 'i1', source_zone: 'branch', dest_zone: 'cardholder',
        expectation: 'deny', note: null, created_by: null,
        created_at: null, updated_at: null,
      }],
    });
    const out = await evaluateSegmentation(pool, { windowDays: 3, now: new Date() });
    assert.equal(out.windowDays, 7, 'the span the evidence covers');
    assert.equal(out.requestedWindowDays, 3, 'and the request, kept distinct');
  });
});

describe('⛔ fleet coverage is computed per device, in the data layer too', () => {
  it('names the active devices that contributed no rules', async () => {
    const pool = stubPool({
      rules: [dbRule({ device_id: 'd1' })],
      devices: [{ id: 'd1', name: 'fw-1' }, { id: 'd2', name: 'fw-2' }, { id: 'd3', name: 'fw-3' }],
    });
    const fleet = await loadFleetRulesWithEvidence(pool, 30, new Date());
    assert.equal(fleet.rulesCollected, true, 'the fleet-wide flag is still true — that is the bug');
    assert.equal(fleet.activeDeviceCount, 3);
    assert.equal(fleet.deviceCount, 1);
    assert.deepEqual(fleet.devicesWithoutRules, ['fw-2', 'fw-3']);
  });

  it('⛔ and an intent evaluated over that fleet is UNKNOWN, not "blocked"', async () => {
    const pool = stubPool({
      rules: [dbRule({ action: 'deny' })],
      devices: [{ id: 'd1', name: 'fw-1' }, { id: 'd2', name: 'fw-2' }],
      intents: [{
        id: 'i1', source_zone: 'branch', dest_zone: 'cardholder',
        expectation: 'deny', note: null, created_by: null,
        created_at: null, updated_at: null,
      }],
    });
    const out = await evaluateSegmentation(pool, { now: new Date() });
    assert.equal(out.intents[0].verdict, 'unknown');
    assert.equal(out.summary.pairsBlockedByUncollectedDevices, 1);
    assert.deepEqual(out.devicesWithoutRules, ['fw-2']);
  });

  it('an empty fleet still reports which devices are missing', async () => {
    const pool = stubPool({ rules: [], devices: [{ id: 'd1', name: 'fw-1' }] });
    const fleet = await loadFleetRulesWithEvidence(pool, 30, new Date());
    assert.equal(fleet.rulesCollected, false);
    assert.deepEqual(fleet.devicesWithoutRules, ['fw-1']);
    assert.equal(fleet.windowDays, 30, 'the window is reported even with nothing to measure');
  });

  it('counts enabled rules whose action verb could not be read', async () => {
    const pool = stubPool({
      rules: [dbRule(), dbRule({ id: 'r2', action: 'tunnel-inspect' }), dbRule({ id: 'r3', action: 'weird', enabled: false })],
      devices: [{ id: 'd1', name: 'fw-1' }],
    });
    const fleet = await loadFleetRulesWithEvidence(pool, 30, new Date());
    // Disabled rules are excluded: a rule that cannot act cannot open anything.
    assert.equal(fleet.rulesWithUnrecognisedAction, 1);
  });
});

describe('⛔ the SEAM between summarise() and the sentence, driven end to end', () => {
  // The earlier tests here handed buildSegmentationAnswer a hand-built summary
  // literal, so the two halves were each pinned and the joint between them was
  // not — which is exactly where the shipped bug lived: `summarise()` counted
  // every correctly-blocked path as unmeasurable, so the all-clear became
  // unreachable the moment a customer declared an intent their fleet enforces.
  // A literal `{ unmeasurable: 0 }` can never catch that. These feed real
  // evaluateIntent output through real summarise().
  const { buildSegmentationAnswer } = require('../lib/answers');

  const answerFor = (results) => buildSegmentationAnswer({
    intents: results,
    summary: summarise(results),
    windowDays: 30,
    rulesWithoutHitData: 0,
  });

  it('⛔ a fleet that ENFORCES every declared intent gets the all-clear', () => {
    const results = [
      evaluateIntent(DENY_INTENT, [rule({ action: 'deny' })], FULL_COVERAGE),
      evaluateIntent(DENY_INTENT, [rule({ action: 'drop' })], FULL_COVERAGE),
      evaluateIntent(ALLOW_INTENT, [rule({ dst_zones: ['core'], effectiveHitCount: 12 })], FULL_COVERAGE),
    ];
    const s = summarise(results);
    assert.equal(s.unmeasurable, 0, 'a correctly blocked path is not a measurement gap');
    assert.equal(s.ok, 3);
    const a = answerFor(results);
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
    assert.match(a.sentence, /every one was measurable/);
  });

  it('⛔ one unverifiable path removes the all-clear, through the real summary', () => {
    const results = [
      evaluateIntent(DENY_INTENT, [rule({ action: 'deny' })], FULL_COVERAGE),
      evaluateIntent(ALLOW_INTENT, [
        rule({ dst_zones: ['core'], effectiveHitCount: null, logEvidence: 'no-coverage' }),
      ], FULL_COVERAGE),
    ];
    assert.equal(summarise(results).unmeasurable, 1);
    const a = answerFor(results);
    assert.equal(a.tone, 'unknown');
    assert.match(a.coverage, /1 of 2/);
  });

  it('⛔ an uncollected firewall removes the all-clear too', () => {
    // The state that used to read as a perfect score: 1 of 2 devices collected,
    // every deny-intent "Blocked, as intended".
    const results = [
      evaluateIntent(DENY_INTENT, [rule({ action: 'deny' })], {
        rulesCollected: true, activeDeviceCount: 2, devicesWithRules: 1,
        devicesWithoutRules: ['fw-2'],
      }),
    ];
    const s = summarise(results);
    assert.equal(s.ok, 0);
    assert.equal(s.unmeasurable, 1);
    assert.equal(answerFor(results).tone, 'unknown');
  });

  it('summarise keeps the field names lib/answers.js reads', () => {
    // buildSegmentationAnswer consumes summary.unmeasurable and
    // summary.expectedAllowMissing by those exact names, from another file.
    const s = summarise([evaluateIntent(ALLOW_INTENT, [rule({ dst_zones: ['core'], action: 'deny' })], FULL_COVERAGE)]);
    assert.equal(s.expectedAllowMissing, 1);
    assert.equal(typeof s.unmeasurable, 'number');
  });
});

describe('⛔ "DID" may not be described as windowed — most counts are lifetime', () => {
  // effectiveHitCount prefers the DEVICE'S OWN cumulative counter over the
  // log-derived windowed count; live, 1,524 of 1,757 rules are device-sourced.
  // "no traffic in the last 30 days" is therefore false for ~87% of the rules
  // these sentences describe. The error direction is tolerable (a lifetime
  // counter overstates usage, so it overstates violations) but the prose may
  // not claim a measurement that was not taken.
  const { VERDICTS } = require('../lib/engines/segmentation');

  it('no verdict detail claims the traffic was seen "in the window"', () => {
    for (const [name, v] of Object.entries(VERDICTS)) {
      assert.ok(
        !/in the window/i.test(v.detail),
        `${name}: "${v.detail}" claims a windowed measurement the hit count does not support`
      );
    }
  });

  it('the board repeats the same wording, not a stronger one', () => {
    // Comments are stripped first: the house style is to explain the footgun at
    // length beside the code, and a comment quoting the banned phrase in order
    // to ban it must not fail the check that enforces it.
    const src = readSrc('components', 'segmentation', 'SegmentationBoard.js');
    const prose = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.ok(!/in the window/i.test(prose), 'SegmentationBoard.js must not claim a windowed count');
    assert.match(prose, /cumulative since/, 'the caveat must be stated to the operator');
  });
});

describe('⛔ the board reports its own failures instead of rendering nothing', () => {
  const src = readSrc('components', 'segmentation', 'SegmentationBoard.js');

  it('never returns null when it has no data', () => {
    // `if (!data) return null` sat ABOVE the JSX holding the error message, so
    // the one case the message existed for — a failed fetch — was the one case
    // it could not mount. A 500 rendered a header and then an empty page: no
    // matrix, no form, no reason, no retry.
    assert.ok(!/if \(!data\) return null;/.test(src), 'the empty/error state must render');
    assert.match(src, /Retry/, 'and must offer a way to try again');
  });

  it('checks res.ok on the DELETE', () => {
    // A 403 (an account without OPERATE) used to reload the board unchanged, so
    // Remove looked like a broken button rather than a permission boundary.
    const remove = src.slice(src.indexOf('async function remove'));
    assert.match(remove.slice(0, 900), /if \(!res\.ok\)/);
  });

  it('catches a network failure in the submit handler', () => {
    // try/finally with no catch made a dropped connection an unhandled rejection
    // and left the form sitting there: the declaration was never saved and
    // nothing said so.
    const add = src.slice(src.indexOf('async function addIntent'), src.indexOf('async function remove'));
    assert.match(add, /catch \(/);
    assert.match(add, /was not saved/);
  });

  it('⛔ passes no `style` prop to <Badge>, which silently drops it', () => {
    // Badge destructures {color, children, className, title} only.
    assert.ok(
      !/<Badge[^>]*\sstyle=/.test(src),
      'Badge ignores style — put spacing on a wrapper or className'
    );
  });
});

describe('⛔ the evaluation runs ONCE per page view', () => {
  const board = readSrc('components', 'segmentation', 'SegmentationBoard.js');
  const page = readSrc('app', '(dashboard)', 'segmentation', 'page.js');

  it('the page hands its result to the board', () => {
    // Both used to evaluate independently: ~19 queries and ~700ms each, ~1.4s
    // and ~40 queries per view for the same answer — and if a rule pull landed
    // between the two, the server-rendered headline and the matrix under it
    // disagreed with each other.
    assert.match(page, /initial=\{/);
    assert.match(page, /initialError=\{/);
    assert.match(board, /function SegmentationBoard\(\{ initial/);
  });

  it('the board does not refetch what it was handed', () => {
    const effect = board.slice(board.indexOf('useEffect(('), board.indexOf('async function addIntent'));
    assert.match(effect, /if \(!initial && !initialError\) load\(\)/);
  });

  it('but still reloads after a mutation', () => {
    // The one moment the data can genuinely have changed while it is on screen.
    assert.match(board, /await load\(\);/);
  });
});
