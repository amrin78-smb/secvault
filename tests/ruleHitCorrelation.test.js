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

// ⛔ `sufficientHistory: true` on all three is deliberate: these fixtures are
// about what the DEVICE did, so SecVault's own history must be out of the
// picture. The case where OUR history is the limit has its own block below.
const GOOD_COVERAGE = { hoursWithEvents: 700, windowHours: 720, ratio: 0.97, covered: true, sufficientHistory: true, historyHours: 2000 };
const GAPPY_COVERAGE = { hoursWithEvents: 400, windowHours: 720, ratio: 0.56, covered: false, sufficientHistory: true, historyHours: 2000 };
const SHORT_COVERAGE = { hoursWithEvents: 6, windowHours: 720, ratio: 0.008, covered: false, sufficientHistory: true, historyHours: 2000 };

// ⛔ LOGS THAT DO IDENTIFY RULES — just not this one. An EMPTY pair of maps
// now means something different and much worse: the device's logs name no
// rule at all, so nothing on it can be certified. Fixtures asking 'what if
// this rule is absent?' must carry a neighbouring rule's hit or they exercise
// the wrong guard.
const OTHER_HIT = { hits: 5, firstHit: null, lastHit: null };
const LOGS_BY_ID = () => ({ byVendorId: new Map([['99', OTHER_HIT]]), byName: new Map(), rowsSeen: 1 });
const LOGS_BY_NAME = () => ({ byVendorId: new Map(), byName: new Map([['Other_Rule', OTHER_HIT]]), rowsSeen: 1 });
// ⛔ GENUINELY EMPTY — the device logs, but its logs name no rule at all.
// (A blind search/replace over the old empty-maps literal briefly rewrote
// THIS definition into LOGS_BY_ID(), so the no-rule-identity test silently
// asserted the opposite of its own name. The test caught it.)
// ⛔ rowsSeen: 1 is what makes this the FORMAT case rather than an idle one.
// The device DID produce a rule-hit row and it identified nothing. With
// rowsSeen: 0 this is simply a quiet firewall, which must stay answerable.
const LOGS_NAME_NOTHING = () => ({ byVendorId: new Map(), byName: new Map(), rowsSeen: 1 });
const LOGS_NO_ROWS = () => ({ byVendorId: new Map(), byName: new Map(), rowsSeen: 0 });

function rule(over) {
  return Object.assign(
    { id: 'r1', rule_name: 'Allow_Web', rule_id_vendor: '21', hit_count: null, log_enabled: true },
    over
  );
}

describe('⛔ a logged zero is only a measurement when it can be one', () => {
  it('is a MEASURED ZERO when the device was logging and the rule logs', () => {
    const [r] = enrichRulesWithLogEvidence([rule()], GOOD_COVERAGE, LOGS_BY_ID());
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
      [rule({ log_enabled: false })], GOOD_COVERAGE, LOGS_BY_ID()
    );
    assert.equal(r.logEvidence, 'rule-logging-disabled');
    assert.equal(r.loggedHits, null, 'must stay null, never 0');
    assert.equal(r.effectiveHitCount, null);
    assert.equal(r.hitCountSource, null);
  });

  it('⛔ is NOT a measurement when the device had logging GAPS', () => {
    // Zero logged hits then measures the collector, not the rule.
    const [r] = enrichRulesWithLogEvidence([rule()], GAPPY_COVERAGE, LOGS_BY_ID());
    assert.equal(r.logEvidence, 'no-coverage');
    assert.equal(r.loggedHits, null);
    assert.equal(r.effectiveHitCount, null);
  });

  it('⛔ is NOT a measurement when the window is too SHORT', () => {
    // A rule idle for six hours is not unused.
    const [r] = enrichRulesWithLogEvidence([rule()], SHORT_COVERAGE, LOGS_BY_ID());
    assert.equal(r.logEvidence, 'window-too-short');
    assert.equal(r.loggedHits, null);
  });

  it('⛔ is NOT a measurement when there is no coverage record at all', () => {
    const [r] = enrichRulesWithLogEvidence([rule()], null, LOGS_BY_ID());
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
      [rule({ hit_count: 0 })], GOOD_COVERAGE, LOGS_BY_ID()
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
  // ⛔ TWO QUERIES NOW: the history probe, then the per-device rollup. A stub
  // that returned the same rows for both made the new history guard look broken
  // rather than new -- `first_bucket` came back undefined, history read as
  // unknown, and unknown correctly certifies nothing.
  // ⛔ ONE query, and the device row carries `first_bucket` — how far back the
  // whole rollup goes. Omit it and history reads as unknown, which correctly
  // certifies nothing.
  function coveragePool(hoursWithEvents, firstBucket) {
    return {
      query: async () => ({
        rows: [{
          device_id: 'dev-1',
          hours_with_events: hoursWithEvents,
          first_bucket: firstBucket === undefined
            // 60 days back, relative to now, so the fixture does not rot.
            ? new Date(Date.now() - 60 * 24 * 3600 * 1000)
            : firstBucket,
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
    // (an empty history probe also yields rows: [] -- history unknown, which denies)
    assert.equal(m.get('dev-1'), undefined);
    // And an undefined coverage must never enrich into a measured zero.
    const [r] = enrichRulesWithLogEvidence([rule()], m.get('dev-1') || null, LOGS_BY_ID());
    assert.equal(r.loggedHits, null);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// A3 — log-derived rule usage carries a GRADE (2026-09-25)
//
// ⛔ Measured on the live fleet, and the split is total:
//     Fortinet    61,835 rollup rows, a rule_id on EVERY one
//     Palo Alto   80,203 rollup rows, rule_id NULL on EVERY one — names only
//   84 of 235 unmeasured rules gain a log answer: 54 by ID, 30 by NAME.
//
// An ID is exact. A NAME is neither unique nor stable across a config change,
// so a rule RENAMED during the window reads as having had no traffic while it
// is passing some — and the act that answer can authorise is DELETING IT FROM
// A FIREWALL.

describe('⛔ A3 — an ID match and a NAME match are not the same evidence', () => {
  const hit = { hits: 4242, firstHit: null, lastHit: new Date('2026-09-20T00:00:00Z') };

  it('a vendor-ID match grades log-id and MAY authorise a deletion', () => {
    const [r] = enrichRulesWithLogEvidence(
      [rule()], GOOD_COVERAGE,
      { byVendorId: new Map([['21', hit]]), byName: new Map() }
    );
    assert.equal(r.logEvidence, 'hits');
    assert.equal(r.usageGrade, 'log-id');
    assert.equal(r.deletionEvidence, true);
    assert.equal(r.loggedHits, 4242);
  });

  it('a NAME-only match grades log-name and may NOT authorise a deletion', () => {
    const [r] = enrichRulesWithLogEvidence(
      [rule({ rule_id_vendor: null })], GOOD_COVERAGE,
      { byVendorId: new Map(), byName: new Map([['Allow_Web', hit]]) }
    );
    assert.equal(r.logEvidence, 'hits', 'the value must NOT have been renamed');
    assert.equal(r.usageGrade, 'log-name');
    assert.equal(r.deletionEvidence, false);
  });

  it('the device own counter outranks both', () => {
    const [r] = enrichRulesWithLogEvidence(
      [rule({ hit_count: 17 })], GOOD_COVERAGE,
      { byVendorId: new Map([['21', hit]]), byName: new Map() }
    );
    assert.equal(r.usageGrade, 'device');
    assert.equal(r.deletionEvidence, true);
    assert.equal(r.effectiveHitCount, 17, 'the device wins over the log count');
  });

  // ⛔ THE DANGEROUS DIRECTION. A match saying "in use" only ever REFUSES a
  // deletion, so a wrong one is safe. An ABSENCE saying "unused" is what
  // removes a rule from a firewall, and it is only as strong as the identity
  // we could have searched by.
  it('a measured zero on ID-carrying logs grades log-id', () => {
    const [r] = enrichRulesWithLogEvidence([rule()], GOOD_COVERAGE, LOGS_BY_ID());
    assert.equal(r.logEvidence, 'measured-zero');
    assert.equal(r.usageGrade, 'log-id');
    assert.equal(r.deletionEvidence, true);
  });

  it('⛔ a measured zero on NAME-only logs grades log-name, never log-id', () => {
    const [r] = enrichRulesWithLogEvidence([rule()], GOOD_COVERAGE, LOGS_BY_NAME());
    assert.equal(r.logEvidence, 'measured-zero');
    assert.equal(r.usageGrade, 'log-name');
    assert.equal(r.deletionEvidence, false,
      'a renamed rule reads as unused here — this may never delete a rule');
  });

  it('⛔ a rule with NO vendor id cannot be ID-certified even on ID-carrying logs', () => {
    // The logs could name it by id; this rule has no id to be looked up under,
    // so its absence was only ever searched for by name.
    const [r] = enrichRulesWithLogEvidence(
      [rule({ rule_id_vendor: null })], GOOD_COVERAGE, LOGS_BY_ID()
    );
    assert.equal(r.usageGrade, 'log-name');
    assert.equal(r.deletionEvidence, false);
  });

  it('an empty-string vendor id is not an id', () => {
    const [r] = enrichRulesWithLogEvidence(
      [rule({ rule_id_vendor: '' })], GOOD_COVERAGE, LOGS_BY_ID()
    );
    assert.equal(r.usageGrade, 'log-name');
  });

  it('an unmeasurable rule grades null and never claims deletion evidence', () => {
    for (const cov of [GAPPY_COVERAGE, SHORT_COVERAGE, null]) {
      const [r] = enrichRulesWithLogEvidence([rule()], cov, LOGS_BY_ID());
      assert.equal(r.usageGrade, null);
      assert.equal(r.deletionEvidence, false);
      assert.equal(r.effectiveHitCount, null);
    }
  });
});

describe('⛔ A3 — logs that name NO rule condemn nothing', () => {
  it('a device whose logs carry neither id nor name yields no-rule-identity', () => {
    // Reachable live: PAKFood single rollup row carries neither. Without this
    // guard every rule on such a device is "absent" and, with good coverage,
    // certifies as a measured zero — a whole ruleset condemned by a logging
    // FORMAT rather than by any observation.
    const [r] = enrichRulesWithLogEvidence([rule()], GOOD_COVERAGE, LOGS_NAME_NOTHING());
    assert.equal(r.logEvidence, 'no-rule-identity');
    assert.equal(r.loggedHits, null, 'must stay null, never 0');
    assert.equal(r.effectiveHitCount, null);
    assert.equal(r.usageGrade, null);
    assert.equal(r.deletionEvidence, false);
  });

  it('but a rule with logging disabled still reports THAT, which is more specific', () => {
    const [r] = enrichRulesWithLogEvidence(
      [rule({ log_enabled: false })], GOOD_COVERAGE, LOGS_NAME_NOTHING()
    );
    assert.equal(r.logEvidence, 'rule-logging-disabled');
  });
});

describe('⛔ A3 — too little HISTORY is OUR limitation, not the firewall', () => {
  // Measured 2026-09-25: the rollup began 2026-09-08 (the day the collector
  // shipped), so only 412 of a 30-day window 720 hours COULD hold data. Every
  // device scored ratio 0.572 and failed — while logging 100% of every hour it
  // was possible to log. The gate was reporting SecVault install date as a
  // fact about the firewall.
  const YOUNG = {
    hoursWithEvents: 412, windowHours: 720, ratio: 0.572,
    covered: false, sufficientHistory: false, historyHours: 412,
  };

  function coverageStub(hoursWithEvents, firstBucket) {
    return {
      query: async () => ({ rows: [{ device_id: 'dev-1', hours_with_events: hoursWithEvents,
        first_bucket: firstBucket, first_seen: null, last_seen: null, events: '1000000' }] }),
    };
  }

  it('reports insufficient-history, NOT no-coverage', () => {
    const [r] = enrichRulesWithLogEvidence([rule()], YOUNG, LOGS_BY_ID());
    assert.equal(r.logEvidence, 'insufficient-history',
      'blaming the device for our own install date is the wrong attribution');
    assert.equal(r.loggedHits, null);
    assert.equal(r.usageGrade, null);
  });

  it('⛔ insufficient history is tested BEFORE the ratio', () => {
    // A young rollup ALSO produces a low ratio, so a ratio-first order reports
    // `no-coverage` and the real cause never surfaces. Order is load-bearing.
    const [r] = enrichRulesWithLogEvidence([rule()], YOUNG, LOGS_BY_ID());
    assert.notEqual(r.logEvidence, 'no-coverage');
  });

  it('a device that genuinely gapped still reports no-coverage', () => {
    const [r] = enrichRulesWithLogEvidence([rule()], GAPPY_COVERAGE, LOGS_BY_ID());
    assert.equal(r.logEvidence, 'no-coverage', 'this one IS the device');
  });

  it('⛔ history shorter than the window can never certify a zero', async () => {
    // 10 days of rollup, 30-day window asked for.
    const young = coverageStub(700, new Date(Date.now() - 10 * 24 * 3600 * 1000));
    const m = await getDeviceLogCoverage(young, 30, new Date());
    const c = m.get('dev-1');
    assert.equal(c.sufficientHistory, false);
    assert.equal(c.covered, false, 'ratio alone must not be able to certify');
  });

  it('⛔ an UNREADABLE history is unknown, which denies — never "plenty"', async () => {
    // A row set that cannot say when collection began. Reachable from an older
    // deployed query shape, and the safe reading is "we do not know".
    const c = (await getDeviceLogCoverage(coverageStub(700, undefined), 30, new Date())).get('dev-1');
    assert.equal(c.historyHours, null, 'null, never 0 and never a large number');
    assert.equal(c.sufficientHistory, false);
    assert.equal(c.covered, false);
  });

  it('⛔ no rule-hit ROWS is a quiet firewall, not an unidentifiable one', () => {
    // The distinction that keeps the format guard from swallowing every idle
    // ruleset: rowsSeen 0 means nothing matched, rowsSeen>0 with empty maps
    // means the logs named nothing.
    const [r] = enrichRulesWithLogEvidence([rule()], GOOD_COVERAGE, LOGS_NO_ROWS());
    assert.equal(r.logEvidence, 'measured-zero');
    // ...and it still cannot authorise a deletion, because nothing proved the
    // logs carry ids.
    assert.equal(r.usageGrade, 'log-name');
    assert.equal(r.deletionEvidence, false);
  });

  it('with enough history a densely-logging device still qualifies', async () => {
    const old = coverageStub(700, new Date(Date.now() - 200 * 24 * 3600 * 1000));
    const c = (await getDeviceLogCoverage(old, 30, new Date())).get('dev-1');
    assert.equal(c.sufficientHistory, true);
    assert.equal(c.covered, true, 'the guard must not be a blanket refusal');
  });
});

describe('⛔ A3 — the deletion bar cannot drift open', () => {
  it('ruleChangeRequests gates on the DEVICE hit_count, and says why', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'lib', 'engines', 'ruleChangeRequests.js'), 'utf8');
    // ⛔ Comments stripped FIRST. This repo has repeatedly had a source scan
    // satisfied by the comment explaining the very thing it was hunting.
    const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

    assert.match(code, /r\.hit_count === null \|\| r\.hit_count === undefined/,
      'the withheld test must still be the device-reported counter');
    // If log evidence is ever accepted here it must be the graded field, never
    // the raw effectiveHitCount — which silently includes name-grade answers.
    assert.ok(!/effectiveHitCount/.test(code),
      'effectiveHitCount includes NAME-grade evidence; accepting it here would '
      + 'let a renamed rule be deleted. Use deletionEvidence.');
  });
});
