'use strict';
// Pins lib/engines/riskScore.js — the DEVICE risk score (0-100) and the
// per-RULE risk band.
//
// ⛔ POLARITY. This engine is 0-100 where HIGHER IS WORSE. Its sibling
// lib/engines/securityScore.js is 0-100 where HIGHER IS BETTER, and it
// CONSUMES this engine's output (the one inversion lives in
// securityScore.js's hygieneSubscore and nowhere else). Anyone "unifying"
// the two conventions gets a plausible number that says the fleet is
// healthiest exactly when it is worst — nothing throws. The directional
// tests below are here to break loudly first.
//
// THE INCIDENTS pinned here:
//
// 1. Medium saturation (2026-07-23). The original formula summed all four
//    weighted counts and clamped only the TOTAL. 7 of the 12 rule-finding
//    types are medium severity and `unused` accumulates on any long-lived
//    firewall (real fleet counts: 7-551), so `2 * medium` alone blew past
//    100 and 13 of 14 real devices scored an identical "Critical (100)".
//    Fixed by capping each tier's contribution INDEPENDENTLY before summing.
//
// 2. The same-day follow-up. The first cut used TIER_CAPS.critical = 40,
//    which is BELOW the high->critical band boundary (59) — so a device with
//    50 critical findings was permanently stuck in 'high'. Raised to 60.
//    Because the caps now sum to 110, the outer Math.min(MAX_SCORE, ...) is
//    load-bearing, not a defensive backstop.
//
// 3. The object-vs-number bug (v2.53.0). getDeviceRiskScores() in
//    lib/engines/fleetHeadline.js does `rows.map(r => computeRiskScoreFromCounts(r).score)`
//    and an earlier version omitted `.score`, mapping {score,band,raw} objects
//    where numbers were expected. Every element failed hygieneSubscore's
//    Number.isFinite check, so the entire 30%-weighted rule-hygiene component
//    silently dropped out of the fleet Security Score's denominator — while
//    the dashboard looked perfectly healthy about it.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  computeRiskScore,
  computeRiskScoreFromCounts,
  computeRuleRiskBand,
  SEVERITY_WEIGHTS,
  TIER_CAPS,
  MAX_SCORE,
} = require('../lib/engines/riskScore');

/** Severity counts as the analysis queries hand them over (all keys present). */
function counts(overrides) {
  return Object.assign({ critical: 0, high: 0, medium: 0, info: 0 }, overrides);
}

/** N findings of one severity, as rule_analysis_results rows. */
function findings(severity, n) {
  return Array.from({ length: n }, (_, i) => ({ id: `f-${i}`, severity }));
}

const scoreOf = (overrides) => computeRiskScoreFromCounts(counts(overrides)).score;
const bandOf = (overrides) => computeRiskScoreFromCounts(counts(overrides)).band;

describe('riskScore: ⛔ 0-100 where HIGHER IS WORSE (opposite of securityScore.js)', () => {
  it('scores a clean device 0 and the worst possible device 100', () => {
    // If this pair ever inverts, the whole convention has been flipped.
    assert.equal(scoreOf({}), 0, 'no findings is the BEST end of this scale');
    assert.equal(
      scoreOf({ critical: 500, high: 500, medium: 500 }),
      MAX_SCORE,
      'a ruleset drowning in findings is the WORST end of this scale'
    );
  });

  it('scores MORE findings of the same severity higher, never lower', () => {
    const ladder = [0, 1, 2, 3, 4, 5, 6].map((c) => scoreOf({ critical: c }));
    for (let i = 1; i < ladder.length; i += 1) {
      assert.ok(
        ladder[i] > ladder[i - 1],
        `${i} critical findings must score strictly worse than ${i - 1} ` +
          `(got ${ladder[i]} vs ${ladder[i - 1]})`
      );
    }
  });

  it('scores a SEVERER finding higher than a milder one', () => {
    // 1 critical (10) > 1 high (5) > 1 medium (2) > 1 info (0).
    assert.ok(scoreOf({ critical: 1 }) > scoreOf({ high: 1 }));
    assert.ok(scoreOf({ high: 1 }) > scoreOf({ medium: 1 }));
    assert.ok(scoreOf({ medium: 1 }) > scoreOf({ info: 1 }));
  });

  it('bands a worse score into a worse-sounding band', () => {
    assert.equal(bandOf({}), 'low');
    assert.equal(bandOf({ critical: 1 }), 'medium');
    assert.equal(bandOf({ critical: 3 }), 'high');
    assert.equal(bandOf({ critical: 6 }), 'critical');
  });
});

describe('riskScore: the RETURN SHAPE is an object, not a bare number', () => {
  it('returns exactly {score, band, raw} — the v2.53.0 fleetHeadline bug', () => {
    const result = computeRiskScoreFromCounts(counts({ critical: 2, high: 1 }));

    assert.notEqual(
      typeof result,
      'number',
      'callers must destructure `.score`; fleetHeadline once mapped these objects ' +
        'straight into securityScore.js, which silently dropped rule hygiene from ' +
        'the fleet score denominator'
    );
    assert.deepEqual(Object.keys(result).sort(), ['band', 'raw', 'score']);
    assert.equal(typeof result.score, 'number');
    assert.ok(Number.isFinite(result.score), 'securityScore.js filters on Number.isFinite');
    assert.equal(typeof result.band, 'string');
    assert.equal(typeof result.raw, 'number');
    assert.ok(Number.isFinite(result.raw));
  });

  it('computeRiskScore() over a findings array returns the same shape', () => {
    const result = computeRiskScore(findings('high', 2));
    assert.deepEqual(Object.keys(result).sort(), ['band', 'raw', 'score']);
    assert.equal(result.score, 10); // 2 high * 5
  });

  it('`raw` is the TRUE UNCAPPED sum, while `score` is capped and clamped', () => {
    // 100 critical: raw = 100*10 = 1000, score = min(100, min(1000,60)) = 60.
    const result = computeRiskScoreFromCounts(counts({ critical: 100 }));
    assert.equal(result.raw, 1000, 'raw is diagnostic and deliberately un-capped');
    assert.equal(result.score, 60);
  });
});

describe('riskScore: the documented constants', () => {
  it('weights severities 10/5/2/0', () => {
    assert.deepEqual(SEVERITY_WEIGHTS, { critical: 10, high: 5, medium: 2, info: 0 });
  });

  it('caps each tier at 60/30/20 with NO info cap', () => {
    // info's weight is already 0, so an info cap could never bind — it was
    // removed on 2026-07-23 precisely because its presence made "the caps sum
    // to MAX_SCORE" look intentional rather than coincidental.
    assert.deepEqual(TIER_CAPS, { critical: 60, high: 30, medium: 20 });
    assert.equal(
      Object.prototype.hasOwnProperty.call(TIER_CAPS, 'info'),
      false,
      'an info cap is dead code — do not reintroduce one'
    );
  });

  it('keeps TIER_CAPS.critical ABOVE the high band ceiling (the 40 regression)', () => {
    assert.ok(
      TIER_CAPS.critical > 59,
      'with critical capped at 40, a device with 50 critical findings could never ' +
        'leave the "high" band, no matter how many more it accumulated'
    );
  });

  it('caps sum ABOVE MAX_SCORE, so the outer clamp is load-bearing', () => {
    assert.equal(MAX_SCORE, 100);
    assert.ok(TIER_CAPS.critical + TIER_CAPS.high + TIER_CAPS.medium > MAX_SCORE); // 110
  });

  it('caps each tier INDEPENDENTLY before summing (the medium-saturation fix)', () => {
    // 551 medium findings was a REAL fleet count. Un-capped that is 1102,
    // which clamped the total to 100 and made a device with nothing but an
    // unused-rule backlog look identical to one with 40 critical findings.
    assert.equal(scoreOf({ medium: 551 }), 20, 'medium alone can never exceed TIER_CAPS.medium');
    assert.equal(bandOf({ medium: 551 }), 'medium', 'a pure medium backlog is NOT critical');
    assert.ok(
      scoreOf({ critical: 40 }) > scoreOf({ medium: 551 }),
      '40 critical findings must outrank any amount of medium clutter — the ' +
        'differentiation the 2026-07-23 fix restored'
    );
  });

  it('does not let one saturated tier hide another tier still climbing', () => {
    // medium is already capped at 20 in both, so the delta is purely the high tier.
    assert.equal(scoreOf({ medium: 551 }), 20);
    assert.equal(scoreOf({ medium: 551, high: 4 }), 40); // 20 + min(4*5, 30)
  });
});

describe('riskScore: band boundaries (exact cut points, both sides)', () => {
  it("'low' requires a score of EXACTLY 0 — one medium finding is never 'low'", () => {
    assert.equal(bandOf({}), 'low');
    assert.equal(scoreOf({ medium: 1 }), 2);
    assert.equal(bandOf({ medium: 1 }), 'medium', 'the strict 0 cut point is deliberate');
  });

  it('info-only findings still band `low` (weight 0)', () => {
    assert.equal(scoreOf({ info: 99 }), 0);
    assert.equal(bandOf({ info: 99 }), 'low');
  });

  it("24 is the last 'medium'; 25 is already 'high'", () => {
    // 24 = 2 critical (20) + 2 medium (4). 25 = 5 high (25).
    assert.equal(scoreOf({ critical: 2, medium: 2 }), 24);
    assert.equal(bandOf({ critical: 2, medium: 2 }), 'medium');
    assert.equal(scoreOf({ high: 5 }), 25);
    assert.equal(bandOf({ high: 5 }), 'high');
  });

  it("59 is the last 'high'; 60 is already 'critical'", () => {
    // 59 = 4 critical (40) + 1 high (5) + 7 medium (14). 60 = 6 critical.
    assert.equal(scoreOf({ critical: 4, high: 1, medium: 7 }), 59);
    assert.equal(bandOf({ critical: 4, high: 1, medium: 7 }), 'high');
    assert.equal(scoreOf({ critical: 6 }), 60);
    assert.equal(bandOf({ critical: 6 }), 'critical');
  });

  it('keeps the documented low-critical-count edge cases where they were', () => {
    // These are called out in riskScore.js's own comments; they are the
    // "did the retune move anything users notice" canaries.
    assert.equal(scoreOf({ critical: 1 }), 10);
    assert.equal(bandOf({ critical: 1 }), 'medium', 'ONE critical is medium, not high');
    assert.equal(bandOf({ critical: 2 }), 'medium'); // 20
    assert.equal(bandOf({ critical: 3 }), 'high'); // 30 — three is what escalates
  });
});

describe('riskScore: MAX_SCORE clamping', () => {
  it('clamps an absurd fleet-worst device to exactly MAX_SCORE, still finite', () => {
    // All three tiers saturated: 60 + 30 + 20 = 110 -> clamped to 100.
    const result = computeRiskScoreFromCounts(counts({ critical: 9999, high: 9999, medium: 9999 }));
    assert.equal(result.score, MAX_SCORE);
    assert.ok(Number.isFinite(result.score));
    assert.ok(result.score <= MAX_SCORE, 'the score must never exceed 100');
    assert.equal(result.band, 'critical');
  });

  it('reaches MAX_SCORE only with all three weighted tiers saturated', () => {
    // Nothing short of that gets there — no single tier can max the score.
    assert.equal(scoreOf({ critical: 9999 }), 60);
    assert.equal(scoreOf({ critical: 9999, high: 9999 }), 90);
    assert.equal(scoreOf({ critical: 9999, high: 9999, medium: 9999 }), 100);
  });
});

describe('riskScore: degenerate input never throws and lands at the CLEAN end', () => {
  // ⛔ CONTRACT NOTE: "nothing was measurable" is NOT this engine's job.
  // computeRiskScoreFromCounts({}) is genuinely 0 / 'low' — zero weighted
  // findings. The "this device has no analysis rows at all, so report
  // nothing rather than a confident number" decision lives in the CALLER:
  // lib/engines/deviceInventory.js does `analysed ? risk.score : null` and
  // passes [] (not [0]) to securityScore.js so hygiene drops out of the
  // denominator instead of scoring a fake perfect 100. Do not move that
  // null in here — a 0 from this function means "measured, and clean".
  it('treats a completely absent counts argument as a clean device', () => {
    assert.deepEqual(computeRiskScoreFromCounts(), { score: 0, band: 'low', raw: 0 });
  });

  it('treats an explicit NULL counts argument as a clean device, not a crash', () => {
    // A default parameter only fires on `undefined`. `null` is what a SQL
    // LEFT JOIN with no matching row hands you, and it used to throw
    // "Cannot read properties of null" -- inside a scheduled job that feeds
    // securityScore.js. Guarded 2026-08-25.
    assert.deepEqual(computeRiskScoreFromCounts(null), { score: 0, band: 'low', raw: 0 });
  });

  it('treats a non-object counts argument as a clean device, not a crash', () => {
    for (const junk of ['nope', 42, [], true]) {
      assert.deepEqual(
        computeRiskScoreFromCounts(junk),
        { score: 0, band: 'low', raw: 0 },
        `computeRiskScoreFromCounts(${JSON.stringify(junk)}) must not throw`
      );
    }
  });

  it('treats an empty counts object as a clean device', () => {
    assert.deepEqual(computeRiskScoreFromCounts({}), { score: 0, band: 'low', raw: 0 });
  });

  it('treats null / undefined / NaN / non-numeric count fields as 0, not NaN', () => {
    const result = computeRiskScoreFromCounts({
      critical: null,
      high: undefined,
      medium: NaN,
      info: 'not-a-number',
    });
    assert.deepEqual(result, { score: 0, band: 'low', raw: 0 });
    assert.ok(Number.isFinite(result.score), 'a NaN score would poison every consumer downstream');
  });

  it('accepts counts arriving as STRINGS (pg returns bigint/count as text)', () => {
    // The same class of bug as ruleAnalysis.test.js's string "0": a real
    // measured count must not be lost to a type mismatch.
    assert.equal(scoreOf({ critical: '3' }), 30);
    assert.equal(bandOf({ critical: '3' }), 'high');
  });

  it('computeRiskScore() survives a missing / non-array / junk findings list', () => {
    for (const input of [undefined, null, 'nope', 42, {}, []]) {
      assert.deepEqual(
        computeRiskScore(input),
        { score: 0, band: 'low', raw: 0 },
        `computeRiskScore(${JSON.stringify(input)}) must not throw`
      );
    }
  });

  it('computeRiskScore() ignores rows with an unknown or missing severity', () => {
    const mixed = [
      { severity: 'critical' },
      { severity: 'catastrophic' }, // not a real severity in this vocabulary
      { severity: null },
      {},
      null,
    ];
    assert.equal(computeRiskScore(mixed).score, 10, 'only the one real critical counts');
  });
});

describe('riskScore: per-RULE band is the WORST of that rule’s own findings', () => {
  it('takes the worst severity, not a sum, regardless of order', () => {
    assert.equal(computeRuleRiskBand([{ severity: 'medium' }, { severity: 'critical' }], true), 'critical');
    assert.equal(computeRuleRiskBand([{ severity: 'critical' }, { severity: 'medium' }], true), 'critical');
    assert.equal(computeRuleRiskBand([{ severity: 'medium' }, { severity: 'high' }], true), 'high');
  });

  it('does not escalate on COUNT — ten mediums on one rule is still medium', () => {
    // Unlike the device score, many findings on ONE rule do not add up: a
    // single rule is only as risky as its own worst finding.
    assert.equal(computeRuleRiskBand(findings('medium', 10), true), 'medium');
  });

  it("maps info findings to 'low'", () => {
    assert.equal(computeRuleRiskBand([{ severity: 'info' }], true), 'low');
  });

  it("bands an ENABLED rule with zero findings 'attention', never 'low'", () => {
    // 'attention' means "nothing wrong found, but nothing cleared it either" —
    // a 5th band, deliberately not the false confidence of 'low'.
    assert.equal(computeRuleRiskBand([], true), 'attention');
  });

  it("bands a DISABLED rule with zero findings 'low'", () => {
    // Phase 5 findings only key off enabled rules' live behaviour, so this
    // one really is unambiguously low risk.
    assert.equal(computeRuleRiskBand([], false), 'low');
  });

  it('falls back to the no-findings case when every finding is unrecognised', () => {
    const junk = [{ severity: 'catastrophic' }, { severity: null }, null];
    assert.equal(computeRuleRiskBand(junk, true), 'attention');
    assert.equal(computeRuleRiskBand(junk, false), 'low');
  });

  it('survives a missing / non-array findings list', () => {
    assert.equal(computeRuleRiskBand(undefined, true), 'attention');
    assert.equal(computeRuleRiskBand(null, false), 'low');
    assert.equal(computeRuleRiskBand('nope', true), 'attention');
  });
});
