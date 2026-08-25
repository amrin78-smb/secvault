'use strict';
// Pins the fleet/per-device Security Score (v2.53.0, lib/engines/securityScore.js).
//
// THE INCIDENT CLASS THIS GUARDS AGAINST: this engine consumes riskScore.js,
// which is 0-100 where HIGHER IS WORSE, and republishes it as 0-100 where
// HIGHER IS BETTER. The inversion happens in exactly ONE line
// (`100 - meanRisk`, in hygieneSubscore). Flip it, or "simplify" it away, and
// nothing throws, nothing fails a build, and the dashboard renders a
// perfectly plausible number that says the fleet is healthiest exactly when it
// is worst. There is no crash to notice and no log line to grep. The only
// thing that can catch it is a test that asserts the DIRECTION.
//
// The second silent failure is the family the tests/README calls out: "a
// failed read recorded as an affirmative value". Here that would be scoring an
// unmeasurable component as 0 instead of dropping it from the denominator — a
// brand-new install with no analysis run yet would report a DATA GAP as a
// security problem (100 -> 70), and the operator would go hunting for a
// vulnerability that does not exist.
//
// Third: the 40/30/30 weights and SCHEDULED_EXPOSURE_FACTOR are documented in
// CLAUDE.md, which requires any change to be written there BEFORE the code
// changes. That rule is only enforceable if a test breaks when the numbers
// move, so they are pinned both as constants and functionally (via a score
// that could only come out that way with those weights).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  computeSecurityScore,
  securityScoreBand,
  vulnerabilitySubscore,
  hygieneSubscore,
  complianceSubscore,
  WEIGHTS,
  SCHEDULED_EXPOSURE_FACTOR,
} = require('../lib/engines/securityScore');

/**
 * A fleet whose three components are all individually perfect, so any single
 * override isolates exactly one component's contribution to the final score.
 *   vulnerability: 10 active devices, none exposed  -> 100
 *   hygiene:       one device at riskScore 0        -> 100
 *   compliance:    100%                             -> 100
 */
function fleetWith(overrides) {
  return Object.assign(
    {
      activeDevices: 10,
      devicesWithPatchNow: 0,
      devicesWithScheduled: 0,
      deviceRiskScores: [0],
      fleetCompliancePct: 100,
    },
    overrides
  );
}

const scoreOf = (overrides) => computeSecurityScore(fleetWith(overrides)).score;
const componentNamed = (result, key) => result.components.find((c) => c.key === key);

describe('securityScore: THE polarity inversion (riskScore is higher-is-WORSE)', () => {
  it('scores a fleet of high-risk rulesets LOW and a fleet of low-risk rulesets HIGH', () => {
    // Everything but hygiene is held perfect, so the only moving part is the
    // inversion. Bad fleet mean risk 95 -> hygiene 5; good fleet mean risk 5
    // -> hygiene 95. (100*40 + 5*30 + 100*40... ) worked out below.
    const bad = scoreOf({ deviceRiskScores: [95, 90, 100] });
    const good = scoreOf({ deviceRiskScores: [5, 0, 10] });

    assert.ok(
      good > bad,
      `A fleet of CLEAN rulesets must score higher than a fleet of terrible ones. ` +
        `Got good=${good}, bad=${good === bad ? bad : bad} — if these are inverted, the ` +
        `100 - meanRisk in hygieneSubscore has been flipped.`
    );
    // bad:  mean risk 95 -> hygiene 5.  (100*40 + 5*30 + 100*30)/100 = 71.5 -> 72
    assert.equal(bad, 72);
    // good: mean risk 5  -> hygiene 95. (100*40 + 95*30 + 100*30)/100 = 98.5 -> 99
    assert.equal(good, 99);
  });

  it('converts a riskScore of 0 to hygiene 100 and a riskScore of 100 to hygiene 0', () => {
    assert.equal(hygieneSubscore([0]), 100, 'risk 0 = clean ruleset = best possible hygiene');
    assert.equal(hygieneSubscore([100]), 0, 'risk 100 = saturated = worst possible hygiene');
    assert.equal(hygieneSubscore([30]), 70, 'the inversion is 100 - risk, not any other mapping');
  });

  it('hygiene falls monotonically as device risk rises', () => {
    const scores = [0, 25, 50, 75, 100].map((risk) => hygieneSubscore([risk]));
    for (let i = 1; i < scores.length; i += 1) {
      assert.ok(
        scores[i] < scores[i - 1],
        `hygiene must strictly decrease as risk increases; got ${JSON.stringify(scores)}`
      );
    }
  });

  it('leaves the OTHER two components uninverted — the flip belongs to hygiene alone', () => {
    // Compliance is already higher-is-better and is used as-is. If someone
    // "consistently" inverted all three, this is what would catch it.
    assert.equal(complianceSubscore(80), 80, 'compliance is already higher-is-better: 80 stays 80');
    assert.equal(complianceSubscore(20), 20);
    // Vulnerability is expressed as exposure, and 100 means NO exposure.
    assert.equal(
      vulnerabilitySubscore({ activeDevices: 10, devicesWithPatchNow: 0, devicesWithScheduled: 0 }),
      100,
      'no exposed devices is the BEST vulnerability posture, so 100'
    );
    assert.equal(
      vulnerabilitySubscore({ activeDevices: 10, devicesWithPatchNow: 10, devicesWithScheduled: 0 }),
      0,
      'every device carrying a patch_now is the WORST vulnerability posture, so 0'
    );
  });
});

describe('securityScore: unmeasurable is null and is DROPPED from the denominator', () => {
  it('reports a never-analysed fleet as null hygiene, not 0', () => {
    assert.equal(hygieneSubscore([]), null, '"no analysis has run" is not "every ruleset is terrible"');
    assert.equal(hygieneSubscore(undefined), null);
    assert.equal(hygieneSubscore(null), null);
    assert.equal(hygieneSubscore([null, undefined, NaN]), null);
  });

  it('reports a fleet with no active devices as null vulnerability, not 0', () => {
    for (const activeDevices of [0, null, undefined, NaN, -1]) {
      assert.equal(
        vulnerabilitySubscore({ activeDevices, devicesWithPatchNow: 0, devicesWithScheduled: 0 }),
        null,
        `activeDevices=${String(activeDevices)} means nothing to measure, not a perfect or a zero score`
      );
    }
  });

  it('reports an unmeasurable compliance percentage as null, but a real 0% as 0', () => {
    assert.equal(complianceSubscore(null), null);
    assert.equal(complianceSubscore(undefined), null);
    assert.equal(
      complianceSubscore(0),
      0,
      'a genuinely measured 0% is a fact, and must NOT be collapsed into "unmeasurable"'
    );
  });

  it('drops an unanalysed device from the hygiene mean instead of scoring it 0 risk', () => {
    // A device absent from rule_analysis_results is unknown, not clean. If it
    // were coerced to risk 0 the mean below would be 50 (hygiene 50); if
    // coerced to risk 100 it would be 0. It must simply not participate.
    assert.equal(hygieneSubscore([null, 100]), 0);
    assert.equal(hygieneSubscore([null, 0]), 100);
    assert.equal(hygieneSubscore([NaN, 50]), 50);
  });

  it('still scores an all-perfect fleet 100 when ONE component cannot be measured', () => {
    // THE REGRESSION: treating the missing component as 0 gives 70, and a
    // fresh install looks like a security problem instead of a data gap.
    assert.equal(scoreOf({ deviceRiskScores: [] }), 100, 'hygiene missing: (100*40 + 100*30)/70 = 100');
    assert.equal(scoreOf({ fleetCompliancePct: null }), 100, 'compliance missing: (100*40 + 100*30)/70 = 100');
    assert.equal(scoreOf({ activeDevices: 0 }), 100, 'vulnerability missing: (100*30 + 100*30)/60 = 100');
  });

  it('still scores an all-perfect fleet 100 when TWO components cannot be measured', () => {
    assert.equal(scoreOf({ deviceRiskScores: [], fleetCompliancePct: null }), 100);
    assert.equal(scoreOf({ activeDevices: 0, deviceRiskScores: [] }), 100);
  });

  it('reweights the survivors rather than diluting them with a phantom zero', () => {
    // vulnerability 100 (weight 40) + compliance 50 (weight 30), hygiene absent.
    // (100*40 + 50*30) / 70 = 5500/70 = 78.57 -> 79.
    // Scoring the missing hygiene as 0 would instead give 5500/100 = 55.
    const result = computeSecurityScore(
      fleetWith({ deviceRiskScores: null, fleetCompliancePct: 50 })
    );
    assert.equal(result.score, 79);
    assert.equal(result.measuredWeight, 70, 'the missing component leaves the denominator entirely');
  });

  it('returns a null score, not 0, when nothing at all is measurable', () => {
    const result = computeSecurityScore({
      activeDevices: 0,
      devicesWithPatchNow: 0,
      devicesWithScheduled: 0,
      deviceRiskScores: [],
      fleetCompliancePct: null,
    });
    assert.equal(result.score, null, 'rendered "—" on the dashboard; 0 would read as "catastrophic"');
    assert.notEqual(result.score, 0);
    assert.equal(result.measuredWeight, 0);
    for (const c of result.components) {
      assert.equal(c.score, null, `component ${c.key} must be null, never 0, when unmeasurable`);
    }
  });

  it('always returns all three components so the UI can show WHY, even the missing ones', () => {
    const result = computeSecurityScore(fleetWith({ deviceRiskScores: [] }));
    assert.deepEqual(
      result.components.map((c) => c.key),
      ['vulnerability', 'hygiene', 'compliance'],
      'stable key set and order — the dashboard breakdown renders straight off this array'
    );
    assert.equal(componentNamed(result, 'hygiene').score, null);
    assert.equal(componentNamed(result, 'vulnerability').score, 100);
  });
});

describe('securityScore: the documented weights (CLAUDE.md must change BEFORE the code)', () => {
  it('weights vulnerability 40, hygiene 30, compliance 30', () => {
    assert.deepEqual(WEIGHTS, { vulnerability: 40, hygiene: 30, compliance: 30 });
    assert.equal(
      WEIGHTS.vulnerability + WEIGHTS.hygiene + WEIGHTS.compliance,
      100,
      'the weights must sum to 100 or a fully-measured fleet cannot reach 100'
    );
  });

  it('exposes those same weights on each component', () => {
    const result = computeSecurityScore(fleetWith({}));
    assert.equal(componentNamed(result, 'vulnerability').weight, 40);
    assert.equal(componentNamed(result, 'hygiene').weight, 30);
    assert.equal(componentNamed(result, 'compliance').weight, 30);
    assert.equal(result.measuredWeight, 100, 'all three measurable = full denominator');
  });

  it('loses exactly the documented number of points when one component bottoms out', () => {
    // These are the weights observed through the arithmetic, so they fail even
    // if WEIGHTS and the composition were retuned "consistently" together.
    assert.equal(scoreOf({ activeDevices: 10, devicesWithPatchNow: 10 }), 60, 'vulnerability 0 costs 40');
    assert.equal(scoreOf({ deviceRiskScores: [100] }), 70, 'hygiene 0 costs 30');
    assert.equal(scoreOf({ fleetCompliancePct: 0 }), 70, 'compliance 0 costs 30');
  });

  it('treats a scheduled-band device as exactly 0.4 of a patch_now device', () => {
    assert.equal(SCHEDULED_EXPOSURE_FACTOR, 0.4);
    // 10 devices, one exposed device each way:
    //   patch_now: exposure 1/10   -> 100 * (1 - 0.10) = 90  (10 points lost)
    //   scheduled: exposure 0.4/10 -> 100 * (1 - 0.04) = 96  ( 4 points lost)
    const patchNow = vulnerabilitySubscore({
      activeDevices: 10,
      devicesWithPatchNow: 1,
      devicesWithScheduled: 0,
    });
    const scheduled = vulnerabilitySubscore({
      activeDevices: 10,
      devicesWithPatchNow: 0,
      devicesWithScheduled: 1,
    });
    assert.equal(patchNow, 90);
    assert.equal(scheduled, 96);
    assert.equal(100 - scheduled, (100 - patchNow) * SCHEDULED_EXPOSURE_FACTOR);
  });

  it('does not penalise a monitor-band device at all', () => {
    // 'monitor' is deliberately absent from the input shape: the only two
    // exposure inputs are patch_now and scheduled. A fleet whose every CVE is
    // monitor-band therefore scores a perfect 100, by design.
    assert.equal(
      vulnerabilitySubscore({ activeDevices: 5, devicesWithPatchNow: 0, devicesWithScheduled: 0 }),
      100,
      'counting monitor-band CVEs would make a healthy fleet look permanently mediocre'
    );
  });
});

describe('securityScore: band boundaries', () => {
  it('names each band at its exact threshold', () => {
    assert.equal(securityScoreBand(90), 'excellent');
    assert.equal(securityScoreBand(75), 'good');
    assert.equal(securityScoreBand(50), 'fair');
    assert.equal(securityScoreBand(49), 'poor');
  });

  it('drops to the next band one point below each threshold', () => {
    assert.equal(securityScoreBand(89), 'good', 'off-by-one here is the classic silent regression');
    assert.equal(securityScoreBand(74), 'fair');
    assert.equal(securityScoreBand(50 - 1), 'poor');
  });

  it('covers the extremes', () => {
    assert.equal(securityScoreBand(100), 'excellent');
    assert.equal(securityScoreBand(0), 'poor');
  });

  it('returns null for an unmeasurable score rather than banding it "poor"', () => {
    assert.equal(securityScoreBand(null), null, 'a data gap must not be labelled a bad posture');
    assert.equal(securityScoreBand(undefined), null);
  });
});

describe('securityScore: clamping and degenerate input', () => {
  it('never returns a negative score, however over-exposed the fleet is', () => {
    // 5 patch_now devices across an activeDevices of 2 (a stale/miscounted
    // join) gives exposure 2.5 and a raw -150 before clamping.
    assert.equal(
      vulnerabilitySubscore({ activeDevices: 2, devicesWithPatchNow: 5, devicesWithScheduled: 0 }),
      0
    );
    assert.equal(hygieneSubscore([150]), 0);
    assert.equal(complianceSubscore(-5), 0);
  });

  it('never returns a score above 100', () => {
    assert.equal(hygieneSubscore([-20]), 100);
    assert.equal(complianceSubscore(150), 100);
    assert.equal(
      vulnerabilitySubscore({ activeDevices: 10, devicesWithPatchNow: -3, devicesWithScheduled: -3 }),
      100,
      'negative exposure counts are floored at 0, not credited as bonus points'
    );
  });

  it('keeps the composed score an integer inside 0-100 across a sweep of inputs', () => {
    const risks = [[], [0], [37], [100], [12, 88], null];
    for (const activeDevices of [0, 1, 7, 250]) {
      for (const deviceRiskScores of risks) {
        for (const fleetCompliancePct of [null, 0, 33.3, 100]) {
          const { score } = computeSecurityScore({
            activeDevices,
            devicesWithPatchNow: Math.min(activeDevices, 3),
            devicesWithScheduled: 1,
            deviceRiskScores,
            fleetCompliancePct,
          });
          if (score === null) continue;
          assert.ok(
            Number.isInteger(score) && score >= 0 && score <= 100,
            `score out of range: ${score}`
          );
        }
      }
    }
  });

  it('does not throw on an empty or all-null input object', () => {
    assert.doesNotThrow(() => computeSecurityScore({}));
    assert.equal(computeSecurityScore({}).score, null);
    assert.doesNotThrow(() =>
      computeSecurityScore({
        activeDevices: null,
        devicesWithPatchNow: null,
        devicesWithScheduled: null,
        deviceRiskScores: null,
        fleetCompliancePct: null,
      })
    );
    assert.equal(
      computeSecurityScore({
        activeDevices: null,
        devicesWithPatchNow: null,
        devicesWithScheduled: null,
        deviceRiskScores: null,
        fleetCompliancePct: null,
      }).score,
      null
    );
  });

  it('does not throw on non-array / wrong-typed risk input', () => {
    assert.doesNotThrow(() => hygieneSubscore('47'));
    assert.equal(hygieneSubscore('47'), null, 'a string is not an array of risk scores');
    assert.equal(hygieneSubscore({ 0: 47 }), null);
    assert.equal(complianceSubscore('not a number'), null, 'unparseable is unmeasurable, not 0');
  });

  it('reads counts that arrive as bigint STRINGS, because pg returns them that way', () => {
    // node-postgres hands COUNT(*) back as a string unless the query casts it.
    // '10' is unambiguously ten, so refusing it would discard a real measurement
    // -- the same reason ruleAnalysis treats a hit_count of "0" as a genuine
    // measured zero. Both engines must agree that a cleanly-parsing numeric
    // string is DATA; a disagreement between them is exactly the drift these
    // tests exist to catch.
    assert.equal(
      vulnerabilitySubscore({ activeDevices: '10', devicesWithPatchNow: '2', devicesWithScheduled: '0' }),
      80,
      "2 of 10 devices exposed -> 100 * (1 - 0.2) = 80"
    );
  });

  it('fails SAFE (null) when a count is genuinely unreadable, never a flattering 0', () => {
    // ⛔ The direction is the point. `Number(x) || 0` used to turn an
    // unreadable exposure count into "no exposed devices" -- good news
    // invented from a failed read, which is the class CLAUDE.md now names as
    // a Critical Rule. Made strict 2026-08-25.
    for (const junk of ['abc', null, undefined, '', false, {}]) {
      assert.equal(
        vulnerabilitySubscore({ activeDevices: 10, devicesWithPatchNow: junk, devicesWithScheduled: 0 }),
        null,
        `devicesWithPatchNow=${JSON.stringify(junk)} is unmeasurable, so the whole component is`
      );
    }
  });

  it('treats a non-numeric activeDevices as unmeasurable', () => {
    assert.equal(
      vulnerabilitySubscore({ activeDevices: 'lots', devicesWithPatchNow: 0, devicesWithScheduled: 0 }),
      null
    );
  });
});
