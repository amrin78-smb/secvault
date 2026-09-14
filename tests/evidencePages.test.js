'use strict';
// Pins the page-level evidence builders and answer sentences added in Phase 1
// (v2.108.0): CVE posture, per-device compliance, and fleet rule hygiene.
//
// The companion file tests/evidence.test.js covers the dashboard. This one
// exists because each of these three pages has its OWN way of being quietly
// dishonest, and they are not the same way:
//
//   CVE posture       two units that must never be conflated (distinct
//                     advisories vs device-CVE pairs), and a fleet nothing has
//                     assessed rendering as a fleet with nothing wrong.
//   Compliance        `na` — a limitation of SecVault — must never make a
//                     device look worse, and must never quietly make it look
//                     better either.
//   Rule hygiene      hit_count's NULL bucket. This is the canonical tri-state
//                     in the whole codebase and the clearest thing the product
//                     does that its competitors do not.
//
// ⛔ The single assertion shape repeated throughout: ZERO PROBLEMS + INCOMPLETE
// COVERAGE must never return tone 'ok'. Every one of these builders has a
// branch that is one careless edit away from reporting a measurement gap as an
// all-clear, which is CLAUDE.md's failed-read-as-a-fact bug wearing a sentence.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  cvePostureEvidence,
  deviceComplianceEvidence,
  ruleHygieneEvidence,
  isRenderableEvidence,
} = require('../lib/evidence');

const {
  buildCveAnswer,
  buildDeviceComplianceAnswer,
  buildRuleHygieneAnswer,
} = require('../lib/answers');

// Shapes mirror the live queries: components/vulnerability/CvePostureTab.js's
// getSummary()/getAssessmentCoverage() and app/(dashboard)/analysis/page.js's
// getHitCountCoverage().
const CVE_SUMMARY = {
  total_cves: 26,
  patch_now_cves: 1, scheduled_cves: 25, monitor_cves: 0,
  patch_now_count: 3, scheduled_count: 163, monitor_count: 0,
};
const CVE_COVERED = { active_devices: 16, devices_with_version: 16, devices_assessed: 16 };
const CVE_PARTIAL = { active_devices: 16, devices_with_version: 14, devices_assessed: 13 };

const HITS = { total: 1716, not_measured: 164, measured_zero: 466, with_hits: 1086 };
const HITS_FULL = { total: 1716, not_measured: 0, measured_zero: 630, with_hits: 1086 };
const TOTALS = { critical: 2, high: 30, medium: 100, info: 53, total: 185 };
const TOTALS_CLEAN = { critical: 0, high: 0, medium: 0, info: 0, total: 0 };

describe('CVE posture — two units that must not be conflated', () => {
  it('the sentence counts DISTINCT CVEs, not device-CVE pairs', () => {
    // ⛔ 1 advisory, 3 pairs. The dashboard got this exact distinction wrong in
    // v2.107.0 and shipped "3 vulnerabilities" for one CVE on three firewalls.
    const a = buildCveAnswer(CVE_SUMMARY, CVE_COVERED);
    assert.match(a.lead, /^1 CVE$/);
    assert.doesNotMatch(a.lead, /3/);
  });

  it('the drawer shows both units, each labelled', () => {
    const ev = cvePostureEvidence(CVE_SUMMARY, CVE_COVERED);
    assert.match(ev.formula, /patch_now\s+1 CVEs\s+3 device-CVE pairs/);
    assert.match(ev.formula, /never sum together/);
  });

  it('⛔ a fleet with no assessment is UNKNOWN, never clean', () => {
    const a = buildCveAnswer(
      { total_cves: 0, patch_now_cves: 0, scheduled_cves: 0, monitor_cves: 0 },
      { active_devices: 16, devices_with_version: 16, devices_assessed: 0 }
    );
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /nothing here has been measured/);
  });

  it('⛔ refuses an all-clear while any firewall is unassessed', () => {
    const a = buildCveAnswer(
      { total_cves: 5, patch_now_cves: 0, scheduled_cves: 0, monitor_cves: 5 },
      CVE_PARTIAL
    );
    assert.equal(a.tone, 'unknown');
    assert.ok(a.coverage);
    assert.match(a.coverage, /3 of 16/);
  });

  it('allows the all-clear only at full coverage', () => {
    const a = buildCveAnswer(
      { total_cves: 5, patch_now_cves: 0, scheduled_cves: 0, monitor_cves: 5 },
      CVE_COVERED
    );
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
  });

  it('reports an un-versioned device as its own distinct gap', () => {
    // A version row is a PRECONDITION for assessment, never evidence of one,
    // so the two gaps are listed separately rather than merged.
    const ev = cvePostureEvidence(CVE_SUMMARY, CVE_PARTIAL);
    const labels = ev.unmeasured.map((u) => u.label).join(' | ');
    assert.match(labels, /no completed assessment/);
    assert.match(labels, /no collected firmware version/);
  });
});

describe('compliance — `na` is SecVault\'s limitation, not the device\'s', () => {
  it('excludes na from the denominator and says so', () => {
    const ev = deviceComplianceEvidence({ pass: 19, fail: 12, warning: 7, na: 7 }, 'TSR-TL');
    assert.match(ev.formula, /measurable\s+38/);
    assert.match(ev.formula, /na\s+7\s+EXCLUDED/);
    assert.match(ev.title, /50% compliant/);
  });

  it('⛔ a clean sweep with unanswerable checks is UNKNOWN, not ok', () => {
    const a = buildDeviceComplianceAnswer({ pass: 38, fail: 0, warning: 0, na: 7 }, 'TSR-TL');
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /not every check could be asked/);
    assert.ok(a.coverage);
  });

  it('allows the all-clear only when nothing was unanswerable', () => {
    const a = buildDeviceComplianceAnswer({ pass: 38, fail: 0, warning: 0, na: 0 }, 'TSR-TL');
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
  });

  it('a warning is the DEVICE\'s problem and keeps the score honest', () => {
    // ⛔ warning counts against the score (we asked, and could not tell);
    // na does not (we could not ask). The two must not be merged.
    const a = buildDeviceComplianceAnswer({ pass: 30, fail: 0, warning: 8, na: 0 }, 'TSR-TL');
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /indeterminate against a config we did collect/);
  });

  it('claims no score when nothing is answerable, never 0%', () => {
    const a = buildDeviceComplianceAnswer({ pass: 0, fail: 0, warning: 0, na: 12 }, 'TSR-TL');
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /no answerable compliance checks/);
    assert.doesNotMatch(a.sentence, /0%/);

    const ev = deviceComplianceEvidence({ pass: 0, fail: 0, warning: 0, na: 12 }, 'TSR-TL');
    assert.equal(ev.inputs.find((r) => r.label === 'Score').value, '—');
  });

  it('distinguishes "audited and clean" from "never audited"', () => {
    const never = buildDeviceComplianceAnswer({}, 'TSR-TL');
    assert.equal(never.tone, 'unknown');
    assert.match(never.sentence, /no compliance findings on record/);
  });
});

describe('rule hygiene — the canonical tri-state', () => {
  it('renders hit_count as three distinct buckets', () => {
    const ev = ruleHygieneEvidence(TOTALS, HITS);
    assert.match(ev.formula, /with hits\s+1,086/);
    assert.match(ev.formula, /measured zero\s+466/);
    assert.match(ev.formula, /NOT MEASURED\s+164/);
    assert.match(ev.formula, /Only a MEASURED zero can produce an `unused` finding/);
  });

  it('⛔ states that unmeasured rules are REFUSED from cleanup, not just flagged', () => {
    const ev = ruleHygieneEvidence(TOTALS, HITS);
    const reason = ev.unmeasured.map((u) => u.reason).join(' ');
    assert.match(reason, /REFUSED from cleanup requests/);
    assert.match(reason, /is not a reason to delete it/);
  });

  it('⛔ no findings + unmeasured rules is UNKNOWN, never an all-clear', () => {
    // The most dangerous sentence this page could print. A ruleset where 164
    // rules were never measured has not been shown to be clean.
    const a = buildRuleHygieneAnswer(TOTALS_CLEAN, HITS);
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /not every rule could be/);
    assert.match(a.coverage, /164 of 1,716/);
    assert.match(a.coverage, /never be judged unused/);
  });

  it('allows the all-clear only when every rule had usage data', () => {
    const a = buildRuleHygieneAnswer(TOTALS_CLEAN, HITS_FULL);
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
    assert.match(a.sentence, /every rule had usage data/);
  });

  it('escalates to critical only when a critical finding exists', () => {
    assert.equal(buildRuleHygieneAnswer({ critical: 2, high: 30, total: 185 }, HITS).tone, 'critical');
    assert.equal(buildRuleHygieneAnswer({ critical: 0, high: 30, total: 185 }, HITS).tone, 'warn');
  });

  it('a critical result still carries the coverage caveat', () => {
    // ⛔ A gap does not stop mattering because something worse was found.
    const a = buildRuleHygieneAnswer(TOTALS, HITS);
    assert.ok(a.coverage, 'coverage must survive the critical branch');
  });

  it('says nothing was analysed rather than reporting zero findings', () => {
    const a = buildRuleHygieneAnswer({}, { total: 0, not_measured: 0 });
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /No firewall rules have been collected/);
  });

  it('every builder produces a renderable descriptor on real-shaped data', () => {
    assert.ok(isRenderableEvidence(cvePostureEvidence(CVE_SUMMARY, CVE_COVERED)));
    assert.ok(isRenderableEvidence(deviceComplianceEvidence({ pass: 1, fail: 1, warning: 0, na: 0 }, 'x')));
    assert.ok(isRenderableEvidence(ruleHygieneEvidence(TOTALS, HITS)));
  });

  it('returns null rather than a half-built descriptor on missing data', () => {
    assert.equal(cvePostureEvidence({}, {}), null);
    assert.equal(deviceComplianceEvidence({}, 'x'), null);
    assert.equal(ruleHygieneEvidence({}, {}), null);
  });
});
