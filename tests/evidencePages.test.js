'use strict';
// Pins the page-level evidence builders and answer sentences added in Phase 1:
// CVE posture, per-device compliance and fleet rule hygiene (v2.108.0), then
// lifecycle, device inventory and internet exposure (v2.109.0).
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
  lifecycleEvidence,
  deviceInventoryEvidence,
  exposureEvidence,
  isRenderableEvidence,
} = require('../lib/evidence');

const {
  buildCveAnswer,
  buildDeviceComplianceAnswer,
  buildRuleHygieneAnswer,
  buildLifecycleAnswer,
  buildDeviceInventoryAnswer,
  buildExposureAnswer,
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

describe('lifecycle — an unparsed expiry is unknown, never current', () => {
  it('⛔ nothing expired + an unreadable expiry is UNKNOWN, not ok', () => {
    // The failure this page exists to prevent is a support contract lapsing
    // unnoticed. An expiry SecVault could not parse is exactly that risk, so it
    // may never be absorbed into a clean result.
    const a = buildLifecycleAnswer({
      expired: 0, expiring: 0, unknown: 3,
      devicesWithoutLicenceData: 0, activeDevices: 16,
    });
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /not every contract could be/);
    assert.match(a.coverage, /could not read/);
  });

  it('⛔ perpetual is NOT a problem and NOT a gap', () => {
    // A NULL expiry reported verbatim as 'Never' is a real, healthy answer.
    // Only the OTHER kind of NULL is unknown.
    const a = buildLifecycleAnswer({
      expired: 0, expiring: 0, unknown: 0, perpetual: 12,
      devicesWithoutLicenceData: 0, activeDevices: 16,
    });
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
  });

  it('a vendor that reports no licences at all is a coverage gap', () => {
    const a = buildLifecycleAnswer({
      expired: 0, expiring: 0, unknown: 0,
      devicesWithoutLicenceData: 9, activeDevices: 16,
    });
    assert.equal(a.tone, 'unknown');
    assert.match(a.coverage, /9 of 16/);
  });

  it('an expired contract still carries the coverage caveat', () => {
    const a = buildLifecycleAnswer({
      expired: 4, expiring: 2, unknown: 3,
      devicesWithoutLicenceData: 9, activeDevices: 16,
    });
    assert.equal(a.tone, 'critical');
    assert.ok(a.coverage);
  });

  it('the drawer separates unknown from perpetual', () => {
    const ev = lifecycleEvidence({
      expired: 4, expiring: 2, unknown: 3, perpetual: 12,
      devicesWithoutLicenceData: 9, activeDevices: 16, devicesWithHaData: 4,
    });
    assert.match(ev.formula, /unknown\s+3\s+no parseable expiry date/);
    assert.match(ev.formula, /perpetual\s+12/);
    assert.match(ev.formula, /never read as healthy/);
    assert.match(ev.unmeasured.map((u) => u.label).join(' | '), /no parseable expiry/);
  });
});

describe('device inventory — a never-assessed firewall is not a clean one', () => {
  it('⛔ zero findings over an unassessed fleet is UNKNOWN, not ok', () => {
    const a = buildDeviceInventoryAnswer({
      total: 16, online: 16, neverChecked: 0, cveNotAssessed: 3, patchNowDevices: 0,
    });
    assert.equal(a.tone, 'unknown');
    assert.match(a.coverage, /never been CVE-assessed/);
  });

  it('allows the all-clear only at full coverage', () => {
    const a = buildDeviceInventoryAnswer({
      total: 16, online: 16, neverChecked: 0, cveNotAssessed: 0, patchNowDevices: 0,
    });
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
  });

  it('says a never-probed device is neither online nor offline', () => {
    const ev = deviceInventoryEvidence({
      total: 16, online: 13, neverChecked: 3, criticalCves: 0, criticalCveDevices: 0,
      patchNow: 0, patchNowDevices: 0, cveNotAssessed: 0,
    });
    assert.match(ev.unmeasured.map((u) => u.reason).join(' '), /neither online nor offline/);
  });

  it('states that an unassessed device adds 0 exactly like a clean one', () => {
    const ev = deviceInventoryEvidence({
      total: 16, online: 16, neverChecked: 0, criticalCves: 4, criticalCveDevices: 2,
      patchNow: 3, patchNowDevices: 3, cveNotAssessed: 3,
    });
    assert.match(ev.formula, /adds 0 to the CVE sums/);
    assert.match(ev.unmeasured.map((u) => u.reason).join(' '), /only one of them is good news/);
  });
});

describe('exposure — not seen is not closed', () => {
  it('⛔ an unreached path is never described as closed', () => {
    const a = buildExposureAnswer(
      { paths: 40, observed: 0, unmeasured: 0, devicesWithoutSyslog: 0 }, 0
    );
    assert.equal(a.tone, 'warn');
    assert.match(a.sentence, /not the same as closed/);
    // ⛔ never 'ok': 40 open paths is not an all-clear just because no traffic
    // was seen on them.
    assert.notEqual(a.tone, 'ok');
  });

  it('leads with paths actually reached when any were', () => {
    const a = buildExposureAnswer(
      { paths: 40, observed: 12, unmeasured: 0, devicesWithoutSyslog: 0 }, 0
    );
    assert.equal(a.tone, 'critical');
    assert.match(a.sentence, /actually reached from a public source/);
  });

  it('⛔ counts devices excluded by an analysis ERROR as a gap', () => {
    // These devices are absent from every total, so a sentence built from
    // totals alone would describe a smaller fleet without saying so.
    const a = buildExposureAnswer({ paths: 0, observed: 0 }, 2);
    assert.equal(a.tone, 'unknown');
    assert.match(a.coverage, /could not be analysed/);
  });

  it('lists three gaps as a sentence, not "A, and B, and C"', () => {
    const a = buildExposureAnswer(
      { paths: 40, observed: 5, unmeasured: 8, devicesWithoutSyslog: 2 }, 1
    );
    assert.doesNotMatch(a.coverage, /, and .*, and /);
    assert.match(a.coverage, /, and /);
  });

  it('separates never-watched paths from watched-but-quiet ones', () => {
    const ev = exposureEvidence(
      { paths: 40, observed: 5, notObserved: 27, unmeasured: 8, devicesWithoutSyslog: 2, publicIps: 9, devicesWithExposure: 6 },
      0
    );
    assert.match(ev.formula, /not seen\s+27\s+watched, no traffic — still OPEN/);
    assert.match(ev.formula, /NOT MEASURED\s+8\s+never watched/);
    assert.match(ev.unmeasured.map((u) => u.reason).join(' '), /absence of evidence, not evidence of absence/);
  });

  it('an empty fleet with no gaps is genuinely ok', () => {
    const a = buildExposureAnswer({ paths: 0, observed: 0 }, 0);
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
  });

  it('all three builders return null rather than half-built descriptors', () => {
    assert.equal(lifecycleEvidence({}), null);
    assert.equal(deviceInventoryEvidence({}), null);
    assert.equal(exposureEvidence({}), null);
  });
});

describe('sentences agree with their own counts', () => {
  // ⛔ THESE READ WRONG PRECISELY WHEN THE FLEET IS NEARLY CLEAN. A single
  // outstanding item is the common case in production and the rare case in a
  // test fixture, so "1 of 16 firewall report no licence data" survived every
  // multi-item example until it was read on a live page.
  //
  // Two rules: an "N of M" construction takes a PLURAL noun regardless of N,
  // and the verb agrees with N.
  it('N-of-M uses a plural noun and a verb agreeing with N', () => {
    const one = buildDeviceInventoryAnswer({
      total: 16, online: 16, neverChecked: 0, cveNotAssessed: 0, patchNowDevices: 1,
    });
    assert.match(one.lead, /1 of 16 firewalls$/);
    assert.match(one.sentence, /^needs patching now/);

    const many = buildDeviceInventoryAnswer({
      total: 16, online: 16, neverChecked: 0, cveNotAssessed: 0, patchNowDevices: 3,
    });
    assert.match(many.lead, /3 of 16 firewalls$/);
    assert.match(many.sentence, /^need patching now/);
  });

  it('a single unmeasured rule reads "1 of N rules has ... it can never"', () => {
    const a = buildRuleHygieneAnswer({ critical: 1, high: 0, total: 5 }, { total: 1756, not_measured: 1 });
    assert.match(a.coverage, /1 of 1,756 rules has no usage data at all, so it can never be judged unused\./);
  });

  it('a single silent firewall reads "1 firewall sends no syslog"', () => {
    const a = buildExposureAnswer({ paths: 9, observed: 1, unmeasured: 0, devicesWithoutSyslog: 1 }, 0);
    assert.match(a.coverage, /1 firewall sends no syslog/);
  });

  it('a single uncollected licence reads "1 of 16 firewalls reports"', () => {
    const a = buildLifecycleAnswer({
      expired: 0, expiring: 0, unknown: 0, devicesWithoutLicenceData: 1, activeDevices: 16,
    });
    assert.match(a.coverage, /1 of 16 firewalls reports no licence data/);
  });

  it('no sentence ever contains a singular noun straight after "of N"', () => {
    // A broad net: scan a spread of shapes for the specific broken form.
    const samples = [
      buildDeviceInventoryAnswer({ total: 16, online: 15, neverChecked: 0, cveNotAssessed: 1, patchNowDevices: 0 }),
      buildLifecycleAnswer({ expired: 0, expiring: 0, unknown: 0, devicesWithoutLicenceData: 1, activeDevices: 16 }),
      buildRuleHygieneAnswer({ critical: 0, high: 0, total: 0 }, { total: 100, not_measured: 1 }),
      buildExposureAnswer({ paths: 5, observed: 0, unmeasured: 1, devicesWithoutSyslog: 1 }, 1),
    ];
    for (const s of samples) {
      const text = [s.lead, s.sentence, s.coverage].filter(Boolean).join(' ');
      assert.doesNotMatch(text, /of \d[\d,]* (firewall|rule|check|path|entitlement)\b(?!s)/,
        'singular noun after "of N": ' + text);
    }
  });
});
