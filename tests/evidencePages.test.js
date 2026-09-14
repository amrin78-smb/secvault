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
  buildSegmentationAnswer,
  buildWorkQueueAnswer,
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
    // ⛔ THIS TEST USED TO BLESS THE BUG NEXT TO IT. `paths: 0` and
    // `paths: null` shared one branch, so pinning the zero case as `ok` also
    // pinned "the engine returned nothing" as `ok` — see the sibling test
    // below, which is the half that was missing. Keep them adjacent: the pair
    // is the assertion, not either one alone.
    const a = buildExposureAnswer({ paths: 0, observed: 0 }, 0);
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
    assert.match(a.sentence, /No internet exposure paths were found/);
  });

  it('⛔ NO PATHS FOUND and NO ANALYSIS RUN are different answers', () => {
    // `buildExposureAnswer(null, 0)` returned tone `ok` and the sentence "No
    // internet exposure paths were found on any firewall." The word "found"
    // claims an act of looking that never happened — and with no coverage
    // clauses to soften it, the page rendered a green all-clear over an
    // exposure engine that produced nothing at all.
    const notRun = buildExposureAnswer(null, 0);
    assert.equal(notRun.tone, 'unknown');
    assert.doesNotMatch(notRun.sentence, /were found/);
    assert.match(notRun.sentence, /cannot say whether any path/);

    // And the two must not have converged on identical prose either.
    assert.notEqual(notRun.sentence, buildExposureAnswer({ paths: 0, observed: 0 }, 0).sentence);
  });

  it('⛔ open paths with no traffic evidence are not "none was reached"', () => {
    // `observed` was read as `num(t.observed) || 0`, so an absent observation
    // count became a measured zero and the page said "none was observed being
    // reached" — a statement about traffic evidence, made without any. The
    // paths themselves WERE measured, so the count still leads; only the
    // traffic half is withheld.
    const a = buildExposureAnswer({ paths: 40, unmeasured: 0, devicesWithoutSyslog: 0 }, 0);
    assert.equal(a.tone, 'unknown');
    assert.match(a.lead, /40 exposure paths/);
    assert.match(a.sentence, /never measured/);
    assert.doesNotMatch(a.sentence, /none was observed/);
  });

  it('all three builders return null rather than half-built descriptors', () => {
    assert.equal(lifecycleEvidence({}), null);
    assert.equal(deviceInventoryEvidence({}), null);
    assert.equal(exposureEvidence({}), null);
  });
});

describe('⛔ a null primary measurement is never a zero', () => {
  // THE CLASS OF BUG THIS BLOCK EXISTS FOR, found on NINE of the ten builders
  // in lib/answers.js at once. `num()` returns null for an absent input, and
  // `null > 0` is silently false in JavaScript — so every builder, being a
  // ladder of `> 0` branches ending in an all-clear, walked a null primary
  // measurement past every rung and printed the green sentence. The result is
  // not a wrong number but a wrong CONCLUSION, stated in the product's most
  // consequential position, computed from nothing.
  //
  // Each case below is the exact call that produced a tone of `ok` before the
  // guards existed. They are grouped here rather than spread through the
  // page-specific blocks above because they are ONE bug, and the next builder
  // added to that file will have it too unless this list is extended with it.

  it('CVE posture: an unread band total is not an empty band', () => {
    const a = buildCveAnswer(null, CVE_COVERED);
    assert.equal(a.tone, 'unknown');
    assert.doesNotMatch(a.sentence, /No outstanding CVEs/);
    assert.match(a.sentence, /could not be read/);
  });

  it('CVE posture: a measured band still leads when its neighbour is missing', () => {
    const a = buildCveAnswer({ patch_now_cves: 2 }, CVE_COVERED);
    assert.equal(a.tone, 'critical');
    assert.match(a.lead, /2 CVEs/);
  });

  it('rule hygiene: an unread coverage query is not full hit-count coverage', () => {
    // The green sentence here asserts "every rule had usage data behind it" —
    // the strongest claim on the page, and the one that turns "no findings"
    // into "a clean ruleset". It was being made from a hitCoverage object that
    // never arrived, which is hit_count's own NULL bug used as its own alibi.
    const a = buildRuleHygieneAnswer({ total: 0 }, null);
    assert.equal(a.tone, 'unknown');
    assert.doesNotMatch(a.sentence, /every rule had usage data/);
    assert.match(a.sentence, /unverified ruleset, not a clean one/);
  });

  it('lifecycle: one missing count is enough, and the other still leads', () => {
    const halfRead = buildLifecycleAnswer({ expired: null, expiring: 0, activeDevices: 16 });
    assert.equal(halfRead.tone, 'unknown');
    assert.doesNotMatch(halfRead.sentence, /Every support contract is current/);

    const stillExpired = buildLifecycleAnswer({ expired: 4, expiring: null, activeDevices: 16 });
    assert.equal(stillExpired.tone, 'critical');
    assert.match(stillExpired.lead, /4 support entitlements/);
  });

  it('lifecycle: an expiring count does not speak for the expired one', () => {
    const a = buildLifecycleAnswer({ expired: null, expiring: 2, activeDevices: 16 });
    assert.equal(a.tone, 'warn');
    assert.match(a.sentence, /whether anything has already lapsed was not measured/);
  });

  it('device inventory: an unread reachability count is not "all reachable"', () => {
    const a = buildDeviceInventoryAnswer({
      total: 16, online: null, neverChecked: 0, cveNotAssessed: 0, patchNowDevices: 0,
    });
    assert.equal(a.tone, 'unknown');
    assert.doesNotMatch(a.sentence, /are reachable, assessed, and free of/);
    assert.match(a.sentence, /none of them can be called reachable/);
  });

  it('device inventory: an unread patch-now count is not "free of urgent vulnerabilities"', () => {
    const a = buildDeviceInventoryAnswer({ total: 16, online: 16, neverChecked: 0, cveNotAssessed: 0 });
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /free of urgent vulnerabilities/);
    assert.match(a.sentence, /could not be read/);
  });

  it('segmentation: unread verdicts are not a matrix that holds', () => {
    // ⛔ `expectedAllowMissing` is deliberately NOT required by that guard — it
    // is summarise()'s newest counter, and demanding it would turn the whole
    // page unknown against any caller predating it. The four required here have
    // been emitted by every version of summarise() this page has had.
    const a = buildSegmentationAnswer({ intents: [1], summary: { total: 9 }, windowDays: 30 });
    assert.equal(a.tone, 'unknown');
    assert.doesNotMatch(a.sentence, /Every declared boundary holds/);
    assert.match(a.sentence, /could not be counted/);
  });

  it('segmentation: a complete summary is still allowed its all-clear', () => {
    const a = buildSegmentationAnswer({
      intents: [1], windowDays: 30, rulesWithoutHitData: 0,
      summary: {
        total: 9, violations: 0, activeViolations: 0, unusedPermissions: 0,
        unmeasurable: 0, expectedAllowMissing: 0,
      },
    });
    assert.equal(a.tone, 'ok');
  });

  it('work queue: "nothing is outstanding" may not be printed from no queue', () => {
    // The single most consequential sentence in the product — an operator who
    // reads it closes the tab — and `buildWorkQueueAnswer(null)` printed it in
    // green, along with "and every source was readable", having consulted no
    // engine and read no source.
    const a = buildWorkQueueAnswer(null);
    assert.equal(a.tone, 'unknown');
    assert.doesNotMatch(a.lead + ' ' + a.sentence, /Nothing is outstanding/);
    assert.match(a.lead, /could not be counted/);
  });

  it('work queue: an urgent item still leads when the scheduled band is missing', () => {
    const a = buildWorkQueueAnswer({ act_now: 3, sourcesFailed: 0, sourcesTotal: 4 });
    assert.equal(a.tone, 'critical');
    assert.match(a.lead, /3 items need attention now/);
    assert.doesNotMatch(a.sentence, /nothing else is outstanding/);
  });

  it('every one of these builders survives a null argument', () => {
    // A guard that throws is not a guard — the page would render its error
    // boundary, which is at least honest, but none of these may crash.
    const calls = [
      () => buildCveAnswer(null, null),
      () => buildRuleHygieneAnswer(null, null),
      () => buildLifecycleAnswer(null),
      () => buildDeviceInventoryAnswer(null),
      () => buildExposureAnswer(null, null),
      () => buildSegmentationAnswer(null),
      () => buildWorkQueueAnswer(null),
      () => buildDeviceComplianceAnswer(null, null),
    ];
    for (const call of calls) {
      const a = call();
      assert.equal(a.tone, 'unknown');
      assert.equal(typeof a.sentence, 'string');
      assert.ok(a.sentence.length > 0);
    }
  });
});

describe('⛔ the drawer never invents a row it was not given', () => {
  // evidence.js's own Rule 1: if the caller does not have the number, the row
  // does not appear. A plausible "0" in an evidence drawer is strictly worse
  // than the same 0 on a tile, because the drawer is where the operator goes
  // specifically to check — and every case below rendered one, as an itemised,
  // aligned, authoritative-looking line.

  it('compliance: an absent `na` bucket is an em-dash, not "0 EXCLUDED"', () => {
    // "na 0 EXCLUDED" is an explicit claim that nothing was unanswerable on
    // this firewall — the row this whole builder exists to show, invented.
    const ev = deviceComplianceEvidence({ pass: 10, fail: 2, warning: 1 }, 'TSR-TL');
    assert.equal(ev.inputs.find((r) => r.label === 'Not applicable').value, '—');
    assert.match(ev.formula, /na\s+—\s+EXCLUDED/);
    assert.deepEqual(ev.unmeasured, []);
  });

  it('lifecycle: absent buckets are em-dashes, not "0 no parseable expiry date"', () => {
    const ev = lifecycleEvidence({ expired: 0, expiring: 0, activeDevices: 16 });
    assert.match(ev.formula, /unknown\s+—\s+no parseable expiry date/);
    assert.match(ev.formula, /perpetual\s+—/);
    assert.equal(ev.inputs.find((r) => r.label === 'Expiry not parseable').value, '—');
    // ⛔ And the subtraction that reported the WHOLE fleet as licence-covered
    // from the absence of the no-data count.
    assert.equal(ev.inputs.find((r) => r.label === 'Firewalls with licence data').value, '—');
  });

  it('exposure: an absent "reached" count is an em-dash, not a measured zero', () => {
    const ev = exposureEvidence({ paths: 40, publicIps: 9, devicesWithExposure: 6 }, 0);
    assert.match(ev.formula, /reached\s+—\s+traffic observed arriving/);
    assert.match(ev.formula, /not seen\s+—/);
    assert.equal(ev.inputs.find((r) => r.label === 'Reached from a public source').value, '—');
  });

  it('rule hygiene: a sum of two absent numbers is not zero', () => {
    // "Critical + high 0" is an all-clear, and "Rules with usage evidence 0"
    // would have an operator believe the fleet reports no hit counts at all.
    const ev = ruleHygieneEvidence({ total: 185 }, { total: 1716 });
    assert.equal(ev.inputs.find((r) => r.label === 'Critical + high').value, '—');
    assert.equal(ev.inputs.find((r) => r.label === 'Rules with usage evidence').value, '—');
  });

  it('rule hygiene: a real zero still shows as 0', () => {
    // The mirror of the rule — the fix is a null check, not a truthiness one.
    const ev = ruleHygieneEvidence(TOTALS_CLEAN, HITS_FULL);
    assert.equal(ev.inputs.find((r) => r.label === 'Critical + high').value, '0');
  });

  it('device inventory: "never probed 0" is a coverage claim, not a count', () => {
    const ev = deviceInventoryEvidence({ total: 16, online: 13 });
    assert.match(ev.formula, /never probed\s+—/);
    assert.equal(ev.inputs.find((r) => r.label === 'Never probed').value, '—');
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

  it('a single unmeasurable path reads "1 of 9 paths", not "1 of 9 path"', () => {
    // ⛔ buildSegmentationAnswer was missing from this block entirely, and had
    // the bug the block was written for in two places at once: "1 of 12 path
    // could not be measured" (a singular noun inside an N-of-M construction)
    // and "1 rules cannot report usage at all" (a hardcoded plural). Both read
    // wrong at exactly one outstanding item, which is the production case.
    const a = buildSegmentationAnswer({
      intents: [1], windowDays: 30, rulesWithoutHitData: 1,
      summary: {
        total: 9, violations: 0, activeViolations: 0, unusedPermissions: 0,
        unmeasurable: 1, expectedAllowMissing: 0,
      },
    });
    assert.match(a.coverage, /1 of 9 paths could not be measured/);
    assert.match(a.coverage, /1 rule cannot report usage at all/);
  });

  it('segmentation reads correctly at one of each finding', () => {
    const one = (over) => buildSegmentationAnswer({
      intents: [1], windowDays: 30, rulesWithoutHitData: 0,
      summary: {
        total: 9, violations: 0, activeViolations: 0, unusedPermissions: 0,
        unmeasurable: 0, expectedAllowMissing: 0, ...over,
      },
    });

    const active = one({ violations: 1, activeViolations: 1 });
    assert.match(active.lead, /^1 segmentation violation$/);
    assert.match(active.sentence, /^is permitted AND carrying traffic/);

    const standing = one({ violations: 1 });
    assert.match(standing.sentence, /a standing hole rather than an active breach/);

    const missing = one({ expectedAllowMissing: 1 });
    assert.match(missing.lead, /^1 expected path$/);
    assert.match(missing.sentence, /^is declared as required but no rule permits it/);

    const unused = one({ unusedPermissions: 1 });
    assert.match(unused.lead, /^1 permitted path$/);
    assert.match(unused.sentence, /^has carried no traffic/);
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
      buildSegmentationAnswer({
        intents: [1], windowDays: 30, rulesWithoutHitData: 1,
        summary: {
          total: 9, violations: 0, activeViolations: 0, unusedPermissions: 1,
          unmeasurable: 1, expectedAllowMissing: 0,
        },
      }),
    ];
    for (const s of samples) {
      const text = [s.lead, s.sentence, s.coverage].filter(Boolean).join(' ');
      assert.doesNotMatch(text, /of \d[\d,]* (firewall|rule|check|path|entitlement)\b(?!s)/,
        'singular noun after "of N": ' + text);
    }
  });
});
