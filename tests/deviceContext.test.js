'use strict';

// lib/deviceContext.js — the facts the persistent per-device header states.
//
// ⛔ EVERY TEST HERE IS A VARIANT OF ONE QUESTION: can a figure SecVault never
// measured be rendered as a zero? This header appears on six routes, so a
// single fabricated zero is repeated six times per firewall — which is why the
// "we could not measure this" case is tested FIRST for every figure, and why
// the measured-zero case is tested beside it. A guard that returns `null` for
// everything would pass the first half alone.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { stripComments } = require('./stripComments');

const {
  deviceContextFacts,
  collectionFreshness,
  postureFigure,
  loadDeviceContext,
  FRESH_AFTER_DAYS,
} = require('../lib/deviceContext');

const NOW = new Date('2026-11-02T12:00:00Z');
const ago = (days) => new Date(NOW.getTime() - days * 86400000).toISOString();

// A fully-measured firewall: collected today, assessed today, rules pulled,
// analysis run, compliance evaluated, two snapshots on file.
function healthy(over = {}) {
  return {
    id: 'd1',
    name: 'TSR-EKM',
    vendor: 'fortinet',
    site: 'Bangkok',
    mgmt_ip: '10.0.0.1',
    version_string: 'v7.4.3',
    last_collected_at: ago(1),
    last_cve_assessed_at: ago(1),
    last_rules_collected_at: ago(1),
    rule_count: 706,
    assessment_count: 12,
    analysis_run_count: 5,
    patch_now_count: 0,
    critical_cve_count: 0,
    critical_findings: 0,
    high_findings: 0,
    open_findings: 0,
    compliance_pct: 51,
    open_diffs: 0,
    config_snapshot_count: 4,
    pollBand: 'healthy',
    ...over,
  };
}

describe('a figure that was not measured is not a zero', () => {
  it('⛔ an unassessed firewall reports patch-now and critical CVEs as NOT MEASURED', () => {
    const f = deviceContextFacts(
      healthy({ last_cve_assessed_at: null, assessment_count: 0 }),
      { now: NOW }
    );
    assert.equal(f.posture.patchNow.measured, false);
    assert.equal(f.posture.patchNow.value, null, 'null, never 0 — a 0 reads as "assessed and clean"');
    assert.equal(f.posture.criticalCves.measured, false);
    assert.match(f.posture.patchNow.reason, /no completed cve assessment/i);
  });

  it('⛔ AND A MEASURED ZERO IS STILL A ZERO — the guard must not blanket-null', () => {
    const f = deviceContextFacts(healthy(), { now: NOW });
    assert.equal(f.posture.patchNow.measured, true);
    assert.equal(f.posture.patchNow.value, 0);
    assert.equal(f.posture.patchNow.reason, null);
  });

  it('⛔ either CVE signal alone is enough — a stamp with no rows, or rows with no stamp', () => {
    const stampOnly = deviceContextFacts(
      healthy({ assessment_count: 0 }), { now: NOW }
    );
    assert.equal(stampOnly.posture.patchNow.measured, true,
      'a device assessed and matching nothing has been assessed');
    const rowsOnly = deviceContextFacts(
      healthy({ last_cve_assessed_at: null }), { now: NOW }
    );
    assert.equal(rowsOnly.posture.patchNow.measured, true,
      'assessment rows can only exist because a match ran');
  });

  it('⛔ findings need BOTH a ruleset and a completed analysis run', () => {
    const noRules = deviceContextFacts(
      healthy({ rule_count: 0, last_rules_collected_at: null }), { now: NOW }
    );
    assert.equal(noRules.posture.openFindings.measured, false);
    assert.match(noRules.posture.openFindings.reason, /no ruleset/i);

    const rulesButNoRun = deviceContextFacts(
      healthy({ analysis_run_count: 0 }), { now: NOW }
    );
    assert.equal(rulesButNoRun.posture.openFindings.measured, false,
      'zero findings on a never-analysed device is arithmetic, not hygiene');
    assert.match(rulesButNoRun.posture.openFindings.reason, /analysis has not run/i);

    // ⛔ The reason an analysis RUN count is needed at all: a device analysed
    // and found clean holds zero finding rows, exactly like one never
    // analysed. Without device_risk_history the two are indistinguishable.
    const cleanAndAnalysed = deviceContextFacts(healthy(), { now: NOW });
    assert.equal(cleanAndAnalysed.posture.openFindings.measured, true);
    assert.equal(cleanAndAnalysed.posture.openFindings.value, 0);
  });

  // ⛔ THE TILE IS LABELLED "Open findings" AND LINKS TO THE UNFILTERED
  // FINDINGS TAB, SO IT MUST COUNT EVERY SEVERITY. It summed critical + high
  // only, and the version of this file that shipped that pinned the bug: the
  // fixture set those two to 0, never set a medium count, and the assertion
  // above therefore agreed that the zero was correct.
  //
  // ⛔ IT WAS THE COMMON CASE. ruleAnalysis.js emits `medium` for EIGHT of
  // thirteen finding types and `info` for a ninth, so only four could ever
  // reach the tile -- and `unused`, 185 live on the reference fleet, is one of
  // the eight. A firewall in that state reported a MEASURED ZERO (no em-dash,
  // no hue, no named gap) on all six of its pages while /devices banded it
  // `medium` from the same rows.
  it('⛔ "Open findings" counts EVERY severity, not just critical and high', () => {
    const mediumOnly = deviceContextFacts(
      healthy({ critical_findings: 0, high_findings: 0, open_findings: 197 }),
      { now: NOW }
    );
    assert.equal(mediumOnly.posture.openFindings.measured, true);
    assert.equal(mediumOnly.posture.openFindings.value, 197,
      'a firewall whose findings are all medium/info must not read as a measured zero');

    // And the query has to supply it, or the figure is 0 for every device on a
    // live database however correct the arithmetic here is.
    const src = stripComments(
      fs.readFileSync(path.join(__dirname, '..', 'lib', 'deviceContext.js'), 'utf8')
    );
    assert.match(src, /COUNT\(\*\)\s+AS open_findings/,
      'the lateral must count all rule_analysis_results rows for this device');
    assert.doesNotMatch(src, /critical_findings \|\| 0\) \+ \(r\.high_findings/,
      'summing only critical+high is the regression this test exists for');
  });

  it('⛔ drift needs TWO snapshots — one is a device collected from with nothing to compare', () => {
    for (const n of [0, 1]) {
      const f = deviceContextFacts(healthy({ config_snapshot_count: n }), { now: NOW });
      assert.equal(f.posture.openDiffs.measured, false, `snapshot_count=${n}`);
      assert.match(f.posture.openDiffs.reason, /fewer than two/i);
    }
    assert.equal(
      deviceContextFacts(healthy({ config_snapshot_count: 2 }), { now: NOW }).posture.openDiffs.measured,
      true
    );
  });

  it('⛔ a NULL compliance score is unmeasured, never 0%', () => {
    const f = deviceContextFacts(healthy({ compliance_pct: null }), { now: NOW });
    assert.equal(f.posture.compliancePct.measured, false);
    assert.equal(f.posture.compliancePct.value, null);
    // 0 is a real score and must survive.
    assert.equal(
      deviceContextFacts(healthy({ compliance_pct: 0 }), { now: NOW }).posture.compliancePct.value,
      0
    );
  });

  it('postureFigure keeps a falsy-but-real value', () => {
    assert.deepEqual(postureFigure(0, true), { value: 0, measured: true, reason: null });
    assert.equal(postureFigure(5, false, 'why').value, null);
  });
});

describe('freshness is four states, not two', () => {
  it('⛔ "never" and "stale" are different facts and are never collapsed', () => {
    assert.equal(collectionFreshness(null, NOW).state, 'never');
    assert.equal(collectionFreshness(ago(FRESH_AFTER_DAYS + 1), NOW).state, 'stale');
    assert.equal(collectionFreshness(ago(1), NOW).state, 'fresh');
  });

  it('⛔ a FUTURE timestamp is `unknown`, not fresh — it is a clock disagreement', () => {
    const future = new Date(NOW.getTime() + 3600000).toISOString();
    const f = collectionFreshness(future, NOW);
    assert.equal(f.state, 'unknown');
    assert.equal(f.ageDays, null, 'an age that cannot be computed must not be a number');
    assert.equal(f.at, future, 'the raw value is still carried — it is the evidence');
  });

  it('the boundary is exclusive, so exactly the threshold is still fresh', () => {
    assert.equal(collectionFreshness(ago(FRESH_AFTER_DAYS), NOW).state, 'fresh');
    assert.equal(collectionFreshness(ago(FRESH_AFTER_DAYS + 0.01), NOW).state, 'stale');
  });

  it('an unparseable timestamp is unknown, not an exception', () => {
    assert.equal(collectionFreshness('not a date', NOW).state, 'unknown');
  });
});

describe('reachability', () => {
  it('⛔ comes from the poll band, NOT from last_connectivity_ok', () => {
    // The live case this exists for: a device whose manual check passed weeks
    // ago while every scheduled poll has failed since.
    const f = deviceContextFacts(
      healthy({ last_connectivity_ok: true, pollBand: 'failing' }), { now: NOW }
    );
    assert.equal(f.reachability.band, 'failing');

    // ⛔ AND THE PROBE BOOLEAN IS NOT CARRIED AT ALL ANY MORE. It used to be,
    // under a comment saying the manual result "is still carried — labelled as
    // what it is" — but nothing on any page ever read it, so that described
    // code which did not exist, and this assertion pinned the dead field in
    // place. Reachability here is the dot plus PollHealthNote; the
    // latest-probe boolean is still shown on /devices, where the fleet
    // comparison lives.
    assert.equal(f.reachability.lastManualOk, undefined,
      'a field no surface renders must not be carried as though it were displayed');
  });

  it('⛔ an absent band is `unknown`, never `healthy`', () => {
    const f = deviceContextFacts(healthy({ pollBand: undefined }), { now: NOW });
    assert.equal(f.reachability.band, 'unknown');
  });
});

describe('coverage gaps are named, never summed', () => {
  it('⛔ each gap is its own entry with its own first step', () => {
    const f = deviceContextFacts(
      healthy({
        version_string: null,
        rule_count: 0,
        last_rules_collected_at: null,
        last_cve_assessed_at: null,
        assessment_count: 0,
        last_collected_at: null,
        pollBand: 'failing',
      }),
      { now: NOW }
    );
    const keys = f.gaps.map((g) => g.key);
    assert.deepEqual(
      keys,
      ['version', 'rules', 'cve', 'config', 'reach'],
      'five distinct problems with five different fixes — a single percentage would cover all of them'
    );
    // ⛔ NOT a percentage anywhere on the object.
    assert.equal('coveragePct' in f, false);
  });

  it('⛔ "never collected" and "collected long ago" are separate gaps', () => {
    const never = deviceContextFacts(healthy({ last_collected_at: null }), { now: NOW });
    const stale = deviceContextFacts(
      healthy({ last_collected_at: ago(FRESH_AFTER_DAYS + 5) }), { now: NOW }
    );
    assert.ok(never.gaps.some((g) => g.key === 'config'));
    assert.ok(stale.gaps.some((g) => g.key === 'config-stale'));
    assert.equal(stale.gaps.some((g) => g.key === 'config'), false,
      'a credential problem and a job that stopped running are not the same gap');
  });

  it('a fully-measured firewall reports no gaps, so its header stays short', () => {
    assert.deepEqual(deviceContextFacts(healthy(), { now: NOW }).gaps, []);
  });

  it('⛔ an unpolled device is a NAMED gap, distinct from a failing one', () => {
    const f = deviceContextFacts(healthy({ pollBand: 'unknown' }), { now: NOW });
    assert.ok(f.gaps.some((g) => g.key === 'reach-unknown'));
    assert.equal(f.gaps.some((g) => g.key === 'reach'), false);
  });
});

describe('the loader', () => {
  it('⛔ NEVER THROWS — a failed aggregate must not take down the page it decorates', async () => {
    const pool = { query: async () => { throw new Error('connection reset'); } };
    assert.equal(await loadDeviceContext(pool, 'd1'), null);
  });

  it('returns null rather than a half-object when the device is not there', async () => {
    const pool = { query: async () => ({ rows: [] }) };
    assert.equal(await loadDeviceContext(pool, 'd1'), null);
  });

  it('is a no-op without a pool or an id', async () => {
    assert.equal(await loadDeviceContext(null, 'd1'), null);
    assert.equal(await loadDeviceContext({ query: async () => ({ rows: [] }) }, null), null);
  });

  it('⛔ CARRIES NO `active = true` FILTER — a deactivated firewall still has pages', () => {
    const src = stripComments(
      fs.readFileSync(path.join(__dirname, '..', 'lib', 'deviceContext.js'), 'utf8'),
      // ⛔ The query's own `--` comments must go too: one of them contains the
      // word `active`, which is exactly what the scan below forbids.
      { sql: true }
    );
    assert.equal(
      /active\s*=\s*true/.test(src),
      false,
      'getDeviceRows filters on active; filtering here would make the header vanish '
      + 'on exactly the devices whose history somebody is reading'
    );
    assert.match(src, /WHERE d\.id = \$1::uuid/, 'parameterised and cast, per CLAUDE.md');
  });

  it('⛔ selects a single device — it does not load the fleet to describe one', () => {
    const src = stripComments(
      fs.readFileSync(path.join(__dirname, '..', 'lib', 'deviceContext.js'), 'utf8')
    );
    assert.equal(/getDeviceRows/.test(src), false);
  });
});

describe('every per-device route renders the shared header', () => {
  const ROUTES = [
    'app/(dashboard)/devices/[id]/page.js',
    'app/(dashboard)/devices/[id]/rules/page.js',
    'app/(dashboard)/devices/[id]/changes/page.js',
    'app/(dashboard)/devices/[id]/vpn/page.js',
    'app/(dashboard)/devices/[id]/snmp/page.js',
    'app/(dashboard)/devices/[id]/analysis/page.js',
  ];

  for (const rel of ROUTES) {
    it(`${rel} mounts DeviceContextHeader with a nav`, () => {
      const src = fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
      assert.match(src, /<DeviceContextHeader/, 'the asset context must travel with the operator');
      assert.match(src, /nav=\{deviceNav\}/);
      assert.match(src, /loadDeviceContext\(pool, device\.id\)/);
    });

    it(`${rel} no longer carries its own "Back to <device>" link`, () => {
      const src = fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
      // ⛔ The header owns the breadcrumb. Two back links one above the other
      // is what six pages had, each pointing somewhere slightly different.
      assert.equal(
        /Back to \{device\.name\}/.test(src),
        false,
        'the context header is the breadcrumb now'
      );
    });
  }

  it('⛔ a page that cannot resolve write capability HIDES Manage rather than offering it', () => {
    for (const rel of ROUTES) {
      const src = fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
      const call = src.slice(src.indexOf('visibleDeviceNav({'));
      const block = call.slice(0, call.indexOf('});') + 3);
      if (!/can:/.test(block)) continue;
      // Where a predicate IS supplied it must be the manage_devices one, not
      // a different capability standing in for it.
      assert.match(block, /manage_devices/, `${rel}: the gate must name the capability it checks`);
    }
  });
});
