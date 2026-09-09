'use strict';
// The two REMAINING CVE-coverage call sites, pinned at the source level.
//
// ⛔ WHY THIS FILE EXISTS. tests/cveAssessmentCoverage.test.js pins the
// producer (versionMatcher.js stamps devices.last_cve_assessed_at) and the one
// consumer that is a pure engine (deviceInventory.js's computeTiles). Two more
// consumers were shipped in the same wave and neither is reachable from a
// CommonJS test at all:
//
//   components/devices/OverviewCveCard.js   — the per-device Overview tab
//   components/vulnerability/CvePostureTab.js — the fleet CVE Posture tab
//
// Both are ESM async React SERVER components containing JSX. `node:test` runs
// CommonJS here, Node cannot parse JSX in any module system, and each file
// opens `lib/db`'s pool at import time — so there is no way to `require()`
// them, hand them a stub pool and assert on what they render. The choice is a
// source-level pin or no pin at all, and the behaviour being protected is the
// single most-repeated bug class in this codebase (a failed/absent read
// rendered as a confident zero), so it gets a pin.
//
// ⛔ WHAT THIS DOES AND DOES NOT PROVE. It proves the two decision expressions
// and the coverage SQL still have the SHAPE that makes them honest: two
// signals, ORed; the gate driven by evidence of a RUN and not by a version
// row; a NotMeasured with a reason on the "no evidence" branch. It does not
// execute a component, does not render, and does not touch a database.
// tests/sqlColumns.test.js separately proves every column named below exists,
// and tests/jsxSyntax.test.js proves both files parse.
//
// ⛔ CONSERVATIVE, like every other repo-wide lint here: assertions run over
// whitespace-COLLAPSED source, so reformatting, re-wrapping and re-indenting
// cannot fail this test. Only a change of meaning can — `||` becoming `&&`,
// the gate moving back onto devices_with_version, a branch losing its
// NotMeasured. If one of these ever fires on a legal rewrite, widen the
// pattern; do not lower the assertion.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');

// Whitespace-collapsed source. Comments are LEFT IN deliberately for the
// "stale claim" assertions below, and stripped where a comment could satisfy a
// code assertion by accident (see codeOf).
function read(...parts) {
  return fs.readFileSync(path.join(REPO, ...parts), 'utf8');
}
function flat(src) {
  return src.replace(/\s+/g, ' ');
}
// Code only: line comments and block comments removed, then collapsed. Every
// assertion about behaviour uses THIS, so a comment that merely describes the
// right thing can never stand in for code that does it.
function codeOf(src) {
  return flat(src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^\s*\/\/[^\n]*$/gm, ' '));
}

const OVERVIEW_SRC = read('components', 'devices', 'OverviewCveCard.js');
const POSTURE_SRC = read('components', 'vulnerability', 'CvePostureTab.js');
const OVERVIEW = codeOf(OVERVIEW_SRC);
const POSTURE = codeOf(POSTURE_SRC);

// --------------------------------------------------------------------------
// OverviewCveCard — the per-device card
// --------------------------------------------------------------------------

describe('OverviewCveCard gates its three zeros on evidence of a run', () => {
  it('reads the assessment stamp, and never COALESCEs it', () => {
    // ⛔ The stamp is the only thing that separates "assessed and clean" from
    // "never assessed" for a device that HAS a version — the reconciliation
    // DELETE leaves a clean device holding zero rows and no assessed_at.
    assert.match(OVERVIEW, /d\.last_cve_assessed_at/, 'the card must read the stamp');
    assert.ok(
      !/COALESCE\s*\(\s*d\.last_cve_assessed_at/i.test(OVERVIEW),
      'NULL is the answer, not a value to be defaulted away'
    );
  });

  it('ORs the two signals rather than requiring both', () => {
    // ⛔ ANDing them would report the entire already-deployed fleet as
    // unassessed until the matcher next ran, and would also mis-report a
    // genuinely clean device (stamp, zero rows) as unmeasured. Either signal
    // alone is proof: the stamp records the run, and rows can only exist
    // because a run made them.
    assert.match(
      OVERVIEW,
      /const assessed = Boolean\(lastAssessedAt\) \|\| total > 0;/,
      'assessed must be (stamp OR any assessment row), never AND'
    );
    // `total` is the count of ALL bands — a device whose only findings are
    // monitor-band is assessed even though both visible band tiles read zero.
    assert.ok(
      !/WHERE dca\.device_id = \$1 AND dca\.priority_band/i.test(OVERVIEW),
      'the assessment query must not filter by band, or monitor-only devices read as unassessed'
    );
  });

  it('renders NotMeasured with a reason when neither signal is present', () => {
    // ⛔ THE "WE COULD NOT MEASURE THIS" CASE — the one that regresses
    // silently, because the wrong answer is a plausible integer rather than a
    // crash. Three tiles, three NotMeasured branches, all driven by the one
    // reason string.
    assert.match(
      OVERVIEW,
      /const unmeasuredReason = !hasVersion \? NO_VERSION_REASON : assessed \? null : NOT_ASSESSED_REASON;/,
      'the unmeasured gate must consider the version case and the no-evidence case, in that order'
    );
    const branches = OVERVIEW.match(/unmeasuredReason \? \( <NotMeasured reason=\{unmeasuredReason\} \/>/g) || [];
    assert.equal(branches.length, 3, 'Patch Now, Scheduled and Total Tracked CVEs each need the branch');
    // Every reason string is non-empty prose: a bare em-dash with no tooltip
    // is only marginally better than a fabricated zero.
    for (const name of ['NO_VERSION_REASON', 'NOT_ASSESSED_REASON']) {
      const m = OVERVIEW.match(new RegExp(`const ${name} = '([^']+)'`));
      assert.ok(m && m[1].length > 60, `${name} must explain WHY the value is absent`);
      assert.match(m[1], /not a clean result/, `${name} must say what it is NOT`);
    }
  });

  it('keeps a real, earned zero as a muted number carrying its assessment time', () => {
    // ⛔ A measured zero is still a zero, not a NotMeasured — and it is muted,
    // never green and never a "Clear" badge: "no advisory currently matches
    // this firmware" is a fact about today's feed, not a clean bill of health.
    assert.match(OVERVIEW, /var\(--text-muted\)/, 'a measured zero stays muted');
    assert.ok(!/var\(--green\)/.test(OVERVIEW), 'an earned zero must never be coloured as good news');
    assert.match(
      OVERVIEW,
      /function assessedTitle\(lastAssessedAt\)/,
      'the tooltip on a measured value must carry when it was measured'
    );
  });

  it('defines AssessedValue at module top level, not inside the card', () => {
    // CLAUDE.md's React rule: a component defined inside another remounts on
    // every render. Asserted as a position — AssessedValue's declaration must
    // come BEFORE the default export, not inside it.
    const helperAt = OVERVIEW.indexOf('function AssessedValue(');
    const cardAt = OVERVIEW.indexOf('export default async function OverviewCveCard');
    assert.ok(helperAt >= 0 && cardAt >= 0);
    assert.ok(helperAt < cardAt, 'AssessedValue must be a module-top-level component');
  });

  it('no longer claims the versioned-but-zero case is unfixable', () => {
    // ⛔ REGRESSION PIN ON A COMMENT, deliberately. The old ⛔ block asserted
    // this case was indistinguishable "by construction" and pointed the reader
    // away from fixing it. A stale comment on a security product is not
    // cosmetic — it sends the next session to the wrong conclusion with
    // confidence. The correction must survive.
    assert.ok(
      !/does not exist yet/i.test(OVERVIEW_SRC),
      'the stamp exists; no comment here may say otherwise'
    );
    assert.ok(
      !/still CANNOT tell apart/i.test(OVERVIEW_SRC),
      'the old "cannot tell apart" claim must not come back'
    );
    assert.match(OVERVIEW_SRC, /NO LONGER TRUE/, 'the correction must state what changed');
  });
});

// --------------------------------------------------------------------------
// CvePostureTab — the fleet coverage note
// --------------------------------------------------------------------------

describe('CvePostureTab counts coverage by assessment, not by version', () => {
  it('counts a device as covered on EITHER signal', () => {
    // ⛔ The old filter counted only devices_with_version, which is a
    // PRECONDITION for assessment and not evidence of one — so a versioned
    // device the matcher had never reached was silently credited as covered
    // and the CoverageNote understated the gap.
    assert.match(
      POSTURE,
      /WHERE d\.last_cve_assessed_at IS NOT NULL OR EXISTS \(SELECT 1 FROM device_cve_assessments dca WHERE dca\.device_id = d\.id\) \)::int AS devices_assessed/,
      'devices_assessed must be (stamp OR any assessment row)'
    );
    assert.ok(
      !/last_cve_assessed_at IS NOT NULL AND EXISTS/i.test(POSTURE),
      'ANDing the signals would report the whole fleet as uncovered on day one'
    );
  });

  it('feeds CoverageNote the assessed count, not the versioned count', () => {
    assert.match(
      POSTURE,
      /<CoverageNote covered=\{coverage\.devices_assessed\} total=\{coverage\.active_devices\}/,
      'the stated coverage must be the assessed count'
    );
    assert.ok(
      !/covered=\{coverage\.devices_with_version\}/.test(POSTURE),
      'devices_with_version is a lower bound, never the coverage figure'
    );
  });

  it('gates the four tiles on devices_assessed', () => {
    assert.match(
      POSTURE,
      /const nothingAssessed = coverage\.devices_assessed === 0;/,
      'the tile gate must be evidence of a run'
    );
    const tiles = POSTURE.match(/nothingAssessed \? <NotMeasured reason=\{notAssessedReason\} \/>/g) || [];
    assert.equal(tiles.length, 4, 'Unique CVEs, Patch Now, Scheduled and Monitor each need the branch');
  });

  it('names the right reason for each way coverage can be missing', () => {
    // ⛔ "cannot be assessed at all" and "has not been assessed yet" are
    // different operator actions — collect a firmware version, versus wait for
    // or trigger the next match. devices_with_version survives only to choose
    // between those two sentences.
    assert.match(POSTURE, /coverage\.active_devices === 0 \?/, 'an empty fleet says so plainly');
    assert.match(
      POSTURE,
      /coverage\.devices_with_version === 0 \?/,
      'the no-version wording must still be reachable'
    );
    for (const phrase of ['not a clean fleet', 'nothing to assess']) {
      assert.ok(POSTURE.includes(phrase), `the reason strings must include "${phrase}"`);
    }
  });

  it('has dropped the stale "does not exist yet" claim', () => {
    assert.ok(
      !/does not exist yet/i.test(POSTURE_SRC),
      'devices.last_cve_assessed_at exists; no comment here may say otherwise'
    );
  });
});

// --------------------------------------------------------------------------
// The rule both files must obey
// --------------------------------------------------------------------------

describe('neither call site infers an assessment from something merely correlated', () => {
  // ⛔ Only the stamp and the rows a run produced are evidence that a run
  // happened. A last_collected_at, a non-empty ruleset, an SNMP sample or a
  // connectivity check all correlate with a healthy device and prove NOTHING
  // about CVE matching — treating any of them as coverage is the same class of
  // error as the version row was.
  const FORBIDDEN = [
    'last_collected_at',
    'last_connectivity_ok',
    'last_connectivity_checked_at',
    'rule_count',
  ];
  for (const [name, code] of [
    ['OverviewCveCard', OVERVIEW],
    ['CvePostureTab', POSTURE],
  ]) {
    it(`${name} never reads a correlate as coverage`, () => {
      const found = FORBIDDEN.filter((f) => code.includes(f));
      assert.deepEqual(found, [], `${name} must not derive assessment coverage from ${found.join(', ')}`);
    });
  }
});
