'use strict';
// tests/versionComparator.test.js
//
// Pins the per-hotfix-train comparison in lib/engines/versionComparator.js.
//
// ⛔ THE INCIDENT THIS EXISTS FOR (2026-09-10). Vendors publish per-train fix
// points, and PAN-OS's top-level `lessThan` bound is the LOWEST of them. For
// CVE-2026-0310 that bound is 11.1.4-h36 while the named checkpoints run up to
// 11.1.16-h2 — including 11.1.13-h12. Every firewall on this fleet runs
// 11.1.13-h5, which is ABOVE the coarse max, so it fell out at the rangeMax
// check and was reported NOT AFFECTED — even though its own train is named
// right there with a fix it has not reached.
//
// Measured live before the fix: 6 advisories x 11 firewalls = 66 assessments
// silently missing, topped by a CVSS 9.2 unauthenticated RCE. Every one of them
// was a FALSE NEGATIVE on a page an operator reads to decide what to patch.
//
// The rule: a named train is a definite answer in BOTH directions.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { isInRange, isSameTrain, isSafeOnMatchingTrain } = require('../lib/engines/versionComparator');

// Real data, copied from advisories.affected_version_ranges in production.
const CVE_2026_0310 = {
  min: '11.1.0',
  max: '11.1.4-h36', // PAN's own lessThan: the LOWEST fix, not the branch ceiling
  checkpoints: ['11.1.16-h2', '11.1.13-h12', '11.1.10-h33', '11.1.7-h10', '11.1.6-h38', '11.1.4-h36'],
};

const FLEET = [11, 1, 13, 5]; // every Palo Alto firewall on the reference fleet

describe('per-hotfix-train fix points decide in BOTH directions', () => {
  test('⛔ BEHIND its train fix and ABOVE the coarse max => VULNERABLE (the regression)', () => {
    assert.equal(
      isInRange('paloalto', FLEET, CVE_2026_0310.min, CVE_2026_0310.max, true, CVE_2026_0310.checkpoints),
      true,
      '11.1.13-h5 needs 11.1.13-h12; it must not escape via a coarse max of 11.1.4-h36'
    );
  });

  test('AT its train fix => not vulnerable', () => {
    const checkpoints = ['11.1.16', '11.1.13-h5', '11.1.10-h30'];
    assert.equal(isInRange('paloalto', FLEET, '11.1.0', '11.1.15', true, checkpoints), false);
  });

  test('PAST its train fix => not vulnerable', () => {
    const checkpoints = ['11.1.16', '11.1.13-h2'];
    assert.equal(isInRange('paloalto', FLEET, '11.1.0', '11.1.15', true, checkpoints), false);
  });

  test('behind its train fix but INSIDE the coarse range => vulnerable (unchanged)', () => {
    const checkpoints = ['11.1.16', '11.1.13-h9'];
    assert.equal(isInRange('paloalto', FLEET, '11.1.0', '11.1.16', true, checkpoints), true);
  });

  test('⛔ an UNLISTED train still falls through to the coarse range, as before', () => {
    // 11.1.11 is named by no checkpoint, so the train rule must not fire at all
    // and the coarse min/max decides. This is the documented fallback; changing
    // it is a separate decision (see the note in versionComparator.js).
    const unlisted = [11, 1, 11, 0];
    assert.equal(
      isInRange('paloalto', unlisted, '11.1.0', '11.1.16', true, CVE_2026_0310.checkpoints),
      true,
      'inside the coarse range => still conservatively flagged'
    );
  });

  test('no checkpoints at all => pure min/max, fully backward compatible', () => {
    assert.equal(isInRange('paloalto', FLEET, '11.1.0', '11.1.16', true, []), true);
    assert.equal(isInRange('paloalto', FLEET, '11.1.0', '11.1.4-h36', true, []), false);
    assert.equal(isInRange('paloalto', FLEET, '11.1.0', '11.1.16', true, undefined), true);
  });

  test('a different MINOR is not the same train', () => {
    // 11.2.13-h12 must never be read as the fix for an 11.1.13 device.
    assert.equal(isSameTrain(FLEET, [11, 2, 13, 12]), false);
    assert.equal(
      isInRange('paloalto', FLEET, '11.1.0', '11.1.4-h36', true, ['11.2.13-h12']),
      false,
      'no same-train checkpoint => coarse range decides, device is above max'
    );
  });

  test('a missing hotfix component counts as 0 on both sides', () => {
    assert.equal(isSafeOnMatchingTrain([11, 1, 13], [11, 1, 13]), true);
    assert.equal(isSafeOnMatchingTrain([11, 1, 13], [11, 1, 13, 1]), false);
    assert.equal(isSafeOnMatchingTrain([11, 1, 13, 1], [11, 1, 13]), true);
  });
});

// ────────────────────────────────────────────────────────────────────────
// Sophos SFOS version parsing (v2.232.x)
//
// ⛔ BOTH VERSION STRINGS BELOW WERE CAPTURED FROM A LIVE APPLIANCE
// (.ai-codex/connectors.md 13b, 2026-11-19), not derived from Sophos
// documentation. They are the contract; do not "tidy" them.
//
// ⛔ THE READABILITY PAIR IS THE POINT OF THIS BLOCK. CLAUDE.md records that
// parseVersion() returns a fabricated [0,0,0,0] for a string it cannot read,
// and that such a tuple read as a silent fleet-wide NOT AFFECTED on the CVE
// path. parseVersionReadable()/isVersionReadable() detect that only because
// every vendor parser funnels its digits through parseForcepointVersion's
// single `Number.isNaN`. A Sophos parser that built its tuple by hand from an
// anchored regex would pass every tuple assertion below and report junk as
// READABLE — so the two isVersionReadable() cases are what actually guard the
// structural choice, and they are asserted in BOTH directions.

const {
  parseVersion,
  parseVersionReadable,
  isVersionReadable,
  compareVersions,
} = require('../lib/engines/versionComparator');

// Verified on the appliance. 22.0.3 is the newer of the two.
const SFOS_22_0_3 = 'SFOS 22.0.3 MR-3-Build576';
const SFOS_22_0_2 = 'SFOS 22.0.2 MR-2-Build546';

describe('sophos: the measured version strings parse to the measured tuples', () => {
  test('⛔ the two live strings => exact tuples, BUILD as the 4th segment', () => {
    assert.deepEqual(parseVersion('sophos', SFOS_22_0_3), [22, 0, 3, 576]);
    assert.deepEqual(parseVersion('sophos', SFOS_22_0_2), [22, 0, 2, 546]);
  });

  test('⛔ MR-n is DISCARDED, not used as a segment', () => {
    // MR-n tracks the patch digit (22.0.2 -> MR-2, 22.0.3 -> MR-3), so it
    // carries no information the patch does not. If MR ever reached the tuple
    // it would land in the 4th slot and these would read [...,3] / [...,2].
    const a = parseVersion('sophos', SFOS_22_0_3);
    const b = parseVersion('sophos', SFOS_22_0_2);
    assert.equal(a[3], 576, 'the 4th segment must be the BUILD, not MR-3');
    assert.equal(b[3], 546, 'the 4th segment must be the BUILD, not MR-2');
    assert.notEqual(a[3], 3);
    assert.notEqual(b[3], 2);
  });

  test('the registry is wired: an unknown slug would fall back to dot-split and FAIL here', () => {
    // 'SFOS 22.0.3 MR-3-Build576' under the unknown-vendor fallback is garbage,
    // so a passing tuple above proves VENDOR_PARSERS.sophos is actually
    // registered rather than silently defaulting.
    assert.notDeepEqual(
      parseVersion('not_a_vendor', SFOS_22_0_3),
      [22, 0, 3, 576],
      'if the fallback produced the right tuple this test would prove nothing'
    );
  });
});

describe('sophos: ordering — this is why the build is in the tuple at all', () => {
  test('22.0.3-Build576 sorts ABOVE 22.0.2-Build546', () => {
    const newer = parseVersion('sophos', SFOS_22_0_3);
    const older = parseVersion('sophos', SFOS_22_0_2);
    assert.equal(compareVersions(newer, older), 1);
    assert.equal(compareVersions(older, newer), -1);
    assert.equal(compareVersions(newer, newer), 0);
  });

  test('⛔ two releases differing ONLY in build compare correctly', () => {
    // The whole reason the build is the 4th segment: with MR there instead, or
    // with the build dropped, these two would be EQUAL and a device on the
    // earlier build would read as already fixed.
    const lower = parseVersion('sophos', 'SFOS 22.0.3 MR-3-Build500');
    const higher = parseVersion('sophos', 'SFOS 22.0.3 MR-3-Build576');
    assert.deepEqual(lower, [22, 0, 3, 500]);
    assert.deepEqual(higher, [22, 0, 3, 576]);
    assert.equal(compareVersions(higher, lower), 1);
    assert.notEqual(compareVersions(higher, lower), 0, 'same patch, different build: never equal');
  });

  test('a major/minor difference still outranks any build', () => {
    assert.equal(
      compareVersions(parseVersion('sophos', 'SFOS 22.0.0 MR-0-Build1'),
        parseVersion('sophos', 'SFOS 21.5.4 MR-4-Build9999')),
      1
    );
  });
});

describe('sophos: readability — the guard against a fabricated zero', () => {
  test('⛔ a real version string is READABLE', () => {
    assert.equal(isVersionReadable('sophos', SFOS_22_0_3), true);
    assert.equal(isVersionReadable('sophos', SFOS_22_0_2), true);
  });

  test('⛔ junk is NOT readable — the tuple it returns is a fabrication', () => {
    assert.equal(isVersionReadable('sophos', 'nonsense'), false);
    const r = parseVersionReadable('sophos', 'nonsense');
    assert.deepEqual(r.tuple, [0, 0, 0, 0], 'the fabricated tuple is still returned...');
    assert.equal(r.readable, false, '...but the FLAG is the contract');
    assert.deepEqual(r.badSegments, ['nonsense'], 'and it names what it could not read');
  });

  test('⛔ decoration with no version digits is NOT readable, even though a build was found', () => {
    // 'SFOS MR-3-Build576' has a perfectly good build and no version at all.
    // Reporting [0,0,0,576] as readable would be a fabricated major.minor.patch
    // on the CVE path.
    assert.equal(isVersionReadable('sophos', 'SFOS MR-3-Build576'), false);
  });

  test('null / undefined / empty are NOT readable and do not throw', () => {
    for (const bad of [null, undefined, '', '   ', 'SFOS', 'v?.?.?']) {
      assert.doesNotThrow(() => parseVersion('sophos', bad));
      assert.equal(isVersionReadable('sophos', bad), false, `${JSON.stringify(bad)} must not read as readable`);
    }
  });

  test('unreadable input returns a tuple of numbers rather than throwing', () => {
    const t = parseVersion('sophos', 'nonsense');
    assert.ok(Array.isArray(t));
    assert.ok(t.every((n) => Number.isInteger(n)));
  });

  test('⛔ an unreadable sophos BOUND can never narrow a range to nothing', () => {
    // The consequence the readability flag exists for: with both bounds
    // unreadable isInRange decides NOTHING (false, counted as a coverage gap),
    // and a readable min alone still decides. If the sophos parser bypassed the
    // reporter, the unreadable max would instead have excluded every real
    // version and the advisory would read NOT AFFECTED.
    const device = [22, 0, 3, 576];
    assert.equal(isInRange('sophos', device, 'nonsense', 'nonsense', false, []), false);
    assert.equal(isInRange('sophos', device, 'SFOS 22.0.0', 'nonsense', false, []), true,
      'the readable min decides; the unreadable max is ignored, never used to exclude');
  });
});

describe('sophos: a version string with no Build suffix', () => {
  // ⛔ DECIDED AND DOCUMENTED: it is READABLE and the 4th segment pads with 0.
  // 'SFOS 21.5.1' -> [21, 5, 1, 0]. No build number is invented.
  //
  // Readable, because a version with no build stated is a genuinely readable
  // version: the appliance reports its build in a separate `Firmware Build`
  // field, and any advisory/CPE bound for this vendor will carry no build at
  // all — calling those unreadable would leave isInRange() with no readable
  // bound and decide nothing, turning real verdicts into coverage gaps.
  //
  // 0 rather than a guess, because that is already what compareVersions() pads
  // a short tuple with and what parsePanosVersion() does for an absent `-hN`.
  // The stated consequence: such a version sorts at the FLOOR of its patch
  // level, so against a vulnerable range's upper bound it stays INSIDE the
  // range (flagged) rather than escaping it — the widen-an-uncertain-bound
  // direction CLAUDE.md requires.
  test('⛔ no Build => [major, minor, patch, 0], READABLE, nothing fabricated', () => {
    assert.deepEqual(parseVersion('sophos', 'SFOS 21.5.1'), [21, 5, 1, 0]);
    assert.equal(isVersionReadable('sophos', 'SFOS 21.5.1'), true);
    assert.deepEqual(parseVersionReadable('sophos', 'SFOS 21.5.1').badSegments, []);
  });

  test('a bare dotted version (what a feed/CPE bound looks like) is readable too', () => {
    assert.deepEqual(parseVersion('sophos', '22.0.3'), [22, 0, 3, 0]);
    assert.equal(isVersionReadable('sophos', '22.0.3'), true);
  });

  test('MR with no Build is still readable and still discards MR', () => {
    assert.deepEqual(parseVersion('sophos', 'SFOS 22.0.3 MR-3'), [22, 0, 3, 0]);
    assert.equal(isVersionReadable('sophos', 'SFOS 22.0.3 MR-3'), true);
  });

  test('⛔ a missing build sorts at the FLOOR of its patch level, so it stays FLAGGED', () => {
    const noBuild = parseVersion('sophos', 'SFOS 22.0.3');
    const withBuild = parseVersion('sophos', SFOS_22_0_3);
    assert.equal(compareVersions(noBuild, withBuild), -1);
    assert.equal(
      isInRange('sophos', noBuild, 'SFOS 22.0.0', SFOS_22_0_3, true, []),
      true,
      'an unstated build must not let a device escape a vulnerable range'
    );
  });

  test('the tuple is always 4 segments, never longer', () => {
    for (const s of [SFOS_22_0_3, 'SFOS 21.5.1', '22.0.3', '22.0.3.7', 'nonsense']) {
      assert.equal(parseVersion('sophos', s).length, 4, `${s} must yield 4 segments`);
    }
  });

  test('a genuine 4th dotted segment is not clobbered when there is no Build suffix', () => {
    // Same rule as parsePanosVersion's: an explicit suffix owns slot 4,
    // otherwise only pad. Unmeasured on this vendor, pinned so the house
    // pattern is not quietly dropped.
    assert.deepEqual(parseVersion('sophos', '22.0.3.7'), [22, 0, 3, 7]);
  });
});

describe('sophos: case and separator tolerance (stated assumptions, not measurements)', () => {
  // ⛔ ONLY THE TWO STRINGS AT THE TOP OF THIS BLOCK ARE MEASURED. These cases
  // pin the deliberately-wider separator/case handling so that loosening or
  // tightening it is a visible decision rather than an accident.
  test('lower case and a hyphen before MR parse identically', () => {
    assert.deepEqual(parseVersion('sophos', 'sfos 22.0.3 mr-3-build576'), [22, 0, 3, 576]);
    assert.deepEqual(parseVersion('sophos', 'SFOS 22.0.3-MR-3-Build576'), [22, 0, 3, 576]);
  });

  test('surrounding whitespace is tolerated', () => {
    assert.deepEqual(parseVersion('sophos', `  ${SFOS_22_0_3}  `), [22, 0, 3, 576]);
  });
});
