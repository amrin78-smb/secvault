'use strict';

// ⛔ ROADMAP ROW 24: `parseVersion` RETURNS A FABRICATED ZERO FOR A VERSION IT CANNOT READ.
//
// `parseVersion('fortinet', 'nope')` is `[0,0,0,0]`, which every conceivable target compares
// "at or above" — this codebase's most-repeated bug class, living in a version parser on the
// CVE path. It does console.warn, so it is not literally silent, but a log line is not a
// contract and the RETURN VALUE is what callers act on.
//
// `parseVersion` is deliberately UNCHANGED: making it return null is a breaking change across
// versionMatcher, feeds/nvd, feeds/paloalto and every adapter's version_tuple. What is added is
// a readability signal derived from the SAME parsers (all five funnel through
// parseForcepointVersion's single Number.isNaN), plus the one call-site conversion where a
// fabricated zero became a vulnerability verdict: `isInRange`.
//
// The two bounds failed in OPPOSITE directions, which is why the fix is asymmetric:
//   unreadable MIN → never excluded anything (harmless, now deliberate)
//   unreadable MAX → excluded EVERY real version, so a live CVE read NOT AFFECTED

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  parseVersion,
  parseVersionReadable,
  isVersionReadable,
  isInRange,
} = require('../lib/engines/versionComparator');
const { isUnassessableAdvisory, countUnassessableAdvisories } =
  require('../lib/engines/versionMatcher');

describe('parseVersionReadable reports readability for every vendor', () => {
  const READABLE = [
    ['fortinet', 'v7.4.3,build2573', [7, 4, 3, 0]],
    ['paloalto', '11.1.2-h3', [11, 1, 2, 3]],
    ['cisco_asa', '9.18(4)15', [9, 18, 4, 15]],
    ['checkpoint', 'R81.20 Take 41', [81, 20, 41, 0]],
    ['sangfor', '8.0.85', [8, 0, 85]],
    ['forcepoint', '6.10.21', [6, 10, 21]],
  ];

  it('reports readable: true and the correct tuple for every vendor\'s real format', () => {
    for (const [vendor, str, tuple] of READABLE) {
      const r = parseVersionReadable(vendor, str);
      assert.equal(r.readable, true, `${vendor} ${str}`);
      assert.deepEqual(r.tuple, tuple, `${vendor} ${str}`);
      assert.deepEqual(r.badSegments, []);
    }
  });

  it('⛔ reports readable: false for input that produces a fabricated zero', () => {
    const UNREADABLE = [
      ['fortinet', 'nope'],
      ['fortinet', null],
      ['fortinet', undefined],
      ['paloalto', 'Not applicable'], // the live string that reported a KEV row as CLEARED
      ['cisco_asa', 'N/A'],
      ['checkpoint', 'gold'], // live, CVE-2007-2689
      ['checkpoint', 'vsx_ng_with_application_intelligence'], // live, CVE-2004-0469
      ['checkpoint', 'ng'], // live, CVE-2002-2405
      ['sangfor', 'unknown'],
      ['forcepoint', 'TBD'],
      ['unknown_vendor', 'x'],
    ];
    for (const [vendor, str] of UNREADABLE) {
      assert.equal(
        isVersionReadable(vendor, str),
        false,
        `${vendor} / ${String(str)} must not be reported as a readable version`
      );
    }
  });

  it('⛔ is derived from the parser, not a second regex — the tuple still comes back', () => {
    // A separate readability test that disagreed with what parsing actually does would be
    // worse than none. Same call, same parsers; the flag is the only addition.
    const r = parseVersionReadable('fortinet', 'nope');
    assert.deepEqual(r.tuple, parseVersion('fortinet', 'nope'));
    assert.equal(r.readable, false);
    assert.ok(r.badSegments.length > 0, 'the offending segment is named');
  });

  it('parseVersion itself is unchanged — still a tuple, never null', () => {
    // The whole point of the additive approach: nothing on the CVE path breaks.
    assert.deepEqual(parseVersion('fortinet', 'nope'), [0, 0, 0, 0]);
    assert.deepEqual(parseVersion('fortinet', 'v7.4.3,build2573'), [7, 4, 3, 0]);
  });
});

describe('isInRange: an unreadable bound never narrows the range', () => {
  const DEVICE = parseVersion('fortinet', 'v7.4.3,build2573'); // [7,4,3,0]

  it('⛔ an unreadable MAX no longer clears a device that the min includes', () => {
    // This is the dangerous half. [0,0,0,0] as a max excluded every real version, so the
    // advisory read NOT AFFECTED — a fabricated zero silently clearing a live CVE.
    assert.equal(
      isInRange('fortinet', DEVICE, '7.0.0', 'Not applicable', false, []),
      true,
      'with an unreadable ceiling the readable floor must still decide'
    );
  });

  it('an unreadable MIN leaves the max in charge', () => {
    assert.equal(isInRange('fortinet', DEVICE, 'N/A', '7.6.0', false, []), true);
    assert.equal(
      isInRange('fortinet', DEVICE, 'N/A', '7.0.0', false, []),
      false,
      'a readable ceiling below the device still excludes it'
    );
  });

  it('⛔ a range with NO readable bound decides nothing — never "affects everything"', () => {
    // Seven live Check Point advisories carry a legacy CPE product name in BOTH version
    // fields. CLAUDE.md keeps those strings because version matching makes them incapable of
    // producing a false finding; widening both bounds would have broken exactly that.
    assert.equal(
      isInRange(
        'checkpoint',
        parseVersion('checkpoint', 'R81.20 Take 41'),
        'vsx_ng_with_application_intelligence',
        'vsx_ng_with_application_intelligence',
        false,
        []
      ),
      false
    );
  });

  it('a range with no bounds AT ALL still means "all versions"', () => {
    // Distinct from a bound nobody could read: an absent bound is a real answer.
    assert.equal(isInRange('fortinet', DEVICE, null, null, false, []), true);
  });

  it('⛔ an unreadable safe checkpoint decides nothing in either direction', () => {
    // That loop RETURNS on a train match, so an all-zero tuple could settle the verdict.
    //
    // ⛔ THE DEVICE VERSION HAS TO BE UNREADABLE TOO FOR THIS TO BITE, and the first draft of
    // this test missed that: isSameTrain([11,1,13],[0,0,0]) is false, so a readable device
    // falls through to the range either way and the assertion could not fail. Both tuples
    // all-zero is the combination that matters — a garbage device version meeting a garbage
    // train name — and isSameTrain(zero, zero) is TRUE, so without the guard the checkpoint
    // branch returns `hotfixOf(0) < hotfixOf(0)` = false and the advisory reads NOT AFFECTED
    // off two values nobody could read.
    const unreadableDevice = parseVersion('paloalto', 'nope');
    assert.equal(
      isInRange('paloalto', unreadableDevice, null, null, false, ['Not applicable']),
      true,
      'an unparseable train name must not settle the verdict'
    );

    // And it still falls through to a readable range rather than answering for it.
    assert.equal(
      isInRange('paloalto', parseVersion('paloalto', '11.1.13-h5'), '11.0.0', '11.2.0', false,
        ['Not applicable']),
      true
    );
  });

  it('a READABLE safe checkpoint still decides, exactly as before', () => {
    // The other half: skipping every checkpoint would pass the test above.
    assert.equal(
      isInRange('paloalto', parseVersion('paloalto', '11.1.13-h12'), '11.0.0', '11.1.4', false,
        ['11.1.13-h12']),
      false,
      'a device AT its own train\'s named fix point is not vulnerable'
    );
    assert.equal(
      isInRange('paloalto', parseVersion('paloalto', '11.1.13-h5'), '11.0.0', '11.1.4', false,
        ['11.1.13-h12']),
      true,
      'a device BEHIND its own train\'s fix point is vulnerable despite the coarse max'
    );
  });

  it('readable bounds behave exactly as before — the no-regression cases', () => {
    assert.equal(isInRange('fortinet', DEVICE, '7.0.0', '7.6.0', false, []), true);
    assert.equal(isInRange('fortinet', DEVICE, '7.6.0', '7.8.0', false, []), false);
    assert.equal(isInRange('fortinet', DEVICE, '7.0.0', '7.4.3', false, []), true);
    assert.equal(
      isInRange('fortinet', DEVICE, '7.0.0', '7.4.3', true, []),
      false,
      'exclude_fixed still excludes the exact boundary'
    );
  });
});

describe('isUnassessableAdvisory counts a bound-less range as a gap', () => {
  const legacy = (bound) => ({
    cve_id: 'CVE-2004-0469',
    vendor: 'checkpoint',
    matchability: 'matched',
    affected_version_ranges: [{ min: bound, max: bound }],
  });

  it('⛔ an advisory whose only range has two unreadable bounds is unassessable', () => {
    assert.equal(isUnassessableAdvisory(legacy('vsx_ng_with_application_intelligence')), true);
    assert.equal(isUnassessableAdvisory(legacy('gold')), true);
    assert.equal(isUnassessableAdvisory(legacy('ng')), true);
  });

  it('one readable bound anywhere makes the advisory assessable', () => {
    assert.equal(
      isUnassessableAdvisory({
        vendor: 'checkpoint',
        matchability: 'matched',
        affected_version_ranges: [{ min: 'gold', max: 'R81.20' }],
      }),
      false
    );
  });

  it('one usable range among several makes the advisory assessable', () => {
    assert.equal(
      isUnassessableAdvisory({
        vendor: 'checkpoint',
        matchability: 'matched',
        affected_version_ranges: [{ min: 'gold', max: 'gold' }, { min: 'R80.10', max: 'R81.20' }],
      }),
      false
    );
  });

  it('⛔ a range with no bounds at all is NOT unassessable — it is an "all versions" answer', () => {
    assert.equal(
      isUnassessableAdvisory({
        vendor: 'fortinet', matchability: 'matched', affected_version_ranges: [{}],
      }),
      false
    );
  });

  it('⛔ empty and NULL range lists are left to the matchability rules, unchanged', () => {
    // Treating NULL as unassessable would make every pre-column advisory vanish from matching
    // on the first deploy — a far larger and more silent change than the bug being fixed.
    assert.equal(
      isUnassessableAdvisory({ vendor: 'fortinet', matchability: 'matched', affected_version_ranges: [] }),
      false
    );
    assert.equal(
      isUnassessableAdvisory({ vendor: 'fortinet', matchability: null, affected_version_ranges: null }),
      false
    );
  });

  it('the count uses the same predicate the matcher skips on', () => {
    const list = [
      legacy('gold'),
      { vendor: 'fortinet', matchability: 'matched', affected_version_ranges: [{ min: '7.0.0', max: '7.6.0' }] },
      { vendor: 'fortinet', matchability: 'unmatchable', affected_version_ranges: [] },
    ];
    assert.equal(countUnassessableAdvisories(list), 2);
  });
});
