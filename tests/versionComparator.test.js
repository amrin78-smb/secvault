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
