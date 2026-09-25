'use strict';

// tests/objectUsageOrdering.test.js
//
// ⛔ PINS AN ORDER, BECAUSE THE ORDER IS THE SAFETY PROPERTY.
//
// `lib/engines/objectUsage.js` gained `nat_rules` as a reference surface on
// 2026-09-25. But `collectAndStore` collects NAT in its TOPOLOGY block, and the
// usage analysis used to run earlier, inside the getObjects block — so it read
// the PREVIOUS pull's NAT against this pull's objects and rules.
//
// That is the same mismatched-freshness defect as the 2026-07-18 bug this
// codebase already fixed once, and its dangerous direction is specific:
//
//   • a NAT rule DELETED this cycle merely keeps an object OFF the unused
//     list — under-reporting, which is safe;
//   • a NAT rule ADDED this cycle is invisible, so the object it references is
//     reported UNUSED — a deletion suggestion for an object NAT depends on.
//
// Nothing about that is visible in a unit test of the engine: both orderings
// produce a correct-looking analysis over whatever rows happen to be in the
// table. The defect lives entirely in WHEN it is called, so that is what this
// file asserts.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SRC = path.join(__dirname, '..', 'lib', 'adapters', 'index.js');

// ⛔ Comments stripped FIRST. This repo has repeatedly had a source scan
// satisfied by the very comment explaining the thing it was hunting — three
// separate times in one day. The prose above `runObjectUsageAnalysisForDevice`
// names `storeNatRules`, so an unstripped scan would find the call it wants in
// a sentence rather than in code.
function code() {
  return fs.readFileSync(SRC, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

describe('⛔ object usage analysis runs AFTER NAT collection', () => {
  // ⛔ `await storeNatRules(`, NOT `storeNatRules(`. The function is DEFINED
  // in this same file, so the bare name matches its declaration too -- and the
  // declaration sits ~570 lines ABOVE the analysis call, so an ordering test
  // written against it PASSES WHILE MEASURING NOTHING. Caught by this file's
  // own "exactly once" assertion returning 2.
  const CALL = 'await storeNatRules(';

  it('both calls are present exactly once', () => {
    const c = code();
    const nat = c.split(CALL).length - 1;
    const usage = (c.match(/runObjectUsageAnalysisForDevice\s*\(/g) || []).length;
    assert.equal(nat, 1, 'storeNatRules should be CALLED once');
    assert.equal(usage, 1, 'the usage analysis should be invoked once');
  });

  it('⛔ the analysis is invoked AFTER the NAT rows are stored', () => {
    const c = code();
    const nat = c.indexOf(CALL);
    const usage = c.indexOf('runObjectUsageAnalysisForDevice(');
    assert.ok(nat > -1 && usage > -1, 'both calls must exist');
    assert.ok(
      usage > nat,
      'the usage analysis reads nat_rules, so it must run after storeNatRules — '
      + 'otherwise it analyses this pull\'s objects against the PREVIOUS pull\'s NAT, '
      + 'and an object referenced by a NAT rule added this cycle is reported unused'
    );
  });

  it('⛔ the analysis is gated on NAT having been collected this cycle', () => {
    // Not merely ordered — a device whose NAT collection FAILED must not be
    // analysed against stale NAT either. The 2026-07-18 `objectsCollected`
    // gate exists for exactly this reason one table over.
    const c = code();
    assert.match(c, /natRulesCollected\s*===\s*true/,
      'the gate must test that NAT was actually collected, not merely attempted');
    assert.match(c, /typeof\s+adapter\.getNatRules\s*===\s*'function'/,
      'and it must test the CAPABILITY, so a device with no NAT to collect is not '
      + 'treated as having failed to collect it');
  });

  it('⛔ a failed NAT collection reports its own reason, not the objects one', () => {
    // The operator's next step differs: one sends them to object collection,
    // the other to NAT. A shared message sends half of them to the wrong place.
    const c = code();
    const skips = c.match(/object usage analysis: skipped[^']*/g) || [];
    assert.ok(skips.length >= 2, 'there should be a distinct skip reason per cause');
    assert.ok(
      skips.some((m) => /object collection failed/.test(m)),
      'one names the object-collection failure'
    );
    assert.ok(
      skips.some((m) => /NAT/.test(m)),
      'the other names NAT'
    );
  });

  it('the objects flag is still what gates the analysis at all', () => {
    const c = code();
    assert.match(c, /objectsCollected\s*&&/,
      'a stale object catalogue must still suppress the analysis — the original '
      + '2026-07-18 guard may not be lost in the move');
  });
});
