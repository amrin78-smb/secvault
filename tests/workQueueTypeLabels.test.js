'use strict';

// tests/workQueueTypeLabels.test.js
//
// Roadmap row 70 — the work queue carried TWO `TYPE_LABEL` maps, they had
// already drifted, and both fell through to the raw type on a miss.
//
// ⛔ THE FAILURE IS SILENT BY CONSTRUCTION, WHICH IS WHY IT NEEDS A BUILD GATE.
// A missing entry does not throw and does not blank anything — it renders a
// snake_case identifier where a label should be, and a filter dropdown offers
// an option that can only ever match nothing. Neither looks like a defect on
// screen; both look like the product.
//
// ⛔ IT PINS BOTH DIRECTIONS. A type with no label is the drift that was found;
// a label for a type nothing emits is how the filter bar came to offer four
// options no source has ever produced. One-ended, this guard would have passed
// over half the defect it was written for.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// ⛔ THE SHARED STRIPPER, NOT A LOCAL PAIR OF REGEXES. Rolling my own here
// used the block-before-line order, which lets a `/*` inside a `//` comment
// open a phantom block — `tests/stripOrder.test.js` caught it on the first
// full run, which is the whole reason that guard exists.
const { stripComments } = require('./stripComments');

const root = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(root, ...p), 'utf8');

// ⛔ DERIVED FROM THE PRODUCER, NEVER A SECOND HAND-WRITTEN LIST. A list typed
// out here is a third copy of the thing whose two copies are the defect.
function emittedTypes() {
  // comments first: this repo has twice had a source scan satisfied by prose.
  const src = stripComments(read('lib', 'engines', 'workQueueData.js'));
  const found = new Set();
  for (const m of src.matchAll(/\btype:\s*'([a-z_]+)'/g)) found.add(m[1]);
  return found;
}

// The shared map, read as source — it is an ES module and this suite is CJS.
function labelledTypes() {
  const src = read('components', 'work', 'workItemTypes.js');
  const body = src.slice(src.indexOf('export const WORK_TYPE_LABEL = {'));
  const map = stripComments(body.slice(0, body.indexOf('\n};')));
  const found = new Set();
  for (const m of map.matchAll(/^\s{2}([a-z_]+):\s*'/gm)) found.add(m[1]);
  return found;
}

describe('⛔ every work-queue item type has exactly one label', () => {
  const emitted = emittedTypes();
  const labelled = labelledTypes();

  it('the scan finds real data on both sides', () => {
    // A vacuous guard is the thing being prevented, so prove it can see.
    assert.ok(emitted.size >= 14, `expected the real type list, got ${emitted.size}`);
    assert.ok(labelled.size >= 14, `expected the real label map, got ${labelled.size}`);
    for (const known of ['cve', 'os_lifecycle', 'tunnel_unknown', 'ingest_silent']) {
      assert.ok(emitted.has(known), `${known} must be found by the producer scan`);
    }
  });

  it('⛔ no emitted type renders as a raw snake_case identifier', () => {
    const missing = [...emitted].filter((t) => !labelled.has(t)).sort();
    assert.deepEqual(missing, [], `these types have no label: ${missing.join(', ')}`);
  });

  it('⛔ no label exists for a type nothing emits', () => {
    // `application`, `ingest`, `device` and `conformance` were four such
    // options in the filter dropdown — each one a filter that could only ever
    // return an empty queue.
    const orphans = [...labelled].filter((t) => !emitted.has(t)).sort();
    assert.deepEqual(orphans, [], `these labels match no source: ${orphans.join(', ')}`);
  });

  it('⛔ neither component declares its own map again', () => {
    for (const file of ['WorkQueueBoard.js', 'WorkQueueFilters.js']) {
      const src = read('components', 'work', file);
      assert.doesNotMatch(src, /const\s+TYPE_LABEL\s*=/,
        `${file} must use the shared map, not a local copy`);
      assert.match(src, /from '\.\/workItemTypes'/, `${file} must import the shared map`);
    }
  });
});
