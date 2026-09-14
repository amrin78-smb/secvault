'use strict';
// Pins lib/canonicalJson.js and the two guards that depend on it.
//
// ⛔ THE BUG THIS EXISTS TO PREVENT, because it was invisible for months and
// every symptom looked like success:
//
// PostgreSQL's jsonb sorts object keys by LENGTH then bytes — it is a parsed
// binary form, not the text handed to it. So a range written as
// {min,max,vulnerable,exclude_fixed,...} reads back as
// {max,min,vulnerable,exclude_fixed,...} (lengths 3,3,10,13,19).
// JSON.stringify preserves each object's OWN key order, so comparing the
// stringified database value against the stringified freshly-built value
// returns false for two IDENTICAL values, always.
//
// backfillPaloAltoVersionRanges used exactly that comparison as its "already
// clean — nothing to do" guard. It could never fire. The backfill rewrote the
// same 302 advisory rows with byte-identical data on every deploy, logged
// "cleaned up 302" each time, and left advisories at 18.6% dead tuples.
//
// ⛔ A GUARD THAT CANNOT FIRE IS WORSE THAN NO GUARD, because the code reads as
// though the case is handled and the log line reads as successful maintenance.
// Nothing in the data was ever wrong — which is precisely why nobody looked.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { canonicalJson, jsonEquivalent, canonicalise } = require('../lib/canonicalJson');

describe('order independence', () => {
  it('⛔ the exact live case: jsonb key order vs JS insertion order', () => {
    // Read back from jsonb (sorted by key length, then bytes):
    const fromDb = {
      max: '9.1.2', min: '9.1', vulnerable: true, exclude_fixed: true,
      safe_exact_versions: ['9.1.3'],
    };
    // Built in JS by extractAffectedRanges():
    const fresh = {
      min: '9.1', max: '9.1.2', vulnerable: true, exclude_fixed: true,
      safe_exact_versions: ['9.1.3'],
    };
    assert.notEqual(JSON.stringify(fromDb), JSON.stringify(fresh), 'precondition: the old guard saw these as different');
    assert.equal(jsonEquivalent(fromDb, fresh), true, 'the new guard must see them as the same');
  });

  it('sorts nested object keys too', () => {
    assert.equal(jsonEquivalent({ a: { z: 1, y: 2 } }, { a: { y: 2, z: 1 } }), true);
  });

  it('handles the real shape: an array of range objects', () => {
    const a = [{ max: '1.2', min: '1.0' }, { max: '2.2', min: '2.0' }];
    const b = [{ min: '1.0', max: '1.2' }, { min: '2.0', max: '2.2' }];
    assert.equal(jsonEquivalent(a, b), true);
  });
});

describe('⛔ it must still detect REAL differences', () => {
  it('a changed value is not equivalent', () => {
    assert.equal(jsonEquivalent({ min: '9.1', max: '9.1.2' }, { min: '9.1', max: '9.1.3' }), false);
  });

  it('a missing key is not equivalent', () => {
    assert.equal(jsonEquivalent({ min: '9.1', max: '9.1.2' }, { min: '9.1' }), false);
  });

  it('⛔ ARRAY ORDER IS PRESERVED — it carries meaning', () => {
    // Sorting arrays would make genuinely different rangesets compare equal and
    // suppress a real repair. Only OBJECT KEYS are order-insensitive.
    assert.equal(jsonEquivalent(['a', 'b'], ['b', 'a']), false);
  });

  it('distinguishes empty from absent in the way the guards rely on', () => {
    assert.equal(jsonEquivalent([], []), true);
    assert.equal(jsonEquivalent([], [{ min: '1.0' }]), false);
  });

  it('does not conflate types', () => {
    assert.equal(jsonEquivalent({ a: 1 }, { a: '1' }), false);
    assert.equal(jsonEquivalent({ a: false }, { a: null }), false);
  });
});

describe('robustness', () => {
  it('survives null and undefined', () => {
    assert.equal(canonicalJson(undefined), 'null');
    assert.equal(jsonEquivalent(null, null), true);
    assert.equal(canonicalise(null), null);
  });

  it('does not mutate its input', () => {
    const input = { b: 1, a: 2 };
    canonicalJson(input);
    assert.deepEqual(Object.keys(input), ['b', 'a']);
  });
});

describe('⛔ both backfill guards actually use it', () => {
  const fs = require('fs');
  for (const file of ['../lib/feeds/paloalto.js', '../lib/feeds/nvd.js']) {
    it(`${file} compares with jsonEquivalent, not JSON.stringify`, () => {
      const src = fs.readFileSync(require.resolve(file), 'utf8');
      assert.ok(src.includes('jsonEquivalent('), 'must use the order-independent comparison');
      // The specific broken pattern must not come back.
      assert.equal(
        /currentRangesJson === freshRangesJson/.test(src), false,
        'string comparison of a jsonb value against a JS-built value can never fire'
      );
    });
  }

  it('⛔ the ledger revision was bumped so installs re-run the fixed repair', () => {
    // Fixing a gated repair without bumping its revision means the correction
    // never runs anywhere it already completed — the exact failure the revision
    // mechanism exists to prevent.
    const src = fs.readFileSync(require.resolve('../lib/migrate.js'), 'utf8');
    for (const name of ['palo-alto-version-ranges', 'nvd-native-version-ranges']) {
      const m = src.match(new RegExp(`isDone\\(pool, '${name}', (\\d+)\\)`));
      assert.ok(m, `${name} must still be gated`);
      assert.ok(Number(m[1]) >= 2, `${name} revision must be bumped past 1 now its logic changed`);
    }
  });
});
