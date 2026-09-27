'use strict';

// tests/fixBoundary.test.js
//
// ⛔ THE GUARD THAT COST FOUR DEPLOYS, AND THE TEST THAT COULD NOT CATCH IT.
//
// "Does this advisory carry a usable fix boundary" is asked in FOUR places: the
// hub's JS predicate, the hub's SQL `WHERE`, and the Fortinet and Palo Alto
// ON CONFLICT clauses. They were four separate expressions.
//
//   v2.186.0/.1 — fixed the JS predicate; the SQL kept the old rule, so every
//                 repair was permitted by one half and refused by the other.
//                 80 rows reported repaired, 0 written, because
//                 `stats.repaired++` counted INTENT.
//   v2.186.2    — fixed that pair.
//   2026-09-27  — review found the halves STILL disagreed, because the SQL used
//                 jsonb containment (`@> '[{"exclude_fixed": true}]'`), which is
//                 BLIND TO `max`:
//
//                   local {exclude_fixed:true, max:null}   JS: repair  SQL: refuse
//
//                 And `paloalto.js` never got the guard at all, so it reverted
//                 the hub's repair every cycle: `updated: 20` on twelve
//                 consecutive runs with zero surviving writes.
//
// ⛔ THE OLD TEST WAS FOUR REGEXES OVER THE SQL STRING'S TEXT, asserting each
// half's wording separately. It never constructed an input where the halves
// disagreed — which is why the disagreement above passed a green suite. It was
// demonstrated inert: wrapping the widened SQL disjunct in a block comment left
// all four assertions passing.
//
// So the definition now lives in ONE module and the SQL is GENERATED from it.
// The halves cannot drift, and the tests below check that property rather than
// the spelling of either half.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  hasUsableFixBoundary, isUnrecognisedRanges, hasUsableFixBoundarySql,
} = require('../lib/feeds/fixBoundary');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

// ⛔ Comments stripped FIRST. This repo has repeatedly had a source scan
// satisfied by the comment explaining the thing it hunts — and the files below
// deliberately discuss jsonb containment in prose while no longer using it.
//
// ⛔ AND THE ORDER OF THE TWO STRIPPERS IS LOAD-BEARING. The obvious order —
// block comments, then line comments — silently ate 216 LINES OF REAL CODE from
// `lib/feeds/paloalto.js`, including two of the three matches this file looks
// for. The cause is a line comment at paloalto.js:407 containing the text
// `feeds/*.js`: its `/*` is not a block-comment opener, but a block-first
// stripper cannot know that, so it swallowed everything to the next `*/` 216
// lines later. Measured: 46,914 chars -> 35,219, and 3 matches -> 1.
//
// A scan over that residue would have reported "paloalto.js does not use the
// shared generator" when it does — a FALSE FAILURE here, which is the safe
// direction, but the identical mechanism produces a false PASS for any scan
// hunting a forbidden pattern. Strip LINE comments first: after that, a `/*`
// inside one is already gone.
function code(rel) {
  return read(rel)
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*--.*$/gm, '');
}

describe('⛔ a boundary with no max names no release', () => {
  it('a real boundary is usable', () => {
    assert.equal(hasUsableFixBoundary([{ exclude_fixed: true, max: '7.4.11' }]), true);
    assert.equal(hasUsableFixBoundary([
      { exclude_fixed: false, max: '1.0' },
      { exclude_fixed: true, max: '2.0' },
    ]), true, 'one usable entry among several is enough');
  });

  it('⛔ these all LOOK like boundaries to jsonb containment and are NOT usable', () => {
    // Every one of these satisfies `@> [{"exclude_fixed": true}]`, which is how
    // the SQL half came to disagree with the JS half.
    for (const r of [
      { exclude_fixed: true, max: null },
      { exclude_fixed: true },
      { exclude_fixed: true, max: '' },
      { exclude_fixed: true, max: '   ' },
    ]) {
      assert.equal(hasUsableFixBoundary([r]), false, JSON.stringify(r));
    }
  });

  it('⛔ `{max: null, exclude_fixed: true}` is PRODUCED BY THIS CODEBASE', () => {
    // `expandWildcardMax('*')` returns exactly that shape, and `lessThan: "*"`
    // is an ordinary CVE-Record value — so the disagreement was reachable, not
    // hypothetical.
    const nvd = code('lib/feeds/nvd.js');
    assert.match(nvd, /expandWildcardMax/, 'the producer still exists');
  });

  it('exclude_fixed must be STRICTLY true', () => {
    // 'false' and 'no' are truthy strings; a feed emitting either would
    // otherwise have its non-boundary read as one.
    for (const v of ['false', 'no', 1, 'true', {}]) {
      assert.equal(hasUsableFixBoundary([{ exclude_fixed: v, max: '7.0' }]), false, String(v));
    }
  });

  it('a non-array, an empty array and junk are not boundaries', () => {
    for (const bad of [null, undefined, 'ranges', 42, {}, [], [null], [{}]]) {
      assert.equal(hasUsableFixBoundary(bad), false, JSON.stringify(bad));
    }
  });

  it('⛔ an UNRECOGNISED shape is distinguished from an empty one', () => {
    // Passing a jsonb string to the statement raises "cannot get array length
    // of a non-array", which lands in stats.errors, flips the sync to partial
    // and re-enables the NVD path that cannot work on this site. The widened
    // branch previously let a SHORT STRING through, because
    // `remote.length >= localRanges.length` compared String.length.
    assert.equal(isUnrecognisedRanges('n/a'), true);
    assert.equal(isUnrecognisedRanges(42), true);
    assert.equal(isUnrecognisedRanges({ a: 1 }), true);
    assert.equal(isUnrecognisedRanges([]), false, 'an empty array IS recognised');
    assert.equal(isUnrecognisedRanges(null), false, 'null is absent, not unrecognised');
    assert.equal(isUnrecognisedRanges(undefined), false);
  });
});

describe('⛔ the SQL half is GENERATED, so it cannot drift from the JS half', () => {
  it('the generator walks the array rather than using containment', () => {
    const sql = hasUsableFixBoundarySql('x');
    // Containment is what was blind to `max`; the generated form must not use it.
    assert.ok(!sql.includes('@>'), 'jsonb containment is blind to max');
    assert.match(sql, /jsonb_array_elements/, 'it must walk the entries');
    assert.match(sql, /exclude_fixed/);
    assert.match(sql, /max/, 'and it must test max');
    assert.match(sql, /jsonb_typeof\(x\) = 'array'/, 'and guard the shape first');
  });

  it('it substitutes the expression everywhere it is needed', () => {
    const sql = hasUsableFixBoundarySql('advisories.affected_version_ranges');
    assert.ok(!sql.includes('${'), 'no unsubstituted placeholder');
    assert.ok(sql.split('advisories.affected_version_ranges').length - 1 >= 2,
      'the expression appears in both the typeof guard and the walk');
  });

  // ⛔ THE PROPERTY THAT REPLACES THE FOUR DEAD REGEXES. The halves cannot
  // disagree if there is only one definition, so what a test can usefully
  // assert is that nobody hand-writes a second one.
  const CONSUMERS = [
    'lib/feeds/cveHub.js',
    'lib/feeds/fortinet.js',
    'lib/feeds/paloalto.js',
  ];

  it('⛔ every consumer uses the shared generator', () => {
    for (const f of CONSUMERS) {
      const c = code(f);
      assert.match(c, /hasUsableFixBoundarySql\(/,
        `${f} must build this predicate from lib/feeds/fixBoundary.js`);
      assert.match(c, /require\('\.\/fixBoundary'\)/, `${f} must import it`);
    }
  });

  it('⛔ and NO consumer hand-writes the containment test any more', () => {
    // This is the assertion that would have caught the 2026-09-27 disagreement:
    // the old SQL spelling is now forbidden outright, in code, comments stripped.
    for (const f of CONSUMERS) {
      const c = code(f);
      assert.ok(!/@>\s*'\[\{"exclude_fixed"/.test(c),
        `${f} still hand-writes a containment test — that is the blind-to-max form`);
    }
  });

  it('⛔ the hub also refuses an unrecognised local shape before any arithmetic', () => {
    const c = code('lib/feeds/cveHub.js');
    assert.match(c, /isUnrecognisedRanges\(local\.affected_version_ranges\)/,
      'a jsonb string must be refused before the length comparison');
  });

  it('⛔ paloalto carries the downgrade guard fortinet has', () => {
    // It did not, and reverted the hub's repair every cycle for three days.
    const c = code('lib/feeds/paloalto.js');
    assert.equal((c.match(/hasUsableFixBoundarySql\(/g) || []).length, 2,
      'both sides of the downgrade comparison must be generated');
    assert.match(c, /THEN advisories\.affected_version_ranges/,
      'and the refusal must keep the local value');
  });
});
