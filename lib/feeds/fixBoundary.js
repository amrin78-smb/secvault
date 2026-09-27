'use strict';

// lib/feeds/fixBoundary.js
//
// ONE DEFINITION OF "THIS ADVISORY CARRIES A USABLE FIX BOUNDARY", in both the
// languages that need it.
//
// ── ⛔ WHY THIS FILE EXISTS ────────────────────────────────────────────────
//
// `exclude_fixed: true` means "vulnerable up to but NOT INCLUDING max", so by
// its own definition `max` IS the first fixed release. That single fact drives
// three separate guards:
//
//   * `cveHub.hubIsBetter()` — may the hub repair our ranges?
//   * `cveHub`'s UPDATE `WHERE`  — the SQL half of the SAME decision
//   * `fortinet.js` / `paloalto.js` ON CONFLICT — may a vendor feed running
//     seconds later overwrite what the hub just repaired?
//
// ⛔ THEY WERE THREE DIFFERENT TESTS, AND IT COST FOUR DEPLOYS. v2.186.0 and
// .1 fixed the JS predicate while the SQL `WHERE` kept the old rule, so every
// repair was permitted by one half and refused by the other — 80 rows reported
// repaired, 0 written, and `stats.repaired++` counting INTENT so the log said
// success. v2.186.2 fixed that pair, and a 2026-09-27 review then found the
// halves STILL disagreed:
//
//   local {exclude_fixed:true, max:null}     JS: repair   SQL: refuse
//   local {exclude_fixed:true, max absent}   JS: repair   SQL: refuse
//   local {exclude_fixed:true, max:''}       JS: repair   SQL: refuse
//
// because the SQL used jsonb containment — `@> '[{"exclude_fixed": true}]'` —
// which is BLIND TO `max`. A boundary with no `max` names no version and fixes
// nothing, but it satisfied containment, so a local row holding a USELESS
// boundary blocked the statement while the JS predicate said go. Reachable
// today: `expandWildcardMax('*')` returns exactly `{max: null,
// excludeFixed: true}`, and `lessThan: "*"` is an ordinary CVE-Record value.
//
// ⛔ The same blind test sat in the vendor-feed guards, where it fails the
// OTHER way: a local useless boundary would REFUSE a legitimate vendor update.
//
// So the predicate is defined ONCE, here, and the SQL is generated from the
// same reasoning rather than hand-written beside it. `tests/fixBoundary.test.js`
// executes both halves over a shared table of cases and fails if they ever
// disagree — which the old test could not do, because it only grepped the SQL
// string's TEXT.

/**
 * Does this ranges array carry a boundary that names a version?
 *
 * ⛔ `exclude_fixed === true` STRICTLY, not truthy: `"false"` and `"no"` are
 * both truthy strings, and a feed that emitted either would otherwise have its
 * non-boundary read as one.
 * ⛔ A non-array is NOT a boundary. It is also not "no boundary" in the sense
 * that matters — see `isUnrecognisedRanges` below, which callers must check
 * FIRST, because passing an unrecognised shape to the SQL raises "cannot get
 * array length of a non-array" and turns a sync `partial`.
 */
function hasUsableFixBoundary(ranges) {
  if (!Array.isArray(ranges)) return false;
  return ranges.some((r) => {
    if (!r || typeof r !== 'object') return false;
    if (r.exclude_fixed !== true) return false;
    // A `max` of null/''/undefined names no release. `0` is not a version
    // string either, but String(0) is truthy-length, so test the text.
    const max = r.max === undefined || r.max === null ? '' : String(r.max).trim();
    return max !== '';
  });
}

/**
 * ⛔ AN UNRECOGNISED SHAPE IS NOT AN EMPTY ONE, and must never reach the SQL.
 * `jsonb` legitimately holds a string, a number or an object where this code
 * expects an array; `jsonb_array_length` raises on all three, which lands in
 * `stats.errors`, flips the sync to `partial` and re-enables the NVD path that
 * cannot work on this site. Callers refuse these BEFORE building a statement.
 */
function isUnrecognisedRanges(ranges) {
  return ranges !== null && ranges !== undefined && !Array.isArray(ranges);
}

/**
 * The SQL predicate for the same question, over a jsonb expression.
 *
 * ⛔ GENERATED, NOT HAND-WRITTEN BESIDE THE JS. `jsonb` containment cannot
 * express "has a key whose sibling is non-empty", so this walks the array —
 * which is also what makes it agree with `hasUsableFixBoundary` on the cases
 * containment got wrong.
 *
 * @param {string} expr a jsonb-valued SQL expression
 * @returns {string} a boolean SQL expression
 */
function hasUsableFixBoundarySql(expr) {
  return `(jsonb_typeof(${expr}) = 'array' AND EXISTS (
            SELECT 1 FROM jsonb_array_elements(${expr}) AS _r
             WHERE _r->>'exclude_fixed' = 'true'
               AND coalesce(btrim(_r->>'max'), '') <> ''))`;
}

module.exports = {
  hasUsableFixBoundary,
  isUnrecognisedRanges,
  hasUsableFixBoundarySql,
};
