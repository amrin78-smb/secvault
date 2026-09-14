'use strict';

// Order-independent JSON comparison, for "has this value actually changed?".
//
// ⛔ ═══ WHY THIS EXISTS: JSONB DOES NOT PRESERVE KEY ORDER ═══════════════
// PostgreSQL's `jsonb` stores an object with its keys sorted by LENGTH first,
// then bytewise — it is a parsed binary form, not the text you handed it. So a
// value written as
//
//     {"min":"9.1","max":"9.1.2","vulnerable":true,"exclude_fixed":true}
//
// reads back as
//
//     {"max":"9.1.2","min":"9.1","vulnerable":true,"exclude_fixed":true}
//
// (key lengths 3, 3, 10, 13). `JSON.stringify` faithfully preserves each
// object's OWN key order, so comparing `JSON.stringify(fromDatabase)` against
// `JSON.stringify(freshlyBuiltInJs)` returns false for two IDENTICAL values,
// every single time.
//
// Measured consequence, live: `backfillPaloAltoVersionRanges` had exactly that
// guard. It never once fired. The backfill rewrote the same 302 advisory rows
// with byte-identical data on every deploy for months, reporting "cleaned up
// 302" each time, and left `advisories` sitting at 18.6% dead tuples.
//
// ⛔ THE DATA WAS NEVER WRONG — THE COMPARISON WAS. That is what made it
// invisible: every value in the database was correct, every log line looked
// like successful maintenance, and the only symptom was a number that never
// went down. A guard that cannot ever fire is worse than no guard, because the
// code reads as though the case is handled.
//
// ⛔ USE THIS FOR COMPARISON ONLY, NEVER FOR STORAGE. Writes keep passing their
// natural JS-ordered JSON; Postgres canonicalises on the way in regardless, so
// there is nothing to gain and a diff to review for no reason.

/**
 * Recursively sort object keys so two structurally-equal values serialise
 * identically. Arrays keep their order — order is meaningful in an array and
 * sorting one would make genuinely different values compare equal.
 */
function canonicalise(value) {
  if (Array.isArray(value)) return value.map(canonicalise);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = canonicalise(value[key]);
    return out;
  }
  return value;
}

/**
 * Stable stringify: structurally-equal values produce identical strings
 * regardless of key order on either side.
 */
function canonicalJson(value) {
  return JSON.stringify(canonicalise(value === undefined ? null : value));
}

/**
 * Are these two values the same data, ignoring key order?
 *
 * @returns {boolean}
 */
function jsonEquivalent(a, b) {
  return canonicalJson(a) === canonicalJson(b);
}

module.exports = { canonicalise, canonicalJson, jsonEquivalent };
