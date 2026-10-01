'use strict';

// tests/stripComments.js — ONE comment-stripper for every source scan.
//
// ⛔ NOT a `*.test.js` file, so `node --test tests/` does not execute it; it is
// required by the tests that need it. `tests/stripOrder.test.js` is its guard.
//
// ── ⛔ WHY THIS EXISTS: THE ORDER OF THE TWO STRIPPERS IS LOAD-BEARING ─────
//
// This repo scans source text in 44 test files, because several of its rules can
// only be checked that way — "no hardcoded hex", "no causal vocabulary", "this
// surface is classified", "the analysis runs after NAT is stored". Every one of
// those scans must strip comments first, because the prose EXPLAINING a rule
// almost always contains the very pattern the rule forbids.
//
// The obvious implementation strips block comments, then line comments. That is
// WRONG, and measured 2026-09-27 it was wrong in ELEVEN test files:
//
//   A line comment containing the text `/*` is not a block-comment opener — but
//   a block-first stripper cannot tell, so it swallows everything up to the next
//   `*/`, which may be hundreds of lines later.
//
// `lib/feeds/paloalto.js:407` contains, inside a `//` comment, the phrase
// `feeds/*.js`. Its `/*` opened a phantom block that ran to a real `*/` 216
// lines further down:
//
//   raw 46,914 chars  ->  block-first 35,219  ->  8,261 chars of REAL CODE gone
//
// Across the repo, 17 source files carry that trigger and block-first discards
// **52,339 characters of real code** from them — a quarter of `scripts/dbCheck.js`,
// 40% of `lib/deviceScopePaths.js`.
//
// ⛔ NO SECURITY VERDICT CURRENTLY FLIPS. Measured: `deviceScopeCoverage.test.js`
// is the one block-first test that reads a damaged file, and its
// `DEVICE_RE.test(stripComments(src))` returns the same answer either way for all
// 17. So this was a latent defect in eleven guards, not a live hole — which is
// precisely the state this codebase names most often, and the reason to fix it
// before it stops being latent.
//
// ⛔ LINE COMMENTS FIRST. After they are gone, a `/*` inside one cannot open
// anything. The residual hazard runs the other way — a `//` inside a block
// comment leaves that line's text in — which OVER-scans, and over-scanning
// produces a false FAILURE a developer investigates, never a false pass.

/**
 * Strip JS comments for a source scan.
 *
 * @param {string} src
 * @param {{sql?: boolean}} [opts] also strip SQL `--` line comments, for files
 *   that embed SQL in template literals.
 */
function stripComments(src, opts = {}) {
  let out = String(src == null ? '' : src)
    // ⛔ FIRST. The `[^:]` guard keeps `https://` from eating the rest of a URL
    // line, which would be harmless here but makes the residue confusing to read.
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
    .replace(/\/\*[\s\S]*?\*\//g, '');
  if (opts.sql) out = out.replace(/^\s*--.*$/gm, '');
  return out;
}

module.exports = { stripComments };
