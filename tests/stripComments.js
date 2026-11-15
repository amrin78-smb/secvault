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
 * @param {{sql?: boolean, keepLines?: boolean, ps?: boolean}} [opts]
 *   `ps` strips POWERSHELL comments instead of JS ones, for the tests that scan
 *   `installer/*.ps1`.
 *   ⛔ AND IT IS DELIBERATELY THE OPPOSITE ORDER — BLOCK FIRST, THEN LINE — FOR
 *   A REASON SPECIFIC TO THE LANGUAGE, NOT OUT OF CARELESSNESS. PowerShell's
 *   block terminator is `#>`, which ITSELF BEGINS WITH `#`. A line-comment pass
 *   run first matches `^\s*#` against a line holding only `#>` and deletes the
 *   terminator; the block pass then finds an opener with no closer and eats
 *   forward to the next `#>` anywhere in the file — exactly the failure the JS
 *   order exists to prevent, arrived at from the other side. The JS hazard
 *   (`/*` inside a `//` line) has no PowerShell equivalent, because `<#` inside
 *   a `#` line comment is removed with that line either way.
 *   ⛔ THREE TESTS PREDATE THIS AND ROLL IT THEMSELVES — `backupScripts.test.js`,
 *   `packageLauncher.test.js` and `installerNativeCalls.test.js` — all in the
 *   same block-then-line order, and all invisible to `stripOrder.test.js`
 *   because they use `split('\n')` rather than the `.*$` form it looks for.
 *   They are not migrated here only because `backupScripts.test.js`'s
 *   assertions are pinned to the text its stripper produces and that guard
 *   protects `CREDENTIAL_KEY`; new PS scans must use this option.
 *   `sql` also strips SQL `--` line comments, for files that embed SQL in
 *   template literals.
 *   `keepLines` replaces a BLOCK comment with its own newlines instead of
 *   removing them, so line numbers in the result still match the original file.
 *   ⛔ Without it a scan that REPORTS a line number reports the wrong one: the
 *   line-comment pass keeps its newline (`.*$` under /m does not match it), but
 *   the block pass removes every newline inside the comment. Measured on
 *   app/(dashboard)/devices/[id]/page.js — a real offender on line 1227 was
 *   reported as 1149, i.e. 78 lines adrift, which sends a reader to unrelated
 *   code. An OPTION here rather than a second stripper in the caller, because a
 *   caller rolling its own is what tests/stripOrder.test.js exists to prevent.
 */
function stripComments(src, opts = {}) {
  const blank = (m) => m.replace(/[^\n]/g, '');
  if (opts.ps) {
    // See the `ps` note above: BLOCK first here, and that is load-bearing.
    const noBlocks = String(src == null ? '' : src)
      .replace(/\r\n/g, '\n')
      .replace(/<#[\s\S]*?#>/g, opts.keepLines ? blank : '');
    return noBlocks
      .split('\n')
      .map((line) => line.replace(/^\s*#.*$/, ''))
      .join('\n');
  }
  let out = String(src == null ? '' : src)
    // ⛔ FIRST. The `[^:]` guard keeps `https://` from eating the rest of a URL
    // line, which would be harmless here but makes the residue confusing to read.
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
    .replace(/\/\*[\s\S]*?\*\//g, opts.keepLines ? blank : '');
  if (opts.sql) out = out.replace(/^\s*--.*$/gm, '');
  return out;
}

module.exports = { stripComments };
