'use strict';
// tests/installerNativeCalls.test.js
//
// ⛔ ONE INVARIANT, AND IT COST A FALSE DEPLOY FAILURE. On PowerShell 5.1,
// `2>&1` on a NATIVE executable wraps each stderr line in a NativeCommandError
// — and both installer scripts run under `$ErrorActionPreference = 'Stop'`, so
// that record is TERMINATING. Normal, harmless stderr (npm's deprecation
// warnings, git's progress text, node's TLS notice) therefore aborts the step
// before its own `$LASTEXITCODE` check is ever reached.
//
// `Invoke-Native` exists in both scripts for exactly this, and its own comment
// says so. It was applied to every native call but ONE: the page-render sweep
// called `& node scripts\smoke.js 2>&1` directly. That went unnoticed for
// thirteen versions because the step returned early with a SKIP whenever
// SMOKE_USER/SMOKE_PASS were unset, so node was never launched. The first
// deploy on which the sweep actually ran (v2.163.0, 2026-09-22) reported:
//
//   Step FAILED: Verify every page renders -- (node:5152) Warning: Setting the
//   NODE_TLS_REJECT_UNAUTHORIZED environment variable to '0' ...
//
// and the closing banner read "completed WITH ERRORS" — while the sweep had in
// fact passed 28/28 with exit code 0. A deploy that cries wolf is a deploy
// nobody reads, which is the same argument CLAUDE.md makes about a permanently
// amber feed chip.
//
// So the rule is now structural rather than a matter of care: EVERY `2>&1` in
// an installer script must sit inside an Invoke-Native block. This is a repo
// scan, the same shape as the `SET ended_at` scan that pins vpn_sessions'
// end-detection to one file.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const INSTALLER_DIR = path.join(__dirname, '..', 'installer');

// A line is a comment if the first non-space character is `#`. PowerShell has
// no trailing-comment form that could hide a redirect, so this is sufficient.
const isComment = (line) => /^\s*#/.test(line);

function scriptsWithNativeRedirects() {
  return fs.readdirSync(INSTALLER_DIR)
    .filter((f) => f.endsWith('.ps1'))
    .map((f) => ({ file: f, text: fs.readFileSync(path.join(INSTALLER_DIR, f), 'utf8') }))
    .filter((s) => s.text.includes('2>&1'));
}

// ⛔ A SHRINKING ALLOW-LIST, NOT A PASS. Four occurrences predate this rule and
// sit in scripts this test's author could not verify end to end: Restore- and
// Uninstall-SecVault.ps1 are DESTRUCTIVE (a dry run is not the same code path),
// and SecVault-Tls.ps1's openssl call only executes when a certificate is being
// minted, which every normal deploy skips ("Existing certificate left
// untouched"). Editing them blind to satisfy a test would trade a latent
// misreport for an untested change to a script that restores a database.
//
// So they are named here instead. The list may only ever SHRINK: a new
// occurrence fails the test, and removing one of these requires fixing it.
// openssl is the one worth doing first — it writes progress to stderr as a
// matter of course, so it is the likeliest of the four to bite.
const KNOWN_UNROUTED = new Set([
  // Restore-SecVault.ps1:221 was here and is GONE -- the v2.175.0 lifecycle
  // audit routed that call through Invoke-Native. The list shrank, which is
  // the only direction it is allowed to move.
  // Uninstall-SecVault.ps1:107 and :113 were here and are GONE for the same
  // reason. ⛔ ONE ENTRY LEFT, and it is the one the header called out as
  // worth doing first: openssl writes key-generation progress to stderr as a
  // matter of course, so it is the likeliest of the original four to bite.
  'SecVault-Tls.ps1:135',
]);

describe('⛔ every native 2>&1 in an installer script is inside Invoke-Native', () => {
  it('finds the scripts that use it at all', () => {
    const found = scriptsWithNativeRedirects();
    assert.ok(found.length > 0, 'expected at least one installer script to redirect stderr');
    assert.ok(found.some((s) => s.file === 'Update-SecVault.ps1'));
  });

  it('and every occurrence is routed through the helper', () => {
    // ⛔ "ON THE SAME LINE AS Invoke-Native" IS NOT THE RULE — "inside an
    // Invoke-Native block" is. This used to test the line, so routing a call
    // through the helper across several lines (which is what capturing the
    // exit code inside the block requires) reported the correctly-routed call
    // as an offender. The scan now brace-matches the block.
    const offenders = [];
    for (const { file, text } of scriptsWithNativeRedirects()) {
      const ranges = invokeNativeRanges(text);
      let at = text.indexOf('2>&1');
      while (at !== -1) {
        const lineNo = text.slice(0, at).split('\n').length;
        const line = text.split('\n')[lineNo - 1];
        const where = `${file}:${lineNo}`;
        const inside = ranges.some(([open, close]) => at > open && at < close);
        if (!isComment(line) && !inside && !KNOWN_UNROUTED.has(where)) {
          offenders.push(`${where}: ${line.trim().slice(0, 90)}`);
        }
        at = text.indexOf('2>&1', at + 1);
      }
    }
    assert.deepEqual(offenders, [],
      'these redirect a native command\'s stderr without Invoke-Native, so normal '
      + 'stderr becomes a terminating NativeCommandError under $ErrorActionPreference = '
      + `'Stop':\n  ${offenders.join('\n  ')}`);
  });

  it('⛔ and the helper is actually DEFINED in each script that uses it', () => {
    // Routing a call through a helper that does not exist in that file would
    // throw a CommandNotFoundException — a worse failure than the one being
    // fixed, and one no local test of the JS could see.
    // ⛔ SecVault-Tls.ps1 is DOT-SOURCED into both installer scripts and
    // deliberately does not define its own copy (CLAUDE.md: one copy, two
    // callers, so they cannot drift). It is therefore exempt from this
    // assertion and NOT from the routing one above.
    const DOT_SOURCED = new Set(['SecVault-Tls.ps1']);
    for (const { file, text } of scriptsWithNativeRedirects()) {
      if (!text.includes('Invoke-Native') || DOT_SOURCED.has(file)) continue;
      assert.match(text, /function\s+Invoke-Native/,
        `${file} calls Invoke-Native but does not define it`);
    }
  });

  it('⛔ and it cannot leak Continue out of the function — the assertion that replaced one that could not fail', () => {
    // ⛔ WHAT WAS HERE BEFORE COULD NOT FAIL, TWICE OVER, and it is worth
    // recording why rather than quietly replacing it.
    //
    // 1. `body` was `text.slice(indexOf('function Invoke-Native'))` — i.e.
    //    everything from the declaration to END OF FILE. Any `finally { ... }`
    //    anywhere later in an 1,100-line installer satisfied it, and both
    //    scripts have several.
    // 2. More fundamentally, `$ErrorActionPreference = 'Continue'` INSIDE a
    //    PowerShell function is FUNCTION-SCOPED: it vanishes when the function
    //    returns whether or not anything restores it. Deleting the `finally`
    //    outright would change no behaviour at all, so the assertion pinned a
    //    property the code did not depend on.
    //
    // What IS real is the one way this helper could genuinely leak: assigning
    // to the SCRIPT or GLOBAL copy, which outlives the call and would disable
    // the script's own error handling for every step after the first native
    // call. That is a mistake somebody could make while "fixing" a preference
    // that did not seem to stick — so it is what gets pinned, against a
    // brace-matched function body rather than the rest of the file.
    for (const { file, text } of scriptsWithNativeRedirects()) {
      if (!/function\s+Invoke-Native/.test(text)) continue;
      const body = functionBody(text, 'Invoke-Native');
      assert.ok(body, `${file}: could not find the body of Invoke-Native`);
      assert.doesNotMatch(body, /\$(script|global):ErrorActionPreference\s*=/,
        `${file}'s Invoke-Native must not assign the script/global ErrorActionPreference — `
        + 'that copy outlives the call and would silence every later step');
      assert.match(body, /\$ErrorActionPreference\s*=\s*'Continue'/,
        `${file}'s Invoke-Native must set the FUNCTION-scoped preference to Continue — that scope is what makes it safe`);
      assert.match(body, /&\s*\$Command/,
        `${file}'s Invoke-Native must actually invoke the scriptblock it was given`);
    }
  });
});

/**
 * The text between the braces of `function <name> { ... }`, matched by
 * counting braces. ⛔ NOT a slice to end-of-file: an assertion made against
 * "everything after the declaration" is satisfied by any later line in the
 * script and can never fail, which is how the assertion above got there.
 */
/**
 * The character ranges of every `Invoke-Native { … }` block, brace-matched.
 * A block whose braces do not balance yields no range, so anything inside it
 * is reported as unrouted — loud rather than silently excused.
 */
function invokeNativeRanges(text) {
  const ranges = [];
  const re = /Invoke-Native\s*\{/g;
  let m = re.exec(text);
  while (m !== null) {
    const open = text.indexOf('{', m.index);
    let depth = 0;
    for (let i = open; i < text.length; i += 1) {
      if (text[i] === '{') depth += 1;
      else if (text[i] === '}') {
        depth -= 1;
        if (depth === 0) { ranges.push([open, i]); break; }
      }
    }
    m = re.exec(text);
  }
  return ranges;
}

function functionBody(text, name) {
  const at = text.search(new RegExp(`function\\s+${name}\\b`));
  if (at === -1) return null;
  const open = text.indexOf('{', at);
  if (open === -1) return null;
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    if (text[i] === '{') depth += 1;
    else if (text[i] === '}') {
      depth -= 1;
      if (depth === 0) return text.slice(open + 1, i);
    }
  }
  return null;
}

describe('⛔ the allow-list is honest about itself', () => {
  it('every entry still exists, so a fixed line cannot sit here forever claiming debt', () => {
    // A stale allow-list is the same defect as a stale roadmap entry: it makes
    // work look outstanding that is already done, or hides a line that moved.
    for (const entry of KNOWN_UNROUTED) {
      const [file, lineNo] = entry.split(':');
      const full = path.join(INSTALLER_DIR, file);
      assert.ok(fs.existsSync(full), `${file} no longer exists — drop ${entry}`);
      const line = fs.readFileSync(full, 'utf8').split('\n')[Number(lineNo) - 1];
      assert.ok(line !== undefined, `${entry} is past the end of the file — the list has drifted`);
      assert.ok(line.includes('2>&1'),
        `${entry} no longer redirects stderr — either it was fixed (remove it from `
        + 'KNOWN_UNROUTED) or the line numbers have shifted (re-measure)');
    }
  });
});
