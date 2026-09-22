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
  'Restore-SecVault.ps1:221',
  'SecVault-Tls.ps1:135',
  'Uninstall-SecVault.ps1:107',
  'Uninstall-SecVault.ps1:113',
]);

describe('⛔ every native 2>&1 in an installer script is inside Invoke-Native', () => {
  it('finds the scripts that use it at all', () => {
    const found = scriptsWithNativeRedirects();
    assert.ok(found.length > 0, 'expected at least one installer script to redirect stderr');
    assert.ok(found.some((s) => s.file === 'Update-SecVault.ps1'));
  });

  it('and every occurrence is routed through the helper', () => {
    const offenders = [];
    for (const { file, text } of scriptsWithNativeRedirects()) {
      const lines = text.split('\n');
      lines.forEach((line, i) => {
        if (!line.includes('2>&1') || isComment(line)) return;
        if (line.includes('Invoke-Native')) return;
        const where = `${file}:${i + 1}`;
        if (KNOWN_UNROUTED.has(where)) return;
        offenders.push(`${where}: ${line.trim().slice(0, 90)}`);
      });
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

  it('⛔ and it restores the previous preference rather than leaving Continue set', () => {
    // A helper that set 'Continue' and never put it back would silently disable
    // the script's own error handling for every step after the first native
    // call — turning one false failure into a fleet of missed real ones.
    for (const { file, text } of scriptsWithNativeRedirects()) {
      if (!/function\s+Invoke-Native/.test(text)) continue;
      const body = text.slice(text.search(/function\s+Invoke-Native/));
      assert.match(body, /finally\s*\{[\s\S]{0,120}ErrorActionPreference\s*=\s*\$prevEAP/,
        `${file}'s Invoke-Native must restore $ErrorActionPreference in a finally block`);
    }
  });
});

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
