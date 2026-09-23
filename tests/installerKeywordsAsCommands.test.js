'use strict';
// tests/installerKeywordsAsCommands.test.js
//
// ⛔ A POWERSHELL PARSE CHECK IS NOT A SYNTAX GATE, AND THIS IS THE PROOF.
//
// installer\Install-SecVault.ps1 shipped with a DUPLICATED `} else {`:
//
//     } elseif (...) {
//         Fail "..."
//     } else {
//     } else {
//         Write-Step "Cloning SecVault from $SecVaultGitUrl..."
//
// [Parser]::ParseFile reported 7,611 tokens and ZERO ERRORS over it, because
// PowerShell parses a dangling `else { ... }` as a CALL TO A COMMAND NAMED
// `else` with a ScriptBlock argument. It is only at RUNTIME that it says
// "The term 'else' is not recognized as the name of a cmdlet". Both halves
// were measured on PS 5.1 before this test was written.
//
// The cost: on a fresh install the empty `else {}` ran, NOTHING WAS CLONED,
// and the script then died on the bare `else` — so the packaged installer
// could not install SecVault at all. It got past a parse check, a package
// build, and a review of the diff around it.
//
// ⛔ THIS IS `node --check` ON ESM WEARING A DIFFERENT HAT. CLAUDE.md already
// records that `node --check` exits 0 on four different syntax errors in any
// file with a top-level `import`, so "it parses" was never evidence. The same
// sentence is now true of the installer scripts, and this file is what makes
// it false again.
//
// The check: no PowerShell KEYWORD may appear as a COMMAND NAME. That is the
// exact signature of a block keyword that lost its statement — `else` after
// `else`, a `catch` with no `try`, a `finally` orphaned by an edit. Anything
// matching is a structural break the parser will happily accept.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const INSTALLER_DIR = path.join(__dirname, '..', 'installer');

// Keywords that can only ever be a command name by accident. `if`, `foreach`
// and `while` are deliberately absent: `foreach` is a real alias for
// ForEach-Object, and a command genuinely named `if` does not occur here.
const ORPHANS = ['else', 'elseif', 'catch', 'finally', 'until'];

// ⛔ THE AST IS ASKED FOR, NEVER RE-IMPLEMENTED. A regex over braces would
// have to model here-strings, escaped braces and comments, and would then be a
// second parser disagreeing with the real one — on the very question the real
// one is authoritative about.
const PROBE = [
  '$ErrorActionPreference = "Stop"',
  '$out = @()',
  'foreach ($f in (Get-ChildItem -Path $args[0] -Filter *.ps1 -File)) {',
  '  $errs = $null; $toks = $null',
  '  $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$toks, [ref]$errs)',
  '  foreach ($e in $errs) {',
  '    $out += ("{0}|{1}|PARSE: {2}" -f $f.Name, $e.Extent.StartLineNumber, $e.Message)',
  '  }',
  '  $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)',
  '  foreach ($c in $cmds) {',
  '    $name = $c.GetCommandName()',
  '    if ($name) { $out += ("{0}|{1}|CMD: {2}" -f $f.Name, $c.Extent.StartLineNumber, $name) }',
  '  }',
  '}',
  '$out -join "`n"',
].join('\n');

function inspectInstallerScripts() {
  const probePath = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'sv-astprobe-')),
    'probe.ps1'
  );
  fs.writeFileSync(probePath, PROBE, 'utf8');
  try {
    const stdout = execFileSync(
      'powershell',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', probePath, INSTALLER_DIR],
      { encoding: 'utf8', timeout: 120000 }
    );
    return stdout
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [file, line, rest] = l.split('|');
        return { file, line: Number(line), rest };
      });
  } finally {
    fs.rmSync(path.dirname(probePath), { recursive: true, force: true });
  }
}

describe('installer scripts are structurally sound, not merely parseable', () => {
  // ⛔ NO SKIP BRANCH. If PowerShell cannot be reached this test FAILS — a gate
  // that quietly passes when it could not run is the guard-that-cannot-fire
  // pattern, which is the defect this whole file exists to close. These scripts
  // only ever run on Windows; so does their gate.
  const findings = inspectInstallerScripts();

  it('reached PowerShell and actually inspected something', () => {
    assert.ok(
      findings.length > 0,
      'the AST probe returned nothing — it inspected no scripts, so it is pinning nothing'
    );
  });

  it('has no parse errors', () => {
    const parseErrors = findings.filter((f) => f.rest.startsWith('PARSE: '));
    assert.deepEqual(
      parseErrors.map((f) => `${f.file}:${f.line} ${f.rest}`),
      [],
      'installer script(s) do not parse'
    );
  });

  it('never parses a block keyword as a command name', () => {
    const orphans = findings.filter((f) => {
      if (!f.rest.startsWith('CMD: ')) return false;
      return ORPHANS.includes(f.rest.slice(5).toLowerCase());
    });
    assert.deepEqual(
      orphans.map((f) => `${f.file}:${f.line} ${f.rest}`),
      [],
      'A PowerShell keyword is being parsed as a COMMAND, which means a block ' +
        'lost its statement — most often a duplicated `} else {`. This PARSES ' +
        'CLEANLY and fails at runtime with "The term \'else\' is not recognized". ' +
        'Read the lines named above.'
    );
  });
});
