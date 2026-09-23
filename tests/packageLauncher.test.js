'use strict';
// tests/packageLauncher.test.js
//
// installer/Build-SecVaultPackage.ps1 GENERATES the launcher an operator
// double-clicks. Nothing else in this repo ever loads that .cmd, and it is
// produced from a here-string, so the only thing standing between a broken
// launcher and a customer's server is this file.
//
// ⛔ THE ELEVATED RE-LAUNCH MUST CARRY THE ARGUMENTS. The .cmd self-elevates,
// and the obvious way to do that --
//     Start-Process -FilePath '%~f0' -Verb RunAs
// -- silently DROPS everything the operator typed. The elevated window then
// prompts interactively for values they already supplied, which reads as "the
// switches were ignored", and on an imaged deployment it hangs for ever on a
// prompt nobody is watching. That is the shape this codebase names most often:
// it runs, it reports nothing wrong, and it does not do the thing.
//
// ⛔ AND THE APPLICATION SOURCE MUST NOT COME BACK INTO THE PACKAGE. An
// earlier design bundled the tree and node_modules so an install needed no
// network. It was withdrawn (CLAUDE.md, Installer Scripts) because a copied
// tree carries no .git, so that installation could never update itself -- with
// no error, the update button simply doing nothing. The negative assertions
// below exist so reintroducing it has to be a deliberate act that also deletes
// a test, rather than a copy step somebody adds back for convenience.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const PACKAGER = path.join(__dirname, '..', 'installer', 'Build-SecVaultPackage.ps1');
const source = fs.readFileSync(PACKAGER, 'utf8');

// PowerShell comments, stripped so a negative scan cannot fire on the script's
// own explanation of what it no longer does. Block comments first, then any
// line whose first non-space character is `#` -- the same rule
// tests/installerNativeCalls.test.js uses.
const code = source
  .replace(/<#[\s\S]*?#>/g, '')
  .split('\n')
  .filter((line) => !/^\s*#/.test(line))
  .join('\n');

// The generated launcher is the $cmdText here-string. Pull out just that, so
// an assertion can never be satisfied by a comment elsewhere in the script.
function generatedCmd() {
  const start = source.indexOf('$cmdText = @"');
  assert.notEqual(start, -1, 'the $cmdText here-string is gone -- this test is pinning nothing');
  const end = source.indexOf('\n"@', start);
  assert.notEqual(end, -1, 'the $cmdText here-string is unterminated');
  return source.slice(start, end);
}

describe('the generated installer launcher', () => {
  const cmd = generatedCmd();

  it('stashes the arguments before it can lose them', () => {
    // `set "SVARGS=%*"` runs BEFORE the elevation branch. Put it after and the
    // non-elevated path works while the elevated one silently loses everything
    // -- the worse half being the one an operator actually hits.
    const stash = cmd.indexOf('set "SVARGS=%*"');
    const branch = cmd.indexOf('net session');
    assert.notEqual(stash, -1, 'the launcher no longer captures %*');
    assert.notEqual(branch, -1, 'the launcher no longer checks for elevation');
    assert.ok(stash < branch, '%* must be captured before the elevation branch');
  });

  it('forwards those arguments to the elevated re-launch', () => {
    const relaunch = cmd
      .split('\n')
      .find((l) => l.includes('-Verb RunAs'));
    assert.ok(relaunch, 'the launcher no longer self-elevates');
    assert.match(
      relaunch,
      /-ArgumentList \$env:SVARGS/,
      'the elevated re-launch does not pass the arguments on'
    );
    // Both branches are required: -ArgumentList with an empty string is not
    // the same as omitting it, and passing '' makes Start-Process fail rather
    // than start an interactive install.
    assert.match(relaunch, /if \(\$env:SVARGS\)/, 'the empty-argument case is not handled');
    assert.match(relaunch, /else \{ Start-Process/, 'the empty-argument case has no branch');
  });

  it('hands the same arguments to the installer on the elevated pass', () => {
    assert.match(
      cmd,
      /Install-SecVault\.ps1" %\*/,
      'the launcher runs the installer without passing the arguments through'
    );
  });
});

describe('the package contents', () => {
  it('does not copy the application source or node_modules', () => {
    // Withdrawn design -- see the header. Scanned over CODE ONLY: the script's
    // own header explains in prose why node_modules is no longer bundled, and
    // a raw-source scan read that sentence as evidence that it is. The same
    // trap lib/deviceScopeCoverage.js hit, and for the same reason -- a check
    // that fires on its own documentation gets deleted rather than fixed.
    for (const banned of ['node_modules', 'IncludeNodeModules', 'secvault-bundled']) {
      assert.ok(
        !code.includes(banned),
        `Build-SecVaultPackage.ps1 mentions "${banned}". The installer CLONES its source; ` +
          'bundling it produces an installation with no .git that can never update itself. ' +
          'See CLAUDE.md, Installer Scripts.'
      );
    }
  });

  it('requires the deploy key rather than treating it as optional', () => {
    // The repo is private and the installer clones from it, so a package
    // without the key installs nothing at all. It was optional only while the
    // source was bundled.
    const row = source
      .split('\n')
      .find((l) => l.includes("Pattern = 'secvault_deploy'"));
    assert.ok(row, 'the deploy key is no longer a checked prerequisite');
    assert.match(row, /Required\s*=\s*\$true/, 'the deploy key is marked optional');
  });

  it('refuses to ship a package whose deploy key did not make it in', () => {
    assert.match(
      source,
      /Fail 'The deploy key did not reach the package/,
      'a package missing the key would ship, and fail on the customer’s server'
    );
  });
});
