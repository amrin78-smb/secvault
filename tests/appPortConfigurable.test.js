'use strict';
// tests/appPortConfigurable.test.js
//
// ⛔ ONE INVARIANT: NOTHING THAT DECIDES WHERE THE CONSOLE LISTENS MAY CARRY
// 3010 AS A LITERAL.
//
// The port has been configurable since the beginning — Install-SecVault.ps1
// takes -AppPort, writes APP_PORT, and threads it through NEXTAUTH_URL, the
// NSSM entry point, the inbound firewall rule, the health probe and the
// closing banner; lib/tlsConfig.js resolves HTTPS_PORT || APP_PORT at every
// startup. Three places had drifted off that and hardcoded the default
// instead, found when 3010 turned out to be taken by another NocVault app:
//
//   1. Update-SecVault.ps1's ROLLBACK fallback entry point (`-p 3010`). It
//      fires only when the captured NSSM value looks corrupt, but on a moved
//      install it would put SecVault-App back on 3010 while writing a
//      NEXTAUTH_URL built from $port naming the real one — NextAuth then
//      issues its cookie for an origin the browser is not on and every
//      sign-in bounces silently back to the login page. The line meant to be
//      the safety net would have caused the exact failure the NEXTAUTH_URL
//      comment beside it exists to prevent.
//   2. package.json's `dev` and `start` scripts.
//   3. Settings → About printed `['Port', '3010']`, so a moved install was
//      told in its own UI that it was on a port it was not on.
//
// ⛔ WHY A SOURCE SCAN AND NOT A BEHAVIOUR TEST. CLAUDE.md's own rule is to
// assert the OUTCOME, and for the PowerShell half there is no outcome
// reachable here: these scripts only run on Windows, the suite skips the
// PowerShell host on this dev box, and the rollback branch requires a failed
// HTTPS probe against a live service. A scan is the only gate that can fire at
// all — so it is written against the INVARIANT ("no literal default port in
// the lines that set the entry point") rather than against today's exact text,
// which is the mistake that made tests/consolidationTab.test.js fail on
// correct code twice.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { readPs } = require('./psScripts');

const REPO = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(REPO, p), 'utf8');

/**
 * A PowerShell script with its comments removed.
 *
 * ⛔ COMMENTS ARE STRIPPED FIRST, the same lesson lib/deviceScopeCoverage.js
 * records: its raw-source scan read a file's PROSE saying it held no device
 * data as evidence that it did. Here the prose is legitimate -- an incident
 * narrative about a truncated rollback value, and the documented manual
 * `nssm set` command -- and both quote an entry point. Scanning them would
 * fail the build on correct code, which is how a guard gets deleted.
 *
 * Quote state is tracked so a `#` inside a string is not mistaken for a
 * comment; PowerShell here-strings are not used in these scripts.
 */
function stripPsComments(text) {
  return text.split('\n').map((line) => {
    let single = false;
    let double = false;
    for (let i = 0; i < line.length; i += 1) {
      const c = line[i];
      if (c === '`' && double) { i += 1; continue; }
      if (c === "'" && !double) single = !single;
      else if (c === '"' && !single) double = !double;
      else if (c === '#' && !single && !double) return line.slice(0, i);
    }
    return line;
  }).join('\n');
}

describe('the console port is configurable end to end', () => {
  test('Update-SecVault.ps1 sets no entry point with a literal port', () => {
    const text = stripPsComments(readPs('Update-SecVault.ps1'));
    // Any `next start -p <digits>` is a hardcoded entry point. The real one
    // must interpolate $port, which is resolved from APP_PORT above it.
    const literal = text.match(/next start -p \d+/g) || [];
    assert.deepEqual(
      literal, [],
      `Update-SecVault.ps1 builds an entry point with a literal port: ${literal.join(', ')}. `
      + 'Use "-p $port" — $port is resolved from APP_PORT in the same scope.',
    );
    // And the rollback must still restore SOMETHING: an empty fallback would
    // satisfy the assertion above while leaving a service that cannot start.
    assert.match(
      text, /\$restore = "node_modules\\next\\dist\\bin\\next start -p \$port"/,
      'the rollback fallback entry point is gone — a rollback must be the one path that cannot fail',
    );
  });

  test('Update-SecVault.ps1 resolves the port from APP_PORT, not from a bare default', () => {
    const text = readPs('Update-SecVault.ps1');
    const reads = (text.match(/Get-SecVaultEnvValue[^\n]*-Key 'APP_PORT'/g) || []).length;
    // Two steps need it: the health probe and the page-render sweep.
    assert.ok(
      reads >= 2,
      `expected both the health probe and the page sweep to read APP_PORT, found ${reads} read(s)`,
    );
  });

  test('Install-SecVault.ps1 never hardcodes the app port where it matters', () => {
    const text = stripPsComments(readPs('Install-SecVault.ps1'));
    // -AppPort's own default is the one place the literal belongs.
    const defaults = (text.match(/\[int\]\$AppPort = 3010/g) || []).length;
    assert.equal(defaults, 1, 'expected exactly one -AppPort default declaration');

    for (const re of [
      /next start -p 3010/,
      /New-NetFirewallRule[^\n]*-LocalPort 3010/,
      /Test-SecVaultResponding[^\n]*-Port 3010/,
    ]) {
      assert.ok(!re.test(text), `Install-SecVault.ps1 hardcodes the port: ${re}`);
    }
  });

  test('the npm scripts follow the configured port', () => {
    const pkg = JSON.parse(read('package.json'));
    for (const name of ['dev', 'start']) {
      assert.ok(
        !/-p\s*\d+/.test(pkg.scripts[name]),
        `package.json "${name}" hardcodes a port: ${pkg.scripts[name]}`,
      );
      assert.match(
        pkg.scripts[name], /nextPort\.js/,
        `package.json "${name}" should go through scripts/nextPort.js`,
      );
    }
  });

  test('Settings → About reads the port rather than asserting it', () => {
    const text = read('app/(dashboard)/settings/page.js');
    assert.ok(
      !/\['Port',\s*'\d+'\]/.test(text),
      'the About table hardcodes a port again — read it from window.location instead',
    );
    assert.match(text, /\['Console port', consolePort\]/);
    assert.match(text, /function readConsolePort\(\)/);
  });

  test('every variable the port resolver reads is documented in .env.local.example', () => {
    const tls = read('lib/tlsConfig.js');
    const example = read('.env.local.example');
    // The keys resolveTlsConfig() actually consults, harvested from source so
    // a new one cannot be added without being documented.
    const keys = [...tls.matchAll(/\be\.([A-Z][A-Z0-9_]+)/g)].map((m) => m[1]);
    assert.ok(keys.includes('HTTPS_PORT'), 'expected tlsConfig to still read HTTPS_PORT');
    for (const key of new Set(keys)) {
      assert.match(
        example, new RegExp(`^${key}=`, 'm'),
        `${key} is read by lib/tlsConfig.js but absent from .env.local.example`,
      );
    }
  });

  test('nextPort.js refuses to invent a port from an unreadable env file', () => {
    const text = read('scripts/nextPort.js');
    // A failed read must return null and fall through to the stated default,
    // never silently become a number — the failed-read-as-a-fact rule.
    assert.match(text, /catch \{\s*\n\s*return null;/);
    assert.match(text, /const DEFAULT_PORT = 3010;/);
  });
});
