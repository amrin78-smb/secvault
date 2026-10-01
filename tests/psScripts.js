'use strict';

// tests/psScripts.js
//
// ONE definition of "can this machine authoritatively check an installer .ps1",
// and one reader that normalises line endings. Shared by every test that touches
// `installer/*.ps1`.
//
// ── ⛔ WINDOWS POWERSHELL 5.1 IS THE ONLY AUTHORITY (decided 2026-10-01) ──
//
// The servers run Windows PowerShell 5.1. **PowerShell 7 on Linux is NOT a
// substitute and must never be treated as one**: pwsh ACCEPTS syntax 5.1
// REJECTS — `&&`, `||`, `??`, `?:` and `?.` all parse cleanly in 7 and are hard
// errors in 5.1. A green pwsh run would therefore certify a script that cannot
// execute on the machine it ships to, which is strictly worse than no check:
// this repo already learned that `[Parser]::ParseFile` reporting 7,611 tokens
// and zero errors is not a syntax gate, and a second parser that disagrees with
// the authoritative one is the same mistake with a different binary.
//
// ── ⛔ OFF WINDOWS THESE TESTS SKIP, AND THAT REVERSES AN EARLIER RULE ────
//
// `installerKeywordsAsCommands.test.js` used to carry "NO SKIP BRANCH ... these
// scripts only ever run on Windows, and so does their gate". That held while
// development happened on Windows. Development moved to Linux on 2026-10-01, so
// the rule as written now makes the ENTIRE SUITE fail with
// `spawnSync powershell ENOENT` on the only machine anyone develops on — a gate
// that fails for a reason unrelated to what it checks gets deleted or ignored,
// which loses the check altogether.
//
// ⛔ SO: SKIP, NEVER PASS, AND NEVER ENOENT. A skip is VISIBLE in TAP output
// with its reason attached; a silent pass is the guard-that-cannot-fire pattern
// this file exists to avoid. The authoritative run happens on the Windows
// staging server — see CLAUDE.md's "Machines" section.
//
// ⛔ `pwsh` IS OPT-IN ONLY and is never authoritative. `SECVAULT_ALLOW_PWSH=1`
// enables it for a deliberate local spot-check; the reason string still says so,
// so nobody reads a pwsh pass as a 5.1 pass.

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const INSTALLER_DIR = path.join(__dirname, '..', 'installer');

/**
 * ⛔ NORMALISE CRLF, ALWAYS. A Windows checkout stores these scripts with CRLF
 * (`core.autocrlf=true` is set on the Windows machines), so a test that does
 * `text.split('\n')[n]` gets a line with a trailing `\r` and every anchored
 * regex against it quietly stops matching — the check reports clean because it
 * compared against a string nobody writes, not because the script is correct.
 * A lone CR is normalised too; old-Mac endings are not expected but cost
 * nothing to handle and would otherwise collapse a file to one line.
 */
function readPs(file) {
  const full = path.isAbsolute(file) ? file : path.join(INSTALLER_DIR, file);
  return fs.readFileSync(full, 'utf8').replace(/\r\n?/g, '\n');
}

/** Every installer script, as {file, text} with endings normalised. */
function readAllPs() {
  return fs.readdirSync(INSTALLER_DIR)
    .filter((f) => f.toLowerCase().endsWith('.ps1'))
    .sort()
    .map((file) => ({ file, text: readPs(file) }));
}

/**
 * Where an authoritative PowerShell 5.1 can be reached, or why it cannot.
 *
 * @returns {{exe: string|null, authoritative: boolean, reason: string}}
 *   `exe === null` means the caller must SKIP with `reason`.
 */
function powershellHost() {
  if (process.platform === 'win32') {
    return {
      exe: 'powershell',
      authoritative: true,
      reason: 'Windows PowerShell 5.1 — the version the servers run',
    };
  }
  if (process.env.SECVAULT_ALLOW_PWSH === '1') {
    return {
      exe: 'pwsh',
      authoritative: false,
      // ⛔ Stated on every run, not only in a comment: a pwsh pass is a weaker
      // claim than a 5.1 pass and the output has to say which one happened.
      reason: 'pwsh (PowerShell 7) via SECVAULT_ALLOW_PWSH=1 — NOT authoritative; '
        + 'it accepts &&, ||, ??, ?: and ?. which 5.1 rejects',
    };
  }
  return {
    exe: null,
    authoritative: false,
    reason: `could not measure here: Windows PowerShell 5.1 is unavailable on ${process.platform}. `
      + 'These scripts only ever run under 5.1, and pwsh is not a substitute (it accepts syntax 5.1 '
      + 'rejects). Run this check on the Windows staging server; set SECVAULT_ALLOW_PWSH=1 for a '
      + 'deliberate, non-authoritative local spot-check.',
  };
}

/**
 * Run a .ps1 probe and return its stdout, or `null` when this machine cannot.
 *
 * ⛔ IT RETURNS null RATHER THAN THROWING on an unavailable host, so the caller
 * can skip with a reason. A throw here is the ENOENT this module exists to
 * prevent. A failure of the probe ITSELF still throws — that is a real result.
 */
function runPsProbe(scriptText, args, opts) {
  const host = powershellHost();
  if (!host.exe) return null;
  const dir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'sv-psprobe-'));
  const probePath = path.join(dir, 'probe.ps1');
  fs.writeFileSync(probePath, scriptText, 'utf8');
  try {
    return execFileSync(
      host.exe,
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', probePath, ...(args || [])],
      Object.assign({ encoding: 'utf8', timeout: 120000 }, opts || {})
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

module.exports = {
  INSTALLER_DIR,
  readPs,
  readAllPs,
  powershellHost,
  runPsProbe,
};
