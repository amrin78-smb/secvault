'use strict';

// tests/psScripts.test.js
//
// Pins tests/psScripts.js — the one place that decides whether this machine can
// authoritatively check an installer .ps1, and the one reader that normalises
// line endings.
//
// ⛔ WHAT THIS GUARDS, AND WHY IT IS NOT CIRCULAR. The installer tests now SKIP
// off Windows. A skip is the right answer there and the WRONG answer on the
// Windows staging server, where the check is the whole point — and a skip that
// spreads to the authoritative machine would be invisible, because a skipped
// suite prints `ok` and the summary counts no failure. So the rule is asserted
// from the other side: on win32 the host must be real and authoritative, and
// the reason string must always say something.

const { describe, it, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { readPs, readAllPs, powershellHost, runPsProbe, INSTALLER_DIR } = require('./psScripts');

describe('⛔ line endings are normalised before any .ps1 is matched against', () => {
  it('CRLF, lone CR and LF all read back as LF', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sv-crlf-'));
    try {
      const f = path.join(dir, 'x.ps1');
      fs.writeFileSync(f, 'if ($a) {\r\n  Write-Host "hi"\r\n}\r\n', 'utf8');
      const text = readPs(f);
      assert.ok(!text.includes('\r'), 'a CR survived — an anchored regex would stop matching');
      assert.deepEqual(text.split('\n')[1], '  Write-Host "hi"',
        'the line must not carry a trailing CR');

      fs.writeFileSync(f, 'a\rb\r', 'utf8');
      assert.equal(readPs(f), 'a\nb\n', 'a lone CR must not collapse the file to one line');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('⛔ splitting a normalised file gives clean lines', () => {
    // The live failure shape: `text.split('\n')[n]` on a CRLF checkout returns
    // `...}\r`, and `/\}$/` then fails while the test reports clean.
    const withCr = 'one\r\ntwo\r\n';
    assert.ok(withCr.split('\n')[0].endsWith('\r'), 'the hazard exists in raw text');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sv-crlf2-'));
    try {
      const f = path.join(dir, 'y.ps1');
      fs.writeFileSync(f, withCr, 'utf8');
      assert.ok(!readPs(f).split('\n')[0].endsWith('\r'), 'and readPs removes it');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('readAllPs finds the real installer scripts and returns them normalised', () => {
    const all = readAllPs();
    assert.ok(all.length >= 3, `expected several installer scripts, found ${all.length}`);
    for (const { file, text } of all) {
      assert.match(file, /\.ps1$/i);
      assert.ok(!text.includes('\r'), `${file} still carries CR after readPs`);
    }
  });
});

describe('⛔ only Windows PowerShell 5.1 is authoritative', () => {
  test('the host decision always carries a reason', () => {
    const h = powershellHost();
    assert.equal(typeof h.reason, 'string');
    assert.ok(h.reason.length > 20, 'a skip with no explanation is a silent pass');
  });

  test('⛔ on Windows it must NOT skip', { skip: process.platform !== 'win32' }, () => {
    // The authoritative machine. If this ever skips there, the check has
    // silently stopped happening anywhere.
    const h = powershellHost();
    assert.equal(h.exe, 'powershell', 'must use 5.1, never pwsh, on Windows');
    assert.equal(h.authoritative, true);
  });

  test('⛔ off Windows it skips by default and names the limitation', { skip: process.platform === 'win32' }, () => {
    const saved = process.env.SECVAULT_ALLOW_PWSH;
    delete process.env.SECVAULT_ALLOW_PWSH;
    try {
      const h = powershellHost();
      assert.equal(h.exe, null, 'it must refuse rather than reach for pwsh');
      assert.equal(h.authoritative, false);
      assert.match(h.reason, /could not measure here/);
      assert.match(h.reason, /not a substitute/);
    } finally {
      if (saved !== undefined) process.env.SECVAULT_ALLOW_PWSH = saved;
    }
  });

  test('⛔ the pwsh opt-in is never reported as authoritative', () => {
    const saved = process.env.SECVAULT_ALLOW_PWSH;
    process.env.SECVAULT_ALLOW_PWSH = '1';
    try {
      const h = powershellHost();
      if (process.platform === 'win32') {
        // On Windows the real thing wins; the opt-in must not downgrade it.
        assert.equal(h.exe, 'powershell');
        assert.equal(h.authoritative, true);
      } else {
        assert.equal(h.exe, 'pwsh');
        assert.equal(h.authoritative, false, 'pwsh accepts syntax 5.1 rejects');
        assert.match(h.reason, /NOT authoritative/);
      }
    } finally {
      if (saved === undefined) delete process.env.SECVAULT_ALLOW_PWSH;
      else process.env.SECVAULT_ALLOW_PWSH = saved;
    }
  });

  test('⛔ runPsProbe returns null rather than throwing ENOENT', { skip: process.platform === 'win32' }, () => {
    // The exact failure this module was written to remove: the suite died with
    // `spawnSync powershell ENOENT` on the only machine anyone develops on.
    const saved = process.env.SECVAULT_ALLOW_PWSH;
    delete process.env.SECVAULT_ALLOW_PWSH;
    try {
      assert.equal(runPsProbe('Write-Host hi', []), null);
    } finally {
      if (saved !== undefined) process.env.SECVAULT_ALLOW_PWSH = saved;
    }
  });

  test('the installer directory it points at actually exists', () => {
    assert.ok(fs.existsSync(INSTALLER_DIR), 'INSTALLER_DIR is wrong — every scan would read nothing');
  });
});
