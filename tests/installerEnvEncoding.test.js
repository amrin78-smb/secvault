'use strict';
// tests/installerEnvEncoding.test.js
//
// ⛔ ONE INVARIANT, AND IT COST A PRODUCTION OUTAGE ON 2026-09-24.
//
// In Windows PowerShell 5.1 `Get-Content` decodes using the ANSI CODEPAGE, not
// UTF-8. The installer scripts read `.env.local` with it and write the result
// back as UTF-8 (deliberately hand-rolled via .NET, so the write side is
// correct and carries sixteen lines of comment explaining itself). The round
// trip is what is wrong: every non-ASCII byte is read as a separate cp1252
// character and re-encoded as one or two bytes, so each character ROUGHLY
// DOUBLES — once per deploy.
//
// The seed was an em-dash inside a COMMENT that `.env.local.example` ships:
//
//     # Auth (standalone — not shared with NocVault suite)
//
// Nothing read that line. It still grew, deploy after deploy, into a single
// 2,209,122,508-byte line. node then refused the whole file —
// ERR_STRING_TOO_LONG, "Cannot create a string longer than 0x1fffffe8
// characters" — so NO environment loaded at all, `server.js` took its
// documented degrade-to-HTTP path, and the console came up on PLAINTEXT with
// no CREDENTIAL_KEY and no NEXTAUTH_SECRET. `sc.exe` reported Running
// throughout.
//
// ⛔ AN ENCODING IS A ROUND TRIP. Whoever wrote the write side reasoned about
// it carefully and never looked at the read. Checking one half proves nothing:
// it is the DISAGREEMENT between the two that corrupts, and either half alone
// looks defensible.
//
// ⛔ AND THE DAMAGE WAS INVISIBLE UNTIL IT WAS TOTAL. Doubling a comment is
// harmless at 40 bytes, at 400, at 40,000. There is no threshold at which it
// starts misbehaving — it works perfectly right up to the deploy where the
// file crosses a limit in a different language's runtime and the product
// silently stops encrypting.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const INSTALLER_DIR = path.join(__dirname, '..', 'installer');

// The variables the installer scripts use for a path to an env file. A read of
// any of these is a read of .env.local (or a backup copy of it).
const ENV_PATH_VARS = [
  '$EnvPath', '$envLocalPath', '$EnvFile', '$envCopy', '$envBackupPath',
];

const isComment = (line) => /^\s*#/.test(line);

function scriptLines() {
  return fs.readdirSync(INSTALLER_DIR)
    .filter((f) => f.endsWith('.ps1'))
    .flatMap((file) => fs.readFileSync(path.join(INSTALLER_DIR, file), 'utf8')
      .split('\n')
      .map((text, i) => ({ file, line: i + 1, text }))
      .filter((l) => !isComment(l.text)));
}

describe('⛔ every env-file read states its encoding', () => {
  const lines = scriptLines();

  it('found the installer scripts at all', () => {
    // A scan over nothing passes vacuously, which is the failure this whole
    // file exists to prevent in a different guise.
    assert.ok(lines.length > 500, `only ${lines.length} lines scanned — the glob is wrong`);
  });

  it('never reads an env file without -Encoding UTF8', () => {
    const offenders = lines
      .filter((l) => /Get-Content/.test(l.text))
      .filter((l) => ENV_PATH_VARS.some((v) => l.text.includes(v)))
      .filter((l) => !/-Encoding\s+UTF8/i.test(l.text))
      .map((l) => `${l.file}:${l.line}  ${l.text.trim()}`);

    assert.deepEqual(
      offenders,
      [],
      'Get-Content decodes with the ANSI codepage on PowerShell 5.1. These scripts '
        + 'write .env.local back as UTF-8, so a read without -Encoding UTF8 doubles '
        + 'every non-ASCII character on every deploy. It grew a comment to 2.2 GB and '
        + 'took the console down to plaintext HTTP. Add -Encoding UTF8.'
    );
  });

  it('keeps .env.local.example pure ASCII', () => {
    // ⛔ THE THIRD LAYER, AND THE ONLY ONE THAT REMOVES THE FUEL.
    // Layer 1 is -Encoding UTF8 on every read; layer 2 is the writer refusing an
    // oversized file. Both stop the DOUBLING. This stops there being anything to
    // double: .env.local.example is copied verbatim to .env.local on a fresh
    // install, so every byte in it is a byte the installer will read and rewrite
    // on every deploy for the life of that server.
    //
    // It held 27 non-ASCII characters -- 19 marker glyphs and 8 em-dashes, all in
    // COMMENTS that nothing ever read. One of them reached 2,209,122,508 bytes.
    const example = fs.readFileSync(path.join(__dirname, '..', '.env.local.example'), 'utf8');
    const offenders = [...example]
      .map((ch, i) => ({ ch, i }))
      .filter((c) => c.ch.codePointAt(0) > 127)
      .slice(0, 10)
      .map((c) => `offset ${c.i}: U+${c.ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`);

    assert.deepEqual(
      offenders,
      [],
      'A non-ASCII character reached .env.local.example. It will be copied into every '
        + 'new .env.local and re-encoded on every deploy. Use -- for a dash and !! for '
        + 'the emphasis marker.'
    );
  });

  it('keeps the size tripwire on the writer', () => {
    // ⛔ THE SECOND LAYER, because the first is one forgotten flag away from
    // coming back. A real .env.local is a few KB; the writer refuses to rewrite
    // anything remotely larger rather than laundering corruption into a
    // freshly-written file.
    const tls = fs.readFileSync(path.join(INSTALLER_DIR, 'SecVault-Tls.ps1'), 'utf8');
    assert.match(
      tls,
      /\$envSize\s*-gt\s*1MB/,
      'the oversized-.env.local guard in Set-SecVaultEnvLine is gone'
    );
  });
});
