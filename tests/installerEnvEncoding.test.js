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

// Anything that names an env file: the variables the scripts hold one in, plus
// the literal filename for an inline Join-Path.
//
// ⛔ MATCHED CASE-INSENSITIVELY AND AS A PREFIX, because PowerShell
// variables are case-insensitive and the near-miss name is ALREADY IN THE TREE:
// Update-SecVault.ps1 holds the same path in `$envLocal` and
// `$envLocalForScheme`, neither of which contains the substring
// `$envLocalPath`. Both only feed a reader that is already correct, so nothing
// is missed today -- but one `Get-Content $envLocal -Raw` added beside them
// reintroduces the 2.2 GB outage with this test still green. A guard that
// matches the exact spellings that happen to exist today is a guard that
// cannot fire tomorrow.
const ENV_PATH_PATTERNS = [
  /\$env(Local|File|Path|Copy|Backup)/i,   // $envLocal, $envLocalPath, $envLocalForScheme, $envFile, $envCopy...
  /\$EnvPath\b/i,
  /\.env\.local/i,                         // an inline Join-Path / literal
];
const namesAnEnvFile = (text) => ENV_PATH_PATTERNS.some((re) => re.test(text));

// ⛔ EVERY WAY PS 5.1 CAN DECODE OR ENCODE A FILE, not just the two
// that were used on the day. Each of these has its OWN default: Get-Content
// and Set-Content/Add-Content/Out-File use the ANSI codepage, Select-String
// and `switch -File` have their own, and the .NET helpers default to UTF-8
// (correct, and exempt -- they state their encoding by construction).
const READERS = /\b(Get-Content|Select-String|switch\s+-File)\b/i;
const WRITERS = /\b(Set-Content|Add-Content|Out-File)\b/i;
const STATES_UTF8 = /-Encoding\s+UTF8/i;

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

  const offendersMatching = (cmdlets) => lines
    .filter((l) => cmdlets.test(l.text))
    .filter((l) => namesAnEnvFile(l.text))
    .filter((l) => !STATES_UTF8.test(l.text))
    .map((l) => `${l.file}:${l.line}  ${l.text.trim()}`);

  it('never READS an env file without -Encoding UTF8', () => {
    assert.deepEqual(
      offendersMatching(READERS),
      [],
      'Get-Content decodes with the ANSI codepage on PowerShell 5.1. These scripts '
        + 'write .env.local back as UTF-8, so a read without -Encoding UTF8 doubles '
        + 'every non-ASCII character on every deploy. It grew a comment to 2.2 GB and '
        + 'took the console down to plaintext HTTP. Add -Encoding UTF8.'
    );
  });

  it('never WRITES an env file without stating its encoding', () => {
    // ⛔ THIS HALF WAS MISSING, AND SO WAS THE DEFECT IT CATCHES.
    // The original scan filtered on /Get-Content/ and asserted nothing about any
    // write, so `Set-Content -Path $envLocalPath -Value $envContent -NoNewline`
    // -- in Install-SecVault.ps1, the script that CREATES the file, nine lines
    // above a read that had been corrected -- passed it cleanly. Measured in a
    // PS 5.1.26100 harness: that write emits an em-dash as the single ANSI byte
    // 0x97, and `Get-Content -Encoding UTF8` reads it back as U+FFFD.
    //
    // The same disagreement as the outage, running the other way. Fixing one
    // half of a round trip and testing only that half is what left it.
    assert.deepEqual(
      offendersMatching(WRITERS),
      [],
      'Set-Content/Add-Content/Out-File encode with the ANSI codepage on PowerShell '
        + '5.1, while every read of these files now decodes UTF-8. Write with '
        + '[System.IO.File]::WriteAllText(path, text, (New-Object System.Text.UTF8Encoding($false))) '
        + 'or pass -Encoding UTF8. An encoding is a ROUND TRIP -- both ends have to agree.'
    );
  });

  it('every pattern the scan is built from still matches something', () => {
    // ⛔ A SCAN THAT MATCHES NOTHING PASSES. Both assertions above are
    // negative, so a typo'd regex or a renamed variable turns this file into
    // decoration that reports success for ever.
    //
    // The three patterns are pinned SEPARATELY rather than as an intersection,
    // because the intersection of WRITERS and namesAnEnvFile is now legitimately
    // EMPTY -- that is the fix: the one cmdlet-based env write in the tree became
    // [System.IO.File]::WriteAllText, which states its encoding by construction.
    // Requiring a compliant example of the thing we just abolished would fail the
    // moment the codebase got it right.
    const matching = (re) => lines.filter((l) => re.test(l.text)).length;
    assert.ok(matching(READERS) >= 6, `READERS matched ${matching(READERS)} lines -- the cmdlet pattern has drifted`);
    assert.ok(matching(WRITERS) >= 6, `WRITERS matched ${matching(WRITERS)} lines -- the cmdlet pattern has drifted`);
    assert.ok(
      lines.filter((l) => namesAnEnvFile(l.text)).length >= 10,
      'no line names an env file any more -- ENV_PATH_PATTERNS has drifted'
    );
    // And the reads it polices are really there, stating UTF8.
    const envReads = lines.filter((l) => READERS.test(l.text)).filter((l) => namesAnEnvFile(l.text));
    assert.ok(envReads.length >= 6, `only ${envReads.length} env-file reads matched -- the patterns have drifted`);
  });

  it('keeps .env.local.example pure ASCII', () => {
    // ⛔ THE THIRD LAYER, AND THE ONLY ONE THAT REMOVES THE FUEL.
    // Layer 1 is a STATED ENCODING ON BOTH ENDS of every round trip (read AND
    // write -- the write side was the half originally left out, and left
    // unchecked); layer 2 is both writers refusing an oversized file. Both stop
    // the DOUBLING. This stops there being anything to
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
    // ⛔ ON BOTH READ-MODIFY-WRITE PATHS. It was only on
    // SecVault-Tls.ps1's Set-SecVaultEnvLine; Install-SecVault.ps1's step 10
    // (Copy-Item backup -> two Get-Content -Raw -> write) had none, so the
    // corrupt file it exists to catch produced a 2.2 GB backup copy and an
    // opaque OutOfMemoryException instead of the recovery instructions.
    for (const file of ['SecVault-Tls.ps1', 'Install-SecVault.ps1']) {
      assert.match(
        fs.readFileSync(path.join(INSTALLER_DIR, file), 'utf8'),
        /-gt\s*1MB/,
        `the oversized-.env.local guard is gone from ${file}`
      );
    }
  });
});
