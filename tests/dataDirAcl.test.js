'use strict';

// ⛔ THE SPOOL AND THE ARCHIVE WERE NEVER RESTRICTED, AND v2.225.3 FIXED ONLY
// THE BACKUP DIRECTORY. Measured read-only on production 2026-11-15, before
// anything was changed:
//
//   E:\                    BUILTIN\Users:(OI)(CI)(RX) + (CI)(AD) + (CI)(WD)
//   E:\SecVaultBackup      inheritance broken  (v2.225.3)   OK
//   E:\PostgreSQL\16\data  inheritance broken  (installer)  OK
//   E:\SecVaultArchive     BUILTIN\Users:(I)(OI)(CI)(RX)    EXPOSED
//   E:\SecVaultSpool       same, plus (AD)/(WD)             EXPOSED + WRITABLE
//
// Confirmed on a real file rather than the container:
// E:\SecVaultArchive\syslog-20261001.log.gz -> BUILTIN\Users:(I)(RX).
//
// The archive is the ONLY copy of the raw line for the ~89% of rows the
// database strips, and the spool is WRITABLE by non-admins while the collector
// REPLAYS any .ready file it finds there at startup -- an injection path into
// syslog_events, and therefore into log_hit (priority-tree rule 2), hit_count
// and every rule-usage finding.
//
// ⛔ THIS GUARD IS TEXT-BASED AND THAT IS A STATED LIMITATION, NOT AN OVERSIGHT.
// It cannot execute PowerShell off Windows. The BEHAVIOUR was verified on the
// authoritative platform (staging, PowerShell 5.1.26100.9818): 18 assertions
// including the production-faithful INHERITED case, that SYSTEM can still write
// afterwards, idempotency, that a missing path is not created, and that an
// EXPLICIT non-admin ACE fails CLOSED with the principal named. What this file
// pins is that the call sites do not quietly disappear.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { readPs } = require('./psScripts');
const { stripComments } = require('./stripComments');

// ⛔ COMMENTS ARE STRIPPED BEFORE ANY CODE-SHAPED ASSERTION, AND THE FIRST
// DRAFT OF THIS FILE PROVED WHY TWICE. Its "must not create the directory"
// check was a bare /New-Item/ over the raw source and FAILED ON CORRECT CODE,
// because the helper's own header names `New-Item` twice while explaining the
// Windows default; and its `/inheritance:r` and verify assertions PASSED over
// mutations that removed those lines from the code, because the same strings
// appear in the surrounding prose. Both halves of the prose-read-as-code trap,
// in the test written to prevent it.
// ⛔ The SHARED stripper's `ps` mode, not a fourth hand-rolled copy — see
// tests/stripComments.js for why PowerShell needs the opposite order to JS.
const acl = readPs('SecVault-Acl.ps1');
const aclCode = stripComments(acl, { ps: true });
const install = readPs('Install-SecVault.ps1');
const update = readPs('Update-SecVault.ps1');

describe('⛔ the shared data-directory lockdown', () => {
  it('exists as ONE definition, dot-sourced rather than copied', () => {
    assert.match(aclCode, /function\s+Protect-SecVaultDirectory/);
    // ⛔ A second copy is what SecVault-Tls.ps1 exists to prevent. Both
    // installers must dot-source it, not reimplement it.
    for (const [name, text] of [['Install', install], ['Update', update]]) {
      assert.match(text, /SecVault-Acl\.ps1/, `${name} does not reference the shared helper`);
      assert.match(text, /\.\s+\$aclHelpers/, `${name} does not dot-source it`);
    }
  });

  it('⛔ breaks inheritance, which is the part that actually does the work', () => {
    // Every offending ACE on production is INHERITED, so without
    // /inheritance:r the grants below change nothing at all.
    assert.match(aclCode, /'\/inheritance:r'/);
  });

  it('⛔ leaves SYSTEM in control, because all three services run as LocalSystem', () => {
    assert.match(aclCode, /NT AUTHORITY\\SYSTEM:\(OI\)\(CI\)F/);
    assert.match(aclCode, /BUILTIN\\Administrators:\(OI\)\(CI\)F/);
  });

  it('⛔ VERIFIES the result instead of trusting the exit code', () => {
    // A zero exit says icacls RAN. The only fact that matters is whether a
    // non-admin principal can still reach the directory.
    assert.match(aclCode, /\$aclCheck\s*=\s*Invoke-Native/);
    assert.match(aclCode, /BUILTIN\\\\Users\|\\bEveryone\\b/);
    const grant = aclCode.indexOf("'/inheritance:r'");
    const verify = aclCode.indexOf('$aclCheck');
    assert.ok(grant > 0 && verify > grant, 'the verification must run AFTER the lockdown');
  });

  it('⛔ never throws, and never creates the directory', () => {
    // Refusing to proceed would stop the collector, and while it is down
    // datagrams are gone rather than queued.
    assert.ok(!/\bthrow\b/i.test(aclCode), 'this helper must not throw -- callers decide');
    assert.match(aclCode, /return \$false/);
    // Creating a missing directory would make a wrong SYSLOG_SPOOL_DIR look healthy.
    assert.ok(!/New-Item/.test(aclCode),
      'it must not create the directory it was asked to protect');
  });

  it('⛔ an EXPLICIT non-admin ACE is NAMED and not silently stripped', () => {
    // /inheritance:r cannot remove it and /grant:r does not either. Removing
    // every unrecognised principal could cut off a customer's backup agent.
    assert.match(aclCode, /EXPLICIT ACEs/);
    assert.match(aclCode, /\/remove:g/);
  });

  it('⛔ UPDATE restricts both directories on EVERY deploy — the call site that matters', () => {
    // Every deployed server already HAS these directories, so a create-time
    // fix reaches fresh installs only: the CREATE TABLE IF NOT EXISTS trap.
    // The backup directory got away with it because a nightly job re-applies
    // it; these two have no such job.
    const calls = update.match(/Protect-SecVaultDirectory/g) || [];
    assert.ok(calls.length >= 2,
      `Update must restrict the spool AND the archive, found ${calls.length} call(s)`);
    assert.match(update, /-Label 'Syslog spool'/);
    assert.match(update, /-Label 'Syslog archive'/);
  });

  it('⛔ and it is non-fatal in Update, so a bad ACL can never stop the deploy', () => {
    const at = update.indexOf('SecVault-Acl.ps1');
    assert.ok(at > 0);
    const block = update.slice(at - 1200, at + 3000);
    assert.match(block, /\[WARN\]/, 'a failure here must warn, not fail the update');
  });

  it('⛔ reads .env.local as UTF8 in both scripts — an encoding is a round trip', () => {
    // Get-Content decodes with the ANSI codepage; the bare form is the
    // round-trip bug CLAUDE.md records as a production outage.
    // ⛔ ANCHORED ON THE ACL BLOCK, NOT ON THE FIRST MENTION OF THE VARIABLE.
    // The first draft searched for `SYSLOG_ARCHIVE_DIR` with indexOf and found
    // a COMMENT about it 400 lines earlier in Install-SecVault.ps1, so the
    // window it examined contained no code at all -- a guard looking in the
    // wrong place, which reads exactly like a guard that passed.
    for (const [name, text] of [['Install', install], ['Update', update]]) {
      const at = text.indexOf('SecVault-Acl.ps1');
      assert.ok(at > 0, `${name} does not reference the shared helper`);
      const block = text.slice(at, at + 2500);
      // Accepts either spelling: Install matches SYSLOG_ARCHIVE_DIR on its
      // own, Update uses one combined SYSLOG_(SPOOL|ARCHIVE)_DIR pattern.
      assert.match(block, /SYSLOG_(?:ARCHIVE_DIR|\(SPOOL\|ARCHIVE\)_DIR)/,
        `${name} does not resolve the archive directory beside the lockdown`);
      assert.match(block, /Get-Content -LiteralPath \$env\w+ -Encoding UTF8/,
        `${name} must read .env.local with -Encoding UTF8`);
    }
  });
});
