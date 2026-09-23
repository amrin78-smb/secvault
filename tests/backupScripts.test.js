'use strict';
// Pins the backup/restore scripts' load-bearing properties.
//
// ⛔ WHY A SOURCE-SCAN TEST. These are PowerShell, so `npm test` cannot execute
// them — but every property below fails SILENTLY if it regresses, and the place
// you find out is a disaster recovery. A scan that asserts the flags are present
// is worth far more here than nothing, and it is the same technique this repo
// already uses for `syslog_events` refusals and the segmentation tint ranking.
//
// What it cannot check is that a restore actually works. Only running one does
// that, and `docs/SIZING-AND-BACKUP.md` says so.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const dir = path.join(__dirname, '..', 'installer');
const backup = fs.readFileSync(path.join(dir, 'Backup-SecVault.ps1'), 'utf8');
const restore = fs.readFileSync(path.join(dir, 'Restore-SecVault.ps1'), 'utf8');
const install = fs.readFileSync(path.join(dir, 'Install-SecVault.ps1'), 'utf8');

/**
 * The script with its comments stripped.
 *
 * ⛔ THE BANS BELOW ARE ABOUT CODE, NOT PROSE. Scanning the raw source made two
 * of these tests fail against the comments that EXPLAIN the ban — the line
 * "sc.exe, never Stop-Service" contains "Stop-Service", and the paragraph
 * recording that -SkipCertificateCheck cost two outages contains
 * "-SkipCertificateCheck". Loosening the assertion would have been the wrong
 * fix, and deleting those comments to satisfy it would have been far worse:
 * they are the only reason the next person does not reintroduce either one.
 */
function codeOnly(src) {
  // ⛔ NORMALISE LINE ENDINGS FIRST. Without this the stripper silently does
  // nothing on a CRLF file: `.` does not match `\r`, so `.*$` cannot reach the
  // end of a line that ends `\r`, and `^\s*#.*$` never matches a comment.
  //
  // It passed when written and failed later for no apparent code change,
  // because a file WRITTEN here is LF and the same file CHECKED OUT FROM GIT is
  // CRLF (core.autocrlf). A test whose result depends on which of those you are
  // looking at is worse than no test — it goes green locally and red in CI, or
  // the reverse, and the obvious "fix" is to weaken the assertion it was right
  // about all along.
  return src
    .replace(/\r\n/g, '\n')
    .replace(/<#[\s\S]*?#>/g, '')                // block comments
    .split('\n')
    .map((line) => line.replace(/^\s*#.*$/, '')) // whole-line comments
    .join('\n');
}
const restoreCode = codeOnly(restore);
const backupCode = codeOnly(backup);

describe('⛔ raw syslog is excluded by DATA, never by TABLE', () => {
  it('uses --exclude-table-data', () => {
    assert.match(backup, /--exclude-table-data=public\.syslog_events\*/);
  });

  it('⛔ NEVER uses --exclude-table on syslog_events', () => {
    // The distinction is the whole thing. --exclude-table drops the CREATE
    // TABLE and every partition definition too, so a restore comes up with no
    // partitioned syslog_events, the collector starts, every INSERT fails, and
    // the only symptom is a syslog pipeline that is quietly dead.
    assert.ok(
      !/--exclude-table=/.test(backup),
      'Backup-SecVault.ps1 uses --exclude-table, which would lose the partition structure'
    );
  });

  it('dumping raw syslog is opt-in, not the default', () => {
    assert.match(backup, /\[switch\]\$IncludeSyslog/);
    assert.match(backup, /if \(-not \$IncludeSyslog\)/);
  });
});

describe('⛔ the credential key travels with the backup, and is checked on restore', () => {
  it('the backup copies .env.local', () => {
    // device_credentials is AES-256-GCM keyed on CREDENTIAL_KEY, which lives
    // only in .env.local. A dump without it restores an installation that looks
    // entirely healthy and cannot reach a single firewall.
    assert.match(backup, /Copy-Item[\s\S]{0,120}\$envCopy/);
    assert.match(backup, /CREDENTIAL_KEY/);
  });

  it('⛔ the restore STOPS when the key does not match', () => {
    assert.match(restore, /CREDENTIAL_KEY/);
    assert.match(restore, /Restore ABORTED/);
    // And the escape hatch exists, because "re-enter every credential" is a
    // legitimate choice — it just must not be the silent default.
    assert.match(restore, /\[switch\]\$SkipKeyCheck/);
  });

  it('the mismatch message says what actually goes wrong, not just "mismatch"', () => {
    // "Key mismatch" tells an operator nothing about what they are about to
    // break. The symptom — a healthy-looking install that cannot authenticate
    // to anything — is what makes the warning actionable.
    assert.match(restore, /cannot authenticate to a single firewall/i);
  });
});

describe('⛔ a backup verifies itself while a good copy still exists', () => {
  it('reads the finished dump back with pg_restore --list', () => {
    assert.match(backup, /PgRestore[\s\S]{0,60}--list/);
  });

  it('deletes a dump it could not read back', () => {
    // A corrupt file that looks like a backup is worse than no backup: it is
    // relied on, and discovered at the disaster.
    assert.match(backup, /Remove-Item \$dumpPath[\s\S]{0,80}exit 1/);
  });

  it('⛔ rejects a well-formed but EMPTY archive', () => {
    // An empty archive passes --list cleanly. A real SecVault database has
    // dozens of tables, so a single-digit entry count means something upstream
    // went wrong and the exit code did not say so.
    assert.match(backup, /tocCount -lt 20/);
  });

  it('checks free space BEFORE dumping', () => {
    // A dump that fills its volume leaves a TRUNCATED file that looks complete.
    assert.match(backup, /requiredMb/);
    assert.match(backup, /Refusing to write a backup that may be truncated/);
  });

  it('⛔ prunes old backups only AFTER the new one is verified', () => {
    const verifyAt = backup.indexOf('--list');
    const pruneAt = backup.indexOf('$KeepBackups)');
    assert.ok(verifyAt > 0 && pruneAt > 0, 'could not locate both phases');
    assert.ok(
      verifyAt < pruneAt,
      'pruning happens before verification — a bad night would become data loss'
    );
  });
});

describe('⛔ the restore is a dry run until told otherwise', () => {
  it('requires -Force to change anything', () => {
    assert.match(restore, /\[switch\]\$Force/);

    // ⛔ BRACE-MATCHED, NOT A FIXED CHARACTER WINDOW. This asserted
    // `if \(-not \$Force\)[\s\S]{0,400}exit 0` and broke the moment the block
    // grew past 400 characters -- which it did by gaining two lines of
    // explanation, with the guard itself completely intact. A test that fails
    // when correct code is DOCUMENTED teaches the next person to widen the
    // number, and the time after that to delete the test. Find the block and
    // read what is actually in it.
    const at = restore.indexOf('if (-not $Force)');
    assert.ok(at !== -1, 'the dry-run gate is gone entirely');
    const open = restore.indexOf('{', at);
    assert.ok(open !== -1, 'the dry-run gate has no block');
    let depth = 0;
    let close = -1;
    for (let i = open; i < restore.length; i += 1) {
      if (restore[i] === '{') depth += 1;
      else if (restore[i] === '}') {
        depth -= 1;
        if (depth === 0) { close = i; break; }
      }
    }
    assert.ok(close !== -1, 'the dry-run gate block is unterminated');
    const block = restore.slice(open, close);
    assert.match(block, /\bexit 0\b/,
      'without -Force the restore must EXIT, not fall through into a destructive path');
  });

  it('stops services with sc.exe, never the PowerShell cmdlets', () => {
    // Stop-Service silently disconnects WinRM sessions and hangs terminals on
    // this platform — a Critical Rule in this repo.
    assert.match(restoreCode, /sc\.exe stop/);
    for (const banned of ['Stop-Service', 'Start-Service', 'Get-Service', 'Restart-Service']) {
      assert.ok(!restoreCode.includes(banned), 'Restore-SecVault.ps1 uses ' + banned);
      assert.ok(!backupCode.includes(banned), 'Backup-SecVault.ps1 uses ' + banned);
    }
  });

  it('⛔ verifies the APP answers, not that the SERVICE is running', () => {
    // NSSM restarts a crashing process, so sc.exe reports Running while node
    // crash-loops. Same lesson the TLS upgrade learned the hard way.
    assert.match(restore, /Test-SecVaultResponding/);
    assert.match(restore, /api\/health/);
  });

  it('⛔ does NOT hand-roll the TLS probe', () => {
    // -SkipCertificateCheck is PowerShell 7 only and this runs on 5.1, and the
    // obvious ServerCertificateValidationCallback route cost two production
    // outages (it cannot work in 5.1 — no runspace on the callback thread — so
    // the probe always returns false over HTTPS and a good deploy gets rolled
    // back). The shared helper in SecVault-Tls.ps1 is the only correct route.
    assert.ok(
      !restoreCode.includes('SkipCertificateCheck'),
      'uses -SkipCertificateCheck, which is PowerShell 7 only'
    );
    assert.ok(
      !restoreCode.includes('ServerCertificateValidationCallback'),
      'uses ServerCertificateValidationCallback, which cannot work on PowerShell 5.1'
    );
    assert.match(restoreCode, /SecVault-Tls\.ps1/);
    // ⛔ And the comments explaining both bans must SURVIVE — they are the only
    // reason the next person does not reintroduce either one. Asserted against
    // the RAW source, deliberately.
    assert.match(restore, /TWO PRODUCTION OUTAGES/);
  });

  it('re-applies schema and grants, which the dump could not carry', () => {
    // The dump predates any schema shipped since, and --no-acl drops the
    // readonly grants entirely.
    assert.match(restore, /migrate\.js/);
    assert.match(restore, /schema-grants\.sql/);
  });
});

describe('the install registers the backup', () => {
  it('creates a daily SYSTEM scheduled task', () => {
    assert.match(install, /SecVaultBackup/);
    assert.match(install, /schtasks \/create[\s\S]{0,140}\/ru SYSTEM/);
  });

  it('⛔ a failure to register warns rather than failing the install', () => {
    // A machine where the task cannot be registered still has a working
    // SecVault, and the script can always be run by hand.
    const at = install.indexOf('SecVaultBackup');
    const block = install.slice(at - 900, at + 900);
    assert.match(block, /\[WARN\]/);
  });
});

describe('⛔ BOTH installer paths register the task', () => {
  const update = fs.readFileSync(path.join(dir, 'Update-SecVault.ps1'), 'utf8');

  it('the UPDATER registers it too, not just the installer', () => {
    // It was added to Install-SecVault.ps1 alone, and the reference deployment
    // — which upgrades and never reinstalls — had no backup task at all. The
    // script was present, tested and working; nothing was going to run it.
    // Same shape as CREATE TABLE IF NOT EXISTS guarding only creation.
    assert.match(update, /SecVaultBackup/);
    assert.match(update, /schtasks \/create/);
  });

  it('registration is idempotent and never fatal', () => {
    const at = update.indexOf('SecVaultBackup');
    const block = update.slice(Math.max(0, at - 1400), at + 1200);
    assert.match(block, /\/f /, 'schtasks needs /f to overwrite on every update');
    assert.match(block, /\[WARN\]/, 'a failure to register must warn, not fail the update');
  });
});

describe('the sizing guide states measurements, not estimates', () => {
  const doc = fs.readFileSync(
    path.join(__dirname, '..', 'docs', 'SIZING-AND-BACKUP.md'), 'utf8'
  );

  it('⛔ warns against sizing by device count', () => {
    // The busiest firewall on the reference fleet produces 94x the traffic of
    // the quietest. A per-device model is wrong for almost every customer.
    assert.match(doc, /Do not size by device count/i);
    assert.match(doc, /94/);
  });

  it('states the row cost depends on SYSLOG_RAW_MESSAGE', () => {
    // ~340 bytes/row is only true at `security`. At `all` the window triples.
    assert.match(doc, /SYSLOG_RAW_MESSAGE/);
    assert.match(doc, /triple/i);
  });

  it('says what a restore does NOT bring back', () => {
    assert.match(doc, /What a restore does not bring back/i);
  });
});
