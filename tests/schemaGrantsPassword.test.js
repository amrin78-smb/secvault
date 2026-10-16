'use strict';

// tests/schemaGrantsPassword.test.js
//
// ⛔ THE READONLY ROLE PASSWORD MAY NEVER BE A LITERAL IN THIS REPOSITORY.
// It was one until 2026-10-16: `CREATE ROLE claude_readonly LOGIN PASSWORD
// '<literal>'`, run verbatim by Install-SecVault.ps1 on every fresh install, so
// every SecVault in the field shared one password that anyone with the
// distribution folder could read. CertVault had already fixed this and its own
// schema-grants.sql names SecVault as the app that had not.
//
// This is a REPO SCAN rather than a behaviour test on purpose: the defect is
// the presence of a secret in a file, which no amount of running the code can
// reveal. The PowerShell side cannot be executed here at all (the 5.1 gate
// SKIPS off Windows), so the SQL contract is what gets pinned.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SQL = fs.readFileSync(path.join(__dirname, '..', 'lib', 'schema-grants.sql'), 'utf8');

describe('⛔ schema-grants.sql must not carry a password literal', () => {
  it('no CREATE ROLE ... PASSWORD \'<literal>\'', () => {
    // Matches a quoted literal after PASSWORD. The legitimate form is
    // `PASSWORD %L` inside a format(), which has no quotes around it.
    const bad = SQL.match(/PASSWORD\s+'[^']*'/gi) || [];
    assert.deepEqual(bad, [],
      `a password literal is present in schema-grants.sql: ${bad.join(', ')}`);
  });

  it('the role is created through format(%L) from a session setting', () => {
    assert.match(SQL, /current_setting\('secvault\.ro_pw'/,
      'the password must come from the GUC set in section 0');
    assert.match(SQL, /CREATE ROLE %I LOGIN PASSWORD %L/,
      'DDL cannot bind a parameter — %L is what quotes it safely');
  });

  it('⛔ absent password + absent role => NOLOGIN, never a default', () => {
    // The dangerous "fix" is a fallback literal. Failing closed is the whole
    // point: these roles are diagnostic-only, so a NOLOGIN role breaks nothing,
    // while a default password reinstates the original defect silently.
    assert.match(SQL, /CREATE ROLE %I NOLOGIN/);
    assert.match(SQL, /RAISE WARNING 'role % created NOLOGIN/,
      'a role that cannot log in must say why, or it looks like a broken install');
  });

  it('⛔ the password is read from the ENVIRONMENT, not from argv', () => {
    assert.match(SQL, /\\getenv readonly_password SECVAULT_READONLY_PASSWORD/,
      'a command line is readable by any local process and lands in transcripts');
  });

  it('⛔ server statement logging is suppressed across the password span', () => {
    // psql interpolates :'readonly_password' into the statement TEXT, so with
    // log_statement='all' the password would be written to the PostgreSQL log.
    // ⛔ ANCHORED TO THE START OF A LINE. The first version of this matched
    // `SET log_statement` anywhere, so commenting the statement out —
    // `-- SET log_statement removed;` — still satisfied it and the mutation
    // escaped. A check that a disabled line passes is a guard that cannot fire.
    const span = SQL.slice(SQL.indexOf('\\getenv readonly_password'), SQL.indexOf('RESET log_statement'));
    const KEYS = ['log_statement', 'log_min_duration_statement', 'log_min_error_statement', 'log_min_messages'];
    for (const k of KEYS) {
      assert.match(span, new RegExp(`^SET ${k}\\b`, 'm'), `${k} is not suppressed around the password`);
    }
    for (const k of KEYS) {
      assert.match(SQL, new RegExp(`^RESET ${k};`, 'm'), `${k} is suppressed but never RESET`);
    }
  });

  it('the session setting is cleared at the end of the file', () => {
    assert.match(SQL, /set_config\('secvault\.ro_pw', '', false\)[\s\S]*readonly_password_cleared/,
      'it was set with is_local=false, so it outlives the statement that set it');
  });

  it('⛔ set_config output is never the password itself', () => {
    // set_config RETURNS the new value, and installer output is routinely
    // logged — so every call is wrapped in a comparison that yields t/f.
    for (const m of SQL.match(/SELECT set_config\([^;]*;/g) || []) {
      assert.ok(/<>\s*''|=\s*''/.test(m), `set_config result is not reduced to a boolean: ${m.trim()}`);
    }
  });
});
