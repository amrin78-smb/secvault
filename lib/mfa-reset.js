#!/usr/bin/env node
'use strict';

// lib/mfa-reset.js — the last way back in.
//
//   node lib/mfa-reset.js <username>
//   node lib/mfa-reset.js --list
//
// ⛔ THIS EXISTS BECAUSE THE OTHER TWO PATHS CAN BOTH BE GONE AT ONCE. Recovery
// codes get lost with the laptop they were printed from, and a Super Admin can
// only reset SOMEONE ELSE — so an installation with one Super Admin who loses
// their phone has, without this, no way back that does not involve editing the
// database by hand. That is a rebuilt server over a lost phone.
//
// ⛔ IT IS NOT A BACKDOOR, and the distinction is worth being precise about.
// Running it requires a shell on the server that hosts the application and its
// database — which is strictly more access than any SecVault account confers.
// Anyone with that already owns the installation. The trust boundary here is
// the machine, not the account, and that is the same boundary the installer,
// the .env.local file and the PostgreSQL superuser already sit behind.
//
// ⛔ It removes the second factor. It does NOT set a password, weaken one, or
// grant a role — so it cannot turn shell access into an account that did not
// already exist.

const path = require('path');
const fs = require('fs');

// The app loads .env.local through Next; a bare node script does not, so read it
// here. Without CREDENTIAL_KEY the credStore require would throw on first use.
function loadEnvLocal() {
  const envPath = path.join(__dirname, '..', '.env.local');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)$/);
    if (!m) continue;
    // ⛔ Never overwrite a variable already present in the environment: an
    // operator who exported DATABASE_URL to point at a different server meant it.
    if (process.env[m[1]] === undefined) process.env[m[1]] = m[2].trim();
  }
}

async function main() {
  loadEnvLocal();

  // Required AFTER the env is loaded — lib/db.js builds its pool from
  // DATABASE_URL at module load.
  const { pool } = require('./db');
  const mfa = require('./mfa');

  const arg = process.argv[2];

  if (!arg || arg === '--help' || arg === '-h') {
    console.log('Usage:');
    console.log('  node lib/mfa-reset.js <username>   remove MFA from an account');
    console.log('  node lib/mfa-reset.js --list       show MFA state for every account');
    process.exitCode = arg ? 0 : 1;
    await pool.end();
    return;
  }

  if (arg === '--list') {
    const { rows } = await pool.query(
      `SELECT u.username, u.role,
              (m.user_id IS NOT NULL AND m.enabled) AS mfa_enabled,
              COALESCE(m.required, false) AS mfa_required,
              COALESCE(jsonb_array_length(m.recovery_codes), 0) AS recovery_left
         FROM users u LEFT JOIN user_mfa m ON m.user_id = u.id
        ORDER BY u.username`
    );
    console.log('username             role          MFA        required  recovery codes left');
    for (const r of rows) {
      console.log(
        `${String(r.username).padEnd(20)} ${String(r.role).padEnd(13)} `
        + `${(r.mfa_enabled ? 'ENABLED' : 'off').padEnd(10)} `
        + `${String(r.mfa_required).padEnd(9)} ${r.recovery_left}`
      );
    }
    await pool.end();
    return;
  }

  const { rows } = await pool.query('SELECT id, username FROM users WHERE username = $1', [arg]);
  if (rows.length === 0) {
    console.error(`No local account named '${arg}'. Use --list to see the accounts that exist.`);
    process.exitCode = 1;
    await pool.end();
    return;
  }

  const before = await mfa.getStatus(pool, rows[0].id);
  if (!before.enrolled) {
    console.log(`'${arg}' has no MFA enrolment — nothing to reset.`);
    await pool.end();
    return;
  }

  await mfa.resetFor(pool, rows[0].id);

  console.log(`MFA removed from '${arg}'.`);
  console.log('They can now sign in with username and password alone, and should enrol a new');
  console.log('device from Settings -> Security immediately.');
  // ⛔ Said out loud rather than left for the operator to notice. A silent reset
  // of a REQUIRED account looks like the requirement was lifted, and it was not.
  if (before.required) {
    console.log('');
    console.log('NOTE: this account is still flagged as REQUIRING MFA, so the requirement stands');
    console.log('and they will be prompted to enrol again. That flag was deliberately left alone.');
  }

  await pool.end();
}

// ⛔ ONLY WHEN RUN DIRECTLY. Without this guard, merely requiring the file —
// which tests/moduleLoad.test.js does to every server module, and which caught
// exactly this — executes main(), prints the usage text and sets a non-zero
// process.exitCode. That turns an unrelated test run (or any future import) into
// a failure with no obvious cause. A CLI entry point must be inert on import.
if (require.main === module) {
  main().catch((err) => {
    console.error('mfa-reset failed:', err.message);
    process.exitCode = 1;
  });
}

module.exports = { main };
