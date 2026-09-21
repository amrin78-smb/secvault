'use strict';
//
// lib/envFile.js — change ONE value in .env.local without losing the rest.
//
// ⛔ THIS FILE HOLDS EVERY SECRET THE PRODUCT HAS. CREDENTIAL_KEY, which is the
// only thing that can decrypt `device_credentials`; the database password; the
// NextAuth secret. A bug here that truncated or re-serialised the file would be
// worse than any outage in this codebase: the backup script exists precisely
// because a restore without CREDENTIAL_KEY produces an installation that looks
// completely healthy and cannot reach a single firewall.
//
// So this does the least possible: a LINE EDIT. Comments, ordering, blank lines
// and every untouched value survive byte for byte, because nothing re-writes
// them — the file is split into lines, one line is replaced, and the lines are
// joined again.
//
// ⛔ AND IT VERIFIES ITSELF AFTER WRITING. Every key that existed before must
// still exist afterwards with the same value, except the one being changed. If
// that does not hold, the backup is restored and the call fails. A write that
// silently dropped a key would not be noticed until the next restart, by which
// point the original is gone.

const fs = require('node:fs');
const path = require('node:path');

// Matches KEY=value, capturing the key. Leading `export ` is tolerated because
// some operators paste from a shell script.
//
// ⛔ THE TRAILING \r IS NOT COSMETIC — WITHOUT IT THIS FILE CORRUPTS THE ONE
// FILE IT EXISTS TO PROTECT. JavaScript's `.` does not match \r and `$` without
// the `m` flag will not match before one, so on a CRLF file every exec()
// returned null: the key was never FOUND, so it was never REPLACED, so it was
// APPENDED — and the duplicate-key refusal below could never fire either,
// because the scan that counts occurrences uses this same regex.
//
// And CRLF is the shipped shape, not an edge case: `.env.local` is copied from
// `.env.local.example`, which this repo checks out CRLF under git's default
// `core.autocrlf=true` on Windows, and `Set-SecVaultEnvValue` in the installer
// appends `\r\n` explicitly.
//
// The consequence was silent and asymmetric: node/dotenv reads the LAST
// occurrence so the console kept working, while `Get-SecVaultEnvValue` in
// Update-SecVault.ps1 reads the FIRST — the stale one — and writes it back,
// reverting the console address to the old hostname on the next deploy.
const LINE_RE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*?)\r?$/;

/** Parse into { key: value } without touching the file. */
function parseEnv(text) {
  const out = {};
  for (const line of String(text || '').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const m = LINE_RE.exec(line);
    if (!m) continue;
    // A value is taken verbatim, including '=' inside it (DATABASE_URL and
    // base64 secrets both contain them). Only a wrapping pair of quotes is
    // stripped, because that is how a value with spaces is written.
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    out[m[1]] = v;
  }
  return out;
}

function readEnvFile(filePath) {
  const text = fs.readFileSync(filePath, 'utf8');
  return { text, values: parseEnv(text) };
}

/**
 * Replace (or append) one key. Returns {ok, backupPath, previous} or {ok:false,error}.
 *
 * ⛔ NOT ATOMIC BY RENAME, DELIBERATELY. A rename would replace the file and
 * drop any ACL set on it; .env.local is the most access-controlled file in the
 * install and inheriting a fresh default would widen it silently. It writes in
 * place, after a verified backup, and restores that backup on any mismatch.
 */
function setEnvValue(filePath, key, value) {
  if (!LINE_RE.test(`${key}=x`)) return { ok: false, error: `Invalid environment key: ${key}` };
  const newValue = String(value == null ? '' : value);
  if (/[\r\n]/.test(newValue)) {
    return { ok: false, error: 'A value may not contain a line break.' };
  }

  let before;
  try {
    before = readEnvFile(filePath);
  } catch (err) {
    return { ok: false, error: `Could not read ${filePath}: ${err.message}` };
  }

  const previous = Object.prototype.hasOwnProperty.call(before.values, key)
    ? before.values[key]
    : null;
  if (previous === newValue) {
    return { ok: true, unchanged: true, previous, backupPath: null };
  }

  // Timestamped, beside the original, same convention the certificate install
  // already uses. An operator who needs to undo this must be able to see it.
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = path.join(path.dirname(filePath), `${path.basename(filePath)}.${stamp}.bak`);
  try {
    fs.writeFileSync(backupPath, before.text, { encoding: 'utf8', mode: 0o600 });
  } catch (err) {
    return { ok: false, error: `Could not write a backup before changing the file: ${err.message}` };
  }

  // ⛔ SPLIT ON BOTH, AND REMEMBER WHICH. Splitting on '\n' alone leaves a
  // trailing '\r' on every line of a CRLF file; joining with '\n' alone would
  // then silently rewrite the whole file to LF, which is a diff against every
  // secret in it and a gratuitous change to a file the installer also edits.
  const eol = before.text.includes('\r\n') ? '\r\n' : '\n';
  const lines = before.text.split(/\r?\n/);
  const occurrences = [];
  for (let i = 0; i < lines.length; i++) {
    const m = LINE_RE.exec(lines[i]);
    if (m && m[1] === key) occurrences.push(i);
  }

  // ⛔ A DUPLICATED KEY IS REFUSED, NOT GUESSED AT. Which copy a loader
  // honours is a property of the LOADER, not of this file -- and picking the
  // wrong one means the save reports success and changes nothing, which is
  // precisely the silent failure this whole feature exists to prevent.
  // Found by a test: the writer replaced the FIRST occurrence while parseEnv
  // read the LAST, so the two disagreed about which value was even current.
  if (occurrences.length > 1) {
    return {
      ok: false,
      error: `${key} appears ${occurrences.length} times in ${path.basename(filePath)} `
        + `(lines ${occurrences.map((i) => i + 1).join(', ')}). Remove the duplicates by hand `
        + 'first -- editing one of them may have no effect, depending on which the loader reads.',
    };
  }

  let replaced = false;
  if (occurrences.length === 1) {
    lines[occurrences[0]] = `${key}=${newValue}`;
    replaced = true;
  }
  if (!replaced) {
    if (lines.length && lines[lines.length - 1].trim() === '') lines.pop();
    lines.push(`${key}=${newValue}`, '');
  }

  try {
    fs.writeFileSync(filePath, lines.join(eol), 'utf8');
  } catch (err) {
    return { ok: false, error: `Could not write ${filePath}: ${err.message}`, backupPath };
  }

  // ⛔ THE SELF-CHECK. Read it back and prove nothing else moved.
  // ⛔ ITS OWN READ IS GUARDED. It used to be bare, so a transient EBUSY here
  // threw out of setEnvValue AFTER the file had already been rewritten — and
  // the callers expect a verdict object, not an exception, so the operator got
  // an opaque 500 with no backupPath and no recovery sentence on the very field
  // this function exists to make recoverable.
  let after;
  try {
    after = readEnvFile(filePath);
  } catch (err) {
    return {
      ok: false,
      error: `Wrote ${path.basename(filePath)} but could not read it back to verify it: `
        + `${err.message}. The previous contents are at the backup path below.`,
      backupPath,
    };
  }
  const lost = [];
  for (const [k, v] of Object.entries(before.values)) {
    if (k === key) continue;
    if (!Object.prototype.hasOwnProperty.call(after.values, k) || after.values[k] !== v) lost.push(k);
  }
  if (lost.length > 0 || after.values[key] !== newValue) {
    try {
      fs.writeFileSync(filePath, before.text, 'utf8');
    } catch (err) {
      return {
        ok: false,
        error: `The file was written incorrectly (${lost.join(', ') || key}) AND could not be restored: `
          + `${err.message}. Restore it by hand from ${backupPath}.`,
        backupPath,
      };
    }
    return {
      ok: false,
      error: `Writing ${key} would have changed ${lost.length} other value(s) (${lost.slice(0, 5).join(', ')}). `
        + 'Nothing was changed — the original file has been restored.',
      backupPath,
    };
  }

  return { ok: true, previous, backupPath, unchanged: false };
}

module.exports = { parseEnv, readEnvFile, setEnvValue, LINE_RE };
