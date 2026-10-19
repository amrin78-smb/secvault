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
const crypto = require('crypto');
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

// ⛔ 1 MB, the same bound both installer env writers use. An environment file
// is a few hundred bytes; anything approaching this is corruption, not config.
const MAX_ENV_BYTES = 1024 * 1024;

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

  // ⛔ THE SIZE TRIPWIRE, WHICH BOTH POWERSHELL ENV WRITERS HAVE AND THIS ONE
  // DID NOT. `Set-SecVaultEnvLine` and Install-SecVault.ps1 each refuse a
  // .env.local over 1 MB, the latter explicitly BEFORE taking its backup so a
  // corrupt file is not duplicated first. A 2.2 GB file already fails closed
  // here (readFileSync throws ERR_STRING_TOO_LONG, caught above) — but a
  // 50-500 MB one does not: it would be read, COPIED IN FULL into a
  // secret-bearing .bak, rewritten and read back. Refuse instead, and refuse
  // before the backup for the same reason the installer does.
  if (before.text.length > MAX_ENV_BYTES) {
    return {
      ok: false,
      error: `${path.basename(filePath)} is ${before.text.length} bytes, which is far larger than `
        + 'an environment file can legitimately be. Refusing to rewrite it — it is probably '
        + 'corrupt. Inspect it on the server before changing any setting.',
    };
  }

  const previous = Object.prototype.hasOwnProperty.call(before.values, key)
    ? before.values[key]
    : null;
  if (previous === newValue) {
    return { ok: true, unchanged: true, previous, backupPath: null };
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

  // ⛔ THE BACKUP IS WRITTEN HERE, AFTER THE READ-SIDE REFUSALS ABOVE AND NOT
  // BEFORE THEM. The duplicate-key refusal changes nothing, so it needs no
  // backup -- and it used to return WITHOUT a backupPath, which left an
  // unreferenced copy of every secret in the install directory that nothing
  // reported and nobody would think to delete.
  // ⛔ THE STAMP CARRIES RANDOMNESS BECAUSE IT IS ONLY MILLISECOND-RESOLUTION.
  // Two saves in the same millisecond against the same file derived the SAME
  // backup path, so the first to finish deleted the file the second was about
  // to report — and the second then returned a path that did not exist, which
  // is exactly what the success path below exists to avoid.
  const stamp = `${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(3).toString('hex')}`;
  const backupPath = path.join(path.dirname(filePath), `${path.basename(filePath)}.${stamp}.bak`);
  try {
    fs.writeFileSync(backupPath, before.text, { encoding: 'utf8', mode: 0o600 });
  } catch (err) {
    // ⛔ A FAILED BACKUP WRITE CAN STILL HAVE LEFT A PARTIAL FILE. writeFileSync
    // opens and truncates before it can throw, so a mid-write ENOSPC/EIO leaves
    // a truncated copy holding part of CREDENTIAL_KEY in the install directory,
    // under the DIRECTORY's wider ACL, named in no response and deleted by
    // nothing. That is the orphan this commit set out to remove, so remove it
    // here too rather than only on the refusal paths.
    try { fs.unlinkSync(backupPath); } catch { /* nothing to clean up */ }
    return { ok: false, error: `Could not write a backup before changing the file: ${err.message}` };
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
    // ⛔ THE TARGET MAY ALREADY BE TRUNCATED, SO TRY TO PUT IT BACK AND SAY
    // WHICH HAPPENED. writeFileSync opens-and-truncates before it can throw, so
    // an ENOSPC or a post-open lock can leave .env.local partial — possibly
    // without CREDENTIAL_KEY, at which point the app cannot decrypt a single
    // firewall credential. Reporting only "could not write" invites the
    // operator to assume nothing changed. The verify-mismatch branch below
    // already restores; this one must too.
    // ⛔ MEASURE THE RESULTING STATE; DO NOT ASSUME IT. The first version of
    // this branch always announced that the file "MAY NOW BE INCOMPLETE",
    // which is wrong for the common case: a read-only or locked target fails
    // at OPEN, so nothing was truncated and the file is untouched. Telling an
    // operator their credential store may be corrupt when it is intact is its
    // own kind of false reading — and it would send them to restore a backup
    // over a perfectly good file.
    let state = 'unreadable';
    try {
      state = fs.readFileSync(filePath, 'utf8') === before.text ? 'unchanged' : 'damaged';
    } catch { /* leave it unreadable */ }
    if (state === 'damaged') {
      try {
        fs.writeFileSync(filePath, before.text, 'utf8');
        state = 'restored';
      } catch { /* stays damaged */ }
    }
    const SAID = {
      unchanged: 'Nothing was changed — the file is byte-for-byte as it was.',
      restored: 'The file had already been partially written and has been restored.',
      damaged: 'IT IS NOW INCOMPLETE and could not be restored automatically — restore it by '
        + 'hand from the backup path below BEFORE restarting the service.',
      unreadable: 'Its current state could not be read — check it by hand against the backup '
        + 'path below before restarting the service.',
    };
    return {
      ok: false,
      error: `Could not write ${path.basename(filePath)}: ${err.message}. ${SAID[state]}`,
      fileState: state,
      backupPath,
    };
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

  // ⛔ THE BACKUP IS REMOVED ONCE THE SELF-CHECK ABOVE HAS PROVEN THE WRITE.
  // It exists to recover from a FAILED write, and every failure path above
  // keeps it and reports its path. Left behind on SUCCESS it is a permanent
  // second copy of the file holding CREDENTIAL_KEY, the database password and
  // NEXTAUTH_SECRET -- and because it is created in the install directory it
  // inherits THAT directory's ACL, not .env.local's own, so it is readable by
  // principals the original is not. Found on the reference deployment as five
  // such copies, the oldest a month old, beside a 2.06 GB corrupt one.
  // ⛔ `previous` is the real recovery information and is returned regardless;
  // a path to a file that no longer exists would be worse than none, so the
  // path is reported ONLY while the file is still there.
  let backupRemoved = false;
  try {
    fs.unlinkSync(backupPath);
    backupRemoved = true;
  } catch {
    // Best effort. The write succeeded and was verified, which is what was
    // asked; a backup that cannot be removed is reported, never hidden.
  }

  return {
    ok: true,
    previous,
    backupPath: backupRemoved ? null : backupPath,
    unchanged: false,
  };
}

module.exports = { parseEnv, readEnvFile, setEnvValue, LINE_RE };
