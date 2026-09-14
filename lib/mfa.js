'use strict';

// lib/mfa.js
//
// Multi-factor authentication: enrolment, verification, recovery.
//
// Sits between the pure lib/totp.js (RFC 6238 arithmetic, no I/O) and the auth
// route. Everything that touches the database or a secret lives here.
//
// ⛔ THE SECRET IS ENCRYPTED AT REST with the same AES-256-GCM as every device
// credential, reusing credStore's `encrypt`/`decrypt` rather than a second
// implementation. A TOTP secret is a bearer credential: anyone holding it can
// generate valid codes forever, so it is exactly as sensitive as the SSH
// password next to it in device_credentials, and `user_mfa` is excluded from the
// readonly grants for the same reason.
//
// ⛔ LOCKOUT IS THE REAL RISK HERE, not bypass. An MFA feature that cannot be
// recovered from turns a lost phone into a rebuilt server — and if the last
// Super Admin is the one who lost it, nobody can even reset it. Three
// independent ways back in, deliberately:
//   1. recovery codes, shown once at enrolment;
//   2. a Super Admin can reset ANOTHER user's MFA (but never their own last
//      remaining path — see the route guard);
//   3. an offline script run on the server itself, which requires machine
//      access and is therefore a legitimate trust boundary rather than a hole.

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { encrypt, decrypt } = require('./credStore');
const totp = require('./totp');

const RECOVERY_CODE_COUNT = 10;
// bcrypt cost for recovery codes. Lower than a password's because a recovery
// code is 80 bits of true randomness rather than something a human chose — the
// hash is protecting against database disclosure, not a dictionary attack.
const RECOVERY_BCRYPT_ROUNDS = 10;

// ── recovery codes ──────────────────────────────────────────────────────────

/**
 * ⛔ Crockford-ish alphabet with no 0/O/1/I/L. These are TRANSCRIBED BY A HUMAN
 * under stress — from a printout, at the point where they have already lost
 * their phone. A character pair that cannot be told apart in a sans-serif font
 * converts a working recovery code into a failed login.
 */
const RECOVERY_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';

function randomRecoveryCode() {
  // 16 characters of ~5 bits = ~80 bits, formatted in four groups for legibility.
  const bytes = crypto.randomBytes(16);
  let out = '';
  for (let i = 0; i < 16; i += 1) {
    out += RECOVERY_ALPHABET[bytes[i] % RECOVERY_ALPHABET.length];
    if (i % 4 === 3 && i !== 15) out += '-';
  }
  return out;
}

/** Normalise what a user typed so formatting never causes a false rejection. */
function normaliseRecoveryCode(input) {
  return String(input || '').toUpperCase().replace(/[^0-9A-Z]/g, '');
}

function generateRecoveryCodes(count = RECOVERY_CODE_COUNT) {
  return Array.from({ length: count }, randomRecoveryCode);
}

async function hashRecoveryCodes(codes) {
  return Promise.all(codes.map((c) => bcrypt.hash(normaliseRecoveryCode(c), RECOVERY_BCRYPT_ROUNDS)));
}

// ── state ───────────────────────────────────────────────────────────────────

async function getRow(pool, userId) {
  const { rows } = await pool.query(
    `SELECT user_id, secret_encrypted, secret_iv, enabled, confirmed_at,
            last_counter, required, recovery_codes
       FROM user_mfa WHERE user_id = $1`,
    [userId]
  );
  return rows[0] || null;
}

/**
 * What the UI needs, with NO secret in it.
 *
 * ⛔ Never returns the secret or the recovery hashes. A status endpoint is the
 * easiest place to leak a bearer credential by accident, because it looks like
 * metadata.
 */
async function getStatus(pool, userId) {
  const row = await getRow(pool, userId);
  if (!row) {
    return { enrolled: false, enabled: false, required: false, recoveryRemaining: 0, confirmedAt: null };
  }
  const codes = Array.isArray(row.recovery_codes) ? row.recovery_codes : [];
  // ⛔ A ROW IS NOT AN ENROLMENT. setRequired() creates a placeholder row for a
  // user who has never enrolled, so that the 'required' flag has somewhere to
  // live. Reporting that as enrolled would tell the UI to stop prompting for
  // enrolment on exactly the account an admin just insisted must enrol.
  const hasSecret = typeof row.secret_encrypted === 'string' && row.secret_encrypted.length > 0;
  return {
    enrolled: hasSecret,
    enabled: row.enabled === true,
    required: row.required === true,
    recoveryRemaining: codes.length,
    confirmedAt: row.confirmed_at || null,
  };
}

/** Does this login need a second factor? */
async function isEnabledFor(pool, userId) {
  const row = await getRow(pool, userId);
  // Belt and braces: a placeholder row can never be 'enabled', but requiring a
  // secret here means a malformed row fails CLOSED into 'no MFA expected'
  // rather than into 'MFA expected but unverifiable', which would lock the user out.
  return !!(row && row.enabled === true && row.secret_encrypted);
}

// ── enrolment ───────────────────────────────────────────────────────────────

/**
 * Begin enrolment: mint a secret, store it ENCRYPTED and DISABLED, and return
 * the provisioning URI for the QR code.
 *
 * ⛔ `enabled` stays false until confirmEnrolment() proves the user can actually
 * generate a code. Enabling on issue would lock out anyone whose phone clock is
 * wrong, or who closed the tab before scanning — the failure mode of an MFA
 * rollout is almost never "an attacker got in", it is "a real user cannot".
 *
 * ⛔ Re-enrolling REPLACES the pending secret. Someone who restarts enrolment
 * because the first QR did not scan must not end up with the server expecting a
 * different secret from the one their app now holds.
 */
async function startEnrolment(pool, userId, username) {
  const secret = totp.generateSecret();
  const { encrypted, iv } = encrypt(secret);

  await pool.query(
    `INSERT INTO user_mfa (user_id, secret_encrypted, secret_iv, enabled, confirmed_at, last_counter, recovery_codes, updated_at)
     VALUES ($1, $2, $3, false, NULL, NULL, '[]'::jsonb, now())
     ON CONFLICT (user_id) DO UPDATE
       SET secret_encrypted = EXCLUDED.secret_encrypted,
           secret_iv        = EXCLUDED.secret_iv,
           enabled          = false,
           confirmed_at     = NULL,
           last_counter     = NULL,
           recovery_codes   = '[]'::jsonb,
           updated_at       = now()`,
    [userId, encrypted, iv]
  );

  return { secret, otpauthUri: totp.buildOtpauthUri(secret, username) };
}

/**
 * Finish enrolment by proving a code. Returns the recovery codes IN PLAINTEXT,
 * once — they are only ever stored hashed.
 */
async function confirmEnrolment(pool, userId, code) {
  const row = await getRow(pool, userId);
  if (!row) return { ok: false, reason: 'not_enrolled' };
  if (row.enabled === true) return { ok: false, reason: 'already_enabled' };

  // ⛔ A REQUIREMENT-ONLY PLACEHOLDER IS NOT AN ENROLMENT. setRequired() and
  // resetFor() both create a row carrying `required: true` with an EMPTY
  // secret, so that the next sign-in forces enrolment. Calling confirm before
  // start then reached decrypt('', '') and credStore threw "Malformed
  // encrypted credential value" — an unhandled 500 where the honest answer is
  // "you have not started enrolling yet".
  if (!row.secret_encrypted || !row.secret_iv) {
    return { ok: false, reason: 'not_enrolled' };
  }

  const secret = decrypt(row.secret_encrypted, row.secret_iv);
  const result = totp.verifyCode(secret, code);
  if (!result.valid) return { ok: false, reason: 'invalid_code' };

  const codes = generateRecoveryCodes();
  const hashes = await hashRecoveryCodes(codes);

  await pool.query(
    `UPDATE user_mfa
        SET enabled = true, confirmed_at = now(), last_counter = $2,
            recovery_codes = $3::jsonb, updated_at = now()
      WHERE user_id = $1`,
    [userId, result.counter, JSON.stringify(hashes)]
  );

  return { ok: true, recoveryCodes: codes };
}

// ── verification ────────────────────────────────────────────────────────────

/**
 * Verify a second factor at login. Accepts either a TOTP code or an unused
 * recovery code.
 *
 * ⛔ SINGLE USE, ENFORCED. A TOTP code is valid for up to 90 seconds across the
 * ±1 window, so without this a code observed over a shoulder — or captured by
 * anything sitting between the browser and the server, which on a plain-HTTP
 * deployment is a real possibility — can be replayed. `last_counter` is compared
 * with `<=`, not `!==`: rejecting only an exact repeat would still allow
 * replaying the PREVIOUS step's code.
 *
 * ⛔ A used recovery code is DELETED, not flagged.
 *
 * ⛔ Reasons are returned for logging, never for display to the person logging
 * in. "invalid_code" and "code_reused" must look identical at the login form, or
 * the form becomes an oracle telling an attacker their captured code was real.
 */
async function verifyForLogin(pool, userId, code) {
  const row = await getRow(pool, userId);
  if (!row || row.enabled !== true) return { ok: false, reason: 'not_enabled' };

  const submitted = String(code || '').trim();
  if (submitted === '') return { ok: false, reason: 'missing_code' };

  // Try TOTP first — the overwhelmingly common case.
  const secret = decrypt(row.secret_encrypted, row.secret_iv);
  const result = totp.verifyCode(secret, submitted);
  if (result.valid) {
    if (row.last_counter !== null && row.last_counter !== undefined
        && Number(result.counter) <= Number(row.last_counter)) {
      return { ok: false, reason: 'code_reused' };
    }
    await pool.query(
      'UPDATE user_mfa SET last_counter = $2, updated_at = now() WHERE user_id = $1',
      [userId, result.counter]
    );
    return { ok: true, method: 'totp' };
  }

  // Then a recovery code.
  const normalised = normaliseRecoveryCode(submitted);
  // ⛔ A recovery code is 16 characters; a 6-digit TOTP normalises to 6. Without
  // this length check every failed TOTP attempt would run ten bcrypt compares,
  // turning the login form into a cheap CPU-exhaustion target.
  if (normalised.length >= 12) {
    const hashes = Array.isArray(row.recovery_codes) ? row.recovery_codes : [];
    for (let i = 0; i < hashes.length; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      const match = await bcrypt.compare(normalised, hashes[i]);
      if (match) {
        const remaining = hashes.filter((_, idx) => idx !== i);
        // eslint-disable-next-line no-await-in-loop
        await pool.query(
          'UPDATE user_mfa SET recovery_codes = $2::jsonb, updated_at = now() WHERE user_id = $1',
          [userId, JSON.stringify(remaining)]
        );
        return { ok: true, method: 'recovery', recoveryRemaining: remaining.length };
      }
    }
  }

  return { ok: false, reason: 'invalid_code' };
}

// ── administration ──────────────────────────────────────────────────────────

/**
 * Remove MFA from an account entirely — the Super Admin reset, and what the
 * offline script calls.
 *
 * ⛔ DELETES the row rather than setting enabled=false, so no stale secret
 * survives a reset. The user re-enrols from scratch with a new secret.
 */
async function resetFor(pool, userId) {
  // ⛔ THE `required` FLAG MUST SURVIVE A RESET. A plain DELETE destroyed it
  // along with the secret, so resetting a locked-out user on a mandatory-MFA
  // account silently returned that account to password-only — permanently, with
  // no re-enrolment prompt and no audit signal. lib/mfa-reset.js printed the
  // opposite in the same breath ("this account is still flagged as REQUIRING
  // MFA, so the requirement stands ... that flag was deliberately left alone"),
  // which is how it would have gone unnoticed: the tool told the operator the
  // enforcement held.
  //
  // Read the flag first, delete, then re-assert it if it was set. The secret is
  // still destroyed — that is the point of a reset — but the POLICY is not a
  // credential and an admin unlocking an account is not deciding to exempt it.
  const prior = await pool.query('SELECT required FROM user_mfa WHERE user_id = $1', [userId]);
  const wasRequired = prior.rows[0] ? prior.rows[0].required === true : false;

  const { rowCount } = await pool.query('DELETE FROM user_mfa WHERE user_id = $1', [userId]);

  if (wasRequired) {
    // Re-create the placeholder carrying ONLY the requirement. enabled stays
    // false and the secret stays empty, so the next sign-in forces enrolment.
    await pool.query(
      `INSERT INTO user_mfa (user_id, secret_encrypted, secret_iv, enabled, required)
       VALUES ($1, '', '', false, true)
       ON CONFLICT (user_id) DO UPDATE SET required = true`,
      [userId]
    );
  }

  return { reset: rowCount > 0, requirementPreserved: wasRequired };
}

/**
 * Flag an account as required-to-use-MFA.
 *
 * ⛔ Requiring MFA never blocks a login. It forces ENROLMENT on the next visit;
 * refusing to authenticate someone who has not enrolled yet would lock out a
 * user the moment an admin ticked a box, which is the opposite of the intent.
 */
async function setRequired(pool, userId, required) {
  await pool.query(
    `INSERT INTO user_mfa (user_id, secret_encrypted, secret_iv, enabled, required, updated_at)
     VALUES ($1, '', '', false, $2, now())
     ON CONFLICT (user_id) DO UPDATE SET required = EXCLUDED.required, updated_at = now()`,
    [userId, required === true]
  );
  return { required: required === true };
}

module.exports = {
  getStatus,
  isEnabledFor,
  startEnrolment,
  confirmEnrolment,
  verifyForLogin,
  resetFor,
  setRequired,
  generateRecoveryCodes,
  normaliseRecoveryCode,
  RECOVERY_CODE_COUNT,
};
