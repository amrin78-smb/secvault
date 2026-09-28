'use strict';

// lib/localPassword.js
//
// ONE definition of "is this username and password a valid LOCAL account".
//
// ⛔ WHY THIS IS A SHARED MODULE AND NOT TWO COPIES. Two surfaces now ask the
// question — NextAuth's `authorize()` and `POST /api/auth/mfa/precheck` — and if
// they ever disagree the precheck becomes a lie: it would tell the login form
// "that password is fine, show the code field" for a credential `authorize()`
// then rejects, or the reverse. A second copy of an auth predicate is the kind
// of drift this codebase has already been bitten by (two `check_id` columns,
// two registries of vendor metadata), and here the blast radius is the login
// path of a security product.
//
// ⛔ CONSTANT-TIME-ISH, AND THE REASON IS MEASURED. Returning early on a missing
// user skips the bcrypt compare, and bcrypt is the expensive part. Measured
// against the live server: a REAL username with a wrong password took
// 0.119-0.176s, an unknown username 0.035-0.039s — a consistent ~4x gap with no
// overlap across 8 attempts. Identical status and body, so timing alone was a
// reliable oracle for "does this account exist", which is the reconnaissance
// step before credential spraying. Comparing against a fixed dummy hash makes
// both paths do the same work.
//
// The dummy is a real bcrypt hash of a random string, so it can never validate.

const bcrypt = require('bcryptjs');

const DUMMY_BCRYPT_HASH = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';

/**
 * @returns {Promise<{user: object|null, valid: boolean}>}
 *
 * ⛔ `user` IS NON-NULL ONLY WHEN THE ROW EXISTS, and `valid` only when the
 * password also matched. Callers must check `valid`, never merely `user` —
 * returning the row on a failed compare is deliberate so a caller can tell
 * "no such account" from "wrong password" INTERNALLY (for logging), while every
 * HTTP surface above collapses the two into one response.
 *
 * ⛔ IT THROWS on a database failure rather than returning `{valid: false}`.
 * A read failure is not a wrong password: reporting it as one would tell a user
 * their credentials are bad during an outage, and — worse for the precheck —
 * would let a database blip quietly decide that an MFA-protected account has no
 * MFA. The callers fail closed on the throw.
 */
async function verifyLocalPassword(pool, username, password) {
  const name = typeof username === 'string' ? username : '';
  const pass = typeof password === 'string' ? password : '';
  if (!name || !pass) {
    // Still burn a compare: an empty submission must not be measurably faster
    // than a populated one against a real account.
    await bcrypt.compare(pass || 'x', DUMMY_BCRYPT_HASH);
    return { user: null, valid: false };
  }

  const result = await pool.query(
    'SELECT id, username, password_hash, role FROM users WHERE username = $1',
    [name]
  );
  const user = result.rows[0] || null;
  const hashToCheck = user && user.password_hash ? user.password_hash : DUMMY_BCRYPT_HASH;
  const valid = await bcrypt.compare(pass, hashToCheck);
  return { user, valid: Boolean(user) && valid };
}

module.exports = { verifyLocalPassword, DUMMY_BCRYPT_HASH };
