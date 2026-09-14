'use strict';

// lib/totp.js
//
// RFC 6238 TOTP + RFC 4648 base32, implemented on node's own `crypto`.
//
// ⛔ WHY NOT A LIBRARY. `Update-SecVault.ps1` runs `npm ci` on a
// firewall-management server, and this repo deliberately carries no
// devDependencies so that what ships is what was tested. TOTP is an HMAC over a
// counter — about sixty lines including base32 — and every one of those lines is
// covered by the RFC's own published test vectors, which tests/totp.test.js
// asserts against. A dependency here would buy nothing and add a supply-chain
// surface to a security product.
//
// ⛔ SHA-1 IS CORRECT HERE AND IS NOT A DEFECT. RFC 6238's default is
// HMAC-SHA1, and it is what every authenticator app (Google Authenticator,
// Microsoft Authenticator, 1Password, Aegis) implements when no algorithm is
// declared. TOTP's security does not rest on collision resistance — it rests on
// the secret — so SHA-1's collision weakness does not apply. Changing this to
// SHA-256 would silently break every enrolled authenticator.
//
// Pure and dependency-free apart from node:crypto: no pool, no I/O, no clock
// injection beyond an explicit parameter. That is what lets the tests run the
// RFC vectors directly.

const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const DEFAULT_DIGITS = 6;
const DEFAULT_PERIOD = 30;

/**
 * ⛔ ±1 STEP, NOT MORE. One step either side tolerates the clock skew between a
 * phone and a server that is realistically present (and a user who starts
 * typing at second 29). Each extra step widens the window in which a code
 * observed over someone's shoulder — or replayed — is still valid. At ±1 a code
 * is live for at most 90 seconds, and lib/mfa.js additionally refuses to accept
 * any counter it has already seen, so a code is single-use within that window.
 */
const DEFAULT_WINDOW = 1;

// ── base32 (RFC 4648, no padding on output) ─────────────────────────────────

/** Encode bytes as base32 — the format every authenticator app expects. */
function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/**
 * Decode a base32 secret.
 *
 * ⛔ Tolerant of what a HUMAN retypes: lower case, spaces, and the `=` padding
 * some apps display. A user copying a secret by hand is the normal case during
 * enrolment, and rejecting "jbsw y3dp" for its space would be a support ticket
 * rather than a security measure. Anything that is still not a base32 character
 * after that throws — it is not silently skipped, because quietly ignoring a
 * character yields a DIFFERENT secret and an endless stream of "wrong code".
 */
function base32Decode(input) {
  if (typeof input !== 'string') throw new Error('base32Decode: expected a string');
  const clean = input.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  if (clean.length === 0) throw new Error('base32Decode: empty secret');

  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`base32Decode: invalid character "${ch}"`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// ── secret generation ───────────────────────────────────────────────────────

/**
 * A new enrolment secret.
 *
 * ⛔ 20 bytes (160 bits), which is the RFC 4226 recommendation and what every
 * authenticator handles without complaint. Uses randomBytes, never Math.random
 * — the same rule the rest of this codebase follows for anything a secret
 * depends on.
 */
function generateSecret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

// ── code generation / verification ──────────────────────────────────────────

/** The RFC 6238 time counter: seconds since epoch divided by the period. */
function counterFor(timeSeconds, period = DEFAULT_PERIOD) {
  return Math.floor(timeSeconds / period);
}

/**
 * The HOTP value for one counter (RFC 4226 dynamic truncation).
 */
function hotp(secretBase32, counter, digits = DEFAULT_DIGITS) {
  const key = base32Decode(secretBase32);

  // 8-byte big-endian counter. Written as two 32-bit halves because a JS number
  // cannot hold a 64-bit integer exactly — at 30-second steps the high half
  // stays 0 until the year ~10,000, but writing it correctly costs one line.
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);

  const digest = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  return String(binary % 10 ** digits).padStart(digits, '0');
}

/** The code for a moment in time. `timeSeconds` defaults to now. */
function generateCode(secretBase32, timeSeconds, options = {}) {
  const period = options.period || DEFAULT_PERIOD;
  const digits = options.digits || DEFAULT_DIGITS;
  const t = Number.isFinite(timeSeconds) ? timeSeconds : Math.floor(Date.now() / 1000);
  return hotp(secretBase32, counterFor(t, period), digits);
}

/**
 * Verify a submitted code.
 *
 * @returns {{valid:boolean, counter:number|null}} `counter` is the step the code
 *   matched, so the caller can REFUSE TO ACCEPT IT TWICE. Returning a bare
 *   boolean would make single-use enforcement impossible, which is why this
 *   returns the step rather than hiding it.
 *
 * ⛔ Constant-time comparison. A length-independent early-exit compare on a
 * 6-digit code is a weak oracle, but it is a real one, and the fix is one
 * function call.
 */
function verifyCode(secretBase32, code, options = {}) {
  const period = options.period || DEFAULT_PERIOD;
  const digits = options.digits || DEFAULT_DIGITS;
  const window = Number.isInteger(options.window) ? options.window : DEFAULT_WINDOW;
  const t = Number.isFinite(options.timeSeconds)
    ? options.timeSeconds
    : Math.floor(Date.now() / 1000);

  if (typeof code !== 'string' && typeof code !== 'number') return { valid: false, counter: null };
  const submitted = String(code).replace(/\s+/g, '');
  if (!new RegExp(`^\\d{${digits}}$`).test(submitted)) return { valid: false, counter: null };

  const current = counterFor(t, period);
  for (let drift = -window; drift <= window; drift += 1) {
    const counter = current + drift;
    if (counter < 0) continue;
    const expected = hotp(secretBase32, counter, digits);
    const a = Buffer.from(expected);
    const b = Buffer.from(submitted);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      return { valid: true, counter };
    }
  }
  return { valid: false, counter: null };
}

/**
 * The `otpauth://` URI an authenticator app scans.
 *
 * ⛔ The issuer appears TWICE by design — once as a label prefix and once as a
 * parameter. Older apps read only the label; newer ones prefer the parameter.
 * Emitting both is what makes the entry show as "SecVault (alice)" rather than
 * a bare username in an app full of other accounts.
 */
function buildOtpauthUri(secretBase32, accountName, issuer = 'SecVault') {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: 'SHA1',
    digits: String(DEFAULT_DIGITS),
    period: String(DEFAULT_PERIOD),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

module.exports = {
  base32Encode,
  base32Decode,
  generateSecret,
  counterFor,
  hotp,
  generateCode,
  verifyCode,
  buildOtpauthUri,
  DEFAULT_DIGITS,
  DEFAULT_PERIOD,
  DEFAULT_WINDOW,
};
