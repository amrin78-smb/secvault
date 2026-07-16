// lib/adapters/credentials.js
// Shared credential-plaintext parsing for API-based adapters.
//
// CommonJS ONLY — required by vendor adapters, which are in turn required by
// services/engine-worker.js (plain node) as well as bundled into Next.js API
// routes.
//
// The write side lives in components/devices/vendorMeta.js
// (buildCredentialPlaintext). This is the read side. Keep them in step.
//
// ⛔ NEVER include the decrypted plaintext (or any fragment of it) in a thrown
// error, a log line, or an API response. Adapter errors surface BOTH in
// engine.log and in the /api/devices/[id]/test HTTP response body, so a
// credential echoed into an error message is a real disclosure. Note in
// particular that JSON.parse's own SyntaxError embeds a snippet of its input —
// which is why every parse below is caught and replaced, never re-thrown.

'use strict';

/**
 * Parses the plaintext for an 'apikey_or_userpass' credential.
 *
 * Accepts, in order:
 *   {"api_key": "..."}               → { apiKey }
 *   {"username": "...", "password": "..."} → { username, password }
 *   a bare non-JSON string           → { apiKey: <the string> }
 *
 * That last case is deliberate BACKWARD COMPATIBILITY: before access-method
 * selection existed, fortinet/paloalto stored the API token as a raw string.
 * Devices added then must keep working after this change without re-entering
 * credentials.
 *
 * @param {string} plaintext decrypted credential
 * @param {string} vendorLabel human label used in error messages (never the secret)
 * @returns {{apiKey: string|null, username: string|null, password: string|null}}
 * @throws {Error} with an actionable, secret-free message when unusable
 */
function parseApiCredential(plaintext, vendorLabel = 'device') {
  if (typeof plaintext !== 'string' || plaintext.trim() === '') {
    throw new Error(
      `No credential stored for this ${vendorLabel} — save credentials before connecting.`
    );
  }

  const trimmed = plaintext.trim();

  // Only attempt JSON when it actually looks like an object. A bare token that
  // happens to be invalid JSON must fall through to the legacy path below, not
  // raise a parse error.
  if (trimmed.startsWith('{')) {
    let obj;
    try {
      obj = JSON.parse(trimmed);
    } catch (err) {
      // Do NOT surface err.message — JSON.parse embeds input in its SyntaxError.
      throw new Error(
        `Stored ${vendorLabel} credential looks like JSON but could not be parsed. ` +
          `Expected {"api_key":"..."} or {"username":"...","password":"..."}. Re-save the credential.`
      );
    }

    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
      const apiKey = typeof obj.api_key === 'string' && obj.api_key !== '' ? obj.api_key : null;
      const username = typeof obj.username === 'string' && obj.username !== '' ? obj.username : null;
      const password = typeof obj.password === 'string' ? obj.password : null;

      if (apiKey) return { apiKey, username: null, password: null };
      if (username && password !== null) return { apiKey: null, username, password };

      // Valid JSON, wrong keys. Name the KEYS only — never echo the values,
      // which would put the operator's password in the log/HTTP response.
      throw new Error(
        `Stored ${vendorLabel} credential JSON has no usable keys. ` +
          `Expected "api_key", or both "username" and "password". Re-save the credential.`
      );
    }

    throw new Error(
      `Stored ${vendorLabel} credential JSON is not an object. ` +
        `Expected {"api_key":"..."} or {"username":"...","password":"..."}. Re-save the credential.`
    );
  }

  // Legacy: bare API token string.
  return { apiKey: trimmed, username: null, password: null };
}

module.exports = { parseApiCredential };
