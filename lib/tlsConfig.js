'use strict';

// lib/tlsConfig.js
//
// Resolves SecVault's TLS configuration and says, unambiguously, which of three
// states the server is in. Pure apart from reading the two files it is pointed
// at, so tests can drive every branch.
//
// ⛔ THREE STATES, NOT TWO, and conflating any two of them is the bug this file
// exists to prevent:
//
//   'active'      certs configured and loaded — HTTPS is really on
//   'disabled'    no certs configured — plain HTTP, as this product shipped
//                 for its whole life before v2.112.0. Not an error.
//   'failed'      certs WERE configured and could not be loaded
//
// ⛔ 'failed' MUST NEVER LOOK LIKE 'disabled'. The operator asked for TLS and is
// not getting it; degrading quietly to plaintext while the settings still say
// "TLS_CERT_PATH=..." is this codebase's failed-read-as-a-fact rule applied to
// the transport — the most dangerous version of it, because the reader's
// conclusion ("we're encrypted") is the opposite of the truth. The server logs
// it at error level on every start and /api/health reports it.
//
// ⛔ WHY IT DEGRADES RATHER THAN REFUSING TO START. On a firewall-management
// platform an outage has its own security cost: nobody can see the fleet. A
// broken cert file turning into a dead console is a worse day than a loud,
// visible "TLS is configured but not active". The choice is deliberate and was
// made explicitly — it is only safe BECAUSE 'failed' is never silent.

const fs = require('fs');

const DEFAULT_HTTPS_PORT = 3010;
const DEFAULT_HTTP_PORT = 3080;

/** A port from the environment, or the default. Never NaN, never 0. */
function portFrom(value, fallback) {
  const n = Number.parseInt(String(value == null ? '' : value).trim(), 10);
  return Number.isInteger(n) && n > 0 && n < 65536 ? n : fallback;
}

/**
 * Decide the TLS state from an environment.
 *
 * @param {object} [env=process.env]
 * @param {{readFileSync?:Function, existsSync?:Function}} [fsImpl]
 * @returns {{status:'active'|'disabled'|'failed', httpsPort:number, httpPort:number,
 *            cert:Buffer|null, key:Buffer|null, certPath:string|null,
 *            keyPath:string|null, error:string|null}}
 */
function resolveTlsConfig(env, fsImpl) {
  const e = env || process.env;
  const io = fsImpl || fs;

  const httpsPort = portFrom(e.HTTPS_PORT || e.APP_PORT, DEFAULT_HTTPS_PORT);
  const httpPort = portFrom(e.HTTP_REDIRECT_PORT, DEFAULT_HTTP_PORT);

  const certPath = (e.TLS_CERT_PATH || '').trim() || null;
  const keyPath = (e.TLS_KEY_PATH || '').trim() || null;

  const base = { httpsPort, httpPort, cert: null, key: null, certPath, keyPath, error: null };

  // ⛔ BOTH or NEITHER. One path set alone is a half-finished configuration, and
  // treating it as "disabled" would silently ignore an operator who has clearly
  // started turning TLS on. It is a failure, and it is reported as one.
  if (!certPath && !keyPath) return { ...base, status: 'disabled' };
  if (!certPath || !keyPath) {
    return {
      ...base,
      status: 'failed',
      error: `TLS is half-configured: ${certPath ? 'TLS_KEY_PATH' : 'TLS_CERT_PATH'} is not set. `
        + 'Set both, or neither.',
    };
  }

  try {
    const cert = io.readFileSync(certPath);
    const key = io.readFileSync(keyPath);

    // ⛔ An empty file reads without throwing and then fails deep inside the TLS
    // handshake, where the error is far less legible. Catch it here.
    if (!cert || cert.length === 0) {
      return { ...base, status: 'failed', error: `Certificate file is empty: ${certPath}` };
    }
    if (!key || key.length === 0) {
      return { ...base, status: 'failed', error: `Private key file is empty: ${keyPath}` };
    }

    return { ...base, status: 'active', cert, key };
  } catch (err) {
    return {
      ...base,
      status: 'failed',
      error: `Could not read the TLS certificate or key: ${err.message}`,
    };
  }
}

/**
 * The one-line summary for a log or a health response.
 *
 * ⛔ 'failed' reads as a problem in plain words. A reader skimming a startup log
 * must not be able to mistake it for a normal state.
 */
function describeTlsStatus(config) {
  if (!config) return 'TLS: unknown';
  if (config.status === 'active') {
    return `TLS: ACTIVE on port ${config.httpsPort} (HTTP redirect on ${config.httpPort})`;
  }
  if (config.status === 'disabled') {
    return `TLS: not configured — serving plain HTTP on port ${config.httpsPort}`;
  }
  return `TLS: **CONFIGURED BUT NOT ACTIVE** — ${config.error} — serving plain HTTP on port ${config.httpsPort}`;
}

/**
 * The public origin, for NEXTAUTH_URL sanity checks and links.
 *
 * ⛔ EXISTS BECAUSE A SCHEME MISMATCH BREAKS SIGN-IN SILENTLY. NextAuth builds
 * its callback URL from NEXTAUTH_URL; if that still says http:// after TLS is
 * switched on, the cookie is issued for an origin the browser is not on and the
 * user is bounced back to the login page with no error anywhere.
 */
function expectedOrigin(config, host) {
  const scheme = config && config.status === 'active' ? 'https' : 'http';
  const port = config ? config.httpsPort : DEFAULT_HTTPS_PORT;
  return `${scheme}://${host || 'localhost'}:${port}`;
}

/** Does NEXTAUTH_URL agree with the transport we are actually serving? */
function nextAuthUrlMismatch(config, nextAuthUrl) {
  if (!config || !nextAuthUrl) return null;
  const isHttps = /^https:/i.test(String(nextAuthUrl).trim());
  if (config.status === 'active' && !isHttps) {
    return 'NEXTAUTH_URL is http:// but TLS is active. Sign-in will fail: update it to https://.';
  }
  if (config.status !== 'active' && isHttps) {
    return 'NEXTAUTH_URL is https:// but TLS is NOT active. Sign-in will fail: update it to http://.';
  }
  return null;
}

module.exports = {
  resolveTlsConfig,
  describeTlsStatus,
  expectedOrigin,
  nextAuthUrlMismatch,
  portFrom,
  DEFAULT_HTTPS_PORT,
  DEFAULT_HTTP_PORT,
};
