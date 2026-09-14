'use strict';
// Pins lib/tlsConfig.js — the decision about whether SecVault's traffic is
// actually encrypted (v2.112.0).
//
// ⛔ THE FAILURE THIS GUARDS IS THE WORST-SHAPED ONE IN THE PRODUCT. Every other
// "failed read as a fact" bug in this codebase produces a wrong number on a
// screen. This one produces a reader who believes their admin console is
// encrypted when it is serving plaintext — the conclusion is the exact opposite
// of the truth, and nothing on screen contradicts it.
//
// So there are THREE states and the tests exist mainly to keep them apart:
//
//   active     certs configured and loaded
//   disabled   no certs configured — plain HTTP, the pre-v2.112.0 default, and
//              NOT an error
//   failed     certs WERE configured and could not be loaded
//
// `failed` must never be reported as `disabled`, and its description must read
// as a problem in plain words.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  resolveTlsConfig,
  describeTlsStatus,
  nextAuthUrlMismatch,
  portFrom,
  DEFAULT_HTTPS_PORT,
  DEFAULT_HTTP_PORT,
} = require('../lib/tlsConfig');

/** A filesystem stub: a map of path -> contents, anything else throws ENOENT. */
function fsWith(files) {
  return {
    readFileSync(p) {
      if (Object.prototype.hasOwnProperty.call(files, p)) return files[p];
      const err = new Error(`ENOENT: no such file or directory, open '${p}'`);
      err.code = 'ENOENT';
      throw err;
    },
  };
}

// ⛔ REAL KEY MATERIAL, and it has to be. This fixture used to be the literal
// strings '-----BEGIN CERTIFICATE-----' / '-----BEGIN PRIVATE KEY-----' and
// asserted status ACTIVE — material OpenSSL cannot parse, blessed as a working
// TLS configuration. That is precisely why the crash-loop shipped: `active`
// only ever meant "two non-empty files exist", and the test agreed with it.
// A fixture that cannot fail the way production fails is not a fixture.
const { cert: REAL_CERT, key: REAL_KEY } = require('./fixtures/testCert');

// The env both new tests use: both paths set, so resolution reaches the point
// where the material is actually loaded.
const BOTH_PATHS = { TLS_CERT_PATH: 'C:/certs/secvault.crt', TLS_KEY_PATH: 'C:/certs/secvault.key' };

const GOOD = fsWith({
  'C:/certs/secvault.crt': Buffer.from(REAL_CERT),
  'C:/certs/secvault.key': Buffer.from(REAL_KEY),
});

describe('⛔ unloadable material is FAILED, never active', () => {
  // These are the corruption classes that actually happen: a DER .cer saved
  // over the .crt, a truncated download, a restored .bak pair whose halves do
  // not match. Before this, each of them returned ACTIVE here and then threw
  // synchronously inside https.createServer(), exiting the process — which
  // NSSM restarts, forever, with no rollback in the path because a reboot
  // never runs the updater.
  it('unparseable certificate material is FAILED', () => {
    const c = resolveTlsConfig(BOTH_PATHS, fsWith({
      'C:/certs/secvault.crt': Buffer.from('definitely not a certificate'),
      'C:/certs/secvault.key': Buffer.from('definitely not a key'),
    }));
    assert.equal(c.status, 'failed');
    assert.match(c.error, /could not be loaded/);
  });

  it('⛔ a VALID certificate with the WRONG key is FAILED', () => {
    // Both halves parse perfectly and only the pairing is wrong — the failure
    // mode the certificate-install route validates against, reproduced here at
    // the point where the server actually loads them.
    const { generateKeyPairSync } = require('crypto');
    const other = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    const c = resolveTlsConfig(BOTH_PATHS, fsWith({
      'C:/certs/secvault.crt': Buffer.from(REAL_CERT),
      'C:/certs/secvault.key': Buffer.from(other.privateKey),
    }));
    assert.equal(c.status, 'failed');
    assert.match(c.error, /MISMATCH/i);
  });
});

describe('the three transport states', () => {
  it('no certificate configured is DISABLED, not failed', () => {
    // Plain HTTP is how this product shipped for its entire life before
    // v2.112.0. An install that has not been given certs is not broken.
    const c = resolveTlsConfig({}, GOOD);
    assert.equal(c.status, 'disabled');
    assert.equal(c.error, null);
  });

  it('both paths present and readable is ACTIVE', () => {
    const c = resolveTlsConfig(
      { TLS_CERT_PATH: 'C:/certs/secvault.crt', TLS_KEY_PATH: 'C:/certs/secvault.key' },
      GOOD
    );
    assert.equal(c.status, 'active');
    assert.ok(c.cert.length > 0);
    assert.ok(c.key.length > 0);
    assert.equal(c.error, null);
  });

  it('⛔ a missing certificate file is FAILED, never disabled', () => {
    const c = resolveTlsConfig(
      { TLS_CERT_PATH: 'C:/certs/gone.crt', TLS_KEY_PATH: 'C:/certs/secvault.key' },
      GOOD
    );
    assert.equal(c.status, 'failed');
    assert.match(c.error, /ENOENT|Could not read/);
  });

  it('⛔ HALF-configured is FAILED, never disabled', () => {
    // One path set alone is an operator who has started turning TLS on.
    // Treating it as "disabled" would silently ignore them.
    const certOnly = resolveTlsConfig({ TLS_CERT_PATH: 'C:/certs/secvault.crt' }, GOOD);
    assert.equal(certOnly.status, 'failed');
    assert.match(certOnly.error, /TLS_KEY_PATH/);

    const keyOnly = resolveTlsConfig({ TLS_KEY_PATH: 'C:/certs/secvault.key' }, GOOD);
    assert.equal(keyOnly.status, 'failed');
    assert.match(keyOnly.error, /TLS_CERT_PATH/);
  });

  it('⛔ an EMPTY file is FAILED — it reads without throwing', () => {
    // An empty cert reads fine and then fails deep inside the TLS handshake,
    // where the error is far less legible.
    const empty = fsWith({
      'C:/certs/secvault.crt': Buffer.alloc(0),
      'C:/certs/secvault.key': Buffer.from('key'),
    });
    const c = resolveTlsConfig(
      { TLS_CERT_PATH: 'C:/certs/secvault.crt', TLS_KEY_PATH: 'C:/certs/secvault.key' },
      empty
    );
    assert.equal(c.status, 'failed');
    assert.match(c.error, /empty/i);
  });

  it('whitespace-only paths count as not configured', () => {
    const c = resolveTlsConfig({ TLS_CERT_PATH: '   ', TLS_KEY_PATH: '  ' }, GOOD);
    assert.equal(c.status, 'disabled');
  });
});

describe('the status line reads as what it is', () => {
  it('⛔ FAILED is unmistakable in a log a human is skimming', () => {
    const c = resolveTlsConfig(
      { TLS_CERT_PATH: 'C:/certs/gone.crt', TLS_KEY_PATH: 'C:/certs/secvault.key' },
      GOOD
    );
    const line = describeTlsStatus(c);
    assert.match(line, /CONFIGURED BUT NOT ACTIVE/);
    assert.match(line, /plain HTTP/);
    // ⛔ Must not be phrased so it can be mistaken for the normal disabled case.
    assert.doesNotMatch(line, /not configured/);
  });

  it('disabled says plainly that it is plain HTTP', () => {
    const line = describeTlsStatus(resolveTlsConfig({}, GOOD));
    assert.match(line, /not configured/);
    assert.match(line, /plain HTTP/);
    assert.doesNotMatch(line, /NOT ACTIVE/);
  });

  it('active names both ports', () => {
    const c = resolveTlsConfig(
      { TLS_CERT_PATH: 'C:/certs/secvault.crt', TLS_KEY_PATH: 'C:/certs/secvault.key' },
      GOOD
    );
    const line = describeTlsStatus(c);
    assert.match(line, /ACTIVE on port 3010/);
    assert.match(line, /redirect on 3080/);
  });
});

describe('⛔ NEXTAUTH_URL scheme agreement', () => {
  // A mismatch breaks sign-in with NO error anywhere: NextAuth builds its
  // callback from NEXTAUTH_URL, and a cookie issued for the wrong origin simply
  // bounces the user back to the login page. It is the single most likely way
  // for this change to break a working installation.
  const active = resolveTlsConfig(
    { TLS_CERT_PATH: 'C:/certs/secvault.crt', TLS_KEY_PATH: 'C:/certs/secvault.key' },
    GOOD
  );
  const off = resolveTlsConfig({}, GOOD);

  it('flags http:// while TLS is active', () => {
    const m = nextAuthUrlMismatch(active, 'http://192.168.7.69:3010');
    assert.match(m, /update it to https/);
  });

  it('flags https:// while TLS is NOT active', () => {
    const m = nextAuthUrlMismatch(off, 'https://192.168.7.69:3010');
    assert.match(m, /update it to http/);
  });

  it('stays quiet when they agree', () => {
    assert.equal(nextAuthUrlMismatch(active, 'https://192.168.7.69:3010'), null);
    assert.equal(nextAuthUrlMismatch(off, 'http://192.168.7.69:3010'), null);
  });

  it('says nothing when NEXTAUTH_URL is absent', () => {
    assert.equal(nextAuthUrlMismatch(active, ''), null);
    assert.equal(nextAuthUrlMismatch(active, undefined), null);
  });
});

describe('ports', () => {
  it('defaults to 3010 / 3080', () => {
    const c = resolveTlsConfig({}, GOOD);
    assert.equal(c.httpsPort, DEFAULT_HTTPS_PORT);
    assert.equal(c.httpPort, DEFAULT_HTTP_PORT);
  });

  it('HTTPS_PORT wins over APP_PORT', () => {
    assert.equal(resolveTlsConfig({ HTTPS_PORT: '8443', APP_PORT: '3010' }, GOOD).httpsPort, 8443);
  });

  it('falls back to APP_PORT, which every existing install already sets', () => {
    assert.equal(resolveTlsConfig({ APP_PORT: '3010' }, GOOD).httpsPort, 3010);
  });

  it('⛔ junk never yields NaN or 0', () => {
    // A port of 0 binds a RANDOM free port, which presents as "the app started
    // but nothing can reach it".
    for (const bad of ['', '  ', 'abc', '0', '-1', '99999', null, undefined, {}]) {
      assert.equal(portFrom(bad, 3010), 3010);
    }
  });

  it('accepts a real port', () => {
    assert.equal(portFrom('443', 3010), 443);
    assert.equal(portFrom(' 8443 ', 3010), 8443);
  });
});
