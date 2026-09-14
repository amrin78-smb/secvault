'use strict';
// Pins lib/certValidate.js — the check that stands between an operator pasting a
// certificate and the console failing to start (v2.112.0).
//
// ⛔ THE FAILURE IS DELAYED, WHICH IS WHAT MAKES IT DANGEROUS. A mismatched
// certificate and key both parse perfectly. Nothing goes wrong when the button
// is clicked; it goes wrong at the NEXT RESTART, which may be weeks later during
// an unrelated upgrade, and by then nobody connects the dead console to the
// certificate somebody installed in the meantime. Every check here exists to
// move that failure forward to the moment of the paste.
//
// Real key pairs are generated in-process rather than embedded as fixtures, so
// the "wrong key" case is genuinely a different key rather than a corrupted
// string that would fail for the wrong reason.

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { validateCertificatePair, describeCertificate, daysUntil } = require('../lib/certValidate');

// ── build a real self-signed certificate without shelling out to OpenSSL ────
//
// node cannot MINT an X.509 certificate, so this uses a fixed, known-good
// self-signed pair generated once for this test. It is a test fixture and
// nothing else — the key is public, in a public repository, and must never be
// used by anything.
const FIXTURE = require('./fixtures/testCert');

describe('rejects the paste mistakes people actually make', () => {
  it('empty input', () => {
    assert.match(validateCertificatePair('', '').error, /Paste the certificate/);
    assert.match(validateCertificatePair(FIXTURE.cert, '').error, /Paste the private key/);
  });

  it('⛔ the two boxes filled in the wrong order', () => {
    const r = validateCertificatePair(FIXTURE.key, FIXTURE.cert);
    assert.equal(r.valid, false);
    assert.match(r.error, /does not look like a certificate/);
  });

  it('a certificate pasted into the key box', () => {
    const r = validateCertificatePair(FIXTURE.cert, FIXTURE.cert);
    assert.equal(r.valid, false);
    assert.match(r.error, /other way round/);
  });

  it('⛔ a passphrase-protected key, with the reason and the fix', () => {
    // There is nowhere to prompt for a passphrase when a Windows service starts,
    // so this would fail at boot rather than at install.
    const enc = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----';
    const r = validateCertificatePair(FIXTURE.cert, enc);
    assert.equal(r.valid, false);
    assert.match(r.error, /passphrase-protected/);
    assert.match(r.error, /openssl rsa/);
  });

  it('garbage in either box', () => {
    assert.equal(validateCertificatePair('not a cert', FIXTURE.key).valid, false);
    assert.equal(validateCertificatePair(FIXTURE.cert, 'not a key').valid, false);
  });
});

describe('⛔ the check that matters: does the key belong to the certificate', () => {
  it('accepts a genuine pair', () => {
    const r = validateCertificatePair(FIXTURE.cert, FIXTURE.key);
    assert.equal(r.valid, true, r.error || '');
    assert.equal(r.error, null);
  });

  it('⛔ REFUSES a valid certificate with a valid but UNRELATED key', () => {
    // Both parse. Both are well-formed. They fail only at the TLS handshake,
    // which is to say: at the next restart, silently, in production.
    const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
      .privateKey.export({ type: 'pkcs8', format: 'pem' });
    const r = validateCertificatePair(FIXTURE.cert, other);
    assert.equal(r.valid, false);
    assert.match(r.error, /does not belong to this certificate/);
    assert.match(r.error, /break the console/);
  });
});

describe('reports what the certificate actually covers', () => {
  it('returns subject, issuer, names and expiry', () => {
    const r = validateCertificatePair(FIXTURE.cert, FIXTURE.key);
    assert.ok(r.subject.length > 0);
    assert.ok(Array.isArray(r.sans) && r.sans.length > 0);
    assert.ok(r.validTo);
    assert.equal(typeof r.daysRemaining, 'number');
  });

  it('flags a self-signed certificate without treating it as an error', () => {
    // Perfectly valid on an internal appliance; it just warns in a browser.
    const r = validateCertificatePair(FIXTURE.cert, FIXTURE.key);
    assert.equal(r.selfSigned, true);
    assert.equal(r.valid, true);
  });

  it('describeCertificate works WITHOUT a key', () => {
    // ⛔ The bug this function exists to fix: validateCertificatePair refuses a
    // missing key before it parses anything, so reusing it to report a deployed
    // certificate silently returned nothing at all.
    const d = describeCertificate(FIXTURE.cert);
    assert.ok(d.subject.length > 0);
    assert.ok(d.sans.length > 0);
    assert.equal(d.parseError, null);
  });

  it('describeCertificate reports a parse error rather than throwing', () => {
    const d = describeCertificate('-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----');
    assert.ok(d.parseError);
  });

  it('describeCertificate returns null for nothing', () => {
    assert.equal(describeCertificate(''), null);
    assert.equal(describeCertificate(null), null);
  });
});

describe('expiry', () => {
  it('daysUntil is negative once past', () => {
    const past = new Date(Date.now() - 5 * 86400000);
    assert.ok(daysUntil(past) < 0);
  });

  it('⛔ an already-expired certificate is REFUSED, not warned about', () => {
    // Installing one guarantees a browser wall on the next restart, and it is
    // almost always the wrong file rather than a deliberate choice.
    const r = validateCertificatePair(FIXTURE.cert, FIXTURE.key, new Date('2099-01-01T00:00:00Z'));
    assert.equal(r.valid, false);
    assert.match(r.error, /expired/);
    assert.match(r.error, /unreachable in every browser/);
  });
});
