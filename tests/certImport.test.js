'use strict';
// Pins lib/certImport.js — accepting the certificate formats a Windows
// administrator actually has (v2.112.1).
//
// ⛔ WHY THIS MATTERS MORE THAN IT LOOKS. A Microsoft CA issues .pfx; exporting
// from the Windows certificate store offers .cer; almost nothing on Windows
// produces the PEM pair node wants. A feature that demands three OpenSSL
// commands before it can be used does not get used — the console simply stays
// on its self-signed certificate forever, which is the outcome the whole TLS
// change exists to avoid.
//
// ⛔ The dangerous case here is a container written to disk AS THOUGH it were a
// certificate. A .pfx is binary; store it unconverted and every check in the
// install route still passes, because the route validated the CONVERTED PEM.
// The failure appears at the next restart.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { importCertificate, looksLikePem, derCertToPem } = require('../lib/certImport');
const { validateCertificatePair } = require('../lib/certValidate');
const FIXTURE = require('./fixtures/testCert');

const CERT_BUF = Buffer.from(FIXTURE.cert, 'utf8');
const KEY_BUF = Buffer.from(FIXTURE.key, 'utf8');
// DER is just the certificate's raw bytes — no external tool needed to build it.
const DER_BUF = Buffer.from(new crypto.X509Certificate(FIXTURE.cert).raw);

describe('format detection', () => {
  it('recognises PEM text', () => {
    assert.equal(looksLikePem(CERT_BUF), true);
    assert.equal(looksLikePem(KEY_BUF), true);
  });

  it('⛔ does NOT mistake binary DER for PEM', () => {
    // Getting this backwards would write a binary blob into a .crt file.
    assert.equal(looksLikePem(DER_BUF), false);
  });

  it('only sniffs the head, so a large binary file is cheap to classify', () => {
    const big = Buffer.concat([DER_BUF, Buffer.alloc(500000)]);
    assert.equal(looksLikePem(big), false);
  });
});

describe('PEM', () => {
  it('passes a cert + key pair straight through', () => {
    const r = importCertificate(CERT_BUF, KEY_BUF);
    assert.equal(r.error, null);
    assert.equal(validateCertificatePair(r.certPem, r.keyPem).valid, true);
  });

  it('splits a COMBINED file containing both', () => {
    // Common when a CA emits a single "fullchain + key" bundle.
    const combined = Buffer.from(`${FIXTURE.cert}\n${FIXTURE.key}`, 'utf8');
    const r = importCertificate(combined, null);
    assert.equal(r.error, null);
    assert.equal(validateCertificatePair(r.certPem, r.keyPem).valid, true);
  });
});

describe('DER (.cer exported from the Windows certificate store)', () => {
  it('converts to PEM in-process, with no external tool', () => {
    const pem = derCertToPem(DER_BUF);
    assert.match(pem, /-----BEGIN CERTIFICATE-----/);
    // and it is the SAME certificate, not merely a well-formed one
    assert.equal(
      new crypto.X509Certificate(pem).fingerprint256,
      new crypto.X509Certificate(FIXTURE.cert).fingerprint256
    );
  });

  it('a .cer plus its PEM key installs cleanly', () => {
    const r = importCertificate(DER_BUF, KEY_BUF);
    assert.equal(r.error, null);
    assert.equal(validateCertificatePair(r.certPem, r.keyPem).valid, true);
  });

  it('⛔ a .cer ALONE is refused with the reason, not accepted half-way', () => {
    // A certificate with no key cannot serve TLS. Saying which file is missing
    // is the difference between a fixable message and a mystery.
    const r = importCertificate(DER_BUF, null);
    assert.ok(r.error);
    assert.match(r.error, /certificate only/);
    assert.match(r.error, /\.pfx/);
    assert.equal(r.keyPem, null);
  });
});

describe('rejects what cannot work', () => {
  it('an empty upload', () => {
    const r = importCertificate(Buffer.alloc(0), null);
    assert.match(r.error, /No certificate file/);
  });

  it('random bytes are not silently accepted', () => {
    // Neither PEM nor DER nor PKCS#12 — must not fall through to "fine".
    const junk = Buffer.from([0x30, 0x82, 0x01, 0x02, 0x03, 0x04, 0x05]);
    const r = importCertificate(junk, null);
    assert.ok(r.error, 'junk was accepted');
    assert.equal(r.certPem, null);
  });

  it('a DER cert with a non-PEM key file is refused', () => {
    const r = importCertificate(DER_BUF, Buffer.from([1, 2, 3, 4]));
    assert.ok(r.error);
    assert.match(r.error, /not in PEM format/);
  });
});
