'use strict';

// lib/certValidate.js
//
// Validates a certificate + private key pair BEFORE it is written to disk.
//
// ⛔ THIS IS THE WHOLE POINT OF THE FEATURE. Installing a certificate that does
// not match its key, or a key the runtime cannot parse, does not fail when you
// click the button — it fails on the NEXT RESTART, which may be weeks later
// during an unrelated upgrade, and it takes the console down. By then nobody
// connects the outage to the certificate. Everything that can be checked is
// checked here, in memory, and a pair that does not pass is never written.
//
// ⛔ It reports what the certificate IS, not just whether it parsed. An operator
// pasting a certificate almost always wants to know the two things that actually
// bite: does it cover the name they reach this server by (SANs), and when does
// it expire. Both are returned.
//
// Pure apart from node:crypto — no filesystem, no pool — so tests drive every
// branch with literal PEM.

const crypto = require('crypto');

/** Days until a date, negative if already past. */
function daysUntil(date, now) {
  const ref = now instanceof Date ? now : new Date();
  return Math.floor((date.getTime() - ref.getTime()) / 86400000);
}

/**
 * @returns {{valid:boolean, error:string|null, subject?:string, issuer?:string,
 *            sans?:string[], validFrom?:string, validTo?:string,
 *            daysRemaining?:number, expired?:boolean, selfSigned?:boolean}}
 */
function validateCertificatePair(certPem, keyPem, now) {
  const cert = String(certPem || '').trim();
  const key = String(keyPem || '').trim();

  if (!cert) return { valid: false, error: 'Paste the certificate (PEM).' };
  if (!key) return { valid: false, error: 'Paste the private key (PEM).' };

  // ⛔ Checked explicitly so the commonest paste mistakes get a sentence a human
  // can act on, rather than whatever OpenSSL's parser says about byte 0.
  if (!/-----BEGIN CERTIFICATE-----/.test(cert)) {
    return {
      valid: false,
      error: 'That does not look like a certificate. It should begin with '
        + '"-----BEGIN CERTIFICATE-----". If you have a .pfx or .p12 file, export the '
        + 'certificate and key to PEM first.',
    };
  }
  if (/-----BEGIN CERTIFICATE-----/.test(key)) {
    return {
      valid: false,
      error: 'The private key box contains a certificate. The two boxes are the other way round.',
    };
  }
  if (!/-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----/.test(key)) {
    return {
      valid: false,
      error: 'That does not look like a private key. It should begin with "-----BEGIN PRIVATE KEY-----" '
        + '(or "BEGIN RSA PRIVATE KEY").',
    };
  }
  // ⛔ An encrypted key cannot be loaded at boot without a passphrase, and there
  // is nowhere to prompt for one when a Windows service starts. Rejected here
  // with an explanation rather than at 3am on the next restart.
  if (/-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(key)) {
    return {
      valid: false,
      error: 'This private key is passphrase-protected. SecVault starts as a Windows service and has '
        + 'nowhere to ask for a passphrase, so the key must be decrypted first '
        + '(openssl rsa -in enc.key -out plain.key).',
    };
  }

  let x509;
  try {
    x509 = new crypto.X509Certificate(cert);
  } catch (err) {
    return { valid: false, error: `The certificate could not be parsed: ${err.message}` };
  }

  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(key);
  } catch (err) {
    return { valid: false, error: `The private key could not be parsed: ${err.message}` };
  }

  // ⛔ THE CHECK THAT MATTERS. A valid certificate and a valid key that are not
  // each other's pair parse perfectly and fail only at the TLS handshake.
  let matches = false;
  try {
    matches = x509.checkPrivateKey(privateKey);
  } catch (err) {
    return { valid: false, error: `The key could not be checked against the certificate: ${err.message}` };
  }
  if (!matches) {
    return {
      valid: false,
      error: 'This private key does not belong to this certificate. Installing them would break '
        + 'the console the next time it restarts.',
    };
  }

  const sans = String(x509.subjectAltName || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  const validTo = new Date(x509.validTo);
  const remaining = daysUntil(validTo, now);

  const info = {
    valid: true,
    error: null,
    subject: String(x509.subject || '').replace(/\n/g, ', '),
    issuer: String(x509.issuer || '').replace(/\n/g, ', '),
    sans,
    validFrom: x509.validFrom,
    validTo: x509.validTo,
    daysRemaining: remaining,
    expired: remaining < 0,
    // Informational only — a self-signed certificate is a perfectly valid thing
    // to run on an internal appliance, it just produces a browser warning.
    selfSigned: String(x509.subject) === String(x509.issuer),
  };

  // ⛔ An ALREADY-EXPIRED certificate is refused rather than warned about.
  // Installing one guarantees a browser wall on the next restart, and it is
  // almost always a copy-paste of the wrong file.
  if (info.expired) {
    // ⛔ SPREAD FIRST, THEN OVERRIDE. Written the other way round, `...info`
    // carried its own `error: null` over the message set above and this branch
    // returned invalid-with-no-reason — which the UI would render as a silent
    // refusal the operator cannot act on. Caught by tests/certValidate.test.js.
    return {
      ...info,
      valid: false,
      error: `This certificate expired on ${x509.validTo}. Installing it would make the console `
        + 'unreachable in every browser.',
    };
  }

  // ⛔ SANs are REQUIRED by every current browser — the CN is ignored entirely.
  // A certificate without them is not merely untrusted, it is rejected.
  if (sans.length === 0) {
    return {
      ...info,
      valid: false,
      error: 'This certificate has no Subject Alternative Names. Modern browsers ignore the Common '
        + 'Name entirely and will reject it. Ask for a certificate that lists the hostname and/or '
        + 'IP address you use to reach SecVault.',
    };
  }

  return info;
}

/**
 * Describe a certificate WITHOUT needing its key.
 *
 * ⛔ Separate from validateCertificatePair on purpose. That function refuses a
 * missing key BEFORE it parses anything, which is right when installing a pair
 * and wrong when simply reporting what is already deployed — reusing it there
 * silently returned nothing at all.
 */
function describeCertificate(certPem, now) {
  const cert = String(certPem || '').trim();
  if (!cert) return null;
  let x509;
  try {
    x509 = new crypto.X509Certificate(cert);
  } catch (err) {
    return { parseError: err.message };
  }
  const sans = String(x509.subjectAltName || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const remaining = daysUntil(new Date(x509.validTo), now);
  return {
    subject: String(x509.subject || '').replace(/\n/g, ', '),
    issuer: String(x509.issuer || '').replace(/\n/g, ', '),
    sans,
    validFrom: x509.validFrom,
    validTo: x509.validTo,
    daysRemaining: remaining,
    expired: remaining < 0,
    selfSigned: String(x509.subject) === String(x509.issuer),
    parseError: null,
  };
}

module.exports = { validateCertificatePair, describeCertificate, daysUntil };
