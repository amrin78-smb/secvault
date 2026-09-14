'use strict';

// lib/certImport.js
//
// Turns whatever a Windows administrator actually has into the PEM pair the
// server needs.
//
// ⛔ WHY THIS EXISTS. A Microsoft CA hands out .pfx; "export the certificate"
// in the Windows certificate store offers .cer; almost nothing on Windows
// produces the PEM pair node wants. Requiring the operator to run three OpenSSL
// commands before they can install a certificate is how a feature ends up
// unused and the console stays on a self-signed cert forever. Accepting what
// they have is the difference.
//
// Three inputs, three paths:
//
//   PEM          passed through. Already what we want.
//   DER (.cer)   converted IN-PROCESS. node's X509Certificate reads DER and can
//                re-emit PEM, so this needs no external tool at all.
//   PKCS#12      converted with OpenSSL. There is no PKCS#12 reader in node's
//   (.pfx/.p12)  crypto, and adding a parser dependency to handle a container
//                format would be a poor trade in authentication code. OpenSSL
//                ships with Git for Windows, which is already a hard dependency
//                of this suite's installer.
//
// ⛔ A PFX HOLDS THE PRIVATE KEY. Everything here runs on material that must not
// be logged, echoed, or left on disk: temp files are written with a random name,
// read once, and deleted in a finally block. The passphrase is passed to OpenSSL
// via an environment variable, never on the command line, because a command line
// is readable by any other process on the box.

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const PEM_CERT = /-----BEGIN CERTIFICATE-----/;
const PEM_KEY = /-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----/;

/**
 * Where OpenSSL lives on a SecVault host.
 *
 * ⛔ Mirrors installer/SecVault-Tls.ps1's list deliberately. Git for Windows is
 * a hard dependency of the suite installer, so it is present by the time
 * anything here runs.
 */
function findOpenSsl() {
  const candidates = [
    'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
    'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe',
    'C:\\Program Files (x86)\\Git\\usr\\bin\\openssl.exe',
    'C:\\Program Files\\PostgreSQL\\16\\bin\\openssl.exe',
    '/usr/bin/openssl',
    '/usr/local/bin/openssl',
  ];
  for (const c of candidates) {
    try {
      if (fs.existsSync(c)) return c;
    } catch (err) { /* keep looking */ }
  }
  return null;
}

/** Is this buffer text that looks like PEM? */
function looksLikePem(buf) {
  // Only sniff the head: a PFX is binary and may contain anything later on.
  const head = buf.slice(0, 2048).toString('latin1');
  return PEM_CERT.test(head) || PEM_KEY.test(head);
}

/**
 * Convert a DER certificate to PEM, in process.
 *
 * ⛔ No external tool. node's X509Certificate accepts DER and its toString()
 * emits PEM, so a .cer exported from the Windows certificate store needs
 * nothing but this.
 */
function derCertToPem(buf) {
  const x509 = new crypto.X509Certificate(buf);
  return x509.toString();
}

/**
 * Extract cert + key PEM from a PKCS#12 container.
 *
 * @returns {{certPem:string|null, keyPem:string|null, error:string|null}}
 */
function pfxToPem(buf, passphrase) {
  const openssl = findOpenSsl();
  if (!openssl) {
    return {
      certPem: null,
      keyPem: null,
      error: 'A .pfx file needs OpenSSL to unpack, and it was not found on this server. '
        + 'Export the certificate and key to PEM on another machine, or paste them directly.',
    };
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sv-pfx-'));
  const pfxPath = path.join(dir, 'in.pfx');

  try {
    fs.writeFileSync(pfxPath, buf, { mode: 0o600 });

    // ⛔ The passphrase goes through the ENVIRONMENT, never argv. A command line
    // is readable by any other process on the machine; an environment variable
    // of a short-lived child is not.
    //
    // ⛔ BUT THE CHILD GETS A MINIMAL ENVIRONMENT, NOT A COPY OF OURS. This
    // spread `...process.env` before, which handed OpenSSL CREDENTIAL_KEY,
    // DATABASE_URL and NEXTAUTH_SECRET — the keys that decrypt every stored
    // device credential — to a process that has no use for any of them. A child
    // process's environment is readable by anything that can inspect it, and it
    // is inherited onward by anything OpenSSL itself spawns. There is no benefit
    // to weigh against that: OpenSSL is invoked by ABSOLUTE PATH, so it does not
    // even need PATH to be found.
    //
    // The allowlist is the minimum a Windows process needs to start and to find
    // its own runtime: SystemRoot/windir for the OS DLLs, TEMP/TMP because
    // OpenSSL may write scratch files, PATH for the Git-for-Windows MSYS DLLs
    // that sit beside the exe, and OPENSSL_CONF because an operator who has set
    // it deliberately would otherwise get silently different behaviour here than
    // from their own shell.
    const env = { SV_PFX_PASS: passphrase == null ? '' : String(passphrase) };
    for (const name of ['SystemRoot', 'windir', 'TEMP', 'TMP', 'PATH', 'Path', 'OPENSSL_CONF']) {
      if (process.env[name] != null) env[name] = process.env[name];
    }
    const common = ['-in', pfxPath, '-passin', 'env:SV_PFX_PASS'];

    const run = (args) => execFileSync(openssl, args, {
      env,
      encoding: 'utf8',
      // ⛔ stderr is CAPTURED, not inherited. OpenSSL writes progress and
      // warnings there, and letting it reach the app log risks echoing
      // something derived from key material.
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let certPem;
    let keyPem;
    try {
      certPem = run(['pkcs12', ...common, '-nokeys', '-clcerts']);
      keyPem = run(['pkcs12', ...common, '-nocerts', '-nodes']);
    } catch (err) {
      // ⛔ OpenSSL 3 refuses the older RC2/3DES encryption that Windows still
      // produces unless -legacy is given. Retrying is the difference between
      // "works" and "your certificate is mysteriously rejected".
      try {
        certPem = run(['pkcs12', '-legacy', ...common, '-nokeys', '-clcerts']);
        keyPem = run(['pkcs12', '-legacy', ...common, '-nocerts', '-nodes']);
      } catch (err2) {
        // ⛔ READ BOTH STDERRs, NOT JUST THE RETRY'S. This preferred err2 alone,
        // and the retry is exactly the attempt whose failure says the LEAST.
        // Verified live against the OpenSSL that actually ships here (Git for
        // Windows, /usr/bin/openssl.exe): it has no legacy provider module, so
        // `-legacy` NEVER gets as far as the password and always dies with
        // "unable to load provider legacy". That error then overwrote the first
        // attempt's "Mac verify error: invalid password?" — so a mistyped .pfx
        // password produced the vague catch-all below instead of the one
        // sentence that would have ended the problem, on the primary upload
        // path, for the single most likely mistake an operator can make here.
        const firstMessage = String((err && err.stderr) || '');
        const retryMessage = String((err2 && err2.stderr) || '');
        const combined = `${firstMessage}\n${retryMessage}`;

        // Checked FIRST and across both attempts: a wrong password fails the MAC
        // check before any decryption, so it is reported by whichever attempt
        // got that far — usually attempt one, which the retry then buries.
        if (/mac verify (error|failure)|invalid password|wrong password/i.test(combined)) {
          return { certPem: null, keyPem: null, error: 'That password did not open the .pfx file.' };
        }

        // ⛔ NAME THE MISSING PROVIDER RATHER THAN BLAMING THE PASSWORD. An
        // older Windows .pfx (RC2/3DES) with an entirely CORRECT password lands
        // here, and telling that operator to "check the password" sends them to
        // re-export and retype it forever. The file is fine, the password is
        // fine, and this server's OpenSSL simply cannot open that container.
        if (/unable to load provider legacy|legacy\.dll|ossl-modules/i.test(retryMessage)) {
          return {
            certPem: null,
            keyPem: null,
            error: 'That .pfx uses older encryption (RC2/3DES) that this server\'s OpenSSL build '
              + 'cannot open — its legacy provider is not installed. The password is not the '
              + 'problem. Re-export the .pfx with AES encryption, or upload the certificate and '
              + 'key as separate PEM files.',
          };
        }

        return {
          certPem: null,
          keyPem: null,
          error: 'The .pfx file could not be read. Check the password, and that the file is a '
            + 'PKCS#12 export containing both the certificate and its private key.',
        };
      }
    }

    // OpenSSL prints "Bag Attributes" blocks around the PEM. Keep only the PEM.
    const certMatch = String(certPem).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
    const keyMatch = String(keyPem).match(/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----/);

    if (!certMatch) {
      return { certPem: null, keyPem: null, error: 'No certificate was found inside that .pfx file.' };
    }
    if (!keyMatch) {
      return {
        certPem: null,
        keyPem: null,
        error: 'That .pfx file contains a certificate but no private key. Re-export it with the '
          + 'private key included.',
      };
    }

    return { certPem: certMatch[0], keyPem: keyMatch[0], error: null };
  } catch (err) {
    return { certPem: null, keyPem: null, error: `The .pfx file could not be processed: ${err.message}` };
  } finally {
    // ⛔ ALWAYS. The temp file is a private key on disk.
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* best effort */ }
  }
}

/**
 * Normalise whatever was uploaded into { certPem, keyPem }.
 *
 * @param {Buffer} certBuf   the certificate or container
 * @param {Buffer|null} keyBuf  a separate key file, when the format needs one
 * @param {string} [passphrase] for PKCS#12
 */
function importCertificate(certBuf, keyBuf, passphrase) {
  if (!certBuf || certBuf.length === 0) {
    return { certPem: null, keyPem: null, error: 'No certificate file was provided.' };
  }

  // ── PKCS#12: one file carries both halves ──────────────────────────────
  // A DER certificate and a PFX both begin 0x30, so the certificate is tried
  // first and PFX is the fallback — not the other way round.
  if (!looksLikePem(certBuf)) {
    try {
      const pem = derCertToPem(certBuf);
      if (!keyBuf || keyBuf.length === 0) {
        return {
          certPem: pem,
          keyPem: null,
          error: 'That is a certificate only (.cer/.der). Add the matching private key file, or '
            + 'upload a .pfx which contains both.',
        };
      }
      const keyPem = looksLikePem(keyBuf) ? keyBuf.toString('utf8') : null;
      if (!keyPem) {
        return { certPem: pem, keyPem: null, error: 'The private key file is not in PEM format.' };
      }
      return { certPem: pem, keyPem, error: null };
    } catch (err) {
      // Not a DER certificate — try PKCS#12.
      return pfxToPem(certBuf, passphrase);
    }
  }

  // ── PEM ─────────────────────────────────────────────────────────────────
  const text = certBuf.toString('utf8');

  // A single PEM file often contains BOTH the certificate and the key.
  const hasKeyInline = PEM_KEY.test(text);
  if (hasKeyInline && (!keyBuf || keyBuf.length === 0)) {
    const certMatch = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
    const keyMatch = text.match(/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----/);
    if (certMatch && keyMatch) {
      return { certPem: certMatch[0], keyPem: keyMatch[0], error: null };
    }
  }

  return {
    certPem: text,
    keyPem: keyBuf && keyBuf.length ? keyBuf.toString('utf8') : null,
    error: null,
  };
}

module.exports = { importCertificate, pfxToPem, derCertToPem, looksLikePem, findOpenSsl };
