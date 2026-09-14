import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import fs from 'fs';
import path from 'path';
import { authOptions } from '../../auth/[...nextauth]/route';
import { pool } from '../../../../lib/db';
import { can, forbiddenResponse, MANAGE_SETTINGS } from '../../../../lib/rbac';
import { resolveTlsConfig } from '../../../../lib/tlsConfig';
import { validateCertificatePair, describeCertificate } from '../../../../lib/certValidate';
import { importCertificate } from '../../../../lib/certImport';
import { logActivity } from '../../../../lib/activityLog';

export const dynamic = 'force-dynamic';

// Certificate management for the console's own TLS.
//
// ⛔ MANAGE_SETTINGS. Replacing the certificate changes how every user reaches
// this product, and a bad one takes the console down on the next restart. It is
// administration of the installation, not of a device.
//
// ⛔ THE PRIVATE KEY IS NEVER RETURNED, by any handler, in any shape. It is
// write-only from the API's point of view: the GET reports what the certificate
// IS (subject, names, expiry) and nothing about the key beyond whether one is
// present.

const CERT_DIR = path.join(process.cwd(), 'certs');
const CERT_PATH = path.join(CERT_DIR, 'secvault.crt');
const KEY_PATH = path.join(CERT_DIR, 'secvault.key');

/** Describe whatever certificate is currently on disk, without the key. */
function currentCertificate() {
  const config = resolveTlsConfig(process.env);
  const out = {
    status: config.status,
    error: config.error,
    httpsPort: config.httpsPort,
    httpPort: config.httpPort,
    certPath: config.certPath,
    certificate: null,
  };

  if (!config.certPath) return out;

  try {
    // ⛔ describeCertificate, NOT validateCertificatePair. The latter refuses a
    // missing key BEFORE it parses anything — correct when installing a pair,
    // and silently returns nothing when simply reporting what is deployed. The
    // private key is never read here, because nothing on this path needs it.
    const pem = fs.readFileSync(config.certPath, 'utf8');
    out.certificate = describeCertificate(pem);
  } catch (err) {
    out.certificate = null;
  }

  return out;
}

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) return forbiddenResponse(MANAGE_SETTINGS);
  return NextResponse.json(currentCertificate());
}

/**
 * Install a new certificate + key.
 *
 * ⛔ VALIDATE, THEN BACK UP, THEN WRITE — in that order, and never any other.
 * Writing first would leave a broken pair on disk if validation failed, and
 * skipping the backup would make a mistaken install unrecoverable without
 * re-issuing from the CA.
 */
export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) return forbiddenResponse(MANAGE_SETTINGS);

  const body = await request.json().catch(() => ({}));

  // ⛔ ACCEPT WHAT A WINDOWS ADMINISTRATOR ACTUALLY HAS. A Microsoft CA issues
  // .pfx; exporting from the Windows certificate store offers .cer; almost
  // nothing on Windows produces the PEM pair node wants. Requiring three OpenSSL
  // commands before a certificate can be installed is how this feature would go
  // unused and the console would stay self-signed forever.
  //
  // Files arrive base64-encoded (a .pfx is binary and cannot survive JSON any
  // other way); pasted PEM still arrives as plain text.
  let certInput = body && body.certificate;
  let keyInput = body && body.privateKey;

  if (body && body.certificateB64) {
    const certBuf = Buffer.from(String(body.certificateB64), 'base64');
    const keyBuf = body.privateKeyB64
      ? Buffer.from(String(body.privateKeyB64), 'base64')
      : null;
    const imported = importCertificate(certBuf, keyBuf, body.passphrase);
    if (imported.error && !imported.keyPem) {
      return NextResponse.json({ error: imported.error, certificate: null }, { status: 400 });
    }
    certInput = imported.certPem;
    keyInput = imported.keyPem;
  }

  const info = validateCertificatePair(certInput, keyInput);

  if (!info.valid) {
    // ⛔ Nothing has been written at this point, and the message is the one the
    // validator produced — it is written for an operator, not a developer.
    return NextResponse.json({ error: info.error, certificate: null }, { status: 400 });
  }

  try {
    if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

    // ⛔ Timestamped backup of whatever is there now. An operator who pastes the
    // wrong certificate must be able to get back to a working console without
    // going to their CA.
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    for (const [src, label] of [[CERT_PATH, 'crt'], [KEY_PATH, 'key']]) {
      if (fs.existsSync(src)) {
        fs.copyFileSync(src, path.join(CERT_DIR, `secvault.${stamp}.bak.${label}`));
      }
    }

    // ⛔ The NORMALISED PEM, not the raw request body. A .pfx or .cer upload has
    // already been converted above, and writing body.certificate here would
    // store the binary container as though it were a certificate — producing a
    // file that passes every check in this route and breaks the next restart.
    fs.writeFileSync(CERT_PATH, String(certInput).trim() + '\n', 'utf8');
    // ⛔ 0600 where the platform honours it. On Windows the installer's ACL is
    // what actually protects this; the mode is belt and braces for any other host.
    fs.writeFileSync(KEY_PATH, String(keyInput).trim() + '\n', { encoding: 'utf8', mode: 0o600 });
  } catch (err) {
    return NextResponse.json(
      { error: `The certificate could not be written: ${err.message}` },
      { status: 500 }
    );
  }

  try {
    await logActivity(pool, {
      actor: (session.user && session.user.name) || 'unknown',
      action: 'tls_certificate_installed',
      // ⛔ Subject and expiry only. Never the key, and never the certificate body.
      detail: `TLS certificate replaced: ${info.subject} (expires ${info.validTo})`,
    });
  } catch (err) {
    console.warn(`[tls route] activity log failed: ${err.message}`);
  }

  return NextResponse.json({
    ok: true,
    // ⛔ SAID PLAINLY. The files on disk have changed but the running process is
    // still holding the OLD certificate in memory — node reads it once, at
    // startup. Without this sentence an operator reasonably concludes the new
    // certificate is live, and is then baffled when the browser keeps showing
    // the old one.
    restartRequired: true,
    message: 'Certificate installed. Restart the SecVault-App service to begin serving it.',
    certificate: {
      subject: info.subject,
      issuer: info.issuer,
      sans: info.sans,
      validFrom: info.validFrom,
      validTo: info.validTo,
      daysRemaining: info.daysRemaining,
      selfSigned: info.selfSigned,
    },
  });
}
