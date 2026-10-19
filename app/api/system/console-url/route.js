import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import dns from 'node:dns/promises';
import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '../../auth/[...nextauth]/route';
import { can, forbiddenResponse, MANAGE_SETTINGS } from '../../../../lib/rbac';
import { resolveTlsConfig } from '../../../../lib/tlsConfig';
import { validateConsoleUrl, hostPointsHere } from '../../../../lib/consoleUrl';
import { setEnvValue, readEnvFile } from '../../../../lib/envFile';
import { findGitRoot } from '../../../../lib/updateCheck';

// Reads and writes .env.local, so it can never be prerendered.
export const dynamic = 'force-dynamic';

// ⛔ THE ADDRESS THE CONSOLE IS REACHED ON, which NextAuth builds its callback
// from. Set it wrong and every sign-in bounces back to the login page with no
// error anywhere — and nobody can log in to undo it. That is why this route
// validates before it writes, refuses a host that does not point here, backs
// the file up, and states the manual recovery path in its own response.
//
// It exists because the alternative is editing .env.local over RDP, which is
// what the competing product replaced with a settings page years ago.

function envPath() {
  const root = findGitRoot() || process.cwd();
  return path.join(root, '.env.local');
}

/** Every address this machine holds, for the points-here check. */
function localAddresses() {
  const out = ['127.0.0.1', '::1'];
  const ifaces = os.networkInterfaces();
  for (const list of Object.values(ifaces)) {
    for (const i of list || []) if (i && i.address) out.push(i.address);
  }
  return out;
}

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) return forbiddenResponse(MANAGE_SETTINGS);

  const tls = resolveTlsConfig(process.env);
  const file = envPath();
  let current = process.env.NEXTAUTH_URL || null;
  let writable = false;
  try {
    // The RUNNING value and the value ON DISK can differ — the process keeps
    // whatever it started with. Showing the file's value is what makes
    // "restart required" mean something the operator can verify.
    const { values } = readEnvFile(file);
    current = values.NEXTAUTH_URL || current;
    fs.accessSync(file, fs.constants.W_OK);
    writable = true;
  } catch { /* reported below rather than thrown */ }

  return NextResponse.json({
    current,
    running: process.env.NEXTAUTH_URL || null,
    // A restart is pending whenever the file and the process disagree.
    restartPending: !!(current && process.env.NEXTAUTH_URL && current !== process.env.NEXTAUTH_URL),
    tlsActive: tls.status === 'active',
    scheme: tls.status === 'active' ? 'https' : 'http',
    httpsPort: tls.httpsPort,
    httpPort: tls.httpPort,
    envPath: file,
    writable,
  });
}

export async function PUT(request) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) return forbiddenResponse(MANAGE_SETTINGS);

  const body = await request.json().catch(() => ({}));
  const tls = resolveTlsConfig(process.env);
  const check = validateConsoleUrl(body && body.url, { tlsActive: tls.status === 'active' });
  if (!check.ok) return NextResponse.json({ error: check.error }, { status: 400 });

  // ⛔ THE LOCKOUT GUARD, and the ONLY place a typo is caught. Refused unless
  // the operator has explicitly acknowledged it — a name that resolves nowhere
  // near this server is the single way to make the console unreachable.
  const where = await hostPointsHere(check.host, {
    lookup: (h) => dns.lookup(h, { all: true }),
    localAddresses: localAddresses(),
  });
  if (where.resolved && where.pointsHere === false && !body.force) {
    return NextResponse.json({
      error: `${check.host} resolves to ${where.addresses.join(', ')}, which is not an address on this `
        + 'server. Signing in at that address would not reach SecVault. Create the DNS record first, '
        + 'or confirm to save it anyway.',
      needsConfirmation: true,
      resolvedTo: where.addresses,
    }, { status: 409 });
  }

  const file = envPath();
  const result = setEnvValue(file, 'NEXTAUTH_URL', check.url);
  if (!result.ok) {
    // ⛔ THE BACKUP PATH TRAVELS WITH THE FAILURE, AND IN THE MESSAGE ITSELF.
    // setEnvValue's own error strings end "...at the backup path below" — and
    // this route used to send `error` alone, so the operator read a sentence
    // promising a path with nothing beneath it, on the one file that holds
    // CREDENTIAL_KEY. It matters more since a VERIFIED success no longer keeps
    // a backup: a reported path now means the write really did fail. The panel
    // renders `error` only, so the path goes in the string as well as the field
    // rather than relying on a component change to become visible.
    return NextResponse.json({
      error: result.backupPath
        ? `${result.error} The previous file is at ${result.backupPath}.`
        : result.error,
      backupPath: result.backupPath || null,
    }, { status: 500 });
  }

  return NextResponse.json({
    ok: true,
    url: check.url,
    previous: result.previous,
    unchanged: !!result.unchanged,
    backupPath: result.backupPath,
    warnings: [
      ...check.warnings,
      ...(where.resolved ? [] : [
        `${check.host} could not be resolved from this server (${where.error}). That may simply mean `
        + 'this host uses a different resolver than your workstations — but nothing has verified the '
        + 'address is reachable.',
      ]),
      ...(where.pointsHere === false ? [
        `Saved anyway: ${check.host} resolves to ${where.addresses.join(', ')}, not to this server.`,
      ] : []),
    ],
    // ⛔ Stated in the response, not only in the UI. Node reads this value once,
    // at startup; until the service restarts the change has done nothing.
    restartRequired: !result.unchanged,
    // ⛔ THE PREVIOUS VALUE IS THE RECOVERY INFORMATION, NOT A BACKUP PATH.
    // setEnvValue removes its backup once it has verified the write, so a
    // sentence naming that path would name a file that is no longer there —
    // and the operator needs the old URL, which is what they have to type
    // back. The path is mentioned only when a backup actually survived.
    recovery: result.unchanged ? null
      // ⛔ `== null`, NOT `||`. A key present but BLANK (`NEXTAUTH_URL=`) has a
      // previous value of '', which `||` reports as "it was not previously
      // set" — telling the operator there is nothing to type back when the
      // correct recovery is to blank the line again.
      : `If sign-in stops working, set NEXTAUTH_URL back to `
        + `${result.previous == null ? '(it was not previously set)' : `"${result.previous}"`} `
        + `in ${file} on the server and `
        + 'restart SecVault-App with sc.exe.'
        + (result.backupPath ? ` A copy of the previous file is at ${result.backupPath}.` : ''),
  });
}
