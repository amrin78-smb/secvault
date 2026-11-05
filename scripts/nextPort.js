#!/usr/bin/env node
'use strict';

// ---------------------------------------------------------------------------
// `next dev` / `next start` on the port THIS INSTALL is configured for.
//
// ⛔ BOTH SCRIPTS CARRIED `-p 3010` AS A LITERAL. Install-SecVault.ps1 has
// always taken -AppPort and written APP_PORT, and lib/tlsConfig.js has always
// resolved HTTPS_PORT || APP_PORT at startup — so the npm scripts were the one
// place in the repo that could not follow the install. On a server moved off
// the default, `npm start` served the console on a port nothing was firewalled
// for or bookmarked at; on the Linux dev box `npm run dev` collided with
// another NocVault app already holding 3010.
//
// ⛔ A TAKEN PORT DOES NOT FAIL LOUDLY HERE, which is why this matters more
// than a convenience. Measured on the dev box: the process printed its TLS
// line and exited, and the API sweep then reported `/api/auth/csrf returned
// 426` — the OTHER app answering. A 426 from a SecVault URL means you are
// talking to the wrong server, so a silently-wrong port costs a debugging
// session, not an error message.
//
// ⛔ NOT a shell-expanded `${APP_PORT:-3010}` in package.json: npm runs scripts
// through cmd.exe on Windows, which does not expand that form — the same
// portability trap scripts/runTests.js exists for. And not `next`'s own PORT
// variable, whose fallback is 3000 rather than this product's 3010.
//
// ⛔ It spawns node against next's REAL JS entry point, never node_modules\.bin\next
// — that is npm's POSIX shell wrapper, and launching it on Windows crashes on
// every start while the service manager still reports success (CLAUDE.md,
// NSSM registration).
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const DEFAULT_PORT = 3010;
const REPO_ROOT = path.join(__dirname, '..');

/** A port from a string, or null. Never NaN, never 0 — same shape as lib/tlsConfig.js's portFrom. */
function parsePort(value) {
  const n = Number.parseInt(String(value == null ? '' : value).trim(), 10);
  return Number.isInteger(n) && n > 0 && n < 65536 ? n : null;
}

/**
 * APP_PORT out of .env.local, without loading dotenv (this runs before next does).
 * ⛔ A MISSING OR UNREADABLE FILE IS NOT A PORT — it returns null and the caller
 * falls back to the documented default, rather than this function inventing one.
 */
function portFromEnvFile(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
  // Last assignment wins, matching how the env loaders read a duplicated key.
  let found = null;
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*APP_PORT\s*=\s*(.*)$/.exec(line);
    if (m) found = parsePort(m[1].replace(/^["']|["']$/g, ''));
  }
  return found;
}

function resolvePort() {
  const fromEnv = parsePort(process.env.APP_PORT);
  if (fromEnv) return { port: fromEnv, source: 'APP_PORT in the environment' };
  const fromFile = portFromEnvFile(path.join(REPO_ROOT, '.env.local'));
  if (fromFile) return { port: fromFile, source: '.env.local' };
  return { port: DEFAULT_PORT, source: 'the built-in default' };
}

const argv = process.argv.slice(2);
const sub = argv[0];
if (sub !== 'dev' && sub !== 'start') {
  console.error(`[nextPort] expected "dev" or "start", got ${sub ? `"${sub}"` : 'nothing'}`);
  process.exit(2);
}

const { port, source } = resolvePort();
const nextBin = path.join(REPO_ROOT, 'node_modules', 'next', 'dist', 'bin', 'next');
if (!fs.existsSync(nextBin)) {
  console.error(`[nextPort] next is not installed at ${nextBin} — run npm ci`);
  process.exit(2);
}

// An explicit -p/--port on the command line still wins, so an operator can
// override without editing anything.
const hasExplicitPort = argv.some((a) => a === '-p' || a === '--port' || a.startsWith('--port='));
const args = hasExplicitPort ? argv : [sub, '-p', String(port), ...argv.slice(1)];
if (!hasExplicitPort) console.log(`[nextPort] next ${sub} on port ${port} (from ${source})`);

const child = spawn(process.execPath, [nextBin, ...args], { stdio: 'inherit' });
child.on('exit', (code, signal) => {
  if (signal) { process.kill(process.pid, signal); return; }
  process.exit(code == null ? 1 : code);
});
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { try { child.kill(sig); } catch { /* already gone */ } });
}
