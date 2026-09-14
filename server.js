'use strict';

// server.js — SecVault's HTTP/HTTPS entry point.
//
// ⛔ WHY A CUSTOM SERVER EXISTS AT ALL. `next start` cannot serve TLS; there is
// no flag for it, in any version. Terminating TLS therefore means either a
// reverse proxy (another component to install, configure and keep running on a
// firewall-management box) or wrapping Next's request handler in
// https.createServer, which is this file. NSSM's SecVault-App AppParameters
// points here instead of at next/dist/bin/next.
//
// ⛔ ROLLBACK IS ONE COMMAND, and worth knowing before you need it:
//     nssm set SecVault-App AppParameters "node_modules\next\dist\bin\next start -p 3010"
//   That restores the pre-v2.112.0 plaintext server exactly.
//
// ── The three listeners ────────────────────────────────────────────────────
//
//   3010  HTTPS (was plain HTTP before v2.112.0 — the port is deliberately
//         UNCHANGED so every bookmark, ticket link and firewall rule still
//         points at the right place)
//   3010  ...and ALSO plain HTTP, on the same port. A browser following an old
//         http://host:3010 bookmark would otherwise get an unexplained
//         connection error, because a plaintext request into a TLS listener is
//         not a redirect, it is a protocol failure. The first byte of a TLS
//         handshake is 0x16; anything else is treated as plaintext and answered
//         with a redirect to https. See demux() below.
//   3080  plain HTTP, redirect only. A conventional place to point anything
//         that cannot be changed to https.
//
// ⛔ IF TLS IS CONFIGURED BUT BROKEN, THIS SERVES PLAIN HTTP AND SAYS SO LOUDLY
// (lib/tlsConfig.js explains the reasoning). It does not pretend to be
// encrypted, and it does not refuse to start — on this product an outage means
// nobody can see the fleet, which has its own security cost.

const http = require('http');
const https = require('https');
const net = require('net');
const next = require('next');
const { loadEnvConfig } = require('@next/env');

// ⛔ LOAD .env.local BEFORE READING ANY OF IT. `next start` does this itself, but
// a CUSTOM SERVER must do it explicitly — and this file reads TLS_CERT_PATH at
// its top level, before next() is even constructed.
//
// This cost a production outage. On the server the TLS paths live in .env.local,
// so resolveTlsConfig() saw an empty process.env and reported "TLS: not
// configured" — the console came up on plain HTTP, the updater's HTTPS probe
// correctly found nothing, and the rollback fired. Everything else worked
// throughout, because Next loads the env for the APP's code; only this file's
// own top-level read was empty.
//
// ⛔ AND IT IS WHY THE LOCAL TEST PASSED. I exported TLS_CERT_PATH in the shell
// before running server.js, so process.env already had it and the missing load
// was invisible. A local test that supplies configuration differently from
// production is not testing the path production takes.
loadEnvConfig(process.cwd());

const {
  resolveTlsConfig,
  describeTlsStatus,
  nextAuthUrlMismatch,
} = require('./lib/tlsConfig');

const TLS_HANDSHAKE_FIRST_BYTE = 0x16;

// A client that connects and then says nothing holds a socket open forever
// while we wait to see its first byte. Firewalls, health probes and port
// scanners all do this.
const FIRST_BYTE_TIMEOUT_MS = 15000;

function redirectHandler(httpsPort) {
  return (req, res) => {
    // Host header minus any port the client used, plus our HTTPS port.
    const rawHost = (req.headers.host || '').split(':')[0] || 'localhost';
    const suffix = httpsPort === 443 ? '' : `:${httpsPort}`;
    const location = `https://${rawHost}${suffix}${req.url || '/'}`;
    res.writeHead(301, { Location: location, 'Content-Length': '0' });
    res.end();
  };
}

/**
 * Route one connection on the HTTPS port to either the TLS server or the
 * plaintext redirect server, by peeking at its first byte.
 *
 * ⛔ THE UNSHIFT IS LOAD-BEARING. The byte has already been consumed by the time
 * we can look at it, so it must be pushed back before the chosen server reads
 * the stream, or every request loses its first character and fails to parse.
 * Pause first, unshift, hand over, then resume on the next tick so the
 * receiving server has attached its own listeners.
 */
function demux(socket, tlsServer, plainServer) {
  socket.setTimeout(FIRST_BYTE_TIMEOUT_MS, () => socket.destroy());

  socket.once('data', (buf) => {
    socket.setTimeout(0);
    socket.pause();
    socket.unshift(buf);
    const target = buf[0] === TLS_HANDSHAKE_FIRST_BYTE ? tlsServer : plainServer;
    target.emit('connection', socket);
    process.nextTick(() => socket.resume());
  });

  // A socket that errors before its first byte is normal traffic noise on a
  // firewall-facing port: a scan, a probe, a dropped connection. Never let it
  // reach the process-level handler.
  socket.on('error', () => socket.destroy());
}

async function main() {
  const tls = resolveTlsConfig(process.env);
  const app = next({ dev: false });
  await app.prepare();
  const handle = app.getRequestHandler();

  // ── announce the transport before anything binds ────────────────────────
  const line = describeTlsStatus(tls);
  if (tls.status === 'failed') {
    console.error('');
    console.error('  ' + '='.repeat(72));
    console.error('  ' + line);
    console.error('  SecVault is running, but traffic is NOT encrypted.');
    console.error('  ' + '='.repeat(72));
    console.error('');
  } else {
    console.log(`[secvault] ${line}`);
  }

  // ⛔ A scheme mismatch here breaks sign-in with no error anywhere: NextAuth
  // builds its callback from NEXTAUTH_URL, and a cookie issued for the wrong
  // origin simply bounces the user back to the login page.
  const mismatch = nextAuthUrlMismatch(tls, process.env.NEXTAUTH_URL);
  if (mismatch) {
    console.error(`[secvault] ⛔ ${mismatch}`);
  }

  if (tls.status !== 'active') {
    // Exactly what `next start -p 3010` did before this file existed.
    http.createServer((req, res) => handle(req, res)).listen(tls.httpsPort, () => {
      console.log(`[secvault] listening on http://0.0.0.0:${tls.httpsPort}`);
    });
    return;
  }

  // ── TLS ─────────────────────────────────────────────────────────────────
  const tlsServer = https.createServer(
    {
      cert: tls.cert,
      key: tls.key,
      // ⛔ TLS 1.2 floor. 1.0/1.1 are deprecated and are a finding in any scan of
      // a security product; anything older than 1.2 has no business terminating
      // an admin console in 2026.
      minVersion: 'TLSv1.2',
    },
    (req, res) => handle(req, res)
  );
  tlsServer.on('tlsClientError', () => { /* scans and probes; not actionable */ });

  const plainOnTlsPort = http.createServer(redirectHandler(tls.httpsPort));

  // Neither of the two above binds a port itself — the front door does.
  const front = net.createServer((socket) => demux(socket, tlsServer, plainOnTlsPort));
  front.on('error', (err) => {
    console.error(`[secvault] listener on ${tls.httpsPort} failed: ${err.message}`);
    process.exit(1);
  });
  front.listen(tls.httpsPort, () => {
    console.log(`[secvault] listening on https://0.0.0.0:${tls.httpsPort} (plaintext on this port is redirected)`);
  });

  // ── the dedicated redirect port ─────────────────────────────────────────
  if (tls.httpPort && tls.httpPort !== tls.httpsPort) {
    const redirector = http.createServer(redirectHandler(tls.httpsPort));
    // ⛔ Never fatal. The redirect port is a convenience; failing to bind it
    // must not take down the console, which is already listening on 3010.
    redirector.on('error', (err) => {
      console.error(`[secvault] HTTP redirect port ${tls.httpPort} unavailable: ${err.message}`);
    });
    redirector.listen(tls.httpPort, () => {
      console.log(`[secvault] redirecting http://0.0.0.0:${tls.httpPort} -> https://…:${tls.httpsPort}`);
    });
  }
}

main().catch((err) => {
  console.error('[secvault] failed to start:', err && err.stack ? err.stack : err);
  process.exit(1);
});
