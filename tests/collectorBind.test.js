'use strict';
// Does this collector know whether it is LISTENING? (roadmap row 36)
//
// ⛔ THE DEFECT. `sock.bind`/`server.listen` reported failure only through an
// 'error' handler that logged and returned; `main()` never inspected the
// outcome and printed `collector ready.` regardless. A process that bound
// NOTHING stayed alive looking healthy — and the only liveness signal in the
// product, `max(recorded_at) FROM syslog_ingest_stats`, is written by
// `doFlush()` ONLY when there is a batch. So a deaf collector and a quiet
// fleet produced byte-identical evidence.
//
// ⛔ AND THE CHECK WOULD HAVE BEEN WORTHLESS OVER A reuseAddr SOCKET, which is
// why the socket option changed with it. The second describe block below is
// the measurement, re-run on whatever platform the suite runs on rather than
// quoted from a session that ran it once.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');

const { stripComments } = require('./stripComments');
const {
  bindTracker, awaitBind, listenerVerdict, fmtListener, fmtListenerError,
} = require('../lib/syslog/listenerState');

const ok = (port) => ({ protocol: 'udp', port, ok: true, error: null });
const bad = (port) => ({ protocol: 'udp', port, ok: false, error: 'bind EADDRINUSE' });
const unk = (port) => ({ protocol: 'tcp', port, ok: null, error: 'did not report within 10000ms' });

describe('⛔ the verdict: deaf requires that EVERY listener be a CONFIRMED failure', () => {
  it('everything bound is "listening"', () => {
    assert.equal(listenerVerdict([ok(514), ok(1514)]).state, 'listening');
  });

  it('every listener confirmed failed is "deaf"', () => {
    assert.equal(listenerVerdict([bad(514), bad(1514)]).state, 'deaf');
  });

  it('⛔ nothing bound but something UNKNOWN is "unknown", never "deaf"', () => {
    // Reporting deaf when we merely could not tell sends an operator to
    // restart a service that may be working perfectly.
    assert.equal(listenerVerdict([bad(514), unk(1514)]).state, 'unknown');
    assert.equal(listenerVerdict([unk(514)]).state, 'unknown');
  });

  it('⛔ some bound and some not is "partial", never "listening"', () => {
    assert.equal(listenerVerdict([ok(514), bad(1514)]).state, 'partial');
    assert.equal(listenerVerdict([ok(514), unk(1514)]).state, 'partial');
  });

  it('⛔ NO CONFIGURED LISTENER AT ALL is "deaf", not a vacuous all-clear', () => {
    // parsePortList rejects malformed entries, so a typo in SYSLOG_UDP_PORT
    // can empty both lists. An empty set passes "did everything bind?"
    // vacuously, which is how a guard reports success over nothing.
    assert.equal(listenerVerdict([]).state, 'deaf');
    assert.equal(listenerVerdict(undefined).state, 'deaf');
  });

  it('separates the three groups rather than counting them together', () => {
    const v = listenerVerdict([ok(514), bad(1514), unk(601)]);
    assert.deepEqual(v.bound.map(fmtListener), ['udp/514']);
    assert.deepEqual(v.failed.map(fmtListenerError), ['udp/1514: bind EADDRINUSE']);
    assert.equal(v.unknown.length, 1);
  });
});

describe('⛔ awaitBind is bounded, and a timeout is UNKNOWN rather than failed', () => {
  it('returns the real answer when the bind reports first', async () => {
    const r = await awaitBind(Promise.resolve(ok(514)), 'udp', 514, 5000);
    assert.equal(r.ok, true);
  });

  it('⛔ resolves ok:null — not false — when nothing reports in time', async () => {
    // Waiting forever would hold the flush timer hostage, which is worse than
    // the bug being fixed: a collector that never drains its spool.
    const never = new Promise(() => {});
    const r = await awaitBind(never, 'tcp', 514, 20);
    assert.equal(r.ok, null);
    assert.match(r.error, /did not report/);
    assert.equal(listenerVerdict([r]).state, 'unknown');
  });

});

describe('⛔ bindTracker: a bind failure and a runtime fault need OPPOSITE handling', () => {
  const track = () => {
    let resolve;
    const p = new Promise((r) => { resolve = r; });
    return { t: bindTracker(resolve), p };
  };

  it('a socket that never bound IS closed, so the retry can take the port', async () => {
    const { t, p } = track();
    assert.equal(t.failed(bad(514)), true, 'the caller must release the port');
    assert.equal((await p).ok, false);
  });

  it('⛔ a runtime fault on a LIVE listener is NOT closed — the guard must not cause the outage it detects', async () => {
    // This is what the collector did before the bind check existed: log, and
    // keep listening. Closing here would answer one bad packet by going deaf.
    const { t, p } = track();
    t.listening(ok(514));
    assert.equal(t.failed(bad(514)), false, 'a bound listener must never be torn down');
    assert.equal((await p).ok, true, 'and the startup verdict must stand');
  });

  it('a second failure does not close an already-released socket twice', () => {
    const { t } = track();
    assert.equal(t.failed(bad(514)), true);
    assert.equal(t.failed(bad(514)), false);
  });
});

describe('⛔ the socket option the whole check rests on, MEASURED here', () => {
  const PORT = 15190 + (process.pid % 200);

  const bind = (opts, port) => new Promise((resolve) => {
    const s = dgram.createSocket(opts);
    let done = false;
    s.on('error', (e) => { if (!done) { done = true; resolve({ bound: false, code: e.code, sock: null }); } });
    s.bind(port, () => { if (!done) { done = true; resolve({ bound: true, code: null, sock: s }); } });
  });

  it('⛔ WITHOUT reuseAddr a second bind is REFUSED — which is what makes a bind check mean anything', async () => {
    const a = await bind({ type: 'udp4' }, PORT);
    assert.equal(a.bound, true);
    try {
      const b = await bind({ type: 'udp4' }, PORT);
      assert.equal(b.bound, false, 'a second bind must fail');
      assert.equal(b.code, 'EADDRINUSE');
    } finally {
      a.sock.close();
    }
  });

  it('⛔ WITH reuseAddr it silently SUCCEEDS, which is the defect', async () => {
    // Measured 2026-11-15 with two real processes: on Windows the second
    // binder received 0 of 10 datagrams (the first holder kept them); on Linux
    // the second binder TOOK all 10 (libuv maps reuseAddr to SO_REUSEPORT
    // there). Either way the bind succeeds and the datagrams go elsewhere — so
    // a bind check over such a socket certifies a collector that is deaf.
    // 514 is LogVault's collector port on the shared staging box, so this is a
    // live configuration rather than a hypothetical.
    const p2 = PORT + 1;
    const a = await bind({ type: 'udp4', reuseAddr: true }, p2);
    assert.equal(a.bound, true);
    try {
      const b = await bind({ type: 'udp4', reuseAddr: true }, p2);
      assert.equal(b.bound, true, 'the whole point: this is NOT refused');
      b.sock.close();
    } finally {
      a.sock.close();
    }
  });

  it('⛔ a close-then-immediately-rebind still works without the flag, so a deploy is unaffected', async () => {
    const p3 = PORT + 2;
    const a = await bind({ type: 'udp4' }, p3);
    assert.equal(a.bound, true);
    await new Promise((r) => a.sock.close(r));
    const b = await bind({ type: 'udp4' }, p3);
    assert.equal(b.bound, true, 'UDP has no TIME_WAIT; a restart must rebind at once');
    b.sock.close();
  });
});

describe('⛔ the collector actually uses all of it', () => {
  // ⛔ COMMENT-STRIPPED, and here that is not a formality: the listener block's
  // own prose says `reuseAddr: true` five times while explaining why it is
  // gone, so a raw-text scan would report the defect it is documenting. The
  // prose-read-as-code trap, which this repo has now hit four times.
  const raw = fs.readFileSync(path.join(__dirname, '..', 'services', 'collector.js'), 'utf8')
    .replace(/\r\n/g, '\n');
  const code = stripComments(raw);

  it('creates its UDP sockets WITHOUT reuseAddr', () => {
    assert.match(code, /dgram\.createSocket\(\{\s*type:\s*'udp4'\s*\}\)/,
      'startUdp must create a plain udp4 socket');
    assert.doesNotMatch(code, /reuseAddr/,
      'reuseAddr lets us bind a port somebody else holds and then hear nothing');
  });

  it('⛔ AWAITS the bind result instead of assuming it', () => {
    assert.match(code, /await Promise\.all\(starts\)/);
    assert.match(code, /listenerVerdict\(/);
  });

  it('⛔ records the verdict durably, because a log line is not a health signal', () => {
    assert.match(code, /INSERT INTO syslog_listener_state/);
    assert.match(code, /recordListenerState\(verdict, 'startup'\)/);
  });

  it('⛔ does not print "collector ready" unconditionally any more', () => {
    // The closing banner line is the one an operator reads after a deploy. It
    // may not claim a state nobody checked.
    const readys = code.match(/collector ready/g) || [];
    assert.ok(readys.length > 0);
    assert.match(code, /verdict\.state === 'listening'/);
    assert.match(code, /NOT LISTENING/);
  });

  it('⛔ CLOSES a socket only when the tracker says it never bound', () => {
    // Closing on every 'error' would tear down a WORKING listener in response
    // to one runtime fault — the guard causing the outage it exists to detect.
    // Pinned on the source because startUdp/startTcp cannot be required.
    for (const [proto, closer] of [['udp', 'sock.close()'], ['tcp', 'server.close()']]) {
      const re = new RegExp(
        `if \\(track\\.failed\\(\\{ protocol: '${proto}'[^)]*\\}\\)\\) \\{[\\s\\S]{0,200}?${closer.replace(/[.()]/g, '\\$&')}`,
      );
      assert.match(code, re, `the ${proto} close must be gated on track.failed()`);
    }
  });

  it('⛔ retries an unbound listener rather than giving up on it for ever', () => {
    assert.match(code, /LISTENER_RETRY_MS/);
    assert.match(code, /clearInterval\(listenerRetryTimer\)/, 'and clears it on shutdown');
  });

  it('⛔ reports an unreadable spool directory as NULL, never as an empty queue', () => {
    const fn = code.slice(code.indexOf('function countReadyFiles()'));
    const body = fn.slice(0, fn.indexOf('\n}'));
    assert.match(body, /return null;/);
    assert.doesNotMatch(body, /return 0;/);
  });
});
