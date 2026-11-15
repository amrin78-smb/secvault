'use strict';

// lib/syslog/listenerState.js
//
// WHAT IS THIS COLLECTOR ACTUALLY HEARING?
//
// ⛔ NOTHING ANSWERED THAT (roadmap row 36). `sock.bind` / `server.listen` in
// `services/collector.js` reported failure only through an 'error' handler
// that logged and returned; `main()` never inspected the outcome and printed
// `collector ready.` regardless. A process that bound NOTHING stayed alive
// looking healthy — and the only liveness signal in the product,
// `max(recorded_at) FROM syslog_ingest_stats`, is written by `doFlush()` ONLY
// when there is a batch. So a deaf collector and a quiet fleet produced
// byte-identical evidence, which is precisely the pair
// `lib/syslog/collectorConfig.js`'s own header names: "'we are listening and
// receiving nothing' and 'we are not listening where they are sending' look
// identical from the inside". That header's guard was built for the CONFIG
// half and had no counterpart for the BIND half.
//
// ⛔ THE VERDICT LIVES HERE BECAUSE services/collector.js CANNOT BE REQUIRED —
// it binds sockets and starts timers at module load. Every guard that stays in
// that file can only ever be asserted against its SOURCE TEXT, and this repo
// has twice watched a source-shape assertion pass over an inverted guard. The
// decision of whether this collector is deaf is not a decision to grep for.

/**
 * Track one listener's bind, and decide what an 'error' means for it.
 *
 * ⛔ A SOCKET EMITS 'error' FOR A FAILED BIND **AND** FOR RUNTIME FAULTS HOURS
 * LATER, AND THE TWO NEED OPPOSITE HANDLING. A bind failure must release the
 * port, or the retry below can never rebind it. A runtime fault on a LIVE
 * listener must do nothing but log — which is exactly what this collector did
 * before the bind check existed. Closing there would take down a working
 * listener in response to one bad packet and make the collector genuinely
 * deaf: the bug this whole guard exists to detect, caused by the guard.
 *
 * ⛔ THE RETURN VALUE IS THE DECISION, so it can be tested. The first version
 * of this was a bare `settleOnce()` and the missing-latch mutation stayed
 * GREEN — a native promise ignores a second resolve, so the test could not see
 * the guard at all while the socket-closing half went unpinned.
 *
 * @returns {{listening: Function, failed: (v) => boolean}} `failed` returns
 *          true when the caller should CLOSE the socket.
 */
function bindTracker(resolve) {
  // ⛔ ONE FLAG, NOT TWO. The first draft carried a separate `bound` and
  // tested `bound || settled` — but `listening()` always settles, so `bound`
  // could never be true while `settled` was false and the extra flag was an
  // EQUIVALENT MUTANT: deleting it left every test green, which is how it was
  // found. A second flag that cannot disagree with the first is not
  // defence in depth, it is a claim of a check that does not exist.
  let settled = false;
  return {
    listening(value) {
      if (!settled) { settled = true; resolve(value); }
    },
    failed(value) {
      // Already settled means either a successful bind (a LIVE listener, which
      // must only be logged) or a failure already reported (already released).
      if (settled) return false;
      settled = true;
      resolve(value);
      return true;                          // release the port for the retry
    },
  };
}

/**
 * Wait for one listener to report, with a bound.
 *
 * ⛔ `ok: null` IS A THIRD STATE AND NEVER READS AS A FAILURE. A bind that
 * reports neither 'listening' nor 'error' within the timeout is UNKNOWN. We
 * must not wait forever — that would hold the flush timer hostage and be worse
 * than the bug being fixed, a collector that never drains — and we must not
 * record it as deaf, because a socket that binds late is still listening.
 */
function awaitBind(ready, protocol, port, timeoutMs) {
  let timer = null;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(
      () => resolve({ protocol, port, ok: null, error: `did not report within ${timeoutMs}ms` }),
      timeoutMs,
    );
    // ⛔ NOT unref'd. It is always cleared when the race settles, so it cannot
    // leak — and an unref'd timer here lets the process exit while this is the
    // only pending work, which during startup is the one moment nothing else
    // is holding the loop open. It also made the timeout branch untestable:
    // the runner reported "Promise resolution is still pending but the event
    // loop has already resolved" rather than the verdict.
  });
  return Promise.race([ready, timeout]).then((r) => {
    if (timer) clearTimeout(timer);
    return r;
  });
}

/**
 * The one sentence describing what bound.
 *
 * ⛔ FOUR STATES, AND `deaf` REQUIRES THAT EVERY LISTENER BE A CONFIRMED
 * FAILURE. One unknown makes the whole verdict `unknown`: reporting "deaf"
 * when we merely could not tell sends an operator to restart a service that
 * may be working perfectly, and reporting "listening" is the
 * failed-read-as-a-fact bug inside the one signal built to prevent it.
 *
 * ⛔ NO CONFIGURED PORT AT ALL IS `deaf`, NOT `listening`. `parsePortList`
 * rejects malformed entries, so a typo in SYSLOG_UDP_PORT can leave both lists
 * empty — and a collector with nothing to bind is not a collector that bound
 * everything it was asked to. An empty set satisfying a "did everything fail?"
 * test vacuously is how a guard reports an all-clear over nothing.
 */
function listenerVerdict(results) {
  const all = Array.isArray(results) ? results : [];
  const bound = all.filter((r) => r && r.ok === true);
  const failed = all.filter((r) => r && r.ok === false);
  const unknown = all.filter((r) => r && r.ok === null);
  let state;
  if (all.length === 0) state = 'deaf';
  else if (bound.length === 0) state = unknown.length > 0 ? 'unknown' : 'deaf';
  else if (failed.length > 0 || unknown.length > 0) state = 'partial';
  else state = 'listening';
  return { state, bound, failed, unknown };
}

const fmtListener = (r) => `${r.protocol}/${r.port}`;
const fmtListenerError = (r) => `${r.protocol}/${r.port}: ${r.error || 'unknown error'}`;

module.exports = { bindTracker, awaitBind, listenerVerdict, fmtListener, fmtListenerError };
