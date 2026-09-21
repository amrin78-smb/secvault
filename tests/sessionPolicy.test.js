'use strict';
// tests/sessionPolicy.test.js
//
// ⛔ THIS FILE DECIDES HOW LONG A SESSION TO A FIREWALL-MANAGEMENT CONSOLE
// SURVIVES, and every way it can be wrong is quiet:
//
//   - too permissive and the control is not there (the state this product
//     shipped in: no maxAge at all, so NextAuth's 30-DAY default applied);
//   - too aggressive and it is an ABSOLUTE timeout wearing an idle timeout's
//     name, signing active people out mid-edit, which ends with an operator
//     turning it off;
//   - a typo in the environment silently disabling it, which looks exactly like
//     it working.
//
// None of those throws. All of them render a perfectly normal login page.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  idleMinutes, sessionOptions, clientPolicy, validateIdleMinutes,
  DEFAULT_IDLE_MINUTES, DISABLED_MAX_AGE_SECONDS, MIN_IDLE_MINUTES, MAX_IDLE_MINUTES,
  WARN_SECONDS,
} = require('../lib/sessionPolicy');

const env = (v) => (v === undefined ? {} : { SESSION_IDLE_MINUTES: v });

describe('⛔ only an explicit 0 disables the timeout', () => {
  it('a missing or blank value is the default, not "off"', () => {
    assert.equal(idleMinutes({}), DEFAULT_IDLE_MINUTES);
    assert.equal(idleMinutes(env('')), DEFAULT_IDLE_MINUTES);
    assert.equal(idleMinutes(env('   ')), DEFAULT_IDLE_MINUTES);
  });

  it('⛔ a NEGATIVE is a typo and falls back to the default', () => {
    // An earlier draft returned 0 here, so `-30` in .env.local would have
    // silently switched the control off while looking like a configured policy.
    assert.equal(idleMinutes(env('-30')), DEFAULT_IDLE_MINUTES);
    assert.equal(idleMinutes(env('-1')), DEFAULT_IDLE_MINUTES);
    assert.equal(clientPolicy(env('-30')).enabled, true);
  });

  it('⛔ unparseable text falls back to the default, never to off', () => {
    for (const v of ['abc', 'thirty', '30m', 'null', 'NaN']) {
      assert.equal(idleMinutes(env(v)), DEFAULT_IDLE_MINUTES, `${v} must not disable the timeout`);
    }
  });

  it('0 IS honoured, and restores exactly the behaviour before this existed', () => {
    assert.equal(idleMinutes(env('0')), 0);
    const o = sessionOptions(env('0'));
    assert.equal(o.maxAge, DISABLED_MAX_AGE_SECONDS, "NextAuth's own 30-day default");
    assert.equal(clientPolicy(env('0')).enabled, false);
    assert.equal(clientPolicy(env('0')).warnSeconds, 0);
  });
});

describe('⛔ the keep-alive is what makes this IDLE rather than ABSOLUTE', () => {
  it('⛔ `updateAge` is NOT passed, because it does nothing under the jwt strategy', () => {
    // Verified against the installed next-auth 4.24.15: `updateAge` is read in
    // exactly one place, inside the DATABASE-session branch of
    // core/routes/session.js. The jwt branch re-encodes unconditionally. An
    // earlier version of this file clamped it carefully and documented it as
    // load-bearing; it was inert configuration, which is the "guard that cannot
    // fire" pattern with a comment vouching for it.
    for (const v of [undefined, '2', '30', '1440']) {
      assert.equal(sessionOptions(env(v)).updateAge, undefined);
    }
  });

  it('every enabled window advertises a keep-alive well inside it', () => {
    // If the refresh cadence ever reached the window, an active user's token
    // would die before the next refresh arrived — the absolute-timeout failure
    // arriving through the other side.
    for (const v of ['2', '5', '15', '30', '120', '1440']) {
      const c = clientPolicy(env(v));
      const windowSeconds = c.idleMinutes * 60;
      assert.ok(c.keepAliveSeconds > 0, `${v} must advertise a keep-alive`);
      assert.ok(c.keepAliveSeconds <= Math.floor(windowSeconds / 4),
        `keepAlive ${c.keepAliveSeconds} must be well inside the ${windowSeconds}s window`);
    }
  });

  it('a DISABLED timeout advertises no keep-alive', () => {
    // Nothing to keep alive, and a background fetch loop on a console that
    // never times out is pure noise.
    assert.equal(clientPolicy(env('0')).keepAliveSeconds, 0);
  });

  it('the shortest allowed window is still refreshable', () => {
    const o = sessionOptions(env(String(MIN_IDLE_MINUTES)));
    assert.equal(o.maxAge, MIN_IDLE_MINUTES * 60);
    assert.ok(clientPolicy(env(String(MIN_IDLE_MINUTES))).keepAliveSeconds < o.maxAge);
  });

  it('keeps the jwt strategy in every case — this must never become a DB session', () => {
    for (const v of [undefined, '0', '30', 'abc']) {
      assert.equal(sessionOptions(env(v)).strategy, 'jwt');
    }
  });
});

describe('⛔ the window is clamped, and the client is told the same number', () => {
  it('clamps below the minimum and above the maximum', () => {
    assert.equal(idleMinutes(env('1')), MIN_IDLE_MINUTES);
    assert.equal(idleMinutes(env('99999')), MAX_IDLE_MINUTES);
  });

  it('the client policy matches what the server will enforce', () => {
    for (const v of ['5', '30', '1440', '99999']) {
      const mins = idleMinutes(env(v));
      const c = clientPolicy(env(v));
      assert.equal(c.idleMinutes, mins, 'one source of truth, or the modal lies');
      assert.equal(c.idleMinutes * 60, sessionOptions(env(v)).maxAge);
    }
  });

  it('⛔ the shortest window is at least twice the warning, so it always fits', () => {
    // This is the INVARIANT that makes clientPolicy's Math.min unreachable, and
    // testing it here is what stops that clamp being a guard nobody can fire.
    // Drop MIN_IDLE_MINUTES below 2 and this fails — which is the moment the
    // clamp starts mattering and the modal would otherwise begin its countdown
    // before the session had started.
    assert.ok(MIN_IDLE_MINUTES * 60 >= 2 * WARN_SECONDS,
      `a ${MIN_IDLE_MINUTES}-minute minimum cannot carry a ${WARN_SECONDS}s warning`);
    const c = clientPolicy(env(String(MIN_IDLE_MINUTES)));
    assert.equal(c.warnSeconds, WARN_SECONDS);
    assert.ok(c.warnSeconds < MIN_IDLE_MINUTES * 60);
  });
});

describe('⛔ what an operator may type is validated before it is written', () => {
  it('accepts a whole number in range, and 0', () => {
    assert.deepEqual(validateIdleMinutes('30'), { ok: true, value: 30, disabled: false });
    assert.deepEqual(validateIdleMinutes(15), { ok: true, value: 15, disabled: false });
    assert.deepEqual(validateIdleMinutes('0'), { ok: true, value: 0, disabled: true });
  });

  it('refuses rather than silently clamping — the operator asked for something', () => {
    for (const bad of ['', '  ', 'abc', '1.5', '-5', '1', '99999']) {
      const v = validateIdleMinutes(bad);
      assert.equal(v.ok, false, `${JSON.stringify(bad)} should be refused`);
      assert.ok(typeof v.error === 'string' && v.error.length > 0, 'and say why');
    }
  });

  it('the refusal for "too long" points at 0 rather than leaving a dead end', () => {
    assert.match(validateIdleMinutes('99999').error, /Use 0/);
  });
});

describe('⛔ the server, not the browser, is the boundary', () => {
  const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

  it('NextAuth takes its session block from sessionPolicy, not a literal', () => {
    // A hardcoded `{ strategy: 'jwt' }` here is how this shipped with a 30-day
    // session; a literal maxAge would drift from what the modal promises.
    const src = read('app/api/auth/[...nextauth]/route.js');
    assert.match(src, /session:\s*sessionOptions\(process\.env\)/);
    assert.doesNotMatch(src, /session:\s*\{\s*strategy:\s*'jwt',?\s*\}/);
  });

  it('the client component carries NO window of its own', () => {
    const src = read('components/layout/IdleTimeout.js');
    assert.match(src, /session-policy/, 'it reads the policy the server enforces');
    // ⛔ NetVault guesses 30 minutes when the fetch fails. Here a failed read
    // arms nothing, because the server is still expiring the token and a
    // guessed-short window would sign people out of a valid session.
    assert.match(src, /FAIL_OPEN\s*=\s*\{\s*enabled:\s*false/);
  });

  it('the login page wires the shared guard rather than a local copy', () => {
    const src = read('app/(auth)/login/page.js');
    assert.match(src, /from '\.\.\/\.\.\/\.\.\/lib\/returnPath'/);
    assert.match(src, /router\.push\(returnTo\.current\)/);
    // ⛔ And NOT a local reimplementation. The first version defined
    // safeReturnPath inside this client component, where no test could call it,
    // and it shipped bypassable.
    assert.doesNotMatch(src, /function safeReturnPath/);
  });
});
