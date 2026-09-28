'use strict';

// tests/mfaPrecheck.test.js
//
// Pins the conditional MFA field: lib/rateLimit.js, lib/localPassword.js, the
// login form's three-state logic, and the properties POST /api/auth/mfa/precheck
// must hold.
//
// ⛔ WHAT THIS GUARDS. The feature reverses a decision the login page previously
// forbade, and it is safe ONLY because of two properties that are easy to break
// by accident and invisible when broken:
//
//   1. The password is verified BEFORE any answer is given. Break it and the
//      endpoint becomes the username-enumeration oracle the old comment feared:
//      type a username, watch the field appear.
//   2. Every failure path shows the field. Break it and a rate limit, an
//      outage or an LDAP account silently HIDES the one input that account
//      needs — and the user gets a generic "sign-in failed" for a field they
//      were never offered.
//
// Neither has a visible symptom in the good case, which is why they are pinned
// here rather than left to the smoke sweep.

const { describe, it, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { stripComments } = require('./stripComments');
const { checkRateLimit, _resetForTests } = require('../lib/rateLimit');
const { verifyLocalPassword, DUMMY_BCRYPT_HASH } = require('../lib/localPassword');

const ROOT = path.join(__dirname, '..');
const ROUTE = path.join(ROOT, 'app', 'api', 'auth', 'mfa', 'precheck', 'route.js');
const LOGIN = path.join(ROOT, 'app', '(auth)', 'login', 'page.js');
const AUTH = path.join(ROOT, 'app', 'api', 'auth', '[...nextauth]', 'route.js');

// ── the shared password verifier ───────────────────────────────────────────

describe('⛔ ONE password check, shared by authorize() and the precheck', () => {
  test('authorize() does not roll its own bcrypt compare', () => {
    // ⛔ TWO COPIES WOULD LET THEM DISAGREE. The precheck would then tell the
    // form to hide the code field for a credential authorize() rejects, or
    // reveal it for one it accepts — a login that behaves differently depending
    // on which half answered.
    const src = stripComments(fs.readFileSync(AUTH, 'utf8'));
    assert.ok(!/bcrypt\.compare/.test(src),
      'the auth route must delegate to lib/localPassword.js');
    assert.ok(!/DUMMY_BCRYPT_HASH\s*=/.test(src),
      'the dummy hash has one definition, in lib/localPassword.js');
    assert.match(src, /verifyLocalPassword/);
  });

  test('the precheck uses the same verifier', () => {
    const src = stripComments(fs.readFileSync(ROUTE, 'utf8'));
    assert.match(src, /verifyLocalPassword/);
    assert.ok(!/bcrypt/.test(src), 'no second password implementation');
  });

  it('the dummy hash is a real bcrypt hash that cannot validate', async () => {
    assert.match(DUMMY_BCRYPT_HASH, /^\$2[aby]\$\d{2}\$/);
    const pool = { query: async () => ({ rows: [] }) };
    for (const guess of ['', 'password', 'admin', DUMMY_BCRYPT_HASH]) {
      const r = await verifyLocalPassword(pool, 'nobody', guess);
      assert.equal(r.valid, false);
    }
  });

  it('an unknown user still pays the bcrypt cost', async () => {
    // The measured defect: a real username took ~4x longer than an unknown one,
    // making timing alone a reliable "does this account exist" oracle. Asserted
    // as a floor on elapsed time rather than a comparison, because a ratio
    // between two bcrypt calls is too noisy to pin on a loaded CI box.
    const pool = { query: async () => ({ rows: [] }) };
    const t0 = Date.now();
    await verifyLocalPassword(pool, 'definitely-not-a-user', 'hunter2');
    assert.ok(Date.now() - t0 >= 10,
      'an unknown user returned too fast to have run bcrypt');
  });

  it('⛔ an empty username or password still burns a compare', async () => {
    const pool = { query: async () => { throw new Error('must not be queried'); } };
    for (const [u, p] of [['', 'x'], ['x', ''], ['', ''], [null, null]]) {
      const t0 = Date.now();
      const r = await verifyLocalPassword(pool, u, p);
      assert.equal(r.valid, false);
      assert.ok(Date.now() - t0 >= 10, 'an empty submission must not be faster');
    }
  });

  it('⛔ a database failure THROWS rather than reporting a wrong password', async () => {
    const pool = { query: async () => { throw new Error('db down'); } };
    await assert.rejects(() => verifyLocalPassword(pool, 'alice', 'pw'));
    // Returning {valid:false} here would let an outage quietly decide that an
    // MFA-protected account has no MFA.
  });

  it('a row with no password_hash cannot validate', async () => {
    const pool = { query: async () => ({ rows: [{ id: 'u1', username: 'alice', password_hash: null }] }) };
    const r = await verifyLocalPassword(pool, 'alice', 'anything');
    assert.equal(r.valid, false);
  });
});

// ── the rate limiter ───────────────────────────────────────────────────────

describe('the rate limiter', () => {
  const OPTS = { maxAttempts: 3, windowMs: 1000 };

  it('allows up to the limit and then reports limited', () => {
    _resetForTests();
    for (let i = 0; i < 3; i++) {
      assert.equal(checkRateLimit('k', OPTS, 1000).limited, false, `attempt ${i + 1}`);
    }
    const r = checkRateLimit('k', OPTS, 1000);
    assert.equal(r.limited, true);
    assert.ok(r.retryAfterSec >= 1);
  });

  it('the window resets', () => {
    _resetForTests();
    for (let i = 0; i < 5; i++) checkRateLimit('k', OPTS, 1000);
    assert.equal(checkRateLimit('k', OPTS, 1000).limited, true);
    assert.equal(checkRateLimit('k', OPTS, 2001).limited, false, 'a new window starts fresh');
  });

  it('keys are independent, so one account cannot exhaust another', () => {
    _resetForTests();
    for (let i = 0; i < 5; i++) checkRateLimit('a', OPTS, 1000);
    assert.equal(checkRateLimit('a', OPTS, 1000).limited, true);
    assert.equal(checkRateLimit('b', OPTS, 1000).limited, false);
  });

  it('⛔ FAILS OPEN on a nonsense configuration', () => {
    // A NaN threshold compared with `>` is always false, which would disable
    // the limiter while looking configured. Refusing explicitly is the same
    // outcome, stated.
    _resetForTests();
    for (const bad of [null, undefined, {}, { maxAttempts: NaN, windowMs: 1000 },
      { maxAttempts: 3, windowMs: 0 }, { maxAttempts: 0, windowMs: 1000 }]) {
      assert.equal(checkRateLimit('k', bad, 1000).limited, false);
    }
    for (const badKey of ['', null, undefined, 42]) {
      assert.equal(checkRateLimit(badKey, OPTS, 1000).limited, false);
    }
  });
});

// ── the route's security properties ────────────────────────────────────────

describe('⛔ the precheck answers only AFTER the password is verified', () => {
  const src = stripComments(fs.readFileSync(ROUTE, 'utf8'));

  test('the MFA lookup happens after the password check, not before', () => {
    // ⛔ ORDER IS THE WHOLE SECURITY PROPERTY. Looking up MFA first and
    // answering on the username alone is precisely the oracle the old login
    // comment feared — and it would still pass a test that only checked both
    // calls exist.
    // ⛔ MATCH THE CALL, NOT THE NAME. The first draft used
    // `src.indexOf('verifyLocalPassword')`, which finds the IMPORT at the top
    // of the file — always before everything — so the comparison was between an
    // import and a call and could never fail. Proven: swapping the two blocks
    // left all 24 tests green. Imports are stripped and the awaited call form
    // is matched instead.
    const body = src.slice(src.indexOf('export async function POST'));
    assert.ok(body.length > 0, 'the handler must be findable');
    const verifyAt = body.indexOf('await verifyLocalPassword(');
    const mfaAt = body.indexOf('await mfa.isEnabledFor(');
    assert.ok(verifyAt > -1, 'the awaited password check must be in the handler');
    assert.ok(mfaAt > -1, 'the awaited MFA lookup must be in the handler');
    assert.ok(verifyAt < mfaAt,
      'the password must be verified before the account is described');
    // And the refusal on a bad password must sit BETWEEN them, so the lookup
    // is unreachable without valid credentials — ordering alone is not enough
    // if nothing returns in between.
    const guardAt = body.indexOf('if (!user || !valid) return cannotSay();');
    assert.ok(guardAt > verifyAt && guardAt < mfaAt,
      'the bad-credential refusal must stand between the check and the lookup');
  });

  test('there is exactly one shape for every refusal', () => {
    // A `reason` on any refusal would rebuild the oracle.
    assert.match(src, /function cannotSay\(\)/);
    assert.match(src, /ok:\s*false/);
    const refusals = src.match(/return cannotSay\(\);/g) || [];
    assert.ok(refusals.length >= 5,
      `every failure path should route through cannotSay(); found ${refusals.length}`);
    // The only other JSON response is the positive one.
    const jsons = src.match(/NextResponse\.json\(/g) || [];
    assert.equal(jsons.length, 2,
      'exactly two response shapes: the refusal helper and the positive answer');
  });

  test('⛔ a rate limit returns the refusal shape, never a 429', () => {
    // A 429 distinguishes "this account is being hammered" from "wrong
    // password", which is an oracle about account activity — and it would tell
    // an attacker their guessing was noticed.
    assert.ok(!/429/.test(src), 'no distinguishable status for a limited caller');
    assert.match(src, /rl\.limited/);
  });

  test('the limiter is keyed on the username, lowercased', () => {
    assert.match(src, /mfa-precheck:\$\{username\.toLowerCase\(\)\}/,
      'Admin and admin must share one budget');
  });

  test('⛔ the MFA lookup failing shows the field rather than hiding it', () => {
    // authorize() fails closed by REFUSING the login. The equivalent here is to
    // reveal the field: answering `mfaRequired: false` on an error would hide
    // the one input that account needs.
    const mfaAt = src.indexOf('isEnabledFor');
    const after = src.slice(mfaAt);
    const catchAt = after.indexOf('catch');
    const refusalAt = after.indexOf('return cannotSay();');
    assert.ok(catchAt > -1 && refusalAt > catchAt,
      'the MFA lookup must be wrapped and fall through to the refusal');
  });

  test('it grants nothing — no session, token or cookie', () => {
    for (const forbidden of ['setCookie', 'cookies(', 'signIn', 'encode(', 'jwt']) {
      assert.ok(!src.includes(forbidden),
        `${forbidden} has no business in a route that only picks a form field`);
    }
  });

  test('the positive answer carries a boolean and nothing else', () => {
    assert.match(src, /ok:\s*true,\s*mfaRequired:\s*enabled === true/,
      'no role, no username, no enrolment state — only what the form needs');
  });
});

// ── the login form ─────────────────────────────────────────────────────────

describe('⛔ every failure of the precheck SHOWS the field', () => {
  const src = stripComments(fs.readFileSync(LOGIN, 'utf8'));

  test('the field is hidden only on an explicit false', () => {
    // ⛔ THREE STATES. `null` (not asked / could not tell) and `true` both
    // show it. A truthiness test here — `hidden={!codeNeeded}` — would hide the
    // field whenever the precheck failed, which is the dangerous inversion.
    assert.match(src, /hidden=\{codeNeeded === false\}/,
      'must compare against false explicitly, never coerce');
    assert.ok(!/hidden=\{!codeNeeded\}/.test(src));
  });

  test('askWhetherCodeNeeded returns null on every failure', () => {
    const fn = src.slice(src.indexOf('async function askWhetherCodeNeeded'));
    const body = fn.slice(0, fn.indexOf('\n  }'));
    assert.match(body, /if \(!res\.ok\) return null;/, 'a non-200 must not hide the field');
    assert.match(body, /data\.ok !== true/, 'an ok:false must not hide the field');
    assert.match(body, /catch \{\s*return null;/, 'a network failure must not hide the field');
  });

  test('⛔ it is asked once, and only while the field is hidden', () => {
    assert.match(src, /if \(codeNeeded === null\)/,
      're-asking would spend the rate-limit budget on submissions that already carry a code');
  });

  test('revealing the field stops that submission rather than failing it', () => {
    const at = src.indexOf('if (needed === true)');
    assert.ok(at > -1);
    const block = src.slice(at, at + 400);
    assert.match(block, /setCodeNeeded\(true\)/);
    assert.match(block, /return;/, 'must not fall through to signIn with an empty code');
  });

  test('a null answer still proceeds to sign in', () => {
    // "Could not tell" must not block the login — it shows the field AND
    // attempts the sign-in, so an account without MFA is unaffected.
    assert.match(src, /setCodeNeeded\(needed\);/);
  });

  test('the one generic failure message is unchanged', () => {
    // ⛔ The precheck confirms a password to whoever HAS it; the failure message
    // must still not confirm anything to whoever does not.
    assert.match(src, /Check your username, password and authenticator code\./);
  });
});
