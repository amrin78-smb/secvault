'use strict';
// Pins TOTP multi-factor authentication (v2.111.0): lib/totp.js + lib/mfa.js.
//
// TWO DIFFERENT KINDS OF RISK, and they need different kinds of test.
//
// lib/totp.js is arithmetic, so it is verified against RFC 6238's OWN PUBLISHED
// TEST VECTORS rather than against itself. A hand-rolled TOTP that is subtly
// wrong does not crash — it produces six plausible digits that no authenticator
// app agrees with, and the failure appears as "MFA is broken for everyone" on
// the day it is switched on. Matching the RFC's vectors is the only way to know
// the implementation is right before a phone ever sees it.
//
// lib/mfa.js is where the SECURITY properties live, and every one of them is a
// property that fails silently:
//   - a code must be single-use, or it can be replayed inside its 90s window;
//   - a recovery code must be consumed, or it is a permanent password;
//   - a half-finished enrolment must NOT demand a code at login, or it locks
//     the user out of their own account;
//   - the secret must never leave the module in plaintext.
//
// ⛔ THE DOMINANT RISK IN AN MFA FEATURE IS LOCKOUT, NOT BYPASS. Several cases
// below exist only to prove that a user cannot be locked out by a half-finished
// enrolment, a placeholder row, or an admin ticking "required".

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');

// credStore needs a key before lib/mfa.js is required (it destructures at load).
process.env.CREDENTIAL_KEY = 'a'.repeat(64);

const totp = require('../lib/totp');
const mfa = require('../lib/mfa');

// ── a stub pool that behaves like one row of user_mfa ───────────────────────
function makePool() {
  const state = { row: null, queries: [] };
  return {
    state,
    async query(sql, params) {
      state.queries.push({ sql, params });
      const s = String(sql);

      if (/^\s*SELECT/i.test(s)) {
        return { rows: state.row ? [{ ...state.row }] : [] };
      }
      if (/^\s*INSERT INTO user_mfa/i.test(s)) {
        // ⛔ resetFor's re-assertion: a single-parameter INSERT with the values
        // inline, re-creating a requirement-only placeholder after the DELETE.
        // Modelled explicitly because the row it produces — required true,
        // enabled false, EMPTY secret — is precisely the state the reset is
        // supposed to leave behind, and the state confirmEnrolment must refuse
        // rather than 500 on.
        if (params.length === 1 && /required\s*\)\s*VALUES|,\s*true\s*\)/i.test(s)) {
          state.row = {
            user_id: params[0], secret_encrypted: '', secret_iv: '',
            enabled: false, confirmed_at: null, last_counter: null,
            required: true, recovery_codes: [],
          };
          return { rows: [], rowCount: 1 };
        }
        // startEnrolment: (userId, encrypted, iv) | setRequired: (userId, required)
        if (params.length === 3) {
          state.row = {
            user_id: params[0], secret_encrypted: params[1], secret_iv: params[2],
            enabled: false, confirmed_at: null, last_counter: null,
            required: state.row ? state.row.required : false, recovery_codes: [],
          };
        } else {
          state.row = state.row
            ? { ...state.row, required: params[1] }
            : {
                user_id: params[0], secret_encrypted: '', secret_iv: '',
                enabled: false, confirmed_at: null, last_counter: null,
                required: params[1], recovery_codes: [],
              };
        }
        return { rows: [], rowCount: 1 };
      }
      // ⛔ THE STUB MUST HONOUR THE WHERE CLAUSES, or the single-use tests below
      // prove nothing. Both consuming writes are now CONDITIONAL — that is what
      // makes them atomic against a concurrent duplicate — and a stub that
      // returns rowCount 1 unconditionally would report every race as won by
      // both parties, which is exactly the bug being pinned.
      if (/UPDATE user_mfa/i.test(s)) {
        if (/enabled = true/.test(s)) {
          state.row = {
            ...state.row, enabled: true, confirmed_at: new Date(),
            last_counter: params[1], recovery_codes: JSON.parse(params[2]),
          };
          return { rows: [], rowCount: 1 };
        }

        if (/last_counter = \$2/.test(s)) {
          // WHERE last_counter IS NULL OR last_counter < $2
          const current = state.row ? state.row.last_counter : null;
          const wins = current === null || current === undefined
            || Number(params[1]) > Number(current);
          if (!wins) return { rows: [], rowCount: 0 };
          state.row = { ...state.row, last_counter: params[1] };
          return { rows: [], rowCount: 1 };
        }

        if (/recovery_codes = COALESCE/i.test(s)) {
          // WHERE recovery_codes @> jsonb_build_array($2::text)
          const hashes = (state.row && Array.isArray(state.row.recovery_codes))
            ? state.row.recovery_codes : [];
          if (!hashes.includes(params[1])) return { rows: [], rowCount: 0 };
          state.row = { ...state.row, recovery_codes: hashes.filter((h) => h !== params[1]) };
          return { rows: [], rowCount: 1 };
        }

        if (/required = true/i.test(s)) {
          state.row = { ...state.row, required: true };
          return { rows: [], rowCount: 1 };
        }
        return { rows: [], rowCount: 1 };
      }
      if (/DELETE FROM user_mfa/i.test(s)) {
        const had = state.row !== null;
        state.row = null;
        return { rows: [], rowCount: had ? 1 : 0 };
      }
      return { rows: [], rowCount: 0 };
    },
  };
}

const USER = '11111111-2222-3333-4444-555555555555';

describe('lib/totp — RFC 6238 published test vectors', () => {
  // Appendix B seed for HMAC-SHA1: the ASCII string '12345678901234567890'.
  const SEED = totp.base32Encode(Buffer.from('12345678901234567890', 'ascii'));

  const VECTORS = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    // ⛔ Exercises the HIGH 32 bits of the 8-byte counter. A counter written as a
    // single 32-bit word passes every other vector here and fails only this one.
    [20000000000, '65353130'],
  ];

  for (const [time, expected] of VECTORS) {
    it(`t=${time} -> ${expected}`, () => {
      assert.equal(totp.generateCode(SEED, time, { digits: 8 }), expected);
    });
  }

  it('base32 round-trips', () => {
    assert.equal(totp.base32Decode(SEED).toString('ascii'), '12345678901234567890');
  });

  it('tolerates what a human retypes — lower case, spaces, padding', () => {
    const spaced = SEED.toLowerCase().replace(/(.{4})/g, '$1 ');
    assert.deepEqual(totp.base32Decode(spaced), totp.base32Decode(SEED));
    assert.deepEqual(totp.base32Decode(`${SEED}======`), totp.base32Decode(SEED));
  });

  it('⛔ THROWS on an invalid character rather than skipping it', () => {
    // Silently dropping a character yields a DIFFERENT secret and an endless
    // run of "wrong code" that nobody can diagnose.
    assert.throws(() => totp.base32Decode('ABCD1EFG'), /invalid character/);
    assert.throws(() => totp.base32Decode(''), /empty/);
  });

  it('generates a 160-bit secret from a CSPRNG, never Math.random', () => {
    const a = totp.generateSecret();
    const b = totp.generateSecret();
    assert.equal(totp.base32Decode(a).length, 20);
    assert.notEqual(a, b);
  });

  it('accepts ±1 step and refuses ±2', () => {
    const t = 1700000000;
    const opts = (drift) => ({ timeSeconds: t + drift * 30 });
    const code = totp.generateCode(SEED, t);
    assert.equal(totp.verifyCode(SEED, code, opts(0)).valid, true);
    assert.equal(totp.verifyCode(SEED, code, opts(1)).valid, true);
    assert.equal(totp.verifyCode(SEED, code, opts(-1)).valid, true);
    // ⛔ Each extra step widens the replay window by 30 seconds.
    assert.equal(totp.verifyCode(SEED, code, opts(2)).valid, false);
    assert.equal(totp.verifyCode(SEED, code, opts(-2)).valid, false);
  });

  it('returns the matched counter, so the caller can enforce single use', () => {
    const t = 1700000000;
    const r = totp.verifyCode(SEED, totp.generateCode(SEED, t), { timeSeconds: t });
    assert.equal(r.valid, true);
    assert.equal(r.counter, Math.floor(t / 30));
  });

  it('rejects malformed input without throwing', () => {
    for (const bad of ['', '12345', '1234567', 'abcdef', null, undefined, {}, []]) {
      assert.doesNotThrow(() => totp.verifyCode(SEED, bad));
      assert.equal(totp.verifyCode(SEED, bad).valid, false);
    }
  });

  it('the otpauth URI carries the issuer twice, for old and new apps', () => {
    const uri = totp.buildOtpauthUri(SEED, 'alice');
    assert.match(uri, /^otpauth:\/\/totp\/SecVault%3Aalice\?/);
    assert.match(uri, /issuer=SecVault/);
    assert.match(uri, /algorithm=SHA1/);
  });
});

describe('lib/mfa — enrolment', () => {
  it('stores the secret ENCRYPTED, never in plaintext', async () => {
    const pool = makePool();
    const { secret } = await mfa.startEnrolment(pool, USER, 'alice');
    assert.ok(secret.length > 0);
    // ⛔ The stored value must not contain the secret in any recoverable form.
    assert.notEqual(pool.state.row.secret_encrypted, secret);
    assert.equal(pool.state.row.secret_encrypted.includes(secret), false);
    assert.match(pool.state.row.secret_encrypted, /^[0-9a-f]+:[0-9a-f]+$/);
  });

  it('⛔ a started-but-unconfirmed enrolment does NOT demand a code at login', async () => {
    // The lockout case. If issuing a secret enabled MFA, anyone who closed the
    // tab before scanning would be locked out of their own account.
    const pool = makePool();
    await mfa.startEnrolment(pool, USER, 'alice');
    assert.equal(await mfa.isEnabledFor(pool, USER), false);
    assert.equal((await mfa.getStatus(pool, USER)).enabled, false);
    assert.equal((await mfa.getStatus(pool, USER)).enrolled, true);
  });

  it('confirming requires a real code and then returns recovery codes once', async () => {
    const pool = makePool();
    const { secret } = await mfa.startEnrolment(pool, USER, 'alice');

    const bad = await mfa.confirmEnrolment(pool, USER, '000000');
    assert.equal(bad.ok, false);
    assert.equal(await mfa.isEnabledFor(pool, USER), false);

    const good = await mfa.confirmEnrolment(pool, USER, totp.generateCode(secret));
    assert.equal(good.ok, true);
    assert.equal(good.recoveryCodes.length, mfa.RECOVERY_CODE_COUNT);
    assert.equal(await mfa.isEnabledFor(pool, USER), true);
  });

  it('⛔ recovery codes are stored HASHED, never recoverable', async () => {
    const pool = makePool();
    const { secret } = await mfa.startEnrolment(pool, USER, 'alice');
    const { recoveryCodes } = await mfa.confirmEnrolment(pool, USER, totp.generateCode(secret));
    const stored = pool.state.row.recovery_codes;
    assert.equal(stored.length, mfa.RECOVERY_CODE_COUNT);
    for (const hash of stored) assert.match(hash, /^\$2[aby]\$/);
    for (const code of recoveryCodes) {
      assert.equal(stored.includes(code), false);
      assert.equal(stored.join('|').includes(code), false);
    }
  });

  it('recovery codes avoid characters a human confuses when retyping', () => {
    // 0/O and 1/I/L are the pairs that turn a valid code into a failed login,
    // and these are read off a printout by someone who just lost their phone.
    for (const code of mfa.generateRecoveryCodes(25)) {
      assert.doesNotMatch(code, /[01OIL]/);
    }
  });

  it('re-enrolling replaces the pending secret rather than keeping both', async () => {
    const pool = makePool();
    const first = await mfa.startEnrolment(pool, USER, 'alice');
    const second = await mfa.startEnrolment(pool, USER, 'alice');
    assert.notEqual(first.secret, second.secret);
    const ok = await mfa.confirmEnrolment(pool, USER, totp.generateCode(second.secret));
    assert.equal(ok.ok, true);
  });
});

describe('lib/mfa — verification', () => {
  async function enrolled() {
    const pool = makePool();
    const { secret } = await mfa.startEnrolment(pool, USER, 'alice');
    const { recoveryCodes } = await mfa.confirmEnrolment(pool, USER, totp.generateCode(secret));
    return { pool, secret, recoveryCodes };
  }

  it('accepts a valid code', async () => {
    const { pool, secret } = await enrolled();
    // A step later than the one confirmEnrolment consumed.
    const later = Math.floor(Date.now() / 1000) + 30;
    const r = await mfa.verifyForLogin(pool, USER, totp.generateCode(secret, later));
    assert.equal(r.ok, true);
    assert.equal(r.method, 'totp');
  });

  it('⛔ REFUSES THE SAME CODE TWICE — a code is valid for up to 90 seconds', async () => {
    // Without this, anyone who observes a code (shoulder, or anything between
    // the browser and a plain-HTTP server) can replay it inside that window.
    const { pool, secret } = await enrolled();
    const later = Math.floor(Date.now() / 1000) + 30;
    const code = totp.generateCode(secret, later);

    assert.equal((await mfa.verifyForLogin(pool, USER, code)).ok, true);
    const second = await mfa.verifyForLogin(pool, USER, code);
    assert.equal(second.ok, false);
    assert.equal(second.reason, 'code_reused');
  });

  it('⛔ refuses an EARLIER step too, not just an exact repeat', async () => {
    // last_counter is compared with <=. Rejecting only the exact counter would
    // still allow replaying the previous step's code, which is also still live.
    const { pool, secret } = await enrolled();
    const now = Math.floor(Date.now() / 1000);
    await mfa.verifyForLogin(pool, USER, totp.generateCode(secret, now + 30));
    const older = await mfa.verifyForLogin(pool, USER, totp.generateCode(secret, now));
    assert.equal(older.ok, false);
  });

  it('accepts a recovery code and CONSUMES it', async () => {
    const { pool, recoveryCodes } = await enrolled();
    const first = await mfa.verifyForLogin(pool, USER, recoveryCodes[0]);
    assert.equal(first.ok, true);
    assert.equal(first.method, 'recovery');
    assert.equal(first.recoveryRemaining, mfa.RECOVERY_CODE_COUNT - 1);

    // ⛔ A recovery code that still worked the second time would be a password.
    const again = await mfa.verifyForLogin(pool, USER, recoveryCodes[0]);
    assert.equal(again.ok, false);
  });

  it('accepts a recovery code however the user formats it', async () => {
    const { pool, recoveryCodes } = await enrolled();
    const messy = recoveryCodes[1].toLowerCase().replace(/-/g, ' ');
    assert.equal((await mfa.verifyForLogin(pool, USER, messy)).ok, true);
  });

  it('a wrong code is refused and consumes nothing', async () => {
    const { pool } = await enrolled();
    const r = await mfa.verifyForLogin(pool, USER, '000000');
    assert.equal(r.ok, false);
    assert.equal(pool.state.row.recovery_codes.length, mfa.RECOVERY_CODE_COUNT);
  });

  it('⛔ a short wrong code never runs the bcrypt loop', async () => {
    // Ten bcrypt compares per failed 6-digit attempt would make the login form
    // a cheap CPU-exhaustion target.
    const { pool } = await enrolled();
    const started = Date.now();
    for (let i = 0; i < 20; i += 1) await mfa.verifyForLogin(pool, USER, '123456');
    assert.ok(Date.now() - started < 2000, 'short codes appear to be hitting bcrypt');
  });

  it('refuses when MFA is not enabled', async () => {
    const pool = makePool();
    const r = await mfa.verifyForLogin(pool, USER, '123456');
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'not_enabled');
  });
});

describe('lib/mfa — administration and lockout recovery', () => {
  it('a reset DELETES the row, leaving no stale secret', async () => {
    const pool = makePool();
    const { secret } = await mfa.startEnrolment(pool, USER, 'alice');
    await mfa.confirmEnrolment(pool, USER, totp.generateCode(secret));
    assert.equal(await mfa.isEnabledFor(pool, USER), true);

    const r = await mfa.resetFor(pool, USER);
    assert.equal(r.reset, true);
    assert.equal(pool.state.row, null);
    assert.equal(await mfa.isEnabledFor(pool, USER), false);
  });

  it('⛔ marking a user "required" never blocks their login', async () => {
    // Enforcement is a forced ENROLMENT. Refusing to authenticate someone who
    // has not enrolled yet would lock them out the moment an admin ticks a box.
    const pool = makePool();
    await mfa.setRequired(pool, USER, true);
    assert.equal(await mfa.isEnabledFor(pool, USER), false);

    const status = await mfa.getStatus(pool, USER);
    assert.equal(status.required, true);
    // ⛔ And the placeholder row must not read as an enrolment, or the UI stops
    // prompting exactly the user an admin just insisted must enrol.
    assert.equal(status.enrolled, false);
    assert.equal(status.enabled, false);
  });

  it('setting required preserves an existing enrolment', async () => {
    const pool = makePool();
    const { secret } = await mfa.startEnrolment(pool, USER, 'alice');
    await mfa.confirmEnrolment(pool, USER, totp.generateCode(secret));
    await mfa.setRequired(pool, USER, true);
    assert.equal(await mfa.isEnabledFor(pool, USER), true);
    assert.equal((await mfa.getStatus(pool, USER)).required, true);
  });

  it('⛔ status never returns the secret or the recovery hashes', async () => {
    const pool = makePool();
    const { secret } = await mfa.startEnrolment(pool, USER, 'alice');
    await mfa.confirmEnrolment(pool, USER, totp.generateCode(secret));
    const status = await mfa.getStatus(pool, USER);
    const serialised = JSON.stringify(status);
    assert.equal(serialised.includes(secret), false);
    assert.equal(/\$2[aby]\$/.test(serialised), false);
    assert.deepEqual(
      Object.keys(status).sort(),
      ['confirmedAt', 'enabled', 'enrolled', 'recoveryRemaining', 'required']
    );
  });
});

// Shared by the concurrency and requirement blocks below: a fully enrolled
// account with its recovery codes in hand.
async function enrolAndConfirm(pool) {
  const { secret } = await mfa.startEnrolment(pool, USER, 'alice');
  const { recoveryCodes } = await mfa.confirmEnrolment(pool, USER, totp.generateCode(secret));
  return { secret, codes: recoveryCodes };
}

describe('⛔ single use survives CONCURRENCY, not just repetition', () => {
  // The previous tests prove a code cannot be replayed SERIALLY. That was the
  // whole guarantee, and it was not enough: the reuse check was a READ and the
  // write that followed was unconditional, so two requests carrying the same
  // captured code and arriving together both read the stale counter, both
  // passed the `<=` test, and both authenticated.
  //
  // A replay is by definition not a serial event — it is an attacker firing a
  // captured code as fast as they can, which is exactly the concurrent case the
  // old guard did not cover. Both consuming writes are now conditional, so the
  // DATABASE picks the winner and the loser gets rowCount 0.

  it('two simultaneous logins with the SAME TOTP code: exactly one succeeds', async () => {
    const pool = makePool();
    const { secret } = await enrolAndConfirm(pool);
    // A step later than the one confirmEnrolment already consumed.
    const later = Math.floor(Date.now() / 1000) + 30;
    const code = totp.generateCode(secret, later);

    const [a, b] = await Promise.all([
      mfa.verifyForLogin(pool, USER, code),
      mfa.verifyForLogin(pool, USER, code),
    ]);

    const wins = [a, b].filter((r) => r.ok).length;
    assert.equal(wins, 1, 'exactly one of two racing duplicates may authenticate');
    const loser = [a, b].find((r) => !r.ok);
    assert.equal(loser.reason, 'code_reused');
  });

  it('two simultaneous logins with DIFFERENT recovery codes do not restore each other', async () => {
    // The worse of the two races. Each request computed `remaining` from the
    // same stale read and wrote the WHOLE array back, so the second write
    // RESTORED the code the first had just consumed — a single-use recovery
    // code silently became live again. That does not merely admit a replay; it
    // manufactures a fresh credential.
    const pool = makePool();
    const { codes } = await enrolAndConfirm(pool);
    assert.ok(codes.length >= 2, 'need two distinct recovery codes');

    const [a, b] = await Promise.all([
      mfa.verifyForLogin(pool, USER, codes[0]),
      mfa.verifyForLogin(pool, USER, codes[1]),
    ]);
    assert.equal(a.ok, true);
    assert.equal(b.ok, true, 'two DIFFERENT codes are both legitimate');

    // Both must now be gone. Before the fix, one of them survived.
    assert.equal((await mfa.verifyForLogin(pool, USER, codes[0])).ok, false);
    assert.equal((await mfa.verifyForLogin(pool, USER, codes[1])).ok, false);
    assert.equal(pool.state.row.recovery_codes.length, codes.length - 2);
  });

  it('spending the LAST recovery code leaves an empty list rather than throwing', async () => {
    // jsonb_agg over zero rows is NULL and the column is NOT NULL, so the
    // removal has to COALESCE to '[]'.
    const pool = makePool();
    const { codes } = await enrolAndConfirm(pool);
    for (const c of codes) {
      // eslint-disable-next-line no-await-in-loop
      assert.equal((await mfa.verifyForLogin(pool, USER, c)).ok, true);
    }
    assert.deepEqual(pool.state.row.recovery_codes, []);
  });
});

describe('⛔ an admin MFA reset must not silently lift a REQUIREMENT', () => {
  it('preserves user_mfa.required across a reset', async () => {
    // resetFor() was a plain DELETE, which destroyed the `required` flag along
    // with the secret — so unlocking a user on a mandatory-MFA account returned
    // it to password-only, permanently, with no re-enrolment prompt. The CLI
    // printed the opposite in the same breath ("that flag was deliberately left
    // alone"), which is how it would have gone unnoticed: the tool told the
    // operator the enforcement held.
    //
    // The secret is still destroyed — that is what a reset IS. The POLICY is
    // not a credential, and an admin unlocking an account is not deciding to
    // exempt it.
    const pool = makePool();
    await enrolAndConfirm(pool);
    await mfa.setRequired(pool, USER, true);
    assert.equal(pool.state.row.required, true);

    const out = await mfa.resetFor(pool, USER);
    assert.equal(out.reset, true);
    assert.equal(out.requirementPreserved, true);
    assert.equal(pool.state.row.required, true, 'the requirement must survive');
    assert.equal(pool.state.row.enabled, false, 'but the account is no longer enrolled');
    assert.equal(pool.state.row.secret_encrypted, '', 'and the secret is gone');
  });

  it('a reset on a NON-required account leaves no row behind', async () => {
    const pool = makePool();
    await enrolAndConfirm(pool);
    const out = await mfa.resetFor(pool, USER);
    assert.equal(out.requirementPreserved, false);
    assert.equal(pool.state.row, null);
  });

  it('⛔ confirming before starting enrolment is refused, not a 500', async () => {
    // setRequired() and the reset above both create a placeholder carrying only
    // the requirement, with an EMPTY secret. confirmEnrolment reached
    // decrypt('', '') and credStore threw — an unhandled 500 where the honest
    // answer is "you have not started enrolling yet".
    const pool = makePool();
    await mfa.setRequired(pool, USER, true);
    const r = await mfa.confirmEnrolment(pool, USER, '123456');
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'not_enrolled');
  });
});
