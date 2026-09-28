import { NextResponse } from 'next/server';
import { pool } from '../../../../../lib/db';
import { verifyLocalPassword } from '../../../../../lib/localPassword';
import { checkRateLimit } from '../../../../../lib/rateLimit';
import * as mfa from '../../../../../lib/mfa';

export const dynamic = 'force-dynamic';

// POST /api/auth/mfa/precheck  { username, password }
//   -> { ok: false }                                  cannot say — show the field
//   -> { ok: true, mfaRequired: true }                this account uses a code
//   -> { ok: true, mfaRequired: false }               no code needed
//
// Login step 1. It decides ONE thing: whether the sign-in form reveals the
// authenticator-code field. It issues no session, no token and no cookie, and
// NextAuth's authorize() independently re-checks the password AND the code, so
// a client that skips this call or lies about the answer gains nothing.
//
// ── ⛔ THIS REVERSES A DOCUMENTED DECISION, AND THE OLD REASON WAS WRONG ──
//
// The login page carried a comment forbidding exactly this, on the grounds that
// a conditionally-revealed field is an oracle: "type a username, watch whether
// the box appears, and you know which accounts are protected". That objection
// does not apply to this design, and did not apply to NetVault's either — the
// comment described a version of the endpoint neither product has. THE PASSWORD
// IS VERIFIED BEFORE ANY ANSWER IS GIVEN. Without valid credentials every
// caller gets the same `{ ok: false }`, whether the account has MFA, has no
// MFA, or does not exist.
//
// ⛔ WHAT IS GIVEN UP IS DIFFERENT, AND SMALLER, AND REAL. A correct password
// for an MFA-protected account now returns `{ ok: true, mfaRequired: true }`,
// which CONFIRMS THE PASSWORD before the second factor is supplied. Previously
// one generic failure meant an attacker holding a stolen password could not
// tell whether the password or the code was wrong. This turns a
// credential-stuffing miss into a confirmed hit worth pursuing by other means —
// phishing the code, SIM swap, session theft.
//
// That disclosure is INHERENT: any answer useful enough to drive the form
// confirms the password. It was accepted deliberately, for a login that does
// not show a code box to the majority of users who have none, and for the
// enrolment case below. Do not "fix" it by answering before the password check.
//
// ── ⛔ EVERY FAILURE PATH SHOWS THE FIELD ────────────────────────────────
//
// Rate limited, database down, malformed body, unknown user, LDAP account,
// MFA lookup threw: all `{ ok: false }`, and the form then renders the code
// field exactly as this product always did. The endpoint can only ever REMOVE
// a field, never demand one, so no failure here can stop anyone signing in.
// That property is what makes it safe to rate-limit by username.

const RATE_LIMIT = { maxAttempts: 20, windowMs: 5 * 60 * 1000 };

// ⛔ ONE RESPONSE FOR EVERY "WE CANNOT SAY". Built by a helper so no branch can
// accidentally add a distinguishing field — a `reason` here would rebuild the
// oracle this endpoint is careful not to be.
function cannotSay() {
  return NextResponse.json({ ok: false });
}

export async function POST(req) {
  let body = {};
  try {
    body = await req.json();
  } catch {
    return cannotSay();
  }

  const username = typeof body?.username === 'string' ? body.username.trim() : '';
  const password = typeof body?.password === 'string' ? body.password : '';
  if (!username || !password) return cannotSay();

  // ⛔ KEYED ON THE USERNAME — see lib/rateLimit.js for why not the IP, and why
  // that is only safe because being limited shows the field rather than
  // blocking anything. Lowercased so `Admin` and `admin` cannot be used as two
  // budgets against one account.
  const rl = checkRateLimit(`mfa-precheck:${username.toLowerCase()}`, RATE_LIMIT);
  if (rl.limited) {
    // ⛔ 200, not 429, and the SAME body as every other refusal. A 429 would
    // tell an attacker their guessing was noticed, and — worse — would
    // distinguish "this account is being hammered" from "wrong password",
    // which is an oracle about account activity. The form treats it like any
    // other `ok: false` and shows the field.
    return cannotSay();
  }

  let user = null;
  let valid = false;
  try {
    ({ user, valid } = await verifyLocalPassword(pool, username, password));
  } catch (err) {
    // ⛔ A FAILED READ IS NOT A WRONG PASSWORD. Show the field and say nothing.
    console.error('[mfa-precheck] password verification failed:', err.message);
    return cannotSay();
  }

  // ⛔ NO SUCH USER AND WRONG PASSWORD COLLAPSE HERE. This also covers every
  // LDAP account, which has no `users` row at all — those users always see the
  // code field. That is correct rather than merely acceptable: SecVault's MFA
  // is unavailable for LDAP accounts (their second factor belongs in the
  // directory), and answering for them would need an LDAP bind, i.e. a second
  // unauthenticated surface against the customer's directory. Not worth a
  // hidden form field.
  if (!user || !valid) return cannotSay();

  let enabled = false;
  try {
    enabled = await mfa.isEnabledFor(pool, user.id);
  } catch (err) {
    // ⛔ FAILS CLOSED TOWARDS SHOWING THE FIELD. authorize() fails closed by
    // REFUSING the login when this lookup throws; here the equivalent is to
    // reveal the field, because answering `mfaRequired: false` on an error
    // would hide the one input that account needs and make a database blip
    // look like a wrong code.
    console.error('[mfa-precheck] MFA status check failed:', err.message);
    return cannotSay();
  }

  return NextResponse.json({ ok: true, mfaRequired: enabled === true });
}
