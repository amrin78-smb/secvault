'use strict';
//
// lib/sessionPolicy.js — how long a signed-in session survives without activity.
//
// ⛔ SECVAULT HAD NO IDLE TIMEOUT AT ALL. `session: { strategy: 'jwt' }` with no
// `maxAge` means NextAuth's default applies, which is THIRTY DAYS. A browser
// left signed in on a firewall-management console stayed signed in for a month.
//
// ⛔ THE SERVER IS THE BOUNDARY; THE MODAL IS ONLY THE COURTESY. NetVault
// (`components/IdleTimeout.tsx`) implements this purely on the client: it
// listens for mouse and key events and calls `signOut()`. That is a real
// control against someone walking up to an unattended screen, and it is NOT a
// session-security control — it clears the cookie in that one browser while the
// JWT stays cryptographically valid for its full lifetime, so a copied cookie
// is unaffected. On a product that stores firewall credentials that gap matters,
// so the timeout here is enforced by NextAuth's own token expiry and the modal
// exists to warn and to land the user back where they were.
//
// ⛔ `updateAge` IS LOAD-BEARING AND IS THE EASY THING TO GET WRONG. With the
// JWT strategy NextAuth only REWRITES the token — extending its expiry — when
// `updateAge` has elapsed since it was issued. Leave it at the default (24h)
// beside a 30-minute `maxAge` and the token is never refreshed, so every user
// is signed out 30 minutes after LOGGING IN however hard they are working. That
// is an absolute timeout wearing an idle timeout's name. It is therefore
// clamped below to at most half the idle window, and a test pins the relation
// rather than the number.

const DEFAULT_IDLE_MINUTES = 30;
// A month, which is NextAuth's own default and therefore exactly the behaviour
// this product shipped with. ⛔ Used when the timeout is DISABLED, so turning it
// off restores what was there before rather than producing a session that
// expires instantly or never expires at all.
const DISABLED_MAX_AGE_SECONDS = 30 * 24 * 60 * 60;
// Below a minute the warning modal (60s of lead time) could never be shown, and
// a console that signs you out while you read one screen is one nobody keeps
// switched on.
const MIN_IDLE_MINUTES = 2;
// A day. Longer than this is indistinguishable from off, and an operator who
// wants off should say off rather than type a number that looks like a policy.
const MAX_IDLE_MINUTES = 24 * 60;
// How much notice the UI gives before signing out. Matches NetVault.
const WARN_SECONDS = 60;

/**
 * Read the configured idle window, in minutes.
 *
 * ⛔ 0 MEANS DISABLED AND IS A REAL, SUPPORTED CHOICE — not a missing value. An
 * air-gapped console on a locked rack may legitimately want no timeout, and an
 * operator who sets 0 must get that rather than a silently-applied default.
 * Anything unparseable IS a missing value and falls back to the default, which
 * is the safe direction: a typo must not switch the control off.
 */
function idleMinutes(env = process.env) {
  const raw = env.SESSION_IDLE_MINUTES;
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return DEFAULT_IDLE_MINUTES;
  }
  const n = Number(String(raw).trim());
  if (!Number.isFinite(n)) return DEFAULT_IDLE_MINUTES;
  const t = Math.trunc(n);
  // ⛔ ONLY AN EXPLICIT ZERO DISABLES. A NEGATIVE IS A TYPO, NOT AN INTENT,
  // and an earlier draft of this function returned 0 for it — so `-30` would
  // have silently switched the timeout off, which is the exact failure the
  // paragraph above promises not to allow. It falls back to the default.
  if (t < 0) return DEFAULT_IDLE_MINUTES;
  if (t === 0) return 0;
  return Math.min(Math.max(t, MIN_IDLE_MINUTES), MAX_IDLE_MINUTES);
}

/**
 * The NextAuth `session` block. Returned whole so the auth route cannot
 * assemble a half-correct one, and so the maxAge/updateAge relation below is
 * decided in exactly one place.
 */
function sessionOptions(env = process.env) {
  const mins = idleMinutes(env);
  if (mins === 0) {
    return { strategy: 'jwt', maxAge: DISABLED_MAX_AGE_SECONDS };
  }
  const maxAge = mins * 60;
  // ⛔ NEVER >= maxAge. See the header note: an updateAge at or above the idle
  // window turns this into an absolute timeout that fires mid-work. Half the
  // window, capped at a minute so an active user's token is refreshed promptly
  // and the cost stays one token rewrite per minute per active session.
  const updateAge = Math.max(1, Math.min(60, Math.floor(maxAge / 2)));
  return { strategy: 'jwt', maxAge, updateAge };
}

/**
 * What the browser needs to arm its warning.
 *
 * ⛔ ONE SOURCE OF TRUTH. The client does NOT carry its own copy of the window:
 * it reads this. Two numbers — one in the environment and one in a settings
 * table — would drift, and the drift would show up as a modal promising 60
 * seconds on a session the server already ended, or worse, no modal at all
 * before a silent logout.
 */
function clientPolicy(env = process.env) {
  const mins = idleMinutes(env);
  return {
    idleMinutes: mins,
    enabled: mins > 0,
    // ⛔ THE CLAMP IS DEFENCE-IN-DEPTH AND CANNOT FIRE TODAY — said out loud,
    // because a guard that cannot fire reads as handled and is the defect this
    // codebase keeps finding. MIN_IDLE_MINUTES (2) is deliberately at least
    // twice WARN_SECONDS (60), so the warning always fits; the invariant is
    // pinned by a test rather than left to this line. Lower the minimum and the
    // test fails, which is when this clamp starts doing real work.
    warnSeconds: mins > 0 ? Math.min(WARN_SECONDS, Math.floor((mins * 60) / 2)) : 0,
  };
}

/** Validate a value an operator typed, before it is written to .env.local. */
function validateIdleMinutes(input) {
  const s = String(input === undefined || input === null ? '' : input).trim();
  if (s === '') return { ok: false, error: 'Enter a number of minutes, or 0 to switch the timeout off.' };
  const n = Number(s);
  if (!Number.isFinite(n) || !Number.isInteger(n)) {
    return { ok: false, error: 'Enter a whole number of minutes.' };
  }
  if (n < 0) return { ok: false, error: 'Minutes cannot be negative. Use 0 to switch the timeout off.' };
  if (n === 0) return { ok: true, value: 0, disabled: true };
  if (n < MIN_IDLE_MINUTES) {
    return {
      ok: false,
      error: `The shortest usable timeout is ${MIN_IDLE_MINUTES} minutes — below that the warning `
        + 'cannot be shown before the session ends.',
    };
  }
  if (n > MAX_IDLE_MINUTES) {
    return {
      ok: false,
      error: `The longest timeout is ${MAX_IDLE_MINUTES} minutes (24 hours). Use 0 if you want no `
        + 'timeout at all, rather than a number that reads like a policy but is not one.',
    };
  }
  return { ok: true, value: n, disabled: false };
}

module.exports = {
  idleMinutes,
  sessionOptions,
  clientPolicy,
  validateIdleMinutes,
  DEFAULT_IDLE_MINUTES,
  DISABLED_MAX_AGE_SECONDS,
  MIN_IDLE_MINUTES,
  MAX_IDLE_MINUTES,
  WARN_SECONDS,
};
