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
// ⛔ CORRECTED 2026-09-21, AND THE CORRECTION IS THE WHOLE POINT OF THIS
// PARAGRAPH. An earlier version of this comment claimed `updateAge` governs
// when NextAuth rewrites the token, and clamped it carefully on that basis.
// THAT IS FALSE FOR THE JWT STRATEGY, verified against the installed
// next-auth 4.24.15: `updateAge` is read in exactly one place
// (core/routes/session.js), inside the DATABASE-session branch. The JWT branch
// re-encodes and re-sets the cookie UNCONDITIONALLY on every call, and never
// consults it. The option was dead configuration and is no longer passed.
//
// ⛔ WHAT ACTUALLY EXTENDS A SESSION IS A REQUEST TO /api/auth/session, AND
// ALMOST NOTHING ISSUES ONE. `getServerSession()` in App Router server
// components builds a STUB response (`setCookie(){}`), so the refreshed cookie
// it produces is discarded — no page load and no API call extends anything.
// There is no SessionProvider in this app, so nothing refetches on a timer.
// Left alone, `maxAge` is therefore an ABSOLUTE timeout: signed out N minutes
// after LOGGING IN however hard you are working.
//
// So the keep-alive is explicit and lives in components/layout/IdleTimeout.js:
// on real activity, at most once per KEEPALIVE_MS, it fetches
// /api/auth/session, which re-issues the token. Idle means no fetch, which
// means expiry. That is what makes this an IDLE timeout rather than a clock
// that started at login.

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
  // ⛔ NO `updateAge`. It does nothing under the JWT strategy (see the header),
  // and carrying an option a comment calls load-bearing while it is inert is
  // precisely the "guard that cannot fire" this codebase keeps finding.
  return { strategy: 'jwt', maxAge: mins * 60 };
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
    // ⛔ HOW OFTEN AN ACTIVE BROWSER MAY REFRESH THE TOKEN. Frequent enough
    // that a working user never reaches expiry, rare enough that it is not a
    // request per mouse move: a quarter of the window, capped at a minute.
    // ⛔ It MUST stay well below idleMinutes, or an active user's refresh
    // arrives after the token has already died.
    keepAliveSeconds: mins > 0 ? Math.max(5, Math.min(60, Math.floor((mins * 60) / 4))) : 0,
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
