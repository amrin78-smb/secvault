'use strict';

// lib/rateLimit.js
//
// In-memory fixed-window rate limiter. Ported from NetVault's `lib/rateLimit.ts`
// — same shape, same fail-open stance — with ONE deliberate difference, below.
//
// ⛔ FAILS OPEN. Any unexpected error returns "not limited". The limiter must
// never be the reason a legitimate sign-in fails; it exists to slow a hammering
// client, not to gate access.
//
// ── ⛔ KEYED ON THE USERNAME, NOT THE CLIENT IP — AND THAT IS A CHANGE ────
//
// NetVault keys its precheck limiter on `getClientIp()`, which reads
// `x-forwarded-for` / `x-real-ip` and falls back to a SHARED 'unknown' bucket
// when neither is present.
//
// ⛔ ON SECVAULT THAT FALLBACK IS THE NORMAL CASE, NOT THE EDGE CASE. This
// product serves its own TLS from `server.js` on 3010 with no reverse proxy in
// front of it (see CLAUDE.md's TLS section), so those headers are usually
// absent and every caller would land in ONE bucket. Twenty attempts anywhere
// would then throttle the login for the whole organisation — a denial of
// service on a firewall-management console, created by the control meant to
// protect it.
//
// And where the headers ARE present they are trusted on shape alone, so a
// client that reaches the app directly can spoof one and mint itself a fresh
// bucket per request. An IP key is therefore both harmful when absent and
// weak when present.
//
// Keying on the submitted username instead is accurate about what is being
// limited — password guesses against an ACCOUNT — and confines the effect to
// that account.
//
// ⛔ WHICH IS ONLY SAFE BECAUSE BEING LIMITED CANNOT LOCK ANYONE OUT. The one
// caller is the MFA precheck, and a limited precheck DEGRADES TO SHOWING THE
// CODE FIELD — exactly the behaviour this product shipped with. Sign-in itself
// is never throttled and never blocked. If a future caller uses this to refuse
// an action rather than to decide a form field, the username key becomes an
// account-lockout weapon and this decision must be revisited IN THAT COMMIT.

const buckets = new Map();

// Opportunistic cleanup so a long-lived process does not accumulate one bucket
// per distinct key for ever. Swept lazily off the hot path — no timer.
const SWEEP_INTERVAL_MS = 5 * 60 * 1000;
let lastSweepAt = 0;

function sweepExpired(now, windowMs) {
  if (now - lastSweepAt < SWEEP_INTERVAL_MS) return;
  lastSweepAt = now;
  for (const [key, b] of buckets) {
    if (now - b.windowStart >= windowMs) buckets.delete(key);
  }
}

/**
 * checkRateLimit('mfa-precheck:alice', { maxAttempts: 20, windowMs: 300000 })
 *   -> { limited: false, retryAfterSec: 0 }
 *
 * A classic FIXED window: the count resets once `windowMs` has elapsed since
 * the window opened, so a caller sitting on the seam can burst up to ~2x
 * `maxAttempts` across it. That is an accepted trade for "slow a hammering
 * client"; it is not a precise quota and must not be used as one.
 *
 * @param {number} [now] injectable clock, so the window can be tested without
 *   sleeping. Defaults to Date.now().
 */
function checkRateLimit(key, opts, now) {
  try {
    const o = opts || {};
    const maxAttempts = Number(o.maxAttempts);
    const windowMs = Number(o.windowMs);
    // ⛔ A NONSENSE CONFIG DOES NOT LIMIT. A NaN threshold compared with `>`
    // is always false, which would silently disable the limiter while looking
    // configured; refusing explicitly is the same call, stated.
    if (!Number.isFinite(maxAttempts) || !Number.isFinite(windowMs)
      || maxAttempts < 1 || windowMs < 1 || typeof key !== 'string' || key === '') {
      return { limited: false, retryAfterSec: 0 };
    }
    const t = Number.isFinite(now) ? now : Date.now();
    sweepExpired(t, windowMs);

    const existing = buckets.get(key);
    if (!existing || t - existing.windowStart >= windowMs) {
      buckets.set(key, { windowStart: t, count: 1 });
      return { limited: false, retryAfterSec: 0 };
    }

    existing.count++;
    if (existing.count > maxAttempts) {
      const retryAfterSec = Math.max(1, Math.ceil((existing.windowStart + windowMs - t) / 1000));
      return { limited: true, retryAfterSec };
    }
    return { limited: false, retryAfterSec: 0 };
  } catch {
    // The limiter itself must never be the reason a legitimate request fails.
    return { limited: false, retryAfterSec: 0 };
  }
}

/** Test seam only — the process-wide map would otherwise leak between cases. */
function _resetForTests() {
  buckets.clear();
  lastSweepAt = 0;
}

module.exports = { checkRateLimit, _resetForTests };
