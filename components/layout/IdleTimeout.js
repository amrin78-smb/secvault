'use client';

import { useEffect, useRef, useState } from 'react';
import { signOut } from 'next-auth/react';

// components/layout/IdleTimeout.js
//
// The warning before an idle session ends, and a clean way back to the page you
// were on. Adapted from NetVault's `components/IdleTimeout.tsx` — same shape,
// same activity events, same 60 seconds of notice — with two differences that
// matter.
//
// ⛔ THIS IS NOT THE BOUNDARY — BUT IT IS WHAT MAKES THE BOUNDARY AN *IDLE*
// ONE. The server expires the token (lib/sessionPolicy.js drives NextAuth's
// maxAge). What it does NOT do is extend it: verified against next-auth
// 4.24.15, only a request to /api/auth/session re-issues the cookie, and
// getServerSession() in App Router server components writes its refreshed
// cookie into a STUB response that is thrown away. There is no SessionProvider
// here either. So without the keep-alive below, maxAge is an ABSOLUTE timeout
// that signs people out mid-work N minutes after they logged in.
//
// This component therefore does two jobs:
//   1. KEEP-ALIVE — on real activity, at most once per keepAliveSeconds, hit
//      /api/auth/session so the token is re-issued. Idle means no fetch means
//      expiry, which is the definition of an idle timeout.
//   2. WARN — show the countdown, and land the user back where they were.
// Delete it and sessions still expire, on the clock that started at login,
// with no warning.
//
// ⛔ AND IT DOES NOT CARRY ITS OWN COPY OF THE WINDOW. It reads the same value
// the server enforces. A hardcoded number here would drift from the environment
// and promise 60 seconds on a session that had already ended.
//
// Colours come from the design tokens, not from literals: NetVault's version
// hardcodes #fef3c7 / #d97706 / rgba(15,23,42,0.55), which in this product
// would opt the modal out of the theme and out of dark mode.

const ACTIVITY_EVENTS = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'];

// ⛔ NextAuth's own session endpoint. Hitting it re-encodes the JWT and re-sets
// the cookie with a fresh expiry (next-auth/core/routes/session.js, the jwt
// branch, unconditionally). This is the ONLY thing in the app that extends a
// session.
const SESSION_ENDPOINT = '/api/auth/session';

// ⛔ CROSS-TAB ACTIVITY. Each tab used to arm its own timer from its own
// events, so a forgotten tab reaching the window called signOut() and destroyed
// the cookie for the whole browser — signing out a user who was demonstrably
// active in another tab. Activity is broadcast through localStorage (a `storage`
// event fires in the OTHER tabs only, which is exactly what is wanted) and every
// tab re-arms from the most recent activity anywhere.
const ACTIVITY_KEY = 'secvault:last-activity';

// ⛔ FAIL OPEN ON A FAILED READ, AND SAY WHY. If the policy cannot be fetched we
// arm NOTHING rather than guessing a window: the server is still enforcing its
// own expiry, so the worst case is an unwarned logout — while a guessed window
// that is SHORTER than the real one would sign people out of a session that was
// still perfectly valid. NetVault guesses 30 minutes here; it can afford to,
// because there the client IS the timeout and a guess is the only option.
const FAIL_OPEN = { enabled: false, idleMinutes: 0, warnSeconds: 0, keepAliveSeconds: 0 };

function timeoutSignOut() {
  const here = window.location.pathname + window.location.search;
  const dest = here && !here.startsWith('/login') ? here : '/';
  signOut({ callbackUrl: `/login?reason=timeout&callbackUrl=${encodeURIComponent(dest)}` });
}

function markActivity() {
  try {
    window.localStorage.setItem(ACTIVITY_KEY, String(Date.now()));
  } catch { /* private mode, blocked storage: this tab still works alone */ }
}

function lastActivityElsewhere() {
  try {
    const v = Number(window.localStorage.getItem(ACTIVITY_KEY));
    return Number.isFinite(v) ? v : 0;
  } catch { return 0; }
}

export default function IdleTimeout() {
  const [remaining, setRemaining] = useState(null);
  const policy = useRef(FAIL_OPEN);
  const mainTimer = useRef(null);
  const warnTimer = useRef(null);
  const tickTimer = useRef(null);
  const scheduleRef = useRef(() => {});
  // ⛔ "Stay signed in" must extend the SERVER session too. Re-arming only the
  // client timer would dismiss the dialog and then let the token die anyway,
  // which is worse than not offering the button.
  const stayRef = useRef(() => {});

  useEffect(() => {
    let cancelled = false;
    let lastKeepAlive = 0;
    // ⛔ While the warning is up, activity must NOT silently dismiss it. It used
    // to: onActivity called schedule(), which cleared `remaining`, and because
    // the overlay covers the viewport the mouse movement needed to REACH the
    // "Stay signed in" button dismissed the dialog before it could be clicked.
    // Worse, dismissing it re-armed only the CLIENT timer while the server
    // clock kept running, so the session then died with no warning at all.
    let warning = false;

    // ⛔ THE KEEP-ALIVE IS THE HALF THAT MAKES THIS AN IDLE TIMEOUT. It fires
    // only on real activity and only once per keepAliveSeconds, so an idle
    // browser issues nothing and the token expires on schedule.
    function keepAlive() {
      const p = policy.current;
      if (!p.enabled || !p.keepAliveSeconds) return;
      const now = Date.now();
      if (now - lastKeepAlive < p.keepAliveSeconds * 1000) return;
      lastKeepAlive = now;
      // Fire and forget: a failed refresh is not worth reporting, because the
      // consequence (the session ends) is already the documented behaviour.
      fetch(SESSION_ENDPOINT, { credentials: 'same-origin' }).catch(() => {});
    }

    function clearTimers() {
      for (const t of [mainTimer, warnTimer, tickTimer]) {
        if (t.current !== null) { clearTimeout(t.current); clearInterval(t.current); t.current = null; }
      }
    }

    function schedule() {
      clearTimers();
      warning = false;
      setRemaining(null);
      const p = policy.current;
      if (!p.enabled || !p.idleMinutes) return;
      const ms = p.idleMinutes * 60_000;
      const warnMs = (p.warnSeconds || 0) * 1000;
      const warnDelay = ms - warnMs;
      if (warnDelay > 0 && warnMs > 0) {
        warnTimer.current = setTimeout(() => {
          warning = true;
          setRemaining(Math.round(warnMs / 1000));
          // A live countdown, so the dialog is checkable rather than a claim.
          tickTimer.current = setInterval(() => {
            setRemaining((r) => (r === null || r <= 1 ? 0 : r - 1));
          }, 1000);
        }, warnDelay);
      }
      mainTimer.current = setTimeout(timeoutSignOut, ms);
    }

    scheduleRef.current = schedule;
    stayRef.current = () => {
      warning = false;
      lastKeepAlive = 0; // force the refresh through the throttle
      markActivity();
      keepAlive();
      schedule();
    };

    // ⛔ ACTIVITY DOES THREE THINGS, AND ALL THREE ARE NEEDED. It re-arms this
    // tab's timers, broadcasts to the other tabs, and — throttled — refreshes
    // the SERVER token. An earlier version of this comment said activity does
    // NOT extend the session; that was accurate about the code at the time and
    // is exactly why the timeout was absolute rather than idle.
    let last = 0;
    function onActivity() {
      // ⛔ The warning is dismissed by a BUTTON, never by a mouse move. See the
      // `warning` declaration above for why.
      if (warning) return;
      const now = Date.now();
      // Throttled: mousemove fires continuously and rescheduling two timers on
      // every pixel is wasted work on a page already rendering tables.
      if (now - last < 1000) return;
      last = now;
      if (!policy.current.enabled) return;
      markActivity();
      keepAlive();
      schedule();
    }

    // Activity in ANOTHER tab re-arms this one. Note `storage` fires only in
    // other tabs, so this cannot recurse with markActivity() above.
    function onStorage(e) {
      if (e.key !== ACTIVITY_KEY || warning || !policy.current.enabled) return;
      schedule();
    }

    ACTIVITY_EVENTS.forEach((e) => window.addEventListener(e, onActivity, { passive: true }));
    window.addEventListener('storage', onStorage);

    fetch('/api/system/session-policy')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((p) => {
        if (cancelled) return;
        policy.current = {
          enabled: Boolean(p.enabled),
          idleMinutes: Number(p.idleMinutes) || 0,
          warnSeconds: Number(p.warnSeconds) || 0,
          keepAliveSeconds: Number(p.keepAliveSeconds) || 0,
        };
        // ⛔ Arm from the most recent activity in ANY tab, not from now, so a
        // tab opened beside an active one does not start its own fresh window.
        const elsewhere = lastActivityElsewhere();
        if (!elsewhere || Date.now() - elsewhere > 1000) markActivity();
        schedule();
      })
      .catch(() => { policy.current = FAIL_OPEN; });

    return () => {
      cancelled = true;
      clearTimers();
      ACTIVITY_EVENTS.forEach((e) => window.removeEventListener(e, onActivity));
      window.removeEventListener('storage', onStorage);
    };
  }, []);

  if (remaining === null) return null;

  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="idle-title"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(16, 24, 38, 0.55)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: 'var(--s4)',
      }}
    >
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)',
        padding: 'var(--s7)',
        width: '100%',
        maxWidth: 420,
        boxShadow: '0 20px 60px rgba(0,0,0,0.3)',
        textAlign: 'center',
      }}>
        <div style={{
          width: 52, height: 52, borderRadius: '50%',
          background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          margin: '0 auto var(--s4)',
        }}>
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor"
            strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="10" />
            <polyline points="12 6 12 12 16 14" />
          </svg>
        </div>
        <h2 id="idle-title" style={{
          fontSize: 'var(--text-lg)', fontWeight: 700,
          color: 'var(--text-primary)', margin: '0 0 var(--s2)',
        }}>
          Session expiring
        </h2>
        <p style={{
          fontSize: 'var(--text-base)', color: 'var(--text-secondary)',
          margin: '0 0 var(--s6)', lineHeight: 1.6,
        }}>
          You will be signed out in{' '}
          <strong style={{ color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums' }}>
            {remaining}
          </strong>{' '}
          second{remaining === 1 ? '' : 's'} because there has been no activity. You will come back
          to this page when you sign in again.
        </p>
        <div style={{ display: 'flex', gap: 'var(--s3)', justifyContent: 'center' }}>
          <button type="button" className="btn btn-primary"
            onClick={() => stayRef.current()} style={{ padding: '10px 24px' }}>
            Stay signed in
          </button>
          <button type="button" className="btn"
            onClick={timeoutSignOut} style={{ padding: '10px 24px' }}>
            Sign out now
          </button>
        </div>
      </div>
    </div>
  );
}
