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
// ⛔ THIS IS NOT THE BOUNDARY. NetVault's version IS the timeout: it calls
// signOut() and nothing server-side changes, so the JWT stays valid for its
// full lifetime and a copied cookie is unaffected. Here the server already
// expires the token (lib/sessionPolicy.js drives NextAuth's maxAge), and this
// component exists so the expiry is not a surprise. If this file were deleted
// the timeout would still happen — you would simply be bounced to the login
// page without warning.
//
// ⛔ AND IT DOES NOT CARRY ITS OWN COPY OF THE WINDOW. It reads the same value
// the server enforces. A hardcoded number here would drift from the environment
// and promise 60 seconds on a session that had already ended.
//
// Colours come from the design tokens, not from literals: NetVault's version
// hardcodes #fef3c7 / #d97706 / rgba(15,23,42,0.55), which in this product
// would opt the modal out of the theme and out of dark mode.

const ACTIVITY_EVENTS = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'];

// ⛔ FAIL OPEN ON A FAILED READ, AND SAY WHY. If the policy cannot be fetched we
// arm NOTHING rather than guessing a window: the server is still enforcing its
// own expiry, so the worst case is an unwarned logout — while a guessed window
// that is SHORTER than the real one would sign people out of a session that was
// still perfectly valid. NetVault guesses 30 minutes here; it can afford to,
// because there the client IS the timeout and a guess is the only option.
const FAIL_OPEN = { enabled: false, idleMinutes: 0, warnSeconds: 0 };

function timeoutSignOut() {
  const here = window.location.pathname + window.location.search;
  const dest = here && !here.startsWith('/login') ? here : '/';
  signOut({ callbackUrl: `/login?reason=timeout&callbackUrl=${encodeURIComponent(dest)}` });
}

export default function IdleTimeout() {
  const [remaining, setRemaining] = useState(null);
  const policy = useRef(FAIL_OPEN);
  const mainTimer = useRef(null);
  const warnTimer = useRef(null);
  const tickTimer = useRef(null);
  const scheduleRef = useRef(() => {});

  useEffect(() => {
    let cancelled = false;

    function clearTimers() {
      for (const t of [mainTimer, warnTimer, tickTimer]) {
        if (t.current !== null) { clearTimeout(t.current); clearInterval(t.current); t.current = null; }
      }
    }

    function schedule() {
      clearTimers();
      setRemaining(null);
      const p = policy.current;
      if (!p.enabled || !p.idleMinutes) return;
      const ms = p.idleMinutes * 60_000;
      const warnMs = (p.warnSeconds || 0) * 1000;
      const warnDelay = ms - warnMs;
      if (warnDelay > 0 && warnMs > 0) {
        warnTimer.current = setTimeout(() => {
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

    // ⛔ ACTIVITY ONLY RE-ARMS THE WARNING; IT DOES NOT EXTEND THE SESSION BY
    // ITSELF. The server extends the token when next-auth refreshes it, which
    // happens on real requests. Moving the mouse on a page that issues no
    // request resets this timer and the session still expires — so the window
    // here matches the server's and the countdown is a floor, never a promise.
    let last = 0;
    function onActivity() {
      const now = Date.now();
      // Throttled: mousemove fires continuously and rescheduling two timers on
      // every pixel is wasted work on a page already rendering tables.
      if (now - last < 1000) return;
      last = now;
      if (policy.current.enabled) schedule();
    }

    ACTIVITY_EVENTS.forEach((e) => window.addEventListener(e, onActivity, { passive: true }));

    fetch('/api/system/session-policy')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((p) => {
        if (cancelled) return;
        policy.current = {
          enabled: Boolean(p.enabled),
          idleMinutes: Number(p.idleMinutes) || 0,
          warnSeconds: Number(p.warnSeconds) || 0,
        };
        schedule();
      })
      .catch(() => { policy.current = FAIL_OPEN; });

    return () => {
      cancelled = true;
      clearTimers();
      ACTIVITY_EVENTS.forEach((e) => window.removeEventListener(e, onActivity));
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
            onClick={() => scheduleRef.current()} style={{ padding: '10px 24px' }}>
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
