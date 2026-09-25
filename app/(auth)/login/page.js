'use client';

// app/(auth)/login/page.js
//
// ⛔ THE LEVEL WAS TAKEN FROM NETVAULT'S LOGIN; NONE OF ITS CONTENT WAS.
// Benchmarked against `netvault/app/(auth)/login/page.tsx` on 2026-09-25 at the
// user's request. What is worth copying there is the FINISH — an animated
// ground, a glass card with real depth, page chrome instead of bare panels.
// Four things in it are actively wrong for this product and are deliberately
// absent. Each is listed at its own site below, because a later session
// comparing the two files will otherwise "fix" the difference:
//
//   1. the suite RED               → SecVault reserves red for danger (v2.87.0)
//   2. a hardcoded "Platform Status: Operational" badge
//   3. the version + build number in the footer
//   4. the two-step MFA precheck that reveals whether an account has MFA
//
// ⛔ AND (2) IS THE ONE THAT MATTERS MOST. NetVault paints a green dot and the
// word "Operational" as static markup — it measures nothing. On a product whose
// entire thesis is that it does not assert what it has not measured, a
// decorative health indicator on the FIRST screen anybody sees would be the
// failed-read-as-a-fact rule broken before the user has even signed in. If a
// status indicator is ever wanted here it must read a real probe, and an
// unreadable probe must render as unknown, not green.

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { signIn } from 'next-auth/react';
import { PRODUCT_NAME } from '../../../lib/branding';
// ⛔ A PURE MODULE, NOT A LOCAL HELPER. The first version lived here, could
// not be imported by a test, and was bypassable with an embedded tab.
import { safeReturnPath } from '../../../lib/returnPath';
import LoadingSpinner from '../../../components/ui/LoadingSpinner';
import LoginBackdrop from '../../../components/auth/LoginBackdrop';

// The shield from Header.js's SecVaultLogo — reused, not reinvented, so the
// sign-in page is recognisably the same product as the rest of the app rather
// than a generic auth template.
function Shield(props) {
  return (
    <svg viewBox="0 0 38 40" fill="none" aria-hidden="true" {...props}>
      <path
        d="M19 3l13 5v8c0 9-5.5 15-13 18-7.5-3-13-9-13-18V8z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M13 19l4 4 8-9"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function Check(props) {
  return (
    <svg viewBox="0 0 24 24" width={15} height={15} fill="none" stroke="currentColor"
      strokeWidth={2.4} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function Wordmark({ size = 20 }) {
  return (
    <span style={{ fontSize: size, fontWeight: 700, letterSpacing: '-0.3px' }}>
      <span style={{ color: 'var(--shell-fg)' }}>Sec</span>
      <span style={{ color: 'var(--primary)' }}>Vault</span>
    </span>
  );
}

const PROOF = [
  'CVE tracking across every managed firewall vendor',
  'Rule hygiene, shadow, and redundancy analysis',
  'PCI DSS, ISO 27001, CIS v8, NIST, and SANS compliance scoring',
];

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  // ⛔ READ FROM window.location IN AN EFFECT, NOT useSearchParams(). This page
  // is statically prerendered; useSearchParams() in a client component opts the
  // whole subtree out of that unless it is wrapped in Suspense, and a login
  // page that renders a moment later is a worse trade than reading the query
  // string directly once the browser has it.
  const [timedOut, setTimedOut] = useState(false);
  const returnTo = useRef('/');

  useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    setTimedOut(q.get('reason') === 'timeout');
    returnTo.current = safeReturnPath(q.get('callbackUrl'));
  }, []);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setSubmitting(true);

    try {
      const result = await signIn('local', {
        username,
        password,
        // Empty for accounts without MFA; the server ignores it in that case.
        totp,
        redirect: false,
      });

      if (!result || result.error) {
        // ⛔ ONE MESSAGE FOR EVERY FAILURE, and it deliberately does not
        // mention the code. Distinguishing "wrong password" from "wrong code"
        // would confirm to an attacker that a captured password was correct and
        // that only the second factor stands in the way — which is precisely
        // the thing the second factor exists to keep uncertain. The specific
        // reason is written to the server log, where the operator can see it.
        setError('Sign-in failed. Check your username, password and authenticator code.');
        setSubmitting(false);
        return;
      }

      // Back to whatever the idle timeout interrupted, or the dashboard.
      router.push(returnTo.current);
    } catch (err) {
      setError('Login failed. Please try again.');
      setSubmitting(false);
    }
  }

  return (
    <div className="login-page">
      <LoginBackdrop />

      {/* Page chrome. ⛔ The sibling puts a green "Platform Status: Operational"
          pill opposite this one; see the file header for why there is none
          here. */}
      <div className="login-chrome login-chrome-top">
        <Shield style={{ width: 30, height: 30, color: 'var(--primary)' }} />
        <div>
          <Wordmark size={20} />
          <div className="login-eyebrow">FIREWALL SECURITY PLATFORM</div>
        </div>
      </div>

      <div className="login-center">
        <div className="login-pitch">
          {/* ⛔ This sentence is the /login smoke marker (scripts/smoke.js).
              Changing it without changing the marker turns the one gate that
              actually loads this page green over a page that did not render. */}
          <h1>Firewall security posture, in one place.</h1>
          <div className="login-rule" />
          <p className="login-lede">
            Standalone CVE tracking, rule analysis, and compliance scoring across your entire
            managed firewall fleet.
          </p>
          <div className="login-proof">
            {PROOF.map((p) => (
              <div key={p} className="login-proof-row">
                <Check />
                <span>{p}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="login-card">
          <div className="login-compact-brand" style={{ textAlign: 'center', marginBottom: 'var(--s5)' }}>
            <Wordmark size={22} />
          </div>

          <h2>Sign in</h2>
          <p className="login-card-sub">Enter your credentials to access the platform.</p>

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
            <div className="login-field">
              <label htmlFor="username">Username</label>
              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                className="login-input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoFocus
              />
            </div>

            <div className="login-field">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                className="login-input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            {/* ⛔ ALWAYS VISIBLE, never revealed conditionally. Showing this field
                only for accounts that have MFA would turn the login form into an
                oracle: type a username, watch whether the box appears, and you
                know which accounts are protected and which are worth attacking.
                It is optional for everyone and ignored for accounts without MFA.
                ⛔ NetVault's login does the opposite — it POSTs the credentials
                to /api/auth/mfa/precheck and shows the field only when the
                answer is yes. Do not port that here: it is the oracle this
                comment exists to prevent, and CLAUDE.md's single-form rule
                ("NextAuth v4's authorize() is ONE call") is the other half of
                the same decision. */}
            <div className="login-field">
              <label htmlFor="totp">
                Authenticator code
                <span className="login-hint"> — if enabled</span>
              </label>
              <input
                id="totp"
                name="totp"
                type="text"
                /* one-time-code lets a phone offer the SMS/authenticator code.
                   ⛔ Not type="number": it strips a leading zero, and a TOTP
                   starting 0 is perfectly ordinary. */
                autoComplete="one-time-code"
                inputMode="numeric"
                placeholder="123456"
                className="login-input"
                value={totp}
                onChange={(e) => setTotp(e.target.value)}
                style={{ fontFamily: 'var(--font-mono)', letterSpacing: '0.14em' }}
              />
            </div>

            {/* ⛔ A TIMEOUT IS NOT A FAILURE, and it is tinted as information
                rather than danger. Someone returning to a signed-out console
                needs to know nothing went wrong and nothing was lost — shown
                in the danger colour it reads as a rejected sign-in, and the
                next thing they do is doubt their password. */}
            {timedOut && !error && (
              <p className="login-note login-note-info">
                You were signed out because there was no activity. Sign in again and you will go
                back to the page you were on.
              </p>
            )}

            {error && (
              <p className="login-note login-note-error" role="alert">
                {error}
              </p>
            )}

            <button type="submit" className="login-submit" disabled={submitting}>
              {submitting ? (
                <>
                  <LoadingSpinner size={14} /> Signing in...
                </>
              ) : (
                'Sign in'
              )}
            </button>
          </form>
        </div>
      </div>

      {/* ⛔ No version number here. This page is PRE-AUTH, and the exact
          version maps an unauthenticated visitor straight onto the precise
          advisory set for this build — measured live, the login HTML read
          "SecVault v2.61.2". The product name is fine; the version is not.
          It is still shown to signed-in users under Settings -> About, which
          is where support actually needs it. ⛔ NetVault's login prints
          "NocVault v1.2.0 • Build 2026.06.11" in this exact position. Do not
          copy it back. */}
      <div className="login-chrome login-chrome-bottom">{PRODUCT_NAME}</div>
    </div>
  );
}
