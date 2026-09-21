'use client';

import { useState, useEffect, useRef } from 'react';
import { PRODUCT_NAME } from '../../../lib/branding';
import { useRouter } from 'next/navigation';
import { signIn } from 'next-auth/react';
// ⛔ A PURE MODULE, NOT A LOCAL HELPER. The first version lived here, could
// not be imported by a test, and was bypassable with an embedded tab.
import { safeReturnPath } from '../../../lib/returnPath';
import Button from '../../../components/ui/Button';
import LoadingSpinner from '../../../components/ui/LoadingSpinner';

// Large watermark version of Header.js's SecVaultLogo shield path -- reused
// (not reinvented) so the login page's brand panel is recognizably the same
// product identity as the rest of the app, not a generic auth-template shape.
function ShieldWatermark(props) {
  return (
    <svg viewBox="0 0 38 40" fill="none" aria-hidden="true" {...props}>
      <path
        d="M19 3l13 5v8c0 9-5.5 15-13 18-7.5-3-13-9-13-18V8z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path d="M13 19l4 4 8-9" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const FEATURES = [
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
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      {/* Brand panel -- hidden on narrow viewports (min-width media query via
          inline-style-unfriendly CSS, so this uses a plain className hook
          instead), watermark shield + product context. Nothing here is
          interactive, so it's safe as a server-renderable static block even
          though the page itself is a client component. */}
      <div className="login-brand-panel">
        <div
          style={{
            position: 'absolute',
            inset: 0,
            backgroundImage:
              'radial-gradient(circle at 15% 20%, rgba(8,145,178,0.16), transparent 45%), ' +
              'radial-gradient(circle at 85% 85%, rgba(200,16,46,0.14), transparent 45%)',
          }}
        />
        <ShieldWatermark
          style={{
            position: 'absolute',
            right: '-6%',
            bottom: '-8%',
            width: '65%',
            height: 'auto',
            color: 'rgba(255,255,255,0.05)',
          }}
        />
        <div style={{ position: 'relative', maxWidth: 420 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 28 }}>
            <ShieldWatermark style={{ width: 30, height: 30, color: 'var(--accent-teal)' }} />
            <span style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.3px' }}>
              <span style={{ color: '#fff' }}>Sec</span>
              <span style={{ color: 'var(--accent-teal)' }}>Vault</span>
            </span>
          </div>
          <h1
            style={{
              fontSize: 30,
              fontWeight: 700,
              lineHeight: 1.25,
              letterSpacing: '-0.5px',
              color: '#fff',
              marginBottom: 16,
            }}
          >
            Firewall security posture, in one place.
          </h1>
          <p style={{ fontSize: 'var(--text-md)', color: 'rgba(255,255,255,0.55)', lineHeight: 1.6, marginBottom: 32 }}>
            Standalone CVE tracking, rule analysis, and compliance scoring across your entire
            managed firewall fleet.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {FEATURES.map((f) => (
              <div key={f} style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                <svg
                  viewBox="0 0 24 24"
                  width={16}
                  height={16}
                  style={{ marginTop: 2, flexShrink: 0, color: 'var(--accent-teal)' }}
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={2}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <polyline points="20 6 9 17 4 12" />
                </svg>
                <span style={{ fontSize: 'var(--text-base)', color: 'rgba(255,255,255,0.75)', lineHeight: 1.4 }}>
                  {f}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Form panel */}
      <div
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '32px 16px',
          background: 'var(--bg-primary)',
        }}
      >
        <div style={{ width: '100%', maxWidth: 360 }}>
          {/* Compact brand mark, shown only when the wide brand panel is hidden
              (narrow viewports) -- see .login-brand-panel/.login-compact-brand
              in globals.css for the responsive swap. */}
          <div className="login-compact-brand" style={{ textAlign: 'center', marginBottom: 28 }}>
            <span style={{ fontSize: 'var(--text-xl)', fontWeight: 700, letterSpacing: '-0.3px', color: 'var(--text-primary)' }}>
              Sec<span style={{ color: 'var(--primary)' }}>Vault</span>
            </span>
          </div>

          <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            Sign in
          </h2>
          <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)', marginBottom: 28 }}>
            Enter your credentials to access the platform.
          </p>

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="form-field">
              <label htmlFor="username">Username</label>
              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="input"
                autoFocus
              />
            </div>

            <div className="form-field">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="input"
              />
            </div>

            {/* ⛔ ALWAYS VISIBLE, never revealed conditionally. Showing this field
                only for accounts that have MFA would turn the login form into an
                oracle: type a username, watch whether the box appears, and you
                know which accounts are protected and which are worth attacking.
                It is optional for everyone and ignored for accounts without
                MFA. */}
            <div className="form-field">
              <label htmlFor="totp">
                Authenticator code
                <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}> — if enabled</span>
              </label>
              <input
                id="totp"
                name="totp"
                type="text"
                /* one-time-code lets a phone offer the SMS/authenticator code */
                autoComplete="one-time-code"
                inputMode="numeric"
                placeholder="123456"
                value={totp}
                onChange={(e) => setTotp(e.target.value)}
                className="input"
                style={{ fontFamily: 'var(--font-mono)', letterSpacing: '0.12em' }}
              />
            </div>

            {/* ⛔ A TIMEOUT IS NOT A FAILURE, and it is tinted as information
                rather than danger. Someone returning to a signed-out console
                needs to know nothing went wrong and nothing was lost — shown
                in the danger colour it reads as a rejected sign-in, and the
                next thing they do is doubt their password. */}
            {timedOut && !error && (
              <p
                style={{
                  borderRadius: 'var(--radius-sm)',
                  background: 'var(--tint-info)',
                  color: 'var(--tint-info-fg)',
                  padding: '8px 12px',
                  fontSize: 'var(--text-base)',
                }}
              >
                You were signed out because there was no activity. Sign in again and you will go
                back to the page you were on.
              </p>
            )}

            {error && (
              <p
                style={{
                  borderRadius: 'var(--radius-sm)',
                  background: 'var(--tint-danger)',
                  color: 'var(--tint-danger-fg)',
                  padding: '8px 12px',
                  fontSize: 'var(--text-base)',
                }}
              >
                {error}
              </p>
            )}

            <Button
              type="submit"
              variant="primary"
              disabled={submitting}
              style={{ width: '100%', justifyContent: 'center' }}
            >
              {submitting ? (
                <>
                  <LoadingSpinner size={14} /> Signing in...
                </>
              ) : (
                'Sign in'
              )}
            </Button>
          </form>
        </div>

        {/* ⛔ No version number here. This page is PRE-AUTH, and the exact
            version maps an unauthenticated visitor straight onto the precise
            advisory set for this build — measured live, the login HTML read
            "SecVault v2.61.2". The product name is fine; the version is not.
            It is still shown to signed-in users under Settings -> About, which
            is where support actually needs it. */}
        <div style={{ marginTop: 40, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {PRODUCT_NAME}
        </div>
      </div>
    </div>
  );
}
