'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { signIn } from 'next-auth/react';
import Button from '../../../components/ui/Button';
import LoadingSpinner from '../../../components/ui/LoadingSpinner';
import pkg from '../../../package.json';

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
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setSubmitting(true);

    try {
      const result = await signIn('local', {
        username,
        password,
        redirect: false,
      });

      if (!result || result.error) {
        setError('Invalid username or password.');
        setSubmitting(false);
        return;
      }

      router.push('/');
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

        <div style={{ marginTop: 40, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          SecVault v{pkg.version}
        </div>
      </div>
    </div>
  );
}
