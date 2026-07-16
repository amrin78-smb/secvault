'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { signIn } from 'next-auth/react';
import Button from '../../../components/ui/Button';
import LoadingSpinner from '../../../components/ui/LoadingSpinner';

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
    <div
      style={{
        display: 'flex',
        minHeight: '100vh',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--navy)',
        padding: '0 16px',
      }}
    >
      <div
        className="card"
        style={{ width: '100%', maxWidth: 384, padding: 32 }}
      >
        <div style={{ marginBottom: 32, textAlign: 'center' }}>
          <span
            style={{
              fontSize: 'var(--text-xl)',
              fontWeight: 700,
              letterSpacing: '-0.3px',
              color: 'var(--text-primary)',
            }}
          >
            Sec<span style={{ color: 'var(--primary)' }}>Vault</span>
          </span>
          <p style={{ marginTop: 8, fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
            Firewall security and management platform
          </p>
        </div>

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
    </div>
  );
}
