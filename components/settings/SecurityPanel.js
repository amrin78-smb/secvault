'use client';

// components/settings/SecurityPanel.js
//
// Self-service multi-factor authentication, for the signed-in user.
//
// ⛔ NO QR CODE IN v1, AND THAT IS A DELIBERATE TRADE RATHER THAN AN OVERSIGHT.
// Rendering one needs either a new npm dependency — on a product whose installer
// runs `npm ci` on a firewall-management server, and which carries no
// devDependencies precisely so that what ships is what was tested — or a
// hand-written QR encoder (Reed-Solomon plus mask selection, several hundred
// lines of code whose bugs present as "my phone will not scan it"). Manual key
// entry is supported by every authenticator app, and the otpauth:// URI is
// offered too, so a user on the same machine can click straight through. QR is
// worth adding; it is not worth adding badly or at the cost of a dependency.
//
// ⛔ THE SECRET AND THE RECOVERY CODES ARE SHOWN EXACTLY ONCE. Neither can be
// read back afterwards — the secret is encrypted and the codes are bcrypt-hashed
// — so this component is careful to keep them on screen until the user
// explicitly dismisses them, rather than clearing on a re-render.

import { useCallback, useEffect, useState } from 'react';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';

const MONO = {
  fontFamily: 'var(--font-mono)',
  fontSize: 'var(--text-base)',
  letterSpacing: '0.08em',
};

function Section({ children }) {
  return <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>{children}</div>;
}

export default function SecurityPanel() {
  const [status, setStatus] = useState(null);
  const [enrolment, setEnrolment] = useState(null); // { secret, otpauthUri }
  const [recoveryCodes, setRecoveryCodes] = useState(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/mfa');
      setStatus(await res.json());
    } catch {
      setMessage('Could not load your security settings.');
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function start() {
    setBusy(true); setMessage('');
    try {
      const res = await fetch('/api/mfa', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) { setMessage(data.error || 'Could not start enrolment.'); return; }
      setEnrolment(data);
    } finally { setBusy(false); }
  }

  async function confirm(e) {
    e.preventDefault();
    setBusy(true); setMessage('');
    try {
      const res = await fetch('/api/mfa', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      if (!res.ok) { setMessage(data.error || 'That code was not correct.'); return; }
      setEnrolment(null);
      setCode('');
      setRecoveryCodes(data.recoveryCodes);
      await load();
    } finally { setBusy(false); }
  }

  async function disable(e) {
    e.preventDefault();
    setBusy(true); setMessage('');
    try {
      const res = await fetch('/api/mfa', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      if (!res.ok) { setMessage(data.error || 'Could not turn MFA off.'); return; }
      setCode('');
      await load();
    } finally { setBusy(false); }
  }

  if (!status) return null;

  // Directory accounts have no `users` row, so there is nowhere to attach a
  // secret. Said plainly rather than hidden — a missing control with no
  // explanation reads as a broken page.
  if (status.supported === false) {
    return (
      <Card>
        <CardHeader><CardTitle>Multi-factor authentication</CardTitle></CardHeader>
        <CardBody>
          <p style={{ margin: 0, color: 'var(--text-secondary)' }}>{status.error}</p>
        </CardBody>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 'var(--s3)' }}>
          Multi-factor authentication
          {status.enabled
            ? <Badge color="success">Active</Badge>
            : <Badge color="muted">Off</Badge>}
          {status.required && <Badge color="warn">Required by an administrator</Badge>}
        </CardTitle>
      </CardHeader>

      <CardBody>
        <Section>
          {/* ── one-time recovery codes ─────────────────────────────────── */}
          {recoveryCodes && (
            <div
              style={{
                border: '1px solid var(--sev-med)',
                background: 'var(--tint-warn)',
                borderRadius: 'var(--radius)',
                padding: 'var(--s5)',
              }}
            >
              <div style={{ fontWeight: 700, color: 'var(--tint-warn-fg)', marginBottom: 'var(--s3)' }}>
                Save these recovery codes now — they are shown only once
              </div>
              <p style={{ margin: '0 0 var(--s4)', color: 'var(--text-secondary)', fontSize: 'var(--text-base)' }}>
                Each one works a single time, in place of your authenticator. They are the way back
                in if you lose your phone. Store them somewhere that is not your phone.
              </p>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))',
                  gap: 'var(--s2)',
                  ...MONO,
                }}
              >
                {recoveryCodes.map((c) => (
                  <div key={c} style={{ padding: '6px 8px', background: 'var(--bg-card)', borderRadius: 'var(--radius-sm)' }}>
                    {c}
                  </div>
                ))}
              </div>
              <Button
                variant="secondary"
                style={{ marginTop: 'var(--s4)' }}
                onClick={() => setRecoveryCodes(null)}
              >
                I have saved them
              </Button>
            </div>
          )}

          {/* ── enrolment in progress ───────────────────────────────────── */}
          {enrolment && (
            <div>
              <p style={{ marginTop: 0, color: 'var(--text-secondary)' }}>
                Add this key to your authenticator app (Microsoft Authenticator, Google
                Authenticator, 1Password, Aegis — any of them), then enter the six-digit code it
                shows to confirm.
              </p>

              <div style={{ marginBottom: 'var(--s4)' }}>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginBottom: 4 }}>
                  Setup key
                </div>
                <div
                  style={{
                    ...MONO,
                    padding: 'var(--s3) var(--s4)',
                    background: 'var(--surface-subtle)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-sm)',
                    wordBreak: 'break-all',
                  }}
                >
                  {/* Grouped in fours — this gets typed by hand on a phone. */}
                  {enrolment.secret.replace(/(.{4})/g, '$1 ').trim()}
                </div>
              </div>

              <div style={{ marginBottom: 'var(--s4)' }}>
                <a href={enrolment.otpauthUri} style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
                  Open in an authenticator app on this device
                </a>
              </div>

              <form onSubmit={confirm} style={{ display: 'flex', gap: 'var(--s3)', alignItems: 'flex-end' }}>
                <div className="form-field" style={{ margin: 0 }}>
                  <label htmlFor="mfa_confirm">Six-digit code</label>
                  <input
                    id="mfa_confirm"
                    className="input"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    placeholder="123456"
                    style={{ ...MONO, maxWidth: 160 }}
                  />
                </div>
                <Button type="submit" variant="primary" disabled={busy}>Confirm</Button>
                <Button type="button" variant="secondary" disabled={busy} onClick={() => { setEnrolment(null); setCode(''); }}>
                  Cancel
                </Button>
              </form>
            </div>
          )}

          {/* ── steady state ───────────────────────────────────────────── */}
          {!enrolment && !status.enabled && (
            <div>
              <p style={{ marginTop: 0, color: 'var(--text-secondary)' }}>
                Add a second step to your sign-in using an authenticator app. Your password alone
                will no longer be enough to reach this account.
              </p>
              <Button variant="primary" onClick={start} disabled={busy}>
                Turn on multi-factor authentication
              </Button>
            </div>
          )}

          {!enrolment && status.enabled && (
            <div>
              <p style={{ marginTop: 0, color: 'var(--text-secondary)' }}>
                Multi-factor authentication is active on your account.{' '}
                <strong>{status.recoveryRemaining}</strong> recovery{' '}
                {status.recoveryRemaining === 1 ? 'code remains' : 'codes remain'}.
              </p>

              {/* ⛔ Stated plainly. Running out is not an error today and is a
                  lockout tomorrow, and the only fix is to re-enrol. */}
              {status.recoveryRemaining === 0 && (
                <p style={{ color: 'var(--tint-warn-fg)', fontSize: 'var(--text-base)' }}>
                  You have no recovery codes left. If you lose your authenticator you will need an
                  administrator to reset it. Turn MFA off and on again to get a new set.
                </p>
              )}

              {status.required ? (
                <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-base)' }}>
                  An administrator requires multi-factor authentication on this account, so it
                  cannot be turned off here.
                </p>
              ) : (
                <form onSubmit={disable} style={{ display: 'flex', gap: 'var(--s3)', alignItems: 'flex-end' }}>
                  <div className="form-field" style={{ margin: 0 }}>
                    <label htmlFor="mfa_off">Current code, to turn it off</label>
                    <input
                      id="mfa_off"
                      className="input"
                      value={code}
                      onChange={(e) => setCode(e.target.value)}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      placeholder="123456"
                      style={{ ...MONO, maxWidth: 160 }}
                    />
                  </div>
                  <Button type="submit" variant="secondary" disabled={busy}>
                    Turn off
                  </Button>
                </form>
              )}
            </div>
          )}

          {message && (
            <p style={{ margin: 0, color: 'var(--tint-danger-fg)', fontSize: 'var(--text-base)' }}>
              {message}
            </p>
          )}
        </Section>
      </CardBody>
    </Card>
  );
}
