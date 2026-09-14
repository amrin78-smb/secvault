'use client';

// components/settings/TlsPanel.js
//
// Shows what certificate the console is serving, and lets an administrator
// replace it with one from their own CA.
//
// ⛔ THE TWO FACTS AN OPERATOR ACTUALLY NEEDS are which names the certificate
// covers and when it expires — not its fingerprint or its serial. A certificate
// that is valid but does not list the address people type is indistinguishable,
// in a browser, from no certificate at all, and an expiry nobody is watching is
// how an internal console goes dark on a Sunday. Both are shown without being
// asked for.
//
// ⛔ A RESTART IS REQUIRED AND IS SAID SO EXPLICITLY. node reads the certificate
// ONCE, at startup, so a newly installed certificate is on disk but not in use.
// Leaving that unsaid produces an operator who is certain the install worked and
// cannot understand why the browser still shows the old certificate.
//
// ⛔ The private key is write-only. It is posted, never returned, and the field
// is cleared as soon as the install succeeds.

import { useCallback, useEffect, useState } from 'react';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';

const MONO = { fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' };

function StatusBadge({ status }) {
  if (status === 'active') return <Badge color="success">HTTPS active</Badge>;
  // ⛔ 'failed' and 'disabled' must never look alike. One is an operator who
  // asked for TLS and is not getting it; the other never asked.
  if (status === 'failed') return <Badge color="danger">Configured but NOT active</Badge>;
  return <Badge color="muted">Not configured — plain HTTP</Badge>;
}

function Row({ label, children }) {
  return (
    <div style={{ display: 'flex', gap: 'var(--s4)', padding: '6px 0', borderBottom: '1px dashed var(--border-light)' }}>
      <div style={{ minWidth: 150, color: 'var(--text-muted)', fontSize: 'var(--text-base)' }}>{label}</div>
      <div style={{ flex: 1, color: 'var(--text-primary)', fontSize: 'var(--text-base)', wordBreak: 'break-word' }}>
        {children}
      </div>
    </div>
  );
}

export default function TlsPanel() {
  const [state, setState] = useState(null);
  const [cert, setCert] = useState('');
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [installed, setInstalled] = useState(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/system/tls');
      if (res.ok) setState(await res.json());
      else setState({ status: 'unknown', forbidden: res.status === 403 });
    } catch {
      setError('Could not read the current TLS status.');
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function install(e) {
    e.preventDefault();
    setBusy(true); setError(''); setInstalled(null);
    try {
      const res = await fetch('/api/system/tls', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ certificate: cert, privateKey: key }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || 'The certificate could not be installed.'); return; }
      setInstalled(data);
      setCert('');
      setKey('');   // ⛔ cleared immediately; it is a secret sitting in a textarea
      await load();
    } finally { setBusy(false); }
  }

  if (!state) return null;
  if (state.forbidden) return null;

  const c = state.certificate;
  const expiringSoon = c && !c.expired && typeof c.daysRemaining === 'number' && c.daysRemaining < 30;

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 'var(--s3)' }}>
          TLS certificate
          <StatusBadge status={state.status} />
        </CardTitle>
      </CardHeader>

      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s5)' }}>
          {state.status === 'failed' && (
            <div
              style={{
                border: '1px solid var(--sev-crit)',
                background: 'var(--tint-danger)',
                color: 'var(--tint-danger-fg)',
                borderRadius: 'var(--radius)',
                padding: 'var(--s4)',
              }}
            >
              <strong>Traffic is not encrypted.</strong>
              <div style={{ marginTop: 4, fontSize: 'var(--text-base)' }}>{state.error}</div>
            </div>
          )}

          {/* ── what is deployed now ─────────────────────────────────────── */}
          {c && !c.parseError ? (
            <div>
              <Row label="Issued to">{c.subject}</Row>
              <Row label="Issued by">
                {c.issuer}{' '}
                {c.selfSigned && (
                  <Badge color="warn" title="Browsers will warn until this certificate is trusted">
                    self-signed
                  </Badge>
                )}
              </Row>
              <Row label="Valid for">
                {/* ⛔ The names are the thing that actually decides whether a
                    browser accepts this. Shown in full, never truncated. */}
                {c.sans && c.sans.length
                  ? <span style={MONO}>{c.sans.join('  ·  ')}</span>
                  : <span style={{ color: 'var(--unmeasured)' }}>no names listed — browsers will reject this</span>}
              </Row>
              <Row label="Expires">
                <span style={MONO}>{c.validTo}</span>{' '}
                {c.expired
                  ? <Badge color="danger">expired</Badge>
                  : expiringSoon
                    ? <Badge color="warn">{c.daysRemaining} days left</Badge>
                    : <span style={{ color: 'var(--text-muted)' }}>({c.daysRemaining} days left)</span>}
              </Row>
              <Row label="Served on">
                <span style={MONO}>port {state.httpsPort}</span>
                <span style={{ color: 'var(--text-muted)' }}>
                  {' '}— plain HTTP on {state.httpPort} redirects here
                </span>
              </Row>
            </div>
          ) : (
            <p style={{ margin: 0, color: 'var(--text-secondary)' }}>
              {state.status === 'disabled'
                ? 'No certificate is configured. SecVault is serving plain HTTP.'
                : 'A certificate is configured but could not be read.'}
            </p>
          )}

          {/* ── install a new one ────────────────────────────────────────── */}
          {installed && (
            <div
              style={{
                border: '1px solid var(--sev-med)',
                background: 'var(--tint-warn)',
                borderRadius: 'var(--radius)',
                padding: 'var(--s4)',
              }}
            >
              <strong style={{ color: 'var(--tint-warn-fg)' }}>
                Installed — but not in use yet
              </strong>
              <p style={{ margin: '6px 0 0', fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
                SecVault reads its certificate once, when it starts. Restart the service to begin
                serving this one:
              </p>
              <pre style={{ ...MONO, margin: '8px 0 0', padding: 'var(--s3)', background: 'var(--bg-card)', borderRadius: 'var(--radius-sm)' }}>
sc.exe stop SecVault-App
sc.exe start SecVault-App
              </pre>
              <p style={{ margin: '8px 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                The previous certificate was backed up alongside it, so you can put it back if this
                one turns out to be wrong.
              </p>
            </div>
          )}

          <form onSubmit={install} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
            <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Install a certificate</div>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: 'var(--text-base)' }}>
              Paste a PEM certificate and its unencrypted private key. The pair is checked before
              anything is written — a key that does not match its certificate is refused rather than
              installed.
            </p>

            <div className="form-field" style={{ margin: 0 }}>
              <label htmlFor="tls_cert">Certificate (PEM)</label>
              <textarea
                id="tls_cert"
                className="input"
                rows={6}
                spellCheck={false}
                value={cert}
                onChange={(e) => setCert(e.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----"
                style={MONO}
              />
            </div>

            <div className="form-field" style={{ margin: 0 }}>
              <label htmlFor="tls_key">Private key (PEM, not passphrase-protected)</label>
              <textarea
                id="tls_key"
                className="input"
                rows={6}
                spellCheck={false}
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder="-----BEGIN PRIVATE KEY-----"
                style={MONO}
              />
            </div>

            {error && (
              <p style={{ margin: 0, color: 'var(--tint-danger-fg)', fontSize: 'var(--text-base)' }}>{error}</p>
            )}

            <Button type="submit" variant="primary" disabled={busy || !cert || !key} style={{ alignSelf: 'flex-start' }}>
              {busy ? 'Checking…' : 'Validate and install'}
            </Button>
          </form>
        </div>
      </CardBody>
    </Card>
  );
}
