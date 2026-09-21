'use client';

// components/settings/ConsoleAddressPanel.js
//
// The address this console is reached on — the value NextAuth builds its
// callback from.
//
// ⛔ WHY THIS IS THE MOST DANGEROUS FIELD IN SETTINGS. Set it to a name the
// browser is not using and every sign-in bounces silently back to the login
// page: no error in the UI, none in the browser console, nothing in the
// network tab that looks wrong. And the person who set it cannot log in to
// change it back. Recovery is editing .env.local over RDP and restarting the
// service.
//
// So this panel is deliberately unlike the others: it shows the current value
// before the box, refuses a scheme that disagrees with the transport, refuses a
// host that does not resolve to this server unless the operator confirms, and
// prints the manual recovery path after a successful save rather than a tick.

import { useCallback, useEffect, useState } from 'react';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';

const MONO = { fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' };

function Row({ label, children }) {
  return (
    <div style={{ display: 'flex', gap: 'var(--s4)', padding: '6px 0', flexWrap: 'wrap' }}>
      <div style={{ minWidth: 150, color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>{label}</div>
      <div style={{ flex: 1, minWidth: 260 }}>{children}</div>
    </div>
  );
}

export default function ConsoleAddressPanel() {
  const [state, setState] = useState(null);
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [confirm, setConfirm] = useState(null);
  const [result, setResult] = useState(null);
  const [loadError, setLoadError] = useState('');

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/system/console-url');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setState(data);
      setValue((v) => v || data.current || '');
      setLoadError('');
    } catch (err) {
      // ⛔ A panel that cannot read its own state says so rather than rendering
      // an empty box that looks like "not configured".
      setLoadError(`Could not read the current address: ${err.message}`);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function save(force) {
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const res = await fetch('/api/system/console-url', {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url: value, force: !!force }),
      });
      const data = await res.json();
      if (res.status === 409 && data.needsConfirmation) {
        setConfirm(data.error);
        return;
      }
      if (!res.ok) { setError(data.error || `HTTP ${res.status}`); return; }
      setConfirm(null);
      setResult(data);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 'var(--s3)' }}>
          Console address
          {state && state.restartPending ? <Badge variant="warning">restart pending</Badge> : null}
        </CardTitle>
      </CardHeader>
      <CardBody>
        {loadError ? (
          <div style={{ color: 'var(--tint-danger-fg)', marginBottom: 'var(--s4)' }}>{loadError}</div>
        ) : null}

        <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', marginTop: 0 }}>
          The address people type to reach this console. SecVault issues its sign-in cookie for this
          origin, so it must match what the browser is actually using — including the port.
        </p>

        {state ? (
          <div style={{ marginBottom: 'var(--s4)' }}>
            <Row label="Saved in .env.local">
              <span style={MONO}>{state.current || <em style={{ color: 'var(--unmeasured)' }}>not set</em>}</span>
            </Row>
            {/* ⛔ The RUNNING value is shown separately whenever it differs. node
                reads this once at startup, so "saved" and "in effect" are two
                different facts and collapsing them is how an operator concludes
                a change did nothing. */}
            {state.restartPending ? (
              <Row label="Currently in effect">
                <span style={MONO}>{state.running}</span>
                <div style={{ color: 'var(--tint-warn-fg)', fontSize: 'var(--text-xs)', marginTop: 4 }}>
                  Restart SecVault-App for the saved value to take effect.
                </div>
              </Row>
            ) : null}
            <Row label="Transport">
              <span style={MONO}>
                {state.tlsActive ? `https (port ${state.httpsPort})` : `http (port ${state.httpPort})`}
              </span>
              <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', marginTop: 4 }}>
                The address must use {state.scheme}:// to match.
              </div>
            </Row>
            {!state.writable ? (
              <Row label="Configuration file">
                <span style={{ color: 'var(--tint-danger-fg)', fontSize: 'var(--text-sm)' }}>
                  {state.envPath} is not writable by the service account — this change would fail.
                </span>
              </Row>
            ) : null}
          </div>
        ) : null}

        <label htmlFor="console-url" style={{ fontSize: 'var(--text-sm)', fontWeight: 600 }}>New address</label>
        <input
          id="console-url"
          value={value}
          onChange={(e) => { setValue(e.target.value); setConfirm(null); setError(''); }}
          placeholder="https://secvault.example.com:3010"
          style={{
            display: 'block', width: '100%', marginTop: 6, padding: '8px 10px',
            borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
            background: 'var(--bg-card)', color: 'var(--text-primary)', ...MONO,
          }}
        />

        {error ? (
          <div style={{ color: 'var(--tint-danger-fg)', fontSize: 'var(--text-sm)', marginTop: 'var(--s3)' }}>
            {error}
          </div>
        ) : null}

        {confirm ? (
          /* ⛔ The one place a typo becomes a lockout, so it is a deliberate
             second action rather than a checkbox ticked in advance. */
          <div style={{
            marginTop: 'var(--s3)', padding: 'var(--s3)', borderRadius: 'var(--radius-sm)',
            background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)', fontSize: 'var(--text-sm)',
          }}>
            {confirm}
            <div style={{ marginTop: 'var(--s3)' }}>
              <Button onClick={() => save(true)} disabled={busy} variant="secondary">
                Save it anyway
              </Button>
            </div>
          </div>
        ) : null}

        {result ? (
          <div style={{
            marginTop: 'var(--s3)', padding: 'var(--s3)', borderRadius: 'var(--radius-sm)',
            background: 'var(--tint-success)', color: 'var(--tint-success-fg)', fontSize: 'var(--text-sm)',
          }}>
            {result.unchanged ? 'That is already the saved address.' : `Saved: ${result.url}`}
            {result.warnings && result.warnings.length > 0 ? (
              <ul style={{ margin: '8px 0 0 18px' }}>
                {result.warnings.map((w) => <li key={w}>{w}</li>)}
              </ul>
            ) : null}
            {result.restartRequired ? (
              <div style={{ marginTop: 8 }}>
                <strong>Restart SecVault-App for this to take effect.</strong>
              </div>
            ) : null}
            {result.recovery ? (
              <div style={{ marginTop: 8, color: 'var(--text-secondary)' }}>{result.recovery}</div>
            ) : null}
          </div>
        ) : null}

        <div style={{ marginTop: 'var(--s4)' }}>
          <Button onClick={() => save(false)} disabled={busy || !value.trim()}>
            {busy ? 'Saving…' : 'Save address'}
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}
