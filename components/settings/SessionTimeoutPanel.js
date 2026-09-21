'use client';

// components/settings/SessionTimeoutPanel.js
//
// How long a session survives without activity.
//
// ⛔ VISIBLE TO EVERY ROLE, EDITABLE ONLY WITH `manage_settings` — the same call
// the Subscription tab makes. Everyone is SUBJECT to this timeout, so everyone
// should be able to read it; someone who is signed out after half an hour and
// cannot find out why concludes the product is broken. Only the control that
// changes it is gated, here and in the route behind it.
//
// ⛔ THE SAVED VALUE AND THE RUNNING VALUE ARE SHOWN SEPARATELY WHENEVER THEY
// DIFFER. NextAuth reads its session options once, at startup, so a saved
// change does nothing until the service restarts — and a panel that displayed
// the new number as though it were in force would be asserting a security
// control the product is not applying. Same rule the console-address panel
// follows, for the same reason.

import { useCallback, useEffect, useState } from 'react';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Button from '../ui/Button';

const ENDPOINT = '/api/system/session-policy';

function describe(mins) {
  if (!mins) return 'No timeout — sessions stay signed in until the browser is closed or the token expires.';
  if (mins < 60) return `Signed out after ${mins} minutes without activity.`;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return `Signed out after ${h} hour${h === 1 ? '' : 's'}${m ? ` ${m} minutes` : ''} without activity.`;
}

export default function SessionTimeoutPanel({ canManage = false }) {
  const [policy, setPolicy] = useState(null);
  const [value, setValue] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [loadFailed, setLoadFailed] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await fetch(ENDPOINT);
      if (!r.ok) throw new Error(String(r.status));
      const p = await r.json();
      setPolicy(p);
      setValue(String(p.idleMinutes ?? ''));
      setLoadFailed(false);
    } catch {
      // ⛔ NOT rendered as "no timeout". A failed read tells us nothing about
      // the policy, and showing a reassuring default would be this product's
      // signature bug on the one panel that describes a security control.
      setLoadFailed(true);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function save(e) {
    e.preventDefault();
    setSaving(true);
    setError('');
    setResult(null);
    try {
      const r = await fetch(ENDPOINT, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idleMinutes: value }),
      });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) {
        setError(body.error || 'Could not save the timeout.');
      } else {
        setResult(body);
        await load();
      }
    } catch (err) {
      setError(err.message || 'Could not save the timeout.');
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Session timeout</CardTitle>
      </CardHeader>
      <CardBody>
        {loadFailed ? (
          <p style={{ color: 'var(--unmeasured)', fontSize: 'var(--text-base)', lineHeight: 1.6 }}>
            The session timeout could not be read, so it is not shown here. This does not mean there
            is no timeout — the setting is unchanged and still in force.
          </p>
        ) : policy === null ? (
          <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-base)' }}>Loading…</p>
        ) : (
          <>
            <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-primary)', margin: '0 0 var(--s2)' }}>
              {describe(policy.idleMinutes)}
            </p>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', margin: '0 0 var(--s5)', lineHeight: 1.6 }}>
              {policy.enabled
                ? `A warning appears ${policy.warnSeconds} seconds beforehand, and signing in again `
                  + 'returns you to the page you were on. The timeout is enforced by the server, so '
                  + 'it applies even if the browser tab is closed or the warning is ignored.'
                : 'Nobody is signed out for being idle. On a console that can change firewall '
                  + 'configuration this is worth turning on.'}
            </p>

            {canManage ? (
              <form onSubmit={save} style={{ display: 'flex', gap: 'var(--s3)', alignItems: 'flex-end', flexWrap: 'wrap' }}>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s1)' }}>
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                    Minutes of inactivity (0 switches it off)
                  </span>
                  <input
                    type="number"
                    min="0"
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                    style={{
                      width: 160, padding: '8px 10px',
                      border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
                      background: 'var(--bg-card)', color: 'var(--text-primary)',
                      fontSize: 'var(--text-base)',
                    }}
                  />
                </label>
                <Button type="submit" disabled={saving}>{saving ? 'Saving…' : 'Save'}</Button>
              </form>
            ) : (
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                Changing this needs the Manage settings permission.
              </p>
            )}

            {error ? (
              <p style={{
                marginTop: 'var(--s4)', padding: '8px 12px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--tint-danger)', color: 'var(--tint-danger-fg)',
                fontSize: 'var(--text-sm)',
              }}>
                {error}
              </p>
            ) : null}

            {result ? (
              <p style={{
                marginTop: 'var(--s4)', padding: '8px 12px',
                borderRadius: 'var(--radius-sm)',
                background: result.restartRequired ? 'var(--tint-warn)' : 'var(--tint-success)',
                color: result.restartRequired ? 'var(--tint-warn-fg)' : 'var(--tint-success-fg)',
                fontSize: 'var(--text-sm)', lineHeight: 1.6,
              }}>
                {result.message}
              </p>
            ) : null}
          </>
        )}
      </CardBody>
    </Card>
  );
}
