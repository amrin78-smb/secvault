'use client';

// components/settings/EntraSsoPanel.js
//
// Entra ID tenant configuration. Phase 2b of .ai-codex/entra-sso-proposal.md.
//
// ⛔ THIS EXISTS BECAUSE "EDIT .env.local ON THE SERVER" IS NOT A SETUP STEP A
// CUSTOMER CAN BE GIVEN. SecVault ships to customers who administer it through
// this console; telling them to RDP into a Windows box and hand-edit a dotfile
// to switch SSO on is how a feature goes unused. The precedent is already
// here: Settings -> Certificate -> Console address writes NEXTAUTH_URL, and
// Security writes SESSION_IDLE_MINUTES, both through lib/envFile.js.
//
// ⛔ THE SECRET IS WRITE-ONLY. It is never sent to the browser — the API
// reports only whether one is set. The field is therefore a REPLACE field, and
// leaving it blank keeps the stored secret rather than clearing it, which the
// label has to say or an administrator editing the tenant id will believe they
// have just wiped their credentials.

import { useState, useEffect, useCallback } from 'react';
import Card, { CardBody, CardHeader } from '../ui/Card';
import Button from '../ui/Button';

export default function EntraSsoPanel() {
  const [data, setData] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [tenantId, setTenantId] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/system/entra');
      if (!res.ok) {
        const b = await res.json().catch(() => ({}));
        setLoadError(b.error || `HTTP ${res.status}`);
        return;
      }
      const d = await res.json();
      setData(d);
      setTenantId(d.tenantId || '');
      setClientId(d.clientId || '');
      setLoadError('');
    } catch (err) {
      setLoadError(err.message || String(err));
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function save() {
    setBusy(true);
    setStatus('');
    try {
      const res = await fetch('/api/system/entra', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tenantId,
          clientId,
          // ⛔ OMITTED when blank, so the stored secret survives an edit to the
          // ids. Sending '' would CLEAR it — see the route's own note.
          ...(clientSecret === '' ? {} : { clientSecret }),
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setStatus(body.error || `HTTP ${res.status}`);
      } else {
        setStatus(body.disabled
          ? 'Entra SSO settings cleared. Restart SecVault-App to apply.'
          : 'Saved. Restart SecVault-App to apply — the sign-in button appears after the restart.');
        setClientSecret('');
        await load();
      }
    } catch (err) {
      setStatus(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  if (loadError) {
    return (
      <Card>
        <CardBody>
          <div style={{ color: 'var(--sev-crit)', fontSize: 'var(--text-sm)' }}>
            The Entra settings could not be read: {loadError}
          </div>
        </CardBody>
      </Card>
    );
  }
  if (!data) return null;

  const savedConfigured = Boolean(data.tenantId && data.clientId && data.clientSecretSet);
  // ⛔ SAVED IS NOT RUNNING. The process read its environment at startup, so a
  // value saved a moment ago is not yet in force — the same distinction the
  // console-address and session-policy panels draw, and for the same reason:
  // without it an administrator concludes the feature is broken.
  const pendingRestart = savedConfigured !== data.runningConfigured;

  return (
    <Card>
      <CardHeader>Entra ID single sign-on</CardHeader>
      <CardBody>
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 'var(--s4)' }}>
          Optional. Local accounts always keep working, with or without this, and continue to work
          if Microsoft is unreachable. Leave the fields blank to turn it off.
        </div>

        {pendingRestart ? (
          <div style={{
            background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)',
            padding: 'var(--s3)', borderRadius: 'var(--radius-sm)',
            fontSize: 'var(--text-sm)', lineHeight: 1.6, marginBottom: 'var(--s4)',
          }}>
            <strong>Saved, but not yet in force.</strong> SecVault reads these values once, when it
            starts. Restart the <code>SecVault-App</code> service to apply them.
          </div>
        ) : null}

        {/* ⛔ REFUSED SIGN-INS, SHOWN BESIDE THE SETTINGS THAT CAUSE THEM.
            Without this an operator meets "No Role" in the header and has
            nothing to act on — the reason existed but only on the token. The
            three causes need three different fixes (the claim is missing from
            the ID token / the user is in no mapped group / too many group
            memberships), so naming which one it was is the whole value. */}
        {(data.refusals || []).length > 0 ? (
          <div style={{
            background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)',
            padding: 'var(--s3)', borderRadius: 'var(--radius-sm)',
            marginBottom: 'var(--s4)',
          }}>
            <div style={{ fontWeight: 600, marginBottom: 'var(--s2)', fontSize: 'var(--text-sm)' }}>
              Recent refused sign-ins
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
              {data.refusals.map((r, i) => (
                <div key={i} style={{ fontSize: 'var(--text-xs)', lineHeight: 1.5 }}>
                  <strong>{r.actor}</strong>
                  {r.at ? ` · ${new Date(r.at).toLocaleString()}` : ''}
                  <div>{r.detail}</div>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {/* ⛔ THE REDIRECT URI IS SHOWN, NOT DESCRIBED. It must be registered in
            Entra byte for byte, and a mismatch fails on Microsoft's side with
            an error that never reaches our logs — so the exact string belongs
            on screen, derived from the console address rather than typed. */}
        <div style={{ marginBottom: 'var(--s4)' }}>
          <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, marginBottom: 4 }}>
            Redirect URI to register in Entra
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)',
            background: 'var(--surface-subtle)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)', padding: 'var(--s3)', wordBreak: 'break-all',
          }}>
            {data.redirectUri}
          </div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 4 }}>
            Must match exactly in the app registration, under platform <strong>Web</strong>. It
            follows the console address ({data.consoleUrl || 'not set'}), which is set on the
            Certificate tab.
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <div className="form-field">
            <label htmlFor="entra_tenant">Directory (tenant) ID</label>
            <input
              id="entra_tenant"
              className="input"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              placeholder="8f4a1c2e-9b7d-4e6a-bc13-5d2f70a9e4c1"
              spellCheck={false}
              autoComplete="off"
            />
          </div>
          <div className="form-field">
            <label htmlFor="entra_client">Application (client) ID</label>
            <input
              id="entra_client"
              className="input"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              placeholder="1b2c3d4e-5f60-4718-9a2b-3c4d5e6f7081"
              spellCheck={false}
              autoComplete="off"
            />
          </div>
          <div className="form-field">
            <label htmlFor="entra_secret">
              Client secret {data.clientSecretSet ? '(a secret is stored)' : '(none stored)'}
            </label>
            <input
              id="entra_secret"
              className="input"
              type="password"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              placeholder={data.clientSecretSet ? 'Leave blank to keep the stored secret' : 'Paste the secret VALUE'}
              spellCheck={false}
              autoComplete="new-password"
            />
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 4 }}>
              {/* ⛔ Said explicitly. The field cannot be pre-filled because the
                  secret is never sent to the browser, so a blank box looks
                  identical to a cleared one. */}
              Never shown again once saved. Leave blank to keep the stored secret; it is only
              replaced when you type a new one. Paste the secret <strong>value</strong>, not its ID.
            </div>
          </div>

          {status ? (
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>{status}</div>
          ) : null}

          <Button variant="primary" onClick={save} disabled={busy} style={{ alignSelf: 'flex-start' }}>
            Save
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}
