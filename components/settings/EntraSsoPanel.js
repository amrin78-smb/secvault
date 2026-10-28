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
//
// ⛔ AND BECAUSE BLANK MEANS KEEP, THERE MUST BE AN EXPLICIT WAY TO CLEAR. Both
// of them are here and neither can be reached by emptying a box:
//
//   "Remove the stored secret"     sends clientSecret: ''   (the secret alone)
//   "Turn off single sign-on"      sends all three blank    (the whole feature)
//
// This panel used to say "Leave the fields blank to turn it off", which was
// FALSE: the save handler omitted `clientSecret` whenever the box was blank, so
// the one body the API accepts as a disable instruction could not be produced,
// and an administrator decommissioning a tenant was answered "The Directory
// (tenant) ID must be a GUID" — an instruction to put back the value they had
// just removed, with no path to off except RDP into the server. That was the
// exact problem this panel was built to remove.

import { useState, useEffect, useCallback } from 'react';
import Card, { CardBody, CardHeader } from '../ui/Card';
import Button from '../ui/Button';

/**
 * The body the "Turn off single sign-on" control sends.
 *
 * ⛔ IT IS A MODULE CONSTANT, NOT A LITERAL INSIDE A HANDLER, SO A TEST CAN
 * FEED IT TO THE ROUTE'S OWN PLANNER. The defect this replaces was pure
 * REACHABILITY: `disabling` at the API, its `disabled:true` response, its
 * `entra_sso_disabled` audit action and this panel's own cleared-status string
 * were all correct and all unreachable, because the only body that satisfied
 * them could not be produced by the form. That is the repo's v2.193.0 pattern
 * again — the mechanism worked, nothing could get to it — and the test that
 * catches it has to assert the END STATE, not that the branch exists.
 */
export const ENTRA_DISABLE_PAYLOAD = { tenantId: '', clientId: '', clientSecret: '' };

/**
 * The body a Save sends, from the form's own state.
 *
 * ⛔ THE THREE-WAY SECRET SEMANTICS LIVE HERE AND NOWHERE ELSE. `clientSecret`
 * is OMITTED to keep the stored value — which is what a blank box must always
 * mean, because the box cannot be pre-filled from a write-only value — set to
 * '' only on the explicit "remove the stored secret" tick, and otherwise
 * carries the typed value.
 */
export function entraSavePayload({ tenantId, clientId, clientSecret, clearSecret }) {
  const payload = { tenantId, clientId };
  if (clearSecret) payload.clientSecret = '';
  else if (clientSecret !== '') payload.clientSecret = clientSecret;
  return payload;
}

export default function EntraSsoPanel() {
  const [data, setData] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [tenantId, setTenantId] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  // ⛔ EXPLICIT INTENT, NOT AN EMPTY BOX. An empty secret box means "keep what
  // is stored" and always will; this is the only thing that can mean "remove
  // it".
  const [clearSecret, setClearSecret] = useState(false);
  const [confirmOff, setConfirmOff] = useState(false);
  const [status, setStatus] = useState('');
  // 'ok' | 'bad' | '' — a failed save must not read in the same colour as a
  // successful one, which is what a single grey status line did.
  const [statusTone, setStatusTone] = useState('');
  const [partial, setPartial] = useState(null);
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

  /**
   * One submit path for every change, including the two explicit clears, so
   * there is no second place for the three-way secret semantics to drift.
   *
   * `secret` is passed as `undefined` to KEEP the stored value, '' to clear it,
   * or a string to replace it.
   */
  async function submit(payload) {
    setBusy(true);
    setStatus('');
    setStatusTone('');
    setPartial(null);
    try {
      const res = await fetch('/api/system/entra', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setStatus(body.error || `HTTP ${res.status}`);
        setStatusTone('bad');
        // ⛔ THE PARTIAL STATE IS SHOWN, because the person reading this is the
        // one who has to recover from it. The route used to return `written` on
        // the 500 path and this panel rendered `body.error` alone, so even a
        // real failure did not say which keys had landed.
        if (Array.isArray(body.writtenFields) && body.writtenFields.length > 0) {
          setPartial({ fields: body.writtenFields, ssoDisabled: Boolean(body.ssoDisabled) });
        }
      } else {
        setStatus(body.message || 'Saved. Restart SecVault-App to apply.');
        setStatusTone('ok');
        setClientSecret('');
        setClearSecret(false);
        setConfirmOff(false);
      }
      await load();
    } catch (err) {
      setStatus(err.message || String(err));
      setStatusTone('bad');
    } finally {
      setBusy(false);
    }
  }

  function save() {
    return submit(entraSavePayload({ tenantId, clientId, clientSecret, clearSecret }));
  }

  function turnOff() {
    // ⛔ ALL THREE BLANK, EXPLICITLY — the only body the API treats as a
    // disable, and the only way to reach it.
    return submit(ENTRA_DISABLE_PAYLOAD);
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

  // ⛔ THE ROUTE DECIDES THIS, NOT THE PANEL, AND THAT IS THE FIX. This used to
  // be `savedConfigured !== data.runningConfigured` — boolean against boolean —
  // and both are true whenever Entra is already live, so any EDIT to a
  // configured tenant showed no banner at all. The failure that mattered was
  // the routine secret rotation: the new secret saved, no banner, and the
  // running process still presenting the REVOKED secret to Microsoft while the
  // panel implied the change was in force. The comparison needs the secret
  // values, and the secret may not be sent to the browser, so it is made on the
  // server and only the field LABELS come back.
  const pendingRestart = Boolean(data.restartPending);
  const pendingFields = Array.isArray(data.restartPendingFields) ? data.restartPendingFields : [];
  const anythingStored = Boolean(data.tenantId || data.clientId || data.clientSecretSet);

  return (
    <Card>
      <CardHeader>Entra ID single sign-on</CardHeader>
      <CardBody>
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 'var(--s4)' }}>
          Optional. Local accounts always keep working, with or without this, and continue to work
          if Microsoft is unreachable. Use <strong>Turn off single sign-on</strong> below to switch
          it off — clearing the boxes does not, because a blank secret box means &ldquo;keep the
          secret already stored&rdquo;.
        </div>

        {pendingRestart ? (
          <div style={{
            background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)',
            padding: 'var(--s3)', borderRadius: 'var(--radius-sm)',
            fontSize: 'var(--text-sm)', lineHeight: 1.6, marginBottom: 'var(--s4)',
          }}>
            <strong>Saved, but not yet in force.</strong> SecVault reads these values once, when it
            starts. Restart the <code>SecVault-App</code> service to apply them.
            {pendingFields.length > 0 ? (
              <div style={{ marginTop: 4 }}>
                Waiting on a restart: {pendingFields.join(', ')}.
              </div>
            ) : null}
          </div>
        ) : null}

        {/* ⛔ REFUSED SIGN-INS, SHOWN BESIDE THE SETTINGS THAT CAUSE THEM.
            Without this an operator meets "No Role" in the header and has
            nothing to act on — the reason existed but only on the token. The
            three causes need three different fixes (the claim is missing from
            the ID token / the user is in no mapped group / too many group
            memberships), so naming which one it was is the whole value.
            ⛔ TIME-BOUNDED BY THE ROUTE, so a problem that has been fixed stops
            being reported instead of leaving a permanent amber panel. */}
        {data.refusalState === 'some' && (data.refusals || []).length > 0 ? (
          <div style={{
            background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)',
            padding: 'var(--s3)', borderRadius: 'var(--radius-sm)',
            marginBottom: 'var(--s4)',
          }}>
            <div style={{ fontWeight: 600, marginBottom: 'var(--s2)', fontSize: 'var(--text-sm)' }}>
              Refused sign-ins in the last {data.refusalWindowDays || 7} days
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

        {/* ⛔ HUELESS, NOT AMBER. "We could not read the activity log" is a gap
            in OUR evidence, not a severity — and it must not look like the
            all-clear that an empty list used to produce for both cases. */}
        {data.refusalState === 'unknown' ? (
          <div style={{
            border: '1px dashed var(--border)', color: 'var(--unmeasured)',
            padding: 'var(--s3)', borderRadius: 'var(--radius-sm)',
            fontSize: 'var(--text-sm)', lineHeight: 1.6, marginBottom: 'var(--s4)',
          }}>
            {data.refusalNote || 'Recent refused sign-ins could not be read.'}
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

        <div className="form-grid">
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
          {/* ⛔ SPANS BOTH COLUMNS. Its hint is a full sentence about what blank
              means, and halving the field would wrap that into four lines
              beside an empty cell. */}
          <div className="form-field span-2">
            <label htmlFor="entra_secret">
              Client secret {data.clientSecretSet ? '(a secret is stored)' : '(none stored)'}
            </label>
            <input
              id="entra_secret"
              className="input"
              type="password"
              value={clearSecret ? '' : clientSecret}
              disabled={clearSecret}
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
              Surrounding spaces and line breaks are stripped — a pasted trailing newline is
              harmless.
            </div>
            {data.clientSecretSet ? (
              <label style={{
                display: 'flex', alignItems: 'center', gap: 8,
                fontSize: 'var(--text-sm)', marginTop: 'var(--s2)',
              }}>
                <input
                  type="checkbox"
                  checked={clearSecret}
                  onChange={(e) => setClearSecret(e.target.checked)}
                />
                Remove the stored secret (single sign-on stops until a new one is saved)
              </label>
            ) : null}
          </div>

          {partial ? (
            <div className="span-2" style={{
              background: 'var(--tint-danger)', color: 'var(--tint-danger-fg)',
              padding: 'var(--s3)', borderRadius: 'var(--radius-sm)',
              fontSize: 'var(--text-sm)', lineHeight: 1.6,
            }}>
              <strong>{partial.ssoDisabled
                ? 'Part-finished — single sign-on is now off.'
                : 'Part-finished.'}</strong>{' '}
              These values were written before the failure: {partial.fields.join(', ')}.
            </div>
          ) : null}

          {status ? (
            <div
              className="span-2"
              style={{
                fontSize: 'var(--text-sm)',
                lineHeight: 1.6,
                color: statusTone === 'bad' ? 'var(--sev-crit)' : 'var(--text-secondary)',
              }}
            >
              {status}
            </div>
          ) : null}

          <div className="span-2" style={{ display: 'flex', gap: 'var(--s3)', alignItems: 'center' }}>
            <Button variant="primary" onClick={save} disabled={busy}>
              Save
            </Button>
            {/* ⛔ TWO STEPS, AND ONLY WHEN SOMETHING IS STORED. Turning this off
                is not destructive to any firewall data, but it does remove
                every directory user's way in, so it is not one click away from
                a Save button. */}
            {anythingStored ? (
              confirmOff ? (
                <>
                  <Button variant="danger" onClick={turnOff} disabled={busy}>
                    Confirm: turn off single sign-on
                  </Button>
                  <Button variant="secondary" onClick={() => setConfirmOff(false)} disabled={busy}>
                    Cancel
                  </Button>
                </>
              ) : (
                <Button variant="secondary" onClick={() => setConfirmOff(true)} disabled={busy}>
                  Turn off single sign-on
                </Button>
              )
            ) : null}
          </div>
        </div>
      </CardBody>
    </Card>
  );
}
