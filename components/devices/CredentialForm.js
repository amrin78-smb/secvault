'use client';

import { useState } from 'react';
import Button from '../ui/Button';
import { VENDOR_META, buildCredentialPlaintext } from './vendorMeta';

const inputClasses =
  'rounded border border-border bg-bg-base px-2 py-1.5 text-sm text-text-primary focus:border-accent focus:outline-none';

// Reusable piece for rotating the stored credential on an existing device.
// PUTs { credential, credential_type } to /api/devices/[id] — the route handler
// routes those values through credStore instead of writing them to the devices table.
//
// `vendor` defaults to 'forcepoint' for backward compatibility — the existing call
// site (device detail page) passes only deviceId today.
export default function CredentialForm({ deviceId, vendor = 'forcepoint' }) {
  const meta = VENDOR_META[vendor] || VENDOR_META.forcepoint;
  const isSecretShape = meta.credentialShape === 'secret';
  const hasEnable = meta.credentialShape === 'userpass_enable';

  const [secret, setSecret] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [enablePassword, setEnablePassword] = useState('');
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState(null); // { ok, text }

  const ready = isSecretShape ? Boolean(secret) : Boolean(username && password);

  async function handleSave() {
    if (!ready || saving) return;
    setSaving(true);
    setResult(null);
    try {
      const plaintext = buildCredentialPlaintext(vendor, {
        secret,
        username,
        password,
        enablePassword,
      });
      const res = await fetch(`/api/devices/${deviceId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: plaintext, credential_type: meta.credentialType }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Failed to save credential');
      }
      setResult({ ok: true, text: isSecretShape ? `${meta.secretLabel} updated.` : 'Credentials updated.' });
      setSecret('');
      setUsername('');
      setPassword('');
      setEnablePassword('');
    } catch (err) {
      setResult({ ok: false, text: err.message || 'Failed to save credential' });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      {isSecretShape ? (
        <input
          type="password"
          autoComplete="new-password"
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          placeholder={`New ${meta.secretLabel}`}
          className={inputClasses}
        />
      ) : (
        <>
          <input
            type="text"
            autoComplete="off"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Username"
            className={inputClasses}
          />
          <input
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
            className={inputClasses}
          />
          {hasEnable && (
            <input
              type="password"
              autoComplete="new-password"
              value={enablePassword}
              onChange={(e) => setEnablePassword(e.target.value)}
              placeholder="Enable password (optional)"
              className={inputClasses}
            />
          )}
        </>
      )}
      <Button type="button" variant="secondary" onClick={handleSave} disabled={saving || !ready}>
        {saving ? 'Saving…' : isSecretShape ? `Update ${meta.secretLabel}` : 'Update Credentials'}
      </Button>
      {result && (
        <span className={`text-sm ${result.ok ? 'text-success' : 'text-danger'}`}>{result.text}</span>
      )}
    </div>
  );
}
