'use client';

import { useState } from 'react';
import Button from '../ui/Button';
import { VENDOR_META, buildCredentialPlaintext, resolveAccessMethod } from './vendorMeta';

const inputClasses =
  'rounded border border-border bg-bg-base px-2 py-1.5 text-sm text-text-primary focus:border-accent focus:outline-none';

const AUTH_MODE_OPTIONS = [
  { value: 'apikey', label: 'API Key / Token' },
  { value: 'userpass', label: 'Username & Password' },
];

// Reusable piece for rotating the stored credential on an existing device.
// PUTs { credential, credential_type } to /api/devices/[id] — the route handler
// routes those values through credStore instead of writing them to the devices table.
//
// `mgmtMethod` MUST be the device's STORED devices.mgmt_method, not a value
// re-derived from the vendor. A fortinet device saved as ssh and a fortinet
// device saved as api need different credential shapes ('userpass' vs
// 'apikey_or_userpass'); deriving from the vendor alone would always produce the
// vendor's DEFAULT method's shape and would happily write an API-shaped
// credential over an SSH device's — which fails only later, at connect time.
// resolveAccessMethod tolerates null/unknown (legacy rows predating the
// selector) by falling back to the vendor default, matching adapter dispatch.
//
// `vendor` defaults to 'forcepoint' for backward compatibility.
export default function CredentialForm({ deviceId, vendor = 'forcepoint', mgmtMethod = null }) {
  const resolved =
    resolveAccessMethod(vendor, mgmtMethod) || resolveAccessMethod('forcepoint', null);
  const { method, config } = resolved;

  const shape = config.credentialShape;
  const isSecretShape = shape === 'secret';
  const isApiKeyOrUserPass = shape === 'apikey_or_userpass';
  const hasEnable = shape === 'userpass_enable';

  const [authMode, setAuthMode] = useState('apikey');
  const [secret, setSecret] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [enablePassword, setEnablePassword] = useState('');
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState(null); // { ok, text }

  const showSecretInput = isSecretShape || (isApiKeyOrUserPass && authMode === 'apikey');
  const ready = showSecretInput ? Boolean(secret) : Boolean(username && password);

  async function handleSave() {
    if (!ready || saving) return;
    setSaving(true);
    setResult(null);
    try {
      const plaintext = buildCredentialPlaintext(vendor, method, {
        authMode,
        secret,
        username,
        password,
        enablePassword,
      });
      const res = await fetch(`/api/devices/${deviceId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        // No mgmt_method is sent — rotating a credential must never change the
        // device's access method. The server re-derives credential_type from
        // the vendor + the device's stored mgmt_method.
        body: JSON.stringify({ credential: plaintext, credential_type: config.credentialType }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Failed to save credential');
      }
      setResult({
        ok: true,
        text: showSecretInput ? `${config.secretLabel} updated.` : 'Credentials updated.',
      });
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
      {isApiKeyOrUserPass && (
        <select
          aria-label="Authentication mode"
          value={authMode}
          onChange={(e) => {
            setAuthMode(e.target.value);
            setSecret('');
            setUsername('');
            setPassword('');
            setResult(null);
          }}
          className={inputClasses}
        >
          {AUTH_MODE_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      )}

      {showSecretInput ? (
        <input
          type="password"
          autoComplete="new-password"
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          placeholder={`New ${config.secretLabel}`}
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
        {saving ? 'Saving…' : showSecretInput ? `Update ${config.secretLabel}` : 'Update Credentials'}
      </Button>
      {result && (
        <span className={`text-sm ${result.ok ? 'text-success' : 'text-danger'}`}>{result.text}</span>
      )}
    </div>
  );
}
