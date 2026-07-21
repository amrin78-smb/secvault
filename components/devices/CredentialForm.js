'use client';

import { useState, useEffect } from 'react';
import Button from '../ui/Button';
import { VENDOR_META, buildCredentialPlaintext, resolveAccessMethod } from './vendorMeta';

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

  // Saved connection-profile picker (ManageEngine parity). Deliberately NOT
  // offered for the 'secret' shape (Forcepoint SMC) — see `isSecretShape` gate
  // below and DeviceForm.js's identical scope note for why.
  const [profiles, setProfiles] = useState([]);
  const [selectedProfileId, setSelectedProfileId] = useState('');
  const [saveAsProfile, setSaveAsProfile] = useState(false);
  const [newProfileName, setNewProfileName] = useState('');

  useEffect(() => {
    fetch('/api/credential-profiles')
      .then((res) => (res.ok ? res.json() : { profiles: [] }))
      .then((data) => setProfiles(Array.isArray(data.profiles) ? data.profiles : []))
      .catch(() => setProfiles([]));
  }, []);

  // Recomputed on every render — cheap, and `profiles` only ever changes once
  // (the mount-time fetch), so there's no benefit to memoizing this.
  const matchingProfiles = profiles.filter((p) => p.credential_type === config.credentialType);

  const showSecretInput = isSecretShape || (isApiKeyOrUserPass && authMode === 'apikey');
  const ready = selectedProfileId
    ? true
    : showSecretInput
      ? Boolean(secret)
      : Boolean(username && password);

  function resetProfilePicker() {
    setSelectedProfileId('');
    setSaveAsProfile(false);
    setNewProfileName('');
  }

  async function handleSave() {
    if (!ready || saving) return;
    setSaving(true);
    setResult(null);
    try {
      const body = selectedProfileId
        ? { credential_profile_id: selectedProfileId }
        : {
            credential: buildCredentialPlaintext(vendor, method, {
              authMode,
              secret,
              username,
              password,
              enablePassword,
            }),
            credential_type: config.credentialType,
            ...(saveAsProfile && newProfileName.trim()
              ? { save_as_profile_name: newProfileName.trim() }
              : {}),
          };
      const res = await fetch(`/api/devices/${deviceId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        // No mgmt_method is sent — rotating a credential must never change the
        // device's access method. The server re-derives credential_type from
        // the vendor + the device's stored mgmt_method.
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || 'Failed to save credential');
      }
      setResult({
        ok: true,
        text: data.warning || (showSecretInput ? `${config.secretLabel} updated.` : 'Credentials updated.'),
      });
      setSecret('');
      setUsername('');
      setPassword('');
      setEnablePassword('');
      resetProfilePicker();
    } catch (err) {
      setResult({ ok: false, text: err.message || 'Failed to save credential' });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
      {!isSecretShape && (
        <select
          aria-label="Use saved profile"
          value={selectedProfileId}
          onChange={(e) => {
            setSelectedProfileId(e.target.value);
            setSaveAsProfile(false);
            setNewProfileName('');
            setResult(null);
          }}
          className="input"
          style={{ width: 'auto' }}
        >
          <option value="">— Enter credentials manually —</option>
          {matchingProfiles.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
              {p.username ? ` — ${p.username}` : ''}
            </option>
          ))}
        </select>
      )}

      {!selectedProfileId && isApiKeyOrUserPass && (
        <select
          aria-label="Authentication mode"
          value={authMode}
          onChange={(e) => {
            setAuthMode(e.target.value);
            setSecret('');
            setUsername('');
            setPassword('');
            setResult(null);
            resetProfilePicker();
          }}
          className="input"
          style={{ width: 'auto' }}
        >
          {AUTH_MODE_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      )}

      {!selectedProfileId &&
        (showSecretInput ? (
          <input
            type="password"
            autoComplete="new-password"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder={`New ${config.secretLabel}`}
            className="input"
            style={{ width: 'auto' }}
          />
        ) : (
          <>
            <input
              type="text"
              autoComplete="off"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              className="input"
              style={{ width: 'auto' }}
            />
            <input
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              className="input"
              style={{ width: 'auto' }}
            />
            {hasEnable && (
              <input
                type="password"
                autoComplete="new-password"
                value={enablePassword}
                onChange={(e) => setEnablePassword(e.target.value)}
                placeholder="Enable password (optional)"
                className="input"
                style={{ width: 'auto' }}
              />
            )}
          </>
        ))}

      {!selectedProfileId && (
        <label
          style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}
        >
          <input
            type="checkbox"
            checked={saveAsProfile}
            onChange={(e) => setSaveAsProfile(e.target.checked)}
          />
          Save as profile
        </label>
      )}
      {!selectedProfileId && saveAsProfile && (
        <input
          type="text"
          placeholder="Profile name"
          value={newProfileName}
          onChange={(e) => setNewProfileName(e.target.value)}
          className="input"
          style={{ width: 'auto' }}
        />
      )}

      <Button type="button" variant="secondary" onClick={handleSave} disabled={saving || !ready}>
        {saving ? 'Saving…' : showSecretInput ? `Update ${config.secretLabel}` : 'Update Credentials'}
      </Button>
      {result && (
        <span style={{ fontSize: 'var(--text-base)', color: result.ok ? 'var(--green)' : 'var(--red)' }}>
          {result.text}
        </span>
      )}
    </div>
  );
}
