'use client';

import { useState } from 'react';
import Button from '../ui/Button';

// Smaller reusable piece for rotating just the SMC API key on an existing device.
// PUTs { smc_api_key } to /api/devices/[id] — the route handler routes that value
// through credStore instead of writing it to the devices table.
export default function CredentialForm({ deviceId }) {
  const [apiKey, setApiKey] = useState('');
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState(null); // { ok, text }

  async function handleSave() {
    if (!apiKey || saving) return;
    setSaving(true);
    setResult(null);
    try {
      const res = await fetch(`/api/devices/${deviceId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ smc_api_key: apiKey }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Failed to save credential');
      }
      setResult({ ok: true, text: 'API key updated.' });
      setApiKey('');
    } catch (err) {
      setResult({ ok: false, text: err.message || 'Failed to save credential' });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <input
        type="password"
        autoComplete="new-password"
        value={apiKey}
        onChange={(e) => setApiKey(e.target.value)}
        placeholder="New SMC API key"
        className="rounded border border-border bg-bg-base px-2 py-1.5 text-sm text-text-primary focus:border-accent focus:outline-none"
      />
      <Button type="button" variant="secondary" onClick={handleSave} disabled={saving || !apiKey}>
        {saving ? 'Saving…' : 'Update API Key'}
      </Button>
      {result && (
        <span className={`text-sm ${result.ok ? 'text-success' : 'text-danger'}`}>{result.text}</span>
      )}
    </div>
  );
}
