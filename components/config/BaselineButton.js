'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Button from '../ui/Button';

// Designates (or clears) a device_configs row as that device's known-good
// baseline, then refreshes the server component page so the Baseline Drift
// card re-renders against the new baseline.
//
// Same action->refresh pattern as components/config/BackupActions.js. The
// route (PUT /api/devices/[id]/configs/[configId]/baseline) is admin-gated
// server-side; the page only renders this for admins so a viewer never gets a
// surprise 403.
export default function BaselineButton({ deviceId, configId, isBaseline }) {
  const router = useRouter();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  async function handleClick() {
    if (saving) return;
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`/api/devices/${deviceId}/configs/${configId}/baseline`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ baseline: !isBaseline }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Failed to update baseline');
      }
      router.refresh();
    } catch (err) {
      setError(err.message || 'Failed to update baseline');
    } finally {
      setSaving(false);
    }
  }

  const label = isBaseline ? 'Clear baseline' : 'Set as baseline';

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
      <Button type="button" variant="secondary" onClick={handleClick} disabled={saving}>
        {saving ? 'Saving…' : label}
      </Button>
      {error && <span style={{ fontSize: 'var(--text-base)', color: 'var(--red)' }}>{error}</span>}
    </div>
  );
}
