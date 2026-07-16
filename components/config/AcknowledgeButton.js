'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Button from '../ui/Button';

// Marks one config diff as acknowledged via PUT, then refreshes the server
// component page so the acknowledged badge (queried server-side) appears.
export default function AcknowledgeButton({ deviceId, diffId }) {
  const router = useRouter();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  async function handleAcknowledge() {
    if (saving) return;
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`/api/devices/${deviceId}/diffs/${diffId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Failed to acknowledge change');
      }
      router.refresh();
    } catch (err) {
      setError(err.message || 'Failed to acknowledge change');
    } finally {
      setSaving(false);
    }
  }

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
      <Button type="button" variant="secondary" onClick={handleAcknowledge} disabled={saving}>
        {saving ? 'Acknowledging…' : 'Acknowledge'}
      </Button>
      {error && <span style={{ fontSize: 'var(--text-base)', color: 'var(--red)' }}>{error}</span>}
    </span>
  );
}
