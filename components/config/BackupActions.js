'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Button from '../ui/Button';

// Creates a manual config backup, then refreshes the server component page so
// the new row shows up in the server-queried backups table.
export default function BackupActions({ deviceId }) {
  const router = useRouter();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  async function handleCreateBackup() {
    if (saving) return;
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`/api/devices/${deviceId}/backups`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label: 'manual' }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Failed to create backup');
      }
      router.refresh();
    } catch (err) {
      setError(err.message || 'Failed to create backup');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button type="button" onClick={handleCreateBackup} disabled={saving}>
        {saving ? 'Creating…' : 'Create backup'}
      </Button>
      {error && <span className="text-sm text-danger">{error}</span>}
    </div>
  );
}
