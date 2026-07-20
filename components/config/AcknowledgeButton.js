'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Button from '../ui/Button';

// Marks one config diff as acknowledged via PUT, then refreshes the server
// component page so the acknowledged badge (queried server-side) appears.
// An optional reason note travels alongside — same idea as
// cve_assessment_acknowledgements' existing optional `note` field, just not
// previously available for config diffs.
export default function AcknowledgeButton({ deviceId, diffId }) {
  const router = useRouter();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [note, setNote] = useState('');
  const [showNote, setShowNote] = useState(false);

  async function handleAcknowledge() {
    if (saving) return;
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`/api/devices/${deviceId}/diffs/${diffId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: note.trim() || undefined }),
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
    <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 6, alignItems: 'flex-start' }}>
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
        <Button type="button" variant="secondary" onClick={handleAcknowledge} disabled={saving}>
          {saving ? 'Acknowledging…' : 'Acknowledge'}
        </Button>
        {!showNote && (
          <button
            type="button"
            onClick={() => setShowNote(true)}
            style={{
              background: 'none',
              border: 'none',
              padding: 0,
              fontSize: 'var(--text-xs)',
              color: 'var(--text-muted)',
              textDecoration: 'underline',
              cursor: 'pointer',
            }}
          >
            + add note
          </button>
        )}
        {error && <span style={{ fontSize: 'var(--text-base)', color: 'var(--red)' }}>{error}</span>}
      </span>
      {showNote && (
        <input
          type="text"
          className="input"
          placeholder="Optional reason (e.g. change ticket #, planned maintenance)"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          disabled={saving}
          style={{ fontSize: 'var(--text-sm)', minWidth: 280 }}
        />
      )}
    </span>
  );
}
