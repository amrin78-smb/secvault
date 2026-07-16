'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';

// Same pattern as components/devices/DeviceActions.js / RunAnalysisButton.js.
//
// This replaces what used to be a `'use server'` action (syncNowAction) wired to
// a plain <form action={...}>, with an internalFetch() cookie-forwarding helper
// calling runFullSync() directly on the server. That had no client JS in front
// of it at all -- clicking it did a genuine top-level form navigation with zero
// pending UI, and just sat there until the sync finished. That wait is not
// always short: runFullSync() runs NVD queries across all 6 vendor CPE strings
// (NVD rate-limits to 1 request per 6s without an API key) plus a KEV download,
// so a full sync can legitimately take well over a minute now that the fleet
// covers more than just Forcepoint. A raw form submission has no way to show
// that; a real fetch() does.
export default function SyncNowButton() {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null); // { ok, text }

  async function handleSync() {
    if (running) return;
    setRunning(true);
    setResult(null);
    try {
      const res = await fetch('/api/feeds/sync', { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) {
        throw new Error(data.error || 'Sync failed');
      }
      setResult({ ok: true, text: 'Sync complete.' });
      router.refresh();
    } catch (err) {
      setResult({ ok: false, text: err.message || 'Sync failed' });
    } finally {
      setRunning(false);
    }
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <Button type="button" variant="primary" onClick={handleSync} disabled={running}>
        {running && <LoadingSpinner size={14} />}
        {running ? 'Syncing…' : 'Sync Now'}
      </Button>
      {result && (
        <span style={{ fontSize: 'var(--text-base)', color: result.ok ? 'var(--green)' : 'var(--red)' }}>
          {result.text}
        </span>
      )}
      {running && (
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          Can take a minute or more (NVD is rate-limited).
        </span>
      )}
    </div>
  );
}
