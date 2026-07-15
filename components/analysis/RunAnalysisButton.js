'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';

// Client action button mirroring components/devices/CredentialForm.js:
// POST /api/devices/[id]/analysis (contract: 200 JSON {findings, byType} or {error}),
// disabled + spinner while the run is in flight, then router.refresh() so the
// server component re-queries findings. Errors render as inline text.
export default function RunAnalysisButton({ deviceId }) {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);

  async function handleRun() {
    if (running) return;
    setRunning(true);
    setError(null);
    try {
      const res = await fetch(`/api/devices/${deviceId}/analysis`, { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) {
        throw new Error(data.error || 'Analysis failed');
      }
      router.refresh();
    } catch (err) {
      setError(err.message || 'Analysis failed');
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="flex items-center gap-2">
      <Button type="button" variant="primary" onClick={handleRun} disabled={running}>
        {running && <LoadingSpinner size={14} />}
        {running ? 'Running…' : 'Run Analysis'}
      </Button>
      {error && <span className="text-sm text-danger">{error}</span>}
    </div>
  );
}
