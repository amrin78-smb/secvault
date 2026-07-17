'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';

// Client action button for "run an on-demand compliance audit" -- mirrors
// components/analysis/RunAnalysisButton.js's exact idiom (same disabled +
// spinner while in flight, router.refresh() on success so the server
// component re-queries findings, inline error text on failure). Posts to
// the frozen contract: POST /api/compliance/[deviceId]/run (no body) ->
// 200 JSON { deviceId, ranAt, findings } or { error }.
export default function RunAuditButton({ deviceId }) {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);

  async function handleRun() {
    if (running) return;
    setRunning(true);
    setError(null);
    try {
      const res = await fetch(`/api/compliance/${deviceId}/run`, { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) {
        throw new Error(data.error || 'Compliance audit failed');
      }
      router.refresh();
    } catch (err) {
      setError(err.message || 'Compliance audit failed');
    } finally {
      setRunning(false);
    }
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <Button type="button" variant="primary" onClick={handleRun} disabled={running}>
        {running && <LoadingSpinner size={14} />}
        {running ? 'Running…' : 'Run Audit'}
      </Button>
      {error && <span style={{ fontSize: 'var(--text-sm)', color: 'var(--red)' }}>{error}</span>}
    </div>
  );
}
