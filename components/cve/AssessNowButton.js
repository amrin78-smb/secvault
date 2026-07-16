'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';

// Same pattern as components/devices/DeviceActions.js / RunAnalysisButton.js /
// components/advisories/SyncNowButton.js.
//
// Replaces a `'use server'` action (assessNowAction) wired to a plain
// <form action={...}> with an internalFetch() cookie-forwarding helper calling
// /api/cve/assess directly. Same root cause as Sync Now and the earlier
// Collect Now/Test Connectivity bug: no client JS in front of it meant a
// genuine top-level form navigation with zero pending UI, and
// runMatchForAllDevices() iterating every device's advisories is not
// guaranteed fast as the fleet grows past a handful of devices.
export default function AssessNowButton() {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null); // { ok, text }

  async function handleAssess() {
    if (running) return;
    setRunning(true);
    setResult(null);
    try {
      const res = await fetch('/api/cve/assess', { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) {
        throw new Error(data.error || 'Assessment failed');
      }
      setResult({ ok: true, text: 'Assessment complete.' });
      router.refresh();
    } catch (err) {
      setResult({ ok: false, text: err.message || 'Assessment failed' });
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="flex items-center gap-2">
      <Button type="button" variant="primary" onClick={handleAssess} disabled={running}>
        {running && <LoadingSpinner size={14} />}
        {running ? 'Assessing…' : 'Assess Now'}
      </Button>
      {result && (
        <span className={`text-sm ${result.ok ? 'text-success' : 'text-danger'}`}>{result.text}</span>
      )}
    </div>
  );
}
