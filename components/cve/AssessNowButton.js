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
      // /api/cve/assess can return 200 OK with a per-device `errors` array
      // (runMatchForAllDevices in lib/engines/versionMatcher.js) when some
      // devices' assessment succeeded and others failed -- that's distinct
      // from the top-level `error` field checked above, which only appears
      // when the whole call threw (500). Surface partial failures instead of
      // reporting a blanket success.
      if (Array.isArray(data.errors) && data.errors.length > 0) {
        const deviceIds = data.errors.map((e) => e.device_id).filter(Boolean).join(', ');
        setResult({
          ok: false,
          text: `Assessment completed with ${data.errors.length} error(s)${deviceIds ? ` (device: ${deviceIds})` : ''}.`,
        });
      } else {
        setResult({ ok: true, text: 'Assessment complete.' });
      }
      router.refresh();
    } catch (err) {
      setResult({ ok: false, text: err.message || 'Assessment failed' });
    } finally {
      setRunning(false);
    }
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <Button type="button" variant="primary" onClick={handleAssess} disabled={running}>
        {running && <LoadingSpinner size={14} />}
        {running ? 'Assessing…' : 'Assess Now'}
      </Button>
      {result && (
        <span style={{ fontSize: 'var(--text-sm)', color: result.ok ? 'var(--green)' : 'var(--red)' }}>
          {result.text}
        </span>
      )}
    </div>
  );
}
