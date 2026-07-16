'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

// Compact Collect/Test actions for one row of the devices list table
// (app/(dashboard)/devices/page.js). Same fetch+pending+router.refresh()
// pattern as components/devices/DeviceActions.js (the device detail page's
// version) -- this is a separate component because that page's dense table
// row uses small inline text links ("View"/"Edit"/"Delete"), not full
// <Button> elements, and matching that existing visual style here (rather
// than dropping in full-size buttons) keeps the row from ballooning in height.
//
// Replaces what used to be two 'use server' actions (collectNowAction /
// testConnectivityAction) wired to plain <form action={...}> elements with an
// internalFetch() cookie-forwarding helper -- the same root cause as the
// device-detail-page hang fixed earlier: no client JS in front of them meant
// a genuine top-level form navigation with zero pending UI, on a call that
// can legitimately take up to ~2 minutes on an unreachable device.
export default function DeviceRowActions({ deviceId }) {
  const router = useRouter();
  const [running, setRunning] = useState(null); // 'collect' | 'test' | null
  const [error, setError] = useState(null);

  async function runAction(kind, path) {
    if (running) return;
    setRunning(kind);
    setError(null);
    try {
      const res = await fetch(path, { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) {
        throw new Error(data.error || `${kind === 'collect' ? 'Collect' : 'Test'} failed`);
      }
      router.refresh();
    } catch (err) {
      setError(err.message || `${kind === 'collect' ? 'Collect' : 'Test'} failed`);
    } finally {
      setRunning(null);
    }
  }

  return (
    <>
      <button
        type="button"
        className="text-accent hover:underline disabled:opacity-50"
        disabled={Boolean(running)}
        onClick={() => runAction('collect', `/api/devices/${deviceId}/collect`)}
      >
        {running === 'collect' ? 'Collecting…' : 'Collect'}
      </button>
      <button
        type="button"
        className="text-accent hover:underline disabled:opacity-50"
        disabled={Boolean(running)}
        onClick={() => runAction('test', `/api/devices/${deviceId}/test`)}
      >
        {running === 'test' ? 'Testing…' : 'Test'}
      </button>
      {error && <span className="text-danger" title={error}>⚠</span>}
    </>
  );
}
