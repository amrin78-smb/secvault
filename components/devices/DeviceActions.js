'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';

// Collect Now / Test Connectivity, as real client actions — mirrors the
// pending/spinner/inline-result pattern already used by CredentialForm.js and
// RunAnalysisButton.js.
//
// This replaces what used to be two `'use server'` actions wired to plain
// <form action={...}> elements in devices/[id]/page.js. Those had NO client JS
// wrapping them at all, so the browser did a genuine top-level form
// navigation and just sat there, unresponsive, until the response arrived —
// with zero spinner/toast, because nothing was rendering a pending state.
// That wait is not always short: collectAndStore calls getVersion, getRules
// and getConfig in sequence, and on an unreachable device each one runs to
// its own adapter timeout before the next starts (see CLAUDE.md's adapter
// section — PAN-OS's getConfig alone budgets 120s). A raw form submission has
// no way to show that; a real fetch() does.
export default function DeviceActions({ deviceId }) {
  const router = useRouter();
  const [running, setRunning] = useState(null); // 'collect' | 'test' | null
  const [result, setResult] = useState(null); // { ok, text }

  async function runAction(kind, path) {
    if (running) return;
    setRunning(kind);
    setResult(null);
    try {
      const res = await fetch(path, { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) {
        throw new Error(data.error || `${kind === 'collect' ? 'Collect' : 'Test'} failed`);
      }
      if (kind === 'test') {
        setResult({
          ok: data.ok === true,
          text: data.message || (data.ok ? 'Connected' : 'Connection failed'),
        });
      } else {
        const errCount = Array.isArray(data.errors) ? data.errors.length : 0;
        setResult({
          ok: errCount === 0,
          text:
            errCount === 0
              ? `Collected — ${data.rulesCount ?? 0} rules.`
              : `Collected with ${errCount} error(s): ${data.errors[0]}`,
        });
      }
      router.refresh();
    } catch (err) {
      setResult({ ok: false, text: err.message || `${kind === 'collect' ? 'Collect' : 'Test'} failed` });
    } finally {
      setRunning(null);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button
        type="button"
        variant="secondary"
        onClick={() => runAction('collect', `/api/devices/${deviceId}/collect`)}
        disabled={Boolean(running)}
      >
        {running === 'collect' && <LoadingSpinner size={14} />}
        {running === 'collect' ? 'Collecting…' : 'Collect Now'}
      </Button>
      <Button
        type="button"
        variant="secondary"
        onClick={() => runAction('test', `/api/devices/${deviceId}/test`)}
        disabled={Boolean(running)}
      >
        {running === 'test' && <LoadingSpinner size={14} />}
        {running === 'test' ? 'Testing…' : 'Test Connectivity'}
      </Button>
      {result && (
        <span className={`text-sm ${result.ok ? 'text-success' : 'text-danger'}`}>{result.text}</span>
      )}
      {running && (
        <span className="text-xs text-text-muted">
          This can take up to a couple of minutes on an unreachable device.
        </span>
      )}
    </div>
  );
}
