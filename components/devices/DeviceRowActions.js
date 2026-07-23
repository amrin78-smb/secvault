'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import RowActionsMenu from '../ui/RowActionsMenu';

// Devices-list row actions (app/(dashboard)/devices/page.js) -- View +
// Collect + Test + Delete, consolidated into one "⋮" overflow menu.
//
// ⛔ Changed 2026-07-24 (UI audit): this used to render Collect/Test as two
// small underlined text links sitting inline next to a separately-built
// View link and (conditionally) a Delete link in the page's own JSX -- four
// stacked underlined links per row, wrapping to 2 lines, all in the same
// brand-red color regardless of what they actually did. Consolidated here
// so the page only needs to render <DeviceRowActions deviceId sortKey
// canWrite />; View is always offered (read-only, safe for a viewer
// session), Collect/Test/Delete only when canWrite -- same permission
// shape this component already had, just centralized instead of split
// between here and the page.
export default function DeviceRowActions({ deviceId, sortKey, canWrite }) {
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

  const actions = [{ type: 'link', label: 'View', href: `/devices/${deviceId}` }];

  if (canWrite) {
    actions.push(
      {
        type: 'button',
        label: 'Collect Now',
        pending: running === 'collect',
        pendingLabel: 'Collecting…',
        disabled: Boolean(running),
        onClick: () => runAction('collect', `/api/devices/${deviceId}/collect`),
      },
      {
        type: 'button',
        label: 'Test Connectivity',
        pending: running === 'test',
        pendingLabel: 'Testing…',
        disabled: Boolean(running),
        onClick: () => runAction('test', `/api/devices/${deviceId}/test`),
      },
      {
        type: 'link',
        label: 'Delete',
        href: `/devices?sort=${sortKey}&confirmDelete=${deviceId}`,
        danger: true,
      }
    );
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <RowActionsMenu actions={actions} />
      {error && (
        <span style={{ color: 'var(--red)', fontSize: 'var(--text-xs)' }} title={error}>
          ⚠
        </span>
      )}
    </div>
  );
}
