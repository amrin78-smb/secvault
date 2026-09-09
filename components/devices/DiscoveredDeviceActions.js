'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';

// Per-row actions on /devices/discovered. Same fetch + pending + refresh
// pattern as DeviceActions.js / CredentialForm.js.
//
// ⛔ The two kinds get DIFFERENT primary actions, and that asymmetry is the
// safety property of the whole feature:
//
//   unmanaged  -> "Add to inventory", which goes to the normal Add Device form
//                 with the OBSERVED fields prefilled. It cannot complete
//                 without credentials, so nothing enters the fleet denominators
//                 on the strength of an unauthenticated syslog packet.
//   ha-peer    -> "Link to <device>", which files the address against a device
//                 that already exists. Offering Promote here would invite the
//                 operator to duplicate a firewall they already manage.
//
// ⛔ These controls are hidden from viewers by the caller as defence in depth
// only — the real gate is isAdmin() in each route (lib/rbac.js).
export default function DiscoveredDeviceActions({
  id,
  kind,
  sourceIp,
  hostname,
  vendor,
  deviceId,
  deviceName,
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);

  async function post(action, body) {
    setBusy(action);
    setError(null);
    try {
      const res = await fetch(`/api/discovered-devices/${id}/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body || {}),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        // ⛔ Show what the server said. A failed decision that looks like a
        // successful one is how an operator concludes a sender was handled.
        setError(data.error || `Request failed (${res.status})`);
        return;
      }
      router.refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  }

  // Prefill only what was OBSERVED. Vendor is passed through only when it was
  // actually detected — the Add Device form must not arrive with a guessed
  // vendor sitting in a field an operator will skim past.
  const promoteHref =
    '/devices/new?' +
    new URLSearchParams(
      Object.entries({
        mgmt_ip: sourceIp || '',
        name: hostname || '',
        vendor: vendor || '',
      }).filter(([, v]) => v !== '')
    ).toString();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {kind === 'unmanaged' ? (
          <Link href={promoteHref}>
            <Button variant="primary" size="sm">
              Add to inventory
            </Button>
          </Link>
        ) : (
          <Button
            variant="primary"
            size="sm"
            disabled={busy !== null}
            onClick={() => post('link', { device_id: deviceId, note: `HA peer of ${deviceName}` })}
          >
            {busy === 'link' ? <LoadingSpinner size={14} /> : `Link to ${deviceName}`}
          </Button>
        )}
        <Button variant="secondary" size="sm" disabled={busy !== null} onClick={() => post('ignore')}>
          {busy === 'ignore' ? <LoadingSpinner size={14} /> : 'Ignore'}
        </Button>
      </div>
      {error ? (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--red)' }}>{error}</div>
      ) : null}
    </div>
  );
}
