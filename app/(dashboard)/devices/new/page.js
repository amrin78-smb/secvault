'use client';

import { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import DeviceForm from '../../../../components/devices/DeviceForm';
import PageHeader from '../../../../components/ui/PageHeader';

// This page needs no server-side data fetching (a blank "add device" form has nothing
// to pre-load from the DB), so the whole file can be a Client Component with no
// server/client boundary conflict — DeviceForm's onSubmit does the POST and this page
// redirects to the new device's detail page on success.
//
// ⛔ BUT IT DOES PRE-LOAD FROM THE URL, AND FOR ITS WHOLE LIFE IT DID NOT
// (fixed v2.237.0). `components/devices/DiscoveredDeviceActions.js` has linked
// here as `/devices/new?mgmt_ip=…&name=…&vendor=…` since the discovered list
// shipped, and this page read none of it — so every "Add to inventory" click on
// a firewall SecVault had just seen sending syslog opened a BLANK FORCEPOINT
// form. The operator retyped the address they had just been shown and picked
// the vendor again, and the comment above was the reason nobody looked: it is
// true about the DATABASE and silent about the query string.
//
// ⛔ It also left a carefully-argued guard in that file unable to fire — see
// the `seed` block in DeviceForm for what that cost.
//
// ⛔ `useSearchParams()` NEEDS A SUSPENSE BOUNDARY. Without one, `next build`
// fails this route with "useSearchParams() should be wrapped in a suspense
// boundary" (or, worse, silently prerenders it with empty params), which would
// reinstate exactly the blank form being fixed here.
function NewDeviceFormSection({ onSubmit }) {
  const params = useSearchParams();
  // Only what the discovered list actually sends. `mgmt_method` is deliberately
  // NOT honoured: see the accessMethod initialiser in DeviceForm.
  const prefill = {
    name: params.get('name') || '',
    vendor: params.get('vendor') || '',
    mgmt_ip: params.get('mgmt_ip') || '',
  };
  return <DeviceForm onSubmit={onSubmit} prefill={prefill} />;
}

export default function NewDevicePage() {
  const router = useRouter();
  const [error, setError] = useState('');

  async function handleSubmit(payload) {
    setError('');
    const res = await fetch('/api/devices', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const message = data.error || 'Failed to create device';
      setError(message);
      throw new Error(message);
    }
    router.push(`/devices/${data.id}`);
  }

  return (
    <div style={{ maxWidth: 576, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader title="Add firewall" />
      {error && <p style={{ fontSize: 'var(--text-base)', color: 'var(--red)' }}>{error}</p>}
      {/* ⛔ THE FALLBACK IS `null`, NOT A SECOND `DeviceForm`.
          It cannot fire as configured — the `(dashboard)` layout calls
          `headers()` and `getServerSession`, so this route is dynamic and
          `useSearchParams()` reads context synchronously without suspending
          (verified: nothing under `(dashboard)` is prerendered). But a
          `<DeviceForm>` fallback is a DIFFERENT ELEMENT TYPE at this tree
          position from `<NewDeviceFormSection>`, so React cannot preserve
          state across the swap: if it ever did render — someone adds
          `force-static`, the layout stops calling `headers()`, a Next upgrade
          changes the bailout — the operator would type into a blank form and
          have a fresh one mount under them, losing the lot, plus a duplicate
          credential-profiles fetch. A net that is unreachable and harmful if
          reached is worse than none. */}
      <Suspense fallback={null}>
        <NewDeviceFormSection onSubmit={handleSubmit} />
      </Suspense>
    </div>
  );
}
