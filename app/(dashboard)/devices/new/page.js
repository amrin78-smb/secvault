'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import DeviceForm from '../../../../components/devices/DeviceForm';
import PageHeader from '../../../../components/ui/PageHeader';

// This page needs no server-side data fetching (a blank "add device" form has nothing
// to pre-load from the DB), so the whole file can be a Client Component with no
// server/client boundary conflict — DeviceForm's onSubmit does the POST and this page
// redirects to the new device's detail page on success.
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
      <PageHeader title="Add Device" />
      {error && <p style={{ fontSize: 'var(--text-base)', color: 'var(--red)' }}>{error}</p>}
      <DeviceForm onSubmit={handleSubmit} />
    </div>
  );
}
