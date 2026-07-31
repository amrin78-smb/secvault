'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Button from '../ui/Button';
import Modal from '../ui/Modal';
import DeviceForm from './DeviceForm';

// Manage tab entry point for editing a device's core details — everything
// PUT /api/devices/[id] already supports except credential rotation
// (CredentialForm.js, rendered right below this in the Manage tab, owns
// that) and delete/enable-disable (DeviceActions.js + the Delete button own
// device lifecycle elsewhere on this same tab).
//
// Self-contained client component, same convention as CredentialForm.js /
// DeviceActions.js — devices/[id]/page.js stays a server component and just
// drops this in with the `device` row it already loaded. Modal open state is
// a plain local useState, NOT the searchParams-driven pattern the page's own
// Delete-confirmation modal uses: that pattern exists so a zero-JS server
// <Link> can drive the modal open/closed via navigation. DeviceForm is
// already a client component full of its own input state, so there's no
// benefit to routing "open the edit form" through a page navigation too —
// a local toggle is simpler and doesn't disturb the URL/tab query param.
export default function EditDeviceModal({ device }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  // Bumped every time the modal closes (cancelled or saved) and used as
  // DeviceForm's `key` below, so a fresh mount — and fresh pre-fill from the
  // current `device` prop — happens every time the modal is reopened, instead
  // of a stale, half-edited, previously-typed value (or a stale credential
  // input that was never meant to persist) surviving into the next open.
  const [instance, setInstance] = useState(0);

  function handleClose() {
    setOpen(false);
    setInstance((n) => n + 1);
  }

  async function handleSubmit(payload) {
    const res = await fetch(`/api/devices/${device.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || 'Failed to save device');
    }
    setOpen(false);
    setInstance((n) => n + 1);
    // Device details (name/vendor/access method/site/criticality/etc.) are
    // rendered by the SERVER component above (devices/[id]/page.js) — this
    // re-runs that server render with the freshly-updated row, same
    // router.refresh() pattern DeviceActions.js already uses elsewhere on
    // this same Manage tab after Collect Now / Test Connectivity.
    router.refresh();
  }

  return (
    <>
      <Button type="button" variant="secondary" onClick={() => setOpen(true)}>
        Edit Device Details
      </Button>
      <Modal open={open} onClose={handleClose} title="Edit Device Details" maxWidth={680}>
        {/* `key` forces a fresh DeviceForm instance (and fresh pre-fill) each
            time the modal opens — see the `instance` comment above. Errors
            from a failed save render inside DeviceForm itself (submitError),
            so nothing extra is needed here. */}
        <DeviceForm key={instance} mode="edit" initialDevice={device} onSubmit={handleSubmit} />
      </Modal>
    </>
  );
}
