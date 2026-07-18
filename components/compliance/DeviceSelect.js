'use client';

import { useRouter } from 'next/navigation';

// Device picker for the /compliance Cards view (app/(dashboard)/compliance/page.js).
// Same "'use client', navigate via router.push on every onChange" convention
// already used by components/alerts/AlertsFilters.js for its own <select>
// filters -- a real Next.js client-side navigation (not a full page reload),
// which is what re-renders the server-component page with the newly
// selected device's donuts/stats. No local fetch/state management needed
// here; the server component does all the data work on the resulting
// request, matching this app's established query-param-driven server
// navigation pattern (see devices/[id]/analysis/page.js's `?tab=`).
//
// Only rendered inside the Cards view, so there's no `view` param to
// preserve on navigate -- the destination is always `/compliance?device=...`.
export default function DeviceSelect({ devices = [], selectedId }) {
  const router = useRouter();

  return (
    <div className="form-field" style={{ maxWidth: 320 }}>
      <label htmlFor="compliance-device">Firewall</label>
      <select
        id="compliance-device"
        className="select"
        value={selectedId || ''}
        onChange={(e) => router.push(`/compliance?device=${e.target.value}`)}
      >
        {devices.map((d) => (
          <option key={d.id} value={d.id}>
            {d.name} ({d.vendor})
          </option>
        ))}
      </select>
    </div>
  );
}
