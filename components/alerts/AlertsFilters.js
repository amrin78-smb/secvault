'use client';

import { useRouter } from 'next/navigation';

// Filter bar for /alerts. Same enumerable-field-uses-<select> convention as
// the vendor/cvssBand filters on components/vulnerability/CvePostureTab.js
// and components/vulnerability/AdvisoriesTab.js (formerly separate
// app/(dashboard)/cve/page.js and app/(dashboard)/advisories/page.js, merged
// into /vulnerability's two tabs), but those tabs use a plain
// <form method="GET"> full-page-navigation submit -- this one is 'use client'
// (per this feature's file contract) and navigates on every onChange instead
// of waiting for a submit click, via router.push (still a full navigation,
// not a client-side re-fetch, matching the "?tab=" pattern
// devices/[id]/analysis/page.js already uses for its own query-param state).
// Any filter change resets `page` back to 1 -- the old page number from a
// different, larger result set would otherwise silently land past the end.
const TYPE_OPTIONS = [
  { value: '', label: 'All Types' },
  { value: 'new_finding', label: 'Finding' },
  { value: 'patch_now', label: 'Patch-Now CVE' },
  { value: 'config_diff', label: 'Config Diff' },
];

const STATUS_OPTIONS = [
  { value: 'open', label: 'Open' },
  { value: 'all', label: 'All' },
];

export default function AlertsFilters({
  currentType = '',
  currentStatus = 'open',
  currentDeviceId = '',
  devices = [],
}) {
  const router = useRouter();

  function navigate(next) {
    const merged = {
      type: currentType,
      status: currentStatus,
      device_id: currentDeviceId,
      ...next,
    };
    const params = new URLSearchParams();
    if (merged.type) params.set('type', merged.type);
    if (merged.status && merged.status !== 'open') params.set('status', merged.status);
    if (merged.device_id) params.set('device_id', merged.device_id);
    const qs = params.toString();
    router.push(`/alerts${qs ? `?${qs}` : ''}`);
  }

  return (
    <div className="filter-row">
      <div className="form-field">
        <label htmlFor="alerts-type">Type</label>
        <select
          id="alerts-type"
          className="select"
          value={currentType}
          onChange={(e) => navigate({ type: e.target.value })}
        >
          {TYPE_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>
      <div className="form-field">
        <label htmlFor="alerts-status">Status</label>
        <select
          id="alerts-status"
          className="select"
          value={currentStatus}
          onChange={(e) => navigate({ status: e.target.value })}
        >
          {STATUS_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>
      <div className="form-field">
        <label htmlFor="alerts-device">Device</label>
        <select
          id="alerts-device"
          className="select"
          value={currentDeviceId}
          onChange={(e) => navigate({ device_id: e.target.value })}
        >
          <option value="">All devices</option>
          {devices.map((d) => (
            <option key={d.id} value={d.id}>
              {d.name}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}
