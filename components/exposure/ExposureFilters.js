'use client';

import { useRouter } from 'next/navigation';

// Firewall filter for /exposure.
//
// Same convention as components/alerts/AlertsFilters.js: an enumerable field
// uses a <select>, navigation happens on change via router.push (a full
// navigation, matching the "?tab=" pattern used elsewhere), and ⛔ ANY FILTER
// CHANGE RESETS `page` TO 1 — a page number from a larger result set would
// otherwise land past the end of a smaller one and render an empty table, which
// on THIS page reads as "no exposure" rather than "wrong page".
//
// ⛔ THIS FILTERS THE TABLE AND NOTHING ELSE, and the page says so beside it.
// The KPI tiles, the answer sentence and the unmeasured caveat above are FLEET
// statements; exposure/page.js carries a comment saying that scoping them to a
// subset "would turn a fleet statement into a per-page one without changing a
// word of its label". A device filter is that same hazard with a nicer control,
// so the scope is stated rather than inferred.

export default function ExposureFilters({ currentDeviceId = '', devices = [] }) {
  const router = useRouter();

  function navigate(nextDeviceId) {
    const params = new URLSearchParams();
    if (nextDeviceId) params.set('device_id', nextDeviceId);
    // `page` is deliberately NOT carried over — see the header.
    const qs = params.toString();
    router.push(qs ? `/exposure?${qs}` : '/exposure');
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--s3)', flexWrap: 'wrap' }}>
      <label
        htmlFor="exposure-device"
        style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontWeight: 600 }}
      >
        Firewall
      </label>
      <select
        id="exposure-device"
        value={currentDeviceId}
        onChange={(e) => navigate(e.target.value)}
        style={{
          padding: '6px 10px',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--border)',
          background: 'var(--bg-card)',
          color: 'var(--text-primary)',
          fontSize: 'var(--text-sm)',
          minWidth: 220,
        }}
      >
        <option value="">All firewalls</option>
        {/* ⛔ THE COUNT TRAVELS WITH THE NAME. Without it the operator has to
            select a firewall to discover it has no exposure paths at all, which
            is the question they most often came to ask. A device with 0 is
            still LISTED — its absence would be indistinguishable from it not
            being monitored. */}
        {devices.map((d) => (
          <option key={d.deviceId} value={d.deviceId}>
            {d.name} ({d.paths} path{d.paths === 1 ? '' : 's'})
          </option>
        ))}
      </select>
      {currentDeviceId ? (
        <button
          type="button"
          onClick={() => navigate('')}
          style={{
            padding: '6px 10px',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border)',
            background: 'transparent',
            color: 'var(--text-secondary)',
            fontSize: 'var(--text-sm)',
            cursor: 'pointer',
          }}
        >
          Clear
        </button>
      ) : null}
    </div>
  );
}
