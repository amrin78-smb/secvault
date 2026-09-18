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

export default function ExposureFilters({
  currentDeviceId = '',
  devices = [],
  unassessed = [],
  currentLimit = '',
}) {
  const router = useRouter();

  function navigate(nextDeviceId) {
    const params = new URLSearchParams();
    if (nextDeviceId) params.set('device_id', nextDeviceId);
    // ⛔ `limit` IS CARRIED, `page` IS NOT. Dropping page is deliberate and the
    // header explains why. Dropping limit was not: the Pagination control writes
    // the rows-per-page there, so choosing a firewall silently reset a reader
    // who had selected 200 rows back to 50, with nothing to indicate it. The
    // comment said "page is deliberately NOT carried over", implying everything
    // else was — and the code carried nothing.
    if (currentLimit) params.set('limit', String(currentLimit));
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
        {/* ⛔ A FIREWALL WHOSE EXPOSURE COULD NOT BE COMPUTED IS SHOWN AND
            DISABLED. Leaving it out made it indistinguishable from a firewall
            SecVault does not monitor -- the same reason a device with zero
            paths is listed above. It is not selectable because the only thing
            selecting it could render is an empty table, and an empty exposure
            table reads as "nothing is exposed here", which is precisely the
            claim we cannot make about a device we failed to assess. */}
        {unassessed.length > 0 ? (
          <optgroup label="Could not be assessed — not in any figure on this page">
            {unassessed.map((d) => (
              <option key={d.deviceId || d.name} value="" disabled title={d.error || undefined}>
                {d.name} (not assessed)
              </option>
            ))}
          </optgroup>
        ) : null}
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
