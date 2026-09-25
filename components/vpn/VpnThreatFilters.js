'use client';

// components/vpn/VpnThreatFilters.js
//
// The filter bar for /vpn?vtab=detections. Holds NO state of its own: it reads
// the current values from the URL and writes new ones back with router.push, so
// the URL IS the filter. Same convention as ExposureFilters / AlertsFilters /
// DeviceFilters — a filtered view is then linkable, bookmarkable and pasteable
// into a ticket.
//
// ⛔ SERVER-SIDE, NOT CLIENT-SIDE. The narrowing happens in the server
// component against the full finding set. Filtering in the browser would look
// identical on this page and break two things: SavedViews stores the query
// string verbatim, and a filter that only touches the rendered rows silently
// stops being a statement about the fleet.
//
// ⛔ ONE BAR FOR THE WHOLE PAGE, not one per panel. The mockup this came from
// put search/country/severity on each of six panels, which is eighteen URL
// parameters and six places to forget to reset. A reader asking "what is
// coming from Switzerland" wants that answered across every detection at once,
// and each panel already states how many of how many it is showing.

import { useRouter, useSearchParams, usePathname } from 'next/navigation';

// ⛔ WINDOW OPTIONS STOP AT 192 HOURS because that is the engine's own
// MAX_WINDOW_HOURS. Offering a value it will silently clamp would show a
// reader "30 days" and hand them eight.
const WINDOWS = [
  { value: '24', label: 'Last 24 hours' },
  { value: '72', label: 'Last 3 days' },
  { value: '168', label: 'Last 7 days' },
  { value: '192', label: 'Last 8 days' },
];

const SEVERITIES = [
  { value: '', label: 'All severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

const FIELD = {
  padding: '7px 10px',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  background: 'var(--bg-card)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-base)',
  fontFamily: 'inherit',
};

export default function VpnThreatFilters({ countries = [], hours = 24 }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const set = (key, value) => {
    const next = new URLSearchParams(searchParams.toString());
    if (value) next.set(key, value);
    else next.delete(key);
    // ⛔ The TAB is part of the URL and must survive a filter change, or
    // narrowing by country would bounce the reader back to Fleet Status.
    next.set('vtab', 'detections');
    router.push(`${pathname}?${next.toString()}`);
  };

  const q = searchParams.get('dq') || '';
  const country = searchParams.get('dCountry') || '';
  const severity = searchParams.get('dSeverity') || '';
  const active = Boolean(q || country || severity);

  return (
    <div
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        gap: 'var(--s3)',
        marginBottom: 'var(--s5)',
      }}
    >
      <input
        type="search"
        defaultValue={q}
        placeholder="Search account, address or country..."
        aria-label="Search detections"
        style={{ ...FIELD, minWidth: 260, flex: '1 1 260px' }}
        // Committed on Enter or blur, never per keystroke: every change here is
        // a full server navigation.
        onKeyDown={(e) => { if (e.key === 'Enter') set('dq', e.currentTarget.value.trim()); }}
        onBlur={(e) => { if (e.currentTarget.value.trim() !== q) set('dq', e.currentTarget.value.trim()); }}
      />

      <select
        value={country}
        onChange={(e) => set('dCountry', e.target.value)}
        aria-label="Filter by country"
        style={FIELD}
      >
        <option value="">All countries</option>
        {countries.map((c) => <option key={c} value={c}>{c}</option>)}
      </select>

      <select
        value={severity}
        onChange={(e) => set('dSeverity', e.target.value)}
        aria-label="Filter by severity"
        style={FIELD}
      >
        {SEVERITIES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
      </select>

      <select
        value={String(hours)}
        onChange={(e) => set('dHours', e.target.value)}
        aria-label="Detection window"
        style={FIELD}
      >
        {WINDOWS.map((w) => <option key={w.value} value={w.value}>{w.label}</option>)}
      </select>

      {active && (
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => {
            const next = new URLSearchParams(searchParams.toString());
            for (const k of ['dq', 'dCountry', 'dSeverity']) next.delete(k);
            next.set('vtab', 'detections');
            router.push(`${pathname}?${next.toString()}`);
          }}
        >
          Reset
        </button>
      )}
    </div>
  );
}
