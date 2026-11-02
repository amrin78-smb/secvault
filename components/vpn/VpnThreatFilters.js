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

import { useSearchParams } from 'next/navigation';
import FilterBar, { FilterSelect, FilterSearch, useFilterNav } from '../ui/FilterBar';

// ⛔ WINDOW OPTIONS STOP AT 192 HOURS because that is the engine's own
// MAX_WINDOW_HOURS. Offering a value it will silently clamp would show a
// reader "30 days" and hand them eight.
const WINDOWS = [
  { value: '24', label: 'Last 24 hours' },
  { value: '72', label: 'Last 3 days' },
  { value: '168', label: 'Last 7 days' },
  { value: '192', label: 'Last 8 days' },
];

// ⛔ THE LIST MUST CONTAIN THE WINDOW ACTUALLY IN FORCE. The page clamps `dHours`
// to 1..192, so `?dHours=48` runs a 48-hour window while this fixed list left the
// control reading "Last 24 hours" — a filter reporting a value that is not the one
// the figures beside it were computed from, and the reader has no way to tell.
// Whatever the engine resolved is added as its own option rather than silently
// snapped to a neighbour, because snapping would change the query on the next
// interaction without being asked to.
function windowLabel(h) {
  if (h % 24 === 0) {
    const days = h / 24;
    return `Last ${days} day${days === 1 ? '' : 's'}`;
  }
  return `Last ${h} hour${h === 1 ? '' : 's'}`;
}

function windowOptions(hours) {
  const h = Math.trunc(Number(hours));
  if (!Number.isFinite(h) || h <= 0) return WINDOWS;
  if (WINDOWS.some((w) => w.value === String(h))) return WINDOWS;
  return [...WINDOWS, { value: String(h), label: windowLabel(h) }]
    .sort((a, b) => Number(a.value) - Number(b.value));
}

const SEVERITIES = [
  { value: '', label: 'All severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

// ⛔ THE FOURTH HAND-ROLLED FILTER BAR, AND THE LAST (v2.220.0). Phase 1
// moved /devices, /alerts and /exposure onto the shared FilterBar and left
// this one deliberately, because the VPN page was Phase 5's work. It had the
// same three gaps the other three had:
//
//   • NO CHIPS AND NO COUNT. A narrowed detections list and a quiet fleet
//     looked identical the moment you glanced away from the controls.
//   • IT REBUILT THE QUERY. `set()` copied the whole URL and then had to
//     RE-ADD `vtab` by hand, with a comment explaining that narrowing by
//     country would otherwise bounce the reader back to Fleet Status. That
//     is the merge-never-rebuild rule being re-implemented per component,
//     and the comment is what a near-miss looks like.
//   • Reset cleared a HARDCODED list of three keys, so a fourth filter added
//     later would have survived a reset nobody could see had failed.
//
// ⛔ `dHours` IS NOT A FILTER AND IS NOT CLEARED. It is the detection WINDOW:
// every detection in lib/engines/vpnDetections.js is computed over it, and
// "clear" cannot mean "all of time" when the baseline gates are expressed in
// days. It stays a control and never becomes a chip — the same call
// lib/urlFilters.js makes for `limit`.

const DEFS = [
  { key: 'dq', label: 'Search' },
  { key: 'dCountry', label: 'Country' },
  { key: 'dSeverity', label: 'Severity', options: SEVERITIES },
];

export default function VpnThreatFilters({ countries = [], hours = 24 }) {
  const params = useSearchParams();
  // ⛔ `vtab` IS CARRIED, NOT RE-ADDED. useFilterNav MERGES into the current
  // query, and lib/urlFilters.js classes `vtab` as a non-filter — so the tab
  // survives a filter change because nothing deletes it, rather than because
  // somebody remembered to put it back.
  const nav = useFilterNav('/vpn');

  const countryOptions = [
    { value: '', label: 'All countries' },
    ...countries.map((c) => ({ value: c, label: c })),
  ];
  const defs = DEFS.map((d) => (d.key === 'dCountry' ? { ...d, options: countryOptions } : d));
  const set = (k, v) => nav.set({ [k]: v });

  return (
    <FilterBar basePath="/vpn" defs={defs}>
      <FilterSearch
        param="dq"
        placeholder="Search detections…"
        value={params.get('dq') || ''}
        onChange={set}
      />
      <FilterSelect
        label="Country"
        param="dCountry"
        value={params.get('dCountry')}
        options={countryOptions}
        onChange={set}
        idPrefix="vpn"
      />
      <FilterSelect
        label="Severity"
        param="dSeverity"
        value={params.get('dSeverity')}
        options={SEVERITIES}
        onChange={set}
        idPrefix="vpn"
      />
      {/* ⛔ A CONTROL, NEVER A CHIP. It is not in `defs`, so "Clear filters"
          leaves it alone and it never appears in the applied list — widening
          the window is not clearing a filter, it is asking a different
          question. */}
      <FilterSelect
        label="Window"
        param="dHours"
        value={String(hours)}
        options={windowOptions(hours)}
        onChange={set}
        idPrefix="vpn"
      />
    </FilterBar>
  );
}
