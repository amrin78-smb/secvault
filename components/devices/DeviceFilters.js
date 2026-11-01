'use client';

import { useSearchParams } from 'next/navigation';
import FilterBar, { FilterSelect, FilterSearch, useFilterNav } from '../ui/FilterBar';

// Devices-page filter bar. Client component only because it needs live input;
// it holds NO state of its own — every control writes to the URL and the server
// component re-renders from that.
//
// Filtering happens SERVER-side against the full row set, so a filter narrows
// the whole fleet, not just the current page of it.
//
// ⛔ THE LAYOUT, THE DEBOUNCE, THE COUNT LINE, THE CLEAR AFFORDANCE AND THE
// APPLIED CHIPS ALL LIVE IN components/ui/FilterBar.js NOW. This file is the
// DEFINITIONS — which parameters exist and what their values are called — and
// nothing else. The four pages that each had their own copy of the bar each
// got a different subset of it right; see that file's header.

// ⛔ ONE DEFINITION PER FILTER, AND THE CHIPS READ FROM IT. The `options` are
// not duplicated for display: the chip shows the option's own wording, so a
// reader sees "Lapsed licence" rather than the `expired` that is in the URL.
const DEFS = [
  { key: 'q', label: 'Search' },
  { key: 'vendor', label: 'Vendor' },
  {
    key: 'risk',
    label: 'Risk level',
    options: [
      { value: '', label: 'All' },
      { value: 'critical', label: 'Critical' },
      { value: 'high', label: 'High' },
      { value: 'medium', label: 'Medium' },
      { value: 'low', label: 'Low' },
      { value: 'unanalysed', label: 'Not analysed' },
    ],
  },
  {
    key: 'status',
    label: 'Status',
    options: [
      { value: '', label: 'All' },
      { value: 'online', label: 'Online' },
      { value: 'offline', label: 'Offline' },
      { value: 'unchecked', label: 'Never checked' },
    ],
  },
  {
    key: 'support',
    label: 'Support',
    options: [
      { value: '', label: 'All' },
      { value: 'expired', label: 'Lapsed licence' },
      { value: 'expiring', label: 'Expiring < 90d' },
      { value: 'unknown', label: 'Unreadable date' },
    ],
  },
  { key: 'site', label: 'Site' },
];

const byKey = (k) => DEFS.find((d) => d.key === k);

export default function DeviceFilters({ vendors, sites, activeCount, totalCount }) {
  const params = useSearchParams();
  const nav = useFilterNav('/devices');

  const vendorOptions = [{ value: '', label: 'All' }, ...vendors.map((v) => ({ value: v, label: v }))];
  const siteOptions = [
    { value: '', label: 'All' },
    ...sites.map((s) => ({ value: s, label: s })),
    // ⛔ Surfaced explicitly rather than hidden: several devices have no site
    // set, and a Site filter that silently omits them would make the fleet look
    // smaller than it is.
    { value: '__none__', label: '(no site set)' },
  ];

  // The two option lists are built from live data, so the chip definitions have
  // to be completed here or those two chips would print the raw URL value.
  const defs = DEFS.map((d) => {
    if (d.key === 'vendor') return { ...d, options: vendorOptions };
    if (d.key === 'site') return { ...d, options: siteOptions };
    return d;
  });

  return (
    <FilterBar
      basePath="/devices"
      defs={defs}
      count={{ shown: activeCount, total: totalCount, noun: 'firewalls' }}
    >
      <FilterSearch
        param="q"
        placeholder="Name, IP address or site…"
        value={params.get('q') || ''}
        onChange={(k, v) => nav.set({ [k]: v })}
      />
      <FilterSelect label="Vendor" param="vendor" value={params.get('vendor')} options={vendorOptions} onChange={(k, v) => nav.set({ [k]: v })} />
      <FilterSelect label="Risk level" param="risk" value={params.get('risk')} options={byKey('risk').options} onChange={(k, v) => nav.set({ [k]: v })} />
      <FilterSelect label="Status" param="status" value={params.get('status')} options={byKey('status').options} onChange={(k, v) => nav.set({ [k]: v })} />
      <FilterSelect label="Support" param="support" value={params.get('support')} options={byKey('support').options} onChange={(k, v) => nav.set({ [k]: v })} />
      <FilterSelect label="Site" param="site" value={params.get('site')} options={siteOptions} onChange={(k, v) => nav.set({ [k]: v })} />
    </FilterBar>
  );
}
