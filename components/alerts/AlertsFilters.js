'use client';

import FilterBar, { FilterSelect, useFilterNav } from '../ui/FilterBar';

// Filter bar for /alerts.
//
// ⛔ IT NOW MERGES INTO THE URL INSTEAD OF REBUILDING IT. This file used to
// assemble the whole query from the three parameters it knew about, so any
// other state in the URL was discarded on every filter change — the same
// defect ExposureFilters.js documented against itself when choosing a firewall
// silently reset a reader's rows-per-page. `useFilterNav` merges, and resets
// `page` because a page number from a larger result set lands past the end of
// a smaller one and renders an empty table.
//
// ⛔ AND IT NOW SHOWS WHAT IS APPLIED. It previously had no chips, no count and
// no way to clear — three selects whose state was invisible the moment you
// looked away from them.

const DEFS = [
  {
    key: 'type',
    label: 'Type',
    options: [
      { value: '', label: 'All Types' },
      { value: 'patch_now', label: 'Patch-Now CVE' },
      { value: 'config_diff', label: 'Config Diff' },
    ],
  },
  {
    key: 'status',
    label: 'Status',
    options: [
      { value: 'open', label: 'Open' },
      { value: 'all', label: 'All' },
    ],
  },
  { key: 'device_id', label: 'Device' },
];

const byKey = (k) => DEFS.find((d) => d.key === k);

export default function AlertsFilters({
  currentType = '',
  currentStatus = 'open',
  currentDeviceId = '',
  devices = [],
}) {
  const nav = useFilterNav('/alerts');
  const deviceOptions = [
    { value: '', label: 'All devices' },
    ...devices.map((d) => ({ value: d.id, label: d.name })),
  ];
  const defs = DEFS.map((d) => (d.key === 'device_id' ? { ...d, options: deviceOptions } : d));

  // ⛔ `open` IS THE DEFAULT AND IS WRITTEN AS AN ABSENT PARAMETER, so it must
  // not be pushed into the URL as a filter — a chip reading "Status: Open" on
  // every single visit is a chip nobody reads, and clearing it would change
  // what the page shows rather than widening it.
  const set = (k, v) => nav.set({ [k]: k === 'status' && v === 'open' ? '' : v });

  return (
    <FilterBar basePath="/alerts" defs={defs}>
      <FilterSelect label="Type" param="type" value={currentType} options={byKey('type').options} onChange={set} idPrefix="alerts" />
      <FilterSelect label="Status" param="status" value={currentStatus} options={byKey('status').options} onChange={set} idPrefix="alerts" />
      <FilterSelect label="Device" param="device_id" value={currentDeviceId} options={deviceOptions} onChange={set} idPrefix="alerts" />
    </FilterBar>
  );
}
