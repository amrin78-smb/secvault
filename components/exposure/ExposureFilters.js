'use client';

import FilterBar, { FilterField, useFilterNav } from '../ui/FilterBar';

// Firewall filter for /exposure.
//
// ⛔ THIS FILTERS THE TABLE AND NOTHING ELSE, and the page says so beside it.
// The KPI tiles, the answer sentence and the unmeasured caveat above are FLEET
// statements; exposure/page.js carries a comment saying that scoping them to a
// subset "would turn a fleet statement into a per-page one without changing a
// word of its label". A device filter is that same hazard with a nicer control,
// so the scope is stated rather than inferred.
//
// ⛔ THE REBUILD BUG THIS FILE DOCUMENTED AGAINST ITSELF IS GONE. It used to
// assemble the query from the two parameters it knew about, which is how
// choosing a firewall silently reset a reader who had selected 200 rows back
// to 50. The comment admitting it ended "the code carried nothing". The merge
// now lives in lib/urlFilters.js, where no caller can forget it, and `limit`
// is carried because nothing deletes it rather than because this file
// remembered to re-add it.
//
// ⛔ IT KEEPS ITS OWN <select> RATHER THAN USING FilterSelect, and that is the
// abstraction working rather than failing: the control carries an <optgroup>
// of firewalls that could not be assessed, each disabled and titled with its
// error. FilterField gives it the shared label and the shared box; a
// FilterSelect general enough to express that would be a worse component than
// two that each do one thing.

export default function ExposureFilters({
  currentDeviceId = '',
  devices = [],
  unassessed = [],
}) {
  const nav = useFilterNav('/exposure');

  // Built from live data, so the chip definition is completed here or the chip
  // would print a device UUID.
  const defs = [{
    key: 'device_id',
    label: 'Firewall',
    options: [
      { value: '', label: 'All firewalls' },
      ...devices.map((d) => ({ value: d.deviceId, label: d.name })),
    ],
  }];

  return (
    <FilterBar basePath="/exposure" defs={defs}>
      <FilterField label="Firewall" htmlFor="exposure-device">
        <select
          id="exposure-device"
          className="select filter-control"
          style={{ minWidth: 220 }}
          value={currentDeviceId}
          onChange={(e) => nav.set({ device_id: e.target.value })}
        >
          <option value="">All firewalls</option>
          {/* ⛔ THE COUNT TRAVELS WITH THE NAME. Without it the operator has to
              select a firewall to discover it has no exposure paths at all,
              which is the question they most often came to ask. A device with 0
              is still LISTED — its absence would be indistinguishable from it
              not being monitored. */}
          {devices.map((d) => (
            <option key={d.deviceId} value={d.deviceId}>
              {d.name} ({d.paths} path{d.paths === 1 ? '' : 's'})
            </option>
          ))}
          {/* ⛔ A FIREWALL WHOSE EXPOSURE COULD NOT BE COMPUTED IS SHOWN AND
              DISABLED. Leaving it out made it indistinguishable from a firewall
              SecVault does not monitor — the same reason a device with zero
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
      </FilterField>
    </FilterBar>
  );
}
