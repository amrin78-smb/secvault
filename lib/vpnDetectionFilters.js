'use strict';

// lib/vpnDetectionFilters.js
//
// Narrowing for the VPN threat detections view. PURE — no pool, no JSX, no
// React — so the judgement can be tested directly rather than by scanning a
// component for the right words. Same split segmentation.js / applicationView.js
// use, and for the same reason: the judgement is the part worth pinning.
//
// ⛔ A FILTER NARROWS WHAT IS LISTED, NEVER WHAT WAS MEASURED. These run over
// findings the engine already produced, so no filter can change a severity, a
// baseline verdict, or an unverifiable count. The caller states "N of M"
// whenever the two differ, because a filtered list that looks complete is the
// same lie as a truncated one.

/**
 * The countries a finding can be said to involve.
 *
 * ⛔ THE SIX DETECTIONS CARRY COUNTRY IN THREE DIFFERENT SHAPES — `country`
 * (spray, brute force), `countries[]` (account targeted, off hours), and a
 * from/to PAIR (country change). Checking only the first would silently drop
 * three detections out of every country filter, and the reader would conclude
 * nothing came from that country.
 *
 * ⛔ AND THE SHAPE HAS TO BE THE SHAPE, NOT THE NAME. `account_targeted` once
 * emitted `countries: 8` — a COUNT wearing the array field's name.
 * `Array.isArray(8)` is false, so every one of its findings was silently dropped
 * by every country filter (live: 28 findings, 0 survivors, all 19 offered
 * countries) and the panel then printed its earned-all-clear sentence. The
 * engine now emits `countries[]` plus a separate `countryCount`, and
 * tests/vpnDetections.test.js pins the two files' agreement — a docstring
 * asserting the shape is not a guard.
 */
function countriesOf(finding) {
  if (!finding || typeof finding !== 'object') return [];
  const out = [
    finding.country,
    finding.fromCountry,
    finding.toCountry,
    ...(Array.isArray(finding.countries) ? finding.countries : []),
  ];
  return out.filter((c) => typeof c === 'string' && c.trim() !== '').map((c) => c.trim());
}

/** Everything about a finding a free-text search should look at. */
function searchableOf(finding) {
  if (!finding || typeof finding !== 'object') return '';
  const devices = Array.isArray(finding.devices)
    ? finding.devices.map((d) => (d && typeof d === 'object' ? d.deviceName : d))
    : [];
  return [
    finding.username,
    finding.srcIp,
    finding.fromSrcIp,
    finding.toSrcIp,
    ...countriesOf(finding),
    ...devices,
    ...(Array.isArray(finding.sources) ? finding.sources : []),
  ]
    .filter((v) => typeof v === 'string' && v !== '')
    .join(' ')
    .toLowerCase();
}

/**
 * Does this finding survive the active filters?
 *
 * ⛔ A FINDING THAT NAMES NO COUNTRY IS EXCLUDED BY A COUNTRY FILTER, not
 * passed through. "We do not know where this came from" is not a match for
 * "Switzerland", and letting it through would put unlocatable findings under a
 * heading that claims a location for them. The cost is that narrowing by
 * country hides findings whose country the firewall never reported — which is
 * why the caller prints "showing N of M" rather than N alone.
 */
function matchesFilters(finding, filters) {
  if (!filters) return true;
  const { q, country, severity } = filters;

  if (severity && finding && finding.severity !== severity) return false;

  if (country) {
    if (!countriesOf(finding).some((c) => c === country)) return false;
  }

  if (q) {
    const needle = String(q).trim().toLowerCase();
    if (needle && !searchableOf(finding).includes(needle)) return false;
  }

  return true;
}

/** Is any filter actually set? */
function filtersActive(filters) {
  if (!filters || typeof filters !== 'object') return false;
  return Boolean(
    (typeof filters.q === 'string' && filters.q.trim())
    || filters.country
    || filters.severity
  );
}

/**
 * Every country named by any finding, for the filter's own dropdown.
 *
 * ⛔ DERIVED FROM THE DATA, NEVER TYPED. The same rule segmentation follows for
 * its zone axis: a hand-written list drifts the moment a vendor spells a country
 * differently, and every option referencing the old spelling then matches
 * nothing — which reads as "no attacks from there".
 *
 * ⛔ AND IT READS `unverifiable` TOO. Those items carry countries and are shown
 * on the page; a dropdown built from `findings` alone would offer no option for
 * a country that appears only among the observations we could not judge.
 */
function countriesIn(detections) {
  const seen = new Set();
  for (const d of Array.isArray(detections) ? detections : []) {
    if (!d || typeof d !== 'object') continue;
    const rows = [
      ...(Array.isArray(d.findings) ? d.findings : []),
      ...(Array.isArray(d.unverifiable) ? d.unverifiable : []),
    ];
    for (const f of rows) for (const c of countriesOf(f)) seen.add(c);
  }
  return [...seen].sort((a, b) => a.localeCompare(b));
}

/**
 * Everything one detection PANEL should render, once the filters are applied.
 *
 * ⛔ THE EARNED ALL-CLEAR IS KEYED ON THE UNFILTERED SET, AND THAT IS THE WHOLE
 * REASON THIS FUNCTION EXISTS. The component computed the filtered array and then
 * said, of `findings.length === 0`, "Nothing matched this detection in the last
 * 24 hours" — a claim about the WINDOW, printed directly under "showing 0 of
 * 130". Live: `?vtab=detections&dCountry=CH` did it to credential_spray, and a
 * bogus `?dSeverity=xyz` did it to all six panels at once. A filter narrows what
 * is LISTED; it can never earn a statement about what was MEASURED.
 *
 * ⛔ SO THERE ARE FOUR OUTCOMES, NOT TWO: rows to show, an EARNED all-clear
 * (nothing was found), NARROWED TO NOTHING (findings exist, none match — which
 * must say so and say how many it is hiding), and not measured at all (the
 * caller's baseline panel, keyed on `measured`).
 *
 * ⛔ `unverifiable` IS NARROWED BY THE SAME FILTERS, because it was not: a single
 * card could print "Nothing matched…", "showing 0 of 130" and 25 unverifiable
 * rows from other countries simultaneously. But `unverifiableTotal` stays the
 * ENGINE'S total and no filter may shrink it — that count is the claim, the list
 * is illustration, and the caller states both.
 */
function panelView(detection, filters) {
  const d = detection && typeof detection === 'object' ? detection : {};
  const all = Array.isArray(d.findings) ? d.findings : [];
  const allUnverifiable = Array.isArray(d.unverifiable) ? d.unverifiable : [];
  const active = filtersActive(filters);
  const findings = active ? all.filter((f) => matchesFilters(f, filters)) : all;
  const unverifiable = active
    ? allUnverifiable.filter((f) => matchesFilters(f, filters))
    : allUnverifiable;
  // The engine's own total, which is never the length of the sampled array.
  const declared = Number(d.unverifiableTotal);
  const unverifiableTotal = Number.isFinite(declared) ? declared : allUnverifiable.length;
  const measured = d.status === 'measured';

  return {
    measured,
    filtersActive: active,
    findings,
    findingsTotal: all.length,
    hiddenByFilters: all.length - findings.length,
    earnedAllClear: measured && all.length === 0,
    narrowedToNothing: measured && all.length > 0 && findings.length === 0,
    unverifiable,
    unverifiableListed: unverifiable.length,
    unverifiableTotal,
    unverifiableHiddenByFilters: allUnverifiable.length - unverifiable.length,
  };
}

module.exports = {
  matchesFilters,
  filtersActive,
  countriesIn,
  countriesOf,
  searchableOf,
  panelView,
};
