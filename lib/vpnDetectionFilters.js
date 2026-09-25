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

module.exports = {
  matchesFilters,
  filtersActive,
  countriesIn,
  countriesOf,
  searchableOf,
};
