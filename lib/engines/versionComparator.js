// lib/engines/versionComparator.js
//
// Version string <-> tuple parsing and comparison, per-vendor.
//
// See CLAUDE.md "CVE Engine Architecture" > "Version Scheme (Forcepoint)":
//   "6.10.21" -> tuple [6, 10, 21]
//   "7.1.0"   -> tuple [7, 1, 0]
// Simple semver-like, no hotfix suffixes (unlike PAN-OS `-h3`).
// Version 7.1+ = FlexEdge SD-WAN (rebranded) -- same comparator applies.

'use strict';

/**
 * Forcepoint version parser: split on '.', parseInt each segment, replace
 * NaN with 0 (logging a warning), handle null/undefined input.
 * @param {string|null|undefined} versionString
 * @returns {number[]}
 */
function parseForcepointVersion(versionString) {
  if (versionString === null || versionString === undefined) {
    return [0];
  }
  const parts = String(versionString).split('.');
  return parts.map((part) => {
    const n = parseInt(part, 10);
    if (Number.isNaN(n)) {
      console.warn(
        `[versionComparator] Unparseable version segment "${part}" in "${versionString}" - defaulting to 0`
      );
      return 0;
    }
    return n;
  });
}

/**
 * Fortinet FortiOS: "7.4.3" -> [7, 4, 3, 0]. Also tolerates the raw API/CLI
 * forms "v7.4.3,build2573,240201" and "v7.4.3" — the leading 'v' and anything
 * after a comma are stripped before the dot-split. Padded to 4 segments.
 */
function parseFortinetVersion(versionString) {
  if (versionString === null || versionString === undefined) return [0];
  let s = String(versionString).trim();
  s = s.split(',')[0].replace(/^v/i, '');
  const tuple = parseForcepointVersion(s);
  while (tuple.length < 4) tuple.push(0);
  return tuple;
}

/**
 * Palo Alto PAN-OS: "11.1.2-h3" -> [11, 1, 2, 3] (hotfix number is the 4th
 * segment); "11.1.2" -> [11, 1, 2, 0].
 */
function parsePanosVersion(versionString) {
  if (versionString === null || versionString === undefined) return [0];
  const s = String(versionString).trim();
  const hotfixMatch = s.match(/-h(\d+)\s*$/i);
  const hotfix = hotfixMatch ? parseInt(hotfixMatch[1], 10) : 0;
  const base = s.replace(/-h\d+\s*$/i, '');
  const tuple = parseForcepointVersion(base);
  while (tuple.length < 3) tuple.push(0);
  // Found in a full-app audit (2026-07-16): this used to unconditionally do
  // `tuple[3] = hotfix`, which silently OVERWROTE a genuine 4th dotted segment
  // (e.g. "11.1.2.5", no "-hN" suffix -> parseForcepointVersion already
  // produced [11,1,2,5]) with 0. A "-hN" suffix always means the hotfix
  // number regardless of how many dotted segments the base has; absent that
  // suffix, only pad with 0 when there ISN'T already a real 4th segment --
  // never clobber one that's actually there.
  if (hotfixMatch) {
    tuple[3] = hotfix;
  } else if (tuple.length < 4) {
    tuple[3] = 0;
  }
  return tuple.slice(0, 4).map((n) => (Number.isInteger(n) ? n : 0));
}

/**
 * Cisco ASA: "9.18(4)" -> [9, 18, 4, 0]; interim releases "9.18(4)15"
 * -> [9, 18, 4, 15].
 */
function parseCiscoAsaVersion(versionString) {
  if (versionString === null || versionString === undefined) return [0];
  const s = String(versionString).trim();
  const m = s.match(/^(\d+)\.(\d+)\((\d+)\)(\d+)?/);
  if (m) {
    return [
      parseInt(m[1], 10),
      parseInt(m[2], 10),
      parseInt(m[3], 10),
      m[4] !== undefined ? parseInt(m[4], 10) : 0,
    ];
  }
  // Fall back to plain dot-split for unexpected formats (e.g. "9.18.4").
  const tuple = parseForcepointVersion(s);
  while (tuple.length < 4) tuple.push(0);
  return tuple;
}

/**
 * Check Point: "R81.20" -> [81, 20, 0, 0]. The leading 'R' is stripped;
 * take/hotfix suffixes like "R81.20 Take 41" contribute the take number as
 * the 3rd segment: [81, 20, 41, 0].
 */
function parseCheckpointVersion(versionString) {
  if (versionString === null || versionString === undefined) return [0];
  const s = String(versionString).trim();
  const takeMatch = s.match(/take[\s_-]*(\d+)/i);
  const take = takeMatch ? parseInt(takeMatch[1], 10) : 0;
  const base = s.replace(/^r/i, '').split(/\s/)[0];
  const tuple = parseForcepointVersion(base);
  while (tuple.length < 2) tuple.push(0);
  return [tuple[0], tuple[1], take, 0];
}

// Per-vendor dispatch table. Canonical vendor slugs (see CLAUDE.md "Supported
// Vendors"): forcepoint, fortinet, paloalto, cisco_asa, checkpoint, sangfor.
// Sangfor uses the simple dot-split scheme. The default/fallback case (see
// parseVersion below) behaves like the forcepoint parser as a reasonable
// fallback for unknown vendors, rather than throwing.
const VENDOR_PARSERS = {
  forcepoint: parseForcepointVersion,
  fortinet: parseFortinetVersion,
  paloalto: parsePanosVersion,
  cisco_asa: parseCiscoAsaVersion,
  checkpoint: parseCheckpointVersion,
  sangfor: parseForcepointVersion,
};

/**
 * Parse a vendor version string into a numeric tuple.
 * @param {string} vendor
 * @param {string|null|undefined} versionString
 * @returns {number[]}
 */
function parseVersion(vendor, versionString) {
  const parser = VENDOR_PARSERS[vendor];
  if (parser) {
    return parser(versionString);
  }
  // Unknown vendor: fall back to the simple dot-split scheme rather than
  // throwing, since new vendors plug in here in later phases.
  return parseForcepointVersion(versionString);
}

/**
 * Tuple-wise comparison. Pads the shorter tuple with trailing zeros to match
 * length before comparing.
 * @param {number[]} tupleA
 * @param {number[]} tupleB
 * @returns {-1|0|1}
 */
function compareVersions(tupleA, tupleB) {
  const len = Math.max(tupleA.length, tupleB.length);
  for (let i = 0; i < len; i++) {
    const a = tupleA[i] !== undefined ? tupleA[i] : 0;
    const b = tupleB[i] !== undefined ? tupleB[i] : 0;
    if (a > b) return 1;
    if (a < b) return -1;
  }
  return 0;
}

/**
 * Determine whether a device's version tuple falls within a vulnerable range,
 * accounting for exact-fixed-version exclusions.
 *
 * @param {string} vendor
 * @param {number[]} deviceTuple
 * @param {string|null} rangeMin - null = no lower bound (skip check)
 * @param {string|null} rangeMax - null = no upper bound (skip check)
 * @param {string[]} excludeFixed - exact fixed version strings that are NOT
 *   vulnerable even if numerically in range
 * @returns {boolean}
 */
function isInRange(vendor, deviceTuple, rangeMin, rangeMax, excludeFixed) {
  const exclusions = excludeFixed || [];

  // Exact-match exclusion check first: if the device's version is an exact
  // fixed version, it is not vulnerable regardless of range.
  for (const fixedVersion of exclusions) {
    const fixedTuple = parseVersion(vendor, fixedVersion);
    if (compareVersions(deviceTuple, fixedTuple) === 0) {
      return false;
    }
  }

  if (rangeMin !== null && rangeMin !== undefined) {
    const minTuple = parseVersion(vendor, rangeMin);
    if (compareVersions(deviceTuple, minTuple) < 0) {
      return false;
    }
  }

  if (rangeMax !== null && rangeMax !== undefined) {
    const maxTuple = parseVersion(vendor, rangeMax);
    if (compareVersions(deviceTuple, maxTuple) > 0) {
      return false;
    }
  }

  return true;
}

module.exports = {
  parseVersion,
  compareVersions,
  isInRange,
};
