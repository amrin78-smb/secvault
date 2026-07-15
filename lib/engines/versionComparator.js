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

// Per-vendor dispatch table. Only 'forcepoint' is implemented in Phase 1+2;
// new vendors plug in here in later phases. The default/fallback case (see
// parseVersion below) behaves like the forcepoint parser as a reasonable
// fallback for unknown vendors, rather than throwing.
const VENDOR_PARSERS = {
  forcepoint: parseForcepointVersion,
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
