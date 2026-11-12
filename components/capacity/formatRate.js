'use strict';

// components/capacity/formatRate.js
//
// Byte formatting for the bandwidth trend board.
//
// ⛔ A SEPARATE, JSX-FREE MODULE SO `npm test` CAN ACTUALLY REQUIRE IT. The
// board is a JSX file and `node:test` loads modules with no transform, so a
// formatter living inside it could only be checked by a SOURCE SCAN — which is
// "testing the mechanism, not the outcome", the pattern CLAUDE.md records
// shipping three broken features in one day. The rules below are decisions
// about what a reader sees, so they are pinned by behaviour.
//
// ⛔ COMMONJS, like lib/navRegistry.js and lib/navLayout.js, which components
// already import the same way. ES `export` here would make this file
// unrequirable by `node:test` (this package is not type:module), which is the
// one thing it was split out to allow. webpack handles the interop, so the
// board's `import { rateGroup } from './formatRate'` works unchanged.

const UNITS = [
  ['TB', 1024 ** 4],
  ['GB', 1024 ** 3],
  ['MB', 1024 ** 2],
  ['KB', 1024],
];

/**
 * ⛔ NULL IS NEVER FORMATTED AS A NUMBER. It returns null and the caller renders
 * <NotMeasured>, because `(0).toFixed(2)` on a missing figure is the fabricated
 * zero this whole feature exists to refuse.
 */
function bytesText(v) {
  // ⛔ THE EMPTY STRING IS TESTED SEPARATELY, AND LEAVING IT OUT WAS A LIVE
  // FABRICATED ZERO IN THE FUNCTION WHOSE DOCSTRING REFUSES THEM. `Number('')`
  // is 0 and `Number.isFinite(0)` is true, so `bytesText('')` returned
  // "0 B" — a confident zero printed for a figure that did not arrive. `pg`
  // hands back an empty string for some shapes, which is exactly why
  // `capacityForecast.js`'s own `num()` lists it. Found by the test below, not
  // by reading this.
  if (v === null || v === undefined || v === '') return null;
  if (!Number.isFinite(Number(v))) return null;
  const n = Number(v);
  const abs = Math.abs(n);
  for (const [unit, size] of UNITS) {
    if (abs >= size) return `${(n / size).toFixed(abs / size >= 100 ? 0 : 2)} ${unit}`;
  }
  return `${Math.round(n)} B`;
}

/** A rate. Always carries its "/day", so it can never be read as a total. */
function rateText(v) {
  const t = bytesText(v);
  return t === null ? null : `${t}/day`;
}

/**
 * A value and its interval, formatted in ONE unit.
 *
 * ⛔ THE UNIT IS CHOSEN FROM THE LARGEST OF THEM, AND THIS WAS A REAL DEFECT
 * FOUND BY RENDERING THE LIVE FLEET. Formatting each figure independently gave
 * SMT a rate of `+1.19 GB/day` against an interval of
 * `-699 MB/day to +5.02 GB/day`. A reader scanning that has to convert in their
 * head, and `-699` beside `+5.02` reads as the LARGER of the two — on the one
 * figure whose entire job is to say that the direction is not settled.
 *
 * ⛔ THE PRECISION COMES FROM THE GROUP TOO, or the point and its bounds print
 * to different numbers of decimals and stop lining up as one statement.
 *
 * @param {Array<number|null>} values  the point first, then its bounds
 * @returns {Array<string|null>} signed, same unit, same precision; null for a
 *   figure that was not measured
 */
function rateGroup(values) {
  // ⛔ SAME EMPTY-STRING RULE AS `bytesText`, for the same reason.
  const nums = (Array.isArray(values) ? values : [])
    .map((v) => (v === null || v === undefined || v === '' || !Number.isFinite(Number(v))
      ? null
      : Number(v)));
  const present = nums.filter((v) => v !== null).map(Math.abs);
  const biggest = present.length ? Math.max(...present) : 0;
  const pick = UNITS.find(([, size]) => biggest >= size);
  return nums.map((v) => {
    if (v === null) return null;
    // ⛔ THE SIGN IS APPLIED ONCE, AFTER THE UNIT IS CHOSEN, SO BOTH BRANCHES
    // GET IT. It used to sit inside the scaled branch only, so a group entirely
    // under a kilobyte came back unsigned while the same group in KB was
    // signed — the identical statement reading as a rate in one unit and as a
    // level in another. Found by a test, not by reading this.
    const text = pick
      ? `${(v / pick[1]).toFixed(biggest / pick[1] >= 100 ? 0 : 2)} ${pick[0]}/day`
      : `${Math.round(v)} B/day`;
    // ⛔ ONLY A POSITIVE value gets a `+`. A zero is not "+0": it is a measured
    // zero, and signing it would read as a movement.
    return v > 0 ? `+${text}` : text;
  });
}

/**
 * The same group, unsigned — for LEVELS rather than changes.
 *
 * ⛔ A projection is a level a firewall reaches, not a delta, and printing
 * `On this trend, +6.81 GB/day` reads as a projected INCREASE of 6.81 GB/day
 * on top of today's traffic rather than as the traffic itself.
 */
function levelGroup(values) {
  return rateGroup(values).map((t) => (t === null ? null : t.replace(/^\+/, '')));
}

module.exports = {
  bytesText,
  rateText,
  rateGroup,
  levelGroup,
  RATE_UNITS: UNITS,
};
