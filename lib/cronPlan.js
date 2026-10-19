'use strict';
// lib/cronPlan.js
//
// The minute-scale cron expression builder, extracted PURE so a test can ask
// what the engine's computed schedules actually are.
//
// ⛔ IT WAS INLINE IN services/engine-worker.js, AND THAT IS WHY A LIVE
// COLLISION SHIPPED. tests/engineSchedules.test.js scrapes the source for
// `cron.schedule('<literal>'`, so it saw 7 of the 12 schedules; the five built
// by this function — feed, config, vpn, snmp, notifications — were invisible to
// the "no two jobs share a minute" assertion entirely. The engine cannot be
// `require`d from a test because it calls main() at load, so the only way to
// make that guard see a computed schedule is to put the computation somewhere
// importable. A guard that covers one shape and reports clean about the rest is
// worse than none: [dashboard-snapshot catch-up] was given minute :37 with the
// stated reasoning that it "never shares a second with the :00/:15/:30/:45
// jobs", and [snmp-poll] runs at 7,22,37,52 on the shipped defaults.
//
// ⛔ ONE IMPLEMENTATION, NOT TWO. The test must import this rather than
// recomputing the minutes itself — a second copy of this arithmetic would
// eventually disagree with the engine's, and the disagreeing one would be the
// one reporting the schedule safe.

/**
 * Pure. Returns { expr, fellBack } — `fellBack` is true when the interval was
 * unusable and 30 was substituted, so the caller can log that in its own voice
 * rather than this module needing a logger.
 */
function planMinutelyCron(intervalMinutes, offsetMinutes = 0) {
  let n = parseInt(intervalMinutes, 10);
  let fellBack = false;
  if (!Number.isInteger(n) || n < 5 || n > 59) {
    fellBack = true;
    n = 30;
  }
  const offset = Number.isInteger(offsetMinutes) ? ((offsetMinutes % n) + n) % n : 0;
  if (offset === 0) return { expr: `*/${n} * * * *`, fellBack };
  const minutes = [];
  for (let m = offset; m < 60; m += n) minutes.push(m);
  // A tail shorter than the interval would make the last gap of the hour
  // shorter than `n`; that is inherent to any non-divisor of 60 and is true of
  // `*/n` too, so it is accepted rather than papered over.
  return { expr: `${minutes.join(',')} * * * *`, fellBack };
}

/**
 * Pure. The hours-scale counterpart. Same contract as planMinutelyCron.
 */
function planHourlyCron(intervalHours) {
  let n = parseInt(intervalHours, 10);
  let fellBack = false;
  if (!Number.isInteger(n) || n < 1 || n > 24) {
    fellBack = true;
    n = 6;
  }
  return { expr: `0 */${n} * * *`, fellBack };
}

/**
 * The set of minutes-past-the-hour a cron minute field fires on. Handles the
 * three shapes this codebase emits: `*`, `*​/n`, and a comma list.
 */
function minutesOf(minuteField) {
  if (minuteField === '*') return Array.from({ length: 60 }, (_, i) => i);
  if (minuteField.startsWith('*/')) {
    const n = parseInt(minuteField.slice(2), 10);
    if (!Number.isInteger(n) || n < 1) return [];
    const out = [];
    for (let i = 0; i < 60; i += n) out.push(i);
    return out;
  }
  return minuteField.split(',').map((x) => parseInt(x, 10)).filter(Number.isInteger);
}

/**
 * The set of hours a cron hour field fires on. Handles `*`, `a-b` and a list.
 */
function hoursOf(hourField) {
  if (hourField === '*') return Array.from({ length: 24 }, (_, i) => i);
  const out = new Set();
  for (const part of hourField.split(',')) {
    const range = part.match(/^(\d+)-(\d+)$/);
    if (range) {
      for (let h = Number(range[1]); h <= Number(range[2]); h++) out.add(h);
    } else if (/^\d+$/.test(part)) {
      out.add(Number(part));
    }
  }
  return [...out].sort((a, b) => a - b);
}

module.exports = { planMinutelyCron, planHourlyCron, minutesOf, hoursOf };
