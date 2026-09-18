'use strict';
// tests/trafficTimelineGaps.test.js
//
// ⛔ WHEN TRAFFIC STOPPED IS THE ONE THING A TRAFFIC TIMELINE EXISTS TO SHOW.
// The rollup writes no row for an hour in which nothing was stored, so a strip
// that maps only the rows it received spreads however many bars exist evenly
// across a 24-hour axis: a ten-hour ingestion outage renders as an unbroken,
// healthy-looking series. Every case here is that failure.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { fillHourlyGaps } = require('../lib/syslog/trafficStats');

const H = 3600000;
const NOW = Date.parse('2026-09-18T10:30:00Z');
const at = (iso) => new Date(iso);

describe('fillHourlyGaps', () => {
  it('⛔ always returns one slot per hour, however few rows came back', () => {
    const out = fillHourlyGaps([{ hour: at('2026-09-18T09:00:00Z'), events: 5 }], 24, NOW);
    assert.equal(out.length, 24);
  });

  it('⛔ a filled hour is NOT MEASURED, not a measured zero', () => {
    const out = fillHourlyGaps([{ hour: at('2026-09-18T09:00:00Z'), events: 5 }], 4, NOW);
    const missing = out.filter((r) => !r.measured);
    assert.equal(missing.length, 3);
    for (const m of missing) {
      assert.equal(m.measured, false, 'the renderer gates its hueless treatment on this');
      // ⛔ denied stays NULL. Filling it with 0 would state that no traffic was
      // denied in an hour we have no rows for at all.
      assert.equal(m.denied, null);
      assert.equal(m.bytesSent, null);
    }
  });

  it('a real row keeps every field and is marked measured', () => {
    const src = { hour: at('2026-09-18T09:00:00Z'), events: 5, denied: 2, bytesSent: 9, bytesReceived: 8 };
    const out = fillHourlyGaps([src], 2, NOW);
    const kept = out.find((r) => r.measured);
    assert.equal(kept.events, 5);
    assert.equal(kept.denied, 2);
    assert.equal(kept.bytesSent, 9);
    assert.equal(kept.bytesReceived, 8);
  });

  it('the window ends at the current hour and runs backwards in order', () => {
    const out = fillHourlyGaps([], 3, NOW);
    assert.deepEqual(
      out.map((r) => r.hour.toISOString()),
      [
        new Date(Math.floor(NOW / H) * H - 2 * H).toISOString(),
        new Date(Math.floor(NOW / H) * H - 1 * H).toISOString(),
        new Date(Math.floor(NOW / H) * H).toISOString(),
      ]
    );
  });

  it('⛔ an empty series is 24 gaps, never an empty chart', () => {
    // An empty chart and a silent fleet look identical; 24 hueless slots do not.
    const out = fillHourlyGaps([], 24, NOW);
    assert.equal(out.length, 24);
    assert.equal(out.every((r) => r.measured === false), true);
    assert.equal(out.reduce((n, r) => n + r.events, 0), 0);
  });

  it('a row outside the window is dropped rather than shifted into it', () => {
    const out = fillHourlyGaps([{ hour: at('2026-09-01T09:00:00Z'), events: 999 }], 4, NOW);
    assert.equal(out.every((r) => r.measured === false), true);
    assert.equal(out.reduce((n, r) => n + r.events, 0), 0, 'an old row must not be redated');
  });

  it('an unparseable hour is ignored, not turned into a bar at epoch zero', () => {
    const out = fillHourlyGaps([{ hour: 'not a date', events: 7 }], 4, NOW);
    assert.equal(out.length, 4);
    assert.equal(out.every((r) => r.measured === false), true);
  });

  it('a string timestamp from the driver is matched to its hour', () => {
    // node-pg returns Date objects, but the rollup rows travel through a server
    // component boundary in places; a string must not silently become a gap.
    const out = fillHourlyGaps([{ hour: '2026-09-18T10:00:00.000Z', events: 3 }], 2, NOW);
    assert.equal(out.filter((r) => r.measured).length, 1);
    assert.equal(out[out.length - 1].events, 3);
  });

  it('is pure — the clock is a parameter, and two calls agree', () => {
    const a = fillHourlyGaps([], 5, NOW);
    const b = fillHourlyGaps([], 5, NOW);
    assert.deepEqual(a.map((r) => r.hour.toISOString()), b.map((r) => r.hour.toISOString()));
  });
});
