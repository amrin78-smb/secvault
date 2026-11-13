'use strict';

// tests/complianceTrendZone.test.js
//
// Pins ONE property of lib/engines/complianceTrend.js's `isoDay`: a DATE
// column read back through `pg` must keep the day the database stored,
// whatever timezone the server runs in.
//
// ⛔ WHY THIS IS A SEPARATE FILE WITH CHILD PROCESSES. The whole existing
// suite feeds `isoDay` plain 'YYYY-MM-DD' STRINGS, which take an early
// branch and never reach the Date path at all — so 49 passing tests said
// nothing about it. `pg` parses a `date` column (no time, no zone) into a JS
// Date at LOCAL MIDNIGHT, and the original line formatted that with
// `toISOString()`. On this product's own reference deployment
// (Asia/Bangkok, UTC+7) every stored day came back ONE DAY EARLY: measured
// against production, all 100 snapshots and both ends of the chart's caption.
//
// ⛔ AND AN IN-PROCESS TEST COULD NOT HAVE CAUGHT IT. Under a UTC host local
// midnight IS UTC midnight, so the broken code is correct there and a test
// running in CI's usual UTC passes either way. The zone has to be forced, and
// V8 caches it per process, so each case runs in its own child.
//
// ⛔ THE ZONE LIST IS CHOSEN, NOT DECORATIVE. A NEGATIVE offset cannot expose
// this bug — local midnight in UTC-5 is 05:00Z on the SAME day — so a test
// built only from UTC and a US zone would have passed on the broken code.
// Asia/Bangkok is what production runs; Pacific/Kiritimati (UTC+14) is the
// largest offset in the world and the strongest form of the same case.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const REPO = path.join(__dirname, '..');

// Zones where the day-key must survive a round trip. The two positive
// offsets are the ones that fail on a UTC-formatted key.
const ZONES = ['UTC', 'Asia/Bangkok', 'Pacific/Kiritimati', 'America/New_York'];

// Dates worth pinning: an ordinary day, a month boundary, a year boundary,
// and the four cron days CLAUDE.md records as permanently lost — the exact
// days this feature exists to render as holes, and so the exact days whose
// labels must not drift.
const DAYS = [
  [2026, 11, 13],
  [2026, 10, 11], [2026, 10, 12], [2026, 10, 13], [2026, 10, 15],
  [2026, 1, 1], [2026, 12, 31], [2026, 3, 1],
];

function isoDayUnder(zone, days) {
  // `new Date(y, m - 1, d)` is LOCAL midnight — the exact shape `pg` hands a
  // caller for a `date` column, which is what makes this a real reproduction
  // rather than a restatement of the implementation.
  const script = `
    const { isoDay } = require(${JSON.stringify(path.join(REPO, 'lib/engines/complianceTrend.js'))});
    const days = ${JSON.stringify(days)};
    console.log(JSON.stringify(days.map(([y, m, d]) => isoDay(new Date(y, m - 1, d)))));
  `;
  const out = execFileSync(process.execPath, ['-e', script], {
    env: { ...process.env, TZ: zone },
    encoding: 'utf8',
  });
  return JSON.parse(out);
}

const expected = DAYS.map(
  ([y, m, d]) => `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`
);

for (const zone of ZONES) {
  test(`isoDay keeps a DATE column's own day under TZ=${zone}`, () => {
    assert.deepEqual(
      isoDayUnder(zone, DAYS),
      expected,
      `under TZ=${zone} a date read from the database came back as a different day`
    );
  });
}

test('isoDay still accepts a plain day string unchanged, in every zone', () => {
  for (const zone of ZONES) {
    const script = `
      const { isoDay } = require(${JSON.stringify(path.join(REPO, 'lib/engines/complianceTrend.js'))});
      console.log(JSON.stringify([isoDay('2026-10-15'), isoDay('2026-10-15T00:00:00+07:00')]));
    `;
    const [bare, withTime] = JSON.parse(
      execFileSync(process.execPath, ['-e', script], { env: { ...process.env, TZ: zone }, encoding: 'utf8' })
    );
    // ⛔ The string branch must stay zone-free: it is what the engine's own
    // day arithmetic (addDays/daysBetween) round-trips through.
    assert.equal(bare, '2026-10-15', `bare day string shifted under TZ=${zone}`);
    assert.equal(withTime, '2026-10-15', `prefixed day string shifted under TZ=${zone}`);
  }
});
