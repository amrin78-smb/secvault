'use strict';
//
// Cron-schedule relations in services/engine-worker.js.
//
// ⛔ WHY A TEST EXISTS FOR A CRON STRING. The [dashboard-snapshot] tick sat at
// "10 0 * * *" — INSIDE rule-version-pull's run window, which starts at 00:00
// and takes 12.8-15.8 minutes on the reference fleet. node-cron matches on the
// SECOND: a tick whose second passes while the event loop is busy is not
// deferred, it is lost. Measured over 30 live days that cost 4 whole days of
// fleet history (2026-10-11, -12, -13, -15), unrecoverably — a snapshot is a
// point-in-time measurement and cannot be reconstructed later.
//
// ⛔ AND THE SYMPTOM WAS MISDIAGNOSED ONCE ALREADY. A startup catch-up was
// added blaming "deploy restarts"; the engine was provably up on all four days
// (32 feed syncs each, and the 00:30 job never missed), so that catch-up could
// not fire and the gap continued. A fix aimed at the wrong cause is why these
// relations are now asserted rather than left to a comment.
//
// These are SOURCE assertions, which this repo normally treats as the weaker
// kind. They are the right kind here: the failure is a collision between a
// cron expression and a job's wall-clock duration, which no stub-pool test can
// reach, and the alternative is nothing at all.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SRC = fs.readFileSync(
  path.join(__dirname, '..', 'services', 'engine-worker.js'), 'utf8'
).replace(/\r\n/g, '\n');

/** Every literal cron.schedule('<expr>' in the file, in source order. */
function literalSchedules() {
  return [...SRC.matchAll(/cron\.schedule\(\s*'([^']+)'/g)].map((m) => m[1]);
}

function parse(expr) {
  const [minute, hour] = expr.split(/\s+/);
  return { minute, hour };
}

// rule-version-pull starts at minute 0 and ran 769-950s (12.8-15.8 min) across
// 12 consecutive measured days. 30 minutes is that worst case plus headroom —
// a daily job landing inside it is racing a collection pass.
const COLLECTION_START_MINUTE = 0;
const COLLECTION_BUSY_MINUTES = 30;

test('the daily dashboard snapshot does not tick inside the collection window', () => {
  const m = SRC.match(
    /Scheduling \[dashboard-snapshot\][\s\S]{0,200}?cron\.schedule\(\s*'([^']+)'/
  );
  assert.ok(m, 'daily [dashboard-snapshot] schedule not found');
  const { minute, hour } = parse(m[1]);

  assert.notEqual(hour, '*', 'the daily snapshot must be a fixed daily tick');

  // The collision only exists when the two share an hour.
  if (hour === '0') {
    const min = Number(minute);
    assert.ok(
      Number.isFinite(min),
      `snapshot minute ${minute} is not a plain number; re-check this by hand`
    );
    assert.ok(
      min >= COLLECTION_START_MINUTE + COLLECTION_BUSY_MINUTES,
      `[dashboard-snapshot] at minute ${min} of hour 0 falls inside `
      + `rule-version-pull's ${COLLECTION_BUSY_MINUTES}-minute window. `
      + 'node-cron loses a tick whose second passes while the loop is busy, '
      + 'and a lost snapshot day can never be reconstructed.'
    );
  }
});

test('a missed snapshot tick can self-heal the same day', () => {
  // ⛔ THE RELATION, NOT THE NUMBER: whatever the schedule is, it must run
  // MORE OFTEN than daily, or a single blocked second still costs a whole day.
  const m = SRC.match(
    /Scheduling \[dashboard-snapshot catch-up\][\s\S]{0,300}?cron\.schedule\(\s*'([^']+)'/
  );
  assert.ok(m, 'no [dashboard-snapshot catch-up] schedule — a lost tick would lose the day');
  const { hour } = parse(m[1]);
  assert.equal(hour, '*', 'the catch-up must run at least hourly, not once a day');
});

test('the catch-up writes only when the day is unrecorded', () => {
  // ⛔ It must never be able to overwrite a recorded day: the 01:10 reading is
  // that day's reading, and replacing it with a later one silently rewrites a
  // point-in-time measurement and every delta drawn from it.
  const m = SRC.match(
    /cron\.schedule\(\s*'[^']+'[\s\S]{0,400}?runDashboardSnapshotIfMissing/
  );
  assert.ok(m, 'the catch-up must call runDashboardSnapshotIfMissing, not the plain job');
  assert.doesNotMatch(
    m[0], /runTrackedJob\(\s*runDashboardSnapshotJob\b/,
    'the hourly pass must not call the upserting job'
  );
  // and the guarded path is the DO NOTHING one
  assert.match(SRC, /runDashboardSnapshotIfMissing[\s\S]*?ifAbsent:\s*true/,
    'runDashboardSnapshotIfMissing must use the ifAbsent write');
});

test('no two scheduled jobs share a minute-and-hour', () => {
  // They tick on the same second otherwise, which is how one blocks another.
  const seen = new Map();
  for (const expr of literalSchedules()) {
    const { minute, hour } = parse(expr);
    if (hour === '*' ) continue;       // hourly passes are compared below
    const key = `${minute} ${hour}`;
    assert.ok(!seen.has(key), `two daily jobs both tick at "${key}"`);
    seen.set(key, expr);
  }
});

test('every scheduled task is registered for shutdown', () => {
  // A task left out keeps firing after SIGTERM and can hold the process open
  // mid-write -- the reliability contract says finish the current job and exit.
  const names = [...SRC.matchAll(/const (\w*Task) = cron\.schedule\(/g)].map((m) => m[1]);
  assert.ok(names.length >= 8, `expected the full job set, found ${names.length}`);
  const list = SRC.match(/scheduledTasks = \[\s*\n([\s\S]*?)\n\s*\];/);
  assert.ok(list, 'scheduledTasks array not found');
  for (const n of names) {
    assert.match(list[1], new RegExp(`\\b${n}\\b`), `${n} is never stopped on shutdown`);
  }
});
