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

const { planMinutelyCron, planHourlyCron, minutesOf, hoursOf } = require('../lib/cronPlan');

/** Every literal cron.schedule('<expr>' in the file, in source order. */
function literalSchedules() {
  return [...SRC.matchAll(/cron\.schedule\(\s*'([^']+)'/g)].map((m) => m[1]);
}

// ⛔ EVERY schedule the engine registers, not just the quoted ones. This test
// used to read literals only, so the five COMPUTED schedules (feed, config,
// vpn, snmp, notifications) were invisible to the collision check below — and
// that is exactly how the snapshot catch-up shipped on minute :37, sharing a
// second with [snmp-poll]'s computed 7,22,37,52 every hour. Three shapes are
// resolved: a quoted literal, a `cron.schedule(IDENT` whose const is declared
// in the file, and the minute-scale builders, whose arithmetic is IMPORTED from
// lib/cronPlan.js rather than recomputed here — a second copy would eventually
// disagree, and the disagreeing one would be the one calling the schedule safe.
function allSchedules() {
  const out = [];
  for (const expr of literalSchedules()) out.push({ expr, how: 'literal' });

  for (const m of SRC.matchAll(/cron\.schedule\(\s*([A-Za-z_$][\w$]*)\s*,/g)) {
    const ident = m[1];
    const lit = SRC.match(new RegExp(`const ${ident}\\s*=\\s*'([^']+)'`));
    if (lit) { out.push({ expr: lit[1], how: `const ${ident}` }); continue; }
    // Built by buildMinutelyCron — covered by the `computed` list below, whose
    // arithmetic is the engine's own via lib/cronPlan.js.
    const built = SRC.match(new RegExp(`const ${ident}\\s*=\\s*build(?:Minutely|Hourly)Cron\\(`));
    assert.ok(built, `cron.schedule(${ident}) but ${ident} is neither a literal const nor `
      + 'built by build(Minutely|Hourly)Cron — this test cannot see that schedule, which is '
      + 'gap it exists to close');
  }

  // The defaults documented in .env.local.example / CLAUDE.md. If a default
  // changes, this list must change with it.
  const computed = [
    ['feed-sync', planHourlyCron(6).expr],
    ['config-pull', planHourlyCron(24).expr],
    ['vpn-poll', planMinutelyCron(30).expr],
    ['snmp-poll', planMinutelyCron(15, 7).expr],
    ['notifications', planMinutelyCron(15).expr],
  ];
  for (const [name, expr] of computed) out.push({ expr, how: `computed ${name}` });
  return out;
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
  // The expression is a named const now (so the collision test can read it),
  // so match that rather than an inline literal.
  const m = SRC.match(
    /Scheduling \[dashboard-snapshot catch-up\][\s\S]{0,300}?cron\.schedule\(\s*CATCHUP_CRON/
  )
    ? SRC.match(/const CATCHUP_CRON = '([^']+)'/)
    : null;
  assert.ok(m, 'no [dashboard-snapshot catch-up] schedule — a lost tick would lose the day');
  // ⛔ THE RELATION, read through the shared cron parser: the catch-up must fire
  // on more than one hour a day. It used to assert `hour === '*'`, which is a
  // SHAPE — and that shape is exactly what had to change, because an
  // every-hour catch-up pre-empted the daily tick it exists to back up.
  const { hour } = parse(m[1]);
  assert.ok(hoursOf(hour).length > 1,
    `the catch-up must run more than once a day, got hour field "${hour}"`);
});

test('the catch-up writes only when the day is unrecorded', () => {
  // ⛔ It must never be able to overwrite a recorded day: the 01:10 reading is
  // that day's reading, and replacing it with a later one silently rewrites a
  // point-in-time measurement and every delta drawn from it.
  const m = SRC.match(
    /cron\.schedule\(\s*(?:'[^']+'|CATCHUP_CRON)[\s\S]{0,400}?runDashboardSnapshotIfMissing/
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

test('⛔ neither snapshot job shares a tick with any other job', () => {
  // ⛔ SCOPED TO THE SNAPSHOT JOBS DELIBERATELY, AND THE SCOPE IS THE FINDING.
  // A general "no two jobs ever collide" assertion fails on the shipped
  // defaults: buildHourlyCron(6)/(24) put feed-sync and config-pull on minute
  // 0, vpn-poll is */30 and notifications */15, so minute 0 of hour 0 already
  // carries four jobs by design. Those overlaps are tolerable because every
  // one of those jobs is REPEATED — a lost VPN poll is replaced 30 minutes
  // later. A lost fleet snapshot is not: it is a point-in-time measurement and
  // nothing can reconstruct what the fleet looked like that day, which is why
  // four days of history were permanently lost. So the snapshot jobs get the
  // strict rule and the repeated ones do not.
  //
  // ⛔ THIS REPLACES A CHECK THAT COULD NOT FIRE. It read `if (hour === '*')
  // continue; // hourly passes are compared below` and there was no comparison
  // below, so every hourly job was skipped; and it collected only quoted
  // literals, so the five COMPUTED schedules were never compared at all. That
  // is how the catch-up came to share minute :37 with [snmp-poll]'s computed
  // 7,22,37,52 on the shipped defaults.
  const all = allSchedules();
  const snapshotExprs = new Set();
  const daily = SRC.match(
    /Scheduling \[dashboard-snapshot\][\s\S]{0,200}?cron\.schedule\(\s*'([^']+)'/
  );
  const catchUp = SRC.match(/const CATCHUP_CRON = '([^']+)'/);
  assert.ok(daily && catchUp, 'both snapshot schedules must be readable');
  snapshotExprs.add(daily[1]);
  snapshotExprs.add(catchUp[1]);

  const slotsOf = (expr) => {
    const [minute, hour] = expr.split(/\s+/);
    const dom = expr.split(/\s+/)[2] || '*';
    const out = [];
    for (const h of hoursOf(hour)) for (const m of minutesOf(minute)) out.push(`${dom} ${h}:${m}`);
    return out;
  };

  for (const expr of snapshotExprs) {
    const mine = new Set(slotsOf(expr));
    for (const other of all) {
      if (snapshotExprs.has(other.expr)) continue;
      for (const slot of slotsOf(other.expr)) {
        assert.ok(!mine.has(slot),
          `the snapshot schedule "${expr}" collides with ${other.how} ("${other.expr}") `
          + `at ${slot} — they would start in the same second, and node-cron LOSES a tick `
          + 'whose second passes while the event loop is busy');
      }
    }
  }
});

test('⛔ the catch-up may not pre-empt the daily snapshot tick', () => {
  // At 00:37 the catch-up ran BEFORE the 01:10 daily tick every single day:
  // today's row did not exist yet, so the "safety net" computed the whole fleet
  // snapshot and the daily tick then recomputed it — the heaviest read-only job
  // in the engine running twice nightly, with the catch-up as the de-facto
  // primary writer. The stored value was still the 01:10 reading only because
  // that path upserts, i.e. by accident rather than by this mechanism.
  const daily = SRC.match(
    /Scheduling \[dashboard-snapshot\][\s\S]{0,200}?cron\.schedule\(\s*'([^']+)'/
  );
  assert.ok(daily, 'daily [dashboard-snapshot] schedule not found');
  const [dMin, dHour] = daily[1].split(/\s+/);

  const catchUp = SRC.match(/const CATCHUP_CRON = '([^']+)'/);
  assert.ok(catchUp, 'the catch-up schedule must be a named const this test can read');
  const [cMin, cHour] = catchUp[1].split(/\s+/);

  const dailyHour = Number(dHour);
  assert.ok(Number.isInteger(dailyHour), 'the daily tick must be at a fixed hour');
  for (const h of hoursOf(cHour)) {
    assert.ok(h > dailyHour,
      `the catch-up fires at hour ${h}, at or before the daily tick's hour ${dailyHour} `
      + '— it would write the day before the daily tick ever measured it');
  }
  // And it must still be more often than daily, or it is not a catch-up.
  assert.ok(hoursOf(cHour).length > 1, 'the catch-up must run more than once a day');
  assert.ok(minutesOf(cMin).length >= 1);
  assert.notEqual(`${cMin} ${cHour}`, `${dMin} ${dHour}`);
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
