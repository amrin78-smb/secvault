'use strict';
// Pins the spool durability contract of services/collector.js and the two
// rollup/archive behaviours that hang off it.
//
// ⛔ WHY THIS FILE EXISTS. At ~74M events/day from 16 devices, every bug fixed
// here produced MILLIONS of wrong rows without a single error line:
//
//   1. a fire-and-forget startup replay racing the flush cycle's drain over the
//      same .ready files, INSERTing every event in them twice;
//   2. a "5 attempts" spool retry budget that, running once per 2s flush, was
//      really a TEN-SECOND budget — a brief DB restart quarantined ~78,000
//      events into .failed files that nothing ever reads again;
//   3. syslog_threat_hourly missing from the detail-rollup trim, growing at
//      ~22 GB/year while the trim logged success every cycle;
//   4. the threat rollup having no wide tier, so any event that landed late sat
//      in a bucket nothing ever revisited — permanently under-counted;
//   5. a replayed spool file archived under TODAY's day file rather than the
//      day the lines actually arrived;
//   6. `stored` omitting the drain's own rows, so a backlog clearing correctly
//      read as ongoing loss on the health panel.
//
// Every one is the same shape as hit_count DEFAULT 0: a plausible number where
// there should have been a measurement, so nothing crashes and nothing looks
// wrong. Tests are the only thing that catch this class.
//
// ⛔ services/collector.js CANNOT BE REQUIRED — it binds sockets and starts
// timers at module load (tests/moduleLoad.test.js lists it as parse-only). So
// the wiring facts are asserted against its SOURCE, and the two pieces that are
// importable (lib/syslog/archive.js, lib/syslog/rollups.js) are exercised for
// real, on a real temp directory and a recording pool stub.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const { appendRecords, fileNameFor } = require('../lib/syslog/archive');
const { trimDetailRollups } = require('../lib/syslog/rollups');

const COLLECTOR = fs.readFileSync(
  path.join(__dirname, '..', 'services', 'collector.js'), 'utf8'
);
const ENV_EXAMPLE = fs.readFileSync(
  path.join(__dirname, '..', '.env.local.example'), 'utf8'
);

// Call-site counting must not count the COMMENTS that explain the call sites —
// this file's rules are heavily documented in the source they pin.
function codeOnly(src) {
  return src
    .split('\n')
    .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
    .join('\n');
}
const COLLECTOR_CODE = codeOnly(COLLECTOR);

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sv-collector-'));
}

function readDay(dir, date) {
  const file = path.join(dir, fileNameFor(date));
  return zlib.gunzipSync(fs.readFileSync(file)).toString('utf8').split('\n').filter(Boolean);
}

// ─────────────────────────────────────────────────────────────────────────
// 1. ONE path picks up a spool file, not two
// ─────────────────────────────────────────────────────────────────────────
describe('spool: exactly one path processes a .ready file', () => {
  it('⛔ has no separate startup replay to race the flush drain', () => {
    // The deleted replayBacklog() was launched fire-and-forget after the
    // listeners bound, with a comment claiming it "shares the flush cycle's
    // `flushing` mutex". It never read or set that flag, so two seconds later
    // doFlush -> drainBacklog iterated the same directory and both called
    // processSpoolFile() on the same file: double INSERT, double archive
    // append, double count in every rollup rebuilt from raw, and an ENOENT
    // from the losing unlinkSync straight into a swallowed catch.
    assert.doesNotMatch(COLLECTOR, /function\s+replayBacklog/);
    assert.doesNotMatch(COLLECTOR, /replayBacklog\s*\(\s*\)\s*[.;]/);
  });

  it('⛔ calls processSpoolFile from exactly two places, both inside the flush', () => {
    // doFlush() on the file it just wrote, and drainBacklog() on the backlog —
    // and drainBacklog is only ever called from doFlush, which is guarded by
    // the `flushing` mutex. A third call site is how the race came back.
    const calls = COLLECTOR_CODE.match(/(?<!function\s)processSpoolFile\s*\(/g) || [];
    assert.equal(calls.length, 2, 'doFlush and drainBacklog, and nothing else');
    const drainCalls = COLLECTOR_CODE.match(/(?<!function\s)drainBacklog\s*\(/g) || [];
    assert.equal(drainCalls.length, 1, 'the single doFlush call');
  });

  it('⛔ drains the backlog even when no new datagrams arrived', () => {
    // The drain used to sit inside `if (batch.length > 0)`. A backlog is
    // exactly the state where traffic may have stopped, so gating the only
    // retry path on new arrivals let a quiet fleet strand its own spool
    // indefinitely — with replayBacklog gone, that would have been the only
    // catch-up path there is.
    const body = COLLECTOR.slice(COLLECTOR.indexOf('async function doFlush'));
    const drainAt = body.indexOf('await drainBacklog(');
    const branchAt = body.indexOf('if (batch.length > 0) {');
    assert.ok(drainAt > 0 && branchAt > 0);
    // The drain must be after the write branch has CLOSED, not nested in it.
    const between = body.slice(branchAt, drainAt);
    assert.match(between, /\n\s*}\n/, 'the drain must sit outside the batch branch');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// 2. The retry budget is a duration, and quarantine is reversible
// ─────────────────────────────────────────────────────────────────────────
describe('spool: the retry budget is time, not attempts', () => {
  it('⛔ quarantines only after BOTH a minimum attempt count and elapsed time', () => {
    assert.match(COLLECTOR, /SYSLOG_SPOOL_RETRY_MINUTES/);
    assert.match(COLLECTOR, /const\s+SPOOL_RETRY_MS\s*=/);
    // Both conditions on the same rename decision. drainBacklog runs once per
    // SYSLOG_FLUSH_MS, so an attempt count alone silently rescales with the
    // flush interval: at the default 2s, "5 attempts" was ten seconds.
    assert.match(
      COLLECTOR,
      /state\.attempts\s*>=\s*MIN_SPOOL_ATTEMPTS\s*&&\s*tryingMs\s*>=\s*SPOOL_RETRY_MS/
    );
  });

  it('⛔ re-arms .failed files at startup — nothing else ever reads one', () => {
    // Both scanners filter on .ready, so before this a quarantined file was a
    // permanent loss of durably-written events. The rename is the only thing
    // that puts them back in the queue.
    assert.match(COLLECTOR, /function\s+rearmFailedSpool/);
    assert.match(COLLECTOR, /replace\(\/\\\.failed\$\/,\s*'\.ready'\)/);
    assert.match(COLLECTOR, /rearmFailedSpool\(\)/);
  });

  it('⛔ documents the new variable in .env.local.example', () => {
    // A variable read in code but absent from the example file is a setting
    // no deployment will ever have.
    assert.match(ENV_EXAMPLE, /^SYSLOG_SPOOL_RETRY_MINUTES=/m);
  });

  it('never deletes a spool file it could not insert', () => {
    // Quarantine is a rename, always. A file we cannot parse or insert is
    // still evidence.
    const drain = COLLECTOR.slice(COLLECTOR.indexOf('async function drainBacklog'));
    assert.doesNotMatch(drain.slice(0, drain.indexOf('\n}')), /unlinkSync/);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// 3. Every detail rollup is trimmed, and the trim cannot outrun its readers
// ─────────────────────────────────────────────────────────────────────────
describe('rollups: syslog_threat_hourly is trimmed like every other detail rollup', () => {
  function recordingPool() {
    const calls = [];
    return { calls, query: async (sql, params) => { calls.push({ sql: String(sql), params }); return { rowCount: 1 }; } };
  }

  it('⛔ trims the threat rollup at all', async () => {
    // Measured live: 119,404 rows / 70 MB in 27 hours, ~22 GB/year, with
    // nothing anywhere deleting a row — while the trim's own log line reported
    // success on every cycle.
    const pool = recordingPool();
    const out = await trimDetailRollups(pool, 30);
    assert.ok('syslog_threat_hourly' in out.deleted);
    const call = pool.calls.find((c) => c.sql.includes('syslog_threat_hourly'));
    assert.match(call.sql, /bucket_hour </);
    assert.deepEqual(call.params, [30]);
  });

  it('⛔ keeps at least the 8 days its readers can ask for', async () => {
    // lib/syslog/threatStats.js clamps every query to 24*8 hours. Trimming
    // below that would answer a legitimate "last 7 days" with a partial series
    // and no sign it was partial — a rollup lying by omission.
    const pool = recordingPool();
    await trimDetailRollups(pool, 2);
    const threat = pool.calls.find((c) => c.sql.includes('syslog_threat_hourly'));
    assert.deepEqual(threat.params, [8], 'floored to the readers\' window');
    const talker = pool.calls.find((c) => c.sql.includes('syslog_talker_hourly'));
    assert.deepEqual(talker.params, [2], 'the floor is per-table, not a global override');
  });

  it('still passes the day count as a bound parameter', async () => {
    const pool = recordingPool();
    await trimDetailRollups(pool, 45);
    for (const c of pool.calls) {
      assert.doesNotMatch(c.sql, /45/, 'never interpolated into SQL');
      assert.deepEqual(c.params, [45]);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────
// 4. The threat rollup has a wide tier of its own
// ─────────────────────────────────────────────────────────────────────────
describe('rollups: the threat pass catches late arrivals', () => {
  it('⛔ runs a periodic WIDE pass, not just one at startup', () => {
    // refreshThreatRollup sits outside recomputeWindow, so it is also outside
    // the sliced wide sweep that exists to revisit buckets an event landed in
    // late. received_at is stamped on arrival and never rewritten, so a spool
    // file drained hours later belongs to a bucket the recent tier no longer
    // covers. With the 24h pass only at startup, that bucket stayed wrong
    // forever with no error anywhere.
    const main = COLLECTOR.slice(COLLECTOR.indexOf('async function main'));
    assert.match(
      main,
      /setInterval\(\s*\(\)\s*=>\s*\{\s*threatRollupCycle\(ROLLUP_LOOKBACK_HOURS,\s*'wide'\);\s*\},\s*60\s*\*\s*60\s*\*\s*1000/
    );
    assert.match(main, /threatRollupCycle\(ROLLUP_RECENT_HOURS \+ 1, 'recent'\)/);
    assert.match(main, /clearInterval\(threatWideTimer\)/, 'and is stopped on shutdown');
  });

  it('⛔ never overlaps two threat passes', () => {
    // Both tiers DELETE and re-INSERT the same buckets, and the table's
    // UNIQUE NULLS NOT DISTINCT key means the loser aborts its bucket.
    assert.match(COLLECTOR, /if \(threatRunning\)/);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// 5. The archive files a line under the day it ARRIVED
// ─────────────────────────────────────────────────────────────────────────
describe('archive: records are filed by their own receivedAt', () => {
  it('⛔ splits one batch across the UTC midnight it straddles', () => {
    // Guaranteed once a day, forever: a flush that starts at 23:59:59 and
    // inserts at 00:00:01. Passing `new Date()` put the 23:59 lines in the
    // next day's file.
    const dir = tmpDir();
    try {
      const before = new Date('2026-09-08T23:59:59Z');
      const after = new Date('2026-09-09T00:00:01Z');
      const r = appendRecords(dir, [
        { line: 'late on the 8th', receivedAt: before },
        { line: 'early on the 9th', receivedAt: after },
        { line: 'also the 8th', receivedAt: before },
      ]);
      assert.equal(r.ok, true);
      assert.deepEqual(readDay(dir, before), ['late on the 8th', 'also the 8th']);
      assert.deepEqual(readDay(dir, after), ['early on the 9th']);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('⛔ a spool file replayed days later still lands in ITS day', () => {
    // The forensic case. This archive is the ONLY copy of the raw line for the
    // ~89% of traffic SYSLOG_RAW_MESSAGE=security drops from the database, so
    // filing a replayed batch under the restart date makes a zgrep of the
    // correct day silently come back short — no error, no gap, just fewer
    // lines than really existed.
    const dir = tmpDir();
    try {
      const arrived = new Date('2026-09-01T04:20:00Z');
      appendRecords(dir, [{ line: 'stranded by a DB outage', receivedAt: arrived }]);
      assert.deepEqual(readDay(dir, arrived), ['stranded by a DB outage']);
      // and nothing was written under "today"
      assert.equal(fs.existsSync(path.join(dir, fileNameFor(new Date()))), false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('⛔ never throws, whatever it is handed — ingest must survive the archive', () => {
    const dir = tmpDir();
    try {
      assert.equal(appendRecords(dir, []).ok, true);
      assert.equal(appendRecords(dir, null).ok, true);
      assert.equal(appendRecords('', [{ line: 'x', receivedAt: new Date() }]).ok, false);
      // A record with an unusable stamp falls back to the supplied day rather
      // than throwing or being dropped: the line is still evidence.
      const fallback = new Date('2026-09-05T12:00:00Z');
      const r = appendRecords(dir, [{ line: 'no stamp', receivedAt: null }], fallback);
      assert.equal(r.ok, true);
      assert.deepEqual(readDay(dir, fallback), ['no stamp']);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('⛔ the collector passes records, not lines plus new Date()', () => {
    assert.match(COLLECTOR, /archive\.appendRecords\(ARCHIVE_DIR, records\)/);
    assert.doesNotMatch(COLLECTOR, /appendBatch\([^)]*new Date\(\)\)/);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// 6. stored counts what the drain stored
// ─────────────────────────────────────────────────────────────────────────
describe('ingest stats: a clearing backlog is not reported as loss', () => {
  it('⛔ adds the drain\'s own rows to stored/parsed/unknown counts', () => {
    // `stored + dropped === received` is an AGGREGATE identity over time, not
    // a per-row one: a file that fails in cycle A is received there with
    // stored 0, and its rows are credited in whichever later cycle inserted
    // them. Omitting the drain broke that identity permanently, in the
    // direction that looks like data loss.
    assert.match(COLLECTOR, /stored:\s*r\.stored \+ drain\.stored/);
    assert.match(COLLECTOR, /parsed:\s*r\.parsed \+ drain\.parsed/);
    assert.match(COLLECTOR, /unknownVendor:\s*r\.unknownVendor \+ drain\.unknownVendor/);
    assert.match(COLLECTOR, /unknownSource:\s*r\.unknownSource \+ drain\.unknownSource/);
  });

  it('⛔ still records a row whenever anything happened, including drops', () => {
    // `dropped` is the one number an operator cannot reconstruct from
    // anywhere else, and a stdout line is not a record.
    assert.match(
      COLLECTOR,
      /if \(batch\.length > 0 \|\| droppedThisCycle > 0 \|\| drain\.files > 0\)/
    );
  });
});
