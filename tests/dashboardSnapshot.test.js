'use strict';
// Pins lib/engines/dashboardSnapshot.js's WRITE semantics.
//
// WHY THIS FILE EXISTS: fleet_dashboard_snapshots is the only place a
// point-in-time fleet measurement is ever recorded. Two distinct ways to get
// it wrong, both of which build clean and both of which produce a chart that
// looks entirely plausible:
//
//  1. A missed 00:10 tick (node-cron does not re-run one the process was down
//     for) permanently loses that day. Measured live: 21 snapshots across 28
//     days. The startup catch-up exists to stop TODAY joining that list.
//  2. The catch-up overwriting a day already recorded — replacing the 00:10
//     measurement with mid-day numbers under the same date. That is the
//     failed-read-as-a-fact rule pointed at history instead of at a device:
//     the row still says "this is what the fleet looked like on Sep 09", and
//     it is no longer true. It really happened — the startup run was
//     unconditional, so every deploy restart rewrote that day.
//
// ⛔ NO DATABASE. `computeAndStoreDashboardSnapshot(pool, options)` only ever
// calls `pool.query(sql, params)`, so every test hands it a stub that records
// the statements it was given and returns canned rows. That gives two things
// to pin: the SQL the engine BUILDS (which conflict action it chose) and how
// it interprets what comes back.
//
// SQL assertions match a meaningful FRAGMENT, never a whole string — a
// reformat is then a one-line test update, while a removed protection still
// fails loudly.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  computeAndStoreDashboardSnapshot,
  computeFleetCveSeverity,
  computeFleetComplianceScores,
} = require('../lib/engines/dashboardSnapshot');

// --------------------------------------------------------------------------
// Stub pool
// --------------------------------------------------------------------------

// The engine runs several reads before its write (CVE severity, compliance
// findings, and fleetHeadline's own queries). None of them are what this file
// is about, so the stub answers every SELECT with an empty result and only
// pays attention to the INSERT. `insertRowCount` is what PostgreSQL would
// report back for the write: 1 when a row was written, 0 when
// ON CONFLICT DO NOTHING found today already present.
function makeStubPool({ insertRowCount = 1, cveRows = null } = {}) {
  const calls = [];
  const pool = {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      if (/^\s*INSERT INTO fleet_dashboard_snapshots/i.test(sql)) {
        return { rowCount: insertRowCount, rows: insertRowCount ? [{ snapshot_date: '2026-09-09' }] : [] };
      }
      if (cveRows && /FROM device_cve_assessments/i.test(sql)) {
        return { rowCount: cveRows.length, rows: cveRows };
      }
      return { rowCount: 0, rows: [] };
    },
  };
  return pool;
}

function insertOf(pool) {
  const call = pool.calls.find((c) => /^\s*INSERT INTO fleet_dashboard_snapshots/i.test(c.sql));
  assert.ok(call, 'engine never issued an INSERT into fleet_dashboard_snapshots');
  return call;
}

// --------------------------------------------------------------------------
// The write mode the startup catch-up uses
// --------------------------------------------------------------------------

describe('computeAndStoreDashboardSnapshot — ifAbsent mode never overwrites a recorded day', () => {
  it('uses ON CONFLICT DO NOTHING, so an already-recorded day is left exactly as measured', async () => {
    const pool = makeStubPool({ insertRowCount: 0 });
    await computeAndStoreDashboardSnapshot(pool, { ifAbsent: true });
    const { sql } = insertOf(pool);

    // The guarantee: it rests on the table's own UNIQUE(snapshot_date), not on
    // a read-then-write check that two racing startups could both pass.
    assert.match(sql, /ON CONFLICT \(snapshot_date\) DO NOTHING/i);
    // And emphatically NOT the upsert — a DO UPDATE here would rewrite the
    // 00:10 measurement with restart-time numbers.
    assert.doesNotMatch(sql, /DO UPDATE/i);
    assert.doesNotMatch(sql, /recorded_at\s*=\s*now\(\)/i);
  });

  it('reports stored:false — "today was already recorded", not a silent success', async () => {
    // ⛔ The "we could not measure this" case for this engine. A conflict is
    // not a failure and not a write; the caller has to be able to tell the
    // difference, or a log line will claim a row was taken when none was.
    const pool = makeStubPool({ insertRowCount: 0 });
    const res = await computeAndStoreDashboardSnapshot(pool, { ifAbsent: true });
    assert.equal(res.stored, false);
  });

  it('reports stored:true when today really was missing and the row went in', async () => {
    const pool = makeStubPool({ insertRowCount: 1 });
    const res = await computeAndStoreDashboardSnapshot(pool, { ifAbsent: true });
    assert.equal(res.stored, true);
  });

  it('never names a date other than CURRENT_DATE — no backfilling a lost day', async () => {
    // The columns are all "as of now" values, so an older day's numbers no
    // longer exist. Writing today's under an older snapshot_date would
    // fabricate history, which is worse than the gap the chart already shows
    // honestly. The engine must have no way to express any other date: the
    // date is a SQL literal, never a parameter a caller could supply.
    const pool = makeStubPool({ insertRowCount: 1 });
    await computeAndStoreDashboardSnapshot(pool, { ifAbsent: true });
    const { sql, params } = insertOf(pool);

    assert.match(sql, /VALUES \(CURRENT_DATE,/i);
    assert.doesNotMatch(sql, /snapshot_date\s*=\s*\$/i);
    for (const p of params) {
      assert.ok(!(p instanceof Date), 'a Date reached the INSERT params — the date must stay CURRENT_DATE');
    }
  });
});

// --------------------------------------------------------------------------
// The write mode the 00:10 daily tick uses — deliberately unchanged
// --------------------------------------------------------------------------

describe('computeAndStoreDashboardSnapshot — default mode is still the daily upsert', () => {
  it('upserts and refreshes recorded_at when called with no options', async () => {
    const pool = makeStubPool({ insertRowCount: 1 });
    await computeAndStoreDashboardSnapshot(pool);
    const { sql } = insertOf(pool);
    assert.match(sql, /ON CONFLICT \(snapshot_date\) DO UPDATE/i);
    assert.match(sql, /recorded_at\s*=\s*now\(\)/i);
  });

  it('treats an absent/garbage options object as the default, never as ifAbsent', async () => {
    // ifAbsent is opt-in and strictly boolean-true — a truthy string or a
    // missing object must not silently flip the daily tick into a mode that
    // stops refreshing the row.
    for (const opts of [undefined, {}, { ifAbsent: 'yes' }, { ifAbsent: 1 }, null]) {
      const pool = makeStubPool({ insertRowCount: 1 });
      // eslint-disable-next-line no-await-in-loop
      await computeAndStoreDashboardSnapshot(pool, opts);
      assert.match(insertOf(pool).sql, /DO UPDATE/i, `options ${JSON.stringify(opts)} should use the upsert`);
    }
  });

  it('writes exactly one row per call, in one statement — no DELETE, no second INSERT', async () => {
    const pool = makeStubPool({ insertRowCount: 1 });
    await computeAndStoreDashboardSnapshot(pool);
    const writes = pool.calls.filter((c) => /INSERT|UPDATE|DELETE/i.test(c.sql));
    assert.equal(writes.length, 1);
    assert.doesNotMatch(writes[0].sql, /DELETE/i);
  });
});

// --------------------------------------------------------------------------
// The severity bucketing behind the stored counts
// --------------------------------------------------------------------------

describe('computeFleetCveSeverity — an unscored CVE is not a low-severity CVE', () => {
  it('excludes NULL and unparseable CVSS from every bucket rather than defaulting to low', async () => {
    // ⛔ The "we could not measure this" case. A missing CVSS score is not
    // evidence the CVE is minor; bucketing it as `low` would manufacture a
    // reassuring number out of an absent one, and it would be invisible
    // because the totals still look sane.
    const rows = [
      { cvss_score: 9.8 }, { cvss_score: 7.0 }, { cvss_score: 4.0 }, { cvss_score: 1.2 },
      { cvss_score: null }, { cvss_score: undefined }, { cvss_score: 'n/a' },
    ];
    const pool = makeStubPool({ cveRows: rows });
    const counts = await computeFleetCveSeverity(pool);
    assert.deepEqual(counts, { critical: 1, high: 1, medium: 1, low: 1 });
  });

  it('puts the band boundaries at >=9 / >=7 / >=4, inclusive', async () => {
    const rows = [{ cvss_score: 9 }, { cvss_score: 8.9 }, { cvss_score: 7 }, { cvss_score: 6.9 }, { cvss_score: 4 }, { cvss_score: 3.9 }];
    const pool = makeStubPool({ cveRows: rows });
    assert.deepEqual(await computeFleetCveSeverity(pool), { critical: 1, high: 2, medium: 2, low: 1 });
  });
});

describe('computeFleetComplianceScores — nothing measurable scores null, never 0', () => {
  it('returns null (not 0) for overall and every standard when no findings exist', async () => {
    // ⛔ Same rule again: 0% compliance and "we have not measured compliance"
    // are different facts, and only one of them is the fleet's problem.
    const pool = makeStubPool();
    const { overall, byStandard } = await computeFleetComplianceScores(pool);
    assert.equal(overall, null);
    for (const key of Object.keys(byStandard)) assert.equal(byStandard[key], null);
  });
});
