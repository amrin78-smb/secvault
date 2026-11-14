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

// --------------------------------------------------------------------------
// ⛔ `overall` COUNTS EACH FINDING ONCE — roadmap row 30
// --------------------------------------------------------------------------
//
// `overall` used to be built by summing the five PER-STANDARD buckets, which
// got the unit wrong in both directions at once:
//
//  1. A check mapped to five frameworks was counted FIVE times. Measured
//     against the live seed library the expansion factor is ~2.64x, and
//     because the mapping is not uniform the skew does not cancel — on a
//     synthetic 16-device fleet built from the real mapping it reached SIX
//     points (51% standard-expanded against 45% per finding). On the
//     reference fleet the two sat one point apart (47% against 48%), which is
//     precisely why nothing looked wrong: the skew tracks how many frameworks
//     the LIBRARY maps a check to, so it moves with curation and not with the
//     fleet, and it feeds computeSecurityScore's 30%-weighted compliance
//     component and every nightly snapshot row.
//
//  2. ⛔ A check mapped to NO recognised standard was DISCARDED. That is the
//     half worth the test file: a real measurement, thrown away by a curation
//     field. Measured on the old code, one `pass` mapped to PCI_DSS beside
//     one `fail` mapped to `{CUSTOM}` reported overall = 100%.
//
// The unit after the fix is the (device, check) PAIR — one row per finding,
// counted once. CLAUDE.md's "TWO UNITS, KEPT APART": a count of pairs may
// never be mixed with a count of distinct checks or of standard-mappings.

// The arithmetic app/(dashboard)/compliance/page.js already applies to ONE
// firewall — `statusCounts` reduced over its findings, then
// scorePctFromCounts. Re-expressed here rather than imported because that page
// is an ESM Next.js server component importing next-auth and lib/db, which
// node:test cannot require; the same reason tests/complianceScoreFormula
// .test.js keeps its own `canonical`. ⛔ The operand order
// `(pass / measurable) * 100` is load-bearing (see that file) and is the form
// the engine must use.
function perDevicePageArithmetic(rows) {
  const counts = { pass: 0, fail: 0, warning: 0, na: 0 };
  for (const r of rows) {
    if (Object.prototype.hasOwnProperty.call(counts, r.status)) counts[r.status] += 1;
  }
  const measurable = counts.pass + counts.fail + counts.warning;
  return {
    counts,
    measurable,
    scorePct: measurable > 0 ? Math.round((counts.pass / measurable) * 100) : null,
  };
}

// A pool whose audit_findings read answers with the given finding rows. Every
// other statement (CVE severity, fleetHeadline's own queries) answers empty —
// none of them is what these tests are about.
function makeFindingsPool(findingRows) {
  return {
    async query(sql) {
      if (/FROM audit_findings/i.test(sql)) {
        return { rowCount: findingRows.length, rows: findingRows };
      }
      return { rowCount: 0, rows: [] };
    },
  };
}

describe('computeFleetComplianceScores — `overall` counts each finding ONCE (roadmap row 30)', () => {
  it('⛔ a check mapped to five frameworks contributes ONE row, not five', async () => {
    // One pass mapped to all five, one fail mapped to one. Standard-expanded
    // that is 5 pass of 6 measurable = 83%; per finding it is 1 of 2 = 50%.
    const rows = [
      { status: 'pass', standards: ['PCI_DSS', 'ISO_27001', 'CIS_V8', 'NIST', 'SANS'] },
      { status: 'fail', standards: ['PCI_DSS'] },
    ];
    const { overall, overallCounts } = await computeFleetComplianceScores(makeFindingsPool(rows));

    assert.equal(overall, 50, 'the broadly-mapped pass must not outvote the narrowly-mapped fail');
    assert.notEqual(overall, 83, 'that is the standard-expanded figure this fix removed');
    assert.deepEqual(overallCounts, { pass: 1, fail: 1, warning: 0, na: 0 });
  });

  it('⛔ a finding mapped to NO standard is INCLUDED, not silently discarded', async () => {
    // `audit_checks.standards` is TEXT[] NOT NULL, which permits '{}', and
    // schema.sql:902 names 'CUSTOM' as a legitimate value outside the five
    // scored frameworks — app/(dashboard)/compliance/page.js:302 guards for it
    // by name. Either made the row contribute to zero buckets and vanish.
    //
    // ⛔ The discarded row here is a FAILURE, which is the direction that
    // matters: the old code reported 100% for a fleet that was half failing.
    for (const unmapped of [[], ['CUSTOM'], ['SOC2', 'HIPAA'], null, undefined, 'PCI_DSS']) {
      const rows = [
        { status: 'pass', standards: ['PCI_DSS'] },
        { status: 'fail', standards: unmapped },
      ];
      // eslint-disable-next-line no-await-in-loop
      const { overall, overallCounts } = await computeFleetComplianceScores(makeFindingsPool(rows));
      const label = JSON.stringify(unmapped);
      assert.equal(overall, 50, `standards=${label}: the fail must still be counted`);
      assert.notEqual(overall, 100, `standards=${label}: a discarded fail reads as a clean fleet`);
      assert.equal(overallCounts.fail, 1, `standards=${label}: the fail must appear in the basis counts`);
    }
  });

  it('⛔ agrees with the per-device page exactly, over the LIVE seed library mapping', async () => {
    // A property, not a hand-written number: hand-written numbers agree with
    // whatever the author computed and cannot catch a divergence between two
    // implementations (the lesson recorded in complianceScoreFormula.test.js).
    // Built from the real 74-check library so the mapping breadth is the real
    // one, with a pass rate deliberately CORRELATED to that breadth — a
    // uniform pattern makes the two definitions agree by accident and the test
    // then proves nothing.
    const { CHECKS } = require('../lib/auditChecksSeed');
    const rows = [];
    for (let device = 0; device < 16; device += 1) {
      CHECKS.forEach((check, i) => {
        const standards = Array.isArray(check.standards) ? check.standards : [];
        let status;
        if (i % 11 === 0) status = 'na';
        else if (i % 7 === 0) status = 'warning';
        else status = ((device + i) % 5) < standards.length ? 'pass' : 'fail';
        rows.push({ status, standards });
      });
    }

    const want = perDevicePageArithmetic(rows);
    const { overall, overallCounts, byStandardCounts } = await computeFleetComplianceScores(makeFindingsPool(rows));

    assert.equal(overall, want.scorePct);
    assert.deepEqual(overallCounts, want.counts);
    assert.equal(
      overallCounts.pass + overallCounts.fail + overallCounts.warning + overallCounts.na,
      rows.length,
      'every finding row must land in exactly one bucket'
    );

    // And the two definitions really do differ on this input, so the equality
    // above is evidence rather than a coincidence of a flat mapping.
    const expandedPass = Object.values(byStandardCounts).reduce((s, c) => s + c.pass, 0);
    const expandedMeasurable = Object.values(byStandardCounts)
      .reduce((s, c) => s + c.pass + c.fail + c.warning, 0);
    const expandedPct = Math.round((expandedPass / expandedMeasurable) * 100);
    assert.notEqual(expandedPct, overall,
      'fixture is degenerate — pick a pattern where the two units disagree');
    assert.ok(expandedMeasurable > want.measurable * 2,
      `expected the real library to expand >2x, got ${(expandedMeasurable / want.measurable).toFixed(2)}x`);
  });

  it('⛔ the PER-STANDARD figures keep their standard-expanded counting, untouched', async () => {
    // Legitimately per standard: a check mapped to PCI_DSS and NIST really is
    // evidence about both, and one mapped to neither really is not evidence
    // about either. Only the POOLED figure was wrong, and fixing them together
    // would have replaced one wrong denominator with another.
    const rows = [
      { status: 'pass', standards: ['PCI_DSS', 'NIST'] },
      { status: 'fail', standards: ['PCI_DSS'] },
      { status: 'fail', standards: ['CUSTOM'] },
    ];
    const { overall, byStandard, byStandardCounts } = await computeFleetComplianceScores(makeFindingsPool(rows));

    assert.deepEqual(byStandardCounts.PCI_DSS, { pass: 1, fail: 1, warning: 0 });
    assert.equal(byStandard.PCI_DSS, 50);
    // NIST sees only the pass — the same finding, counted again under its own
    // framework. That is the behaviour being preserved.
    assert.deepEqual(byStandardCounts.NIST, { pass: 1, fail: 0, warning: 0 });
    assert.equal(byStandard.NIST, 100);
    // A framework no finding maps to is null, never 0 — it has not been
    // measured, it has not failed.
    for (const key of ['ISO_27001', 'CIS_V8', 'SANS']) {
      assert.equal(byStandard[key], null, `${key} must be null, not 0`);
    }
    // And the CUSTOM-only fail reaches none of them while still reaching
    // `overall`: 1 pass of 3 measurable.
    assert.equal(overall, 33);
  });

  it('⛔ `na` is tallied but never enters the denominator', async () => {
    // "SecVault cannot ask this question of this device" is a fact about
    // SecVault, not a compliance failure. 3 pass, 1 fail, 6 na is 75% — not
    // 30%. Carried in the counts so a caller can SAY how many were unaskable.
    const rows = [
      ...Array(3).fill({ status: 'pass', standards: ['NIST'] }),
      { status: 'fail', standards: ['NIST'] },
      ...Array(6).fill({ status: 'na', standards: ['NIST'] }),
    ];
    const { overall, overallCounts } = await computeFleetComplianceScores(makeFindingsPool(rows));
    assert.equal(overall, 75);
    assert.equal(overallCounts.na, 6, 'na must be visible, not dropped on the floor');
  });

  it('⛔ a fleet of nothing but `na` scores null, never 0', async () => {
    // ⛔ THE "WE COULD NOT MEASURE THIS" CASE. A fleet where no check could be
    // asked has not failed compliance — 0 here would travel into
    // fleet_dashboard_snapshots.compliance_overall_score and into
    // computeSecurityScore's 30%-weighted component, reporting a data gap as a
    // security problem. That engine drops an unmeasurable component from its
    // denominator, which only works if it is handed null.
    const rows = Array(12).fill({ status: 'na', standards: ['PCI_DSS', 'NIST'] });
    const { overall, overallCounts, byStandard } = await computeFleetComplianceScores(makeFindingsPool(rows));
    assert.equal(overall, null);
    assert.notEqual(overall, 0);
    assert.equal(overallCounts.na, 12);
    for (const key of Object.keys(byStandard)) assert.equal(byStandard[key], null, key);
  });

  it('⛔ an unrecognised status is excluded from the denominator, never counted as a fail', async () => {
    // audit_findings.status has no CHECK constraint, so an unknown verb is
    // reachable. Counting it as a `fail` would manufacture a failure out of a
    // value nobody measured; counting it as a `pass` would manufacture
    // compliance. It enters no bucket, matching the per-device page's own
    // hasOwnProperty guard — one pass of one measurable.
    const rows = [
      { status: 'pass', standards: ['NIST'] },
      { status: 'skipped', standards: ['NIST'] },
      { status: '', standards: ['NIST'] },
      { status: null, standards: ['NIST'] },
    ];
    const { overall, overallCounts } = await computeFleetComplianceScores(makeFindingsPool(rows));
    assert.equal(overall, 100);
    assert.deepEqual(overallCounts, { pass: 1, fail: 0, warning: 0, na: 0 });
  });

  it('⛔ uses the operand order the compliance pages show — 23 of 40 is 57, not 58', async () => {
    // tests/complianceScoreFormula.test.js records why this is load-bearing:
    // `(pass / measurable) * 100` and `(100 * pass) / measurable` disagree at
    // exact-.5 boundaries, because 23/40 is 0.575 in decimal and
    // 57.49999999999999 in binary floating point. The fleet PDF once printed
    // "PCI DSS 57%" with "the 58% rests on 40 checks" one line beneath it.
    // That file pins complianceReport.js and has never covered THIS function's
    // own `overall`, which the row-30 fix rewrote — so the line that computes
    // it is pinned here too, or the next edit to it reintroduces the drift
    // silently and only on some ratios.
    const rows = [
      ...Array(23).fill({ status: 'pass', standards: ['NIST'] }),
      ...Array(17).fill({ status: 'fail', standards: ['NIST'] }),
    ];
    const { overall } = await computeFleetComplianceScores(makeFindingsPool(rows));
    assert.equal(overall, Math.round((23 / 40) * 100), 'must match the form the pages use');
    assert.equal(overall, 57, 'the value every compliance surface shows for this split');
  });

  it('carries overall through to the snapshot INSERT as compliance_overall_score', async () => {
    // The whole reason the unit matters: this value is what the nightly row
    // records and what every day-over-day compliance delta is drawn from.
    const rows = [
      { status: 'pass', standards: ['PCI_DSS', 'ISO_27001', 'CIS_V8', 'NIST', 'SANS'] },
      { status: 'fail', standards: [] },
    ];
    const calls = [];
    const pool = {
      calls,
      async query(sql, params) {
        calls.push({ sql, params });
        if (/^\s*INSERT INTO fleet_dashboard_snapshots/i.test(sql)) {
          return { rowCount: 1, rows: [{ snapshot_date: '2026-11-15' }] };
        }
        if (/FROM audit_findings/i.test(sql)) return { rowCount: rows.length, rows };
        return { rowCount: 0, rows: [] };
      },
    };
    const res = await computeAndStoreDashboardSnapshot(pool);
    assert.equal(res.compliance.overall, 50);
    // $5 is compliance_overall_score in SNAPSHOT_INSERT_HEAD's VALUES list.
    assert.equal(insertOf(pool).params[4], 50);
  });
});
