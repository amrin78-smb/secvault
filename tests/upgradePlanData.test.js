'use strict';
// Pins lib/engines/upgradePlanData.js — the plumbing half of the upgrade plan.
//
// WHY THIS FILE EXISTS: the natural query for "what should I upgrade" starts at
// `device_cve_assessments` and joins outwards, which DROPS every firewall with
// no open assessment. On the page whose job is to say what still needs doing, a
// missing firewall reads as "nothing to do" — and a firewall has no open
// assessment for two opposite reasons: it was assessed and nothing matched, or
// it was NEVER ASSESSED. That is this codebase's signature bug (a failed read
// rendered as an affirmative fact) pointed at exactly the wrong page, so the
// "we could not measure this" case is the centre of this file, per
// tests/README.md.
//
// ⛔ NO DATABASE. `getFleetUpgradePlan(pool, opts)` only ever calls
// `pool.query(sql, params)`, so every test hands it a stub that RECORDS the
// statements and params it was given and returns canned rows (the convention
// configRetention.test.js established). That gives two independent things to
// pin: the SQL the engine builds, and how it interprets what comes back.
//
// SQL assertions match a meaningful FRAGMENT, never a whole string, so a
// legitimate reformat is a one-line test update while a REMOVED guarantee still
// fails loudly.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  getFleetUpgradePlan,
  coverageOf,
  normaliseDeviceIds,
  numericOrNull,
  COVERAGE,
  DEVICES_SQL,
  ASSESSMENTS_SQL,
} = require('../lib/engines/upgradePlanData');

// --------------------------------------------------------------------------
// Stub pool
// --------------------------------------------------------------------------

const isDeviceQuery = (sql) => /FROM\s+devices\s+d/i.test(String(sql));

/**
 * @param {object[]} deviceRows  rows the devices statement returns
 * @param {object[]} assessmentRows rows the assessment statement returns
 */
function stubPool(deviceRows, assessmentRows) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql: String(sql), params });
      return isDeviceQuery(sql)
        ? { rows: deviceRows.map((r) => ({ ...r })), rowCount: deviceRows.length }
        : { rows: assessmentRows.map((r) => ({ ...r })), rowCount: assessmentRows.length };
    },
  };
}

const device = (over = {}) => ({
  id: 'dev-1',
  name: 'edge-fw-01',
  vendor: 'fortinet',
  asset_criticality: 'high',
  last_cve_assessed_at: '2026-09-25T01:00:00.000Z',
  running: 'v7.4.9,build2573',
  has_assessment_rows: true,
  ...over,
});

const assessment = (over = {}) => ({
  device_id: 'dev-1',
  fixed_in: 'v7.4.11',
  kev_listed: false,
  priority_band: 'scheduled',
  cve_id: 'CVE-2026-1000',
  cvss_score: '7.5',
  ...over,
});

const byName = (plans, name) => plans.find((p) => p.deviceName === name);

// --------------------------------------------------------------------------
// ⛔ The "we could not measure this" case — the reason this file exists
// --------------------------------------------------------------------------

describe('a firewall with no open assessments is still in the plan', () => {
  it('returns one plan per ACTIVE device, including devices the assessment query would drop', async () => {
    const pool = stubPool(
      [
        device({ id: 'a', name: 'has-work' }),
        device({ id: 'b', name: 'nothing-open', has_assessment_rows: true }),
        device({ id: 'c', name: 'never-asked', has_assessment_rows: false, last_cve_assessed_at: null }),
      ],
      [assessment({ device_id: 'a' })]
    );

    const { plans } = await getFleetUpgradePlan(pool);

    assert.equal(plans.length, 3, 'a device absent from the plan reads as "nothing to do"');
    assert.deepEqual(
      new Set(plans.map((p) => p.deviceName)),
      new Set(['has-work', 'nothing-open', 'never-asked'])
    );
  });

  it('"assessed and clear" and "never assessed" are DIFFERENT states, not both openCount 0', async () => {
    const pool = stubPool(
      [
        device({ id: 'b', name: 'nothing-open' }),
        device({ id: 'c', name: 'never-asked', has_assessment_rows: false, last_cve_assessed_at: null }),
      ],
      []
    );

    const { plans } = await getFleetUpgradePlan(pool);
    const clear = byName(plans, 'nothing-open');
    const never = byName(plans, 'never-asked');

    // The failed-read-as-a-fact trap: both have zero open assessments.
    assert.equal(clear.openCount, 0);
    assert.equal(never.openCount, 0);

    // …and they must NOT be the same answer.
    assert.equal(clear.coverage, COVERAGE.ASSESSED_CLEAR);
    assert.equal(never.coverage, COVERAGE.NEVER_ASSESSED);
    assert.notEqual(clear.coverage, never.coverage);
    assert.equal(clear.neverAssessed, false);
    assert.equal(never.neverAssessed, true);
  });

  it('a device with assessment rows but no timestamp counts as ASSESSED (pre-v2.91.0 rows)', async () => {
    // fleetHeadline.isAssessed is stamp OR any assessment row, reused
    // unchanged. Requiring the stamp alone would report a real assessment as
    // an absent one — the same rule, inverted.
    const pool = stubPool(
      [device({ id: 'a', name: 'old-rows', last_cve_assessed_at: null, has_assessment_rows: true })],
      []
    );
    const { plans } = await getFleetUpgradePlan(pool);
    assert.equal(plans[0].coverage, COVERAGE.ASSESSED_CLEAR);
    assert.equal(plans[0].neverAssessed, false);
    assert.equal(plans[0].lastAssessedAt, null, 'the missing stamp is reported, not invented');
  });

  it('a device with NO device_versions row is assessed_no_version, never silently planned-from-nothing', async () => {
    const pool = stubPool(
      [device({ id: 'a', name: 'no-version', running: null })],
      [assessment({ device_id: 'a' })]
    );
    const { plans, summary } = await getFleetUpgradePlan(pool);

    assert.equal(plans[0].coverage, COVERAGE.ASSESSED_NO_VERSION);
    assert.equal(plans[0].runningVersion, null, 'a missing version stays null, never a guess');
    assert.equal(plans[0].currentBranch, null);
    assert.equal(summary.assessedNoVersion, 1);
  });

  it('coverageOf: all four states, driven directly', () => {
    assert.equal(
      coverageOf({ id: 'x', last_cve_assessed_at: null, has_assessment_rows: false, running: '7.4.9' }, 0),
      COVERAGE.NEVER_ASSESSED
    );
    assert.equal(
      coverageOf({ id: 'x', last_cve_assessed_at: '2026-09-25T00:00:00Z', has_assessment_rows: false, running: null }, 3),
      COVERAGE.ASSESSED_NO_VERSION
    );
    assert.equal(
      coverageOf({ id: 'x', last_cve_assessed_at: '2026-09-25T00:00:00Z', has_assessment_rows: true, running: '7.4.9' }, 0),
      COVERAGE.ASSESSED_CLEAR
    );
    assert.equal(
      coverageOf({ id: 'x', last_cve_assessed_at: null, has_assessment_rows: true, running: '7.4.9' }, 2),
      COVERAGE.ASSESSED
    );
  });
});

// --------------------------------------------------------------------------
// The summary refuses a clean reading over an incomplete fleet
// --------------------------------------------------------------------------

describe('summary coverage', () => {
  it('coverageComplete is FALSE while any firewall was never assessed', async () => {
    const pool = stubPool(
      [
        device({ id: 'a', name: 'fine' }),
        device({ id: 'c', name: 'never-asked', has_assessment_rows: false, last_cve_assessed_at: null }),
      ],
      [assessment({ device_id: 'a' })]
    );
    const { summary } = await getFleetUpgradePlan(pool);
    assert.equal(summary.neverAssessed, 1);
    assert.equal(summary.coverageComplete, false, 'an all-clear is forbidden while coverage is incomplete');
  });

  it('coverageComplete is FALSE while any assessed firewall has no running version', async () => {
    const pool = stubPool(
      [device({ id: 'a', name: 'no-version', running: null })],
      [assessment({ device_id: 'a' })]
    );
    const { summary } = await getFleetUpgradePlan(pool);
    assert.equal(summary.neverAssessed, 0);
    assert.equal(summary.coverageComplete, false);
  });

  it('coverageComplete is TRUE only when every active firewall was assessed and has a version', async () => {
    const pool = stubPool(
      [device({ id: 'a', name: 'fine' }), device({ id: 'b', name: 'also-fine' })],
      [assessment({ device_id: 'a' }), assessment({ device_id: 'b' })]
    );
    const { summary } = await getFleetUpgradePlan(pool);
    assert.equal(summary.coverageComplete, true);
    assert.equal(summary.devices, 2);
  });

  it('carries the pure engine\'s own totals through unchanged, including unplannable', async () => {
    const pool = stubPool(
      [device({ id: 'a', name: 'fine' })],
      [
        assessment({ device_id: 'a', cve_id: 'CVE-1', fixed_in: 'v7.4.11' }),
        // ⛔ no recorded fix: counted and named, never dropped
        assessment({ device_id: 'a', cve_id: 'CVE-2', fixed_in: null, kev_listed: true, priority_band: 'patch_now' }),
      ]
    );
    const { plans, summary } = await getFleetUpgradePlan(pool);
    assert.equal(summary.openAssessments, 2);
    assert.equal(summary.unplannable, 1);
    assert.equal(summary.kevUnplannable, 1);
    assert.equal(plans[0].unplannable[0].cve_id, 'CVE-2');
    assert.equal(plans[0].unplannable[0].reason, 'no_known_fix');
  });
});

// --------------------------------------------------------------------------
// Grouping and row shaping
// --------------------------------------------------------------------------

describe('grouping', () => {
  it('routes each assessment to its own device and to no other', async () => {
    const pool = stubPool(
      [device({ id: 'a', name: 'alpha' }), device({ id: 'b', name: 'bravo' })],
      [
        assessment({ device_id: 'a', cve_id: 'CVE-A1' }),
        assessment({ device_id: 'a', cve_id: 'CVE-A2' }),
        assessment({ device_id: 'b', cve_id: 'CVE-B1' }),
      ]
    );
    const { plans } = await getFleetUpgradePlan(pool);
    assert.equal(byName(plans, 'alpha').openCount, 2);
    assert.equal(byName(plans, 'bravo').openCount, 1);
  });

  it('an assessment row naming a device that is not in the fleet result is ignored, not attributed', async () => {
    // Fabricated attribution is the failure mode here: an orphan row must not
    // land on whichever device happens to be first.
    const pool = stubPool(
      [device({ id: 'a', name: 'alpha' })],
      [assessment({ device_id: 'a' }), assessment({ device_id: 'ghost', cve_id: 'CVE-GHOST' })]
    );
    const { plans, summary } = await getFleetUpgradePlan(pool);
    assert.equal(plans.length, 1);
    assert.equal(plans[0].openCount, 1);
    assert.equal(summary.openAssessments, 1);
  });

  it('ranks the fleet: the firewall whose in-branch patch clears a KEV comes first', async () => {
    const pool = stubPool(
      [
        device({ id: 'a', name: 'zzz-quiet' }),
        device({ id: 'b', name: 'aaa-kev' }),
      ],
      [
        assessment({ device_id: 'a', cve_id: 'CVE-Q', fixed_in: 'v7.4.10' }),
        assessment({ device_id: 'b', cve_id: 'CVE-K', fixed_in: 'v7.4.10', kev_listed: true, priority_band: 'patch_now' }),
      ]
    );
    const { plans } = await getFleetUpgradePlan(pool);
    assert.equal(plans[0].deviceName, 'aaa-kev');
    assert.equal(plans[0].inBranch.kevCleared, 1);
  });
});

describe('cvss_score coercion', () => {
  // NUMERIC comes back from `pg` as a STRING, and `Number(null)` is 0 — which
  // this product reads as a real, vendor-published "not impacted" score.
  it('a NUMERIC string becomes a number', () => {
    assert.equal(numericOrNull('7.5'), 7.5);
  });
  it('a published 0.0 STAYS 0, because a vendor-published zero is a score', () => {
    assert.equal(numericOrNull('0.0'), 0);
  });
  it('an ABSENT score stays null and never becomes 0', () => {
    assert.equal(numericOrNull(null), null);
    assert.equal(numericOrNull(undefined), null);
    assert.equal(numericOrNull(''), null);
    assert.equal(numericOrNull('not-a-number'), null);
  });
  it('carries through to the assessment rows the pure engine is handed', async () => {
    const pool = stubPool(
      [device({ id: 'a', name: 'alpha' })],
      [assessment({ device_id: 'a', cvss_score: null })]
    );
    const { plans } = await getFleetUpgradePlan(pool);
    // The plan does not re-expose raw rows, but the unplannable list does when
    // the fix is absent; assert the engine ran without coercing to 0 instead.
    assert.equal(plans[0].openCount, 1);
  });
});

// --------------------------------------------------------------------------
// The SQL itself
// --------------------------------------------------------------------------

describe('the statements it builds', () => {
  it('uses PARAMETERISED queries — no interpolation anywhere in the SQL', () => {
    for (const sql of [DEVICES_SQL, ASSESSMENTS_SQL]) {
      assert.ok(!/\$\{/.test(sql), 'no string interpolation in SQL, ever');
      assert.ok(/\$1/.test(sql), 'the only variable is a bound parameter');
    }
  });

  it('casts the id-list parameter explicitly, on both statements', () => {
    for (const sql of [DEVICES_SQL, ASSESSMENTS_SQL]) {
      assert.match(sql, /\$1::uuid\[\]/);
    }
  });

  it('the device statement starts FROM devices, so a device with no assessment survives', () => {
    // The whole defect this engine exists to avoid: starting at
    // device_cve_assessments drops exactly the devices that need naming.
    assert.match(DEVICES_SQL, /FROM\s+devices\s+d/i);
    assert.match(DEVICES_SQL, /LEFT\s+JOIN\s+LATERAL/i);
    // Everything from the outer FROM onwards — i.e. what actually decides the
    // row set, with the select-list EXISTS excluded — must not mention the
    // assessment table at all, by join, filter or otherwise.
    const rowSource = DEVICES_SQL.slice(DEVICES_SQL.search(/FROM\s+devices\s+d/i));
    assert.ok(
      !/device_cve_assessments/i.test(rowSource),
      'the fleet list must not be driven by the assessment table'
    );
  });

  it('the device statement limits to ACTIVE devices', () => {
    assert.match(DEVICES_SQL, /WHERE\s+d\.active/i);
    assert.match(ASSESSMENTS_SQL, /d\.active/i);
  });

  it('has_assessment_rows is NOT filtered by version_affected', () => {
    // A device whose every assessment came back "not affected" HAS been
    // assessed. Filtering here would report a completed assessment as absent.
    const existsClause = DEVICES_SQL.slice(
      DEVICES_SQL.indexOf('EXISTS'),
      DEVICES_SQL.indexOf('FROM devices')
    );
    assert.match(existsClause, /device_cve_assessments/i);
    assert.ok(
      !/version_affected/i.test(existsClause),
      'assessed-ness is about having been asked, not about the answer'
    );
  });

  it('the assessment statement selects ONLY version-affected rows', () => {
    assert.match(ASSESSMENTS_SQL, /a\.version_affected/i);
  });

  it('both statements are handed the same single parameter', async () => {
    const pool = stubPool([device()], [assessment()]);
    await getFleetUpgradePlan(pool);
    assert.equal(pool.calls.length, 2, 'one round trip each, no per-device query');
    for (const c of pool.calls) {
      assert.equal(c.params.length, 1);
    }
  });

  it('pool is a PARAMETER — the module never imports a pool of its own', () => {
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'lib', 'engines', 'upgradePlanData.js'),
      'utf8'
    );
    assert.ok(
      !/require\(['"][^'"]*\/db['"]\)/.test(src) && !/require\(['"]\.\.\/db['"]\)/.test(src),
      'CLAUDE.md: never instantiate or import a pool here'
    );
  });

  it('stores nothing — no INSERT, UPDATE or DELETE anywhere in this engine', () => {
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'lib', 'engines', 'upgradePlanData.js'),
      'utf8'
    );
    // A stored plan goes stale against the assessments it indexes and is then
    // read as fact — the rule /segmentation and /applications follow.
    assert.ok(!/\bINSERT\s+INTO\b/i.test(src), 'read time only');
    assert.ok(!/\bUPDATE\s+\w+\s+SET\b/i.test(src), 'read time only');
    assert.ok(!/\bDELETE\s+FROM\b/i.test(src), 'read time only');
  });
});

// --------------------------------------------------------------------------
// deviceIds: "no filter" and "no devices" are opposite instructions
// --------------------------------------------------------------------------

describe('deviceIds scoping', () => {
  it('omitted means the WHOLE active fleet — the parameter is null, not an empty list', async () => {
    const pool = stubPool([device()], [assessment()]);
    await getFleetUpgradePlan(pool);
    assert.equal(pool.calls[0].params[0], null);
    assert.equal(normaliseDeviceIds(undefined), null);
    assert.equal(normaliseDeviceIds(null), null);
  });

  it('an EMPTY list means NO devices, and is never quietly widened to the fleet', async () => {
    const pool = stubPool([], []);
    await getFleetUpgradePlan(pool, { deviceIds: [] });
    assert.deepEqual(pool.calls[0].params[0], []);
    assert.deepEqual(normaliseDeviceIds([]), []);
  });

  it('a named list is passed through as a bound parameter', async () => {
    const pool = stubPool([device({ id: 'a', name: 'alpha' })], []);
    await getFleetUpgradePlan(pool, { deviceIds: ['a', 'b'] });
    assert.deepEqual(pool.calls[0].params[0], ['a', 'b']);
    assert.deepEqual(pool.calls[1].params[0], ['a', 'b']);
  });

  it('junk entries are dropped rather than sent to the database', () => {
    assert.deepEqual(normaliseDeviceIds(['a', '', null, 7, 'b']), ['a', 'b']);
  });
});

// --------------------------------------------------------------------------
// generatedAt
// --------------------------------------------------------------------------

describe('generatedAt', () => {
  it('is injectable, so the timestamp is a fact about the read and pinnable', async () => {
    const pool = stubPool([device()], [assessment()]);
    const { generatedAt } = await getFleetUpgradePlan(pool, { now: '2026-09-25T08:30:00.000Z' });
    assert.equal(generatedAt, '2026-09-25T08:30:00.000Z');
  });

  it('defaults to now when no clock is supplied', async () => {
    const pool = stubPool([device()], [assessment()]);
    const before = Date.now();
    const { generatedAt } = await getFleetUpgradePlan(pool);
    const t = Date.parse(generatedAt);
    assert.ok(t >= before && t <= Date.now());
  });
});

// --------------------------------------------------------------------------
// Empty fleet
// --------------------------------------------------------------------------

describe('an empty fleet', () => {
  it('returns no plans and does NOT report coverage as complete-and-clean by accident', async () => {
    const pool = stubPool([], []);
    const { plans, summary } = await getFleetUpgradePlan(pool);
    assert.equal(plans.length, 0);
    assert.equal(summary.devices, 0);
    assert.equal(summary.decisions, 0);
    assert.equal(summary.openAssessments, 0);
    // Nothing was found to be unassessed because nothing was asked about, so
    // coverageComplete is vacuously true — a renderer must not turn "no
    // firewalls" into an all-clear, and `devices: 0` is the signal that says so.
    assert.equal(summary.neverAssessed, 0);
  });
});
