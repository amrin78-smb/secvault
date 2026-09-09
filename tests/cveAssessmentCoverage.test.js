'use strict';
// Pins the "assessed and clean" vs "never assessed" distinction — roadmap
// Tier 3 items 3 and 4, shipped 2026-09-09.
//
// ⛔ WHY THIS FILE EXISTS. device_cve_assessments records only advisories that
// STILL apply: matchDeviceToAdvisories() emits nothing for a non-match, and
// runMatchForAllDevices()'s reconciliation DELETE removes rows that stopped
// applying. So a device assessed and found CLEAN ends up holding zero rows —
// byte-identical, from the output alone, to a device the matcher has never
// touched. Every consumer COALESCEd that to 0 and rendered a confident zero
// for both: CLAUDE.md's most-repeated bug class, a failed/absent read recorded
// as an affirmative value.
//
// The fix persists the RUN rather than its output (devices.last_cve_assessed_at)
// and the thing worth pinning is therefore not "does a count come out right" —
// it is WHEN the stamp is written and, per tests/README.md, that the
// "we could not measure this" case is reported as unmeasured rather than as a
// plausible number. Both halves are asserted below.
//
// ⛔ NO DATABASE, same convention as every other test here: the engines are
// handed stub pools that record the SQL they were given and return canned rows.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { runMatchForAllDevices } = require('../lib/engines/versionMatcher');
const { computeTiles, getDeviceInventory } = require('../lib/engines/deviceInventory');

// --------------------------------------------------------------------------
// Stub pool for versionMatcher
// --------------------------------------------------------------------------

const STAMP_SQL = /UPDATE\s+devices\s+SET\s+last_cve_assessed_at/i;

// A device that WILL be matched, and one the matcher must skip outright. The
// skipped one is the whole point: it is the live fleet's OKF(F2), which has no
// device_versions row, so runMatchForAllDevices() `continue`s on it with
// 'no version row - skipped' before any transaction opens.
const DEVICES = [
  { id: 'dev-with-version', vendor: 'fortinet', asset_criticality: 'medium' },
  { id: 'dev-no-version', vendor: 'fortinet', asset_criticality: 'medium' },
];

function makeStubPool({ failOn = null } = {}) {
  // Every statement issued on the transaction client, in order. Order is
  // load-bearing here — the stamp must land after the writes and before COMMIT.
  const clientSql = [];
  const clientParams = [];

  const answer = (sql) => {
    const s = String(sql);
    if (/FROM\s+devices\s+WHERE\s+active/i.test(s)) return { rows: DEVICES.map((d) => ({ ...d })) };
    if (/FROM\s+device_versions/i.test(s)) return { rows: [] }; // overridden below
    return { rows: [] };
  };

  const pool = {
    async query(sql, params) {
      const s = String(sql);
      if (/FROM\s+device_versions/i.test(s)) {
        // Only the first device has a version row.
        return params && params[0] === 'dev-with-version'
          ? { rows: [{ version_string: 'v7.4.3,build2573' }] }
          : { rows: [] };
      }
      return answer(s);
    },
    async connect() {
      return {
        async query(sql, params) {
          const s = String(sql);
          clientSql.push(s);
          clientParams.push(params);
          if (failOn && failOn.test(s)) throw new Error('simulated write failure');
          return { rows: [] };
        },
        release() {},
      };
    },
  };

  return { pool, clientSql, clientParams };
}

describe('versionMatcher stamps devices.last_cve_assessed_at', () => {
  it('stamps a device whose match ran to completion', async () => {
    const { pool, clientSql, clientParams } = makeStubPool();
    const result = await runMatchForAllDevices(pool);

    const stampIdx = clientSql.findIndex((s) => STAMP_SQL.test(s));
    assert.ok(stampIdx >= 0, 'a completed per-device match must write the stamp');
    // Parameterised, and for the right device — never interpolated.
    assert.deepEqual(clientParams[stampIdx], ['dev-with-version']);
    assert.equal(result.assessed, 1);
  });

  it('writes the stamp INSIDE the transaction, after the writes and before COMMIT', async () => {
    // ⛔ Position is the correctness property, not the presence of the UPDATE.
    // Stamping on ENTRY would claim an assessment for a run that then threw —
    // exactly the lie the column exists to remove — and stamping outside the
    // transaction would survive a ROLLBACK that discarded the assessments it
    // describes.
    const { pool, clientSql } = makeStubPool();
    await runMatchForAllDevices(pool);

    const beginIdx = clientSql.findIndex((s) => /^\s*BEGIN/i.test(s));
    const lockIdx = clientSql.findIndex((s) => /pg_advisory_xact_lock/i.test(s));
    const deleteIdx = clientSql.findIndex((s) => /DELETE\s+FROM\s+device_cve_assessments/i.test(s));
    const stampIdx = clientSql.findIndex((s) => STAMP_SQL.test(s));
    const commitIdx = clientSql.findIndex((s) => /^\s*COMMIT/i.test(s));

    assert.ok(beginIdx >= 0 && commitIdx >= 0, 'the per-device write phase is a transaction');
    assert.ok(beginIdx < stampIdx, 'stamp is inside the transaction');
    assert.ok(lockIdx < stampIdx, 'stamp is covered by the per-device advisory lock');
    assert.ok(deleteIdx < stampIdx, 'stamp comes after the reconciliation DELETE');
    assert.ok(stampIdx < commitIdx, 'stamp commits with the assessments it describes');
  });

  it('NEVER stamps a device the matcher skipped for having no version row', async () => {
    // ⛔ The "we could not measure this" case. A skipped device must keep a
    // NULL stamp so the UI reports it as never assessed; stamping it would
    // manufacture a clean bill of health for a device CVE matching never even
    // began on.
    const { pool, clientParams, clientSql } = makeStubPool();
    const result = await runMatchForAllDevices(pool);

    const stampedIds = clientSql
      .map((s, i) => (STAMP_SQL.test(s) ? clientParams[i][0] : null))
      .filter(Boolean);
    assert.deepEqual(stampedIds, ['dev-with-version']);
    assert.ok(
      result.errors.some((e) => e.device_id === 'dev-no-version' && /no version row/.test(e.error)),
      'the skipped device is reported as an error, not silently assessed'
    );
  });

  it('does not stamp when the transaction fails', async () => {
    // A run that threw is not a run. Rolling the stamp back is the safe
    // direction: an unrecorded real assessment reads as "not measured".
    const { pool, clientSql } = makeStubPool({ failOn: /DELETE\s+FROM\s+device_cve_assessments/i });
    const result = await runMatchForAllDevices(pool);

    assert.ok(!clientSql.some((s) => STAMP_SQL.test(s)), 'no stamp on a failed run');
    assert.ok(clientSql.some((s) => /^\s*ROLLBACK/i.test(s)), 'the transaction is rolled back');
    assert.equal(result.assessed, 0);
  });
});

// --------------------------------------------------------------------------
// computeTiles coverage counts
// --------------------------------------------------------------------------

// A minimal row shaped like getDeviceRows()' output. Defaults describe a fully
// measured, entirely healthy device, so each test below changes exactly the one
// field it is about.
function row(overrides = {}) {
  return {
    id: overrides.id || 'd',
    name: overrides.name || 'fw',
    version_string: 'v7.4.3',
    last_cve_assessed_at: '2026-09-09T00:00:00Z',
    assessment_count: 3,
    patch_now_count: 0,
    scheduled_count: 0,
    monitor_count: 0,
    critical_cve_count: 0,
    open_diffs: 0,
    config_snapshot_count: 40,
    licence_row_count: 5,
    expired_count: 0,
    unknown_expiry_count: 0,
    soonest_future_expiry: null,
    last_connectivity_ok: true,
    pollBand: 'healthy',
    ...overrides,
  };
}

describe('computeTiles states its own CVE coverage', () => {
  it('counts a device with neither a stamp nor any assessment row as not assessed', () => {
    const tiles = computeTiles([
      row({ id: 'a' }),
      row({ id: 'b', last_cve_assessed_at: null, assessment_count: 0 }),
    ]);
    assert.equal(tiles.cveNotAssessed, 1);
  });

  it('accepts EITHER signal as evidence of a completed run', () => {
    // ⛔ ORed, never ANDed. last_cve_assessed_at is NULL on every already-
    // deployed row until the matcher next runs, and assessment_count is
    // legitimately 0 for a device no advisory matches. Requiring both would
    // report the whole fleet as uncovered on the day the column shipped.
    const stampOnly = computeTiles([row({ assessment_count: 0 })]);
    assert.equal(stampOnly.cveNotAssessed, 0, 'a stamp alone is proof the run happened');

    const rowsOnly = computeTiles([row({ last_cve_assessed_at: null })]);
    assert.equal(rowsOnly.cveNotAssessed, 0, 'assessment rows can only exist because a run made them');
  });

  it('names the definite subset the matcher skips outright', () => {
    const tiles = computeTiles([
      row({ id: 'a' }),
      row({ id: 'b', version_string: null, last_cve_assessed_at: null, assessment_count: 0 }),
    ]);
    assert.equal(tiles.cveNoVersion, 1);
    // No version implies no assessment, so it is a SUBSET of cveNotAssessed —
    // the two counts must never be added together.
    assert.equal(tiles.cveNotAssessed, 1);
  });

  it('reports full coverage as zero, not as a missing field', () => {
    const tiles = computeTiles([row({ id: 'a' }), row({ id: 'b' })]);
    assert.equal(tiles.cveNotAssessed, 0);
    assert.equal(tiles.cveNoVersion, 0);
  });
});

describe('computeTiles states its own config-drift coverage', () => {
  it('counts a device with fewer than two snapshots as not comparable', () => {
    // ⛔ `< 2`, not `=== 0`. A config_diff is computed between consecutive
    // snapshots, so a device holding exactly one has been collected from and
    // still has nothing to compare against — its 0 drift is arithmetic, not
    // stability.
    const tiles = computeTiles([
      row({ id: 'a', config_snapshot_count: 40 }),
      row({ id: 'b', config_snapshot_count: 1 }),
      row({ id: 'c', config_snapshot_count: 0 }),
    ]);
    assert.equal(tiles.driftNotComparable, 2);
    assert.equal(tiles.driftDevices, 0);
  });

  it('is zero when every device has a comparable history', () => {
    assert.equal(computeTiles([row({ config_snapshot_count: 2 })]).driftNotComparable, 0);
  });
});

describe('computeTiles reads licence coverage from a projected column', () => {
  it('does not report a fleet with licences as having none', () => {
    // ⛔ REGRESSION PIN. licence_row_count was computed inside getDeviceRows()'
    // lateral and then never projected into the outer SELECT, so every row
    // carried `undefined`, `(undefined || 0) === 0` was true for all of them,
    // and supportNoData silently equalled the whole fleet — the Support tile
    // permanently claimed "Not collected for any device" about 15 devices whose
    // licences ARE collected. Both the wrong and the right answer are plausible
    // integers, which is why nothing caught it. Pinned as a behaviour so a
    // dropped projection fails here instead of on the page.
    const tiles = computeTiles([row({ id: 'a' }), row({ id: 'b' })]);
    assert.equal(tiles.supportNoData, 0);
  });

  it('still counts a device from which no licence was ever collected', () => {
    const tiles = computeTiles([row({ id: 'a' }), row({ id: 'b', licence_row_count: 0 })]);
    assert.equal(tiles.supportNoData, 1);
  });
});

// --------------------------------------------------------------------------
// getDeviceRows' own column names
// --------------------------------------------------------------------------

// ⛔ WHY THIS IS DUPLICATED HERE RATHER THAN LEFT TO tests/sqlColumns.test.js.
// That test is conservative by construction: a query naming any table it cannot
// resolve is SKIPPED whole. getDeviceRows()' query is built from ten
// `LEFT JOIN LATERAL` sub-selects, and its table-reference regex reads the word
// `LATERAL` itself as a table name — which is not in schema.sql, so the ENTIRE
// query is silently unverified. Confirmed empirically: renaming
// d.last_cve_assessed_at to a nonsense column left that test green.
//
// This is exactly the query behind /devices, and a wrong column name here is a
// server-side exception on the fleet inventory page, so the gap is worth
// closing narrowly rather than loosening the shared lint (a false failure there
// would train the next person to delete it). Scoped deliberately to the `d.`
// alias — the one table whose columns this change touched.
describe('getDeviceRows names only real devices columns', () => {
  const schemaSql = fs.readFileSync(path.join(__dirname, '..', 'lib', 'schema.sql'), 'utf8');

  // devices' CREATE TABLE body plus every ALTER ... ADD COLUMN against it. The
  // ALTERs are not optional: CLAUDE.md requires a column added to an
  // already-deployed table to live in one, so a CREATE-body-only parse would
  // reject mgmt_port, snmp_host and last_cve_assessed_at alike.
  const createBody = schemaSql.match(/CREATE TABLE IF NOT EXISTS\s+devices\s*\(([\s\S]*?)\n\);/i)[1];
  const columns = new Set(
    createBody
      .replace(/--[^\n]*/g, '')
      .split('\n')
      .map((l) => (l.trim().match(/^([a-z_][a-z0-9_]*)\s+[A-Za-z]/) || [])[1])
      .filter(Boolean)
  );
  for (const m of schemaSql.matchAll(
    /ALTER TABLE\s+devices\s+ADD COLUMN IF NOT EXISTS\s+([a-z_][a-z0-9_]*)/gi
  )) {
    columns.add(m[1]);
  }

  it('has the assessment stamp in schema.sql, added via ALTER not CREATE', () => {
    // ⛔ devices exists on every deployed server, so a CREATE TABLE IF NOT
    // EXISTS body change would be a no-op there and the first query selecting
    // the column would crash. It must be an ALTER.
    assert.ok(columns.has('last_cve_assessed_at'), 'devices.last_cve_assessed_at is missing');
    assert.match(
      schemaSql,
      /ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_cve_assessed_at/i,
      'the stamp must be added by ALTER TABLE ... ADD COLUMN IF NOT EXISTS'
    );
  });

  it('selects nothing from d. that devices does not have', async () => {
    const seen = [];
    const stub = {
      async query(sql) {
        seen.push(String(sql));
        return { rows: [] };
      },
    };
    await getDeviceInventory(stub);

    const sql = seen.find((s) => /FROM\s+devices\s+d\b/i.test(s));
    assert.ok(sql, 'getDeviceRows did not run its query');
    const bad = [...sql.replace(/--[^\n]*/g, ' ').matchAll(/\bd\.([a-z_][a-z0-9_]*)\b/g)]
      .map((m) => m[1])
      .filter((c) => !columns.has(c));
    assert.deepEqual([...new Set(bad)], [], 'columns selected from devices that do not exist');
    // The projection itself, not just the column's existence: licence_row_count
    // was computed and never projected, and that class of bug is invisible to
    // any check that only asks whether a column exists.
    assert.match(sql, /d\.last_cve_assessed_at/, 'the stamp must be projected to the page');
    assert.match(sql, /licence_row_count/, 'licence coverage must be projected');
    assert.match(sql, /config_snapshot_count/, 'drift coverage must be projected');
  });
});
