// tests/cvssVersionBackfill.test.js
//
// ⛔ WHY THIS EXISTS. `advisories.cvss_source`/`cvss_version` were added in v2.90.3 after the
// fleet severity histogram alternated between two states on identical totals — two feeds
// scoring the same CVE on two different CVSS versions (cve-pipeline.md, "CVSS provenance").
// The COLUMN shipped. The DATA did not: measured live on 2026-09-11, `cvss_version` was NULL
// on all 1,004 advisories, 749 of which are scored and every single one of which stores a
// vector that states its own version in its first eight characters. So the product rendered
// the `v—` NOT-MEASURED marker for a fact it was already holding in the same row.
//
// Two things are pinned here, and they are two halves of one rule — A SCORE AND ITS SCALE MUST
// COME FROM THE SAME PLACE:
//   1. lib/migrate.js's backfill derives the scale ONLY from the `CVSS:x.y/` prefix the vector
//      itself declares, only for rows that have a score, and only where the column is NULL.
//   2. lib/feeds/paloalto.js — which owns the largest share of scored rows (286 with a NULL
//      source, plus 67 mislabelled `circl`) and wrote NEITHER column — now reports the version
//      out of the same metric key the score was read from, and tags the source `psirt`.
//
// ⛔ Nothing here connects to Postgres (tests/README.md). The backfill gets a STUB pool and
// what is asserted is the SQL's guards, because this is a single statement whose entire safety
// lives in three WHERE clauses that a careless edit could drop with nothing failing until an
// advisory started claiming a scale nobody published.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { backfillCvssVersionFromVector } = require('../lib/migrate');
const { pickCvssFromPanOsRecord } = require('../lib/feeds/paloalto');

const PALOALTO_SRC = fs.readFileSync(
  path.join(__dirname, '..', 'lib', 'feeds', 'paloalto.js'),
  'utf8'
);

// Records every statement it is handed and replays canned results in order.
function stubPool(responses) {
  const calls = [];
  const queue = responses.slice();
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      return queue.shift() || { rows: [], rowCount: 0 };
    },
  };
}

const UPDATE_RESULT = {
  rows: [
    { vendor: 'paloalto', cvss_version: '4.0' },
    { vendor: 'paloalto', cvss_version: '3.1' },
    { vendor: 'fortinet', cvss_version: '3.1' },
  ],
};
const REMAINDER_RESULT = {
  rows: [{ unscored: '255', scored_no_vector: '0', vector_declares_no_version: '0' }],
};

async function runBackfill() {
  const pool = stubPool([UPDATE_RESULT, REMAINDER_RESULT]);
  const result = await backfillCvssVersionFromVector(pool);
  return { pool, result, updateSql: pool.calls[0].sql };
}

describe('cvss_version backfill derives the scale, never guesses it', () => {
  it('⛔ reads the version out of the vector\'s own CVSS: prefix', async () => {
    const { updateSql } = await runBackfill();
    // The SET expression and the WHERE filter must be the SAME anchored pattern. Filtering on
    // one pattern and extracting with another is how a row gets a version that isn't the one
    // its vector declares.
    assert.match(updateSql, /SET cvss_version = substring\(cvss_vector from '\^CVSS:\(\[0-9\]\+\[\.\]\[0-9\]\+\)\/'\)/);
    assert.match(updateSql, /cvss_vector ~ '\^CVSS:\[0-9\]\+\[\.\]\[0-9\]\+\/'/);
  });

  it('⛔ a vector that declares no version is left NULL (the v2 case)', async () => {
    const { updateSql, result } = await runBackfill();
    // A CVSS 2.0 vector ("AV:N/AC:L/Au:N/C:P/I:P/A:P") carries no CVSS: prefix at all. The
    // anchored `~` filter is the only thing standing between that row and a fabricated scale —
    // there is no fallback, no default and no inference from the score or the vendor.
    assert.ok(!/COALESCE\s*\(\s*substring/i.test(updateSql), 'no default may be coalesced in');
    assert.ok(!/ELSE\s*'3/i.test(updateSql), 'no version literal may be assumed');
    // And the count of what stayed NULL is REPORTED, not swallowed.
    assert.deepEqual(result.stillNull, {
      unscored: 255,
      scoredNoVector: 0,
      vectorDeclaresNoVersion: 0,
    });
  });

  it('⛔ fills a gap only — a version a feed already wrote is never overwritten', async () => {
    const { updateSql } = await runBackfill();
    assert.match(updateSql, /WHERE cvss_version IS NULL/);
  });

  it('⛔ refuses a row with no score: a scale describes a measurement', async () => {
    const { updateSql } = await runBackfill();
    assert.match(updateSql, /AND cvss_score IS NOT NULL/);
  });

  it('does not churn updated_at on rows whose advisory data did not change', async () => {
    const { updateSql } = await runBackfill();
    assert.ok(!/updated_at/.test(updateSql), 'the backfill must not restamp updated_at');
  });

  it('is bounded to advisories and issues exactly one UPDATE', async () => {
    const { pool } = await runBackfill();
    const updates = pool.calls.filter((c) => /^\s*UPDATE/i.test(c.sql));
    assert.equal(updates.length, 1);
    assert.match(updates[0].sql, /^\s*UPDATE advisories/);
    assert.ok(!/DELETE|DROP|INSERT/i.test(updates[0].sql));
  });

  it('reports what it changed, by version and by vendor', async () => {
    const { result } = await runBackfill();
    assert.equal(result.updated, 3);
    assert.deepEqual(result.byVersion, { '4.0': 1, '3.1': 2 });
    assert.deepEqual(result.byVendor, { paloalto: 2, fortinet: 1 });
  });

  it('is idempotent — a re-run matching nothing reports 0 and does not throw', async () => {
    const pool = stubPool([{ rows: [] }, REMAINDER_RESULT]);
    const result = await backfillCvssVersionFromVector(pool);
    assert.equal(result.updated, 0);
    assert.deepEqual(result.byVersion, {});
    assert.deepEqual(result.byVendor, {});
  });
});

describe('Palo Alto PSIRT reports the scale it scored on', () => {
  const record = (metrics) => ({ containers: { cna: { metrics } } });

  it('returns score, vector and version as one triple from one metric key', () => {
    const got = pickCvssFromPanOsRecord(
      record([{ cvssV3_1: { baseScore: 8.6, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N' } }])
    );
    assert.deepEqual(got, {
      score: 8.6,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
      version: '3.1',
    });
  });

  it('⛔ the version follows the cascade\'s CHOICE, not the other metrics present', () => {
    // Live-confirmed shape: Palo Alto has been migrating to v4.0 and a single record can carry
    // both. The score taken is v4.0's, so the scale reported must be v4.0's too — reporting
    // "3.1" beside a 4.0 number is precisely the mislabelling this column exists to prevent.
    const got = pickCvssFromPanOsRecord(
      record([
        { cvssV3_1: { baseScore: 8.6, vectorString: 'CVSS:3.1/AV:N' } },
        { cvssV4_0: { baseScore: 9.3, vectorString: 'CVSS:4.0/AV:N' } },
      ])
    );
    assert.equal(got.score, 9.3);
    assert.equal(got.version, '4.0');
    assert.equal(got.vector, 'CVSS:4.0/AV:N');
  });

  it('⛔ NOT MEASURED: no metrics at all yields nulls, never a default scale', () => {
    assert.deepEqual(pickCvssFromPanOsRecord(record([])), {
      score: null,
      vector: null,
      version: null,
    });
    assert.deepEqual(pickCvssFromPanOsRecord({}), { score: null, vector: null, version: null });
    assert.deepEqual(pickCvssFromPanOsRecord(null), { score: null, vector: null, version: null });
  });

  it('⛔ a metric block with no usable baseScore yields no score', () => {
    // The advisory published a vector but not a number we can read. `score: null` is what then
    // suppresses the source/scale in the normalizer below — provenance describes a score, and
    // there is none.
    const got = pickCvssFromPanOsRecord(record([{ cvssV4_0: { vectorString: 'CVSS:4.0/AV:N' } }]));
    assert.equal(got.score, null);
  });

  it('tags the score `psirt` and the scale together, and both NULL without a score', () => {
    assert.match(PALOALTO_SRC, /cvss_source: score === null \? null : 'psirt'/);
    assert.match(PALOALTO_SRC, /cvss_version: score === null \? null : version/);
  });

  it('⛔ the upsert moves source and scale under the SAME guard as the score', () => {
    // Split the four and a row ends up holding this feed's number under the previous source's
    // label — the exact state 67 live paloalto rows were in, scored by this feed and still
    // reading `cvss_source = 'circl'`.
    assert.match(PALOALTO_SRC, /cwe_ids, vulnerability_category, cvss_source, cvss_version,/);
    for (const col of ['cvss_score', 'cvss_vector', 'cvss_source', 'cvss_version']) {
      const guard = new RegExp(
        `${col} = CASE WHEN advisories\\.vendor = EXCLUDED\\.vendor\\s+THEN EXCLUDED\\.${col} ELSE advisories\\.${col} END`
      );
      assert.match(PALOALTO_SRC, guard, `${col} must keep the cross-vendor ownership guard`);
    }
  });
});
