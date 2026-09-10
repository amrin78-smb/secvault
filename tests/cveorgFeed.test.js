// tests/cveorgFeed.test.js
//
// Pins `lib/feeds/cveorg.js` — the CVE.org (MITRE CVE Program) ENRICHMENT-ONLY feed.
//
// ⛔ WHY THIS FILE EXISTS. Three properties of that feed are the kind that survive review,
// build clean, pass every static check, and then destroy data quietly months later:
//
//   1. IT MUST NEVER INSERT AN ADVISORY. `advisories.cve_id` is UNIQUE with exactly ONE
//      `vendor`, so an inserting feed permanently claims a CVE for whichever vendor got
//      there first. That harm is demonstrated, not hypothetical: CVE-2022-0778 is an
//      OpenSSL bug Fortinet republishes, and on this fleet it belongs to `paloalto` with 6
//      real version ranges. CVE.org covers EVERY CVE in existence, so one careless
//      `INSERT ... ON CONFLICT` copied in from a sibling feed file would eventually squat a
//      large fraction of the corpus — and it would look exactly like the other feeds.
//
//   2. IT MUST ONLY FILL A GAP. A vendor PSIRT's CVSS and version data outrank a generic
//      CVE Record for firewall purposes, so the write may only land where the column is
//      empty. This is the same precedence rule tests/cvssProvenance.test.js defends for
//      CIRCL-vs-NVD, and the same reason: it lives in a long SQL string where dropping one
//      clause fails nothing until a severity histogram starts moving on its own.
//
//   3. NO DATA MUST STAY NULL. Per tests/README.md, the "we could not measure this" case is
//      the one that regresses silently, because the wrong answer is a plausible number
//      rather than a crash. On the live corpus this is not an edge case, it is the NORMAL
//      case: 255 of 255 gap advisories carry no CVSS at CVE.org.
//
// SQL-shape assertions here are not database tests — nothing connects to Postgres. What is
// being defended is the presence and DIRECTION of each rule.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SRC_PATH = path.join(__dirname, '..', 'lib', 'feeds', 'cveorg.js');
const SRC = fs.readFileSync(SRC_PATH, 'utf8');
// The executable half only. This file's header explains at length why the feed must never
// INSERT — a whole-file grep for "INSERT INTO" would fire on that explanation. Conservative
// by construction: it only ever REMOVES text, so it cannot manufacture a pass by inventing
// code that is not there.
const CODE = SRC.split(/\r?\n/)
  .filter((line) => !/^\s*\/\//.test(line))
  .join('\n');
const C = require('../lib/feeds/cveorg');

// A pool stub that records every statement it is handed and returns canned rows.
// `rowsFor` lets a test decide what the candidate SELECT returns.
function stubPool(rowsFor) {
  const calls = [];
  return {
    calls,
    writes: () => calls.filter((c) => /\b(INSERT|UPDATE|DELETE)\b/i.test(c.sql)),
    async query(sql, params) {
      calls.push({ sql, params });
      const rows = rowsFor ? rowsFor(sql, params) : null;
      if (rows) return { rows, rowCount: rows.length };
      return { rows: [], rowCount: 0 };
    },
  };
}

// Runs the feed with node-fetch replaced in require.cache.
//
// ⛔ `lib/feeds/cveorg.js` does `require('node-fetch')` and binds it at load time, so
// stubbing `global.fetch` does NOTHING — the module would silently hit the LIVE CVE.org
// endpoint and the test would pass or fail according to the internet's mood. That exact
// mistake cost a sibling feed test 14 s and a false pass (.ai-codex/cve-pipeline.md's
// "tests here must stub node-fetch via require.cache" note). Reload the feed AFTER the
// stub is installed, and restore both entries afterwards.
async function runWithStubbedFetch(fetchStub, pool, options) {
  const fetchPath = require.resolve('node-fetch');
  const feedPath = require.resolve('../lib/feeds/cveorg');
  const savedFetch = require.cache[fetchPath];
  const savedFeed = require.cache[feedPath];
  delete require.cache[feedPath];
  require.cache[fetchPath] = {
    id: fetchPath,
    filename: fetchPath,
    loaded: true,
    exports: fetchStub,
  };
  try {
    const Fresh = require('../lib/feeds/cveorg');
    return await Fresh.fetchAndEnrichFromCveOrg(pool, { requestDelayMs: 0, ...(options || {}) });
  } finally {
    delete require.cache[feedPath];
    if (savedFetch) require.cache[fetchPath] = savedFetch;
    else delete require.cache[fetchPath];
    if (savedFeed) require.cache[feedPath] = savedFeed;
  }
}

// One candidate row, shaped exactly as SELECT_CANDIDATES_SQL returns it.
function candidateRows(over) {
  return [
    Object.assign(
      { cve_id: 'CVE-2024-21762', vendor: 'fortinet', needs_cvss: true, needs_cwe: true, tier: 0 },
      over || {}
    ),
  ];
}

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    },
  };
}

// A real CVE Record 5.x skeleton (shape captured live from cveawg.mitre.org 2026-09-10).
function record({ cnaMetrics, adpMetrics, cnaProblemTypes, adpProblemTypes, state = 'PUBLISHED', tags }) {
  return {
    dataType: 'CVE_RECORD',
    dataVersion: '5.2',
    cveMetadata: { cveId: 'CVE-2024-21762', state, assignerShortName: 'fortinet' },
    containers: {
      cna: {
        tags,
        metrics: cnaMetrics,
        problemTypes: cnaProblemTypes,
        descriptions: [{ lang: 'en', value: 'A out-of-bounds write in Fortinet FortiOS...' }],
      },
      adp: adpMetrics || adpProblemTypes
        ? [{ metrics: adpMetrics, problemTypes: adpProblemTypes }]
        : undefined,
    },
  };
}

// ════════════════════════════════════════════════════════════════════════
describe('⛔ enrichment-only: this feed can never create an advisory', () => {
  it('the source contains no INSERT into advisories at all', () => {
    // Not "no INSERT is executed on the paths we tested" — no INSERT EXISTS. That is the
    // only version of this property that survives someone copying an upsert in from
    // nvd.js/paloalto.js/fortinet.js, all three of which have one.
    //
    // Comments are stripped first: the file's own header explains at length WHY it must not
    // insert, and a lint that fires on its own rationale is a lint that gets deleted.
    assert.equal(
      /INSERT\s+INTO/i.test(CODE),
      false,
      'lib/feeds/cveorg.js must contain no INSERT statement of any kind'
    );
    assert.equal(/ON\s+CONFLICT/i.test(CODE), false, 'no upsert may exist in this file');
    assert.equal(/DELETE\s+FROM/i.test(CODE), false, 'this feed never deletes an advisory either');
  });

  it('the one write statement is an UPDATE keyed on an existing cve_id', () => {
    assert.match(C.ENRICH_SQL, /^\s*UPDATE advisories SET/);
    assert.match(C.ENRICH_SQL, /WHERE advisories\.cve_id = \$1::text/);
  });

  it('a record for a CVE we do not hold cannot create one', async () => {
    // The candidate list comes from `advisories` itself, so an unknown CVE is never even a
    // candidate — and if the UPDATE ever ran for one it would match zero rows.
    const pool = stubPool((sql) => (/^\s*WITH gaps/.test(sql) ? [] : null));
    const res = await runWithStubbedFetch(async () => {
      throw new Error('no request should be made when there are no candidates');
    }, pool);
    assert.equal(res.inserted, 0);
    assert.equal(res.updated, 0);
    assert.equal(pool.writes().length, 0);
  });

  it('`inserted` is always 0 in the returned shape', async () => {
    const pool = stubPool((sql) => (/^\s*WITH gaps/.test(sql) ? candidateRows() : null));
    const res = await runWithStubbedFetch(
      async () => jsonResponse(record({ cnaMetrics: [{ cvssV3_1: { baseScore: 9.6 } }] })),
      pool
    );
    assert.equal(res.inserted, 0);
  });
});

// ════════════════════════════════════════════════════════════════════════
describe('⛔ precedence: a CVE.org value may fill a gap, never overwrite a source', () => {
  it('every CVSS column is written only when the stored score IS NULL', () => {
    // Four columns, one guard each, all reading the PRE-update row. Drop the guard from any
    // one of them and CVE.org starts overwriting a vendor PSIRT's own score — or, worse,
    // leaves a score from one source beside a vector from another.
    const guards = C.ENRICH_SQL.match(/WHEN advisories\.cvss_score IS NULL AND \$2::numeric IS NOT NULL/g) || [];
    assert.equal(
      guards.length,
      4,
      'expected the IS NULL gap guard on cvss_score, cvss_vector, cvss_source and cvss_version'
    );
  });

  it('CWE is written only into an absent-or-empty array', () => {
    // `cwe_ids = '{}'` is a real answer ("we looked, there are none"), so emptiness is
    // tested explicitly rather than relying on NULL alone.
    const guards =
      C.ENRICH_SQL.match(
        /WHEN \(advisories\.cwe_ids IS NULL OR cardinality\(advisories\.cwe_ids\) = 0\)/g
      ) || [];
    assert.equal(guards.length, 2, 'expected the CWE gap guard on cwe_ids and vulnerability_category');
  });

  it('⛔ vendor-owned columns are never written', () => {
    // A vendor PSIRT's title/description/ranges/URL are more actionable for a firewall
    // operator than a generic CVE Record's, and the ranges are what versionMatcher reads.
    // The strongest possible protection is that they do not appear in the SET list at all.
    const setClause = C.ENRICH_SQL.split(/WHERE/i)[0];
    for (const col of [
      'vendor',
      'title',
      'description',
      'affected_version_ranges',
      'fixed_in_versions',
      'advisory_url',
      'raw_data',
      'matchability',
      'kev_listed',
      'kev_date',
      'published_at',
    ]) {
      assert.equal(
        new RegExp(`(^|[\\s,])${col}\\s*=`, 'm').test(setClause),
        false,
        `${col} must never be assigned by the CVE.org feed`
      );
    }
  });

  it('provenance travels with the score', () => {
    // A number with no recorded origin is a number whose meaning can change without anyone
    // noticing — the incident tests/cvssProvenance.test.js exists for.
    assert.match(C.ENRICH_SQL, /cvss_source = CASE[\s\S]*?THEN 'cveorg'/);
    assert.match(C.ENRICH_SQL, /cvss_version = CASE/);
  });

  it('a row with nothing to fill is not touched at all', () => {
    // The WHERE repeats the gap test, so no write and no updated_at bump happens for a row
    // that gains nothing — which is what makes `updated` an honest count.
    assert.match(
      C.ENRICH_SQL,
      /AND \( \(advisories\.cvss_score IS NULL AND \$2::numeric IS NOT NULL\)/
    );
  });

  it('every parameter is bound, never interpolated', () => {
    assert.equal(/\$\{/.test(C.ENRICH_SQL), false, 'no template interpolation in SQL');
    assert.equal(/\$\{/.test(C.SELECT_CANDIDATES_SQL), false);
  });
});

// ════════════════════════════════════════════════════════════════════════
describe('⛔ CVSS block selection is a decision, not "the first one"', () => {
  it('the CNA container outranks an ADP container', () => {
    // Live evidence for this direction: CVE-2024-21762's cna carries cvssV3_1 while its adp
    // carries only ssvc/kev; CVE-2022-0778's cna carries only `other` and the adp supplies
    // the score. ADP fills where the assigner is silent.
    const rec = record({
      cnaMetrics: [{ cvssV3_1: { baseScore: 9.6, vectorString: 'CVSS:3.1/CNA' } }],
      adpMetrics: [{ cvssV4_0: { baseScore: 5.0, vectorString: 'CVSS:4.0/ADP' } }],
    });
    const got = C.pickCvssFromCveRecord(rec);
    assert.equal(got.score, 9.6);
    assert.equal(got.container, 'cna');
    assert.equal(got.version, '3.1');
    // ⛔ Note this beats the ADP's NEWER version. Container outranks version, deliberately.
  });

  it('within a container the newest CVSS version wins', () => {
    const rec = record({
      cnaMetrics: [
        { cvssV2_0: { baseScore: 5.0 } },
        { cvssV3_1: { baseScore: 7.5 } },
        { cvssV4_0: { baseScore: 8.8, vectorString: 'CVSS:4.0/X' } },
      ],
    });
    const got = C.pickCvssFromCveRecord(rec);
    assert.equal(got.score, 8.8);
    assert.equal(got.version, '4.0');
  });

  it('ADP is used when the CNA has metrics but no CVSS among them', () => {
    // The live CVE-2022-0778 shape: cna.metrics exists and holds only an `other` entry.
    const rec = record({
      cnaMetrics: [{ other: { type: 'ssvc', content: {} } }],
      adpMetrics: [{ other: { type: 'kev' } }, { cvssV3_1: { baseScore: 7.5, vectorString: 'V' } }],
    });
    const got = C.pickCvssFromCveRecord(rec);
    assert.equal(got.score, 7.5);
    assert.equal(got.container, 'adp');
  });

  it('two blocks of the same version take the first, never an average or a max', () => {
    // Averaging two assessors invents a number neither published; taking the max is a silent
    // editorial choice. One published score, plus the provenance to trace it.
    const rec = record({
      cnaMetrics: [{ cvssV3_1: { baseScore: 4.0, vectorString: 'FIRST' } }, { cvssV3_1: { baseScore: 9.9 } }],
    });
    const got = C.pickCvssFromCveRecord(rec);
    assert.equal(got.score, 4.0);
    assert.equal(got.vector, 'FIRST');
  });

  it('⛔ NOT MEASURED: no CVSS anywhere yields null, never 0', () => {
    // THE case that matters. 255 of 255 gap advisories on the live fleet look exactly like
    // this. A 0 here would read as "harmless" to prioritization.js, which is a fabricated
    // clean bill of health; a null reads as "no CVSS signal", which is the truth.
    for (const rec of [
      record({}),
      record({ cnaMetrics: [] }),
      record({ cnaMetrics: [{ other: { type: 'ssvc' } }], adpMetrics: [{ other: { type: 'kev' } }] }),
      {},
      { containers: {} },
    ]) {
      const got = C.pickCvssFromCveRecord(rec);
      assert.equal(got.score, null);
      assert.equal(got.vector, null);
      assert.equal(got.version, null);
    }
  });

  it('a non-numeric baseScore is not a score', () => {
    // A string "7.5" is a shape this codebase has been burned by elsewhere; it is refused
    // rather than coerced, because a coerced value cannot be told from a measured one.
    const rec = record({ cnaMetrics: [{ cvssV3_1: { baseScore: '7.5' } }, { cvssV3_0: { baseScore: 6.1 } }] });
    const got = C.pickCvssFromCveRecord(rec);
    assert.equal(got.score, 6.1);
    assert.equal(got.version, '3.0');
  });

  it('a null score is never sent to the database as a value', async () => {
    const pool = stubPool((sql) => (/^\s*WITH gaps/.test(sql) ? candidateRows() : null));
    const res = await runWithStubbedFetch(
      async () => jsonResponse(record({ cnaMetrics: [{ other: { type: 'ssvc' } }] })),
      pool
    );
    assert.equal(res.updated, 0, 'nothing to write means nothing written');
    assert.equal(pool.writes().length, 0, 'no UPDATE may be issued for a record with no data');
    assert.equal(res.summary.no_data_at_cveorg, 1);
  });
});

// ════════════════════════════════════════════════════════════════════════
describe('CWE extraction', () => {
  it('reads cna.problemTypes[].descriptions[].cweId', () => {
    const rec = record({
      cnaProblemTypes: [{ descriptions: [{ cweId: 'CWE-787', type: 'CWE' }, { cweId: 'CWE-787' }] }],
    });
    assert.deepEqual(C.extractCweIdsFromCveRecord(rec), ['CWE-787']);
  });

  it('falls back to an ADP container only when the CNA supplied none', () => {
    const both = record({
      cnaProblemTypes: [{ descriptions: [{ cweId: 'CWE-193' }] }],
      adpProblemTypes: [{ descriptions: [{ cweId: 'CWE-999' }] }],
    });
    assert.deepEqual(C.extractCweIdsFromCveRecord(both), ['CWE-193'], 'the assigner outranks the ADP');
    const adpOnly = record({ adpProblemTypes: [{ descriptions: [{ cweId: 'CWE-125' }] }] });
    assert.deepEqual(C.extractCweIdsFromCveRecord(adpOnly), ['CWE-125']);
  });

  it('⛔ NOT MEASURED: no weakness mapping yields an empty list, never a guess', () => {
    // 307 of the 311 CWE-gap rows on the live fleet are exactly this. An empty list is
    // returned and — see the run behaviour below — no UPDATE is issued at all, so
    // vulnerability_category is never rewritten to 'Other' on the strength of nothing.
    assert.deepEqual(C.extractCweIdsFromCveRecord(record({})), []);
    assert.deepEqual(C.extractCweIdsFromCveRecord({}), []);
    assert.deepEqual(
      C.extractCweIdsFromCveRecord(record({ cnaProblemTypes: [{ descriptions: [{ description: 'no cwe' }] }] })),
      []
    );
  });
});

// ════════════════════════════════════════════════════════════════════════
describe('⛔ a rejected CVE Record is a real state, handled deliberately', () => {
  it('recordState reads cveMetadata.state', () => {
    assert.equal(C.recordState(record({})), 'PUBLISHED');
    assert.equal(C.recordState(record({ state: 'REJECTED' })), 'REJECTED');
    assert.equal(C.recordState({}), null);
  });

  it('a REJECTED record enriches nothing and is reported by id', async () => {
    // Not enriched (a withdrawn record's contents are not evidence), not deleted (that
    // would cascade operator-curated advisory_conditions and is a different decision), and
    // never silent — an advisory pointing at a withdrawn CVE is something an operator
    // should see once rather than never.
    const pool = stubPool((sql) => (/^\s*WITH gaps/.test(sql) ? candidateRows() : null));
    const res = await runWithStubbedFetch(
      async () =>
        jsonResponse(
          record({ state: 'REJECTED', cnaMetrics: [{ cvssV3_1: { baseScore: 9.9, vectorString: 'X' } }] })
        ),
      pool
    );
    assert.equal(res.updated, 0);
    assert.equal(pool.writes().length, 0, 'a rejected record must not reach the write statement');
    assert.deepEqual(res.summary.rejected, ['CVE-2024-21762 (REJECTED)']);
  });

  it('a DISPUTED-but-published record IS used, and is reported', async () => {
    // A dispute is about whether the vulnerability exists, not about whether the CNA
    // published that number. Refusing it would leave cvss_score NULL, which
    // prioritization.js treats as no signal — narrowing an uncertain bound, which this
    // codebase's tri-state rule forbids. So: use it, and say so.
    const pool = stubPool((sql) =>
      /^\s*WITH gaps/.test(sql) ? candidateRows() : /^\s*UPDATE advisories/.test(sql) ? [{ cve_id: 'CVE-2024-21762' }] : null
    );
    const res = await runWithStubbedFetch(
      async () =>
        jsonResponse(
          record({ tags: ['disputed'], cnaMetrics: [{ cvssV3_1: { baseScore: 7.5, vectorString: 'V' } }] })
        ),
      pool
    );
    assert.equal(res.updated, 1);
    assert.deepEqual(res.summary.disputed, ['CVE-2024-21762']);
  });
});

// ════════════════════════════════════════════════════════════════════════
describe('bounded, polite work', () => {
  it('⛔ a non-CVE-shaped id is never sent at the network, and is counted', async () => {
    // 59 live advisories carry Palo Alto's own `PAN-SA-*` ids, 33 of them with a gap, and
    // CVE.org answers 400 for every one. Discovering that 33 times over the network would
    // report a structural fact as 33 request failures.
    assert.equal(C.isCveShapedId('CVE-2024-21762'), true);
    assert.equal(C.isCveShapedId('PAN-SA-2024-0001'), false);
    assert.equal(C.isCveShapedId('CVE-24-1'), false);
    assert.equal(C.isCveShapedId(null), false);
    assert.match(C.SELECT_CANDIDATES_SQL, /AND cve_id ~ \$1::text/);
    assert.match(C.COUNT_NON_CVE_GAPS_SQL, /AND cve_id !~ \$1::text/);

    const pool = stubPool((sql) =>
      /^\s*WITH gaps/.test(sql) ? candidateRows({ cve_id: 'PAN-SA-2024-0001' }) : /count\(\*\)::int/.test(sql) ? [{ n: 33 }] : null
    );
    let requests = 0;
    const res = await runWithStubbedFetch(async () => {
      requests += 1;
      return jsonResponse({});
    }, pool);
    assert.equal(requests, 0, 'a known-bad id must not be requested');
    assert.equal(res.summary.skipped_non_cve_id, 33, 'and the excluded rows must be reported');
  });

  it('the candidate query asks only for rows with a gap', () => {
    // Never "all 1,004 every 6 hours" — a row with both a score and a CWE has nothing this
    // feed can add, so requesting it is pure cost to somebody else's service.
    assert.match(
      C.SELECT_CANDIDATES_SQL,
      /WHERE \(cvss_score IS NULL OR cwe_ids IS NULL OR cardinality\(cwe_ids\) = 0\)/
    );
    assert.match(C.SELECT_CANDIDATES_SQL, /LIMIT \$5::int/);
    assert.ok(C.MAX_RECORDS_PER_RUN <= 500, 'the per-run ceiling must stay small');
  });

  it('⛔ a stored 0.0 is NOT treated as a gap', () => {
    // 12 live rows are stored 0.0 with a NULL cvss_source and CVE.org publishes 7.5 / 8.8 /
    // 9.8 for three of them — almost certainly a fabricated default upstream. It is still
    // not this feed's call: a CVSS base score of 0.0 IS publishable, and 682 rows predate
    // cvss_source entirely, so "0.0 with no source is fake" would also condemn a real 0.0.
    // Overwriting on that guess is the failed-read bug pointed the other way.
    assert.equal(
      /cvss_score\s*=\s*0/.test(C.SELECT_CANDIDATES_SQL),
      false,
      'the candidate query must not treat a stored zero as a missing score'
    );
    // It is reported instead — skip AND report, never skip silently.
    assert.match(C.SUSPICIOUS_ZERO_SCORES_SQL, /WHERE cvss_score = 0/);
    assert.match(C.SUSPICIOUS_ZERO_SCORES_SQL, /^\s*SELECT cve_id/);
  });

  it('⛔ the backfill bucket count is PRIME so no cadence can strand rows', () => {
    // The bucket index advances with the clock because there is no column to remember
    // progress in. With a composite count, a run cadence sharing a factor with it would
    // visit a subset of buckets FOREVER while every log line looked healthy.
    const n = C.BACKFILL_BUCKETS;
    for (let d = 2; d * d <= n; d++) assert.notEqual(n % d, 0, `${n} must be prime`);
    // Any step that is not a multiple of a prime modulus walks the whole rotation. The
    // sample window is expressed in WALL-CLOCK time, not in run count: a cadence faster than
    // the 6 h bucket period simply repeats a bucket several times before advancing, and
    // counting runs instead of hours would make that look like a stranded rotation.
    const bucketPeriodHours = 6;
    for (const stepHours of [1, 6, 12, 24, 72]) {
      // Enough wall-clock for the bucket index to advance n times, whichever of the two
      // periods is the slower.
      const windowHours = n * Math.max(bucketPeriodHours, stepHours) * 2;
      const seen = new Set();
      for (let h = 0; h <= windowHours; h += stepHours) {
        seen.add(C.currentBackfillBucket(h * 3600 * 1000, n));
      }
      assert.equal(seen.size, n, `a ${stepHours}h cadence must still reach all ${n} buckets`);
    }
  });

  it('there is a delay between requests by default', () => {
    assert.match(SRC, /const REQUEST_DELAY_MS = \d+/);
    const delay = Number(SRC.match(/const REQUEST_DELAY_MS = (\d+)/)[1]);
    assert.ok(delay >= 100, 'requests must be spaced; CVE.org publishes no rate limit to lean on');
  });

  it('every request carries a timeout', () => {
    // node-fetch@2 has NO default timeout: one silently-dropped packet hangs the run.
    assert.match(SRC, /const FETCH_TIMEOUT_MS = 20000/);
    assert.match(SRC, /timeout: FETCH_TIMEOUT_MS/);
  });
});

// ════════════════════════════════════════════════════════════════════════
describe('failure handling', () => {
  it('a 404 changes nothing and is reported, not counted as an error', async () => {
    const pool = stubPool((sql) => (/^\s*WITH gaps/.test(sql) ? candidateRows() : null));
    const res = await runWithStubbedFetch(async () => jsonResponse({}, 404), pool);
    assert.equal(pool.writes().length, 0);
    assert.deepEqual(res.summary.not_found, ['CVE-2024-21762']);
    assert.equal(res.errors.length, 0, 'a 404 is an answer, not a malfunction');
  });

  it('⛔ the run abandons itself once CVE.org is unreachable', async () => {
    // Without this, an unreachable host costs MAX_RECORDS_PER_RUN × 20 s of sleeping per
    // run — the exact waste nvd.js's circuit breaker was added to remove (474 runs, zero
    // successes, ~500 s each).
    const rows = [];
    for (let i = 0; i < 40; i++) {
      rows.push({ cve_id: `CVE-2024-0${1000 + i}`, vendor: 'fortinet', needs_cvss: true, needs_cwe: true, tier: 1 });
    }
    const pool = stubPool((sql) => (/^\s*WITH gaps/.test(sql) ? rows : null));
    let requests = 0;
    const res = await runWithStubbedFetch(
      async () => {
        requests += 1;
        throw new Error('connect ETIMEDOUT'); // fetch() itself throwing: no .status
      },
      pool,
      { unreachableStreak: 4 }
    );
    assert.equal(requests, 4, `expected 4 probes before giving up, saw ${requests}`);
    assert.equal(res.summary.unreachable, true);
    assert.ok(res.errors.some((e) => /\[CVE\.org unreachable\]/.test(e.message)));
    assert.equal(pool.writes().length, 0);
  });

  it('⛔ an HTTP answer RESETS the streak — it is proof the host is up', async () => {
    // A 5xx means CVE.org replied. Letting it accumulate toward "unreachable" would
    // abandon a run against a host that is demonstrably answering.
    const rows = [];
    for (let i = 0; i < 12; i++) {
      rows.push({ cve_id: `CVE-2024-0${1000 + i}`, vendor: 'fortinet', needs_cvss: true, needs_cwe: true, tier: 1 });
    }
    const pool = stubPool((sql) => (/^\s*WITH gaps/.test(sql) ? rows : null));
    let requests = 0;
    const res = await runWithStubbedFetch(
      async () => {
        requests += 1;
        return jsonResponse({}, 503);
      },
      pool,
      { unreachableStreak: 4 }
    );
    assert.equal(requests, 12, 'every candidate should still be attempted');
    assert.equal(res.summary.unreachable, false);
  });

  it('a malformed body on a 200 is not a reachability problem', async () => {
    const pool = stubPool((sql) => (/^\s*WITH gaps/.test(sql) ? candidateRows() : null));
    const res = await runWithStubbedFetch(
      async () => ({
        ok: true,
        status: 200,
        async json() {
          throw new SyntaxError('Unexpected end of JSON input');
        },
      }),
      pool
    );
    // A bare SyntaxError has no `.status`, which is exactly why the module tags it — without
    // the tag it would look identical to "the host never answered".
    assert.equal(res.summary.unreachable, false);
    assert.equal(pool.writes().length, 0);
    assert.equal(res.errors.length, 1);
  });

  it('a failure selecting candidates returns cleanly and writes nothing', async () => {
    const pool = {
      calls: [],
      writes: () => [],
      async query() {
        throw new Error('DB down');
      },
    };
    const res = await runWithStubbedFetch(async () => jsonResponse({}), pool);
    assert.equal(res.inserted, 0);
    assert.equal(res.updated, 0);
    assert.equal(res.examined, 0);
    assert.match(res.errors[0].message, /candidate selection failed/);
  });
});

// ════════════════════════════════════════════════════════════════════════
describe('run summary is honest', () => {
  it('informational counters live in `summary`, never in `errors`', async () => {
    // lib/feeds/index.js decides feed_sync_log.status as
    // `errors.length > 0 ? 'partial' : 'success'`. An informational entry pushed into
    // `errors` would therefore paint every healthy run 'partial' — which is how a real
    // degradation stops standing out.
    const pool = stubPool((sql) =>
      /^\s*WITH gaps/.test(sql) ? candidateRows() : /^\s*UPDATE advisories/.test(sql) ? [{ cve_id: 'CVE-2024-21762' }] : null
    );
    const res = await runWithStubbedFetch(
      async () =>
        jsonResponse(
          record({
            cnaMetrics: [{ cvssV3_1: { baseScore: 9.6, vectorString: 'CVSS:3.1/AV:N' } }],
            cnaProblemTypes: [{ descriptions: [{ cweId: 'CWE-787' }] }],
          })
        ),
      pool
    );
    assert.equal(res.errors.length, 0, 'a clean run must report zero errors');
    assert.equal(res.updated, 1);
    assert.equal(res.summary.filled_cvss, 1);
    assert.equal(res.summary.filled_cwe, 1);
    assert.equal(res.summary.examined, 1);
  });

  it('a filled row sends score, vector, version and CWEs together', async () => {
    const pool = stubPool((sql) =>
      /^\s*WITH gaps/.test(sql) ? candidateRows() : /^\s*UPDATE advisories/.test(sql) ? [{ cve_id: 'CVE-2024-21762' }] : null
    );
    await runWithStubbedFetch(
      async () =>
        jsonResponse(
          record({
            cnaMetrics: [{ cvssV3_1: { baseScore: 9.6, vectorString: 'CVSS:3.1/AV:N' } }],
            cnaProblemTypes: [{ descriptions: [{ cweId: 'CWE-787' }] }],
          })
        ),
      pool
    );
    const write = pool.writes()[0];
    assert.ok(write, 'an UPDATE should have been issued');
    assert.equal(write.params[0], 'CVE-2024-21762');
    assert.equal(write.params[1], 9.6);
    assert.equal(write.params[2], 'CVSS:3.1/AV:N');
    assert.equal(write.params[3], '3.1');
    assert.deepEqual(write.params[4], ['CWE-787']);
    // vulnerability_category is recomputed WITH cwe_ids, never left contradicting it: a row
    // holding CWE-787 beside 'Other' (categorizeCwes' honest answer for an EMPTY list) would
    // disagree with itself.
    assert.ok(typeof write.params[5] === 'string' && write.params[5].length > 0);
  });

  it('a gap the record cannot fill counts as no_data, not as an error', async () => {
    const pool = stubPool((sql) => (/^\s*WITH gaps/.test(sql) ? candidateRows() : null));
    const res = await runWithStubbedFetch(async () => jsonResponse(record({})), pool);
    assert.equal(res.summary.no_data_at_cveorg, 1);
    assert.equal(res.errors.length, 0);
    assert.equal(res.updated, 0);
  });
});
