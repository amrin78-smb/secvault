// tests/epssFeed.test.js
//
// Pins the two properties the EPSS feed exists to guarantee:
//
//   1. ENRICHMENT-ONLY — it may UPDATE an advisory that already exists and may
//      NEVER INSERT one. EPSS covers ~371,000 CVEs; SecVault tracks ~1,004.
//      `advisories.cve_id` is UNIQUE with a single `vendor`, so an inserting
//      feed can permanently squat a CVE under the wrong vendor — demonstrated
//      live by CVE-2022-0778, an OpenSSL bug that belongs to `paloalto` in this
//      database with 6 real version ranges.
//
//   2. NO SCORE IS NULL, NEVER 0 — an EPSS of 0.0 is a real measurement
//      ("essentially never exploited"); the absence of one is not. Per
//      tests/README.md every test here carries the "we could not measure this"
//      case, because that is the one that regresses silently: the wrong answer
//      is a plausible number rather than a crash.
//
// Fixtures are REAL bytes captured from the live services on 2026-09-10, not
// invented from documentation (CLAUDE.md's "documentation lies" rule).

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');

const E = require('../lib/feeds/epss');

// ── Fixtures ────────────────────────────────────────────────────────────────

// The first lines of the real decompressed
// https://epss.empiricalsecurity.com/epss_scores-current.csv.gz, verbatim.
const REAL_CSV_HEAD = [
  '#model_version:v2026.06.15,score_date:2026-09-10T12:00:22Z',
  'cve,epss,percentile',
  'CVE-1999-0001,0.03351,0.87967',
  'CVE-1999-0002,0.27858,0.97975',
  'CVE-2022-0778,0.73188,0.99423',
  'CVE-2024-3400,0.99999,1.00000',
  '',
].join('\n');

// One real api.first.org envelope, verbatim.
const REAL_API_ENVELOPE = {
  status: 'OK',
  'status-code': 200,
  version: '1.0',
  access: 'public',
  total: 1,
  offset: 0,
  limit: 100,
  data: [
    { cve: 'CVE-2022-0778', epss: '0.731880000', percentile: '0.994230000', date: '2026-09-10' },
  ],
};

function stubPool(rows) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      if (/^\s*SELECT/i.test(sql)) return { rows: rows || [], rowCount: (rows || []).length };
      // An UPDATE ... WHERE cve_id = $6 touches exactly the one row it names.
      return { rows: [], rowCount: 1 };
    },
  };
}

// The require.cache pattern CLAUDE.md documents for CommonJS collaborators:
// lib/feeds/epss.js does `require('node-fetch')` and binds it at load time, so
// stubbing `global.fetch` would silently do nothing and the test would hit the
// LIVE endpoint (the exact mistake tests/fortinetFeed.test.js records).
async function withStubbedFetch(stub, fn) {
  const fetchPath = require.resolve('node-fetch');
  const feedPath = require.resolve('../lib/feeds/epss');
  const savedFetch = require.cache[fetchPath];
  const savedFeed = require.cache[feedPath];
  delete require.cache[feedPath];
  require.cache[fetchPath] = { id: fetchPath, filename: fetchPath, loaded: true, exports: stub };
  try {
    return await fn(require('../lib/feeds/epss'));
  } finally {
    delete require.cache[feedPath];
    if (savedFetch) require.cache[fetchPath] = savedFetch;
    else delete require.cache[fetchPath];
    if (savedFeed) require.cache[feedPath] = savedFeed;
  }
}

function gzipResponse(csv) {
  const body = zlib.gzipSync(Buffer.from(csv, 'utf8'));
  return { ok: true, status: 200, arrayBuffer: async () => body };
}

const writeStatements = (pool) => pool.calls.filter((c) => /\b(INSERT|UPDATE|DELETE)\b/i.test(c.sql));

// ── The value parser: unreadable is NULL, and 0 is a real answer ─────────────

describe('parseProbability: an unreadable value is null, never 0', () => {
  it('reads a real 5-decimal value and a real 9-decimal API value identically', () => {
    assert.equal(E.parseProbability('0.73188'), 0.73188);
    assert.equal(E.parseProbability('0.731880000'), 0.73188);
  });

  it('returns 0 for a genuine zero — that IS a measurement', () => {
    assert.equal(E.parseProbability('0.00000'), 0);
    assert.equal(E.parseProbability(0), 0);
  });

  it('returns null (NOT 0) for absent, empty and whitespace values', () => {
    // Number('') is 0 and 0 is FINITE — this is exactly how an absent value
    // becomes a confident "essentially never exploited". Same trap as clampInt.
    for (const bad of [null, undefined, '', '   ', '\t']) {
      assert.equal(E.parseProbability(bad), null, `${JSON.stringify(bad)} must be null, not 0`);
    }
  });

  it('returns null for garbage and for values outside [0,1]', () => {
    for (const bad of ['n/a', 'NaN', 'unknown', '-0.5', '1.5', '12']) {
      assert.equal(E.parseProbability(bad), null, `${bad} must be null`);
    }
  });
});

describe('parseScoreDate', () => {
  it('reads both real forms: the CSV timestamp and the API date', () => {
    assert.equal(E.parseScoreDate('2026-09-10T12:00:22Z'), '2026-09-10');
    assert.equal(E.parseScoreDate('2026-09-10'), '2026-09-10');
  });

  it('returns null rather than inventing a date', () => {
    for (const bad of [null, undefined, '', 'today', '10/09/2026']) {
      assert.equal(E.parseScoreDate(bad), null);
    }
  });
});

// ── The bulk CSV parser ─────────────────────────────────────────────────────

describe('parseEpssCsv against the real published file', () => {
  it('reads the metadata comment, the header and the rows', () => {
    const parsed = E.parseEpssCsv(REAL_CSV_HEAD, null);
    assert.equal(parsed.error, null);
    assert.equal(parsed.modelVersion, 'v2026.06.15');
    // score_date's value contains its own colons — splitting on every colon
    // instead of the first would lose the date entirely.
    assert.equal(parsed.scoreDate, '2026-09-10');
    assert.equal(parsed.feedRows, 4);
    assert.equal(parsed.scores.get('CVE-2022-0778').score, 0.73188);
    assert.equal(parsed.scores.get('CVE-2022-0778').percentile, 0.99423);
  });

  it('counts every feed row but stores only the advisories we actually have', () => {
    // The whole point of enrichment-only: ~370,000 records match nothing here.
    const parsed = E.parseEpssCsv(REAL_CSV_HEAD, new Set(['CVE-2022-0778']));
    assert.equal(parsed.feedRows, 4, 'unmatched records must still be COUNTED');
    assert.equal(parsed.scores.size, 1, 'and must not be carried forward for storage');
    assert.ok(!parsed.scores.has('CVE-2024-3400'));
  });

  it('locates columns BY NAME, so a reordered header cannot swap probability and percentile', () => {
    // Both quantities live in [0,1], so a positional swap produces two entirely
    // plausible numbers and nothing errors. 0.02 probability is ~80th percentile.
    const reordered = [
      '#model_version:v2026.06.15,score_date:2026-09-10T12:00:22Z',
      'cve,percentile,epss',
      'CVE-2022-0778,0.99423,0.73188',
      '',
    ].join('\n');
    const parsed = E.parseEpssCsv(reordered, null);
    assert.equal(parsed.error, null);
    assert.equal(parsed.scores.get('CVE-2022-0778').score, 0.73188);
    assert.equal(parsed.scores.get('CVE-2022-0778').percentile, 0.99423);
  });

  it('refuses to parse at all when a header name is missing — stores nothing', () => {
    const noHeader = ['#score_date:2026-09-10T12:00:22Z', 'CVE-2022-0778,0.73188,0.99423', ''].join('\n');
    const parsed = E.parseEpssCsv(noHeader, null);
    assert.ok(parsed.error, 'a header it cannot understand must be a hard failure');
    assert.equal(parsed.scores.size, 0);
  });

  it('drops a row with an unreadable score instead of storing a zero', () => {
    const withGaps = [
      '#model_version:v1,score_date:2026-09-10T12:00:22Z',
      'cve,epss,percentile',
      'CVE-2000-0001,,0.5',
      'CVE-2000-0002,n/a,0.5',
      'CVE-2000-0003,0.00000,0.00100',
      '',
    ].join('\n');
    const parsed = E.parseEpssCsv(withGaps, null);
    assert.ok(!parsed.scores.has('CVE-2000-0001'), 'an empty score must not become 0');
    assert.ok(!parsed.scores.has('CVE-2000-0002'), 'garbage must not become 0');
    assert.equal(parsed.malformed, 2, 'and both must be COUNTED, not silently dropped');
    // A genuine zero survives — it is a real measurement.
    assert.equal(parsed.scores.get('CVE-2000-0003').score, 0);
  });
});

// ── The API fallback parser ─────────────────────────────────────────────────

describe('parseEpssApiPayload', () => {
  it('reads the real envelope', () => {
    const parsed = E.parseEpssApiPayload(REAL_API_ENVELOPE);
    assert.equal(parsed.error, null);
    assert.equal(parsed.returned, 1);
    assert.equal(parsed.scores.get('CVE-2022-0778').score, 0.73188);
    assert.equal(parsed.scores.get('CVE-2022-0778').scoreDate, '2026-09-10');
  });

  it('carries a NULL model version rather than borrowing the bulk file\'s', () => {
    // The API does not publish one. Labelling a new score with the previous
    // run's model version would attribute it to a model that did not produce it.
    assert.equal(E.parseEpssApiPayload(REAL_API_ENVELOPE).scores.get('CVE-2022-0778').modelVersion, null);
  });

  it('has no entry for an id the API omitted — verified live: unknown ids are absent', () => {
    const parsed = E.parseEpssApiPayload(REAL_API_ENVELOPE);
    assert.ok(!parsed.scores.has('PAN-SA-2014-0001'));
    assert.equal(parsed.scores.size, 1);
  });

  it('reports a response with no data array as an error, not as zero results', () => {
    for (const bad of [null, {}, { data: 'nope' }, { status: 'OK' }]) {
      assert.ok(E.parseEpssApiPayload(bad).error, `${JSON.stringify(bad)} must be an error`);
    }
  });
});

// ── The run: enrichment-only, end to end ────────────────────────────────────

describe('fetchAndUpsertEpssScores', () => {
  it('never issues an INSERT — it may only UPDATE advisories that already exist', async () => {
    const pool = stubPool([
      { cve_id: 'CVE-2022-0778', epss_score: null },
      { cve_id: 'PAN-SA-2014-0001', epss_score: null },
    ]);
    const result = await withStubbedFetch(
      async () => gzipResponse(REAL_CSV_HEAD),
      (Feed) => Feed.fetchAndUpsertEpssScores(pool)
    );

    const inserts = pool.calls.filter((c) => /\bINSERT\b/i.test(c.sql));
    assert.equal(inserts.length, 0, 'an INSERT here can squat a CVE under the wrong vendor');
    assert.equal(result.inserted, 0, 'inserted is a structural invariant, not a coincidence');
    assert.ok(
      writeStatements(pool).every((c) => /^\s*UPDATE\s+advisories\b/i.test(c.sql)),
      'every write must be an UPDATE against advisories'
    );
    assert.equal(result.errors.length, 0);
  });

  it('counts the EPSS records that matched nothing instead of storing them', async () => {
    const pool = stubPool([{ cve_id: 'CVE-2022-0778', epss_score: null }]);
    const { summary } = await withStubbedFetch(
      async () => gzipResponse(REAL_CSV_HEAD),
      (Feed) => Feed.fetchAndUpsertEpssScores(pool)
    );
    assert.equal(summary.matched, 1);
    assert.equal(summary.feed_records, 4);
    assert.equal(summary.feed_records_unmatched, 3, 'reported, never stored');
    assert.equal(summary.model_version, 'v2026.06.15');
    assert.equal(summary.score_date, '2026-09-10');
    assert.equal(summary.source, 'bulk');
  });

  it('records "looked up, no score" separately from "never looked up"', async () => {
    // Live, 59 of 1,004 advisories are PAN-SA-* ids that EPSS cannot score.
    // They get epss_checked_at and NO epss_score — never a zero.
    const pool = stubPool([
      { cve_id: 'CVE-2022-0778', epss_score: null },
      { cve_id: 'PAN-SA-2014-0001', epss_score: null },
    ]);
    const { summary } = await withStubbedFetch(
      async () => gzipResponse(REAL_CSV_HEAD),
      (Feed) => Feed.fetchAndUpsertEpssScores(pool)
    );
    assert.equal(summary.no_score, 1);

    const stamp = pool.calls.find((c) => /epss_checked_at = now\(\)/i.test(c.sql) && /ANY\(/i.test(c.sql));
    assert.ok(stamp, 'the unscored advisory must be stamped as CHECKED');
    assert.deepEqual(stamp.params[0], ['PAN-SA-2014-0001']);
    assert.ok(!/epss_score\s*=/.test(stamp.sql), 'and must never be given a score of any kind');
  });

  it('writes NOTHING — not even epss_checked_at — when the fetch fails entirely', async () => {
    // Stamping "checked" after a failed download would assert "we looked and
    // there is no score". That is the failed-read-as-a-fact bug.
    const pool = stubPool([{ cve_id: 'CVE-2022-0778', epss_score: 0.5 }]);
    const result = await withStubbedFetch(
      async () => {
        const err = new Error('connect ETIMEDOUT');
        throw err;
      },
      (Feed) => Feed.fetchAndUpsertEpssScores(pool)
    );
    assert.equal(writeStatements(pool).length, 0, 'no write statement may reach the database');
    assert.equal(result.updated, 0);
    assert.ok(result.errors.length >= 2, 'and both the bulk and the fallback failure must be reported');
  });

  it('falls back to the per-CVE API when the bulk response is not the score file', async () => {
    // An HTTP 200 that is not gzip is an interstitial/proxy page. Saying so is
    // a different and true statement from "the CSV was malformed" — the
    // FortiGuard lesson, where a confident wrong reason cost three weeks.
    const pool = stubPool([{ cve_id: 'CVE-2022-0778', epss_score: null }]);
    const seen = [];
    const result = await withStubbedFetch(
      async (url) => {
        seen.push(String(url));
        if (String(url).includes('epss_scores-current')) {
          return { ok: true, status: 200, arrayBuffer: async () => Buffer.from('<html>Just a moment</html>') };
        }
        return { ok: true, status: 200, json: async () => REAL_API_ENVELOPE };
      },
      (Feed) => Feed.fetchAndUpsertEpssScores(pool)
    );
    assert.equal(result.summary.source, 'api');
    assert.equal(result.summary.matched, 1);
    assert.ok(seen.some((u) => u.includes('api.first.org')));
    assert.ok(
      result.errors.some((e) => /not gzip/i.test(e.message)),
      'the reason for falling back must be recorded so the run logs as partial'
    );
    // ⛔ The API path cannot know how many EPSS records matched nothing — it
    // only ever sees the ids it asked about. Reporting 0 would be fabricated.
    assert.equal(result.summary.feed_records, null);
    assert.equal(result.summary.feed_records_unmatched, null);
  });

  it('refuses to store a score it cannot date', async () => {
    const dateless = ['cve,epss,percentile', 'CVE-2022-0778,0.73188,0.99423', ''].join('\n');
    const pool = stubPool([{ cve_id: 'CVE-2022-0778', epss_score: null }]);
    const result = await withStubbedFetch(
      async (url) => {
        if (String(url).includes('epss_scores-current')) return gzipResponse(dateless);
        throw new Error('api unreachable in this test');
      },
      (Feed) => Feed.fetchAndUpsertEpssScores(pool)
    );
    assert.equal(writeStatements(pool).length, 0);
    assert.ok(result.errors.some((e) => /score_date/i.test(e.message)));
  });

  it('does not touch the CVE priority tree', async () => {
    // CLAUDE.md: the priority decision tree may only change after CLAUDE.md
    // itself is changed. This feed stores and exposes EPSS; it does not band.
    const src = require('node:fs').readFileSync(require.resolve('../lib/feeds/epss'), 'utf8');
    // Only real query literals — a backtick span inside a prose comment is not
    // a statement (the file's own comments name the tree in order to disclaim it).
    const sql = (src.match(/`[^`]*`/g) || []).filter((lit) =>
      /\b(SELECT|INSERT INTO|UPDATE|DELETE FROM)\b/.test(lit)
    );
    assert.ok(sql.length >= 2, 'the query literals must actually have been found');
    for (const lit of sql) {
      assert.ok(!/priority_band/i.test(lit), 'EPSS must not write priority_band');
      assert.ok(!/device_cve_assessments/i.test(lit), 'EPSS must not touch assessments');
    }
  });
});

// ── Staleness: an old score must never read as a current one ────────────────

describe('epssFreshness', () => {
  const now = new Date('2026-09-10T00:00:00Z');

  it('separates "never checked" from "checked, no score" from a real zero', () => {
    assert.equal(E.epssFreshness({ epss_score: null, epss_checked_at: null }, now), 'never_checked');
    assert.equal(
      E.epssFreshness({ epss_score: null, epss_checked_at: '2026-09-10T00:00:00Z' }, now),
      'no_score'
    );
    // ⛔ A genuine 0 is a SCORE. It must not fall into either "unmeasured" bucket.
    assert.equal(
      E.epssFreshness({ epss_score: 0, epss_score_date: '2026-09-10', epss_checked_at: now }, now),
      'fresh'
    );
  });

  it('calls an old score stale rather than current — EPSS republishes daily', () => {
    assert.equal(
      E.epssFreshness({ epss_score: 0.9, epss_score_date: '2026-09-09', epss_checked_at: now }, now),
      'fresh'
    );
    assert.equal(
      E.epssFreshness({ epss_score: 0.9, epss_score_date: '2026-05-01', epss_checked_at: now }, now),
      'stale'
    );
  });

  it('says unknown rather than defaulting to fresh when it cannot tell', () => {
    assert.equal(E.epssFreshness(null, now), 'unknown');
    assert.equal(E.epssFreshness({ epss_score: 0.9, epss_score_date: null }, now), 'unknown');
    assert.equal(E.epssFreshness({ epss_score: 0.9, epss_score_date: 'sometime' }, now), 'unknown');
  });

  it('accepts a Date, which is what pg returns for a DATE column', () => {
    assert.equal(
      E.epssFreshness(
        { epss_score: 0.9, epss_score_date: new Date('2026-09-09T00:00:00Z'), epss_checked_at: now },
        now
      ),
      'fresh'
    );
  });
});
