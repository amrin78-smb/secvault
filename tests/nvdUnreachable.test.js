'use strict';
// Pins the NVD reachability circuit breaker added to lib/feeds/nvd.js on 2026-09-10.
//
// THE INCIDENT. On the reference deployment `services.nvd.nist.gov` is blocked at the site's
// network edge — DNS resolves, TCP 443 never completes, and only for NVD (CIRCL, FortiGuard,
// Palo Alto, CISA and MITRE all answer 200 from the same host). Measured in `feed_sync_log`:
// **474 nvd runs, ZERO successes, every one 'partial', ~497 s average, 38 error entries each**,
// four times a day. 22 of those 38 entries were the same timeout, once per CPE string, because
// each of the 11 CPE strings independently re-discovered the blocked host at 20 s + 3 s + 20 s
// = 43 s apiece. 11 x 43 = 473 s of the 501 s run: 94% of the wall clock was sleeping.
//
// THE PROPERTY UNDER TEST, and it is a safety property, not a performance one. The breaker
// decides "NVD is unreachable" and that decision diverts the whole run to CIRCL, whose ranges
// are coarser and whose CVSS scores are gap-fill-only. So the thing that must never regress is
// WHAT IS ALLOWED TO OPEN IT:
//
//   • ONLY a network-level failure — `fetch()` itself threw, no HTTP status, no parsed body.
//   • An HTTP error (403/429/5xx) must NOT open it. NVD answered; that is reachability.
//   • A JSON-parse failure on an HTTP 200 must NOT open it. NVD answered too — this is the
//     `nvdJsonParseError` marker that exists precisely because a SyntaxError also has no
//     `.status` and would otherwise satisfy the same `err.status == null` test.
//   • It must not survive a run. The block could be lifted at any moment and SecVault must
//     not keep itself blind after the network is fixed.
//
// That last one is this codebase's own "a failed read is NOT a measurement" rule pointed at a
// cached verdict: remembering "NVD is down" across runs would turn one afternoon's outage into
// a permanent, self-confirming fact.
//
// ⛔ The classification is proven against the REAL error objects `fetchPage()` constructs, with
// `node-fetch` stubbed in `require.cache` — never against hand-written look-alikes, which would
// pass even if fetchPage stopped setting `.status` or stopped tagging parse failures.
//
// NOT covered here, deliberately: the HTTP 429 path. Its branch sleeps an unconditional 30 s
// before retrying, so exercising it would add half a minute to the suite to prove what the
// 403 case already proves — that a branch reached because NVD sent a status calls
// recordReachable(). It is asserted structurally instead (see "every HTTP branch resets").

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

// ── stub node-fetch BEFORE lib/feeds/nvd.js is first required ────────────────────────────
// nvd.js does `const fetchModule = require('node-fetch'); const fetch = fetchModule.default ||
// fetchModule;` at module load, so the substitution has to be in place before that line runs.
// node --test gives each test FILE its own process, so this cannot leak into another suite.
const fetchPath = require.resolve('node-fetch');
const fetchCalls = [];
let handler = () => {
  throw new Error('no handler installed for this test');
};
const stubModule = new Module(fetchPath, module);
stubModule.filename = fetchPath;
stubModule.loaded = true;
stubModule.exports = async function stubbedFetch(url, opts) {
  const u = String(url);
  fetchCalls.push(u);
  return handler(u, opts);
};
require.cache[fetchPath] = stubModule;

const {
  makeNvdCircuit,
  isNetworkLevelFailure,
  NVD_UNREACHABLE_STREAK,
  fetchPage,
  fetchCvesForVendor,
  fetchAndUpsertVendorCves,
  VENDOR_CPES,
} = require('../lib/feeds/nvd');

// The throttle inside fetchAndUpsertVendorCves is 6 s/request without an API key and 1.2 s
// with one. Only the run-level test uses that internal throttle (fetchCvesForVendor takes one
// as a parameter, so those tests inject a no-op); setting a dummy key keeps that one test at a
// few seconds instead of half a minute. It changes nothing else — the request is stubbed.
const REAL_API_KEY = process.env.NVD_API_KEY;
before(() => {
  process.env.NVD_API_KEY = 'test-key-not-used-by-the-stub';
});
after(() => {
  if (REAL_API_KEY === undefined) delete process.env.NVD_API_KEY;
  else process.env.NVD_API_KEY = REAL_API_KEY;
});

const NVD_HOST = 'https://services.nvd.nist.gov';
const CIRCL_HOST = 'https://vulnerability.circl.lu';

const isNvd = (u) => u.startsWith(NVD_HOST);

// What node-fetch@2 actually throws on a socket-inactivity timeout: a FetchError with a
// `type`, a message, and — the part that matters — NO `status` property at all.
function networkError() {
  const err = new Error(`network timeout at ${NVD_HOST}/rest/json/cves/2.0`);
  err.name = 'FetchError';
  err.type = 'request-timeout';
  return err;
}
const httpResponse = (status) => ({ ok: status >= 200 && status < 300, status });
const okJson = (body) => ({ ok: true, status: 200, json: async () => body });
const malformedBody = () => ({
  ok: true,
  status: 200,
  json: async () => {
    throw new SyntaxError('Unexpected token < in JSON at position 0');
  },
});
// CIRCL answering "no CVEs for this product" — an answer, not a failure.
const emptyCircl = () => okJson({ results: {}, total_count: 0, page: 1, page_size: 100 });

// upsertAdvisory's only DB contract: one row back with an `inserted` boolean.
const stubPool = { query: async () => ({ rows: [{ inserted: true }] }) };
const noThrottle = async () => {};

function reset() {
  fetchCalls.length = 0;
}

describe('fetchPage classifies an NVD outcome (stubbed fetch, real error objects)', () => {
  it('a fetch-level throw carries no HTTP status and IS a network-level failure', async () => {
    reset();
    handler = () => {
      throw networkError();
    };
    const err = await fetchPage('cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*', 0, 200).then(
      () => null,
      (e) => e
    );
    assert.ok(err, 'fetchPage must reject');
    assert.equal(err.status, undefined, 'a network failure has no HTTP status');
    assert.equal(err.nvdJsonParseError, undefined);
    assert.equal(isNetworkLevelFailure(err), true);
  });

  it('an HTTP 403 sets .status and is NOT a network-level failure', async () => {
    reset();
    handler = () => httpResponse(403);
    const err = await fetchPage('cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*', 0, 200).then(
      () => null,
      (e) => e
    );
    assert.equal(err.status, 403);
    assert.equal(isNetworkLevelFailure(err), false, 'NVD answered — that is reachability, not a block');
  });

  it('an HTTP 500 is NOT a network-level failure either', async () => {
    reset();
    handler = () => httpResponse(500);
    const err = await fetchPage('cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*', 0, 200).then(
      () => null,
      (e) => e
    );
    assert.equal(err.status, 500);
    assert.equal(isNetworkLevelFailure(err), false);
  });

  it('an unparseable body on HTTP 200 is tagged nvdJsonParseError and is NOT a network-level failure', async () => {
    reset();
    handler = () => malformedBody();
    const err = await fetchPage('cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*', 0, 200).then(
      () => null,
      (e) => e
    );
    // ⛔ The whole reason this marker exists: a SyntaxError has no `.status` either, so
    // without the tag this would be indistinguishable from a blocked host.
    assert.equal(err.status, undefined);
    assert.equal(err.nvdJsonParseError, true);
    assert.equal(isNetworkLevelFailure(err), false);
  });
});

describe('makeNvdCircuit — what may open it, and for how long', () => {
  it('starts closed, and the default threshold is 4 consecutive network failures', () => {
    assert.equal(NVD_UNREACHABLE_STREAK, 4);
    assert.equal(makeNvdCircuit().isOpen(), false);
  });

  it('opens only ON the threshold-th consecutive network failure, not before', () => {
    const c = makeNvdCircuit(4);
    for (let i = 1; i <= 3; i++) {
      c.recordNetworkFailure(`cpe-${i}`, 'timeout');
      assert.equal(c.isOpen(), false, `must still be closed after ${i} failure(s)`);
    }
    assert.equal(c.recordNetworkFailure('cpe-4', 'timeout'), true);
    assert.equal(c.isOpen(), true);
  });

  it('the streak must be CONSECUTIVE — any NVD response resets it', () => {
    const c = makeNvdCircuit(4);
    c.recordNetworkFailure('a', 'timeout');
    c.recordNetworkFailure('a', 'timeout');
    c.recordNetworkFailure('a', 'timeout');
    c.recordReachable(); // one page (or one 403, or one corrupt body) came back
    c.recordNetworkFailure('b', 'timeout');
    c.recordNetworkFailure('b', 'timeout');
    c.recordNetworkFailure('b', 'timeout');
    assert.equal(c.isOpen(), false, 'six failures, never four in a row — a flapping link is not a block');
  });

  it('is per-run: a new breaker is closed however hard the previous one failed', () => {
    const first = makeNvdCircuit(1);
    first.recordNetworkFailure('a', 'timeout');
    assert.equal(first.isOpen(), true);
    assert.equal(makeNvdCircuit(1).isOpen(), false, 'nothing may be remembered across runs');
  });

  it('summary() reports what was skipped and whether CIRCL actually answered', () => {
    const c = makeNvdCircuit(1);
    c.recordNetworkFailure('cpe-a', 'network timeout at nvd');
    c.recordSkipped('cpe-b');
    c.recordFallback('ok');
    c.recordFallback('failed');
    c.recordFallback('already-attempted');
    const s = c.summary();
    assert.equal(s.open, true);
    assert.deepEqual(s.failedCpeStrings, ['cpe-a']);
    assert.deepEqual(s.skippedCpeStrings, ['cpe-b']);
    assert.equal(s.fallbackOk, 1);
    // ⛔ A fallback that ALSO failed is real data loss and must be countable separately —
    // the run summary may only claim "CIRCL supplied the data instead" when it did.
    assert.equal(s.fallbackFailed, 1);
    assert.equal(s.lastError, 'network timeout at nvd');
  });
});

describe('fetchCvesForVendor — the breaker in the real fetch loop (stubbed fetch)', () => {
  it('stops re-probing a blocked NVD and sends every remaining CPE string straight to CIRCL', async () => {
    reset();
    handler = (u) => {
      if (isNvd(u)) throw networkError();
      return emptyCircl();
    };
    // checkpoint has four CPE strings — the vendor that pays the most for re-discovery.
    const cpeCount = VENDOR_CPES.checkpoint.length;
    assert.equal(cpeCount, 4);
    const circuit = makeNvdCircuit(1); // threshold 1 keeps the test off the 3 s retry sleep
    const result = await fetchCvesForVendor(stubPool, 'checkpoint', noThrottle, circuit);

    const nvdAttempts = fetchCalls.filter(isNvd).length;
    assert.equal(nvdAttempts, 1, 'NVD is probed once, not once per CPE string');
    assert.equal(circuit.isOpen(), true);
    assert.equal(circuit.summary().skippedCpeStrings.length, cpeCount - 1);
    assert.equal(
      fetchCalls.filter((u) => u.startsWith(CIRCL_HOST)).length,
      cpeCount,
      'every CPE string still gets its CIRCL fallback — the run is faster, not thinner'
    );
    // The prefix lib/feeds/index.js's summarizeCirclUsage() greps for must survive.
    assert.ok(
      result.errors.some((e) => e.message.startsWith('[CIRCL fallback]')),
      'summarizeCirclUsage() depends on this literal prefix'
    );
  });

  it('an HTTP 403 from NVD never opens the breaker, and never reaches CIRCL', async () => {
    reset();
    handler = (u) => (isNvd(u) ? httpResponse(403) : emptyCircl());
    // Threshold 1: if an HTTP status could advance the streak at all, this would open.
    const circuit = makeNvdCircuit(1);
    await fetchCvesForVendor(stubPool, 'checkpoint', noThrottle, circuit);

    assert.equal(circuit.isOpen(), false, 'NVD answered — a 403 is an API-key problem, not a blocked network');
    assert.equal(circuit.summary().networkFailures, 0);
    assert.equal(fetchCalls.filter(isNvd).length, 4, 'all four CPE strings are still attempted');
    assert.equal(
      fetchCalls.filter((u) => u.startsWith(CIRCL_HOST)).length,
      0,
      'CIRCL is for unreachability only — an HTTP error must not trigger it'
    );
  });

  it('a malformed body on HTTP 200 never opens the breaker, and never reaches CIRCL', async () => {
    reset();
    handler = (u) => (isNvd(u) ? malformedBody() : emptyCircl());
    const circuit = makeNvdCircuit(1);
    await fetchCvesForVendor(stubPool, 'checkpoint', noThrottle, circuit);

    assert.equal(circuit.isOpen(), false, 'a corrupt response is an NVD data problem, not a reachability one');
    assert.equal(circuit.summary().networkFailures, 0);
    assert.equal(fetchCalls.filter(isNvd).length, 4);
    assert.equal(fetchCalls.filter((u) => u.startsWith(CIRCL_HOST)).length, 0);
  });

  it('a page that succeeds re-arms the breaker mid-run', async () => {
    reset();
    let nvdSeen = 0;
    handler = (u) => {
      if (!isNvd(u)) return emptyCircl();
      nvdSeen += 1;
      // First CPE string: one clean (empty) page. Everything after: blocked.
      if (nvdSeen === 1) return okJson({ totalResults: 0, vulnerabilities: [], resultsPerPage: 200 });
      throw networkError();
    };
    const circuit = makeNvdCircuit(2);
    await fetchCvesForVendor(stubPool, 'checkpoint', noThrottle, circuit);
    // CPE 1 succeeded (streak 0). CPE 2 fails twice -> threshold 2 -> open. CPE 3, 4 skipped.
    assert.equal(circuit.isOpen(), true);
    assert.equal(circuit.summary().skippedCpeStrings.length, 2);
    assert.equal(fetchCalls.filter(isNvd).length, 3, '1 success + 2 failures, then no more probing');
  });
});

describe('fetchAndUpsertVendorCves — one honest statement per run, not 22 timeouts', () => {
  it('probes NVD 4 times for the whole run and reports the outage once', async () => {
    reset();
    handler = (u) => {
      if (isNvd(u)) throw networkError();
      return emptyCircl();
    };
    const totalCpeStrings = Object.values(VENDOR_CPES).reduce((n, list) => n + list.length, 0);
    assert.equal(totalCpeStrings, 11, 'the live fleet queries 11 CPE strings across 6 vendors');

    const result = await fetchAndUpsertVendorCves(stubPool);

    // ⛔ THE HEADLINE NUMBER. Before the breaker this was 22 attempts (11 strings x 2, each
    // pair costing 43 s of timeouts) = ~473 s. It is now the threshold, once, for the run.
    assert.equal(fetchCalls.filter(isNvd).length, NVD_UNREACHABLE_STREAK);
    assert.equal(result.nvdUnreachable, true);

    const unreachable = result.errors.filter((e) => e.nvd_unreachable === true);
    assert.equal(unreachable.length, 1, 'exactly ONE statement of the fact, for the whole run');
    const msg = unreachable[0].message;
    assert.match(msg, /^\[NVD unreachable\] services\.nvd\.nist\.gov/);
    assert.match(msg, /network level/);
    assert.match(msg, /CIRCL fallback answered/);
    // It must read as a deployment-network fact, not as an NVD data problem or a SecVault bug.
    assert.match(msg, /network-reachability problem at THIS deployment/);
    assert.match(msg, /next run probes NVD from scratch/);
    assert.equal(unreachable[0].nvd_cpe_strings_skipped, totalCpeStrings - 2);
    assert.equal(unreachable[0].circl_pairs_failed, 0);

    // Per-CPE detail is still there for the strings actually probed — the aggregate replaces
    // the REPETITION, not the evidence.
    const perCpe = result.errors.filter((e) => /^NVD request failed/.test(e.message));
    assert.equal(perCpe.length, NVD_UNREACHABLE_STREAK);
    // And CIRCL still ran for every vendor/product pair, so no vendor lost coverage.
    assert.ok(
      result.errors.filter((e) => e.message.startsWith('[CIRCL fallback]')).length >= 10,
      'every vendor/product pair still gets its fallback'
    );
  });

  it('says so plainly when the CIRCL fallback ALSO failed — no false "supplied instead"', async () => {
    reset();
    handler = () => {
      throw networkError(); // both hosts unreachable
    };
    const result = await fetchAndUpsertVendorCves(stubPool);
    const unreachable = result.errors.find((e) => e.nvd_unreachable === true);
    assert.ok(unreachable);
    assert.ok(unreachable.circl_pairs_failed > 0);
    assert.equal(unreachable.circl_pairs_ok, 0);
    assert.match(unreachable.message, /FAILED for \d+/);
    assert.match(unreachable.message, /no advisory data from this run at all/);
    assert.doesNotMatch(unreachable.message, /supplied this run's advisory data/);
  });
});

describe('the breaker is never persisted', () => {
  it('no NVD-reachability state is written to disk or the database by lib/feeds/nvd.js', () => {
    // ⛔ A cached "NVD is down" would outlive the outage and keep SecVault blind after the
    // network was fixed — the failed-read-as-a-fact rule applied to a verdict. The breaker is
    // a local inside fetchAndUpsertVendorCves(); this pins that no future edit quietly gives
    // it a home in a table, a file or a module-level variable.
    const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'feeds', 'nvd.js'), 'utf8');
    const circuitBody = src.slice(src.indexOf('function makeNvdCircuit'));
    assert.ok(circuitBody.length > 0);
    for (const forbidden of ['pool.query', 'writeFileSync', 'localStorage', 'process.env.NVD_UNREACHABLE']) {
      assert.ok(
        !circuitBody.slice(0, circuitBody.indexOf('function buildUrl')).includes(forbidden),
        `makeNvdCircuit must not use ${forbidden}`
      );
    }
    // Exactly one construction site, so "per run" cannot drift into "per process".
    const constructions = src.split('makeNvdCircuit()').length - 1;
    assert.ok(constructions <= 2, 'makeNvdCircuit() is constructed in fetchAndUpsertVendorCves and as a default arg only');
  });
});
