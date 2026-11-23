'use strict';
// Pins lib/feeds/osHub.js — the OS branch lifecycle feed consumer.
//
// ⛔ IT IS DRIVEN BY THE REAL PUBLISHED FEED, THROUGH THE REAL HTTP PATH, with
// `global.fetch` stubbed to serve the exact bytes and the exact signature the
// hub published (tests/fixtures/osFeedSigned.js). So "PAN-OS 11.1 comes back
// with support_end_date 2027-05-03" is asserted END TO END — through the
// transport, through the pinned key, through the parse, through the apply — and
// not against a fixture this test wrote to suit itself.
//
// ⛔ AND THE FAILURE BRANCHES ARE FORCED, because this repo's own record is full
// of guards verified by reading that then could not fire. A tampered body must
// REFUSE; an unreachable hub must leave the stored corpus untouched; a corpus
// nobody could read must change nothing at all.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const osHub = require('../lib/feeds/osHub');
const fx = require('./fixtures/osFeedSigned');

// ── stubs ────────────────────────────────────────────────────────────────

function stubPool(responses = {}) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      if (/^\s*INSERT INTO os_branch_cycles/.test(sql)) {
        return responses.insert || { rowCount: (params && params[0] ? params[0].length : 0), rows: [] };
      }
      if (/^\s*DELETE FROM os_branch_cycles/.test(sql)) {
        return responses.delete || { rowCount: 0, rows: [] };
      }
      return { rowCount: 0, rows: [] };
    },
  };
}

function headerBag(h) {
  const lower = Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]));
  return { get: (k) => (k.toLowerCase() in lower ? lower[k.toLowerCase()] : null) };
}

/** Serve a body + headers as the hub would. */
function stubFetch({
  body = fx.BODY, signature = fx.SIGNATURE_B64, sha = fx.SHA256, checkedAt = null,
  ok = true, status = 200, throws = null,
} = {}) {
  const seen = [];
  global.fetch = async (url, opts) => {
    seen.push({ url, headers: (opts && opts.headers) || {} });
    if (throws) throw throws;
    return {
      ok,
      status,
      headers: headerBag({
        'x-feed-signature': signature === null ? undefined : signature,
        'x-feed-sha256': sha === null ? undefined : sha,
        'x-feed-checked-at': checkedAt === null ? undefined : checkedAt,
      }),
      async arrayBuffer() {
        return body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength);
      },
    };
  };
  return seen;
}

const realFetch = global.fetch;
let prevKey;
beforeEach(() => {
  prevKey = process.env.CVE_HUB_LICENSE_KEY;
  process.env.CVE_HUB_LICENSE_KEY = 'test-key';
});
afterEach(() => {
  global.fetch = realFetch;
  if (prevKey === undefined) delete process.env.CVE_HUB_LICENSE_KEY;
  else process.env.CVE_HUB_LICENSE_KEY = prevKey;
});

// ── the whole path, against the real feed ─────────────────────────────────

describe('END TO END against the real published feed', () => {
  it('⛔ verifies, parses, and PAN-OS 11.1 arrives with the published dates', async () => {
    stubFetch();
    const { feed, sha256 } = await osHub.fetchSignedOsFeed('test-key');
    assert.equal(sha256, fx.SHA256);
    assert.equal(feed.feed_version, fx.FEED_VERSION);
    assert.equal(feed.cycles.length, fx.ROW_COUNT);

    const row = feed.cycles.find((c) => c.product === 'PAN-OS' && c.cycle === '11.1');
    assert.ok(row, 'PAN-OS 11.1 must survive the round trip');
    assert.equal(row.support_end_date, '2027-05-03');
    assert.equal(row.extended_end_date, '2027-08-31');
    assert.equal(row.confidence, 'high');
  });

  it('sends the licence key and asks for gzip, to the os-feed route', async () => {
    const seen = stubFetch();
    await osHub.fetchSignedOsFeed('test-key');
    assert.equal(seen.length, 1);
    assert.match(seen[0].url, /\/api\/v1\/os-feed$/);
    assert.equal(seen[0].headers['x-license-key'], 'test-key');
    // node's fetch does not negotiate compression on its own.
    assert.equal(seen[0].headers['accept-encoding'], 'gzip');
  });

  it('⛔ applies the whole real corpus and stores every cycle', async () => {
    stubFetch();
    const pool = stubPool();
    const result = await osHub.fetchAndUpsertOsCycles(pool);
    assert.equal(result.received, fx.ROW_COUNT);
    assert.equal(result.stored, fx.ROW_COUNT);
    assert.deepEqual(result.refused, []);
    assert.equal(result.feed_version, fx.FEED_VERSION);
    // The live corpus's three products, by count.
    const byProduct = result.byProduct;
    assert.equal(byProduct['Palo Alto PAN-OS'], 27);
    assert.equal(byProduct['Fortinet FortiOS'], 8);
    assert.equal(byProduct['Cisco Cisco IOS-XE'], 19);
  });

  it('⛔ reports the cycles that can NEVER be matched rather than hiding them', async () => {
    stubFetch();
    const result = await osHub.fetchAndUpsertOsCycles(stubPool());
    // PAN-OS "9.0-XFR" and "9.0-xfr" are in the live corpus and branchOf can
    // return neither. Storing them is harmless; pretending they are reachable
    // is not.
    assert.equal(result.unmatchable, 2);
  });
});

describe('the failure branches, forced', () => {
  it('⛔ a TAMPERED body fails verification and nothing is written', async () => {
    const tampered = Buffer.from(fx.BODY);
    // Move PAN-OS 11.1's support date out by three years.
    const text = tampered.toString('utf8').replace('"2027-05-03"', '"2030-05-03"');
    assert.notEqual(text, tampered.toString('utf8'), 'the tamper must actually change the body');
    stubFetch({ body: Buffer.from(text, 'utf8'), sha: null });
    const pool = stubPool();
    await assert.rejects(
      () => osHub.fetchAndUpsertOsCycles(pool),
      /OS feed Ed25519 signature did NOT verify/
    );
    assert.equal(pool.calls.length, 0, 'not one statement may run against an unverified corpus');
  });

  it('⛔ an UNREACHABLE hub leaves the stored corpus intact', async () => {
    stubFetch({ throws: Object.assign(new Error('fetch failed'), { cause: 'ECONNREFUSED' }) });
    const pool = stubPool();
    await assert.rejects(() => osHub.fetchAndUpsertOsCycles(pool), /fetch failed/);
    assert.equal(pool.calls.length, 0, 'no INSERT and above all no DELETE');
  });

  it('a non-2xx response throws with the status attached, and writes nothing', async () => {
    stubFetch({ ok: false, status: 401 });
    const pool = stubPool();
    await assert.rejects(
      () => osHub.fetchAndUpsertOsCycles(pool),
      (err) => /OS branch hub responded HTTP 401/.test(err.message) && err.status === 401
    );
    assert.equal(pool.calls.length, 0);
  });

  it('⛔ a VERIFIED BUT EMPTY corpus is refused — it would be an instruction to delete everything', async () => {
    // applyOsFeed deletes rows absent from the feed, so a publisher bug
    // emitting zero cycles would be a correctly-signed instruction to empty the
    // table, reported as a clean success.
    const { body, signature } = signNewBody({ schema_version: 1, feed_version: 'x', row_count: 0, cycles: [] });
    stubFetch({ body, signature, sha: null });
    const pool = stubPool();
    await assert.rejects(() => osHub.fetchAndUpsertOsCycles(pool), /contained 0 cycles/);
    assert.equal(pool.calls.length, 0);
  });

  it('a body with no cycles ARRAY is refused', async () => {
    const { body, signature } = signNewBody({ schema_version: 1, feed_version: 'x' });
    stubFetch({ body, signature, sha: null });
    await assert.rejects(() => osHub.fetchAndUpsertOsCycles(stubPool()), /carried no cycles array/);
  });

  it('a verified body that is not JSON is refused with a distinct message', async () => {
    const { body, signature } = signRaw(Buffer.from('not json at all', 'utf8'));
    stubFetch({ body, signature, sha: null });
    await assert.rejects(() => osHub.fetchAndUpsertOsCycles(stubPool()), /verified but did not parse/);
  });

  it('⛔ NOT CONFIGURED is `notRun` with a reason, not a failure and not a silent skip', async () => {
    delete process.env.CVE_HUB_LICENSE_KEY;
    const pool = stubPool();
    const r = await osHub.fetchAndUpsertOsCycles(pool);
    assert.equal(r.notRun, true);
    assert.match(r.reason, /CVE_HUB_LICENSE_KEY is not set/);
    assert.deepEqual(r.errors, []);
    assert.equal(pool.calls.length, 0);
  });
});

// ── the apply rules ───────────────────────────────────────────────────────

const GOOD = {
  vendor: 'Palo Alto', product: 'PAN-OS', cycle: '11.1',
  release_date: '2023-11-03', support_end_date: '2027-05-03', extended_end_date: '2027-08-31',
  latest_version: null, lts: null, confidence: 'high', source: 'https://vendor', vendor_link: null,
};
const feedOf = (cycles) => ({
  schema_version: 1, feed_version: '2026-11-16.1', generated_at: '2026-11-16T04:41:34.396Z',
  row_count: cycles.length, cycles,
});

describe('applyOsFeed', () => {
  it('upserts in ONE round trip and then deletes what the feed no longer carries', async () => {
    const pool = stubPool({ delete: { rowCount: 3 } });
    const stats = await osHub.applyOsFeed(pool, feedOf([GOOD]));
    assert.equal(pool.calls.length, 2, 'one INSERT, one DELETE — never one per row');
    assert.match(pool.calls[0].sql, /INSERT INTO os_branch_cycles/);
    assert.match(pool.calls[0].sql, /ON CONFLICT \(vendor, product, cycle\) DO UPDATE/);
    assert.match(pool.calls[1].sql, /DELETE FROM os_branch_cycles/);
    assert.equal(stats.removed, 3);
  });

  it('⛔ the DELETE is scoped to the cycles the feed DID carry', async () => {
    const pool = stubPool();
    await osHub.applyOsFeed(pool, feedOf([GOOD]));
    const del = pool.calls[1];
    assert.deepEqual(del.params, [['Palo Alto'], ['PAN-OS'], ['11.1']]);
    assert.match(del.sql, /NOT IN/);
  });

  it('⛔ the feed_version is stored with every row, so a stale corpus is identifiable', async () => {
    const pool = stubPool();
    await osHub.applyOsFeed(pool, feedOf([GOOD]));
    assert.equal(pool.calls[0].params[11], '2026-11-16.1');
  });

  it('⛔ `lts` stays TRI-STATE — a missing flag is null, never false', async () => {
    const pool = stubPool();
    await osHub.applyOsFeed(pool, feedOf([
      { ...GOOD, cycle: '11.1', lts: null },
      { ...GOOD, cycle: '11.2', lts: undefined },
      { ...GOOD, cycle: '17.12', lts: true },
      { ...GOOD, cycle: '17.13', lts: false },
      { ...GOOD, cycle: '17.14', lts: 'yes' },
    ]));
    // Coercing null to false would assert "this is not a long-term-support
    // branch" from a field Palo Alto's table never publishes.
    assert.deepEqual(pool.calls[0].params[7], [null, null, true, false, null]);
  });

  it('⛔ an empty string is stored as NULL, not as an empty date', async () => {
    const pool = stubPool();
    await osHub.applyOsFeed(pool, feedOf([{ ...GOOD, extended_end_date: null, latest_version: '' }]));
    assert.equal(pool.calls[0].params[6][0], null, 'latest_version');
    assert.equal(pool.calls[0].params[5][0], null, 'extended_end_date');
  });

  it('⛔ a confidence the publisher invents is stored as the WEAKEST', async () => {
    const pool = stubPool();
    await osHub.applyOsFeed(pool, feedOf([{ ...GOOD, confidence: 'probably' }]));
    assert.equal(pool.calls[0].params[8][0], 'low');
  });
});

describe('applyOsFeed refusals', () => {
  const refusalOf = async (row) => {
    const pool = stubPool();
    const stats = await osHub.applyOsFeed(pool, feedOf([GOOD, row]));
    return { stats, pool };
  };

  it('⛔ a row with NEITHER date is refused — it tells a consumer nothing', async () => {
    const { stats } = await refusalOf({
      ...GOOD, cycle: '9.9', support_end_date: null, extended_end_date: null,
    });
    assert.equal(stats.refused.length, 1);
    assert.match(stats.refused[0].reason, /neither support_end_date nor extended_end_date/);
  });

  it('⛔ extended BEFORE standard is refused — the columns were read swapped', async () => {
    // Stored as-is this does not fail, it ANSWERS WRONG: branchState would read
    // a live branch as eol, or a dead one as extended_only.
    const { stats } = await refusalOf({
      ...GOOD, cycle: '9.8', support_end_date: '2027-05-03', extended_end_date: '2024-01-01',
    });
    assert.equal(stats.refused.length, 1);
    assert.match(stats.refused[0].reason, /columns likely swapped/);
  });

  it('a malformed date is refused and the value is NAMED', async () => {
    const { stats } = await refusalOf({ ...GOOD, cycle: '9.7', support_end_date: '03/05/2027' });
    assert.match(stats.refused[0].reason, /must be YYYY-MM-DD or null/);
    assert.match(stats.refused[0].reason, /03\/05\/2027/);
  });

  it('a cycle that is not major.minor is refused', async () => {
    const { stats } = await refusalOf({ ...GOOD, cycle: 'Gaia R81' });
    assert.match(stats.refused[0].reason, /is not major\.minor/);
  });

  it('⛔ a refused row is NOT stored, so its branch degrades to "unknown"', async () => {
    const { stats, pool } = await refusalOf({
      ...GOOD, cycle: '9.9', support_end_date: null, extended_end_date: null,
    });
    assert.equal(stats.stored, 1, 'only the good row');
    assert.deepEqual(pool.calls[0].params[2], ['11.1'], 'the refused cycle never reaches the INSERT');
    assert.deepEqual(pool.calls[1].params[2], ['11.1'], 'and is therefore deleted if it was held');
  });

  it('⛔ an ALL-REFUSED corpus THROWS and changes nothing', async () => {
    // Applying it would delete every row we hold on the strength of a
    // disagreement between two validators, with no vendor data having changed.
    const pool = stubPool();
    await assert.rejects(
      () => osHub.applyOsFeed(pool, feedOf([
        { ...GOOD, support_end_date: null, extended_end_date: null },
        { ...GOOD, cycle: 'nonsense' },
      ])),
      /NONE could be read/
    );
    assert.equal(pool.calls.length, 0);
  });

  it('a schema_version bump is WARNED about, not refused', async () => {
    const pool = stubPool();
    const stats = await osHub.applyOsFeed(pool, { ...feedOf([GOOD]), schema_version: 2 });
    assert.equal(stats.stored, 1, 'the corpus still applies');
    assert.equal(stats.errors.length, 1);
    assert.match(stats.errors[0].message, /schema_version 2 is not the expected 1/);
  });

  it('checkCycleRow accepts the whole real corpus', () => {
    const cycles = JSON.parse(fx.BODY.toString('utf8')).cycles;
    const bad = cycles.map((c) => osHub.checkCycleRow(c)).filter(Boolean);
    assert.deepEqual(bad, [], 'our validator must agree with the publisher\'s on live data');
  });
});

// ── freshness ─────────────────────────────────────────────────────────────

describe('feedFreshness — liveness, not freshness', () => {
  const now = Date.parse('2026-11-16T12:00:00Z');

  it('⛔ a NULL checked_at is `unknown`, which is this hub\'s KNOWN state today', async () => {
    const f = osHub.feedFreshness(null, now);
    assert.equal(f.state, 'unknown');
    assert.equal(f.checkedAt, null);
    assert.match(f.reason, /daily source watch has not yet had a first successful run/);
  });

  it('⛔ and `unknown` contributes NO error — a permanent amber chip nobody can clear', async () => {
    // The CVE feed treats an absent header as a fault because there it means an
    // old hub build. Here it is the present, expected state.
    const errs = osHub.syncErrors({ stats: { refused: [], errors: [] }, freshness: osHub.feedFreshness(null, now) });
    assert.deepEqual(errs, []);
  });

  it('⛔ but `unknown` is NOT read as healthy — it never claims freshness', () => {
    assert.notEqual(osHub.feedFreshness(null, now).state, 'fresh');
    assert.notEqual(osHub.feedFreshness('nonsense', now).state, 'fresh');
    assert.notEqual(osHub.feedFreshness('2026-11-16 06:00:00', now).state, 'fresh');
  });

  it('a recent stamp is fresh', () => {
    const f = osHub.feedFreshness('2026-11-16T06:00:00Z', now);
    assert.equal(f.state, 'fresh');
    assert.match(f.reason, /6h ago/);
  });

  it('⛔ once a stamp EXISTS, a watch that stopped is reported stale and DOES error', () => {
    const old = new Date(now - 9 * 86400000).toISOString();
    const f = osHub.feedFreshness(old, now);
    assert.equal(f.state, 'stale');
    assert.match(f.reason, /9 days ago/);
    const errs = osHub.syncErrors({ stats: { refused: [], errors: [] }, freshness: f });
    assert.equal(errs.length, 1);
    assert.match(errs[0].message, /\[OS branch feed stale\]/);
  });

  it('the threshold is 7 days — seven missed runs of a DAILY watch', () => {
    assert.equal(osHub.STALE_AFTER_MS, 7 * 24 * 60 * 60 * 1000);
    assert.equal(osHub.feedFreshness(new Date(now - 6.9 * 86400000).toISOString(), now).state, 'fresh');
    assert.equal(osHub.feedFreshness(new Date(now - 7.1 * 86400000).toISOString(), now).state, 'stale');
  });

  it('⛔ there is NO corpus-advance check, and that is a decision', async () => {
    // cveHub reports `not_advancing` after 14 days without a new feed_version,
    // because its corpus is machine-ingested hourly. THIS corpus is refreshed
    // by a person against vendor pages that change a few times a year, so the
    // same check would be permanently amber for a hub working exactly as
    // designed. The feed is three months old in this case and reports nothing.
    //
    // ⛔ RELATIVE TO THE REAL CLOCK, NEVER A LITERAL DATE. This read
    // `'2026-11-16T06:00:00Z'` and went RED on 2026-11-23 — the day it aged
    // past feedFreshness()'s own 7-day staleness threshold. The surrounding
    // pure-function tests pin BOTH ends (they pass `now` explicitly), but
    // fetchAndUpsertOsCycles() reads Date.now() internally, so a hardcoded
    // stamp here is a fixture with an expiry date. Same defect as commit
    // 9e8bb49; the assertion is about a STILL generated_at beside a HEALTHY
    // checked_at, and "healthy" has to mean "recent", not "2026-11-16".
    stubFetch({ checkedAt: new Date(Date.now() - 3600 * 1000).toISOString() });
    const r = await osHub.fetchAndUpsertOsCycles(stubPool());
    assert.equal(r.freshness, 'fresh');
    assert.deepEqual(r.errors, [], 'a still generated_at is the resting state here');
    assert.equal(r.generated_at, fx.GENERATED_AT, 'but it is still REPORTED');
  });
});

describe('syncErrors — the wiring, which is the part that goes untested', () => {
  it('⛔ EVERY contributor is consulted; dropping one must go red', () => {
    const errs = osHub.syncErrors({
      stats: {
        refused: [{ cycle: 'Palo Alto/PAN-OS/9.9', reason: 'neither date' }],
        errors: [{ cve_id: null, message: 'an apply-level problem' }],
      },
      freshness: { state: 'stale', reason: 'the hub last checked 9 days ago' },
    });
    const text = errs.map((e) => e.message).join(' | ');
    assert.match(text, /\[OS branch feed stale\]/, 'the freshness contributor');
    assert.match(text, /could not be read and were NOT stored/, 'the refusal contributor');
    assert.match(text, /an apply-level problem/, 'the apply-error contributor');
    assert.equal(errs.length, 3);
  });

  it('a refusal entry states the TRUE total and samples the list', () => {
    const refused = Array.from({ length: 20 }, (_, i) => ({ cycle: `c${i}`, reason: 'nope' }));
    const errs = osHub.syncErrors({ stats: { refused, errors: [] }, freshness: null });
    assert.match(errs[0].message, /20 cycle\(s\)/);
    assert.match(errs[0].message, /; …$/, 'the list is truncated, the count is not');
  });

  it('a clean run contributes nothing', () => {
    assert.deepEqual(osHub.syncErrors({ stats: { refused: [], errors: [] }, freshness: { state: 'fresh' } }), []);
    assert.deepEqual(osHub.syncErrors({}), []);
  });

  it('⛔ a refusal turns the run `partial`, so coverage cannot be lost quietly', async () => {
    // The orchestrator reads errors.length to decide the feed_sync_log status.
    const { body, signature } = signNewBody(feedOf([
      GOOD, { ...GOOD, cycle: '9.9', support_end_date: null, extended_end_date: null },
    ]));
    stubFetch({ body, signature, sha: null });
    const r = await osHub.fetchAndUpsertOsCycles(stubPool());
    assert.equal(r.refused.length, 1);
    assert.ok(r.errors.length > 0, 'a lost branch must reach feed_sync_log');
  });
});

// ── helpers that sign a body with a throwaway key ─────────────────────────
//
// ⛔ ONLY FOR SHAPES THE PUBLISHER DOES NOT PUBLISH (an empty corpus, a
// malformed row). The trust-anchor assertions all run against the REAL
// signature in the fixture — a self-minted key can only ever prove that node's
// crypto agrees with itself.
let throwaway;
function signRaw(body) {
  if (!throwaway) throwaway = crypto.generateKeyPairSync('ed25519');
  // ⛔ SET ON EVERY CALL, not only when the key is minted. The afterEach below
  // clears it after each test, so memoising the ASSIGNMENT alongside the key
  // left later tests verifying a throwaway signature against the PINNED key —
  // which failed for the right reason with the wrong message, and would have
  // read as these tests being wrong about the product.
  process.env.CVE_HUB_PUBLIC_KEY = throwaway.publicKey
    .export({ format: 'der', type: 'spki' }).toString('base64');
  return { body, signature: crypto.sign(null, body, throwaway.privateKey).toString('base64') };
}
function signNewBody(obj) {
  return signRaw(Buffer.from(JSON.stringify(obj, null, 2), 'utf8'));
}
afterEach(() => { delete process.env.CVE_HUB_PUBLIC_KEY; });
