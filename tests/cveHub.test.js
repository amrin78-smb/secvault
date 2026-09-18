// tests/cveHub.test.js
//
// The central CVE feed consumer. Every case here is one of the five rules the
// collision report settled, plus the two that must be IMPOSSIBLE rather than
// merely unreached: a degrade, and a re-attribution.
//
// ⛔ The cases that matter most are the "we could not measure this" ones, per
// tests/README.md: an empty affected_version_ranges means BOTH "not affected"
// and "no range could be extracted", and the whole consumer turns on keeping
// those apart.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  hasRanges, hubIsBetter, applyFeed, FEED_PUBLIC_KEY_SPKI_B64,
} = require('../lib/feeds/cveHub');

const RANGE = [{ min: '1.0', max: '2.0', exclude_fixed: false, vulnerable: true }];

// ── hasRanges ───────────────────────────────────────────────────────────────

test('hasRanges: only a non-empty array counts', () => {
  assert.equal(hasRanges(RANGE), true);
  assert.equal(hasRanges([]), false, 'an empty array is NOT a measurement');
  assert.equal(hasRanges(null), false);
  assert.equal(hasRanges(undefined), false);
  assert.equal(hasRanges({}), false, 'an object is not a range list');
  assert.equal(hasRanges('1.0'), false);
});

// ── hubIsBetter — rules 2 and 3 ─────────────────────────────────────────────

test('hubIsBetter: repairs a blank local row from a matched hub row', () => {
  assert.equal(
    hubIsBetter({ affected_version_ranges: [] }, { matchability: 'matched', affected_version_ranges: RANGE }),
    true
  );
  assert.equal(
    hubIsBetter({ affected_version_ranges: null }, { matchability: 'matched', affected_version_ranges: RANGE }),
    true
  );
});

test('hubIsBetter: REFUSES to overwrite real local ranges — rule 3', () => {
  assert.equal(
    hubIsBetter(
      { affected_version_ranges: RANGE },
      { matchability: 'matched', affected_version_ranges: [] }
    ),
    false,
    'a blank hub row must never replace real local ranges'
  );
  assert.equal(
    hubIsBetter(
      { affected_version_ranges: RANGE },
      { matchability: 'matched', affected_version_ranges: RANGE }
    ),
    false,
    'nothing to gain, so nothing is written'
  );
});

test('hubIsBetter: an unmatchable hub row never wins, even carrying ranges', () => {
  // ⛔ THE CASE THAT LOOKS FINE AND IS NOT. An 'unmatchable' record means the
  // extraction FAILED; any array on it is not a measurement. Deciding on array
  // length alone would import a known-bad extraction over a known-good gap.
  assert.equal(
    hubIsBetter(
      { affected_version_ranges: [] },
      { matchability: 'unmatchable', affected_version_ranges: RANGE }
    ),
    false
  );
  assert.equal(
    hubIsBetter(
      { affected_version_ranges: [] },
      { matchability: 'other_product', affected_version_ranges: RANGE }
    ),
    false
  );
  assert.equal(
    hubIsBetter({ affected_version_ranges: [] }, { matchability: null, affected_version_ranges: RANGE }),
    false,
    'a missing matchability fails CLOSED'
  );
});

// ── applyFeed — against a stub pool ─────────────────────────────────────────

function stubPool(existingRows) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      if (/SELECT cve_id, vendor/.test(sql)) return { rows: existingRows };
      return { rows: [], rowCount: 1 };
    },
  };
}

const feedOf = (advisories) => ({ feed_version: '2026-09-18.1', advisories });

test('applyFeed: inserts a CVE we do not have — rule 1', async () => {
  const pool = stubPool([]);
  const stats = await applyFeed(pool, feedOf([
    { cve_id: 'CVE-2024-1', vendor: 'fortinet', matchability: 'matched', affected_version_ranges: RANGE },
  ]));
  assert.equal(stats.inserted, 1);
  assert.equal(stats.repaired, 0);
  const ins = pool.calls.find((c) => /INSERT INTO advisories/.test(c.sql));
  assert.ok(ins, 'an INSERT was issued');
  assert.match(ins.sql, /ON CONFLICT \(cve_id\) DO NOTHING/);
});

test('applyFeed: repairs a blank local row — rule 2', async () => {
  const pool = stubPool([
    { cve_id: 'CVE-2024-2', vendor: 'cisco_asa', affected_version_ranges: [], matchability: 'unmatchable' },
  ]);
  const stats = await applyFeed(pool, feedOf([
    { cve_id: 'CVE-2024-2', vendor: 'cisco_asa', matchability: 'matched', affected_version_ranges: RANGE },
  ]));
  assert.equal(stats.repaired, 1);
  assert.equal(stats.inserted, 0);
  const upd = pool.calls.find((c) => /UPDATE advisories/.test(c.sql));
  assert.ok(upd, 'an UPDATE was issued');
});

test('applyFeed: the repair UPDATE re-states rule 3 in SQL, not just in JS', async () => {
  // ⛔ THE GUARD IS DOUBLED ON PURPOSE. The JS predicate already decided this,
  // but overwriting real ranges is the one outcome that must be impossible
  // rather than merely unreached — the same doubling config retention uses for
  // its delete protections. If the JS check is ever "simplified" away, the
  // statement still cannot do damage.
  const pool = stubPool([
    { cve_id: 'CVE-2024-3', vendor: 'fortinet', affected_version_ranges: [], matchability: 'unmatchable' },
  ]);
  await applyFeed(pool, feedOf([
    { cve_id: 'CVE-2024-3', vendor: 'fortinet', matchability: 'matched', affected_version_ranges: RANGE },
  ]));
  const upd = pool.calls.find((c) => /UPDATE advisories/.test(c.sql));
  assert.match(
    upd.sql,
    /affected_version_ranges IS NULL[\s\S]*jsonb_array_length\(affected_version_ranges\) = 0/,
    'the UPDATE must refuse to touch a row that already has ranges'
  );
  assert.match(upd.sql, /AND vendor = \$5/, 'and must be vendor-scoped');
});

test('applyFeed: REFUSES a degrade and counts it — rule 3', async () => {
  const pool = stubPool([
    { cve_id: 'CVE-2024-4', vendor: 'paloalto', affected_version_ranges: RANGE, matchability: 'matched' },
  ]);
  const stats = await applyFeed(pool, feedOf([
    { cve_id: 'CVE-2024-4', vendor: 'paloalto', matchability: 'matched', affected_version_ranges: [] },
  ]));
  assert.equal(stats.degradeRefused, 1);
  assert.equal(stats.repaired, 0);
  assert.equal(
    pool.calls.filter((c) => /UPDATE advisories/.test(c.sql)).length, 0,
    'no statement may be issued at all for a degrade'
  );
});

test('applyFeed: never changes an existing vendor — rule 4', async () => {
  const pool = stubPool([
    { cve_id: 'CVE-2022-0778', vendor: 'paloalto', affected_version_ranges: [], matchability: 'unmatchable' },
  ]);
  const stats = await applyFeed(pool, feedOf([
    { cve_id: 'CVE-2022-0778', vendor: 'fortinet', matchability: 'matched', affected_version_ranges: RANGE },
  ]));
  assert.equal(stats.vendorConflict, 1);
  assert.equal(stats.repaired, 0);
  assert.equal(stats.inserted, 0);
  assert.equal(
    pool.calls.filter((c) => /INSERT INTO|UPDATE advisories/.test(c.sql)).length, 0,
    'a row held under another vendor is not touched in either direction'
  );
});

test('applyFeed: a multi-vendor CVE keeps the vendor we already hold — rule 5', async () => {
  const pool = stubPool([
    { cve_id: 'CVE-2004-0112', vendor: 'forcepoint', affected_version_ranges: [], matchability: 'unmatchable' },
  ]);
  const stats = await applyFeed(pool, feedOf([
    { cve_id: 'CVE-2004-0112', vendor: 'checkpoint', matchability: 'matched', affected_version_ranges: RANGE },
    { cve_id: 'CVE-2004-0112', vendor: 'forcepoint', matchability: 'matched', affected_version_ranges: RANGE },
  ]));
  assert.equal(stats.multiVendorCollapsed, 1);
  assert.equal(stats.repaired, 1, 'the forcepoint copy was chosen, so the repair applies');
  assert.equal(stats.vendorConflict, 0, 'picking the matching vendor avoids a false conflict');
});

test('applyFeed: a multi-vendor CVE we hold under NEITHER vendor picks deterministically', async () => {
  const run = async () => {
    const pool = stubPool([]);
    await applyFeed(pool, feedOf([
      { cve_id: 'CVE-2004-0112', vendor: 'forcepoint', matchability: 'matched', affected_version_ranges: RANGE },
      { cve_id: 'CVE-2004-0112', vendor: 'checkpoint', matchability: 'matched', affected_version_ranges: RANGE },
    ]));
    return pool.calls.find((c) => /INSERT INTO advisories/.test(c.sql)).params[1];
  };
  // Alphabetically first, so the choice cannot depend on row order.
  assert.equal(await run(), 'checkpoint');
  assert.equal(await run(), 'checkpoint', 'and is stable across runs');
});

test('applyFeed: an error on one CVE does not abandon the rest', async () => {
  let n = 0;
  const pool = {
    async query(sql) {
      if (/SELECT cve_id, vendor/.test(sql)) return { rows: [] };
      n += 1;
      if (n === 1) throw new Error('transient write failure');
      return { rows: [], rowCount: 1 };
    },
  };
  const stats = await applyFeed(pool, feedOf([
    { cve_id: 'CVE-2024-A', vendor: 'fortinet', matchability: 'matched', affected_version_ranges: RANGE },
    { cve_id: 'CVE-2024-B', vendor: 'fortinet', matchability: 'matched', affected_version_ranges: RANGE },
  ]));
  assert.equal(stats.errors.length, 1);
  assert.equal(stats.errors[0].cve_id, 'CVE-2024-A');
  assert.equal(stats.inserted, 1, 'the second advisory still landed');
});

test('applyFeed: rows with no cve_id or no vendor are skipped, never guessed', async () => {
  const pool = stubPool([]);
  const stats = await applyFeed(pool, feedOf([
    { cve_id: null, vendor: 'fortinet', matchability: 'matched', affected_version_ranges: RANGE },
    { cve_id: 'CVE-2024-C', vendor: null, matchability: 'matched', affected_version_ranges: RANGE },
    { cve_id: 'CVE-2024-D', vendor: 'fortinet', matchability: 'matched', affected_version_ranges: RANGE },
  ]));
  assert.equal(stats.inserted, 1);
});

// ── source-shape guards ─────────────────────────────────────────────────────

function hubSource() {
  return fs.readFileSync(path.join(__dirname, '..', 'lib', 'feeds', 'cveHub.js'), 'utf8')
    .replace(/\r\n/g, '\n');
}

test('verification FAILS CLOSED — an unverified feed is never applied', () => {
  const src = hubSource();
  assert.match(
    src, /signature did NOT verify — refusing to import/,
    'a failed signature must throw, not warn'
  );
  assert.match(src, /carried no X-Feed-Signature — refusing to import/);
  assert.match(src, /sha256 mismatch/);
  // The verify must run against the received bytes, before JSON.parse.
  const verifyAt = src.indexOf('crypto.verify(');
  const parseAt = src.indexOf('JSON.parse(body');
  assert.ok(verifyAt > 0 && parseAt > verifyAt, 'bytes are verified BEFORE they are parsed');
});

test('a verified-but-EMPTY feed is refused, not treated as "nothing to do"', () => {
  assert.match(hubSource(), /contained 0 advisories — refusing/);
});

test('the public key is PINNED in source, not fetched at verification time', () => {
  const src = hubSource();
  assert.match(FEED_PUBLIC_KEY_SPKI_B64, /^[A-Za-z0-9+/=]{40,}$/, 'a real spki-der base64 key');
  assert.doesNotMatch(
    src, /fetch\([^)]*pubkey/,
    'fetching the key from the same host as the feed would verify nothing'
  );
});

test('gzip is requested explicitly — node does not negotiate it', () => {
  // The feed is 3.3 MB raw and 173 KB gzipped, measured. Omitting the header
  // costs a 20x download on a link this product often shares with syslog.
  assert.match(hubSource(), /'accept-encoding':\s*'gzip'/);
});

test('an unset licence key is notRun, never an error', () => {
  const src = hubSource();
  assert.match(src, /notRun: true/);
  assert.match(src, /CVE_HUB_LICENSE_KEY is not set/);
});
