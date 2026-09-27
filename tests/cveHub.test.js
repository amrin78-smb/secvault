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

// ── freshness / liveness ────────────────────────────────────────────────────
//
// ⛔ WITHOUT THIS, THE FEED THAT FIXED THE BLIND SPOT BECOMES ONE. A hub that
// stopped publishing would be invisible: the same feed_version fetched every six
// hours, signature verifying perfectly, nothing applied, `success` logged for
// ever — a green light over a corpus that stopped moving.

const { feedFreshness, freshnessErrors, STALE_AFTER_MS } = require('../lib/feeds/cveHub');
const NOW_MS = Date.parse('2026-09-18T12:00:00Z');
const hoursAgo = (h) => new Date(NOW_MS - h * 3600000).toISOString();

test('freshness: a recent ingest is fresh', () => {
  const f = feedFreshness(hoursAgo(2), NOW_MS);
  assert.equal(f.state, 'fresh');
  assert.equal(f.reason, '');
});

test('freshness: just inside and just outside the threshold', () => {
  assert.equal(feedFreshness(hoursAgo(23), NOW_MS).state, 'fresh');
  assert.equal(feedFreshness(hoursAgo(25), NOW_MS).state, 'stale');
  assert.equal(STALE_AFTER_MS, 24 * 3600000, 'the hub publishes 6-hourly; 24h is four missed runs');
});

test('freshness: a stale verdict NAMES the age and says the data is still valid', () => {
  const f = feedFreshness(hoursAgo(50), NOW_MS);
  assert.equal(f.state, 'stale');
  assert.match(f.reason, /50h ago/);
  assert.match(f.reason, /still valid/i, 'stale data is not wrong data, and the message must say so');
  assert.match(f.reason, /scheduled ingest/i, 'and must point at what to check');
});

test('freshness: MISSING checked_at is unknown, never fresh', () => {
  // ⛔ THE CASE THAT REGRESSES SILENTLY. An absent header is exactly what an
  // older hub build serves; reading it as healthy is a failed read recorded as
  // an affirmative value.
  for (const v of [null, undefined, '', '   ']) {
    const f = feedFreshness(v, NOW_MS);
    assert.equal(f.state, 'unknown', `${JSON.stringify(v)} must be unknown`);
    assert.notEqual(f.state, 'fresh');
    assert.match(f.reason, /cannot be established|no checked_at/i);
  }
});

test('freshness: an unparseable checked_at is unknown, never fresh', () => {
  const f = feedFreshness('yesterday-ish', NOW_MS);
  assert.equal(f.state, 'unknown');
  assert.match(f.reason, /unparseable/i);
});

test('freshness: a FUTURE checked_at is unknown, not fresh', () => {
  // ⛔ Clock disagreement makes the age meaningless; reporting it healthy would
  // hide the skew. Same call vpn_sessions makes on a negative duration.
  const f = feedFreshness(new Date(NOW_MS + 3 * 3600000).toISOString(), NOW_MS);
  assert.equal(f.state, 'unknown');
  assert.match(f.reason, /FUTURE/);
  assert.match(f.reason, /not a measurement/i);
});

test('freshness: small forward skew is tolerated rather than alarmed on', () => {
  assert.equal(feedFreshness(new Date(NOW_MS + 60000).toISOString(), NOW_MS).state, 'fresh');
});

test('freshnessErrors: a fresh verdict contributes nothing', () => {
  assert.deepEqual(freshnessErrors({ state: 'fresh', reason: '' }), []);
});

test('freshnessErrors: stale and unknown BOTH contribute an error', () => {
  // ⛔ Non-empty is what makes the sync report `partial` rather than `success`,
  // and therefore what makes a frozen hub visible at all.
  for (const state of ['stale', 'unknown']) {
    const errs = freshnessErrors({ state, reason: 'because reasons' });
    assert.equal(errs.length, 1, `${state} must contribute an error`);
    assert.equal(errs[0].cve_id, null);
    assert.match(errs[0].message, new RegExp(`central CVE feed ${state}`));
    assert.match(errs[0].message, /because reasons/, 'and must carry the reason through');
  }
});

test('freshnessErrors: a missing verdict is treated as a problem, not as fresh', () => {
  assert.equal(freshnessErrors(null).length, 1);
  assert.equal(freshnessErrors(undefined).length, 1);
});


// ─────────────────────────────────────────────────────────────────────────
// ⛔ A STATEMENT REFUSAL WAS COUNTED NOWHERE (found 2026-09-27)
//
// When hubIsBetter() says yes and the UPDATE's own WHERE clause writes nothing,
// the old code incremented NOTHING: not `repaired` (rowCount 0 now, correctly),
// not `degradeRefused`, not `unchanged`. So the stats stopped summing to
// byCve.size and the ONE outcome the doubled guard exists to make impossible was
// the only one it did not report.
//
// That is the signal that would have caught v2.186.0's doubled-guard drift in ONE
// deploy instead of three: the JS half permitted 80 repairs, the SQL half refused
// all 80, and every number in feed_sync_log looked fine.

function refusingPool(existingRows) {
  // A pool whose UPDATE matches no row — exactly the v2.186.0 shape.
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      if (/SELECT cve_id, vendor/.test(sql)) return { rows: existingRows };
      if (/UPDATE advisories/.test(sql)) return { rows: [], rowCount: 0 };
      return { rows: [], rowCount: 1 };
    },
  };
}

const BLANK_LOCAL = (cve) => ({
  cve_id: cve, vendor: 'cisco_asa', affected_version_ranges: [], matchability: 'unmatchable',
});
const GOOD_REMOTE = (cve) => ({
  cve_id: cve, vendor: 'cisco_asa', matchability: 'matched', affected_version_ranges: RANGE,
});

test('⛔ applyFeed: a permitted-then-refused repair is COUNTED and ERRORED', async () => {
  const pool = refusingPool([BLANK_LOCAL('CVE-2024-9'), BLANK_LOCAL('CVE-2024-10')]);
  const stats = await applyFeed(pool, feedOf([GOOD_REMOTE('CVE-2024-9'), GOOD_REMOTE('CVE-2024-10')]));

  assert.equal(stats.repaired, 0, 'nothing was written, so nothing may be reported repaired');
  assert.equal(stats.statementRefused, 2, 'and the refusal itself must be counted');
  assert.deepEqual(stats.statementRefusedCves, ['CVE-2024-9', 'CVE-2024-10']);
  assert.equal(stats.unchanged, 0, 'a refusal is NOT "nothing to do"');
  assert.equal(stats.degradeRefused, 0, 'nor a degrade');

  // ⛔ AN ERROR, NOT JUST A COUNTER. Pushing it into `errors` is what turns the
  // sync `partial` and puts it on the status banner; a counter buried in a jsonb
  // summary is read by nobody until somebody already suspects a problem.
  const err = stats.errors.find((e) => /guard disagreement/.test(e.message));
  assert.ok(err, 'expected a guard-disagreement error, got ' + JSON.stringify(stats.errors));
  assert.match(err.message, /2 advisories were permitted/);
  assert.match(err.message, /CVE-2024-9/);
  assert.match(err.message, /fixBoundary/, 'it must name where the two halves live');
});

test('⛔ applyFeed: a SUCCESSFUL repair records no refusal and names the CVE', async () => {
  // Keeps the counter meaningful: it must be absent on the healthy path, or the
  // banner it feeds becomes permanent amber and gets ignored.
  const pool = stubPool([BLANK_LOCAL('CVE-2024-11')]);
  const stats = await applyFeed(pool, feedOf([GOOD_REMOTE('CVE-2024-11')]));
  assert.equal(stats.repaired, 1);
  assert.equal(stats.statementRefused, 0);
  assert.deepEqual(stats.repairedCves, ['CVE-2024-11']);
  assert.equal(stats.errors.length, 0);
});

test('⛔ applyFeed: the counters SUM to the advisories considered', async () => {
  // The identity that made the missing counter visible in review at all. Every
  // branch is exercised at once: insert, repair-refused, degrade, vendor
  // conflict, unchanged.
  const pool = {
    calls: [],
    async query(sql, params) {
      this.calls.push({ sql, params });
      if (/SELECT cve_id, vendor/.test(sql)) {
        return {
          rows: [
            BLANK_LOCAL('CVE-R'),
            { cve_id: 'CVE-X', vendor: 'paloalto', affected_version_ranges: RANGE, matchability: 'matched' },
            { cve_id: 'CVE-D', vendor: 'cisco_asa', affected_version_ranges: RANGE, matchability: 'matched' },
            { cve_id: 'CVE-U', vendor: 'cisco_asa', affected_version_ranges: RANGE, matchability: 'matched' },
          ],
        };
      }
      // The repair of CVE-R is permitted by the predicate and refused by the
      // statement — the drift this counter exists to expose.
      if (/UPDATE advisories/.test(sql)) return { rows: [], rowCount: 0 };
      return { rows: [], rowCount: 1 };
    },
  };
  const stats = await applyFeed(pool, feedOf([
    GOOD_REMOTE('CVE-R'),
    { cve_id: 'CVE-N', vendor: 'fortinet', matchability: 'matched', affected_version_ranges: RANGE },
    { cve_id: 'CVE-X', vendor: 'cisco_asa', matchability: 'matched', affected_version_ranges: RANGE },
    { cve_id: 'CVE-D', vendor: 'cisco_asa', matchability: 'matched', affected_version_ranges: [] },
    { cve_id: 'CVE-U', vendor: 'cisco_asa', matchability: 'matched', affected_version_ranges: RANGE },
  ]));

  assert.equal(stats.considered, 5);
  assert.equal(stats.inserted, 1);
  assert.equal(stats.statementRefused, 1);
  assert.equal(stats.vendorConflict, 1);
  assert.equal(stats.degradeRefused, 1);
  assert.equal(stats.unchanged, 1);
  assert.equal(stats.unaccounted, 0, 'an uncounted outcome is an outcome nobody can see');
  assert.ok(!stats.errors.some((e) => /accounting/.test(e.message)));
});

test('⛔ applyFeed: an INSERT that writes nothing is counted, not silently dropped', async () => {
  // `ON CONFLICT DO NOTHING` writing nothing means the snapshot read at the top
  // was stale against a concurrent sync. Not an error — but not invisible either,
  // or the accounting identity above would have a hole in it.
  const pool = {
    async query(sql) {
      if (/SELECT cve_id, vendor/.test(sql)) return { rows: [] };
      return { rows: [], rowCount: 0 };
    },
  };
  const stats = await applyFeed(pool, feedOf([
    { cve_id: 'CVE-2024-12', vendor: 'fortinet', matchability: 'matched', affected_version_ranges: RANGE },
  ]));
  assert.equal(stats.inserted, 0);
  assert.equal(stats.insertSkipped, 1);
  assert.equal(stats.unaccounted, 0);
});

// ── repairTrend — "repaired 20" every six hours is not progress ──────────────

const { repairTrend, REPAIR_CONVERGENCE_RUNS } = require('../lib/feeds/cveHub');

test('⛔ repairTrend: a steady nonzero repair count is NOT converging', () => {
  // The symptom that read as progress for three days: a repair is a backfill and
  // should converge to zero, so a steady count every cycle means something is
  // undoing the writes between cycles.
  const t = repairTrend([20, 20, 20], 20);
  assert.equal(t.state, 'not_converging');
  assert.match(t.reason, /consecutive runs/);
  assert.match(t.reason, /not sticking|overwriting/);
});

test('repairTrend: a repair after a quiet run is ordinary convergence', () => {
  assert.equal(repairTrend([0, 20, 20], 5).state, 'converging');
  assert.equal(repairTrend([20, 0], 5).state, 'converging');
});

test('repairTrend: no repairs this run is idle, never an alarm', () => {
  assert.equal(repairTrend([20, 20, 20], 0).state, 'idle');
  assert.equal(repairTrend([], 0).state, 'idle');
});

test('⛔ repairTrend: an UNREADABLE history is unknown, never converging', () => {
  // A failed read is not a measurement. It is also deliberately NOT an error —
  // see the function's own note: this is a diagnostic over our own log table, and
  // a blip reading it must not raise an alarm about CVE discovery.
  const t = repairTrend(null, 20);
  assert.equal(t.state, 'unknown');
  assert.match(t.reason, /could not be read/);
  assert.notEqual(t.state, 'converging');
});

test('repairTrend: too little history to judge is unknown, not a clean bill', () => {
  assert.equal(repairTrend([20], 20).state, 'unknown');
  assert.equal(repairTrend([], 20).state, 'unknown');
  assert.ok(REPAIR_CONVERGENCE_RUNS >= 3, 'fewer than three runs cannot show a trend');
});
