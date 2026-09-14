'use strict';
// Pins lib/engines/workQueue.js and buildWorkQueueAnswer — the single ranked
// feed across every engine (Phase 3).
//
// ⛔ THIS FEATURE HAS EXACTLY TWO WAYS TO FAIL, and both produce a page that
// looks better than the truth:
//
//   1. EVERYTHING BECOMES URGENT. CLAUDE.md already records this outcome from
//      the rejected `log_hit` definition, which would have moved ~all 155
//      assessments to patch_now: "a queue where everything is urgent has no
//      prioritisation left". The guard is that `act_now` is a claim about
//      EVIDENCE — an item SecVault could not measure may never enter it,
//      however loudly its source declares itself urgent.
//
//   2. A FAILED SOURCE MAKES THE QUEUE LOOK CLEAN. If the compliance query
//      throws and the queue simply renders five fewer items, it is shortest and
//      most reassuring at precisely the moment it is least trustworthy. This is
//      the codebase's oldest bug — a failed read recorded as an affirmative
//      value — applied to the to-do list itself.
//
// The third rule worth pinning is that `verify` is a REAL band, not a bin. The
// items in it (a licence expiry that would not parse, a firewall that cannot be
// collected from) are the ones every competing product silently drops, and a
// firewall SecVault cannot read otherwise looks like the healthiest device on
// the fleet because it contributes no findings to anything.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  bandFor, rankItems, summarise, WORK_BANDS, magnitudeOf,
} = require('../lib/engines/workQueue');
const {
  groupBy,
  withCap,
  combineCapped,
  runSource,
  tunnelStatusOf,
  gatherPatchNow,
  gatherConfigDiffs,
  gatherLicences,
  gatherRuleCleanup,
  gatherTunnelsDown,
  gatherCollectionGaps,
  gatherSegmentation,
  gatherIngestDrops,
  PER_SOURCE_CAP,
  TUNNEL_STATE_FRESH_HOURS,
} = require('../lib/engines/workQueueData');
const { buildWorkQueueAnswer } = require('../lib/answers');

// A pool stub, per tests/README.md: returns canned rows and records the SQL it
// was handed, so a query's ORDER BY and predicate can be asserted without a
// database. `queue` is consumed one result per query() call, in order.
function stubPool(queue) {
  const seen = [];
  const results = queue.slice();
  return {
    sql: seen,
    async query(text, params) {
      seen.push({ text, params });
      const next = results.shift();
      if (next instanceof Error) throw next;
      return { rows: next === undefined ? [] : next };
    },
  };
}

const item = (over) => ({
  type: 'cve',
  key: 'k',
  title: 't',
  severity: 'high',
  urgency: 'soon',
  evidence: 'reported',
  count: 1,
  deviceIds: ['d1'],
  ...over,
});

describe('banding', () => {
  it('measured + urgent is act_now', () => {
    assert.equal(bandFor(item({ evidence: 'measured', urgency: 'now' })), 'act_now');
  });

  it('reported + urgent is still act_now', () => {
    // A KEV-listed CVE on an affected version is the vendor's word plus our
    // version match. That is enough to act on; it is not a measurement.
    assert.equal(bandFor(item({ evidence: 'reported', urgency: 'now' })), 'act_now');
  });

  it('non-urgent is scheduled', () => {
    assert.equal(bandFor(item({ evidence: 'measured', urgency: 'soon' })), 'scheduled');
  });

  it('⛔ UNMEASURED CAN NEVER BE act_now, however urgent the source says it is', () => {
    // The load-bearing line. A source cannot promote a guess by declaring it
    // urgent — `act_now` is a claim about evidence we do not have.
    assert.equal(bandFor(item({ evidence: 'unmeasured', urgency: 'now' })), 'verify');
    assert.equal(bandFor(item({ evidence: 'unmeasured', urgency: 'soon' })), 'verify');
  });

  it('⛔ an unknown or missing evidence value fails CLOSED to verify', () => {
    // Never fall through to act_now on a typo.
    assert.equal(bandFor(item({ evidence: undefined })), 'verify');
    assert.equal(bandFor(item({ evidence: 'probably' })), 'verify');
    assert.equal(bandFor({}), 'verify');
    assert.equal(bandFor(null), 'verify');
  });
});

describe('ranking', () => {
  it('orders by band first', () => {
    const ranked = rankItems([
      item({ key: 'c', evidence: 'unmeasured' }),
      item({ key: 'b', evidence: 'measured', urgency: 'soon' }),
      item({ key: 'a', evidence: 'measured', urgency: 'now' }),
    ]);
    assert.deepEqual(ranked.map((r) => r.band), ['act_now', 'scheduled', 'verify']);
  });

  it('orders by severity inside a band', () => {
    const ranked = rankItems([
      item({ key: 'low', severity: 'low', urgency: 'now', evidence: 'measured' }),
      item({ key: 'crit', severity: 'critical', urgency: 'now', evidence: 'measured' }),
    ]);
    assert.equal(ranked[0].key, 'crit');
  });

  it('an item spanning more firewalls outranks one of the same kind on fewer', () => {
    const ranked = rankItems([
      item({ key: 'small', magnitude: 3, urgency: 'soon', evidence: 'measured' }),
      item({ key: 'big', magnitude: 90, urgency: 'soon', evidence: 'measured' }),
    ]);
    assert.equal(ranked[0].key, 'big');
  });

  it('falls back to the deviceIds length when a source supplied no magnitude', () => {
    const ranked = rankItems([
      item({ key: 'one', urgency: 'soon', evidence: 'measured', deviceIds: ['d1'] }),
      item({ key: 'three', urgency: 'soon', evidence: 'measured', deviceIds: ['d1', 'd2', 'd3'] }),
    ]);
    assert.equal(ranked[0].key, 'three');
  });

  it('⛔ a huge DISPLAY count does not outrank anything — `count` is not one unit', () => {
    // The live incident: 324,875 dropped syslog datagrams. `count` means
    // dropped datagrams there, affected firewalls for a CVE, entitlements for a
    // licence and permitting rules for a segmentation violation — so while the
    // sort read `count`, the ingest item pinned itself permanently above every
    // other high-severity item, purely because syslog is counted in bigger
    // numbers than firewalls are. Ranking is on `magnitude`, which is always
    // "how many firewalls is this about".
    const ranked = rankItems([
      item({ key: 'ingest', title: 'A', count: 324875, magnitude: 1, urgency: 'now', evidence: 'measured' }),
      item({ key: 'cve', title: 'B', count: 3, magnitude: 3, urgency: 'now', evidence: 'measured' }),
    ]);
    assert.equal(ranked[0].key, 'cve');
  });

  it('⛔ an item with no magnitude falls back to 1, NEVER to its display count', () => {
    // The fallback is where the bug would silently return: an item that omits
    // magnitude must not be allowed to borrow its display count and start
    // winning again.
    assert.equal(magnitudeOf({ count: 324875 }), 1);
    assert.equal(magnitudeOf({ count: 99, deviceIds: [] }), 1);
    assert.equal(magnitudeOf({ magnitude: 0, deviceIds: ['a', 'b'] }), 2);
    assert.equal(magnitudeOf({ magnitude: 'x', count: 50 }), 1);
    assert.equal(magnitudeOf(null), 1);
    // Duplicated device ids are one firewall, not two.
    assert.equal(magnitudeOf({ deviceIds: ['d1', 'd1', null] }), 1);
  });

  it('⛔ is STABLE across identical inputs', () => {
    // A queue that reorders itself between refreshes destroys the one thing a
    // queue is for. Two items alike in every rank key fall back to the title.
    const mk = () => [
      item({ key: 'z', title: 'Zebra', urgency: 'soon', evidence: 'measured' }),
      item({ key: 'a', title: 'Apple', urgency: 'soon', evidence: 'measured' }),
    ];
    assert.deepEqual(rankItems(mk()).map((r) => r.title), rankItems(mk()).map((r) => r.title));
    assert.equal(rankItems(mk())[0].title, 'Apple');
  });

  it('does not mutate its input', () => {
    const input = [item({ key: 'x' })];
    rankItems(input);
    assert.equal(input[0].band, undefined);
  });

  it('survives junk', () => {
    assert.deepEqual(rankItems(null), []);
    assert.deepEqual(rankItems([null, undefined]), []);
  });
});

describe('⛔ a failed source is never silently zero', () => {
  it('counts and names failed sources', () => {
    const s = summarise([], [
      { key: 'cve', ok: true },
      { key: 'compliance', ok: false, error: 'relation does not exist' },
    ]);
    assert.equal(s.sourcesFailed, 1);
    assert.equal(s.sourcesTotal, 2);
    assert.deepEqual(s.failedSources, [{ key: 'compliance', error: 'relation does not exist' }]);
  });

  it('⛔ REFUSES an all-clear when a source failed, even with an empty queue', () => {
    // The most dangerous sentence this page can print. An operator who reads
    // "nothing outstanding" closes the tab.
    const a = buildWorkQueueAnswer(summarise([], [
      { key: 'cve', ok: true },
      { key: 'compliance', ok: false, error: 'boom' },
    ]));
    assert.notEqual(a.tone, 'ok');
    assert.match(a.lead + ' ' + a.sentence, /could not be built|not a complete picture/);
    assert.match(a.coverage, /could not be read/);
  });

  it('allows the all-clear only when every source ran and nothing is unverifiable', () => {
    const a = buildWorkQueueAnswer(summarise([], [{ key: 'cve', ok: true }]));
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
    assert.match(a.lead, /Nothing is outstanding/);
  });

  it('⛔ REFUSES an all-clear while anything sits in verify', () => {
    const items = rankItems([item({ evidence: 'unmeasured' })]);
    const a = buildWorkQueueAnswer(summarise(items, [{ key: 'licence', ok: true }]));
    assert.notEqual(a.tone, 'ok');
    assert.match(a.coverage, /cannot verify/);
  });
});

describe('the summary', () => {
  it('counts each band and de-duplicates devices across items', () => {
    const items = rankItems([
      item({ key: 'a', urgency: 'now', evidence: 'measured', deviceIds: ['d1'] }),
      item({ key: 'b', urgency: 'soon', evidence: 'measured', deviceIds: ['d1', 'd2'] }),
      item({ key: 'c', evidence: 'unmeasured', deviceIds: ['d2'] }),
    ]);
    const s = summarise(items, []);
    assert.equal(s.total, 3);
    assert.equal(s.act_now, 1);
    assert.equal(s.scheduled, 1);
    assert.equal(s.verify, 1);
    assert.equal(s.deviceCount, 2);
  });

  it('leads with the act_now count when there is one', () => {
    const items = rankItems([
      item({ key: 'a', urgency: 'now', evidence: 'measured' }),
      item({ key: 'b', urgency: 'soon', evidence: 'measured' }),
    ]);
    const a = buildWorkQueueAnswer(summarise(items, [{ key: 'x', ok: true }]));
    assert.equal(a.tone, 'critical');
    assert.match(a.lead, /1 item needs attention now/);
    assert.match(a.sentence, /1 more scheduled/);
  });

  it('never throws on junk', () => {
    for (const bad of [null, undefined, {}, { act_now: 'x' }]) {
      const a = buildWorkQueueAnswer(bad);
      assert.equal(typeof a.sentence, 'string');
    }
    assert.equal(summarise(null, null).total, 0);
  });

  it('the three bands are the documented three', () => {
    assert.deepEqual(WORK_BANDS, ['act_now', 'scheduled', 'verify']);
  });
});

describe('⛔ a cap that bit is disclosed', () => {
  it('carries the shown/total through the summary', () => {
    // Live on the first run: 74 critical/high compliance failures existed, the
    // cap returned 50, and the page reported nothing. A truncated list looks
    // complete, which makes this the more insidious of the two ways the queue
    // can be shorter than the truth.
    const s = summarise([], [{ key: 'compliance', ok: true, count: 50, truncatedFrom: 74 }]);
    assert.equal(s.sourcesTruncated, 1);
    assert.deepEqual(s.truncatedSources, [{ key: 'compliance', shown: 50, of: 74 }]);
  });

  it('says so in the coverage line, with the real numbers', () => {
    const a = buildWorkQueueAnswer(
      summarise([], [{ key: 'compliance', ok: true, count: 50, truncatedFrom: 74 }])
    );
    assert.match(a.coverage, /only 50 of 74 compliance items are listed/);
  });

  it('⛔ still discloses the cap when even the count failed', () => {
    const a = buildWorkQueueAnswer(
      summarise([], [{ key: 'cve', ok: true, count: 50, truncatedFrom: 'unknown' }])
    );
    assert.match(a.coverage, /more work than is listed here/);
  });

  it('an uncapped source reports no truncation', () => {
    const s = summarise([], [{ key: 'cve', ok: true, count: 3, truncatedFrom: null }]);
    assert.equal(s.sourcesTruncated, 0);
  });
});

describe('⛔ grouping — an item is a decision, not a fact', () => {
  // These assert the SHAPE the gathers must produce, because the rule is easy
  // to state and was missed on the first pass: one compliance check failing on
  // five firewalls shipped as five items repeating an identical remediation,
  // which is precisely the wall of duplicated prose a queue exists to replace.
  it('a grouped item keeps every affected device in deviceIds', () => {
    const grouped = item({
      key: 'compliance:any-any',
      count: 5,
      deviceIds: ['d1', 'd2', 'd3', 'd4', 'd5'],
      urgency: 'now',
      evidence: 'measured',
      severity: 'critical',
    });
    const s = summarise(rankItems([grouped]), []);
    assert.equal(s.total, 1, 'one decision, not five');
    assert.equal(s.deviceCount, 5, 'but the scope is not lost');
  });

  it('a grouped item outranks a smaller one of the same severity', () => {
    // Breadth has to stay visible in the ordering after aggregation — but as
    // the FIREWALL count, which is the one unit every source shares.
    const ranked = rankItems([
      item({
        key: 'one', count: 1, magnitude: 1, urgency: 'now', evidence: 'measured', severity: 'critical',
      }),
      item({
        key: 'five', count: 5, magnitude: 5, urgency: 'now', evidence: 'measured', severity: 'critical',
      }),
    ]);
    assert.equal(ranked[0].key, 'five');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// THE GATHER HALF (lib/engines/workQueueData.js).
//
// ⛔ These were unreachable from a test until the module exported them, and
// three real bugs were living in exactly the functions it did not export: a
// non-deterministic group cut, a cap that announced "showing 50 of 50", and one
// device's fixed version printed as the instruction for every device in a
// group. "It needs a pool" is not a reason to leave logic untested — the pool
// is a stub that returns canned rows.
// ────────────────────────────────────────────────────────────────────────────

describe('groupBy — one decision, not one row', () => {
  it('collapses rows sharing a key and hands the whole group to the merge', () => {
    const out = groupBy(
      [{ k: 'a', d: 1 }, { k: 'b', d: 2 }, { k: 'a', d: 3 }],
      (x) => x.k,
      (group) => ({ key: group[0].k, n: group.length, ds: group.map((g) => g.d) })
    );
    assert.equal(out.length, 2);
    assert.deepEqual(out[0], { key: 'a', n: 2, ds: [1, 3] });
  });

  it('preserves first-seen key order, so the merge output is deterministic', () => {
    const out = groupBy([{ k: 'z' }, { k: 'a' }, { k: 'z' }], (x) => x.k, (g) => g[0].k);
    assert.deepEqual(out, ['z', 'a']);
  });
});

describe('⛔ withCap — a cap is disclosed only when something is actually hidden', () => {
  const items = (n) => Array.from({ length: n }, (_, i) => ({ key: `i${i}` }));

  it('a short list is returned untouched and never runs the count', async () => {
    let counted = false;
    const out = await withCap(items(3), async () => { counted = true; return { rows: [{ n: 99 }] }; });
    assert.ok(Array.isArray(out));
    assert.equal(out.length, 3);
    assert.equal(counted, false, 'the COUNT costs a query and is only worth it when the cap bit');
  });

  it('⛔ exactly at the cap with a true total of exactly the cap is NOT truncated', async () => {
    // The false positive: the old guard was `items.length < PER_SOURCE_CAP`, so
    // 50 items out of a true 50 reported "showing 50 of 50" and lit the
    // truncation banner over a list with nothing missing from it. A banner that
    // cries wolf is spent by the first time it is right.
    const out = await withCap(items(PER_SOURCE_CAP), async () => ({ rows: [{ n: PER_SOURCE_CAP }] }));
    assert.ok(Array.isArray(out), 'no truncation envelope');
    assert.equal(out.length, PER_SOURCE_CAP);
  });

  it('reports the real total when the cap genuinely cut the list', async () => {
    const out = await withCap(items(PER_SOURCE_CAP), async () => ({ rows: [{ n: 74 }] }));
    assert.equal(out.items.length, PER_SOURCE_CAP);
    assert.equal(out.truncatedFrom, 74);
  });

  it('⛔ still discloses the cap when the COUNT itself failed', async () => {
    // Losing the number is tolerable; losing the disclosure is not.
    const out = await withCap(items(PER_SOURCE_CAP), async () => { throw new Error('boom'); });
    assert.equal(out.truncatedFrom, 'unknown');
    assert.equal(out.items.length, PER_SOURCE_CAP);
  });

  it('⛔ discloses rather than trusting a COUNT that came back unusable', async () => {
    // A NULL/absent/NaN count is not a measurement of zero rows hidden.
    for (const bad of [[], [{ n: null }], [{ n: 'plenty' }]]) {
      const out = await withCap(items(PER_SOURCE_CAP), async () => ({ rows: bad }));
      assert.equal(out.truncatedFrom, 'unknown');
    }
  });

  it('slices the list itself, so an over-cap in-memory list is both cut AND disclosed', async () => {
    const out = await withCap(items(63), async () => ({ rows: [{ n: 63 }] }));
    assert.equal(out.items.length, PER_SOURCE_CAP);
    assert.equal(out.truncatedFrom, 63);
  });
});

describe('combineCapped — a source that asks two questions', () => {
  it('returns a plain array when neither half was cut', () => {
    const out = combineCapped([[{ a: 1 }], [{ b: 2 }]]);
    assert.ok(Array.isArray(out));
    assert.equal(out.length, 2);
  });

  it('⛔ a cut in EITHER half truncates the whole source, and the total covers both', () => {
    const out = combineCapped([
      { items: [{ a: 1 }], truncatedFrom: 60 },
      [{ b: 2 }, { b: 3 }],
    ]);
    assert.equal(out.items.length, 3);
    assert.equal(out.truncatedFrom, 62, '60 truncated + 2 complete');
  });

  it('⛔ an uncountable half makes the combined total unknown, never a short sum', () => {
    // A sum quietly missing a term reads as exact and is not.
    const out = combineCapped([
      { items: [{ a: 1 }], truncatedFrom: 'unknown' },
      { items: [{ b: 2 }], truncatedFrom: 12 },
    ]);
    assert.equal(out.truncatedFrom, 'unknown');
  });
});

describe('runSource — a throw is reported, never an empty list', () => {
  it('reports ok:false with the message', async () => {
    const out = await runSource('compliance', async () => { throw new Error('relation does not exist'); });
    assert.equal(out.ok, false);
    assert.equal(out.items.length, 0);
    assert.equal(out.error, 'relation does not exist');
  });

  it('carries truncatedFrom through from a capped gather', async () => {
    const out = await runSource('cve', async () => ({ items: [1, 2], truncatedFrom: 74 }));
    assert.equal(out.ok, true);
    assert.equal(out.count, 2);
    assert.equal(out.truncatedFrom, 74);
  });

  it('accepts a plain array and reports no truncation', async () => {
    const out = await runSource('cve', async () => [1, 2, 3]);
    assert.deepEqual([out.ok, out.count, out.truncatedFrom], [true, 3, null]);
  });
});

describe('the CVE source', () => {
  const cveRow = (over) => ({
    cve_id: 'CVE-2026-1', title: 't', cvss_score: 9.8, kev_listed: false, vendor: 'paloalto',
    device_id: 'd1', device_name: 'FW-1', asset_criticality: 'normal',
    log_hit: null, config_applies: 'yes', fixed_in: '11.1.4-h1',
    ...over,
  });

  it('⛔ orders on a UNIQUE tail, so the row cut cannot vary between refreshes', async () => {
    // kev_listed and cvss_score tie across whole blocks of rows, and the rows
    // are GROUPED after the LIMIT — so a plan-dependent cut moved devices in
    // and out of a CVE's group and rewrote the item's own title ("on 3
    // firewalls" / "on 2 firewalls") between two loads of the same page.
    const pool = stubPool([[cveRow()]]);
    await gatherPatchNow(pool);
    assert.match(pool.sql[0].text, /ORDER BY[\s\S]*a\.cve_id, d\.name/);
  });

  it('groups per CVE and carries every device, with magnitude in firewalls', async () => {
    const pool = stubPool([[
      cveRow({ device_id: 'd1', device_name: 'FW-1' }),
      cveRow({ device_id: 'd2', device_name: 'FW-2' }),
      cveRow({ device_id: 'd3', device_name: 'FW-3' }),
    ]]);
    const out = await gatherPatchNow(pool);
    assert.equal(out.length, 1, 'one patch decision');
    assert.equal(out[0].count, 3);
    assert.equal(out[0].magnitude, 3);
    assert.deepEqual(out[0].deviceIds, ['d1', 'd2', 'd3']);
  });

  it('names the fixed version when every device in the group shares one', async () => {
    const pool = stubPool([[
      cveRow({ fixed_in: '11.1.4-h1' }),
      cveRow({ device_id: 'd2', fixed_in: '11.1.4-h1' }),
    ]]);
    const out = await gatherPatchNow(pool);
    assert.equal(out[0].action, 'Upgrade to 11.1.4-h1.');
  });

  it('⛔ REFUSES to print one device’s fixed version as the instruction for all of them', async () => {
    // `fixed_in` is per-assessment. Two firewalls on different maintenance
    // branches are legitimately fixed by different releases, and printing
    // group[0]'s value told the operator of the 11.1 box to DOWNGRADE it, in a
    // sentence that sounded certain.
    const pool = stubPool([[
      cveRow({ device_id: 'd1', fixed_in: '10.1.14-h2' }),
      cveRow({ device_id: 'd2', fixed_in: '11.1.4-h1' }),
    ]]);
    const out = await gatherPatchNow(pool);
    assert.match(out[0].action, /differ by device/);
    assert.match(out[0].action, /10\.1\.14-h2/);
    assert.match(out[0].action, /11\.1\.4-h1/);
  });

  it('⛔ a group where only SOME devices have a recorded fix is also a mixture', async () => {
    const pool = stubPool([[
      cveRow({ device_id: 'd1', fixed_in: '11.1.4-h1' }),
      cveRow({ device_id: 'd2', fixed_in: null }),
    ]]);
    const out = await gatherPatchNow(pool);
    assert.match(out[0].action, /differ by device/);
    assert.match(out[0].action, /no recorded fixed version/);
  });

  it('says so plainly when no device has a recorded fix', async () => {
    const pool = stubPool([[cveRow({ fixed_in: null }), cveRow({ device_id: 'd2', fixed_in: null })]]);
    const out = await gatherPatchNow(pool);
    assert.match(out[0].action, /No fixed version is recorded/);
  });

  it('⛔ discloses its cap — it was the one grouping source that never did', async () => {
    const many = Array.from({ length: 60 }, (_, i) => cveRow({ cve_id: `CVE-2026-${i}` }));
    const pool = stubPool([many, [{ n: 60 }]]);
    const out = await gatherPatchNow(pool);
    assert.equal(out.items.length, PER_SOURCE_CAP);
    assert.equal(out.truncatedFrom, 60);
    assert.match(pool.sql[1].text, /count\(DISTINCT a\.cve_id\)/, 'counted in the unit the items are in');
  });
});

describe('the config-diff source', () => {
  const diffRow = (i) => ({
    id: `diff-${i}`, detected_at: '2026-09-01T00:00:00Z', change_summary: 's',
    device_id: `d${i}`, device_name: `FW-${i}`,
  });

  it('⛔ discloses its cap instead of ending the backlog at 50 in silence', async () => {
    const pool = stubPool([Array.from({ length: PER_SOURCE_CAP }, (_, i) => diffRow(i)), [{ n: 137 }]]);
    const out = await gatherConfigDiffs(pool);
    assert.equal(out.items.length, PER_SOURCE_CAP);
    assert.equal(out.truncatedFrom, 137);
  });

  it('breaks the detected_at tie on the row id', async () => {
    const pool = stubPool([[diffRow(1)]]);
    await gatherConfigDiffs(pool);
    assert.match(pool.sql[0].text, /ORDER BY cd\.detected_at DESC, cd\.id/);
  });

  it('one unreviewed change is one firewall, whatever it contains', async () => {
    const pool = stubPool([[diffRow(1)]]);
    const out = await gatherConfigDiffs(pool);
    assert.equal(out[0].magnitude, 1);
  });
});

describe('the licence source', () => {
  it('⛔ ranks on firewalls, not on the entitlement count it displays', async () => {
    const pool = stubPool([
      [{ device_id: 'd1', device_name: 'ITC-SK', within_horizon: 11, expired: 1, soonest: '2026-09-20' }],
      [],
    ]);
    const out = await gatherLicences(pool);
    assert.equal(out[0].count, 1, 'the display count is the expired entitlements');
    assert.equal(out[0].magnitude, 1, 'but the item is about one firewall');
  });

  it('⛔ discloses a cap in EITHER half, and totals both', async () => {
    const expiring = Array.from({ length: PER_SOURCE_CAP }, (_, i) => ({
      device_id: `d${i}`, device_name: `FW-${i}`, within_horizon: 2, expired: 0, soonest: '2026-09-20',
    }));
    const pool = stubPool([expiring, [{ device_id: 'u1', device_name: 'FW-U', n: 4 }], [{ n: 71 }]]);
    const out = await gatherLicences(pool);
    assert.equal(out.items.length, PER_SOURCE_CAP + 1);
    assert.equal(out.truncatedFrom, 72, '71 expiring-device total + 1 uncapped unknown-expiry device');
  });

  it('an unparseable expiry is unmeasured, so it lands in verify', async () => {
    const pool = stubPool([[], [{ device_id: 'd1', device_name: 'FW-1', n: 44 }]]);
    const out = await gatherLicences(pool);
    assert.equal(out[0].evidence, 'unmeasured');
    assert.equal(bandFor(out[0]), 'verify');
  });
});

describe('the rule-cleanup source', () => {
  const cleanupRow = (over) => ({
    device_id: 'd1', device_name: 'TSR-TL', n: 2, unused: 0, shadow: 2, redundant: 0, ...over,
  });

  it('⛔ does NOT claim measured-zero backing for a device with no unused rules', async () => {
    // Live: TSR-TL has 2 shadowed rules and 0 unused ones, and this item stated
    // "every 'never used' rule here is backed by a measured zero hit count"
    // about no rules at all. An evidence claim attached to an empty set teaches
    // the reader that the sentence is boilerplate — so they discount it next
    // time, over 89 rules where it is true and load-bearing.
    const pool = stubPool([[cleanupRow()]]);
    const out = await gatherRuleCleanup(pool);
    assert.match(out[0].why, /2 shadowed/);
    assert.doesNotMatch(out[0].why, /never used/);
    assert.doesNotMatch(out[0].why, /measured zero/);
  });

  it('makes the claim when there ARE unused rules behind it', async () => {
    const pool = stubPool([[cleanupRow({ n: 132, unused: 89, shadow: 43 })]]);
    const out = await gatherRuleCleanup(pool);
    assert.match(out[0].why, /89 never used/);
    assert.match(out[0].why, /measured zero hit count/);
  });

  it('⛔ discloses its cap, counted in devices — the unit its items are in', async () => {
    const many = Array.from(
      { length: PER_SOURCE_CAP },
      (_, i) => cleanupRow({ device_id: `d${i}`, device_name: `FW-${i}` })
    );
    const pool = stubPool([many, [{ n: 58 }]]);
    const out = await gatherRuleCleanup(pool);
    assert.equal(out.truncatedFrom, 58);
  });

  it('a 132-finding backlog on one firewall has magnitude 1, not 132', async () => {
    const pool = stubPool([[cleanupRow({ n: 132, unused: 89, shadow: 43 })]]);
    const out = await gatherRuleCleanup(pool);
    assert.equal(out[0].count, 132);
    assert.equal(out[0].magnitude, 1);
  });
});

describe('⛔ the tunnel source — an unreadable state is not a healthy one', () => {
  const hoursAgo = (h) => new Date(Date.now() - h * 3600 * 1000).toISOString();
  const tunnel = (over) => ({
    id: 't1', name: 'BRANCH-1', peer: '203.0.113.5', status: 'down',
    collected_at: hoursAgo(1), device_id: 'd1', device_name: 'FW-1', ...over,
  });

  it('classifies vendor verbs, and refuses to guess at the ones it does not know', () => {
    assert.equal(tunnelStatusOf('down'), 'down');
    assert.equal(tunnelStatusOf(' DISCONNECTED '), 'down');
    assert.equal(tunnelStatusOf('up'), 'up');
    assert.equal(tunnelStatusOf('established'), 'up');
    // ⛔ The whole point: none of these are 'up'.
    assert.equal(tunnelStatusOf(null), 'unreadable');
    assert.equal(tunnelStatusOf(''), 'unreadable');
    assert.equal(tunnelStatusOf('   '), 'unreadable');
    assert.equal(tunnelStatusOf('phase2-negotiating'), 'unreadable');
  });

  it('⛔ selects by NOT-up, so an unknown verb reaches the queue instead of vanishing', async () => {
    // The old predicate was a positive `IN ('down','inactive','disconnected')`,
    // which silently classified NULL and every unrecognised vendor verb as
    // healthy — a failed read recorded as an affirmative "fine", and invisible
    // because the symptom is SILENCE.
    const pool = stubPool([[]]);
    await gatherTunnelsDown(pool);
    assert.match(pool.sql[0].text, /NOT IN \('up','active','connected','established'\)/);
    assert.match(pool.sql[0].text, /t\.status IS NULL/);
  });

  it('a fresh "down" reading is measured and urgent', async () => {
    const pool = stubPool([[tunnel()]]);
    const out = await gatherTunnelsDown(pool);
    assert.equal(out[0].type, 'tunnel');
    assert.equal(out[0].evidence, 'measured');
    assert.equal(bandFor(out[0]), 'act_now');
  });

  it('⛔ a STALE "down" reading is demoted to unmeasured and lands in verify', async () => {
    // Only the latest snapshot per device is kept, so "this tunnel is down" is
    // a statement about now only if the snapshot is recent. A four-day-old
    // reading asserted as a current measurement is a stale fact in a fresh
    // one's clothes — and collected_at was already selected and thrown away.
    const pool = stubPool([[tunnel({ collected_at: hoursAgo(TUNNEL_STATE_FRESH_HOURS + 5) })]]);
    const out = await gatherTunnelsDown(pool);
    assert.equal(out[0].type, 'tunnel_stale');
    assert.equal(out[0].evidence, 'unmeasured');
    assert.equal(bandFor(out[0]), 'verify');
    assert.match(out[0].why, /may have recovered since/);
  });

  it('⛔ a NULL or unrecognised status becomes its own verify-band item', async () => {
    const pool = stubPool([[
      tunnel({ id: 't2', status: null }),
      tunnel({ id: 't3', status: 'phase2-negotiating' }),
    ]]);
    const out = await gatherTunnelsDown(pool);
    assert.deepEqual(out.map((o) => o.type), ['tunnel_unknown', 'tunnel_unknown']);
    assert.deepEqual(out.map((o) => bandFor(o)), ['verify', 'verify']);
    assert.match(out[0].why, /nothing at all/);
    assert.match(out[1].why, /phase2-negotiating/);
    // ⛔ It must never read as an all-clear.
    assert.match(out[0].why, /NOT evidence that the tunnel is healthy/);
  });

  it('a missing collected_at is treated as stale, never as fresh', async () => {
    const pool = stubPool([[tunnel({ collected_at: null })]]);
    const out = await gatherTunnelsDown(pool);
    assert.equal(out[0].type, 'tunnel_stale');
    assert.equal(out[0].evidence, 'unmeasured');
  });

  it('discloses its cap', async () => {
    const many = Array.from({ length: PER_SOURCE_CAP }, (_, i) => tunnel({ id: `t${i}` }));
    const pool = stubPool([many, [{ n: 66 }]]);
    const out = await gatherTunnelsDown(pool);
    assert.equal(out.truncatedFrom, 66);
  });
});

describe('the collection-gap source', () => {
  it('⛔ discloses its cap — it measures the hole in every other number here', async () => {
    const many = Array.from({ length: PER_SOURCE_CAP }, (_, i) => ({
      device_id: `d${i}`, device_name: `FW-${i}`, vendor: 'fortinet', mgmt_method: 'ssh',
      last_collected_at: null, last_connectivity_ok: false, last_connectivity_checked_at: null,
    }));
    const pool = stubPool([many, [{ n: 63 }]]);
    const out = await gatherCollectionGaps(pool);
    assert.equal(out.items.length, PER_SOURCE_CAP);
    assert.equal(out.truncatedFrom, 63);
    assert.equal(bandFor(out.items[0]), 'verify');
  });

  it('breaks the NULL last_collected_at tie on the device name', async () => {
    const pool = stubPool([[]]);
    await gatherCollectionGaps(pool);
    assert.match(pool.sql[0].text, /ORDER BY d\.last_collected_at NULLS FIRST, d\.name/);
  });
});

describe('⛔ the segmentation source — four verdicts, not two', () => {
  const intent = (over) => ({
    id: 'i1', sourceZone: 'guest', destZone: 'server', expectation: 'deny',
    verdict: 'violation_active', permittingRuleCount: 2,
    examples: [
      { deviceId: 'd1', deviceName: 'FW-1' },
      { deviceId: 'd2', deviceName: 'FW-2' },
    ],
    ...over,
  });
  const run = (intents) => gatherSegmentation(null, { intents });

  it('keeps the two measured violations banded as before', async () => {
    const out = await run([
      intent({ id: 'a', verdict: 'violation_active' }),
      intent({ id: 'b', verdict: 'violation_permitted' }),
    ]);
    assert.deepEqual(out.map((o) => bandFor(o)), ['act_now', 'scheduled']);
    assert.deepEqual(out.map((o) => o.severity), ['critical', 'high']);
  });

  it('⛔ INCLUDES violation_unverified, as unmeasured — it must be assumed live', async () => {
    // Dropping it made the queue quietest about the firewalls SecVault can see
    // least: Fortinet over SSH reports no hit counts at all, so every violation
    // on those devices is unverified, and every one of them was omitted.
    const out = await run([intent({ verdict: 'violation_unverified' })]);
    assert.equal(out.length, 1);
    assert.equal(out[0].evidence, 'unmeasured');
    assert.equal(bandFor(out[0]), 'verify');
    assert.match(out[0].why, /assumed live/);
    assert.match(out[0].action, /Treat the path as live/);
  });

  it('⛔ INCLUDES unknown, and says plainly that no ruleset was collected', async () => {
    // An untested boundary rendered as nothing at all reads as a satisfied one.
    const out = await run([intent({ verdict: 'unknown', permittingRuleCount: 0, examples: [] })]);
    assert.equal(out.length, 1);
    assert.equal(out[0].evidence, 'unmeasured');
    assert.equal(bandFor(out[0]), 'verify');
    assert.match(out[0].why, /No ruleset has been collected/);
    assert.match(out[0].why, /not the same as it holding/);
    assert.match(out[0].title, /cannot be judged/);
  });

  it('still ignores the verdicts that are not violations', async () => {
    const out = await run([
      intent({ verdict: 'ok_blocked' }),
      intent({ verdict: 'ok_in_use' }),
      intent({ verdict: 'unused_permission' }),
      intent({ verdict: 'ok_unverified' }),
      intent({ verdict: 'expected_allow_missing' }),
    ]);
    assert.equal(out.length, 0);
  });

  it('⛔ SAYS the device list is a sample rather than implying completeness', async () => {
    // segmentation.js exposes at most five `examples` per intent, so a
    // violation permitted by 40 rules across 12 firewalls contributes at most
    // five device ids — understating summary.deviceCount with no "and N more"
    // to warn the reader, because the object does not carry the information to
    // write one.
    const out = await run([intent({
      permittingRuleCount: 40,
      examples: [1, 2, 3, 4, 5].map((i) => ({ deviceId: `d${i}`, deviceName: `FW-${i}` })),
    })]);
    assert.equal(out[0].affectsPartial, true);
    assert.equal(out[0].deviceIdsPartial, true);
    assert.match(out[0].why, /only the first 5 of 40 permitting rules/);
    assert.match(out[0].why, /more firewalls than the ones named here/);
    // describeAffected summarises the tail instead of printing five names.
    assert.deepEqual(out[0].affects, ['FW-1', 'FW-2', 'FW-3', 'FW-4', 'and 1 more']);
  });

  it('does not cry sample when every permitting rule was exposed', async () => {
    const out = await run([intent({ permittingRuleCount: 2 })]);
    assert.equal(out[0].affectsPartial, false);
    assert.doesNotMatch(out[0].why, /only the first/);
  });

  it('⛔ ranks on firewalls, not on the permitting-rule count it displays', async () => {
    const out = await run([intent({ permittingRuleCount: 40 })]);
    assert.equal(out[0].count, 40);
    assert.equal(out[0].magnitude, 2, 'two distinct firewalls in the exposed examples');
  });

  it('discloses its own cap exactly, since every intent is already in memory', async () => {
    const many = Array.from({ length: 55 }, (_, i) => intent({ id: `i${i}` }));
    const out = await gatherSegmentation(null, { intents: many });
    assert.equal(out.items.length, PER_SOURCE_CAP);
    assert.equal(out.truncatedFrom, 55);
  });

  it('a missing or malformed segmentation result is an empty list, not a throw', async () => {
    assert.deepEqual(await gatherSegmentation(null, null), []);
    assert.deepEqual(await gatherSegmentation(null, {}), []);
    assert.deepEqual(await gatherSegmentation(null, { intents: [null, { verdict: 'nonsense' }] }), []);
  });
});

describe('the ingest source', () => {
  it('⛔ a 324,875-event drop is one collector problem, not 324,875 firewalls', async () => {
    const pool = stubPool([[{ dropped: '324875', received: '9000000', last_at: '2026-09-12T10:00:00Z' }]]);
    const out = await gatherIngestDrops(pool);
    assert.equal(out[0].type, 'ingest_drop');
    assert.equal(out[0].count, 324875, 'the scale stays visible where it belongs');
    assert.equal(out[0].magnitude, 1);
    // And with that magnitude it no longer pins itself above real exposure.
    const ranked = rankItems([
      out[0],
      {
        type: 'cve', title: 'Patch', severity: 'high', urgency: 'now',
        evidence: 'measured', count: 3, magnitude: 3,
      },
    ]);
    assert.equal(ranked[0].type, 'cve');
  });

  it('a silent collector is still unmeasured, and still magnitude 1', async () => {
    const pool = stubPool([[{ dropped: '0', received: '0', last_at: null }]]);
    const out = await gatherIngestDrops(pool);
    assert.equal(out[0].type, 'ingest_silent');
    assert.equal(bandFor(out[0]), 'verify');
    assert.equal(out[0].magnitude, 1);
  });
});
