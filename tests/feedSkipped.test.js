// tests/feedSkipped.test.js
//
// A DELIBERATE SKIP IS NOT A DEGRADATION.
//
// ⛔ This pins behaviour CLAUDE.md has documented since the vendor-PSIRT gate
// shipped and which the code did NOT implement: 'skipped' had no entry in
// FEED_STATUS_ORDER, so it fell through to the unknown-status rank and rendered
// DEGRADED — the exact opposite of a deliberate skip. It was latent only because
// nothing had ever been skipped on the reference fleet (both PSIRT vendors are
// in the inventory, so planVendorPsirts never skipped either).
//
// The "we could not measure this" case here is the one that matters: a skipped
// feed must be excluded from the verdict WITHOUT being mistaken for a healthy
// one, and a fleet where everything is skipped must not report itself green.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { feedStatusRank } = require('../lib/formatDisplay');
const { getSyncPillStatus, KNOWN_FEEDS } = require('../lib/feedStatus');

const NOW = Date.parse('2026-09-18T06:00:00Z');
const ago = (min) => new Date(NOW - min * 60000).toISOString();

function row(feed, status, opts = {}) {
  return {
    feed_name: feed,
    status,
    started_at: opts.started ?? ago(10),
    finished_at: opts.finished === null ? null : (opts.finished ?? ago(9)),
    error_count: opts.errors ?? 0,
  };
}

function poolWith(rows) {
  return { async query() { return { rows }; } };
}

test('feedStatusRank knows about skipped and does not file it with the problems', () => {
  // ⛔ The bug: an unrecognised status returns 1 (partial), which is 'degraded'.
  assert.notEqual(feedStatusRank('skipped'), feedStatusRank('definitely-not-a-status'));
  assert.ok(
    feedStatusRank('skipped') > feedStatusRank('success'),
    'a skip sorts after a success — it is not a result at all'
  );
});

test('a skipped feed does NOT make the pill degraded', async () => {
  const rows = KNOWN_FEEDS.map((f) => row(f, 'success'));
  rows[rows.findIndex((r) => r.feed_name === 'nvd')] = row('nvd', 'skipped');
  const pill = await getSyncPillStatus(poolWith(rows), { now: NOW });
  assert.equal(pill.state, 'ok');
  assert.equal(pill.ok, true);
  const nvd = pill.feeds.find((f) => f.feed === 'nvd');
  assert.equal(nvd.state, 'skipped', 'and it is reported as skipped, not as ok');
});

test('a skipped feed is never rendered as a success either', async () => {
  // ⛔ Excluded from the VERDICT is not the same as counted as healthy. An
  // operator must still be able to see that this feed did not run.
  const rows = KNOWN_FEEDS.map((f) => row(f, 'success'));
  rows[0] = row(KNOWN_FEEDS[0], 'skipped');
  const pill = await getSyncPillStatus(poolWith(rows), { now: NOW });
  assert.notEqual(pill.feeds[0].state, 'ok');
  assert.equal(pill.feeds[0].state, 'skipped');
});

test('a REAL degradation still shows through, beside a skip', async () => {
  // This is the live shape: nvd skipped because the hub delivered, while
  // fortinet_psirt is genuinely failing to ingest anything.
  const rows = KNOWN_FEEDS.map((f) => row(f, 'success'));
  rows[rows.findIndex((r) => r.feed_name === 'nvd')] = row('nvd', 'skipped');
  const fi = rows.findIndex((r) => r.feed_name === 'fortinet_psirt');
  if (fi >= 0) rows[fi] = row('fortinet_psirt', 'partial', { errors: 1 });
  const pill = await getSyncPillStatus(poolWith(rows), { now: NOW });
  assert.equal(pill.state, 'degraded', 'the skip must not mask a real problem');
  assert.match(pill.title, /Fortinet/i, 'and the pill names which feed is incomplete');
});

test('every feed skipped is NOT reported as healthy', async () => {
  // ⛔ THE DANGEROUS CASE. If every feed were skipped, excluding them all from
  // the verdict would leave the reduce() seed — 'ok' — and the product would
  // report itself green while collecting nothing at all.
  const rows = KNOWN_FEEDS.map((f) => row(f, 'skipped'));
  const pill = await getSyncPillStatus(poolWith(rows), { now: NOW });
  assert.notEqual(pill.state, 'ok', 'a fleet collecting nothing is never green');
  assert.equal(pill.ok, false);
});

test('a partial feed is still degraded — the skip change must not have widened', async () => {
  const rows = KNOWN_FEEDS.map((f) => row(f, 'success'));
  rows[0] = row(KNOWN_FEEDS[0], 'partial', { errors: 3 });
  const pill = await getSyncPillStatus(poolWith(rows), { now: NOW });
  assert.equal(pill.state, 'degraded');
});

test('an unknown status is still treated as a problem, not as a skip', async () => {
  // ⛔ Adding 'skipped' must not have opened a door for any unrecognised value
  // to escape the verdict. A status this app has never seen is not evidence
  // that things are fine.
  const rows = KNOWN_FEEDS.map((f) => row(f, 'success'));
  rows[0] = row(KNOWN_FEEDS[0], 'who-knows');
  const pill = await getSyncPillStatus(poolWith(rows), { now: NOW });
  assert.equal(pill.state, 'degraded');
});
