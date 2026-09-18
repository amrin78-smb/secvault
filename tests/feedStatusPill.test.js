'use strict';
// tests/feedStatusPill.test.js
//
// ⛔ THE HEADER PILL IS THE PRODUCT'S ONE STANDING STATEMENT ABOUT WHETHER ITS
// ADVISORY DATA IS COMPLETE, and every defect pinned here is the same family:
// SecVault knew one thing and said another. A pill that is wrong in the
// reassuring direction is worse than no pill, because the operator stops
// checking the page it sits on.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { getSyncPillStatus, severityOf, KNOWN_FEEDS } = require('../lib/feedStatus');

// The pill runs exactly one query (DISTINCT ON per feed). The stub answers it
// with whatever rows the case needs.
function stubPool(rows) {
  return { query: async () => ({ rows }) };
}

const row = (feed_name, status, extra = {}) => ({
  feed_name,
  status,
  started_at: new Date('2026-09-18T06:00:00Z'),
  finished_at: new Date('2026-09-18T06:01:00Z'),
  error_count: 0,
  ...extra,
});

const NOW = Date.parse('2026-09-18T07:00:00Z');

describe('every feed skipped is not "no feed has ever run"', () => {
  it('⛔ reports its own state, not the never-run one', async () => {
    const rows = KNOWN_FEEDS.map((f) => row(f, 'skipped'));
    const s = await getSyncPillStatus(stubPool(rows), { now: NOW });
    assert.equal(s.state, 'skipped');
    assert.equal(s.ok, false, 'nothing collected advisories — this is not an all-clear');
    // The old branch told the operator no feed had EVER completed a sync and
    // that every CVE count was empty for want of data. A skip is written BY a
    // cycle that ran, so both halves of that sentence were false.
    assert.doesNotMatch(s.title, /has ever completed/i);
    assert.doesNotMatch(s.title, /empty for want of data/i);
    assert.match(s.title, /skipped/i);
  });

  it('a genuinely empty log still reports NO SYNC YET', async () => {
    const s = await getSyncPillStatus(stubPool([]), { now: NOW });
    assert.equal(s.state, 'none');
    assert.equal(s.ok, false);
    assert.match(s.title, /has ever completed/i);
  });

  it('a never-run feed and a skipped one together still read as skipped', async () => {
    // Only cve_hub has a row, and it was skipped. Nothing was rated, but
    // something DID run and decide — which is the distinction being drawn.
    const s = await getSyncPillStatus(stubPool([row('cve_hub', 'skipped')]), { now: NOW });
    assert.equal(s.state, 'skipped');
  });
});

describe('a skip is excluded from the verdict but never from the evidence', () => {
  it('⛔ the OK title names the skipped feeds as well as the clean ones', async () => {
    // On the reference deployment NVD is skipped every cycle because the
    // central feed supplied the corpus. The title listed only the feeds that
    // ran, so the reader saw a list with NVD missing and no explanation — an
    // omission invites a worse conclusion than the truth.
    const s = await getSyncPillStatus(
      stubPool([row('cve_hub', 'success'), row('nvd', 'skipped')]),
      { now: NOW }
    );
    assert.equal(s.state, 'ok');
    assert.equal(s.ok, true);
    assert.match(s.title, /skipped/i);
    assert.match(s.title, /Vulnerability Database|NVD/i);
  });

  it('a skipped feed cannot turn the pill amber or red', async () => {
    const s = await getSyncPillStatus(
      stubPool([row('cve_hub', 'success'), row('nvd', 'skipped'), row('kev', 'success')]),
      { now: NOW }
    );
    assert.equal(s.state, 'ok');
  });

  it('a real failure still wins over a skip', async () => {
    const s = await getSyncPillStatus(
      stubPool([row('cve_hub', 'error'), row('nvd', 'skipped')]),
      { now: NOW }
    );
    assert.equal(s.state, 'error');
  });
});

describe('an unlisted state must not read as healthy', () => {
  it('⛔ severityOf ranks an unknown state WORSE than error, never undefined', () => {
    // The reduce compared STATE_SEVERITY[state] with `<`. For a state absent
    // from the table that is `undefined < n`, which is FALSE — so an unhandled
    // state left the accumulator on 'ok'. The filter above it and the severity
    // table were coupled by nothing but happening to agree.
    assert.equal(severityOf('ok'), 3);
    assert.equal(severityOf('error'), 0);
    assert.ok(severityOf('some-state-nobody-added-yet') < severityOf('error'));
    assert.ok(severityOf('skipped') < severityOf('error'));
    assert.ok(severityOf(undefined) < severityOf('error'));
  });
});

describe("a skip's recorded reason is not an error count", () => {
  it('⛔ the per-feed query zeroes error_count for a skipped row', () => {
    // logSkipped() writes the reason into `errors` because feed_sync_log has no
    // detail column, so jsonb_array_length reported 1 error for a feed that
    // worked exactly as designed. This is a SQL-shape pin: a stub pool cannot
    // exercise a CASE expression the database evaluates.
    const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'feedStatus.js'), 'utf8')
      .replace(/^\s*\/\/.*$/gm, '');
    assert.match(src, /CASE WHEN lower\(status\) = 'skipped' THEN 0/);
  });
});
