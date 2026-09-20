'use strict';
// tests/feedBlocked.test.js
//
// ⛔ `blocked` — the feed RAN and the PUBLISHER REFUSED IT.
//
// FortiGuard answers every advisory page with a Cloudflare JavaScript
// interstitial. Measured byte-identical (19,751 bytes) from the SecVault box, an
// office connection and a Netlify function, so it is neither IP reputation nor a
// user-agent check, and relocating the fetch cannot fix it. The run therefore
// reported `partial` every six hours, for ever — a permanent amber chip for a
// system behaving exactly as designed, which is how an operator learns to ignore
// the chip that matters.
//
// ⛔ IT IS NOT A SKIP, AND THE DISTINCTION IS THE POINT. `skipped` means SecVault
// DECIDED not to run the feed. This one ran and was turned away. Collapsing them
// would claim we chose not to collect, which is false.
//
// ⛔ AND IT IS NOT SILENT. Excluded from the verdict, never from the evidence.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { isPublisherBlocked } = require('../lib/feeds/fortinet');
const { feedStatusRank } = require('../lib/formatDisplay');
const { feedState, getSyncPillStatus, severityOf } = require('../lib/feedStatus');

const base = {
  rssItemCount: 50,
  resolvedFromPage: 0,
  pageFailureReasons: { bot_challenge: 45 },
  upsertErrors: [],
};

describe('⛔ isPublisherBlocked is narrow on purpose', () => {
  it('true when every page failure was the challenge and nothing resolved', () => {
    assert.equal(isPublisherBlocked(base), true);
  });

  it('FALSE the moment one advisory page resolves — that run did useful work', () => {
    // Self-clearing: the day FortiGuard drops the challenge, or credentials
    // arrive, the feed leaves this state on its own with no code change.
    assert.equal(isPublisherBlocked({ ...base, resolvedFromPage: 1 }), false);
  });

  it('FALSE when an upsert failed — a real fault must not hide behind the block', () => {
    assert.equal(
      isPublisherBlocked({ ...base, upsertErrors: [{ cve_id: 'CVE-1', message: 'boom' }] }),
      false
    );
  });

  it('FALSE when any other failure reason is mixed in', () => {
    assert.equal(
      isPublisherBlocked({ ...base, pageFailureReasons: { bot_challenge: 40, page_empty: 5 } }),
      false
    );
  });

  it('FALSE when the RSS itself failed — that is an ordinary outage', () => {
    assert.equal(isPublisherBlocked({ ...base, rssItemCount: 0 }), false);
  });

  it('FALSE when there were no page failures at all', () => {
    assert.equal(isPublisherBlocked({ ...base, pageFailureReasons: {} }), false);
  });
});

describe('⛔ the status is ranked, or it sorts with the failures', () => {
  it('blocked does not rank with the problems', () => {
    // An unlisted status falls through to rank 1, which IS the permanent-amber
    // outcome this state exists to remove. That is how `skipped` shipped broken.
    assert.ok(feedStatusRank('blocked') > feedStatusRank('partial'));
    assert.ok(feedStatusRank('blocked') > feedStatusRank('success'));
    assert.notEqual(feedStatusRank('blocked'), feedStatusRank('a-status-nobody-added'));
  });

  it('feedState maps it to its own state, not to degraded', () => {
    const row = { status: 'blocked', started_at: new Date(), finished_at: new Date() };
    assert.equal(feedState(row, Date.now()), 'blocked');
  });

  it('and severityOf still treats an UNLISTED state as worse than error', () => {
    // blocked is deliberately absent from STATE_SEVERITY, like skipped and
    // missing — the `rated` filter removes it before the reduction. This pins
    // that the fail-safe behind that filter is intact.
    assert.ok(severityOf('blocked') < severityOf('error'));
  });
});

describe('⛔ excluded from the verdict, never from the evidence', () => {
  const stub = (rows) => ({ query: async () => ({ rows }) });
  const row = (feed_name, status) => ({
    feed_name, status,
    started_at: new Date('2026-09-20T06:00:00Z'),
    finished_at: new Date('2026-09-20T06:01:00Z'),
    error_count: 0,
  });
  const NOW = Date.parse('2026-09-20T07:00:00Z');

  it('a blocked feed cannot turn the pill amber', () => {
    const s = getSyncPillStatus(stub([row('cve_hub', 'success'), row('fortinet_psirt', 'blocked')]), { now: NOW });
    return s.then((v) => {
      assert.equal(v.state, 'ok');
      assert.equal(v.ok, true);
    });
  });

  it('but the OK title names it and says who refused', async () => {
    const v = await getSyncPillStatus(
      stub([row('cve_hub', 'success'), row('fortinet_psirt', 'blocked')]),
      { now: NOW }
    );
    assert.match(v.title, /Refused by the publisher/i);
    assert.match(v.title, /Fortinet/i);
    // It must also say the data is still covered, or the reader is left to guess.
    assert.match(v.title, /supplied by the other feeds/i);
  });

  it('a real failure still outranks a block', async () => {
    const v = await getSyncPillStatus(
      stub([row('cve_hub', 'error'), row('fortinet_psirt', 'blocked')]),
      { now: NOW }
    );
    assert.equal(v.state, 'error');
  });

  it('⛔ EVERY feed blocked is NOT an all-clear', async () => {
    // The dangerous corner: excluding blocked from the reduction must not leave
    // a fleet collecting nothing reporting green.
    const v = await getSyncPillStatus(
      stub([row('cve_hub', 'blocked'), row('nvd', 'blocked')]),
      { now: NOW }
    );
    assert.equal(v.state, 'blocked');
    assert.equal(v.ok, false);
    assert.match(v.title, /nothing collected advisories/i);
  });
});

describe('⛔ the renderers do not paint it as a fault', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8').replace(/\r\n/g, '\n');

  it('the dashboard badge maps blocked to muted', () => {
    const src = read('app/(dashboard)/page.js');
    assert.match(src, /if \(status === 'blocked'\) return 'muted';/);
  });

  it('the Advisories tab does not fall through to the danger colour', () => {
    const src = read('components/vulnerability/AdvisoriesTab.js');
    assert.match(src, /entry\.status === 'skipped' \|\| entry\.status === 'blocked'/);
  });

  it('the header pill has a hueless tone for it', () => {
    assert.match(read('components/layout/Header.js'), /PILL_TONE\.blocked = /);
  });

  it('the customer PDF counts it as a completed cycle', () => {
    // Otherwise the report tells the customer in red that the feed has NEVER
    // SUCCEEDED and its advisories are absent — both false.
    const src = read('lib/reports/vulnerabilityPosture.js');
    assert.match(src, /FILTER \(WHERE status IN \('success', 'skipped', 'blocked'\)\)/);
  });
});
