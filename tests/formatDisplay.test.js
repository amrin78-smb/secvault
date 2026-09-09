// tests/formatDisplay.test.js
//
// Presentation helpers. Small, but each one replaced a raw value the reader
// had to decode — and each has a "we don't know" case that must not render as
// a confident answer.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  timeAgo,
  absoluteUtc,
  titleCase,
  FEED_LABELS,
  feedStatusRank,
  newestFeedAt,
} = require('../lib/formatDisplay');

describe('timeAgo', () => {
  it('renders recent ages in the unit a reader thinks in', () => {
    const now = Date.now();
    assert.equal(timeAgo(new Date(now - 30 * 1000)), 'just now');
    assert.equal(timeAgo(new Date(now - 12 * 60 * 1000)), '12m ago');
    assert.equal(timeAgo(new Date(now - 3 * 3600 * 1000)), '3h ago');
    assert.equal(timeAgo(new Date(now - 2 * 86400 * 1000)), '2d ago');
  });

  it('⛔ returns null for absent/unparseable input, never a placeholder', () => {
    // The caller owns how absence reads — several sites have a load-bearing
    // "Never" or "—" branch that must keep winning.
    for (const v of [null, undefined, '', 'not-a-date', NaN]) {
      assert.equal(timeAgo(v), null, String(v));
    }
  });

  it('⛔ a future timestamp is named, not rendered as "just now"', () => {
    // Clock skew between a device and the collector is real. Reporting it as
    // 0 minutes ago would hide it.
    assert.equal(timeAgo(new Date(Date.now() + 60 * 60 * 1000)), 'in the future');
  });
});

describe('absoluteUtc', () => {
  it('keeps the existing UTC convention for the tooltip', () => {
    assert.equal(absoluteUtc('2026-09-09T06:11:00.000Z'), '2026-09-09 06:11 UTC');
  });
  it('returns null rather than an epoch for bad input', () => {
    assert.equal(absoluteUtc('nonsense'), null);
    assert.equal(absoluteUtc(null), null);
  });
});

describe('titleCase', () => {
  it('turns enum spellings into words', () => {
    assert.equal(titleCase('patch_now'), 'Patch Now');
    assert.equal(titleCase('block-url'), 'Block Url');
  });
  it('passes through non-strings untouched', () => {
    assert.equal(titleCase(null), null);
    assert.equal(titleCase(''), '');
  });
});

describe('feed status ordering', () => {
  it('sorts problems ahead of successes', () => {
    const rows = [
      { feed_name: 'kev', status: 'success' },
      { feed_name: 'nvd', status: 'partial' },
      { feed_name: 'x', status: 'failed' },
    ];
    const sorted = [...rows].sort((a, b) => feedStatusRank(a.status) - feedStatusRank(b.status));
    assert.deepEqual(sorted.map((r) => r.status), ['failed', 'partial', 'success']);
  });

  it('⛔ an UNRECOGNISED status sorts with the problems, not the successes', () => {
    // A status this app has never seen is not evidence that things are fine.
    assert.ok(feedStatusRank('who-knows') < feedStatusRank('success'));
  });

  it('names the feeds rather than showing slugs', () => {
    assert.equal(FEED_LABELS.nvd, 'NVD');
    assert.equal(FEED_LABELS.fortinet_psirt, 'Fortinet PSIRT');
  });
});

describe('newestFeedAt', () => {
  it('picks the latest completion and ignores unusable rows', () => {
    const got = newestFeedAt([
      { completed_at: '2026-09-09T06:00:00Z' },
      { completed_at: 'nonsense' },
      { started_at: '2026-09-09T06:11:00Z' },
      {},
    ]);
    assert.equal(got.toISOString(), '2026-09-09T06:11:00.000Z');
  });
  it('returns null when nothing is usable', () => {
    assert.equal(newestFeedAt([]), null);
    assert.equal(newestFeedAt([{}, { completed_at: null }]), null);
  });
});
