'use strict';
// Shared server-side pagination.
//
// Two properties carry the weight, and both are honesty rather than mechanics:
//
//   1. A PAGE NUMBER IS USER INPUT. It must always resolve to a usable page —
//      never NaN, never negative, never past the end — because an unvalidated
//      value flowing into LIMIT/OFFSET produces a blank table, and a blank
//      table is indistinguishable from "there is nothing here".
//   2. THE TOTAL MUST BE HONEST. A view showing its first fifty rows as though
//      they were the whole set is the same class of lie as a truncated search
//      result presented as complete.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  resolvePage, resolvePageSize, totalPages, pageWindow,
  buildPageHref, describeRange, paginateArray, MAX_PAGE_SIZE,
} = require('../lib/pagination');

describe('⛔ a page number is user input', () => {
  it('always resolves to a usable page', () => {
    for (const [raw, want] of [
      ['1', 1], ['7', 7], ['0', 1], ['-3', 1], ['abc', 1], ['', 1],
      [null, 1], [undefined, 1], ['2x', 2], [['4', '9'], 4],
    ]) {
      assert.equal(resolvePage(raw), want, `page=${JSON.stringify(raw)}`);
    }
  });

  it('clamps a page past the end to the LAST page, never an empty view', () => {
    // A bookmarked ?page=40 after rows were deleted must not render a blank
    // table that reads as "everything is gone".
    const w = pageWindow(40, 50, 120);
    assert.equal(w.page, 3);
    assert.equal(w.offset, 100);
  });

  it('caps page size so one URL cannot ask for everything', () => {
    assert.equal(resolvePageSize('999999', 50), MAX_PAGE_SIZE);
    assert.equal(resolvePageSize('abc', 50), 50);
    assert.equal(resolvePageSize('-1', 50), 50);
    assert.equal(resolvePageSize('25', 50), 25);
  });

  it('totalPages is never 0, so an empty list still reads "page 1 of 1"', () => {
    assert.equal(totalPages(0, 50), 1);
    assert.equal(totalPages(null, 50), 1);
    assert.equal(totalPages(NaN, 50), 1);
    assert.equal(totalPages(50, 50), 1);
    assert.equal(totalPages(51, 50), 2);
  });
});

describe('⛔ the total must be honest', () => {
  it('describes the real range, not the page contents', () => {
    assert.equal(describeRange(2, 50, 1522), '51–100 of 1,522');
    assert.equal(describeRange(1, 50, 12), '1–12 of 12');
  });

  it('⛔ returns null rather than inventing a count when total is unknown', () => {
    // "1–50 of 50" on an uncounted list would imply the first page is the whole
    // set. The component renders "total not counted" instead.
    for (const bad of [null, undefined, NaN, 'x']) {
      assert.equal(describeRange(1, 50, bad), null, JSON.stringify(bad));
    }
  });

  it('says "none" for a genuinely empty set', () => {
    assert.equal(describeRange(1, 50, 0), 'none');
  });

  it('does not run the range past the total on the last page', () => {
    assert.equal(describeRange(3, 50, 120), '101–120 of 120');
  });
});

describe('⛔ links preserve every other query param', () => {
  it('keeps the active filters when changing page', () => {
    // Losing the filter on "next" silently changes what you are reading
    // halfway through reading it.
    const href = buildPageHref('/alerts', { severity: 'high', device: 'abc', page: '2' }, { page: 3 });
    assert.match(href, /severity=high/);
    assert.match(href, /device=abc/);
    assert.match(href, /page=3/);
  });

  it('drops page=1 so the first page has a clean URL', () => {
    assert.equal(buildPageHref('/alerts', { page: '2' }, { page: null }), '/alerts');
  });

  it('ignores empty params rather than emitting page=&device=', () => {
    assert.equal(buildPageHref('/x', { a: '', b: null, c: undefined }, {}), '/x');
  });

  it('takes the first value of a repeated param', () => {
    assert.match(buildPageHref('/x', { tab: ['a', 'b'] }, {}), /tab=a/);
  });
});

describe('paginateArray, for genuinely computed lists', () => {
  const items = Array.from({ length: 120 }, (_, i) => i);

  it('slices the right window and reports the real total', () => {
    const r = paginateArray(items, 2, 50);
    assert.equal(r.rows.length, 50);
    assert.equal(r.rows[0], 50);
    assert.equal(r.total, 120);
    assert.equal(r.totalPages, 3);
  });

  it('clamps a page past the end instead of returning nothing', () => {
    const r = paginateArray(items, 99, 50);
    assert.equal(r.page, 3);
    assert.equal(r.rows.length, 20);
  });

  it('handles an empty or junk list without throwing', () => {
    for (const bad of [[], null, undefined, 'nope']) {
      const r = paginateArray(bad, 1, 50);
      assert.deepEqual(r.rows, []);
      assert.equal(r.total, 0);
      assert.equal(r.totalPages, 1);
    }
  });
});
