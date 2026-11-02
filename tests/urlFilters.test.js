'use strict';

// tests/urlFilters.test.js
//
// The URL is the filter state, and this is the arithmetic on it.
//
// ⛔ THE BUG CLASS THIS EXISTS TO END IS ALREADY RECORDED IN THE CODEBASE.
// `components/exposure/ExposureFilters.js` carried a comment admitting that
// choosing a firewall silently reset a reader who had selected 200 rows back
// to 50 — because that copy REBUILT the query from the two parameters it knew
// about instead of merging into the one that existed. Its own header had
// claimed everything but `page` was carried over; the comment ended "and the
// code carried nothing". Four pages each had their own copy of this and each
// got a different subset of it right.
//
// So the assertions below are mostly about MERGING: a filter control knows
// about its own parameters and must not have an opinion about anybody else's.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { stripComments } = require('./stripComments');
const {
  NON_FILTER_PARAMS,
  mergeFilterQuery,
  filterHref,
  clearedFilterQuery,
  hasActiveFilters,
  activeFilterChips,
} = require('../lib/urlFilters');

const ROOT = path.join(__dirname, '..');

describe('⛔ MERGE, NEVER REBUILD', () => {
  test('a parameter this control knows nothing about SURVIVES', () => {
    // The exact regression ExposureFilters documented against itself.
    assert.equal(
      mergeFilterQuery('device_id=a&limit=200', { device_id: 'b' }),
      'device_id=b&limit=200',
    );
  });

  test('every unrelated parameter survives, not just the one we remembered', () => {
    const out = new URLSearchParams(
      mergeFilterQuery('vendor=fortinet&limit=200&tab=rules&sort=name&dir=asc', { vendor: 'paloalto' }),
    );
    assert.equal(out.get('vendor'), 'paloalto');
    assert.equal(out.get('limit'), '200');
    assert.equal(out.get('tab'), 'rules');
    assert.equal(out.get('sort'), 'name');
    assert.equal(out.get('dir'), 'asc');
  });

  test('⛔ AN EMPTY VALUE DELETES RATHER THAN BEING WRITTEN THROUGH', () => {
    // "All" in a select is the ABSENCE of a filter, not a filter whose value
    // is nothing. `?vendor=` is a filter the server then has to decide how to
    // read, and the two sides will eventually disagree.
    assert.equal(mergeFilterQuery('vendor=x&risk=high', { vendor: '' }), 'risk=high');
    assert.equal(mergeFilterQuery('vendor=x', { vendor: null }), '');
    assert.equal(mergeFilterQuery('vendor=x', { vendor: undefined }), '');
  });

  test('a falsy but REAL value is kept', () => {
    // 0 and 'false' are values somebody chose. Only '', null and undefined mean
    // "no filter" — collapsing the two is how a legitimate 0 disappears.
    assert.equal(mergeFilterQuery('', { threshold: 0 }), 'threshold=0');
    assert.equal(mergeFilterQuery('', { enabled: false }), 'enabled=false');
  });

  test('an empty starting query is fine, in every shape', () => {
    for (const start of ['', null, undefined, new URLSearchParams()]) {
      assert.equal(mergeFilterQuery(start, { a: '1' }), 'a=1');
    }
  });
});

describe('⛔ `page` RESETS, because a stale page reads as an empty result', () => {
  test('any filter change drops the page number', () => {
    // A page number from a larger result set lands past the end of a smaller
    // one and renders an empty table — which on /exposure reads as "no
    // exposure found" rather than "wrong page".
    assert.equal(mergeFilterQuery('vendor=x&page=7', { vendor: 'y' }), 'vendor=y');
  });

  test('…but `limit` is NOT a page number and is kept', () => {
    assert.equal(mergeFilterQuery('page=7&limit=200', { vendor: 'y' }), 'limit=200&vendor=y');
  });

  test('an EXPLICIT page survives, so pagination itself still works', () => {
    // The reset must not make the control that sets a page unable to set one.
    assert.equal(mergeFilterQuery('vendor=x&page=1', { page: '3' }), 'vendor=x&page=3');
  });

  test('a caller can opt out of the reset entirely', () => {
    assert.equal(mergeFilterQuery('page=7', { vendor: 'y' }, { reset: [] }), 'page=7&vendor=y');
  });
});

describe('⛔ "Clear filters" clears FILTERS', () => {
  test('it keeps the tab you are on and the rows you chose', () => {
    // Three of the four hand-rolled copies pushed a bare path here, which threw
    // away state the operator deliberately set and never asked to lose.
    assert.equal(
      clearedFilterQuery('vendor=x&risk=high&limit=200&tab=rules'),
      'limit=200&tab=rules',
    );
  });

  test('it drops the page number too', () => {
    assert.equal(clearedFilterQuery('vendor=x&page=4&limit=50'), 'limit=50');
  });

  test('clearing nothing yields nothing', () => {
    assert.equal(clearedFilterQuery(''), '');
  });

  test('the non-filter list covers the parameters that are not filters', () => {
    // ⛔ `tab`/`vtab`/`view` are in here because a chip that removes them is a
    // chip that NAVIGATES SOMEWHERE ELSE while appearing to widen a result set.
    for (const k of ['page', 'limit', 'tab', 'vtab', 'view', 'sort', 'dir']) {
      assert.ok(NON_FILTER_PARAMS.has(k), `${k} would render as a removable filter chip`);
    }
  });
});

describe('hasActiveFilters distinguishes a narrowed table from a short one', () => {
  test('pagination state alone is not a filter', () => {
    assert.equal(hasActiveFilters('page=3&limit=200&tab=rules'), false);
  });
  test('a real filter is', () => {
    assert.equal(hasActiveFilters('page=3&vendor=fortinet'), true);
  });
  test('an empty value is not', () => {
    assert.equal(hasActiveFilters('vendor='), false);
  });
});

describe('⛔ EVERY APPLIED FILTER GETS A CHIP, INCLUDING ONE WE CANNOT LABEL', () => {
  const defs = [
    { key: 'vendor', label: 'Vendor', options: [{ value: 'fortinet', label: 'Fortinet' }] },
    { key: 'support', label: 'Support', options: [{ value: 'expired', label: 'Lapsed licence' }] },
  ];

  test('a chip reads as its control did, not as the URL does', () => {
    const [chip] = activeFilterChips('support=expired', defs);
    assert.equal(chip.label, 'Support');
    assert.equal(chip.valueLabel, 'Lapsed licence');
    assert.equal(chip.value, 'expired', 'the raw value is what removes it');
    assert.equal(chip.known, true);
  });

  test('⛔ an UNDEFINED filter is shown under its raw key, never skipped', () => {
    // Skipping it hides an active filter from the one row whose job is to list
    // the active filters, and the operator then cannot work out why the table
    // is short. "Unknown is not nothing", pointed at the UI's own state.
    const chips = activeFilterChips('vendor=fortinet&mystery=42', defs);
    const mystery = chips.find((c) => c.key === 'mystery');
    assert.ok(mystery, 'an unrecognised filter vanished from the applied list');
    assert.equal(mystery.label, 'mystery');
    assert.equal(mystery.valueLabel, '42');
    assert.equal(mystery.known, false, 'it must be MARKED as unlabelled, not passed off as known');
  });

  test('a value with no matching option still shows its raw value', () => {
    const [chip] = activeFilterChips('vendor=sangfor', defs);
    assert.equal(chip.valueLabel, 'sangfor');
  });

  test('pagination and tab state never become chips', () => {
    assert.deepEqual(activeFilterChips('page=2&limit=50&tab=x&view=map', defs), []);
  });

  test('no defs at all still lists everything applied', () => {
    const chips = activeFilterChips('a=1&b=2', undefined);
    assert.deepEqual(chips.map((c) => c.key), ['a', 'b']);
    assert.ok(chips.every((c) => c.known === false));
  });
});

describe('filterHref', () => {
  test('omits the ? when nothing is left', () => {
    assert.equal(filterHref('/devices', 'vendor=x', { vendor: '' }), '/devices');
  });
  test('includes it otherwise', () => {
    assert.equal(filterHref('/devices', '', { vendor: 'x' }), '/devices?vendor=x');
  });
});

describe('⛔ the four hand-rolled copies are gone, not merely bypassed', () => {
  // ⛔ COMMENTS STRIPPED, AND THE FIRST DRAFT PROVED WHY AGAIN. The
  // `currentLimit` assertion below failed on the COMMENT in exposure/page.js
  // that explains why the prop was removed. Prose read as code — the same
  // defect that made the device-scope check believe lib/notificationChannels.js
  // held device data because a comment said it did not.
  const read = (p) => stripComments(fs.readFileSync(path.join(ROOT, p), 'utf8'));

  test('the adopting filter bars push through the shared helper', () => {
    for (const p of [
      'components/devices/DeviceFilters.js',
      'components/alerts/AlertsFilters.js',
      'components/exposure/ExposureFilters.js',
      // ⛔ THE FOURTH AND LAST, adopted in v2.220.0. Phase 1 left it
      // deliberately because /vpn was Phase 5's work; it had all three of the
      // gaps the other three had, and its `set()` carried a comment
      // explaining that it had to RE-ADD `vtab` by hand or narrowing by
      // country would bounce the reader back to Fleet Status — which is what
      // a near-miss on the merge-never-rebuild rule looks like.
      'components/vpn/VpnThreatFilters.js',
    ]) {
      const src = read(p);
      assert.match(src, /from '\.\.\/ui\/FilterBar'/, `${p} does not use the shared bar`);
      // ⛔ The real assertion: no local query assembly survives beside it. A
      // file that imports the helper AND still builds its own URLSearchParams
      // has two ways to navigate, and only one of them merges.
      assert.ok(!/new URLSearchParams\(/.test(src),
        `${p} still assembles its own query — that is the rebuild bug`);
      assert.ok(!/router\.push\(/.test(src),
        `${p} still pushes directly, bypassing the merge`);
    }
  });

  test('⛔ ExposureFilters no longer needs telling about rows-per-page', () => {
    // The parameter it used to carry BY HAND is now carried because nothing
    // deletes it. A parameter carried by hand is one the next parameter's
    // author forgets.
    const src = read('components/exposure/ExposureFilters.js');
    assert.ok(!/currentLimit/.test(src), 'the hand-carried limit prop is back');
    assert.ok(!/currentLimit/.test(read('app/(dashboard)/exposure/page.js')),
      'the call site still passes a prop the component no longer takes');
  });

  test('no filter control hardcodes its own box', () => {
    // ⛔ ExposureFilters styled its <select> with a hardcoded padding and
    // border, opting that one control out of the density and corner settings
    // every control around it honours — the same failure mode CLAUDE.md
    // records for a table cell that hardcodes `padding: 12px 16px`.
    const src = read('components/exposure/ExposureFilters.js');
    assert.ok(!/borderRadius:\s*'var\(--radius-sm\)'/.test(src), 'hand-rolled control box is back');
    assert.match(src, /className="select filter-control"/);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// ⛔ A WINDOW IS NOT A FILTER
// ────────────────────────────────────────────────────────────────────────────

describe('the detection window survives "Clear filters"', () => {
  // ⛔ MEASURED AS A REAL REGRESSION DURING v2.220.0. With `dHours` absent
  // from NON_FILTER_PARAMS, adopting the shared bar on /vpn made "Clear
  // filters" drop `dHours=168` — silently returning a 7-day investigation to
  // the 24-hour default and changing every number on the page, while
  // appearing to do nothing but remove a chip.
  const defs = [
    { key: 'dq', label: 'Search' },
    { key: 'dCountry', label: 'Country' },
    { key: 'dSeverity', label: 'Severity' },
  ];
  const qs = 'vtab=detections&dHours=168&dCountry=Poland';

  test('clearing filters KEEPS the window and the tab', () => {
    const cleared = clearedFilterQuery(qs);
    assert.match(cleared, /dHours=168/, 'the window is what the detections are computed over');
    assert.match(cleared, /vtab=detections/);
    assert.ok(!/dCountry/.test(cleared), 'a real filter must still clear');
  });

  test('⛔ the window never renders as a chip', () => {
    const keys = activeFilterChips(qs, defs).map((c) => c.key);
    assert.deepEqual(keys, ['dCountry'],
      'widening the window is asking a different question, not clearing a filter');
  });

  test('⛔ and it is not in the VPN bar\u2019s defs, so nothing can chip it by accident', () => {
    const src = stripComments(
      fs.readFileSync(path.join(ROOT, 'components/vpn/VpnThreatFilters.js'), 'utf8')
    );
    const defsBlock = src.slice(src.indexOf('const DEFS = ['), src.indexOf('];', src.indexOf('const DEFS = [')));
    assert.ok(!/dHours/.test(defsBlock), 'dHours must stay a control, never a filter definition');
    assert.match(src, /param="dHours"/, 'but the control itself must still be rendered');
  });
});

describe('a column selection is not a filter either', () => {
  // ⛔ THE SECOND INSTANCE OF THE SAME MISTAKE IN TWO RELEASES. `dHours`
  // was the first; `cols` arrived with the column chooser and rendered as
  // "cols: ha,vendor,rules ×" — a chip meaningless to a reader, which
  // "Clear filters" would also have used to silently restore three columns
  // the operator had deliberately hidden.
  const defs = [{ key: 'vendor', label: 'Vendor' }, { key: 'risk', label: 'Risk' }];
  const qs = 'vendor=fortinet&cols=ha,vendor,rules&sort=score';

  test('it never renders as a chip', () => {
    assert.deepEqual(activeFilterChips(qs, defs).map((c) => c.key), ['vendor']);
  });

  test('clearing filters KEEPS the columns and the sort', () => {
    const cleared = clearedFilterQuery(qs);
    assert.match(cleared, /cols=ha%2Cvendor%2Crules|cols=ha,vendor,rules/);
    assert.match(cleared, /sort=score/);
    assert.ok(!/vendor=fortinet/.test(cleared));
  });

  test('⛔ a selection alone does not make the page look filtered', () => {
    assert.equal(hasActiveFilters('cols=ha&sort=score'), false,
      'a "Clear filters" link over a table nobody filtered is a control that does nothing');
  });
});
