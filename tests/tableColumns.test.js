'use strict';

// lib/tableColumns.js + the /devices adoption — §10's column chooser and
// prioritised responsive columns.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { stripComments } = require('./stripComments');

const { resolveColumns, toggleColumn, priorityOf } = require('../lib/tableColumns');

const ROOT = path.join(__dirname, '..');
const PAGE = stripComments(fs.readFileSync(path.join(ROOT, 'app/(dashboard)/devices/page.js'), 'utf8'));
const CHOOSER = stripComments(fs.readFileSync(path.join(ROOT, 'components/ui/ColumnChooser.js'), 'utf8'));
const CSS = stripComments(fs.readFileSync(path.join(ROOT, 'app/globals.css'), 'utf8'));

const DEFS = [
  { key: 'name', label: 'Device', required: true, priority: 1 },
  { key: 'vendor', label: 'Vendor', priority: 3 },
  { key: 'score', label: 'Score', priority: 1 },
  { key: 'actions', label: 'Actions', required: true, priority: 1 },
];

describe('resolving a selection', () => {
  it('no value shows everything', () => {
    const { visible, hiddenCount } = resolveColumns(DEFS, '');
    assert.equal(visible.length, DEFS.length);
    assert.equal(hiddenCount, 0);
    assert.equal(resolveColumns(DEFS, undefined).visible.length, DEFS.length);
  });

  it('⛔ THE PARAMETER NAMES WHAT IS HIDDEN, so a NEW column appears by default', () => {
    // If it named the visible set, a column added later would be absent from
    // every saved view and every pasted URL — silently.
    const { visible } = resolveColumns(DEFS, 'vendor');
    assert.deepEqual(visible.map((c) => c.key), ['name', 'score', 'actions']);
    const grown = [...DEFS, { key: 'brand_new', label: 'New', priority: 2 }];
    assert.ok(
      resolveColumns(grown, 'vendor').visible.some((c) => c.key === 'brand_new'),
      'an old link must not hide a column that did not exist when it was written'
    );
  });

  it('⛔ A REQUIRED COLUMN CANNOT BE HIDDEN, however the URL was typed', () => {
    const { visible } = resolveColumns(DEFS, 'name,actions,vendor');
    assert.ok(visible.some((c) => c.key === 'name'), 'the identity column went');
    assert.ok(visible.some((c) => c.key === 'actions'), 'the actions column went');
    assert.equal(visible.some((c) => c.key === 'vendor'), false);
  });

  it('⛔ an unknown key is IGNORED, not an error and not a blank table', () => {
    // What a link from an older release looks like after a column is renamed.
    const { visible } = resolveColumns(DEFS, 'vendor,was_removed_in_v9');
    assert.deepEqual(visible.map((c) => c.key), ['name', 'score', 'actions']);
  });

  it('junk and whitespace are tolerated', () => {
    assert.equal(resolveColumns(DEFS, ' vendor , , score ').visible.length, 2);
    assert.equal(resolveColumns(null, 'vendor').visible.length, 0);
    assert.equal(resolveColumns(DEFS, 42).visible.length, DEFS.length);
  });

  it('⛔ a URL cannot hide an unbounded number of columns', () => {
    const many = Array.from({ length: 200 }, (_, i) => `k${i}`).join(',');
    assert.doesNotThrow(() => resolveColumns(DEFS, many));
  });
});

describe('toggling', () => {
  it('hides, then shows again', () => {
    const hidden = toggleColumn(DEFS, '', 'vendor');
    assert.equal(hidden, 'vendor');
    assert.equal(toggleColumn(DEFS, hidden, 'vendor'), '');
  });

  it('⛔ EMPTIES TO "", so the parameter leaves the URL entirely', () => {
    // A bare `cols=` in a pasted link reads as a setting somebody made.
    assert.equal(toggleColumn(DEFS, 'vendor', 'vendor'), '');
  });

  it('⛔ refuses a required column rather than silently doing nothing visible', () => {
    assert.equal(toggleColumn(DEFS, '', 'name'), '');
    assert.equal(toggleColumn(DEFS, 'vendor', 'actions'), 'vendor');
  });

  it('⛔ EMITS IN REGISTRY ORDER, so one selection is always one string', () => {
    // Otherwise two identical views save as two different query strings.
    const a = toggleColumn(DEFS, toggleColumn(DEFS, '', 'score'), 'vendor');
    const b = toggleColumn(DEFS, toggleColumn(DEFS, '', 'vendor'), 'score');
    assert.equal(a, b);
    assert.equal(a, 'vendor,score');
  });
});

describe('priority', () => {
  it('defaults to 1 — never drop — for an unclassified column', () => {
    assert.equal(priorityOf({}), 1);
    assert.equal(priorityOf({ priority: 0 }), 1);
    assert.equal(priorityOf({ priority: 'x' }), 1);
    assert.equal(priorityOf(null), 1);
  });

  it('clamps to the bands the stylesheet knows about', () => {
    assert.equal(priorityOf({ priority: 9 }), 4);
    assert.equal(priorityOf({ priority: 3 }), 3);
  });

  it('⛔ every band above 1 has a breakpoint, and they get NARROWER in order', () => {
    const widths = [];
    for (const n of [2, 3, 4]) {
      // ⛔ WHITESPACE-TOLERANT. The first draft required exactly one space
      // after the `)` and failed on a rule that differed only by alignment —
      // a guard that reports a missing breakpoint because of a space is one
      // that gets deleted rather than fixed.
      const re = new RegExp(`@media\\s*\\(max-width:\\s*(\\d+)px\\)\\s*\\{\\s*\\[data-col-priority="${n}"\\]`);
      const m = CSS.match(re);
      assert.ok(m, `priority ${n} has no breakpoint — it would never drop`);
      widths.push(Number(m[1]));
    }
    // 4 drops first (widest breakpoint), then 3, then 2.
    assert.ok(widths[2] > widths[1] && widths[1] > widths[0],
      `bands must drop in order, got ${JSON.stringify(widths)}`);
  });

  it('⛔ PRIORITY 1 IS NEVER HIDDEN BY ANY BREAKPOINT', () => {
    assert.equal(/\[data-col-priority="1"\][^{]*\{[^}]*display:\s*none/.test(CSS), false);
  });
});

describe('the /devices adoption', () => {
  it('⛔ the identity and action columns are required', () => {
    const block = PAGE.slice(PAGE.indexOf('const DEVICE_COLUMNS = ['), PAGE.indexOf('];', PAGE.indexOf('const DEVICE_COLUMNS = [')));
    for (const key of ['name', 'actions']) {
      const row = block.split('\n').find((l) => l.includes(`key: '${key}'`));
      assert.match(row, /required: true/, `${key} must not be hideable`);
    }
  });

  it('⛔ EVERY COLUMN IS GATED AND EVERY GATE NAMES A REGISTERED KEY', () => {
    const block = PAGE.slice(PAGE.indexOf('const DEVICE_COLUMNS = ['), PAGE.indexOf('];', PAGE.indexOf('const DEVICE_COLUMNS = [')));
    const keys = [...block.matchAll(/key: '([a-z_]+)'/g)].map((m) => m[1]);
    assert.equal(keys.length, 10, `expected ten columns, found ${keys.length}`);
    const gated = new Set([...PAGE.matchAll(/show\('([a-z_]+)'\)/g)].map((m) => m[1]));
    for (const k of keys) {
      assert.ok(gated.has(k), `${k} is in the registry but its cells are always rendered`);
    }
    for (const g of gated) {
      assert.ok(keys.includes(g), `show('${g}') names no registered column`);
    }
  });

  it('⛔ THE HEADER AND THE BODY ARE GATED THE SAME NUMBER OF TIMES', () => {
    // A gate on the <th> but not the <td> shifts every cell in the row one
    // column left — a table that is wrong rather than narrow.
    const counts = {};
    for (const m of PAGE.matchAll(/show\('([a-z_]+)'\)/g)) counts[m[1]] = (counts[m[1]] || 0) + 1;
    for (const [key, n] of Object.entries(counts)) {
      assert.equal(n, 2, `${key} is gated ${n} times — header and body must both be gated, exactly once each`);
    }
  });

  it('⛔ the colgroup is derived, so a hidden column leaves no width behind', () => {
    assert.match(PAGE, /deviceColumns\.filter\(\(c\) => !c\.hidden\)\.map\(\(c\) => \(\s*<col/);
    assert.equal(/<col style=\{\{ width: '\d+%' \}\} \/>/.test(PAGE), false,
      'a hand-written <col> list is a second list that must agree with the headers');
  });

  it('⛔ the chooser does not sit between the filter bar and the table', () => {
    const filters = PAGE.indexOf('<DeviceFilters');
    const table = PAGE.indexOf('<Table>');
    const between = PAGE.slice(PAGE.indexOf('/>', filters), table);
    assert.equal(/<ColumnChooser/.test(between), false,
      'that is ~40px of the 190px Phase 3 recovered, spent on a control most operators touch once');
    assert.match(PAGE, /<ColumnChooser basePath="\/devices" defs=\{DEVICE_COLUMNS\} \/>/);
  });
});

describe('the chooser', () => {
  it('⛔ WRITES THE URL THROUGH THE SHARED MERGE, never rebuilding it', () => {
    assert.match(CHOOSER, /mergeFilterQuery\(qs, \{ \[param\]: next \}/);
    assert.equal(/new URLSearchParams\(/.test(CHOOSER), false,
      'rebuilding the query discards the filters and the sort — the defect Phase 1 removed from four filter bars');
  });

  it('⛔ DOES NOT RESET `page`, because hiding a column changes no row', () => {
    assert.match(CHOOSER, /\{ reset: \[\] \}/);
  });

  it('⛔ a required column is shown and DISABLED, never omitted from the menu', () => {
    // An operator looking for "Device" and not finding it concludes the
    // control is broken; finding it greyed out says it cannot be turned off.
    assert.match(CHOOSER, /disabled=\{Boolean\(c\.required\)\}/);
    assert.match(CHOOSER, /always shown/);
  });

  it('⛔ the trigger states the hidden count', () => {
    assert.match(CHOOSER, /hiddenCount > 0 && <span className="colch-count">/);
  });

  it('is keyboard-dismissable and restores focus', () => {
    assert.match(CHOOSER, /e\.key === 'Escape'/);
    assert.match(CHOOSER, /btnRef\.current\?\.focus\(\)/);
    assert.match(CHOOSER, /aria-expanded=\{open\}/);
  });
});
