'use strict';

// /devices — the compact summary strip and the sortable table headers.
//
// ⛔ THIS SUITE PINS TWO THINGS THAT WENT WRONG WHILE THE CHANGE WAS BEING
// MADE, and both were the kind that ship green:
//   1. A column header wired to a sort key that sorts by something ELSE
//      (Support was briefly wired to `site`). The fleet reorders, the header
//      announces the wrong reason, and a screen reader is told so too.
//   2. A CVE figure rendering 0 over a fleet with no completed assessment.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { SORT_OPTIONS, SORT_DIRECTION } = require('../lib/engines/deviceInventory');

const PAGE = fs.readFileSync(
  path.join(__dirname, '..', 'app', '(dashboard)', 'devices', 'page.js'), 'utf8'
);
const STRIP = fs.readFileSync(
  path.join(__dirname, '..', 'components', 'devices', 'InventorySummaryStrip.js'), 'utf8'
);

// Comments stripped before any source scan, through the SHARED helper.
//
// ⛔ FOUR GUARDS IN THIS REPO HAVE NOW MATCHED THEIR OWN EXPLANATORY PROSE,
// and the comments here describe exactly the patterns being searched for — so
// scanning the raw file would be certain to do it a fifth time.
//
// ⛔ AND THE FIRST DRAFT OF THIS FILE ROLLED ITS OWN STRIPPER IN THE ONE ORDER
// tests/stripOrder.test.js EXISTS TO FORBID: block comments before line
// comments, which lets a `/*` inside a `//` comment open a phantom block that
// eats everything to the next real `*/`. It was caught by that guard-on-guards
// within minutes, which is the whole argument for having one.
const { stripComments } = require('./stripComments');
const strip = (s) => stripComments(s).replace(/\{\s*\}/g, '');
const PAGE_CODE = strip(PAGE);
const STRIP_CODE = strip(STRIP);

describe('the table comes above the fold', () => {
  it('⛔ THE SEVEN-TILE GRID IS GONE AND THE COMPONENT WITH IT', () => {
    assert.equal(
      fs.existsSync(path.join(__dirname, '..', 'components', 'devices', 'DeviceInventoryTiles.js')),
      false,
      'an orphaned component is dead code; its reasoning moved into InventorySummaryStrip.js'
    );
    assert.equal(/DeviceInventoryTiles/.test(PAGE_CODE), false);
    assert.match(PAGE_CODE, /<InventorySummaryStrip tiles=\{tiles\} \/>/);
  });

  it('⛔ THE STRIP IS ONE SCROLLING ROW, not a grid that can wrap', () => {
    assert.match(STRIP_CODE, /className="fact-strip"/);
    assert.equal(/gridTemplateColumns/.test(STRIP_CODE), false,
      'the old grid wrapped 6+1 at 1440 and orphaned the seventh tile');
    const css = strip(fs.readFileSync(path.join(__dirname, '..', 'app', 'globals.css'), 'utf8'));
    const i = css.indexOf('.fact-strip {');
    const block = css.slice(i, css.indexOf('}', i));
    assert.match(block, /overflow-x:\s*auto/);
    assert.equal(/flex-wrap/.test(block), false);
  });

  it('⛔ THE SEPARATE "Sort by:" ROW IS GONE', () => {
    assert.equal(/Sort by:/.test(PAGE_CODE), false,
      'five link names that had to be matched by eye to five of the ten headings beneath them');
    assert.equal(/function sortLink\(/.test(PAGE_CODE), false);
  });

  it('⛔ nothing else was inserted between the filter bar and the table', () => {
    const filters = PAGE_CODE.indexOf('<DeviceFilters');
    const table = PAGE_CODE.indexOf('<Table>');
    assert.ok(filters > -1 && table > filters);
    const between = PAGE_CODE.slice(PAGE_CODE.indexOf('/>', filters), table);
    // Only the empty-state ternary may sit here.
    assert.equal(
      /<(div|Card|StatCard|section)\b/.test(between), false,
      `an element between the filter bar and the table pushes the rows down again: ${between.slice(0, 200)}`
    );
  });
});

describe('a sortable header states the sort it actually performs', () => {
  // Every sortKey the page hands to SortableTh.
  const used = [...PAGE_CODE.matchAll(/sortKey="([a-z_]+)"/g)].map((m) => m[1]);

  it('⛔ EVERY sortKey IS A REAL ENGINE SORT KEY', () => {
    assert.ok(used.length >= 5, `expected several sortable columns, found ${used.length}`);
    for (const k of used) {
      assert.ok(SORT_OPTIONS[k], `${k} is not a sort the engine performs`);
    }
  });

  it('⛔ EVERY sortKey HAS A DECLARED DIRECTION, because aria-sort announces it', () => {
    for (const k of used) {
      assert.ok(
        SORT_DIRECTION[k] === 'ascending' || SORT_DIRECTION[k] === 'descending',
        `${k}: aria-sort would announce "other", which tells a screen-reader user nothing`
      );
    }
  });

  it('⛔ EVERY SORT KEY THE ENGINE OFFERS HAS A DIRECTION, not just the used ones', () => {
    for (const k of Object.keys(SORT_OPTIONS)) {
      assert.ok(SORT_DIRECTION[k], `${k} is sortable with no declared direction`);
    }
  });

  it('⛔ THE COLUMN LABEL MATCHES THE KEY IT SORTS BY', () => {
    // The live bug: `Support` was wired to sortKey="site". The fleet would
    // reorder by site while the header said it had sorted by support expiry.
    // ⛔ MATCHED ON THE WHOLE ELEMENT, NOT ON PROP ORDER. This used to require
    // `label` to follow `sortKey` immediately, so a future
    // `<SortableTh sortKey="site" searchParams={…} label="Support" />` would
    // produce NO pair at all and the EXPECTED check below would silently stop
    // firing for that column — a guard written for exactly that bug, disarmed
    // by reformatting. All six are covered either way today; the point is that
    // they stay covered.
    const elements = [...PAGE_CODE.matchAll(/<SortableTh\b[\s\S]*?\/>/g)].map((m) => m[0]);
    assert.ok(elements.length > 0, 'found no SortableTh elements in the page');
    const pairs = elements.map((el) => {
      const k = el.match(/sortKey="([a-z_]+)"/);
      const l = el.match(/label="([^"]+)"/);
      assert.ok(k, `a SortableTh has no sortKey: ${el.slice(0, 80)}`);
      assert.ok(l, `a SortableTh has no label: ${el.slice(0, 80)}`);
      return { key: k[1], label: l[1] };
    });
    const EXPECTED = {
      name: 'Device', vendor: 'Vendor', score: 'Score',
      rules: 'Rules', cve_count: 'CVEs', last_collected: 'Collected',
    };
    // ⛔ EVERY EXPECTED COLUMN MUST ACTUALLY HAVE BEEN FOUND, or the loop below
    // is vacuous over a list the regex failed to build.
    for (const key of Object.keys(EXPECTED)) {
      assert.ok(pairs.some((x) => x.key === key), `no SortableTh found for "${key}"`);
    }
    for (const p of pairs) {
      assert.equal(p.label, EXPECTED[p.key],
        `${p.key} is labelled "${p.label}" — a header that names a different fact than it orders by `
        + 'is a confident wrong answer about the order on screen');
    }
  });

  it('⛔ Support is NOT sortable and is not faked as such', () => {
    assert.equal(used.includes('site'), false,
      'site is a real sort key and Support is a real column; pairing them sorts by the wrong thing');
    // ⛔ The MARKUP moved (the cell is wrapped in the column gate now) but
    // the invariant did not: Support renders a plain <th>, never a
    // SortableTh. Asserted on the element rather than on its formatting.
    assert.match(PAGE_CODE, /show\('support'\) && \(\s*<th/,
      'Support must render a plain header, not a sortable one');
    assert.match(PAGE_CODE, /title="Support contract expiry/);
  });

  it('⛔ aria-sort is on the <th> and is "none" when inactive', () => {
    const fn = PAGE_CODE.slice(PAGE_CODE.indexOf('function SortableTh('));
    const body = fn.slice(0, fn.indexOf('\n}'));
    assert.match(body, /<th\n?\s*aria-sort=\{active \? SORT_DIRECTION\[sortKey\][^}]*: 'none'\}/);
  });

  it('⛔ the arrow glyph is aria-hidden — aria-sort is the answer, not the arrow', () => {
    const fn = PAGE_CODE.slice(PAGE_CODE.indexOf('function SortableTh('));
    const body = fn.slice(0, fn.indexOf('\n}'));
    assert.match(body, /aria-hidden="true" className="th-sort-glyph"/);
  });

  it('⛔ the ACTIVE header is not a link, because clicking it does nothing', () => {
    const fn = PAGE_CODE.slice(PAGE_CODE.indexOf('function SortableTh('));
    const body = fn.slice(0, fn.indexOf('\n}'));
    assert.match(body, /\{active \? \(\s*<span className="th-sort" data-active="">/,
      'there is no direction toggle, so an active header that looks clickable lies');
  });

  it('⛔ a sort link PRESERVES the active filters', () => {
    assert.match(
      PAGE_CODE,
      /href=\{buildDevicesHref\(searchParams, \{ sort: sortKey, confirmDelete: null \}\)\}/,
      'sorting used to be able to discard the operator\u2019s filters'
    );
  });

  it('⛔ the active header is separated by WEIGHT, not by colour alone', () => {
    const css = strip(fs.readFileSync(path.join(__dirname, '..', 'app', 'globals.css'), 'utf8'));
    const i = css.indexOf('.th-sort[data-active] {');
    const block = css.slice(i, css.indexOf('}', i));
    assert.match(block, /font-weight:\s*700/);
  });
});

describe('a fleet figure over unassessed assets is not a zero', () => {
  // The strip is a server component, so it is asserted through its source. Its
  // decisions are simple predicates and each one is named here.
  it('⛔ BOTH CVE FIGURES ARE GATED ON THE SAME COVERAGE TEST', () => {
    assert.match(STRIP_CODE, /const cveMeasured = total > 0 && cveNotAssessed < total;/);
    const patch = STRIP_CODE.slice(STRIP_CODE.indexOf('label="Patch now"'));
    assert.match(patch.slice(0, 300), /measured=\{cveMeasured\}/);
    const crit = STRIP_CODE.slice(STRIP_CODE.indexOf('label="Critical CVEs"'));
    assert.match(crit.slice(0, 300), /measured=\{cveMeasured\}/,
      'stating the gap on only one of two sums invites the reader to treat the other as complete');
  });

  it('⛔ `measured` IS NEVER DERIVED FROM value > 0', () => {
    const fn = STRIP_CODE.slice(STRIP_CODE.indexOf('function Fact('), STRIP_CODE.indexOf('export default'));
    assert.match(fn, /measured = true/, 'it is a parameter');
    assert.equal(
      /measured\s*=\s*[^;]*value\s*[>!=]/.test(fn), false,
      'deriving it makes every genuine zero indistinguishable from an absent measurement'
    );
  });

  it('⛔ an unmeasured fact is a hueless em-dash with its reason on hover', () => {
    const fn = STRIP_CODE.slice(STRIP_CODE.indexOf('function Fact('), STRIP_CODE.indexOf('export default'));
    const branch = fn.slice(fn.indexOf('if (!measured)'), fn.indexOf('const hot'));
    assert.match(branch, /var\(--unmeasured\)/);
    assert.match(branch, /<strong>—<\/strong>/);
    assert.match(branch, /title=\{reason \|\| undefined\}/);
    assert.equal(/tone/.test(branch), false);
  });

  it('⛔ A PARTIAL-COVERAGE NOTE IS INLINE, NOT HOVER-ONLY, AND CARRIES A GLYPH', () => {
    const fn = STRIP_CODE.slice(STRIP_CODE.indexOf('function Fact('), STRIP_CODE.indexOf('export default'));
    const measured = fn.slice(fn.indexOf('const hot'));
    assert.match(measured, /⚠/, 'never colour alone');
    assert.match(measured, /var\(--tint-warn-fg\)/, 'amber, not on the danger end of the ramp');
    assert.ok(measured.includes('{note}'), 'the note renders in the body, not only in a title');
  });

  it('⛔ a hue is applied only to a measured, non-zero value', () => {
    assert.match(STRIP_CODE, /const hot = tone && Number\(value\) > 0;/);
  });

  it('⛔ support expiry is gated on supportNoData, so "0 lapsed" over nothing collected is a dash', () => {
    assert.match(STRIP_CODE, /const supportMeasured = total > 0 && \(t\.supportNoData \|\| 0\) < total;/);
  });

  it('⛔ drift is gated on TWO snapshots — one is a device with nothing to compare', () => {
    assert.match(STRIP_CODE, /const driftMeasured = total > 0 && driftNotComparable < total;/);
  });

  it('⛔ "never checked" is reported separately from "reachable"', () => {
    assert.match(STRIP_CODE, /never checked/);
  });

  it('⛔ every figure that links, links somewhere that can act on it', () => {
    // A number with no destination is a dead end on a page whose job is
    // getting the operator to the firewall.
    for (const href of ['/vulnerability', '/lifecycle', '/coverage', '/alerts?type=config_diff']) {
      assert.ok(STRIP_CODE.includes(`href="${href}"`), `missing destination: ${href}`);
    }
  });
});
