'use strict';

// How many surfaces and edges a page is allowed to draw (v2.215.0).
//
// ⛔ WHY THIS FILE EXISTS. SecVault's Overview was measured against a sibling
// product's dashboard — same viewport, both sidebars cropped, the screenshot
// median-filtered twice so text and icons drop out and only real surfaces
// remain. It drew SEVEN distinct surface levels to the other's TWO, and 57
// long border edges to its 28. Nothing in the token file was wrong; usage had
// drifted off it. These tests pin the rules that pulled it back, because every
// one of them is a CSS rule whose absence looks like nothing at all.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const CSS = fs.readFileSync(path.join(__dirname, '..', 'app', 'globals.css'), 'utf8');

/** Every `selector { body }` pair, comments stripped first. */
function rules(css) {
  const bare = css.replace(/\/\*[\s\S]*?\*\//g, '');
  const out = [];
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let m;
  while ((m = re.exec(bare)) !== null) {
    out.push({ selector: m[1].trim().replace(/\s+/g, ' '), body: m[2] });
  }
  return out;
}

const ALL = rules(CSS);

test('a compact tile inside a card draws no box of its own', () => {
  // The whole point of the change: without this rule the page is back to a
  // bordered card holding seven bordered tiles.
  const flatten = ALL.filter(
    (r) => /\.card\b/.test(r.selector)
      && /\.kpi-card-compact/.test(r.selector)
      && /border-color\s*:\s*transparent/.test(r.body)
  );
  assert.ok(
    flatten.length >= 1,
    'no rule flattens .card .kpi-card-compact — the inner boxes are back'
  );
});

test('⛔ the flatten rule EXCLUDES [data-unmeasured], or the dashed border vanishes', () => {
  // ⛔ THE DASHED BORDER IS THE ONLY CARRIER of "we could not measure this" on
  // a tile — globals.css's own v2.200.0 note records that grey was not enough,
  // because --unmeasured and --text-muted are four hex digits apart. A rule
  // that clears border-color on a flattened tile WITHOUT this exclusion makes
  // an unmeasured tile pixel-identical to a measured one, which is this
  // codebase's signature bug aimed at the signal that exists to prevent it.
  //
  // Asserted over EVERY matching rule, not just the one that exists today: a
  // second flatten rule added later is exactly how this would come back.
  const offenders = ALL.filter(
    (r) => /\.kpi-card(-compact)?/.test(r.selector)
      && /border(-color)?\s*:\s*(transparent|none|0)/.test(r.body)
      && !/:not\(\[data-unmeasured\]\)/.test(r.selector)
  );
  assert.deepEqual(
    offenders.map((r) => r.selector),
    [],
    'a rule clears a KPI tile border without excluding [data-unmeasured] — '
      + 'an unmeasured tile would be indistinguishable from a measured one'
  );
});

test('⛔ the dashed unmeasured border itself still exists', () => {
  // The other half: the exclusion above is worthless if the rule it protects
  // has been deleted.
  const dashed = ALL.filter(
    (r) => /\[data-unmeasured\]/.test(r.selector) && /border-style\s*:\s*dashed/.test(r.body)
  );
  assert.ok(dashed.length >= 1, 'the dashed [data-unmeasured] tile border is gone');
});

test('⛔ the notice strip borders its last ROW, never the container', () => {
  // Both notices are usually absent. A border-bottom on .notice-bar draws a
  // hairline across every page with nothing above it — a 1px banner that can
  // never be dismissed.
  const bar = ALL.filter((r) => /^\.notice-bar$/.test(r.selector));
  assert.ok(bar.length >= 1, '.notice-bar is missing');
  for (const r of bar) {
    assert.ok(
      !/border-bottom\s*:\s*[^;]*\b(1px|2px|thin)\b/.test(r.body),
      '.notice-bar must not carry its own bottom border — put it on .notice-row:last-child'
    );
  }
  const lastRow = ALL.filter(
    (r) => /\.notice-row:last-child/.test(r.selector) && /border-bottom\s*:/.test(r.body)
  );
  assert.ok(lastRow.length >= 1, 'nothing closes the notice strip off from the content');
});

test('⛔ only the `bad` tone keeps a coloured ground', () => {
  // "Renews in 31 days" is information, not risk, and a full-width amber band
  // for it is the chrome breaking the rule the palette keeps. A lapsed
  // subscription IS risk and is the one exception.
  // ⛔ THE ROW ITSELF, NOT ITS DESCENDANTS. A first draft of this test matched
  // any selector containing `.notice-row[data-tone=`, which also caught
  // `.notice-row[data-tone="warn"] .notice-dot { background: ... }` — the DOT,
  // which is precisely where tone is SUPPOSED to live now. It failed on
  // correct CSS, i.e. it tested the wrong thing in the right area.
  const toned = ALL.filter(
    (r) => /^\.notice-row\[data-tone="[a-z]+"\]$/.test(r.selector)
      && /background\s*:/.test(r.body)
  );
  for (const r of toned) {
    assert.match(
      r.selector,
      /data-tone="bad"/,
      `${r.selector} gives a notice tone a coloured ground; only "bad" may have one`
    );
  }
});

test('⛔ .stat-label stepped DOWN in size but NOT onto --text-muted', () => {
  // v2.203.0 moved both at once, which made .stat-label byte-identical to
  // .stat-sub — the production minifier merged the two selectors, which is
  // proof rather than opinion. Label and caption separate on weight and
  // colour, never by collapsing onto one token.
  const label = ALL.filter((r) => /^\.stat-label$/.test(r.selector)).pop();
  assert.ok(label, '.stat-label is missing');
  assert.match(label.body, /font-size:\s*var\(--text-xs\)/, '.stat-label should be --text-xs');
  assert.match(
    label.body,
    /color:\s*var\(--text-secondary\)/,
    '.stat-label must stay on --text-secondary — on --text-muted at 12px it IS .stat-sub'
  );
  const sub = ALL.filter((r) => /^\.stat-sub$/.test(r.selector)).pop();
  assert.ok(sub, '.stat-sub is missing');
  assert.notEqual(
    label.body.replace(/\s/g, ''),
    sub.body.replace(/\s/g, ''),
    'the tile label and its caption have collapsed into one treatment again'
  );
});

test('⛔ .answer-header carries no box', () => {
  // It sat directly above a row of bordered tiles, so every answer-first page
  // opened with two stacked boxes before the first number.
  const ah = ALL.filter((r) => /^\.answer-header$/.test(r.selector)).pop();
  assert.ok(ah, '.answer-header is missing');
  assert.ok(
    !/background:\s*var\(--bg-card\)/.test(ah.body),
    '.answer-header is boxed again — the sentence should sit on the canvas'
  );
  assert.ok(
    !/border:\s*1px/.test(ah.body),
    '.answer-header has regained a border'
  );
});
