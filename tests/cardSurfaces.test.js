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
  // ⛔ ANY BORDER DECLARATION THAT COULD NEUTRALISE THE EDGE, not the one
  // spelling that ships today. The predicate used to be
  // `border(-color)?: (transparent|none|0)`, which caught the live rule and
  // MISSED every natural alternative. Measured against mutated bodies for the
  // selector `.card .kpi-card-compact` with no exclusion:
  //
  //   CAUGHT   border-color: transparent;     (what ships)
  //   CAUGHT   border: 0 none;
  //   ESCAPED  border: 1px solid transparent; (the most natural way to write it)
  //   ESCAPED  border-width: 0;
  //   ESCAPED  border-left-color: transparent;
  //   ESCAPED  border-style: solid;           (kills the DASH without a colour)
  //
  // CLAUDE.md records this guard as "verified by deleting the :not() and
  // watching it go red" — true, and it only ever proved the one mutation that
  // was tried. `border-style: solid` is the sharpest case: it removes the
  // dashed edge from the other side without touching a colour at all.
  const NEUTRALISING = /border(?:-(?:top|right|bottom|left))?(?:-(?:color|style|width))?\s*:\s*([^;}]+)/g;
  const clearsTheEdge = (body) => {
    for (const m of body.matchAll(NEUTRALISING)) {
      const value = m[1].trim().toLowerCase();
      // A rule that explicitly re-asserts the dash is not an offender.
      if (/\bdashed\b/.test(value)) continue;
      if (/\b(transparent|none)\b/.test(value)) return true;
      // `0`, `0px`, `border-width: 0 0 0 0`, `border: 0 solid ...`
      if (/(^|\s)0(px|em|rem)?(\s|$)/.test(value)) return true;
      // Any explicit non-dashed style replaces the dash.
      if (/\b(solid|dotted|double|groove|ridge|inset|outset|hidden)\b/.test(value)) return true;
    }
    return false;
  };
  // ⛔ THE CASCADE IS MODELLED, NOT GUESSED AT. The base `.kpi-card` and
  // `.kpi-card-compact` rules legitimately set `border: 1px solid var(--border)`
  // — that IS the default edge, and the dashed rule overrides it afterwards by
  // source order. So only rules that come AFTER the dashed rule can take the
  // dash away, and those are the ones this guard is about. (A first pass of this
  // widening flagged the two base rules, which would have been a false finding
  // reported as a defect.)
  const dashedAt = ALL.findIndex((r) => /\[data-unmeasured\]/.test(r.selector));
  assert.ok(dashedAt >= 0, 'the [data-unmeasured] rule has gone — the signal has no carrier');

  const offenders = ALL.filter(
    (r, i) => i > dashedAt
      && /\.kpi-card(-compact)?/.test(r.selector)
      && clearsTheEdge(r.body)
      && !/:not\(\[data-unmeasured\]\)/.test(r.selector)
      && !/\[data-unmeasured\]/.test(r.selector)
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

// ─────────────────────────────────────────────────────────────────────────
// ⛔ THE CSS RULE WAS GUARDED FROM BOTH ENDS AND NOTHING ASKED WHETHER A
// CALLER COULD ARM IT (v2.228.12)
// ─────────────────────────────────────────────────────────────────────────
//
// The two tests above pin the dashed `[data-unmeasured]` border and the
// `:not([data-unmeasured])` exclusion that keeps the flatten rule from
// clearing it. Both were green, and both would have stayed green if NO TILE IN
// THE PRODUCT had ever set the attribute — a rule nothing triggers, which is
// this repo's guard-that-cannot-fire pattern aimed at the one signal v2.200.0
// added because grey alone was judged insufficient (--unmeasured and
// --text-muted are four hex digits apart and indistinguishable on screen).
//
// Two call sites were in exactly that state, both already rendering
// a NotMeasured em-dash AS THE TILE'S VALUE:
//
//   ConformanceBoard.js  passed `textColor` and no `color`
//   VpnDetections.js     passed NEITHER `color` nor `textColor`
//
// StatCard's only signal was `color === 'var(--unmeasured)'`, so the em-dash
// said "not measured" inside a tile drawn exactly like the measured ones
// beside it. The fix is an explicit `unmeasured` prop; these tests are the half
// that was missing.

const STATCARD = fs.readFileSync(
  path.join(__dirname, '..', 'components', 'ui', 'StatCard.js'), 'utf8'
);

test('⛔ StatCard accepts an EXPLICIT `unmeasured` prop, not only a colour string', () => {
  const { stripComments } = require('./stripComments');
  const src = stripComments(STATCARD, { keepLines: true });
  assert.match(
    src, /unmeasured:\s*unmeasuredProp/,
    'StatCard no longer destructures an `unmeasured` prop. "Was this measured" and '
    + '"what colour is the number" are different facts, and inferring one from the '
    + 'other is what lost the signal on two call sites: a caller that did not spell '
    + 'the fact as the hue var(--unmeasured) got a tile that looked measured'
  );
  assert.match(
    src, /data-unmeasured=\{unmeasured\}/,
    'the resolved flag no longer reaches the DOM attribute the stylesheet keys on'
  );
});

test('⛔ the legacy colour inference is KEPT, and an explicit value overrides it', () => {
  const { stripComments } = require('./stripComments');
  const src = stripComments(STATCARD, { keepLines: true });
  // ⛔ ADDITIVE, DELIBERATELY. ~40 call sites arm this through
  // `color: 'var(--unmeasured)'` — ConsolidationTab.js passes exactly that —
  // so dropping the inference would trade two missing borders for forty.
  assert.match(
    src, /color === 'var\(--unmeasured\)'/,
    'the colour inference was removed, which silently unarms every existing call '
    + 'site that states the fact that way'
  );
  // ⛔ AND THE "WE COULD NOT MEASURE THIS" CASE IS THE THIRD STATE, NOT A
  // BOOLEAN. `undefined` means the caller said nothing and the inference
  // decides; `false` means the caller stated the value IS measured. Collapsing
  // them to `Boolean(prop) || inference` would make an explicit `false`
  // unexpressible, so a tile with a deliberately hueless MEASURED number could
  // never stop being dashed.
  assert.match(
    src, /unmeasuredProp === undefined\s*\?/,
    'the three-way resolution is gone: an explicit `false` must beat the colour '
    + 'inference, or "the caller said nothing" and "the caller said no" are the same'
  );
});

test('⛔ at least one tile in the product can actually set data-unmeasured', () => {
  // The guard the two CSS tests above could not be: a scan for a real caller.
  // Named files, not a count — six other call sites adopting the prop while
  // these regressed would satisfy a count, which is the both-ends reasoning
  // tests/deviceScopeCoverage.test.js applies to its aware floor and its names.
  const { stripComments } = require('./stripComments');
  const CALLERS = {
    // The two the roadmap row named, each keyed on the SAME condition its own
    // value renderer uses, so the border and the em-dash cannot disagree.
    'components/analysis/ConformanceBoard.js': /unmeasured=\{tile\.value === null\}/,
    'components/vpn/VpnDetections.js': /unmeasured=\{f\.current === null \|\| f\.current === undefined\}/,
    // A third, found while fixing them: `value === null` renders NotMeasured
    // here too and left `color` on --border, so a figure that could not be
    // computed sat in a solid-bordered tile.
    'components/analysis/ConsolidationTab.js': /unmeasured=\{Boolean\(f\.unmeasured\) \|\| f\.value === null\}/,
  };
  const missing = [];
  for (const [rel, re] of Object.entries(CALLERS)) {
    const src = stripComments(
      fs.readFileSync(path.join(__dirname, '..', rel), 'utf8'), { keepLines: true }
    );
    if (!re.test(src)) missing.push(rel);
  }
  assert.deepEqual(
    missing, [],
    'these tiles render a NotMeasured em-dash as their value and no longer tell StatCard '
    + 'so, '
    + 'which puts an em-dash meaning "we could not measure this" inside a tile drawn '
    + 'identically to a measured one:\n  ' + missing.join('\n  ')
  );
});

test('⛔ a tile keyed on a TONE rather than on the value is refused', () => {
  // ⛔ THE TWO FACTS DIVERGE AND THIS IS WHERE. ConformanceBoard's
  // "Firewalls not compared" tile is TONED --unmeasured because it COUNTS
  // firewalls nothing could be said about — the count itself is a real
  // measurement, and dashing that tile would claim SecVault could not read the
  // number it is printing. So `tone === 'unmeasured'` is the WRONG key, and the
  // obvious one-line fix for this row would have been exactly that.
  const { stripComments } = require('./stripComments');
  const src = stripComments(
    fs.readFileSync(path.join(__dirname, '..', 'components/analysis/ConformanceBoard.js'), 'utf8'),
    { keepLines: true }
  );
  assert.equal(
    /unmeasured=\{[^}]*tone/.test(src), false,
    'the dashed border is keyed on the tile TONE. A tile toned --unmeasured because it '
    + 'COUNTS unmeasured firewalls holds a measured count; dashing it says SecVault '
    + 'could not read a number it is displaying. Key on the value, which is what '
    + 'statValue() turns into the em-dash.'
  );
  // And the tone really is set on tiles whose value is measured, so the
  // distinction above is live rather than hypothetical.
  assert.match(src, /tone: 'unmeasured'/, 'no tile is toned unmeasured any more, so the '
    + 'divergence this test protects can no longer be exercised — re-derive it');
});
