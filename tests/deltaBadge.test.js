// tests/deltaBadge.test.js
//
// components/ui/DeltaBadge.js — the change marker under a headline figure.
//
// ⛔ WHY THESE ARE RENDERED AND NOT SOURCE-SCANNED. Every rule this component
// carries has a wrong answer that is a CONFIDENT, PLAUSIBLE PHRASE on screen:
// a "0" where the truth is "we have no prior value", a green ↑ over a rising
// count of urgent CVEs, or "No change since yesterday" under a tile comparing
// something other than yesterday. None of those is visible as a missing guard
// in one line of source — each is only visible in the words and the colour the
// component actually prints. So these tests mount it with react-dom/server and
// read them.
//
// The JSX is compiled with the parser tests/jsxSyntax.test.js already uses
// (`next/dist/build/swc`, a runtime dependency), exactly as
// tests/applicationRoutes.test.js does — package.json deliberately has no
// devDependencies.
//
// ⛔ The absent-`previous` case is the one that matters most, and it is the one
// that would regress silently: rendering a 0 there is CLAUDE.md's most-repeated
// bug class (a failed read recorded as an affirmative value) in a single
// character, and "0" under a tile looks like a finished, reassuring answer.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const REPO = path.join(__dirname, '..');

/** Compile-on-require for the app's own ESM+JSX. */
function installRenderHooks() {
  const swc = require('next/dist/build/swc');
  const origExt = Module._extensions['.js'];
  Module._extensions['.js'] = function (mod, filename) {
    if (filename.split(path.sep).join('/').includes('/node_modules/')) {
      return origExt(mod, filename);
    }
    const out = swc.transformSync(fs.readFileSync(filename, 'utf8'), {
      filename,
      jsc: {
        parser: { syntax: 'ecmascript', jsx: true },
        target: 'es2020',
        transform: { react: { runtime: 'automatic' } },
      },
      module: { type: 'commonjs' },
    });
    return mod._compile(out.code, filename);
  };
}

let React = null;
let renderToStaticMarkup = null;
let DeltaBadge = null;
let GOOD = null;
let loadError = null;
try {
  installRenderHooks();
  React = require('react');
  ({ renderToStaticMarkup } = require('react-dom/server'));
  const mod = require('../components/ui/DeltaBadge');
  DeltaBadge = mod.default;
  GOOD = mod.GOOD;
} catch (err) {
  // Reported as a failure rather than skipped: a suite that quietly stops
  // checking is the same shape of problem as the bugs it covers.
  loadError = err;
}

const html = (props) => {
  assert.ok(DeltaBadge, 'could not load DeltaBadge for rendering: '
    + (loadError ? loadError.message : 'unknown'));
  return renderToStaticMarkup(React.createElement(DeltaBadge, props));
};

/** The visible words, tags stripped and whitespace collapsed. */
const text = (props) => html(props).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();

describe('DeltaBadge — an absent comparison renders NOTHING', () => {
  // ⛔ Not a 0 and not an em-dash. A 0 reads as "unchanged", which is a
  // different and unearned claim; a dashboard row whose previous snapshot
  // predates a column would otherwise assert stability it never measured.
  for (const [name, previous] of [
    ['null (no prior snapshot row)', null],
    ['undefined (column absent from the prior row)', undefined],
    ['NaN', NaN],
    ['a non-numeric string', 'n/a'],
  ]) {
    it(`renders empty when previous is ${name}`, () => {
      assert.equal(html({ current: 12, previous, goodDirection: GOOD.up }), '');
    });
  }

  it('renders empty when previous is omitted entirely', () => {
    assert.equal(html({ current: 12, goodDirection: GOOD.up }), '');
  });

  // The same rule from the other side: a metric that is itself unmeasurable
  // (a null security score) has no change to report either.
  it('renders empty when current is null or undefined', () => {
    assert.equal(html({ current: null, previous: 40, goodDirection: GOOD.up }), '');
    assert.equal(html({ current: undefined, previous: 40, goodDirection: GOOD.up }), '');
  });

  it('renders empty when current cannot be made a number', () => {
    assert.equal(html({ current: 'later', previous: 40, goodDirection: GOOD.up }), '');
  });

  it('does NOT render empty for a real, measured zero', () => {
    // 0 vs 3 is a measurement, not a gap — the whole distinction this
    // component exists to keep.
    assert.match(text({ current: 0, previous: 3, goodDirection: GOOD.down }), /↓ 3/);
  });
});

describe('DeltaBadge — a zero difference says so, in words', () => {
  it('prints "No change since yesterday" by default', () => {
    assert.equal(text({ current: 51, previous: 51, goodDirection: GOOD.up }), 'No change since yesterday');
  });

  it('prints it for a genuine zero-to-zero comparison too', () => {
    assert.equal(text({ current: 0, previous: 0, goodDirection: GOOD.down }), 'No change since yesterday');
  });

  it('carries no arrow and no severity hue', () => {
    const markup = html({ current: 51, previous: 51, goodDirection: GOOD.up });
    assert.ok(!markup.includes('↑') && !markup.includes('↓'), 'no arrow on a zero difference');
    assert.ok(!markup.includes('var(--green)'), 'a zero difference is not good news');
    assert.ok(!markup.includes('var(--red)'), 'a zero difference is not bad news');
  });
});

describe('DeltaBadge — GOOD has a direction, and it is PER METRIC', () => {
  // ⛔ The mockup this came from coloured every arrow the same way, which would
  // have shown "more urgent CVEs than yesterday" as a reassuring green tick.
  it('a rising compliance score (up is good) is green and ↑', () => {
    const markup = html({ current: 62, previous: 51, goodDirection: GOOD.up });
    assert.ok(markup.includes('var(--green)'), 'expected green');
    assert.match(text({ current: 62, previous: 51, goodDirection: GOOD.up }), /↑ 11/);
  });

  it('a falling compliance score (up is good) is red and ↓', () => {
    const markup = html({ current: 51, previous: 62, goodDirection: GOOD.up });
    assert.ok(markup.includes('var(--red)'), 'expected red');
    assert.match(text({ current: 51, previous: 62, goodDirection: GOOD.up }), /↓ 11/);
  });

  it('a RISING critical-alert count (down is good) is RED, not green', () => {
    const markup = html({ current: 9, previous: 4, goodDirection: GOOD.down });
    assert.ok(markup.includes('var(--red)'), 'more patch-now CVEs is not good news');
    assert.ok(!markup.includes('var(--green)'));
    assert.match(text({ current: 9, previous: 4, goodDirection: GOOD.down }), /↑ 5/);
  });

  it('a FALLING critical-alert count (down is good) is GREEN', () => {
    const markup = html({ current: 4, previous: 9, goodDirection: GOOD.down });
    assert.ok(markup.includes('var(--green)'));
    assert.match(text({ current: 4, previous: 9, goodDirection: GOOD.down }), /↓ 5/);
  });

  it('an unrecognised or missing direction is never painted green', () => {
    // A movement nobody has classified must not read as an all-clear.
    for (const goodDirection of [undefined, null, 'sideways', 'UP']) {
      const markup = html({ current: 9, previous: 4, goodDirection });
      assert.ok(!markup.includes('var(--green)'), `green for goodDirection=${String(goodDirection)}`);
      assert.ok(markup.includes('var(--red)'));
    }
  });

  it('prints the magnitude, never a signed negative', () => {
    assert.ok(!text({ current: 4, previous: 9, goodDirection: GOOD.down }).includes('-5'));
  });

  it('GOOD is exactly the two directions, so a typo cannot masquerade as one', () => {
    assert.deepEqual(GOOD, { up: 'up', down: 'down' });
  });
});

describe('DeltaBadge — comparisonLabel', () => {
  it('defaults to "from yesterday" on the delta row', () => {
    assert.equal(text({ current: 62, previous: 51, goodDirection: GOOD.up }), '↑ 11 from yesterday');
  });

  it('prints a supplied label verbatim instead', () => {
    const t = text({ current: 62, previous: 51, goodDirection: GOOD.up, comparisonLabel: 'vs previous 24h' });
    assert.equal(t, '↑ 11 vs previous 24h');
    assert.ok(!t.includes('yesterday'), 'the default period must not leak through');
  });

  it('the no-change sentence FOLLOWS the label rather than hardcoding yesterday', () => {
    assert.equal(
      text({ current: 51, previous: 51, goodDirection: GOOD.up, comparisonLabel: 'vs previous 24h' }),
      'No change vs previous 24h'
    );
  });

  it('a blank or non-string label falls back rather than printing a bare "No change"', () => {
    // "No change" with no period stated is a comparison against nothing.
    for (const comparisonLabel of ['', '   ', null, 42]) {
      assert.equal(
        text({ current: 51, previous: 51, goodDirection: GOOD.up, comparisonLabel }),
        'No change since yesterday'
      );
      assert.equal(
        text({ current: 62, previous: 51, goodDirection: GOOD.up, comparisonLabel }),
        '↑ 11 from yesterday'
      );
    }
  });

  it('an absent comparison still renders nothing whatever the label says', () => {
    assert.equal(html({ current: 12, previous: null, comparisonLabel: 'vs previous 24h' }), '');
  });

  // ⛔ NO PERCENTAGE MODE — decided against. Pinned so it is not helpfully
  // added later: these tiles carry counts of 0, 1 and 2, where a percentage is
  // either a division by zero or a "+100%" that means one more CVE.
  it('reports absolute change, never a percentage', () => {
    const t = text({ current: 2, previous: 1, goodDirection: GOOD.down });
    assert.equal(t, '↑ 1 from yesterday');
    assert.ok(!t.includes('%'));
  });
});

describe('the six dashboard call sites still get the shipped wording', () => {
  // A source scan, deliberately: the six tiles must keep the output they had
  // before the lift, and the way that silently breaks is a call site quietly
  // acquiring a label or losing its direction.
  const src = fs.readFileSync(path.join(REPO, 'components/dashboard/HeadlineStats.js'), 'utf8');

  it('HeadlineStats imports the shared badge and keeps no local copy', () => {
    assert.match(src, /import DeltaBadge, \{ GOOD \} from '\.\.\/ui\/DeltaBadge'/);
    assert.ok(!/function DeltaBadge\b/.test(src), 'a second copy would drift from the shared one');
    assert.ok(!/const GOOD = \{/.test(src), 'GOOD travels with the badge');
  });

  it('all six tiles pass a direction and none overrides the label', () => {
    const uses = src.match(/<DeltaBadge[\s\S]*?\/>/g) || [];
    assert.equal(uses.length, 6, 'expected the six headline tiles');
    for (const use of uses) {
      assert.match(use, /goodDirection=\{GOOD\.(up|down)\}/, `no direction on: ${use}`);
      assert.ok(!use.includes('comparisonLabel'), 'the dashboard compares against yesterday');
    }
  });
});
