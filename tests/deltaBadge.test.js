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

// ─────────────────────────────────────────────────────────────────────────
// ⛔ THE VPN THREAT STRIP — THE CALL SITE WHERE A NULL BECAME A GREEN ARROW
// ─────────────────────────────────────────────────────────────────────────
//
// This badge already refuses a delta against a null `current` (above). The bug
// was one layer up: lib/engines/vpnDetections.js coerced a NULL
// `sum(event_count) FILTER (...)` to 0 with `num()`, and components/vpn/
// VpnDetections.js had no not-measured branch in its headline strip. So when the
// syslog collector stopped, the page rendered
//
//     Failed VPN authentications   0
//     ↓ 47881 from the previous window          <- var(--green)
//
// i.e. a TOTAL INGEST OUTAGE as the largest security improvement the page is
// capable of showing, with a reassuring hue on it. Nothing threw, nothing looked
// broken, and the arrow pointed the way an operator wants it to point.
//
// ⛔ RENDERED, because the wrong answer is a colour and a sentence. The engine
// half is pinned in tests/vpnDetections.test.js; this is the half a reader sees.
describe('⛔ the VPN threat headline strip — an outage is never a green arrow', () => {
  let VpnDetections = null;
  let vpnLoadError = null;
  try {
    // The filter bar inside this component is a client component calling
    // useRouter/useSearchParams; there is no app router in a test process, so
    // next/navigation is stubbed to let the REAL tree render.
    const origLoad = Module._load;
    Module._load = function (request, parent, isMain) {
      if (request === 'next/navigation') {
        return {
          useRouter: () => ({ push() {}, replace() {} }),
          usePathname: () => '/vpn',
          useSearchParams: () => new URLSearchParams('vtab=detections'),
        };
      }
      return origLoad(request, parent, isMain);
    };
    VpnDetections = require('../components/vpn/VpnDetections').default;
  } catch (err) {
    vpnLoadError = err;
  }

  const DATA = (figures) => ({
    windowHours: 24,
    windowStart: new Date('2026-09-26T16:00:00Z'),
    generatedAt: new Date('2026-09-27T16:00:00Z'),
    baseline: { hasHistory: true, spanDays: 18.2, firstBucketAt: new Date('2026-09-09T01:00:00Z') },
    headline: { figures },
    coverage: {
      devices: [], reportingGapDevices: [], unattributedCoverage: [],
      totalFailures: 0, totalSuccesses: 0, sourcesSeen: 0,
    },
    detections: [],
  });

  const strip = (figures) => {
    assert.ok(VpnDetections, 'could not load VpnDetections: '
      + (vpnLoadError ? vpnLoadError.stack : 'unknown'));
    return renderToStaticMarkup(React.createElement(VpnDetections, {
      data: DATA(figures), canSearchLogs: false, hours: 24, filters: null,
    }));
  };

  // What the engine now returns for the outage: no rows in the window, so the
  // figure is unmeasured and carries its reason.
  const OUTAGE = {
    key: 'failed_events',
    label: 'Failed VPN authentications',
    current: null,
    currentReason: 'No VPN authentication logs were received in this window at all, so this is '
      + 'not a measured zero.',
    previous: 47881,
    previousReason: null,
    isFloor: false,
    goodDirection: 'down',
  };

  it('⛔ prints NO delta at all against an unmeasured current figure', () => {
    const out = strip([OUTAGE]);
    assert.ok(!out.includes('47881'), 'computed a change against a figure nobody measured');
    assert.doesNotMatch(out, /↓/);
    assert.doesNotMatch(out, /from the previous window/);
  });

  it('⛔ and NEVER in var(--green) — this is not good news', () => {
    const out = strip([OUTAGE]);
    assert.ok(!out.includes('var(--green)'),
      'an ingest outage was painted as an improvement');
    assert.ok(!out.includes('var(--red)'),
      'and it is not bad news either: absence of news has no hue');
  });

  it('⛔ renders the hueless not-measured marker, with the reason on it', () => {
    const out = strip([OUTAGE]);
    assert.ok(out.includes('var(--unmeasured)'), 'no not-measured treatment at all');
    assert.match(out, /not a measured zero/);
    // ⛔ And not a 0 sitting where the number goes. Scoped to the tile's own
    // value element: the coverage strip legitimately prints zeros of its own, and
    // a whole-page text scan would go green on the wrong one.
    const value = out.match(/class="stat-value-compact"[^>]*>(.*?)<\/div>/);
    assert.ok(value, 'the tile rendered no value element at all');
    assert.match(value[1], /—/, 'the value is not the em-dash NotMeasured renders');
    assert.ok(!/>0</.test(value[1]) && value[1].trim() !== '0',
      'rendered a zero for a window with no evidence');
  });

  it('⛔ a MEASURED zero keeps its number and its arrow — the distinction survives', () => {
    // Rows arrived and none was a failure. That is a real, earned zero and it
    // must still compare: an em-dash here would hide a genuinely clean window.
    const out = strip([{ ...OUTAGE, current: 0, currentReason: null }]);
    const text = out.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    assert.match(text, /↓ 47,?881|↓ 47881/);
    assert.ok(out.includes('var(--green)'), 'a real fall in failures is good news');
  });

  it('a measured figure whose COMPARISON is missing says why, hueless', () => {
    const out = strip([{
      ...OUTAGE,
      current: 46090,
      currentReason: null,
      previous: null,
      previousReason: 'SecVault does not hold VPN authentication history reaching back to the '
        + 'start of the previous window.',
    }]);
    assert.match(out, /No comparison/);
    assert.match(out, /does not hold/);
    assert.ok(!out.includes('var(--green)') && !out.includes('var(--red)'));
  });
});
