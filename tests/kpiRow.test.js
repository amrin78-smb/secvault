'use strict';

// components/ui/KpiRow.js — explicit column counts for stat-tile rows.
//
// ⛔ THE RULE THIS ENFORCES WAS ESTABLISHED IN v2.218.0 ON ONE PAGE AND THEN
// RE-IMPLEMENTED BROKEN EVERYWHERE ELSE. Twenty-odd `repeat(auto-fit,
// minmax(Npx, 1fr))` grids, each with its own hand-picked minmax, and
// auto-fit cannot be fixed by tuning that number: it does not know how many
// tiles there are, so any width that fits five orphans a sixth.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { stripComments } = require('./stripComments');

const ROOT = path.join(__dirname, '..');
const CSS = stripComments(fs.readFileSync(path.join(ROOT, 'app', 'globals.css'), 'utf8'));
const SRC = stripComments(fs.readFileSync(path.join(ROOT, 'components', 'ui', 'KpiRow.js'), 'utf8'));

// ⛔ BRACE-MATCHED, NOT INDEX ARITHMETIC. The first draft sliced each @media
// block with `indexOf('}', start + 200)`, which cut the block short and made
// every lookup return null — four tests "passed" the reduction check by
// finding nothing to check. A guard that measures an empty string is the
// defect this repo names most often, so the scope is parsed properly.
function mediaBlock(width) {
  const head = `@media (max-width: ${width}px)`;
  // ⛔ SEARCHED FROM THE KPI SECTION, NOT FROM THE TOP OF THE FILE. There
  // used to be a second `@media (max-width: 1100px)` four hundred lines
  // earlier for the Overview's own `.ov-grid` — the same rule written twice —
  // so a bare indexOf found the wrong copy and this guard reported that no
  // step existed. The duplicate is gone (the Overview uses <KpiRow> now), and
  // the search is anchored anyway: a stylesheet this size will grow another
  // breakpoint at the same width sooner or later.
  const from = CSS.indexOf('.kpi-row { display: grid;');
  const i = CSS.indexOf(head, from === -1 ? 0 : from);
  if (i === -1) return null;
  let depth = 0;
  for (let j = CSS.indexOf('{', i); j < CSS.length; j += 1) {
    if (CSS[j] === '{') depth += 1;
    else if (CSS[j] === '}') {
      depth -= 1;
      if (depth === 0) return CSS.slice(i, j + 1);
    }
  }
  return null;
}

function colsRule(n, media) {
  const scope = media ? mediaBlock(media) : CSS.slice(0, CSS.indexOf('@media (max-width: 1320px)'));
  if (!scope) return null;
  // The selector may be grouped: `.kpi-row[data-cols="5"],\n.kpi-row[data-cols="3"] { … }`
  const re = new RegExp(`\\.kpi-row\\[data-cols="${n}"\\][^{]*\\{([^}]*)\\}`);
  const m = scope.match(re);
  return m ? m[1] : null;
}

function columnsOf(decl) {
  if (!decl) return null;
  const m = decl.match(/repeat\((\d+),/);
  if (m) return Number(m[1]);
  if (/grid-template-columns:\s*minmax\(0, 1fr\)/.test(decl)) return 1;
  return null;
}

describe('the guard is measuring something', () => {
  it('⛔ every responsive scope this file reads actually exists', () => {
    for (const w of [1320, 1100, 860, 640]) {
      assert.ok(mediaBlock(w), `no @media (max-width: ${w}px) block — the step tests below `
        + 'would silently pass over nothing');
      assert.match(mediaBlock(w), /kpi-row/, `the ${w}px block declares no kpi-row step`);
    }
  });
});

describe('every supported count has a base rule', () => {
  for (const n of [1, 2, 3, 4, 5, 6]) {
    it(`data-cols="${n}" declares ${n} columns`, () => {
      assert.equal(columnsOf(colsRule(n)), n);
    });
  }
});

describe('⛔ EVERY RESPONSIVE STEP DIVIDES THE TILE COUNT', () => {
  // A four-tile row going 4 -> 3 -> 2 -> 1 orphans its fourth on the way
  // down, which is the same defect one breakpoint later.
  const WIDTHS = [1320, 1100, 860, 640];

  for (const n of [2, 3, 4, 5, 6]) {
    it(`a ${n}-tile row never renders a ragged step`, () => {
      let current = n;
      for (const w of WIDTHS) {
        const step = columnsOf(colsRule(n, w));
        if (step === null) continue;
        assert.ok(step <= current, `${n}: ${current} -> ${step} at ${w}px is not a reduction`);
        assert.equal(
          n % step, 0,
          `${n} tiles in ${step} columns leaves ${n % step} stranded on the last row`
        );
        current = step;
      }
    });
  }

  it('⛔ FIVE DROPS STRAIGHT TO ONE, because nothing divides five', () => {
    assert.equal(columnsOf(colsRule(5, 1100)), 1,
      'any intermediate step for five tiles is ragged by construction; an awkward '
      + 'tile count is surfaced, never smoothed over');
  });

  it('⛔ THREE SKIPS TWO for the same reason', () => {
    assert.equal(columnsOf(colsRule(3, 1100)), 1);
  });

  it('six goes 6 -> 3 -> 2 -> 1, every step a divisor', () => {
    assert.equal(columnsOf(colsRule(6, 1320)), 3);
    assert.equal(columnsOf(colsRule(6, 860)), 2);
    assert.equal(columnsOf(colsRule(6, 640)), 1);
  });

  it('four goes 4 -> 2 -> 1, never through three', () => {
    assert.equal(columnsOf(colsRule(4, 1100)), 2);
    assert.equal(columnsOf(colsRule(4, 640)), 1);
  });
});

describe('the component', () => {
  it('⛔ A BAD `cols` FALLS BACK TO ONE COLUMN, never to auto-fit', () => {
    assert.match(SRC, /data-cols="1"/);
    assert.equal(/auto-fit/.test(SRC), false,
      'one column is obviously wrong, which gets it fixed; auto-fit is subtly '
      + 'wrong at some widths and on some data, which does not');
  });

  it('⛔ it does not count its own children', () => {
    assert.equal(/children\.length|Children\.count/.test(SRC), false,
      'React children can be conditional: a tile rendered only when a count is '
      + 'non-zero would silently change the column count with the DATA, and the '
      + 'layout would be right in development and ragged in production');
  });

  it('the stylesheet carries no auto-fit for a kpi-row', () => {
    const block = CSS.slice(CSS.indexOf('.kpi-row {'), CSS.indexOf('.kpi-row-caption'));
    assert.equal(/auto-fit|auto-fill/.test(block), false);
  });
});

describe('⛔ no adopting page exceeds four primary indicators', () => {
  // §10's cap. Measured before this: three separate five-tile rows, each of
  // which divides into no column count at all.
  const ADOPTERS = [
    'app/(dashboard)/lifecycle/page.js',
    'app/(dashboard)/analysis/page.js',
    'components/devices/CoverageRegister.js',
  ];

  for (const rel of ADOPTERS) {
    it(`${rel} uses KpiRow and declares at most four`, () => {
      const src = stripComments(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
      assert.match(src, /<KpiRow cols=\{(\d)\}>/, 'still hand-rolling a grid');
      for (const m of src.matchAll(/<KpiRow cols=\{(\d)\}>/g)) {
        assert.ok(Number(m[1]) <= 4, `${rel} declares ${m[1]} primary indicators`);
      }
    });

    it(`${rel} renders exactly as many tiles as it declares`, () => {
      const src = stripComments(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
      const open = src.indexOf('<KpiRow cols={');
      const declared = Number(src.slice(open).match(/cols=\{(\d)\}/)[1]);
      const body = src.slice(open, src.indexOf('</KpiRow>', open));
      const tiles = (body.match(/<StatCard/g) || []).length;
      assert.equal(tiles, declared,
        `declares ${declared} columns and renders ${tiles} tiles — the last row is ragged`);
      assert.equal(/&& <StatCard|\? <StatCard/.test(body), false,
        'a conditional tile changes the column count with the data');
    });
  }

  it('⛔ the figure each row dropped is still reported, as a caption or an eyebrow', () => {
    const cov = stripComments(fs.readFileSync(path.join(ROOT, 'components/devices/CoverageRegister.js'), 'utf8'));
    assert.match(cov, /kpi-row-caption/, 'the register total must still be stated');
    const ana = stripComments(fs.readFileSync(path.join(ROOT, 'app/(dashboard)/analysis/page.js'), 'utf8'));
    assert.match(ana, /eyebrow=\{`Whole fleet · \$\{totals\.total\} findings`\}/,
      'the findings total must still be stated');
    const life = stripComments(fs.readFileSync(path.join(ROOT, 'app/(dashboard)/lifecycle/page.js'), 'utf8'));
    assert.match(life, /licenseGapDevices\.length > 0 && \(/, 'the coverage gap must still be stated');
    assert.match(life, /Licence data could not be collected from/);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// ⛔ THE FIVE BOARDS ADOPTED IN v2.228.12, AND WHY THEY ARE NOT UNDER THE
// `cols <= 4` RULE ABOVE
// ─────────────────────────────────────────────────────────────────────────
//
// That rule is about a PAGE's primary indicator row — "four primary indicators
// maximum, and three pages were at five", where the fifth tile was a sum, a
// denominator or a coverage figure masquerading as a peer. These five rows are
// a different thing: each is the COMPLETE ENUMERATION of a closed set the
// engine defines, so there is no fifth tile to demote. ChangeOutcomeBoard shows
// one tile per verdict in VERDICT_ORDER; RiskyRulesTab one per risk band;
// ConformanceBoard and ConsolidationTab one per figure in a fixed array
// literal; VpnDetections one per headline figure. Dropping one would drop a
// state, not a restatement.
//
// ⛔ WHAT THEY WERE BEFORE. All five hand-rolled `repeat(auto-fit,
// minmax(Npx, 1fr))`, which is the shape KpiRow was built to delete.
// Re-measured 2026-11-14: five of the roadmap row's six reproduced;
// components/dashboard/DeviceStatusSummary.js is PREMISE WRONG — it is
// `repeat(3, 1fr)`, explicit since v2.10.0, and was never auto-fit.
//
// ⛔ THE WORST ONE WAS ChangeOutcomeBoard. Six tiles under auto-fit strand the
// SIXTH at any width that fits five, and the sixth is `indistinguishable`
// (rank 3, "Within normal variation") — the measured-and-unremarkable verdict
// that file's own header ranks LAST precisely so it is not prominent. The
// layout gave it a row to itself.
describe('⛔ the boards that stopped hand-rolling auto-fit (v2.228.12)', () => {
  // rel -> [declared cols, the const the row maps over]
  const BOARDS = {
    'components/analysis/ChangeOutcomeBoard.js': [6, 'VERDICT_ORDER'],
    'components/analysis/ConformanceBoard.js': [5, 'tiles'],
    'components/analysis/ConsolidationTab.js': [5, 'figures'],
    'components/analysis/RiskyRulesTab.js': [5, 'BAND_ORDER'],
    'components/vpn/VpnDetections.js': [4, 'headline.figures'],
  };

  for (const [rel, [cols, mapped]] of Object.entries(BOARDS)) {
    it(`${rel} declares cols={${cols}} and hand-rolls no auto-fit grid`, () => {
      const src = stripComments(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
      assert.equal(
        /auto-fit/.test(src), false,
        `${rel} still carries a repeat(auto-fit, minmax(...)) grid. auto-fit cannot be `
        + 'fixed by tuning the minmax: it does not know how many tiles there are, so any '
        + 'width that fits n-1 orphans the nth, and an orphaned tile reads as a layout '
        + 'fault rather than as a group'
      );
      assert.match(src, /import KpiRow from '[./]*ui\/KpiRow';/, `${rel} does not import KpiRow`);
      const found = [...src.matchAll(/<KpiRow cols=\{(\d)\}>/g)].map((m) => Number(m[1]));
      // ⛔ THE "COULD NOT MEASURE THIS" CASE. A row this guard cannot find is
      // not a pass: the scan would report clean over a file it never read,
      // which is the guard-that-cannot-fire pattern this suite exists against.
      assert.ok(
        found.length > 0,
        `${rel}: no <KpiRow cols={n}> was found at all, so nothing here was measured — `
        + 'either the row was removed or it is spelled in a way this scan cannot see'
      );
      assert.ok(found.includes(cols), `${rel} declares ${found.join(',')}, expected ${cols}`);
    });

    it(`${rel} renders exactly ${cols} tiles, with no conditional tile`, () => {
      const src = stripComments(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
      const open = src.indexOf(`<KpiRow cols={${cols}}>`);
      assert.notEqual(open, -1, `${rel}: could not locate the cols={${cols}} row`);
      const close = src.indexOf('</KpiRow>', open);
      assert.notEqual(close, -1, `${rel}: the KpiRow is never closed`);
      const body = src.slice(open, close);
      // Every one of these rows is ONE <StatCard> inside a .map(), so the
      // declared count has to match the mapped array's length, not the number
      // of StatCard elements in the source.
      assert.equal(
        (body.match(/<StatCard/g) || []).length, 1,
        `${rel}: expected a single mapped <StatCard>; a literal list of tiles would have `
        + 'to be counted instead'
      );
      assert.ok(
        body.includes(`${mapped}.map(`),
        `${rel}: the row no longer maps ${mapped}, so cols={${cols}} may no longer match it`
      );
      assert.equal(
        /&& <StatCard|\? <StatCard/.test(body), false,
        `${rel}: a conditional tile changes the column count with the data — correct in `
        + 'development and ragged in production'
      );
    });
  }

  // ⛔ A DECLARED COUNT IS ONLY HONEST IF THE ARRAY IS FIXED. KpiRow does not
  // count its own children by design, so `cols` is a claim about the engine.
  // These three arrays are literals in files this suite can read; the count is
  // derived from the SOURCE, never hardcoded here, so growing one fails the
  // build rather than silently stranding a tile.
  it('⛔ the fixed-length arrays behind cols are still the length declared', () => {
    const lens = {};

    const co = stripComments(fs.readFileSync(
      path.join(ROOT, 'components/analysis/ChangeOutcomeBoard.js'), 'utf8'));
    // VERDICT_ORDER is Object.keys(VERDICT_WEIGHT) minus `unknown`.
    const weightStart = co.indexOf('const VERDICT_WEIGHT = {');
    assert.notEqual(weightStart, -1, 'VERDICT_WEIGHT is gone; cols={6} describes nothing');
    let depth = 0;
    let weightEnd = -1;
    for (let i = co.indexOf('{', weightStart); i < co.length; i += 1) {
      if (co[i] === '{') depth += 1;
      else if (co[i] === '}') { depth -= 1; if (depth === 0) { weightEnd = i; break; } }
    }
    const weightBody = co.slice(weightStart, weightEnd);
    const keys = [...weightBody.matchAll(/^ {2}([a-z_]+): \{/gm)].map((m) => m[1]);
    lens['ChangeOutcomeBoard VERDICT_ORDER'] = keys.filter((k) => k !== 'unknown').length;

    const rr = stripComments(fs.readFileSync(
      path.join(ROOT, 'components/analysis/RiskyRulesTab.js'), 'utf8'));
    const bandLine = rr.match(/const BAND_ORDER = \[([^\]]*)\]/);
    assert.ok(bandLine, 'BAND_ORDER is no longer an array literal');
    lens['RiskyRulesTab BAND_ORDER'] = bandLine[1].split(',').filter((s) => s.trim()).length;

    const vd = stripComments(fs.readFileSync(
      path.join(ROOT, 'lib/engines/vpnDetections.js'), 'utf8'));
    const figStart = vd.indexOf('figures: [');
    assert.notEqual(figStart, -1, 'the engine no longer builds a figures array');
    // ⛔ BRACKET-MATCHED, NOT A NEARBY LANDMARK. The first draft sliced to
    // `indexOf('usernamesIsFloor', figStart)` — a name that occurs BEFORE
    // `figures: [` as well, so the slice ended three characters in and the
    // count came back 3 for a four-element array. The test caught it, which is
    // the only reason this comment exists rather than a wrong number in the
    // expectation. Same defect mediaBlock() above records: index arithmetic
    // over a landmark instead of parsing the scope.
    let fd = 0;
    let figEnd = -1;
    for (let i = vd.indexOf('[', figStart); i < vd.length; i += 1) {
      if (vd[i] === '[') fd += 1;
      else if (vd[i] === ']') { fd -= 1; if (fd === 0) { figEnd = i; break; } }
    }
    assert.notEqual(figEnd, -1, 'the figures array literal is unbalanced');
    lens['vpnDetections figures'] = [...vd.slice(figStart, figEnd)
      .matchAll(/^ {8}key: '/gm)].length;

    assert.deepEqual(lens, {
      'ChangeOutcomeBoard VERDICT_ORDER': 6,
      'RiskyRulesTab BAND_ORDER': 5,
      'vpnDetections figures': 4,
    }, 'a declared cols no longer matches the set it enumerates — move the cols AND the '
      + 'responsive steps deliberately, in the same commit, rather than letting a tile strand');
  });
});
