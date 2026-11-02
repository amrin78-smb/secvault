'use strict';

// tests/overviewSections.test.js
//
// The Overview's three questions, and the grid that stopped orphaning tiles.
//
// ⛔ WHAT THIS REPLACED. The Overview opened with six headline figures in one
// `repeat(auto-fit, minmax(190px, 1fr))` grid — every one the same size and
// the same weight, so a firewall COUNT sat beside a patch-now count with
// nothing on the page saying which was the reason to still be reading. And
// because the grid was `auto-fit`, the row broke wherever the viewport
// happened to fall: measured at 1440 with the rail expanded it rendered FIVE
// ACROSS AND ORPHANED THE SIXTH, which reads as a layout fault rather than a
// group. `auto-fit` cannot be fixed by tuning the minmax, because it does not
// know how many tiles there are — any width that fits five will orphan a
// sixth.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { stripComments } = require('./stripComments');

const ROOT = path.join(__dirname, '..');
const stripCss = (src) => src.replace(/\/\*[\s\S]*?\*\//g, ' ');
const HEADLINE = stripComments(fs.readFileSync(
  path.join(ROOT, 'components', 'dashboard', 'HeadlineStats.js'), 'utf8'));
const CSS = stripCss(fs.readFileSync(path.join(ROOT, 'app', 'globals.css'), 'utf8'));

describe('⛔ three questions, and every figure kept', () => {
  test('the three sections are present, in the order an operator asks them', () => {
    const order = ['What needs attention', 'Fleet posture', 'Can these numbers be trusted?'];
    let last = -1;
    for (const title of order) {
      const at = HEADLINE.indexOf(title);
      assert.ok(at > -1, `the "${title}" section is missing`);
      assert.ok(at > last, `"${title}" is out of order`);
      last = at;
    }
  });

  test('⛔ NOTHING WAS REMOVED — all six headline figures survive', () => {
    // The restructure is about which question each figure answers, not about
    // showing fewer of them. A tile quietly dropped in a layout change is a
    // measurement the operator stops seeing.
    for (const label of [
      'Critical Alerts', 'High Risks',
      'Security Score', 'Compliance Score', 'Devices', 'Total Rules',
    ]) {
      assert.ok(HEADLINE.includes(`label="${label}"`), `the ${label} tile is gone`);
    }
  });

  test('every tile keeps its evidence mark and its delta', () => {
    // The evidence drawer and the vs-yesterday comparison are what make these
    // figures auditable; a layout change must not cost either.
    // 7, not 6: the six tiles plus AnswerHeader's own `evidence={ev.patchNow
    // || ev.security}`. Pinned as 7 rather than loosened to >=6, so losing a
    // tile's drawer still fails.
    assert.equal((HEADLINE.match(/evidence=\{ev\./g) || []).length, 7);
    assert.equal((HEADLINE.match(/<DeltaBadge/g) || []).length, 6);
  });

  test('the two action figures are in the attention section, not the posture one', () => {
    const attention = HEADLINE.indexOf('What needs attention');
    const posture = HEADLINE.indexOf('Fleet posture');
    const trust = HEADLINE.indexOf('Can these numbers be trusted?');
    const at = (s) => HEADLINE.indexOf(`label="${s}"`);
    for (const l of ['Critical Alerts', 'High Risks']) {
      assert.ok(at(l) > attention && at(l) < posture, `${l} is in the wrong section`);
    }
    for (const l of ['Security Score', 'Compliance Score', 'Devices', 'Total Rules']) {
      assert.ok(at(l) > posture && at(l) < trust, `${l} is in the wrong section`);
    }
  });

  test('the attention section links to the queue rather than acting here', () => {
    assert.match(HEADLINE, /href="\/work"/);
    assert.match(HEADLINE, /href="\/coverage"/);
  });
});

describe('⛔ THE GRID CANNOT ORPHAN A TILE', () => {
  // ⛔ THE COLUMN RULES MOVED TO components/ui/KpiRow.js IN v2.220.0, and
  // tests/kpiRow.test.js owns them now — including "every responsive step
  // divides". This file used to assert them against `.ov-grid`, a stylesheet
  // block that was the SAME RULE as the KPI-row block written twice, four
  // hundred lines apart, with two @media (max-width: 1100px) copies. What
  // belongs HERE is the Overview's own decision: how many tiles each section
  // has and that the declared count matches.

  test('sections use the shared KpiRow, never a hand-rolled grid', () => {
    assert.match(HEADLINE, /<KpiRow cols=\{2\}>/);
    assert.match(HEADLINE, /<KpiRow cols=\{4\}>/);
    assert.ok(!/auto-fit/.test(HEADLINE),
      'auto-fit is back — it cannot know how many tiles there are, so it will orphan one again');
    assert.ok(!/ov-grid/.test(HEADLINE), 'the retired duplicate is back');
  });

  test('each declared column count divides its tile count', () => {
    const sections = [...HEADLINE.matchAll(/<KpiRow cols=\{(\d)\}>([\s\S]*?)<\/KpiRow>/g)];
    assert.equal(sections.length, 2, 'the section grids have moved');
    for (const [, cols, body] of sections) {
      const tiles = (body.match(/<StatCard/g) || []).length;
      assert.equal(tiles, Number(cols),
        `a ${cols}-column section holds ${tiles} tiles, so the last row is short`);
    }
  });

  test('⛔ the six figures are still 2 + 4, not one row of six', () => {
    const counts = [...HEADLINE.matchAll(/<KpiRow cols=\{(\d)\}>/g)].map((m) => Number(m[1]));
    assert.deepEqual(counts, [2, 4],
      'the grouping is the feature: two things that need action, four that describe posture');
    assert.equal(counts.reduce((a, b) => a + b, 0), 6, 'a figure was added or lost');
  });
});

describe('⛔ the trust section is not more KPIs', () => {
  test('it is a list, not StatCards', () => {
    // Everything above it is a measurement; this is a QUALIFIER on those
    // measurements. Rendered as tiles it would read as the seventh and eighth
    // headline figures — the exact complaint the sections exist to answer.
    const trustBlock = HEADLINE.slice(HEADLINE.indexOf('Can these numbers be trusted?'));
    assert.ok(!/<StatCard/.test(trustBlock), 'the trust section is drawing KPI tiles');
    assert.match(trustBlock, /className="ov-trust"/);
  });

  test('⛔ EVERY FIGURE CARRIES ITS DENOMINATOR', () => {
    // "7 reachable" is a true sentence that reads as a statement about the
    // whole fleet.
    assert.match(HEADLINE, /of \{h\.deviceCount\}/);
  });

  test('⛔ it is never a single percentage', () => {
    // One "62% coverage" covers three different problems with three different
    // first steps, and hides which one you have.
    const trustBlock = HEADLINE.slice(HEADLINE.indexOf('const trust = ['));
    assert.ok(!/%/.test(trustBlock.slice(0, 1200)), 'a coverage percentage has appeared');
  });

  test('⛔ "never collected" and "stale" stay TWO counts, not one', () => {
    // A device nothing has ever been pulled from and one whose last pull is
    // eight days old send the operator to different places — a credential or
    // reachability problem versus a job that stopped running.
    assert.match(HEADLINE, /devicesNeverCollected/);
    assert.match(HEADLINE, /staleCollected/);
    assert.match(HEADLINE, /never collected from at all/);
    assert.match(HEADLINE, /last collected over/);
  });

  test('the two problem entries render only when non-zero', () => {
    // "0 never collected" beside three coverage figures reads as a fourth
    // thing going well, spending a line on the absence of a problem.
    assert.match(HEADLINE, /h\.devicesNeverCollected > 0\s*\?/);
    assert.match(HEADLINE, /staleCollected > 0\s*\?/);
  });

  test('⛔ PARTIAL COVERAGE IS MARKED, and not by colour alone', () => {
    // The design system's table: measured zero is neutral, PARTIAL coverage is
    // amber with its numerator and denominator. "0 of 8 assessed" rendered in
    // the same ink as "8 of 8" makes the one state this section exists to
    // expose look like the state it exists to rule out.
    assert.match(HEADLINE, /const partial = \(n\) => \(n < h\.deviceCount \? true : undefined\)/);
    assert.match(CSS, /\.ov-trust-item\[data-bad\] \.ov-trust-n::before \{ content: '⚠ '; \}/);
    // Hueless-or-amber, never the danger end: a gap in OUR collection is not a
    // severity of the customer's.
    assert.match(CSS, /\.ov-trust-item\[data-bad\][\s\S]{0,120}var\(--tint-warn-fg\)/);
  });

  test('staleCollected can never go negative', () => {
    // It is derived by subtraction from two independently-counted FILTERs, and
    // a negative would render as "⚠ -1 of 8".
    assert.match(HEADLINE, /Math\.max\(\s*0,/);
  });
});

describe('⛔ the freshness counts cost no extra query', () => {
  const FH = stripComments(fs.readFileSync(
    path.join(ROOT, 'lib', 'engines', 'fleetHeadline.js'), 'utf8'));

  test('they ride on the device scan that was already happening', () => {
    // A second statement for them would have put a fleet query on the landing
    // page to answer a question the existing one was already in a position to
    // answer.
    // ⛔ Sliced to the NEXT top-level declaration, not to the first '}' — the
    // first brace inside this function closes an object in the fallback
    // return, so the old slice measured an empty string and the assertion
    // passed over nothing. A guard that measures the wrong text is a guard
    // that cannot fire.
    const from = FH.indexOf('async function getDeviceCounts');
    const rest = FH.slice(from + 1);
    const nextDecl = rest.search(/\n(async )?function /);
    const body = nextDecl > -1 ? rest.slice(0, nextDecl) : rest;
    assert.ok(body.length > 200, 'the function body slice is empty — the guard is measuring nothing');
    assert.equal((body.match(/pool\.query\(/g) || []).length, 1,
      'getDeviceCounts issues more than one statement');
    assert.match(body, /never_collected/);
    assert.match(body, /collected_fresh/);
  });

  test('⛔ the staleness threshold is IMPORTED, not a literal', () => {
    // /coverage is the page the trust section links to. A summary calling a
    // device stale on a different threshold from the register it points at
    // would send the operator to a page that disagrees with the line they
    // clicked.
    assert.match(FH, /require\('\.\/coverageRegister'\)/);
    assert.match(FH, /STALE_AFTER_DAYS/);
    assert.ok(!/INTERVAL '7 day'/.test(FH), 'the threshold is hardcoded in the SQL');
  });

  test('the three counts are returned separately, never pre-divided', () => {
    assert.match(FH, /devicesCollectedFresh:/);
    assert.match(FH, /devicesNeverCollected:/);
    assert.match(FH, /collectionStaleAfterDays:/);
  });
});
