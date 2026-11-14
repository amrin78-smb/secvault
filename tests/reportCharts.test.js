'use strict';
// tests/reportCharts.test.js
//
// ⛔ A CHART IS A CLAIM, AND IT IS THE ONE FORM OF CLAIM NOBODY CHECKS. A wrong
// number in a table gets queried by the person who knows what it should be; a
// wrong bar just looks like a bar. Every assertion below pins a way a picture
// can say something the data does not:
//
//   - a value SecVault could not measure drawn as a short bar or a small slice,
//     which reads as "nearly none" rather than "we do not know";
//   - an hour with no data drawn at zero height, which turns a collector outage
//     into a quiet night;
//   - a slice that is an ABSENCE of a verdict counted into the percentages of
//     the verdicts;
//   - more rows handed to a chart than it draws, so a truncated list looks
//     complete.
//
// The doc is a stub that records every primitive call, because what matters is
// WHAT WAS DRAWN, not that pdfkit did not throw.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const chassis = require('../lib/reports/chassis');
const PDFDocument = require('pdfkit');
const { contentStreams } = require('../lib/reports/pdfCompare');
const {
  drawBarChart, drawDonut, drawTimeSeries, fmtCompact, UNMEASURED, ALLOWED_RAMP, DENIED_RAMP,
} = chassis;

// A pdfkit stand-in. Every drawing call is recorded with the fill colour that
// followed it, which is the only thing these tests care about.
function stubDoc() {
  const calls = [];
  const doc = {
    y: 100,
    page: { width: 595, height: 842, margins: { left: 40, right: 40, top: 40, bottom: 40 } },
    _pending: null,
    addPage() { calls.push({ op: 'addPage' }); this.y = 40; return this; },
    rect(x, y, w, h) { this._pending = { op: 'rect', x, y, w, h }; return this; },
    roundedRect(x, y, w, h, r) { this._pending = { op: 'roundedRect', x, y, w, h, r }; return this; },
    path(d) { this._pending = { op: 'path', d }; return this; },
    fill(color) { calls.push({ ...this._pending, color }); this._pending = null; return this; },
    fillAndStroke(a, b) { calls.push({ ...this._pending, color: a, stroke: b }); this._pending = null; return this; },
    fillColor(c) { this._fill = c; return this; },
    fontSize() { return this; },
    font() { return this; },
    // ⛔ THE CHARTS MEASURE THEIR CAPTIONS NOW, so the stub has to answer the
    // two metric calls pdfkit answers — a helper that fell back to a guessed
    // height when the doc could not measure would be fabricating the number
    // this whole file exists to stop being fabricated.
    // ⛔ THESE ARE APPROXIMATIONS AND NO GEOMETRY ASSERTION MAY BE READ OFF
    // THEM. The stub ignores fontSize, so both answers are the real 7.5pt
    // caption metrics measured against pdfkit 0.18.0 and nothing else. Page
    // positions and page numbers are asserted further down against a REAL
    // PDFDocument, because that is the only thing that knows font metrics.
    currentLineHeight() { return 8.67; },
    heightOfString(s, o) {
      const width = (o && o.width) || 515;
      const perLine = Math.max(1, Math.floor(width / 3.5)); // ~3.5px/char at 7.5pt
      return Math.max(1, Math.ceil(String(s == null ? '' : s).length / perLine)) * 8.67;
    },
    text(t) { calls.push({ op: 'text', text: String(t), color: this._fill }); return this; },
  };
  return { doc, calls };
}
const layout = { pageW: 595, pageH: 842, left: 40, right: 555, contentW: 515 };

describe('⛔ drawBarChart — a null is not a short bar', () => {
  it('draws no coloured bar for an unmeasured row, and prints an em dash not a 0', () => {
    const { doc, calls } = stubDoc();
    drawBarChart(doc, layout, [
      { label: 'measured', value: 100 },
      { label: 'unmeasured', value: null },
    ], { color: '#111111' });

    const bars = calls.filter((c) => c.op === 'roundedRect' && c.color === '#111111');
    assert.equal(bars.length, 1, 'only the measured row gets a filled bar');

    const texts = calls.filter((c) => c.op === 'text').map((c) => c.text);
    assert.ok(texts.includes('—'), 'the unmeasured row prints an em dash');
    assert.ok(!texts.includes('0'), 'and never a zero');

    // The em dash must also be drawn in the hueless colour, not in ink — an
    // ink-coloured dash reads as a value that happens to be short.
    const dash = calls.find((c) => c.op === 'text' && c.text === '—');
    assert.equal(dash.color, UNMEASURED);

    // ⛔ AND THE ROW IS VISIBLY PRESENT. An empty track with a dash beside it is
    // not enough: the row must carry the hueless mark that says "asked, not
    // answered", the printed form of the --hatch token. Added after a mutation
    // that deleted this branch entirely left every other assertion green.
    const ticks = calls.filter((c) => c.op === 'rect' && c.color === UNMEASURED);
    assert.equal(ticks.length, 1, 'the unmeasured row gets a hueless rule across its track');
    assert.ok(ticks[0].h <= 1.5, 'a rule, not a bar');
  });

  it('scales from the largest MEASURED value, so a null cannot flatten the chart', () => {
    const { doc, calls } = stubDoc();
    drawBarChart(doc, layout, [
      { label: 'a', value: 50 }, { label: 'b', value: 100 }, { label: 'c', value: null },
    ], { color: '#222222' });
    const widths = calls.filter((c) => c.op === 'roundedRect' && c.color === '#222222').map((c) => c.w);
    assert.equal(widths.length, 2);
    // b is the max, so a is half of it.
    assert.ok(Math.abs(widths[0] / widths[1] - 0.5) < 0.02, `expected ~0.5, got ${widths[0] / widths[1]}`);
  });

  it('⛔ truncates to `max` — pinned because a truncated chart looks complete', () => {
    const { doc, calls } = stubDoc();
    const rows = Array.from({ length: 20 }, (_, i) => ({ label: `r${i}`, value: 20 - i }));
    drawBarChart(doc, layout, rows, { max: 15, color: '#333333' });
    const bars = calls.filter((c) => c.op === 'roundedRect' && c.color === '#333333');
    assert.equal(bars.length, 15, 'this is the behaviour every caller must pass `max` for');

    const { doc: d2, calls: c2 } = stubDoc();
    drawBarChart(d2, layout, rows, { color: '#333333' });
    assert.equal(c2.filter((c) => c.op === 'roundedRect' && c.color === '#333333').length, 10,
      'the default is 10, which is why a caller slicing to 15 and not passing max silently loses 5');
  });

  it('honours a custom value formatter, so bytes are not printed as a bare count', () => {
    const { doc, calls } = stubDoc();
    drawBarChart(doc, layout, [{ label: 'x', value: 1073741824 }], {
      format: (n) => `${(n / 1024 ** 3).toFixed(1)} GB`,
    });
    assert.ok(calls.some((c) => c.op === 'text' && c.text === '1.0 GB'));
    assert.equal(fmtCompact(1073741824), '1.1B', 'the default would have said "1.1B", which is not a size');
  });
});

describe('⛔ drawDonut — an absence of a verdict is not a verdict', () => {
  const slices = () => ([
    { label: 'allow', value: 70 },
    { label: 'deny', value: 30 },
    { label: '(unreported)', value: 100, unmeasured: true },
  ]);

  it('excludes an unmeasured slice from the percentages', () => {
    const { doc, calls } = stubDoc();
    drawDonut(doc, layout, slices());
    const texts = calls.filter((c) => c.op === 'text').map((c) => c.text);
    assert.ok(texts.some((t) => /allow.*70.*\(70%\)/.test(t)), `allow should be 70% of the measured 100, got ${texts}`);
    assert.ok(texts.some((t) => /deny.*30.*\(30%\)/.test(t)));
    // ⛔ and it carries NO percentage of its own, because we do not know what
    // share of anything it is.
    assert.ok(texts.some((t) => /unreported/.test(t) && !/%/.test(t)));
  });

  it('still draws the unmeasured slice at its true size, in the hueless colour', () => {
    const { doc, calls } = stubDoc();
    drawDonut(doc, layout, slices());
    const arcs = calls.filter((c) => c.op === 'path');
    assert.equal(arcs.length, 3, 'it is drawn, not dropped — dropping it would re-normalise the ring');
    assert.equal(arcs[2].color, UNMEASURED);
  });

  it('a zero-value slice is dropped rather than drawn as a hairline', () => {
    const { doc, calls } = stubDoc();
    drawDonut(doc, layout, [{ label: 'a', value: 1 }, { label: 'b', value: 0 }]);
    assert.equal(calls.filter((c) => c.op === 'path').length, 1);
  });
});

describe('⛔ drawTimeSeries — a gap is drawn as a gap', () => {
  const pts = [
    { t: '2026-09-20T00:00:00Z', value: 100 },
    { t: '2026-09-20T01:00:00Z', value: null },
    { t: '2026-09-20T02:00:00Z', value: 50 },
  ];

  it('an unmeasured hour is a hueless baseline tick, never a zero-height bar', () => {
    const { doc, calls } = stubDoc();
    drawTimeSeries(doc, layout, pts, { color: '#444444' });
    const bars = calls.filter((c) => c.op === 'rect' && c.color === '#444444');
    assert.equal(bars.length, 2, 'only measured hours get a value bar');
    const ticks = calls.filter((c) => c.op === 'rect' && c.color === UNMEASURED);
    assert.equal(ticks.length, 1, 'the gap hour is drawn in the unmeasured colour');
    assert.ok(ticks[0].h <= 2, 'as a baseline tick, so it cannot be misread as a small value');
  });

  it('a real zero is still a measurement and is not drawn as a gap', () => {
    const { doc, calls } = stubDoc();
    drawTimeSeries(doc, layout, [
      { t: '2026-09-20T00:00:00Z', value: 10 },
      { t: '2026-09-20T01:00:00Z', value: 0 },
    ], { color: '#555555' });
    assert.equal(calls.filter((c) => c.op === 'rect' && c.color === UNMEASURED).length, 0);
    assert.equal(calls.filter((c) => c.op === 'rect' && c.color === '#555555').length, 2);
  });

  it('scales from the largest measured point', () => {
    const { doc, calls } = stubDoc();
    drawTimeSeries(doc, layout, pts, { color: '#666666', height: 100 });
    const bars = calls.filter((c) => c.op === 'rect' && c.color === '#666666');
    assert.ok(bars[0].h > bars[1].h, 'the 100 is taller than the 50');
  });
});

describe('⛔ the chart palette may not borrow a reserved colour', () => {
  it('no chart colour is the unmeasured grey or the shell navy', () => {
    // Both were in the first version of the palette, and a category rendered in
    // UNMEASURED grey reads as "we could not measure this" — the exact claim
    // the rest of this product spends its effort not making by accident.
    const used = new Set();
    for (let i = 0; i < 24; i++) used.add(chassis.chartColor(i).toUpperCase());
    assert.ok(!used.has(chassis.UNMEASURED.toUpperCase()), 'grey is reserved for NOT MEASURED');
    assert.ok(!used.has(chassis.NAVY.toUpperCase()), 'navy is the shell, not a category');
  });

  it('the outcome ramps are long enough for the six slices the donut draws', () => {
    // A four-entry ramp wrapped on this fleet and drew `server-rst` in exactly
    // the same green as `allow`.
    assert.ok(ALLOWED_RAMP.length >= 6, 'six slices are drawn, so six colours are needed');
    assert.ok(DENIED_RAMP.length >= 4);
    assert.equal(new Set([...ALLOWED_RAMP, ...DENIED_RAMP]).size, ALLOWED_RAMP.length + DENIED_RAMP.length,
      'and no colour appears in both families');
  });
});

// ───────────────────────────────────────────────────────────────────────────
// ⛔ PAGINATION, MEASURED AGAINST REAL pdfkit RATHER THAN THE STUB ABOVE.
//
// The stub cannot see any of this. It has no font metrics, so it cannot know
// that a caption is two lines rather than one; it never breaks a page, so it
// cannot show a sentence torn across one. Every assertion below therefore
// drives the real library and reads the RENDERED result back out of the PDF —
// which page a word landed on, and at what y — because the defects these pin
// shipped past a green suite of stub-based tests.
//
// What they pin, in one sentence each:
//   - a chart's CAPTION states its denominator, so it may not be orphaned from
//     the chart onto the next page;
//   - a chart taller than a page is BOUNDED AND COUNTED, never shredded one bar
//     per page;
//   - `ensureSpace` may not report "fitted" when it only managed to add a page,
//     and may not report "did not fit" when it could not measure at all;
//   - two hueless disclosure lines may not be printed on top of each other;
//   - `drawDonut` formats a value the same way `drawBarChart` does.

// A real A4 document at the margin every chart-bearing report uses.
function realDoc(margin = 40) {
  const doc = new PDFDocument({ size: 'A4', margin, bufferPages: true });
  chassis.installPdfSafeText(doc);
  const chunks = [];
  doc.on('data', (c) => chunks.push(c));
  const buffer = new Promise((res) => doc.on('end', () => res(Buffer.concat(chunks))));
  return { doc, layout: chassis.layoutOf(doc), buffer };
}

// ⛔ The text of each page that carries any, in page order. pdfkit writes glyphs
// as hex inside TJ arrays and splits a single string across several of them for
// kerning, so the segment boundaries are DROPPED — a matcher that kept them
// reports "the caption is not on this page" for a caption that plainly is, which
// is how the first draft of these tests passed over a real split.
function pageTexts(buf) {
  return contentStreams(buf).map((s) => {
    let out = '';
    s.replace(/<([0-9a-fA-F]+)>/g, (whole, hex) => {
      if (hex.length % 2) return whole;
      for (let i = 0; i < hex.length; i += 2) out += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
      return whole;
    });
    return out;
  }).filter((t) => t.length > 0);
}

// Records the y every string was drawn at, so an overprint is measurable.
function traceText(doc) {
  const seen = [];
  const orig = doc.text.bind(doc);
  doc.text = (t, x, y, o) => {
    seen.push({ text: String(t), y: y === undefined ? doc.y : y });
    return orig(t, x, y, o);
  };
  return seen;
}

const bottomOf = (doc, layout) => layout.pageH - doc.page.margins.bottom;

// The real caption from lib/reports/ruleRiskByTrafficPdf.js:149-155. Measured at
// 7.5pt over contentW 515.28: TWO lines, 17.34px.
const CAPTION_TWO_LINE = 'Logged hits over 65 days, for the top 15 of 21 rules shown here'
  + '. Red bars are rules that ALSO carry a rule-hygiene finding — those are the ones worth '
  + 'looking at first, because whatever is wrong with them is wrong on the busiest paths in '
  + 'the estate.';
// The real caption from lib/reports/trafficActivity.js:540-543 — ONE line, 8.67px.
const CAPTION_ONE_LINE = 'Volume by application, highest first. Traffic the firewall could not identify is '
  + 'excluded from this chart and totalled below.';

describe('⛔ a caption is the chart\'s denominator and may not be orphaned from it', () => {
  // The cursor is placed where the OLD reservation (rows only, + 16px) fitted
  // exactly. The bars consume all but 10px of it, so anything the caption needs
  // beyond 10px used to be flowed onto the next page by pdfkit.
  const fifteen = Array.from({ length: 15 }, (_, i) => ({ label: `BAR${i}`, value: 15 - i }));

  it('a two-line caption stays on the page its bars are on', async () => {
    const { doc, layout, buffer } = realDoc();
    doc.y = bottomOf(doc, layout) - (15 * 20 + 16);
    drawBarChart(doc, layout, fifteen, { max: 15, labelW: 210, caption: CAPTION_TWO_LINE });
    doc.end();
    const pages = pageTexts(await buffer);

    const barPage = pages.findIndex((t) => t.includes('BAR14'));
    const capStart = pages.findIndex((t) => t.includes('Logged hits over'));
    const capEnd = pages.findIndex((t) => t.includes('the estate'));
    assert.ok(barPage >= 0, 'the last bar must be drawn somewhere');
    assert.equal(capStart, barPage, 'the caption must begin on the chart\'s page');
    assert.equal(capEnd, barPage,
      'and END there: before the fix line 1 printed under the bars and line 2 on the next page');
  });

  it('⛔ and a captionless chart reserves no extra space, so nothing was padded blindly', async () => {
    // The fix must be the caption's MEASURED height, not a constant cushion. If
    // this chart broke the page too, the reservation would have grown for every
    // caller including the ones with nothing to reserve for.
    const { doc, layout } = realDoc();
    doc.y = bottomOf(doc, layout) - (15 * 20 + 16);
    drawBarChart(doc, layout, fifteen, { max: 15, labelW: 210 });
    // ⛔ THE REAL PAGE COUNT, NOT THE COUNT OF PAGES THAT CARRY TEXT. The first
    // draft asserted the latter and a mutation walked straight through it: a
    // blind 20px cushion for an ABSENT caption broke the page, the now-empty
    // first page was filtered out of the text listing, and the assertion still
    // read 1. Testing the mechanism instead of the outcome, one layer in.
    assert.equal(doc.bufferedPageRange().count, 1,
      'no page break without a caption to make room for');
    doc.end();
  });

  it('⛔ the caption is measured THROUGH pdfSafe, or it under-reserves', async () => {
    // `installPdfSafeText` wraps `doc.text` and NOT `heightOfString`, so a raw
    // measurement measures a string that is never drawn. Measured at 7.5pt:
    // `widthOfString('⚠')` is **0** while pdfSafe turns it into '!' at
    // 2.085px — the chassis' own glyph table records that exact asymmetry, and
    // warning glyphs are what it says a caveat string carries. So a caption with
    // one in it measures ONE line, prints TWO, and loses the second. (The em
    // dash diverges the opposite, harmless way: 7.5px raw against 2.4975px
    // safe, i.e. over-reserved.) This caption is 514.17px raw — inside the
    // 515.28px column — and 518.34px sanitised, a whole line apart.
    //
    // ⛔ ASSERTED ON THE **DONUT**, AND THAT IS A MEASUREMENT, NOT A PREFERENCE.
    // drawBarChart reserves `rows + 16` and consumes `rows + 6`, so it carries
    // 10px of slack that absorbs a one-line under-measurement — verified: the
    // same mutation is INVISIBLE there. The donut's reservation is exact, so it
    // is the surface where this guard is load-bearing. A test placed on the bar
    // chart would have been a guard that cannot fire.
    const caption = `${'x'.repeat(136)} ⚠ ⚠`;
    const { doc, layout, buffer } = realDoc();
    // 6 + ring 120 + 6 + a one-line caption (8.67 + 4): what the RAW,
    // unsanitised measurement believes it needs.
    doc.y = bottomOf(doc, layout) - (6 + 120 + 6 + 8.67 + 4);
    drawDonut(doc, layout, [{ label: 'SLICEA', value: 2 }, { label: 'SLICEB', value: 1 }], { caption });
    doc.end();
    const pages = pageTexts(await buffer);
    const ringPage = pages.findIndex((t) => t.includes('SLICEA'));
    assert.ok(ringPage >= 0, 'the legend must be drawn');
    // pdfSafe renders both glyphs as '!', so the drawn tail is '! !'.
    assert.equal(pages.findIndex((t) => t.includes('! !')), ringPage,
      'the sanitised caption must be reserved for, not the string nobody prints');
  });

  it('a one-line caption fits the old slack and still lands with its bars', async () => {
    const { doc, layout, buffer } = realDoc();
    doc.y = bottomOf(doc, layout) - (15 * 20 + 16);
    drawBarChart(doc, layout, fifteen, { max: 15, labelW: 170, caption: CAPTION_ONE_LINE });
    doc.end();
    const pages = pageTexts(await buffer);
    const barPage = pages.findIndex((t) => t.includes('BAR14'));
    assert.equal(pages.findIndex((t) => t.includes('totalled below')), barPage);
  });

  it('a donut\'s legend, its disclosures and its caption all land on one page', async () => {
    // Measured before the fix: with the cursor where `size + 24` fitted exactly,
    // twelve slices produced THREE pages — the legend, then the "+ N more"
    // disclosure alone, then the caption alone.
    const { doc, layout, buffer } = realDoc();
    const slices = Array.from({ length: 12 }, (_, i) => ({ label: `SLICE${i}`, value: 12 - i }));
    slices.push({ label: 'UNSIZEDONE', value: null, unmeasured: true });
    doc.y = bottomOf(doc, layout) - (120 + 24);
    drawDonut(doc, layout, slices, { caption: CAPTION_TWO_LINE });
    doc.end();
    const pages = pageTexts(await buffer);

    const legendPage = pages.findIndex((t) => t.includes('SLICE0'));
    assert.ok(legendPage >= 0);
    for (const [what, needle] of [
      ['the legend\'s last drawn row', 'SLICE9'],
      ['the legend truncation disclosure', 'more, drawn but not listed'],
      ['the unmeasurable-slice note', 'UNSIZEDONE'],
      ['the caption\'s first line', 'Logged hits over'],
      ['the caption\'s last line', 'the estate'],
    ]) {
      assert.equal(pages.findIndex((t) => t.includes(needle)), legendPage, `${what} must be on the chart's page`);
    }
  });

  it('a time series keeps its caption too — the same defect, fixed in the same place', async () => {
    const { doc, layout, buffer } = realDoc();
    doc.y = bottomOf(doc, layout) - (90 + 28);
    const pts = Array.from({ length: 24 }, (_, i) => ({
      t: `2026-09-20T${String(i).padStart(2, '0')}:00:00Z`, value: i * 10,
    }));
    drawTimeSeries(doc, layout, pts, { height: 90, caption: CAPTION_TWO_LINE });
    doc.end();
    const pages = pageTexts(await buffer);
    const axisPage = pages.findIndex((t) => t.includes('2026-09-20 23:00'));
    assert.ok(axisPage >= 0, 'the axis label must be drawn');
    assert.equal(pages.findIndex((t) => t.includes('the estate')), axisPage,
      'the caption must not be one page further on than the series it describes');
  });
});

describe('⛔ ensureSpace reports; it does not pretend', () => {
  it('says so when a fresh page is STILL not enough', () => {
    const { doc, layout } = realDoc();
    const page = layout.pageH - doc.page.margins.top - doc.page.margins.bottom;
    const r = chassis.ensureSpace(doc, layout, page + 1);
    assert.equal(r.broke, true, 'it still breaks — a fresh page is the most room there is');
    assert.equal(r.fits, false, '⛔ but it must not report success for a block it cannot fit');
    assert.equal(r.measured, true);
    assert.ok(r.available <= r.pageAvailable);
    doc.end();
  });

  it('reports a clean fit without breaking, and a break that resolves the fit', () => {
    const { doc, layout } = realDoc();
    const fit = chassis.ensureSpace(doc, layout, 50);
    assert.deepEqual([fit.broke, fit.fits], [false, true]);
    doc.y = layout.pageH - doc.page.margins.bottom - 10;
    const broke = chassis.ensureSpace(doc, layout, 200);
    assert.deepEqual([broke.broke, broke.fits], [true, true]);
    doc.end();
  });

  it('⛔ AN UNMEASURABLE NEED IS `null`, NEVER `false` AND NEVER `true`', () => {
    // The "we could not measure this" case. `false` here would be a caller's
    // licence to drop content on the strength of a number nobody read, and
    // `true` would be the failed-read-as-a-fact rule in page layout.
    const { doc, layout } = realDoc();
    for (const bad of [NaN, undefined, null, 'tall', {}, Infinity, -Infinity]) {
      const r = chassis.ensureSpace(doc, layout, bad);
      assert.equal(r.fits, null, `${String(bad)} must report an unknown fit`);
      assert.equal(r.measured, false, `${String(bad)} is not a measurement`);
      assert.equal(r.broke, false, 'and it must not repaginate on a value it could not read');
    }
    // `null` is distinguishable from `false` by identity, which is the whole point.
    assert.notEqual(chassis.ensureSpace(doc, layout, NaN).fits, false);
    doc.end();
  });
});

describe('⛔ a chart taller than one page is bounded and counted, never shredded', () => {
  // ⛔ UNREACHABLE FROM ANY CALL SITE TODAY and pinned anyway: every caller
  // passes an explicit max of 10, 12 or 15, and the smallest row count that
  // overruns an A4 page at margin 40 is 38. Measured BEFORE the fix, by handing
  // drawBarChart more rows than a page holds: 38 rows -> 3 pages, 45 -> 17
  // pages (38 bars on one page then ONE BAR PER PAGE, caption on page 16 of
  // 17), 60 -> 47 pages. `ensureSpace` can add exactly one page; the chart then
  // kept drawing from its own local cursor, so every remaining label triggered
  // another.
  const rows = (n) => Array.from({ length: n }, (_, i) => ({ label: `BAR${i}`, value: n - i }));

  for (const n of [38, 45, 60]) {
    it(`${n} rows stay on one page, and the ones that do not fit are counted`, async () => {
      const { doc, layout, buffer } = realDoc();
      doc.y = bottomOf(doc, layout) - 60;
      drawBarChart(doc, layout, rows(n), { max: n, caption: CAPTION_ONE_LINE });
      const pageCount = doc.bufferedPageRange().count;
      doc.end();
      const pages = pageTexts(await buffer);

      assert.ok(pageCount <= 2, `one break, not ${pageCount} pages`);
      assert.equal(pages.length, 1, 'all of the chart\'s ink on a single page');

      const drawn = (pages[0].match(/BAR\d+/g) || []).length;
      assert.ok(drawn > 0 && drawn < n, `some rows drawn (${drawn}) and some withheld`);

      // ⛔ THE WITHHELD ROWS ARE DISCLOSED AND THE COUNT RECONCILES. A shorter
      // chart that looks complete is the failure this file documents twice over.
      const m = pages[0].match(/\+\s*(\d+)\s*more not drawn/);
      assert.ok(m, 'the undrawn rows must be disclosed on the page');
      assert.equal(Number(m[1]) + drawn, n, 'drawn + withheld must account for every row');

      // And the caption is still attached to the chart.
      assert.ok(pages[0].includes('totalled below'), 'the caption stays with the chart');
    });
  }

  it('a chart that fits is untouched: every row drawn and no disclosure', async () => {
    // The guard must not fire on the fleet's real charts. 15 rows is what the
    // two largest call sites pass.
    const { doc, layout, buffer } = realDoc();
    drawBarChart(doc, layout, rows(15), { max: 15, caption: CAPTION_ONE_LINE });
    doc.end();
    const pages = pageTexts(await buffer);
    assert.equal(pages.length, 1);
    assert.equal((pages[0].match(/BAR\d+/g) || []).length, 15, 'all fifteen bars');
    assert.equal(/more not drawn/.test(pages[0]), false, 'nothing to disclose');
  });
});

describe('⛔ two hueless disclosure lines may not be printed on top of each other', () => {
  it('the unmeasurable-slice note clears the legend truncation note', () => {
    // Measured before the fix at entry y=200, size 120, 12 sized slices + 1
    // unsized: the truncation disclosure printed at y=336 and is 8.67px tall,
    // and the unsized note printed at y=342 — a 2.67px OVERPRINT of this
    // product's own two "we could not tell you everything" sentences, both in
    // the same hueless 7.5pt grey.
    const { doc, layout } = realDoc();
    const seen = traceText(doc);
    doc.y = 200;
    const slices = Array.from({ length: 12 }, (_, i) => ({ label: `SLICE${i}`, value: 12 - i }));
    slices.push({ label: 'UNSIZEDONE', value: null, unmeasured: true });
    drawDonut(doc, layout, slices, { caption: CAPTION_ONE_LINE });
    doc.end();

    const trunc = seen.find((s) => /more, drawn but not listed/.test(s.text));
    const unsizedNote = seen.find((s) => s.text.includes('UNSIZEDONE'));
    const caption = seen.find((s) => s.text.includes('totalled below'));
    assert.ok(trunc && unsizedNote && caption, 'all three lines must be drawn');

    const LINE = 8.67; // 7.5pt Helvetica, measured
    assert.ok(unsizedNote.y >= trunc.y + LINE,
      `the unsized note at y=${unsizedNote.y} overprints the truncation note at y=${trunc.y}`);
    assert.ok(caption.y > unsizedNote.y, 'and the caption clears the unsized note');
  });
});

describe('⛔ drawDonut formats a value exactly the way drawBarChart does (opts.format)', () => {
  it('honours a byte formatter instead of printing a gigabyte as "1.1B"', async () => {
    const GIB = 1073741824;
    const fmtBytes = (n) => `${(n / 1024 ** 3).toFixed(1)} GB`;
    const { doc, layout, buffer } = realDoc();
    drawDonut(doc, layout, [
      { label: 'INBOUND', value: GIB },
      { label: 'OUTBOUND', value: GIB / 2 },
    ], { format: fmtBytes });
    doc.end();
    const text = pageTexts(await buffer).join('');
    assert.ok(text.includes('1.0 GB'), `expected the formatter's output, got: ${text}`);
    assert.equal(text.includes('1.1B'), false,
      'fmtCompact\'s count-shaped suffix must not survive a format option');
  });

  it('⛔ the DEFAULT is unchanged, so no existing donut was restyled', async () => {
    const { doc, layout, buffer } = realDoc();
    drawDonut(doc, layout, [{ label: 'ONLY', value: 1073741824 }]);
    doc.end();
    assert.ok(pageTexts(await buffer).join('').includes('1.1B'));
    assert.equal(fmtCompact(1073741824), '1.1B');
  });

  it('the option is spelled and called the same in both helpers', async () => {
    // One convention, not two. Same key, same single argument, same default —
    // asserted by OUTPUT: the identical formatter must produce the identical
    // string in a bar chart and in a donut for the same value.
    const seenBar = [];
    const seenDonut = [];
    const fmt = (n) => `FMT<${n}>`;

    const a = realDoc();
    drawBarChart(a.doc, a.layout, [{ label: 'x', value: 4242 }], { format: fmt });
    a.doc.end();
    seenBar.push(pageTexts(await a.buffer).join(''));

    const b = realDoc();
    drawDonut(b.doc, b.layout, [{ label: 'x', value: 4242 }], { format: fmt });
    b.doc.end();
    seenDonut.push(pageTexts(await b.buffer).join(''));

    assert.ok(seenBar[0].includes('FMT<4242>'), 'drawBarChart calls format(value)');
    assert.ok(seenDonut[0].includes('FMT<4242>'), 'and drawDonut calls it identically');
  });
});
