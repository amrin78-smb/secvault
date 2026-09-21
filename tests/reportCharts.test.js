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
