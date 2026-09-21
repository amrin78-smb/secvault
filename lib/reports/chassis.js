'use strict';

// lib/reports/chassis.js — the shared PDF chassis for every SecVault report.
//
// ⛔ WHY THIS EXISTS, AND WHAT THE REFACTOR ACTUALLY FOUND.
//
// `complianceReport.js` and `ruleChangeRequestReport.js` each carried their own
// private copy of SEVEN helpers — pdfSafe, installPdfSafeText, fmtStamp,
// drawCover, sectionTitle, drawTable, stampHeadersFooters. The second file's
// own header note says the helpers were "ported" from the first.
//
// They had NOT stayed in step. Measured before extraction: all four of the
// drawing helpers had diverged, and `ruleChangeRequestReport.js` had grown
// three more the other never received — `ensureSpace`, `paragraph` and
// `labelledNote`.
//
// ⛔ THE IMPORTANT ONE IS `ensureSpace`, AND ITS ABSENCE WAS A LATENT BUG IN
// THE MONTHLY COMPLIANCE PDF. Its comment records a real observed failure: a
// table header started 20px above the bottom margin produced FIVE pages each
// carrying a single column heading, with the rows on a sixth. That fix was
// written into the change-request report and never travelled back to the
// compliance report, which is the one emailed to stakeholders every month.
// Measured on the live fleet the compliance PDF is 17 pages and none of them is
// sparse, so the defect is LATENT rather than firing — it waits for a data
// volume that lands a table header in the danger zone.
//
// That is the argument for a chassis in one sentence: a fix applied to one copy
// of duplicated code is not applied to the other, and nobody finds out until
// the shape of the data changes.
//
// ⛔ EXTRACTION MUST NOT CHANGE OUTPUT. A report is an audit artefact; silently
// repaginating one is not a refactor, it is a new document with the old name.
// So every difference between the two copies is PARAMETERISED here rather than
// unified, and each caller passes the options that reproduce exactly what it
// rendered before. Unifying the look is a design decision and belongs in its
// own commit, where someone can look at the before and after on purpose.
//
// The one exception is deliberate and is the point of the exercise: the
// compliance report now inherits `ensureSpace`. That can only ever ADD a page
// break that pdfkit would otherwise have mangled, and on current data it adds
// none — which is why the byte-comparison in tests/reportChassis.test.js is
// meaningful rather than merely reassuring.

const { PRODUCT_NAME, PRODUCT_TAGLINE } = require('../branding');

// ── Palette ────────────────────────────────────────────────────────────────
// ⛔ Both reports already carried IDENTICAL values for these; the only
// difference was that complianceReport.js aliased `RED = ACCENT`, a leftover
// from when the product's brand colour was red. The alias is not reproduced —
// a colour constant named for a colour it is not is how the palette rot in
// app/globals.css started. Mirrors the CSS custom properties named alongside.
const ACCENT = '#098294'; // --primary
const NAVY = '#101826'; // --navy (shell)
const MUTED = '#69788B'; // --text-muted
const LIGHT = '#F1F4F8'; // --surface-subtle
const BORDER = '#DDE3EB'; // --border
const GREEN = '#17825A'; // --green / --sev-ok
const INK = '#0D131C'; // body text on the cover

// ── Status ramp ────────────────────────────────────────────────────────────
// ⛔ THE PRINTED COUNTERPART OF THE SEVERITY TOKENS in app/globals.css, and it
// must not drift from them: a finding that is amber on screen and red on the
// PDF an auditor holds is two different claims about the same fact.
//
// Promoted here after a THIRD file began carrying the same four literals. The
// first extraction deliberately left the severity ramp behind, on the grounds
// that it is semantic rather than chrome — which was the wrong call for the
// same reason the seven drawing helpers were: identical constants copied into
// three files are three chances to fix one and miss two.
//
// ⛔ UNMEASURED HAS NO HUE, deliberately. It is the printed form of
// --unmeasured: a value SecVault could not measure is neither good news nor
// bad, and giving it a ramp colour in either direction is the failed-read-as-
// a-fact rule committed in ink, where it cannot be corrected by a refresh.
const STATUS_RED = '#D4353B'; // --red / --sev-crit
const ORANGE = '#E05E12';     // --orange / --sev-high
const YELLOW = '#B7791F';     // --yellow / --sev-med
const BLUE = '#2F6FE0';       // --blue
const UNMEASURED = '#6D7784';  // --unmeasured (no hue, by design)

// ⛔ CHART-ONLY TINTS, AND THE REASON THEY ARE NOT FREE COLOURS. A donut of
// session outcomes holds several slices that are all the SAME judgement: on
// this fleet `allow`, `accept` and `close` are all traffic that was permitted,
// and they are the three largest slices. Drawing them in three unrelated hues
// says they are three different kinds of thing; drawing them in one flat GREEN
// makes the three largest slices indistinguishable — which is what the first
// render of that chart actually did. A ramp within the family keeps the
// semantics readable and the slices apart. They are tints of GREEN and
// STATUS_RED and must stay that way: a chart is not licensed to introduce a
// hue the status ramp does not have.
// ⛔ LONG ENOUGH NOT TO WRAP. The outcomes donut draws up to six slices, and
// on this fleet five of them were allowed verbs - with a four-entry ramp the
// fifth wrapped back to the first colour and `server-rst` rendered identically
// to `allow`. A ramp that repeats is a legend that lies.
const ALLOWED_RAMP = ['#17825A', '#2E9C70', '#54B68E', '#84CEAE', '#0E5C40', '#AFE0CB'];
const DENIED_RAMP = ['#D4353B', '#E1605F', '#EC8B88', '#8E2126', '#F5B7B4'];

// ── Text safety ────────────────────────────────────────────────────────────

/**
 * pdfkit's built-in Helvetica is WinAnsi and has no glyph for characters that
 * arrive from a vendor rule name or an analyser detail string. Sanitise to
 * ASCII once, from one place.
 */
function pdfSafe(s) {
  if (s == null) return '';
  return String(s)
    .replace(/[–—―]/g, '-')
    .replace(/•/g, '-')
    .replace(/[‘’‚‛]/g, "'")
    .replace(/[“”„‟]/g, '"')
    .replace(/ /g, ' ');
}

/** Wrap doc.text so every string drawn anywhere is sanitised. */
function installPdfSafeText(doc) {
  const origText = doc.text.bind(doc);
  doc.text = (text, ...rest) => origText(pdfSafe(text), ...rest);
  return doc;
}

/**
 * The generated-at stamp. ALWAYS UTC with an explicit ' UTC' suffix — a report
 * is read in a different timezone from the one that produced it, and a bare
 * local timestamp on an audit artefact is ambiguous evidence.
 *
 * ⛔ This is ruleChangeRequestReport.js's version verbatim, which is a strict
 * superset of complianceReport.js's: identical output for a valid Date, plus
 * guards for null and for an unparseable value. An earlier draft of this file
 * REWROTE this function from memory and produced a different format with no
 * UTC marker — which would have silently restamped every report. Copy these
 * helpers; do not reconstruct them.
 */
function fmtStamp(value) {
  if (!value) return '';
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString('en-GB', { hour12: false, timeZone: 'UTC' }) + ' UTC';
}

// ── Layout ─────────────────────────────────────────────────────────────────

/**
 * The layout object every helper below takes. Derived from the live doc so a
 * caller cannot hand round stale page dimensions after an addPage().
 */
function layoutOf(doc) {
  const pageW = doc.page.width;
  const pageH = doc.page.height;
  const left = doc.page.margins.left;
  const right = pageW - doc.page.margins.right;
  return { pageW, pageH, left, right, contentW: right - left };
}

/**
 * ⛔ Break to a new page if `needed` px would not fit.
 *
 * Every caller asks for the height it MEASURED, never a guessed constant:
 * pdfkit draws at the y it is handed, and a block started too near the bottom
 * either vanishes off the page or gets auto-flowed a fragment at a time. Both
 * were observed — a table header started 20px above the bottom margin produced
 * FIVE pages each carrying a single column heading, with the rows on a sixth.
 */
function ensureSpace(doc, layout, needed) {
  if (doc.y + needed > layout.pageH - doc.page.margins.bottom) doc.addPage();
}

// ── Cover ──────────────────────────────────────────────────────────────────

/**
 * The report cover.
 *
 * ⛔ THE GEOMETRY OPTIONS EXIST TO PRESERVE EXISTING OUTPUT, NOT AS STYLE KNOBS.
 * The two reports' covers had drifted: one draws its title at 28pt from a fixed
 * y with the accent rule at a fixed 238, the other at 26pt flowing from the
 * title with a computed rule. Unifying them here would silently restyle a
 * document an auditor may already hold. Each caller passes what it had.
 *
 * When someone does decide to unify the cover, delete these options in that
 * commit and look at both PDFs side by side — do not let it happen as a side
 * effect of an unrelated change.
 *
 * @param {object} o
 * @param {string}   o.title
 * @param {string}  [o.subtitle]      second line under the title
 * @param {string}  [o.company]
 * @param {string}   o.generatedAt
 * @param {Array}   [o.meta]          [[label, value], ...] rows
 * @param {Array}   [o.summary]       [{value, label, color}] chips
 * @param {boolean} [o.fixedGeometry] reproduce complianceReport's fixed layout
 * @param {number}  [o.titleSize=26]
 * @param {boolean} [o.footerStamp]   draw "Generated ..." under the chips
 */
function drawCover(doc, o, layout) {
  const {
    title, subtitle, company, generatedAt, meta, summary,
    fixedGeometry = false, titleSize = 26, footerStamp = false,
  } = o;
  const { pageW, left, contentW } = layout;

  doc.rect(0, 0, pageW, 150).fill(NAVY);
  doc.rect(0, 150, pageW, 6).fill(ACCENT);
  doc.roundedRect(left, 44, 64, 64, 10).fill(ACCENT);
  doc.fillColor('#fff').fontSize(30).font('Helvetica-Bold')
    .text('S', left, 60, { width: 64, align: 'center' });
  // ⛔ PRODUCT_NAME, not a hardcoded 'SecVault'. complianceReport.js hardcoded
  // it while reading PRODUCT_TAGLINE from the branding module one line below —
  // the same branding-surface leak the page header carried. Same value today,
  // so the output is unchanged; the difference is that a rebrand now reaches it.
  doc.fillColor('#fff').fontSize(22).font('Helvetica-Bold')
    .text(PRODUCT_NAME, left + 80, 56);
  doc.fillColor('#B9C6D6').fontSize(11).font('Helvetica')
    .text(PRODUCT_TAGLINE, left + 80, 86);

  let ruleY;
  if (fixedGeometry) {
    doc.fillColor(NAVY).fontSize(titleSize).font('Helvetica-Bold')
      .text(title, left, 196, { width: contentW });
    ruleY = 238;
  } else {
    doc.fillColor(NAVY).fontSize(titleSize).font('Helvetica-Bold')
      .text(title, left, 190, { width: contentW });
    if (subtitle) {
      doc.fillColor(MUTED).fontSize(12).font('Helvetica')
        .text(subtitle, left, doc.y + 2, { width: contentW });
    }
    ruleY = doc.y + 10;
  }
  doc.moveTo(left, ruleY).lineTo(left + 120, ruleY).lineWidth(3).stroke(ACCENT);

  // The two covers also differ in metadata metrics. Fixed geometry uses the
  // wider 11pt/120px/22px rhythm; the flowing one uses 10pt/130px/19px.
  const metaSize = fixedGeometry ? 11 : 10;
  const labelW = fixedGeometry ? 120 : 130;
  const valueX = fixedGeometry ? 130 : 140;
  const rowStep = fixedGeometry ? 22 : 19;

  const rows = meta || (fixedGeometry
    ? [['Company', company], ['Generated', generatedAt]]
    : []);

  let my = fixedGeometry ? 262 : ruleY + 20;
  doc.fontSize(metaSize);
  rows.forEach(([k, v]) => {
    doc.fillColor(MUTED).font('Helvetica-Bold').text(k, left, my, { width: labelW });
    doc.fillColor(INK).font('Helvetica')
      .text(v == null || v === '' ? '-' : String(v), left + valueX, my, { width: contentW - valueX });
    my += rowStep;
  });

  if (summary && summary.length) {
    my += 12;
    doc.fillColor(NAVY).fontSize(13).font('Helvetica-Bold').text('Summary', left, my);
    my += 22;
    let cx = left;
    const chipW = Math.min(170, (contentW - 30) / Math.max(summary.length, 1));
    summary.forEach((s) => {
      doc.roundedRect(cx, my, chipW - 10, 52, 8).fillAndStroke(LIGHT, BORDER);
      doc.fillColor(s.color || NAVY).fontSize(18).font('Helvetica-Bold')
        .text(String(s.value), cx + 10, my + 8, { width: chipW - 26 });
      doc.fillColor(MUTED).fontSize(8).font('Helvetica')
        .text(s.label, cx + 10, my + 32, { width: chipW - 26 });
      cx += chipW;
    });
    my += 66;
  }

  // ⛔ THE COVER OWNS THE CURSOR IT LEAVES BEHIND. A caller that did not pass
  // `footerStamp` got back whatever y pdfkit happened to be at, which on a
  // cover that drew summary CHIPS was a point INSIDE them — so the next block
  // was written over the chip row. Observed on the Traffic Activity cover: the
  // coverage note, the one thing this product insists on printing before any
  // total, was drawn across the chips and half-unreadable.
  //
  // ⛔ CORRECTED 2026-09-21: the commit that introduced this line called it "a
  // no-op for the eight reports that pass footerStamp and the fix for the ones
  // that do not", and cited the byte-comparison in tests/reportChassis.test.js
  // as proof. Both halves were wrong in the same direction. There is a NINTH
  // caller — lib/engines/complianceReport.js, the monthly PDF emailed to
  // stakeholders — which passes no footerStamp, so its body DID move, by
  // 24.75pt. It moved for the better (its "Fleet Summary" heading had been
  // drawing at y 381 while the chips occupy 340-392, i.e. on top of them, and
  // the rendered page 1 is now clean), but it moved, and the file header says
  // EXTRACTION MUST NOT CHANGE OUTPUT. And the test cited could not have shown
  // it: comparePdfs runs on hand-built fakePdf() fixtures, so NO test renders a
  // real report and the "byte comparison" stays green through any repagination
  // of any document. The invariant below is pinned behaviourally instead.
  doc.y = my;

  if (footerStamp) {
    doc.fillColor(MUTED).fontSize(9).font('Helvetica')
      .text(`Generated ${generatedAt}`, left, doc.y, { width: contentW });
  }
}

// ── Blocks ─────────────────────────────────────────────────────────────────

function sectionTitle(doc, layout, text) {
  const { left, contentW } = layout;
  ensureSpace(doc, layout, 46);
  doc.fillColor(NAVY).fontSize(12).font('Helvetica-Bold')
    .text(text, left, doc.y, { width: contentW });
  doc.y += 8;
}

function paragraph(doc, layout, text, color = MUTED, size = 9) {
  const { left, contentW } = layout;
  const h = doc.fontSize(size).font('Helvetica')
    .heightOfString(pdfSafe(text), { width: contentW });
  ensureSpace(doc, layout, h + 6);
  doc.fillColor(color).fontSize(size).font('Helvetica')
    .text(text, left, doc.y, { width: contentW });
  doc.y += 6;
}

/** A bold label with its explanatory paragraph, kept together on one page. */
function labelledNote(doc, layout, label, color, text) {
  const { left, contentW } = layout;
  const lh = doc.fontSize(9).font('Helvetica-Bold')
    .heightOfString(pdfSafe(label), { width: contentW });
  const th = doc.fontSize(9).font('Helvetica')
    .heightOfString(pdfSafe(text), { width: contentW - 12 });
  ensureSpace(doc, layout, lh + th + 8);
  doc.fillColor(color).fontSize(9).font('Helvetica-Bold')
    .text(label, left, doc.y, { width: contentW });
  doc.fillColor(MUTED).fontSize(9).font('Helvetica')
    .text(text, left + 12, doc.y, { width: contentW - 12 });
  doc.y += 6;
}


// ── Tables ─────────────────────────────────────────────────────────────────

/**
 * Wrapped-height zebra table. Measures every cell so a row fits its tallest,
 * and redraws the header after a page break.
 *
 * ⛔ THIS IS THE change-request COPY, which was the more evolved of the two.
 * It is a strict superset of the compliance copy except for one caller-specific
 * string, now `o2.emptyText`. What it adds:
 *   - the two `ensureSpace` calls, i.e. THE LATENT FIX the compliance report
 *     never received (see this file's header);
 *   - `c.font` accepted as a function OR a string, where the compliance copy
 *     hardcoded 'Helvetica'. A caller that passes nothing still gets
 *     'Helvetica', so adopting the superset changes no existing output.
 *
 * @param {object} [o2]
 * @param {boolean} [o2.continueOnPage]  continue on the current page rather
 *   than starting a new one
 * @param {string}  [o2.emptyText='No data.']
 */
function drawTable(doc, tbl, layout, o2 = {}) {
  const { columns, rows } = tbl;
  const { left, contentW, pageH } = layout;
  const rowH = 18;
  const headerH = 22;
  const pad = 5;
  if (o2.continueOnPage) {
    doc.y = doc.y + 8;
    // ⛔ The header AND at least one row must fit, or the header is drawn into
    // the margin and pdfkit auto-flows it one column heading per page. Checked
    // here rather than trusted to the caller's section title.
    ensureSpace(doc, layout, headerH + rowH);
  } else {
    doc.addPage();
  }
  const totalW = columns.reduce((a, c) => a + (c.width || 80), 0);
  const scale = contentW / totalW;
  const colX = [];
  let acc = left;
  columns.forEach((c) => {
    colX.push(acc);
    acc += (c.width || 80) * scale;
  });
  const colW = (c) => (c.width || 80) * scale;

  function drawHeader() {
    const y = doc.y;
    doc.rect(left, y, contentW, headerH).fill(NAVY);
    doc.fillColor('#fff').fontSize(8).font('Helvetica-Bold');
    columns.forEach((c, i) => {
      doc.text(c.label, colX[i] + 4, y + 7, { width: colW(c) - 8, align: c.align || 'left', ellipsis: true, lineBreak: false });
    });
    doc.y = y + headerH;
  }

  drawHeader();
  rows.forEach((r, idx) => {
    doc.font('Helvetica').fontSize(8);
    let rh = rowH;
    columns.forEach((c) => {
      const txt = String(r[c.key] == null ? '' : r[c.key]);
      const th = doc.heightOfString(pdfSafe(txt), { width: colW(c) - 8 }) + pad * 2;
      if (th > rh) rh = th;
    });
    if (doc.y + rh > pageH - doc.page.margins.bottom) {
      doc.addPage();
      drawHeader();
      doc.font('Helvetica').fontSize(8);
    }
    const y = doc.y;
    if (idx % 2 === 1) doc.rect(left, y, contentW, rh).fill(LIGHT);
    columns.forEach((c, i) => {
      const color = typeof c.color === 'function' ? c.color(r) || INK : c.color || INK;
      doc
        .fillColor(color)
        .font(typeof c.font === 'function' ? c.font(r) : c.font || 'Helvetica')
        .fontSize(8)
        .text(String(r[c.key] == null ? '' : r[c.key]), colX[i] + 4, y + pad, { width: colW(c) - 8, align: c.align || 'left' });
    });
    doc.y = y + rh;
  });

  if (rows.length === 0) {
    ensureSpace(doc, layout, 32);
    doc.fillColor(MUTED).fontSize(11).font('Helvetica-Oblique')
      .text(o2.emptyText || 'No data.', left, doc.y + 14, { width: contentW, align: 'center' });
  }
}

/**
 * Running header and footer on every buffered page.
 *
 * ⛔ The two copies of this differed ONLY in line breaking — one chained
 * .fillColor().fontSize().font() across four lines, the other on one. Verified
 * semantically identical before extraction; no behaviour is being chosen here.
 */
function stampHeadersFooters(doc, { title, company, generatedAt }) {
  const pageW = doc.page.width;
  const pageH = doc.page.height;
  const left = doc.page.margins.left;
  const right = pageW - doc.page.margins.right;
  const contentW = right - left;
  const range = doc.bufferedPageRange();
  const stampH = 12;
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    if (i > range.start) {
      doc.fillColor(MUTED).fontSize(8).font('Helvetica')
        .text(title, left, 18, { width: contentW / 2, align: 'left', lineBreak: false, height: stampH });
      doc.text(company, left + contentW / 2, 18, { width: contentW / 2, align: 'right', lineBreak: false, height: stampH });
      doc.moveTo(left, 30).lineTo(right, 30).lineWidth(0.5).strokeColor(BORDER).stroke();
    }
    doc.fillColor(MUTED).fontSize(8).font('Helvetica')
      .text(`Generated ${generatedAt}`, left, pageH - 26, { width: contentW / 2, align: 'left', lineBreak: false, height: stampH });
    doc.text(`Page ${i - range.start + 1} of ${range.count}`, left + contentW / 2, pageH - 26, {
      width: contentW / 2,
      align: 'right',
      lineBreak: false,
      height: stampH,
    });
  }
}

// ── Charts ─────────────────────────────────────────────────────────────────
//
// ⛔ HAND-ROLLED VECTORS, NO CHARTING LIBRARY. package.json carries no
// devDependencies by policy and pdfkit already draws paths; a chart library
// would ship to a firewall-management box through `npm ci` to produce shapes
// that are thirty lines of arithmetic. Same call the topology map made on the
// client, for the same reason.
//
// ⛔ A CHART MAY NOT HIDE WHAT A TABLE WOULD HAVE SHOWN. These are the rules
// that make a picture as honest as the number beside it:
//   - an UNMEASURABLE quantity is drawn in --unmeasured grey and LABELLED, never
//     omitted and never rendered as zero. A pie that silently drops the slice it
//     could not measure re-normalises every other slice and is simply wrong.
//   - a gap in a time series is drawn, not closed up. Joining the line across a
//     collector outage turns missing data into a smooth trend.
//   - every percentage states its denominator in the caption, because a share
//     of the measured subset is not a share of the estate.

// ⛔ NO GREY AND NO NEAR-BLACK IN HERE. Both were in the first version, and
// both are already spoken for: UNMEASURED grey is this product's printed mark
// for "we could not measure this", and NAVY is the chrome. A category drawn in
// either one reads as a non-answer — observed live, `ms-ds-smbv3` rendered in
// the same grey the report uses for an em dash. Every entry below is a hue that
// means nothing but "a different one from its neighbour".
// ⛔ AND NO VERDICT COLOUR EITHER. GREEN and STATUS_RED are what the session-
// outcomes donut means by "permitted" and "refused", captioned in those words
// two sections above the protocols donut — which then painted its 3rd protocol
// in exactly that green and its 6th in exactly that red, on a fleet that
// reports both the name and the number form of every protocol, so six or more
// slices is the normal case. The ramp tints were in here too. A category chart
// may not borrow a hue that a neighbouring chart has defined as a judgement.
const CHART_PALETTE = ['#098294', '#2F6FE0', '#7A5AF8', '#E05E12', '#B7791F', '#0E7490',
  '#9D4EDD', '#C2410C'];

function chartColor(i) { return CHART_PALETTE[i % CHART_PALETTE.length]; }

function fmtCompact(n) {
  if (n === null || n === undefined || !Number.isFinite(Number(n))) return '\u2014';
  const v = Number(n);
  if (Math.abs(v) >= 1e9) return `${(v / 1e9).toFixed(1)}B`;
  if (Math.abs(v) >= 1e6) return `${(v / 1e6).toFixed(1)}M`;
  if (Math.abs(v) >= 1e3) return `${(v / 1e3).toFixed(1)}k`;
  return String(Math.round(v));
}

/**
 * Horizontal bars — the right shape for a top-N list, because the labels are
 * long and a vertical axis would clip them.
 *
 * rows: [{label, value, color?, note?}]  value === null means NOT MEASURED.
 */
function drawBarChart(doc, layout, rows, opts = {}) {
  // ⛔ A CALLER THAT PASSES MORE ROWS THAN `max` IS TRUNCATED SILENTLY, which
  // is why `max` is spelled out at each call site rather than left to default.
  // Observed: a chart sliced to 15 by its caller rendered 10 and looked
  // complete — the same shape of wrongness as the work queue's PER_SOURCE_CAP,
  // which is why that one discloses "shown of total".
  const items = (rows || []).slice(0, opts.max || 10);
  if (items.length === 0) return;
  const { left, contentW } = layout;
  const barH = opts.barH || 14;
  const gap = 6;
  const labelW = opts.labelW || 150;
  const valueW = 58;
  const trackW = contentW - labelW - valueW - 12;

  ensureSpace(doc, layout, items.length * (barH + gap) + 16);

  // ⛔ The scale comes from the largest MEASURED value. A null must not become
  // a zero-length bar that reads as "nearly none".
  // ⛔ FINITE-ONLY, for the same reason drawTimeSeries is: one NaN in the list
  // blanked every bar while the value column kept printing real numbers.
  const max = items.reduce(
    (m, r) => (Number.isFinite(Number(r && r.value)) ? Math.max(m, Number(r.value)) : m), 0
  );

  let y = doc.y + 4;
  for (const [i, r] of items.entries()) {
    const measured = r.value !== null && r.value !== undefined && Number.isFinite(Number(r.value));
    doc.fillColor(INK).fontSize(8).font('Helvetica')
      .text(String(r.label ?? ''), left, y + 3, { width: labelW - 8, ellipsis: true, lineBreak: false });

    doc.roundedRect(left + labelW, y, trackW, barH, 3).fill(LIGHT);
    if (measured && max > 0) {
      const w = Math.max(2, (Number(r.value) / max) * trackW);
      doc.roundedRect(left + labelW, y, w, barH, 3).fill(r.color || opts.color || ACCENT);
    } else if (!measured) {
      // Hueless hatch stand-in: a thin grey rule across the track, so the row is
      // visibly present and visibly not a measurement.
      doc.rect(left + labelW, y + barH / 2 - 0.5, trackW, 1).fill(UNMEASURED);
    }

    doc.fillColor(measured ? INK : UNMEASURED).fontSize(8).font('Helvetica-Bold')
      .text(measured ? (opts.format || fmtCompact)(r.value) : '\u2014', left + labelW + trackW + 8, y + 3,
        { width: valueW, align: 'right', lineBreak: false });
    y += barH + gap;
  }
  doc.y = y + 2;
  if (opts.caption) {
    doc.fillColor(MUTED).fontSize(7.5).font('Helvetica').text(opts.caption, left, doc.y, { width: contentW });
    doc.y += 4;
  }
}

// One donut segment as an SVG path. pdfkit understands SVG path data, which is
// the whole reason a pie needs no library.
function arcPath(cx, cy, rOuter, rInner, a0, a1) {
  const p = (r, a) => [cx + r * Math.cos(a), cy + r * Math.sin(a)];
  const large = a1 - a0 > Math.PI ? 1 : 0;
  const [x0, y0] = p(rOuter, a0);
  const [x1, y1] = p(rOuter, a1);
  const [x2, y2] = p(rInner, a1);
  const [x3, y3] = p(rInner, a0);
  return `M ${x0} ${y0} A ${rOuter} ${rOuter} 0 ${large} 1 ${x1} ${y1} `
    + `L ${x2} ${y2} A ${rInner} ${rInner} 0 ${large} 0 ${x3} ${y3} Z`;
}

/**
 * A donut with a legend beside it.
 *
 * slices: [{label, value, color?, unmeasured?}]
 * ⛔ A slice marked `unmeasured` is drawn in grey AND excluded from the
 * percentages, with the exclusion stated in the caption — including it in the
 * denominator would imply we know its size.
 */
function drawDonut(doc, layout, slices, opts = {}) {
  // ⛔ A SLICE WHOSE SIZE IS UNKNOWN IS NOT A SLICE OF ZERO, AND IT IS NOT
  // DROPPED SILENTLY. The filter used to discard every non-positive value
  // BEFORE consulting the `unmeasured` flag, so passing {value: null,
  // unmeasured: true} — exactly what the flag invites — removed it from the ring
  // and then reported the survivors as 100%, which is the re-normalisation this
  // function's own docblock forbids eight lines above. It cannot be drawn to
  // scale, so it is reported to the caller instead of being quietly lost.
  const all = (slices || []).filter(Boolean);
  const unsized = all.filter((x) => x.unmeasured && !(Number(x.value) > 0));
  const items = all.filter((x) => Number(x.value) > 0);
  if (items.length === 0) return;
  const { left, contentW } = layout;
  const size = opts.size || 120;
  const r = size / 2;
  const rInner = r * 0.58;

  ensureSpace(doc, layout, size + 24);
  const top = doc.y + 6;
  const cx = left + r;
  const cy = top + r;

  const measuredTotal = items
    .filter((s) => !s.unmeasured)
    .reduce((n, s) => n + Number(s.value), 0);
  const total = items.reduce((n, s) => n + Number(s.value), 0);

  let angle = -Math.PI / 2;
  items.forEach((s, i) => {
    const frac = total > 0 ? Number(s.value) / total : 0;
    const next = angle + frac * Math.PI * 2;
    doc.path(arcPath(cx, cy, r, rInner, angle, next))
      .fill(s.unmeasured ? UNMEASURED : (s.color || chartColor(i)));
    angle = next;
  });

  // Legend
  let ly = top;
  const lx = left + size + 18;
  const legendW = contentW - size - 18;
  for (const [i, s] of items.entries()) {
    const pctOf = s.unmeasured || measuredTotal === 0
      ? null
      : Math.round((Number(s.value) / measuredTotal) * 100);
    doc.rect(lx, ly + 2, 8, 8).fill(s.unmeasured ? UNMEASURED : (s.color || chartColor(i)));
    doc.fillColor(INK).fontSize(8).font('Helvetica')
      .text(`${s.label}  ${fmtCompact(s.value)}${pctOf === null ? '' : `  (${pctOf}%)`}`,
        lx + 13, ly, { width: legendW - 13, ellipsis: true, lineBreak: false });
    ly += 13;
    // ⛔ DISCLOSE THE TRUNCATION. The legend height is bounded by the ring's
    // diameter, so at the default size it holds 10 rows — while the ring keeps
    // drawing every slice. A legend shorter than its own chart looks complete,
    // which is the failure drawBarChart documents a hundred lines above and the
    // work queue's PER_SOURCE_CAP discloses.
    if (ly > top + size && i < items.length - 1) {
      doc.fillColor(UNMEASURED).fontSize(7.5).font('Helvetica')
        .text(`+ ${items.length - i - 1} more, drawn but not listed`, lx + 13, ly,
          { width: legendW - 13, lineBreak: false });
      break;
    }
  }

  doc.y = Math.max(cy + r, ly) + 6;
  // ⛔ NAMED, NOT DROPPED. These could not be drawn to scale, so they are
  // listed under the ring rather than vanishing from it.
  if (unsized.length > 0) {
    doc.fillColor(UNMEASURED).fontSize(7.5).font('Helvetica').text(
      `Not shown, because their size could not be measured: ${unsized.map((x) => x.label).join(', ')}.`,
      left, doc.y, { width: contentW }
    );
    doc.y += 10;
  }
  if (opts.caption) {
    doc.fillColor(MUTED).fontSize(7.5).font('Helvetica').text(opts.caption, left, doc.y, { width: contentW });
    doc.y += 4;
  }
}

/**
 * A filled time series.
 *
 * points: [{t: Date|string, value: number|null}] — value null == NOT MEASURED.
 * ⛔ A null is a GAP, drawn as a hueless tick at the baseline rather than joined
 * across. An hour with no data and an hour with no traffic are different facts,
 * and closing the line over the first one invents a smooth trend.
 */
function drawTimeSeries(doc, layout, points, opts = {}) {
  const pts = points || [];
  if (pts.length === 0) return;
  const { left, contentW } = layout;
  const h = opts.height || 90;

  ensureSpace(doc, layout, h + 28);
  const top = doc.y + 6;
  const w = contentW;
  // ⛔ THE SCALE SKIPS ANYTHING NOT FINITE, not merely null/undefined. A single
  // NaN made `max` NaN, `max > 0` false, and EVERY bar zero-height — while the
  // labels went on printing real numbers beside an empty chart.
  const max = pts.reduce(
    (m, p) => (Number.isFinite(Number(p && p.value)) ? Math.max(m, Number(p.value)) : m), 0
  );

  doc.rect(left, top, w, h).fill(LIGHT);
  const step = w / Math.max(pts.length, 1);
  const yOf = (v) => top + h - (max > 0 ? (Number(v) / max) * (h - 6) : 0);

  // Bars rather than a line: at hourly grain over a month the point count is in
  // the hundreds, and a 1px bar reads better than a polyline while making each
  // gap individually visible.
  // ⛔ A MEASURED VALUE IS NEVER DRAWN SHORTER THAN THE NOT-MEASURED MARK.
  // Without a floor, the reference fleet's own numbers inverted the design
  // system: against a 5.3M peak, an hour carrying 50,000 real events rendered
  // 0.79px and an hour carrying 5,000 rendered 0.079px, while the hueless
  // "no data" tick is a fixed 2px — so NOT MEASURED was the tallest thing on
  // every quiet stretch. A real measurement of any size outranks an absence.
  const UNMEASURED_TICK = 2;
  const MIN_MEASURED = UNMEASURED_TICK + 0.5;
  pts.forEach((p, i) => {
    const x = left + i * step;
    const measured = p.value !== null && p.value !== undefined && Number.isFinite(Number(p.value));
    const barW = Math.max(0.8, step - 0.4);
    if (measured) {
      const v = Number(p.value);
      // ⛔ A MEASURED ZERO IS DRAWN, AND IS NOT A GAP. `h = 0` meant it was
      // literally not rendered, so "this hour was quiet" and "this hour is
      // missing" both came out as blank background.
      const height = v <= 0 ? MIN_MEASURED : Math.max(MIN_MEASURED, top + h - yOf(v));
      doc.rect(x, top + h - height, barW, height).fill(opts.color || ACCENT);
    } else {
      doc.rect(x, top + h - UNMEASURED_TICK, barW, UNMEASURED_TICK).fill(UNMEASURED);
    }
  });
  doc.rect(left, top + h, w, 0.6).fill(BORDER);

  doc.y = top + h + 6;
  const first = pts[0];
  const last = pts[pts.length - 1];
  // ⛔ GUARDED, like fmtStamp 500 lines above and for the reason its own comment
  // gives. `new Date(x).toISOString()` throws RangeError on an unparseable
  // value, and an axis label is not worth killing a whole report for.
  const stampOf = (t) => {
    if (!t) return '';
    const d = t instanceof Date ? t : new Date(t);
    return Number.isNaN(d.getTime()) ? '' : d.toISOString().slice(0, 16).replace('T', ' ');
  };
  doc.fillColor(MUTED).fontSize(7).font('Helvetica')
    .text(stampOf(first.t), left, doc.y, { width: w / 2 })
    .text(stampOf(last.t), left + w / 2, doc.y - 9, { width: w / 2, align: 'right' });
  doc.y += 6;
  if (opts.caption) {
    doc.fillColor(MUTED).fontSize(7.5).font('Helvetica').text(opts.caption, left, doc.y, { width: w });
    doc.y += 4;
  }
}

module.exports = {
  // palette
  ACCENT, NAVY, MUTED, LIGHT, BORDER, GREEN, INK,
  STATUS_RED, ORANGE, YELLOW, BLUE, UNMEASURED, ALLOWED_RAMP, DENIED_RAMP,
  // text
  pdfSafe, installPdfSafeText, fmtStamp,
  // layout
  layoutOf, ensureSpace,
  // blocks
  drawCover, sectionTitle, paragraph, labelledNote, drawTable, stampHeadersFooters,
  // charts
  drawBarChart, drawDonut, drawTimeSeries, chartColor, fmtCompact,
};
