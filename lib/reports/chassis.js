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

  if (footerStamp) {
    doc.y = my;
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

module.exports = {
  // palette
  ACCENT, NAVY, MUTED, LIGHT, BORDER, GREEN, INK,
  // text
  pdfSafe, installPdfSafeText, fmtStamp,
  // layout
  layoutOf, ensureSpace,
  // blocks
  drawCover, sectionTitle, paragraph, labelledNote, drawTable, stampHeadersFooters,
};
