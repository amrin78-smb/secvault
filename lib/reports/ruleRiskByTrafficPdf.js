'use strict';
//
// lib/reports/ruleRiskByTrafficPdf.js — the Rule Risk by Traffic document.
//
// ⛔ THE CHART IS THE ARGUMENT. One horizontal bar per busiest rule, RED where
// that rule also carries a hygiene finding and teal where it does not. Nothing
// else in this product puts those two facts in the same picture, and no
// competitor can: a traffic tool has never read the rulebase and a policy tool
// has never seen a packet. Everything below the chart is the evidence for it.
//
// ⛔ AND THE COLOUR IS A CLAIM, so it is defined once. A bar is red because
// `worstFinding()` — the same function the tables rank on — returned something,
// never because the renderer decided a rule looked bad.

const PDFDocument = require('pdfkit');

const {
  MUTED, GREEN, STATUS_RED, ORANGE, ACCENT, UNMEASURED,
  fmtStamp, installPdfSafeText, layoutOf,
  drawCover, sectionTitle, paragraph, labelledNote, drawTable, stampHeadersFooters,
  drawBarChart, drawDonut, ensureSpace,
} = require('./chassis');
const { PRODUCT_NAME } = require('../branding');
const {
  buildRuleRiskData, headlineSentence, NEVER_MEASURABLE_FINDING,
} = require('./ruleRiskByTraffic');

const TITLE = 'Rule Risk by Traffic';
const NOT_MEASURED = '—';

const num = (n) => (n === null || n === undefined || Number.isNaN(Number(n))
  ? NOT_MEASURED
  : Number(n).toLocaleString('en-US'));

const pctOf = (x) => (x === null || x === undefined ? NOT_MEASURED : `${Math.round(x * 1000) / 10}%`);

// Severity -> ramp colour. ⛔ The severity words come from the analysis engine;
// this only maps them to ink, and an unrecognised one is HUELESS rather than
// quietly rendered as low — a severity this document does not understand is not
// a mild one.
const SEV_COLOR = { critical: STATUS_RED, high: ORANGE, medium: ACCENT, info: MUTED };
const sevColor = (s) => SEV_COLOR[String(s || '').toLowerCase()] || UNMEASURED;

// A rule label short enough for a bar but still identifying. Device first,
// because two firewalls very often carry a rule with the same name.
const barLabel = (r) => `${r.name} · ${r.deviceName}`;

function renderRuleRiskPdf(d) {
  const doc = new PDFDocument({ size: 'A4', margin: 40, bufferPages: true });
  installPdfSafeText(doc);
  const layout = layoutOf(doc);
  const chunks = [];
  doc.on('data', (c) => chunks.push(c));

  const generatedAt = fmtStamp(d.generatedAt);
  const t = d.totals;
  const wc = d.windowCoverage;
  const riskyIds = new Set(d.busiestWithRisk.map((r) => r.id));

  drawCover(doc, {
    title: TITLE,
    subtitle: `${d.scope} · last ${d.windowDays} days`,
    company: PRODUCT_NAME,
    generatedAt,
    meta: [
      ['Scope', d.scope],
      ['Window', `${d.windowDays} days of firewall logs`],
      ['Enabled rules', num(t.enabled)],
      ['Measured for traffic', `${num(t.measured)} of ${num(t.enabled)}`],
    ],
    summary: [
      { value: num(d.concentration.rules), label: 'Rules carry most traffic' },
      {
        value: num(d.busiestWithRisk.length),
        label: 'of those, with a finding',
        color: d.busiestWithRisk.length > 0 ? STATUS_RED : GREEN,
      },
      {
        // ⛔ A HUELESS DASH, NOT A ZERO, WHEN NOTHING WAS MEASURABLE. This is
        // the chip a reader takes away, and a plain `0` beside "Unused, with a
        // finding" reads as "nothing to clean up" when it means "we could not
        // look". The explanatory note below it is not enough: the number is
        // what gets quoted. Caught by rendering the 30-day document, where the
        // window has no coverage and this chip said 0.
        value: d.cleanupMeasurable === 0 ? NOT_MEASURED : num(d.cleanupCandidates.length),
        label: 'Unused, with a finding',
        color: d.cleanupMeasurable === 0 ? UNMEASURED : undefined,
      },
      {
        value: num(t.unmeasured),
        label: 'Could not be measured',
        color: t.unmeasured > 0 ? UNMEASURED : GREEN,
      },
    ],
  }, layout);

  // ⛔ THE ANSWER FIRST, AND THE COVERAGE VERDICT INSIDE IT. headlineSentence
  // leads with the coverage failure when there is one, so this single call
  // cannot render a confident ranking over a window nothing logged through.
  labelledNote(doc, layout, 'What this found',
    wc && !wc.sufficient ? ORANGE : (d.busiestWithRisk.length > 0 ? STATUS_RED : GREEN),
    headlineSentence(d));

  if (d.failures.length > 0) {
    labelledNote(doc, layout, 'Firewalls that could not be read', STATUS_RED,
      d.failures.map((f) => `${f.device}: ${f.message}`).join(' · ')
      + ' — their rules are absent from every figure here, so each count below describes a '
      + 'smaller fleet than the heading does.');
  }

  // ── the chart ─────────────────────────────────────────────────────────────
  // ⛔ RESERVE THE HEADING AND THE CHART TOGETHER. sectionTitle draws where it
  // stands and drawBarChart then calls ensureSpace for itself, so a heading
  // near the bottom margin got stranded alone on the page with its chart
  // overleaf. That is the orphan-header failure chassis.js's own ensureSpace
  // comment describes, arriving through the gap BETWEEN two helpers that each
  // behave correctly. The figure is the chart's real height: 15 rows at
  // (barH 14 + gap 6) plus its caption.
  ensureSpace(doc, layout, 15 * 20 + 60);
  sectionTitle(doc, layout, 'Where the traffic goes, and what is wrong with it');
  if (d.busiest.length === 0) {
    paragraph(doc, layout,
      'No rule carried measurable traffic in this window, so there is nothing to rank. That is an '
      + 'absence of evidence, not a quiet network.', UNMEASURED);
  } else {
    drawBarChart(doc, layout, d.busiest.slice(0, 15).map((r) => ({
      label: barLabel(r),
      value: r.windowHits,
      // ⛔ RED MEANS "this rule also carries a hygiene finding". It is taken
      // from the same worstFinding() the tables use, never decided here.
      color: riskyIds.has(r.id) ? STATUS_RED : ACCENT,
    })), {
      labelW: 210,
      max: 15,
      caption: `Logged hits over ${d.windowDays} days. Red bars are rules that ALSO carry a rule-`
        + 'hygiene finding — those are the ones worth looking at first, because whatever is wrong '
        + 'with them is wrong on the busiest paths in the estate.',
    });

    // The split as a proportion, which is the sentence management repeats.
    const riskyHits = d.busiestWithRisk.reduce((n, r) => n + r.windowHits, 0);
    const cleanHits = d.busiest.reduce((n, r) => n + r.windowHits, 0) - riskyHits;
    drawDonut(doc, layout, [
      { label: 'on rules with a finding', value: riskyHits, color: STATUS_RED },
      { label: 'on rules with none', value: cleanHits, color: GREEN },
    ], {
      caption: 'Of the traffic carried by the busiest rules only. Shares are of that subset, not of '
        + 'the whole estate — the rest of the rulebase is in the coverage table further down.',
    });
  }

  // ── the fusion table ──────────────────────────────────────────────────────
  sectionTitle(doc, layout, 'Busiest rules that also carry a finding');
  if (d.busiestWithRisk.length === 0) {
    paragraph(doc, layout,
      'None of the busiest rules carries a hygiene finding. That is a real result over the rules '
      + 'that could be measured, and not a statement about the ones that could not.', GREEN);
  } else {
    drawTable(doc, {
      columns: [
        { key: 'r', label: 'Rule', width: 130 },
        { key: 'd', label: 'Firewall', width: 85 },
        { key: 'h', label: 'Hits', width: 65 },
        { key: 's', label: 'Share', width: 45 },
        { key: 'f', label: 'Worst finding', width: 105 },
        { key: 'l', label: 'Lifetime', width: 75 },
      ],
      rows: d.busiestWithRisk.map((r) => ({
        r: r.name,
        d: r.deviceName,
        h: num(r.windowHits),
        s: pctOf(r.share),
        f: `${r.worst.type} (${r.worst.severity})`,
        // ⛔ LABELLED AS LIFETIME AND NEVER COMPARED ACROSS ROWS. Each device's
        // counter resets on its own unknown date, so two of these numbers side
        // by side are not a ranking. It is here because it answers "has this
        // always been busy", which the window cannot.
        l: r.lifetimeHits === null ? NOT_MEASURED : num(r.lifetimeHits),
      })),
    }, layout, { continueOnPage: true });
    paragraph(doc, layout,
      'Hits and Share are logged hits inside this window, comparable across firewalls. Lifetime is '
      + "the firewall's own counter since it last reset, on a date that differs per device — it is "
      + 'context for a single row and must not be compared between rows or added up.', MUTED);
  }

  // ── the rest of the busiest ───────────────────────────────────────────────
  const clean = d.busiest.filter((r) => !riskyIds.has(r.id));
  if (clean.length > 0) {
    sectionTitle(doc, layout, 'The other busiest rules');
    drawTable(doc, {
      columns: [
        { key: 'r', label: 'Rule', width: 170 },
        { key: 'd', label: 'Firewall', width: 110 },
        { key: 'h', label: 'Hits', width: 90 },
        { key: 's', label: 'Share', width: 60 },
      ],
      rows: clean.map((r) => ({
        r: r.name, d: r.deviceName, h: num(r.windowHits), s: pctOf(r.share),
      })),
    }, layout, { continueOnPage: true });
  }

  // ── the inverse ───────────────────────────────────────────────────────────
  sectionTitle(doc, layout, 'Rules that carried nothing and have a finding');
  if (d.cleanupMeasurable === 0) {
    // ⛔ THE MOST DANGEROUS EMPTY LIST IN THIS DOCUMENT. Zero candidates out of
    // zero answerable rules is a coverage gap; zero out of a thousand is good
    // news. Rendering them the same way would put "nothing to clean up" in
    // front of someone over a window nothing was measured in.
    paragraph(doc, layout,
      'No rule in this window could be shown to have carried NO traffic, so this list cannot be '
      + 'produced at all. It is empty because nothing was measurable, not because every rule is in '
      + 'use — and it must not be read as the second.', UNMEASURED);
  } else if (d.cleanupCandidates.length === 0) {
    paragraph(doc, layout,
      `None of the ${num(d.cleanupMeasurable)} rules shown to carry no traffic also carries a `
      + 'finding. That is a real result.', GREEN);
  } else {
    drawTable(doc, {
      columns: [
        { key: 'r', label: 'Rule', width: 150 },
        { key: 'd', label: 'Firewall', width: 100 },
        { key: 'f', label: 'Finding', width: 120 },
        { key: 'v', label: 'Firewall agrees', width: 85 },
      ],
      rows: d.cleanupCandidates.slice(0, 40).map((r) => ({
        r: r.name,
        d: r.deviceName,
        f: `${r.worst.type} (${r.worst.severity})`,
        // ⛔ TWO DIFFERENT CLAIMS, NEVER MERGED. "yes" means the firewall's own
        // counter also reads zero — a longer and independent statement than
        // "nothing in this window". "no" is not evidence of use; it means the
        // firewall did not supply a counter, or its counter is non-zero from
        // before this window.
        v: r.deviceAgreesZero ? 'yes, counter is 0' : NOT_MEASURED,
      })),
    }, layout, { continueOnPage: true });
    if (d.cleanupCandidates.length > 40) {
      paragraph(doc, layout,
        `Showing the 40 most severe of ${num(d.cleanupCandidates.length)}. The full list is on each `
        + "firewall's Rule hygiene tab, where a change request can be raised against it.", MUTED);
    }
    paragraph(doc, layout,
      'These carried no traffic in this window AND have something wrong with them, which makes them '
      + 'the safest removal candidates in the estate. SecVault does not remove anything: raise a '
      + 'change request and it will confirm against the next collected ruleset whether the rule '
      + 'actually went.', MUTED);
  }

  // ── coverage ──────────────────────────────────────────────────────────────
  sectionTitle(doc, layout, 'Coverage — whose rules are in the ranking');
  drawTable(doc, {
    columns: [
      { key: 'n', label: 'Firewall', width: 140 },
      { key: 'v', label: 'Vendor', width: 85 },
      { key: 'm', label: 'Rules measured', width: 100 },
      { key: 'p', label: 'Share of its rules', width: 100 },
      { key: 'h', label: 'Hits', width: 75 },
    ],
    rows: d.coverage.map((c) => ({
      n: c.name,
      v: c.vendor || NOT_MEASURED,
      m: `${num(c.measured)} of ${num(c.enabled)}`,
      // Tri-state: a firewall with no enabled rules collected has an UNKNOWN
      // ratio, not a ratio of zero.
      p: c.ratio === null ? NOT_MEASURED : `${Math.round(c.ratio * 100)}%`,
      h: num(c.traffic),
    })),
  }, layout, { continueOnPage: true });

  const reasons = Object.entries(d.unmeasuredByReason || {});
  if (reasons.length > 0) {
    labelledNote(doc, layout, 'Why some rules could not be measured', UNMEASURED,
      reasons
        .map(([k, n]) => `${num(n)} — ${d.unmeasuredReasonText[k] || k}`)
        .join('; ')
      + '. These rules appear in neither list above. They are not evidence of anything, in either '
      + 'direction.');
  }

  // ── the claim boundary ────────────────────────────────────────────────────
  sectionTitle(doc, layout, 'What this report claims, and what it does not');
  paragraph(doc, layout,
    'Hits are counted from the firewall logs SecVault received, over the stated window, for rules '
    + 'on firewalls that were logging throughout it. A rule that could not be measured is listed as '
    + 'unmeasured and is never shown as carrying no traffic — the difference matters, because the '
    + 'second reads as a deletion candidate.', MUTED);
  paragraph(doc, layout,
    `A rule with logging switched off cannot appear in a firewall log at all, so a ${NEVER_MEASURABLE_FINDING} `
    + 'finding can never reach the busiest list however much traffic the rule really carries. Those '
    + 'rules are counted as unmeasured above, and they are the one case where absence from this '
    + 'report is itself the finding.', MUTED);
  paragraph(doc, layout,
    'A finding describes the rule as written, from the collected configuration. It does not claim '
    + 'that traffic exploited it, and this report does not simulate a path — being busy and being '
    + 'flawed are two facts about the same rule, stated together because acting on the overlap is '
    + 'worth more than acting on either alone.', MUTED);

  stampHeadersFooters(doc, { title: TITLE, company: PRODUCT_NAME, generatedAt });
  doc.end();

  return new Promise((resolve, reject) => {
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });
}

async function generateRuleRiskPdf(pool, options = {}) {
  const data = await buildRuleRiskData(pool, options);
  if (!data) return null;
  return renderRuleRiskPdf(data);
}

module.exports = {
  TITLE,
  NOT_MEASURED,
  sevColor,
  barLabel,
  renderRuleRiskPdf,
  generateRuleRiskPdf,
};
