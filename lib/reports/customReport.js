'use strict';

// lib/reports/customReport.js — the custom report builder, PURE HALF.
//
// A custom report is a NAMED, SAVED SELECTION OF SECTIONS THAT ALREADY EXIST IN
// A SHIPPED REPORT, rendered through the same pdfkit chassis, downloaded through
// the same route, and resolved through the same registry. The plumbing — the
// CRUD on `custom_reports` and the dataset gathers — lives next door in
// lib/reports/customReportData.js. Same split as
// reportSchedule.js/reportScheduleData.js and segmentation.js/segmentationData.js,
// for the same reason: the judgement is the valuable part, so the judgement has
// to be testable without a database.
//
// ⛔ THIS IS NOT A QUERY BUILDER AND MUST NOT BECOME ONE. Letting an operator
// compose predicates over the schema would produce documents whose numbers no
// engine stands behind, and every figure in this product is supposed to carry an
// engine and a measurement. A predicate somebody typed carries neither. So the
// unit of selection is a SECTION, and a section is produced by code that already
// computes it for a shipped report — the registry below cannot express anything
// else, because a section's only inputs are its dataset and its own renderer.
//
// ⛔ A SECTION'S CAVEATS TRAVEL WITH IT, AND THE FRAMEWORK RENDERS THEM, NOT THE
// SECTION. Every entry declares `caveats(data)`, and renderCustomReportPdf()
// calls it unconditionally after the body and again for the closing gaps list.
// A section CANNOT forget its caveats by omission: a missing `caveats` is
// refused by validateRegistry() and fails the build. That matters more here than
// in a shipped report, because the layout is user-chosen and the reviewer of the
// finished PDF is whoever receives it — dropping a coverage statement because
// the arrangement is new would turn an honest figure into a bare one, which is
// the single thing this product must never ship.
//
// ⛔ NOTHING IS RECOMPUTED HERE. Every number comes from the shipped report's own
// data builder and every caveat sentence from that report's own exported pure
// helpers (`headline`, `coverageOf`, `movementOf`, `truncationNote`, the
// per-status cells). A second implementation of any of those judgements would
// eventually disagree with the document it was copied from, and the one nobody
// opens every day is the one that drifts.
//
// ⛔ pdfkit IS REQUIRED LAZILY, inside the renderer. lib/reports/catalogue.js
// imports CUSTOM_REPORT_CAPABILITY from this file so the two cannot declare
// different capabilities for the same report, and the catalogue's own header
// records that it must stay cheap to require — several surfaces read the
// registry without ever drawing a PDF. A top-level `require('pdfkit')` here
// would put it behind every one of them.

const {
  ACCENT, NAVY, MUTED, GREEN, STATUS_RED, YELLOW, UNMEASURED,
  pdfSafe, installPdfSafeText, fmtStamp,
  layoutOf, ensureSpace,
  drawCover, sectionTitle, paragraph, labelledNote, drawTable, stampHeadersFooters,
} = require('./chassis');
const { PRODUCT_NAME } = require('../branding');
const { OPERATE, VIEW_IDENTITY } = require('../rbac');

const NOT_MEASURED_MARK = '—';

/**
 * The capability the `custom-report` catalogue entry declares, and therefore
 * the capability GET /api/reports/custom-report/pdf enforces.
 *
 * ⛔ IT IS A CONSTANT SHARED WITH THE CATALOGUE RATHER THAN A LITERAL TYPED
 * TWICE, and that is load-bearing. The catalogue carries ONE static capability
 * per entry and the download route cannot vary it with the stored selection —
 * it resolves the report before it has read a single `custom_reports` row. So
 * the floor declared there has to equal the strictest capability any
 * REGISTERED section can require, or an identity-bearing section would be
 * served to an operator through a URL that looks exactly like every other
 * report download. assertCapabilityFloor() below refuses to build a document
 * when that stops being true, and tests/customReport.test.js fails the build
 * for the same reason.
 */
const CUSTOM_REPORT_CAPABILITY = OPERATE;

/**
 * ⛔ THE ONE CLAIM THIS DOCUMENT MAKES ABOUT ITSELF, exported so a test can
 * pin it — the same device `IMPACT_CLAIM` and `COVERAGE_CLAIM` use.
 *
 * A composed document is the easiest place in this product to overclaim,
 * because the reader cannot tell which sections were offered and declined. So
 * the cover says what it is and refuses to imply completeness: this is a
 * SELECTION, the figures belong to the reports they came from, and nothing was
 * computed here.
 */
const COMPOSITION_CLAIM =
  'This is a selection of sections from SecVault\'s standard reports. Each section was produced '
  + 'by the same engine that produces it in the report named beside it, and carries that '
  + 'report\'s own coverage statements. Nothing in this document is computed here, and no '
  + 'section states more than its source report states. Sections SecVault was not asked for are '
  + 'absent, so this is not a survey of everything that could have been measured.';

// ── capability ranking ─────────────────────────────────────────────────────

/**
 * Which capability outranks which, for the purpose of composing a selection.
 *
 * ⛔ AN UNRANKED CAPABILITY OUTRANKS EVERYTHING (rank Infinity) and therefore
 * wins, which makes it the required capability — and lib/rbac.js denies an
 * unrecognised capability string, so the composed report becomes
 * undownloadable rather than silently ungated. A typo in a future section's
 * `capability` must fail closed.
 */
const CAPABILITY_RANK = Object.freeze({
  [OPERATE]: 1,
  [VIEW_IDENTITY]: 2,
});

function rankOf(capability) {
  const r = CAPABILITY_RANK[capability];
  return typeof r === 'number' ? r : Infinity;
}

// ── small shared formatters ────────────────────────────────────────────────

/**
 * ⛔ THE SAME STRICTNESS AS executiveSummary.numOrNull, and for the same
 * reason: `Number()` maps '', false and [] to 0, and 0 is a real answer
 * everywhere below. Coercing an unreadable input to it turns a failed read into
 * the most reassuring figure on the page.
 */
function numOrNull(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'boolean') return null;
  if (typeof value !== 'number' && typeof value !== 'string') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

/** A count, or the not-measured mark. ⛔ Never `n || '-'` — 0 is a count. */
function countDisplay(value) {
  const n = numOrNull(value);
  return n === null ? NOT_MEASURED_MARK : n.toLocaleString('en-US');
}

function toneColor(tone) {
  if (tone === 'critical' || tone === 'bad') return STATUS_RED;
  if (tone === 'warn') return YELLOW;
  if (tone === 'ok') return GREEN;
  // ⛔ `unknown` IS HUELESS. It is the tone that means "nothing outstanding, but
  // we could not see all of it", and painting it green is the failure the
  // four-tone scheme exists to prevent.
  return UNMEASURED;
}

/**
 * Lazy module handles.
 *
 * ⛔ THE SHIPPED BUILDERS ARE REQUIRED ON FIRST USE, NEVER AT MODULE LOAD. Each
 * of them pulls pdfkit and most of lib/engines in behind it; this file is
 * imported by lib/reports/catalogue.js, which several surfaces read without
 * ever drawing a document. node caches the resolution, so the cost is paid once
 * per process and only if a section that needs it is actually rendered.
 */
function lazy(fn) {
  let value;
  return () => {
    if (value === undefined) value = fn();
    return value;
  };
}
const execSummary = lazy(() => require('./executiveSummary'));
const hygiene = lazy(() => require('./ruleHygiene'));
const vulnerability = lazy(() => require('./vulnerabilityPosture'));
const segmentation = lazy(() => require('./segmentationPosture'));
const lifecycle = lazy(() => require('./fleetLifecycle'));
const changeAudit = lazy(() => require('./changeAudit'));
const answers = lazy(() => require('../answers'));

/** The section-level refusal used whenever a dataset could not be gathered. */
function datasetRefusal(doc, layout, what, error) {
  labelledNote(
    doc, layout,
    `${what} could not be gathered.`, STATUS_RED,
    `${error || 'No data returned'}. Nothing in this section is a measurement of your estate: `
    + 'an empty section here would read as "there was nothing to find", which is a different '
    + 'claim entirely.'
  );
}

/** The same refusal, as a caveat row. */
function datasetCaveat(what, error) {
  return {
    label: `${what} could not be gathered`,
    text: `${error || 'No data returned'}. Every figure that would have depended on it is shown `
      + 'as not measured rather than assumed.',
  };
}

// ── the section registry ───────────────────────────────────────────────────
//
// ⛔ EVERY SECTION MUST NAME A SHIPPED REPORT. `source` is printed in the
// document beside the section heading and shown in the builder UI, because the
// honesty of the whole feature rests on the reader being able to go and read
// the full report a figure came from. A section with no source would be a
// figure this file invented.
//
// ⛔ EVERY SECTION DECLARES A `capability`, AND NO REGISTERED SECTION IS
// IDENTITY-BEARING TODAY — WHICH IS A REFUSAL, NOT AN OVERSIGHT. The VPN Access
// Review's per-user sections are deliberately NOT offered. The catalogue holds
// ONE static capability per report entry and the download route resolves that
// entry before reading any stored selection, so an identity-bearing section
// would leave two bad options: gate EVERY custom report on `view_identity` and
// take the feature away from operators, or let one capability stand in for two
// different disclosure levels. `requiredCapability()` and
// `assertCapabilityFloor()` below implement the escalation anyway — exercised
// by a test against a synthetic registry — so the day a `view_identity` section
// is added, every custom report containing it fails with a named reason
// pointing at the catalogue entry, rather than quietly handing an operator a
// PDF full of usernames.
const SECTIONS = [
  {
    id: 'fleet-posture',
    name: 'Fleet posture and security score',
    source: 'Executive Security Posture',
    sourceReportId: 'executive-summary',
    dataset: 'executive',
    capability: OPERATE,
    describes:
      'The one-sentence fleet position, the security score, and the three weighted components '
      + 'behind it — with any component that could not be scored shown as dropped from the '
      + 'weighting rather than counted as zero.',
    render(doc, layout, data) {
      const { headline } = data.sections;
      if (!headline.ok || !headline.value) {
        datasetRefusal(doc, layout, 'The fleet posture', headline.error);
        return;
      }
      const h = headline.value;
      const { WEIGHTS, securityScoreBand } = require('../engines/securityScore');
      const { scoreDisplay } = execSummary();

      // ⛔ THE SENTENCE IS NOT COMPOSED HERE. lib/answers.js already enforces
      // that an all-clear is forbidden while coverage is incomplete, and it
      // already carries the scar from getting that wrong once. A second
      // sentence-builder for a composed PDF would be a second implementation of
      // that rule, and the one not exercised on screen every day is the one
      // that drifts.
      const answer = answers().buildFleetAnswer(h);
      paragraph(
        doc, layout,
        `${answer.lead ? `${answer.lead} ` : ''}${answer.sentence}`,
        toneColor(answer.tone), 12
      );

      const score = numOrNull(h.securityScore);
      paragraph(
        doc, layout,
        score === null
          ? `Security score: ${NOT_MEASURED_MARK}  Not measurable. None of the three components `
            + 'could be scored, so no overall figure exists. This is a gap in what has been '
            + 'collected, not a finding about the estate.'
          : `Security score: ${score} / 100 (${securityScoreBand(score)}). Higher is better. `
            + `Weighted vulnerability ${WEIGHTS.vulnerability}, rule hygiene ${WEIGHTS.hygiene}, `
            + `compliance ${WEIGHTS.compliance}.`,
        score === null ? UNMEASURED : NAVY, 11
      );

      const components = Array.isArray(h.securityComponents) ? h.securityComponents : [];
      const measuredWeight = components
        .filter((c) => c.score !== null)
        .reduce((sum, c) => sum + c.weight, 0);
      drawTable(
        doc,
        {
          columns: [
            { key: 'component', label: 'Component', width: 190 },
            { key: 'weight', label: 'Weight', width: 60, align: 'right' },
            {
              key: 'score',
              label: 'Score',
              width: 60,
              align: 'right',
              color: (r) => (r.measured ? NAVY : UNMEASURED),
              font: (r) => (r.measured ? 'Helvetica-Bold' : 'Helvetica-Oblique'),
            },
            {
              key: 'status',
              label: 'Counted toward the score?',
              width: 250,
              color: (r) => (r.measured ? MUTED : UNMEASURED),
            },
          ],
          rows: components.map((c) => ({
            component: c.label,
            weight: String(c.weight),
            score: scoreDisplay(c.score),
            measured: c.score !== null,
            status: c.score === null
              ? `No - not measurable, its ${c.weight} points were dropped from the denominator`
              : `Yes - ${c.weight} of ${measuredWeight} measured points`,
          })),
        },
        layout,
        { continueOnPage: true, emptyText: 'No score components were returned.' }
      );
      doc.y += 8;
    },
    caveats(data) {
      const { headline } = data.sections;
      if (!headline.ok || !headline.value) {
        return [datasetCaveat('The fleet posture', headline.error)];
      }
      const out = [];
      const cov = execSummary().coverageOf(headline);
      if (cov.ok && cov.gap > 0) {
        out.push({
          label: `${cov.gap} of ${cov.devices} firewalls never assessed`,
          text: 'These firewalls are excluded from every fleet figure in this section. Their '
            + 'posture is unknown, which is not the same as clean.',
        });
      }
      const answer = answers().buildFleetAnswer(headline.value);
      // ⛔ RENDERED WHENEVER THE ENGINE PRODUCED ONE, with no "does it look bad"
      // judgement here. It is the qualification that makes the sentence above it
      // true, and a sentence separated from its qualification is a different
      // sentence.
      if (answer.coverage) out.push({ label: 'Coverage', text: answer.coverage });
      for (const c of (headline.value.securityComponents || []).filter((x) => x.score === null)) {
        out.push({
          label: `${c.label} could not be scored`,
          text: `Its ${c.weight} points were removed from the weighting rather than counted as `
            + 'zero, so the score shown is an average of what could be measured, not of the '
            + 'whole model.',
        });
      }
      return out;
    },
  },

  {
    id: 'posture-movement',
    name: 'Movement since the last measured period',
    source: 'Executive Security Posture',
    sourceReportId: 'executive-summary',
    dataset: 'executive',
    capability: OPERATE,
    describes:
      'Six fleet measures against the last nightly snapshot, each judged in its own direction. '
      + 'With no prior snapshot the section says so rather than printing zero change.',
    render(doc, layout, data) {
      const { movementOf } = execSummary();
      const move = movementOf(data.sections.headline, data.sections.previous, data.generatedAt);
      if (!move.available) {
        // ⛔ RENDERED EVEN WITH NOTHING TO SHOW. A movement section that
        // disappears when there is no prior point reads as "no movement".
        paragraph(
          doc, layout,
          move.reason === 'none'
            ? 'There is no prior period to compare against, so no trend can be stated. This is '
              + 'not a report of zero change - it is the absence of a second data point.'
            : move.reason === 'failed'
              ? `The previous period could not be read (${data.sections.previous.error}), so no `
                + 'trend can be stated.'
              : 'The current position could not be read, so no trend can be stated.',
          UNMEASURED, 10
        );
        return;
      }
      paragraph(
        doc, layout,
        `Comparing today against the snapshot taken on ${move.priorDay}`
        + (move.days !== null ? `, ${move.days} day${move.days === 1 ? '' : 's'} ago.` : '.'),
        MUTED, 9
      );
      drawTable(
        doc,
        {
          columns: [
            { key: 'metric', label: 'Measure', width: 240 },
            { key: 'was', label: move.priorDay, width: 90, align: 'right' },
            { key: 'now', label: 'Today', width: 90, align: 'right' },
            {
              key: 'change',
              label: 'Change',
              width: 160,
              align: 'right',
              color: (r) => (r.direction === 'better'
                ? GREEN
                : r.direction === 'worse'
                  ? STATUS_RED
                  : r.direction === 'unknown' ? UNMEASURED : MUTED),
              font: (r) => (r.direction === 'unknown' ? 'Helvetica-Oblique' : 'Helvetica-Bold'),
            },
          ],
          rows: move.rows,
        },
        layout,
        { continueOnPage: true, emptyText: 'No comparable measures were recorded.' }
      );
      doc.y += 8;
    },
    caveats(data) {
      const { movementOf } = execSummary();
      const move = movementOf(data.sections.headline, data.sections.previous, data.generatedAt);
      if (move.available) {
        const unknown = move.rows.filter((r) => r.direction === 'unknown');
        return unknown.length === 0 ? [] : [{
          label: `${unknown.length} measure${unknown.length === 1 ? '' : 's'} had no prior value`,
          text: `${unknown.map((r) => r.metric).join('; ')}. A NULL subtracted from a number is `
            + 'not a movement of that size; it is no movement anybody can see.',
        }];
      }
      return [{
        label: 'No period-over-period comparison',
        text: 'No prior daily snapshot was available, so nothing in this section states whether '
          + 'the posture improved or worsened.',
      }];
    },
  },

  {
    id: 'urgent-work',
    name: 'The urgent work queue',
    source: 'Executive Security Posture',
    sourceReportId: 'executive-summary',
    dataset: 'executive',
    capability: OPERATE,
    describes:
      'What needs action now, ranked across every engine, with the evidence grade per item. '
      + 'An item only reaches the urgent band on measured or vendor-reported evidence.',
    render(doc, layout, data) {
      const { work } = data.sections;
      if (!work.ok || !work.value) {
        datasetRefusal(doc, layout, 'The outstanding work', work.error);
        return;
      }
      const { ranked, summary } = work.value;
      const actNow = (ranked || []).filter((it) => it.band === 'act_now');
      const shown = actNow.slice(0, data.maxWorkItems);

      paragraph(
        doc, layout,
        `${summary.act_now} item${summary.act_now === 1 ? '' : 's'} need action now, `
        + `${summary.scheduled} ${summary.scheduled === 1 ? 'is' : 'are'} scheduled, and `
        + `${summary.verify} require a human to verify because the platform could not measure `
        + `${summary.verify === 1 ? 'it' : 'them'}. An item only reaches the urgent band on `
        + 'measured or vendor-reported evidence; nothing is ranked urgent on a guess.',
        MUTED, 9
      );
      // ⛔ BEFORE THE TABLE, not as a footnote after it: the reader who stops at
      // the bottom of the list is exactly the reader this disclosure is for.
      if (shown.length < actNow.length) {
        labelledNote(
          doc, layout,
          `Showing ${shown.length} of ${actNow.length} urgent items`, YELLOW,
          'The remainder are in the platform, ranked in the same order. This section is capped so '
          + 'it stays readable, not because the list ends here.'
        );
      }
      drawTable(
        doc,
        {
          columns: [
            { key: 'title', label: 'What needs doing', width: 200, font: 'Helvetica-Bold' },
            { key: 'why', label: 'Why it is urgent', width: 220 },
            { key: 'affects', label: 'Affects', width: 120 },
            {
              key: 'evidence',
              label: 'Evidence',
              width: 80,
              color: (r) => (r.evidence === 'Measured' ? GREEN : MUTED),
            },
          ],
          rows: shown.map((it) => ({
            title: it.title || '(untitled item)',
            why: it.why || '',
            affects: it.affects || '',
            evidence: it.evidence === 'measured' ? 'Measured' : 'Reported',
          })),
        },
        layout,
        {
          continueOnPage: true,
          // ⛔ NOT "nothing to do". An empty urgent band with a failed source or
          // an unassessed fleet is an unknown queue, and the caveats say so.
          emptyText: 'No items reached the urgent band in this run.',
        }
      );
      doc.y += 8;
    },
    caveats(data) {
      const { work } = data.sections;
      if (!work.ok || !work.value) return [datasetCaveat('The outstanding work', work.error)];
      const out = [];
      const s = work.value.summary;
      for (const f of s.failedSources || []) {
        out.push({
          label: `Outstanding work from "${f.key}" is missing`,
          text: `That source failed with: ${f.error}. The work list is therefore shorter than the `
            + 'truth by an unknown amount.',
        });
      }
      for (const t of s.truncatedSources || []) {
        out.push({
          label: `Outstanding work from "${t.key}" was capped`,
          text: `Showing ${t.shown} of ${t.of}.`,
        });
      }
      if (s.verify > 0) {
        out.push({
          label: `${s.verify} item${s.verify === 1 ? '' : 's'} need a human to verify`,
          text: 'These are things the platform could not measure - an expiry date that would not '
            + 'parse, a firewall that could not be read. They are not ranked as urgent, because '
            + 'ranking a guess as a measurement is worse than admitting the gap.',
        });
      }
      return out;
    },
  },

  {
    id: 'compliance-standards',
    name: 'Compliance by standard',
    source: 'Executive Security Posture',
    sourceReportId: 'executive-summary',
    dataset: 'executive',
    capability: OPERATE,
    describes:
      'The score for each framework with its pass/fail/indeterminate counts. A standard with '
      + 'nothing measurable is an em-dash, never 0%.',
    render(doc, layout, data) {
      const { compliance } = data.sections;
      if (!compliance.ok || !compliance.value) {
        datasetRefusal(doc, layout, 'The compliance breakdown', compliance.error);
        return;
      }
      const { overall, byStandard, byStandardCounts } = compliance.value;
      const o = numOrNull(overall);
      paragraph(
        doc, layout,
        o === null
          ? `Overall: ${NOT_MEASURED_MARK}  Not measurable. No check could be answered against `
            + 'any collected configuration, so there is no percentage to report.'
          : `Overall: ${o}%. Checks the platform cannot ask of a device are excluded from the `
            + 'denominator entirely, so this figure never counts our own blind spots against '
            + 'the estate.',
        o === null ? UNMEASURED : NAVY, 10
      );
      // ⛔ A PER-STANDARD SCORE IS A SHARE OF SECVAULT'S OWN CHECKS, and the
      // sentence saying so travels with the table. Printed without it, "NIST
      // 42%" reads as that framework's posture — which is the one place this
      // product used to overclaim, and v2.163.0 removed it.
      paragraph(
        doc, layout,
        'Each percentage is a share of the SecVault checks mapped to that standard, not of what '
        + 'the framework publishes. SecVault holds no count of any framework\'s own '
        + 'requirements and states none.',
        MUTED, 8.5
      );
      const keys = Object.keys(byStandard || {});
      drawTable(
        doc,
        {
          columns: [
            { key: 'standard', label: 'Standard', width: 160 },
            {
              key: 'score',
              label: 'Score',
              width: 80,
              align: 'right',
              color: (r) => (r.measured ? NAVY : UNMEASURED),
              font: (r) => (r.measured ? 'Helvetica-Bold' : 'Helvetica-Oblique'),
            },
            { key: 'pass', label: 'Pass', width: 70, align: 'right' },
            { key: 'fail', label: 'Fail', width: 70, align: 'right', color: STATUS_RED },
            { key: 'warning', label: 'Indeterminate', width: 100, align: 'right', color: YELLOW },
          ],
          rows: keys.map((k) => {
            const c = (byStandardCounts || {})[k] || {};
            const pct = numOrNull(byStandard[k]);
            return {
              standard: k.replace(/_/g, ' '),
              score: pct === null ? NOT_MEASURED_MARK : `${pct}%`,
              measured: pct !== null,
              pass: countDisplay(c.pass),
              fail: countDisplay(c.fail),
              warning: countDisplay(c.warning),
            };
          }),
        },
        layout,
        { continueOnPage: true, emptyText: 'No standards were scored.' }
      );
      doc.y += 8;
    },
    caveats(data) {
      const { compliance } = data.sections;
      if (!compliance.ok || !compliance.value) {
        return [datasetCaveat('The compliance breakdown', compliance.error)];
      }
      const out = [];
      const { byStandard } = compliance.value;
      const unmeasurable = Object.keys(byStandard || {})
        .filter((k) => numOrNull(byStandard[k]) === null);
      if (unmeasurable.length > 0) {
        out.push({
          label: `${unmeasurable.length} standard${unmeasurable.length === 1 ? '' : 's'} could `
            + 'not be scored',
          text: `${unmeasurable.join(', ')}. Nothing measurable was found for `
            + `${unmeasurable.length === 1 ? 'it' : 'them'}, which is not the same as failing.`,
        });
      }
      if (numOrNull(compliance.value.overall) === null) {
        out.push({
          label: 'No overall compliance figure exists',
          text: 'No check could be answered against any collected configuration.',
        });
      }
      return out;
    },
  },

  {
    id: 'rule-hygiene',
    name: 'Rule hygiene findings by type',
    source: 'Rule Hygiene & Policy Audit',
    sourceReportId: 'rule-hygiene',
    dataset: 'ruleHygiene',
    capability: OPERATE,
    describes:
      'Open findings per finding type with their severities, and the coverage note per type for '
      + 'firewalls where that comparison did not run at all.',
    render(doc, layout, data) {
      const { STATUS_RED: RED, ORANGE } = require('./chassis');
      // ⛔ The report's OWN headline sentence, verbatim. It is the composed
      // caveat — "this is not a complete picture: N rules have no usage data" —
      // and rewriting it here would be a second implementation of the rule that
      // forbids an unqualified claim.
      paragraph(doc, layout, data.headline, MUTED, 10);
      drawTable(
        doc,
        {
          columns: [
            { key: 'label', label: 'Finding', width: 86, font: 'Helvetica-Bold' },
            { key: 'text', label: 'What it means', width: 180 },
            { key: 'critical', label: 'Crit', width: 28, align: 'right', color: RED },
            { key: 'high', label: 'High', width: 28, align: 'right', color: ORANGE },
            { key: 'medium', label: 'Med', width: 28, align: 'right', color: YELLOW },
            { key: 'total', label: 'Open', width: 32, align: 'right', font: 'Helvetica-Bold' },
            {
              key: 'caveat',
              label: 'Coverage',
              width: 118,
              color: (r) => (r._caveat ? UNMEASURED : MUTED),
            },
          ],
          // ⛔ THE COVERAGE COLUMN IS NOT OPTIONAL. A pairwise type with zero
          // findings still gets a row when the pass was skipped somewhere, and
          // the note is what stops a zero being read as a clean result.
          rows: (data.byType || []).map((t) => ({
            label: t.label,
            text: t.text,
            critical: t.critical || '',
            high: t.high || '',
            medium: t.medium || '',
            total: t.total,
            caveat: t.notRunOn > 0
              ? `NOT RUN on ${t.notRunOn} firewall${t.notRunOn === 1 ? '' : 's'} (ruleset too `
                + 'large). A zero here is not a clean result.'
              : '',
            _caveat: t.notRunOn > 0,
          })),
        },
        layout,
        { continueOnPage: true, emptyText: 'No hygiene findings were returned.' }
      );
      doc.y += 8;
      const t = data.totals || {};
      paragraph(
        doc, layout,
        `${countDisplay(t.rules)} rules examined across ${countDisplay(t.devices)} firewalls over `
        + `a ${countDisplay(data.windowDays)}-day evidence window. `
        + `${countDisplay(t.rulesWithHits)} carried traffic, ${countDisplay(t.rulesMeasuredZero)} `
        + `reported a measured zero, and ${countDisplay(t.rulesNotMeasured)} could not be measured `
        + 'at all.',
        MUTED, 9
      );
    },
    caveats(data) {
      const out = [];
      for (const e of data.sectionErrors || []) {
        out.push({
          label: typeof e === 'string' ? 'A stage of the hygiene analysis failed' : (e.section || e.label || e.key),
          text: typeof e === 'string' ? e : (e.message || e.text || 'No reason recorded.'),
        });
      }
      const t = data.totals || {};
      if (t.rulesNotMeasured > 0) {
        out.push({
          label: `${countDisplay(t.rulesNotMeasured)} of ${countDisplay(t.rules)} rules have no `
            + 'usage data',
          text: 'The firewall cannot report a hit counter for them, so no unused-rule verdict is '
            + 'offered for any of them. That is not the same as a measured zero.',
        });
      }
      if (t.devicesNoRuleset > 0) {
        out.push({
          label: `${countDisplay(t.devicesNoRuleset)} firewall(s) have no ruleset collected`,
          text: 'Nothing on them was analysed, so their counts are unknown rather than zero.',
        });
      }
      if (t.devicesPairwiseSkipped > 0) {
        out.push({
          label: `${countDisplay(t.devicesPairwiseSkipped)} firewall(s) exceeded the pairwise `
            + 'comparison limit',
          text: `Rulesets above ${countDisplay(data.pairwiseCap)} rules skip the rule-versus-rule `
            + 'checks, so zero shadow/redundant findings there means not measured, not clean.',
        });
      }
      const note = hygiene().truncationNote(
        (data.findings || []).length,
        (data.totals || {}).findings,
        'findings'
      );
      if (note) out.push({ label: 'The findings list was capped', text: note });
      return out;
    },
  },

  {
    id: 'vulnerability-bands',
    name: 'Vulnerability bands and patch-now work',
    source: 'Vulnerability & Patch Posture',
    sourceReportId: 'vulnerability-posture',
    dataset: 'vulnerability',
    capability: OPERATE,
    describes:
      'The patch-now, scheduled and monitor bands with their CVE and firewall counts, plus the '
      + 'advisories that could not be matched and the firewalls never assessed.',
    render(doc, layout, data) {
      const answer = data.answer || {};
      paragraph(
        doc, layout,
        `${answer.lead ? `${answer.lead} ` : ''}${answer.sentence || 'No vulnerability answer was produced.'}`,
        toneColor(answer.tone), 12
      );
      const { BAND_LABEL } = vulnerability();
      const bands = data.bands || {};
      drawTable(
        doc,
        {
          columns: [
            { key: 'band', label: 'Band', width: 140, font: 'Helvetica-Bold' },
            { key: 'cves', label: 'CVEs', width: 80, align: 'right' },
            { key: 'devices', label: 'Firewalls', width: 90, align: 'right' },
            { key: 'assessments', label: 'Assessments', width: 100, align: 'right' },
            { key: 'meaning', label: 'What the band means', width: 220, color: MUTED },
          ],
          rows: ['patch_now', 'scheduled', 'monitor'].map((key) => {
            const b = bands[key] || {};
            return {
              band: BAND_LABEL[key] || key,
              // ⛔ null in, em-dash out. A band that could not be counted must
              // not print as an empty band — those are opposite claims.
              cves: countDisplay(b.cves),
              devices: countDisplay(b.devices),
              assessments: countDisplay(b.assessments),
              meaning: key === 'patch_now'
                ? 'Known exploited, observed reached, or critical and applicable.'
                : key === 'scheduled'
                  ? 'Real and applicable, or applicable-unknown and treated conservatively.'
                  : 'Everything else - tracked, not queued.',
            };
          }),
        },
        layout,
        { continueOnPage: true, emptyText: 'No bands were counted.' }
      );
      doc.y += 8;
      const cov = data.coverage || {};
      paragraph(
        doc, layout,
        `${countDisplay(cov.assessed)} of ${countDisplay(cov.activeDevices)} active firewalls have `
        + 'a CVE assessment on record. '
        + `${cov.neverAssessed === null || cov.neverAssessed === undefined
          ? 'How many were never assessed could not be determined.'
          : `${countDisplay((cov.neverAssessed || []).length)} were never assessed and contribute `
            + 'nothing to the counts above.'}`,
        MUTED, 9
      );
    },
    caveats(data) {
      const out = [];
      for (const e of data.errors || []) {
        out.push({
          label: `${e.label || e.key} could not be read`,
          text: `${e.message}. Every figure depending on it is shown as not measured.`,
        });
      }
      const answer = data.answer || {};
      if (answer.coverage) out.push({ label: 'Coverage', text: answer.coverage });
      const never = (data.coverage || {}).neverAssessed;
      if (Array.isArray(never) && never.length > 0) {
        out.push({
          label: `${never.length} firewall${never.length === 1 ? '' : 's'} never assessed for CVEs`,
          text: `${never.slice(0, 12).map((d) => d.name || d.id).join(', ')}`
            + `${never.length > 12 ? `, +${never.length - 12} more` : ''}. They contribute no `
            + 'findings, which makes them look like the healthiest firewalls on the fleet.',
        });
      }
      const ac = data.advisoryCoverage;
      if (ac && ac.unmatchable > 0) {
        out.push({
          label: `${countDisplay(ac.unmatchable)} of ${countDisplay(ac.total)} advisories carry no `
            + 'usable version range',
          text: 'They can never match a firewall, so no finding was raised from them either way. '
            + 'This is a limit of what the feed published, not a statement that your estate is '
            + 'unaffected.',
        });
      }
      const fs = data.feedSummary;
      if (fs && (fs.neverSucceeded || []).length > 0) {
        out.push({
          label: `${fs.neverSucceeded.length} advisory feed(s) have never succeeded`,
          text: `${fs.neverSucceeded.join(', ')}. A feed that has never run is ABSENT, not old.`,
        });
      } else if (fs === null) {
        out.push({
          label: 'Feed freshness could not be read',
          text: 'The advisories behind this section may be any age; nothing here states how '
            + 'current they are.',
        });
      }
      return out;
    },
  },

  {
    id: 'segmentation-posture',
    name: 'Segmentation boundaries and violations',
    source: 'Segmentation Posture',
    sourceReportId: 'segmentation-posture',
    dataset: 'segmentation',
    capability: OPERATE,
    describes:
      'Declared zone-to-zone intent scored both ways — whether a rule permits it and whether '
      + 'traffic was recorded. A boundary whose usage cannot be measured is unverified, never '
      + 'clean.',
    render(doc, layout, data) {
      // ⛔ The engine's own sentence. With nothing declared it says so in as
      // many words — "an empty violation list reads as perfect; it is not a
      // result, nothing was checked" — and that is exactly the claim a composed
      // document must not be allowed to lose.
      paragraph(doc, layout, data.headline, MUTED, 10);
      const t = data.totals || {};
      drawTable(
        doc,
        {
          columns: [
            { key: 'state', label: 'Verdict', width: 200, font: 'Helvetica-Bold' },
            { key: 'count', label: 'Pairs', width: 70, align: 'right' },
            { key: 'meaning', label: 'How to read it', width: 300, color: MUTED },
          ],
          rows: [
            {
              state: 'Violation - traffic recorded', count: countDisplay(t.violationsActive),
              meaning: 'A rule permits a declared deny, and traffic was observed on it.',
            },
            {
              state: 'Violation - cannot tell', count: countDisplay(t.violationsUnverified),
              meaning: 'A rule permits it and usage could not be measured. Assume it is live.',
            },
            {
              state: 'Violation - permitted only', count: countDisplay(t.violationsPermitted),
              meaning: 'A rule permits it and a measured zero says nothing used it. The safest '
                + 'kind to close.',
            },
            {
              state: 'Satisfied', count: countDisplay(t.ok),
              meaning: 'The rulebase agrees with the declared intent.',
            },
            {
              state: 'Unused permission', count: countDisplay(t.unusedPermissions),
              meaning: 'Allowed and declared, but nothing measured used it.',
            },
            {
              state: 'Expected allow missing', count: countDisplay(t.expectedAllowMissing),
              meaning: 'Declared as allowed and no rule permits it.',
            },
            {
              state: 'Could not be measured', count: countDisplay(t.unmeasurable),
              meaning: 'No verdict is offered. This is not a pass.',
            },
          ],
        },
        layout,
        { continueOnPage: true, emptyText: 'No zone-to-zone intent has been declared.' }
      );
      doc.y += 8;
      paragraph(
        doc, layout,
        `${countDisplay(t.intents)} declared boundaries over ${countDisplay(t.zoneCount)} zones, `
        + `measured across ${countDisplay(data.windowDays)} days of traffic evidence. `
        + '"A rule permits this" is never a claim that a packet would pass: addresses, services, '
        + 'profiles and rule order all still apply and are deliberately not modelled.',
        MUTED, 9
      );
    },
    caveats(data) {
      const out = [];
      for (const e of data.sectionErrors || []) {
        out.push({
          label: typeof e === 'string' ? 'A stage of the segmentation analysis failed' : (e.section || e.label || e.key),
          text: typeof e === 'string' ? e : (e.message || e.text || 'No reason recorded.'),
        });
      }
      const t = data.totals || {};
      if (Number(t.intents) === 0) {
        out.push({
          label: 'Nothing has been declared, so nothing was checked',
          text: 'An empty violation list here is an empty result, not a clean one.',
        });
      }
      if (t.rulesCollected === false) {
        out.push({
          label: 'No ruleset has been collected from any firewall',
          text: 'Not one of these pairs was tested against a real rulebase.',
        });
      }
      if (Number(t.devicesWithoutRules) > 0) {
        out.push({
          label: `${countDisplay(t.devicesWithoutRules)} firewall(s) have no ruleset collected`,
          text: 'A rule permitting a declared-deny path could be sitting on one of them unseen.',
        });
      }
      if (Number(t.unmeasurable) > 0) {
        out.push({
          label: `${countDisplay(t.unmeasurable)} of ${countDisplay(t.intents)} declared paths `
            + 'could not be measured',
          text: 'They carry no verdict at all, and none of them may be read as satisfied.',
        });
      }
      if (Number(t.rulesWithoutHitData) > 0) {
        out.push({
          label: `${countDisplay(t.rulesWithoutHitData)} of ${countDisplay(t.ruleCount)} rules `
            + 'cannot report whether traffic used them',
          text: 'If even one permitting rule cannot report usage, the whole pair is UNKNOWN - that '
            + 'one rule might be the one carrying the traffic.',
        });
      }
      if (data.narrowing) {
        out.push({
          label: 'This section was narrowed to one firewall',
          text: 'Narrowing changes WHICH pairs are listed and never how any of them was decided. '
            + 'Segmentation is an estate-wide judgement.',
        });
      }
      return out;
    },
  },

  {
    id: 'lifecycle-renewals',
    name: 'Licences and support expiry',
    source: 'Lifecycle & Support',
    sourceReportId: 'fleet-lifecycle',
    dataset: 'lifecycle',
    capability: OPERATE,
    describes:
      'The renewal timeline, soonest first, with unknown expiries last rather than first — and '
      + 'perpetual, not-licensed and unreadable expiries each shown as themselves.',
    render(doc, layout, data) {
      paragraph(doc, layout, data.headline, MUTED, 10);
      const { licenseColor, daysText } = lifecycle();
      const cap = (data.caps || {}).maxRenewalRows || 60;
      const all = data.renewals || [];
      const shown = all.slice(0, cap);
      drawTable(
        doc,
        {
          columns: [
            { key: 'device', label: 'Firewall', width: 120, font: 'Helvetica-Bold' },
            { key: 'entitlement', label: 'Entitlement', width: 200 },
            {
              key: 'expires',
              label: 'Expires',
              width: 150,
              // ⛔ FOUR STATES, FOUR STRINGS, and the hue comes from the source
              // report's own licenseColor() so an unreadable expiry stays
              // hueless here exactly as it is there.
              color: (r) => licenseColor(r._status),
            },
            { key: 'when', label: 'When', width: 70, align: 'right', color: (r) => licenseColor(r._status) },
          ],
          rows: shown.map((g) => ({
            device: g.deviceName || NOT_MEASURED_MARK,
            entitlement: g.label || NOT_MEASURED_MARK,
            expires: (g.expiry && g.expiry.text) || NOT_MEASURED_MARK,
            when: g.expiry && g.expiry.kind === 'date' ? daysText(g.delta) : NOT_MEASURED_MARK,
            _status: g.status,
          })),
        },
        layout,
        { continueOnPage: true, emptyText: 'No licence or support entitlement was collected.' }
      );
      doc.y += 8;
      const t = data.totals || {};
      paragraph(
        doc, layout,
        `${countDisplay(t.renewalEventsExpired)} already lapsed, `
        + `${countDisplay(t.renewalEventsExpiring)} within ${countDisplay(t.warnDays)} days, and `
        + `${countDisplay(t.renewalEventsUnknown)} whose expiry could not be read. `
        + 'A perpetual entitlement and one whose date would not parse are different facts and are '
        + 'never summed.',
        MUTED, 9
      );
    },
    caveats(data) {
      const out = [];
      for (const e of data.sectionErrors || []) {
        out.push({
          label: typeof e === 'string' ? 'A stage of the lifecycle collection failed' : (e.section || e.label || e.key),
          text: typeof e === 'string' ? e : (e.message || e.text || 'No reason recorded.'),
        });
      }
      const t = data.totals || {};
      if (t.licensesUnknownExpiry > 0) {
        out.push({
          label: `${countDisplay(t.licensesUnknownExpiry)} entitlement(s) have an expiry SecVault `
            + 'could not read',
          text: 'They are absent from the renewal dates above, not "fine". Treating an unparsed '
            + 'expiry as fine is how a contract lapses.',
        });
      }
      if (t.licensesNotLicensed > 0) {
        out.push({
          label: `${countDisplay(t.licensesNotLicensed)} entitlement(s) are not held at all`,
          text: 'The device reports no entitlement rather than a date that failed to parse, so '
            + 'they are deliberately excluded from the renewal list.',
        });
      }
      for (const g of data.coverageGaps || []) {
        if (g.notCollected > 0 || g.unknown > 0) {
          out.push({
            label: `${g.label}: ${countDisplay(g.notCollected + g.unknown)} firewall(s) have no data`,
            text: `${countDisplay(g.collected)} collected, ${countDisplay(g.notSupported)} cannot `
              + `be asked at all, ${countDisplay(g.notCollected)} can be asked and returned `
              + `nothing, ${countDisplay(g.unknown)} unknown. This section speaks only for the `
              + 'collected ones.',
          });
        }
      }
      const note = lifecycle().truncationNote(
        Math.min((data.renewals || []).length, (data.caps || {}).maxRenewalRows || 60),
        (data.renewals || []).length,
        'renewal events'
      );
      if (note) out.push({ label: 'The renewal list was capped', text: note });
      return out;
    },
  },

  {
    id: 'change-log',
    name: 'Configuration changes and reviews',
    source: 'Configuration Change Audit',
    sourceReportId: 'change-audit',
    dataset: 'changeAudit',
    capability: OPERATE,
    describes:
      'What changed on the firewalls in the window, how much of it nobody has acknowledged, and '
      + 'which firewalls could not be confirmed at all — so "no changes" is never printed over a '
      + 'collection outage.',
    render(doc, layout, data) {
      paragraph(doc, layout, data.headline, MUTED, 10);
      const t = data.totals || {};
      drawTable(
        doc,
        {
          columns: [
            { key: 'measure', label: 'Measure', width: 240, font: 'Helvetica-Bold' },
            { key: 'value', label: 'Count', width: 80, align: 'right' },
            { key: 'note', label: 'How to read it', width: 260, color: MUTED },
          ],
          rows: [
            {
              measure: 'Changes detected', value: countDisplay(t.changes),
              note: `Over the last ${countDisplay(t.windowDays)} days.`,
            },
            {
              measure: 'Nobody has reviewed', value: countDisplay(t.unacknowledged),
              note: 'Detected and never acknowledged by an operator.',
            },
            {
              measure: 'Firewalls with changes', value: countDisplay(t.devicesWithChanges),
              note: 'Of ' + countDisplay(t.devices) + ' in scope.',
            },
            {
              measure: 'Quiet AND confirmed quiet', value: countDisplay(t.devicesQuietConfirmed),
              note: 'Observed in the window and nothing changed. This is a result.',
            },
            {
              measure: 'Not observed at all', value: countDisplay(t.devicesUnobserved),
              note: 'No comparison ran. Their quietness is unknown, not confirmed.',
            },
            {
              measure: 'Never collected from', value: countDisplay(t.devicesNeverCollected),
              note: 'SecVault has never read a configuration from these.',
            },
          ],
        },
        layout,
        { continueOnPage: true, emptyText: 'No change data was returned.' }
      );
      doc.y += 8;
    },
    caveats(data) {
      const out = [];
      for (const e of data.sectionErrors || []) {
        out.push({
          label: typeof e === 'string' ? 'A stage of the change audit failed' : (e.section || e.label || e.key),
          text: typeof e === 'string' ? e : (e.message || e.text || 'No reason recorded.'),
        });
      }
      const t = data.totals || {};
      if (t.devicesUnobserved > 0) {
        out.push({
          label: `${countDisplay(t.devicesUnobserved)} firewall(s) were not observed in this window`,
          // ⛔ The two are kept APART, not summed: never collected from is a
          // credential or reachability problem, nothing inside the window is a
          // job that stopped running, and folding them loses which one you
          // have. Written as labelled counts rather than a sentence so a count
          // of 1 does not read as "1 have never been collected".
          text: 'No configuration comparison ran on them, so "no changes" cannot be said of them. '
            + `Never collected from at all: ${countDisplay(t.devicesNeverCollected)}. Produced `
            + `nothing inside the window: ${countDisplay(t.devicesStale)}.`,
        });
      }
      if (t.devicesFirstSnapshotOnly > 0) {
        out.push({
          label: `${countDisplay(t.devicesFirstSnapshotOnly)} firewall(s) have only one snapshot`,
          text: 'A change needs a predecessor to compare against, so no change could be detected '
            + 'on them either way.',
        });
      }
      if (t.changesUnreadablePayload > 0 || t.changesWithCorruptedKeys > 0) {
        out.push({
          label: `${countDisplay(t.changesUnreadablePayload + t.changesWithCorruptedKeys)} change `
            + 'record(s) could not be read in full',
          text: 'The change is recorded; what it touched is partly unknown. An unreadable record '
            + 'is not an empty one.',
        });
      }
      if (t.changesWithLostSnapshots > 0 || t.changesPartiallyRetained > 0) {
        out.push({
          label: `${countDisplay(t.changesWithLostSnapshots + t.changesPartiallyRetained)} change(s) `
            + 'no longer have both source snapshots',
          text: 'Configuration retention has aged them out, so the diff cannot be re-derived from '
            + 'the stored configurations.',
        });
      }
      if (t.devicesWithoutBaseline > 0) {
        out.push({
          label: `${countDisplay(t.devicesWithoutBaseline)} firewall(s) have no designated baseline`,
          text: 'Drift against a known-good configuration cannot be measured for them.',
        });
      }
      const note = changeAudit().truncationNote(t.changesListed, t.changes, 'changes');
      if (note) out.push({ label: 'The change list was capped', text: note });
      return out;
    },
  },
];

const BY_ID = new Map(SECTIONS.map((s) => [s.id, s]));

/** @returns {object|null} the section, or null — never a partial stub. */
function sectionById(id) {
  return BY_ID.get(String(id || '')) || null;
}

/**
 * The registry as the builder UI should render it.
 *
 * ⛔ FUNCTIONS CANNOT CROSS INTO A CLIENT COMPONENT, and in a production build
 * that failure is a bare digest on an empty page — which is exactly how
 * /reports shipped blank in v2.120.0. Written as an ALLOW-LIST, not as "drop
 * render and caveats", because the next field added here might also be a
 * function and a deny-list would silently start passing it.
 *
 * @param {object} capabilities the session's capability object; a section the
 *   session cannot download is marked rather than hidden, so an operator is
 *   never shown a shorter list that looks complete.
 */
function clientSafeSections(capabilities) {
  const caps = capabilities || {};
  return SECTIONS.map((s) => ({
    id: s.id,
    name: s.name,
    source: s.source,
    sourceReportId: s.sourceReportId,
    describes: s.describes,
    capability: s.capability,
    allowed: Boolean(caps[s.capability]),
  }));
}

/**
 * The capability a selection REQUIRES: the strictest among its sections.
 *
 * ⛔ AN UNKNOWN SECTION ID CONTRIBUTES NOTHING TO THE REQUIREMENT, because a
 * withdrawn section renders no data — and it is reported separately as a named
 * failure, which is where it belongs. Returning a stricter capability for it
 * would lock an operator out of the sections that still work for a reason
 * nobody could act on.
 *
 * ⛔ AN EMPTY OR UNUSABLE SELECTION RETURNS THE FLOOR, never null. A null would
 * be passed to can() and denied, which is correct but reports the wrong
 * problem: an empty selection is refused by validateDefinition and by the
 * database, with its own message.
 */
function requiredCapability(sectionIds, registry) {
  const list = Array.isArray(sectionIds) ? sectionIds : [];
  const sections = (registry || SECTIONS);
  const byId = new Map(sections.map((s) => [s.id, s]));
  let best = CUSTOM_REPORT_CAPABILITY;
  let bestRank = rankOf(best);
  for (const id of list) {
    const s = byId.get(String(id || ''));
    if (!s) continue;
    const r = rankOf(s.capability);
    if (r > bestRank) {
      bestRank = r;
      best = s.capability;
    }
  }
  return best;
}

/**
 * ⛔ THE STRUCTURAL GUARD THAT KEEPS THE CATALOGUE'S STATIC CAPABILITY HONEST.
 *
 * GET /api/reports/custom-report/pdf gates on the catalogue entry's own
 * `capability` and cannot know the stored selection — it resolves the entry
 * before reading a single row. So if a section ever requires MORE than that
 * entry declares, that route becomes a URL that serves the stricter content
 * under the looser gate. This refuses to produce the document at all, by name,
 * rather than letting it be served.
 *
 * It fires for nobody today (every registered section is `operate`, which is
 * what the entry declares) and it is the reason an identity-bearing section can
 * be added safely: the failure is loud and points at the fix.
 *
 * @throws {Error} naming the section and the capability
 */
function assertCapabilityFloor(sectionIds, floor, registry) {
  const need = requiredCapability(sectionIds, registry);
  if (rankOf(need) <= rankOf(floor || CUSTOM_REPORT_CAPABILITY)) return;
  const sections = registry || SECTIONS;
  const byId = new Map(sections.map((s) => [s.id, s]));
  const offenders = (sectionIds || [])
    .map((id) => byId.get(String(id || '')))
    .filter((s) => s && rankOf(s.capability) > rankOf(floor || CUSTOM_REPORT_CAPABILITY))
    .map((s) => `${s.name} (${s.id}) requires ${s.capability}`);
  throw new Error(
    `This custom report contains a section the download route cannot gate: ${offenders.join('; ')}, `
    + `while the custom-report catalogue entry declares only ${floor || CUSTOM_REPORT_CAPABILITY}. `
    + 'Nothing was produced. Raise the catalogue entry\'s capability in the same commit that '
    + 'registers such a section, or remove the section.'
  );
}

const MAX_NAME = 120;
const MAX_SUBTITLE = 240;
const MAX_SECTIONS = SECTIONS.length;

/**
 * Validate a definition as submitted.
 *
 * ⛔ NEVER THROWS — a malformed body is a 400, not a 500, exactly as
 * validateSchedule treats one.
 *
 * @returns {{ok: boolean, errors: string[], value: object|null}}
 */
function validateDefinition(input) {
  const errors = [];
  try {
    const src = input && typeof input === 'object' && !Array.isArray(input) ? input : {};

    const rawName = typeof src.name === 'string' ? src.name.trim() : '';
    if (rawName === '') {
      errors.push('A custom report needs a name - it is the title on the cover page.');
    } else if (rawName.length > MAX_NAME) {
      errors.push(`The name must be ${MAX_NAME} characters or fewer.`);
    }

    // ⛔ '' BECOMES null, NOT ''. An absent subtitle and an empty one are the
    // same fact and only one of them should be storable, or two rows that
    // render identically compare unequal for ever.
    let subtitle = null;
    if (src.subtitle !== undefined && src.subtitle !== null) {
      if (typeof src.subtitle !== 'string') {
        errors.push('subtitle must be text.');
      } else {
        const s = src.subtitle.trim();
        if (s.length > MAX_SUBTITLE) {
          errors.push(`The subtitle must be ${MAX_SUBTITLE} characters or fewer.`);
        }
        subtitle = s === '' ? null : s;
      }
    }

    const sections = [];
    if (!Array.isArray(src.sections)) {
      errors.push('sections must be an array of section ids.');
    } else if (src.sections.length === 0) {
      // ⛔ REFUSED, NOT RENDERED. A zero-section PDF is a document that looks
      // like a report and says nothing, and somebody would file it. The
      // database refuses it too (custom_reports_sections_chk).
      errors.push('Choose at least one section - an empty report is a document that says nothing.');
    } else if (src.sections.length > MAX_SECTIONS) {
      errors.push(`There are only ${MAX_SECTIONS} sections to choose from.`);
    } else {
      const seen = new Set();
      for (const raw of src.sections) {
        const id = typeof raw === 'string' ? raw.trim() : '';
        if (id === '') {
          errors.push('A section id cannot be blank.');
          continue;
        }
        if (!sectionById(id)) {
          // ⛔ REFUSED AT SAVE TIME. A section that does not exist cannot be
          // chosen; one withdrawn LATER is a different state, handled at render
          // time as a named failure. Both are needed: this one stops a typo
          // becoming a permanently broken report.
          errors.push(`There is no section called "${id}".`);
          continue;
        }
        if (seen.has(id)) {
          // ⛔ A DUPLICATE IS REFUSED RATHER THAN DEDUPLICATED. The same figures
          // printed twice under two numbers invites a reader to treat them as
          // two measurements, and silently dropping the second would make the
          // saved order differ from the order submitted.
          errors.push(`"${sectionById(id).name}" is selected more than once.`);
          continue;
        }
        seen.add(id);
        sections.push(id);
      }
    }

    if (errors.length > 0) return { ok: false, errors, value: null };
    return { ok: true, errors: [], value: { name: rawName, subtitle, sections } };
  } catch (err) {
    return {
      ok: false,
      errors: errors.length > 0 ? errors : [`Could not read the definition: ${err.message}`],
      value: null,
    };
  }
}

/**
 * Which of a stored selection still exist, in order, and which do not.
 *
 * ⛔ THE WITHDRAWN ONES ARE RETURNED, NOT FILTERED OUT. A section id is CODE and
 * a saved report outlives a release, so a withdrawal is a real state — the same
 * one report_schedules.report_id has. The caller must be able to NAME it on the
 * cover, in place of the section, and in the closing gaps list, because a
 * document that quietly loses a section is indistinguishable from one that was
 * never asked for it.
 */
function resolveSelection(sectionIds) {
  const list = Array.isArray(sectionIds) ? sectionIds : [];
  return list.map((id) => ({ id: String(id || ''), section: sectionById(id) }));
}

/** The distinct dataset keys a selection needs gathering. */
function datasetsFor(sectionIds) {
  const out = [];
  for (const { section } of resolveSelection(sectionIds)) {
    if (section && !out.includes(section.dataset)) out.push(section.dataset);
  }
  return out;
}

/**
 * ⛔ A REGISTRY INVARIANT CHECKED IN CODE, not only in a test. A section missing
 * `caveats` would render a body with no coverage statement and nothing would
 * fail — which is the one defect this whole feature is written to prevent. So
 * the registry is checked before anything is drawn.
 *
 * @returns {string[]} the problems, empty when the registry is sound.
 */
function validateRegistry(registry) {
  const sections = registry || SECTIONS;
  const problems = [];
  const seen = new Set();
  for (const s of sections) {
    const label = (s && s.id) || '(unnamed section)';
    if (!s || typeof s.id !== 'string' || !/^[a-z0-9-]+$/.test(s.id)) {
      problems.push(`${label}: the id must be lower-case, digits and hyphens only.`);
    }
    if (seen.has(s && s.id)) problems.push(`${label}: duplicate section id.`);
    seen.add(s && s.id);
    if (!s || typeof s.render !== 'function') problems.push(`${label}: no render function.`);
    if (!s || typeof s.caveats !== 'function') {
      problems.push(`${label}: no caveats function - a section must state what it could not measure.`);
    }
    if (!s || typeof s.dataset !== 'string' || s.dataset === '') {
      problems.push(`${label}: no dataset.`);
    }
    if (!s || typeof s.source !== 'string' || s.source === '') {
      problems.push(`${label}: no source report named.`);
    }
    if (!s || typeof s.capability !== 'string' || s.capability === '') {
      problems.push(`${label}: no capability.`);
    }
  }
  return problems;
}

// ── rendering ──────────────────────────────────────────────────────────────

/**
 * Collect one section's caveats without letting it take the document down.
 *
 * ⛔ A THROW IS NOT AN EMPTY LIST. An empty caveat array is a real answer — this
 * section has nothing to qualify — and a failure to compute them is the
 * opposite claim. Folding the second into the first would print a section with
 * no coverage statement, which is this codebase's signature bug aimed at the
 * mechanism built to prevent it.
 */
function caveatsOf(section, datasetValue) {
  try {
    const out = section.caveats(datasetValue);
    return Array.isArray(out) ? out.filter(Boolean) : [];
  } catch (err) {
    return [{
      label: `The coverage statements for "${section.name}" could not be computed`,
      text: `${err.message}. Read this section as unqualified: the gaps it would have declared `
        + 'are unknown, not absent.',
    }];
  }
}

function withdrawnCaveat(id) {
  return {
    label: `Section "${id}" is no longer part of SecVault`,
    text: 'It was selected when this report was defined and has since been withdrawn, so it is '
      + 'MISSING from this document. Edit the report to choose a replacement. Nothing was '
      + 'silently dropped: this is the whole of what that section would have said.',
  };
}

/**
 * Every caveat in the document, collected — including the ones belonging to
 * sections whose dataset failed and to sections that no longer exist.
 *
 * ⛔ BUILT FROM THE SAME OBJECTS THE BODY RENDERS, so a gap cannot be present in
 * one and absent from the other. The two going out of step would produce a
 * document whose closing page certifies completeness the body contradicts.
 */
function gapsOf(data) {
  const gaps = [];
  for (const { id, section } of data.selection) {
    if (!section) {
      gaps.push(withdrawnCaveat(id));
      continue;
    }
    const ds = data.datasets[section.dataset];
    if (!ds || !ds.ok) {
      gaps.push({
        label: `"${section.name}" has no data`,
        text: `${(ds && ds.error) || 'The data for this section could not be gathered'}. The `
          + 'section is present and empty: that is an absence of measurement, not a clean result.',
      });
      continue;
    }
    for (const c of caveatsOf(section, ds.value)) {
      gaps.push({ label: `${section.name} - ${c.label}`, text: c.text });
    }
  }
  return gaps;
}

function renderCover(doc, data, layout) {
  const generatedAt = fmtStamp(data.generatedAt);
  const rendered = data.selection.filter((s) => s.section).length;
  const withdrawn = data.selection.filter((s) => !s.section).map((s) => s.id);
  const failed = data.selection.filter(
    (s) => s.section && !(data.datasets[s.section.dataset] || {}).ok
  ).map((s) => s.section.name);
  const sources = [];
  for (const { section } of data.selection) {
    if (section && !sources.includes(section.source)) sources.push(section.source);
  }

  drawCover(
    doc,
    {
      title: data.report.name,
      subtitle: data.report.subtitle || 'A selected set of sections from SecVault\'s standard reports',
      company: data.company,
      generatedAt,
      footerStamp: true,
      // ⛔ THE SECTION ACCOUNTING IS ON THE COVER, not in an appendix, because
      // the cover is the only page guaranteed to be read and a composed
      // document's biggest risk is a reader assuming it is the whole picture.
      // The withdrawn and failed rows are stated EVEN WHEN ZERO: an absent row
      // reads as "not applicable", a present one reads as checked.
      meta: [
        ['Sections', `${rendered} of ${data.selection.length} selected`],
        ['Withdrawn since saved', withdrawn.length === 0
          ? 'None'
          : `${withdrawn.length} - ${withdrawn.join(', ')} - MISSING from this document`],
        ['Sections with no data', failed.length === 0 ? 'None' : `${failed.length} - ${failed.join('; ')}`],
        ['Composed from', sources.length === 0 ? NOT_MEASURED_MARK : sources.join('; ')],
        ['Defined by', data.report.createdBy || NOT_MEASURED_MARK],
        ['Generated', generatedAt],
      ],
    },
    layout
  );
}

/**
 * Draw the document from an already-gathered data object.
 *
 * ⛔ SPLIT FROM THE GATHER ON PURPOSE, the same split executiveSummary.js and
 * the change-request report use. Rendering is where every rule above is
 * actually enforced, and a renderer that needed a database to exercise would be
 * a renderer nobody tests — the withdrawn section, the failed dataset and the
 * thrown caveats function are all states a live fleet does not reproduce on
 * demand.
 *
 * @returns {Promise<Buffer>}
 */
function renderCustomReportPdf(data) {
  const registryProblems = validateRegistry();
  if (registryProblems.length > 0) {
    throw new Error(`The custom-report section registry is not usable: ${registryProblems.join(' ')}`);
  }
  // ⛔ CHECKED HERE TOO, not only in the route. This function is callable from
  // anywhere, and the capability floor is the only thing standing between an
  // identity-bearing section and a URL gated on `operate`.
  assertCapabilityFloor(data.selection.map((s) => s.id), data.capabilityFloor);

  const live = data.selection.filter((s) => s.section);
  if (live.length === 0) {
    // ⛔ NOT AN EMPTY DOCUMENT. Every section in the saved selection has been
    // withdrawn, so there is nothing left to render and a cover page with
    // nothing behind it is the confident-looking artefact this product refuses.
    throw new Error(
      `None of the ${data.selection.length} section(s) saved in "${data.report.name}" exist any `
      + `more (${data.selection.map((s) => s.id).join(', ')}), so no document was produced. Edit `
      + 'the report and choose sections that still exist.'
    );
  }

  // ⛔ LAZY: see the header. The catalogue imports this module for one constant
  // and must not gain pdfkit by doing so.
  const PDFDocument = require('pdfkit');
  const doc = installPdfSafeText(
    new PDFDocument({ size: 'A4', layout: 'portrait', margin: 36, bufferPages: true })
  );
  const layout = layoutOf(doc);
  const generatedAt = fmtStamp(data.generatedAt);

  renderCover(doc, data, layout);

  sectionTitle(doc, layout, 'What this document is');
  paragraph(doc, layout, COMPOSITION_CLAIM, MUTED, 9.5);

  let n = 0;
  for (const { id, section } of data.selection) {
    n += 1;
    if (!section) {
      // ⛔ THE WITHDRAWN SECTION KEEPS ITS PLACE AND ITS NUMBER. Skipping it
      // would renumber everything after it and leave nothing on the page saying
      // the document is shorter than its definition.
      sectionTitle(doc, layout, `${n}. Section "${id}" is unavailable`);
      const c = withdrawnCaveat(id);
      labelledNote(doc, layout, c.label, STATUS_RED, c.text);
      doc.y += 6;
      continue;
    }

    sectionTitle(doc, layout, `${n}. ${section.name}`);
    paragraph(doc, layout, `From SecVault's ${section.source} report.`, ACCENT, 8.5);

    const ds = data.datasets[section.dataset] || { ok: false, error: 'No dataset was gathered.' };
    if (!ds.ok) {
      datasetRefusal(doc, layout, section.name, ds.error);
      doc.y += 6;
      continue;
    }

    try {
      section.render(doc, layout, ds.value, { generatedAt });
    } catch (err) {
      // ⛔ ONE SECTION'S FAILURE MUST NOT COST THE WHOLE DOCUMENT, and it must
      // not be silent either. The operator gets the sections that worked plus
      // the name of the one that did not.
      labelledNote(
        doc, layout,
        `${section.name} could not be rendered.`, STATUS_RED,
        `${err.message}. The other sections of this document are unaffected; this one is missing, `
        + 'not empty.'
      );
    }

    // ⛔ THE FRAMEWORK RENDERS THE CAVEATS, NOT THE SECTION. That is what makes
    // it impossible for a section to ship without them.
    const caveats = caveatsOf(section, ds.value);
    if (caveats.length > 0) {
      ensureSpace(doc, layout, 40);
      paragraph(doc, layout, 'What this section could not measure:', UNMEASURED, 9);
      for (const c of caveats) labelledNote(doc, layout, c.label, UNMEASURED, c.text);
    }
    doc.y += 8;
  }

  // ── the closing account ──────────────────────────────────────────────────
  sectionTitle(doc, layout, 'What could not be measured');
  const gaps = gapsOf(data);
  if (gaps.length === 0) {
    // ⛔ The only reassuring sentence in the document, and it is reachable only
    // when every selected section exists, every dataset was gathered and every
    // one of them declared no gap. It still refuses to speak for the sections
    // nobody selected.
    paragraph(
      doc, layout,
      'Every section in this document rests on a completed measurement, and none of them '
      + 'declared a coverage gap. That is a statement about the sections selected here and about '
      + 'nothing else.',
      GREEN, 10
    );
  } else {
    paragraph(
      doc, layout,
      `${gaps.length} gap${gaps.length === 1 ? '' : 's'} in what this document could measure. `
      + 'Each one narrows what the figures above may be read to mean.',
      MUTED, 9
    );
    for (const g of gaps) labelledNote(doc, layout, g.label, UNMEASURED, g.text);
  }

  stampHeadersFooters(doc, {
    title: `${PRODUCT_NAME} ${data.report.name}`,
    company: data.company,
    generatedAt,
  });

  return new Promise((resolve, reject) => {
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    doc.end();
  });
}

module.exports = {
  CUSTOM_REPORT_CAPABILITY,
  COMPOSITION_CLAIM,
  SECTIONS,
  MAX_NAME,
  MAX_SUBTITLE,
  NOT_MEASURED_MARK,
  sectionById,
  clientSafeSections,
  requiredCapability,
  assertCapabilityFloor,
  validateDefinition,
  validateRegistry,
  resolveSelection,
  datasetsFor,
  caveatsOf,
  gapsOf,
  withdrawnCaveat,
  renderCustomReportPdf,
  numOrNull,
  countDisplay,
  // Exported so a test can assert the ranking rather than a table of literals.
  rankOf,
  // Unused by the renderer; kept exported because the chassis palette is what
  // a future section will reach for, and a section reaching for its own hex is
  // how app/globals.css's palette rot started.
  PALETTE: { ACCENT, NAVY, MUTED, GREEN, STATUS_RED, YELLOW, UNMEASURED },
  pdfSafe,
};
