// lib/reports/executiveSummary.js
//
// R1 — "Executive Security Posture". The fleet-wide, board-facing report.
//
// ⛔ WHY THIS REPORT EXISTS, IN ONE LINE: it is written for someone who will
// not read page two. Four independent reviewers of the product this replaces
// name the same absence — "wish it had more summary or weekly manager type
// reports" — and no researched competitor ships an executive tier as a report
// of its own. Every other artefact here is an analyst's document: a ruleset, a
// findings appendix, a change request. This one answers three questions and
// then stops. How exposed are we, is it getting better, and what is being done.
//
// ⛔ THE DANGEROUS THING ABOUT AN EXECUTIVE REPORT IS THAT NOBODY AUDITS IT.
// The analyst reading the compliance appendix will notice a device missing from
// the list. The board reading one number will not. So every rule below is about
// refusing to let a partial measurement wear the clothes of a complete one:
//
//   1. THE COVER STATES COVERAGE. Devices included, devices that could NOT be
//      assessed, and the window actually compared. A fleet claim over a partial
//      fleet is the most dangerous thing this product prints, and the cover is
//      the only page guaranteed to be read.
//   2. AN ALL-CLEAR IS FORBIDDEN WHILE COVERAGE IS INCOMPLETE. The fleet
//      sentence is NOT composed here — it comes from the answers engine, which
//      already carries that rule and has already been caught breaking it once.
//      Re-deriving it in a PDF would be a second implementation, and the second
//      implementation is always the one that is wrong.
//   3. A NULL SCORE IS "NOT MEASURABLE", NEVER 0. The security score drops an
//      unmeasurable component from its denominator and returns null when all
//      three are gone. Rendering that null as 0 would report a data gap as the
//      worst possible security posture, to the audience least able to tell the
//      difference.
//   4. NO SILENT TRUNCATION. Any capped list prints "showing N of M".
//   5. A SECTION THAT FAILED TO GATHER SAYS SO, IN PLACE. It must not vanish:
//      a missing section reads as "nothing to report", and this document is
//      shortest and most reassuring exactly when it is least trustworthy.
//   6. TREND NEEDS A REAL PRIOR POINT. With no previous snapshot the movement
//      section says "no prior period to compare" — never a 0 delta, which reads
//      as "unchanged" when the truth is "unknown".
//
// ⛔ EVERY GATHER IS WRAPPED SEPARATELY, and that is rule 5's mechanism. One
// failing query must cost its own section and nothing else. A single try/catch
// around the whole gather would turn a compliance outage into a blank report.
//
// pdfkit only, via the shared chassis. No headless browser: the product's
// earlier puppeteer implementation worked in every manual test and failed only
// when spawned inside the NSSM Windows service, and package.json carries no
// devDependencies on purpose.
//
// CommonJS — the App Router route and the scheduler (plain node) both load it.

'use strict';

const PDFDocument = require('pdfkit');

const {
  NAVY, MUTED, GREEN,
  installPdfSafeText, fmtStamp,
  layoutOf, ensureSpace, drawCover, sectionTitle, paragraph, labelledNote,
  drawTable, stampHeadersFooters,
  // ⛔ The severity ramp comes from the chassis too. It was defined locally
  // here first, which made a THIRD copy of the same four literals — the exact
  // duplication the chassis exists to absorb, reappearing one file later.
  STATUS_RED, YELLOW, UNMEASURED,
} = require('./chassis');

const { PRODUCT_NAME } = require('../branding');
const { getFleetHeadline, getPreviousHeadline } = require('../engines/fleetHeadline');
const { WEIGHTS, securityScoreBand } = require('../engines/securityScore');
const { computeFleetComplianceScores } = require('../engines/dashboardSnapshot');
const { gatherWorkQueue } = require('../engines/workQueueData');
const { rankItems, summarise } = require('../engines/workQueue');
const { buildFleetAnswer } = require('../answers');

const TITLE = 'Executive Security Posture';

// ⛔ THE CAP IS DISCLOSED, NOT HIDDEN (rule 4). Twelve is the most an executive
// page can carry without becoming the analyst's list this report exists not to
// be — but a reader who works the list to the bottom and believes they are
// finished has been misled, so the count it was cut from is printed beside it.
const MAX_WORK_ITEMS = 12;

// The em-dash the product uses on screen for "not measured". The chassis'
// pdfSafe folds it to a hyphen for the WinAnsi built-in font; the point is that
// it is NOT a number, and a hyphen carries that just as well as an em-dash.
const NOT_MEASURED_MARK = '—';

// ── Number handling ────────────────────────────────────────────────────────

/**
 * ⛔ DELIBERATELY THE SAME STRICTNESS AS THE SECURITY SCORE ENGINE'S OWN GUARD,
 * and for the same reason. `Number()` maps '', false and [] to 0, and 0 is a
 * real, meaningful value everywhere in this document — a count of zero urgent
 * items, a score of zero. Coercing an unreadable input to it turns a failed
 * read into the most reassuring (or most alarming) figure on the page. A
 * numeric string is accepted because node-postgres returns COUNT(*) as text.
 */
function numOrNull(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'boolean') return null;
  if (typeof value !== 'number' && typeof value !== 'string') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

/** A score, or the not-measured mark. ⛔ Never `score || '-'` — 0 is a score. */
function scoreDisplay(score, suffix = '') {
  const n = numOrNull(score);
  return n === null ? NOT_MEASURED_MARK : `${n}${suffix}`;
}

function countDisplay(value) {
  const n = numOrNull(value);
  return n === null ? NOT_MEASURED_MARK : String(n);
}

/**
 * The calendar day PostgreSQL stored, recovered from what node-postgres hands
 * back.
 *
 * ⛔ FORMATTING A pg `DATE` IN UTC IS OFF BY ONE ON THIS DEPLOYMENT. node-pg
 * parses DATE into a JS Date at LOCAL midnight, so the row whose snapshot_date
 * is 2026-09-14 arrives as 2026-09-13T17:00:00Z on a UTC+7 server. Taking the
 * UTC date part of that — the obvious thing to do, and what the generated-at
 * stamp correctly does for a TIMESTAMPTZ — would print every comparison date a
 * day early on the cover of a document nobody will re-derive. Local components
 * recover exactly the date the database stored.
 */
function localDay(d) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function fmtDay(value) {
  if (value === null || value === undefined || value === '') return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : localDay(value);
  const s = String(value);
  // A bare 'YYYY-MM-DD' is already the stored day and must NOT be round-tripped
  // through Date — that would parse it as UTC midnight and shift it the other
  // way on a negative-offset server.
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : localDay(d);
}

/** Whole calendar days between two 'YYYY-MM-DD' strings, or null. */
function daysBetween(fromDay, toDay) {
  if (!fromDay || !toDay) return null;
  const a = Date.parse(`${fromDay}T00:00:00Z`);
  const b = Date.parse(`${toDay}T00:00:00Z`);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
  return Math.round((b - a) / 86400000);
}

// ── Gathering ──────────────────────────────────────────────────────────────

const SECTION_LABELS = {
  headline: 'Fleet posture',
  previous: 'Previous period',
  work: 'Outstanding work',
  compliance: 'Compliance breakdown',
};

/**
 * Run one gather, and NEVER let it take the report down with it.
 *
 * ⛔ The returned shape distinguishes "gathered, and the value is null" from
 * "could not gather". Those render differently and must: the first is a fact
 * about the fleet, the second is a fact about this run, and collapsing them is
 * the failed-read-as-a-fact bug wearing a section heading.
 */
async function gatherSection(key, fn) {
  try {
    return { key, ok: true, value: await fn(), error: null };
  } catch (err) {
    return { key, ok: false, value: null, error: err && err.message ? err.message : 'unknown error' };
  }
}

/**
 * Everything the report renders, gathered section by section.
 *
 * @param {import('pg').Pool} pool
 * @param {{generatedAt?:Date, company?:string, maxWorkItems?:number, segmentation?:object}} [options]
 */
async function gatherExecutiveSummary(pool, options = {}) {
  const [headline, previous, work, compliance] = await Promise.all([
    gatherSection('headline', () => getFleetHeadline(pool)),
    gatherSection('previous', () => getPreviousHeadline(pool)),
    gatherSection('work', async () => {
      const { items, sources } = await gatherWorkQueue(pool, { segmentation: options.segmentation });
      const ranked = rankItems(items);
      return { ranked, summary: summarise(ranked, sources) };
    }),
    gatherSection('compliance', () => computeFleetComplianceScores(pool)),
  ]);

  const capRaw = Number(options.maxWorkItems);
  return {
    generatedAt: options.generatedAt || new Date(),
    company: options.company || PRODUCT_NAME,
    // ⛔ Clamped to at least 1. A cap of 0 would render an empty act-now table
    // under a heading that says there is work outstanding — the two halves of
    // the page disagreeing, with no error anywhere.
    maxWorkItems: Number.isFinite(capRaw) && capRaw >= 1 ? Math.floor(capRaw) : MAX_WORK_ITEMS,
    sections: { headline, previous, work, compliance },
  };
}

// ── Derived views over the gathered data ───────────────────────────────────

/**
 * Fleet coverage, as the cover must state it.
 *
 * ⛔ `deviceCount` and `devicesCveAssessed` are NOT interchangeable and the gap
 * between them is the single most important number on the cover. Every fleet
 * figure below is computed over the assessed set; a reader who assumes it
 * covers the managed set has been given a broader assurance than was measured.
 */
function coverageOf(headlineSection) {
  const section = headlineSection || {};
  if (!section.ok || !section.value) {
    return { ok: false, devices: null, assessed: null, gap: null };
  }
  const devices = numOrNull(section.value.deviceCount);
  const assessed = numOrNull(section.value.devicesCveAssessed);
  const gap = devices !== null && assessed !== null && assessed < devices ? devices - assessed : 0;
  return { ok: true, devices, assessed, gap };
}

/**
 * The period-over-period rows.
 *
 * @returns {{available:boolean, reason:string|null, priorDay:string|null,
 *            days:number|null, rows:Array}}
 */
function movementOf(headlineSection, previousSection, generatedAt) {
  const head = headlineSection || {};
  const prevSection = previousSection || {};
  if (!head.ok || !head.value) {
    return { available: false, reason: 'current', priorDay: null, days: null, rows: [] };
  }
  if (!prevSection.ok) {
    return { available: false, reason: 'failed', priorDay: null, days: null, rows: [] };
  }
  const prev = prevSection.value;
  // ⛔ RULE 6. No prior row is not a zero delta. The nightly snapshot is what
  // creates a prior point, so a fleet in its first day of management, or one
  // whose snapshot job has never run, genuinely has nothing to compare against
  // — and "0 change" would be an invented reassurance that the posture held
  // steady over a period that was never observed.
  if (!prev) {
    return { available: false, reason: 'none', priorDay: null, days: null, rows: [] };
  }

  const h = head.value;
  const priorDay = fmtDay(prev.snapshot_date);
  const days = daysBetween(priorDay, localDay(generatedAt));

  // `betterWhen` is what turns a delta into a judgement. It is declared per
  // metric rather than inferred from the sign, because the two directions
  // genuinely coexist on this page: a score going up is good, a count of urgent
  // findings going up is not, and one rule would get half of them backwards.
  const METRICS = [
    { label: 'Security score (0-100)', now: h.securityScore, was: prev.security_score, betterWhen: 'higher' },
    { label: 'Compliance score (%)', now: h.complianceScore, was: prev.compliance_overall_score, betterWhen: 'higher' },
    { label: 'Findings needing patching now', now: h.patchNowCount, was: prev.patch_now_count, betterWhen: 'lower' },
    { label: 'High-risk rule findings', now: h.highRiskCount, was: prev.high_risk_count, betterWhen: 'lower' },
    { label: 'Firewalls reachable', now: h.devicesOnline, was: prev.devices_online, betterWhen: 'higher' },
    { label: 'Firewalls under management', now: h.deviceCount, was: prev.device_count, betterWhen: 'higher' },
  ];

  const rows = METRICS.map((m) => {
    const now = numOrNull(m.now);
    const was = numOrNull(m.was);
    // ⛔ EITHER SIDE MISSING MEANS NO CHANGE CAN BE STATED. Snapshot rows
    // written before the headline columns existed carry NULLs, and a NULL
    // subtracted from a number is not a movement of that size — it is no
    // movement anybody can see.
    if (now === null || was === null) {
      return {
        metric: m.label,
        was: was === null ? NOT_MEASURED_MARK : String(was),
        now: now === null ? NOT_MEASURED_MARK : String(now),
        change: 'No prior value recorded',
        direction: 'unknown',
      };
    }
    const delta = now - was;
    const direction = delta === 0
      ? 'flat'
      : (m.betterWhen === 'higher') === (delta > 0) ? 'better' : 'worse';
    return {
      metric: m.label,
      was: String(was),
      now: String(now),
      change: delta === 0 ? 'No change' : `${delta > 0 ? '+' : ''}${delta}`,
      direction,
    };
  });

  return { available: true, reason: null, priorDay, days, rows };
}

/**
 * Every gap on the page, collected into the one section an executive reader is
 * most likely to skip and most needs to see.
 *
 * ⛔ THIS SECTION IS NEVER EMPTIED BY FAILURE. It is built from the same
 * objects the sections above render, so a gap cannot be present in the body and
 * absent here — the two going out of step would produce a report whose closing
 * page certifies completeness the body contradicts.
 */
function gapsOf(data) {
  const { headline, previous, work, compliance } = data.sections;
  const gaps = [];

  for (const section of [headline, previous, work, compliance]) {
    if (section.ok) continue;
    gaps.push({
      label: SECTION_LABELS[section.key] || section.key,
      text: `Could not be gathered: ${section.error}. Every figure that depends on it is shown as `
        + 'not measured rather than assumed.',
    });
  }

  const cov = coverageOf(headline);
  if (cov.ok && cov.gap > 0) {
    gaps.push({
      label: `${cov.gap} of ${cov.devices} firewalls never assessed`,
      text: 'These firewalls are excluded from every fleet figure in this report. Their posture is '
        + 'unknown, which is not the same as clean.',
    });
  }

  if (headline.ok && headline.value) {
    const unmeasurable = (headline.value.securityComponents || []).filter((c) => c.score === null);
    for (const c of unmeasurable) {
      gaps.push({
        label: `${c.label} could not be scored`,
        text: `Its ${c.weight} points were removed from the weighting rather than counted as zero, so `
          + 'the score above is an average of what could be measured, not of the whole model.',
      });
    }
  }

  if (!movementOf(headline, previous, data.generatedAt).available) {
    gaps.push({
      label: 'No period-over-period comparison',
      text: 'No prior daily snapshot was available, so nothing in this report states whether the '
        + 'posture improved or worsened.',
    });
  }

  if (work.ok && work.value) {
    const s = work.value.summary;
    for (const f of s.failedSources || []) {
      gaps.push({
        label: `Outstanding work from "${f.key}" is missing`,
        text: `That source failed with: ${f.error}. The work list is therefore shorter than the `
          + 'truth by an unknown amount.',
      });
    }
    for (const t of s.truncatedSources || []) {
      gaps.push({
        label: `Outstanding work from "${t.key}" was capped`,
        text: `Showing ${t.shown} of ${t.of}.`,
      });
    }
    if (s.verify > 0) {
      gaps.push({
        label: `${s.verify} item${s.verify === 1 ? '' : 's'} need a human to verify`,
        text: 'These are things the platform could not measure - an expiry date that would not parse, '
          + 'a firewall that could not be read. They are not ranked as urgent, because ranking a '
          + 'guess as a measurement is worse than admitting the gap.',
      });
    }
  }

  return gaps;
}

// ── Rendering ──────────────────────────────────────────────────────────────

function directionColor(direction) {
  if (direction === 'better') return GREEN;
  if (direction === 'worse') return STATUS_RED;
  if (direction === 'unknown') return UNMEASURED;
  return MUTED;
}

function scoreColor(score) {
  const n = numOrNull(score);
  if (n === null) return UNMEASURED;
  if (n >= 75) return GREEN;
  if (n >= 50) return YELLOW;
  return STATUS_RED;
}

function renderCover(doc, data, layout) {
  const { headline, work } = data.sections;
  const generatedAt = fmtStamp(data.generatedAt);
  const cov = coverageOf(headline);
  const move = movementOf(headline, data.sections.previous, data.generatedAt);
  const score = headline.ok && headline.value ? headline.value.securityScore : null;
  const actNow = work.ok && work.value ? work.value.summary.act_now : null;

  const periodText = move.available
    ? `${move.priorDay} to ${localDay(data.generatedAt)}`
      + (move.days !== null ? ` (${move.days} day${move.days === 1 ? '' : 's'})` : '')
    : 'No prior period to compare - a point-in-time position only';

  const okSections = Object.values(data.sections).filter((s) => s.ok).length;
  const totalSections = Object.values(data.sections).length;

  drawCover(
    doc,
    {
      title: TITLE,
      subtitle: 'How exposed is the estate, is it improving, and what is being done about it',
      company: data.company,
      generatedAt,
      footerStamp: true,
      // ⛔ RULE 1 LIVES HERE. Coverage is on the cover, not in an appendix,
      // because the cover is the only page guaranteed to be read and an
      // unqualified fleet number is the most dangerous thing this product
      // prints. The "not assessed" row is stated even when it is zero — an
      // absent row reads as "not applicable", a present one reads as checked.
      meta: [
        ['Firewalls managed', cov.ok ? countDisplay(cov.devices) : 'Could not be read'],
        ['Firewalls assessed', cov.ok && cov.devices !== null
          ? `${countDisplay(cov.assessed)} of ${countDisplay(cov.devices)}`
          : 'Could not be read'],
        ['Not assessed', cov.ok
          ? (cov.gap > 0
            ? `${cov.gap} - excluded from every figure in this report`
            : 'None - coverage is complete')
          : 'Unknown'],
        ['Period compared', periodText],
        ['Evidence gathered', `${okSections} of ${totalSections} data sources`],
        ['Generated', generatedAt],
      ],
      summary: [
        {
          label: score === null ? 'Security score: not measurable' : 'Security score (0-100)',
          value: scoreDisplay(score),
          color: scoreColor(score),
        },
        { label: 'Firewalls managed', value: countDisplay(cov.devices), color: NAVY },
        {
          label: 'Needs action now',
          value: countDisplay(actNow),
          color: actNow === null ? UNMEASURED : actNow > 0 ? STATUS_RED : GREEN,
        },
        {
          label: 'Never assessed',
          value: cov.ok ? countDisplay(cov.gap) : NOT_MEASURED_MARK,
          color: cov.ok && cov.gap > 0 ? UNMEASURED : MUTED,
        },
      ],
    },
    layout
  );
}

/**
 * The one sentence this report is for.
 *
 * ⛔ THE SENTENCE IS NOT COMPOSED HERE, AND MUST NOT BE. The answers engine
 * already enforces that an all-clear is forbidden while coverage is incomplete,
 * and it already carries the scar from getting that wrong: a green "no urgent
 * exposure across all firewalls" printed off a count that did not exist.
 * Writing a second sentence-builder for the PDF would mean two implementations
 * of that rule, and the one not exercised on screen every day is the one that
 * drifts.
 *
 * ⛔ AND IT IS NOT CALLED AT ALL WHEN THE GATHER FAILED. Handed a null headline
 * the engine answers "No firewalls are under management yet" — correct for an
 * empty fleet, and a confident falsehood for a fleet whose query threw. A
 * failed read must never be routed through a function that will phrase it as a
 * finding.
 */
function renderAnswer(doc, data, layout) {
  const { headline } = data.sections;
  sectionTitle(doc, layout, 'The position today');

  if (!headline.ok || !headline.value) {
    labelledNote(
      doc, layout,
      'The fleet position could not be determined.', STATUS_RED,
      `The posture figures could not be gathered (${headline.error || 'no data returned'}). `
      + 'Nothing in this report should be read as an all-clear: this is an absence of measurement, '
      + 'not an absence of exposure.'
    );
    return;
  }

  const answer = buildFleetAnswer(headline.value);
  const lead = answer.lead ? `${answer.lead} ` : '';
  const toneColor = answer.tone === 'critical'
    ? STATUS_RED
    : answer.tone === 'warn'
      ? YELLOW
      : answer.tone === 'ok'
        ? GREEN
        // ⛔ `unknown` IS HUELESS. It is the tone that means "nothing
        // outstanding, but we could not see all of it", and painting it green
        // is the exact failure the four-tone scheme exists to prevent.
        : UNMEASURED;

  ensureSpace(doc, layout, 60);
  paragraph(doc, layout, `${lead}${answer.sentence}`, toneColor, 13);

  // ⛔ RULE 2's VISIBLE HALF. The coverage clause is rendered whenever the
  // engine produced one, without exception and without a "does it look bad"
  // judgement call here — it is the qualification that makes the sentence above
  // it true, and a sentence separated from its qualification is a different
  // sentence.
  if (answer.coverage) {
    labelledNote(doc, layout, 'Coverage', UNMEASURED, answer.coverage);
  }
}

function renderScore(doc, data, layout) {
  const { headline } = data.sections;
  sectionTitle(doc, layout, 'Security score, and what it is made of');

  if (!headline.ok || !headline.value) {
    paragraph(
      doc, layout,
      'The security score could not be gathered for this report, so no score is shown. '
      + 'It is not zero and it is not low - it is unknown.',
      STATUS_RED, 10
    );
    return;
  }

  const h = headline.value;
  const components = Array.isArray(h.securityComponents) ? h.securityComponents : [];
  const measured = components.filter((c) => c.score !== null);
  const measuredWeight = measured.reduce((sum, c) => sum + c.weight, 0);
  const totalWeight = WEIGHTS.vulnerability + WEIGHTS.hygiene + WEIGHTS.compliance;

  if (numOrNull(h.securityScore) === null) {
    // ⛔ RULE 3. Never a number here. A board reading "0 / 100" concludes the
    // estate is maximally exposed; the truth is that nothing has been measured
    // yet, which is a different problem with a different response.
    paragraph(
      doc, layout,
      `Score: ${NOT_MEASURED_MARK}  Not measurable. None of the three components could be scored, `
      + 'so no overall figure exists. This is a gap in what has been collected, not a finding about '
      + 'the estate.',
      UNMEASURED, 13
    );
  } else {
    const band = securityScoreBand(h.securityScore);
    paragraph(
      doc, layout,
      `Score: ${h.securityScore} / 100 (${band}). Higher is better.`,
      scoreColor(h.securityScore), 13
    );
  }

  paragraph(
    doc, layout,
    `The score weights vulnerability posture ${WEIGHTS.vulnerability}, rule hygiene `
    + `${WEIGHTS.hygiene} and compliance ${WEIGHTS.compliance}. A component that cannot be measured `
    + 'is removed from the weighting rather than scored zero, so a gap in collection never presents '
    + 'itself as a security problem. '
    + (measuredWeight === totalWeight
      ? 'All three components were measurable for this report.'
      : `${measuredWeight} of ${totalWeight} weighting points were measurable for this report.`),
    MUTED, 9
  );

  drawTable(
    doc,
    {
      columns: [
        { key: 'component', label: 'Component', width: 200 },
        { key: 'weight', label: 'Weight', width: 70, align: 'right' },
        {
          key: 'score',
          label: 'Score',
          width: 70,
          align: 'right',
          color: (r) => (r.measured ? scoreColor(r.rawScore) : UNMEASURED),
          font: (r) => (r.measured ? 'Helvetica-Bold' : 'Helvetica-Oblique'),
        },
        {
          key: 'status',
          label: 'Counted toward the score?',
          width: 240,
          color: (r) => (r.measured ? MUTED : UNMEASURED),
        },
      ],
      rows: components.map((c) => ({
        component: c.label,
        weight: String(c.weight),
        score: scoreDisplay(c.score),
        rawScore: c.score,
        measured: c.score !== null,
        status: c.score === null
          ? `No - not measurable, its ${c.weight} points were dropped from the denominator`
          : `Yes - ${c.weight} of ${measuredWeight} measured points`,
      })),
    },
    layout,
    { continueOnPage: true, emptyText: 'No score components were returned.' }
  );
  doc.y += 10;
}

function renderMovement(doc, data, layout) {
  const move = movementOf(data.sections.headline, data.sections.previous, data.generatedAt);
  sectionTitle(doc, layout, 'Movement since the last measured period');

  if (!move.available) {
    // ⛔ RULE 6, AND RULE 5 IN THE SAME BREATH. The section is rendered even
    // though it has nothing to show, because a movement section that simply
    // disappears when there is no prior point reads as "no movement".
    const why = move.reason === 'none'
      ? 'There is no prior period to compare against, so no trend can be stated. This is not a '
        + 'report of zero change - it is the absence of a second data point.'
      : move.reason === 'failed'
        ? `The previous period could not be read (${data.sections.previous.error}), so no trend can `
          + 'be stated.'
        : 'The current position could not be read, so no trend can be stated.';
    paragraph(doc, layout, why, UNMEASURED, 10);
    doc.y += 6;
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
          color: (r) => directionColor(r.direction),
          font: (r) => (r.direction === 'unknown' ? 'Helvetica-Oblique' : 'Helvetica-Bold'),
        },
      ],
      rows: move.rows,
    },
    layout,
    { continueOnPage: true, emptyText: 'No comparable measures were recorded.' }
  );
  doc.y += 10;
}

function renderWork(doc, data, layout) {
  const { work } = data.sections;
  sectionTitle(doc, layout, 'What is being done - the urgent queue');

  if (!work.ok || !work.value) {
    labelledNote(
      doc, layout,
      'The outstanding work could not be gathered.', STATUS_RED,
      `${work.error || 'No data returned'}. An empty work list here would mean nothing is `
      + 'outstanding; that claim cannot be made from this run.'
    );
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
    + `${summary.verify === 1 ? 'it' : 'them'}. `
    + 'An item only reaches the urgent band on measured or vendor-reported evidence; nothing is '
    + 'ranked urgent on a guess.',
    MUTED, 9
  );

  // ⛔ RULE 4. Printed BEFORE the table, not as a footnote after it, because
  // the reader who stops at the bottom of the list is exactly the reader this
  // disclosure is for.
  if (shown.length < actNow.length) {
    labelledNote(
      doc, layout,
      `Showing ${shown.length} of ${actNow.length} urgent items`, YELLOW,
      'The remainder are in the platform, ranked in the same order. This page is capped so it stays '
      + 'readable, not because the list ends here.'
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
        // The queue's own vocabulary, capitalised for a reader who has never
        // seen the product: measured (we observed it) vs reported (a vendor
        // asserts it and we matched faithfully). `unmeasured` cannot appear
        // here — the queue refuses it entry to this band.
        evidence: it.evidence === 'measured' ? 'Measured' : 'Reported',
      })),
    },
    layout,
    {
      continueOnPage: true,
      // ⛔ NOT "nothing to do". An empty urgent band with a failed source or an
      // unassessed fleet is an unknown queue, and the gaps section says so.
      emptyText: 'No items reached the urgent band in this run.',
    }
  );
  doc.y += 10;
}

function renderCompliance(doc, data, layout) {
  const { compliance } = data.sections;
  sectionTitle(doc, layout, 'Compliance against the standards');

  if (!compliance.ok || !compliance.value) {
    paragraph(
      doc, layout,
      `The compliance breakdown could not be gathered (${compliance.error || 'no data returned'}). `
      + 'No standard is shown as passing or failing on the strength of a query that did not run.',
      STATUS_RED, 10
    );
    return;
  }

  const { overall, byStandard, byStandardCounts } = compliance.value;
  paragraph(
    doc, layout,
    numOrNull(overall) === null
      ? `Overall: ${NOT_MEASURED_MARK}  Not measurable. No check could be answered against any `
        + 'collected configuration, so there is no percentage to report.'
      : `Overall: ${overall}%. Checks the platform cannot ask of a device are excluded from the `
        + 'denominator entirely, so this figure never counts our own blind spots against the estate.',
    numOrNull(overall) === null ? UNMEASURED : scoreColor(overall), 10
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
          color: (r) => (r.measured ? scoreColor(r.rawScore) : UNMEASURED),
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
          // ⛔ A standard with nothing measurable is a dash, not 0%. A board
          // reading "PCI DSS 0%" concludes the estate fails every card-data
          // control; the truth may be that no check for it could be answered.
          score: pct === null ? NOT_MEASURED_MARK : `${pct}%`,
          rawScore: pct,
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
  doc.y += 10;
}

/**
 * ⛔ THE CLOSING SECTION, AND THE ONE THAT MAKES THE REST DEFENSIBLE. Every
 * other page states what was found; this one states what could not be looked
 * at. Without it an executive summary is indistinguishable from a complete one,
 * which is precisely the criticism this report was built to answer.
 */
function renderGaps(doc, data, layout) {
  sectionTitle(doc, layout, 'What could not be measured');
  const gaps = gapsOf(data);

  if (gaps.length === 0) {
    // ⛔ The ONLY place this document is allowed to sound reassuring, and it is
    // reachable only when every source was gathered, every managed firewall was
    // assessed, all three score components were measurable and a prior period
    // existed. Loosen any one of those conditions and this becomes an
    // all-clear over a partial fleet.
    paragraph(
      doc, layout,
      'Every figure in this report rests on a completed measurement: all data sources were '
      + 'gathered, every firewall under management was assessed, all three score components were '
      + 'measurable, and a prior period was available to compare against.',
      GREEN, 10
    );
    return;
  }

  paragraph(
    doc, layout,
    `${gaps.length} gap${gaps.length === 1 ? '' : 's'} in what this report could measure. Each one `
    + 'narrows what the figures above may be read to mean.',
    MUTED, 9
  );
  for (const g of gaps) {
    labelledNote(doc, layout, g.label, UNMEASURED, g.text);
  }
}

/**
 * Draw the document from an already-gathered data object.
 *
 * ⛔ SPLIT FROM THE GATHER ON PURPOSE, and it is the same split the change
 * request report uses. Rendering is where every rule above is actually
 * enforced, and a renderer that needed a database to exercise would be a
 * renderer nobody tests — the null score, the failed section and the capped
 * list are all states the live fleet does not helpfully reproduce on demand.
 *
 * @returns {Promise<Buffer>}
 */
function renderExecutiveSummaryPdf(data) {
  const doc = installPdfSafeText(
    new PDFDocument({ size: 'A4', layout: 'portrait', margin: 36, bufferPages: true })
  );
  const layout = layoutOf(doc);
  const generatedAt = fmtStamp(data.generatedAt);

  renderCover(doc, data, layout);
  renderAnswer(doc, data, layout);
  renderScore(doc, data, layout);
  renderMovement(doc, data, layout);
  renderWork(doc, data, layout);
  renderCompliance(doc, data, layout);
  renderGaps(doc, data, layout);

  stampHeadersFooters(doc, {
    title: `${PRODUCT_NAME} ${TITLE}`,
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

/**
 * @param {import('pg').Pool} pool
 * @param {{generatedAt?:Date, company?:string, maxWorkItems?:number, segmentation?:object}} [options]
 * @returns {Promise<Buffer>}
 */
async function generateExecutiveSummaryPdf(pool, options = {}) {
  const data = await gatherExecutiveSummary(pool, options);
  return renderExecutiveSummaryPdf(data);
}

module.exports = {
  generateExecutiveSummaryPdf,
  // Exported so the rules above can be tested without a database — the whole
  // point of the gather/render split.
  gatherExecutiveSummary,
  renderExecutiveSummaryPdf,
  coverageOf,
  movementOf,
  gapsOf,
  scoreDisplay,
  countDisplay,
  numOrNull,
  fmtDay,
  daysBetween,
  MAX_WORK_ITEMS,
  TITLE,
};
