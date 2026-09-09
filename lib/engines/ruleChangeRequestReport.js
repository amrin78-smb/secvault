// lib/engines/ruleChangeRequestReport.js
//
// The DOCUMENT half of the rule-cleanup loop (lib/engines/ruleChangeRequests.js
// is the frozen state machine; this file only renders it).
//
// ⛔ THIS ARTEFACT LEAVES THE TOOL. It is handed to a change board, a vendor or
// a NOC engineer who has never logged into SecVault, will never see the UI, and
// has no reason to trust us. So it may not say "delete rule 47" — that is what
// ManageEngine produces and it asks for faith. Every row here states the
// EVIDENCE the proposal rests on, in numbers the reader can disagree with: the
// device's own hit counter at the moment the request was raised, AND what the
// firewall's own logs showed over a bounded window. A reviewer who thinks we
// are wrong must be able to point at a specific figure and say so.
//
// ⛔ hit_count IS TRI-STATE AND MUST RENDER AS THREE DISTINCT THINGS.
//   a real count  -> the number
//   a measured 0  -> "0 (measured zero)"
//   NULL          -> "Not measured"
// Printing NULL as `0` in a document that proposes deletions would MANUFACTURE
// the exact evidence the deletion rests on — the worst bug available in this
// feature, and the same failed-read-as-a-fact class CLAUDE.md documents for
// firewall_rules.hit_count itself. ruleChangeRequests.js already refuses to put
// an unmeasured rule into a request, but this renderer must never be the thing
// that reintroduces the confusion: it also renders historical rows written
// before any such guard, and rows whose evidence JSON is incomplete.
//
// ⛔ node-pg RETURNS BIGINT AS A STRING. hit_count_at_request arrives as '0',
// not 0, so any truthiness test on it is wrong in both directions: '0' is
// truthy, and a naive `Number(v) || null` turns a MEASURED ZERO into
// "not measured". hitCountDisplay() is the single place that decides.
//
// ⛔ pdfkit ONLY. No puppeteer, no headless browser, no new dependency —
// package.json has no devDependencies and that is deliberate. See
// complianceReport.js's top-of-file note: the puppeteer implementation worked
// in every manual test and failed only when spawned inside the NSSM Windows
// service. The drawCover/drawTable/sectionTitle/stampHeadersFooters helpers
// below are ported from that file rather than imported, because it does not
// export them and it is owned elsewhere; this is the same acknowledged
// duplication convention CLAUDE.md already documents for vendorMeta.js <->
// adapters/index.js. If the palette moves in globals.css, BOTH files need it.
//
// CommonJS — same reason as every other engine: services/engine-worker.js and
// the App Router both load it, and the worker runs under plain node.

'use strict';

const PDFDocument = require('pdfkit');
const { PRODUCT_NAME, PRODUCT_TAGLINE } = require('../branding');
const { getRequest } = require('./ruleChangeRequests');
const {
  getDeviceLogCoverage,
  getLoggedRuleHits,
  enrichRulesWithLogEvidence,
} = require('./ruleHitCorrelation');

// The log window this document quotes. Deliberately a constant and not an env
// var: it is the sentence the reviewer reads ("no traffic in 30 days of
// firewall logs"), and a document whose claim silently changes size between
// two installations is not a document. ruleHitCorrelation.clampDays() floors
// anything below 7 anyway, for its own documented reason.
const EVIDENCE_WINDOW_DAYS = 30;

// ── Palette (mirrors app/globals.css LIGHT tokens by hand — a PDF has no
// var() to resolve). Same values and same reasoning as complianceReport.js:
// ACCENT is teal because red means DANGER and nothing else since v2.87.0.
const ACCENT = '#098294';      // --primary
const NAVY = '#101826';        // --navy
const MUTED = '#69788B';       // --text-muted
const LIGHT = '#F1F4F8';       // --surface-subtle
const BORDER = '#DDE3EB';      // --border
const GREEN = '#17825A';       // --green / --sev-ok
const YELLOW = '#B7791F';      // --yellow / --sev-med
const BLUE = '#2F6FE0';        // --blue
const STATUS_RED = '#D4353B';  // --red / --sev-crit
const INK = '#0D131C';
// ⛔ NO HUE, by design — the printed form of --unmeasured. "We did not measure
// this" must not be drawn in a colour that reads as a value, good or bad.
const UNMEASURED = '#6D7784';

// ── tri-state hit count ───────────────────────────────────────────────────

/**
 * The ONE place that decides how a hit count renders.
 *
 * @param {number|string|null|undefined} raw hit_count_at_request as it comes
 *   out of pg (BIGINT -> string), or a plain number in tests.
 * @returns {{state:'measured'|'measured_zero'|'not_measured', text:string, value:number|null}}
 */
function hitCountDisplay(raw) {
  if (raw === null || raw === undefined || raw === '') {
    return {
      state: 'not_measured',
      text: 'Not measured',
      value: null,
    };
  }
  const n = Number(raw);
  // ⛔ Unparseable is NOT zero. If we cannot read the number back we do not
  // know what it was, and the safe direction is to say so.
  if (!Number.isFinite(n)) {
    return { state: 'not_measured', text: 'Not measured', value: null };
  }
  if (n === 0) {
    // ⛔ Says "measured" out loud. A bare `0` is indistinguishable on the page
    // from the NULL case, and the whole request rests on the difference.
    return { state: 'measured_zero', text: '0 (measured zero)', value: 0 };
  }
  return { state: 'measured', text: String(n), value: n };
}

function hitCountColor(state) {
  if (state === 'not_measured') return UNMEASURED;
  if (state === 'measured_zero') return GREEN;
  return YELLOW; // a rule with real hits, proposed for removal — read it twice
}

// ── log evidence ──────────────────────────────────────────────────────────

/**
 * Turn ruleHitCorrelation's logEvidence code into a sentence a stranger can
 * act on. ⛔ Four of the five codes are NOT MEASUREMENTS — they each say why
 * the logs cannot answer, and none of them may read as "no traffic".
 */
function logEvidenceDisplay(enriched, windowDays) {
  const d = windowDays == null ? EVIDENCE_WINDOW_DAYS : windowDays;
  if (!enriched) {
    return { state: 'not_measured', text: 'Not measured: no log evidence available.' };
  }
  switch (enriched.logEvidence) {
    case 'hits': {
      const last = enriched.loggedLastHit ? ` Last seen ${fmtStamp(enriched.loggedLastHit)}.` : '';
      return {
        state: 'hits',
        text: `${enriched.loggedHits} matching log events in the last ${d} days.${last}`,
      };
    }
    case 'measured-zero': {
      const cov = enriched.logCoverageRatio == null
        ? ''
        : ` Device logged continuously for ${Math.round(enriched.logCoverageRatio * 100)}% of that window.`;
      return {
        state: 'measured_zero',
        text: `No matching traffic in ${d} days of firewall logs.${cov}`,
      };
    }
    case 'rule-logging-disabled':
      return {
        state: 'not_measured',
        text: 'Not measured: logging is switched off on this rule, so it cannot appear in the logs at all. Its absence is not evidence.',
      };
    case 'no-coverage':
      return {
        state: 'not_measured',
        text: `Not measured: this device did not send logs continuously over the ${d}-day window, so silence measures the collector, not the rule.`,
      };
    case 'window-too-short':
      return {
        state: 'not_measured',
        text: 'Not measured: too little log history for this device to draw any conclusion.',
      };
    default:
      return { state: 'not_measured', text: 'Not measured: no log evidence available.' };
  }
}

function logEvidenceColor(state) {
  if (state === 'measured_zero') return GREEN;
  if (state === 'hits') return YELLOW;
  return UNMEASURED;
}

// ── verification ──────────────────────────────────────────────────────────

/**
 * ⛔ `unverifiable` is NOT a failure and NOT "still present". It means no rules
 * collection has SUCCEEDED for this device since the request was submitted, so
 * nothing at all can be concluded. Rendering it as anything else reports our
 * own collection gap as the operator's inaction.
 */
function outcomeDisplay(item) {
  const when = item && item.verified_at ? fmtStamp(item.verified_at) : null;
  switch (item && item.outcome) {
    case 'removed':
      return {
        label: 'Removed',
        color: GREEN,
        text: when
          ? `Confirmed: the rule was absent from the ruleset SecVault collected from the device on ${when}.`
          : 'Confirmed: the rule was absent from the ruleset SecVault most recently collected from the device.',
      };
    case 'still_present':
      return {
        label: 'Still present',
        color: STATUS_RED,
        text: when
          ? `The rule was still in the ruleset SecVault collected from the device on ${when}.`
          : 'The rule was still in the ruleset SecVault most recently collected from the device.',
      };
    case 'unverifiable':
      return {
        label: 'Not yet verifiable',
        color: UNMEASURED,
        text: 'No rule collection has succeeded on this device since the request was submitted. This is NOT a failure and does NOT mean the rule is still there - SecVault simply has nothing newer to compare against.',
      };
    case 'pending':
    default:
      return {
        label: 'Pending',
        color: MUTED,
        text: 'Awaiting the next successful rule collection from this device. SecVault will check automatically.',
      };
  }
}

const STATUS_TEXT = {
  draft: 'Draft - not yet issued.',
  submitted: 'Submitted - handed over, awaiting the change and its verification.',
  verified: 'Verified - every requested rule is confirmed absent from the re-collected ruleset.',
  partial: 'Partially applied - some requested rules are confirmed absent, others are still present.',
  abandoned: 'Abandoned - withdrawn; no change is expected.',
};

const FINDING_TEXT = {
  unused: 'Unused - no recorded traffic has matched this rule.',
  redundant: 'Redundant - another rule already permits or denies exactly this traffic.',
  shadow: 'Shadowed - an earlier rule in the list always matches first, so this one can never take effect.',
};

// ── formatting helpers ────────────────────────────────────────────────────

function fmtStamp(value) {
  if (!value) return '';
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString('en-GB', { hour12: false, timeZone: 'UTC' }) + ' UTC';
}

function evidenceOf(item) {
  const e = item && item.evidence;
  if (!e || typeof e !== 'object' || Array.isArray(e)) return {};
  return e;
}

/**
 * Whether per-rule logging was on, preferring what was captured AT REQUEST TIME.
 *
 * ⛔ Three-way, and the third case is the point. `true`/`false` are answers;
 * `undefined` means we do not know, and `enrichRulesWithLogEvidence` must be
 * allowed to see that rather than being handed a `false` it would read as
 * "logging was off". Requests created before this was snapshotted, and rules
 * already removed from a device whose ruleset no longer lists them, both land
 * here honestly instead of borrowing a neighbouring rule's answer.
 */
function snapshotLogEnabled(evidence, logEnabledBy, ruleIdVendor) {
  if (evidence && evidence.logEnabled !== undefined && evidence.logEnabled !== null) {
    return evidence.logEnabled;
  }
  return logEnabledBy.has(ruleIdVendor) ? logEnabledBy.get(ruleIdVendor) : undefined;
}

/**
 * EVERY reason the rule was flagged, not just the one in the `finding_type`
 * column.
 *
 * ⛔ A rule can be `unused` AND `shadow` AND `redundant` at once — 10 are, on
 * the live fleet — but `rule_change_request_items` stores one row per RULE, so
 * the column can only hold the worst-severity one. `evidence.findings` carries
 * the rest, captured at request time because it CANNOT be re-derived later:
 * `firewall_rules` and `rule_analysis_results` are both rebuilt on every pull.
 * Showing a reviewer one reason where three were found understates the case for
 * removal, which is exactly the defect the engine fixed upstream — this is the
 * last place it could be reintroduced.
 *
 * Falls back to the column for rows written before `findings` existed.
 */
function findingsOf(item, ev) {
  const raw = ev && Array.isArray(ev.findings) ? ev.findings.filter(Boolean) : [];
  const list = raw.length > 0
    ? raw
    : [{ findingType: item.finding_type, severity: ev.severity, detail: ev.detail }];
  return list.map((f) => ({
    type: f.findingType || item.finding_type,
    severity: f.severity || null,
    detail: f.detail || null,
    text: FINDING_TEXT[f.findingType || item.finding_type] || (f.findingType || item.finding_type),
  }));
}

/** One line per finding: the reason, then the analyser's own words. */
function findingLines(findings) {
  return findings.map((f) => (f.detail ? `${f.text} ${f.detail}` : f.text));
}

// ── data assembly ─────────────────────────────────────────────────────────

/**
 * Everything both renderers need, fetched once.
 *
 * Not best-effort per query, deliberately (same call as complianceReport.js): a
 * change request with silently-missing evidence is worse than a failed export
 * the operator can see and retry.
 *
 * @param {import('pg').Pool} pool
 * @param {string} requestId
 * @returns {Promise<object|null>} null when the request does not exist.
 */
async function buildRequestReportData(pool, requestId, opts = {}) {
  const now = opts.now instanceof Date ? opts.now : new Date();
  const windowDays = opts.windowDays == null ? EVIDENCE_WINDOW_DAYS : opts.windowDays;

  const request = await getRequest(pool, requestId);
  if (!request) return null;

  const { rows: devRows } = await pool.query(
    `SELECT name, vendor, mgmt_ip, site, mgmt_method, last_rules_collected_at
       FROM devices
      WHERE id = $1::uuid`,
    [request.device_id]
  );
  const device = devRows[0] || null;

  // Current per-rule logging state, so logEvidenceDisplay can tell "the rule
  // cannot appear in a log" apart from "the rule did not appear in the log".
  // ⛔ A rule that has already been REMOVED has no row here, and that is
  // correct: log_enabled comes back undefined and the evidence falls through
  // to the coverage tests rather than claiming a setting we cannot see.
  const { rows: liveRules } = await pool.query(
    `SELECT rule_id_vendor, log_enabled
       FROM firewall_rules
      WHERE device_id = $1::uuid`,
    [request.device_id]
  );
  const logEnabledBy = new Map(liveRules.map((r) => [r.rule_id_vendor, r.log_enabled]));

  const coverageMap = await getDeviceLogCoverage(pool, windowDays, now);
  const hitMaps = await getLoggedRuleHits(pool, request.device_id, windowDays, now);

  const pseudoRules = (request.items || []).map((it) => ({
    rule_id_vendor: it.rule_id_vendor,
    rule_name: it.rule_name,
    // ⛔ The SNAPSHOT, not today's count. schema.sql: the evidence is captured
    // at request time and must not be silently re-derived later.
    hit_count: hitCountDisplay(it.hit_count_at_request).value,
    // ⛔ The SNAPSHOT first, the live row only as a fallback. Once a rule has
    // actually been REMOVED there is no firewall_rules row left to read
    // log_enabled from — so reading it live would make the caveat "this rule
    // could not appear in a log, because logging was switched off on it"
    // silently vanish for exactly the rules a completed request is reporting
    // on, and the absence of log hits would then read as evidence of no
    // traffic. A caveat that disappears makes the evidence look STRONGER than
    // it was, which is the wrong direction for a document justifying a
    // deletion. createRequest captures it for this reason.
    log_enabled: snapshotLogEnabled(evidenceOf(it), logEnabledBy, it.rule_id_vendor),
  }));
  const enriched = enrichRulesWithLogEvidence(
    pseudoRules,
    coverageMap.get(request.device_id) || null,
    hitMaps
  );

  const items = (request.items || []).map((it, i) => {
    const ev = evidenceOf(it);
    const hit = hitCountDisplay(it.hit_count_at_request);
    const log = logEvidenceDisplay(enriched[i], windowDays);
    const outcome = outcomeDisplay(it);
    const findings = findingsOf(it, ev);
    return {
      ruleIdVendor: it.rule_id_vendor,
      ruleName: it.rule_name || '(unnamed)',
      // The single worst-severity type, as stored in the column — kept for
      // sorting/filtering, never as the whole answer.
      findingType: it.finding_type,
      findings,
      findingTypes: findings.map((f) => f.type),
      findingText: findingLines(findings).join(' '),
      severity: ev.severity || null,
      detail: ev.detail || null,
      enabledAtRequest: ev.enabled === undefined ? null : ev.enabled,
      hit,
      log,
      outcome: it.outcome || 'pending',
      outcomeLabel: outcome.label,
      outcomeColor: outcome.color,
      outcomeText: outcome.text,
      verifiedAt: it.verified_at || null,
    };
  });

  const counts = {
    total: items.length,
    removed: items.filter((i) => i.outcome === 'removed').length,
    stillPresent: items.filter((i) => i.outcome === 'still_present').length,
    unverifiable: items.filter((i) => i.outcome === 'unverifiable').length,
    pending: items.filter((i) => i.outcome === 'pending').length,
    // ⛔ Reported separately so a reader can see at a glance whether any row in
    // a DELETION proposal rests on an unmeasured number. Should always be 0 —
    // the engine refuses such rules — and if it ever is not, the document says
    // so rather than hiding it.
    unmeasured: items.filter((i) => i.hit.state === 'not_measured').length,
  };

  return { request, device, items, counts, windowDays, generatedAt: now };
}

// ── CSV ───────────────────────────────────────────────────────────────────

const CSV_COLUMNS = [
  ['request_id', (d, i) => d.request.id],
  ['request_title', (d) => d.request.title],
  ['request_status', (d) => d.request.status],
  // ⛔ Separate from `note`. The note is the INSTRUCTION written for whoever
  // edits the firewall; the abandon reason is why it was withdrawn. Collapsing
  // them destroys the record of what was actually asked for.
  ['request_note', (d) => d.request.note || ''],
  ['request_abandon_reason', (d) => d.request.abandon_reason || ''],
  ['device_name', (d) => (d.device ? d.device.name : '')],
  ['device_vendor', (d) => (d.device ? d.device.vendor : '')],
  ['device_mgmt_ip', (d) => (d.device ? d.device.mgmt_ip : '')],
  ['raised_by', (d) => d.request.created_by || 'unknown'],
  ['raised_at', (d) => fmtStamp(d.request.created_at)],
  ['submitted_at', (d) => fmtStamp(d.request.submitted_at)],
  ['rule_id_vendor', (d, i) => i.ruleIdVendor],
  ['rule_name', (d, i) => i.ruleName],
  // ⛔ EVERY finding, not just the column's worst-severity one — see
  // findingsOf(). `flagged_as_primary` keeps the single value for sorting.
  ['flagged_as', (d, i) => i.findingTypes.join('; ')],
  ['flagged_as_primary', (d, i) => i.findingType],
  ['finding_count', (d, i) => i.findings.length],
  ['why_flagged', (d, i) => findingLines(i.findings).join(' | ')],
  ['analyser_detail', (d, i) => i.findings.map((f) => f.detail).filter(Boolean).join(' | ')],
  ['severity', (d, i) => i.severity || ''],
  // ⛔ TWO columns, not one. The text is for a human ("Not measured"); the
  // state is for a filter, so nobody has to regex a sentence to find the rows
  // whose evidence is absent. Neither is ever a bare 0 standing in for NULL.
  ['hit_count_at_request', (d, i) => i.hit.text],
  ['hit_count_state', (d, i) => i.hit.state],
  ['log_evidence', (d, i) => i.log.text],
  ['log_evidence_state', (d, i) => i.log.state],
  ['evidence_window_days', (d) => d.windowDays],
  ['verification_outcome', (d, i) => i.outcomeLabel],
  ['verification_detail', (d, i) => i.outcomeText],
  ['verified_at', (d, i) => fmtStamp(i.verifiedAt)],
];

/**
 * ⛔ Quotes EVERY field, escapes embedded quotes, and neutralises formula
 * injection. A rule name is attacker-influenced free text that arrives from a
 * firewall config; a cell beginning `=`, `+`, `-`, `@` (or a tab/CR, which
 * Excel strips before re-reading the leading character) is executed as a
 * formula on open in Excel, LibreOffice and Sheets. Prefixing an apostrophe is
 * the standard neutralisation and is visible in the cell, which is the honest
 * trade: a slightly odd-looking name beats a document that runs code.
 *
 * Newlines are folded to a space rather than quoted through: RFC 4180 allows
 * them, but the leading-character check above is defeated by a value that
 * starts with a newline, and a multi-line cell in a change-board spreadsheet
 * helps nobody.
 */
function csvEscape(value) {
  let s = value === null || value === undefined ? '' : String(value);
  s = s.replace(/[\r\n\t]+/g, ' ');
  if (/^[=+\-@]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

function csvRow(values) {
  return values.map(csvEscape).join(',');
}

/** Pure: report data -> CSV string. */
function renderRequestCsv(data) {
  const lines = [csvRow(CSV_COLUMNS.map((c) => c[0]))];
  for (const item of data.items) {
    lines.push(csvRow(CSV_COLUMNS.map((c) => c[1](data, item))));
  }
  // A request with no items still produces a header row, never an empty file:
  // "the export is broken" and "the request is empty" must look different.
  return lines.join('\r\n') + '\r\n';
}

/**
 * @param {import('pg').Pool} pool
 * @param {string} requestId
 * @returns {Promise<string>}
 */
async function generateRequestCsv(pool, requestId, opts = {}) {
  const data = await buildRequestReportData(pool, requestId, opts);
  if (!data) return null;
  return renderRequestCsv(data);
}

// ── PDF (ported helpers — see the top-of-file note) ───────────────────────

// pdfkit's built-in Helvetica is WinAnsi and has no glyph for the characters
// this file would otherwise pick up from a vendor rule name or an analyser
// detail string. Sanitize to ASCII once, from one place, by wrapping doc.text.
function pdfSafe(s) {
  if (s == null) return '';
  return String(s)
    .replace(/[–—―]/g, '-')
    .replace(/•/g, '-')
    .replace(/[‘’‚‛]/g, "'")
    .replace(/[“”„‟]/g, '"')
    .replace(/ /g, ' ');
}

function installPdfSafeText(doc) {
  const origText = doc.text.bind(doc);
  doc.text = (text, ...rest) => origText(pdfSafe(text), ...rest);
  return doc;
}

function drawCover(doc, o, layout) {
  const { title, subtitle, company, generatedAt, meta, summary } = o;
  const { pageW, left, contentW } = layout;

  doc.rect(0, 0, pageW, 150).fill(NAVY);
  doc.rect(0, 150, pageW, 6).fill(ACCENT);
  doc.roundedRect(left, 44, 64, 64, 10).fill(ACCENT);
  doc.fillColor('#fff').fontSize(30).font('Helvetica-Bold').text('S', left, 60, { width: 64, align: 'center' });
  doc.fillColor('#fff').fontSize(22).font('Helvetica-Bold').text(PRODUCT_NAME, left + 80, 56);
  doc.fillColor('#B9C6D6').fontSize(11).font('Helvetica').text(PRODUCT_TAGLINE, left + 80, 86);

  doc.fillColor(NAVY).fontSize(26).font('Helvetica-Bold').text(title, left, 190, { width: contentW });
  if (subtitle) {
    doc.fillColor(MUTED).fontSize(12).font('Helvetica').text(subtitle, left, doc.y + 2, { width: contentW });
  }
  const ruleY = doc.y + 10;
  doc.moveTo(left, ruleY).lineTo(left + 120, ruleY).lineWidth(3).stroke(ACCENT);

  let my = ruleY + 20;
  doc.fontSize(10);
  (meta || []).forEach(([k, v]) => {
    doc.fillColor(MUTED).font('Helvetica-Bold').text(k, left, my, { width: 130 });
    doc.fillColor(INK).font('Helvetica').text(v == null || v === '' ? '-' : String(v), left + 140, my, { width: contentW - 140 });
    my += 19;
  });

  if (summary && summary.length) {
    my += 12;
    doc.fillColor(NAVY).fontSize(13).font('Helvetica-Bold').text('Summary', left, my);
    my += 22;
    let cx = left;
    const chipW = Math.min(170, (contentW - 30) / Math.max(summary.length, 1));
    summary.forEach((s) => {
      doc.roundedRect(cx, my, chipW - 10, 52, 8).fillAndStroke(LIGHT, BORDER);
      doc.fillColor(s.color || NAVY).fontSize(18).font('Helvetica-Bold').text(String(s.value), cx + 10, my + 8, { width: chipW - 26 });
      doc.fillColor(MUTED).fontSize(8).font('Helvetica').text(s.label, cx + 10, my + 32, { width: chipW - 26 });
      cx += chipW;
    });
    my += 66;
  }

  doc.y = my;
  doc.fillColor(company === undefined ? MUTED : MUTED).fontSize(9).font('Helvetica')
    .text(`Generated ${generatedAt}`, left, doc.y, { width: contentW });
}

// ⛔ Break to a new page if `needed` px would not fit. Every block below asks
// for the height it MEASURED, never a guessed constant: pdfkit draws at the y
// it is handed, and a block started too near the bottom either vanishes off the
// page or gets auto-flowed a fragment at a time. Both were observed here — a
// table header started 20px above the bottom margin produced FIVE pages each
// carrying a single column heading, with the rows on a sixth.
function ensureSpace(doc, layout, needed) {
  if (doc.y + needed > layout.pageH - doc.page.margins.bottom) doc.addPage();
}

function sectionTitle(doc, layout, text) {
  const { left, contentW } = layout;
  ensureSpace(doc, layout, 46);
  doc.fillColor(NAVY).fontSize(12).font('Helvetica-Bold').text(text, left, doc.y, { width: contentW });
  doc.y += 8;
}

function paragraph(doc, layout, text, color = MUTED, size = 9) {
  const { left, contentW } = layout;
  const h = doc.fontSize(size).font('Helvetica').heightOfString(pdfSafe(text), { width: contentW });
  ensureSpace(doc, layout, h + 6);
  doc.fillColor(color).fontSize(size).font('Helvetica').text(text, left, doc.y, { width: contentW });
  doc.y += 6;
}

// A bold label with its explanatory paragraph, kept together on one page.
function labelledNote(doc, layout, label, color, text) {
  const { left, contentW } = layout;
  const lh = doc.fontSize(9).font('Helvetica-Bold').heightOfString(pdfSafe(label), { width: contentW });
  const th = doc.fontSize(9).font('Helvetica').heightOfString(pdfSafe(text), { width: contentW - 12 });
  ensureSpace(doc, layout, lh + th + 8);
  doc.fillColor(color).fontSize(9).font('Helvetica-Bold').text(label, left, doc.y, { width: contentW });
  doc.fillColor(MUTED).fontSize(9).font('Helvetica').text(text, left + 12, doc.y, { width: contentW - 12 });
  doc.y += 6;
}

// Generic wrapped-height zebra table, same structure as complianceReport.js's:
// measures every cell's wrapped height so a row fits its tallest cell, and
// redraws the header after a page break.
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
      .text('No rules in this request.', left, doc.y + 14, { width: contentW, align: 'center' });
  }
}

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

// ── PDF body ──────────────────────────────────────────────────────────────

function buildProposedTable(items) {
  return {
    columns: [
      { key: 'ruleId', label: 'Rule ID (on the firewall)', width: 78 },
      { key: 'ruleName', label: 'Rule name', width: 88 },
      { key: 'flagged', label: 'Flagged as', width: 52 },
      { key: 'why', label: 'Why SecVault flagged it', width: 132 },
      { key: 'hits', label: 'Device hit counter at request', width: 66, color: (r) => r._hitColor, font: 'Helvetica-Bold' },
      { key: 'logs', label: 'Firewall log evidence', width: 132, color: (r) => r._logColor },
    ],
    rows: items.map((i) => ({
      ruleId: i.ruleIdVendor,
      ruleName: i.ruleName,
      // ⛔ Every reason, one per line. A rule flagged three ways has three
      // times the case for removal, and the reviewer must see all three.
      flagged: i.findingTypes.join('\n'),
      why: findingLines(i.findings).join('\n'),
      hits: i.hit.text,
      logs: i.log.text,
      _hitColor: hitCountColor(i.hit.state),
      _logColor: logEvidenceColor(i.log.state),
    })),
  };
}

function buildVerificationTable(items) {
  return {
    columns: [
      { key: 'ruleId', label: 'Rule ID', width: 78 },
      { key: 'ruleName', label: 'Rule name', width: 88 },
      { key: 'outcome', label: 'Outcome', width: 62, color: (r) => r._color, font: 'Helvetica-Bold' },
      { key: 'checked', label: 'Checked at', width: 88 },
      { key: 'meaning', label: 'What that means', width: 232 },
    ],
    rows: items.map((i) => ({
      ruleId: i.ruleIdVendor,
      ruleName: i.ruleName,
      outcome: i.outcomeLabel,
      checked: i.verifiedAt ? fmtStamp(i.verifiedAt) : '-',
      meaning: i.outcomeText,
      _color: i.outcomeColor,
    })),
  };
}

// ⛔ THE LEGEND IS NOT DECORATION. This document is read by someone with no
// SecVault account, and every number on it is tri-state. Without this block a
// reader has no way to tell a measured zero from an unmeasured blank, which is
// precisely the confusion the whole feature exists to remove.
function renderLegend(doc, layout, windowDays) {
  sectionTitle(doc, layout, 'How to read this document');
  paragraph(
    doc,
    layout,
    'SecVault does not ask for a rule to be deleted on its own authority. Each rule below carries the two independent measurements the proposal rests on, so you can disagree with a specific number rather than with the tool.',
    INK
  );
  doc.y += 4;

  const bullets = [
    ['Device hit counter at request', INK,
      'The counter the firewall itself reported for that rule at the moment this request was raised. It is deliberately frozen at that moment: a later collection may show something different, and the request must still show what it was justified by.'],
    ['   "0 (measured zero)"', GREEN,
      'The device was asked and answered zero. This is real evidence.'],
    ['   A number', YELLOW,
      'The device reported traffic against this rule. A rule with hits can still be redundant or shadowed by an earlier rule, but read that row twice before acting on it.'],
    ['   "Not measured"', UNMEASURED,
      'SecVault could NOT read a hit counter for this rule - some vendors and transports cannot report one at all. It does NOT mean zero. A rule in this state is not evidence of anything and SecVault will not knowingly propose one for deletion.'],
    [`Firewall log evidence (last ${windowDays} days)`, INK,
      'An independent check against the raw firewall logs SecVault collects. "No matching traffic" counts only when the device was actually logging throughout the window and logging is enabled on the rule; otherwise the row says why the logs cannot answer, and silence there measures the log collector, not the rule.'],
  ];
  bullets.forEach(([label, color, text]) => labelledNote(doc, layout, label, color, text));
}

function renderVerificationLegend(doc, layout) {
  paragraph(
    doc,
    layout,
    'After the change is made, SecVault checks it automatically against the ruleset it re-collects from the device. Nobody ticks a box: a rule counts as removed because the device no longer reports it.',
    INK
  );
  const bullets = [
    ['Removed', GREEN, 'A rule collection succeeded after this request was submitted and the rule was not in it.'],
    ['Still present', STATUS_RED, 'A rule collection succeeded after this request was submitted and the rule was still in it.'],
    ['Not yet verifiable', UNMEASURED, 'No rule collection has succeeded on this device since submission. This is NOT a failure and NOT the same as "still present" - SecVault has nothing newer to compare against, so it will not claim either way.'],
    ['Pending', MUTED, 'Not checked yet; the next successful collection will decide.'],
  ];
  bullets.forEach(([label, color, text]) => labelledNote(doc, layout, label, color, text));
}

function renderRequestBody(doc, data, layout) {
  const { request, items, counts, windowDays } = data;

  doc.addPage();
  renderLegend(doc, layout, windowDays);

  if (request.note) {
    doc.y += 6;
    sectionTitle(doc, layout, 'Note from the requester');
    paragraph(doc, layout, request.note, INK);
  }

  // ⛔ Shown ALONGSIDE the note, never instead of it. The note is what was
  // asked for; this is why it was withdrawn. An abandoned request whose
  // instruction has been overwritten is a record of nothing.
  if (request.abandon_reason) {
    doc.y += 6;
    sectionTitle(doc, layout, 'Why this request was withdrawn');
    paragraph(doc, layout, request.abandon_reason, INK);
  }

  doc.y += 6;
  sectionTitle(doc, layout, `Rules proposed for removal (${counts.total})`);
  if (counts.unmeasured > 0) {
    // Should never happen — ruleChangeRequests.js refuses unmeasured rules —
    // but if a historical row slipped through, the document says so loudly
    // instead of letting a grey "Not measured" pass for supporting evidence.
    paragraph(
      doc,
      layout,
      `WARNING: ${counts.unmeasured} of these rules carry NO measured hit count. There is no usage evidence for them and they should not be removed on the strength of this document.`,
      STATUS_RED
    );
  }
  drawTable(doc, buildProposedTable(items), layout, { continueOnPage: true });

  doc.y += 10;
  sectionTitle(doc, layout, 'Verification');
  renderVerificationLegend(doc, layout);
  drawTable(doc, buildVerificationTable(items), layout, { continueOnPage: true });
}

/** Pure-ish: report data -> PDF Buffer. No DB, no network, no browser. */
function renderRequestPdf(data) {
  const doc = installPdfSafeText(
    new PDFDocument({ size: 'A4', layout: 'portrait', margin: 36, bufferPages: true })
  );
  const layout = {
    pageW: doc.page.width,
    pageH: doc.page.height,
    left: doc.page.margins.left,
    right: doc.page.width - doc.page.margins.right,
    contentW: doc.page.width - doc.page.margins.left - doc.page.margins.right,
  };
  const generatedAt = fmtStamp(data.generatedAt || new Date());
  const { request, device, counts } = data;
  const deviceName = device ? device.name : '(device no longer in inventory)';
  const title = 'Firewall Rule Change Request';

  drawCover(
    doc,
    {
      title,
      subtitle: request.title || 'Rule cleanup',
      company: PRODUCT_NAME,
      generatedAt,
      meta: [
        ['Firewall', device ? `${deviceName} (${device.vendor}${device.mgmt_ip ? ` - ${device.mgmt_ip}` : ''})` : deviceName],
        ['Site', device ? device.site : null],
        ['Raised by', request.created_by || 'unknown'],
        ['Raised at', fmtStamp(request.created_at)],
        ['Submitted at', request.submitted_at ? fmtStamp(request.submitted_at) : 'Not yet submitted'],
        ['Status', `${request.status} - ${STATUS_TEXT[request.status] || ''}`],
        // A partial is the outcome that most needs dating: it is the one that
        // still requires a follow-up.
        request.verified_at ? ['Verified at', fmtStamp(request.verified_at)] : null,
        request.abandon_reason ? ['Withdrawn because', request.abandon_reason] : null,
        ['Last rule collection', device && device.last_rules_collected_at ? fmtStamp(device.last_rules_collected_at) : 'None recorded'],
        ['Request reference', request.id],
      ].filter(Boolean),
      summary: [
        { label: 'Rules requested', value: counts.total, color: NAVY },
        { label: 'Confirmed removed', value: counts.removed, color: counts.removed > 0 ? GREEN : MUTED },
        { label: 'Still present', value: counts.stillPresent, color: counts.stillPresent > 0 ? STATUS_RED : MUTED },
        { label: 'Not yet verifiable', value: counts.unverifiable + counts.pending, color: UNMEASURED },
      ],
    },
    layout
  );

  renderRequestBody(doc, data, layout);
  stampHeadersFooters(doc, {
    title: `${PRODUCT_NAME} ${title}`,
    company: deviceName,
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
 * @param {string} requestId
 * @returns {Promise<Buffer|null>} null when the request does not exist.
 */
async function generateRequestPdf(pool, requestId, opts = {}) {
  const data = await buildRequestReportData(pool, requestId, opts);
  if (!data) return null;
  return renderRequestPdf(data);
}

module.exports = {
  snapshotLogEnabled,
  EVIDENCE_WINDOW_DAYS,
  hitCountDisplay,
  hitCountColor,
  logEvidenceDisplay,
  outcomeDisplay,
  csvEscape,
  buildRequestReportData,
  renderRequestCsv,
  renderRequestPdf,
  generateRequestCsv,
  generateRequestPdf,
  CSV_COLUMNS,
};
