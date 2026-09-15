// lib/reports/ruleHygiene.js
//
// R3 — "Rule Hygiene & Policy Audit". Per-device or fleet-wide.
//
// It answers one question: WHICH RULES ARE UNUSED, SHADOWED, REDUNDANT OR
// OVER-PERMISSIVE — AND HOW SURE ARE WE?
//
// ⛔ THE SECOND HALF OF THAT QUESTION IS THE ENTIRE POINT OF THE DOCUMENT.
//
// ManageEngine Firewall Analyzer derives "unused rule" the same way SecVault
// does: configuration intersected with syslog. What it does not publish is any
// equivalent of `firewall_rules.hit_count`'s THIRD state. On its report a
// firewall whose logs never arrived is indistinguishable from a firewall whose
// rules are genuinely idle — both render as a confident list of deletion
// candidates, and the reader has no way to tell which one they are holding.
//
// `hit_count` is TRI-STATE here:
//     a real count  -> the device was asked and reported traffic
//     0             -> the device was asked and reported none. Real evidence.
//     NULL          -> NOT MEASURED. Some vendors and transports cannot report
//                      a hit counter at all (live today: every Fortinet-SSH and
//                      Palo-Alto-SSH device on the reference fleet, 233 of
//                      1,757 rules). This is a gap in what SecVault can read,
//                      not a statement about the rule.
//
// So this report:
//   1. states on its COVER how many rules have no usage data at all;
//   2. keeps those rules in their OWN counted section, drawn without hue, never
//      mixed into the findings list;
//   3. never prints `0` where the truth is "not measured" — an unknown count is
//      a dash, and the dash is explained in the legend;
//   4. says out loud that an `unused` finding required a MEASURED zero before
//      it was written, because that is the sentence that makes the deletion
//      list trustworthy rather than merely confident.
//
// Printing a not-measured rule as a zero would MANUFACTURE the exact evidence a
// deletion rests on. That is the failed-read-as-a-fact bug this codebase keeps
// finding, and a PDF handed to a change board is the worst place for it: the
// document outlives the session, and nobody who reads it can see the NULL.
//
// ⛔ A SKIPPED ANALYSIS IS NOT A CLEAN RESULT. ruleAnalysis.js skips its five
// O(n^2) pairwise passes entirely above 1,000 rules. Zero shadow findings for
// such a device means NOT MEASURED, not "no shadowing". The per-firewall table
// carries that caveat beside the counts rather than under them, because a
// footnote nobody reads is the same as no footnote.
//
// ⛔ VOCABULARY IS BORROWED, NOT REINVENTED. hitCountDisplay / hitCountColor /
// logEvidenceDisplay come from ruleChangeRequestReport.js. Two reports about
// the same three states, each with its own words for them, would teach the
// operator that the states are different. They are not, and the two documents
// are read side by side during a cleanup.
//
// CommonJS — same reason as every engine: the App Router and plain-node callers
// both load it.

'use strict';

const PDFDocument = require('pdfkit');

const {
  NAVY, MUTED, GREEN, INK,
  // ⛔ The status ramp comes from the chassis, not from a local copy. A finding
  // that is amber on screen and red in the PDF an auditor is holding is two
  // different claims about the same fact — and identical hex literals pasted
  // into a fourth report file would be a fourth chance to fix one and miss three.
  STATUS_RED, ORANGE, YELLOW, UNMEASURED,
  fmtStamp, installPdfSafeText,
  layoutOf,
  drawCover, sectionTitle, paragraph, labelledNote, drawTable, stampHeadersFooters,
} = require('./chassis');

const { PRODUCT_NAME } = require('../branding');

// ⛔ Imported, not re-implemented. These decide how the three usage states
// READ, and the change-request report already made that decision.
const {
  EVIDENCE_WINDOW_DAYS,
  hitCountDisplay,
  hitCountColor,
  logEvidenceDisplay,
} = require('../engines/ruleChangeRequestReport');

const {
  getDeviceLogCoverage,
  getLoggedRuleHits,
  enrichRulesWithLogEvidence,
} = require('../engines/ruleHitCorrelation');

// ⛔ The cap and the list of passes it disables are imported from the ENGINE
// that applies them. A local copy of "1000" here would be a second source of
// truth for a boundary condition, and the day someone tuned the engine this
// report would start quietly claiming passes had run that had not.
const {
  PAIRWISE_FINDING_TYPES,
  skippedPairwiseFindingTypes,
  DEFAULT_OPTIONS: ANALYSIS_DEFAULTS,
} = require('../engines/ruleAnalysis');

// ── palette ───────────────────────────────────────────────────────────────
// STATUS_RED / YELLOW / UNMEASURED are imported from the chassis above.
//
// The full severity ramp, including ORANGE for `high`, now comes from the
// chassis — see its Status ramp block for why a printed ramp that disagrees
// with the on-screen one is two claims about the same finding.

// ⛔ The printed form of an UNKNOWN count. Note chassis.pdfSafe() folds this to
// an ASCII hyphen (Helvetica is WinAnsi), which is fine and is the point: what
// must never appear in the cell is a `0`. A dash reads as "no value"; a zero
// reads as a measurement, and on this report that difference is the product.
const NOT_MEASURED_MARK = '—';

// ── finding vocabulary ────────────────────────────────────────────────────

/**
 * ⛔ Every finding_type ruleAnalysis.js can emit, in one place. A type missing
 * from here does not vanish — the tables fall back to the raw slug — but an
 * unexplained slug in a document read by a change board is a row nobody can
 * act on, so add the sentence when a type is added to the engine.
 *
 * The first three are worded IDENTICALLY to ruleChangeRequestReport.js's
 * FINDING_TEXT, which is not exported. Copied deliberately: the two documents
 * are read together and must not describe the same finding in two voices.
 */
const FINDING_TEXT = Object.freeze({
  unused: 'Unused - no recorded traffic has matched this rule.',
  redundant: 'Redundant - another rule already permits or denies exactly this traffic.',
  shadow: 'Shadowed - an earlier rule in the list always matches first, so this one can never take effect.',
  correlation: 'Conflicting - an earlier rule with the opposite action overlaps this one, so part of this rule never takes effect.',
  generalization: 'Generalised by a later rule - a broader rule further down has the same action and already covers this traffic.',
  any_any: 'Any-to-any - this rule allows any source to any destination on any service.',
  risky_service: 'High-risk service - this rule permits a service with known exposure (cleartext credentials, a legacy protocol, or a commonly exploited port).',
  reorder_candidate: 'Reorder candidate - a busy rule sits below rules that never match, so every packet is evaluated against them first.',
  expiring_soon: 'Expiring soon - this rule carries an expiry date that is close.',
  log_disabled: 'Logging disabled - this rule passes traffic that will never appear in any log, so its usage can never be measured.',
  overly_permissive: 'Overly permissive - an address or service field on this rule is unrestricted.',
  external_exposure: 'External exposure - this rule permits traffic inbound from an untrusted zone.',
});

/** Short column label; the full sentence goes in the "what it means" column. */
const FINDING_LABEL = Object.freeze({
  unused: 'Unused',
  redundant: 'Redundant',
  shadow: 'Shadowed',
  correlation: 'Conflicting',
  generalization: 'Generalised',
  any_any: 'Any-to-any',
  risky_service: 'Risky service',
  reorder_candidate: 'Reorder candidate',
  expiring_soon: 'Expiring soon',
  log_disabled: 'Logging disabled',
  overly_permissive: 'Overly permissive',
  external_exposure: 'External exposure',
});

const SEVERITY_ORDER = Object.freeze(['critical', 'high', 'medium', 'info']);

function severityColor(sev) {
  switch (sev) {
    case 'critical': return STATUS_RED;
    case 'high': return ORANGE;
    case 'medium': return YELLOW;
    default: return MUTED;
  }
}

function severityRank(sev) {
  const i = SEVERITY_ORDER.indexOf(sev);
  return i < 0 ? SEVERITY_ORDER.length : i;
}

/**
 * ⛔ Mirrors ruleChangeRequestReport.js's logEvidenceColor(), which that file
 * defines but does NOT put on its export list. Reproduced here rather than
 * left to drift: the two documents must not disagree about which of these
 * states counts as evidence. If it is ever exported, delete this and import it.
 */
function logStateColor(state) {
  if (state === 'measured_zero') return GREEN;
  if (state === 'hits') return YELLOW;
  return UNMEASURED;
}

// ── small formatters ──────────────────────────────────────────────────────

function num(n) {
  return Number(n || 0).toLocaleString('en-GB');
}

/**
 * A count cell.
 *
 * ⛔ `known === false` means the number is not zero, it is UNKNOWN. A firewall
 * whose ruleset was never collected has not got zero rules, it has an
 * unanswered question, and the two must not share a glyph — that substitution
 * is the whole failed-read-as-a-fact class, expressed in a table cell.
 */
function countCell(value, known) {
  return known === false ? NOT_MEASURED_MARK : num(value);
}

function pct(part, whole) {
  if (!whole) return null;
  return Math.round((Number(part) / Number(whole)) * 100);
}

/**
 * Clamp a caller-supplied table cap. ⛔ Never 0: a cap of 0 would silently
 * empty a section, which on the page is indistinguishable from "nothing was
 * found" — the exact confusion this report exists to remove.
 */
function clampCap(v, def) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(Math.trunc(n), 1);
}

/**
 * The answer-first sentence at the top of the document.
 *
 * ⛔ AN ALL-CLEAR IS FORBIDDEN WHILE COVERAGE IS INCOMPLETE. Zero findings over
 * a fleet with unmeasured rules, uncollected rulesets or skipped pairwise
 * passes is not a clean bill of health, and a sentence that says "no issues"
 * there is the failed-read-as-a-fact bug written in English. The only path to
 * an unqualified sentence is every gap being genuinely zero.
 *
 * Pure — takes totals, returns a string.
 */
function headlineSentence(totals) {
  const firewalls = `${num(totals.devices)} firewall${totals.devices === 1 ? '' : 's'}`;
  const gaps = [];
  if (totals.rulesNotMeasured > 0) {
    const p = pct(totals.rulesNotMeasured, totals.rules);
    gaps.push(
      `${num(totals.rulesNotMeasured)} of those rules${p == null ? '' : ` (${p}%)`} have NO usage data`
      + ' - the firewall cannot report a hit counter for them, so no unused-rule verdict is offered'
      + ' for any of them'
    );
  }
  if (totals.devicesNoRuleset > 0) {
    gaps.push(
      `${num(totals.devicesNoRuleset)} firewall${totals.devicesNoRuleset === 1 ? ' has' : 's have'}`
      + ' no ruleset collected at all, so nothing on them was analysed'
    );
  }
  if (totals.devicesPairwiseSkipped > 0) {
    gaps.push(
      `${num(totals.devicesPairwiseSkipped)} firewall${totals.devicesPairwiseSkipped === 1 ? '' : 's'}`
      + ' exceeded the ruleset size at which the rule-versus-rule comparisons run, so those checks'
      + ' did not run there'
    );
  }

  const head = totals.findings === 0
    // ⛔ Not "no issues found". The gaps clause decides whether this can be read
    // as good news, and with any gap present it cannot.
    ? `Across ${firewalls} SecVault examined ${num(totals.rules)} rules and has no open hygiene findings to report.`
    : `Across ${firewalls} SecVault examined ${num(totals.rules)} rules and is reporting `
      + `${num(totals.findings)} open hygiene finding${totals.findings === 1 ? '' : 's'}`
      + `${totals.findingsCritHigh > 0 ? `, ${num(totals.findingsCritHigh)} of them critical or high` : ''}.`;

  if (gaps.length === 0) {
    return totals.findings === 0
      ? `${head} Every rule on every firewall in scope carried a usage measurement, and every`
        + ' analysis pass ran to completion.'
      : head;
  }
  return `${head} This is not a complete picture: ${gaps.join('; ')}.`;
}

// ── data assembly ─────────────────────────────────────────────────────────

const DEFAULT_MAX_FINDING_ROWS = 250;
const DEFAULT_MAX_UNMEASURED_ROWS = 150;

const ACKNOWLEDGED_STATUSES = Object.freeze(['acknowledged', 'dismissed', 'actioned']);

/**
 * Fetch everything both the cover and the body need.
 *
 * ⛔ THE CORE READS ARE NOT BEST-EFFORT. Devices, rules and findings either
 * arrive or the export fails: a hygiene report with silently-missing findings
 * is worse than an error the operator can see and retry, because an empty
 * findings table reads as "nothing wrong here". Same call as
 * complianceReport.js and ruleChangeRequestReport.js make.
 *
 * ⛔ THE LOG-EVIDENCE STAGE *IS* BEST-EFFORT, and its failure is RECORDED
 * rather than swallowed. syslog is a separate service on a separate schedule;
 * if it cannot be read, the unmeasurable section must say "we could not check
 * the logs", never "the logs answered none of them". Those are opposite claims.
 *
 * @param {import('pg').Pool} pool
 * @param {object} [options]
 * @param {string} [options.deviceId]  omit for a fleet-wide report
 * @param {Date}   [options.now]
 * @param {number} [options.windowDays]
 * @param {number} [options.maxFindingRows]
 * @param {number} [options.maxUnmeasuredRows]
 * @returns {Promise<object|null>} null only when a named device does not exist.
 */
async function buildRuleHygieneData(pool, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date();
  const windowDays = options.windowDays == null ? EVIDENCE_WINDOW_DAYS : options.windowDays;
  const maxFindingRows = clampCap(options.maxFindingRows, DEFAULT_MAX_FINDING_ROWS);
  const maxUnmeasuredRows = clampCap(options.maxUnmeasuredRows, DEFAULT_MAX_UNMEASURED_ROWS);
  const deviceId = options.deviceId || null;

  // ⛔ A gathering failure is a first-class row in the document, not a log line.
  // A section that quietly disappears is read as a section with nothing in it,
  // so "we could not look" would be presented as "there was nothing to find".
  const sectionErrors = [];

  // ⛔ A device-scoped report deliberately does NOT filter on `active`. An
  // operator auditing a firewall they have just deactivated still needs its
  // report, and returning null there would look like the device had vanished
  // from inventory rather than that it was switched off.
  const { rows: deviceRows } = deviceId
    ? await pool.query(
      `SELECT id, name, vendor, mgmt_method, mgmt_ip, site, active, last_rules_collected_at
         FROM devices
        WHERE id = $1::uuid`,
      [deviceId]
    )
    : await pool.query(
      `SELECT id, name, vendor, mgmt_method, mgmt_ip, site, active, last_rules_collected_at
         FROM devices
        WHERE active = true
        ORDER BY name`
    );

  if (deviceRows.length === 0) return null;
  const ids = deviceRows.map((d) => d.id);

  // ⛔ The usage tri-state is counted IN THE DATABASE, with three separate
  // FILTER clauses. Counting it in JS would mean a `hit_count` arriving from
  // node-pg as the STRING '0' passing a truthiness test as non-zero, and a
  // `Number(v) || null` turning a measured zero into "not measured". SQL cannot
  // make either mistake.
  const { rows: countRows } = await pool.query(
    `SELECT device_id,
            count(*)::int                                    AS rules,
            count(*) FILTER (WHERE hit_count IS NULL)::int    AS not_measured,
            count(*) FILTER (WHERE hit_count = 0)::int        AS measured_zero,
            count(*) FILTER (WHERE hit_count > 0)::int        AS with_hits,
            count(*) FILTER (WHERE enabled = false)::int      AS disabled,
            count(*) FILTER (WHERE log_enabled = false)::int  AS logging_off,
            max(collected_at)                                AS collected_at
       FROM firewall_rules
      WHERE device_id = ANY($1::uuid[])
      GROUP BY 1`,
    [ids]
  );
  const countsById = new Map(countRows.map((r) => [r.device_id, r]));

  // ⛔ `ORDER BY fr.hit_count ASC NULLS LAST`. PostgreSQL sorts NULLs FIRST for
  // ASC by default, which would put every unmeasured rule at the head of a list
  // ordered by "least used" — exactly the rules that are NOT evidence of being
  // unused, presented as the strongest deletion candidates. NULLS LAST keeps
  // them out of the ranking instead of ranking them as zeroes.
  const { rows: findingRows } = await pool.query(
    `SELECT r.device_id, r.finding_type, r.severity, r.detail, r.remediation, r.analyzed_at,
            fr.rule_id_vendor, fr.rule_name, fr.sequence_number, fr.enabled,
            fr.hit_count, fr.log_enabled, fr.vdom,
            fa.status AS ack_status, fa.note AS ack_note, fa.updated_at AS ack_at
       FROM rule_analysis_results r
       JOIN firewall_rules fr ON fr.id = r.rule_id
       LEFT JOIN finding_acknowledgements fa
              ON fa.device_id      = r.device_id
             AND fa.rule_id_vendor = fr.rule_id_vendor
             AND fa.finding_type   = r.finding_type
      WHERE r.device_id = ANY($1::uuid[])
      ORDER BY fr.hit_count ASC NULLS LAST, fr.sequence_number ASC NULLS LAST`,
    [ids]
  );

  // ── per-device summaries ────────────────────────────────────────────────
  const devices = deviceRows.map((d) => {
    const c = countsById.get(d.id) || null;
    const rules = c ? Number(c.rules) : 0;
    // ⛔ "No ruleset collected" is not "a firewall with zero rules". Nothing was
    // analysed, so every count for this device is UNKNOWN and renders as a dash.
    const hasRuleset = rules > 0;
    return {
      id: d.id,
      name: d.name,
      vendor: d.vendor,
      mgmtMethod: d.mgmt_method,
      mgmtIp: d.mgmt_ip,
      site: d.site,
      active: d.active,
      lastRulesCollectedAt: d.last_rules_collected_at,
      hasRuleset,
      rules,
      rulesWithHits: c ? Number(c.with_hits) : 0,
      rulesMeasuredZero: c ? Number(c.measured_zero) : 0,
      rulesNotMeasured: c ? Number(c.not_measured) : 0,
      rulesDisabled: c ? Number(c.disabled) : 0,
      rulesLoggingOff: c ? Number(c.logging_off) : 0,
      rulesCollectedAt: c ? c.collected_at : null,
      // ⛔ Re-derived from the engine's own helper against THIS device's rule
      // count. Empty means every pass ran; non-empty names the passes whose
      // zero findings mean "not measured".
      pairwiseSkipped: hasRuleset ? skippedPairwiseFindingTypes(rules) : [],
      findingsActive: 0,
      findingsAcknowledged: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, info: 0 },
      byType: {},
      // ⛔ null until the log stage runs for this device — NOT 0. "The logs
      // answered none of them" and "we never asked the logs" are opposite
      // claims and only one of them is a measurement.
      unmeasuredAnsweredByLogs: null,
      unmeasuredStillUnknown: null,
      logCoverageRatio: null,
      logEvidenceError: null,
    };
  });
  const deviceById = new Map(devices.map((d) => [d.id, d]));

  // ── findings ────────────────────────────────────────────────────────────
  const findings = [];
  const acknowledged = [];
  for (const r of findingRows) {
    const dev = deviceById.get(r.device_id);
    // Cannot happen given the WHERE, but a silently-dropped row would
    // understate the count, so it is skipped explicitly rather than by accident.
    if (!dev) continue;

    const hit = hitCountDisplay(r.hit_count);
    const item = {
      deviceId: r.device_id,
      deviceName: dev.name,
      findingType: r.finding_type,
      findingLabel: FINDING_LABEL[r.finding_type] || r.finding_type,
      findingText: FINDING_TEXT[r.finding_type] || r.finding_type,
      severity: r.severity || 'info',
      detail: r.detail || '',
      remediation: r.remediation || '',
      analyzedAt: r.analyzed_at,
      ruleIdVendor: r.rule_id_vendor,
      ruleName: r.rule_name || '(unnamed)',
      sequenceNumber: r.sequence_number,
      enabled: r.enabled,
      vdom: r.vdom || null,
      logEnabled: r.log_enabled,
      hit,
      ackStatus: r.ack_status || null,
      ackNote: r.ack_note || null,
      ackAt: r.ack_at || null,
    };

    // ⛔ AN ACKNOWLEDGED FINDING IS NOT A DELETED FINDING. It is moved out of the
    // action list and COUNTED, and the count is printed on the cover —
    // otherwise the headline drops silently every time somebody ticks a box,
    // and two runs of the same report disagree for a reason the document never
    // states.
    if (r.ack_status && ACKNOWLEDGED_STATUSES.includes(r.ack_status)) {
      acknowledged.push(item);
      dev.findingsAcknowledged += 1;
      continue;
    }

    findings.push(item);
    dev.findingsActive += 1;
    if (dev.bySeverity[item.severity] === undefined) dev.bySeverity[item.severity] = 0;
    dev.bySeverity[item.severity] += 1;
    dev.byType[item.findingType] = (dev.byType[item.findingType] || 0) + 1;
  }

  // ⛔ Worst severity first, then firewall, then the device's own rule order.
  // This is the presentation order and it must be TOTAL and STABLE, because the
  // findings table is CAPPED — an unstable sort would silently change which
  // rows survive truncation between two runs of the same report, and an audit
  // artefact that differs run to run for no stated reason is not evidence.
  findings.sort((a, b) => (
    severityRank(a.severity) - severityRank(b.severity)
    || String(a.deviceName).localeCompare(String(b.deviceName))
    || (a.sequenceNumber == null ? Number.MAX_SAFE_INTEGER : a.sequenceNumber)
      - (b.sequenceNumber == null ? Number.MAX_SAFE_INTEGER : b.sequenceNumber)
    || String(a.ruleIdVendor).localeCompare(String(b.ruleIdVendor))
    || String(a.findingType).localeCompare(String(b.findingType))
  ));

  // ── log evidence for the rules the device could not measure ─────────────
  // The section that separates this document from a competitor's: for every
  // rule whose hit counter is NULL, can the firewall's own logs answer instead?
  // Sometimes yes. When the answer is no, the rule stays in the unmeasurable
  // list WITH THE REASON it is there.
  const unmeasured = [];
  let coverage = null;
  try {
    coverage = await getDeviceLogCoverage(pool, windowDays, now);
  } catch (err) {
    sectionErrors.push({
      section: 'Firewall log evidence',
      message: `Log coverage could not be read (${err.message}). Rules with no hit counter are `
        + 'listed as unmeasured with no log verdict; SecVault is NOT claiming the logs were silent '
        + 'for them.',
    });
  }

  if (coverage) {
    for (const dev of devices) {
      if (dev.rulesNotMeasured === 0) continue;
      try {
        const { rows: nullRules } = await pool.query(
          `SELECT rule_id_vendor, rule_name, sequence_number, enabled, log_enabled, hit_count, vdom
             FROM firewall_rules
            WHERE device_id = $1::uuid
              AND hit_count IS NULL
            ORDER BY sequence_number ASC NULLS LAST`,
          [dev.id]
        );
        const hitMaps = await getLoggedRuleHits(pool, dev.id, windowDays, now);
        const cov = coverage.get(dev.id) || null;
        const enriched = enrichRulesWithLogEvidence(nullRules, cov, hitMaps);

        dev.logCoverageRatio = cov ? cov.ratio : null;
        let answered = 0;
        let unknown = 0;
        enriched.forEach((e, i) => {
          const log = logEvidenceDisplay(e, windowDays);
          if (log.state === 'not_measured') unknown += 1; else answered += 1;
          unmeasured.push({
            deviceId: dev.id,
            deviceName: dev.name,
            ruleIdVendor: nullRules[i].rule_id_vendor,
            ruleName: nullRules[i].rule_name || '(unnamed)',
            sequenceNumber: nullRules[i].sequence_number,
            enabled: nullRules[i].enabled,
            vdom: nullRules[i].vdom || null,
            // ⛔ hitCountDisplay(null) — the WORDS, not a blank cell. "Not
            // measured" spelled out is what stops a reader (or a spreadsheet
            // import) seeing an empty cell and reading it as zero.
            hit: hitCountDisplay(null),
            log,
          });
        });
        dev.unmeasuredAnsweredByLogs = answered;
        dev.unmeasuredStillUnknown = unknown;
      } catch (err) {
        // ⛔ Per-device, so one unreadable firewall does not blank the section
        // for the other fifteen. This device's counts stay null, which renders
        // as a dash — never as a zero it did not earn.
        dev.logEvidenceError = err.message;
        sectionErrors.push({
          section: `Firewall log evidence - ${dev.name}`,
          message: `Could not be read (${err.message}). This firewall's unmeasured rules are listed `
            + 'without a log verdict rather than being reported as silent.',
        });
      }
    }
  }

  unmeasured.sort((a, b) => (
    String(a.deviceName).localeCompare(String(b.deviceName))
    || (a.sequenceNumber == null ? Number.MAX_SAFE_INTEGER : a.sequenceNumber)
      - (b.sequenceNumber == null ? Number.MAX_SAFE_INTEGER : b.sequenceNumber)
    || String(a.ruleIdVendor).localeCompare(String(b.ruleIdVendor))
  ));

  // ── totals ──────────────────────────────────────────────────────────────
  const totals = {
    devices: devices.length,
    devicesNoRuleset: devices.filter((d) => !d.hasRuleset).length,
    devicesPairwiseSkipped: devices.filter((d) => d.pairwiseSkipped.length > 0).length,
    rules: devices.reduce((a, d) => a + d.rules, 0),
    rulesWithHits: devices.reduce((a, d) => a + d.rulesWithHits, 0),
    rulesMeasuredZero: devices.reduce((a, d) => a + d.rulesMeasuredZero, 0),
    rulesNotMeasured: devices.reduce((a, d) => a + d.rulesNotMeasured, 0),
    findings: findings.length,
    findingsAcknowledged: acknowledged.length,
    findingsCritHigh: findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length,
    // ⛔ null, not 0, when the log stage never ran at all. Same rule as the
    // per-device fields above: the two states are opposite claims.
    unmeasuredAnsweredByLogs: coverage
      ? devices.reduce((a, d) => a + (d.unmeasuredAnsweredByLogs || 0), 0)
      : null,
    unmeasuredStillUnknown: coverage
      ? devices.reduce((a, d) => a + (d.unmeasuredStillUnknown || 0), 0)
      : null,
  };

  // ── by-type rollup ──────────────────────────────────────────────────────
  const emptyTypeRow = (type) => ({
    findingType: type,
    label: FINDING_LABEL[type] || type,
    text: FINDING_TEXT[type] || type,
    critical: 0, high: 0, medium: 0, info: 0, total: 0, acknowledged: 0,
    // ⛔ How many firewalls in scope did NOT have this check run at all.
    // Printed beside the count so "9 redundant findings" is never read as
    // "9 across the whole fleet" when five firewalls never ran the pass.
    notRunOn: 0,
  });
  const byTypeMap = new Map();
  const typeRow = (type) => {
    if (!byTypeMap.has(type)) byTypeMap.set(type, emptyTypeRow(type));
    return byTypeMap.get(type);
  };
  for (const f of findings) {
    const row = typeRow(f.findingType);
    if (row[f.severity] === undefined) row[f.severity] = 0;
    row[f.severity] += 1;
    row.total += 1;
  }
  for (const f of acknowledged) typeRow(f.findingType).acknowledged += 1;

  // ⛔ A pairwise type with ZERO findings STILL GETS A ROW when a pass was
  // skipped somewhere. Omitting it would hide the caveat behind an absence,
  // which is precisely how "we did not look" becomes "there is nothing there".
  for (const type of PAIRWISE_FINDING_TYPES) {
    const skippedOn = devices.filter((d) => d.pairwiseSkipped.includes(type)).length;
    if (skippedOn === 0) continue;
    typeRow(type).notRunOn = skippedOn;
  }
  const byType = Array.from(byTypeMap.values()).sort((a, b) => (
    b.total - a.total || String(a.label).localeCompare(String(b.label))
  ));

  return {
    scope: deviceId ? 'device' : 'fleet',
    device: deviceId ? devices[0] : null,
    generatedAt: now,
    windowDays,
    pairwiseCap: ANALYSIS_DEFAULTS.maxRulesForShadow,
    devices,
    findings,
    acknowledged,
    byType,
    unmeasured,
    totals,
    sectionErrors,
    caps: { maxFindingRows, maxUnmeasuredRows },
    headline: headlineSentence(totals),
  };
}

// ── tables ────────────────────────────────────────────────────────────────

/**
 * "Showing N of M".
 *
 * ⛔ NEVER A SILENT CAP. A truncated table that does not say it is truncated is
 * a WRONG answer, not a shorter one: the reader counts the rows and believes
 * the number. Returns null when nothing was dropped, so the caller prints
 * nothing rather than a reassuring "showing all".
 */
function truncationNote(shown, total, noun) {
  if (shown >= total) return null;
  return `Showing ${num(shown)} of ${num(total)} ${noun}, worst first. `
    + 'The remainder are not in this document - the full list is in the app.';
}

function buildTypeTable(byType) {
  return {
    columns: [
      { key: 'label', label: 'Finding', width: 66, font: 'Helvetica-Bold' },
      { key: 'text', label: 'What it means', width: 196 },
      { key: 'critical', label: 'Crit', width: 24, align: 'right', color: STATUS_RED },
      { key: 'high', label: 'High', width: 24, align: 'right', color: ORANGE },
      { key: 'medium', label: 'Med', width: 24, align: 'right', color: YELLOW },
      { key: 'info', label: 'Info', width: 24, align: 'right', color: MUTED },
      { key: 'total', label: 'Open', width: 28, align: 'right', font: 'Helvetica-Bold' },
      { key: 'ack', label: 'Ack', width: 24, align: 'right', color: MUTED },
      { key: 'caveat', label: 'Coverage', width: 100, color: (r) => (r._caveat ? UNMEASURED : MUTED) },
    ],
    rows: byType.map((t) => ({
      label: t.label,
      text: t.text,
      critical: t.critical || '',
      high: t.high || '',
      medium: t.medium || '',
      info: t.info || '',
      total: t.total,
      ack: t.acknowledged || '',
      caveat: t.notRunOn > 0
        ? `NOT RUN on ${t.notRunOn} firewall${t.notRunOn === 1 ? '' : 's'} (ruleset too large). `
          + 'A zero here is not a clean result.'
        : '',
      _caveat: t.notRunOn > 0,
    })),
  };
}

/**
 * The caveats that must travel WITH a firewall's counts rather than in a
 * footnote. Pure and exported so the wording is pinned by a test — every one of
 * these sentences exists to stop a number being over-read.
 */
function deviceCaveats(d, cap) {
  const out = [];
  if (!d.hasRuleset) {
    out.push('No ruleset collected - nothing on this firewall was analysed. The counts are unknown, not zero.');
  }
  if (d.pairwiseSkipped.length > 0) {
    out.push(
      `Ruleset exceeds ${num(cap)} rules, so the ${d.pairwiseSkipped.join('/')} comparisons did NOT run. `
      + 'Zero of those findings here means not measured, not clean.'
    );
  }
  if (d.rulesNotMeasured > 0) {
    out.push(
      `${num(d.rulesNotMeasured)} rule${d.rulesNotMeasured === 1 ? '' : 's'} carry no hit counter from `
      + 'this firewall, so no unused verdict is offered for them.'
    );
  }
  if (d.logEvidenceError) {
    out.push('Firewall logs could not be read for this device, so its unmeasured rules carry no log verdict.');
  }
  if (d.hasRuleset && !d.lastRulesCollectedAt) {
    out.push('No successful rule collection is recorded, so these rules may predate the running configuration.');
  }
  return out.join(' ');
}

function buildDeviceTable(devices, cap) {
  return {
    columns: [
      { key: 'name', label: 'Firewall', width: 74, font: 'Helvetica-Bold' },
      { key: 'access', label: 'Vendor / access', width: 58, color: MUTED },
      { key: 'rules', label: 'Rules', width: 30, align: 'right' },
      { key: 'hits', label: 'With hits', width: 34, align: 'right', color: YELLOW },
      { key: 'zero', label: 'Measured zero', width: 40, align: 'right', color: GREEN },
      // ⛔ Hueless, and placed BESIDE the two measured columns rather than after
      // the findings count. It is a property of the measurement, not a finding.
      { key: 'unmeasured', label: 'Not measured', width: 40, align: 'right', color: UNMEASURED, font: 'Helvetica-Bold' },
      { key: 'findings', label: 'Open findings', width: 38, align: 'right', font: 'Helvetica-Bold' },
      { key: 'caveats', label: 'Coverage caveats', width: 196, color: (r) => (r._caveat ? UNMEASURED : MUTED) },
    ],
    rows: devices.map((d) => {
      const caveats = deviceCaveats(d, cap);
      return {
        name: d.name,
        access: `${d.vendor}${d.mgmtMethod ? ` / ${d.mgmtMethod}` : ''}`,
        // ⛔ Every count on a firewall with no ruleset is a dash. It has not got
        // zero rules; the question was never put to it.
        rules: countCell(d.rules, d.hasRuleset),
        hits: countCell(d.rulesWithHits, d.hasRuleset),
        zero: countCell(d.rulesMeasuredZero, d.hasRuleset),
        unmeasured: countCell(d.rulesNotMeasured, d.hasRuleset),
        findings: countCell(d.findingsActive, d.hasRuleset),
        caveats: caveats || 'Full analysis ran; every rule carried a usage measurement.',
        _caveat: Boolean(caveats),
      };
    }),
  };
}

function buildFindingTable(items, includeDevice) {
  const columns = [];
  if (includeDevice) columns.push({ key: 'device', label: 'Firewall', width: 54 });
  columns.push(
    { key: 'ruleId', label: 'Rule ID', width: 34 },
    { key: 'ruleName', label: 'Rule name', width: 74 },
    { key: 'finding', label: 'Finding', width: 56, font: 'Helvetica-Bold' },
    { key: 'severity', label: 'Severity', width: 34, color: (r) => r._sevColor, font: 'Helvetica-Bold' },
    // ⛔ The usage column sits INSIDE the findings table, not only in the
    // unmeasurable section. A reader deciding whether to action a row needs to
    // see, on that row, whether its usage was measured at all.
    { key: 'hits', label: 'Device hit counter', width: 50, color: (r) => r._hitColor, font: 'Helvetica-Bold' },
    { key: 'detail', label: 'What SecVault found', width: 190 }
  );
  return {
    columns,
    rows: items.map((f) => ({
      device: f.deviceName,
      ruleId: f.ruleIdVendor == null ? NOT_MEASURED_MARK : String(f.ruleIdVendor),
      ruleName: f.ruleName,
      finding: f.findingLabel,
      severity: f.severity,
      hits: f.hit.text,
      detail: f.detail || f.findingText,
      _sevColor: severityColor(f.severity),
      _hitColor: hitCountColor(f.hit.state),
    })),
  };
}

function buildUnmeasuredTable(rows, includeDevice, windowDays) {
  const columns = [];
  if (includeDevice) columns.push({ key: 'device', label: 'Firewall', width: 54 });
  columns.push(
    { key: 'ruleId', label: 'Rule ID', width: 34 },
    { key: 'ruleName', label: 'Rule name', width: 80 },
    { key: 'enabled', label: 'Enabled', width: 32, color: MUTED },
    { key: 'hits', label: 'Device hit counter', width: 52, color: UNMEASURED, font: 'Helvetica-Bold' },
    { key: 'logs', label: `Firewall log evidence (last ${windowDays} days)`, width: 196, color: (r) => r._logColor }
  );
  return {
    columns,
    rows: rows.map((u) => ({
      device: u.deviceName,
      ruleId: u.ruleIdVendor == null ? NOT_MEASURED_MARK : String(u.ruleIdVendor),
      ruleName: u.ruleName,
      enabled: u.enabled === false ? 'No' : 'Yes',
      hits: u.hit.text,
      logs: u.log.text,
      _logColor: logStateColor(u.log.state),
    })),
  };
}

function buildAcknowledgedTable(items, includeDevice) {
  const columns = [];
  if (includeDevice) columns.push({ key: 'device', label: 'Firewall', width: 54 });
  columns.push(
    { key: 'ruleId', label: 'Rule ID', width: 34 },
    { key: 'ruleName', label: 'Rule name', width: 76 },
    { key: 'finding', label: 'Finding', width: 56 },
    { key: 'status', label: 'Status', width: 44, font: 'Helvetica-Bold' },
    { key: 'when', label: 'Acknowledged at', width: 72, color: MUTED },
    { key: 'note', label: 'Note', width: 150, color: MUTED }
  );
  return {
    columns,
    rows: items.map((f) => ({
      device: f.deviceName,
      ruleId: f.ruleIdVendor == null ? NOT_MEASURED_MARK : String(f.ruleIdVendor),
      ruleName: f.ruleName,
      finding: f.findingLabel,
      status: f.ackStatus,
      // ⛔ A dash, not a blank and not "now". An acknowledgement with no
      // timestamp is an unknown date, and a reader must not be able to read one
      // into it.
      when: f.ackAt ? fmtStamp(f.ackAt) : NOT_MEASURED_MARK,
      note: f.ackNote || '',
    })),
  };
}

// ── body ──────────────────────────────────────────────────────────────────

/**
 * ⛔ THE LEGEND IS NOT DECORATION, AND IT COMES FIRST.
 *
 * This document leaves the tool. The reader may be a change board or an auditor
 * with no SecVault account, and every usage number on the following pages is
 * tri-state. Without this page they have no way to tell a measured zero from an
 * unmeasured blank — which is exactly the ambiguity a competing report leaves
 * in, and the reason its deletion list cannot be trusted.
 */
function renderWhatThisProves(doc, layout, data) {
  sectionTitle(doc, layout, 'What this report can and cannot prove');
  paragraph(
    doc,
    layout,
    'Every rule below carries the measurement the judgement rests on, so you can disagree with a '
    + 'specific number rather than with the tool. Three things can be true of a rule\'s usage, and '
    + 'they are not interchangeable.',
    INK
  );
  doc.y += 4;

  const bullets = [
    ['A number', YELLOW,
      'The firewall itself reported traffic against this rule. A rule with hits can still be '
      + 'shadowed, redundant or far too permissive - but it is carrying traffic, so read any '
      + 'proposal to remove it twice.'],
    ['0 (measured zero)', GREEN,
      'The firewall was asked and answered zero. This is real evidence, and it is the ONLY basis on '
      + 'which an "unused" finding is ever written. A rule with no usage measurement never produces '
      + 'one, however long it has sat there.'],
    [`${NOT_MEASURED_MARK} / "Not measured"`, UNMEASURED,
      'The firewall CANNOT report a hit counter for this rule. Several vendors and access methods '
      + 'have no such counter to read at all. This does NOT mean zero - it means the question was '
      + 'never answered, and no conclusion about this rule\'s usage is drawn from it anywhere in '
      + 'this document. These rules are counted on the cover and listed in their own section below.'],
    [`Firewall log evidence (last ${data.windowDays} days)`, INK,
      'An independent second check against the raw firewall logs. It counts as "no traffic" only '
      + 'when the device was actually sending logs throughout the window AND logging is switched on '
      + 'for that rule; otherwise the row states why the logs cannot answer. Silence from a device '
      + 'that was not logging measures the log collector, not the rule.'],
  ];
  bullets.forEach(([label, color, text]) => labelledNote(doc, layout, label, color, text));

  doc.y += 6;
  labelledNote(
    doc, layout,
    'Where an analysis pass did not run at all', UNMEASURED,
    'Comparing every rule against every other rule is quadratic work, so it is not attempted above '
    + `${num(data.pairwiseCap)} rules on a single firewall. Where that applies, the `
    + `${PAIRWISE_FINDING_TYPES.join('/')} checks did not run, and zero of those findings means NOT `
    + 'MEASURED rather than none. Every firewall affected is named in the per-firewall table, beside '
    + 'its counts.'
  );
}

function renderSectionErrors(doc, layout, sectionErrors) {
  if (!sectionErrors || sectionErrors.length === 0) return;
  doc.y += 8;
  sectionTitle(doc, layout, 'Parts of this report could not be gathered');
  // ⛔ Named, not hidden. A section that silently vanishes reads as a section
  // with nothing in it, and "we could not look" is then presented as "there was
  // nothing to find".
  paragraph(
    doc, layout,
    'The following did not return data for this run. Nothing below is reported as a clean result on '
    + 'their behalf.',
    STATUS_RED
  );
  sectionErrors.forEach((e) => labelledNote(doc, layout, e.section, UNMEASURED, e.message));
}

function renderUnmeasuredSection(doc, layout, data) {
  const { totals, unmeasured, caps, windowDays } = data;
  doc.y += 10;
  sectionTitle(doc, layout, `Rules whose usage SecVault could not measure (${num(totals.rulesNotMeasured)})`);

  if (totals.rulesNotMeasured === 0) {
    paragraph(
      doc, layout,
      'Every rule in scope carried a usage measurement from its firewall. Nothing in this report '
      + 'rests on an unanswered question about traffic.',
      GREEN
    );
    return;
  }

  const p = pct(totals.rulesNotMeasured, totals.rules);
  paragraph(
    doc, layout,
    `${num(totals.rulesNotMeasured)} of ${num(totals.rules)} rules${p == null ? '' : ` (${p}%)`} have no hit `
    + 'counter, because the firewall or the access method in use cannot report one. THIS IS NOT A '
    + 'FINDING AND IT IS NOT A ZERO. They are listed here, apart from the findings, because no usage '
    + 'conclusion is available for them - and a report that quietly folded them in with genuinely '
    + 'idle rules would be offering deletion candidates it cannot support.',
    INK
  );

  if (totals.unmeasuredAnsweredByLogs === null) {
    paragraph(
      doc, layout,
      'The firewall logs could not be consulted for this run, so none of these rules has a second '
      + 'opinion attached. That is a gap in this report, not a verdict about the rules.',
      UNMEASURED
    );
  } else {
    paragraph(
      doc, layout,
      `Of those, the firewalls' own logs over the last ${windowDays} days can answer for `
      + `${num(totals.unmeasuredAnsweredByLogs)}; ${num(totals.unmeasuredStillUnknown)} remain `
      + 'unanswerable from any source SecVault has. The per-rule verdict, and the reason where there '
      + 'is none, is in the table below.',
      INK
    );
  }

  const shown = unmeasured.slice(0, caps.maxUnmeasuredRows);
  const note = truncationNote(shown.length, unmeasured.length, 'unmeasured rules');
  if (note) paragraph(doc, layout, note, MUTED);

  drawTable(
    doc,
    buildUnmeasuredTable(shown, data.scope === 'fleet', windowDays),
    layout,
    {
      continueOnPage: true,
      // ⛔ Not 'No data.' — reaching here means the COUNT is non-zero, so an
      // empty table is a listing failure and must not read as "none".
      emptyText: 'These rules could not be listed individually for this run.',
    }
  );
}

function renderMethodology(doc, layout, data) {
  doc.y += 10;
  sectionTitle(doc, layout, 'How these findings were produced');
  paragraph(
    doc, layout,
    'SecVault collects each firewall\'s full ruleset over that vendor\'s own management API or CLI, '
    + 'stores it, and re-analyses it after every collection. Nothing here is typed in by hand and '
    + 'nothing is inferred from a vendor datasheet.',
    INK
  );
  const bullets = [
    ['Configuration analysis', INK,
      'Every rule is compared against the rules around it for shadowing, redundancy, conflicting '
      + 'actions, over-broad address or service fields, high-risk services and inbound exposure from '
      + 'untrusted zones. These conclusions come from the configuration alone and need no traffic data.'],
    ['Usage analysis', INK,
      'Traffic questions are answered from two independent sources: the counter the firewall itself '
      + 'keeps per rule, and the firewall\'s own logs as received by SecVault. An "unused" finding '
      + 'requires a MEASURED zero from one of them - never the absence of a number.'],
    ['Acknowledged findings', MUTED,
      'A finding an operator has acknowledged, dismissed or actioned is moved out of the open list '
      + 'and counted separately. It is not deleted and it is not hidden: the count is on the cover '
      + 'and the rows are listed in their own section.'],
    ['What this report does not claim', UNMEASURED,
      'It does not claim a packet would or would not pass. Rule order, address and service objects, '
      + 'security profiles and NAT all still apply. It reports what the rulebase says and what the '
      + 'usage evidence shows, and it states plainly where it has neither.'],
  ];
  bullets.forEach(([label, color, text]) => labelledNote(doc, layout, label, color, text));

  doc.y += 6;
  paragraph(
    doc, layout,
    'Findings reflect the rulesets last collected from each firewall; the per-firewall table names '
    + `any whose collection is missing. Log evidence covers the last ${data.windowDays} days.`,
    MUTED
  );
}

function renderBody(doc, data, layout) {
  const { totals, findings, byType, devices, caps, acknowledged } = data;
  const includeDevice = data.scope === 'fleet';

  doc.addPage();

  // Answer first, in a sentence, before any table.
  sectionTitle(doc, layout, 'Summary');
  paragraph(doc, layout, data.headline, INK, 10);
  doc.y += 6;

  renderWhatThisProves(doc, layout, data);
  renderSectionErrors(doc, layout, data.sectionErrors);

  doc.y += 10;
  sectionTitle(doc, layout, 'Findings by type and severity');
  drawTable(doc, buildTypeTable(byType), layout, {
    continueOnPage: true,
    emptyText: 'No open findings, and no analysis pass was skipped.',
  });

  doc.y += 10;
  sectionTitle(doc, layout, `Per-firewall breakdown (${num(devices.length)})`);
  paragraph(
    doc, layout,
    'Usage is counted three ways because it has three states. A dash means the figure is unknown for '
    + 'that firewall, not zero.',
    MUTED
  );
  drawTable(doc, buildDeviceTable(devices, data.pairwiseCap), layout, {
    continueOnPage: true,
    emptyText: 'No firewalls in scope.',
  });

  doc.y += 10;
  const shownFindings = findings.slice(0, caps.maxFindingRows);
  sectionTitle(doc, layout, `Open findings (${num(totals.findings)})`);
  const note = truncationNote(shownFindings.length, findings.length, 'findings');
  if (note) paragraph(doc, layout, note, MUTED);
  if (totals.findings === 0
    && (totals.rulesNotMeasured > 0 || totals.devicesNoRuleset > 0 || totals.devicesPairwiseSkipped > 0)) {
    // ⛔ An empty findings table is NOT an all-clear while coverage is
    // incomplete. Repeated here as well as in the headline, because this is
    // where a reader who skipped the first page will look.
    paragraph(
      doc, layout,
      'No open findings - but coverage is incomplete (see the caveats above), so this is not a '
      + 'statement that these firewalls are clean.',
      UNMEASURED
    );
  }
  drawTable(doc, buildFindingTable(shownFindings, includeDevice), layout, {
    continueOnPage: true,
    emptyText: 'No open rule hygiene findings for the firewalls in scope.',
  });

  if (acknowledged.length > 0) {
    doc.y += 10;
    sectionTitle(doc, layout, `Acknowledged findings, excluded from the counts above (${num(acknowledged.length)})`);
    paragraph(
      doc, layout,
      'These were found by the same analysis and then acknowledged, dismissed or actioned by an '
      + 'operator. They are excluded from the open counts on the cover and listed here so the '
      + 'difference between the two numbers is visible rather than unexplained.',
      MUTED
    );
    const ackShown = acknowledged.slice(0, caps.maxFindingRows);
    const ackNote = truncationNote(ackShown.length, acknowledged.length, 'acknowledged findings');
    if (ackNote) paragraph(doc, layout, ackNote, MUTED);
    drawTable(doc, buildAcknowledgedTable(ackShown, includeDevice), layout, {
      continueOnPage: true,
      emptyText: 'None.',
    });
  }

  renderUnmeasuredSection(doc, layout, data);
  renderMethodology(doc, layout, data);
}

// ── PDF ───────────────────────────────────────────────────────────────────

const TITLE = 'Rule Hygiene & Policy Audit';

/** Pure-ish: report data -> PDF Buffer. No DB, no network, no browser. */
function renderRuleHygienePdf(data) {
  const doc = installPdfSafeText(
    new PDFDocument({ size: 'A4', layout: 'portrait', margin: 36, bufferPages: true })
  );
  const layout = layoutOf(doc);
  const generatedAt = fmtStamp(data.generatedAt || new Date());
  const { totals, scope, device } = data;
  const subject = scope === 'device' && device
    ? `${device.name} (${device.vendor}${device.mgmtMethod ? ` / ${device.mgmtMethod}` : ''})`
    : 'Fleet-wide';

  // ⛔ THE COVER STATES COVERAGE, not only results. A reader who goes no further
  // than page one must still learn how much of the estate this document
  // actually measured. A cover carrying a finding count alone invites the
  // conclusion that everything not counted was fine.
  const collectedNever = data.devices.filter((d) => !d.lastRulesCollectedAt).length;

  drawCover(
    doc,
    {
      title: TITLE,
      subtitle: scope === 'device'
        ? `${subject} - unused, shadowed, redundant and over-permissive rules`
        : 'Unused, shadowed, redundant and over-permissive rules across the firewall estate',
      company: PRODUCT_NAME,
      generatedAt,
      // Same opt-in as the change-request cover: draws the stamp AND leaves
      // doc.y below the chips so the body flows from there.
      footerStamp: true,
      meta: [
        ['Scope', scope === 'device' ? subject : `${num(totals.devices)} firewalls`],
        scope === 'device' && device && device.site ? ['Site', device.site] : null,
        ['Rules examined', totals.rules > 0
          ? num(totals.rules)
          : `${NOT_MEASURED_MARK} (no ruleset collected)`],
        // ⛔ On the cover, in its own row, in the product's own words. This is
        // the number a competing report does not have and cannot state.
        ['Rules with NO usage data', `${num(totals.rulesNotMeasured)}`
          + (totals.rules > 0 ? ` of ${num(totals.rules)} (${pct(totals.rulesNotMeasured, totals.rules)}%)` : '')],
        ['Firewalls with no ruleset collected', num(totals.devicesNoRuleset)],
        ['Firewalls where a comparison pass was skipped', num(totals.devicesPairwiseSkipped)],
        ['Findings acknowledged and excluded', num(totals.findingsAcknowledged)],
        ['Log evidence window', `${data.windowDays} days`],
        collectedNever > 0
          ? ['Firewalls with no successful collection recorded', num(collectedNever)]
          : null,
      ].filter(Boolean),
      summary: [
        { label: 'Open findings', value: num(totals.findings), color: totals.findings > 0 ? NAVY : GREEN },
        { label: 'Critical or high', value: num(totals.findingsCritHigh), color: totals.findingsCritHigh > 0 ? STATUS_RED : GREEN },
        // ⛔ Hueless on purpose. This chip is not good news and not bad news; it
        // is the SIZE OF THE QUESTION SecVault could not answer, and colouring
        // it either way would turn a coverage figure into an assessment.
        { label: 'Rules with no usage data', value: num(totals.rulesNotMeasured), color: UNMEASURED },
        { label: 'Firewalls covered', value: num(totals.devices - totals.devicesNoRuleset), color: NAVY },
      ],
    },
    layout
  );

  renderBody(doc, data, layout);
  stampHeadersFooters(doc, {
    title: `${PRODUCT_NAME} ${TITLE}`,
    company: scope === 'device' && device ? device.name : `${num(totals.devices)} firewalls`,
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
 * @param {object} [options] `{deviceId}` for one firewall; omit for the fleet.
 * @returns {Promise<Buffer|null>} null only when a named device does not exist.
 */
async function generateRuleHygienePdf(pool, options = {}) {
  const data = await buildRuleHygieneData(pool, options);
  if (!data) return null;
  return renderRuleHygienePdf(data);
}

module.exports = {
  TITLE,
  FINDING_TEXT,
  FINDING_LABEL,
  SEVERITY_ORDER,
  NOT_MEASURED_MARK,
  severityColor,
  logStateColor,
  countCell,
  truncationNote,
  headlineSentence,
  deviceCaveats,
  buildRuleHygieneData,
  renderRuleHygienePdf,
  generateRuleHygienePdf,
};
