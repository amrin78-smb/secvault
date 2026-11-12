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
// ⛔ The shared PDF chassis — see lib/reports/chassis.js. These helpers used to
// live here AND in complianceReport.js; this file held the more evolved copy
// (ensureSpace, paragraph, labelledNote), which is why the chassis is based on
// it and why the compliance report gained a page-break fix by adopting it.
const {
  ACCENT, NAVY, MUTED, LIGHT, BORDER, GREEN, INK,
  pdfSafe, installPdfSafeText, fmtStamp,
  ensureSpace, drawCover, sectionTitle, paragraph, labelledNote,
  drawTable, stampHeadersFooters,
} = require('../reports/chassis');

const { PRODUCT_NAME, PRODUCT_TAGLINE } = require('../branding');
const {
  getRequest,
  verificationSupport,
  isDeletionType,
  normaliseRequestType,
} = require('./ruleChangeRequests');
const {
  getDeviceLogCoverage,
  getLoggedRuleHits,
  enrichRulesWithLogEvidence,
} = require('./ruleHitCorrelation');

// The FLOOR of the log window this document quotes, re-exported from the one
// place that now owns it. ruleHitCorrelation.clampDays() floors anything below
// 7 anyway, for its own documented reason.
//
// ⛔ THIS WAS A FIXED CONSTANT AND THE REASONING IS REVISED HERE RATHER THAN
// DELETED. It read: "deliberately a constant and not an env var: it is the
// sentence the reviewer reads ('no traffic in 30 days of firewall logs'), and
// a document whose claim silently changes size between two installations is
// not a document." That argument is still correct about an ENV VAR — an
// operator typing a number changes what the document CLAIMS without changing
// what was measured, and the two then disagree. It does not apply to a window
// DERIVED from the evidence: `windowDays` is resolved once in
// buildRequestReportData() and threaded through the coverage query, the hits
// query, the sentence, the legend and the `evidence_window_days` CSV column
// alike, so the number the reviewer reads is by construction the number the
// measurement used. The document became MORE accurate, not less: on the
// reference fleet it now says 39 days because 40.3 days of history exist,
// where before it said 30 while holding evidence it was not using.
const { MIN_EVIDENCE_WINDOW_DAYS, resolveEvidenceWindowDays } = require('./evidenceWindow');

const EVIDENCE_WINDOW_DAYS = MIN_EVIDENCE_WINDOW_DAYS;

// ── Palette (mirrors app/globals.css LIGHT tokens by hand — a PDF has no
// var() to resolve). Same values and same reasoning as complianceReport.js:
// ACCENT is teal because red means DANGER and nothing else since v2.87.0.
const YELLOW = '#B7791F';      // --yellow / --sev-med
const BLUE = '#2F6FE0';        // --blue
const STATUS_RED = '#D4353B';  // --red / --sev-crit
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
 * act on. ⛔ Five of the seven codes are NOT MEASUREMENTS — they each say why
 * the logs cannot answer, and none of them may read as "no traffic".
 *
 * ⛔ AND THE MEASUREMENTS CARRY THEIR GRADE (A3). A log answer reached by rule
 * NAME rather than by the vendor's rule ID rests on the name not having changed;
 * a renamed rule is absent under its new name while passing traffic under its
 * old one. This document is handed to whoever EDITS THE FIREWALL, so that
 * caveat has to travel with the sentence, not sit in a field they never see.
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
        text: `${enriched.loggedHits} matching log events in the last ${d} days.${last}`
          + byNameCaveat(enriched),
      };
    }
    case 'measured-zero': {
      const cov = enriched.logCoverageRatio == null
        ? ''
        : ` Device logged continuously for ${Math.round(enriched.logCoverageRatio * 100)}% of that window.`;
      return {
        state: 'measured_zero',
        text: `No matching traffic in ${d} days of firewall logs.${cov}`
          + byNameCaveat(enriched),
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
    // ⛔ OURS, NOT THE DEVICE'S — and it must not read like `no-coverage`
    // above. The firewall may have logged every single hour; SecVault simply
    // has not been collecting for as long as the question asks about.
    case 'insufficient-history':
      return {
        state: 'not_measured',
        text: `Not measured: SecVault has not been collecting logs for the full ${d}-day window `
          + 'yet, so nothing can be concluded from their silence. This is a limit of our own '
          + 'history, not a fault on the firewall.',
      };
    // ⛔ A FORMAT FACT ABOUT THE DEVICE'S LOGS, not about this rule.
    case 'no-rule-identity':
      return {
        state: 'not_measured',
        text: 'Not measured: the logs from this firewall do not name a rule at all, so no rule on it '
          + 'can be matched to traffic. Its absence from the logs means nothing.',
      };
    default:
      return { state: 'not_measured', text: 'Not measured: no log evidence available.' };
  }
}

// ⛔ THE CAVEAT TRAVELS WITH THE SENTENCE. `log-name` grade means the answer
// was reached by rule NAME, which is neither unique nor stable across a config
// change. Silent on every other grade, so it stays meaningful where it appears.
//
// ⛔ IT KEYS ON `logGrade`, NOT `usageGrade`, AND THE DIFFERENCE IS THE WHOLE
// CAVEAT (fixed 2026-09-27). `usageGrade` grades `effectiveHitCount` — the
// DEVICE's counter wherever one exists — while the sentence this decorates
// describes `loggedHits`, whose grade is `logGrade`. So on any rule where the
// firewall DOES report a counter, `usageGrade` is 'device' and the old test
// could never be true, however the log answer was reached.
//
// ⛔ AND IN THIS DOCUMENT IT WAS STRUCTURALLY UNREACHABLE. buildRequestReportData
// sets `pseudoRules.hit_count` from `hit_count_at_request`, which
// getCleanupCandidates guarantees is a finite number (an unmeasured rule is
// REFUSED from a request) — so `usageGrade` is ALWAYS 'device' here and the
// caveat could not appear on a single row of a single change request, ever.
// Measured on the live fleet 2026-09-27: 202 rules across 9 firewalls carry
// `logGrade: 'log-name'` with `usageGrade: 'device'` (SMT alone: 45 of 190,
// e.g. `SSL-TO-SAPRise` — hit_count 2,083,930, loggedHits 13,697), and every
// one of them printed "13697 matching log events in the last 30 days" with no
// statement anywhere that the match was by NAME.
//
// ⛔ `usageGrade === 'log-name'` IS STILL ACCEPTED, as an alias rather than as
// the test. It can only arise FROM `logGrade === 'log-name'` (usageGrade is
// `deviceHits !== null ? 'device' : logGrade`), so accepting it adds no case —
// but a caveat only ever REFUSES a deletion, so erring towards printing it is
// the safe direction and an older enriched object missing `logGrade` still
// carries its warning.
function byNameCaveat(enriched) {
  if (!enriched) return '';
  if (enriched.logGrade !== 'log-name' && enriched.usageGrade !== 'log-name') return '';
  // ⛔ ASCII ONLY. pdfkit's built-in Helvetica is WinAnsi: a U+26A0 here was
  // emitted as `&` followed by a non-breaking space, and widthOfString('⚠')
  // is 0 — so the wrap measurement was two glyphs short as well. chassis.pdfSafe
  // now maps the character too, but the document reads better saying the word.
  return ' CAUTION: matched by rule NAME (the logs from this firewall carry no rule id), so this '
    + 'rests on the name being unchanged over the window — it is not sufficient evidence to '
    + 'remove the rule.';
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
    // ⛔ ITS OWN LABEL AND ITS OWN SENTENCE, NEVER "Not yet verifiable". That
    // one says "ask again later, once collection recovers"; this one says "no
    // later collection will ever answer this, because SecVault does not measure
    // this kind of change at all". A reader handed the wrong one waits for a
    // confirmation that is never coming.
    case 'not_supported':
      return {
        label: 'Cannot be verified',
        color: UNMEASURED,
        text: 'SecVault cannot verify this kind of change. A deletion is confirmed by the rule being '
          + 'absent from the ruleset we re-collect; a modification, an addition or an object change '
          + 'is not answerable that way, so nothing here will ever confirm it. Whoever makes the '
          + 'change has to confirm it. This is a limit of SecVault, not a finding about the request.',
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
  // ⛔ SAYS OUT LOUD THAT NOTHING MEASURED THIS. Every other entry here is an
  // analyser finding; this one is a person's instruction, and the document is
  // read by someone deciding whether to trust it.
  operator_request: 'Requested by an operator - this is an instruction, not a SecVault finding.',
};

// ── request type ──────────────────────────────────────────────────────────
//
// ⛔ THE DOCUMENT MUST NAME WHAT IS BEING ASKED FOR. The same artefact now
// carries four different asks, and the deletion wording ("Rules proposed for
// removal", "the proposal rests on these two measurements") is actively wrong
// on the other three: it would hand a change board an evidence legend for a
// decision nobody measured.
const REQUEST_TYPE_TEXT = {
  rule_deletion: 'Rule deletion - the rules listed are proposed for removal.',
  rule_modification: 'Rule modification - the rules listed are to be changed as described.',
  rule_addition: 'Rule addition - the rules described are to be created.',
  object_change: 'Object change - the network objects listed are to be changed as described.',
};

const REQUEST_TYPE_HEADING = {
  rule_deletion: 'Rules proposed for removal',
  rule_modification: 'Rules to be modified',
  rule_addition: 'Rules to be added',
  object_change: 'Objects to be changed',
};

/** The word for whatever an item names, per type. */
const SUBJECT_HEADING = {
  rule_deletion: 'Rule ID (on the firewall)',
  rule_modification: 'Rule ID (on the firewall)',
  rule_addition: 'Proposed rule (requester\'s label)',
  object_change: 'Object name',
};

// ⛔ DELEGATES to the engine rather than deciding again. A row with no
// `request_type` is a DELETION (the column's own default, and what every
// request raised before the column existed is) — and the engine's verifier
// reads it the same way, so the document and the verdict cannot disagree about
// what an old row is.
function requestTypeOf(request) {
  return normaliseRequestType(request && request.request_type);
}

/**
 * ⛔ `submitted` MEANS SOMETHING DIFFERENT PER REQUEST KIND, and the default
 * sentence promises a verification that is not coming for three of the four.
 * STATUS_TEXT's wording — "awaiting the change and its verification" — is
 * correct only where a verification exists.
 */
function statusText(request, requestType) {
  const status = request && request.status;
  if (status === 'submitted' && !isDeletionType(requestType)) {
    return 'Submitted - handed over. SecVault cannot verify this kind of change, so this request '
      + 'will stay at "submitted": whoever makes the change confirms it.';
  }
  return STATUS_TEXT[status] || '';
}

/**
 * The approval sentence for the cover page.
 *
 * ⛔ FOUR STATES AND `not_required` IS NOT "APPROVED". A change board reading
 * this artefact is deciding whether somebody already signed this off; printing
 * "no approval was required" as though it were an approval would put a
 * signature on the document that nobody gave.
 *
 * ⛔ AND A REJECTED REQUEST STILL EXPORTS. It is a record of an ask that was
 * refused and the reason it was refused, which is exactly the thing worth
 * keeping. The sentence says so rather than letting the reader assume it is
 * live work.
 */
function approvalDisplay(request) {
  const state = (request && request.approval_state) || 'not_required';
  const who = (request && request.approved_by) || null;
  const when = request && request.approved_at ? fmtStamp(request.approved_at) : null;
  switch (state) {
    case 'pending':
      return {
        state,
        label: 'Awaiting approval',
        color: YELLOW,
        text: 'This request is waiting for approval and has NOT been issued. It cannot be submitted '
          + 'until another administrator approves it.',
      };
    case 'approved':
      return {
        state,
        label: 'Approved',
        color: GREEN,
        text: `Approved${who ? ` by ${who}` : ''}${when ? ` on ${when}` : ''}. An approval authorises `
          + 'the change; it is not evidence the change was made.',
      };
    case 'rejected':
      return {
        state,
        label: 'Rejected',
        color: STATUS_RED,
        text: `Rejected${who ? ` by ${who}` : ''}${when ? ` on ${when}` : ''}.`
          + (request && request.rejected_reason ? ` Reason: ${request.rejected_reason}` : '')
          + ' This request was not issued and no change was asked for.',
      };
    case 'not_required':
      return {
        state,
        label: 'No approval step',
        color: MUTED,
        // ⛔ Worded as the ABSENCE of a step, never as a pass.
        text: 'This request was raised without an approval step, so nobody has signed it off.',
      };
    default:
      return {
        state,
        label: 'Unknown',
        color: UNMEASURED,
        text: `Unrecognised approval state "${state}" - SecVault cannot say whether this request `
          + 'was approved.',
      };
  }
}

// ── formatting helpers ────────────────────────────────────────────────────


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
  // ⛔ RESOLVED FROM THE EVIDENCE, NOT ASSUMED. An explicit opts.windowDays
  // still wins (a test pins a number so the rendered document is stable), and
  // the resolver falls back to the floor rather than throwing — this export is
  // deliberately not best-effort per query, so a window that could not be
  // resolved must degrade to the old fixed behaviour, never fail the document.
  // ⛔ The caller's OWN clock, when it pinned one. Passing a Date bypasses the
  // per-pool cache and is threaded into the history read, so the window can
  // never be resolved against a different instant from the coverage query
  // below. Passing undefined (the normal case) keeps the cache.
  const windowDays = opts.windowDays == null
    ? (await resolveEvidenceWindowDays(pool, opts.now instanceof Date ? opts.now : undefined)).days
    : opts.windowDays;

  const request = await getRequest(pool, requestId);
  if (!request) return null;

  const requestType = requestTypeOf(request);
  const verification = verificationSupport(requestType);
  const approval = approvalDisplay(request);

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

  // ⛔ LOG EVIDENCE IS COMPUTED FOR A DELETION ONLY, AND THE REASON IS A
  // FABRICATED-CLAIM RISK, NOT A COST SAVING. It exists in this document as the
  // SECOND INDEPENDENT MEASUREMENT behind a proposed removal. Run it on an
  // ADDITION and `enrichRulesWithLogEvidence` would report "no matching traffic
  // in N days of firewall logs" about a rule that DOES NOT EXIST YET — a
  // confident sentence about nothing, printed in an artefact that leaves the
  // tool. The same trap catches a modification whose subject is absent from our
  // collected snapshot. So a non-deletion item states that the figure does not
  // apply, rather than borrowing a measurement it has no subject for.
  const wantsLogEvidence = isDeletionType(requestType);
  const coverageMap = wantsLogEvidence
    ? await getDeviceLogCoverage(pool, windowDays, now)
    : new Map();
  const hitMaps = wantsLogEvidence
    ? await getLoggedRuleHits(pool, request.device_id, windowDays, now)
    : null;

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
  const enriched = wantsLogEvidence
    ? enrichRulesWithLogEvidence(pseudoRules, coverageMap.get(request.device_id) || null, hitMaps)
    : [];

  const NOT_APPLICABLE_LOG = {
    state: 'not_applicable',
    text: 'Not applicable: firewall log evidence is the independent check behind a proposed '
      + 'REMOVAL. This request does not propose removing anything, so there is no absence to '
      + 'corroborate.',
  };

  const items = (request.items || []).map((it, i) => {
    const ev = evidenceOf(it);
    const hit = hitCountDisplay(it.hit_count_at_request);
    const log = wantsLogEvidence ? logEvidenceDisplay(enriched[i], windowDays) : NOT_APPLICABLE_LOG;
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
      // What the requester asked for, in their words. NULL on a deletion, where
      // the ask is the absence — see schema.sql.
      requestedChange: it.requested_change || null,
      // ⛔ TRI-STATE, and `null` is NOT `false`. "SecVault has no collected
      // ruleset for this firewall" and "the read failed" both mean we cannot
      // say whether the rule exists; printing either as "not found" would file
      // our own gap as a fact about the device, in a document handed to
      // somebody who will act on it.
      subjectKnown: ev.subjectKnown === undefined ? null : ev.subjectKnown,
      subjectKnownReason: ev.subjectKnownReason || null,
      subjectKind: ev.subjectKind || null,
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
    // ⛔ COUNTED APART FROM `unverifiable`. One clears when collection
    // recovers; this one never clears, because SecVault does not measure this
    // kind of change. Adding them together would tell a reader that
    // confirmation is on its way.
    notSupported: items.filter((i) => i.outcome === 'not_supported').length,
    // ⛔ Reported separately so a reader can see at a glance whether any row in
    // a DELETION proposal rests on an unmeasured number. Should always be 0 —
    // the engine refuses such rules — and if it ever is not, the document says
    // so rather than hiding it.
    unmeasured: items.filter((i) => i.hit.state === 'not_measured').length,
  };

  return {
    request,
    device,
    items,
    counts,
    windowDays,
    requestType,
    verification,
    approval,
    generatedAt: now,
  };
}

// ── CSV ───────────────────────────────────────────────────────────────────

const CSV_COLUMNS = [
  ['request_id', (d, i) => d.request.id],
  ['request_title', (d) => d.request.title],
  ['request_status', (d) => d.request.status],
  // ⛔ DERIVED FROM `d.request`, not from a field on `d`. renderRequestCsv is
  // pure and is called with hand-built data in tests and by any future caller;
  // reading a convenience field that may be absent would silently emit an empty
  // column for the thing that says WHAT WAS ASKED FOR.
  ['request_type', (d) => requestTypeOf(d.request)],
  // ⛔ Four states, spelled out. A spreadsheet filtered on "approved" must not
  // also catch `not_required`, which is the ABSENCE of an approval step.
  ['approval_state', (d) => approvalDisplay(d.request).state],
  ['approval_detail', (d) => approvalDisplay(d.request).text],
  // The decision actor — approver OR rejecter. Read with approval_state; there
  // is no separate rejected_by column (see rejectRequest()).
  ['approval_decided_by', (d) => d.request.approved_by || ''],
  ['approval_decided_at', (d) => fmtStamp(d.request.approved_at)],
  ['rejected_reason', (d) => d.request.rejected_reason || ''],
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
  // ⛔ The requester's own words, carried verbatim. On a non-deletion request
  // this IS the instruction, and a document that lists subjects without it asks
  // for nothing.
  ['requested_change', (d, i) => i.requestedChange || ''],
  // ⛔ TRI-STATE AS TEXT, never a blank for "unknown". A blank in a spreadsheet
  // reads as "no" to anyone sorting the column.
  ['subject_in_collected_ruleset', (d, i) => {
    if (i.subjectKnown === true) return 'yes';
    if (i.subjectKnown === false) return 'no';
    return 'unknown';
  }],
  ['subject_in_collected_ruleset_note', (d, i) => i.subjectKnownReason || ''],
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
  // ⛔ WHETHER SECVAULT CAN VERIFY THIS KIND OF CHANGE AT ALL, as its own
  // column. Without it, "Cannot be verified" in verification_outcome is
  // indistinguishable to a filter from "Not yet verifiable", and the two have
  // nothing in common except that neither is a measurement.
  ['verification_supported', (d) => (verificationSupport(requestTypeOf(d.request)).supported ? 'yes' : 'no')],
  ['verification_unsupported_reason', (d) => verificationSupport(requestTypeOf(d.request)).reason || ''],
  ['verification_outcome', (d, i) => i.outcomeLabel],
  ['verification_detail', (d, i) => i.outcomeText],
  ['verified_at', (d, i) => fmtStamp(i.verifiedAt)],
];

// ⛔ csvEscape/csvRow MOVED TO lib/csv.js when the log export became the
// second caller. Two files deciding independently how to neutralise a
// spreadsheet formula would eventually disagree, and the one that disagreed
// quietly would be the one writing a document that runs code on open. The
// reasoning that used to live here now lives there, in full.
const { csvEscape, csvRow } = require('../csv');

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



// ⛔ Break to a new page if `needed` px would not fit. Every block below asks
// for the height it MEASURED, never a guessed constant: pdfkit draws at the y
// it is handed, and a block started too near the bottom either vanishes off the
// page or gets auto-flowed a fragment at a time. Both were observed here — a
// table header started 20px above the bottom margin produced FIVE pages each
// carrying a single column heading, with the rows on a sixth.



// A bold label with its explanatory paragraph, kept together on one page.

// Generic wrapped-height zebra table, same structure as complianceReport.js's:
// measures every cell's wrapped height so a row fits its tallest cell, and
// redraws the header after a page break.


// ── PDF body ──────────────────────────────────────────────────────────────

/**
 * ⛔ A NON-DELETION REQUEST GETS ITS OWN TABLE, NOT THE DELETION TABLE WITH ONE
 * EXTRA COLUMN. The deletion table's whole structure is an evidence case —
 * "Flagged as", "Why SecVault flagged it", a hit counter and log corroboration.
 * None of that exists for an operator's instruction, and printing those headings
 * with empty or borrowed cells would dress an unmeasured ask up as a measured
 * one in the artefact a change board signs.
 */
function buildChangeTable(items, requestType) {
  const subjectState = (i) => {
    if (i.subjectKnown === true) return 'Yes';
    if (i.subjectKnown === false) return 'No';
    return 'Unknown';
  };
  return {
    columns: [
      { key: 'subject', label: SUBJECT_HEADING[requestType] || 'Subject', width: 92 },
      { key: 'ruleName', label: 'Name in the collected ruleset', width: 88 },
      { key: 'change', label: 'Requested change (requester\'s words)', width: 196 },
      {
        key: 'known',
        label: 'Present in the ruleset SecVault collected',
        width: 72,
        color: (r) => r._knownColor,
      },
      { key: 'hits', label: 'Device hit counter (context only)', width: 100, color: (r) => r._hitColor },
    ],
    rows: items.map((i) => ({
      subject: i.ruleIdVendor,
      ruleName: i.ruleName,
      change: i.requestedChange || '(no change stated)',
      // ⛔ The reason travels with an Unknown. "Unknown" with no explanation is
      // read as a typo; "Unknown - no ruleset has been collected" is actionable.
      known: i.subjectKnown === null && i.subjectKnownReason
        ? `${subjectState(i)}\n${i.subjectKnownReason}`
        : subjectState(i),
      hits: i.hit.text,
      _knownColor: i.subjectKnown === null ? UNMEASURED : INK,
      _hitColor: hitCountColor(i.hit.state),
    })),
  };
}

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
/**
 * The legend for a request nobody measured.
 *
 * ⛔ IT LEADS WITH THE LIMIT, NOT WITH THE ASK. The deletion legend's opening
 * sentence — "each rule below carries the two independent measurements the
 * proposal rests on" — is the reason a stranger can trust that document. There
 * are no such measurements here, so the honest opening is to say so, before the
 * reader has started assuming otherwise.
 */
function renderChangeLegend(doc, layout, requestType, verification) {
  sectionTitle(doc, layout, 'How to read this document');
  paragraph(
    doc,
    layout,
    'This is an operator\'s instruction, not a SecVault finding. Nothing below was derived from '
    + 'an analysis: a person decided this change should be made and wrote it down here so that '
    + 'the ask, who made it, and when, are all on one page.',
    INK
  );
  doc.y += 4;

  const bullets = [
    [REQUEST_TYPE_HEADING[requestType] || 'Requested changes', INK,
      REQUEST_TYPE_TEXT[requestType] || 'The changes listed below are what is being asked for.'],
    ['Requested change', INK,
      'The requester\'s own words, stored verbatim. SecVault does not interpret, validate or '
      + 'translate them into device configuration.'],
    ['Present in the ruleset SecVault collected', INK,
      'Whether the subject was in the ruleset SecVault had collected from this firewall when the '
      + 'request was raised. "Unknown" means SecVault could not tell - it is not a statement that '
      + 'the subject is missing from the device.'],
    ['Device hit counter', UNMEASURED,
      'CONTEXT ONLY on this kind of request. It is the counter the firewall reported for an '
      + 'existing rule, shown so a reviewer can see how busy a rule they are being asked to change '
      + 'is. It is not evidence for or against the change.'],
    // ⛔ The refusal, in the legend, in the engine's own words. A reader must
    // not reach the verification section expecting a confirmation that is never
    // coming.
    ['SecVault cannot verify this change', UNMEASURED,
      (verification && verification.reason)
        ? `${verification.reason} Whoever makes the change has to confirm it.`
        : 'SecVault cannot verify this kind of change.'],
  ];
  bullets.forEach(([label, color, text]) => labelledNote(doc, layout, label, color, text));
}

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

/**
 * ⛔ A SEPARATE VERIFICATION LEGEND, BECAUSE THE DELETION ONE MAKES A PROMISE
 * THIS REQUEST CANNOT KEEP. It opens "After the change is made, SecVault checks
 * it automatically" — which on a modification or an addition would be a
 * commitment to a confirmation that will never arrive, in the one section a
 * change board reads to find out whether anybody is watching.
 */
function renderUnsupportedVerification(doc, layout, verification) {
  paragraph(
    doc,
    layout,
    (verification && verification.reason)
      ? verification.reason
      : 'SecVault cannot verify this kind of change.',
    INK
  );
  const bullets = [
    ['Cannot be verified', UNMEASURED,
      'This is a limit of SecVault, not a finding about the request and not a fault on the '
      + 'firewall. No future collection will change it.'],
    // ⛔ NAMED AND SET APART. These two are the states this document must never
    // let a reader confuse: one is waiting on us, the other is never coming.
    ['NOT the same as "Not yet verifiable"', UNMEASURED,
      '"Not yet verifiable" appears on a DELETION request and means no rule collection has '
      + 'succeeded since submission - it clears itself once collection recovers. "Cannot be '
      + 'verified" never clears.'],
    ['What SecVault does verify', GREEN,
      'A rule DELETION, and only that: a rule counts as removed because the ruleset SecVault '
      + 're-collected from the device no longer contains it. Nobody ticks a box there either.'],
  ];
  bullets.forEach(([label, color, text]) => labelledNote(doc, layout, label, color, text));
}

function renderRequestBody(doc, data, layout) {
  const { request, items, counts, windowDays } = data;
  const requestType = data.requestType || requestTypeOf(request);
  const verification = data.verification || verificationSupport(requestType);
  const approval = data.approval || approvalDisplay(request);
  const deletion = isDeletionType(requestType);

  doc.addPage();
  if (deletion) renderLegend(doc, layout, windowDays);
  else renderChangeLegend(doc, layout, requestType, verification);

  // ⛔ THE APPROVAL IS ON THE DOCUMENT, NOT ONLY IN THE UI. This artefact is
  // what a change board sees; whether somebody signed the change off, who, and
  // when is exactly what they are looking for, and `not_required` is reported
  // as the absence of a step rather than quietly omitted.
  doc.y += 6;
  sectionTitle(doc, layout, 'Approval');
  labelledNote(doc, layout, approval.label, approval.color, approval.text);

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
  sectionTitle(
    doc,
    layout,
    `${REQUEST_TYPE_HEADING[requestType] || 'Requested changes'} (${counts.total})`
  );
  // ⛔ GATED ON THE REQUEST BEING A DELETION. The warning says these rules
  // "should not be removed on the strength of this document" — printed over an
  // ADDITION it would be nonsense, and on a modification it would argue against
  // a removal nobody asked for. A NULL hit count on a non-deletion item is not
  // a missing justification: an addition's rule does not exist yet, so there is
  // no counter to read.
  if (deletion && counts.unmeasured > 0) {
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
  drawTable(
    doc,
    deletion ? buildProposedTable(items) : buildChangeTable(items, requestType),
    layout,
    {
      continueOnPage: true,
      // ⛔ Not the chassis default 'No data.' — an empty change request is a
      // meaningful state and says so in its own words.
      emptyText: 'No items in this request.',
    }
  );

  doc.y += 10;
  sectionTitle(doc, layout, 'Verification');
  if (deletion) {
    renderVerificationLegend(doc, layout);
    drawTable(doc, buildVerificationTable(items), layout, {
      continueOnPage: true,
      emptyText: 'No rules in this request.',
    });
  } else {
    // ⛔ NO OUTCOME TABLE. Every row would read "Cannot be verified", which is
    // one fact about the whole request, not a per-item result — and a table of
    // identical verdicts invites the reader to look for the row that differs.
    // The refusal is stated once, in words.
    renderUnsupportedVerification(doc, layout, verification);
  }
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
  const requestType = data.requestType || requestTypeOf(request);
  const approval = data.approval || approvalDisplay(request);
  const deletion = isDeletionType(requestType);
  const deviceName = device ? device.name : '(device no longer in inventory)';
  const title = 'Firewall Rule Change Request';

  drawCover(
    doc,
    {
      title,
      subtitle: request.title || 'Rule cleanup',
      company: PRODUCT_NAME,
      generatedAt,
      // ⛔ This report's cover ends with the generated-at line AND sets doc.y so
      // the body flows from below the chips. The chassis makes that opt-in
      // because the compliance cover does neither. Dropping it did not merely
      // lose a line of text — doc.y was left where the last chip put it and
      // every subsequent block moved, which is what the PDF comparison caught.
      footerStamp: true,
      meta: [
        ['Firewall', device ? `${deviceName} (${device.vendor}${device.mgmt_ip ? ` - ${device.mgmt_ip}` : ''})` : deviceName],
        ['Site', device ? device.site : null],
        // ⛔ ON THE COVER, not buried in the body. The reader's first question
        // is what they are being asked to do; four request kinds now share this
        // document and the deletion wording is wrong for three of them.
        ['Request type', REQUEST_TYPE_TEXT[requestType] || requestType],
        ['Approval', `${approval.label} - ${approval.text}`],
        ['Raised by', request.created_by || 'unknown'],
        ['Raised at', fmtStamp(request.created_at)],
        ['Submitted at', request.submitted_at ? fmtStamp(request.submitted_at) : 'Not yet submitted'],
        ['Status', `${request.status} - ${statusText(request, requestType)}`],
        // A partial is the outcome that most needs dating: it is the one that
        // still requires a follow-up.
        request.verified_at ? ['Verified at', fmtStamp(request.verified_at)] : null,
        request.abandon_reason ? ['Withdrawn because', request.abandon_reason] : null,
        ['Last rule collection', device && device.last_rules_collected_at ? fmtStamp(device.last_rules_collected_at) : 'None recorded'],
        ['Request reference', request.id],
      ].filter(Boolean),
      // ⛔ THE CHIPS CHANGE WITH THE REQUEST KIND. "Confirmed removed: 0" on a
      // modification request is not a neutral zero — it reads as a cleanup that
      // has not happened, for a removal nobody asked for. A request SecVault
      // cannot verify gets a chip that says exactly that instead, so the cover
      // never shows a count that implies a measurement was attempted.
      summary: deletion
        ? [
          { label: 'Rules requested', value: counts.total, color: NAVY },
          { label: 'Confirmed removed', value: counts.removed, color: counts.removed > 0 ? GREEN : MUTED },
          { label: 'Still present', value: counts.stillPresent, color: counts.stillPresent > 0 ? STATUS_RED : MUTED },
          { label: 'Not yet verifiable', value: counts.unverifiable + counts.pending, color: UNMEASURED },
        ]
        : [
          { label: 'Changes requested', value: counts.total, color: NAVY },
          { label: 'Verifiable by SecVault', value: 0, color: UNMEASURED },
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
  byNameCaveat,
  outcomeDisplay,
  requestTypeOf,
  statusText,
  approvalDisplay,
  REQUEST_TYPE_TEXT,
  REQUEST_TYPE_HEADING,
  csvEscape,
  buildRequestReportData,
  renderRequestCsv,
  renderRequestPdf,
  generateRequestCsv,
  generateRequestPdf,
  CSV_COLUMNS,
};
