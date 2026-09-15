// lib/reports/segmentationPosture.js
//
// R6 — "Segmentation Posture".
//
// It answers one question: IS OUR DECLARED ZONE-TO-ZONE POLICY ACTUALLY IN
// FORCE — AND WHERE CAN'T WE TELL?
//
// ⛔ THE SECOND HALF IS THE DOCUMENT. Tufin and AlgoSec answer the first half
// from a policy model: they will tell you whether the rulebase permits a path.
// Neither answers "and did anything actually use it", because that needs
// traffic evidence joined to the rulebase on the same inventory. The valuable
// cell is the one only that combination produces — a path that is PERMITTED and
// has carried NO TRAFFIC, which is a standing hole with no business
// justification and the safest possible thing to close.
//
// ⛔ AND NEITHER OF THEM PRINTS THE THIRD STATE, which is what this file exists
// to protect. "Did anything use it" is TRI-STATE:
//     true  -> a permitting rule has recorded traffic
//     false -> every permitting rule was MEASURED and recorded none
//     null  -> at least one permitting rule CANNOT report usage at all
// Fortinet over SSH reports no hit counter for any rule (0 of 180 on the
// reference fleet), so `null` is the COMMON case here, not a corner. A report
// that folded it into `false` would hand a change board a deletion list
// containing rules that may be carrying production traffic right now.
//
// ⛔ WHAT "CAN" CLAIMS, PRECISELY, AND WHAT IT DOES NOT. "Permitted" means AT
// LEAST ONE ENABLED ALLOW RULE MATCHES THIS ZONE PAIR. It does NOT mean a
// packet would pass: addresses, services, security profiles and rule order all
// still apply and are deliberately not modelled. Every sentence in this
// document therefore says "a rule permits this", never "this is reachable".
//
// That distinction matters more in print than on screen. A page can be
// re-read next to its own caveats; a PDF is forwarded, printed and quoted in a
// ticket a year later with the caveats left behind. An overclaim here outlives
// the session that made it, so the claim is narrowed in the prose itself rather
// than in a footnote.
//
// ⛔ NO VERDICT LOGIC LIVES IN THIS FILE. `lib/engines/segmentation.js` decides
// what a violation is and `lib/engines/segmentationData.js` does the loading;
// both are used unchanged. Two implementations of "is this a violation" would
// eventually disagree, and the printed one would be the copy nobody re-runs.
//
// CommonJS — same reason as every engine and every other report: the App Router
// route and plain-node callers both load it.

'use strict';

const PDFDocument = require('pdfkit');

const {
  NAVY, MUTED, GREEN, INK, BLUE,
  // ⛔ The status ramp comes from the chassis, never a local copy of the hex
  // literals. A verdict that is amber on screen and red on the PDF an auditor is
  // holding is two different claims about the same fact.
  STATUS_RED, ORANGE, YELLOW, UNMEASURED,
  fmtStamp, installPdfSafeText,
  layoutOf,
  drawCover, sectionTitle, paragraph, labelledNote, drawTable, stampHeadersFooters,
} = require('./chassis');

const { PRODUCT_NAME } = require('../branding');

// ⛔ Imported, not re-derived. `VERDICTS` carries the label and the sentence for
// every outcome and `UNMEASURABLE_VERDICTS` is the authoritative list of the
// three that mean SecVault could not answer. `summarise` is the same roll-up the
// on-screen board uses, so the PDF and the page cannot disagree about a count.
const {
  VERDICTS,
  UNMEASURABLE_VERDICTS,
  summarise,
  rulesForPair,
  normaliseZone,
} = require('../engines/segmentation');

const {
  resolveWindowDays,
  listFleetZones,
  evaluateSegmentation,
  DEFAULT_WINDOW_DAYS,
} = require('../engines/segmentationData');

// ── the printed form of "not measured" ────────────────────────────────────
//
// ⛔ chassis.pdfSafe() folds this to an ASCII hyphen, which is the point: what
// must never appear in one of these cells is a `0` or a "No". A dash reads as
// "no value"; a zero reads as a measurement, and on this report that difference
// is the entire product.
const NOT_MEASURED_MARK = '—';

const TITLE = 'Segmentation Posture';

// ── verdict presentation ──────────────────────────────────────────────────

/**
 * ⛔ COLOUR IS ASSIGNED PER VERDICT, NEVER PER SEVERITY — and that is forced,
 * not stylistic. `violation_permitted` and `violation_unverified` both carry
 * severity `high` in the engine, so a severity-driven ramp would paint them
 * identically. They are opposite instructions to the reader:
 *
 *   violation_permitted  — a rule allows it and every permitting rule was
 *                          MEASURED at zero traffic. A standing hole, and the
 *                          safest thing on the estate to close. Go and close it.
 *   violation_unverified — a rule allows it and at least one permitting rule
 *                          cannot report usage at all. It may be carrying
 *                          production traffic this minute. ASSUME IT IS LIVE;
 *                          do not close it blind.
 *
 * Deleting a rule on the strength of the wrong one of those two is an outage.
 * They must therefore never share a colour, and the legend says why in as many
 * words.
 *
 * ⛔ THE UNVERIFIED ONE IS PLACED HOTTER THAN THE MEASURED-QUIET ONE. That
 * follows the product's own action ordering (the board ranks
 * `violation_unverified` above `violation_permitted` in its "what to act on"
 * list) and the reasoning above: the one you cannot rule out outranks the one
 * you have measured and found quiet. Note this is the reverse of the on-screen
 * CELL TINT today, where `violation_permitted` borrows the danger tint and
 * `violation_unverified` the warning tint — the screen's own ordering and its
 * own colouring disagree with each other, and this document follows the
 * ordering, which is what the operator acts on.
 *
 * ⛔ THE TWO UNMEASURABLE OUTCOMES ARE HUELESS. `ok_unverified` and `unknown`
 * are neither good news nor bad; giving them a ramp colour in either direction
 * is a failed read recorded as a fact, committed in ink where no refresh can
 * correct it. They render in `UNMEASURED` with a dash in the evidence column.
 *
 * `violation_unverified` keeps a hue even though it is unmeasurable, because
 * severity and evidence are separate axes: how bad it would be is known
 * (a declared boundary is permitted), only how well we know it is not.
 */
const VERDICT_COLOR = Object.freeze({
  violation_active: STATUS_RED,
  violation_unverified: ORANGE,
  violation_permitted: YELLOW,
  // Not a severity band at all — the rulebase and the declared intent simply
  // disagree, and somebody has to say which of the two is wrong.
  expected_allow_missing: BLUE,
  unused_permission: MUTED,
  ok_in_use: GREEN,
  ok_blocked: GREEN,
  ok_unverified: UNMEASURED,
  unknown: UNMEASURED,
});

/** Colour for a verdict. An unrecognised verdict is hueless, never green. */
function verdictColor(verdict) {
  // ⛔ Default UNMEASURED, not GREEN and not MUTED. A verdict this file has
  // never heard of is an unknown, and an unknown painted as a clean result is
  // the one failure mode this document cannot tolerate.
  return VERDICT_COLOR[verdict] || UNMEASURED;
}

/** The engine's own label, so the page and the PDF use the same words. */
function verdictLabel(verdict) {
  const v = VERDICTS[verdict];
  return v ? v.label : String(verdict || 'unknown');
}

function verdictDetail(verdict) {
  const v = VERDICTS[verdict];
  return v ? v.detail : 'SecVault has no description for this outcome, so no conclusion is drawn from it.';
}

/** True when this verdict means SecVault could NOT answer the pair. */
function isUnmeasurable(verdict) {
  return UNMEASURABLE_VERDICTS.has(verdict);
}

/**
 * ⛔ The order an operator should work the list in, worst first — and
 * `violation_unverified` deliberately outranks `violation_permitted`. See
 * VERDICT_COLOR above: the one whose usage cannot be measured is the one you
 * must not close blind, so it goes to the top of the queue.
 */
const VERDICT_ORDER = Object.freeze([
  'violation_active',
  'violation_unverified',
  'violation_permitted',
  'expected_allow_missing',
  'unused_permission',
  'unknown',
  'ok_unverified',
  'ok_in_use',
  'ok_blocked',
]);

function verdictRank(verdict) {
  const i = VERDICT_ORDER.indexOf(verdict);
  return i < 0 ? VERDICT_ORDER.length : i;
}

const VIOLATION_VERDICTS = Object.freeze([
  'violation_active',
  'violation_unverified',
  'violation_permitted',
]);

function isViolation(verdict) {
  return VIOLATION_VERDICTS.includes(verdict);
}

/** How the declared intent reads in a table cell. */
function intentLabel(expectation) {
  return expectation === 'allow' ? 'Must connect' : 'Must NOT connect';
}

// ── the two evidence cells ────────────────────────────────────────────────

/**
 * The "a rule permits this" cell. TRI-STATE, like everything else here.
 *
 * ⛔ `can === null` is NOT "no". It means SecVault could not establish whether
 * anything permits the path — because a firewall in the path has no ruleset
 * collected, or because a matching rule uses an action verb this product cannot
 * classify. Printing "No" there would report a hole as closed, which on a
 * segmentation report is the dangerous direction: a false assurance, not a
 * missed finding.
 */
function canCell(result) {
  if (result.can === true) {
    const n = Number(result.permittingRuleCount) || 0;
    return { text: `Yes - ${n} rule${n === 1 ? '' : 's'}`, color: INK, state: 'yes' };
  }
  if (result.can === false) {
    return { text: 'No rule permits it', color: INK, state: 'no' };
  }
  return { text: `${NOT_MEASURED_MARK} Cannot tell`, color: UNMEASURED, state: 'unknown' };
}

/**
 * The "and did anything use it" cell.
 *
 * ⛔ THE WHOLE TRI-STATE LIVES IN THIS ONE FUNCTION and `null` beats `false`
 * upstream in the engine: if even ONE permitting rule cannot report usage the
 * pair is UNKNOWN, because that one rule might be the one carrying the traffic.
 * This renders that as a dash and the words "not measurable", never as "none".
 *
 * ⛔ AND IT NEVER SAYS "IN THE LAST N DAYS". `effectiveHitCount` prefers the
 * DEVICE'S OWN counter, which is cumulative since that counter was last reset —
 * often years. Only where the device supplies no count does the number come
 * from the bounded log window. "Has recorded traffic" is true of both; "used in
 * the last 30 days" would be false for most of the rules behind these verdicts.
 */
function trafficCell(result) {
  if (result.did === true) {
    return { text: 'Yes - traffic recorded', color: INK, state: 'yes' };
  }
  if (result.did === false) {
    return { text: 'None recorded', color: INK, state: 'measured_zero' };
  }
  if (result.can === false) {
    // Nothing permits the path, so there is no permitting rule whose usage
    // could be measured. ⛔ That is the INTENDED outcome, not a measurement
    // gap, and it must not be counted as one.
    return { text: 'Not applicable - nothing permits it', color: MUTED, state: 'n/a' };
  }
  const n = Number(result.unmeasuredRuleCount) || 0;
  return {
    text: n > 0
      ? `${NOT_MEASURED_MARK} Not measurable (${n} permitting rule${n === 1 ? '' : 's'} cannot report usage)`
      : `${NOT_MEASURED_MARK} Not measurable`,
    color: UNMEASURED,
    state: 'not_measured',
  };
}

/**
 * Why SecVault could not answer, in the operator's language rather than the
 * engine's slugs. ⛔ A reason is always given: "could not be determined" with no
 * cause is indistinguishable from a bug, and a reader who cannot tell the two
 * apart stops trusting the answers that ARE measured.
 */
function unmeasurableReason(result) {
  const reasons = Array.isArray(result.evidenceReasons) ? result.evidenceReasons : [];
  const out = [];
  if (reasons.includes('no-rules-collected')) {
    out.push('No ruleset has been collected from any firewall, so there is nothing to test this against.');
  }
  if (reasons.includes('partial-rule-coverage')) {
    const n = Number(result.uncollectedDeviceCount) || 0;
    out.push(
      `${n} firewall${n === 1 ? ' has' : 's have'} no ruleset collected. A rule permitting this path `
      + 'could be sitting on one of them, so "nothing permits it" cannot be claimed.'
    );
  }
  if (reasons.includes('unrecognised-action')) {
    const n = Number(result.unrecognisedActionRuleCount) || 0;
    out.push(
      `${n} matching rule${n === 1 ? ' uses an action' : 's use actions'} SecVault cannot classify as `
      + 'allow or deny, and an unread verb may well be an allow under another name.'
    );
  }
  if (out.length === 0 && result.can === true && result.did === null) {
    const n = Number(result.unmeasuredRuleCount) || 0;
    out.push(
      `A rule permits this path. ${n === 1 ? 'One permitting rule' : `${n} permitting rules`} cannot `
      + 'report usage at all - the firewall or the access method in use keeps no hit counter SecVault '
      + 'can read, and the logs cannot answer for it either. Assume the path is live.'
    );
  }
  if (out.length === 0) out.push('SecVault could not determine this pair from the data it holds.');
  return out.join(' ');
}

// ── small formatters ──────────────────────────────────────────────────────

function num(n) {
  return Number(n || 0).toLocaleString('en-GB');
}

function plural(n, one, many) {
  return Number(n) === 1 ? one : (many === undefined ? `${one}s` : many);
}

/**
 * Clamp a caller-supplied table cap. ⛔ Never 0: a cap of 0 silently empties a
 * section, and on the page an empty section is indistinguishable from "nothing
 * was found" — the exact confusion this report exists to remove.
 */
function clampCap(v, def) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(Math.trunc(n), 1);
}

/**
 * "Showing N of M". ⛔ NEVER A SILENT CAP — a truncated table that does not say
 * so is a WRONG answer rather than a shorter one, because the reader counts the
 * rows and believes the number. Returns null when nothing was dropped.
 */
function truncationNote(shown, total, noun) {
  if (shown >= total) return null;
  return `Showing ${num(shown)} of ${num(total)} ${noun}, worst first. `
    + 'The remainder are not in this document - the full list is in the app.';
}

/** "site-a -> internet", in the direction the intent was declared. */
function pairLabel(result) {
  return `${result.sourceZone} -> ${result.destZone}`;
}

// ── the headline ──────────────────────────────────────────────────────────

/**
 * The answer-first sentence at the top of the document. Pure — takes totals,
 * returns a string.
 *
 * ⛔ AN ALL-CLEAR IS FORBIDDEN WHILE COVERAGE IS INCOMPLETE. Zero violations
 * over a matrix where a third of the pairs could not be evaluated is not a
 * segmented fleet, and a sentence that says it is would be a failed read
 * recorded as a fact, written in English on page one of a document that leaves
 * the building. The only path to an unqualified sentence is every gap being
 * genuinely zero.
 *
 * ⛔ AND NO INTENTS AT ALL IS THE WORST CASE, NOT THE BEST ONE. A fleet with
 * nothing declared has an empty violation list, which reads as perfect. It is
 * not a result; nothing was checked.
 */
function headlineSentence(totals) {
  const t = totals || {};
  const intents = Number(t.intents) || 0;

  if (intents === 0) {
    return 'No zone-to-zone intent has been declared, so nothing has been checked. '
      + 'This is not a clean result - it is an empty one. Until a boundary is declared, SecVault has '
      + 'no opinion about what these firewalls should or should not connect.';
  }

  // ⛔ Every reason the picture is incomplete, named rather than summed into one
  // "unknown" figure: "no ruleset has ever been read from that firewall" and
  // "this rule cannot report usage" are different problems with different fixes.
  const gaps = [];
  if (t.rulesCollected === false) {
    gaps.push(
      'no ruleset has been collected from any firewall, so not one of these pairs was tested against '
      + 'a real rulebase'
    );
  }
  if (Number(t.devicesWithoutRules) > 0) {
    const n = Number(t.devicesWithoutRules);
    gaps.push(
      `${num(n)} firewall${plural(n, ' has', 's have')} no ruleset collected, so a rule permitting a `
      + 'path could be sitting on one of them unseen'
    );
  }
  if (Number(t.unmeasurable) > 0) {
    gaps.push(
      `${num(t.unmeasurable)} of ${num(intents)} declared ${plural(intents, 'path')} could not be `
      + 'measured at all'
    );
  }
  if (Number(t.rulesWithoutHitData) > 0) {
    const n = Number(t.rulesWithoutHitData);
    gaps.push(
      `${num(n)} of ${num(t.ruleCount)} ${plural(n, 'rule')} on the estate cannot report whether `
      + 'traffic ever used them'
    );
  }
  if (Number(t.rulesWithUnrecognisedAction) > 0) {
    const n = Number(t.rulesWithUnrecognisedAction);
    gaps.push(
      `${num(n)} ${plural(n, 'rule')} ${plural(n, 'uses', 'use')} an action SecVault cannot classify `
      + 'as allow or deny'
    );
  }

  let head;
  if (Number(t.violationsActive) > 0) {
    const n = Number(t.violationsActive);
    head = `${num(n)} declared ${plural(n, 'boundary', 'boundaries')} ${plural(n, 'is', 'are')} `
      + `permitted by a rule AND ${plural(n, 'has', 'have')} recorded traffic across `
      + `${plural(n, 'it', 'them')}.`;
  } else if (Number(t.violations) > 0) {
    const n = Number(t.violations);
    head = `${num(n)} declared ${plural(n, 'boundary', 'boundaries')} ${plural(n, 'is', 'are')} `
      + `permitted by a rule, with no traffic recorded against ${plural(n, 'it', 'them')} - `
      + `${plural(n, 'a standing hole', 'standing holes')} rather than `
      + `${plural(n, 'an active breach', 'active breaches')}.`;
  } else if (Number(t.expectedAllowMissing) > 0) {
    const n = Number(t.expectedAllowMissing);
    head = `No declared boundary is being crossed, but ${num(n)} ${plural(n, 'path')} declared as `
      + `required ${plural(n, 'is', 'are')} permitted by nothing - either the intent is wrong or a `
      + 'rule is missing.';
  } else {
    head = `Across ${num(intents)} declared zone-to-zone ${plural(intents, 'intent')} SecVault found `
      + 'no rule permitting anything you said must not connect.';
  }

  if (gaps.length === 0) {
    return `${head} Every declared pair was evaluated against a collected rulebase, and usage evidence `
      + 'was available for every rule that permits one.';
  }
  // ⛔ This clause is what stops the sentence above being read as an all-clear.
  return `${head} This is NOT a complete picture: ${gaps.join('; ')}.`;
}

// ── data assembly ─────────────────────────────────────────────────────────

const DEFAULT_MAX_MATRIX_ROWS = 300;
const DEFAULT_MAX_VIOLATION_ROWS = 150;
const DEFAULT_MAX_UNMEASURABLE_ROWS = 150;

/**
 * Fetch and shape everything the cover and the body need.
 *
 * ⛔ THE EVALUATION IS NOT BEST-EFFORT. If `evaluateSegmentation` throws, the
 * export fails: a segmentation report with a silently-missing matrix is worse
 * than an error the operator can see and retry, because an empty violations
 * table reads as "nothing is crossing your boundaries".
 *
 * ⛔ THE ZONE CENSUS *IS* BEST-EFFORT AND ITS FAILURE IS RECORDED. It only
 * supplies the "how much of the estate has any declared intent at all" context;
 * losing it must not lose the matrix, and it must never be reported as "no
 * zones" — that would silently turn an unread census into a claim that the
 * declared intents cover everything.
 *
 * @param {import('pg').Pool} pool
 * @param {object} [options]
 * @param {string} [options.deviceId]   optional NARROWING, never a requirement
 * @param {Date}   [options.now]
 * @param {number} [options.windowDays]
 * @param {number} [options.maxMatrixRows]
 * @param {number} [options.maxViolationRows]
 * @param {number} [options.maxUnmeasurableRows]
 * @returns {Promise<object|null>} null only when a named device does not exist.
 */
async function buildSegmentationPostureData(pool, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date();
  const caps = {
    maxMatrixRows: clampCap(options.maxMatrixRows, DEFAULT_MAX_MATRIX_ROWS),
    maxViolationRows: clampCap(options.maxViolationRows, DEFAULT_MAX_VIOLATION_ROWS),
    maxUnmeasurableRows: clampCap(options.maxUnmeasurableRows, DEFAULT_MAX_UNMEASURABLE_ROWS),
  };
  const deviceId = options.deviceId || null;

  // ⛔ A gathering failure is a first-class row in the document, not a log line.
  const sectionErrors = [];

  // ── the optional narrowing ──────────────────────────────────────────────
  //
  // ⛔ SEGMENTATION IS FLEET-WIDE AND CANNOT BE MADE PER-DEVICE. Whether a zone
  // pair is permitted is a question about every firewall that could carry it —
  // evaluating one device in isolation would report "blocked" for a path a
  // neighbouring firewall permits, which is the false-assurance direction. So a
  // `deviceId` FILTERS the fleet-wide result down to the intents this firewall
  // participates in; it never changes how a single verdict was reached, and the
  // document says so on its cover.
  let device = null;
  if (deviceId) {
    const { rows } = await pool.query(
      `SELECT id, name, vendor, mgmt_method, mgmt_ip, site, active
         FROM devices
        WHERE id = $1::uuid`,
      [deviceId]
    );
    // ⛔ The one and only null. An empty report for a firewall that does not
    // exist would render as a perfectly segmented device.
    if (rows.length === 0) return null;
    const d = rows[0];
    device = {
      id: d.id,
      name: d.name,
      vendor: d.vendor,
      mgmtMethod: d.mgmt_method,
      mgmtIp: d.mgmt_ip,
      site: d.site,
      active: d.active,
    };
  }

  const evaluation = await evaluateSegmentation(pool, {
    windowDays: options.windowDays,
    now,
  });

  // ── the zone census (best-effort) ───────────────────────────────────────
  let zones = null;
  try {
    zones = await listFleetZones(pool);
  } catch (err) {
    sectionErrors.push({
      section: 'Zone census',
      message: `The list of zones in use across the estate could not be read (${err.message}). `
        + 'The count of zone pairs with no declared intent is therefore unknown rather than zero - '
        + 'SecVault is NOT claiming the declared intents cover the whole estate.',
    });
  }

  // ── which intents involve the named firewall ────────────────────────────
  let allIntents = evaluation.intents || [];
  let narrowing = null;
  if (device) {
    let deviceRules = null;
    try {
      const { rows } = await pool.query(
        `SELECT rule_name, rule_id_vendor, sequence_number, enabled, action, src_zones, dst_zones
           FROM firewall_rules
          WHERE device_id = $1::uuid`,
        [device.id]
      );
      deviceRules = rows;
    } catch (err) {
      sectionErrors.push({
        section: 'Firewall narrowing',
        message: `This firewall's own rules could not be read (${err.message}), so the report could `
          + 'not be narrowed to it. Every declared intent is listed instead - nothing has been '
          + 'filtered out on the strength of a failed read.',
      });
    }

    if (deviceRules) {
      // ⛔ rulesForPair() is the ENGINE's matcher, imported unchanged. It is what
      // knows that `any` is a wildcard and that an empty zone list constrains
      // nothing. A second, simpler matcher here would quietly drop the 114
      // `any`-bearing rules on the live fleet and shorten the report.
      const involvedIds = new Set();
      for (const r of allIntents) {
        const matched = rulesForPair(
          deviceRules,
          normaliseZone(r.sourceZone),
          normaliseZone(r.destZone)
        );
        if (matched.length > 0) involvedIds.add(r.id);
      }
      // ⛔ A firewall with NO ruleset collected still participates in every
      // unknown: its missing rulebase is the reason those pairs cannot be
      // answered, and hiding them would let the narrowed report look cleaner
      // than the fleet it came from.
      const uncollected = (evaluation.devicesWithoutRules || []).includes(device.name)
        || (evaluation.devicesWithoutRules || []).includes(device.id);
      if (uncollected) {
        for (const r of allIntents) if (isUnmeasurable(r.verdict)) involvedIds.add(r.id);
      }

      narrowing = {
        deviceName: device.name,
        totalIntents: allIntents.length,
        matchedIntents: involvedIds.size,
        hasRuleset: deviceRules.length > 0,
        ruleCount: deviceRules.length,
        uncollected,
      };
      allIntents = allIntents.filter((r) => involvedIds.has(r.id));
    }
  }

  // ⛔ Worst first, then a TOTAL and STABLE tiebreak on the zone names. The
  // tables are capped, so an unstable sort would change which rows survive
  // truncation between two runs of the same report — and an audit artefact that
  // differs run to run for no stated reason is not evidence.
  const intents = allIntents.slice().sort((a, b) => (
    verdictRank(a.verdict) - verdictRank(b.verdict)
    || String(a.sourceZone).localeCompare(String(b.sourceZone))
    || String(a.destZone).localeCompare(String(b.destZone))
  ));

  // ⛔ summarise() from the engine, not a hand count here. It is the same
  // roll-up the on-screen board uses, so the two cannot disagree about how many
  // violations there are — and it is the file that knows `ok_blocked` is NOT a
  // measurement gap even though its `did` is null.
  const summary = summarise(intents);

  const violations = intents.filter((r) => isViolation(r.verdict));
  const unmeasurable = intents.filter((r) => isUnmeasurable(r.verdict));

  const zoneCount = Array.isArray(zones) ? zones.length : null;
  // Ordered pairs, because direction matters: trust -> dmz and dmz -> trust are
  // different questions with different answers.
  const orderedPairs = zoneCount === null ? null : zoneCount * (zoneCount - 1);
  const undeclaredPairs = orderedPairs === null
    ? null
    : Math.max(0, orderedPairs - (evaluation.intents || []).length);

  const totals = {
    intents: intents.length,
    // ⛔ Kept apart from `intents` so a narrowed report can never be read as the
    // whole declared policy.
    intentsDeclaredFleetWide: (evaluation.intents || []).length,
    violations: summary.violations,
    violationsActive: summary.activeViolations,
    violationsPermitted: intents.filter((r) => r.verdict === 'violation_permitted').length,
    violationsUnverified: intents.filter((r) => r.verdict === 'violation_unverified').length,
    unusedPermissions: summary.unusedPermissions,
    expectedAllowMissing: summary.expectedAllowMissing,
    unknown: summary.unknown,
    ok: summary.ok,
    unmeasurable: summary.unmeasurable,
    pairsBlockedByUncollectedDevices: summary.pairsBlockedByUncollectedDevices,
    pairsWithUnrecognisedActions: summary.pairsWithUnrecognisedActions,
    // fleet coverage facts, carried into the headline
    rulesCollected: evaluation.rulesCollected,
    ruleCount: evaluation.ruleCount,
    rulesWithoutHitData: evaluation.rulesWithoutHitData,
    rulesWithUnrecognisedAction: evaluation.rulesWithUnrecognisedAction,
    deviceCount: evaluation.deviceCount,
    activeDeviceCount: evaluation.activeDeviceCount,
    devicesWithoutRules: (evaluation.devicesWithoutRules || []).length,
    zoneCount,
    orderedPairs,
    undeclaredPairs,
  };

  return {
    scope: device ? 'device' : 'fleet',
    device,
    narrowing,
    generatedAt: now,
    // ⛔ The window the evidence ACTUALLY spans, as resolved by the engine — not
    // the number the caller asked for. `?days=3` is measured as 7, and printing
    // the request instead would mislabel every number under it.
    windowDays: evaluation.windowDays == null
      ? resolveWindowDays(options.windowDays == null ? DEFAULT_WINDOW_DAYS : options.windowDays)
      : evaluation.windowDays,
    requestedWindowDays: evaluation.requestedWindowDays == null ? null : evaluation.requestedWindowDays,
    devicesWithoutRules: evaluation.devicesWithoutRules || [],
    zones: Array.isArray(zones) ? zones : null,
    intents,
    violations,
    unmeasurable,
    totals,
    caps,
    sectionErrors,
    headline: headlineSentence(totals),
  };
}

// ── tables ────────────────────────────────────────────────────────────────

function buildMatrixTable(intents) {
  return {
    columns: [
      { key: 'pair', label: 'Zone pair', width: 92, font: 'Helvetica-Bold' },
      { key: 'intent', label: 'Declared intent', width: 58, color: MUTED },
      { key: 'verdict', label: 'Verdict', width: 92, color: (r) => r._verdictColor, font: 'Helvetica-Bold' },
      // ⛔ CAN and DID are SEPARATE COLUMNS, never merged into a pass/fail. The
      // verdict is a conclusion drawn from both, and a reader must be able to
      // disagree with one of the two inputs rather than with the tool.
      { key: 'can', label: 'A rule permits it?', width: 58, color: (r) => r._canColor },
      { key: 'did', label: 'Traffic recorded?', width: 80, color: (r) => r._didColor },
      { key: 'note', label: 'Your note', width: 70, color: MUTED },
    ],
    rows: intents.map((r) => {
      const can = canCell(r);
      const did = trafficCell(r);
      return {
        pair: pairLabel(r),
        intent: intentLabel(r.expectation),
        verdict: verdictLabel(r.verdict),
        can: can.text,
        did: did.text,
        note: r.note || '',
        _verdictColor: verdictColor(r.verdict),
        _canColor: can.color,
        _didColor: did.color,
      };
    }),
  };
}

/** The rules an operator would actually go and look at. */
function examplesText(result) {
  const ex = Array.isArray(result.examples) ? result.examples : [];
  if (ex.length === 0) return '';
  return ex.map((e) => {
    const where = `${e.deviceName || 'unknown firewall'}`;
    const which = e.ruleName || (e.sequence == null ? 'unnamed rule' : `rule ${e.sequence}`);
    const seq = e.sequence == null ? '' : ` #${e.sequence}`;
    // ⛔ A dash, never a 0. This is the same rule as everywhere else in this
    // document: an unmeasured counter is not a measurement of zero.
    const hits = e.hits === null || e.hits === undefined
      ? `${NOT_MEASURED_MARK} usage not measured`
      : `${num(e.hits)} hits`;
    return `${where}: ${which}${seq} [${e.action || 'action unknown'}, ${hits}]`;
  }).join('\n');
}

function buildViolationTable(violations) {
  return {
    columns: [
      { key: 'pair', label: 'Zone pair', width: 84, font: 'Helvetica-Bold' },
      { key: 'verdict', label: 'Verdict', width: 88, color: (r) => r._verdictColor, font: 'Helvetica-Bold' },
      { key: 'act', label: 'What to do', width: 118 },
      { key: 'examples', label: 'Rules permitting it (first few)', width: 160, color: MUTED },
    ],
    rows: violations.map((r) => ({
      pair: pairLabel(r),
      verdict: verdictLabel(r.verdict),
      act: ACTION_TEXT[r.verdict] || verdictDetail(r.verdict),
      examples: examplesText(r) || 'No example rule could be listed for this pair.',
      _verdictColor: verdictColor(r.verdict),
    })),
  };
}

/**
 * ⛔ The instruction, not the description. These three verdicts look alike on a
 * page and demand opposite actions, so the column that tells the reader what to
 * DO is the one that keeps them apart.
 */
const ACTION_TEXT = Object.freeze({
  violation_active: 'A rule permits this AND traffic has been recorded across it. Treat as live: '
    + 'find the business owner before changing anything, then narrow or remove the rule.',
  violation_permitted: 'A rule permits this and every permitting rule was MEASURED at zero traffic. '
    + 'This is a standing hole with nothing using it - the safest kind to close.',
  violation_unverified: 'A rule permits this and at least one permitting rule CANNOT report usage at '
    + 'all, so SecVault cannot say whether anything is using it. ASSUME IT IS LIVE. Do not remove it '
    + 'on the strength of this report; get usage evidence first.',
});

function buildUnmeasurableTable(rows) {
  return {
    columns: [
      { key: 'pair', label: 'Zone pair', width: 84, font: 'Helvetica-Bold' },
      { key: 'intent', label: 'Declared intent', width: 54, color: MUTED },
      // ⛔ Hueless throughout. Not measurable is neither good news nor bad, and
      // a ramp colour in either direction turns a coverage figure into an
      // assessment.
      { key: 'verdict', label: 'Outcome', width: 88, color: UNMEASURED, font: 'Helvetica-Bold' },
      { key: 'reason', label: 'Why SecVault cannot answer it', width: 224, color: UNMEASURED },
    ],
    rows: rows.map((r) => ({
      pair: pairLabel(r),
      intent: intentLabel(r.expectation),
      verdict: verdictLabel(r.verdict),
      reason: unmeasurableReason(r),
    })),
  };
}

// ── body ──────────────────────────────────────────────────────────────────

function renderClaimScope(doc, layout) {
  sectionTitle(doc, layout, 'What this report claims, and what it does not');
  paragraph(
    doc, layout,
    'Each declared zone pair below is tested two ways, and the two answers are shown separately so '
    + 'you can disagree with a specific one rather than with the tool.',
    INK
  );
  doc.y += 4;

  labelledNote(
    doc, layout,
    'A rule permits it', INK,
    'At least one ENABLED rule with an allow action matches this pair of zones. That is all it means. '
    + 'It does NOT mean a packet would actually get through: the addresses, the services, the security '
    + 'profiles and the order the rules are evaluated in all still apply, and none of them is modelled '
    + 'here. Read every verdict on the following pages as "a rule permits this", never as "this is '
    + 'reachable".'
  );
  labelledNote(
    doc, layout,
    'Traffic recorded', INK,
    'Whether any rule permitting the pair has recorded traffic. Where the figure came from the '
    + 'firewall\'s own per-rule counter it is cumulative since that counter was last reset - often '
    + 'since the device last rebooted - so recorded traffic is not necessarily recent. It did happen.'
  );
  labelledNote(
    doc, layout,
    `${NOT_MEASURED_MARK} Not measurable`, UNMEASURED,
    'The third answer, and the one that makes this document worth reading. Many firewalls cannot '
    + 'report a per-rule hit counter at all over the access method in use, and their logs cannot '
    + 'always answer instead. If even ONE rule permitting a pair cannot report usage, the pair is '
    + 'reported as NOT MEASURABLE - never as "no traffic" - because that one rule might be the one '
    + 'carrying it. This is counted on the cover and listed in its own section below.'
  );
  labelledNote(
    doc, layout,
    'Nothing permits it', INK,
    'No enabled allow rule anywhere on the collected rulebase matches this pair. This claim needs '
    + 'COMPLETE evidence, so it is withheld whenever a firewall in the estate has no ruleset collected '
    + 'or a matching rule uses an action SecVault cannot classify. A hole reported as closed is a '
    + 'false assurance, which is worse than an admitted gap.'
  );
}

function renderSectionErrors(doc, layout, sectionErrors) {
  if (!sectionErrors || sectionErrors.length === 0) return;
  doc.y += 8;
  sectionTitle(doc, layout, 'Parts of this report could not be gathered');
  paragraph(
    doc, layout,
    'The following did not return data for this run. Nothing below is reported as a clean result on '
    + 'their behalf.',
    STATUS_RED
  );
  sectionErrors.forEach((e) => labelledNote(doc, layout, e.section, UNMEASURED, e.message));
}

function renderViolations(doc, layout, data) {
  const { totals, violations, caps } = data;
  doc.y += 10;
  sectionTitle(doc, layout, `Declared boundaries that a rule permits (${num(totals.violations)})`);

  if (totals.violations === 0) {
    // ⛔ NOTHING DECLARED IS NOT NOTHING WRONG. An empty violation list over an
    // empty intent list is the most reassuring page this report can produce and
    // the least justified one, so it never renders green.
    if (totals.intents === 0) {
      paragraph(
        doc, layout,
        'Nothing was checked, so nothing was found. This is an empty result, not a clean one.',
        UNMEASURED
      );
      return;
    }
    if (totals.unmeasurable > 0 || totals.rulesCollected === false || totals.devicesWithoutRules > 0) {
      // ⛔ Repeated here as well as in the headline, because this is where a
      // reader who skipped page one will look for the good news.
      paragraph(
        doc, layout,
        'No rule was found permitting anything you declared must not connect - BUT coverage is '
        + 'incomplete (see the caveats above and the section below), so this is not a statement that '
        + 'these boundaries are enforced.',
        UNMEASURED
      );
    } else {
      paragraph(
        doc, layout,
        'No rule anywhere on the collected rulebase permits a pair you declared must not connect.',
        GREEN
      );
    }
    return;
  }

  paragraph(
    doc, layout,
    'Worst first. The three outcomes below look similar and require opposite actions, so the '
    + '"what to do" column is the one to read: a boundary whose permitting rules were MEASURED at zero '
    + 'traffic is the safest thing on the estate to close, while one whose rules cannot report usage '
    + 'must be assumed live until evidence says otherwise.',
    INK
  );

  const shown = violations.slice(0, caps.maxViolationRows);
  const note = truncationNote(shown.length, violations.length, 'violations');
  if (note) paragraph(doc, layout, note, MUTED);

  drawTable(doc, buildViolationTable(shown), layout, {
    continueOnPage: true,
    // ⛔ Not 'No data.' — reaching here means the COUNT is non-zero, so an empty
    // table is a listing failure and must not read as "none".
    emptyText: 'These could not be listed individually for this run.',
  });
}

function renderCouldNotVerify(doc, layout, data) {
  const { totals, unmeasurable, caps } = data;
  doc.y += 10;
  sectionTitle(doc, layout, `What could not be verified, and why (${num(totals.unmeasurable)})`);

  if (totals.intents === 0) {
    // ⛔ Zero unanswered pairs out of zero declared pairs is not coverage.
    paragraph(
      doc, layout,
      'No pair was declared, so none could be answered or left unanswered. The absence of gaps here '
      + 'measures the absence of questions, not the state of the estate.',
      UNMEASURED
    );
  } else if (totals.unmeasurable === 0) {
    paragraph(
      doc, layout,
      'Every declared pair was answered from a collected rulebase, and usage evidence was available '
      + 'for every rule permitting one. Nothing in the verdicts above rests on an unanswered question.',
      GREEN
    );
  } else {
    paragraph(
      doc, layout,
      `${num(totals.unmeasurable)} of ${num(totals.intents)} declared ${plural(totals.intents, 'pair')} `
      + 'could not be answered. THESE ARE NOT PASSES AND THEY ARE NOT FAILURES. They are counted here, '
      + 'apart from the verdicts, because a matrix where some cells could not be evaluated is not a '
      + 'partial pass - and a report that quietly folded them in with the enforced boundaries would be '
      + 'offering an assurance it cannot support.',
      INK
    );

    const shown = unmeasurable.slice(0, caps.maxUnmeasurableRows);
    const note = truncationNote(shown.length, unmeasurable.length, 'unanswered pairs');
    if (note) paragraph(doc, layout, note, MUTED);

    drawTable(doc, buildUnmeasurableTable(shown), layout, {
      continueOnPage: true,
      emptyText: 'These could not be listed individually for this run.',
    });
  }

  // ── the estate-level gaps, whether or not a specific pair tripped on them ──
  doc.y += 10;
  sectionTitle(doc, layout, 'Limits on the evidence behind every verdict above');

  if (totals.rulesCollected === false) {
    labelledNote(
      doc, layout,
      'No ruleset has been collected at all', UNMEASURED,
      'Not one firewall in the estate has a collected rulebase, so nothing above was tested against '
      + 'real rules. Every pair is reported as unknown. A clean-looking violation count here means '
      + 'NOTHING WAS CHECKED, not that the boundaries hold.'
    );
  }

  if (totals.devicesWithoutRules > 0) {
    const n = totals.devicesWithoutRules;
    labelledNote(
      doc, layout,
      `${num(n)} firewall${plural(n, '', 's')} with no ruleset collected`, UNMEASURED,
      `${num(totals.deviceCount)} of ${num(totals.activeDeviceCount)} active firewalls contributed `
      + 'rules to this evaluation. A rule permitting one of your declared boundaries could be sitting '
      + `on ${plural(n, 'the other one', 'one of the others')}, unseen. Where that is the only reason a `
      + 'pair could not be answered, the pair is listed above rather than reported as blocked.'
    );
  }

  if (totals.rulesWithoutHitData > 0) {
    labelledNote(
      doc, layout,
      `${num(totals.rulesWithoutHitData)} of ${num(totals.ruleCount)} rules cannot report usage`, UNMEASURED,
      'The firewall, or the access method SecVault uses to reach it, keeps no per-rule hit counter '
      + 'that can be read - and the logs could not answer for these rules either. This is a gap in '
      + 'what can be measured, not a statement that the rules are idle. It is why some pairs above '
      + 'read "not measurable" rather than "no traffic".'
    );
  }

  if (totals.rulesWithUnrecognisedAction > 0) {
    const n = totals.rulesWithUnrecognisedAction;
    labelledNote(
      doc, layout,
      `${num(n)} rule${plural(n, '', 's')} use an action SecVault cannot classify`, UNMEASURED,
      'These rules carry an action verb that is neither a recognised allow nor a recognised deny. '
      + 'They are NOT ignored: where one matches a declared pair that nothing else permits, the pair '
      + 'is reported as unknown rather than blocked, because an unread verb may well be an allow under '
      + 'another name.'
    );
  }

  if (totals.orderedPairs === null) {
    labelledNote(
      doc, layout,
      'Zone pairs with no declared intent: unknown', UNMEASURED,
      'The list of zones in use across the estate could not be read for this run, so the number of '
      + 'zone pairs nobody has declared an intent for is unknown. It is not zero.'
    );
  } else if (totals.undeclaredPairs > 0) {
    labelledNote(
      doc, layout,
      `${num(totals.undeclaredPairs)} zone pairs carry no declared intent`, UNMEASURED,
      `${num(totals.zoneCount)} distinct zones appear in the estate's rules, which is `
      + `${num(totals.orderedPairs)} ordered pairs of zones. ${num(totals.intentsDeclaredFleetWide)} of `
      + `them ${plural(totals.intentsDeclaredFleetWide, 'has', 'have')} a declared intent; the rest are `
      + 'outside this report entirely. SecVault has no '
      + 'opinion about them, which is NOT the same as their being safe - it means nobody has said what '
      + 'they should be.'
    );
  }
}

/**
 * ⛔ THE LEGEND IS NOT DECORATION. This document leaves the tool: the reader may
 * be a change board or an auditor with no SecVault account, holding a printout,
 * a year after it was generated. Every verdict here is a conclusion drawn from
 * a tri-state measurement, and without this page there is no way to tell a
 * measured answer from an unmeasured one.
 */
function renderLegend(doc, layout, data) {
  doc.y += 10;
  sectionTitle(doc, layout, 'Legend - what each verdict means');

  const order = [
    'violation_active',
    'violation_unverified',
    'violation_permitted',
    'expected_allow_missing',
    'unused_permission',
    'ok_in_use',
    'ok_blocked',
    'ok_unverified',
    'unknown',
  ];
  order.forEach((v) => labelledNote(doc, layout, verdictLabel(v), verdictColor(v), verdictDetail(v)));

  doc.y += 6;
  // ⛔ The distinction the whole colour scheme exists to carry. Acting on the
  // wrong one of these two is an outage, so it is spelled out rather than left
  // to the swatches.
  labelledNote(
    doc, layout,
    'Why two of the violations are coloured differently', INK,
    '"Permitted, no traffic recorded" and "permitted, traffic not measurable" are both breaches of a '
    + 'boundary you declared, and they are NOT interchangeable. The first was MEASURED: every rule '
    + 'permitting it reported zero traffic, which makes it the safest thing on the estate to close. '
    + 'The second was NOT measured at all: a rule permits the path and cannot say whether anything '
    + 'used it, so it must be assumed live and must not be removed on the strength of this document. '
    + 'They are deliberately never given the same colour, and the unmeasured one is ranked higher in '
    + 'the list above, because the one you cannot rule out outranks the one you have already checked.'
  );

  labelledNote(
    doc, layout,
    `${NOT_MEASURED_MARK} in any cell`, UNMEASURED,
    'A dash means the value is UNKNOWN, never zero and never "no". It is drawn without colour, '
    + 'because a measurement SecVault could not take is neither good news nor bad news, and shading it '
    + 'either way would turn a coverage gap into an assessment.'
  );
}

function renderMethodology(doc, layout, data) {
  doc.y += 10;
  sectionTitle(doc, layout, 'How this was produced');
  paragraph(
    doc, layout,
    'SecVault collects each firewall\'s full ruleset over that vendor\'s own management API or CLI and '
    + 'stores it. Nothing here is typed in by hand and nothing is inferred from a vendor datasheet.',
    INK
  );
  const bullets = [
    ['The declared intent', INK,
      'Your own statement of which zones must not connect, and which must. It is the only part of '
      + 'this report a person writes. A pair nobody has declared an intent for is not evaluated at '
      + 'all - it is not silently assumed to be either allowed or denied.'],
    ['The zones', INK,
      'Taken from the rules themselves, never typed in. A hand-entered axis drifts the moment someone '
      + 'renames a zone on a firewall, and every declared pair referencing the old name would then be '
      + 'evaluated against nothing while still reporting a verdict.'],
    ['"A rule permits it"', INK,
      'Every enabled rule with an allow action whose source and destination zone lists cover the pair. '
      + 'A rule scoped to "any", or with no zone constraint at all, is treated as covering every zone - '
      + 'reading it literally would understate what the rulebase permits, and understating a hole is '
      + 'the dangerous direction on a segmentation report.'],
    ['"Traffic recorded"', INK,
      'The firewall\'s own per-rule hit counter where it has one, and the firewall\'s own logs as '
      + 'received by SecVault where it does not. Where neither can answer, the pair is reported as not '
      + `measurable. Log evidence spans the last ${data.windowDays} days; a device counter is cumulative `
      + 'since it was last reset.'],
    ['What this report does not claim', UNMEASURED,
      'It does not claim a packet would or would not pass, it does not model rule order, addresses, '
      + 'services, NAT or security profiles, and it does not treat a pair it could not evaluate as a '
      + 'pair that is safe. Where it has no evidence it says so, by name, in its own section.'],
  ];
  bullets.forEach(([label, color, text]) => labelledNote(doc, layout, label, color, text));
}

function renderBody(doc, data, layout) {
  const { totals, intents, caps } = data;

  doc.addPage();

  // Answer first, in a sentence, before any table.
  sectionTitle(doc, layout, 'Summary');
  paragraph(doc, layout, data.headline, INK, 10);
  doc.y += 6;

  if (data.scope === 'device' && data.narrowing) {
    // ⛔ A narrowed report is NOT this firewall's segmentation posture. Whether
    // a pair is permitted is a question about the whole estate; this is a filter
    // on a fleet-wide evaluation, and saying otherwise would let a device look
    // compliant because a neighbour is the one permitting the path.
    labelledNote(
      doc, layout,
      `Narrowed to ${data.narrowing.deviceName}`, INK,
      `${num(data.narrowing.matchedIntents)} of ${num(data.narrowing.totalIntents)} declared pairs `
      + 'involve rules on this firewall and are listed here. Every verdict shown is still an '
      + 'ESTATE-WIDE judgement: whether a pair is permitted depends on every firewall that could carry '
      + 'it, so this document filters which pairs are shown, never how any of them was decided.'
      + (data.narrowing.hasRuleset
        ? ''
        : ' No ruleset has been collected from this firewall at all, so no pair could be matched to it '
          + 'by rule; the pairs listed are those its missing rulebase prevents SecVault from answering.')
    );
    doc.y += 4;
  }

  renderClaimScope(doc, layout);
  renderSectionErrors(doc, layout, data.sectionErrors);

  doc.y += 10;
  sectionTitle(doc, layout, `Declared intent, checked (${num(totals.intents)})`);
  if (totals.intents === 0) {
    paragraph(
      doc, layout,
      data.scope === 'device'
        ? 'No declared zone-to-zone intent involves this firewall, so nothing was checked for it. An '
          + 'empty table here is an empty result, not a clean one.'
        : 'No zone-to-zone intent has been declared anywhere, so nothing was checked. An empty table '
          + 'here is an empty result, not a clean one.',
      UNMEASURED
    );
  } else {
    paragraph(
      doc, layout,
      'Worst first. "A rule permits it" and "traffic recorded" are shown separately because the '
      + 'verdict is drawn from both, and either can be unknown on its own.',
      MUTED
    );
  }
  const shownIntents = intents.slice(0, caps.maxMatrixRows);
  const note = truncationNote(shownIntents.length, intents.length, 'declared pairs');
  if (note) paragraph(doc, layout, note, MUTED);
  drawTable(doc, buildMatrixTable(shownIntents), layout, {
    continueOnPage: true,
    emptyText: 'No declared intent is in scope for this report. Nothing was checked.',
  });

  renderViolations(doc, layout, data);
  renderCouldNotVerify(doc, layout, data);
  renderLegend(doc, layout, data);
  renderMethodology(doc, layout, data);
}

// ── PDF ───────────────────────────────────────────────────────────────────

/** Pure-ish: report data -> PDF Buffer. No DB, no network, no browser. */
function renderSegmentationPosturePdf(data) {
  const doc = installPdfSafeText(
    new PDFDocument({ size: 'A4', layout: 'portrait', margin: 36, bufferPages: true })
  );
  const layout = layoutOf(doc);
  const generatedAt = fmtStamp(data.generatedAt || new Date());
  const { totals, scope, device } = data;
  const subject = scope === 'device' && device
    ? `${device.name} (${device.vendor}${device.mgmtMethod ? ` / ${device.mgmtMethod}` : ''})`
    : 'Fleet-wide';

  drawCover(
    doc,
    {
      title: TITLE,
      subtitle: scope === 'device'
        ? `${subject} - declared zone-to-zone policy, checked against the rules and the traffic`
        : 'Declared zone-to-zone policy, checked against what the rules permit and what the traffic did',
      company: PRODUCT_NAME,
      generatedAt,
      footerStamp: true,
      meta: [
        ['Scope', scope === 'device' ? subject : `${num(totals.activeDeviceCount)} firewalls`],
        scope === 'device' && device && device.site ? ['Site', device.site] : null,
        ['Zone pairs declared', scope === 'device'
          ? `${num(totals.intents)} of ${num(totals.intentsDeclaredFleetWide)} (narrowed to this firewall)`
          : num(totals.intents)],
        // ⛔ ON THE COVER, in its own row, and stated as a WINDOW rather than
        // left implicit. A "no traffic recorded" verdict means nothing without
        // the span it was measured over.
        ['Traffic evidence window', `${data.windowDays} days`],
        ['Firewalls contributing rules', totals.rulesCollected
          ? `${num(totals.deviceCount)} of ${num(totals.activeDeviceCount)}`
          : `${NOT_MEASURED_MARK} no ruleset collected from any firewall`],
        ['Rules examined', totals.ruleCount > 0
          ? num(totals.ruleCount)
          : `${NOT_MEASURED_MARK} (no ruleset collected)`],
        // ⛔ The figure a competing report does not have and cannot state.
        ['Rules that cannot report usage', totals.ruleCount > 0
          ? `${num(totals.rulesWithoutHitData)} of ${num(totals.ruleCount)}`
          : NOT_MEASURED_MARK],
        ['Zones in use across the estate', totals.zoneCount === null
          ? `${NOT_MEASURED_MARK} (could not be read)`
          : num(totals.zoneCount)],
        ['Zone pairs with no declared intent', totals.undeclaredPairs === null
          ? `${NOT_MEASURED_MARK} (unknown, not zero)`
          : num(totals.undeclaredPairs)],
      ].filter(Boolean),
      summary: [
        { label: 'Zone pairs declared', value: num(totals.intents), color: NAVY },
        {
          label: 'Violations - permitted AND in use',
          value: num(totals.violationsActive),
          color: totals.violationsActive > 0 ? STATUS_RED : GREEN,
        },
        {
          label: 'Violations - usage not measurable',
          value: num(totals.violationsUnverified),
          color: totals.violationsUnverified > 0 ? ORANGE : GREEN,
        },
        // ⛔ Hueless on purpose. This chip is not good news and not bad news; it
        // is the SIZE OF THE QUESTION SecVault could not answer, and colouring
        // it either way would turn a coverage figure into an assessment.
        { label: 'Pairs that could not be answered', value: num(totals.unmeasurable), color: UNMEASURED },
      ],
    },
    layout
  );

  renderBody(doc, data, layout);
  stampHeadersFooters(doc, {
    title: `${PRODUCT_NAME} ${TITLE}`,
    company: scope === 'device' && device ? device.name : `${num(totals.activeDeviceCount)} firewalls`,
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
 * @param {object} [options] `{deviceId}` narrows to the intents one firewall
 *   participates in; omit for the whole estate.
 * @returns {Promise<Buffer|null>} null only when a named device does not exist.
 */
async function generateSegmentationPosturePdf(pool, options = {}) {
  const data = await buildSegmentationPostureData(pool, options);
  if (!data) return null;
  return renderSegmentationPosturePdf(data);
}

module.exports = {
  TITLE,
  NOT_MEASURED_MARK,
  VERDICT_COLOR,
  VERDICT_ORDER,
  VIOLATION_VERDICTS,
  ACTION_TEXT,
  verdictColor,
  verdictLabel,
  verdictDetail,
  verdictRank,
  isViolation,
  isUnmeasurable,
  intentLabel,
  canCell,
  trafficCell,
  unmeasurableReason,
  truncationNote,
  headlineSentence,
  buildSegmentationPostureData,
  renderSegmentationPosturePdf,
  generateSegmentationPosturePdf,
};
