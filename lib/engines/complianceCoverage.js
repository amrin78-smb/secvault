// lib/engines/complianceCoverage.js
//
// ⛔ WHAT THIS FIXES: "NIST 42%" was the one place SecVault overclaimed.
//
// `/compliance` printed five per-standard percentages side by side and let each
// one stand for that framework's compliance posture. Measured on the live fleet
// on 2026-09-22, the library behind those five numbers is FORTY-FIVE checks,
// and a check carries a `standards` ARRAY, so the five denominators are:
//
//     CIS_V8 44 · ISO_27001 35 · PCI_DSS 21 · SANS 12 · NIST 7
//
// Seven. Of those seven, three are vendor-scoped
// (`fortinet-admin-access-untrusted-zone`, `paloalto-admin-access-untrusted-zone`,
// `paloalto-mgmt-not-from-untrusted`) so at most six can ever run on one
// firewall, and four of the seven are generic firewall hygiene wearing a
// framework's name (`rule-no-any-any-allow`, `rule-logging-enabled-on-rules`,
// `rule-has-explicit-deny-all`, `rule-no-external-to-internal-access`).
//
// A bare "NIST 42%" invites the reader to conclude the firewall is 42% of the
// way to NIST. It is not that. It is the share of SecVault's own seven
// NIST-mapped checks that passed. Both sentences are about the same arithmetic
// and only one of them is true, and the true one cannot be told without the
// denominator travelling with the figure.
//
// ⛔ THIS IS THE SAME BUG CLASS AS EVERYTHING ELSE IN THIS CODEBASE, INVERTED.
// Elsewhere the danger is a failed read recorded as an affirmative value. Here
// it is a real, correctly-computed measurement of a SMALL thing presented as a
// measurement of a LARGE one. The arithmetic was never wrong; the claim around
// it was. So nothing here changes a score — every figure in this file is passed
// IN by a caller that already computed it, and this module only ever states
// what it rests on.
//
// ⛔ AND IT MUST NOT REPLACE ONE OVERCLAIM WITH A FABRICATED DENOMINATOR.
// "21 of about 300 PCI DSS requirements" would be worse than the bare 49%: it
// looks like a measurement, it would be quoted, and this codebase does not hold
// — and cannot derive — how many testable requirements any of these frameworks
// publishes. So the refusal is EXPLICIT and it is part of the output
// (COVERAGE_CLAIM below), not a comment. What IS known is stated: how many
// checks the library holds, how many carry the mapping, how many apply here,
// how many ran, how many produced a gradeable answer.
//
// PURE. Data in, data out. No pool, no clock, no queries — the callers
// (`app/(dashboard)/compliance/page.js`, the standards page, and
// `lib/engines/complianceReport.js`) already load every number this needs, and
// keeping it pure is what lets the PDF engine and a React server component
// share one judgement instead of wording it twice and drifting.
//
// CommonJS, dependency-free apart from `lib/evidence.js` (also pure CommonJS) —
// `complianceReport.js` is required by `services/engine-worker.js` under plain
// node, which cannot load ESM.

'use strict';

const { isRenderableEvidence } = require('../evidence');

/**
 * ⛔ THE ONE CLAIM THIS FEATURE MAKES, exported so a test can hold it to it
 * (the same device `applicationView`'s IMPACT_CLAIM uses). It renders verbatim
 * to customers, so it is product prose: it names what the denominator IS and
 * refuses, in as many words, to imply the other one.
 */
const COVERAGE_CLAIM =
  'Every percentage here is the share of SecVault’s own mapped checks that pass. '
  + 'SecVault does not hold a count of the requirements a framework publishes, so no figure '
  + 'here states how much of that framework is covered.';

/**
 * How much EVIDENCE sits behind a per-standard percentage, in distinct checks
 * that produced a gradeable answer.
 *
 * ⛔ THE BASIS IS AN ABSOLUTE COUNT, NOT A SHARE OF THE LIBRARY. Seven checks
 * is seven checks whether the library holds 45 or 4,500 — a ratio would let a
 * standard become "broadly evidenced" because the library shrank around it.
 *
 * ⛔ THE BANDS ARE A SECVAULT POLICY AND THEY ARE A JUDGEMENT, NOT A
 * MEASUREMENT. `thin` at 7 or fewer is chosen because a single-digit number of
 * checks cannot characterise a published framework and must not be allowed to
 * look as though it does; `broad` at 20 or more is a substantial share of the
 * 45 checks that exist. Live, those bands land: NIST 7 thin · SANS 12 moderate
 * · PCI DSS 16 moderate · ISO 27001 30 broad · CIS v8 36 broad — which is the
 * ordering a reader would get from the counts themselves, which is the point.
 *
 * ⛔ `unknown` IS NOT `none`. "We could not determine how many checks ran" and
 * "no check ran" are different facts, and the second is the one a reader can
 * act on. Neither may render as a grade.
 */
const GRADE_THIN_MAX = 7;
const GRADE_BROAD_MIN = 20;

/**
 * ⛔ THE SAME BANDS DO NOT HOLD AT DEVICE GRAIN, AND THAT WAS MEASURED RATHER
 * THAN ASSUMED — TWICE, because the library changed between the two readings
 * and a single number with no library size beside it would have gone stale
 * inside a day.
 *
 * The bands above were chosen against a 45-check library at STANDARD grain,
 * where the five mapped counts are 7/12/21/35/44. A DEVICE can only ever be
 * asked the checks its own vendor admits, so its ceiling is a property of its
 * VENDOR. Measured on the six-vendor mock fleet (`secvault_mock`):
 *
 * ── 2026-11-12, library 45 checks ────────────────────────────────────────
 *   scoping: shared 10 · fortinet 18 · paloalto 14 · cisco_asa 3 ·
 *            checkpoint/sangfor/forcepoint NONE
 *   ceilings: 28 fortinet · 24 paloalto · 13 cisco_asa · 10 the other three
 *
 *     MOCK-FP-DC-07          forcepoint  78%   9 gradeable of 10 applicable
 *     MOCK-CP-Perimeter-04   checkpoint  78%   9 of 10
 *     MOCK-SANGFOR-Branch-06 sangfor     78%   9 of 10
 *     MOCK-ASA-Edge-05       cisco_asa   73%  11 of 13
 *     MOCK-FGT-Branch-01     fortinet    60%  25 of 28
 *     MOCK-FGT-Edge-02       fortinet    40%  25 of 28
 *     MOCK-PAN-DC-01         paloalto    38%  21 of 24
 *     MOCK-UNREACHABLE-03    cisco_asa    —    0 of 13 (every check `na`)
 *
 * ⛔ THAT IS THE DEFECT IN ONE TABLE: the three vendors the library held NO
 * checks for scored HIGHEST, and under the standard-grain bands all three would
 * have graded `moderate` (9 > GRADE_THIN_MAX). A firewall assessed on nine
 * checks is not moderately evidenced — nine was nearly everything the library
 * could ask of it, which is a fact about SecVault's vendor coverage and not
 * about the firewall.
 *
 * ── 2026-11-12, later the same day, library 74 checks ─────────────────────
 * Vendor coverage for the three bare vendors landed (checkpoint 10, forcepoint
 * 10, sangfor 9), so the scoping is now shared 10 · fortinet 18 · paloalto 14 ·
 * checkpoint 10 · forcepoint 10 · sangfor 9 · cisco_asa 3, and the ceilings are
 * 28 · 24 · 20 · 20 · 19 · 13. Re-measured:
 *
 *     MOCK-SANGFOR-Branch-06 sangfor     78%   9 gradeable of 19 applicable
 *     MOCK-FP-DC-07          forcepoint  70%  10 of 20
 *     MOCK-CP-Perimeter-04   checkpoint  70%  10 of 20
 *     (the other five hold no findings at all in this state — 0 of 13/24/28)
 *
 * ⛔ THE BAND JUSTIFICATION SURVIVED THAT CHANGE, WHICH IS WHY IT IS THE ONE
 * WRITTEN DOWN. `thin` runs to 13 at device grain because 13 is cisco_asa's
 * FULL applicable count — the largest number of checks this library can ever
 * put to a firewall of the vendor it covers least — so a device at or below it
 * cannot have been broadly measured, by construction. That sentence was true at
 * 45 checks and is still true at 74. It is NOT a round number chosen to fit.
 * ⛔ If cisco_asa's own coverage is ever filled in, this constant has to be
 * re-derived from the new lowest ceiling IN THE SAME COMMIT, and re-measured
 * rather than guessed.
 *
 * `broad` stays at 20 (GRADE_BROAD_MIN), unchanged — raising it to 25 would
 * have made paloalto, whose ceiling is 24, incapable of ever grading broad
 * however completely it was assessed.
 *
 * ⛔ IT IS STILL AN ABSOLUTE COUNT, NEVER A SHARE OF `applicable`. A ratio
 * would grade the Check Point's 9-of-10 as the best-evidenced device on the
 * fleet, which is exactly the reading this file exists to prevent — the same
 * argument the standard-grain note above makes about a shrinking library.
 *
 * Nothing has landed in 14-19 on either reading; a band may be empty.
 */
const DEVICE_GRADE_THIN_MAX = 13;
const DEVICE_GRADE_BROAD_MIN = GRADE_BROAD_MIN;

const GRADES = ['unknown', 'none', 'thin', 'moderate', 'broad'];

const GRADE_LABEL = {
  unknown: 'Evidence not known',
  none: 'No evidence',
  thin: 'Thin evidence',
  moderate: 'Moderate evidence',
  broad: 'Broad evidence',
};

/**
 * Pips for the strength meter, in the hueless unmeasured/hatch vocabulary the
 * rest of the product already uses. Deliberately NOT a severity colour and
 * NOT a percentage: how well a thing is known is a different axis from how bad
 * it is, and an evidence grade is neither good news nor bad news.
 */
const GRADE_PIP_TOTAL = 3;
const GRADE_PIPS = { unknown: 0, none: 0, thin: 1, moderate: 2, broad: 3 };

/** A count that may be absent. ⛔ Never returns a guessed 0. */
function num(n) {
  return n === null || n === undefined || !Number.isFinite(Number(n)) ? null : Number(n);
}

/** Renders a count, or the em-dash that means "not measured". */
function show(n) {
  const v = num(n);
  return v === null ? '—' : String(v);
}

function plural(n, one, many) {
  return Number(n) === 1 ? one : (many || `${one}s`);
}

/**
 * ⛔ A SUBTRACTION IS ONLY A MEASUREMENT IF BOTH TERMS WERE MEASURED. This
 * file's whole job is to stop a number appearing without its basis, so a
 * derived gap computed from an absent input is exactly the defect it exists to
 * prevent — and it would print as a reassuring "0 checks did not run".
 */
function gap(a, b) {
  const x = num(a);
  const y = num(b);
  if (x === null || y === null) return null;
  return Math.max(0, x - y);
}

function gradeFor(answeredChecks) {
  const n = num(answeredChecks);
  if (n === null) return 'unknown';
  if (n <= 0) return 'none';
  if (n <= GRADE_THIN_MAX) return 'thin';
  if (n < GRADE_BROAD_MIN) return 'moderate';
  return 'broad';
}

/**
 * The same judgement for ONE FIREWALL's whole assessment — see the measurement
 * beside DEVICE_GRADE_THIN_MAX for why the thin band is wider here.
 *
 * ⛔ `null` is `unknown`, identically to gradeFor: "we could not count the
 * checks behind this firewall's score" is not "no check ran", and only the
 * second is something an audit would fix.
 */
function deviceGradeFor(answeredChecks) {
  const n = num(answeredChecks);
  if (n === null) return 'unknown';
  if (n <= 0) return 'none';
  if (n <= DEVICE_GRADE_THIN_MAX) return 'thin';
  if (n < DEVICE_GRADE_BROAD_MIN) return 'moderate';
  return 'broad';
}

/**
 * Builds the coverage statement for ONE standard.
 *
 * Every figure is supplied by the caller. Nothing is recomputed and no score
 * arithmetic happens here — `scorePct` is carried through verbatim so the
 * statement and the figure it qualifies can never disagree.
 *
 * @param {Object} input
 * @param {string} input.standard         key, e.g. 'NIST'
 * @param {string} [input.label]          display label, e.g. 'NIST'
 * @param {'device'|'fleet'} [input.scope]
 * @param {number|null} input.libraryTotal   checks in the whole library (45 live)
 * @param {number|null} input.mapped         library checks carrying this mapping
 * @param {number|null} [input.applicable]   mapped checks the target's vendor admits.
 *   null means NOT KNOWN or not a single-vendor scope — never "none apply".
 * @param {number|null} [input.evaluatedChecks] DISTINCT mapped checks that produced a finding
 * @param {number|null} [input.answeredChecks]  DISTINCT mapped checks that produced pass/fail/warning
 * @param {{pass:number,fail:number,warning:number,na:number}|null} [input.findings]
 *   raw finding rows in scope. On a fleet these are device x check PAIRS.
 * @param {number|null} [input.deviceCount] devices in scope, for the unit wording
 * @param {number|null} [input.scorePct]   the figure being qualified, already computed
 */
function buildStandardCoverage(input) {
  const i = input || {};
  const standard = i.standard || null;
  const label = i.label || standard || 'this standard';
  const scope = i.scope === 'fleet' ? 'fleet' : 'device';

  const libraryTotal = num(i.libraryTotal);
  const mapped = num(i.mapped);
  const applicable = num(i.applicable);
  const evaluatedChecks = num(i.evaluatedChecks);
  const answeredChecks = num(i.answeredChecks);
  const deviceCount = num(i.deviceCount);
  const scorePct = num(i.scorePct);

  const f = i.findings || null;
  const findings = f
    ? { pass: num(f.pass), fail: num(f.fail), warning: num(f.warning), na: num(f.na) }
    : { pass: null, fail: null, warning: null, na: null };

  // ⛔ THE LIBRARY READ IS THE ONE THING THAT CAN MAKE THIS WHOLE STATEMENT
  // UNAVAILABLE, and a failed read must say so rather than print "0 of 0
  // checks map to NIST" — which is a claim, and a false one that reads as
  // "SecVault does not support this standard".
  const available = libraryTotal !== null && mapped !== null;

  const notApplicable = gap(mapped, applicable);
  const neverRan = applicable === null ? gap(mapped, evaluatedChecks) : gap(applicable, evaluatedChecks);
  const unanswerable = gap(evaluatedChecks, answeredChecks);

  const grade = gradeFor(answeredChecks);
  const findingUnit = scope === 'fleet' ? 'firewall-check results' : 'checks';

  // ── the sentences ────────────────────────────────────────────────────────
  //
  // Split into parts rather than one blob so the page can lay them out and the
  // PDF can join them, without two files wording the same judgement twice.

  const headline = available
    ? `${mapped} of ${libraryTotal} ${plural(mapped, 'check')} in SecVault’s library are mapped to ${label}`
    : `The number of SecVault library checks mapped to ${label} could not be read`;

  const detailParts = [];
  if (available) {
    if (applicable !== null && notApplicable !== null && notApplicable > 0) {
      detailParts.push(
        scope === 'fleet'
          ? `${applicable} apply to the vendors on this fleet`
          : `${applicable} apply to this firewall’s vendor`
      );
    }
    detailParts.push(
      evaluatedChecks === null
        ? 'how many of them ran here is not known'
        : `${evaluatedChecks} ran${scope === 'fleet' && deviceCount !== null ? ` across ${deviceCount} ${plural(deviceCount, 'firewall')}` : ''}`
    );
    if (unanswerable !== null && unanswerable > 0) {
      detailParts.push(
        `${unanswerable} could not be assessed at all and ${plural(unanswerable, 'is', 'are')} excluded from the score`
      );
    }
    if (answeredChecks !== null) {
      detailParts.push(
        `the ${scorePct === null ? 'score' : `${scorePct}%`} rests on ${answeredChecks} ${plural(answeredChecks, 'check')}`
      );
    }
  }
  const detail = detailParts.length > 0 ? `${detailParts.join('; ')}.` : '';

  // ⛔ THE REFUSAL, PER STANDARD AND BY NAME. The generic claim is also
  // exported, but a reader looking at the NIST card needs it to say NIST.
  const caveat =
    `SecVault holds no count of the requirements ${label} publishes, so this figure does not state `
    + `how much of ${label} is covered — only how many of SecVault’s own checks mapped to ${label} pass.`;

  // ⛔ TWO FORMS, AND THE DIFFERENCE IS WHETHER THE CLAIM IS ALREADY ADJACENT.
  // `basis` states only what is known; `statement` adds the per-standard
  // refusal. A surface that already prints COVERAGE_CLAIM beside the figure
  // (the report's fleet summary, the two coverage panels) uses `basis`, because
  // repeating the same disclaimer five times in one eyeful is how a reader
  // learns to skip it — and the one they then skip is the one that matters.
  // A surface showing ONE standard on its own uses `statement`.
  const basis = [`${label}:`, headline + (detail ? ';' : '.'), detail]
    .filter(Boolean)
    .join(' ');
  const statement = [basis, caveat].filter(Boolean).join(' ');

  /** Short enough for a table cell or a column header. */
  const cell = available ? `${mapped} of ${libraryTotal}` : '—';

  return {
    standard,
    label,
    scope,
    available,
    libraryTotal,
    mapped,
    applicable,
    evaluatedChecks,
    answeredChecks,
    notApplicable,
    neverRan,
    unanswerable,
    findings,
    findingUnit,
    deviceCount,
    scorePct,
    grade,
    gradeLabel: GRADE_LABEL[grade],
    pips: GRADE_PIPS[grade],
    pipTotal: GRADE_PIP_TOTAL,
    headline,
    detail,
    caveat,
    basis,
    statement,
    cell,
  };
}

/**
 * The same thing for every standard the UI shows, keyed by standard.
 *
 * @param {{key:string,label:string}[]} standards
 * @param {(key:string)=>Object} per  returns the per-standard input for one key
 * @param {Object} [shared]           fields common to every standard
 */
function buildCoverageSet(standards, per, shared = {}) {
  const out = {};
  for (const s of standards || []) {
    const extra = typeof per === 'function' ? (per(s.key) || {}) : {};
    out[s.key] = buildStandardCoverage({
      ...shared,
      ...extra,
      standard: s.key,
      label: s.label || s.key,
    });
  }
  return out;
}

/**
 * The evidence-drawer descriptor for one standard's coverage.
 *
 * ⛔ REUSES THE EXISTING DRAWER RATHER THAN INVENTING A SECOND EXPLANATION
 * SURFACE. `lib/evidence.js` already owns the shape, the violet mark, the
 * "what could not be measured" section and the rule that an all-clear is
 * forbidden while coverage is incomplete. A parallel mechanism for this one
 * figure would be a second affordance to learn and a second place to drift.
 *
 * Returns null when there is nothing honest to show — the mark then does not
 * render at all, rather than opening onto a shrug.
 */
function coverageEvidence(coverage) {
  const c = coverage || null;
  if (!c) return null;

  const row = (text, value) => '  ' + String(text).padEnd(31, ' ') + String(value).padStart(5, ' ');
  const lines = [
    'score = round(100 × pass ÷ (pass + fail + warning))',
    `        over the checks carrying a ${c.label} mapping only`,
    '',
    row('checks in SecVault’s library', show(c.libraryTotal)),
    row(`mapped to ${c.label}`, show(c.mapped)),
  ];
  if (c.applicable !== null) {
    lines.push(row(
      c.scope === 'fleet' ? 'apply to this fleet’s vendors' : 'apply to this firewall’s vendor',
      show(c.applicable)
    ));
  }
  lines.push(
    row('evaluated here', show(c.evaluatedChecks)),
    row('produced a gradeable answer', show(c.answeredChecks)),
    '  ' + '─'.repeat(36),
    row('evidence', c.gradeLabel),
    '',
    '⛔ The denominator is SecVault’s own mapped checks.',
    `   No count of ${c.label}’s published requirements exists here,`,
    '   so this is not a measure of framework coverage.'
  );

  const inputs = [
    { label: 'Checks in SecVault’s library', value: show(c.libraryTotal) },
    {
      label: `Mapped to ${c.label}`,
      value: show(c.mapped),
      note: 'one check commonly carries several mappings, so the five standards do not sum to the library',
    },
  ];
  if (c.applicable !== null) {
    inputs.push({
      label: c.scope === 'fleet' ? 'Apply to this fleet’s vendors' : 'Apply to this firewall’s vendor',
      value: show(c.applicable),
      note: 'a vendor-scoped check can never run elsewhere',
    });
  }
  inputs.push({ label: 'Evaluated here', value: show(c.evaluatedChecks) });
  inputs.push({
    label: 'Produced a gradeable answer',
    value: show(c.answeredChecks),
    note: 'pass, fail or warning — the checks the percentage is computed over',
  });
  if (c.findings && c.findings.na !== null) {
    inputs.push({
      label: `Not assessable (${c.findingUnit})`,
      value: show(c.findings.na),
      note: 'excluded from the score entirely',
    });
  }
  inputs.push({ label: 'Evidence behind the figure', value: c.gradeLabel });
  inputs.push({ label: 'Score', value: c.scorePct === null ? '—' : `${c.scorePct}%` });

  // ── what could not be measured ───────────────────────────────────────────
  const unmeasured = [];

  // ⛔ ALWAYS FIRST, AND ALWAYS PRESENT. This is the gap the whole feature
  // exists for, and it never closes: it is not a collection failure that a
  // later run could fix, it is a limit on what this product claims to know.
  unmeasured.push({
    label: `How much of ${c.label} this covers is not known`,
    reason:
      `SecVault’s library is a curated set of firewall configuration and ruleset checks. It holds `
      + `no inventory of the requirements ${c.label} publishes, and a total invented for one would be `
      + `quoted as though it had been measured. So the denominator stated here is the only one that `
      + `exists: SecVault’s own mapped checks.`,
  });

  if (!c.available) {
    unmeasured.push({
      label: 'The library check counts could not be read',
      reason:
        'Without them there is no denominator to state, so this figure is shown with the caveat '
        + 'rather than with its basis. It is reported as unreadable rather than as zero — '
        + '"no checks map to this standard" would be a claim, and a false one.',
    });
  }

  if (c.notApplicable !== null && c.notApplicable > 0) {
    unmeasured.push({
      label: `${c.notApplicable} mapped ${plural(c.notApplicable, 'check')} cannot apply here`,
      reason:
        'These checks are scoped to a vendor this target is not, so they can never run and are not '
        + 'part of the figure in either direction. Live on this fleet, three of the seven NIST-mapped '
        + 'checks are vendor-scoped, which is why at most six can ever run on one firewall.',
    });
  }

  if (c.neverRan !== null && c.neverRan > 0) {
    unmeasured.push({
      label: `${c.neverRan} applicable ${plural(c.neverRan, 'check')} produced no result here`,
      reason:
        'No finding is recorded for them in this scope, so they are absent from the figure rather '
        + 'than passing or failing in it. An audit run is what closes this gap.',
    });
  }

  if (c.unanswerable !== null && c.unanswerable > 0) {
    unmeasured.push({
      label: `${c.unanswerable} ${plural(c.unanswerable, 'check')} could not be assessed at all`,
      reason:
        'The question cannot be put to this target — it needs telemetry a configuration snapshot '
        + 'never carries, or it is inherently per-rule. Nothing an operator changes on the firewall '
        + 'would make it answerable, so it is excluded from the score rather than counted against it. '
        + 'The findings are still written and still listed, with reasons.',
    });
  }

  if (c.grade === 'thin' || c.grade === 'none' || c.grade === 'unknown') {
    unmeasured.push({
      label:
        c.grade === 'unknown'
          ? 'How many checks the figure rests on is not known'
          : c.grade === 'none'
            ? 'No check produced a gradeable answer'
            : `The figure rests on ${c.answeredChecks} ${plural(c.answeredChecks, 'check')}`,
      reason:
        c.grade === 'thin'
          ? 'A single-digit number of checks cannot characterise a published framework. The '
            + 'percentage is arithmetically correct over those checks and is not a framework score; '
            + 'read it as a finding about those checks, not as a posture.'
          : 'Without a gradeable answer there is no percentage to read, which is why one is not '
            + 'shown as zero. Nothing was measured in either direction.',
    });
  }

  const ev = {
    title:
      c.scorePct === null
        ? `${c.label} — nothing gradeable`
        : `${c.label} ${c.scorePct}% — what it is computed over`,
    claim: COVERAGE_CLAIM,
    formula: lines.join('\n'),
    inputs,
    unmeasured,
    source: 'Compliance coverage engine',
    rule: 'SecVault compliance policy — a percentage states the checks it was computed over',
  };

  // ⛔ Checked here, not trusted from the call site — the same guard the drawer
  // itself applies, so a descriptor that could not render never reaches a mark.
  return isRenderableEvidence(ev) ? ev : null;
}

// ── DEVICE GRAIN ──────────────────────────────────────────────────────────
//
// ⛔ WHAT THIS ADDS, AND WHY THE GUARD ABOVE DID NOT ALREADY COVER IT.
// Everything above keys coverage on the STANDARD. Nothing keyed it on the
// DEVICE, so a per-firewall percentage still travelled alone — and that is the
// axis on which this product's own signature bug bites hardest, because the
// denominator varies by VENDOR rather than by anything the customer did.
// Measured on the mock fleet (table beside DEVICE_GRADE_THIN_MAX): a Check
// Point at 78% on 9 gradeable checks rendered identically to a Fortinet at 60%
// on 25, and a Palo Alto's 38% on 21 looked like the worst firewall on the
// fleet beside three 78%s resting on nine checks each. The vendor the library
// covers least scored highest, and no surface said so.
//
// Same contract as buildStandardCoverage: PURE, every figure supplied by the
// caller, and `scorePct` carried through VERBATIM. No arithmetic changes here.

/**
 * ⛔ THE ONE CLAIM AT DEVICE GRAIN, exported so a test can hold it to it. It
 * names the denominator and refuses the two readings a bare per-firewall
 * percentage invites: that the figure is comparable between firewalls of
 * different vendors, and that a high one means a well-assessed firewall.
 */
const DEVICE_COVERAGE_CLAIM =
  'A firewall’s percentage is the share of the SecVault checks that could be answered on it '
  + 'that passed. How many that is depends on how many checks SecVault holds for that vendor, '
  + 'so two firewalls’ percentages are not comparable unless both rest on a similar number '
  + 'of checks.';

/**
 * The coverage statement for ONE FIREWALL's compliance assessment.
 *
 * @param {Object} input
 * @param {string} [input.deviceId]
 * @param {string} [input.deviceName]
 * @param {string} [input.vendor]        the slug, for the caveat wording
 * @param {string} [input.vendorLabel]   display label; falls back to the slug
 * @param {number|null} input.libraryTotal  checks in the whole library
 * @param {number|null} input.applicable    library checks THIS vendor admits
 *   (vendor-null shared checks plus this vendor's own). null means NOT KNOWN —
 *   never "none apply".
 * @param {number|null} input.evaluatedChecks  ⛔ DISTINCT checks with a finding
 * @param {number|null} input.answeredChecks   ⛔ DISTINCT checks that produced
 *   pass/fail/warning. ⛔ NOT a count of finding ROWS summed across standards:
 *   a check carries a `standards` ARRAY, so the per-standard tallies count one
 *   check several times. On ONE device a finding row and a check coincide
 *   (verified live: finding_rows === distinct_checks for all 8 mock firewalls),
 *   which is exactly what makes the mistake invisible until the figures are
 *   aggregated. The guard below catches the summed form.
 * @param {{pass:number,fail:number,warning:number,na:number}|null} [input.findings]
 * @param {number|null} [input.scorePct]  the figure being qualified, already computed
 */
function buildDeviceCoverage(input) {
  const i = input || {};
  const deviceId = i.deviceId || null;
  const deviceName = i.deviceName || null;
  const vendor = i.vendor || null;
  const vendorLabel = i.vendorLabel || vendor || null;
  const who = deviceName || 'this firewall';

  const libraryTotal = num(i.libraryTotal);
  const applicable = num(i.applicable);
  const evaluatedChecks = num(i.evaluatedChecks);
  const answeredChecksRaw = num(i.answeredChecks);
  const scorePct = num(i.scorePct);

  const f = i.findings || null;
  const findings = f
    ? { pass: num(f.pass), fail: num(f.fail), warning: num(f.warning), na: num(f.na) }
    : { pass: null, fail: null, warning: null, na: null };

  // ⛔ A DENOMINATOR LARGER THAN THE SET OF QUESTIONS THAT CAN BE ASKED IS NOT
  // A DENOMINATOR. Two things produce it: the two-units confusion above (the
  // per-standard rows summed — measured on the mock fleet at the 45-check
  // reading, that yields 26 for the Check Point against 10 applicable checks
  // and 68 for a Fortinet against 28), or genuinely stale findings left behind
  // by a device whose vendor was changed after it was audited. Both are reported as
  // `unknown` with the reason, because the honest answer is that the basis
  // could not be established — never a confident count that cannot be true.
  const bound = applicable !== null
    ? applicable
    : (libraryTotal !== null ? libraryTotal : null);
  const overBound = (n) => n !== null && bound !== null && n > bound;
  const inconsistent = overBound(answeredChecksRaw) || overBound(evaluatedChecks);
  const answeredChecks = inconsistent ? null : answeredChecksRaw;

  const available = libraryTotal !== null && applicable !== null && !inconsistent;

  const notApplicable = gap(libraryTotal, applicable);
  const neverRan = gap(applicable, evaluatedChecks);
  const unanswerable = gap(evaluatedChecks, answeredChecks);

  const grade = deviceGradeFor(answeredChecks);

  // ── the sentences ────────────────────────────────────────────────────────

  const headline = available
    ? `${applicable} of ${libraryTotal} SecVault ${plural(applicable, 'check')} can be asked of ${who}`
      + (vendorLabel ? ` (${vendorLabel})` : '')
    : inconsistent
      ? `The number of SecVault checks behind ${who}’s score could not be established`
      : `How many SecVault checks can be asked of ${who} could not be read`;

  const detailParts = [];
  if (available) {
    detailParts.push(
      evaluatedChecks === null
        ? 'how many of them ran is not known'
        : `${evaluatedChecks} ran`
    );
    if (unanswerable !== null && unanswerable > 0) {
      detailParts.push(
        `${unanswerable} could not be assessed at all and ${plural(unanswerable, 'is', 'are')} excluded from the score`
      );
    }
    if (answeredChecks === 0) {
      // ⛔ "the score rests on 0 checks" invites a 0% to be read as the score.
      // There is no score here, and the sentence has to say so outright.
      detailParts.push('none produced a gradeable answer, so there is no percentage to read');
    } else if (answeredChecks !== null) {
      detailParts.push(
        `the ${scorePct === null ? 'score' : `${scorePct}%`} rests on ${answeredChecks} ${plural(answeredChecks, 'check')}`
      );
    }
  }
  const detail = detailParts.length > 0 ? `${detailParts.join('; ')}.` : '';

  // ⛔ THE CAVEAT IS ABOUT COMPARISON, which is the device-grain reading that
  // goes wrong. The standard-grain caveat refuses a framework total; this one
  // refuses a league table, because side by side on one page that is what a
  // column of bare percentages becomes.
  // ⛔ AND IT MAY NOT SAY "THIS PERCENTAGE" WHERE THERE IS NONE. A firewall
  // with nothing gradeable has no figure to be incomparable with, and a caveat
  // about one implies a figure the reader then goes looking for.
  const caveat = inconsistent
    ? `The checks behind ${who}’s score could not be counted, so this percentage is shown without `
      + 'its basis rather than beside a number that cannot be right.'
    : `How many checks SecVault holds for ${vendorLabel || 'a vendor'} is a property of SecVault, not of `
      + `${who}, so `
      + (scorePct === null || answeredChecks === 0
        ? 'how thoroughly this firewall can be assessed at all differs from a firewall of another '
          + 'vendor.'
        : 'this percentage is not comparable with a firewall assessed on a different number of '
          + 'checks.');

  const basis = [`${who}:`, headline + (detail ? ';' : '.'), detail].filter(Boolean).join(' ');
  const statement = [basis, caveat].filter(Boolean).join(' ');

  /** Short enough for a table cell. ⛔ Never "0 of 0" on a failed read. */
  const cell = answeredChecks === null
    ? '—'
    : (applicable === null ? `${answeredChecks}` : `${answeredChecks} of ${applicable}`);

  return {
    deviceId,
    deviceName,
    vendor,
    vendorLabel,
    scope: 'device',
    available,
    inconsistent,
    libraryTotal,
    applicable,
    evaluatedChecks,
    answeredChecks,
    notApplicable,
    neverRan,
    unanswerable,
    findings,
    scorePct,
    grade,
    gradeLabel: GRADE_LABEL[grade],
    pips: GRADE_PIPS[grade],
    pipTotal: GRADE_PIP_TOTAL,
    headline,
    detail,
    caveat,
    basis,
    statement,
    cell,
  };
}

/**
 * The same thing for a list of devices, keyed by device id.
 *
 * @param {{deviceId:string,deviceName:string,vendor:string}[]} devices
 * @param {(deviceId:string)=>Object} per  the per-device input for one id
 * @param {Object} [shared]                fields common to every device
 */
function buildDeviceCoverageSet(devices, per, shared = {}) {
  const out = {};
  for (const d of devices || []) {
    if (!d || !d.deviceId) continue;
    const extra = typeof per === 'function' ? (per(d.deviceId) || {}) : {};
    out[d.deviceId] = buildDeviceCoverage({
      ...shared,
      ...extra,
      deviceId: d.deviceId,
      deviceName: d.deviceName,
      vendor: d.vendor,
    });
  }
  return out;
}

/**
 * The evidence-drawer descriptor for one firewall's coverage. Same reasoning as
 * coverageEvidence(): reuse the one drawer rather than invent a second
 * explanation surface. Returns null when there is nothing honest to show.
 */
function deviceCoverageEvidence(coverage) {
  const c = coverage || null;
  if (!c) return null;

  const who = c.deviceName || 'this firewall';
  const row = (text, value) => '  ' + String(text).padEnd(31, ' ') + String(value).padStart(5, ' ');
  const lines = [
    'score = round(100 × pass ÷ (pass + fail + warning))',
    `        over the checks that could be answered on ${who}`,
    '',
    row('checks in SecVault’s library', show(c.libraryTotal)),
    row(
      c.vendorLabel ? `can be asked of a ${c.vendorLabel}` : 'can be asked of this vendor',
      show(c.applicable)
    ),
    row('evaluated here', show(c.evaluatedChecks)),
    row('produced a gradeable answer', show(c.answeredChecks)),
    '  ' + '─'.repeat(36),
    row('evidence', c.gradeLabel),
    '',
    '⛔ The denominator depends on the vendor, not on the firewall.',
    '   A percentage resting on fewer checks is not a better',
    '   result — it is a thinner measurement.',
  ];

  const inputs = [
    { label: 'Checks in SecVault’s library', value: show(c.libraryTotal) },
    {
      label: c.vendorLabel ? `Can be asked of a ${c.vendorLabel}` : 'Can be asked of this vendor',
      value: show(c.applicable),
      note: 'the shared firewall checks plus the ones written for this vendor; the rest can never run here',
    },
    { label: 'Evaluated here', value: show(c.evaluatedChecks) },
    {
      label: 'Produced a gradeable answer',
      value: show(c.answeredChecks),
      note: 'pass, fail or warning — the checks the percentage is computed over',
    },
  ];
  if (c.findings && c.findings.na !== null) {
    inputs.push({
      label: 'Not assessable (checks)',
      value: show(c.findings.na),
      note: 'excluded from the score entirely',
    });
  }
  inputs.push({ label: 'Evidence behind the figure', value: c.gradeLabel });
  inputs.push({ label: 'Score', value: c.scorePct === null ? '—' : `${c.scorePct}%` });

  // ── what could not be measured ───────────────────────────────────────────
  const unmeasured = [];

  // ⛔ ALWAYS FIRST, ALWAYS PRESENT, and it never closes: the number of checks
  // SecVault holds for a vendor is not something an audit run can improve.
  unmeasured.push({
    label: 'How thoroughly this vendor can be assessed is a limit of SecVault',
    reason:
      'SecVault’s library is a curated set of firewall configuration and ruleset checks, and it '
      + 'holds a different number of them for each vendor. A firewall whose vendor has few checks '
      + 'is measured against few checks, and its percentage is arithmetically correct over those '
      + 'and says nothing about the questions that were never put to it.',
  });

  if (c.inconsistent) {
    unmeasured.push({
      label: 'The number of checks behind this score could not be established',
      reason:
        'More checks were reported as answered than can be asked of this firewall at all. That is '
        + 'either a miscount or findings left behind by an earlier vendor on the same record, so '
        + 'the basis is reported as unknown rather than as a number that cannot be right.',
    });
  } else if (!c.available) {
    unmeasured.push({
      label: 'The library check counts could not be read',
      reason:
        'Without them there is no denominator to state, so the figure is shown with its caveat '
        + 'rather than with its basis. It is reported as unreadable rather than as zero — '
        + '"no checks apply to this firewall" would be a claim, and a false one.',
    });
  }

  if (c.notApplicable !== null && c.notApplicable > 0) {
    unmeasured.push({
      label: `${c.notApplicable} library ${plural(c.notApplicable, 'check')} cannot apply here`,
      reason:
        'These checks are written for other vendors, so they can never run on this firewall and are '
        + 'not part of the figure in either direction. They are the reason two firewalls’ '
        + 'percentages can rest on very different amounts of evidence.',
    });
  }

  if (c.neverRan !== null && c.neverRan > 0) {
    unmeasured.push({
      label: `${c.neverRan} applicable ${plural(c.neverRan, 'check')} produced no result here`,
      reason:
        'No finding is recorded for them on this firewall, so they are absent from the figure '
        + 'rather than passing or failing in it. An audit run is what closes this gap.',
    });
  }

  if (c.unanswerable !== null && c.unanswerable > 0) {
    unmeasured.push({
      label: `${c.unanswerable} ${plural(c.unanswerable, 'check')} could not be assessed at all`,
      reason:
        'The question cannot be put to this firewall — it needs telemetry a configuration snapshot '
        + 'never carries, or it is inherently per-rule. Nothing an operator changes on the firewall '
        + 'would make it answerable, so it is excluded from the score rather than counted against '
        + 'it. The findings are still written and still listed, with reasons.',
    });
  }

  if (c.grade === 'thin' || c.grade === 'none' || c.grade === 'unknown') {
    unmeasured.push({
      label:
        c.grade === 'unknown'
          ? 'How many checks the figure rests on is not known'
          : c.grade === 'none'
            ? 'No check produced a gradeable answer on this firewall'
            : `The figure rests on ${c.answeredChecks} ${plural(c.answeredChecks, 'check')}`,
      reason:
        c.grade === 'thin'
          ? 'That is a thin basis for a compliance percentage, and it is thin because of how many '
            + 'checks SecVault holds for this vendor rather than because of anything on the '
            + 'firewall. Read the figure as a finding about those checks, and do not rank this '
            + 'firewall against one assessed on more.'
          : 'Without a gradeable answer there is no percentage to read, which is why one is not '
            + 'shown as zero. Nothing was measured in either direction.',
    });
  }

  const ev = {
    title:
      c.scorePct === null
        ? `${who} — nothing gradeable`
        : `${who} ${c.scorePct}% — what it is computed over`,
    claim: DEVICE_COVERAGE_CLAIM,
    formula: lines.join('\n'),
    inputs,
    unmeasured,
    source: 'Compliance coverage engine',
    rule: 'SecVault compliance policy — a percentage states the checks it was computed over',
  };

  return isRenderableEvidence(ev) ? ev : null;
}

module.exports = {
  COVERAGE_CLAIM,
  DEVICE_COVERAGE_CLAIM,
  GRADES,
  GRADE_LABEL,
  GRADE_PIPS,
  GRADE_PIP_TOTAL,
  GRADE_THIN_MAX,
  GRADE_BROAD_MIN,
  DEVICE_GRADE_THIN_MAX,
  DEVICE_GRADE_BROAD_MIN,
  gradeFor,
  deviceGradeFor,
  buildStandardCoverage,
  buildCoverageSet,
  coverageEvidence,
  buildDeviceCoverage,
  buildDeviceCoverageSet,
  deviceCoverageEvidence,
};
