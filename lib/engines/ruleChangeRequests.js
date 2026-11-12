// lib/engines/ruleChangeRequests.js
//
// The rule-cleanup loop: propose rules for removal, hand the list to whoever
// edits the firewall, then VERIFY against the re-collected ruleset whether they
// actually went.
//
// ⛔ THE VERIFY HALF IS THE WHOLE POINT. Listing unused rules is not novel —
// ManageEngine Firewall Analyzer has done it for years, inferring usage from
// logs. What SecVault can do and FWA cannot is close the loop: it already
// re-collects the ruleset on a schedule, so it can state whether the change was
// made instead of asking someone to remember. If this ever degrades into an
// export button, the feature has lost its reason to exist.
//
// ⛔ AN UNMEASURED RULE MAY NEVER ENTER A REQUEST. `firewall_rules.hit_count` is
// tri-state — a real count, a genuine 0, or NULL meaning NOT MEASURED — and 164
// of 1,716 rules on the live fleet are NULL because their vendor/transport
// cannot report hit counts at all (Fortinet SSH, Sangfor, Palo Alto SSH).
// "We cannot tell whether this rule is used" is not a reason to delete it, and
// a cleanup list that quietly includes those rules is the failed-read-as-a-fact
// bug with a delete button attached. This module refuses them; it does not warn
// and continue.
//
// ⛔ THE BAR IS THE DEVICE'S OWN COUNTER, AND LOG EVIDENCE DOES NOT CLEAR IT BY
// DEFAULT — A3, 2026-09-25. `ruleHitCorrelation.js` can now also answer "unused"
// from syslog, and that answer carries a GRADE (`usageGrade` /
// `deletionEvidence`):
//
//   'device'    the firewall reported its own counter.
//   'log-id'    matched or proven absent by the vendor's own rule ID. On this
//               fleet that is Fortinet: 61,835 rollup rows, a rule id on every
//               one.
//   'log-name'  by rule NAME only. Every Palo Alto here — 80,203 rollup rows,
//               rule id NULL on ALL of them.
//
// ⛔ IF THIS FUNCTION IS EVER WIDENED TO ACCEPT LOG EVIDENCE, IT MAY ACCEPT ONLY
// `deletionEvidence === true`. A name is neither unique nor stable across a
// config change, so a rule RENAMED during the log window reads as having had no
// traffic while it is passing some — and the act authorised here is DELETING IT
// FROM A FIREWALL. `tests/ruleHitCorrelation.test.js` pins the grading;
// `tests/ruleChangeRequests.test.js` pins that this gate reads `hit_count`, so
// widening it is a deliberate edit to a failing test rather than a quiet one.
//
// ⛔ v2.225.0 ADDED AN APPROVAL STEP AND THREE NON-DELETION REQUEST KINDS, AND
// NEITHER TOUCHES THE SENTENCE ABOVE. Approval gates SUBMISSION and lives in
// its own column; it can never produce a `verified`. The non-deletion kinds
// (modification/addition/object change) reach `submitted` and STOP, carrying
// `not_supported` — this file has exactly ONE verifier and it answers exactly
// one question: is the rule absent from a ruleset collected after submission.
// See the APPROVAL_STATES and REQUEST_TYPES blocks below.
//
// CommonJS — required by services/engine-worker.js under plain node.

'use strict';

const VALID_STATUS = new Set(['draft', 'submitted', 'verified', 'partial', 'abandoned']);

// Finding types that describe a rule which could be REMOVED. Deliberately not
// every finding type: `overly_permissive` means "tighten this", not "delete
// it", and putting it in a deletion list would invite exactly the wrong action.
const REMOVABLE_FINDING_TYPES = new Set(['unused', 'redundant', 'shadow']);

// ── Approval step (v2.225.0) ──────────────────────────────────────────────
//
// ⛔ APPROVAL GATES SUBMISSION AND CAN NEVER PRODUCE A `verified`. It is a
// SECOND COLUMN beside `status`, not a new status, precisely so that no
// approval code path can reach the one value this feature exists to earn. A
// human saying "go ahead" is not evidence the change was made; `verified`
// comes only from verifyRequestsForDevice() finding the rules absent from a
// ruleset collected AFTER submission. If an approval ever advances a request
// past `submitted`, the product loses the claim its competition cannot make.
//
// ⛔ `not_required` IS THE DEFAULT, AND THE ASYMMETRY IS DELIBERATE — the same
// call lib/ldapRoles.js makes between "no mappings configured" (legacy mode,
// grant as before) and "no mapping matched" (refuse). Every request on every
// deployed server was raised with no approval step in existence; defaulting to
// `pending` would retroactively mark the whole history as awaiting an approval
// nobody can give for changes that already happened. Requiring approval is an
// explicit per-request choice by the requester.
//
// ⛔ AND THAT MEANS THIS IS A WORKFLOW AID, NOT AN ENFORCEMENT BOUNDARY, which
// is stated here rather than left to be discovered: nothing forces a request to
// be approval-gated, so a requester who does not want review simply does not
// ask for it. Making approval mandatory is an INSTALLATION POLICY and needs a
// setting plus a decision about every existing install — not a quiet change
// here.
const APPROVAL_STATES = Object.freeze(['not_required', 'pending', 'approved', 'rejected']);
const APPROVAL_NOT_REQUIRED = 'not_required';
const APPROVAL_PENDING = 'pending';
const APPROVAL_APPROVED = 'approved';
const APPROVAL_REJECTED = 'rejected';

// ── Request types (v2.225.0) ──────────────────────────────────────────────
//
// ⛔ THE VERIFIER IS NOT GENERALISED BY THIS. Deletion is verified by ABSENCE
// from the re-collected ruleset, which is a complete and checkable claim. A
// modification or an addition is NOT verifiable that way — the rule is present
// either way and the question is whether its CONTENT matches the ask, which
// needs a field-level comparison against what was requested in prose. Those
// types reach `submitted` and STOP, carrying an explicit `not_supported`
// verification state. Pointing this verifier at `config_diffs` to cover them is
// explicitly refused in .ai-codex/roadmap.md: a config diff says SOMETHING
// changed on the device, not that THIS request's instruction was carried out,
// and reporting the first as the second would be a plausible verdict with
// nothing behind it.
const REQUEST_TYPES = Object.freeze([
  'rule_deletion',
  'rule_modification',
  'rule_addition',
  'object_change',
]);
const DELETION_TYPE = 'rule_deletion';

// The item `outcome` for a request kind this product cannot verify.
//
// ⛔ DISTINCT FROM `unverifiable`, AND COLLAPSING THEM WOULD REPORT A
// CAPABILITY GAP AS A COLLECTION GAP. `unverifiable` means "no rules pull has
// succeeded since submission" — it clears itself the moment collection
// recovers, and the operator's action is to fix collection. `not_supported`
// means "SecVault cannot verify this KIND of change at all" — no collection
// will ever clear it, and the operator's action is to confirm it themselves.
// Rendering one as the other sends them to the wrong place.
const VERIFICATION_NOT_SUPPORTED = 'not_supported';

// The `finding_type` on an item nobody's analyser produced.
//
// ⛔ `finding_type` is NOT NULL and means "why this item is in the request".
// For a deletion that is the analyser's own finding (unused/redundant/shadow).
// For an operator-raised change there is no finding, and writing one of the
// analyser's words here would dress an operator's opinion up as a measurement.
// This value is deliberately not a member of any finding-type set in
// ruleAnalysis.js, so nothing can mistake it for one.
const OPERATOR_REQUEST_FINDING = 'operator_request';

/** Is this the one request kind whose completion SecVault can measure? */
function isDeletionType(requestType) {
  return requestType === DELETION_TYPE;
}

/**
 * ⛔ ABSENT MEANS `rule_deletion`; AN UNRECOGNISED VALUE DOES NOT. The two are
 * opposite instructions and must never be collapsed — the same asymmetry
 * ldapRoles.js draws between "no mappings configured" and "no mapping matched".
 *
 * `request_type` is NOT NULL DEFAULT 'rule_deletion', so a missing value cannot
 * come from a row: it comes from a caller or a projection written before the
 * column existed, and every such request IS a deletion. Treating that as
 * unverifiable instead would stamp real cleanup items `not_supported` — which
 * is TERMINAL, since the verifier only revisits pending/unverifiable ones — and
 * silently switch off the one claim this feature makes, fleet-wide, with every
 * signal still green.
 *
 * An unrecognised STRING is a different fact: we do not know what kind of
 * change it is, so nothing may claim to have verified it. That one falls
 * through to the unsupported branch.
 *
 * createRequest() applies exactly this rule to its own input, and
 * ruleChangeRequestReport.js's requestTypeOf() delegates here, so the engine,
 * the verifier and the document cannot disagree about what an old row is.
 */
function normaliseRequestType(raw) {
  if (raw === undefined || raw === null || raw === '') return DELETION_TYPE;
  return raw;
}

/**
 * Whether verification is possible for a request kind, and why not when it is
 * not. PURE.
 *
 * ⛔ AN UNRECOGNISED TYPE IS NOT VERIFIABLE. Fails closed: claiming we can
 * measure the completion of a change kind we do not recognise is the only
 * direction here that can manufacture a success.
 */
function verificationSupport(requestType) {
  if (isDeletionType(requestType)) {
    return { supported: true, reason: null };
  }
  if (requestType === 'rule_modification') {
    return {
      supported: false,
      reason:
        'SecVault cannot verify a rule MODIFICATION. The rule is present either way, so absence '
        + 'from the re-collected ruleset proves nothing, and whether its contents match what was '
        + 'asked for in words is not something this product measures.',
    };
  }
  if (requestType === 'rule_addition') {
    return {
      supported: false,
      reason:
        'SecVault cannot verify a rule ADDITION. A new rule appearing in the ruleset is not '
        + 'evidence that it is the rule that was asked for, and SecVault will not claim it is.',
    };
  }
  if (requestType === 'object_change') {
    return {
      supported: false,
      reason:
        'SecVault cannot verify an OBJECT change. The requested contents are described in words, '
        + 'and nothing here compares a collected object against them.',
    };
  }
  return {
    supported: false,
    reason:
      `Unrecognised request type "${requestType}" — SecVault will not claim to have verified a `
      + 'kind of change it does not recognise.',
  };
}

/**
 * Whether a request may be submitted, given its approval state. PURE, and the
 * single definition the route, the UI and submitRequest() all read.
 *
 * @returns {null|string} null to proceed, else the refusal in words.
 *
 * ⛔ UNRECOGNISED STATE REFUSES. Same call lib/rbac.js makes on an unknown
 * capability: an approval state we cannot interpret must not fall through to
 * "go ahead", because the one thing approval exists to do is hold a change
 * back.
 */
function submissionBlock(approvalState) {
  if (approvalState === APPROVAL_NOT_REQUIRED || approvalState === APPROVAL_APPROVED) return null;
  if (approvalState === APPROVAL_PENDING) {
    return 'This request is waiting for approval and cannot be submitted yet.';
  }
  if (approvalState === APPROVAL_REJECTED) {
    return 'This request was rejected and cannot be submitted. Raise a new request instead.';
  }
  return `Unrecognised approval state "${approvalState}" — refusing to submit.`;
}

/**
 * Candidate rules for a cleanup request on one device.
 *
 * ⛔ Returns BOTH the eligible rules and the ones excluded for being
 * unmeasured, because the caller must be able to show the exclusion rather than
 * silently present a shorter list. A cleanup screen that shows 21 candidates
 * without saying 9 more were withheld looks complete and is not.
 */
async function getCleanupCandidates(pool, deviceId) {
  const { rows } = await pool.query(
    // ⛔ The join is rar.rule_id -> firewall_rules.id, but the IDENTITY carried
    // forward is fr.rule_id_vendor. firewall_rules is DELETEd and reinserted on
    // every successful pull, so its UUID is NOT stable across collections — a
    // request keyed on it could never be verified against a later ruleset. This
    // is the same reason finding_acknowledgements keys on rule_id_vendor.
    `SELECT fr.rule_id_vendor,
            rar.finding_type,
            rar.severity,
            rar.detail,
            fr.rule_name,
            fr.hit_count,
            fr.enabled,
            fr.log_enabled,
            fa.status AS ack_status
       FROM rule_analysis_results rar
       JOIN firewall_rules fr ON fr.id = rar.rule_id
       LEFT JOIN finding_acknowledgements fa
              ON fa.device_id = rar.device_id
             AND fa.rule_id_vendor = fr.rule_id_vendor
             AND fa.finding_type = rar.finding_type
      WHERE rar.device_id = $1
        AND rar.finding_type = ANY($2::text[])
      ORDER BY rar.finding_type ASC, fr.rule_id_vendor ASC`,
    [deviceId, [...REMOVABLE_FINDING_TYPES]]
  );

  // ⛔ eligible and withheld rows share ONE shape. They differ only in whether
  // a `reason` is present and whether hitCount is a number. A caller must be
  // able to render a held-back rule in the same table as an offered one — if
  // showing the exclusion costs a second query, the exclusion is what gets
  // dropped, and a silently shorter list is exactly what this returns two
  // lists to prevent.
  //
  // ⛔ hitCount stays NULL on a withheld row. It is the unmeasured value that
  // got the rule withheld in the first place; defaulting it to 0 here would
  // reintroduce the exact claim the exclusion exists to refuse.
  const shape = (r) => ({
    ruleIdVendor: r.rule_id_vendor,
    ruleName: r.rule_name || null,
    findingType: r.finding_type,
    severity: r.severity || null,
    detail: r.detail || null,
    hitCount: r.hit_count === null || r.hit_count === undefined ? null : Number(r.hit_count),
    enabled: r.enabled === undefined ? null : r.enabled,
    // Snapshot at request time. ⛔ Once a rule is actually REMOVED there is no
    // firewall_rules row left to read this from, so an exported request would
    // lose the ability to say 'this rule could not appear in a log because
    // logging was off on it' — and silently fall back to reporting the absence
    // of log hits as evidence of no traffic. A caveat that disappears makes the
    // evidence look STRONGER than it was, which is the wrong direction for a
    // document justifying a deletion.
    logEnabled: r.log_enabled === undefined ? null : r.log_enabled,
  });

  const eligible = [];
  const withheld = [];
  for (const r of rows) {
    if (r.ack_status === 'dismissed') continue;
    // ⛔ SECOND EXCLUSION, same family as the first. rule_id_vendor is
    // nullable, and it is the ONLY identity that survives a ruleset
    // DELETE+reinsert. Without it the rule could be proposed for deletion and
    // then never verified — the request would sit unverifiable forever, which
    // is worse than not offering it, because it looks like progress.
    if (!r.rule_id_vendor) {
      withheld.push({
        ...shape(r),
        ruleIdVendor: null,
        reason:
          'This rule carries no vendor identifier, so SecVault could not confirm '
          + 'afterwards whether it was actually removed.',
      });
      continue;
    }
    // ⛔ NULL hit_count is the withheld case. `0` is fine — that is a MEASURED
    // zero and is precisely the evidence this feature runs on.
    if (r.hit_count === null || r.hit_count === undefined) {
      withheld.push({
        ...shape(r),
        reason:
          'Hit count was never measured for this rule — this vendor or transport '
          + 'cannot report one. Not evidence that the rule is unused.',
      });
      continue;
    }
    eligible.push({ ...shape(r), hitCount: Number(r.hit_count) });
  }
  return { eligible, withheld };
}

// Severity ranking, worst first. Used only to decide which finding gets the
// item's single `finding_type` column; every finding is kept in `evidence`
// regardless, so nothing is lost by the choice.
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const rankOf = (s) => (s && s in SEVERITY_RANK ? SEVERITY_RANK[s] : 5);

/**
 * Collapse per-finding candidate rows into one entry per RULE, keeping every
 * finding rather than letting the last one win.
 */
function mergeByRule(eligible) {
  const byId = new Map();
  for (const e of eligible) {
    const prev = byId.get(e.ruleIdVendor);
    const finding = { findingType: e.findingType, severity: e.severity, detail: e.detail };
    if (!prev) {
      byId.set(e.ruleIdVendor, { ...e, findings: [finding] });
      continue;
    }
    prev.findings.push(finding);
    // The primary is the WORST finding, not the first alphabetically. A rule
    // that is both `unused` and `shadow` is filed under whichever the analyser
    // rated more serious.
    if (rankOf(e.severity) < rankOf(prev.severity)) {
      prev.findingType = e.findingType;
      prev.severity = e.severity;
      prev.detail = e.detail;
    }
  }
  return byId;
}

const trimmed = (v) => (typeof v === 'string' && v.trim() !== '' ? v.trim() : null);

/**
 * Items for a DELETION request, from the measured cleanup candidates.
 *
 * ⛔ Re-checks eligibility server-side against getCleanupCandidates rather than
 * trusting the submitted list. The UI filters, but a filter is a convenience;
 * this is the guarantee. A caller that posts an unmeasured rule gets an error,
 * not a silently shortened request.
 */
async function prepareDeletionItems(pool, deviceId, ruleIds) {
  const wanted = Array.isArray(ruleIds) ? [...new Set(ruleIds.filter(Boolean))] : [];
  if (wanted.length === 0) throw new Error('Select at least one rule');

  // ⛔ `eligible` is one row per FINDING, but a request stores one item per
  // RULE (UNIQUE (request_id, rule_id_vendor)). 10 rules on the live fleet
  // carry two or three removable findings at once — Block-Line-Streaming is
  // unused AND shadowed AND redundant. Building the lookup with a plain
  // last-wins Map silently kept ONE of them, so the stored record understated
  // the case for removal by two thirds, and months later the exported request
  // would give a reviewer one reason where three were found. Merge instead.
  const { eligible } = await getCleanupCandidates(pool, deviceId);
  const byId = mergeByRule(eligible);
  const rejected = wanted.filter((id) => !byId.has(id));
  if (rejected.length > 0) {
    throw new Error(
      `These rules cannot be included because their usage was never measured, or they are `
      + `no longer cleanup candidates: ${rejected.join(', ')}`
    );
  }

  return wanted.map((id) => {
    const e = byId.get(id);
    return {
      ruleIdVendor: e.ruleIdVendor,
      ruleName: e.ruleName,
      findingType: e.findingType,
      hitCount: e.hitCount,
      // ⛔ NULL on a deletion request, per schema.sql: the ask IS the absence,
      // and inventing a sentence for it would put words in the requester's
      // mouth that a change board would read as their instruction.
      requestedChange: null,
      evidence: {
        severity: e.severity,
        detail: e.detail,
        enabled: e.enabled,
        logEnabled: e.logEnabled,
        // ⛔ EVERY finding, not just the primary. `finding_type` is one
        // column and a rule can be unused AND shadowed AND redundant; the
        // reviewer reading this months later needs all three reasons, and
        // re-deriving them later is impossible because firewall_rules and
        // rule_analysis_results are both rebuilt on every pull.
        findings: e.findings,
        findingTypes: e.findings.map((f) => f.findingType),
        // Stated explicitly so the exported request can say WHY, months
        // later, without re-deriving anything.
        justification:
          `${e.findings.map((f) => f.findingType).join(', ')}; `
          + `hit count measured at ${e.hitCount}`,
      },
    };
  });
}

/**
 * What the collected ruleset knows about a set of subject strings.
 *
 * ⛔ THREE OUTCOMES, AND THE TWO NEGATIVE ONES ARE NOT THE SAME. A device with
 * NO collected ruleset, and a read that FAILED, both mean "we cannot say
 * whether this rule exists" — not "it does not exist". Reporting either as
 * `false` would record our own gap as a fact about the firewall, which is this
 * codebase's signature bug.
 */
async function lookupRuleSubjects(pool, deviceId, subjects) {
  try {
    const { rows: countRows } = await pool.query(
      'SELECT count(*)::int AS n FROM firewall_rules WHERE device_id = $1::uuid',
      [deviceId]
    );
    const total = countRows[0] ? Number(countRows[0].n) : 0;
    if (!Number.isFinite(total) || total === 0) {
      return { state: 'no_ruleset', byId: new Map() };
    }
    const { rows } = await pool.query(
      `SELECT rule_id_vendor, rule_name, hit_count
         FROM firewall_rules
        WHERE device_id = $1::uuid
          AND rule_id_vendor = ANY($2::text[])`,
      [deviceId, subjects]
    );
    return {
      state: 'ok',
      byId: new Map(rows.filter((r) => r.rule_id_vendor).map((r) => [r.rule_id_vendor, r])),
    };
  } catch (err) {
    return { state: 'lookup_failed', byId: new Map(), error: err && err.message ? err.message : String(err) };
  }
}

// What a subject string IS, per request type. The label matters because the
// deletion path's subject is a VERIFICATION KEY and these are not.
const SUBJECT_KIND = {
  rule_modification: 'collected_rule_id',
  rule_addition: 'proposed_rule_label',
  object_change: 'network_object',
};

/**
 * Items for a NON-DELETION request.
 *
 * ⛔ HOW AN ITEM IS IDENTIFIED, AND WHY A FREE-TEXT SUBJECT IS ACCEPTABLE HERE
 * WHEN IT WOULD NOT BE ON A DELETION. `rule_id_vendor` is NOT NULL and is the
 * only identity column on an item, so every type must fill it. On a deletion it
 * must be the vendor's own id BECAUSE IT IS THE VERIFICATION KEY: it is the
 * string looked for in the next collected ruleset, and getCleanupCandidates
 * withholds any rule that has none, since the request could otherwise never be
 * confirmed. Nothing is ever verified on these types (verificationSupport()
 * refuses them), so the subject here is a LABEL FOR A HUMAN, not a key:
 *
 *   rule_modification  the rule id as the requester named it. Looked up in the
 *                      collected ruleset and the answer RECORDED, never used to
 *                      refuse — a rule missing from our snapshot may be present
 *                      on the firewall, and refusing an instruction because of
 *                      our own collection gap would be the wrong direction.
 *   rule_addition      THERE IS NO RULE TO REFERENCE YET, so the subject is the
 *                      requester's own label for the rule they intend to
 *                      create (normally the name they mean to give it). It is
 *                      explicitly NOT a vendor id and must never be read as
 *                      one; `subjectKind` says so in the stored evidence.
 *                      Looked up anyway, because a label that ALREADY names a
 *                      rule is worth saying out loud on the document — the
 *                      addition may be a duplicate.
 *   object_change      the object's name. Not looked up at all: it is not a
 *                      rule, and a `false` from a rule table would be a
 *                      meaningless negative.
 */
async function prepareChangeItems(pool, deviceId, requestType, rawItems) {
  const list = Array.isArray(rawItems) ? rawItems : [];
  if (list.length === 0) throw new Error('Add at least one item to the request');

  const cleaned = [];
  const seen = new Set();
  for (const raw of list) {
    const subject = trimmed(raw && raw.subject);
    const change = trimmed(raw && raw.requestedChange);
    if (!subject) {
      throw new Error(
        'Every item needs a subject — the rule or object the change applies to'
      );
    }
    // ⛔ A change request with no instruction cannot be acted on by the person
    // it is handed to, and SecVault cannot verify it either, so it would be a
    // row that asks for nothing and proves nothing.
    if (!change) {
      throw new Error(`Item "${subject}" has no requested change — say what should be changed`);
    }
    if (seen.has(subject)) {
      // UNIQUE (request_id, rule_id_vendor) would abort the whole transaction;
      // naming the duplicate is more use than a constraint violation.
      throw new Error(`"${subject}" appears twice in this request`);
    }
    seen.add(subject);
    cleaned.push({ subject, change });
  }

  const looksUp = requestType !== 'object_change';
  const lookup = looksUp
    ? await lookupRuleSubjects(pool, deviceId, cleaned.map((c) => c.subject))
    : { state: 'not_a_rule', byId: new Map() };

  const KNOWN_REASON = {
    no_ruleset:
      'No ruleset has been collected from this firewall, so SecVault cannot say whether this '
      + 'rule exists. That is a gap in our collection, not a statement about the firewall.',
    lookup_failed:
      "SecVault could not read this firewall's collected ruleset when the request was raised, "
      + 'so whether this rule exists is unknown.',
    not_a_rule:
      'This is a network object, not a rule, so SecVault did not look for it in the ruleset.',
  };

  const verification = verificationSupport(requestType);

  return cleaned.map(({ subject, change }) => {
    let subjectKnown = null;
    let subjectKnownReason = KNOWN_REASON[lookup.state] || null;
    if (lookup.state === 'ok') {
      subjectKnown = lookup.byId.has(subject);
      subjectKnownReason = null;
    }
    const row = lookup.state === 'ok' ? lookup.byId.get(subject) : null;

    // ⛔ hit_count_at_request is CONTEXT here, never justification, and only a
    // modification can have one at all: a rule that does not exist yet has no
    // counter, and borrowing the counter of whatever rule happens to share the
    // requester's label would be a fabricated number. Tri-state as always —
    // NULL where the vendor cannot report a count.
    const hitCount =
      requestType === 'rule_modification' && row && row.hit_count !== null && row.hit_count !== undefined
        ? Number(row.hit_count)
        : null;

    return {
      ruleIdVendor: subject,
      ruleName: (row && row.rule_name) || null,
      // ⛔ NOT an analyser finding type — see OPERATOR_REQUEST_FINDING.
      findingType: OPERATOR_REQUEST_FINDING,
      hitCount,
      requestedChange: change,
      evidence: {
        requestType,
        subject,
        subjectKind: SUBJECT_KIND[requestType] || 'unknown',
        subjectKnown,
        subjectKnownReason,
        requestedChange: change,
        // ⛔ Says out loud, in the stored record, that nothing here was
        // measured. The deletion path's justification quotes a hit counter;
        // this one must not pretend to.
        justification:
          `Raised by an operator as a ${requestType} request. This is an instruction, not a `
          + 'measurement: SecVault did not derive it from any analysis.',
        verification: VERIFICATION_NOT_SUPPORTED,
        verificationReason: verification.reason,
      },
    };
  });
}

/**
 * Create a request.
 *
 * @param {object} opts
 * @param {string}   opts.deviceId
 * @param {string}   [opts.requestType]  one of REQUEST_TYPES; defaults to
 *   `rule_deletion`, which names the only behaviour that existed before.
 * @param {string[]} [opts.ruleIds]      DELETION only: rule_id_vendor strings.
 * @param {object[]} [opts.items]        every other type: {subject, requestedChange}.
 * @param {boolean}  [opts.requiresApproval] true -> approval_state 'pending'.
 */
async function createRequest(pool, {
  deviceId,
  title,
  note,
  createdBy,
  ruleIds,
  requestType,
  items,
  requiresApproval,
} = {}) {
  if (!deviceId) throw new Error('deviceId is required');

  // ⛔ An absent type means the ORIGINAL behaviour, not a guess: every caller
  // that predates this column is asking for a deletion. An unrecognised one is
  // refused rather than defaulted, because defaulting would file somebody's
  // modification request as a deletion.
  const type = normaliseRequestType(requestType);
  if (!REQUEST_TYPES.includes(type)) {
    throw new Error(`Unknown request type "${type}"`);
  }

  const createdByName = trimmed(createdBy);
  const approvalState = requiresApproval === true ? APPROVAL_PENDING : APPROVAL_NOT_REQUIRED;
  // ⛔ An approval-gated request needs a NAMED requester, because the
  // self-approval refusal in approveRequest() is a comparison against this
  // value. Without it the approval step would silently stop being a second
  // pair of eyes. Refused at creation so the refusal is at the moment someone
  // can still do something about it.
  if (approvalState === APPROVAL_PENDING && !createdByName) {
    throw new Error(
      'An approval-gated request needs a named requester — SecVault could not establish who is '
      + 'raising this, and approval must be given by somebody else.'
    );
  }

  const prepared = isDeletionType(type)
    ? await prepareDeletionItems(pool, deviceId, ruleIds)
    : await prepareChangeItems(pool, deviceId, type, items);

  const defaultTitle = isDeletionType(type) ? 'Rule cleanup' : 'Rule change request';

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO rule_change_requests
         (device_id, title, note, created_by, status, request_type, approval_state)
            VALUES ($1, $2, $3, $4, 'draft', $5, $6)
         RETURNING *`,
      [deviceId, title || defaultTitle, note || null, createdByName, type, approvalState]
    );
    const request = rows[0];
    for (const e of prepared) {
      await client.query(
        `INSERT INTO rule_change_request_items
           (request_id, rule_id_vendor, rule_name, finding_type, hit_count_at_request, evidence,
            requested_change)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
        [
          request.id,
          e.ruleIdVendor,
          e.ruleName,
          e.findingType,
          e.hitCount,
          JSON.stringify(e.evidence),
          e.requestedChange,
        ]
      );
    }
    await client.query('COMMIT');
    return request;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * ⛔ SUBMISSION IS WHERE APPROVAL BITES, AND THE GUARD IS EXPRESSED TWICE —
 * once as a readable refusal from submissionBlock() and once as a WHERE clause
 * that cannot be bypassed by a caller that skipped the first. The same doubling
 * convention configRetention.js uses for its delete protections and cveHub.js
 * for its empty-range guard. An approval state the JS does not recognise is
 * refused by submissionBlock(); one that races in between the read and the
 * write is refused by the WHERE.
 */
async function submitRequest(pool, id) {
  const { rows } = await pool.query(
    `UPDATE rule_change_requests
        SET status = 'submitted', submitted_at = now()
      WHERE id = $1 AND status = 'draft'
        AND approval_state IN ('not_required', 'approved')
      RETURNING *`,
    [id]
  );
  if (rows.length > 0) return rows[0];

  // Refused. ⛔ SAY WHICH REFUSAL IT WAS: "this is not a draft" and "this is
  // waiting for approval" send the operator to completely different places,
  // and a single message for both would have them hunting for a state the
  // request is not in. The read happens ONLY on the failure path, so the
  // guarantee stays in the one WHERE clause above rather than becoming a
  // check-then-write race.
  const { rows: current } = await pool.query(
    'SELECT status, approval_state FROM rule_change_requests WHERE id = $1',
    [id]
  );
  if (current.length === 0) throw new Error('Only a draft request can be submitted');
  const block = submissionBlock(current[0].approval_state);
  if (block) throw new Error(block);
  throw new Error('Only a draft request can be submitted');
}

/**
 * Approve a pending request.
 *
 * ⛔ IT TOUCHES `approval_state` AND NOTHING ELSE — NOT `status`, NOT
 * `submitted_at`, NOT `verified_at`. An approval says "go ahead and make this
 * change"; it is not evidence the change was made. The request is still a
 * DRAFT afterwards and still has to be submitted. A test reads this statement's
 * SET clause and fails the build if `status` ever appears in it.
 *
 * ⛔ SELF-APPROVAL IS REFUSED, SERVER-SIDE, AND EXPRESSED TWICE. An approval
 * step whose approver can be the requester is decoration — it reads as a
 * control on screen and in an exported document while gating nothing. The
 * requester asked for a second pair of eyes; they cannot be those eyes.
 *
 * ⛔ AN UNKNOWN IDENTITY ON EITHER SIDE REFUSES. This is an authorisation-shaped
 * check, so it fails CLOSED: if SecVault cannot say who is approving, or cannot
 * say who raised it, it cannot say the two are different people. Unreachable
 * through the normal path (createRequest refuses a pending request with no
 * named requester, and the route takes the approver from the session) — guarded
 * anyway, because "unreachable today" is not a property a later caller
 * preserves.
 */
async function approveRequest(pool, id, { decidedBy } = {}) {
  const who = trimmed(decidedBy);
  if (!who) {
    throw new Error(
      'SecVault could not establish who is approving this request, so it will not record an '
      + 'approval.'
    );
  }

  const { rows: current } = await pool.query(
    'SELECT status, approval_state, created_by FROM rule_change_requests WHERE id = $1',
    [id]
  );
  if (current.length === 0) throw new Error('Request not found');
  const row = current[0];
  if (row.approval_state !== APPROVAL_PENDING || row.status !== 'draft') {
    throw new Error('Only a draft request that is waiting for approval can be approved');
  }
  const requester = trimmed(row.created_by);
  if (!requester) {
    throw new Error(
      'This request does not record who raised it, so SecVault cannot confirm the approver is '
      + 'somebody else.'
    );
  }
  if (requester.toLowerCase() === who.toLowerCase()) {
    throw new Error(
      'You raised this request, so you cannot approve it. Approval has to come from another '
      + 'administrator.'
    );
  }

  const { rows } = await pool.query(
    `UPDATE rule_change_requests
        SET approval_state = 'approved', approved_by = $2, approved_at = now()
      WHERE id = $1 AND status = 'draft' AND approval_state = 'pending'
        AND created_by IS NOT NULL
        AND lower(created_by) <> lower($2)
      RETURNING *`,
    [id, who]
  );
  if (rows.length === 0) {
    throw new Error('Only a draft request that is waiting for approval can be approved');
  }
  return rows[0];
}

/**
 * Reject a pending request.
 *
 * ⛔ TERMINAL FOR THIS REQUEST, AND THAT IS THE HONEST SHAPE. There is no path
 * back to `pending`: a rejected request is abandoned, and a better-justified
 * ask is a NEW request — which is what schema.sql's own comment describes, and
 * what keeps `rejected_reason` a record of one decision rather than the latest
 * of several.
 *
 * ⛔ THE ACTOR GOES IN `approved_by`, WHICH IS THE DECISION ACTOR, NOT A CLAIM
 * OF APPROVAL. There is no `rejected_by` column, and `approved_by` read beside
 * `approval_state = 'rejected'` is unambiguous: this is the person who made the
 * decision that the state records. Every renderer reads the two together.
 *
 * ⛔ A REASON IS REQUIRED. "No" with no reason cannot be acted on, and the
 * requester's only options would be to guess or to re-raise the same request.
 */
async function rejectRequest(pool, id, { decidedBy, reason } = {}) {
  const who = trimmed(decidedBy);
  if (!who) {
    throw new Error(
      'SecVault could not establish who is rejecting this request, so it will not record a '
      + 'rejection.'
    );
  }
  const why = trimmed(reason);
  if (!why) throw new Error('A rejection needs a reason the requester can act on');

  const { rows } = await pool.query(
    `UPDATE rule_change_requests
        SET approval_state = 'rejected', approved_by = $2, approved_at = now(),
            rejected_reason = $3
      WHERE id = $1 AND status = 'draft' AND approval_state = 'pending'
      RETURNING *`,
    [id, who, why]
  );
  if (rows.length === 0) {
    throw new Error('Only a draft request that is waiting for approval can be rejected');
  }
  return rows[0];
}

async function abandonRequest(pool, id, note) {
  const { rows } = await pool.query(
    // ⛔ The abandon reason goes in its own column. `note` is the INSTRUCTION
    // written for whoever edits the firewall; overwriting it with "changed our
    // minds" destroys the record of what was actually asked for, which is the
    // one thing an abandoned request is still useful for.
    `UPDATE rule_change_requests
        SET status = 'abandoned', abandon_reason = $2
      WHERE id = $1 AND status IN ('draft', 'submitted')
      RETURNING *`,
    [id, note || null]
  );
  if (rows.length === 0) throw new Error('Only a draft or submitted request can be abandoned');
  return rows[0];
}

/**
 * Verify every submitted request for one device against the CURRENT ruleset.
 *
 * ⛔ THE UNVERIFIABLE CASE IS THE IMPORTANT ONE. `firewall_rules` is DELETEd and
 * reinserted on every successful pull, so "the rule is absent" is only
 * meaningful if a pull has actually SUCCEEDED since the request was submitted.
 * Without that check, a device whose rule collection has been failing for a
 * week would report every requested rule as removed — turning a collection
 * outage into a fabricated success, which is the worst possible direction for
 * this feature to be wrong in.
 *
 * That is why devices.last_rules_collected_at exists: devices.last_collected_at
 * is stamped when ANY capability succeeded and cannot answer this question.
 *
 * Never throws — a verification problem must not break a collection run.
 */
async function verifyRequestsForDevice(pool, deviceId) {
  const result = {
    checked: 0,
    removed: 0,
    stillPresent: 0,
    unverifiable: 0,
    // ⛔ ITS OWN COUNTER, never folded into `unverifiable`. One is a collection
    // gap that clears itself; the other is a capability this product does not
    // have and never will for that request kind. A caller logging one figure
    // for both would report "verification is behind" about work that is not
    // waiting on anything.
    notSupported: 0,
    error: null,
  };
  try {
    const { rows: devRows } = await pool.query(
      'SELECT last_rules_collected_at FROM devices WHERE id = $1',
      [deviceId]
    );
    const lastRulesAt = devRows[0] ? devRows[0].last_rules_collected_at : null;

    const { rows: items } = await pool.query(
      `SELECT i.id, i.rule_id_vendor, r.submitted_at, r.request_type
         FROM rule_change_request_items i
         JOIN rule_change_requests r ON r.id = i.request_id
        WHERE r.device_id = $1
          AND r.status = 'submitted'
          AND i.outcome IN ('pending', 'unverifiable')`,
      [deviceId]
    );
    if (items.length === 0) return result;

    // ⛔ THE ABSENCE TEST IS ONLY VALID FOR A DELETION, AND THIS SPLIT IS WHERE
    // THAT IS ENFORCED. A rule_modification item's rule is PRESENT in the next
    // ruleset by definition, so running it through the loop below would stamp
    // it `still_present` — a plausible, confident verdict meaning nothing,
    // which is strictly worse than saying we cannot tell. An unrecognised
    // request_type lands on the unsupported side as well, because the test is
    // `isDeletionType`, an equality check, rather than "is it one of the three
    // kinds I know about" — so a kind added to the schema without a verifier
    // is classified, never measured.
    const deletionItems = [];
    const unsupportedItems = [];
    for (const it of items) {
      // ⛔ normaliseRequestType, not a bare read: an ABSENT type is a deletion
      // (the column's own default, and what every pre-column caller means),
      // while an unrecognised one falls to the unsupported branch.
      const kind = normaliseRequestType(it.request_type);
      (isDeletionType(kind) ? deletionItems : unsupportedItems).push(it);
    }

    for (const it of unsupportedItems) {
      result.notSupported += 1;
      // ⛔ `verified_at` stays NULL. Nothing was verified — a timestamp here
      // would read as "we checked at this time", and the whole point of this
      // state is that there is no check to run.
      await pool.query(
        `UPDATE rule_change_request_items
            SET outcome = $2, verified_at = NULL
          WHERE id = $1`,
        [it.id, VERIFICATION_NOT_SUPPORTED]
      );
    }

    // ⛔ The parent request of an unsupported item STAYS `submitted` for ever,
    // deliberately. It is not verified, not partial and not abandoned: it was
    // handed over and this product cannot say what happened next. Saying so
    // permanently is honest; promoting it on a timer or on a config diff would
    // be a verdict with nothing behind it.
    if (deletionItems.length === 0) return result;

    const { rows: present } = await pool.query(
      'SELECT rule_id_vendor FROM firewall_rules WHERE device_id = $1',
      [deviceId]
    );
    const live = new Set(present.map((p) => p.rule_id_vendor));

    for (const it of deletionItems) {
      result.checked += 1;
      // ⛔ A pull must have SUCCEEDED strictly after the request was submitted.
      // Equal timestamps are not good enough — a pull that ran in the same
      // instant cannot have seen the operator's change.
      const usable =
        lastRulesAt && it.submitted_at && new Date(lastRulesAt) > new Date(it.submitted_at);
      let outcome;
      if (!usable) outcome = 'unverifiable';
      else outcome = live.has(it.rule_id_vendor) ? 'still_present' : 'removed';

      if (outcome === 'removed') result.removed += 1;
      else if (outcome === 'still_present') result.stillPresent += 1;
      else result.unverifiable += 1;

      await pool.query(
        `UPDATE rule_change_request_items
            SET outcome = $2, verified_at = CASE WHEN $2 = 'unverifiable' THEN NULL ELSE now() END
          WHERE id = $1`,
        [it.id, outcome]
      );
    }

    // Roll the parent status up. ⛔ Only from MEASURED item outcomes — an
    // unverifiable item leaves the request submitted, never 'partial', because
    // partial would imply we looked and some were undone.
    await pool.query(
      // ⛔ Every branch is guarded by `EXISTS (… any item at all)`. Without it
      // the `NOT EXISTS (outcome <> 'removed')` test is VACUOUSLY TRUE for a
      // request with zero items, flipping it to 'verified' — a fabricated
      // success, in the one query in this feature that must never produce one.
      // createRequest guarantees at least one item so it is unreachable today;
      // it is guarded because "unreachable today" is not a property a later
      // caller preserves.
      //
      // ⛔ `verified_at` is stamped for 'partial' too. It means "when we
      // finished checking", not "when everything was done" — and a partial is
      // precisely the outcome an operator most wants dated, because it is the
      // one that needs a follow-up conversation.
      `UPDATE rule_change_requests r
          SET status = CASE
                WHEN EXISTS (SELECT 1 FROM rule_change_request_items i
                              WHERE i.request_id = r.id)
                 AND NOT EXISTS (SELECT 1 FROM rule_change_request_items i
                                  WHERE i.request_id = r.id AND i.outcome <> 'removed')
                  THEN 'verified'
                WHEN EXISTS (SELECT 1 FROM rule_change_request_items i
                              WHERE i.request_id = r.id AND i.outcome = 'removed')
                 AND NOT EXISTS (SELECT 1 FROM rule_change_request_items i
                                  WHERE i.request_id = r.id AND i.outcome IN ('pending', 'unverifiable'))
                  THEN 'partial'
                ELSE r.status END,
              verified_at = CASE
                WHEN EXISTS (SELECT 1 FROM rule_change_request_items i
                              WHERE i.request_id = r.id)
                 AND NOT EXISTS (SELECT 1 FROM rule_change_request_items i
                                  WHERE i.request_id = r.id AND i.outcome IN ('pending', 'unverifiable'))
                  THEN now() ELSE r.verified_at END
        WHERE r.device_id = $1 AND r.status = 'submitted'
          AND r.request_type = 'rule_deletion'`,
      [deviceId]
    );
  } catch (err) {
    result.error = err && err.message ? err.message : String(err);
  }
  return result;
}

async function listRequests(pool, deviceId) {
  const { rows } = await pool.query(
    `SELECT r.*,
            count(i.id)::int                                         AS item_count,
            count(i.id) FILTER (WHERE i.outcome = 'removed')::int    AS removed_count,
            count(i.id) FILTER (WHERE i.outcome = 'still_present')::int AS still_present_count,
            count(i.id) FILTER (WHERE i.outcome = 'unverifiable')::int  AS unverifiable_count,
            -- ⛔ Counted separately from unverifiable_count, so a list row can
            -- say "SecVault cannot verify this kind of change" rather than
            -- "verification is behind". The two have different first steps.
            count(i.id) FILTER (WHERE i.outcome = 'not_supported')::int AS not_supported_count
       FROM rule_change_requests r
       LEFT JOIN rule_change_request_items i ON i.request_id = r.id
      WHERE ($1::uuid IS NULL OR r.device_id = $1)
      GROUP BY r.id
      ORDER BY r.created_at DESC`,
    [deviceId || null]
  );
  return rows;
}

async function getRequest(pool, id) {
  const { rows } = await pool.query('SELECT * FROM rule_change_requests WHERE id = $1', [id]);
  if (rows.length === 0) return null;
  const { rows: items } = await pool.query(
    'SELECT * FROM rule_change_request_items WHERE request_id = $1 ORDER BY rule_id_vendor ASC',
    [id]
  );
  return { ...rows[0], items };
}

module.exports = {
  REMOVABLE_FINDING_TYPES,
  VALID_STATUS,
  // approval + request types
  APPROVAL_STATES,
  APPROVAL_NOT_REQUIRED,
  APPROVAL_PENDING,
  APPROVAL_APPROVED,
  APPROVAL_REJECTED,
  REQUEST_TYPES,
  DELETION_TYPE,
  VERIFICATION_NOT_SUPPORTED,
  OPERATOR_REQUEST_FINDING,
  isDeletionType,
  normaliseRequestType,
  verificationSupport,
  submissionBlock,
  // storage
  getCleanupCandidates,
  createRequest,
  submitRequest,
  approveRequest,
  rejectRequest,
  abandonRequest,
  verifyRequestsForDevice,
  listRequests,
  getRequest,
};
