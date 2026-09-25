'use strict';
// lib/matchedRuleEvidence.js
//
// ⛔ "MATCHED NOTHING" AND "MATCHED RULES WE CAN NO LONGER NAME" EXPORTED
// IDENTICALLY — an empty cell either way, in the EVIDENCE column of a
// compliance export an auditor reads. That is CLAUDE.md's "a failed read is NOT
// a measurement" rule in the highest-stakes column in the product, and this
// module exists to keep the two apart.
//
// `audit_findings.matched_rule_ids` is a snapshot of `firewall_rules.id` taken
// when the audit ran. `firewall_rules` is **fully DELETE+reinserted on every
// collection** (see `collectAndStore` and CLAUDE.md's adapter contract), so
// those ids are regenerated wholesale on the next pull: an id recorded at audit
// time is not guaranteed to exist at export time, and a rule may also have been
// collected with a NULL `rule_name`. Every call site resolved them with
// `.map(id => map.get(id)).filter(Boolean)` (or, on the detail page, an
// `id = ANY($1)` that simply returned fewer rows), so an unresolvable id
// vanished with no trace and no count.
//
// ⛔ WHAT THIS MODULE MAY NOT DO, and each of these was available and refused:
//   - invent a name;
//   - print a bare UUID where a name goes, which reads as a name to anyone who
//     has not seen a rule id before;
//   - say "(deleted)". We know only that the id is not in the ruleset we hold
//     NOW. A failed collection, a partial pull, a device re-added, a rule
//     renamed through a reinsert — each produces the same absence, and naming
//     one of them as the cause would be a fabricated fact standing in for a
//     missing one, which is the bug this module was written to remove.
//
// ⛔ THE COUNT IS THE PRODUCT, NOT THE LIST. Following
// `lib/engines/vpnDetections.js`'s `unverifiable` / `unverifiableTotal`
// convention: the names we DO hold are listed, and the number we do NOT hold
// travels beside them and is always exact. A caller may shorten the list; it
// may never shorten the count.
//
// Pure: no pool, no clock, no I/O. CommonJS so `tests/` can require it and the
// App Router can `import` it, exactly as `lib/csv.js` and `lib/evidence.js` do.

/**
 * Read a rule name out of whatever the caller's lookup map holds.
 *
 * Two shapes are in use and both are legitimate: the CSV route resolves
 * `SELECT id, rule_name` into a Map(id -> name string), while the two pages
 * resolve whole rule rows into a Map(id -> row) because they also render the
 * addresses/services. Normalising here rather than at each call site is what
 * keeps ONE implementation of the count — CLAUDE.md warns repeatedly that two
 * files deciding the same question independently eventually disagree, and the
 * one that disagreed quietly would be the one writing the audit document.
 *
 * ⛔ An empty string is NOT a name. A rule collected with `rule_name = ''` is
 * as unnameable as one collected with NULL, and letting `''` through would put
 * an invisible entry in a semicolon-joined list — the same empty cell this
 * module exists to prevent, one layer down.
 */
function nameFromEntry(entry) {
  if (entry === null || entry === undefined) return null;
  const raw = typeof entry === 'object' ? entry.rule_name : entry;
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  return trimmed === '' ? null : trimmed;
}

/**
 * Resolve a finding's recorded rule ids against the ruleset held today.
 *
 * @param {string[]} matchedRuleIds  `audit_findings.matched_rule_ids`, as stored.
 * @param {Map} rulesById            Map(id -> rule row | rule name). May be
 *                                   null/undefined, which resolves NOTHING —
 *                                   deliberately distinct from an empty
 *                                   `matchedRuleIds`, and reported as such.
 * @returns {{
 *   total: number, names: string[], namedCount: number,
 *   notInRuleset: number, unnamedInRuleset: number, unusableId: number,
 *   unnamedTotal: number
 * }}
 */
function resolveMatchedRules(matchedRuleIds, rulesById) {
  const ids = Array.isArray(matchedRuleIds) ? matchedRuleIds : [];
  const lookup = rulesById instanceof Map ? rulesById : null;

  const names = [];
  let notInRuleset = 0;
  let unnamedInRuleset = 0;
  let unusableId = 0;

  for (const id of ids) {
    // ⛔ An entry that is not a usable id gets its OWN bucket rather than being
    // folded into "not in the current ruleset". The two send a reader to
    // different places: one is a question about the firewall's ruleset, the
    // other is a defect in what SecVault stored. Collapsing them would report a
    // storage bug as a fact about the customer's firewall.
    if (typeof id !== 'string' || id.trim() === '') {
      unusableId += 1;
      continue;
    }
    if (!lookup || !lookup.has(id)) {
      notInRuleset += 1;
      continue;
    }
    const name = nameFromEntry(lookup.get(id));
    if (name === null) unnamedInRuleset += 1;
    else names.push(name);
  }

  return {
    total: ids.length,
    names,
    namedCount: names.length,
    notInRuleset,
    unnamedInRuleset,
    unusableId,
    unnamedTotal: notInRuleset + unnamedInRuleset + unusableId,
  };
}

/**
 * One sentence naming how many matched rules SecVault cannot name, and why.
 * `null` when every recorded id resolved to a name — and `null` ALSO when the
 * finding recorded no ids at all, because "this check matched nothing" is a
 * complete answer that needs no caveat.
 *
 * ⛔ THE PER-REASON NUMBER IS ALWAYS PRINTED, even when there is only one
 * reason and it therefore repeats the leading figure. Deciding per call whether
 * a number is redundant is a branch that can be got wrong silently; a reader
 * seeing "2 ... (2 not in the current ruleset)" loses nothing.
 */
function matchedRulesNote(resolution) {
  if (!resolution || resolution.total === 0 || resolution.unnamedTotal === 0) return null;
  const reasons = [];
  if (resolution.notInRuleset > 0) {
    reasons.push(`${resolution.notInRuleset} not in the current ruleset`);
  }
  if (resolution.unnamedInRuleset > 0) {
    reasons.push(`${resolution.unnamedInRuleset} collected without a name`);
  }
  if (resolution.unusableId > 0) {
    reasons.push(`${resolution.unusableId} recorded with an unreadable id`);
  }
  const noun = resolution.total === 1 ? 'matched rule' : 'matched rules';
  return `${resolution.unnamedTotal} of ${resolution.total} ${noun} could not be named (${reasons.join(', ')})`;
}

/**
 * Hover/`aria` text for the on-screen marker. States the mechanism and stops
 * short of the cause.
 *
 * ⛔ The last sentence is load-bearing and must not be trimmed for length: a
 * reader who assumes the rules were deleted will close a finding that is still
 * live on the firewall.
 */
function matchedRulesReason(resolution) {
  const note = matchedRulesNote(resolution);
  if (!note) return null;
  return (
    `${note}. Rule ids are recorded when the audit runs, and a firewall's whole ruleset is ` +
    'replaced on every collection, so an id can stop resolving. This is not a statement that ' +
    'those rules were removed from the firewall — only that SecVault cannot name them now. ' +
    'Re-run the audit to re-evaluate this check against the ruleset held today.'
  );
}

/**
 * The CSV "Matched Rules" cell.
 *
 * ⛔ ONE COLUMN, NOT A NEW ONE. This export is a file customers already save,
 * script against and attach to audits, and the header list is defended in
 * `app/api/compliance/[deviceId]/route.js` for that reason. A caveat that only
 * appears in a column an existing consumer does not read is a caveat nobody
 * sees, so it goes in the cell it qualifies.
 *
 * ⛔ The note is bracketed so it cannot be mistaken for a rule name by a reader
 * or by a script splitting on '; ', and it is ASCII so it survives a CSV this
 * export deliberately writes without a BOM.
 *
 *   no ids              -> ''                        (unchanged: matched nothing)
 *   all named           -> 'a; b'                    (unchanged)
 *   partly named        -> 'a [2 of 3 matched rules could not be named (...)]'
 *   none named          -> '[3 of 3 matched rules could not be named (...)]'
 */
function matchedRulesCell(resolution) {
  if (!resolution || resolution.total === 0) return '';
  const joined = resolution.names.join('; ');
  const note = matchedRulesNote(resolution);
  if (!note) return joined;
  return joined === '' ? `[${note}]` : `${joined} [${note}]`;
}

module.exports = {
  resolveMatchedRules,
  matchedRulesNote,
  matchedRulesReason,
  matchedRulesCell,
};
