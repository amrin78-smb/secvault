'use strict';

// lib/engines/ruleConsolidation.js
//
// RULES THAT DIFFER IN EXACTLY ONE FIELD, AND WHETHER MERGING THEM WOULD CHANGE
// POLICY. PURE — takes already-fetched `firewall_rules` rows (and, optionally,
// the device's `network_objects` rows), returns candidate groups. No pool, no
// queries, no clock.
//
// ── ⛔ THIS IS NOT `generalization`, AND THE DIFFERENCE IS WHY IT EXISTS ───
//
// `ruleAnalysis.js`'s `generalization` (and `shadow`/`redundant`/`correlation`)
// is a PAIRWISE SUBSUMPTION relation — "does rule S cover rule R" — computed by
// comparing every rule against every earlier rule. It is O(n²), and it is
// CAPPED: above `maxRulesForShadow` (1000) the whole pairwise block is SKIPPED,
// and `PAIRWISE_FINDING_TYPES` exists precisely so a consumer can tell "we did
// not run this" from "this found nothing".
//
// Consolidation is a different question with a different shape: O(n) grouping by
// a CANONICAL KEY. It asks "are these rows the same rule written N times with N
// different destinations", never "does one cover the other". So it needs no
// pairwise pass, has no cap, and works at any ruleset size — IDC FW's 721 rules
// included, where `generalization` is closest to its ceiling and `shadow` is one
// bad collection away from being skipped entirely.
//
// ⛔ AND IT NEEDS NO HIT COUNTS. Every usage-based cleanup analytic in this
// product is blocked on the five Fortinets, which report no hit counters at all
// (100% unmeasured — see `coverageRegister.js`). `unused` cannot fire there,
// rule cleanup refuses every rule there, and segmentation's "did it happen" is
// UNKNOWN there. This is the one cleanup analytic that is conclusive on those
// firewalls, because identity of a rule's own fields is a fact the device
// already reported.
//
// Measured on the live fleet 2026-09-25, across ENABLED rules on active devices:
// destination 54 groups / 71 removable rows, source 50 / 92, service 15 / 18 —
// ~181 rows. That is the CANDIDATE set. What each group is worth depends
// entirely on the section below.
//
// ── ⛔ THE SAFETY PROPERTY — THIS IS THE WHOLE ENGINE ─────────────────────
//
// A CONSOLIDATION CANDIDATE IS NOT PROVEN SAFE TO MERGE. A firewall evaluates
// rules IN ORDER, so merging rule 10 and rule 40 into one rule at position 10
// moves rule 40's traffic ABOVE rules 11-39. If any of those would have matched
// that traffic, the decision for it changes — on a firewall that means traffic
// that was denied is now allowed, or traffic that was allowed is now denied.
// Nothing about the two merged rows themselves reveals this; it is entirely a
// property of what sits BETWEEN them.
//
// So every group carries a verdict, and the verdict falls CLOSED:
//
//   `safe_to_merge`  no enabled rule between the members could match the
//                    traffic that would move, and every check reached a
//                    definite answer.
//   `needs_review`   an intervening rule might match (named), OR the check
//                    could not be determined at all.
//
// ⛔ AN UNDETERMINABLE CHECK IS `needs_review`, NEVER `safe_to_merge`. An
// unresolved object name, an FQDN, a rule with no sequence number, a field this
// engine does not model — each means we do not know whether policy would
// change. Falling open there proposes a firewall change that silently alters
// policy, which is strictly worse than proposing nothing: the operator makes
// the change, every signal stays green, and the hole is invisible.
//
// ⛔ THE MERGE POSITION IS ASSUMED TO BE THE LOWEST `sequence_number` IN THE
// GROUP, and the check is against exactly that. Merging at the highest position
// instead moves the EARLIER members DOWN past the same intervening rules, which
// is a different question this engine does not answer.
//
// ⛔ ADDRESS AND SERVICE RESOLUTION IS `objectResolver.js`'s, UNCHANGED — the
// same evaluator `topology.js`, `exposure.js` and `applicationView.js` reuse.
// Two files deciding "do these overlap" would eventually disagree, and the
// wrong one would be recommending firewall changes. The only arithmetic that
// lives here is interval OVERLAP over that module's output, because it exports
// containment (`matchesAddress`, a point test) and no overlap predicate.

const {
  buildObjectMap, resolveAddressField, resolveServiceField,
} = require('./objectResolver');

// ⛔ THE ONE CLAIM THIS ENGINE MAKES, exported so a renderer cannot quietly
// upgrade it and a test can pin it. `safe_to_merge` is a statement about RULE
// ORDER and nothing else.
const MERGE_CLAIM = 'These rules are identical except in one field, and no enabled rule between '
  + 'them could match the traffic a merge would move. Merging them is a proposal for a human to '
  + 'make on the firewall, not a verified-safe change.';

const VERDICTS = Object.freeze({
  SAFE: 'safe_to_merge',
  REVIEW: 'needs_review',
});

// The three fields a group may vary in. Nothing else: a rule differing in
// action, zones or logging is a DIFFERENT rule, not the same one written twice.
const VARYING_FIELDS = Object.freeze(['dst_addresses', 'src_addresses', 'services']);

const FIELD_LABEL = Object.freeze({
  dst_addresses: 'destination',
  src_addresses: 'source',
  services: 'service',
});

// ── ⛔ WHICH FIELDS ARE SETS AND WHICH ARE ORDERED ────────────────────────
//
// `lib/canonicalJson.js` exists because `jsonb` does not preserve KEY order,
// and its own warning is explicit: it canonicalises object keys and DELIBERATELY
// LEAVES ARRAYS ALONE, "because order is meaningful in an array and sorting one
// would make genuinely different values compare equal."
//
// ⛔ That is the right default and it is the WRONG TOOL HERE, so this file does
// not use `jsonEquivalent`. These particular arrays are not ordered: a firewall
// matches `src_addresses` as the UNION of its members, so `["A","B"]` and
// `["B","A"]` select exactly the same traffic and must key identically. Sorting
// them is not a shortcut past that warning — it is the claim that THIS field is
// a set, made explicitly, field by field, below.
//
// ⛔ AND THE INVERSE MISTAKE IS THE DANGEROUS ONE. `firewall_rules` is itself an
// ORDERED list, which is the entire subject of the interference check further
// down; sorting rules the way these fields are sorted would destroy the only
// fact this engine exists to check.
const SET_FIELDS = Object.freeze([
  'src_zones', 'dst_zones', 'src_addresses', 'dst_addresses', 'services', 'applications',
]);

// Scalars that must be identical for two rows to be the same rule. `log_enabled`
// and `nat_enabled` are here on purpose: merging a logged rule with an unlogged
// one silently changes what the firewall records, and `schedule`/`expiry_date`
// change WHEN it applies.
const SCALAR_FIELDS = Object.freeze([
  'action', 'schedule', 'log_enabled', 'nat_enabled', 'expiry_date',
]);

// ⛔ DELIBERATELY NOT IN THE KEY, and stated rather than left implied:
// `rule_name`, `comment`, `tags`, `hit_count`, `last_hit_at`, `collected_at`,
// `raw_rule`. None of them affects which traffic a rule matches or what the
// firewall does with it. A merge DOES lose the distinct names, comments and
// tags, so each group reports them — it is an auditability cost for a human to
// weigh, not a reason to refuse the grouping.
const IGNORED_FOR_KEY = Object.freeze(['rule_name', 'comment', 'tags', 'hit_count']);

const ANY_ALIASES = new Set(['any', 'all', 'any4', 'any6']);
const ALLOW_ACTIONS = new Set(['allow', 'permit', 'accept']);
const DENY_ACTIONS = new Set(['deny', 'drop', 'reject', 'block']);

// The canonical token for a wildcard field. ⛔ A null field, an empty array and
// `["any"]` all constrain nothing, so they must key the SAME — otherwise two
// rules that match identical traffic land in different groups and the saving is
// silently missed.
const ANY_TOKEN = '*';

/**
 * Coerce a jsonb field into a list of trimmed strings, preserving case.
 *
 * ⛔ A NON-ARRAY FIELD IS READ AS A ONE-ITEM SET, NEVER DROPPED AND NEVER
 * TREATED AS `any`. A malformed row must not crash the fleet analysis (rule:
 * this engine does not throw on bad input), and it must not FABRICATE a match
 * either. A weird value produces a weird key, a weird key matches nothing, and
 * a rule that groups with nothing produces no claim at all — which is the
 * correct outcome for a field we cannot read.
 */
function toList(value) {
  if (value === null || value === undefined) return null; // the `any` case
  const raw = Array.isArray(value) ? value : [value];
  const out = [];
  for (const item of raw) {
    if (item === null || item === undefined) continue;
    const s = typeof item === 'string' ? item.trim() : JSON.stringify(item);
    if (s && s.length > 0) out.push(s);
  }
  return out;
}

/** Is this field a wildcard? Same three spellings every engine here recognises. */
function isAnyField(value) {
  const list = toList(value);
  if (list === null || list.length === 0) return true;
  return list.some((s) => ANY_ALIASES.has(s.toLowerCase()));
}

/**
 * A set-valued field, canonicalised: lower-cased, de-duplicated, SORTED.
 * See the SET_FIELDS note above for why sorting is correct here and nowhere
 * near the rule list itself.
 */
function canonicalSet(value) {
  if (isAnyField(value)) return ANY_TOKEN;
  const items = [...new Set(toList(value).map((s) => s.toLowerCase()))].sort();
  return items.join(',');
}

/** Scalars, normalised so `null`, `undefined` and `''` cannot key differently. */
function canonicalScalar(value) {
  if (value === null || value === undefined) return '';
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value).trim().toLowerCase();
}

/**
 * allow/permit/accept are one decision; deny/drop/reject/block are another.
 * Anything else keeps its own spelling — an unrecognised verb must not be
 * folded in with a family it may not belong to.
 */
function actionCategory(rule) {
  const a = canonicalScalar(rule && rule.action);
  if (ALLOW_ACTIONS.has(a)) return 'allow';
  if (DENY_ACTIONS.has(a)) return 'deny';
  return a || 'unspecified';
}

/**
 * The key two rules must share to be "the same rule except for one field".
 *
 * @param {object} rule           a firewall_rules row
 * @param {string} varyingField   one of VARYING_FIELDS — excluded from the key
 * @returns {string}
 */
function canonicalKey(rule, varyingField) {
  const r = rule && typeof rule === 'object' ? rule : {};
  const parts = [
    // ⛔ Rules on different devices are NEVER the same rule, and `vdom` is a
    // separate evaluation context on a multi-VDOM Fortinet — `sequence_number`
    // runs contiguously ACROSS vdoms there (see ruleAnalysis's
    // isStrictlyEarlier), so without this two vdoms' rules would group together
    // and their "interference" would be computed across policies that never see
    // each other's traffic.
    `dev=${canonicalScalar(r.device_id)}`,
    `vdom=${canonicalScalar(r.vdom)}`,
    `act=${actionCategory(r)}`,
  ];
  for (const f of SCALAR_FIELDS) {
    if (f === 'action') continue; // already folded into the category above
    parts.push(`${f}=${canonicalScalar(r[f])}`);
  }
  for (const f of SET_FIELDS) {
    if (f === varyingField) continue;
    parts.push(`${f}=${canonicalSet(r[f])}`);
  }
  return parts.join('|');
}

// ─────────────────────────────────────────
// Interference — the safety check
// ─────────────────────────────────────────

/** A rule's sequence number as a real number, or null if it has none. */
function seqOf(rule) {
  const v = rule && rule.sequence_number;
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/**
 * ⛔ NEGATION IS A FIELD THIS ENGINE DOES NOT MODEL, and it inverts a field's
 * extent — so a "these address sets are disjoint" conclusion computed from the
 * literal list is exactly BACKWARDS for a negated field. `firewall_rules` has
 * no negation column, so the only trace is in `raw_rule`. A truthy top-level
 * key containing "negate" makes every comparison involving that rule
 * UNDETERMINED.
 *
 * ⛔ ABSENCE OF THE MARKER IS NOT PROOF OF ABSENCE — not every adapter records
 * it. This narrows the hazard; it does not close it, which is one more reason
 * `safe_to_merge` is a proposal and never an instruction.
 */
function hasNegationMarker(rule) {
  const raw = rule && rule.raw_rule;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return false;
  for (const [k, v] of Object.entries(raw)) {
    if (!/negate|negated/i.test(k)) continue;
    const s = canonicalScalar(v);
    if (v === true || (s && s !== 'false' && s !== '0' && s !== 'disable' && s !== 'no')) return true;
  }
  return false;
}

/** Do two `{start,end}` uint32 intervals share any address? */
function rangesOverlap(a, b) {
  return a.start <= b.end && b.start <= a.end;
}

/** Do two resolved protocol/port entries share any (proto, port)? */
function protoEntriesOverlap(p, q) {
  const wild = (x) => x === 'ip' || x === 'any' || x === 'all';
  if (!(wild(p.proto) || wild(q.proto) || p.proto === q.proto)) return false;
  // A protocol-only entry (`icmp`, `ip`) carries no port and so covers all.
  if (p.portStart === null || q.portStart === null) return true;
  return p.portStart <= q.portEnd && q.portStart <= p.portEnd;
}

/**
 * Tri-state overlap of one dimension.
 *
 * ⛔ 'no' IS THE ONLY ANSWER THAT LETS A GROUP BE CALLED SAFE, so it is the one
 * that must be earned: it requires BOTH sides fully resolved and provably
 * disjoint. A single unresolved object name or FQDN on either side yields
 * 'unknown'. ⛔ Note the order — a RESOLVED overlap is reported even when
 * something else on the rule was unresolved, because an overlap we can already
 * see does not become less certain by there being more we cannot see.
 */
function dimensionOverlap(aResolved, bResolved, kind) {
  if (aResolved.isAny || bResolved.isAny) return 'yes';
  if (kind === 'address') {
    for (const ra of aResolved.ranges) {
      for (const rb of bResolved.ranges) if (rangesOverlap(ra, rb)) return 'yes';
    }
    const unsure = aResolved.unresolvedNames.length + aResolved.unresolvedFqdns.length
      + bResolved.unresolvedNames.length + bResolved.unresolvedFqdns.length;
    return unsure > 0 ? 'unknown' : 'no';
  }
  for (const pa of aResolved.protocols) {
    for (const pb of bResolved.protocols) if (protoEntriesOverlap(pa, pb)) return 'yes';
  }
  const unsure = aResolved.unresolvedNames.length + bResolved.unresolvedNames.length;
  return unsure > 0 ? 'unknown' : 'no';
}

/**
 * A per-rule resolution cache. Resolving a group's members against every
 * intervening rule would otherwise re-expand the same address groups hundreds
 * of times on a 721-rule device.
 */
function makeResolver(objects) {
  const addrMap = buildObjectMap(objects, ['address', 'address_group']);
  const svcMap = buildObjectMap(objects, ['service', 'service_group']);
  const cache = new Map();
  return (rule) => {
    let hit = cache.get(rule);
    if (hit) return hit;
    hit = {
      src: resolveAddressField(toList(rule.src_addresses) || [], addrMap),
      dst: resolveAddressField(toList(rule.dst_addresses) || [], addrMap),
      svc: resolveServiceField(toList(rule.services) || [], svcMap),
    };
    cache.set(rule, hit);
    return hit;
  };
}

/**
 * Could rule `b` match any traffic rule `a` matches? 'yes' | 'no' | 'unknown'.
 *
 * ⛔ ZONES AND APPLICATIONS ARE NOT USED TO EXCLUDE. Two rules naming different
 * zones may still carry the same traffic — a zone is an interface grouping this
 * engine has no map for — so letting a zone mismatch produce 'no' would be
 * concluding disjointness from a field we cannot evaluate. Ignoring them can
 * only ever OVER-report interference, which lands on `needs_review`. That is the
 * direction this engine is allowed to be wrong in.
 */
function mightMatchSameTraffic(a, b, resolve) {
  if (hasNegationMarker(a) || hasNegationMarker(b)) return 'unknown';
  const ra = resolve(a);
  const rb = resolve(b);
  const dims = [
    dimensionOverlap(ra.src, rb.src, 'address'),
    dimensionOverlap(ra.dst, rb.dst, 'address'),
    dimensionOverlap(ra.svc, rb.svc, 'service'),
  ];
  // Any dimension provably disjoint means the rules can never both match.
  if (dims.includes('no')) return 'no';
  return dims.includes('unknown') ? 'unknown' : 'yes';
}

/** Short, stable label for a rule in a finding. Mirrors ruleAnalysis's. */
function ruleLabel(rule) {
  if (rule.rule_name) return String(rule.rule_name);
  if (rule.rule_id_vendor) return String(rule.rule_id_vendor);
  const s = seqOf(rule);
  if (s !== null) return `position ${s}`;
  return String(rule.id || 'unidentified rule');
}

function summarise(rule) {
  return {
    id: rule.id,
    ruleName: rule.rule_name || null,
    ruleIdVendor: rule.rule_id_vendor || null,
    sequenceNumber: seqOf(rule),
    action: rule.action || null,
    label: ruleLabel(rule),
  };
}

/**
 * The safety check. Would merging this group at its LOWEST sequence number
 * change any traffic decision?
 *
 * @param {object[]} group      the candidate rules (any order; sorted here)
 * @param {object[]} candidates every rule on the same device+vdom, the pool the
 *                              intervening rules are drawn from
 * @param {{objects?: object[], resolve?: function}} [opts]
 *        `objects` are that device's `network_objects` rows. ⛔ OMITTING THEM
 *        DOES NOT MAKE THE CHECK EASIER — every object NAME then resolves to
 *        nothing and the verdict falls to `needs_review`. Literal CIDRs still
 *        resolve, so the engine still concludes on rules written with literals.
 * @returns {{verdict, adjacent, interfering, undetermined, examined, mergePosition}}
 */
function checkInterference(group, candidates, opts = {}) {
  const members = [...(Array.isArray(group) ? group : [])]
    .filter((r) => r && typeof r === 'object')
    .sort((a, b) => (seqOf(a) ?? 0) - (seqOf(b) ?? 0));
  const pool = Array.isArray(candidates) ? candidates : [];
  const resolve = opts.resolve || makeResolver(opts.objects || []);

  const interfering = [];
  const undetermined = [];

  // ⛔ A MEMBER WITH NO SEQUENCE NUMBER CANNOT BE POSITIONED, so nothing can be
  // said about what a merge would move past. Undetermined, not skipped.
  const unpositionedMembers = members.filter((m) => seqOf(m) === null);
  for (const m of unpositionedMembers) {
    undetermined.push({ rule: summarise(m), reason: 'member_has_no_sequence_number' });
  }

  const memberSet = new Set(members);
  const seqs = members.map(seqOf).filter((s) => s !== null);
  const mergePosition = seqs.length ? Math.min(...seqs) : null;
  const maxSeq = seqs.length ? Math.max(...seqs) : null;

  // ⛔ AN ENABLED RULE ON THIS DEVICE WITH NO SEQUENCE NUMBER MIGHT SIT INSIDE
  // THE SPAN and we cannot tell. It is counted as undetermined rather than
  // assumed to be outside it. (Measured 2026-09-25: zero such rows on the live
  // fleet — this guard is for the collection that goes wrong later, which is
  // exactly when a cleanup proposal must not be trusted.)
  let examined = 0;
  if (mergePosition !== null) {
    for (const c of pool) {
      if (!c || typeof c !== 'object' || memberSet.has(c)) continue;
      // ⛔ A DISABLED RULE MATCHES NOTHING, SO IT CANNOT INTERFERE. It occupies
      // a position in the list and is never consulted by the firewall, so
      // traffic moving past it is unaffected. Stated here rather than left to
      // be inferred from an `enabled !== false` filter somewhere upstream —
      // 238 of IDC FW's 721 rules are disabled, and treating them as barriers
      // would make almost every group `needs_review` for no reason at all.
      if (c.enabled === false) continue;
      const cs = seqOf(c);
      if (cs === null) {
        undetermined.push({ rule: summarise(c), reason: 'intervening_rule_has_no_sequence_number' });
        continue;
      }
      if (cs <= mergePosition || cs >= maxSeq) continue;
      // Which members would actually be moved past this rule: those sitting
      // BELOW it today. A member above it does not move past it.
      const moved = members.filter((m) => {
        const ms = seqOf(m);
        return ms !== null && ms > cs;
      });
      if (moved.length === 0) continue;
      examined += 1;
      for (const m of moved) {
        const verdict = mightMatchSameTraffic(m, c, resolve);
        if (verdict === 'yes') {
          interfering.push({
            rule: summarise(c),
            movedRule: summarise(m),
            reason: 'matches_moved_traffic',
          });
          break;
        }
        if (verdict === 'unknown') {
          undetermined.push({
            rule: summarise(c),
            movedRule: summarise(m),
            reason: 'overlap_could_not_be_determined',
          });
          break;
        }
      }
    }
  }

  // ⛔ FALLS CLOSED. Anything other than "checked, and clear" is needs_review.
  const clear = interfering.length === 0 && undetermined.length === 0;
  return {
    verdict: clear ? VERDICTS.SAFE : VERDICTS.REVIEW,
    // The trivially safe case: nothing ENABLED sits between the members at all,
    // so there was never anything for the traffic to move past.
    adjacent: clear && examined === 0,
    mergePosition,
    examined,
    interfering,
    undetermined,
  };
}

// ─────────────────────────────────────────
// Grouping
// ─────────────────────────────────────────

/** Distinct canonical values the varying field takes across a group. */
function distinctVaryingValues(rules, field) {
  return new Set(rules.map((r) => canonicalSet(r[field])));
}

/**
 * Find every consolidation candidate group.
 *
 * @param {object[]} rules  `firewall_rules` rows, already ordered by
 *        `sequence_number`. Never mutated.
 * @param {{objectsByDeviceId?: Object<string, object[]>, objects?: object[]}} [opts]
 *        `network_objects` rows for the interference check. `objects` is the
 *        single-device shorthand.
 * @returns {object[]} groups, ranked most-removable first
 */
function findConsolidationGroups(rules, opts = {}) {
  const all = (Array.isArray(rules) ? rules : []).filter((r) => r && typeof r === 'object');
  const byDeviceId = opts.objectsByDeviceId || {};
  // ⛔ The `objects` shorthand applies ONLY when every rule belongs to one
  // device. Applying one device's object catalogue to another's rules would
  // resolve a name that device never defined, and an address invented for a
  // firewall that does not have it is a fabricated measurement deciding a
  // firewall change. With more than one device, `objectsByDeviceId` or nothing.
  const singleDevice = new Set(all.map((r) => canonicalScalar(r.device_id))).size <= 1;

  // Partition into independent evaluation contexts: one device, one vdom.
  const contexts = new Map();
  for (const r of all) {
    const ctxKey = `${canonicalScalar(r.device_id)}|${canonicalScalar(r.vdom)}`;
    if (!contexts.has(ctxKey)) contexts.set(ctxKey, []);
    contexts.get(ctxKey).push(r);
  }

  const groups = [];
  for (const ctxRules of contexts.values()) {
    const deviceId = ctxRules[0].device_id;
    const objects = byDeviceId[deviceId]
      || (singleDevice && Array.isArray(opts.objects) ? opts.objects : []);
    const resolve = makeResolver(objects);

    // ⛔ DISABLED RULES ARE NOT GROUP MEMBERS. A disabled rule is not in force,
    // so "merging" it removes a row that was already doing nothing — a saving
    // that is not a saving, and a change proposal against a rule an operator
    // deliberately parked. They stay in `ctxRules` only so the pool the
    // interference check draws from is the real list; `checkInterference` skips
    // them there too, for the separate reason that they cannot match traffic.
    const enabled = ctxRules.filter((r) => r.enabled !== false);

    for (const field of VARYING_FIELDS) {
      const buckets = new Map();
      for (const r of enabled) {
        // ⛔ A WILDCARD IN THE VARYING FIELD IS NOT A MERGE CANDIDATE. A rule
        // whose destination is already `any` cannot have its destination
        // widened by merging, and pairing it with a narrow rule would propose
        // deleting the narrow one on the strength of a rule that already
        // covers it — which is `generalization`'s question, asked by the wrong
        // engine. Same call ruleAnalysis's `correlation` makes.
        if (isAnyField(r[field])) continue;
        // ⛔ A rule with no sequence number cannot be positioned, so no merge
        // involving it can be checked. Excluded from grouping rather than
        // grouped and then reported undetermined — a candidate nobody can ever
        // act on is noise, not honesty.
        if (seqOf(r) === null) continue;
        const key = canonicalKey(r, field);
        if (!buckets.has(key)) buckets.set(key, []);
        buckets.get(key).push(r);
      }

      for (const bucket of buckets.values()) {
        // ⛔ A GROUP OF 1 IS NOT A GROUP. Doubly enforced — the distinct-value
        // check below also excludes a singleton, since one rule has one value.
        // Kept anyway: this guard states the intent, and if the check below is
        // ever loosened it is what still holds. A test pins the BEHAVIOUR, and
        // so cannot tell which of the two produced it; that is the point of
        // expressing a safety predicate twice.
        if (bucket.length < 2) continue;
        // ⛔ AND THE VARYING FIELD MUST ACTUALLY VARY. Two rows identical in
        // ALL THREE fields key together under every one of them, and would be
        // reported three times as three different savings — while being a
        // straight duplicate, which is `ruleAnalysis`'s `redundant` finding and
        // not a consolidation at all.
        if (distinctVaryingValues(bucket, field).size < 2) continue;

        const members = [...bucket].sort((a, b) => seqOf(a) - seqOf(b));
        const safety = checkInterference(members, ctxRules, { resolve });
        const span = members.length
          ? seqOf(members[members.length - 1]) - seqOf(members[0])
          : 0;

        groups.push({
          deviceId,
          vdom: ctxRules[0].vdom || null,
          varyingField: field,
          varyingFieldLabel: FIELD_LABEL[field],
          rules: members.map(summarise),
          ruleIds: members.map((r) => r.id),
          size: members.length,
          // ⛔ MERGING n ROWS INTO 1 REMOVES n-1 OF THEM, never n. The merged
          // rule still has to exist.
          removableRows: members.length - 1,
          // What merging costs in auditability — separate names, comments and
          // tags do not survive it. Reported, not used to refuse the group.
          distinctNames: [...new Set(members.map((r) => r.rule_name).filter(Boolean))],
          losesDistinctComments:
            new Set(members.map((r) => canonicalScalar(r.comment))).size > 1,
          mergedValue: [...new Set(
            members.flatMap((r) => toList(r[field]) || [])
          )].sort(),
          sequenceSpan: span,
          ...safety,
        });
      }
    }
  }

  // Most rows removed first, then the shortest span — a group whose members sit
  // close together is both likelier to be safe and easier for a human to check.
  return groups.sort((a, b) => b.removableRows - a.removableRows
    || a.sequenceSpan - b.sequenceSpan
    || String(a.deviceId).localeCompare(String(b.deviceId)));
}

/**
 * Fleet totals.
 *
 * ⛔ `removableRows` IS THE CANDIDATE TOTAL AND MUST NOT BE PRESENTED AS AN
 * ACHIEVABLE SAVING. Only `safeRemovableRows` has had its ordering checked, and
 * even that is a proposal — see MERGE_CLAIM. The two are returned separately so
 * no caller has to choose which one the headline is; a single blended figure
 * would be a number nobody could act on.
 */
function summariseConsolidation(groups) {
  const list = Array.isArray(groups) ? groups : [];
  const byField = {};
  const byVerdict = { [VERDICTS.SAFE]: 0, [VERDICTS.REVIEW]: 0 };
  for (const g of list) {
    if (!byField[g.varyingField]) byField[g.varyingField] = { groups: 0, removableRows: 0 };
    byField[g.varyingField].groups += 1;
    byField[g.varyingField].removableRows += g.removableRows;
    if (byVerdict[g.verdict] === undefined) byVerdict[g.verdict] = 0;
    byVerdict[g.verdict] += 1;
  }
  const safe = list.filter((g) => g.verdict === VERDICTS.SAFE);
  const review = list.filter((g) => g.verdict === VERDICTS.REVIEW);
  const sum = (rows) => rows.reduce((n, g) => n + g.removableRows, 0);
  return {
    groups: list.length,
    devices: new Set(list.map((g) => g.deviceId)).size,
    removableRows: sum(list),
    safeGroups: safe.length,
    safeRemovableRows: sum(safe),
    needsReviewGroups: review.length,
    needsReviewRemovableRows: sum(review),
    // ⛔ Counted apart from ordinary interference: "a rule between them matches"
    // and "we could not tell whether one does" send an operator to different
    // places, and collapsing them would hide how much of the review pile is
    // really a COLLECTION gap (an unresolved object name) rather than a policy
    // one. On this fleet that distinction is the whole story.
    undeterminedGroups: list.filter((g) => g.undetermined.length > 0).length,
    adjacentGroups: list.filter((g) => g.adjacent).length,
    byField,
    byVerdict,
    claim: MERGE_CLAIM,
  };
}

module.exports = {
  findConsolidationGroups,
  canonicalKey,
  checkInterference,
  summariseConsolidation,
  // Exported for tests and for a renderer that must not invent its own wording.
  MERGE_CLAIM,
  VERDICTS,
  VARYING_FIELDS,
  FIELD_LABEL,
  SET_FIELDS,
  SCALAR_FIELDS,
  IGNORED_FOR_KEY,
};
