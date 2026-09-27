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
// Measured on the live fleet 2026-09-27, across ENABLED rules on active devices:
// destination 35 groups / 49 removable rows, source 28 / 47, service 5 / 7 —
// 68 groups, 103 rows. That is the CANDIDATE set. What each group is worth
// depends entirely on the section below: 41 groups / 67 rows have had their
// ordering checked, 27 / 36 need review.
//
// ⛔ THOSE NUMBERS ARE SMALLER THAN THE 2026-09-25 ONES THIS COMMENT USED TO
// CARRY (92 groups / 156 rows), and the reduction IS the fix: the canonical key
// then spanned only the columns, so rules differing in a PAN-OS `source-user`, a
// FortiOS `av-profile` or a `log-start` were being grouped as "the same rule
// written twice". 7 of the 41 groups it called `safe_to_merge` were not the same
// rule at all.
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
// `rule_name`, `comment`, `tags`, `hit_count`, `last_hit_at`, `collected_at`.
// None of them affects which traffic a rule matches or what the firewall does
// with it. A merge DOES lose the distinct names, comments and tags, so each
// group reports them — it is an auditability cost for a human to weigh, not a
// reason to refuse the grouping.
//
// ⛔ `raw_rule` IS NOT ON THIS LIST ANY MORE. See the section below.
const IGNORED_FOR_KEY = Object.freeze(['rule_name', 'comment', 'tags', 'hit_count']);

// ── ⛔ `raw_rule` DECIDES MATCHING AND ENFORCEMENT, AND `firewall_rules` HAS
//    NO COLUMN FOR MOST OF IT ───────────────────────────────────────────────
//
// The canonical key used to span only the columns, which made a group of
// `safe_to_merge` rules NOT the same rule at all.
//
// ⛔ THE COUNT IS 7, AND AN EARLIER PASS HERE SAID 9 — the disagreement is
// recorded rather than tidied away, because nobody has explained it. 9 was
// measured 2026-09-26 against the columns-only key; 7 is what an INDEPENDENT
// diff of the members' `raw_rule` found on 2026-09-27 (not this engine's own
// key, so it is not the key agreeing with itself), and 7 is what
// `tests/ruleConsolidation.test.js` pins. Two of the nine had presumably also
// stopped grouping for one of the other reasons fixed in the same change — the
// per-member negation guard and the empty-extent case — but that was not
// measured before the fix landed and may not now be. The examples below are
// each verified individually:
//
//   TUM(TUTH1) #126 vs #127   PAN-OS `source-user` — `{"member":"dlt_…"}` on
//                             one, `"any"` on the other. Merging either grants
//                             #126's destination to EVERY user or strips
//                             #127's access from everyone but one.
//   OKF(F2)    #26  vs #28    FortiOS `utm-status`/`av-profile`/`ips-sensor`/
//                             `webfilter-profile` present on one, absent on
//                             the other — one rule is inspected, one is not.
//   TUG        #5   vs #6     PAN-OS `profile-setting` differing by a whole
//                             spyware profile.
//
// ⛔ AND THE STATED INTENT WAS ALREADY DEFEATED BEFORE THIS. `log_enabled` is
// in the key precisely so a logged rule never merges with an unlogged one, yet
// `safe_to_merge` groups differed in PAN-OS `log-start` (IDC FW #414/#415) and
// FortiOS `logtraffic` (TSR_EKM #33/#57) — the same fact, one layer down, where
// no column was looking.
//
// ⛔ A BLANKET HASH OF `raw_rule` IS NOT THE FIX. It would fold in `@_uuid`,
// `uuid`, `policyid`, `@_name` and Panorama provenance — all distinct per rule —
// and collapse the feature to ZERO groups on the entire fleet. Silently: no
// error, no crash, just a cleanup screen that has nothing to say. So the keys
// are classified BY NAME, with a reason each, in exactly three buckets:
//
//   RAW_KEY_SIGNIFICANT  in the key. It decides what MATCHES or what the
//                        firewall DOES, and two rules disagreeing on it are
//                        not the same rule.
//   RAW_KEY_IGNORED      not in the key, no caveat. Identity, free text,
//                        provenance, or a field a COLUMN already models (and
//                        that column is in the key).
//   anything else        ⛔ NOT IN THE KEY, AND FORCES `needs_review`. A key
//                        nobody has classified might be either of the above,
//                        and guessing is how a merge proposal silently changes
//                        policy. It is named in the group's `undetermined`
//                        list so the fix is to classify it, not to widen a
//                        wildcard.
//
// ⛔ THE ASYMMETRY IS DELIBERATE: adding a key to SIGNIFICANT can only ever
// SPLIT a group (under-report, safe); adding one to IGNORED can CLEAR a group
// that should not be (over-report, unsafe). So SIGNIFICANT is liberal — it
// lists vendor fields not seen live — and IGNORED is strict, and every entry
// there names the column that carries the fact instead.
const RAW_KEY_SIGNIFICANT = Object.freeze({
  // ── Palo Alto (PAN-OS security rule element) ──
  'source-user': 'which USERS the rule matches; "any" and a named group are different rules',
  category: 'URL categories the rule matches',
  'source-hip': 'host-information profiles the source must satisfy to match',
  'destination-hip': 'host-information profiles the destination must satisfy to match',
  'rule-type': 'universal / intrazone / interzone — which traffic the rule is even consulted for',
  'profile-setting': 'the security profiles (AV, spyware, vulnerability, URL) the firewall applies',
  'log-start': 'whether the firewall logs at session start',
  'log-setting': 'which log-forwarding profile the firewall sends the record to',
  option: 'per-rule enforcement options (e.g. disable-server-response-inspection)',
  qos: 'QoS marking the firewall applies',
  'negate-source': 'INVERTS the source extent — see hasNegationMarker',
  'negate-destination': 'INVERTS the destination extent — see hasNegationMarker',
  // ── Fortinet (FortiOS firewall policy) ──
  logtraffic: 'all / utm / disable — what the firewall records. `log_enabled` only carries the '
    + 'disable half, so `all` vs `utm` is invisible without this',
  'logtraffic-start': 'whether the firewall logs at session start',
  groups: 'which user GROUPS the policy matches',
  users: 'which individual USERS the policy matches',
  'fsso-groups': 'which FSSO groups the policy matches',
  'utm-status': 'whether UTM inspection runs at all on this policy',
  'inspection-mode': 'flow vs proxy inspection',
  'av-profile': 'antivirus profile applied',
  'ips-sensor': 'IPS sensor applied',
  'webfilter-profile': 'web filter applied',
  'dnsfilter-profile': 'DNS filter applied',
  'emailfilter-profile': 'email filter applied',
  'file-filter-profile': 'file filter applied',
  'ssl-ssh-profile': 'SSL/SSH inspection profile applied',
  'application-list': 'application-control list applied',
  'profile-protocol-options': 'protocol options applied',
  'profile-group': 'profile group applied',
  'profile-type': 'single profile vs profile group',
  'voip-profile': 'VoIP profile applied',
  'icap-profile': 'ICAP profile applied',
  'waf-profile': 'web application firewall profile applied',
  'dlp-sensor': 'DLP sensor applied',
  ippool: 'whether source NAT uses an IP pool',
  poolname: 'WHICH IP pool source NAT translates to',
  'port-preserve': 'whether NAT preserves the source port',
  'internet-service': 'whether the destination is matched as an Internet Service rather than an address',
  'internet-service-name': 'which Internet Services the destination matches',
  'internet-service-src': 'whether the SOURCE is matched as an Internet Service',
  'internet-service-src-name': 'which Internet Services the source matches',
  'srcaddr-negate': 'INVERTS the source extent — see hasNegationMarker',
  'dstaddr-negate': 'INVERTS the destination extent — see hasNegationMarker',
  'service-negate': 'INVERTS the service extent — see hasNegationMarker',
  'internet-service-negate': 'INVERTS the Internet-Service destination extent',
  'internet-service-src-negate': 'INVERTS the Internet-Service source extent',
});

const RAW_KEY_IGNORED = Object.freeze({
  // ── Palo Alto: already a column, and that column IS in the key ──
  from: 'src_zones', to: 'dst_zones',
  source: 'src_addresses', destination: 'dst_addresses',
  service: 'services (FortiOS `service` too)', application: 'applications',
  action: 'action', disabled: 'enabled', schedule: 'schedule',
  description: 'comment',
  // ⛔ log-end is what `log_enabled` is DERIVED from on PAN-OS, so keying it
  // separately would split an explicit `<log-end>yes</log-end>` from a rule
  // that omits it while both mean the same thing — present on 864 of 1,601
  // live rules, so that split would be common and silent. The column carries
  // the fact; the raw key adds only the spelling.
  'log-end': 'log_enabled',
  // ── Palo Alto: labels and identity ──
  tag: 'tags — a label, not an enforcement field',
  'group-tag': 'a Panorama presentation grouping',
  // ── Fortinet ──
  uuid: 'vendor identity',
  policyid: 'rule_id_vendor',
  name: 'rule_name',
  comments: 'comment',
  status: 'enabled',
  nat: 'nat_enabled',
  srcintf: 'src_zones', dstintf: 'dst_zones',
  srcaddr: 'src_addresses', dstaddr: 'dst_addresses',
  // ⛔ `vdom` is put here by fortinet/parser.js's withVdomRaw because
  // firewall_rules had no vdom column at the time. It has one now, it is in
  // the key already, and keying the raw copy as well would be the same fact
  // twice.
  vdom: 'the vdom column, which is already part of the key',
});

// ⛔ AN XML ATTRIBUTE OF THE RULE ELEMENT IS METADATA, BY PATTERN. fast-xml-parser
// prefixes them `@_`, and on PAN-OS they are `@_name`, `@_uuid`, `@_loc` and
// `@_panorama` — identity and Panorama provenance, none of it policy. A pattern
// rather than four literals because Panorama adds more of them per firmware, and
// a new one arriving should not put the whole fleet into review.
const ATTRIBUTE_KEY_PREFIX = '@_';

// The token every "this key constrains nothing / does nothing" spelling folds
// onto. ⛔ IT IS WHAT MAKES AN EXPLICIT VENDOR DEFAULT KEY THE SAME AS AN ABSENT
// ONE: PAN-OS writes `negate-source: no` on 131 of 1,601 live rules and omits it
// on the rest, and `destination-hip: any` on 1,197 while 404 carry nothing. Key
// those apart and a real group splits for a spelling difference — the silent
// under-report a blanket hash produces, arrived at one field at a time.
//
// ⛔ `all` IS NOT IN THIS FAMILY, and the reason is FortiOS `logtraffic`: `all`
// logs every session while the absent default logs only UTM events. Folding
// them would merge a fully-logged rule with a partly-logged one — the exact
// class of mistake this whole section exists to stop.
const NEUTRAL_TOKEN = '~';
const NEUTRAL_VALUES = new Set([
  '', 'no', 'none', 'false', '0', 'disable', 'disabled', 'off', 'unset', 'any',
]);

/**
 * fast-xml-parser represents an element carrying BOTH text and attributes as
 * `{'#text': 'no', '@_loc': 'PA-220-Ranode'}`. ⛔ Live on the fleet: one rule's
 * `negate-destination` has exactly that shape, and reading the OBJECT instead of
 * its text made it look NEGATED (finding 9). Unwrapped here, once, so every
 * reader — the key, the negation guard, the scalar canonicaliser — agrees.
 */
function unwrapXmlText(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
  if (Object.prototype.hasOwnProperty.call(value, '#text')) return value['#text'];
  return value;
}

/**
 * One `raw_rule` value, canonicalised into a comparable token.
 *
 * ⛔ ARRAYS ARE SORTED HERE, and that is a claim about THIS subset of keys, not
 * a general licence — every keyed raw field is a member SET (`source-user`'s
 * `{member:[…]}`, FortiOS `groups`, PAN-OS `option`), so `[A,B]` and `[B,A]`
 * select the same traffic. The same claim SET_FIELDS makes above, and the same
 * reason `lib/canonicalJson.js` refuses to make it generally.
 *
 * ⛔ Attribute keys are dropped INSIDE a value too, so `@_loc` on a nested
 * member cannot make two identical values key apart.
 */
function canonicalRawValue(value) {
  const v = unwrapXmlText(value);
  if (v === null || v === undefined) return NEUTRAL_TOKEN;
  if (Array.isArray(v)) {
    const items = [...new Set(v.map(canonicalRawValue))]
      .filter((s) => s !== NEUTRAL_TOKEN)
      .sort();
    return items.length ? `[${items.join(',')}]` : NEUTRAL_TOKEN;
  }
  if (typeof v === 'object') {
    const parts = [];
    for (const k of Object.keys(v).sort()) {
      if (k.startsWith(ATTRIBUTE_KEY_PREFIX)) continue;
      const token = canonicalRawValue(v[k]);
      if (token === NEUTRAL_TOKEN) continue;
      parts.push(`${k.toLowerCase()}:${token}`);
    }
    return parts.length ? `{${parts.join(',')}}` : NEUTRAL_TOKEN;
  }
  const s = String(v).trim().toLowerCase();
  return NEUTRAL_VALUES.has(s) ? NEUTRAL_TOKEN : s;
}

/**
 * Split a rule's `raw_rule` top-level keys into the three buckets.
 *
 * @returns {{significant: [string, string][], unclassified: string[]}}
 *   `significant` is `[key, token]` pairs, sorted by key, with neutral-valued
 *   keys DROPPED (so absent and explicitly-default key the same).
 */
function classifyRawRuleKeys(rule) {
  const raw = rule && rule.raw_rule;
  const significant = [];
  const unclassified = [];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { significant, unclassified };
  }
  for (const key of Object.keys(raw).sort()) {
    if (key.startsWith(ATTRIBUTE_KEY_PREFIX)) continue;
    const lower = key.toLowerCase();
    if (Object.prototype.hasOwnProperty.call(RAW_KEY_IGNORED, lower)) continue;
    if (Object.prototype.hasOwnProperty.call(RAW_KEY_SIGNIFICANT, lower)) {
      const token = canonicalRawValue(raw[key]);
      if (token !== NEUTRAL_TOKEN) significant.push([lower, token]);
      continue;
    }
    if (!unclassified.includes(lower)) unclassified.push(lower);
  }
  return { significant, unclassified };
}

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

/**
 * Scalars, normalised so `null`, `undefined` and `''` cannot key differently.
 *
 * ⛔ AN XML TEXT NODE IS UNWRAPPED FIRST. Without it PAN-OS's
 * `{"#text":"no","@_loc":"PA-220-Ranode"}` stringified to a JSON blob, which
 * `hasNegationMarker` then read as NEGATED because it was not the literal string
 * `"no"` — live on TFM-RN #12. That over-reports (it falls closed), which is why
 * it is a low finding and not a critical one, but a count nobody can trust is
 * still not a count.
 */
function canonicalScalar(value) {
  const v = unwrapXmlText(value);
  if (v === null || v === undefined) return '';
  if (v instanceof Date) return v.toISOString();
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v).trim().toLowerCase();
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
  // ⛔ THE CLASSIFIED `raw_rule` KEYS. Only SIGNIFICANT ones, only where the
  // value is not the vendor's neutral default, sorted — see the section above
  // for why a blanket hash here would silently collapse the feature to nothing.
  // UNCLASSIFIED keys deliberately do NOT enter the key: they must not split a
  // group silently, they must make it `needs_review` loudly (checkInterference).
  for (const [k, token] of classifyRawRuleKeys(r).significant) {
    parts.push(`raw.${k}=${token}`);
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
 * ⛔ CALLED FROM TWO PLACES, AND THE SECOND ONE IS WHY THIS GUARD CAN FIRE AT
 * ALL. For a long time it was reachable only from `mightMatchSameTraffic`, which
 * `checkInterference` calls only for an INTERVENING rule — so a negated MEMBER
 * with nothing between it and its partner never reached it, and the group was
 * cleared. `checkInterference` now asks it of every member directly.
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
 *
 * ⛔ AND AN EMPTY EXTENT IS `unknown`, NOT `no` — THE GAP `unresolvedNames`
 * CANNOT SEE. A non-wildcard field that resolved to ZERO ranges is a field
 * nothing is known about, but `objectResolver.resolveAddressEntry` records
 * nothing for it: an address GROUP whose `members` is `[]` resolves fine (the
 * group itself was found) and contributes no range and no unresolved name, so
 * the doc above was satisfied to the letter while `no` was returned for a side
 * that had been enumerated as empty. `storeObjects` writes `[]` for a group the
 * adapter did not return, and two such groups exist on the live fleet
 * (Vietnam-YCC, OKF(F2)) — so a PARTIAL object read produced a confident
 * "provably disjoint" and cleared a group with a `deny` sitting inside its span.
 * A cycle-stopped recursion in that same resolver reaches here the same way.
 */
function dimensionOverlap(aResolved, bResolved, kind) {
  if (aResolved.isAny || bResolved.isAny) return 'yes';
  if (kind === 'address') {
    for (const ra of aResolved.ranges) {
      for (const rb of bResolved.ranges) if (rangesOverlap(ra, rb)) return 'yes';
    }
    const unsure = aResolved.unresolvedNames.length + aResolved.unresolvedFqdns.length
      + bResolved.unresolvedNames.length + bResolved.unresolvedFqdns.length;
    if (unsure > 0) return 'unknown';
    if (aResolved.ranges.length === 0 || bResolved.ranges.length === 0) return 'unknown';
    return 'no';
  }
  for (const pa of aResolved.protocols) {
    for (const pb of bResolved.protocols) if (protoEntriesOverlap(pa, pb)) return 'yes';
  }
  const unsure = aResolved.unresolvedNames.length + bResolved.unresolvedNames.length;
  if (unsure > 0) return 'unknown';
  if (aResolved.protocols.length === 0 || bResolved.protocols.length === 0) return 'unknown';
  return 'no';
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

  // ⛔ NEGATION IS A PROPERTY OF THE RULE, NOT OF ITS NEIGHBOURS — AND THE GUARD
  // COULD NOT FIRE WITHOUT ONE. `hasNegationMarker` was reachable only through
  // `mightMatchSameTraffic`, which is called only for an INTERVENING rule, so a
  // negated member with nothing between it and its partner produced
  // `examined === 0` and a clean `safe_to_merge`: 20 of the live fleet's 92
  // groups take that path. A negated field means the rule matches the COMPLEMENT
  // of what it lists, so two such rules are not the same rule written twice —
  // they may be each other's opposite — and the union a merge writes
  // (`NOT(A ∪ B)`) is not the union of what they match (`NOT A ∪ NOT B`).
  //
  // ⛔ EXPRESSED TWICE, deliberately: the negate keys are also in the canonical
  // key now, so a negated rule no longer GROUPS with a non-negated one. This is
  // the half that still holds when two rules are negated identically, and the
  // half that does not depend on any adapter spelling a negate key the way
  // RAW_KEY_SIGNIFICANT lists it.
  for (const m of members) {
    if (hasNegationMarker(m)) {
      undetermined.push({ rule: summarise(m), reason: 'member_field_is_negated' });
    }
  }

  // ⛔ A `raw_rule` KEY NOBODY HAS CLASSIFIED MIGHT DECIDE WHAT THE RULE MATCHES
  // OR WHAT THE FIREWALL DOES, so the group is reported and never cleared. The
  // key is NAMED: the fix is to classify it in RAW_KEY_SIGNIFICANT or
  // RAW_KEY_IGNORED, not to widen anything.
  const flaggedKeys = new Set();
  for (const m of members) {
    for (const key of classifyRawRuleKeys(m).unclassified) {
      if (flaggedKeys.has(key)) continue;
      flaggedKeys.add(key);
      undetermined.push({
        rule: summarise(m), field: key, reason: 'unclassified_raw_rule_key',
      });
    }
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
      // ⛔ BOTH BOUNDS ARE NOW EXCLUSIVE ONLY OUTSIDE THE SPAN. `cs <= mergePosition
      // || cs >= maxSeq` treated a rule SHARING a member's sequence number as
      // being outside the span, which is sound only if sequence numbers are
      // unique per device+vdom — and nothing in this codebase checks that. A
      // non-member `deny` at the same position as the first member may sit
      // either side of it in evaluation order, and if it sits below, the later
      // members move past it. The old form skipped it and the UI then printed
      // "Nothing enabled sits between these rules." over a deny rule inside the
      // span. (Measured 2026-09-26: ZERO duplicate sequence numbers on the live
      // fleet, so this is a guard for the collection that goes wrong later —
      // which is exactly when a cleanup proposal must not be trusted.)
      if (cs < mergePosition || cs > maxSeq) continue;
      if (seqs.includes(cs)) {
        undetermined.push({
          rule: summarise(c), reason: 'duplicate_sequence_number_in_span',
        });
        continue;
      }
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
  // The `raw_rule` classification. Exported so a test can assert the three
  // buckets are DISJOINT and that every key the live fleet actually carries is
  // in one of them — a live key in neither puts the whole vendor into review.
  RAW_KEY_SIGNIFICANT,
  RAW_KEY_IGNORED,
  ATTRIBUTE_KEY_PREFIX,
  NEUTRAL_TOKEN,
  NEUTRAL_VALUES,
  canonicalRawValue,
  classifyRawRuleKeys,
  hasNegationMarker,
};
