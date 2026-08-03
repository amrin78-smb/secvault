// lib/adapters/paloalto/parser.js
// CommonJS ONLY — required by lib/adapters/paloalto/index.js, which in turn is
// required by services/engine-worker.js (plain node, CommonJS).
//
// Pure functions only — no I/O, no network, no DB access. These functions must NEVER
// throw on malformed/unexpected input (only api.js's network calls should throw).
// Per CLAUDE.md "External API Integrations": field names are verified defensively —
// the MVP was built without a live PAN-OS device, so every lookup here has safe
// fallbacks, and index.js logs raw responses on first-connect paths.
//
// Input shape: PAN-OS XML API responses parsed by fast-xml-parser v4 configured with
// { ignoreAttributes: false, attributeNamePrefix: '@_' }. CRITICAL fast-xml-parser
// gotcha: a single child element parses as an object (or bare scalar), multiple
// children parse as an array. ALWAYS normalize through toArray() before iterating.

const { parseVersion } = require('../../engines/versionComparator');

// fast-xml-parser returns an object for one child and an array for many — normalize
// EVERY list-shaped access through this helper. Exported for tests.
function toArray(value) {
  if (value === null || value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

// Extracts scalar text from a fast-xml-parser node. A plain element parses to a
// string/number; an element with attributes parses to { '#text': ..., '@_attr': ... }.
// Returns null for empty/missing values, never throws.
function scalarText(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'object') {
    if (value['#text'] !== undefined && value['#text'] !== null) {
      const s = String(value['#text']).trim();
      return s.length > 0 ? s : null;
    }
    return null;
  }
  const s = String(value).trim();
  return s.length > 0 ? s : null;
}

// PAN-OS member lists: <from><member>trust</member><member>dmz</member></from>.
// fast-xml-parser yields { member: 'trust' } for ONE member (a bare string, or a
// number if the text is numeric, e.g. service port groups named "8080") and
// { member: [...] } for many — hence toArray + String coercion on every element.
// Always returns an array of strings (possibly empty). Exported for tests.
function memberStrings(field) {
  if (field === null || field === undefined) return [];
  // Degenerate case: the field itself is already a bare scalar (no <member> wrapper).
  if (typeof field !== 'object') {
    const s = scalarText(field);
    return s ? [s] : [];
  }
  return toArray(field.member)
    .map((m) => scalarText(m))
    .filter((s) => s !== null);
}

// Best-effort mapping from the PAN-OS security rule action vocabulary to the
// NormalizedRule vocabulary ('allow'|'deny'|'drop'|'reject'). Unrecognized values
// pass through as-is rather than crashing — better to surface an odd raw value than
// throw during rule collection.
function mapAction(rawAction) {
  const text = scalarText(rawAction);
  if (text === null) return null;
  const value = text.toLowerCase();
  switch (value) {
    case 'allow':
      return 'allow';
    case 'deny':
      return 'deny';
    case 'drop':
      return 'drop';
    // PAN-OS reset variants all send an explicit refusal — normalize to 'reject'.
    case 'reset-client':
    case 'reset-server':
    case 'reset-both':
      return 'reject';
    default:
      return text;
  }
}

// systemInfoResult: the parsed <result> of `show system info` — fields live under
// result.system (sw-version, model, app-version, ...). Field names verified against
// PAN-OS XML API docs but NOT yet against a live device (per CLAUDE.md, the first
// live connect must check the [PaloAlto Debug] raw log in index.js and adjust here).
// → { version_string, version_tuple, build, model }
function parseSystemInfo(systemInfoResult) {
  const result =
    systemInfoResult && typeof systemInfoResult === 'object' ? systemInfoResult : {};
  const system = result.system && typeof result.system === 'object' ? result.system : result;

  const versionString = scalarText(system['sw-version']);
  const model = scalarText(system.model) || 'unknown';
  // PAN-OS `show system info` has no dedicated build field — the contract uses
  // app-version (content release, e.g. "8810-8987") as the build fallback.
  const build = scalarText(system.build) || scalarText(system['app-version']) || null;
  // Added 2026-07-19: `show system info`'s documented `serial` field was never
  // extracted on this transport at all (unlike the SSH transport, which
  // already parsed it but then dropped it before returning — fixed
  // separately). Doc-derived, not yet independently live-verified for THIS
  // specific field on the XML/API transport — flagged per this codebase's
  // standing "documentation lies" rule.
  const serial = scalarText(system.serial) || null;
  // Added 2026-07-23: same as `serial` above — doc-derived, not yet
  // independently live-verified for this XML/API transport specifically
  // (the SSH transport's flat-text `hostname:` field IS live-confirmed, per
  // CLAUDE.md's Live Validation Status — this is the plausible XML-tag
  // equivalent, not assumed identical without checking on first live use).
  const hostname = scalarText(system.hostname) || null;

  if (!versionString) {
    console.warn(
      '[PaloAlto parser] parseSystemInfo: no sw-version field found on system info result — ' +
        'field names may differ on this PAN-OS release. Raw keys: ' +
        JSON.stringify(Object.keys(system))
    );
    return { version_string: null, version_tuple: [0], build, model, serial, hostname };
  }

  // parseVersion('paloalto', ...) handles the -h hotfix suffix: "11.1.2-h3" → [11,1,2,3].
  return {
    version_string: versionString,
    version_tuple: parseVersion('paloalto', versionString),
    build,
    model,
    serial,
    hostname,
  };
}

// Maps one <entry name="..."> security rule element to a NormalizedRule.
// idx is the 0-based position in the rulebase (PAN-OS evaluates rules in document
// order, so document position IS the sequence number, 1-based).
function parseRuleEntry(entry, idx) {
  if (!entry || typeof entry !== 'object') {
    return {
      rule_name: null,
      rule_id_vendor: null,
      sequence_number: idx + 1,
      enabled: true,
      action: null,
      src_zones: [],
      dst_zones: [],
      src_addresses: [],
      dst_addresses: [],
      services: [],
      applications: [],
      schedule: null,
      expiry_date: null,
      log_enabled: true,
      comment: null,
      hit_count: 0,
      raw_rule: entry === undefined ? null : entry,
    };
  }

  const name = scalarText(entry['@_name']);
  // PAN-OS rules are identified by name (the config API exposes no separate stable
  // numeric ID at this xpath), so rule_name and rule_id_vendor are both the name.
  const disabled = scalarText(entry.disabled);
  const logEnd = scalarText(entry['log-end']);

  return {
    rule_name: name,
    rule_id_vendor: name,
    sequence_number: idx + 1,
    // <disabled>yes</disabled> present → disabled; absent (or any other value) → enabled.
    enabled: !(disabled !== null && disabled.toLowerCase() === 'yes'),
    action: mapAction(entry.action),
    src_zones: memberStrings(entry.from),
    dst_zones: memberStrings(entry.to),
    src_addresses: memberStrings(entry.source),
    dst_addresses: memberStrings(entry.destination),
    services: memberStrings(entry.service),
    applications: memberStrings(entry.application),
    schedule: scalarText(entry.schedule),
    expiry_date: null,
    // <log-end>no</log-end> explicitly disables end-of-session logging; the PAN-OS
    // default (element absent) is log-at-end enabled.
    log_enabled: !(logEnd !== null && logEnd.toLowerCase() === 'no'),
    comment: scalarText(entry.description),
    // Hit counts are NOT available via the config API (type=config&action=get) —
    // they require the op command `show rule-hit-count`, which is future work.
    hit_count: 0,
    raw_rule: entry,
  };
}

// rulesResult: the parsed <result> of the config-get on the security rules xpath —
// shape: { '@_count': ..., rules: { entry: <one object OR array> } }. Some responses
// (depending on how deep the xpath resolves) place entry directly under result.
// → NormalizedRule[]
function parseRules(rulesResult) {
  if (!rulesResult || typeof rulesResult !== 'object') {
    console.warn('[PaloAlto parser] parseRules: empty/non-object rules result — no rules parsed');
    return [];
  }

  const rulesNode =
    rulesResult.rules && typeof rulesResult.rules === 'object' ? rulesResult.rules : rulesResult;
  const entries = toArray(rulesNode.entry);

  if (entries.length === 0) {
    console.warn(
      '[PaloAlto parser] parseRules: no <entry> elements found under result/rules — ' +
        'either the rulebase is empty or the response shape differs. Raw keys: ' +
        JSON.stringify(Object.keys(rulesNode))
    );
  }

  return entries.map((entry, idx) => parseRuleEntry(entry, idx));
}

// ---------------------------------------------------------------------------
// Rule hit-count enrichment (XML/API transport) — ADDITIVE, best-effort.
// ---------------------------------------------------------------------------
//
// hitCountResult: the parsed <result> of the `show rule-hit-count` op command
// (api.getRuleHitCount()). ⚠️ The exact response shape is DOC-DERIVED and NOT
// yet verified against a live device — see api.js's buildRuleHitCountCmd()
// comment and CLAUDE.md's "Live Validation Status". The documented shape is
// roughly:
//   <result><rule-hit-count><vsys-name><entry name="vsys1">
//     <rule-base><entry name="security"><rules>
//       <entry name="RuleName"><hit-count>1234</hit-count>...</entry>
//     </rules></entry></rule-base>
//   </entry></vsys-name></rule-hit-count></result>
// but the exact leaf field name for the count (`hit-count` vs `hitcount` vs
// something else entirely) is unconfirmed. Rather than hardcode one guessed
// path, this does a bounded depth-first walk (same "search deep, don't
// assume the absolute path" approach as collectSecurityRuleEntries() above
// and findSecurityRulesContainers() in sshParser.js) for any object that
// carries a rule-identifying '@_name' attribute AND a sibling key whose name
// LOOKS like a hit-count field (matches /hit.?count/i) with a numeric value.
// That is deliberately shape-agnostic so a doc-derived guess about exact
// nesting can't silently return an empty mapping just because one assumed
// path was wrong.
//
// Never throws — returns {} on anything unparseable. Index.js's caller
// (_enrichHitCounts) treats a failure here as non-fatal per CLAUDE.md's
// "hit-count enrichment must never block/throw rule collection" rule; this
// function itself is one more layer of that same safety, not the only one.
const HIT_COUNT_KEY_RE = /hit.?count/i;

function collectHitCounts(node, out, depth) {
  if (depth > 20 || node === null || typeof node !== 'object') return;

  if (Array.isArray(node)) {
    for (const item of node) collectHitCounts(item, out, depth + 1);
    return;
  }

  const name = scalarText(node['@_name']);
  if (name) {
    for (const [key, value] of Object.entries(node)) {
      if (key === '@_name') continue;
      if (!HIT_COUNT_KEY_RE.test(key)) continue;
      const text = scalarText(value);
      const num = text !== null ? Number(text) : NaN;
      if (Number.isFinite(num)) {
        out[name] = num;
        break;
      }
    }
  }

  for (const value of Object.values(node)) {
    if (value !== null && typeof value === 'object') collectHitCounts(value, out, depth + 1);
  }
}

// → { [ruleName]: hitCount } — possibly empty. Never throws.
function parseRuleHitCount(hitCountResult) {
  const out = {};
  if (!hitCountResult || typeof hitCountResult !== 'object') return out;
  try {
    collectHitCounts(hitCountResult, out, 0);
  } catch (err) {
    console.warn(`[PaloAlto parser] parseRuleHitCount: walk failed, returning no hit counts: ${err.message}`);
    return {};
  }
  return out;
}

// Fallback for the predicate-free any-vsys xpath (api.SECURITY_RULES_XPATH_ANY_VSYS).
//
// Why a deep walk instead of a fixed path: when a PAN-OS xpath matches MULTIPLE
// nodes (one rulebase per vsys), the wrapper shape PAN-OS returns is not verified
// against live hardware — and CLAUDE.md is explicit that guessing a response shape
// from documentation is how this codebase gets burned. So rather than assume, walk
// the parsed result and collect every <rules> node that sits directly under a
// <security> node. That is shape-agnostic: it works whether PAN-OS returns repeated
// <rules> siblings, the full <devices><entry><vsys>... spine, or the single-node
// shape parseRules() already handles.
//
// Anchoring on the `security` PARENT key is what keeps the NAT/PBF/QoS rulebases
// (which each also have a <rules> child) out of the security ruleset.
//
// Never throws — returns [] on anything unexpected.
function collectSecurityRuleEntries(node, parentKey, out, depth) {
  if (depth > 40 || node === null || typeof node !== 'object') return;

  if (Array.isArray(node)) {
    // An array inherits its parent's key — <security> containing repeated <rules>
    // parses as { security: { rules: [ ... ] } }.
    for (const item of node) collectSecurityRuleEntries(item, parentKey, out, depth + 1);
    return;
  }

  for (const [key, value] of Object.entries(node)) {
    if (key === 'rules' && parentKey === 'security') {
      for (const rulesNode of toArray(value)) {
        if (rulesNode && typeof rulesNode === 'object') {
          for (const entry of toArray(rulesNode.entry)) out.push(entry);
        }
      }
      continue;
    }
    if (value !== null && typeof value === 'object') {
      collectSecurityRuleEntries(value, key, out, depth + 1);
    }
  }
}

// → NormalizedRule[] (empty when nothing recognisable is found).
function parseRulesDeep(rulesResult) {
  if (!rulesResult || typeof rulesResult !== 'object') return [];

  const entries = [];
  try {
    collectSecurityRuleEntries(rulesResult, null, entries, 0);
  } catch (err) {
    console.warn(`[PaloAlto parser] parseRulesDeep: walk failed, returning no rules: ${err.message}`);
    return [];
  }

  // Rule names are unique per vsys but NOT across vsys, so there is deliberately no
  // de-duplication by name — two vsys may each legitimately own an "allow-web".
  // Document order is preserved; sequence_number runs over the concatenation.
  return entries.map((entry, idx) => parseRuleEntry(entry, idx));
}

// ---------------------------------------------------------------------------
// Effective/merged security policy (XML/API transport) — Panorama-managed
// device fallback, added 2026-07-24.
// ---------------------------------------------------------------------------
//
// Same purpose as sshParser.js's identical-named section (see CLAUDE.md
// "Palo Alto SSH — RESOLVED: Panorama-managed device with no rulebase text
// at all"): a fully Panorama-managed device's LOCAL config tree can have NO
// security-rulebase content at all — every rule is Panorama-pushed and only
// exists in the MERGED effective policy, which `show running security-policy`
// (CLI) / this op command (XML API) returns, not the plain config-get
// rulebase xpath. That CLAUDE.md section explicitly left the XML/API
// transport unbuilt: "its response shape ... has not been live-verified, so
// it wasn't guessed at here." This is that fallback, built the same
// verify-first way is meant to work — but until a real device confirms it,
// treat it as scaffolding, not a finished, trusted parser.
//
// ⚠️ DOC-DERIVED, NOT YET LIVE-VERIFIED. Unlike every other "doc-derived"
// field in this file, this one feeds getRules()'s PRIMARY return value, not
// an additive enrichment (like hit-count) — a wrong guess here is far
// higher-stakes than a wrong number. Two design choices keep that risk
// bounded until a live check happens:
//   1. Shape-agnostic entry DISCOVERY, not a fixed wrapper path. The SSH/CLI
//      version of this exact command needed THREE rounds of live debugging
//      to pin down its own text format (see CLAUDE.md) — assuming one guessed
//      XML wrapper shape here risks the identical mistake. Instead this
//      deep-walks the parsed result for any object carrying BOTH a
//      rule-identifying '@_name' attribute AND an 'action' sibling field —
//      the single most universal signal PAN-OS uses across every rule
//      representation this codebase has already confirmed (plain rulebase
//      entries, and the SSH transport's effective-policy entries alike).
//   2. Tolerant FIELD extraction per rule. The CONFIRMED LIVE CLI/text version
//      of this exact command (sshParser.js) uses a DIFFERENT field vocabulary
//      than the plain rulebase config-get shape parseRuleEntry() above
//      expects — most notably ONE combined "application/service" field (e.g.
//      "0:any/any/any/any") instead of separate application/service fields.
//      That combined field name is a CLI/text-only shape, though: XML
//      element/attribute names cannot contain a '/' character, so PAN-OS's
//      XML rendering of this same command cannot possibly reuse that literal
//      key — extractEffectiveAppsAndServices() below only implements the
//      separate application/service-fields shape (the one that's actually
//      valid under XML naming rules) rather than presenting an
//      XML-impossible combined-key check as a "try this first" branch.
//
// Returns null (NOT []) when zero rule-like entries are found anywhere in
// the response — index.js's caller must treat null as "fallback not usable"
// and fall through to its existing behavior, exactly the same contract
// ssh.js's _getEffectivePolicyRules() already uses. Never throws.
const MAX_EFFECTIVE_POLICY_SEARCH_DEPTH = 25;

function looksLikeEffectivePolicyEntry(node) {
  return (
    node !== null &&
    typeof node === 'object' &&
    !Array.isArray(node) &&
    scalarText(node['@_name']) !== null &&
    node.action !== undefined
  );
}

// Deep walk collecting every rule-like entry anywhere in the tree. Mirrors
// collectSecurityRuleEntries()/collectHitCounts() above in traversal shape.
// A matched entry's own children are never descended into further (a rule
// entry's nested profile-setting object, etc. is never itself a rule).
function collectEffectivePolicyEntries(node, out, depth) {
  if (depth > MAX_EFFECTIVE_POLICY_SEARCH_DEPTH || node === null || typeof node !== 'object') return;

  if (Array.isArray(node)) {
    for (const item of node) collectEffectivePolicyEntries(item, out, depth + 1);
    return;
  }

  if (looksLikeEffectivePolicyEntry(node)) {
    out.push(node);
    return;
  }

  for (const value of Object.values(node)) {
    if (value !== null && typeof value === 'object') collectEffectivePolicyEntries(value, out, depth + 1);
  }
}

// See this section's header comment for why only the separate-fields shape
// is implemented here — the CLI/text transport's combined "application/service"
// field name is not a valid XML element/attribute name, so it can never
// appear as a literal key on a parsed XML response.
function extractEffectiveAppsAndServices(entry) {
  // Separate fields, config-get-style — untested for this specific command
  // (doc-derived, not yet live-verified), but the only shape that's actually
  // possible under XML naming rules for this transport.
  return {
    applications: memberStrings(entry.application),
    services: memberStrings(entry.service),
  };
}

function effectivePolicyEntryToNormalizedRule(entry, idx) {
  const { applications, services } = extractEffectiveAppsAndServices(entry);
  const name = scalarText(entry['@_name']);
  return {
    rule_name: name,
    rule_id_vendor: name,
    sequence_number: idx + 1,
    // Same documented limitation as the SSH transport's identical fallback
    // (sshParser.js): a rule disabled in Panorama or locally is, by
    // definition, not part of the ENFORCED policy, so it never appears in
    // this output at all — there is no way to distinguish "doesn't exist"
    // from "exists but disabled" here.
    enabled: true,
    action: mapAction(entry.action),
    src_zones: memberStrings(entry.from),
    dst_zones: memberStrings(entry.to),
    src_addresses: memberStrings(entry.source),
    dst_addresses: memberStrings(entry.destination),
    services,
    applications,
    schedule: null,
    expiry_date: null,
    // No logging-state field exists in this output (confirmed on the CLI/text
    // transport, assumed here too) — PAN-OS's own platform default (log-at-end
    // enabled) is used rather than guessing "disabled".
    log_enabled: true,
    comment: null,
    // hit_count enrichment needs a confirmed single vsys name the same way
    // the plain rulebase path does — not attempted for this fallback path,
    // same accepted gap as the SSH transport's identical fallback.
    hit_count: 0,
    raw_rule: entry,
  };
}

// result: the parsed <result> of the `show running security-policy` op
// command (api.getEffectiveSecurityPolicy()). -> NormalizedRule[] | null.
function parseEffectiveSecurityPolicy(result) {
  if (!result || typeof result !== 'object') return null;

  const entries = [];
  try {
    collectEffectivePolicyEntries(result, entries, 0);
  } catch (err) {
    console.warn(`[PaloAlto parser] parseEffectiveSecurityPolicy: walk failed, returning null: ${err.message}`);
    return null;
  }

  if (entries.length === 0) return null;

  return entries.map((entry, idx) => effectivePolicyEntryToNormalizedRule(entry, idx));
}

// Builds the `parsed` half of getConfig()'s { raw, parsed } return.
// configResult: the parsed <result> of `show config running` — the actual config
// tree lives under result.config; root the parsed object there so Phase 6 dot-path
// predicates address config keys directly (e.g. 'devices.entry....').
// systemInfoResult: the parsed <result> of `show system info` — merged in under
// parsed.system_info so predicates can also address version/model facts.
function parseConfig(configResult, systemInfoResult) {
  const result = configResult && typeof configResult === 'object' ? configResult : {};
  const root = result.config && typeof result.config === 'object' ? result.config : result;

  const sysResult =
    systemInfoResult && typeof systemInfoResult === 'object' ? systemInfoResult : {};
  const systemInfo =
    sysResult.system && typeof sysResult.system === 'object' ? sysResult.system : sysResult;

  // Shallow copy so we never mutate the caller's parsed tree when merging system_info.
  return { ...root, system_info: systemInfo };
}

// ---------------------------------------------------------------------------
// GlobalProtect current-user count (XML/API transport)
// ---------------------------------------------------------------------------
//
// Backs PaloaltoAdapter.getVpnSessionSummary() (index.js) — see that
// method's own header comment for the full scope-decision rationale
// (GlobalProtect vs. IPsec site-to-site tunnels).
//
// result: the parsed <result> of `show global-protect-gateway current-user`
// (api.getGlobalProtectCurrentUsers()). Response shape confirmed against
// Palo Alto's own published API documentation (docs.paloaltonetworks.com/
// pan-os/10-1/pan-os-panorama-api/pan-os-xml-api-use-cases/
// show-and-manage-globalprotect-users-api, checked 2026-07-30):
//   <response status="success"><result><entry>
//     <domain/><islocal>yes</islocal><username>...</username>
//     <computer>...</computer><client>...</client><vpn-type>...</vpn-type>
//     <virtual-ip>...</virtual-ip><public-ip>...</public-ip>
//     <tunnel-type>...</tunnel-type><login-time>...</login-time>
//     <login-time-utc>...</login-time-utc><lifetime>...</lifetime>
//   </entry></result></response>
// — one <entry> per active session (fast-xml-parser's usual single-vs-array
// collapse applies, hence toArray()). This IS the officially documented
// shape (unlike most of this file's other doc-derived op commands), but has
// never been run against a real device from this codebase — treat as
// doc-derived-but-officially-documented, not live-verified, same standing
// caveat as everything else in this file per CLAUDE.md's Live Validation
// Status.
//
// PAN-OS's own established "nothing matched" convention — already relied on
// elsewhere in this file, see DEFAULT_VSYS's own comment: an empty match
// answers `<response status="success"><result/></response>`, which
// fast-xml-parser collapses to '' / null / an empty object depending on
// exact whitespace. All of those are treated as a CONFIRMED zero sessions,
// not an unrecognized shape. Only an object result with NEITHER of those
// empty forms NOR a scannable 'entry' key is genuinely unrecognized — this
// codebase's "refuse to guess a session count" rule (mirrors Fortinet's
// cliParser.countActiveVpnSessions() returning null on an unrecognized
// shape) applies identically here: returns null (not 0) so the caller can
// throw rather than silently reporting a wrong zero.
// → entry[] | null (null = unrecognized shape, never a guessed 0).
function parseGlobalProtectCurrentUsers(result) {
  if (result === null || result === undefined || result === '') return [];
  if (typeof result !== 'object') return null;
  if (Object.keys(result).length === 0) return [];
  if (result.entry === undefined) return null;
  return toArray(result.entry);
}

// First non-empty scalar among `keys` on `obj` (string trimmed, or a number
// stringified) -- null if none. Small local helper, per this codebase's
// duplicate-small-helper-per-file convention (sshParser.js has its own copy
// for the SSH-text equivalent).
function pickGpField(obj, keys) {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'string' && v.trim() !== '') return v.trim();
    if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  }
  return null;
}

function gpIntOrNull(v) {
  if (v == null) return null;
  const n = parseInt(String(v), 10);
  return Number.isFinite(n) ? n : null;
}

// An all-zeros / unspecified address (`::`, `0.0.0.0`) is what PAN-OS reports
// for the IP family a client ISN'T using (e.g. an IPv4-only GlobalProtect user
// still has a `::` public-ipv6 field) — noise, not a real address. Treat it as
// absent so the picker falls through to the family that actually has a value.
function isUnspecifiedIp(v) {
  return v === '::' || v === '0.0.0.0' || v === '::/0' || v === '0.0.0.0/0';
}

// Like pickGpField but skips unspecified addresses.
function pickGpIp(obj, keys) {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'string') {
      const t = v.trim();
      if (t && !isUnspecifiedIp(t)) return t;
    }
  }
  return null;
}

// Normalizes the raw <entry> objects parseGlobalProtectCurrentUsers() returns
// (fast-xml-parser output, hyphenated element names) into the vendor-agnostic
// active-session shape stored in vpn_active_sessions (see
// lib/engines/vpnSessions.js). Field names are DOC-DERIVED from Palo Alto's
// `show global-protect-gateway current-user` XML response (username, computer,
// virtual-ip, public-ip, login-time, lifetime, gateway-name) and NOT
// live-verified -- so every field is picked from a small candidate list and
// missing fields degrade to null rather than throwing. The `[PaloAlto Debug]`
// raw-response log in index.js's getVpnSessionSummary() is what a real device
// is validated against; correct any field name here once that output is seen.
// Never throws -- caller treats a thrown/empty result as "no session detail",
// leaving the authoritative active_session_count untouched.
function normalizeGlobalProtectUsers(entries) {
  const list = Array.isArray(entries) ? entries : [];
  const out = [];
  for (const e of list) {
    if (!e || typeof e !== 'object') continue;
    out.push({
      username: pickGpField(e, ['username', 'primary-username', 'domain-user-name', '@_name']),
      tunnel_type: 'GlobalProtect',
      source_ip: pickGpIp(e, [
        'public-ip',
        'public-connection-ipv4',
        'client-ip',
        'client-source-ip',
        'public-ipv6',
        'public-connection-ipv6',
        'source-ip',
      ]),
      assigned_ip: pickGpIp(e, ['virtual-ip', 'assign-ip', 'assigned-ip', 'tunnel-ip', 'virtual-ip-v6']),
      login_time: pickGpField(e, ['login-time', 'login-time-utc']),
      duration_seconds: gpIntOrNull(pickGpField(e, ['lifetime', 'login-duration', 'session-duration'])),
      bytes_in: null,
      bytes_out: null,
      client: pickGpField(e, ['computer', 'client', 'host-id', 'machine-name']),
      gateway: pickGpField(e, ['gateway-name', 'gateway']),
      raw: e,
    });
  }
  return out;
}

// Normalizes the `show vpn ipsec-sa` XML result (the op command in
// api.js:getIpsecTunnels) into the vendor-agnostic tunnel shape stored in
// vpn_ipsec_tunnels (see lib/engines/vpnTunnels.js). The result shape varies
// (`result.entries.entry` or `result.entry`); both are handled. DOC-DERIVED
// field names, every field degrades to null; validated later via index.js's
// `[PaloAlto Debug]` raw-response log. Never throws.
function normalizeIpsecTunnels(result) {
  let entries = [];
  if (result && typeof result === 'object') {
    if (result.entries && result.entries.entry !== undefined) entries = toArray(result.entries.entry);
    else if (result.entry !== undefined) entries = toArray(result.entry);
  }
  const out = [];
  for (const e of entries) {
    if (!e || typeof e !== 'object') continue;
    const stateRaw = pickGpField(e, ['state', 'status']);
    let status = 'up';
    if (stateRaw) {
      if (/active|up|establish|complete|mature/i.test(stateRaw)) status = 'up';
      else if (/down|inactive|init|expir|dead/i.test(stateRaw)) status = 'down';
      else status = stateRaw;
    }
    out.push({
      name: pickGpField(e, ['name', 'tunnel', 'tunnel-name', '@_name']),
      peer: pickGpField(e, ['remote', 'peerip', 'peer-ip', 'peer', 'gwip', 'remote-ip', 'gw']),
      status,
      ike_version: pickGpField(e, ['ike-version', 'ikev', 'version']),
      bytes_in: gpIntOrNull(pickGpField(e, ['decap-bytes', 'bytes-in', 'inbytes', 'bytes-dec'])),
      bytes_out: gpIntOrNull(pickGpField(e, ['encap-bytes', 'bytes-out', 'outbytes', 'bytes-enc'])),
      raw: e,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Secret redaction (XML/API transport)
// ---------------------------------------------------------------------------
//
// ⛔ MANDATORY — CLAUDE.md: "Any NEW adapter that returns a raw text config MUST
// redact before returning it from getConfig()." This transport was missing it
// entirely (found in a full-app audit, 2026-07-16): the SSH sibling
// (sshParser.js's redactConfig/SECRET_TOKENS) redacts these exact PAN-OS fields
// for this exact reason, but the XML/API transport — this vendor's DEFAULT
// mgmt_method — never got the equivalent treatment. A PAN-OS config carries
// admin phash hashes, IKE/IPsec pre-shared keys, SNMPv3 auth/priv passwords,
// and RADIUS/LDAP/TACACS+ bind secrets. getConfig()'s `raw` is persisted
// verbatim into device_configs.config_raw, copied into config_backups, served
// by the backup download route — and BOTH tables are GRANT SELECT'd to the
// claude_readonly / nocvault_readonly roles, the exact roles CLAUDE.md bars
// from device_credentials. Nothing downstream redacts. It happens here or not
// at all.
//
// Deliberately NOT shared with sshParser.js's SECRET_TOKENS — that file's own
// header states it is "SEPARATE FROM parser.js ON PURPOSE" (this file parses
// XML API objects; sshParser.js parses CLI text), matching the same
// independent-redaction-per-format convention already used across
// cisco_asa/parser.js, fortinet/parser.js + cliParser.js, and sangfor/parser.js.
const SECRET_TAGS = [
  'phash',
  'password',
  'passwd',
  'password-hash',
  'hashed-password',
  'passphrase',
  'certificate-passphrase',
  'secret',
  'client-secret',
  'pre-shared-key',
  'key',
  'auth-key',
  'esp-auth-key',
  'private-key',
  'bind-password',
  'snmp-community-string',
  'community-string',
  'authpwd',
  'privpwd',
  'api-key',
  'auth-code',
];
const REDACTED_XML = '<redacted>';

// Redacts secret-bearing elements/attributes in a raw PAN-OS config XML string.
// MUST be applied before the text leaves the adapter. Matches BOTH
// `<tag>value</tag>` elements and `tag="value"` attributes for each secret tag
// name, case-insensitively — PAN-OS's XML API can represent the same leaf
// field either way depending on the schema node, and this is fail-closed by
// design (an address object literally named e.g. "secret" also gets scrubbed
// rather than risk a miss).
function redactConfigXml(text) {
  if (typeof text !== 'string' || text.length === 0) return '';
  let result = text;
  for (const tag of SECRET_TAGS) {
    const elementRe = new RegExp(`(<${tag}>)([\\s\\S]*?)(</${tag}>)`, 'gi');
    result = result.replace(elementRe, `$1${REDACTED_XML}$3`);
    const attrRe = new RegExp(`(\\b${tag}=")([^"]*)(")`, 'gi');
    result = result.replace(attrRe, `$1${REDACTED_XML}$3`);
  }
  return result;
}

// Recursively redacts secret-named keys anywhere in a parsed config object
// tree (fast-xml-parser output — attribute keys carry the '@_' prefix, stripped
// before matching). Fails closed: replaces the WHOLE value for a matching key
// (string, number, or an entire nested object/array) rather than trying to be
// clever about partial redaction within it. Never mutates the input.
function redactConfigTree(node) {
  if (Array.isArray(node)) return node.map(redactConfigTree);
  if (node && typeof node === 'object') {
    const out = {};
    for (const [key, value] of Object.entries(node)) {
      const bareKey = key.replace(/^@_/, '').toLowerCase();
      out[key] = SECRET_TAGS.includes(bareKey) ? REDACTED_XML : redactConfigTree(value);
    }
    return out;
  }
  return node;
}

// ---------------------------------------------------------------------------
// Network object catalog (XML/API transport) — FirewallAdapter's OPTIONAL
// getObjects(). See lib/adapters/interface.js for the exact contract and
// CLAUDE.md's "Network Object Catalog" section.
//
// Deliberately reads back the ALREADY-STORED device_configs.config_parsed
// (index.js's getObjects() does this via getLatestConfigParsed()) rather than
// making a new live device call — the full config tree parseConfig() already
// builds contains every address/address-group/service/service-group
// definition, on both transports. This mirrors vpnSummary.js's
// summarizePaloAlto()/adminAccountSummary.js's summarizePaloAltoXml()
// "read what was already collected" pattern exactly, just for a different
// slice of the same tree.
//
// PAN-OS config nesting varies (bare single-vsys root, `shared`, `vsys.entry`,
// Panorama device-group/template shapes) — same structural variability
// findSecurityRulesContainers() (sshParser.js) already documents having to
// search deep for. So this does a bounded depth-first search for the four
// object-container key names, collecting EVERY container found anywhere in
// the tree (not just the first), the same "search deep, don't assume one
// path" approach, rather than fixing on e.g. `shared.address` alone.
//
// All four extraction passes are wrapped individually (extractObjects()
// below) — a malformed/unexpected shape in one category must not lose the
// other three. Doc-derived: no live PAN-OS device with object catalog data
// has verified these exact field names yet (see CLAUDE.md's Live Validation
// Status — the SSH transport's brace-tree grammar for RULES is confirmed
// live, but address/service object shapes specifically have not been).

const OBJECT_CONTAINER_KEYS = ['address', 'address-group', 'service', 'service-group'];
const MAX_OBJECT_SEARCH_DEPTH = 10;

// Depth-first search collecting every node found under any of the four
// object-container key names, anywhere in the tree. `out` is mutated:
// { address: [node, ...], 'address-group': [...], service: [...], 'service-group': [...] }.
// Mirrors collectSecurityRuleEntries()'s traversal shape above. Never throws —
// any unexpected node shape is simply not descended into.
function collectObjectContainers(node, out, depth) {
  if (depth > MAX_OBJECT_SEARCH_DEPTH || node === null || typeof node !== 'object') return;

  if (Array.isArray(node)) {
    for (const item of node) collectObjectContainers(item, out, depth + 1);
    return;
  }

  for (const [key, value] of Object.entries(node)) {
    if (OBJECT_CONTAINER_KEYS.includes(key) && value && typeof value === 'object') {
      if (!out[key]) out[key] = [];
      out[key].push(value);
    }
    if (value !== null && typeof value === 'object') {
      collectObjectContainers(value, out, depth + 1);
    }
  }
}

// PAN-OS address entry: { '@_name': name, 'ip-netmask'|'ip-range'|'ip-wildcard'|'fqdn': value }.
// value/type resolution order matches PAN-OS's own mutually-exclusive address-type choices.
function extractAddressEntries(containers) {
  const out = [];
  for (const container of containers) {
    for (const entry of toArray(container.entry)) {
      if (!entry || typeof entry !== 'object') continue;
      const name = scalarText(entry['@_name']);
      if (!name) continue;
      let type = null;
      let value = null;
      if (entry['ip-netmask'] !== undefined) {
        type = 'ip-netmask';
        value = scalarText(entry['ip-netmask']);
      } else if (entry['ip-range'] !== undefined) {
        type = 'ip-range';
        value = scalarText(entry['ip-range']);
      } else if (entry['ip-wildcard'] !== undefined) {
        type = 'ip-wildcard';
        value = scalarText(entry['ip-wildcard']);
      } else if (entry.fqdn !== undefined) {
        type = 'fqdn';
        value = scalarText(entry.fqdn);
      }
      out.push({ name, type, value });
    }
  }
  return out;
}

// PAN-OS address-group entry: { '@_name': name, static: { member: [...] } } for a
// static group, or { '@_name': name, dynamic: { filter: '...' } } for a dynamic
// (filter-based) one. Dynamic groups have no fixed member list — per the
// contract, rendered as members: [] rather than attempting to resolve the filter.
function extractAddressGroupEntries(containers) {
  const out = [];
  for (const container of containers) {
    for (const entry of toArray(container.entry)) {
      if (!entry || typeof entry !== 'object') continue;
      const name = scalarText(entry['@_name']);
      if (!name) continue;
      const members = entry.static ? memberStrings(entry.static) : [];
      out.push({ name, members });
    }
  }
  return out;
}

// PAN-OS service entry: { '@_name': name, protocol: { tcp: { port: '443' } } }
// (or udp). value is derived as e.g. "tcp/443" — sctp is not a PAN-OS protocol
// choice here, so only tcp/udp are checked.
function extractServiceEntries(containers) {
  const out = [];
  for (const container of containers) {
    for (const entry of toArray(container.entry)) {
      if (!entry || typeof entry !== 'object') continue;
      const name = scalarText(entry['@_name']);
      if (!name) continue;
      const protocol = entry.protocol && typeof entry.protocol === 'object' ? entry.protocol : {};
      let value = null;
      if (protocol.tcp && typeof protocol.tcp === 'object') {
        const port = scalarText(protocol.tcp.port);
        if (port) value = `tcp/${port}`;
      } else if (protocol.udp && typeof protocol.udp === 'object') {
        const port = scalarText(protocol.udp.port);
        if (port) value = `udp/${port}`;
      }
      out.push({ name, value });
    }
  }
  return out;
}

// PAN-OS service-group entry: { '@_name': name, members: { member: [...] } }.
function extractServiceGroupEntries(containers) {
  const out = [];
  for (const container of containers) {
    for (const entry of toArray(container.entry)) {
      if (!entry || typeof entry !== 'object') continue;
      const name = scalarText(entry['@_name']);
      if (!name) continue;
      const members = memberStrings(entry.members);
      out.push({ name, members });
    }
  }
  return out;
}

// → { addresses, addressGroups, services, serviceGroups } — see
// lib/adapters/interface.js for the exact contract. Never throws: an
// unreadable tree (or one with no object containers at all) yields all-empty
// arrays, and each of the four extraction passes is independently guarded so
// one category's malformed data can't lose the other three.
function extractObjects(configTree) {
  const result = { addresses: [], addressGroups: [], services: [], serviceGroups: [] };
  if (!configTree || typeof configTree !== 'object') return result;

  const containers = {};
  try {
    collectObjectContainers(configTree, containers, 0);
  } catch (err) {
    console.warn(`[PaloAlto parser] extractObjects: container search failed: ${err.message}`);
    return result;
  }

  try {
    result.addresses = extractAddressEntries(containers.address || []);
  } catch (err) {
    console.warn(`[PaloAlto parser] extractObjects: address extraction failed: ${err.message}`);
  }
  try {
    result.addressGroups = extractAddressGroupEntries(containers['address-group'] || []);
  } catch (err) {
    console.warn(`[PaloAlto parser] extractObjects: address-group extraction failed: ${err.message}`);
  }
  try {
    result.services = extractServiceEntries(containers.service || []);
  } catch (err) {
    console.warn(`[PaloAlto parser] extractObjects: service extraction failed: ${err.message}`);
  }
  try {
    result.serviceGroups = extractServiceGroupEntries(containers['service-group'] || []);
  } catch (err) {
    console.warn(`[PaloAlto parser] extractObjects: service-group extraction failed: ${err.message}`);
  }

  return result;
}

// ── Topology XML parsers (added 2026-08-03, live-verified against ITC-SLY)
// — see api.js's showInterfacesAll()/showRoutingRoute() header comments for
// the confirmed command/response shapes. No NAT XML parser here: the NAT
// op-command's response is byte-identical in FORMAT to the SSH transport's
// plain text, so paloalto/index.js's getNatRules() reuses
// sshParser.parseNatPolicyOutput() directly instead of a second parser.

// `show interface all`'s <ifnet><entry>...</entry></ifnet> section — the
// <hw> section (physical link state) is deliberately NOT cross-referenced
// for an `enabled` flag: sub-interfaces (e.g. ae1.201) don't appear in <hw>
// at all (only physical/aggregate parents do), so a name-based join would
// leave most entries with no match anyway. Every ifnet entry that reports a
// real `<ip>` is treated as enabled — a device reporting a configured
// address on a logical/sub-interface is virtually always the one in active
// use; documented simplification, not a silent gap.
function parseInterfacesXml(result) {
  const ifnet = result && typeof result === 'object' ? result.ifnet : null;
  const entries = toArray(ifnet && ifnet.entry);
  const out = [];
  for (const entry of entries) {
    const name = scalarText(entry && entry.name);
    const ip = scalarText(entry && entry.ip);
    if (!name || !ip) continue; // no configured address -- nothing usable for topology
    const zone = scalarText(entry && entry.zone);
    out.push({ name, ipAddress: ip, zone: zone || null, vdom: null, enabled: true });
  }
  return out;
}

// `show routing route`'s <result><entry>...</entry></result> list — clean
// structured fields (destination/nexthop/metric/flags/interface), same
// flag-based classification as the SSH transport's text parser
// (sshParser.js's parseRoutingTableOutput) but with none of that function's
// positional-token-guessing: every field already arrives pre-separated.
function parseRoutingTableXml(result) {
  const entries = toArray(result && result.entry);
  const out = [];
  for (const entry of entries) {
    const destination = scalarText(entry && entry.destination);
    if (!destination) continue;
    const nexthop = scalarText(entry && entry.nexthop);
    const flagsText = scalarText(entry && entry.flags) || '';
    const flags = flagsText.split(/\s+/).filter(Boolean);
    const interfaceName = scalarText(entry && entry.interface);
    const metricText = scalarText(entry && entry.metric);

    const isConnected = flags.includes('C');
    const isHost = flags.includes('H');
    if (isHost) continue; // route to the interface's own /32 -- no path-decision value, would wrongly out-rank real routes as most-specific

    let protocol = 'other';
    if (isConnected) protocol = 'connected';
    else if (flags.includes('S')) protocol = 'static';
    else if (flags.some((f) => f[0] === 'O')) protocol = 'ospf';
    else if (flags.includes('B')) protocol = 'bgp';
    else if (flags.includes('R')) protocol = 'rip';

    out.push({
      destinationCidr: destination,
      nextHopIp: isConnected || nexthop === '0.0.0.0' ? null : nexthop,
      interfaceName: interfaceName || null,
      protocol,
      metric: metricText !== null ? parseInt(metricText, 10) : null,
      vdom: null,
    });
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────
// Device lifecycle & health (added 2026-08-03) — licences + content versions.
// Disk and HA are NOT here: both return plain text identical to the SSH
// transport's output, so ./sshParser.js's parsers are reused for both
// transports (see this file's sibling note in api.js).
// ─────────────────────────────────────────────────────────────────────────

// Palo Alto reports licence dates as human-readable strings ("September 16,
// 2027", "Never"). Returns a YYYY-MM-DD string or null — never a guess.
//
// Deliberately duplicated in ./sshParser.js rather than shared: it is a tiny
// pure helper, and this file and sshParser.js are separate on purpose (see
// sshParser.js's own header). Same "small per-adapter helpers are duplicated,
// not imported" convention the topology/objectResolver engines already follow.
const LICENSE_MONTHS = {
  january: 1, february: 2, march: 3, april: 4, may: 5, june: 6,
  july: 7, august: 8, september: 9, october: 10, november: 11, december: 12,
};

function parseLicenseDate(raw) {
  if (typeof raw !== 'string') return null;
  const text = raw.trim();
  if (!text) return null;
  // "September 16, 2027" / "May 20, 2026"
  const m = text.match(/^([A-Za-z]+)\s+(\d{1,2}),\s*(\d{4})$/);
  if (!m) return null; // includes "Never" — a perpetual licence has NO date, by design
  const month = LICENSE_MONTHS[m[1].toLowerCase()];
  if (!month) return null;
  const day = Number(m[2]);
  const year = Number(m[3]);
  if (!Number.isInteger(day) || day < 1 || day > 31) return null;
  return `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
}

// Normalizes one licence entry (already-plain object, from either transport)
// into the device_licenses row shape. Shared by parseLicensesXml() below and
// sshParser.parseLicenseInfoOutput(), which each handle only their own
// transport's field extraction.
function normalizeLicenseEntry({ feature, description, serial, issued, expires, expired, authcode }) {
  const featureText = typeof feature === 'string' ? feature.trim() : '';
  if (!featureText) return null; // a licence with no feature name is not usable data
  const expiresRaw = typeof expires === 'string' ? expires.trim() : null;
  return {
    feature: featureText,
    description: typeof description === 'string' ? description.trim() || null : null,
    serial: typeof serial === 'string' ? serial.trim() || null : null,
    issuedAt: parseLicenseDate(issued),
    // null expiresAt + expiresRaw 'Never' = perpetual; null + anything else =
    // unparsed/unknown. The DB column comment and deviceHealth.licenseStatus()
    // both depend on this distinction being preserved, not flattened.
    expiresAt: parseLicenseDate(expires),
    expiresRaw: expiresRaw,
    // The device's OWN verdict, not ours. null when not reported.
    expired: typeof expired === 'string' ? /^yes$/i.test(expired.trim()) : null,
    authcode: typeof authcode === 'string' ? authcode.trim() || null : null,
  };
}

// `request license info` XML → { licenses: [...] }.
// Live-verified 2026-08-03 against ITC-SLY: <result><licenses><entry> with
// <feature>/<description>/<serial>/<issued>/<expires>/<expired>/<authcode>.
function parseLicensesXml(result) {
  const root = result && typeof result === 'object' ? result : {};
  const container = root.licenses && typeof root.licenses === 'object' ? root.licenses : root;
  const entries = toArray(container.entry);
  const licenses = [];
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') continue;
    const normalized = normalizeLicenseEntry({
      feature: scalarText(entry.feature),
      description: scalarText(entry.description),
      serial: scalarText(entry.serial),
      issued: scalarText(entry.issued),
      expires: scalarText(entry.expires),
      expired: scalarText(entry.expired),
      authcode: scalarText(entry.authcode),
    });
    if (normalized) licenses.push(normalized);
  }
  return { licenses };
}

// Content/signature version components as reported by `show system info`.
// Field names live-verified 2026-08-03. `url_filtering` has a version but NO
// matching *-release-date field on PAN-OS — its version string appears to
// encode a date (e.g. "20260803.20137"), but that is NOT parsed into
// released_at here: inferring a timestamp from a version string is exactly the
// kind of guess this codebase avoids. It stays null (→ "unknown" age), while
// the version itself is still stored and displayed.
const CONTENT_VERSION_FIELDS = [
  { component: 'app', versionKey: 'app-version', dateKey: 'app-release-date' },
  { component: 'av', versionKey: 'av-version', dateKey: 'av-release-date' },
  { component: 'threat', versionKey: 'threat-version', dateKey: 'threat-release-date' },
  { component: 'wildfire', versionKey: 'wildfire-version', dateKey: 'wildfire-release-date' },
  { component: 'url_filtering', versionKey: 'url-filtering-version', dateKey: null },
  { component: 'device_dictionary', versionKey: 'device-dictionary-version', dateKey: 'device-dictionary-release-date' },
];

// PAN-OS release dates look like "2026/07/31 02:42:29 +07". Built explicitly
// rather than handed to `new Date(...)`: that string is not an ISO-8601 form
// and its "+07" (no minutes) offset parses inconsistently across engines —
// exactly the kind of silent, environment-dependent wrongness that would make
// a signature look days older or newer than it is.
function parseContentReleaseDate(raw) {
  if (typeof raw !== 'string') return null;
  const text = raw.trim();
  if (!text || /^unknown$/i.test(text)) return null;
  const m = text.match(
    /^(\d{4})\/(\d{2})\/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\s*([+-])(\d{2}):?(\d{2})?)?$/
  );
  if (!m) return null;
  const [, y, mo, d, h, mi, s, sign, offH, offM] = m;
  const offset = sign ? `${sign}${offH}:${offM || '00'}` : 'Z';
  const iso = `${y}-${mo}-${d}T${h}:${mi}:${s}${offset}`;
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

// Extracts content/signature versions from an ALREADY-FETCHED `show system
// info` result — issues no new device command. Works on both transports'
// shapes: the XML tree (this transport) and sshParser's flat key/value object.
// → [{ component, version, releasedAt }]
function extractContentVersions(systemInfoLike) {
  const src = systemInfoLike && typeof systemInfoLike === 'object' ? systemInfoLike : {};
  const system = src.system && typeof src.system === 'object' ? src.system : src;
  const out = [];
  for (const { component, versionKey, dateKey } of CONTENT_VERSION_FIELDS) {
    const version = scalarText(system[versionKey]);
    // '0' is PAN-OS's "this component is not installed" marker (seen live on
    // wf-private-version / global-protect-datafile-version) — not a real
    // version, so it is skipped rather than stored as a bogus signature.
    if (!version || version === '0') continue;
    out.push({
      component,
      version,
      releasedAt: dateKey ? parseContentReleaseDate(scalarText(system[dateKey])) : null,
    });
  }
  return out;
}

// `show high-availability state` XML → normalized HA status, SAME shape as
// sshParser.parseHaStateOutput() returns.
//
// ⛔ Live-verified 2026-08-03 against IDC FW and PAKFood, and this parser exists
// BECAUSE that check contradicted an assumption: the XML API returns a fully
// STRUCTURED tree for an HA-ENABLED device (<group><local-info>/<peer-info>),
// NOT the plain-text block the CLI prints and NOT the shape a standalone device
// returns. The only API sample available when this feature was first written was
// a standalone device (<enabled>no</enabled>), so reusing the text parser here
// "worked" in testing and would have silently stored nothing for every real HA
// pair on the API transport. Verify per-device-state, not just per-command.
//
// The API also exposes MORE than the CLI text: per-component `*-compat` fields
// (including `url-compat`, absent from the CLI's Version Compatibility block —
// live, IDC FW reports url-compat Mismatch), and it splits the peer's last error
// into `last-error-state` + `last-error-reason` rather than one prose label.
function parseHaStateXml(result) {
  const root = result && typeof result === 'object' ? result : {};
  const enabledText = scalarText(root.enabled);
  if (enabledText && /^no$/i.test(enabledText.trim())) {
    return {
      enabled: false, mode: null, groupId: null, localState: null, peerState: null,
      peerMgmtIp: null, peerSerial: null, peerConnectionStatus: null, configSyncState: null,
      lastNonfunctionalReason: null, versionCompatOk: null, versionCompat: null,
      raw: { source: 'api-xml', enabled: 'no' },
    };
  }
  const group = root.group && typeof root.group === 'object' ? root.group : null;
  if (!group) return null; // unrecognized shape — store nothing rather than a guess

  const local = group['local-info'] && typeof group['local-info'] === 'object' ? group['local-info'] : {};
  const peer = group['peer-info'] && typeof group['peer-info'] === 'object' ? group['peer-info'] : {};

  // Only keys ending in `-compat` are unambiguous Match/Mismatch verdicts.
  // `<DLP>` is deliberately excluded: it carries "Match" in local-info but a
  // version string ("5.0.4") in peer-info, so treating it as a verdict would be
  // reading two different things through one name.
  const versionCompat = {};
  for (const key of Object.keys(local)) {
    if (!/-compat$/.test(key)) continue;
    const v = scalarText(local[key]);
    if (v) versionCompat[key] = v;
  }
  const compatKeys = Object.keys(versionCompat);
  const versionCompatOk =
    compatKeys.length === 0 ? null : compatKeys.every((k) => /^match$/i.test(versionCompat[k].trim()));

  // The API splits what the CLI merges. A peer whose last error STATE was
  // "suspended" (live: reason "User requested") is a deliberate admin action on
  // an otherwise healthy pair and must NOT read as a fault — same rule the SSH
  // parser enforces, just with a cleaner signal to key off.
  const lastErrorState = scalarText(peer['last-error-state']);
  const lastErrorReason = scalarText(peer['last-error-reason']);
  const isFault = lastErrorState ? !/^suspended$/i.test(lastErrorState.trim()) : false;

  const mgmtIp = scalarText(peer['mgmt-ip']);
  const raw = { source: 'api-xml' };
  if (lastErrorState) raw.lastErrorState = lastErrorState;
  if (lastErrorReason) raw.lastErrorReason = lastErrorReason;
  const localDur = scalarText(local['state-duration']);
  const peerDur = scalarText(peer['state-duration']);
  if (localDur) raw.localStateDurationSeconds = localDur;
  if (peerDur) raw.peerStateDurationSeconds = peerDur;

  return {
    enabled: true,
    mode: scalarText(group.mode) || scalarText(local.mode) || null,
    // The XML response carries no HA group NUMBER (the CLI prints "Group 33:").
    // Left null rather than invented.
    groupId: null,
    localState: (scalarText(local.state) || '').toLowerCase() || null,
    peerState: (scalarText(peer.state) || '').toLowerCase() || null,
    peerMgmtIp: mgmtIp ? mgmtIp.split('/')[0].trim() || null : null,
    peerSerial: scalarText(peer['serial-num']) || null,
    peerConnectionStatus: (scalarText(peer['conn-status']) || '').toLowerCase() || null,
    configSyncState: (scalarText(group['running-sync']) || '').toLowerCase() || null,
    lastNonfunctionalReason: isFault ? lastErrorReason || lastErrorState : null,
    versionCompatOk,
    versionCompat: compatKeys.length > 0 ? versionCompat : null,
    raw,
  };
}

module.exports = {
  parseSystemInfo,
  parseLicensesXml,
  parseHaStateXml,
  extractContentVersions,
  normalizeLicenseEntry,
  parseLicenseDate,
  parseContentReleaseDate,
  parseRules,
  parseRulesDeep,
  parseRuleHitCount,
  parseEffectiveSecurityPolicy,
  parseGlobalProtectCurrentUsers,
  normalizeGlobalProtectUsers,
  normalizeIpsecTunnels,
  parseConfig,
  redactConfigXml,
  redactConfigTree,
  extractObjects,
  parseInterfacesXml,
  parseRoutingTableXml,
  // exported for testing / reuse, not part of the documented contract
  toArray,
  memberStrings,
  mapAction,
  scalarText,
};
