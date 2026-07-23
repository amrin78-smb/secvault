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

module.exports = {
  parseSystemInfo,
  parseRules,
  parseRulesDeep,
  parseRuleHitCount,
  parseConfig,
  redactConfigXml,
  redactConfigTree,
  extractObjects,
  // exported for testing / reuse, not part of the documented contract
  toArray,
  memberStrings,
  mapAction,
  scalarText,
};
