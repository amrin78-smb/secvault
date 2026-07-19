// lib/adapters/forcepoint/parser.js
// CommonJS ONLY — required by lib/adapters/forcepoint/index.js, which in turn is
// required by services/engine-worker.js (plain node, CommonJS).
//
// Pure functions only — no I/O, no network, no DB access. These functions must NEVER
// throw on malformed/unexpected input (only smc.js's network calls should throw) —
// SMC field names vary between 6.x and 7.x per CLAUDE.md, so every lookup here is
// defensive with safe fallbacks. ONE deliberate exception: parsePolicy() throws when
// NEITHER known rules-field name is present at all (see its own comment) — a
// field-name mismatch is a retrieval failure, not malformed data, and CLAUDE.md
// requires getRules() to throw rather than let that look like a genuinely empty
// ruleset.

// Best-effort mapping from SMC action vocabulary to the NormalizedRule vocabulary
// ('allow'|'deny'|'drop'|'reject'). Unrecognized values pass through as-is rather than
// crashing — better to surface an odd raw value than throw during rule collection.
function mapAction(rawAction) {
  if (rawAction === null || rawAction === undefined) return null;
  const value = String(rawAction).toLowerCase();
  switch (value) {
    case 'allow':
    case 'permit':
      return 'allow';
    case 'discard':
    case 'drop':
      return 'drop';
    case 'refuse':
    case 'reject':
      return 'reject';
    case 'deny':
      return 'deny';
    case 'continue':
      return 'continue';
    default:
      // Unrecognized — pass the raw string through rather than crashing.
      return rawAction;
  }
}

// engineElement field names for the running software version differ between SMC 6.x
// and 7.x (and possibly between engine types). Check known candidate fields in order,
// use the first non-empty string found. Never throw — return a safe "unknown" shape.
function parseEngineVersion(engineElement) {
  if (!engineElement || typeof engineElement !== 'object') {
    console.warn('[Forcepoint parser] parseEngineVersion: no engine element provided');
    return { version_string: null, version_tuple: [0], model: 'unknown' };
  }

  // NOTE (CLAUDE.md Bug 5, bug-sweep 2026-07-17): `dynamic_package` is Forcepoint/
  // Stonesoft terminology for the installed signature/Dynamic Update package version —
  // a DIFFERENT concept from the engine firmware version this function needs to
  // report. It used to be checked second (ahead of the conceptually-correct
  // `engine_version`), so any engine element carrying both `dynamic_package` and
  // `engine_version` but no `software_version` would silently report the signature
  // package version as the firmware version — which then feeds CVE version-matching
  // directly. Reordered so `engine_version` is preferred and `dynamic_package` is only
  // a last-resort guess. Lower-confidence, doc-derived: SMC field names are still
  // unverified against live hardware (see CLAUDE.md "Live Validation Status" — no
  // Forcepoint device has been live-tested) — revisit once a real SMC engine element
  // is captured via the `[SMC Debug]` log.
  const candidates = [
    engineElement.software_version,
    engineElement.version,
    engineElement.attributes && engineElement.attributes.version,
    engineElement.engine_version,
    engineElement.dynamic_package,
  ];

  let versionString = null;
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      versionString = candidate.trim();
      break;
    }
  }

  const model = engineElement.model || engineElement.type || engineElement.name || 'unknown';

  if (!versionString) {
    console.warn(
      '[Forcepoint parser] parseEngineVersion: no known version field found on engine element — ' +
        'field names may have changed between SMC versions. Raw keys: ' +
        JSON.stringify(Object.keys(engineElement))
    );
    return { version_string: null, version_tuple: [0], model };
  }

  // Forcepoint version scheme (per CLAUDE.md): "6.10.21" -> [6, 10, 21]. No hotfix suffixes.
  const versionTuple = versionString
    .split('.')
    .map((segment) => parseInt(segment, 10) || 0);

  return { version_string: versionString, version_tuple: versionTuple, model };
}

// Builds a lookup map keyed by both href and name for resolving { ref } fields.
function buildRefIndex(elements) {
  const byKey = new Map();
  if (!Array.isArray(elements)) return byKey;

  for (const el of elements) {
    if (!el || typeof el !== 'object') continue;
    if (el.href) byKey.set(el.href, el);
    if (el.key) byKey.set(el.key, el);
    if (el.name) byKey.set(el.name, el);
  }
  return byKey;
}

// Resolves a single ref value (string href/id, or { ref: 'href-or-id' } object) against
// an index built from network/service elements. Falls back to the raw ref if no match
// is found — never throws on an unresolved reference.
function resolveRef(ref, index) {
  if (ref === null || ref === undefined) return ref;

  // SMC's convention for "unrestricted" (any source / any destination / any service)
  // is a { any: true } object, NOT a ref/href pointing at a real network/service
  // element. None of the ref/href/key/name fallbacks below can ever match that shape,
  // so without this explicit check the object falls through to the raw-object
  // fallback at the end of this function, lands in src_addresses/dst_addresses/
  // services as-is, and String()-ifies to "[object Object]" downstream —
  // lib/engines/ruleAnalysis.js's isAny() only recognizes the literal strings
  // 'any'/'all'/'any4'/'any6', so a genuine any-source/any-destination/any-service
  // Forcepoint rule would silently never trigger any_any / overly_permissive / shadow
  // / redundant / reorder_candidate. See CLAUDE.md Bug 4.
  if (typeof ref === 'object' && ref !== null && ref.any === true) {
    return 'any';
  }

  let key = ref;
  if (typeof ref === 'object') {
    key = ref.ref || ref.href || ref.key || ref.name || null;
  }

  if (key && index.has(key)) {
    const resolved = index.get(key);
    return resolved.name || key;
  }

  // Not found — fall back to the raw ref value rather than throwing.
  if (typeof ref === 'object') {
    return ref.ref || ref.href || ref.name || ref;
  }
  return ref;
}

// Resolves a field that may be a single ref, an array of refs, or already-resolved
// plain strings/objects. Always returns an array (possibly empty) for consistency
// with the NormalizedRule shape (src_addresses, dst_addresses, services, etc. are
// stored as JSONB arrays).
function resolveRefList(field, index) {
  if (field === null || field === undefined) return [];
  const list = Array.isArray(field) ? field : [field];
  return list.map((item) => resolveRef(item, index));
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

// policyElement: SMC fw_policy element (or similar) containing a rules list under
// `rules` or `fw_ipv4_access_rules` depending on SMC version/element type.
// networkElements / serviceElements: arrays from getNetworkElements()/getServiceElements(),
// used to resolve { ref } fields on each rule to human-readable names.
function parsePolicy(policyElement, networkElements, serviceElements) {
  if (!policyElement || typeof policyElement !== 'object') {
    console.warn('[Forcepoint parser] parsePolicy: no policy element provided');
    return [];
  }

  // ⛔ FIXED (found in an adversarial bug-sweep, 2026-07-19): this used to return []
  // identically whether the policy genuinely has zero rules OR neither known rules-field
  // name (`rules`/`fw_ipv4_access_rules`, both doc-derived/unverified per CLAUDE.md's Live
  // Validation Status) exists on this SMC version's element at all — index.js's getRules()
  // returned that [] straight through with no way to tell the two apart, and
  // collectAndStore() then DELETEs the device's real firewall_rules row before inserting
  // whatever came back, silently wiping the ruleset on a field-name mismatch while
  // reporting success. This is the exact "getRules() must THROW on a retrieval failure —
  // never return []" case CLAUDE.md documents as already fixed once in Sangfor/Fortinet.
  // Distinguish by field PRESENCE, not just resolved length: if either known key exists on
  // the element at all (even holding a genuinely empty array), that's a real "zero rules"
  // signal; if NEITHER key is present, the field name is unrecognized and this throws —
  // uncaught at index.js's `return parser.parsePolicy(...)` call site, so it propagates out
  // of getRules() exactly like the sibling failures a few lines above it in index.js.
  const hasRulesField = Object.prototype.hasOwnProperty.call(policyElement, 'rules');
  const hasFwIpv4Field = Object.prototype.hasOwnProperty.call(
    policyElement,
    'fw_ipv4_access_rules'
  );

  const rawRules = safeArray(policyElement.rules).length
    ? policyElement.rules
    : safeArray(policyElement.fw_ipv4_access_rules);

  if (!Array.isArray(rawRules) || rawRules.length === 0) {
    if (!hasRulesField && !hasFwIpv4Field) {
      throw new Error(
        'Forcepoint parsePolicy: no rules array found under `rules` or ' +
          '`fw_ipv4_access_rules` — field names may have changed between SMC versions ' +
          `(raw keys present on policy element: ${JSON.stringify(Object.keys(policyElement))}).`
      );
    }
    // One of the known fields IS present on the element (just resolved to an empty
    // array) — a genuinely empty policy, not a field-name mismatch.
    return [];
  }

  const networkIndex = buildRefIndex(networkElements);
  const serviceIndex = buildRefIndex(serviceElements);

  return rawRules.map((rule, idx) => {
    if (!rule || typeof rule !== 'object') {
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
        raw_rule: rule === undefined ? null : rule,
      };
    }

    return {
      rule_name: rule.name || null,
      rule_id_vendor:
        rule.key !== undefined && rule.key !== null
          ? String(rule.key)
          : rule.id !== undefined && rule.id !== null
          ? String(rule.id)
          : null,
      sequence_number:
        typeof rule.sequence_number === 'number' ? rule.sequence_number : idx + 1,
      enabled: rule.is_disabled === undefined ? true : rule.is_disabled !== true,
      action: mapAction(
        rule.action && typeof rule.action === 'object' ? rule.action.action : rule.action
      ),
      src_zones: resolveRefList(rule.sources && rule.sources.zone, networkIndex),
      dst_zones: resolveRefList(rule.destinations && rule.destinations.zone, networkIndex),
      src_addresses: resolveRefList(
        (rule.sources && rule.sources.src) || rule.source_ref || rule.sources,
        networkIndex
      ),
      dst_addresses: resolveRefList(
        (rule.destinations && rule.destinations.dst) || rule.destination_ref || rule.destinations,
        networkIndex
      ),
      services: resolveRefList(
        (rule.services && rule.services.service) || rule.service_ref || rule.services,
        serviceIndex
      ),
      applications: resolveRefList(rule.applications, networkIndex),
      schedule: (rule.time_range && rule.time_range.name) || rule.schedule || null,
      expiry_date: rule.expiry_date || null,
      log_enabled:
        rule.options && rule.options.log_level !== undefined
          ? rule.options.log_level !== 'undefined' && rule.options.log_level !== 'none'
          : true,
      comment: rule.comment || null,
      hit_count:
        typeof rule.hit_count === 'number'
          ? rule.hit_count
          : (rule.hits && typeof rule.hits.hit_count === 'number' ? rule.hits.hit_count : 0),
      raw_rule: rule,
    };
  });
}

// Phase 1+2 doesn't need deep config transformation — deeper structural parsing of the
// engine config is Phase 6 scope. For now, just capture raw + the parsed element as-is.
// ⚠️ Callers MUST pass an already-redacted element (see redactEngineElement below) —
// this function does not redact on its own.
function parseConfig(engineElement) {
  const safeElement = engineElement && typeof engineElement === 'object' ? engineElement : {};
  return {
    raw: JSON.stringify(safeElement),
    parsed: safeElement,
  };
}

// ---------------------------------------------------------------------------
// Engine identity resolution (CLAUDE.md Bug 1)
//
// smc.getEngines() returns EVERY engine on the whole SMC server, unfiltered —
// on any SMC managing more than one engine (a normal case; CLAUDE.md itself
// documents 50+ engines as routine), a positional engines[0] pick silently
// collapses every SecVault device pointed at that smc_host onto whichever
// engine happens to be first in the server's listing. Mirrors
// lib/adapters/checkpoint/parser.js's findGatewayByIdentity — same reasoning,
// adapted to Forcepoint's flat engine-list shape (no separate mgmt-server-IP
// vs. gateway-IP split to also match on: this.device's smc_host addresses the
// SMC server, not the engine, so IP-based matching isn't meaningful here —
// name is the only identity signal available).
// ---------------------------------------------------------------------------

// Strict identity match: the engine element that IS this device, or null.
// Match is by name only, case-insensitive exact match — never a substring/fuzzy
// match. Must NEVER fall back to "some engine": callers depend on null meaning
// "cannot identify this device" so they can throw a clear, actionable error
// rather than guess. Storing nothing is recoverable; storing the wrong engine's
// version/rules/config silently is not.
function findEngineByIdentity(engines, device) {
  const list = Array.isArray(engines) ? engines : [];
  const devName = device && device.name ? String(device.name).trim().toLowerCase() : null;
  if (!devName) return null;

  return (
    list.find(
      (engine) =>
        engine &&
        typeof engine === 'object' &&
        typeof engine.name === 'string' &&
        engine.name.trim().toLowerCase() === devName
    ) || null
  );
}

// Human-readable candidate list for the "which engine are you?" error — engine
// names only (no credentials/secrets ever appear on an engine summary/element).
function describeEngineCandidates(engines, limit = 20) {
  const list = Array.isArray(engines) ? engines : [];
  const labels = list
    .filter((engine) => engine && typeof engine === 'object' && engine.name)
    .map((engine) => `"${engine.name}"`);
  if (labels.length === 0) return '(none returned)';
  const shown = labels.slice(0, limit).join(', ');
  return labels.length > limit ? `${shown}, … (+${labels.length - limit} more)` : shown;
}

// ---------------------------------------------------------------------------
// Config redaction (CLAUDE.md Bug 3)
//
// getConfig() used to store the full engine element with zero secret
// redaction. Every other adapter in this codebase redacts before storing —
// including API/JSON-based ones (Fortinet's REST transport, Palo Alto's XML
// API) that redact defensively even though it's unverified whether the vendor
// API itself already blanks secrets ("fail closed"). device_configs.config_raw/
// config_parsed are GRANT SELECT'd to claude_readonly/nocvault_readonly — the
// same roles CLAUDE.md bars from device_credentials. Mirrors
// lib/adapters/fortinet/parser.js's redactSecretFields — same recursion style,
// same fail-closed keyword-match approach, adapted with a Forcepoint-appropriate
// key pattern.
// ---------------------------------------------------------------------------

// ⛔ WIDENED (found in an adversarial bug-sweep, 2026-07-19): this pattern used to be
// "already identical" to lib/adapters/checkpoint/parser.js's own SECRET_KEY_PATTERN — the
// exact narrow pattern that let a real 'phash' field (a local admin password hash) leak
// unredacted in production for a sibling adapter. The widened keywords (phash,
// pre[-_]?shared, keytab) were added to lib/engines/configDiff.js's SECRET_PATH_PATTERN as
// a downstream defense-in-depth layer for config_diffs, but were never back-ported to this
// file's own adapter-level pass — the FIRST and only redaction step before device_configs
// (GRANT SELECT'd to claude_readonly/nocvault_readonly) is populated for Forcepoint. An SMC
// engine element field named 'phash', 'pre_shared_key'/'pre-shared-key' (a plausible IPsec/
// VPN PSK on an NGFW engine element), or containing 'keytab' would otherwise pass
// isSecretKey() as false and be stored unredacted.
const SECRET_KEY_PATTERN =
  /secret|password|passwd|psk|private[-_]?key|community|credential|token|api[-_]?key|phash|pre[-_]?shared|keytab/i;

function isSecretKey(key) {
  return typeof key === 'string' && SECRET_KEY_PATTERN.test(key);
}

/**
 * Recursively replaces the value of any secret-shaped key with '<redacted>'.
 *
 * Deterministic — the same input always redacts identically, so it can never cause
 * spurious config-change detection (configDiff.js diffs config_parsed).
 *
 * Never throws — on any unexpected error the value is dropped entirely (fails closed,
 * matching lib/adapters/fortinet/parser.js's redactSecretFields).
 *
 * @param {*} value any JSON-ish value (typically a full SMC engine element)
 * @returns {*} the same shape with secret-shaped fields blanked
 */
function redactEngineElement(value, depth = 0) {
  try {
    // Bounded recursion: a cyclic or pathological structure must not hang a collect.
    if (depth > 12) return '<redacted:depth-limit>';
    if (Array.isArray(value)) return value.map((item) => redactEngineElement(item, depth + 1));
    if (value === null || typeof value !== 'object') return value;

    const out = {};
    for (const [key, val] of Object.entries(value)) {
      out[key] = isSecretKey(key) ? '<redacted>' : redactEngineElement(val, depth + 1);
    }
    return out;
  } catch (_err) {
    return '<redacted>';
  }
}

// ---------------------------------------------------------------------------
// Object catalog (getObjects()) — network/service object catalog collection
//
// Unlike getVersion()/getRules()/getConfig(), SMC's object catalog
// (network_elements/service_elements) is SERVER-WIDE, not per-engine — no
// findEngineByIdentity() resolution applies here, these are simply every
// named address/service object defined on the SMC server.
//
// SMC's unified /api/elements/network_elements and /api/elements/service_elements
// listings mix several sub-types in one collection (host/network/address_range/
// group for network elements; tcp_service/udp_service/service_group for service
// elements). Doc-derived, never live-verified against a real SMC instance — see
// CLAUDE.md "Live SMC field verification still pending" (same standing caveat as
// every other Forcepoint field mapping in this file). Classification below
// prefers an explicit `type` field when present, falls back to shape-based
// inference (which fields actually exist on the element) when it isn't, and
// defaults anything unrecognized into the flat (non-group) bucket with a null
// value rather than dropping the object silently — an object with an unresolved
// value is still useful to lib/engines/objectUsage.js for name-matching against
// rule fields, which is all that feature needs.
//
// ⚠️ Genuinely unverified assumption: unlike smc.getEngines() (which follows a
// summary entry's href to fetch the FULL element when the list response only
// carries name/type/href), getNetworkElements()/getServiceElements() here do NOT
// follow per-object hrefs to fetch full element data — the object catalog can
// run into the hundreds/thousands of entries on a large environment, and an
// href-follow per object would be an N+1 request explosion. If a live SMC
// instance's unified listing turns out to be summary-only the way engine list
// entries are, `value`/`members` will mostly resolve to null here until that
// gap is closed — the SAME name-only intermediate would still land members that
// have already-known full elements, but flat host/network/range objects would
// lose their value. Flagged for the first live [SMC Debug] check, not guessed
// at further.
// ---------------------------------------------------------------------------

function typeLower(el) {
  return typeof el.type === 'string' ? el.type.toLowerCase() : '';
}

// ⛔ BUG FIXED 2026-07-18, found in a bug-sweep pass: this function's own
// header comment claims to "prefer an explicit type field, falling back to
// shape-based inference when it isn't present" — the code didn't actually
// implement that priority. The shape-based `Array.isArray(el.element)`
// group check used to run BEFORE the explicit type==='host'/'network'
// checks, so an element with an explicit non-group type that ALSO happened
// to carry an `element` array field (for any reason — unverified live SMC
// shapes, per this file's own standing caveat) would be misclassified as a
// group, silently dropping its real address value from the catalog. Fixed:
// when `type` is present and recognized, it now fully decides the
// classification and the function returns before ever reaching the
// shape-based checks; shape-based inference is now a true fallback, only
// reached when `type` is absent or unrecognized.
function classifyNetworkElement(el) {
  const type = typeLower(el);
  if (type) {
    if (type.includes('group')) return 'group';
    if (type === 'host') return 'host';
    if (type === 'network') return 'network';
    if (type.includes('range')) return 'address_range';
    // Explicit but unrecognized type string — fall through to shape-based
    // inference below as a best-effort fallback.
  }
  if (Array.isArray(el.element)) return 'group';
  if (el.address !== undefined) return 'host';
  if (el.ipv4_network !== undefined || el.ipv6_network !== undefined) return 'network';
  if (el.ip_range !== undefined) return 'address_range';
  return 'other';
}

// value: CIDR/range/fqdn, or null if unresolvable — matches the NamedAddress
// contract in lib/adapters/interface.js.
function addressValue(el, kind) {
  if (kind === 'host') return el.address || null;
  if (kind === 'network') return el.ipv4_network || el.ipv6_network || null;
  if (kind === 'address_range') {
    if (typeof el.ip_range === 'string' && el.ip_range) return el.ip_range;
    if (el.ip_range_from && el.ip_range_to) return `${el.ip_range_from}-${el.ip_range_to}`;
    return null;
  }
  // 'other' — best-effort: whichever address-shaped field is present.
  return el.address || el.ipv4_network || el.ipv6_network || el.ip_range || null;
}

// Same explicit-type-first fix as classifyNetworkElement() above.
function classifyServiceElement(el) {
  const type = typeLower(el);
  if (type) {
    return type.includes('group') ? 'group' : 'service';
  }
  return Array.isArray(el.element) ? 'group' : 'service';
}

// tcp_service/udp_service elements are doc-derived as {name, min_dst_port,
// max_dst_port} with the protocol conveyed by the `type` discriminator
// (e.g. "tcp_service"/"udp_service") rather than a separate field — never
// live-verified. When `type` doesn't say, default to 'tcp' only when a port
// range is actually present (the overwhelmingly common case), otherwise null.
function serviceProtocol(el) {
  const type = typeLower(el);
  if (type.includes('tcp')) return 'tcp';
  if (type.includes('udp')) return 'udp';
  if (type.includes('icmp')) return 'icmp';
  if (type.includes('ip_service') || type.includes('protocol')) return 'ip';
  return el.min_dst_port !== undefined || el.max_dst_port !== undefined ? 'tcp' : null;
}

// value: e.g. "tcp/443" or "tcp/8000-8080", or null if unresolvable — matches
// the NamedService contract in lib/adapters/interface.js.
function serviceValue(el) {
  const protocol = serviceProtocol(el);
  const min = el.min_dst_port;
  const max = el.max_dst_port;

  if (min !== undefined && min !== null) {
    const port = max !== undefined && max !== null && max !== min ? `${min}-${max}` : String(min);
    return protocol ? `${protocol}/${port}` : port;
  }

  // No port range (ip_service/icmp_service and similar) — fall back to whatever
  // protocol-only signal is available, or null.
  return protocol || null;
}

// networkElements: the full array from smc.getNetworkElements() — used both as
// the source of flat address objects AND as the reference index for resolving
// group member hrefs to names (a group's members are other entries in this same
// unified collection, so one index covers both).
//
// → { addresses: NamedAddress[], addressGroups: NamedGroup[] }
function parseAddressObjects(networkElements) {
  const addresses = [];
  const addressGroups = [];
  const elements = safeArray(networkElements);
  const index = buildRefIndex(elements);

  for (const el of elements) {
    if (!el || typeof el !== 'object' || typeof el.name !== 'string') continue;

    const kind = classifyNetworkElement(el);
    if (kind === 'group') {
      addressGroups.push({
        name: el.name,
        // Reuse resolveRef's existing .ref/.href/.name fallback chain (including
        // the {any:true} special case) — group members are HATEOAS refs into
        // this same networkElements collection.
        members: resolveRefList(el.element, index).map((m) => String(m)),
      });
    } else {
      addresses.push({ name: el.name, type: kind, value: addressValue(el, kind) });
    }
  }

  return { addresses, addressGroups };
}

// serviceElements: the full array from smc.getServiceElements() — same
// dual-purpose (flat services + group-member index) as parseAddressObjects above.
//
// → { services: NamedService[], serviceGroups: NamedGroup[] }
function parseServiceObjectCatalog(serviceElements) {
  const services = [];
  const serviceGroups = [];
  const elements = safeArray(serviceElements);
  const index = buildRefIndex(elements);

  for (const el of elements) {
    if (!el || typeof el !== 'object' || typeof el.name !== 'string') continue;

    const kind = classifyServiceElement(el);
    if (kind === 'group') {
      serviceGroups.push({
        name: el.name,
        members: resolveRefList(el.element, index).map((m) => String(m)),
      });
    } else {
      services.push({ name: el.name, value: serviceValue(el) });
    }
  }

  return { services, serviceGroups };
}

module.exports = {
  parseEngineVersion,
  parsePolicy,
  parseConfig,
  findEngineByIdentity,
  describeEngineCandidates,
  redactEngineElement,
  parseAddressObjects,
  parseServiceObjectCatalog,
  // exported for testing / reuse, not part of the documented contract
  mapAction,
  isSecretKey,
  classifyNetworkElement,
  classifyServiceElement,
};
