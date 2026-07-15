// lib/adapters/forcepoint/parser.js
// CommonJS ONLY — required by lib/adapters/forcepoint/index.js, which in turn is
// required by services/engine-worker.js (plain node, CommonJS).
//
// Pure functions only — no I/O, no network, no DB access. These functions must NEVER
// throw on malformed/unexpected input (only smc.js's network calls should throw) —
// SMC field names vary between 6.x and 7.x per CLAUDE.md, so every lookup here is
// defensive with safe fallbacks.

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

  const candidates = [
    engineElement.software_version,
    engineElement.dynamic_package,
    engineElement.version,
    engineElement.attributes && engineElement.attributes.version,
    engineElement.engine_version,
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

  const rawRules = safeArray(policyElement.rules).length
    ? policyElement.rules
    : safeArray(policyElement.fw_ipv4_access_rules);

  if (!Array.isArray(rawRules) || rawRules.length === 0) {
    console.warn(
      '[Forcepoint parser] parsePolicy: no rules array found under `rules` or ' +
        '`fw_ipv4_access_rules` — field names may have changed between SMC versions.'
    );
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
function parseConfig(engineElement) {
  const safeElement = engineElement && typeof engineElement === 'object' ? engineElement : {};
  return {
    raw: JSON.stringify(safeElement),
    parsed: safeElement,
  };
}

module.exports = {
  parseEngineVersion,
  parsePolicy,
  parseConfig,
  // exported for testing / reuse, not part of the documented contract
  mapAction,
};
