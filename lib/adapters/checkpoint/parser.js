// lib/adapters/checkpoint/parser.js
// CommonJS ONLY — required by lib/adapters/checkpoint/index.js, which in turn is
// required by services/engine-worker.js (plain node, CommonJS).
//
// Pure mapping functions only — no I/O, no network, no DB access. These
// functions must NEVER throw on malformed/unexpected input (only api.js's
// network calls should throw). No live Check Point device was available when
// this was written, so every field lookup is defensive with safe fallbacks —
// per CLAUDE.md "External API Integrations", verify field names against the
// raw responses logged by index.js on first connect and adjust here.
//
// show-access-rulebase response shape this parser expects (details-level
// 'standard' + use-object-dictionary: true):
//   {
//     rulebase: [ <access-rule> | <access-section with nested `rulebase`> ],
//     'objects-dictionary': [ { uid, name, type, ... } ],
//     from, to, total
//   }
// Rule fields reference objects by uid string — resolved through the
// objects-dictionary. Sections nest their rules under `rulebase`; rule-number
// is global across sections and is preserved as sequence_number.

const { parseVersion } = require('../../engines/versionComparator');

// Builds a uid → object lookup map from a page's objects-dictionary array.
function buildObjectDictionary(objectsDictionary) {
  const byUid = new Map();
  if (!Array.isArray(objectsDictionary)) return byUid;
  for (const obj of objectsDictionary) {
    if (obj && typeof obj === 'object' && obj.uid) {
      byUid.set(obj.uid, obj);
    }
  }
  return byUid;
}

// Resolves a single value (uid string, or inline object with name/uid) to a
// human-readable name via the dictionary. Falls back to the raw uid rather
// than throwing on an unresolved reference.
function resolveName(value, dict) {
  if (value === null || value === undefined) return null;

  if (typeof value === 'string') {
    const hit = dict && dict.get(value);
    return (hit && hit.name) || value;
  }

  if (typeof value === 'object') {
    if (typeof value.name === 'string' && value.name.length > 0) return value.name;
    if (value.uid) {
      const hit = dict && dict.get(value.uid);
      return (hit && hit.name) || value.uid;
    }
    return null;
  }

  return String(value);
}

// Resolves a field that may be a single uid, an array of uids, or inline
// objects. Always returns an array (possibly empty) — NormalizedRule address/
// service fields are stored as JSONB arrays.
function resolveNameList(field, dict) {
  if (field === null || field === undefined) return [];
  const list = Array.isArray(field) ? field : [field];
  return list.map((item) => resolveName(item, dict)).filter((v) => v !== null && v !== undefined);
}

// Maps a Check Point action (uid or inline object) to the NormalizedRule
// action vocabulary: 'Accept'→'allow', 'Drop'→'drop', 'Reject'→'reject',
// anything else passes through lowercased rather than crashing.
function mapAction(actionField, dict) {
  const name = resolveName(actionField, dict);
  if (name === null || name === undefined) return null;
  switch (String(name).toLowerCase()) {
    case 'accept':
      return 'allow';
    case 'drop':
      return 'drop';
    case 'reject':
      return 'reject';
    default:
      return String(name).toLowerCase();
  }
}

// track.type resolves (via dictionary) to a Track object name like 'Log',
// 'None', 'Detailed Log'. log_enabled = resolved name !== 'None'. Missing or
// unresolvable track defaults to true (surface it rather than hide it).
function isLogEnabled(rule, dict) {
  try {
    const track = rule && rule.track;
    if (!track) return true;
    const typeField = typeof track === 'object' ? track.type : track;
    const typeName = resolveName(typeField, dict);
    if (!typeName) return true;
    return String(typeName).toLowerCase() !== 'none';
  } catch (_err) {
    return true;
  }
}

// hits.value is only present when show-access-rulebase was called with
// 'show-hits': true (and only on versions that support it) — default 0 in its
// own try/catch per the adapter contract.
function extractHitCount(rule) {
  try {
    if (rule && rule.hits && typeof rule.hits.value === 'number') {
      return rule.hits.value;
    }
    return 0;
  } catch (_err) {
    return 0;
  }
}

// Flattens a rulebase array in place-order: 'access-rule' items pass through;
// 'access-section' items contain nested `rulebase` arrays — recurse into them,
// preserving rule-number order. Unknown item types that still look like rules
// (have an action or rule-number) are kept rather than dropped.
function flattenRulebase(items, out) {
  const acc = out || [];
  if (!Array.isArray(items)) return acc;

  for (const item of items) {
    if (!item || typeof item !== 'object') continue;

    if (Array.isArray(item.rulebase)) {
      // access-section (or any container) — flatten its nested rules.
      flattenRulebase(item.rulebase, acc);
      continue;
    }

    if (
      item.type === 'access-rule' ||
      item['rule-number'] !== undefined ||
      item.action !== undefined
    ) {
      acc.push(item);
    }
    // Anything else (empty section stubs, placeholders) is skipped silently.
  }

  return acc;
}

// Maps one flattened access-rule to the NormalizedRule shape documented in
// lib/adapters/interface.js. Check Point access rules have no zone concept —
// src_zones/dst_zones are always empty arrays.
function normalizeRule(rule, dict, fallbackSequence) {
  if (!rule || typeof rule !== 'object') {
    return {
      rule_name: null,
      rule_id_vendor: null,
      sequence_number: fallbackSequence,
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
    rule_id_vendor: rule.uid !== undefined && rule.uid !== null ? String(rule.uid) : null,
    sequence_number:
      typeof rule['rule-number'] === 'number' ? rule['rule-number'] : fallbackSequence,
    enabled: rule.enabled === undefined ? true : rule.enabled === true,
    action: mapAction(rule.action, dict),
    src_zones: [],
    dst_zones: [],
    src_addresses: resolveNameList(rule.source, dict),
    dst_addresses: resolveNameList(rule.destination, dict),
    services: resolveNameList(rule.service, dict),
    applications: [],
    schedule: null,
    expiry_date: null,
    log_enabled: isLogEnabled(rule, dict),
    comment: rule.comments || null,
    hit_count: extractHitCount(rule),
    raw_rule: rule,
  };
}

// Entry point for getRules(): takes the array of show-access-rulebase page
// responses (pagination followed by index.js), merges every page's
// objects-dictionary into one uid index, flattens sections, and maps each
// rule to a NormalizedRule.
function parseRulebasePages(pages) {
  const pageList = Array.isArray(pages) ? pages : [pages];

  const dict = new Map();
  for (const page of pageList) {
    if (!page || typeof page !== 'object') continue;
    const pageDict = buildObjectDictionary(page['objects-dictionary']);
    for (const [uid, obj] of pageDict) {
      dict.set(uid, obj);
    }
  }

  const flat = [];
  for (const page of pageList) {
    if (!page || typeof page !== 'object') continue;
    flattenRulebase(page.rulebase, flat);
  }

  return flat.map((rule, idx) => normalizeRule(rule, dict, idx + 1));
}

// Finds the gateway object for this device in a show-gateways-and-servers
// objects list. The device row's mgmt_ip points at the MANAGEMENT SERVER, not
// the gateway — so match by ipv4-address OR by name (case-insensitive), and
// fall back to the first gateway-typed object with a warning if neither hits.
function findGateway(objects, device) {
  const list = Array.isArray(objects) ? objects : [];
  const devIp = device && device.mgmt_ip ? String(device.mgmt_ip) : null;
  const devName = device && device.name ? String(device.name).toLowerCase() : null;

  const match = list.find(
    (obj) =>
      obj &&
      typeof obj === 'object' &&
      ((devIp && obj['ipv4-address'] === devIp) ||
        (devName && typeof obj.name === 'string' && obj.name.toLowerCase() === devName))
  );
  if (match) return match;

  const gatewayTypes = ['simple-gateway', 'cpmigatewaycluster'];
  const fallback = list.find(
    (obj) =>
      obj &&
      typeof obj === 'object' &&
      typeof obj.type === 'string' &&
      gatewayTypes.includes(obj.type.toLowerCase())
  );
  if (fallback) {
    console.warn(
      `[CheckPoint parser] No gateway matched device mgmt_ip "${devIp}" or name "${devName}" — ` +
        `falling back to first gateway-type object "${fallback.name || fallback.uid}" (type ${fallback.type})`
    );
    return fallback;
  }

  return null;
}

// gateway → { version_string, version_tuple, build, model }
// Version strings look like "R81.20" (parseVersion('checkpoint', ...) handles
// the leading R and optional Take suffix). Field names checked defensively —
// verify against the raw gateway object logged by index.js on first connect.
function parseGatewayVersion(gateway) {
  if (!gateway || typeof gateway !== 'object') {
    console.warn('[CheckPoint parser] parseGatewayVersion: no gateway object provided');
    return { version_string: null, version_tuple: [0], build: null, model: null };
  }

  const versionCandidates = [
    gateway.version,
    gateway['os-version'],
    gateway['software-version'],
  ];
  let versionString = null;
  for (const candidate of versionCandidates) {
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      versionString = candidate.trim();
      break;
    }
  }

  const buildCandidates = [gateway['build-number'], gateway.build];
  let build = null;
  for (const candidate of buildCandidates) {
    if (candidate !== null && candidate !== undefined && String(candidate).trim().length > 0) {
      build = String(candidate).trim();
      break;
    }
  }

  const model =
    typeof gateway.hardware === 'string' && gateway.hardware.trim().length > 0
      ? gateway.hardware.trim()
      : null;

  if (!versionString) {
    console.warn(
      '[CheckPoint parser] parseGatewayVersion: no known version field found on gateway object — ' +
        'field names may differ on this management version. Raw keys: ' +
        JSON.stringify(Object.keys(gateway))
    );
    return { version_string: null, version_tuple: [0], build, model };
  }

  return {
    version_string: versionString,
    version_tuple: parseVersion('checkpoint', versionString),
    build,
    model,
  };
}

module.exports = {
  parseRulebasePages,
  findGateway,
  parseGatewayVersion,
  // exported for testing / reuse, not part of the documented contract
  buildObjectDictionary,
  resolveName,
  resolveNameList,
  mapAction,
  flattenRulebase,
  normalizeRule,
  isLogEnabled,
  extractHitCount,
};
