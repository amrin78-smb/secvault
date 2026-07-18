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

  // ⛔ Found missing in a full-app audit (2026-07-16): unlike every sibling
  // adapter (Forcepoint/Fortinet/Palo Alto/Sangfor all warn or throw when
  // their expected rules array is missing/malformed), this loop silently
  // skipped a page whose `rulebase` field was absent or a different shape —
  // every field path here is explicitly doc-derived/unverified (see this
  // file's header), so a renamed field or a permission-truncated response on
  // some Mgmt API version would produce a silent [], which collectAndStore
  // treats as "device genuinely has zero rules" and deletes the real ruleset.
  const flat = [];
  let malformedPages = 0;
  for (const page of pageList) {
    if (!page || typeof page !== 'object') continue;
    if (!Array.isArray(page.rulebase)) {
      malformedPages += 1;
      continue;
    }
    flattenRulebase(page.rulebase, flat);
  }

  if (malformedPages > 0) {
    console.warn(
      `[CheckPoint parser] ${malformedPages} of ${pageList.length} show-access-rulebase page(s) had ` +
        'no usable "rulebase" array (missing, wrong type, or an unexpected shape on this Mgmt API ' +
        'version) -- those pages contributed zero rules. If the final rule count looks too low, check ' +
        'the [CheckPoint Debug] raw response and this file\'s field mappings.'
    );
  }

  return flat.map((rule, idx) => normalizeRule(rule, dict, idx + 1));
}

// Strict identity match: the gateway object that IS this device, or null.
//
// Match is by ipv4-address OR by name (case-insensitive). Both are needed:
// on a standalone deployment the device row's mgmt_ip is the gateway's own IP,
// but on a distributed deployment mgmt_ip is the MANAGEMENT SERVER's IP and the
// gateway has a different address — there, only the name can identify it.
//
// ⛔ This function must NEVER fall back to "some gateway" — callers that need to
// know *which* device they are looking at (policy-package resolution) depend on
// null meaning "cannot identify this device". Guessing here re-creates the
// packages[0] bug: another gateway's policy stored against this device.
function findGatewayByIdentity(objects, device) {
  const list = Array.isArray(objects) ? objects : [];
  const devIp = device && device.mgmt_ip ? String(device.mgmt_ip) : null;
  const devName = device && device.name ? String(device.name).toLowerCase() : null;

  return (
    list.find(
      (obj) =>
        obj &&
        typeof obj === 'object' &&
        ((devIp && obj['ipv4-address'] === devIp) ||
          (devName && typeof obj.name === 'string' && obj.name.toLowerCase() === devName))
    ) || null
  );
}

// ⛔ Bug fixed 2026-07-19 (a confirmed-still-open item per CLAUDE.md's own
// Known Limitations): findGateway() used to exist here as a "strict match,
// then a warned fallback to the first gateway-type object" variant, used by
// getVersion()/getConfig() while findGatewayByIdentity() (below, strict-only,
// no fallback) was reserved for policy-package resolution. That split was
// itself the bug — CLAUDE.md documented it as "less destructive than the
// packages[0] rules bug, but the same class. Open." lib/adapters/checkpoint/
// index.js's _findGateway() now calls findGatewayByIdentity() directly for
// every purpose (version, config, AND policy), so this fallback-permitting
// function had no remaining callers and was removed rather than left as
// unused dead code.

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

// ---------------------------------------------------------------------------
// Policy-package resolution
//
// A Check Point management server manages MANY gateways, each of which can have
// a DIFFERENT policy package installed. show-packages returns every package on
// the server, so the package this device's rules come from must be resolved from
// the gateway object itself — never positionally.
//
// ⚠️ Every field path below is DOC-DERIVED and UNVERIFIED against live hardware
// (CLAUDE.md "External API Integrations": documentation lies). That is exactly
// why several paths are tried and a miss is tolerated: index.js logs the raw
// gateway/package responses under [CheckPoint Debug] on the first resolution
// attempt — check those on first live connect and prune/extend this list.
// ---------------------------------------------------------------------------

// Walks a dot-path expressed as an array of keys. Returns undefined (never
// throws) on any missing/non-object link.
function getPathValue(obj, path) {
  let cur = obj;
  for (const key of path) {
    if (!cur || typeof cur !== 'object') return undefined;
    cur = cur[key];
  }
  return cur;
}

// Ordered most- to least-likely. All unverified.
const POLICY_NAME_PATHS = [
  ['policy', 'access-policy-name'],
  ['policy', 'policy-name'],
  ['policy', 'name'],
  ['installed-policy', 'name'],
  ['installed-policy'],
  ['access-policy-name'],
  ['policy-name'],
  ['policy'], // when `policy` is itself a bare string
];

// gateway object → the name of the access policy package installed on it, or
// null when no known field carries one. Never throws.
function extractInstalledPolicyName(gateway) {
  if (!gateway || typeof gateway !== 'object') return null;

  try {
    const policy = gateway.policy;
    if (
      policy &&
      typeof policy === 'object' &&
      policy['access-policy-installed'] === false
    ) {
      // Worth surfacing, but not disqualifying: the package named here is still
      // THIS gateway's package, which is what we want to store. It just isn't
      // currently pushed to the appliance.
      console.warn(
        `[CheckPoint parser] Gateway "${gateway.name || gateway.uid}" reports ` +
          'access-policy-installed=false — its policy package is assigned but not currently installed.'
      );
    }

    for (const path of POLICY_NAME_PATHS) {
      const value = getPathValue(gateway, path);
      if (typeof value === 'string' && value.trim().length > 0) {
        return value.trim();
      }
    }

    return null;
  } catch (_err) {
    return null;
  }
}

// Exact (case-insensitive) package lookup by name or uid. Returns null on miss —
// a miss must never degrade into a positional pick.
function matchPackageByNameOrUid(packages, needle) {
  if (!Array.isArray(packages) || typeof needle !== 'string') return null;
  const target = needle.trim().toLowerCase();
  if (!target) return null;

  return (
    packages.find(
      (pkg) =>
        pkg &&
        typeof pkg === 'object' &&
        ((typeof pkg.name === 'string' && pkg.name.trim().toLowerCase() === target) ||
          (typeof pkg.uid === 'string' && pkg.uid.trim().toLowerCase() === target))
    ) || null
  );
}

// Secondary resolution route: packages whose `installation-targets` include this
// gateway. Only useful to the caller when EXACTLY ONE package matches.
//
// An 'all' target counts as a match on purpose: a package installed everywhere
// really does target this gateway, so counting it keeps a genuinely ambiguous
// server ambiguous instead of resolving to whichever package happens to name the
// gateway explicitly.
function findPackagesTargetingGateway(packages, gateway) {
  if (!Array.isArray(packages) || !gateway || typeof gateway !== 'object') return [];

  const gwName = typeof gateway.name === 'string' ? gateway.name.trim().toLowerCase() : null;
  const gwUid = typeof gateway.uid === 'string' ? gateway.uid.trim().toLowerCase() : null;
  if (!gwName && !gwUid) return [];

  const matchesTarget = (target) => {
    if (typeof target === 'string') {
      const t = target.trim().toLowerCase();
      return t === 'all' || (gwName && t === gwName) || (gwUid && t === gwUid);
    }
    if (target && typeof target === 'object') {
      return Boolean(
        (gwName && typeof target.name === 'string' && target.name.trim().toLowerCase() === gwName) ||
          (gwUid && typeof target.uid === 'string' && target.uid.trim().toLowerCase() === gwUid)
      );
    }
    return false;
  };

  const out = [];
  for (const pkg of packages) {
    if (!pkg || typeof pkg !== 'object') continue;
    const targets = pkg['installation-targets'];
    if (targets === undefined || targets === null) continue;

    const list = Array.isArray(targets) ? targets : [targets];
    if (list.some(matchesTarget)) out.push(pkg);
  }
  return out;
}

// Human-readable candidate list for error messages. Names/uids only — these are
// element names, never credentials.
function describePackages(packages, limit = 12) {
  const list = Array.isArray(packages) ? packages : [];
  const labels = list
    .filter((pkg) => pkg && typeof pkg === 'object')
    .map((pkg) => `"${pkg.name || pkg.uid || '(unnamed)'}"`);
  if (labels.length === 0) return '(none)';
  const shown = labels.slice(0, limit).join(', ');
  return labels.length > limit ? `${shown}, … (+${labels.length - limit} more)` : shown;
}

// Human-readable list of gateway-ish objects, for the "which one are you?"
// error. Deliberately includes the ipv4-address: the operator needs to see what
// the management server thinks the gateway is called and addressed as in order
// to line the SecVault device row up with it.
function describeGatewayCandidates(objects, limit = 12) {
  const list = Array.isArray(objects) ? objects : [];
  const labels = list
    .filter((obj) => obj && typeof obj === 'object' && (obj.name || obj.uid))
    .map((obj) => {
      const ip = obj['ipv4-address'] ? ` @ ${obj['ipv4-address']}` : '';
      return `"${obj.name || obj.uid}"${ip}`;
    });
  if (labels.length === 0) return '(none returned)';
  const shown = labels.slice(0, limit).join(', ');
  return labels.length > limit ? `${shown}, … (+${labels.length - limit} more)` : shown;
}

// Generic, defensive, keyword-based secret redaction — added 2026-07-19 (see
// index.js's getConfig() call site comment for the full "why"). Mirrors
// lib/adapters/fortinet/parser.js's redactSecretFields()/isSecretKey()
// approach: recursively walk any object/array structure and blank the VALUE
// of any key whose name matches a broad secret-shaped pattern, leaving
// everything else untouched. Never throws — a malformed/circular-looking
// structure degrades to returning the input unchanged rather than crashing
// a collection over a redaction bug (same "fail closed but never fail
// loud enough to break the primary action" posture used throughout this
// codebase for defence-in-depth passes).
const SECRET_KEY_PATTERN =
  /secret|password|passwd|psk|private[-_]?key|community|credential|token|api[-_]?key/i;

function redactSecrets(value, depth = 0) {
  try {
    if (depth > 20) return '<redaction-depth-exceeded>'; // pathological nesting guard
    if (Array.isArray(value)) return value.map((item) => redactSecrets(item, depth + 1));
    if (value && typeof value === 'object') {
      const out = {};
      for (const [key, val] of Object.entries(value)) {
        out[key] = SECRET_KEY_PATTERN.test(key) ? '<redacted>' : redactSecrets(val, depth + 1);
      }
      return out;
    }
    return value;
  } catch (err) {
    // Fail CLOSED, not open: returning the raw, unredacted `value` here would
    // defeat the entire purpose of this function on the one input shape that
    // broke it — a redaction bug must never become a secret-disclosure bug.
    // Dropping to a placeholder loses that one subtree's data, which is the
    // correct tradeoff (same principle as "no ruleset is safer than the
    // wrong ruleset" elsewhere in this codebase, applied to secrets instead
    // of rules).
    console.warn(`[CheckPoint parser] redactSecrets failed at depth ${depth}: ${err.message}`);
    return '<redaction-error>';
  }
}

// ---------------------------------------------------------------------------
// Object catalog (getObjects()) — SERVER-WIDE address/service objects and
// groups, feeding lib/engines/objectUsage.js's Unused/Duplicate Objects
// feature. Unlike rules, these are not gateway/policy scoped: show-hosts /
// show-networks / show-address-ranges / show-groups / show-services-tcp /
// show-services-udp / show-service-groups return whatever is defined on the
// whole management server this device's mgmt_ip/credentials point at.
//
// ⚠️ Every field path below is DOC-DERIVED and UNVERIFIED against a live
// management server (CLAUDE.md "External API Integrations" — no Check Point
// device exists in this deployment yet; see "Live Validation Status"). None
// of these functions throw — a missing/renamed field degrades to a null
// `value`/empty `members`, never an exception, matching this file's own
// header rule ("pure mapping functions... must NEVER throw").
// ---------------------------------------------------------------------------

// show-hosts → NamedAddress[] (see interface.js). {name, "ipv4-address"} (or
// "ipv6-address" as a fallback) → value = that address.
function parseHostObjects(objects) {
  const list = Array.isArray(objects) ? objects : [];
  return list
    .filter((obj) => obj && typeof obj === 'object' && typeof obj.name === 'string')
    .map((obj) => ({
      name: obj.name,
      type: 'host',
      value: obj['ipv4-address'] || obj['ipv6-address'] || null,
    }));
}

// show-networks → NamedAddress[]. {name, subnet4, "mask-length4"} → value =
// "subnet4/mask-length4" (ipv6 equivalents used as a fallback).
function parseNetworkObjects(objects) {
  const list = Array.isArray(objects) ? objects : [];
  return list
    .filter((obj) => obj && typeof obj === 'object' && typeof obj.name === 'string')
    .map((obj) => {
      let value = null;
      if (obj.subnet4 && obj['mask-length4'] !== undefined && obj['mask-length4'] !== null) {
        value = `${obj.subnet4}/${obj['mask-length4']}`;
      } else if (
        obj.subnet6 &&
        obj['mask-length6'] !== undefined &&
        obj['mask-length6'] !== null
      ) {
        value = `${obj.subnet6}/${obj['mask-length6']}`;
      }
      return { name: obj.name, type: 'network', value };
    });
}

// show-address-ranges → NamedAddress[]. {name, "ipv4-address-first",
// "ipv4-address-last"} → value = "first-last" (ipv6 equivalents as fallback).
function parseAddressRangeObjects(objects) {
  const list = Array.isArray(objects) ? objects : [];
  return list
    .filter((obj) => obj && typeof obj === 'object' && typeof obj.name === 'string')
    .map((obj) => {
      const first = obj['ipv4-address-first'] || obj['ipv6-address-first'] || null;
      const last = obj['ipv4-address-last'] || obj['ipv6-address-last'] || null;
      return {
        name: obj.name,
        type: 'address-range',
        value: first && last ? `${first}-${last}` : null,
      };
    });
}

// A group member can arrive as a bare uid string (older/less-detailed
// responses) or an inline object carrying its own `name` (expected when the
// caller requests 'details-level': 'full' — see index.js's getObjects() call
// site for the standing assumption that this is real, unconfirmed live).
// Falls back to the uid itself rather than dropping the member entirely.
// Never throws.
function extractMemberName(member) {
  if (member === null || member === undefined) return null;
  if (typeof member === 'string') return member;
  if (typeof member === 'object') {
    if (typeof member.name === 'string' && member.name.length > 0) return member.name;
    if (member.uid) return String(member.uid);
  }
  return null;
}

// show-groups / show-service-groups → NamedGroup[] (identical shape for
// both — this codebase does not resolve nested groups any further than
// storing the member NAME, per interface.js's own comment;
// lib/engines/objectUsage.js walks the nesting itself).
function parseGroupObjects(objects) {
  const list = Array.isArray(objects) ? objects : [];
  return list
    .filter((obj) => obj && typeof obj === 'object' && typeof obj.name === 'string')
    .map((obj) => {
      const membersField = Array.isArray(obj.members) ? obj.members : [];
      const members = membersField
        .map((m) => extractMemberName(m))
        .filter((v) => v !== null && v !== undefined);
      return { name: obj.name, members };
    });
}

// show-services-tcp → NamedService[]. {name, port} → value = "tcp/<port>".
function parseTcpServiceObjects(objects) {
  const list = Array.isArray(objects) ? objects : [];
  return list
    .filter((obj) => obj && typeof obj === 'object' && typeof obj.name === 'string')
    .map((obj) => ({
      name: obj.name,
      value:
        obj.port !== undefined && obj.port !== null && String(obj.port).trim().length > 0
          ? `tcp/${obj.port}`
          : null,
    }));
}

// show-services-udp → NamedService[]. {name, port} → value = "udp/<port>".
function parseUdpServiceObjects(objects) {
  const list = Array.isArray(objects) ? objects : [];
  return list
    .filter((obj) => obj && typeof obj === 'object' && typeof obj.name === 'string')
    .map((obj) => ({
      name: obj.name,
      value:
        obj.port !== undefined && obj.port !== null && String(obj.port).trim().length > 0
          ? `udp/${obj.port}`
          : null,
    }));
}

module.exports = {
  parseRulebasePages,
  findGatewayByIdentity,
  redactSecrets,
  extractInstalledPolicyName,
  matchPackageByNameOrUid,
  findPackagesTargetingGateway,
  describePackages,
  describeGatewayCandidates,
  parseGatewayVersion,
  // Object catalog (getObjects())
  parseHostObjects,
  parseNetworkObjects,
  parseAddressRangeObjects,
  parseGroupObjects,
  parseTcpServiceObjects,
  parseUdpServiceObjects,
  extractMemberName,
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
