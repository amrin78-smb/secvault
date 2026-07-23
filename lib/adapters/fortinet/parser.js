// lib/adapters/fortinet/parser.js
// CommonJS ONLY — required by lib/adapters/fortinet/index.js, which in turn is
// required by services/engine-worker.js (plain node, CommonJS).
//
// Pure mapping functions only — no I/O, no network, no DB access. These functions must
// NEVER throw on malformed/unexpected input (only api.js's network calls should throw).
// FortiOS response field names have NOT been live-verified yet (no live device was
// available during this build — per CLAUDE.md "External API Integrations", verify all
// field names against live responses; index.js logs raw responses on first-connect
// paths for exactly that purpose). Every lookup here is defensive with safe fallbacks.

const { parseVersion } = require('../../engines/versionComparator');
const { isSecretKey } = require('./cliParser');

// Best-effort mapping from FortiOS policy action vocabulary to the NormalizedRule
// vocabulary ('allow'|'deny'|...). Unrecognized values pass through as-is rather than
// crashing — better to surface an odd raw value than throw during rule collection.
function mapAction(rawAction) {
  if (rawAction === null || rawAction === undefined) return null;
  const value = String(rawAction).toLowerCase();
  switch (value) {
    case 'accept':
      return 'allow';
    case 'deny':
      return 'deny';
    default:
      // e.g. 'ipsec' (policy-based VPN) — pass the raw string through.
      return rawAction;
  }
}

// FortiOS `logtraffic`: 'all' (log all sessions) / 'utm' (log security events) both
// mean logging is on; 'disable' means off. Missing/unknown values default to true —
// consistent with the conservative defaults used across other adapters.
function mapLogTraffic(logtraffic) {
  if (logtraffic === null || logtraffic === undefined) return true;
  return String(logtraffic).toLowerCase() !== 'disable';
}

// FortiOS represents object references as arrays of { name } (srcintf, dstintf,
// srcaddr, dstaddr, service, ...). Extract the names defensively: tolerate plain
// strings, single objects instead of arrays, and { id }-style entries (the
// `application` field uses numeric ids).
function namesOf(field) {
  if (field === null || field === undefined) return [];
  const list = Array.isArray(field) ? field : [field];
  const names = [];
  for (const item of list) {
    if (item === null || item === undefined) continue;
    if (typeof item === 'object') {
      if (item.name !== undefined && item.name !== null) {
        names.push(String(item.name));
      } else if (item.id !== undefined && item.id !== null) {
        names.push(String(item.id));
      } else if (item['q_origin_key'] !== undefined && item['q_origin_key'] !== null) {
        names.push(String(item['q_origin_key']));
      }
      // Object with none of the known key fields — skip rather than emit garbage.
    } else {
      names.push(String(item));
    }
  }
  return names;
}

// FortiOS `schedule` is usually a plain string ("always"), but some firmware/serializer
// combinations return { name } objects like every other reference field.
function scheduleName(schedule) {
  if (schedule === null || schedule === undefined) return null;
  if (typeof schedule === 'object') {
    return schedule.name !== undefined && schedule.name !== null ? String(schedule.name) : null;
  }
  const s = String(schedule).trim();
  return s.length > 0 ? s : null;
}

// Picks the first non-empty string from a list of candidate values.
function firstString(candidates) {
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate.trim();
    }
  }
  return null;
}

// Coerces a build value (number on most firmware, string on some) to a string, or null.
function buildString(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'string' && value.trim().length > 0) return value.trim();
  return null;
}

// firmwareBody: raw body of GET /api/v2/monitor/system/firmware (may be null if that
// endpoint failed). statusBody: raw body of GET /api/v2/monitor/system/status (may be
// null). Field names here are the FortiOS 7.x shapes and MUST be re-verified against
// the first live device (index.js logs both raw bodies via '[Fortinet Debug]').
// Never throws — returns a safe "unknown" shape when nothing usable is present.
function parseVersionInfo(firmwareBody, statusBody) {
  const firmwareResults =
    firmwareBody && typeof firmwareBody === 'object' && firmwareBody.results
      ? firmwareBody.results
      : null;
  const current =
    firmwareResults && typeof firmwareResults === 'object' && firmwareResults.current
      ? firmwareResults.current
      : null;

  const statusResults =
    statusBody && typeof statusBody === 'object' && statusBody.results
      ? statusBody.results
      : null;

  const versionString = firstString([
    current && current.version,
    // monitor/system/status carries version at the TOP level of the body on 7.x,
    // not inside results — check both.
    statusBody && statusBody.version,
    statusResults && statusResults.version,
  ]);

  if (!versionString) {
    console.warn(
      '[Fortinet parser] parseVersionInfo: no known version field found on firmware/status ' +
        'responses — field names may differ on this firmware. Raw firmware keys: ' +
        JSON.stringify(firmwareBody && typeof firmwareBody === 'object' ? Object.keys(firmwareBody) : null) +
        ', raw status keys: ' +
        JSON.stringify(statusBody && typeof statusBody === 'object' ? Object.keys(statusBody) : null)
    );
  }

  const build =
    buildString(current && current.build) ||
    buildString(statusBody && statusBody.build) ||
    buildString(statusResults && statusResults.build);

  // Model: prefer the human-readable "FortiGate-100F" composite from status, then the
  // short model code, then the firmware platform, then serial/hostname as last resorts.
  let model = null;
  if (statusResults && statusResults.model_name && statusResults.model_number) {
    model = `${statusResults.model_name}-${statusResults.model_number}`;
  } else {
    model = firstString([
      statusResults && statusResults.model,
      statusResults && statusResults.model_name,
      current && current.platform,
      statusBody && statusBody.serial,
      statusResults && statusResults.hostname,
    ]);
  }

  // ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep: statusBody.serial
  // was already being read above, but ONLY as a last-resort fallback value
  // for `model` (a different concept) — the actual serial number was never
  // returned as its own field, so a real, already-available value was
  // silently discarded before it ever reached collectAndStore()'s INSERT.
  const serial = firstString([statusResults && statusResults.serial, statusBody && statusBody.serial]);

  // Added 2026-07-23, same class of gap as `serial` above: `statusResults.hostname`
  // was already being read (line ~149) but ONLY as a last-resort fallback for
  // `model` (a different concept) — never returned as its own field.
  const hostname = firstString([statusResults && statusResults.hostname, statusBody && statusBody.hostname]);

  return {
    version_string: versionString,
    // parseVersion('fortinet', ...) tolerates "v7.4.3" / "v7.4.3,build2573,240201"
    // and null (returns [0]) — see lib/engines/versionComparator.js.
    version_tuple: parseVersion('fortinet', versionString),
    build: build || null,
    model: model || 'unknown',
    serial: serial || null,
    hostname: hostname || null,
  };
}

// statsResults: the results array of GET /api/v2/monitor/firewall/policy. Returns a
// Map keyed by String(policyid) → { hit_count, bytes }. Never throws.
function buildHitCountIndex(statsResults) {
  const index = new Map();
  if (!Array.isArray(statsResults)) return index;

  for (const entry of statsResults) {
    if (!entry || typeof entry !== 'object') continue;
    if (entry.policyid === undefined || entry.policyid === null) continue;

    // Field observed as `hit_count` on 7.x; be tolerant of `hitcount` variants.
    const hitCount =
      typeof entry.hit_count === 'number'
        ? entry.hit_count
        : typeof entry.hitcount === 'number'
        ? entry.hitcount
        : 0;
    const bytes = typeof entry.bytes === 'number' ? entry.bytes : 0;

    index.set(String(entry.policyid), { hit_count: hitCount, bytes });
  }
  return index;
}

// Attaches the VDOM to a raw vendor policy object so rules pulled from different
// VDOMs stay distinguishable in firewall_rules.raw_rule.
//
// WHY raw_rule and not a dedicated column: firewall_rules has NO vdom column and the
// schema is out of this adapter's scope. The `tags` jsonb column exists but is NOT in
// collectAndStore's INSERT column list (lib/adapters/index.js) — a `tags` entry on a
// NormalizedRule would be silently DROPPED on the way to the DB. raw_rule IS inserted,
// so it is the only durable home for the VDOM. The human-facing half of this is the
// rule_name prefix applied below.
function withVdomRaw(rule, vdom) {
  if (!vdom) return rule === undefined ? null : rule;
  if (rule && typeof rule === 'object' && !Array.isArray(rule)) {
    return { ...rule, vdom };
  }
  return { vdom, value: rule === undefined ? null : rule };
}

// policies: the results array of GET /api/v2/cmdb/firewall/policy (for ONE VDOM).
// statsResults: the results array of GET /api/v2/monitor/firewall/policy for THAT SAME
// VDOM (or [] / null when unavailable — hit counts default to 0). Never pass a
// multi-VDOM merge: FortiOS policyid is only unique within a VDOM, so a merged index
// would attribute one VDOM's hit counts to another's policies.
// options:
//   vdom           — VDOM name these policies came from (null = single implicit VDOM)
//   prefixRuleName — prefix rule_name with "[<vdom>] " (only worth doing on a
//                    multi-VDOM box; on a single-VDOM box it would be noise and would
//                    churn every existing rule_name for no information gain)
//   sequenceStart  — sequence numbers continue from here (multi-VDOM concatenation)
// Returns NormalizedRule[] (see lib/adapters/interface.js for the shape).
function parsePolicies(policies, statsResults, options = {}) {
  const { vdom = null, prefixRuleName = false, sequenceStart = 0 } = options || {};

  if (!Array.isArray(policies)) {
    console.warn(
      '[Fortinet parser] parsePolicies: expected a policies array, got ' +
        (policies === null ? 'null' : typeof policies)
    );
    return [];
  }

  const hitIndex = buildHitCountIndex(statsResults);
  const prefix = prefixRuleName && vdom ? `[${vdom}] ` : '';

  return policies.map((rule, idx) => {
    if (!rule || typeof rule !== 'object') {
      return {
        rule_name: prefix ? `${prefix}(unparseable policy)` : null,
        rule_id_vendor: null,
        sequence_number: sequenceStart + idx + 1,
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
        raw_rule: withVdomRaw(rule, vdom),
      };
    }

    const policyId =
      rule.policyid !== undefined && rule.policyid !== null ? String(rule.policyid) : null;
    const stats = policyId !== null && hitIndex.has(policyId) ? hitIndex.get(policyId) : null;

    // FortiOS policy names are optional -- `show firewall policy`/`show
    // full-configuration` simply omit the `set name` line entirely for a policy
    // that was never given one (confirmed live 2026-07-16 on a FortiGate-200E,
    // single VDOM: policy 41 has no `set name` among its sibling policies that
    // all do). This is NOT malformed input; it is real, valid FortiOS output.
    //
    // The fallback below used to be gated on `prefix` (i.e. only applied on a
    // multi-VDOM box), which meant a single-VDOM device's unnamed policy stored
    // rule_name: null -- rendered as a bare "--" in the UI, easily misread as "the
    // parser lost this rule's name" when the device never had one to begin with.
    // FortiOS's own GUI shows the numeric policy ID in the Name column for an
    // unnamed policy, so falling back to it here (regardless of VDOM) matches
    // what an admin actually sees on the box.
    const baseName = rule.name || `policy ${policyId !== null ? policyId : '?'}`;

    return {
      // baseName is never null now (always at least the `policy <id>` fallback).
      rule_name: `${prefix}${baseName}`,
      rule_id_vendor: policyId,
      // FortiOS policy table order IS the evaluation order — sequence from array
      // index (1-based), per contract. On a multi-VDOM box each VDOM's block of
      // rules is numbered contiguously, continuing from sequenceStart.
      sequence_number: sequenceStart + idx + 1,
      // `status` is 'enable'/'disable'; missing status defaults to enabled.
      enabled: rule.status === undefined || rule.status === null
        ? true
        : String(rule.status).toLowerCase() !== 'disable',
      action: mapAction(rule.action),
      src_zones: namesOf(rule.srcintf),
      dst_zones: namesOf(rule.dstintf),
      src_addresses: namesOf(rule.srcaddr),
      dst_addresses: namesOf(rule.dstaddr),
      services: namesOf(rule.service),
      applications: namesOf(rule.application),
      schedule: scheduleName(rule.schedule),
      expiry_date: null, // FortiOS has no per-policy expiry field
      log_enabled: mapLogTraffic(rule.logtraffic),
      comment: rule.comments || null,
      hit_count: stats ? stats.hit_count : 0,
      raw_rule: withVdomRaw(rule, vdom),
    };
  });
}

// CMDB endpoint bodies wrap payloads in { results: ... } — results is an array for
// table endpoints (interface, admin) and an object for singleton endpoints (global,
// vpn.ssl settings, snmp sysinfo). Unwraps defensively; returns null on no body.
function extractResults(body) {
  if (body === null || body === undefined) return null;
  if (typeof body === 'object' && body.results !== undefined) return body.results;
  return body;
}

// Extracts usable VDOM names from the body of GET /api/v2/cmdb/system/vdom.
// Returns null when the response carries nothing usable — callers MUST read null as
// "assume a single implicit VDOM" (the pre-VDOM behaviour), never as "no VDOMs".
// Never throws.
function parseVdomNames(body) {
  const results = extractResults(body);
  if (!Array.isArray(results)) {
    console.warn(
      '[Fortinet parser] parseVdomNames: cmdb/system/vdom response had no results array — ' +
        'raw keys: ' +
        JSON.stringify(body && typeof body === 'object' ? Object.keys(body) : null)
    );
    return null;
  }

  const names = [];
  for (const entry of results) {
    let name = null;
    if (typeof entry === 'string') {
      name = entry;
    } else if (entry && typeof entry === 'object') {
      name = firstString([entry.name, entry['q_origin_key']]);
    }
    if (name && !names.includes(name)) names.push(name);
  }

  if (names.length === 0) {
    console.warn(
      '[Fortinet parser] parseVdomNames: cmdb/system/vdom returned a results array with no ' +
        'usable name fields — treating this box as single-VDOM.'
    );
    return null;
  }
  return names;
}

/**
 * Recursively replaces the value of any secret-named key with '<redacted>'.
 *
 * SECURITY / defence in depth: getConfig()'s `parsed` object is built straight from
 * cmdb responses and lands in device_configs.config_parsed, which
 * lib/schema-grants.sql GRANT SELECTs to claude_readonly / nocvault_readonly — the
 * roles CLAUDE.md bars from device_credentials. Whether FortiOS actually returns
 * `password` / `psksecret` values on a cmdb GET (rather than blanking them) is NOT
 * verified against live firmware, so this fails CLOSED: any key that looks like a
 * secret is blanked regardless. It mirrors what the Cisco ASA parser already does
 * (parseRunningConfig never stores password hashes) and the redaction of `raw`.
 *
 * Deterministic — the same input always redacts identically, so it can never cause
 * spurious config-change detection (and configDiff.js diffs config_parsed).
 *
 * Never throws — on any unexpected error the value is dropped entirely.
 *
 * @param {*} value any JSON-ish value
 * @returns {*} the same shape with secret-named fields blanked
 */
function redactSecretFields(value, depth = 0) {
  try {
    // Bounded recursion: a cyclic or pathological structure must not hang a collect.
    if (depth > 12) return '<redacted:depth-limit>';
    if (Array.isArray(value)) return value.map((item) => redactSecretFields(item, depth + 1));
    if (value === null || typeof value !== 'object') return value;

    const out = {};
    for (const [key, val] of Object.entries(value)) {
      out[key] = isSecretKey(key) ? '<redacted>' : redactSecretFields(val, depth + 1);
    }
    return out;
  } catch (_err) {
    return '<redacted>';
  }
}

module.exports = {
  parseVersionInfo,
  parsePolicies,
  parseVdomNames,
  redactSecretFields,
  buildHitCountIndex,
  extractResults,
  // exported for testing / reuse, not part of the documented contract
  mapAction,
  mapLogTraffic,
  namesOf,
  withVdomRaw,
};
