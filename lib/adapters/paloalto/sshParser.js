// lib/adapters/paloalto/sshParser.js
// Pure text-parsing functions for PAN-OS CLI output. CommonJS ONLY — required by
// lib/adapters/paloalto/ssh.js, which is required (via the adapter registry) by
// services/engine-worker.js (plain node, CommonJS).
//
// SEPARATE FROM parser.js ON PURPOSE. parser.js parses the XML API's parsed-XML
// object tree; this file parses CLI TEXT. They share nothing but the vendor.
//
// No I/O, no network, no DB — every function takes raw CLI text and returns plain
// data. Parsing is defensive everywhere: per CLAUDE.md "External API Integrations",
// this was written WITHOUT a live PAN-OS device, so a malformed or unexpected line
// is skipped (with a console.warn), never thrown. A single bad rule must never abort
// the ruleset.
//
// ── Why `set` format ─────────────────────────────────────────────────────────
// ssh.js runs `set cli config-output-format set` before `show config running`, so
// the config arrives as flat `set ...` lines rather than the default brace/XML tree.
// That choice is what this parser is built on. Reasons:
//   1. Line-oriented and regular — one fact per line, no nesting state machine, so a
//      malformed line can be skipped in isolation (the defensiveness requirement).
//   2. The vsys is NAMED on every line (`set devices localhost.localdomain vsys
//      vsys2 rulebase ...`), so multi-vsys works for free — the XML adapter's
//      hardcoded-vsys1 blind spot does not exist here.
//   3. Redaction is per-line, matching the established fail-closed pattern in
//      cisco_asa/parser.js redactConfig(). A brace tree would need the redactor to
//      track nesting to know what a bare `password x;` line belongs to.
//   4. getRules() and getConfig() share ONE dump — no second command, no second
//      parse dialect. (`show running security-policy` would parse only rules, in a
//      third format, and still leave getConfig() needing the config anyway.)
//
// ⚠️ UNVERIFIED AGAINST LIVE HARDWARE: the exact `set` line grammar below (attribute
// names, `[ a b ]` list syntax, quoting) is derived from PAN-OS CLI knowledge, NOT
// from a live device. ssh.js logs a redacted preview as '[PaloAlto SSH Debug]' on
// first connect — check it and correct this file before trusting the field mapping.

'use strict';

// ---------------------------------------------------------------------------
// show system info  (CLI form: flat "key: value" lines)
// ---------------------------------------------------------------------------

// Parses `show system info` CLI output into a plain { key: value } object.
//   hostname: PA-VM
//   sw-version: 10.1.6
//   model: PA-VM
// Lines that are not "key: value" are ignored. Never throws.
function parseSystemInfoLines(text) {
  const out = {};
  if (typeof text !== 'string' || text.length === 0) return out;

  for (const rawLine of text.replace(/\r/g, '').split('\n')) {
    const line = rawLine.trim();
    if (line === '') continue;
    // Split on the FIRST colon only — values can contain colons (MAC addresses,
    // IPv6, timestamps like "time: Mon Jul 15 10:00:00 2026").
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (key === '' || /\s/.test(key)) continue; // "key: value" keys are single tokens
    out[key] = value;
  }

  return out;
}

// → { version_string, build, model, hostname, serial } (null when absent).
// Field names mirror the XML adapter's parseSystemInfo() so both PAN-OS adapters
// feed device_versions identically.
function parseSystemInfoOutput(text) {
  const fields = parseSystemInfoLines(text);
  const value = (k) => (typeof fields[k] === 'string' && fields[k] !== '' ? fields[k] : null);

  const result = {
    version_string: value('sw-version'),
    // PAN-OS has no dedicated build field — app-version (content release, e.g.
    // "8810-8987") is the build fallback, same as the XML adapter.
    build: value('build') || value('app-version'),
    model: value('model') || 'unknown',
    hostname: value('hostname'),
    serial: value('serial'),
    fields,
  };

  if (!result.version_string) {
    console.warn(
      '[PaloAlto SSH parser] parseSystemInfoOutput: no "sw-version:" line found — ' +
        'check the [PaloAlto SSH Debug] raw output and adjust this parser. Keys seen: ' +
        JSON.stringify(Object.keys(fields).slice(0, 40))
    );
  }

  return result;
}

// ---------------------------------------------------------------------------
// CLI output sanity checks
// ---------------------------------------------------------------------------

// PAN-OS CLI rejections. Anchored to the start of a line so an indented
// `description "Invalid syntax test"` inside a config can never false-positive.
const CLI_ERROR_REGEX =
  /(?:^|\n)\s*(?:Invalid syntax\.?|Unknown command:|Server error\s*:|Command not recognized|Invalid command|.*is not a valid (?:command|keyword))/i;

function looksLikeCliError(text) {
  if (typeof text !== 'string' || text.length === 0) return false;
  return CLI_ERROR_REGEX.test(text);
}

// True when text plausibly IS a PAN-OS config dump. Used to refuse storing a
// rejection/banner/empty buffer as if it were a config.
// Accepts BOTH the `set` format we ask for and the default brace format, so a
// firmware that silently ignores `set cli config-output-format set` degrades to
// "config stored, rules maybe unparsed" rather than "everything fails".
function looksLikePanosConfig(text) {
  if (typeof text !== 'string' || text.trim().length === 0) return false;
  return (
    /^\s*set\s+(?:devices|network|shared|deviceconfig|mgt-config|rulebase|vsys|zone|address|service|policy)\b/im.test(
      text
    ) || /^\s*(?:config\s*\{|devices\s*\{)/im.test(text)
  );
}

// ---------------------------------------------------------------------------
// Secret redaction
// ---------------------------------------------------------------------------
//
// ⛔ MANDATORY — CLAUDE.md: "Any NEW adapter that returns a raw text config MUST
// redact before returning it from getConfig()."
//
// A PAN-OS config carries: admin password hashes (`phash`), IKE/IPsec pre-shared
// keys, SNMP community strings, SNMPv3 auth/priv passwords, LDAP/RADIUS bind
// secrets, and certificate passphrases. getConfig()'s `raw` is persisted verbatim
// into device_configs.config_raw, copied into config_backups.config_raw, served by
// the backup download route — and BOTH tables are GRANT SELECT'd to the
// claude_readonly / nocvault_readonly roles, the exact roles CLAUDE.md bars from
// device_credentials. Nothing downstream redacts. It happens here or not at all.
//
// Strategy: FAIL CLOSED, keyed on the leaf keyword. The `set` grammar is
// `set <path...> <leaf-key> <value>`, so once a secret-bearing keyword token is
// seen, EVERYTHING after it on that line is replaced. This deliberately over-
// redacts (an address object literally named `secret` loses its IP) rather than
// risk a miss — a redactor that is clever about context is a redactor that has a
// context bug. The keyword must be a WHOLE whitespace-delimited token, so
// `password-reset` / `pre-shared-key-profile` do not trigger it.
//
// Redaction is a fixed token, so it is deterministic: two pulls of an unchanged
// config redact identically and cannot cause spurious change detection.
// configDiff.js diffs config_parsed, never config_raw, so it is unaffected anyway.

const REDACTED = '<redacted>';

// Leaf keywords whose VALUE is (or may be) a secret.
const SECRET_TOKENS = new Set([
  'phash', // set mgt-config users admin phash $1$...
  'password', // generic; also `set mgt-config users <u> password`
  'passwd',
  'password-hash',
  'hashed-password',
  'passphrase', // certificate / key passphrase
  'certificate-passphrase',
  'secret', // RADIUS / TACACS+ / email server-profile secret
  'client-secret', // SAML / OAuth
  'pre-shared-key', // set network ike gateway <g> authentication pre-shared-key key <v>
  'key', //   ^ the value sits after the nested `key` token; also manual-key/esp/ah
  'auth-key',
  'esp-auth-key',
  'private-key',
  'bind-password', // LDAP server-profile
  'snmp-community-string', // set deviceconfig system snmp-setting ... v2c ... snmp-community-string
  'community-string',
  'authpwd', // SNMPv3 auth password
  'privpwd', // SNMPv3 priv password
  'api-key',
  'auth-code',
]);

// Redacts one config line. Fails CLOSED: any unexpected error redacts the WHOLE
// line rather than risking a secret passing through.
function redactLine(line) {
  try {
    if (typeof line !== 'string' || line === '') return line;
    const tokenRegex = /\S+/g;
    let match;
    while ((match = tokenRegex.exec(line)) !== null) {
      // Tolerate a trailing ';' (brace-format lines: `phash $1$abc;`) and quotes.
      const token = match[0].toLowerCase().replace(/[;"']+$/, '').replace(/^["']+/, '');
      if (!SECRET_TOKENS.has(token)) continue;

      const endOfToken = match.index + match[0].length;
      const rest = line.slice(endOfToken);
      // The keyword is the last token on the line (e.g. a brace-format section
      // header `pre-shared-key {`) — there is no value here to redact. Keep going:
      // a later token on the same line may still be a real secret leaf.
      if (rest.trim() === '' || /^\s*\{\s*$/.test(rest)) continue;

      return `${line.slice(0, endOfToken)} ${REDACTED}`;
    }
    return line;
  } catch (_err) {
    return REDACTED;
  }
}

// Redacts every secret-bearing line in a raw PAN-OS config dump.
// MUST be applied before the text leaves the adapter — nothing downstream redacts.
function redactConfig(text) {
  if (typeof text !== 'string' || text.length === 0) return '';
  return text.replace(/\r/g, '').split('\n').map(redactLine).join('\n');
}

// ---------------------------------------------------------------------------
// show config running  (set format) → rules
// ---------------------------------------------------------------------------

// Matches the rulebase segment of a `set` line, capturing:
//   1 = vsys/device-group context (may be ''), 2 = rulebase kind, 3 = the rest
// Handles:
//   set devices localhost.localdomain vsys vsys1 rulebase security rules ...
//   set devices localhost.localdomain vsys vsys1 pre-rulebase security rules ...   (Panorama-pushed)
//   set rulebase security rules ...                                                (some firmware omits the spine)
const RULE_LINE_REGEX =
  /^set\s+(.*?)\b((?:pre-|post-)?rulebase)\s+security\s+rules\s+(.+)$/i;

// Pulls the vsys name out of the captured context spine, or null.
function extractVsys(context) {
  const m = /\bvsys\s+(\S+)/i.exec(context || '');
  return m ? m[1].replace(/^["']|["']$/g, '') : null;
}

// Reads a rule name off the front of `rest`: either "quoted name" or a bare token.
// → { name, remainder } or null.
function takeRuleName(rest) {
  const quoted = /^"([^"]*)"\s*(.*)$/.exec(rest);
  if (quoted) return { name: quoted[1], remainder: quoted[2] };
  const single = /^'([^']*)'\s*(.*)$/.exec(rest);
  if (single) return { name: single[1], remainder: single[2] };
  const bare = /^(\S+)\s*(.*)$/.exec(rest);
  if (bare) return { name: bare[1], remainder: bare[2] };
  return null;
}

// Splits a string into tokens, honouring "double quoted" and 'single quoted' runs.
// Quotedness is tracked because it is the only thing that distinguishes PAN-OS's
// list SYNTAX (a bare `[`) from a value that happens to be a bracket.
function tokenizeParts(text) {
  const parts = [];
  const regex = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = regex.exec(text)) !== null) {
    if (m[1] !== undefined) parts.push({ value: m[1], quoted: true });
    else if (m[2] !== undefined) parts.push({ value: m[2], quoted: true });
    else parts.push({ value: m[3], quoted: false });
  }
  return parts;
}

function tokenize(text) {
  return tokenizeParts(text).map((p) => p.value);
}

// Parses a `set` value: `[ a b c ]` → ['a','b','c']; `"x y"` → ['x y']; `x` → ['x'].
// Always returns an array of strings (possibly empty).
//
// The brackets are SYNTAX, not values — and they do not always wrap the whole value:
// nested attributes render as `profile-setting group [ default ]`, where the list
// starts mid-value. So unquoted brackets are stripped wherever they occur rather
// than only when they wrap the entire string. (Verified by test: an earlier
// whole-value-only check let '[' and ']' through as rule tokens for exactly that
// line.) A QUOTED "[" is a legitimate value and is preserved.
function parseSetValue(text) {
  if (typeof text !== 'string') return [];
  const trimmed = text.trim();
  if (trimmed === '') return [];

  const values = [];
  for (const part of tokenizeParts(trimmed)) {
    if (part.quoted) {
      values.push(part.value);
      continue;
    }
    // Tolerate both the documented spaced form `[ a b ]` and an unspaced `[a b]`.
    const stripped = part.value.replace(/^\[+/, '').replace(/\]+$/, '');
    if (stripped !== '') values.push(stripped);
  }
  return values;
}

// Attribute → NormalizedRule field. Only the attributes we normalize are listed;
// everything else on a rule (profile-setting, source-user, category, hip-profiles,
// negate-source, ...) is kept in raw_rule instead of being dropped.
const RULE_ATTRIBUTES = new Set([
  'from',
  'to',
  'source',
  'destination',
  'service',
  'application',
  'action',
  'disabled',
  'description',
  'log-end',
  'log-start',
  'schedule',
  'tag',
  'rule-type',
]);

// Best-effort mapping from PAN-OS's action vocabulary to the NormalizedRule one.
// Mirrors parser.js mapAction() (kept local: that one takes an XML node, this takes
// a plain string). Unrecognized values pass through rather than crashing.
function mapAction(value) {
  if (typeof value !== 'string' || value === '') return null;
  switch (value.toLowerCase()) {
    case 'allow':
      return 'allow';
    case 'deny':
      return 'deny';
    case 'drop':
      return 'drop';
    case 'reset-client':
    case 'reset-server':
    case 'reset-both':
      return 'reject';
    default:
      return value;
  }
}

function newRule(name, vsys, rulebase) {
  return {
    rule_name: name,
    // Name is PAN-OS's rule identity; there is no separate stable numeric ID.
    // Prefixed with the vsys when known, so two vsys owning a same-named rule do
    // not collide in firewall_rules / the Phase 5 findings keyed off it.
    rule_id_vendor: vsys ? `${vsys}:${name}` : name,
    sequence_number: null, // assigned in document order by the caller
    enabled: true, // `disabled yes` flips it
    action: null,
    src_zones: [],
    dst_zones: [],
    src_addresses: [],
    dst_addresses: [],
    services: [],
    applications: [],
    schedule: null,
    expiry_date: null, // PAN-OS security rules have no expiry field
    // PAN-OS default is log-at-end ENABLED; only an explicit `log-end no` disables.
    log_enabled: true,
    comment: null,
    // Hit counts need the op command `show rule-hit-count`, not the config — the
    // XML adapter has the same gap. Future work; 0 is the honest default.
    hit_count: 0,
    raw_rule: { vsys, rulebase, name, attributes: {} },
  };
}

// Applies one `set ... rules <name> <attr> <value>` line to a rule accumulator.
function applyAttribute(rule, attr, valueText) {
  const values = parseSetValue(valueText);
  const first = values.length > 0 ? values[0] : null;

  // Everything is recorded raw, including attributes we do not normalize.
  rule.raw_rule.attributes[attr] = values.length > 1 ? values : first;

  switch (attr) {
    case 'from':
      rule.src_zones = values;
      break;
    case 'to':
      rule.dst_zones = values;
      break;
    case 'source':
      rule.src_addresses = values;
      break;
    case 'destination':
      rule.dst_addresses = values;
      break;
    case 'service':
      rule.services = values;
      break;
    case 'application':
      rule.applications = values;
      break;
    case 'action':
      rule.action = mapAction(first);
      break;
    case 'disabled':
      rule.enabled = !(typeof first === 'string' && first.toLowerCase() === 'yes');
      break;
    case 'description':
      rule.comment = first;
      break;
    case 'log-end':
      rule.log_enabled = !(typeof first === 'string' && first.toLowerCase() === 'no');
      break;
    case 'schedule':
      rule.schedule = first;
      break;
    default:
      // 'log-start', 'tag', 'rule-type' — recorded in raw_rule only.
      break;
  }
}

// Parses `show config running` output in SET format → NormalizedRule[].
//
// One rule spans MANY lines (one per attribute), so rules are accumulated in a map
// keyed by rulebase+vsys+name and emitted in first-seen document order — which is
// PAN-OS's evaluation order within a rulebase.
//
// Never throws: a line that cannot be parsed is counted and warned about once at the
// end, never propagated. A malformed rule must not abort the ruleset.
function parseRulesFromSetConfig(text) {
  if (typeof text !== 'string' || text.length === 0) return [];

  const byKey = new Map(); // key → rule (insertion order == document order)
  let skipped = 0;

  for (const rawLine of text.replace(/\r/g, '').split('\n')) {
    const line = rawLine.trim();
    if (line === '' || !/^set\s/i.test(line)) continue;

    let match;
    try {
      match = RULE_LINE_REGEX.exec(line);
    } catch (_err) {
      match = null;
    }
    if (!match) continue;

    try {
      const vsys = extractVsys(match[1]);
      const rulebase = match[2].toLowerCase();
      const named = takeRuleName(match[3]);
      if (!named || named.name === '') {
        skipped += 1;
        continue;
      }

      const key = `${rulebase} ${vsys || ''} ${named.name}`;
      let rule = byKey.get(key);
      if (!rule) {
        rule = newRule(named.name, vsys, rulebase);
        byKey.set(key, rule);
      }

      const attrMatch = /^(\S+)\s*(.*)$/.exec(named.remainder.trim());
      if (!attrMatch) continue; // `set ... rules <name>` with no attribute — legal, no-op
      const attr = attrMatch[1].toLowerCase();
      const valueText = attrMatch[2];

      if (RULE_ATTRIBUTES.has(attr)) {
        applyAttribute(rule, attr, valueText);
      } else {
        // Unknown/unnormalized attribute — keep it in raw_rule so a live device can
        // be used to extend RULE_ATTRIBUTES later without a re-pull.
        rule.raw_rule.attributes[attr] = parseSetValue(valueText);
      }
    } catch (err) {
      skipped += 1;
      console.warn(`[PaloAlto SSH parser] Skipping unparseable rule line: ${err.message}`);
    }
  }

  if (skipped > 0) {
    console.warn(
      `[PaloAlto SSH parser] ${skipped} rule line(s) could not be parsed and were skipped — ` +
        'check the [PaloAlto SSH Debug] output; the rest of the ruleset was kept.'
    );
  }

  const rules = Array.from(byKey.values());
  rules.forEach((rule, idx) => {
    rule.sequence_number = idx + 1;
  });
  return rules;
}

// ---------------------------------------------------------------------------
// show config running (set format) → structured config for Phase 6 predicates
// ---------------------------------------------------------------------------

// Extracts the vsys names present in the config (`set devices X vsys vsysN ...`).
function parseVsysNames(text) {
  const names = [];
  if (typeof text !== 'string' || text.length === 0) return names;
  const regex = /^set\s+devices\s+\S+\s+vsys\s+(\S+)/gim;
  let m;
  while ((m = regex.exec(text)) !== null) {
    const name = m[1].replace(/^["']|["']$/g, '');
    if (name && !names.includes(name)) names.push(name);
  }
  return names;
}

// Management-plane service toggles:
//   set deviceconfig system service disable-telnet no
//   set deviceconfig system service disable-http yes
// → { 'disable-telnet': 'no', 'disable-http': 'yes', ... }
// Values only, never secrets (this section carries none).
function parseServiceFlags(text) {
  const flags = {};
  if (typeof text !== 'string' || text.length === 0) return flags;
  const regex = /^set\s+deviceconfig\s+system\s+service\s+(\S+)\s+(\S+)\s*$/gim;
  let m;
  while ((m = regex.exec(text)) !== null) {
    flags[m[1].toLowerCase()] = m[2].toLowerCase();
  }
  return flags;
}

// Builds the `parsed` half of getConfig()'s { raw, parsed }.
//
// Deliberately modest: it carries the facts the Phase 6 dot-path predicate engine
// can actually interrogate, and nothing whose shape is a guess. It must NEVER be an
// empty object on a successful pull — lib/engines/applicability.js hasUsableConfig()
// treats {} exactly like null and downgrades every CVE to 'unknown'.
//
// SECURITY: values here come from the config too. Only allow-listed, known-non-secret
// facts are copied (system-info fields, vsys names, service toggles, counts) —
// never a free-form line.
function parseConfigFromSet(text, systemInfoOutput) {
  const info = systemInfoOutput && typeof systemInfoOutput === 'object' ? systemInfoOutput : {};
  const infoFields = info.fields && typeof info.fields === 'object' ? info.fields : {};

  return {
    collected_via: 'ssh',
    source_command: 'show config running (set format)',
    line_count: typeof text === 'string' ? text.split('\n').length : 0,
    hostname: info.hostname || infoFields.hostname || null,
    model: info.model || infoFields.model || null,
    sw_version: info.version_string || infoFields['sw-version'] || null,
    system_info: infoFields,
    vsys: parseVsysNames(text),
    services: parseServiceFlags(text),
    security_rules_count: parseRulesFromSetConfig(text).length,
  };
}

module.exports = {
  parseSystemInfoOutput,
  parseRulesFromSetConfig,
  parseConfigFromSet,
  redactConfig,
  looksLikeCliError,
  looksLikePanosConfig,
  // exported for testing / reuse, not part of the documented contract
  parseSystemInfoLines,
  parseSetValue,
  parseVsysNames,
  parseServiceFlags,
  redactLine,
  mapAction,
  tokenize,
};
