// lib/adapters/sangfor/parser.js
// CommonJS ONLY — required by lib/adapters/sangfor/index.js, which is required by
// services/engine-worker.js (plain node, CommonJS).
//
// Pure functions only — no I/O, no network, no DB access. These functions must NEVER
// throw on malformed/unexpected input. Sangfor NGAF has no stable, documented CLI
// output format (it varies by firmware line and borrows from both Cisco-style and
// Huawei-style syntax), so everything here is best-effort token extraction with safe
// fallbacks. Anything unrecognizable is skipped, never fatal — per CLAUDE.md, partial
// data beats thrown errors for this vendor.

'use strict';

// First token that looks like a dotted version number, e.g. "8.0.85" or "8.0.85.123".
const VERSION_RE = /\d+\.\d+(?:\.\d+)*/;

// Bare action words seen across Sangfor/Cisco/Huawei-flavored CLIs, mapped to the
// NormalizedRule action vocabulary. Unknown values pass through as-is (never throw).
const ACTION_MAP = {
  permit: 'allow',
  allow: 'allow',
  accept: 'allow',
  pass: 'allow',
  deny: 'deny',
  block: 'deny',
  drop: 'drop',
  discard: 'drop',
  reject: 'reject',
  refuse: 'reject',
};

const ACTION_WORDS = new Set(Object.keys(ACTION_MAP));

// A candidate rule/policy block starts at a line whose statement begins with
// 'policy' or 'rule' (optionally prefixed by common section keywords). Lines that
// merely *mention* policy/rule mid-sentence do not start a block.
const HEADER_RE = /^\s*(?:(?:firewall|security|acl|ip|nat|access|app)\s+)*(policy|rule)\b\s*(.*)$/i;

// Lines that terminate a block (Cisco '!' separators, comments, exit/end keywords).
const BLOCK_END_RE = /^\s*(?:[!#].*)?$/;
const BLOCK_EXIT_RE = /^\s*(?:exit|quit|end|return)\s*$/i;

// Field keyword classes. Hyphen/underscore variants are normalized before lookup.
const SRC_ZONE_KEYS = new Set(['source-zone', 'src-zone', 'from', 'from-zone']);
const DST_ZONE_KEYS = new Set(['destination-zone', 'dst-zone', 'dest-zone', 'to', 'to-zone']);
const SRC_ADDR_KEYS = new Set([
  'source', 'src', 'source-address', 'src-address', 'source-ip', 'src-ip', 'source-net', 'src-net',
]);
const DST_ADDR_KEYS = new Set([
  'destination', 'dst', 'dest', 'destination-address', 'dst-address', 'dest-address',
  'destination-ip', 'dst-ip', 'dest-ip',
]);
const SVC_KEYS = new Set(['service', 'services', 'port', 'ports', 'dst-port', 'dest-port', 'protocol', 'proto', 'application', 'app']);
const NAME_KEYS = new Set(['name']);
const ID_KEYS = new Set(['id']);
const COMMENT_KEYS = new Set(['comment', 'description', 'desc', 'remark']);

// Every keyword that terminates a value list (so "source 10.0.0.0/24 destination any"
// stops collecting src values at 'destination').
const STOP_KEYWORDS = new Set([
  ...SRC_ZONE_KEYS, ...DST_ZONE_KEYS, ...SRC_ADDR_KEYS, ...DST_ADDR_KEYS,
  ...SVC_KEYS, ...NAME_KEYS, ...ID_KEYS, ...COMMENT_KEYS,
  ...ACTION_WORDS,
  'action', 'log', 'logging', 'enable', 'enabled', 'disable', 'disabled', 'status',
]);

function normalizeToken(token) {
  return String(token).toLowerCase().replace(/_/g, '-').replace(/[:,;]+$/, '');
}

function mapAction(word) {
  if (word === null || word === undefined) return null;
  const key = String(word).toLowerCase();
  return ACTION_MAP[key] !== undefined ? ACTION_MAP[key] : word;
}

function pushUnique(arr, value) {
  if (value !== null && value !== undefined && value !== '' && !arr.includes(value)) {
    arr.push(value);
  }
}

// ---------------------------------------------------------------------------
// parseVersionOutput(text) → { version_string, build, model }
// Best-effort extraction from `show version` / `display version` output.
// Never throws; every field may be null.
// ---------------------------------------------------------------------------
function parseVersionOutput(text) {
  const result = { version_string: null, build: null, model: null };
  if (typeof text !== 'string' || text.trim().length === 0) return result;

  try {
    const versionMatch = text.match(VERSION_RE);
    if (versionMatch) result.version_string = versionMatch[0];

    const lines = text.split(/\r?\n/);

    // Model: prefer explicit 'model'/'platform' lines, then fall back to any line
    // mentioning NGAF (the product family name often appears in the banner).
    for (const line of lines) {
      if (/\b(model|platform)\b/i.test(line)) {
        const colonIdx = line.indexOf(':');
        const value = colonIdx >= 0 ? line.slice(colonIdx + 1).trim() : null;
        result.model = value && value.length > 0 ? value : line.trim();
        break;
      }
    }
    if (result.model === null) {
      for (const line of lines) {
        if (/\bNGAF\b/i.test(line) || /\bNGAF[\w-]+/i.test(line)) {
          const ngafToken = line.match(/\bNGAF[\w.-]*/i);
          result.model = ngafToken ? ngafToken[0] : line.trim();
          break;
        }
      }
    }

    // Build: first line mentioning 'build', value after the word.
    for (const line of lines) {
      if (/\bbuild\b/i.test(line)) {
        const m = line.match(/build[\s:#-]*([\w.-]+)/i);
        if (m && m[1]) {
          result.build = m[1];
          break;
        }
      }
    }
  } catch (err) {
    // Pure parser — never throw. Log and return whatever was extracted so far.
    console.warn(`[Sangfor parser] parseVersionOutput failed: ${err.message}`);
  }

  return result;
}

// ---------------------------------------------------------------------------
// Internal: scan one line of a rule block, accumulating fields onto `acc`.
// ---------------------------------------------------------------------------
function extractFieldsFromLine(line, acc) {
  const tokens = line.trim().split(/\s+/).filter((t) => t.length > 0);

  for (let i = 0; i < tokens.length; i++) {
    const key = normalizeToken(tokens[i]);

    // Bare action words ("action permit" is handled by the 'action' case below;
    // "rule 20 deny ..." is handled here).
    if (ACTION_WORDS.has(key)) {
      if (acc.action === null) acc.action = mapAction(key);
      continue;
    }

    if (key === 'action') {
      const value = tokens[i + 1];
      if (value !== undefined) {
        acc.action = mapAction(normalizeToken(value));
        i += 1;
      }
      continue;
    }

    if (key === 'log' || key === 'logging') {
      acc.log_enabled = true;
      continue;
    }
    if (key === 'disable' || key === 'disabled') {
      acc.enabled = false;
      continue;
    }

    if (COMMENT_KEYS.has(key)) {
      const rest = tokens.slice(i + 1).join(' ').replace(/^["']|["']$/g, '');
      if (rest.length > 0 && acc.comment === null) acc.comment = rest;
      break; // comment consumes the rest of the line
    }

    if (NAME_KEYS.has(key)) {
      const value = tokens[i + 1];
      if (value !== undefined && acc.rule_name === null) {
        acc.rule_name = value.replace(/^["']|["']$/g, '');
        i += 1;
      }
      continue;
    }

    if (ID_KEYS.has(key)) {
      const value = tokens[i + 1];
      if (value !== undefined && acc.rule_id_vendor === null && /^\d+$/.test(value)) {
        acc.rule_id_vendor = value;
        i += 1;
      }
      continue;
    }

    // Value-list keywords: collect following tokens until the next known keyword.
    let target = null;
    if (SRC_ZONE_KEYS.has(key)) target = acc.src_zones;
    else if (DST_ZONE_KEYS.has(key)) target = acc.dst_zones;
    else if (SRC_ADDR_KEYS.has(key)) target = acc.src_addresses;
    else if (DST_ADDR_KEYS.has(key)) target = acc.dst_addresses;
    else if (SVC_KEYS.has(key)) target = acc.services;

    if (target !== null) {
      let j = i + 1;
      while (j < tokens.length && !STOP_KEYWORDS.has(normalizeToken(tokens[j])) && normalizeToken(tokens[j]) !== 'action') {
        pushUnique(target, tokens[j].replace(/^["']|["']$/g, ''));
        j += 1;
      }
      i = j - 1;
    }
  }
}

// ---------------------------------------------------------------------------
// parseRulesFromConfig(text) → NormalizedRule[]
// Best-effort extraction of policy/rule blocks from a raw CLI config dump.
// A block = a line starting with 'policy'/'rule' (plus its following lines up to
// the next block header, separator, or exit keyword). Only blocks containing a
// recognizable action keyword (permit/deny/allow/drop/...) become rules; anything
// unparseable is skipped silently. Never throws; returns [] on garbage/empty input.
// ---------------------------------------------------------------------------
function parseRulesFromConfig(text) {
  if (typeof text !== 'string' || text.trim().length === 0) return [];

  let lines;
  try {
    lines = text.split(/\r?\n/);
  } catch (err) {
    return [];
  }

  // Pass 1: group lines into candidate blocks.
  const blocks = [];
  let current = null;
  for (const line of lines) {
    const headerMatch = line.match(HEADER_RE);
    if (headerMatch) {
      if (current) blocks.push(current);
      current = { headerRest: headerMatch[2] || '', lines: [line] };
      continue;
    }
    if (!current) continue; // line outside any block — ignore
    if (BLOCK_EXIT_RE.test(line) || BLOCK_END_RE.test(line)) {
      blocks.push(current);
      current = null;
      continue;
    }
    current.lines.push(line);
  }
  if (current) blocks.push(current);

  // Pass 2: parse each block independently — one bad block never kills the rest.
  const rules = [];
  for (const block of blocks) {
    try {
      const blockText = block.lines.join('\n');

      // Only blocks with a recognizable action keyword count as rules.
      const hasAction = block.lines.some((l) =>
        l.trim().split(/\s+/).some((t) => {
          const n = normalizeToken(t);
          return ACTION_WORDS.has(n) || n === 'action';
        })
      );
      if (!hasAction) continue;

      const acc = {
        rule_name: null,
        rule_id_vendor: null,
        enabled: true,
        action: null,
        src_zones: [],
        dst_zones: [],
        src_addresses: [],
        dst_addresses: [],
        services: [],
        log_enabled: false,
        comment: null,
      };

      // Header shorthand: "rule 20 ..." → the leading numeric token is the vendor id.
      const headerTokens = block.headerRest.trim().split(/\s+/).filter((t) => t.length > 0);
      if (headerTokens.length > 0 && /^\d+$/.test(headerTokens[0])) {
        acc.rule_id_vendor = headerTokens[0];
      }

      for (const line of block.lines) {
        extractFieldsFromLine(line, acc);
      }

      // A block with an 'action' keyword token but no resolvable action value is
      // still emitted (action null) — partial data beats dropped data — but a block
      // where literally nothing was extracted beyond the header is skipped.
      const extractedSomething =
        acc.action !== null || acc.rule_name !== null || acc.rule_id_vendor !== null ||
        acc.src_addresses.length > 0 || acc.dst_addresses.length > 0 || acc.services.length > 0 ||
        acc.src_zones.length > 0 || acc.dst_zones.length > 0;
      if (!extractedSomething) continue;

      rules.push({
        rule_name: acc.rule_name,
        rule_id_vendor: acc.rule_id_vendor,
        sequence_number: rules.length + 1,
        enabled: acc.enabled,
        action: acc.action,
        src_zones: acc.src_zones,
        dst_zones: acc.dst_zones,
        src_addresses: acc.src_addresses,
        dst_addresses: acc.dst_addresses,
        services: acc.services,
        applications: [],
        schedule: null,
        expiry_date: null,
        log_enabled: acc.log_enabled,
        comment: acc.comment,
        hit_count: 0,
        raw_rule: { source: 'sangfor-cli-config', text: blockText },
      });
    } catch (err) {
      // Skip the unparseable block; keep going. Never throw.
      console.warn(`[Sangfor parser] Skipping unparseable rule block: ${err.message}`);
    }
  }

  return rules;
}

// ---------------------------------------------------------------------------
// redactConfig(text) → text with secret values replaced by '<redacted>'
//
// SECURITY: the raw config dump is persisted verbatim into
// device_configs.config_raw, copied into config_backups.config_raw, served by
// the backup download route, and both tables are GRANT SELECT'd to the
// claude_readonly / nocvault_readonly diagnostic roles. It MUST be redacted
// before it leaves the adapter — see CLAUDE.md "Security".
//
// Unlike the ASA, Sangfor NGAF's CLI grammar is undocumented and varies by
// firmware, so this cannot be an exhaustive per-command rule set. It therefore
// FAILS CLOSED: any line containing a secret-ish keyword has everything after
// that keyword redacted. Over-redaction is acceptable here (the config snapshot
// is for change tracking, not device restore); under-redaction is not.
// Deterministic by design — configDiff.js diffs config_parsed, never
// config_raw, so redaction cannot affect change detection.
// ---------------------------------------------------------------------------

const REDACTED = '<redacted>';

// Keyword → redact the remainder of the line. Deliberately excludes a bare
// "key" (would maul `key-exchange`, `key-chain`, ...) — that case is handled by
// the standalone-key rule below.
const SECRET_KEYWORD_RE =
  /\b(password|passwd|pwd|secret|pre-shared-key|preshared-key|psk|community|key-string|shared-key|auth-key|authentication-key|private-key|credential)\b(\s*[:=]?\s*)(\S.*)$/i;

// A standalone `key <value>` statement (value runs to end of line).
const STANDALONE_KEY_RE = /^(\s*key\s+)(\S+)\s*$/i;

// PEM private key blocks — unambiguous, and a catastrophic leak if persisted.
const PEM_PRIVATE_KEY_RE =
  /-----BEGIN ([A-Z ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----/g;

function redactConfig(text) {
  if (typeof text !== 'string' || text.length === 0) return '';

  try {
    const withoutPem = text.replace(
      PEM_PRIVATE_KEY_RE,
      (_m, label) => `-----BEGIN ${label}-----\n${REDACTED}\n-----END ${label}-----`
    );

    return withoutPem
      .replace(/\r/g, '')
      .split('\n')
      .map((line) => {
        try {
          if (STANDALONE_KEY_RE.test(line)) {
            return line.replace(STANDALONE_KEY_RE, `$1${REDACTED}`);
          }
          if (SECRET_KEYWORD_RE.test(line)) {
            return line.replace(SECRET_KEYWORD_RE, `$1$2${REDACTED}`);
          }
          return line;
        } catch (_err) {
          return REDACTED; // fail closed
        }
      })
      .join('\n');
  } catch (err) {
    // Never let a redaction failure surface unredacted text.
    console.warn(`[Sangfor parser] redactConfig failed — redacting entire config: ${err.message}`);
    return REDACTED;
  }
}

// ---------------------------------------------------------------------------
// parseConfigSections(text) → { hostname?, version?, interfaces? }
// Best-effort structural hints from the raw config. Fields are simply absent when
// nothing recognizable is found. Never throws.
// ---------------------------------------------------------------------------
function parseConfigSections(text) {
  const sections = {};
  if (typeof text !== 'string' || text.trim().length === 0) return sections;

  try {
    const hostMatch = text.match(/^\s*(?:hostname|host-name|sysname)\s+("?)([^\r\n"]+)\1/im);
    if (hostMatch && hostMatch[2].trim().length > 0) {
      sections.hostname = hostMatch[2].trim();
    }

    const versionMatch = text.match(VERSION_RE);
    if (versionMatch) sections.version = versionMatch[0];

    const interfaces = [];
    const ifaceRe = /^\s*interface\s+(\S+)/gim;
    let m;
    while ((m = ifaceRe.exec(text)) !== null) {
      pushUnique(interfaces, m[1]);
      if (interfaces.length >= 500) break; // sanity cap on pathological input
    }
    if (interfaces.length > 0) sections.interfaces = interfaces;
  } catch (err) {
    console.warn(`[Sangfor parser] parseConfigSections failed: ${err.message}`);
  }

  return sections;
}

module.exports = {
  parseVersionOutput,
  parseRulesFromConfig,
  parseConfigSections,
  redactConfig,
  // exported for testing / reuse, not part of the documented contract
  mapAction,
};
