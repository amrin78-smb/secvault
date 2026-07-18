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
// ── Brace format, not `set` format ───────────────────────────────────────────
// Two prior attempts to get flat `set ...` lines out of this firmware both
// failed live (2026-07-16, PAN-OS 11.1.13-h5, two independent devices — a
// PA-440 and a PA-3220): `configure` + `set cli config-output-format set` +
// bare `show` runs correctly (confirmed: the command executed is `show`, and
// the dump size matches pulling the whole tree from root) but the retrieved
// text is reliably the classic curly-brace tree, never `set` lines. This file
// now parses THAT format, built directly against a real captured sample of
// the actual rulebase section (ssh.js's targeted "rulebase" debug search
// exists specifically because the plain head-of-file preview twice landed in
// deviceconfig/mgt-config and never reached it on a 93KB-1.2MB dump). See the
// tokenizer/parser section below for the confirmed grammar.
//
// getRules() and getConfig() still share ONE dump/one parse dialect — that
// part of the original design was sound and is unchanged.

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
// rejection/banner/empty buffer as if it were a config. Accepts BOTH the brace
// tree this firmware actually returns AND flat `set` lines (in case a
// different firmware genuinely does honour the format preference), so an
// untested firmware degrades to "config stored, rules maybe unparsed" rather
// than "everything fails".
function looksLikePanosConfig(text) {
  if (typeof text !== 'string' || text.trim().length === 0) return false;
  return (
    /^\s*set\s+(?:devices|network|shared|deviceconfig|mgt-config|rulebase|vsys|zone|address|service|policy)\b/im.test(
      text
    ) || /^\s*(?:config\s*\{|devices\s*\{|deviceconfig\s*\{|rulebase\s*\{|mgt-config\s*\{)/im.test(text)
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
// Strategy: FAIL CLOSED, keyed on the leaf keyword — once a secret-bearing
// keyword token is seen on a line, EVERYTHING after it on that line is
// replaced. This deliberately over-redacts (an address object literally named
// `secret` loses its IP) rather than risk a miss — a redactor that is clever
// about context is a redactor that has a context bug. The keyword must be a
// WHOLE whitespace-delimited token, so `password-reset` / `pre-shared-key-profile`
// do not trigger it. Line-based, not brace-tree-aware, on purpose: it works
// identically regardless of which format the device returns.
//
// Redaction is a fixed token, so it is deterministic: two pulls of an unchanged
// config redact identically and cannot cause spurious change detection.
// configDiff.js diffs config_parsed, never config_raw, so it is unaffected anyway.

const REDACTED = '<redacted>';

// Leaf keywords whose VALUE is (or may be) a secret.
const SECRET_TOKENS = new Set([
  'phash', // mgt-config users <u> phash $1$...
  'password', // generic
  'passwd',
  'password-hash',
  'hashed-password',
  'passphrase', // certificate / key passphrase
  'certificate-passphrase',
  'secret', // RADIUS / TACACS+ / email server-profile secret
  'client-secret', // SAML / OAuth
  'pre-shared-key', // network ike gateway <g> authentication pre-shared-key key <v>
  'key', //   ^ the value sits after the nested `key` token; also manual-key/esp/ah
  'auth-key',
  'esp-auth-key',
  'private-key',
  'bind-password', // LDAP server-profile
  'snmp-community-string', // deviceconfig system snmp-setting ... v2c ... snmp-community-string
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
// `show` (brace format) — tokenizer + recursive-descent parser
// ---------------------------------------------------------------------------
//
// Grammar, as directly observed in a real capture (2026-07-16, PAN-OS
// 11.1.13-h5, PA-3220 — see ssh.js's targeted "rulebase" debug search):
//   block      := statement*
//   statement  := KEY ( '{' block '}' | '[' value* ']' ';'? | value ';'? | ';' )
//   value      := bare-token | "quoted string"
// e.g.:
//   rulebase {
//     security {
//       rules {
//         Block_AI_Request {
//           to any;
//           from [ DMZ1 DMZ2 DMZ3];
//           action drop;
//         }
//       }
//     }
//   }
// A bare `KEY;` with nothing between (e.g. `schedule;`) means an empty/absent
// value — some PAN-OS schema nodes render this way for an unset container.
// List brackets are NOT reliably spaced (`[ DMZ1 DMZ2 DMZ3]` — no space
// before `]` even though there is one after `[`), so the tokenizer treats
// `[`/`]`/`{`/`}`/`;` as structural regardless of adjacent whitespace, never
// relying on whitespace to delimit them.

const STRUCTURAL_CHARS = new Set(['{', '}', ';', '[', ']']);

function tokenizeBraceConfig(text) {
  const tokens = [];
  const s = String(text || '');
  let i = 0;
  while (i < s.length) {
    const ch = s[i];
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
      i += 1;
      continue;
    }
    if (ch === '"') {
      i += 1;
      let buf = '';
      while (i < s.length && s[i] !== '"') {
        if (s[i] === '\\' && i + 1 < s.length) {
          buf += s[i + 1];
          i += 2;
          continue;
        }
        buf += s[i];
        i += 1;
      }
      if (s[i] === '"') i += 1;
      tokens.push({ kind: 'value', text: buf });
      continue;
    }
    if (STRUCTURAL_CHARS.has(ch)) {
      tokens.push({ kind: ch });
      i += 1;
      continue;
    }
    const start = i;
    while (i < s.length && !/\s/.test(s[i]) && !STRUCTURAL_CHARS.has(s[i]) && s[i] !== '"') {
      i += 1;
    }
    tokens.push({ kind: 'value', text: s.slice(start, i) });
  }
  return tokens;
}

// Recursive-descent parse of one block's body, starting at `pos` (just past an
// opening '{', or 0 for the document root), stopping at a matching '}' or
// end-of-input. Returns [node, nextPos]. Never throws — any token shape it
// doesn't recognize is skipped defensively so one malformed statement can't
// lose the rest of the tree.
//
// `isRoot` (default true) distinguishes the two call sites:
//   - Root (parseBraceConfig's call, isRoot=true, the default): there is no
//     enclosing '{' for this invocation, so a '}' encountered here is a STRAY,
//     unmatched token (plausible on truncated/corrupted SSH output) — not a
//     legitimate terminator. Treating it as one would end the loop immediately
//     and silently discard the entire rest of the document (including a
//     rulebase that might appear later). Consistent with this function's
//     documented defensive philosophy above, a stray '}' at the root is
//     skipped exactly like any other unrecognized token, and parsing
//     continues.
//   - Nested (every recursive call from the `next.kind === '{'` branch below,
//     isRoot=false): this invocation was entered by consuming a real opening
//     '{', so its matching '}' IS its legitimate close signal and must still
//     terminate the loop.
//
// Each block is a plain object (not a Map) so callers can use ordinary dot
// access / lib/engines/applicability.js's getByPath() directly on the result.
// Sibling keys within one PAN-OS block are unique in every sample observed
// (rule names, zone names, address names are all distinct identifiers) — a
// genuine duplicate key silently overwrites the earlier value rather than
// throwing, an accepted, documented limitation rather than a crash risk.
function parseBraceBlock(tokens, pos, isRoot = true) {
  const node = {};
  while (pos < tokens.length) {
    if (tokens[pos].kind === '}') {
      if (isRoot) {
        // Stray/unmatched '}' at the root — not a legal terminator here.
        // Skip this single token defensively and keep going, same as any
        // other unrecognized token shape, instead of ending the loop.
        pos += 1;
        continue;
      }
      break;
    }

    const keyTok = tokens[pos];
    if (keyTok.kind !== 'value') {
      // Stray structural token where a key was expected — skip and keep going.
      pos += 1;
      continue;
    }
    const key = keyTok.text;
    pos += 1;
    const next = tokens[pos];

    if (!next) {
      node[key] = null;
      break;
    }

    if (next.kind === '{') {
      pos += 1;
      const [child, afterChild] = parseBraceBlock(tokens, pos, false);
      pos = afterChild;
      if (tokens[pos] && tokens[pos].kind === '}') pos += 1;
      node[key] = child;
    } else if (next.kind === '[') {
      pos += 1;
      const values = [];
      while (pos < tokens.length && tokens[pos].kind !== ']') {
        if (tokens[pos].kind === 'value') values.push(tokens[pos].text);
        pos += 1;
      }
      if (tokens[pos] && tokens[pos].kind === ']') pos += 1;
      if (tokens[pos] && tokens[pos].kind === ';') pos += 1;
      node[key] = values;
    } else if (next.kind === ';') {
      pos += 1;
      node[key] = null;
    } else if (next.kind === 'value') {
      pos += 1;
      node[key] = next.text;
      if (tokens[pos] && tokens[pos].kind === ';') pos += 1;
    } else {
      // Unexpected structural token ('}' is handled by the loop guard) — treat
      // as a bare key with no value and keep going.
      node[key] = null;
    }
  }
  return [node, pos];
}

// Parses a full PAN-OS brace-format config dump into a plain nested object.
// Never throws. An empty/unparseable input yields {} — callers must treat
// that the same as "no usable config" (see CLAUDE.md hasUsableConfig()).
function parseBraceConfig(text) {
  if (typeof text !== 'string' || text.length === 0) return {};
  try {
    const tokens = tokenizeBraceConfig(text);
    const [root] = parseBraceBlock(tokens, 0);
    return root;
  } catch (err) {
    console.warn(`[PaloAlto SSH parser] Failed to parse brace config: ${err.message}`);
    return {};
  }
}

// Depth-first search for every `rulebase { security { rules { ... } } }`
// container reachable ANYWHERE in the tree, regardless of what wraps it (a
// bare single-vsys root — confirmed live, this device's `multi-vsys: off` —
// a `vsys { entry-name { ... } }` wrapper, `shared { ... }`, or a Panorama
// `panorama { ... pre-rulebase ... }` shape). Same "search deep, don't assume
// the absolute path" approach fortinet/cliParser.js's findBlockDeep() already
// uses in this codebase. Returns an array of `{ ruleName: attrs }` objects.
function findSecurityRulesContainers(node, depth) {
  const results = [];
  if (!node || typeof node !== 'object' || Array.isArray(node) || depth > 14) return results;

  const rulebase = node.rulebase;
  if (rulebase && typeof rulebase === 'object' && !Array.isArray(rulebase)) {
    const security = rulebase.security;
    if (security && typeof security === 'object' && !Array.isArray(security)) {
      const rules = security.rules;
      if (rules && typeof rules === 'object' && !Array.isArray(rules)) {
        results.push(rules);
      }
    }
  }

  for (const key of Object.keys(node)) {
    const child = node[key];
    if (child && typeof child === 'object' && !Array.isArray(child)) {
      results.push(...findSecurityRulesContainers(child, depth + 1));
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Rule hit-count enrichment (SSH transport) — ADDITIVE, best-effort.
// ---------------------------------------------------------------------------
//
// SEPARATE FROM parser.js's equivalent ON PURPOSE, same "independent per
// format" convention as the rest of this file (redactConfig vs
// redactConfigXml, parseSecurityRules vs parseRules) — this parses CLI TEXT
// output of `show rule-hit-count`, not an XML API response.

const DEFAULT_VSYS_NAME = 'vsys1';

// Best-effort discovery of named vsys entries in the parsed brace tree, for
// the hit-count command (`show rule-hit-count vsys <name> ...`), which needs
// an explicit vsys name unlike findSecurityRulesContainers()'s deep,
// name-agnostic search for the rules themselves. Looks for a
// `vsys { <name>: {...}, <name2>: {...} }` wrapper anywhere in the tree; if
// none is found — the confirmed-live shape for this deployment's device
// (2026-07-16, "multi-vsys: off") has no such wrapper at all — falls back to
// the PAN-OS default single-vsys name, matching the XML/API transport's
// api.DEFAULT_VSYS convention. Never throws.
function resolveVsysNames(tree) {
  const found = new Set();
  try {
    walkForVsysNames(tree, 0, found);
  } catch (err) {
    console.warn(`[PaloAlto SSH parser] resolveVsysNames: walk failed: ${err.message}`);
  }
  return found.size > 0 ? Array.from(found) : [DEFAULT_VSYS_NAME];
}

function walkForVsysNames(node, depth, found) {
  if (depth > 14 || !node || typeof node !== 'object' || Array.isArray(node)) return;

  const vsysNode = node.vsys;
  if (vsysNode && typeof vsysNode === 'object' && !Array.isArray(vsysNode)) {
    for (const key of Object.keys(vsysNode)) {
      const child = vsysNode[key];
      if (child && typeof child === 'object' && !Array.isArray(child)) found.add(key);
    }
  }

  for (const value of Object.values(node)) {
    if (value && typeof value === 'object') walkForVsysNames(value, depth + 1, found);
  }
}

// Lines that are pure table decoration (`---`, `===`, whitespace combos) —
// never a data row.
const HIT_COUNT_SEPARATOR_RE = /^[-=\s]+$/;
// A plausible header row: starts with a "name"-ish column label and mentions
// "hit" somewhere on the line. Skipped defensively rather than parsed as data
// (a header's own text is very unlikely to coincidentally look like a valid
// "name + numeric column" data row, but the check costs nothing and avoids a
// pathological false match).
const HIT_COUNT_HEADER_RE = /^(rule\s*name|name)\b/i;

// Parses the CLI output of `show rule-hit-count vsys <v> rule-base security
// rules all` into a { [ruleName]: hitCount } map.
//
// ⚠️ DOC-DERIVED, NOT YET LIVE-VERIFIED — no live PAN-OS device has confirmed
// this command's exact output shape for this codebase (same standing caveat
// as the XML/API transport's parser.parseRuleHitCount() and every other
// unverified field in this file — see CLAUDE.md's "Live Validation Status").
// `show rule-hit-count` is a real, documented PAN-OS operational command; its
// output is most likely a formatted table (rule name column + a numeric
// hit-count column, plus other columns like last-hit-date this function
// ignores). ssh.js logs the FULL raw output the first time this runs
// (`[PaloAlto SSH Debug] rule-hit-count raw output:`) so a future live
// connection can confirm/correct this parser.
//
// Best-effort, line-based: PAN-OS CLI tables are typically column-aligned
// with runs of 2+ spaces between columns (the same convention
// parseSystemInfoLines() above does NOT need, since that output is
// "key: value", but tabular `show` output generally uses). A row is accepted
// only when it has at least 2 whitespace-delimited columns AND at least one
// of the columns (after the first) is purely numeric (commas tolerated,
// e.g. "1,234") — that numeric column is taken as the hit count, the first
// column as the rule name. Any line that doesn't fit this shape (headers,
// separators, unexpected/differently-shaped rows) is skipped, never guessed
// at — a missed row just means that one rule's hit_count stays at its
// existing default (0), which is the safe direction for a best-effort parse.
// Never throws.
function parseRuleHitCountOutput(text) {
  const out = {};
  if (typeof text !== 'string' || text.length === 0) return out;

  try {
    for (const rawLine of text.replace(/\r/g, '').split('\n')) {
      const line = rawLine.trim();
      if (line === '') continue;
      if (HIT_COUNT_SEPARATOR_RE.test(line)) continue;
      if (HIT_COUNT_HEADER_RE.test(line) && /hit/i.test(line)) continue;
      if (looksLikeCliError(line)) continue;

      const cols = line.split(/\s{2,}/).map((c) => c.trim()).filter((c) => c !== '');
      if (cols.length < 2) continue;

      const name = cols[0];
      if (!name) continue;

      let hitCount = null;
      for (let i = 1; i < cols.length; i += 1) {
        const numeric = cols[i].replace(/,/g, '');
        if (/^\d+$/.test(numeric)) {
          hitCount = Number(numeric);
          break;
        }
      }
      if (hitCount === null) continue;

      out[name] = hitCount;
    }
  } catch (err) {
    console.warn(`[PaloAlto SSH parser] parseRuleHitCountOutput: parse failed, returning no hit counts: ${err.message}`);
    return {};
  }

  return out;
}

// A PAN-OS brace attribute value is a bare scalar, a list (array), or absent
// (null, from a bare `key;`). NormalizedRule fields are always arrays — this
// normalizes all three shapes to one.
function asArray(value) {
  if (value === null || value === undefined) return [];
  if (Array.isArray(value)) return value;
  if (typeof value === 'object') return []; // a nested block where a scalar/list was expected
  return [value];
}

function asScalar(value) {
  return typeof value === 'string' ? value : null;
}

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

// Builds one NormalizedRule from a `{ ruleName: attrs }` container entry. The
// rule's identity IS the block key — there is no separate "name" attribute in
// brace format (unlike `set` format's `set ... rules "Name" ...`), so there is
// no "unnamed rule" ambiguity here: every entry inherently has one.
function ruleFromBraceEntry(name, attrs, sequenceNumber) {
  const a = attrs && typeof attrs === 'object' ? attrs : {};
  return {
    rule_name: name,
    rule_id_vendor: name,
    sequence_number: sequenceNumber,
    enabled: !(asScalar(a.disabled) === 'yes'),
    action: mapAction(asScalar(a.action)),
    src_zones: asArray(a.from),
    dst_zones: asArray(a.to),
    src_addresses: asArray(a.source),
    dst_addresses: asArray(a.destination),
    services: asArray(a.service),
    applications: asArray(a.application),
    schedule: asScalar(a.schedule),
    expiry_date: null, // PAN-OS security rules have no expiry field
    // PAN-OS default is log-at-end ENABLED; only an explicit `log-end no` disables.
    log_enabled: !(asScalar(a['log-end']) === 'no'),
    comment: asScalar(a.description),
    // Hit counts need the op command `show rule-hit-count`, not the config —
    // same gap as the XML adapter.
    hit_count: 0,
    raw_rule: a,
  };
}

// Parses a brace-format config dump → { rules: NormalizedRule[], containersFound }.
// Collects EVERY `rulebase/security/rules` container found anywhere in the tree
// (see findSecurityRulesContainers) and concatenates them in document order —
// covers a single-vsys root view, multi-vsys, and Panorama pre/post-rulebase
// shapes uniformly, without special-casing any of them.
//
// `containersFound` lets the caller (ssh.js's getRules()) distinguish "the
// rulebase container was never found in the tree at all" (a structural
// failure — wrong firmware shape, or a truncated/corrupted parse) from "a
// container WAS found and it genuinely has zero rules in it" (an honest
// empty result) — collapsing both into a bare `rules.length === 0` check
// would hide the first case, which is a retrieval failure that must THROW,
// not the honest [] case.
//
// Never throws: parseBraceConfig() already degrades to {} on failure, which
// yields zero containers found — an honest { rules: [], containersFound: 0 },
// not a crash.
function parseSecurityRules(text) {
  const tree = parseBraceConfig(text);
  const containers = findSecurityRulesContainers(tree, 0);

  const rules = [];
  for (const container of containers) {
    for (const name of Object.keys(container)) {
      rules.push(ruleFromBraceEntry(name, container[name], rules.length + 1));
    }
  }
  // `tree` is returned alongside rules/containersFound so callers that need
  // the parsed brace tree for a SECOND purpose (ssh.js's hit-count
  // enrichment needs it to resolve vsys names) can reuse it instead of
  // re-tokenizing/re-parsing the same config text a second time.
  return { rules, containersFound: containers.length, tree };
}

// Builds the `parsed` half of getConfig()'s { raw, parsed }.
//
// SECURITY: `redactedText` must ALREADY be redacted (ssh.js's getConfig()
// redacts before calling this) — `tree` is included in full for the Phase 6
// dot-path predicate engine to interrogate paths this summary doesn't
// pre-extract, and device_configs.config_parsed is GRANT SELECT'd to
// claude_readonly/nocvault_readonly, the same roles device_credentials is
// barred from. Building `tree` from redacted text is what makes including it
// safe; rule parsing (parseSecurityRules, above) still uses the UNREDACTED
// text, which is fine — rules never carry secrets.
//
// Must NEVER be an empty object on a successful pull — lib/engines/
// applicability.js's hasUsableConfig() treats {} exactly like null and
// downgrades every CVE to 'unknown'.
function parseConfig(redactedText, systemInfoOutput) {
  const info = systemInfoOutput && typeof systemInfoOutput === 'object' ? systemInfoOutput : {};
  const infoFields = info.fields && typeof info.fields === 'object' ? info.fields : {};
  const tree = parseBraceConfig(redactedText);

  return {
    collected_via: 'ssh',
    source_command: 'show (brace format)',
    hostname: info.hostname || infoFields.hostname || null,
    model: info.model || infoFields.model || null,
    sw_version: info.version_string || infoFields['sw-version'] || null,
    system_info: infoFields,
    security_rules_count: findSecurityRulesContainers(tree, 0).reduce(
      (sum, c) => sum + Object.keys(c).length,
      0
    ),
    tree,
  };
}

// ---------------------------------------------------------------------------
// Network object catalog (SSH/brace-tree transport) — FirewallAdapter's
// OPTIONAL getObjects(). See lib/adapters/interface.js for the exact contract
// and CLAUDE.md's "Network Object Catalog" section. Direct sibling of
// parser.js's extractObjects() (XML/API transport) — SAME four object-
// container key names, SAME bounded-deep-search-collecting-every-container
// approach as findSecurityRulesContainers() above, but a DIFFERENT container
// shape: the brace tree has no `.entry` array wrapper — each object's NAME is
// the block key itself, exactly like `rulebase.security.rules`'s
// `{ ruleName: attrs }` shape (see ruleFromBraceEntry() above). That symmetry
// is intentional, not coincidental: both are PAN-OS "named entry" schema
// nodes, and parseBraceBlock() renders every one of them identically.
//
// ssh.js's getObjects() calls this on configParsed.tree (read back via
// getLatestConfigParsed(), not a new live pull — see ssh.js's own comment),
// never on raw CLI text directly.
//
// Doc-derived: no live PAN-OS device with object catalog data has verified
// these exact field names yet (see CLAUDE.md's Live Validation Status — the
// brace grammar itself IS confirmed live for security rules, but address/
// service object leaf field names specifically have not been).

const OBJECT_CONTAINER_KEYS = ['address', 'address-group', 'service', 'service-group'];
const MAX_OBJECT_SEARCH_DEPTH = 10;

// Depth-first search collecting every plain-object node found under any of
// the four object-container key names, anywhere in the tree. `out` is
// mutated: { address: [node, ...], 'address-group': [...], ... }. Mirrors
// findSecurityRulesContainers()'s "search deep, collect every container, not
// just the first" approach above. Never throws.
function collectObjectContainers(node, out, depth) {
  if (depth > MAX_OBJECT_SEARCH_DEPTH || !node || typeof node !== 'object' || Array.isArray(node)) {
    return;
  }

  for (const [key, value] of Object.entries(node)) {
    if (OBJECT_CONTAINER_KEYS.includes(key) && value && typeof value === 'object' && !Array.isArray(value)) {
      if (!out[key]) out[key] = [];
      out[key].push(value);
    }
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      collectObjectContainers(value, out, depth + 1);
    }
  }
}

// One container is `{ objName: attrs, objName2: attrs2, ... }` — the block
// key IS the object name (see header comment). PAN-OS address leaf fields are
// mutually exclusive: ip-netmask | ip-range | ip-wildcard | fqdn, each a bare
// scalar value in brace format (asScalar() returns null for anything else,
// e.g. a nested block, so a malformed entry degrades to value: null rather
// than throwing).
function extractAddressEntriesFromBrace(containers) {
  const out = [];
  for (const container of containers) {
    for (const name of Object.keys(container)) {
      const a = container[name];
      const attrs = a && typeof a === 'object' ? a : {};
      let type = null;
      let value = null;
      if (asScalar(attrs['ip-netmask']) !== null) {
        type = 'ip-netmask';
        value = asScalar(attrs['ip-netmask']);
      } else if (asScalar(attrs['ip-range']) !== null) {
        type = 'ip-range';
        value = asScalar(attrs['ip-range']);
      } else if (asScalar(attrs['ip-wildcard']) !== null) {
        type = 'ip-wildcard';
        value = asScalar(attrs['ip-wildcard']);
      } else if (asScalar(attrs.fqdn) !== null) {
        type = 'fqdn';
        value = asScalar(attrs.fqdn);
      }
      out.push({ name, type, value });
    }
  }
  return out;
}

// `{ grpName: { static: [ 'obj1', 'obj2' ] } }` for a static group (a brace
// `[ ... ]` list parses directly to a string array via asArray() — no
// `.member` wrapper, unlike the XML/API transport's memberStrings()) or
// `{ grpName: { dynamic: { filter: '...' } } }` for a dynamic (filter-based)
// one. Dynamic groups have no fixed member list — rendered as members: [],
// same as the XML/API transport, not an attempt to resolve the filter.
function extractAddressGroupEntriesFromBrace(containers) {
  const out = [];
  for (const container of containers) {
    for (const name of Object.keys(container)) {
      const a = container[name];
      const attrs = a && typeof a === 'object' ? a : {};
      const members = attrs.static !== undefined ? asArray(attrs.static) : [];
      out.push({ name, members });
    }
  }
  return out;
}

// `{ svcName: { protocol: { tcp: { port: '443' } } } }` (or udp). Same
// derivation as the XML/API transport's extractServiceEntries() — "tcp/443".
function extractServiceEntriesFromBrace(containers) {
  const out = [];
  for (const container of containers) {
    for (const name of Object.keys(container)) {
      const a = container[name];
      const attrs = a && typeof a === 'object' ? a : {};
      const protocol = attrs.protocol && typeof attrs.protocol === 'object' ? attrs.protocol : {};
      let value = null;
      if (protocol.tcp && typeof protocol.tcp === 'object') {
        const port = asScalar(protocol.tcp.port);
        if (port) value = `tcp/${port}`;
      } else if (protocol.udp && typeof protocol.udp === 'object') {
        const port = asScalar(protocol.udp.port);
        if (port) value = `udp/${port}`;
      }
      out.push({ name, value });
    }
  }
  return out;
}

// `{ sgName: { members: [ 'svc1', 'svc2' ] } }`.
function extractServiceGroupEntriesFromBrace(containers) {
  const out = [];
  for (const container of containers) {
    for (const name of Object.keys(container)) {
      const a = container[name];
      const attrs = a && typeof a === 'object' ? a : {};
      const members = attrs.members !== undefined ? asArray(attrs.members) : [];
      out.push({ name, members });
    }
  }
  return out;
}

// → { addresses, addressGroups, services, serviceGroups } — see
// lib/adapters/interface.js for the exact contract. `tree` is
// configParsed.tree (a plain nested object — see header comment), NOT raw CLI
// text. Never throws: an unreadable/missing tree yields all-empty arrays, and
// each of the four extraction passes is independently guarded so one
// category's malformed data can't lose the other three.
function extractObjects(tree) {
  const result = { addresses: [], addressGroups: [], services: [], serviceGroups: [] };
  if (!tree || typeof tree !== 'object') return result;

  const containers = {};
  try {
    collectObjectContainers(tree, containers, 0);
  } catch (err) {
    console.warn(`[PaloAlto SSH parser] extractObjects: container search failed: ${err.message}`);
    return result;
  }

  try {
    result.addresses = extractAddressEntriesFromBrace(containers.address || []);
  } catch (err) {
    console.warn(`[PaloAlto SSH parser] extractObjects: address extraction failed: ${err.message}`);
  }
  try {
    result.addressGroups = extractAddressGroupEntriesFromBrace(containers['address-group'] || []);
  } catch (err) {
    console.warn(`[PaloAlto SSH parser] extractObjects: address-group extraction failed: ${err.message}`);
  }
  try {
    result.services = extractServiceEntriesFromBrace(containers.service || []);
  } catch (err) {
    console.warn(`[PaloAlto SSH parser] extractObjects: service extraction failed: ${err.message}`);
  }
  try {
    result.serviceGroups = extractServiceGroupEntriesFromBrace(containers['service-group'] || []);
  } catch (err) {
    console.warn(`[PaloAlto SSH parser] extractObjects: service-group extraction failed: ${err.message}`);
  }

  return result;
}

module.exports = {
  parseSystemInfoOutput,
  parseSecurityRules,
  resolveVsysNames,
  parseRuleHitCountOutput,
  parseConfig,
  redactConfig,
  looksLikeCliError,
  looksLikePanosConfig,
  extractObjects,
  // exported for testing / reuse, not part of the documented contract
  parseSystemInfoLines,
  redactLine,
  mapAction,
  tokenizeBraceConfig,
  parseBraceConfig,
  findSecurityRulesContainers,
};
