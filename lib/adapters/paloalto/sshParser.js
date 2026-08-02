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

// ⛔ FIXED (2026-07-20, found live in production on device "IDC FW" — see
// CLAUDE.md's Config Change Tracking section for the full incident writeup).
//
// Root cause: this function scans EVERY whitespace-delimited token on a line
// against SECRET_TOKENS — including a keyword that merely appears INSIDE a
// quoted free-text VALUE, e.g. a legitimate, human-written address-object
// description that happens to contain the word "Password"
// (`description "Manage Change Password <secret text>";`). Redacting that
// is CORRECT and intentional — CLAUDE.md's own fail-closed posture says
// over-redacting a description is better than missing a real secret, and
// this fix does not weaken that. The bug was in HOW it redacted: the old
// replacement — `line.slice(0, endOfToken) + ' ' + REDACTED` — discarded
// everything after the matched word to the end of the line, INCLUDING the
// value's closing `"` and trailing `;`. Because tokenizeBraceConfig() (below)
// tracks quote state character-by-character and does not stop at a newline
// while inside an open `"..."`, an unterminated opening quote does not stop
// parsing there — it keeps consuming every following character (other
// objects' real `{`/`}`/`;` included) as ONE giant string token, until the
// NEXT `"` anywhere later in the file happens to close it. That silently
// merged dozens of unrelated, subsequent address objects into one corrupted
// ~13,000-character key, which is what CLAUDE.md's incident writeup and
// config_diffs.change_summary showed.
//
// Fix: BOTH properties — secret hidden, structure preserved — hold at once,
// by first locating every quoted span on the line (findQuotedSpans, below),
// then branching on where the matched secret-shaped token actually sits:
//   - Token sits INSIDE an open quoted span (a free-text value happens to
//     contain a secret-shaped word): redact the WHOLE quoted value's content
//     — not just from the matched word onward — but keep the opening AND
//     closing quote characters, and everything after the closing quote
//     (e.g. a trailing ';'), exactly as they were. `key "<redacted>";`.
//   - Token sits OUTSIDE any quoted span (it IS the real leaf KEY): redact
//     only its VALUE (redactValuePreservingStructure, below) — a quoted
//     value keeps its surrounding quotes and any trailing punctuation, a
//     bare value keeps a trailing ';' if the line had one.
// Either way, nothing structural is ever swallowed, so the tokenizer's
// quote-tracking can never desync.
//
// Fails CLOSED throughout: any unexpected error still redacts the WHOLE line
// rather than risking a secret passing through.
function redactLine(line) {
  try {
    if (typeof line !== 'string' || line === '') return line;
    const quotedSpans = findQuotedSpans(line);
    const tokenRegex = /\S+/g;
    let match;
    while ((match = tokenRegex.exec(line)) !== null) {
      // Tolerate a trailing ';' (brace-format lines: `phash $1$abc;`) and quotes.
      const token = match[0].toLowerCase().replace(/[;"']+$/, '').replace(/^["']+/, '');
      if (!SECRET_TOKENS.has(token)) continue;

      // Does this match fall inside (or start exactly at the opening quote
      // of) an open quoted span? `>=` on span.start deliberately covers the
      // no-space case where the token itself begins with the quote char
      // (e.g. `"Password ...` as the very first word of a quoted value).
      const enclosingSpan = quotedSpans.find(
        (span) => match.index >= span.start && match.index < span.end
      );

      if (enclosingSpan) {
        const prefix = line.slice(0, enclosingSpan.start + 1); // up to & including opening "
        if (enclosingSpan.terminated) {
          const suffix = line.slice(enclosingSpan.end); // closing " onward, untouched
          return `${prefix}${REDACTED}${suffix}`;
        }
        // No closing quote found on this line (malformed/truncated input) —
        // fail CLOSED: nothing to preserve past an unterminated value.
        return `${prefix}${REDACTED}`;
      }

      const endOfToken = match.index + match[0].length;
      const rest = line.slice(endOfToken);
      // The keyword is the last token on the line (e.g. a brace-format section
      // header `pre-shared-key {`) — there is no value here to redact. Keep going:
      // a later token on the same line may still be a real secret leaf.
      if (rest.trim() === '' || /^\s*\{\s*$/.test(rest)) continue;

      return `${line.slice(0, endOfToken)} ${redactValuePreservingStructure(rest)}`;
    }
    return line;
  } catch (_err) {
    return REDACTED;
  }
}

// Finds every quoted string span on one line, mirroring tokenizeBraceConfig()'s
// own escape handling (`\"` does not end the string) so redactLine's notion of
// "inside a quote" always agrees with what the real tokenizer will see.
// Returns [{ start, end, terminated }], where `start`/`end` are the indices of
// the opening/closing '"' characters. `terminated: false` means no closing
// quote was found on this line (end === line.length in that case).
function findQuotedSpans(line) {
  const spans = [];
  let i = 0;
  while (i < line.length) {
    if (line[i] !== '"') {
      i += 1;
      continue;
    }
    const start = i;
    let j = i + 1;
    while (j < line.length && line[j] !== '"') {
      j += line[j] === '\\' && j + 1 < line.length ? 2 : 1;
    }
    const terminated = j < line.length && line[j] === '"';
    spans.push({ start, end: terminated ? j : line.length, terminated });
    i = terminated ? j + 1 : line.length;
  }
  return spans;
}

// Redacts a statement's VALUE portion (everything after the leaf key token,
// whitespace not yet trimmed) while preserving the surrounding structure the
// brace tokenizer depends on: a quoted value's closing '"' and any trailing
// ';' are always kept intact, so an unterminated quote can never leak into
// the output and desync tokenizeBraceConfig()'s character-by-character
// quote-tracking (see redactLine's header comment for the incident this
// fixes). Only the secret CONTENT is ever replaced.
function redactValuePreservingStructure(rest) {
  const leadingWs = rest.match(/^\s*/)[0];
  const afterWs = rest.slice(leadingWs.length);

  if (afterWs[0] === '"') {
    // Quoted value: find its matching closing quote (a '"' not preceded by a
    // backslash — mirrors tokenizeBraceConfig()'s own escape handling) and
    // keep everything from it onward (the quote itself, plus any trailing
    // ';') exactly as-is.
    const closeMatch = /^"(?:[^"\\]|\\.)*"/.exec(afterWs);
    if (closeMatch) {
      const suffix = afterWs.slice(closeMatch[0].length); // e.g. ';'
      return `"${REDACTED}"${suffix}`;
    }
    // No closing quote found on this line (a genuinely multi-line quoted
    // value, or malformed/truncated input) — fail CLOSED exactly like the
    // original behavior: redact from here to end of line rather than guess
    // at where the value ends.
    return REDACTED;
  }

  // Bare (unquoted) value — preserve a trailing ';' if the line had one.
  return /;\s*$/.test(afterWs) ? `${REDACTED};` : REDACTED;
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

  // Check `rulebase` (bare single-vsys/shared shape) AND Panorama's
  // `pre-rulebase`/`post-rulebase` keys — all three wrap `security { rules { ... } }`
  // identically, they just differ in what wraps the ruleset itself.
  for (const rulebaseKey of ['rulebase', 'pre-rulebase', 'post-rulebase']) {
    const rulebase = node[rulebaseKey];
    if (rulebase && typeof rulebase === 'object' && !Array.isArray(rulebase)) {
      const security = rulebase.security;
      if (security && typeof security === 'object' && !Array.isArray(security)) {
        const rules = security.rules;
        if (rules && typeof rules === 'object' && !Array.isArray(rules)) {
          results.push(rules);
        }
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

// ---------------------------------------------------------------------------
// Effective/running security policy — `show running security-policy`
// ---------------------------------------------------------------------------
//
// A COMPLETELY DIFFERENT command and output format from the brace-format
// config dump parsed above (parseSecurityRules()) — this is PAN-OS's
// operational-mode view of the ACTUAL ENFORCED policy: local rules AND
// Panorama pre-rulebase/post-rulebase merged together. Added 2026-07-23 for
// a real, confirmed live case: a Panorama-managed device (PA-3410, PAN-OS
// 11.1.13-h5) whose brace-format config dump contained NEITHER "rulebase"
// NOR "pre-rulebase"/"post-rulebase" anywhere at all — because on that
// device every security rule is Panorama-pushed, and Panorama-pushed rules
// simply never appear in the local config tree's rulebase.security.rules
// path, only in this merged effective view. ssh.js's getRules() tries the
// normal brace-tree path FIRST and only falls back to this command when
// that path finds zero containers — see that file for the full fallback
// logic and why this command needs no `configure`/set-format step first
// (it's a plain operational-mode command, confirmed live).
//
// Verified against REAL, complete live output (not a doc-derived guess) —
// 33 real rules from the confirmed device, including the two PAN-OS
// built-in default rules (intrazone-default/interzone-default). Grammar,
// confirmed directly from that output:
//
//   "RuleName; index: N" {
//           from Zone;                       OR  from [ Zone1 Zone2 ];
//           source any;                      OR  source 10.1.1.1;
//                                             OR  source 10.1.1.0/24;
//                                             OR  source 10.1.1.1-10.1.1.9;
//                                             OR  source [ ...any mix of the above... ];
//           source-region none;
//           to ...                            (same shapes as `from`)
//           destination ...                   (same shapes as `source`)
//           destination-region none;
//           user any;
//           source-device any;
//           destination-device any;
//           category any;                    OR category Name;  OR category [ Name1 Name2 ];
//           application/service 0:app/proto/srcport/dstport;
//                                             OR application/service [ 0:.../.../.../... 1:.../.../.../... ];
//           action allow;                    (also: deny, drop)
//           icmp-unreachable: no             <- NOTE: colon, and NO trailing semicolon (unlike every other line — a real, confirmed quirk, not a typo)
//           terminal yes;                    (also: no)
//           type intrazone;                  <- OPTIONAL, only seen on the 2 built-in default rules
//   }
//
// KNOWN, DOCUMENTED LIMITATIONS of this collection path (real gaps, not
// bugs — there is simply no signal for these in this command's output):
//   - enabled is ALWAYS true for every rule this returns. A rule disabled
//     in Panorama or locally is, BY DEFINITION, not part of the ENFORCED
//     policy, so it never appears in this output at all — there is no way
//     to distinguish "doesn't exist" from "exists but disabled" here.
//   - log_enabled defaults to true (PAN-OS's own platform default) — this
//     command carries no logging-state field at all, unlike the brace-tree
//     format's `log-end` attribute.
//   - hit_count is always 0 — `show rule-hit-count`'s own vsys-name
//     resolution needs the brace-tree `configTree`, which this fallback
//     path never builds. Same accepted class of gap as Fortinet-over-SSH's
//     documented zero-hit-count limitation (CLAUDE.md "Known Limitations").
//   - nat_enabled, schedule, expiry_date, comment are always
//     false/null/null/null — NAT is a separate rulebase entirely, and the
//     others simply have no field in this output.
// These mean Phase 5's `log_disabled`/`unused`/`expiring_soon` findings
// will never fire for a device collected via this fallback path — an
// accepted tradeoff: the real ruleset with reduced finding coverage beats
// no ruleset at all, which is what happened before this fallback existed.

const EFFECTIVE_RULE_HEADER_RE = /^"(.+); index: (\d+)"\s*\{$/;
// Matches "key value;" OR "key: value" (no trailing `;`) — both shapes are
// confirmed present in real output (every field except icmp-unreachable
// uses the former; icmp-unreachable alone uses the latter).
const EFFECTIVE_ATTR_RE = /^([A-Za-z0-9_./-]+):?\s+(.*?);?$/;

// Cheap "is this the right command's output at all" gate — mirrors
// looksLikePanosConfig()'s role for the brace-tree format. No anchors (a
// substring search, not a whole-line match) since this checks the whole
// multi-line blob, not one line at a time.
function looksLikeEffectiveSecurityPolicy(text) {
  return typeof text === 'string' && /"\s*[^"]+;\s*index:\s*\d+\s*"\s*\{/.test(text);
}

// "Zone" -> ['Zone']; "[ Zone1 Zone2 ]" -> ['Zone1','Zone2']; "" -> [].
// Tolerates both "[ X Y ]" (space after `[`, seen on zone/address lists) and
// "[X Y" (no space, seen on application/service lists) — both confirmed in
// real output.
function parseEffectiveList(raw) {
  if (typeof raw !== 'string') return [];
  const trimmed = raw.trim();
  if (trimmed === '') return [];
  const inner = trimmed.startsWith('[') && trimmed.endsWith(']') ? trimmed.slice(1, -1).trim() : trimmed;
  if (inner === '') return [];
  return inner.split(/\s+/).filter(Boolean);
}

// "0:appname/proto/srcport/dstport" -> { app, proto, srcPort, dstPort }.
// The leading "N:" is a display index PAN-OS assigns per application/service
// entry, not meaningful data — discarded.
function parseAppServiceToken(token) {
  const colonIdx = token.indexOf(':');
  const rest = colonIdx === -1 ? token : token.slice(colonIdx + 1);
  const parts = rest.split('/');
  return { app: parts[0] || null, proto: parts[1] || null, dstPort: parts[3] || null };
}

function effectivePolicyRuleToNormalizedRule(rule) {
  const a = rule.attrs;

  const applications = [];
  const services = [];
  for (const token of parseEffectiveList(a['application/service'] || '')) {
    const { app, proto, dstPort } = parseAppServiceToken(token);
    if (app && !applications.includes(app)) applications.push(app);
    const hasProto = proto && proto !== 'any';
    const hasPort = dstPort && dstPort !== 'any';
    const svc = hasProto && hasPort ? `${proto}/${dstPort}` : hasProto ? proto : 'any';
    if (!services.includes(svc)) services.push(svc);
  }

  return {
    rule_name: rule.name,
    rule_id_vendor: rule.name,
    sequence_number: rule.index,
    // See this section's own header comment: "enabled" can only ever be
    // true here — a disabled rule (Panorama or local) is not part of the
    // ENFORCED policy and therefore never appears in this output at all.
    enabled: true,
    action: mapAction(a.action),
    src_zones: parseEffectiveList(a.from),
    dst_zones: parseEffectiveList(a.to),
    src_addresses: parseEffectiveList(a.source),
    dst_addresses: parseEffectiveList(a.destination),
    services,
    applications,
    schedule: null,
    expiry_date: null,
    // No logging-state field exists in this output — PAN-OS's own platform
    // default (log-at-end enabled) is used rather than guessing "disabled".
    log_enabled: true,
    comment: null,
    hit_count: 0,
    raw_rule: a,
  };
}

// Parses `show running security-policy` output → NormalizedRule[] | null.
// Never throws. Returns null, NOT [], whenever zero complete rule blocks were
// parsed — including an empty/non-string input — mirroring parser.js's own
// XML-transport sibling (`if (entries.length === 0) return null;`) exactly.
// This is not an honest empty-ruleset case: this section's own header comment
// documents that a real device's merged effective policy always includes
// PAN-OS's two built-in default rules (intrazone-default/interzone-default),
// confirmed directly against live output — so a genuine PAN-OS device can
// never actually have zero rules here. A caller only ever reaches this
// function after looksLikeEffectiveSecurityPolicy() already matched (a single
// substring check on the whole blob), which a truncated/malformed capture can
// satisfy — e.g. one header line surviving with its body cut off — while
// still yielding zero fully-parsed rule blocks. Treating that as null (a
// parse failure) rather than [] (an honest empty result) lets the caller
// (ssh.js's getRules()/_getEffectivePolicyRules(), which already branches on
// `!== null` to decide whether this fallback succeeded) correctly fall
// through to its existing throw instead of accepting a 0-rule result and
// silently wiping/replacing the device's real stored ruleset.
function parseEffectiveSecurityPolicy(text) {
  if (typeof text !== 'string' || text.length === 0) return null;

  const rules = [];
  let current = null; // { name, index, attrs: {} }

  for (const rawLine of text.replace(/\r/g, '').split('\n')) {
    const line = rawLine.trim();
    if (line === '') continue;

    const headerMatch = EFFECTIVE_RULE_HEADER_RE.exec(line);
    if (headerMatch) {
      current = { name: headerMatch[1], index: Number(headerMatch[2]), attrs: {} };
      continue;
    }

    if (line === '}') {
      if (current) {
        rules.push(effectivePolicyRuleToNormalizedRule(current));
        current = null;
      }
      continue;
    }

    if (!current) continue; // outside any rule block (e.g. the trailing "dynamic url: no" line)

    const attrMatch = EFFECTIVE_ATTR_RE.exec(line);
    if (attrMatch) current.attrs[attrMatch[1]] = attrMatch[2];
  }

  return rules.length > 0 ? rules : null;
}

// ---------------------------------------------------------------------------
// GlobalProtect current-user count — `show global-protect-gateway current-user`
// ---------------------------------------------------------------------------
//
// Backs PaloaltoSshAdapter.getVpnSessionSummary() (ssh.js) — see
// lib/adapters/paloalto/index.js's identical-named method for the FULL
// scope-decision rationale (GlobalProtect vs. IPsec site-to-site tunnels,
// why only GlobalProtect feeds active_session_count, and why the
// Panorama-managed-device gap this file documents at length for getRules()
// does NOT apply to this live operational-state query) — not re-quoted here
// to avoid the two copies drifting out of step, same convention this file's
// SNMP monitoring comment block above already uses.
//
// CLI output shape, DOC-DERIVED and NOT LIVE-VERIFIED (unlike the XML/API
// transport's sibling, which IS confirmed against Palo Alto's own published
// API docs — see index.js's citation). Every source consulted (Palo Alto's
// own knowledgebase articles on GlobalProtect gateway CLI commands,
// cross-checked 2026-07-30) consistently shows a per-gateway header line of
// the exact form:
//   GlobalProtect Gateway: <gateway-name> (<N> users)
// followed by a per-user block (Tunnel Name / Domain-User Name / Computer /
// Client / ... — not this codebase's concern here; only the header counts
// matter). A device with more than one configured gateway is expected to
// repeat this header once per gateway, so every header found is summed
// rather than assuming exactly one.
//
// ⚠️ KNOWN, ACCEPTED GAP: no source consulted shows what this command prints
// on a device with NO GlobalProtect gateway configured at all (as distinct
// from a configured gateway with zero current users, which the confirmed
// "(0 users)" form above already handles correctly — that case sums to a
// real, legitimate 0). This function stays pure and returns null for that
// "no header at all" case (mirroring Fortinet's cliParser.countActiveVpnSessions()'s
// null-on-unrecognized-format contract). ⛔ The CALLER's handling of null
// CHANGED 2026-07-31: ssh.js's getVpnSessionSummary() used to THROW on null,
// which made the engine-worker log a WARN on EVERY poll for any PAN-OS device
// with no GlobalProtect gateway (real report: "TFM-RN"). Since a configured
// gateway ALWAYS prints a header, a total absence means the device simply
// doesn't run GlobalProtect — a normal state, not an error — so the caller now
// returns a clean active_session_count 0 (`raw.no_globalprotect_gateway=true`)
// instead of throwing. `looksLikeCliError()` still runs first, so a genuinely
// rejected command is still surfaced.
const GLOBALPROTECT_GATEWAY_HEADER_RE = /GlobalProtect Gateway:\s*\S+\s*\((\d+)\s*users?\)/gi;

// → total active GlobalProtect user count summed across every gateway
// header found, or null when NO header line matches at all (see the ⚠️ note
// above — null is reserved for "no header line found", never returned for a
// confirmed "(0 users)" match, which legitimately sums to 0).
function countActiveGlobalProtectUsers(text) {
  if (typeof text !== 'string' || text.length === 0) return null;
  // Fresh RegExp per call (not reusing the module-level `g`-flagged literal
  // directly) — a shared stateful `lastIndex` across calls is a classic
  // footgun for a `g`-flagged regex reused via exec() in a loop.
  const re = new RegExp(GLOBALPROTECT_GATEWAY_HEADER_RE.source, GLOBALPROTECT_GATEWAY_HEADER_RE.flags);
  let total = 0;
  let matched = false;
  let match;
  while ((match = re.exec(text)) !== null) {
    const n = Number(match[1]);
    if (Number.isFinite(n)) {
      total += n;
      matched = true;
    }
  }
  return matched ? total : null;
}

// Per-user active-session DETAIL from `show global-protect-gateway
// current-user` (the same text countActiveGlobalProtectUsers() above counts).
// BEST-EFFORT and ADDITIVE: the count is the authoritative, already-shipped
// signal; this only enriches it with per-user rows for the vpn_active_sessions
// table (see lib/engines/vpnSessions.js). Returns [] on any doubt -- a wrong
// or empty parse here must NEVER affect the count, so ssh.js calls this in a
// try/catch and treats a throw/empty as "no detail available".
//
// Shape is DOC-DERIVED, NOT live-verified (same standing as
// countActiveGlobalProtectUsers()'s header format): after each
// `GlobalProtect Gateway: <name> (<N> users)` header, PAN-OS prints one
// blank-line-separated block per connected user, each a set of `Key : value`
// lines (Tunnel Name / Domain-User Name / Computer / Client / Virtual IP /
// Public IP / Login Time / Login Duration(sec) / ...). This splits sections by
// header, splits each section body on blank lines into per-user blocks, and
// maps recognized keys (normalized to lowercase-alphanumeric) into the
// vendor-agnostic session shape. The `[PaloAlto SSH Debug]` raw-output log in
// ssh.js is what a real device is validated against -- adjust the key mapping
// here once that output is seen.
const GP_GATEWAY_HEADER_SPLIT_RE = /GlobalProtect Gateway:\s*(\S+)\s*\(\d+\s*users?\)/gi;
const GP_FIELD_LINE_RE = /^\s*([A-Za-z][A-Za-z0-9 .()/_-]*?)\s*:\s*(.+?)\s*$/;

function parseGlobalProtectSessions(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const out = [];
  try {
    const re = new RegExp(GP_GATEWAY_HEADER_SPLIT_RE.source, GP_GATEWAY_HEADER_SPLIT_RE.flags);
    const headers = [];
    let m;
    while ((m = re.exec(text)) !== null) headers.push({ name: m[1], start: m.index, end: re.lastIndex });
    const sections =
      headers.length === 0
        ? [{ name: null, body: text }]
        : headers.map((h, i) => ({
            name: h.name,
            body: text.slice(h.end, i + 1 < headers.length ? headers[i + 1].start : text.length),
          }));

    for (const sec of sections) {
      for (const block of sec.body.split(/\n\s*\n/)) {
        const f = {};
        let any = false;
        for (const line of block.split('\n')) {
          const fm = GP_FIELD_LINE_RE.exec(line);
          if (!fm) continue;
          const key = fm[1].toLowerCase().replace(/[^a-z0-9]/g, '');
          const val = fm[2].trim();
          if (val) {
            f[key] = val;
            any = true;
          }
        }
        if (!any) continue;
        // Confirmed live (2026-07-31): this PAN-OS/mobile-client output has no
        // Windows domain, so `domainusername` carries a spurious leading `\`
        // (empty-domain DOMAIN\username convention) on every row while
        // `primaryusername` is always present and clean — prefer the clean
        // field first, same priority order as parser.js's XML/API sibling
        // normalizeGlobalProtectUsers(). `domainusername` stays as a fallback,
        // stripped of a leading empty-domain backslash, for a device where
        // primaryusername is genuinely absent.
        const username =
          f.primaryusername || f.username || (f.domainusername ? f.domainusername.replace(/^\\+/, '') : null) || null;
        // A block is only a user record if it carries a recognizable identity/
        // address field -- otherwise it's a header/footer/summary block, skip.
        if (!username && !f.virtualip && !f.computer) continue;
        // Confirmed live (2026-07-31): this output carries no elapsed-duration
        // field at all (no logindurationsec/loginduration/lifetime key ever
        // appears) — those three remain as a doc-derived fallback in case a
        // different PAN-OS/client build does print one. `requestlogin` DOES
        // carry a real embedded epoch-ms session-start timestamp, e.g.
        // "2026-07-31 19:41:49.407 (1785501709407), 49.230.71.40" — derive
        // elapsed seconds from that when no literal duration field is present.
        const durationRaw = f.logindurationsec || f.loginduration || f.lifetime;
        const duration = durationRaw != null ? parseInt(durationRaw, 10) : NaN;
        const epochMatch = typeof f.requestlogin === 'string' ? f.requestlogin.match(/\((\d{10,13})\)/) : null;
        const derivedDuration = epochMatch
          ? Math.max(
              0,
              Math.floor(Date.now() / 1000) - Math.floor(Number(epochMatch[1]) / (epochMatch[1].length > 10 ? 1000 : 1))
            )
          : NaN;
        // Skip an all-zeros/unspecified address (the IP family the client isn't
        // using) so a real address wins — same reasoning as parser.js's pickGpIp.
        const usableIp = (v) => (typeof v === 'string' && v && v !== '::' && v !== '0.0.0.0' ? v : null);
        out.push({
          username,
          tunnel_type: 'GlobalProtect',
          // Confirmed live (2026-07-31): the real field names are
          // `publicipconnected`/`clientip` (source) and `privateip` (assigned)
          // — not the doc-derived `publicip`/`clientsourceip`/`sourceip` /
          // `virtualip`/`assignip` guesses, which never occur in this
          // PAN-OS version's output. Those doc-derived names stay as
          // lower-priority fallbacks in case a different build uses them.
          source_ip:
            usableIp(f.publicipconnected) ||
            usableIp(f.clientip) ||
            usableIp(f.publicip) ||
            usableIp(f.clientsourceip) ||
            usableIp(f.sourceip) ||
            usableIp(f.publicipv6) ||
            null,
          assigned_ip: usableIp(f.privateip) || usableIp(f.virtualip) || usableIp(f.assignip) || usableIp(f.privateipv6) || null,
          login_time: f.logintime || null,
          duration_seconds: Number.isFinite(duration) ? duration : Number.isFinite(derivedDuration) ? derivedDuration : null,
          bytes_in: null,
          bytes_out: null,
          client: f.computer || f.client || null,
          gateway: sec.name || null,
          raw: f,
        });
      }
    }
  } catch (_err) {
    return [];
  }
  return out;
}

// IPSec site-to-site tunnels from `show vpn ipsec-sa` (SSH text). BEST-EFFORT
// and doc-derived (same standing as the GlobalProtect parsers above): the
// command prints a header then one row per active Phase-2 SA, each carrying a
// `Tunnel(Gateway)` token and a peer IP among tabular columns. This extracts
// the tunnel name (the `X` in `X(Y)`), gateway (`Y`), and peer IP per data row;
// an SA row existing at all means that tunnel is UP (this command only lists
// established SAs), so status is 'up'. Bytes/IKE-version aren't in this
// command's output (they'd need `show vpn flow`/`show vpn ike-sa`) -> null.
// Multiple SAs for one tunnel are de-duped by name+peer. Returns [] on any
// doubt; never throws. The `[PaloAlto SSH Debug]` raw-output log in ssh.js is
// what a real device is validated against.
const IPSEC_SA_TUNNEL_GW_RE = /(\S+)\(([^)]*)\)/;
const IPSEC_SA_PEER_IP_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;
const IPSEC_SA_SKIP_LINE_RE = /GwID|Peer-Address|Tunnel\(Gateway\)|Algorithm|SPI\(|life\(|^-+$|^=+$|^\s*total/i;

function parseIpsecTunnels(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  try {
    const out = [];
    for (const rawLine of text.split('\n')) {
      const line = rawLine.trimEnd();
      if (line.trim() === '' || IPSEC_SA_SKIP_LINE_RE.test(line)) continue;
      const tg = IPSEC_SA_TUNNEL_GW_RE.exec(line);
      const ip = IPSEC_SA_PEER_IP_RE.exec(line);
      const name = tg ? tg[1] : null;
      const gateway = tg ? tg[2] : null;
      const peer = ip ? ip[1] : null;
      if (!name && !peer) continue; // not a recognizable tunnel row
      out.push({
        name: name || peer,
        peer,
        status: 'up',
        ike_version: null,
        bytes_in: null,
        bytes_out: null,
        raw: { line: line.trim(), gateway },
      });
    }
    const seen = new Set();
    return out.filter((t) => {
      const k = `${t.name}|${t.peer}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  } catch (_err) {
    return [];
  }
}

// ── Topology parsers (added 2026-08-02, for lib/engines/topology.js) ────────
// Built directly against a real captured sample from a live device (HRIS,
// PAN-OS, this deployment) — `show interface all` / `show routing route` /
// `show running nat-policy` — per CLAUDE.md's "verify against live
// responses before writing any parser" rule. Same defensive philosophy as
// every other parser in this file: a malformed/unrecognized line is
// skipped, never thrown.

const { parseCidrOrIp } = require('../../engines/cidrUtils');

// `show interface all` has TWO tables (physical, then logical) — this only
// cares about the logical table (it has the address/zone columns the
// physical table lacks). Deliberately does NOT try to detect the section
// boundary; instead every line is tested against the expected column
// shapes, and the physical table's rows are naturally rejected because
// their last token (a MAC address) never parses as a valid IPv4/CIDR.
//
// Column padding in the real captured output uses 2+ spaces between every
// field, so splitting on runs of 2+ spaces reliably separates columns even
// though the "zone" column is sometimes entirely empty (e.g. the bare
// "tunnel" interface, which has a forwarding of "N/A" and no zone at all —
// that row collapses to 6 tokens instead of 7, handled explicitly below).
function parseInterfacesOutput(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const out = [];
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    const tokens = line.split(/\s{2,}/).map((t) => t.trim()).filter(Boolean);
    if (tokens.length < 4) continue; // too short to be an address row at all

    let name;
    let zone;
    let address;
    if (tokens.length >= 7) {
      // name, id, vsys, zone, forwarding, tag, address
      [name, , , zone] = tokens;
      address = tokens[tokens.length - 1];
    } else if (tokens.length === 6) {
      // zone column empty: name, id, vsys, forwarding, tag, address
      [name] = tokens;
      zone = null;
      address = tokens[tokens.length - 1];
    } else {
      // Unrecognized shape (e.g. the physical-interfaces table) — only keep
      // it if the last token still happens to parse as a real address;
      // otherwise skip silently.
      [name] = tokens;
      zone = null;
      address = tokens[tokens.length - 1];
    }

    if (!name || address === 'N/A') continue;
    const cidr = parseCidrOrIp(address);
    if (cidr === null) continue; // not a real address row (e.g. a MAC-address line from the physical table)

    out.push({ name, ipAddress: address, zone: zone || null, vdom: null, enabled: true });
  }
  return out;
}

// `show routing route`'s "flags" column can hold MULTIPLE space-separated
// single/short codes (e.g. "A S", "A C", "A H") — a plain whitespace split
// misaligns every field after it. Instead, tokens are classified positionally:
// destination, nexthop, metric (must be numeric) are fixed; anything after
// that matching a short all-letters/~ flag code is consumed as a flag; the
// first token that ISN'T flag-shaped is the interface name (the trailing
// "next-AS" column is empty in every real sample captured and is ignored).
const ROUTE_FLAG_TOKEN_RE = /^[A-Za-z~][A-Za-z0-9]?$/;

function parseRoutingTableOutput(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const out = [];
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    const tokens = line.split(/\s+/);
    if (tokens.length < 3) continue;

    const destination = tokens[0];
    const nexthop = tokens[1];
    const metric = tokens[2];
    if (!/^\d+$/.test(metric)) continue; // not a data row (header/divider/blank)
    const destCidr = parseCidrOrIp(destination);
    if (destCidr === null) continue;

    let i = 3;
    const flags = [];
    while (i < tokens.length && ROUTE_FLAG_TOKEN_RE.test(tokens[i])) {
      flags.push(tokens[i]);
      i++;
    }
    const interfaceName = i < tokens.length ? tokens[i] : null;

    const isConnected = flags.includes('C');
    const isHost = flags.includes('H');
    if (isHost) continue; // a route to the interface's own /32 -- not a useful path decision, and would wrongly out-rank real routes as the most-specific match

    let protocol = 'other';
    if (isConnected) protocol = 'connected';
    else if (flags.includes('S')) protocol = 'static';
    else if (flags.some((f) => f[0] === 'O')) protocol = 'ospf';
    else if (flags.includes('B')) protocol = 'bgp';
    else if (flags.includes('R')) protocol = 'rip';

    out.push({
      destinationCidr: destination,
      nextHopIp: isConnected ? null : nexthop === '0.0.0.0' ? null : nexthop,
      interfaceName,
      protocol,
      metric: parseInt(metric, 10),
      vdom: null,
    });
  }
  return out;
}

// `show running nat-policy` — brace-delimited blocks, one per COMPILED
// translation direction (a bidirectional static NAT rule shows up as TWO
// blocks: one with `source <ip>`/translate-to "src: ..." for the outbound
// direction, one with `destination <ip>`/translate-to "dst: ..." for the
// return direction) — confirmed live, this is PAN-OS's own compiled-policy
// shape, not a simplification made here. Each block is treated as its own
// independent nat_rules row; the topology engine only needs "does this
// original src/dst match, and what does it translate to" per direction, it
// never needs to know two rows are a matched pair.
const NAT_BLOCK_RE = /"([^"]+)"\s*\{([^}]*)\}/g;

function parseNatPolicyOutput(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const out = [];
  let match;
  NAT_BLOCK_RE.lastIndex = 0;
  while ((match = NAT_BLOCK_RE.exec(text)) !== null) {
    const header = match[1];
    const body = match[2];

    const indexMatch = /index:\s*(\d+)/.exec(header);
    const sequenceNumber = indexMatch ? parseInt(indexMatch[1], 10) : null;

    const fields = {};
    for (const rawStatement of body.split(';')) {
      const statement = rawStatement.trim();
      if (!statement) continue;
      const spaceIdx = statement.indexOf(' ');
      if (spaceIdx === -1) continue;
      const key = statement.slice(0, spaceIdx).trim();
      const value = statement.slice(spaceIdx + 1).trim();
      fields[key] = value;
    }

    const source = fields['source'];
    const destination = fields['destination'];
    const translateTo = fields['translate-to'] ? fields['translate-to'].replace(/^"|"$/g, '') : null;

    if (!translateTo) continue; // no-translation / pass-through entries carry nothing useful for path simulation

    const srcTranslated = /src:\s*([\d.]+)/.exec(translateTo);
    const dstTranslated = /dst:\s*([\d.]+)/.exec(translateTo);

    if (srcTranslated) {
      out.push({
        sequenceNumber,
        enabled: true,
        natType: 'source',
        originalSrcAddresses: source ? [source] : null,
        originalDstAddresses: destination ? [destination] : null,
        originalServices: fields['service'] ? [fields['service']] : null,
        translatedSrcAddresses: [srcTranslated[1]],
        translatedDstAddresses: null,
        translatedServices: null,
      });
    } else if (dstTranslated) {
      out.push({
        sequenceNumber,
        enabled: true,
        natType: 'destination',
        originalSrcAddresses: source ? [source] : null,
        originalDstAddresses: destination ? [destination] : null,
        originalServices: fields['service'] ? [fields['service']] : null,
        translatedSrcAddresses: null,
        translatedDstAddresses: [dstTranslated[1]],
        translatedServices: null,
      });
    }
  }
  return out;
}

module.exports = {
  parseSystemInfoOutput,
  parseSecurityRules,
  ruleFromBraceEntry,
  resolveVsysNames,
  parseRuleHitCountOutput,
  parseConfig,
  redactConfig,
  looksLikeCliError,
  looksLikePanosConfig,
  extractObjects,
  looksLikeEffectiveSecurityPolicy,
  parseEffectiveSecurityPolicy,
  countActiveGlobalProtectUsers,
  parseGlobalProtectSessions,
  parseIpsecTunnels,
  parseInterfacesOutput,
  parseRoutingTableOutput,
  parseNatPolicyOutput,
  // exported for testing / reuse, not part of the documented contract
  parseSystemInfoLines,
  redactLine,
  redactValuePreservingStructure,
  findQuotedSpans,
  mapAction,
  tokenizeBraceConfig,
  parseBraceConfig,
  findSecurityRulesContainers,
};
