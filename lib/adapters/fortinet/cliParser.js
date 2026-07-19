// lib/adapters/fortinet/cliParser.js
// Pure text-parsing functions for FortiOS CLI output. CommonJS ONLY — required by
// lib/adapters/fortinet/ssh.js, which is required (indirectly) by
// services/engine-worker.js (plain node, CommonJS).
//
// No I/O, no network, no DB — every function takes raw CLI text and returns plain
// data. Nothing here may EVER throw on malformed input (only ssh.js's network calls
// throw): a single unexpected line must never abort a whole ruleset. Unparseable
// lines are skipped, and structural functions return null to mean "I could not find
// this at all" — which callers MUST distinguish from an empty result. See
// policiesFromConfigText().
//
// ⚠️ Written WITHOUT a live FortiGate. FortiOS config syntax is stable and
// well-established, but per CLAUDE.md ("Documentation lies") ssh.js logs raw output
// under '[Fortinet Debug]' on first connect so these assumptions can be checked
// against real hardware.
//
// FortiOS config grammar this parses:
//
//   config firewall policy
//       edit 1
//           set name "allow-web"
//           set srcintf "port1" "port2"
//           set action accept
//           config sub-block
//               ...
//           end
//       next
//   end

'use strict';

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

// Splits the value part of a `set` line into tokens, honouring FortiOS's
// double-quoted values (`set srcaddr "web servers" "all"` → two tokens) and
// backslash escapes. An unterminated quote consumes to end-of-string rather than
// throwing — the multi-line case is handled by the redactor, and by the block
// parser simply ignoring continuation lines.
function tokenize(str) {
  const tokens = [];
  const s = String(str === null || str === undefined ? '' : str);
  let i = 0;

  while (i < s.length) {
    const ch = s[i];

    if (ch === ' ' || ch === '\t') {
      i += 1;
      continue;
    }

    if (ch === '"') {
      i += 1;
      let buf = '';
      while (i < s.length) {
        if (s[i] === '\\' && i + 1 < s.length) {
          buf += s[i + 1];
          i += 2;
          continue;
        }
        if (s[i] === '"') {
          i += 1;
          break;
        }
        buf += s[i];
        i += 1;
      }
      tokens.push(buf);
      continue;
    }

    let buf = '';
    while (i < s.length && s[i] !== ' ' && s[i] !== '\t') {
      buf += s[i];
      i += 1;
    }
    tokens.push(buf);
  }

  return tokens;
}

// Counts double quotes that are not backslash-escaped. An ODD count means the line
// opens a quoted value it does not close — i.e. a multi-line value follows.
function countUnescapedQuotes(s) {
  let count = 0;
  const str = String(s);
  for (let i = 0; i < str.length; i++) {
    if (str[i] === '"' && (i === 0 || str[i - 1] !== '\\')) count += 1;
  }
  return count;
}

// ---------------------------------------------------------------------------
// Config block tree
// ---------------------------------------------------------------------------

function newNode(id) {
  const node = { settings: {}, blocks: {}, entries: [] };
  if (id !== undefined) node.id = id;
  return node;
}

/**
 * Parses FortiOS config syntax into a tree.
 *
 * Node shape: { settings: {key: string[]}, blocks: {name: Node}, entries: Node[] }
 * (entry nodes additionally carry `id`, the `edit <id>` value).
 *
 * Fully defensive: unmatched `end`/`next`, unknown lines and multi-line value
 * continuations are ignored. Never throws.
 *
 * @param {string} text
 * @returns {object} root node
 */
function parseConfigTree(text) {
  const root = newNode();
  if (typeof text !== 'string' || text.length === 0) return root;

  // stack entries: { node, kind: 'root'|'config'|'entry' }
  const stack = [{ node: root, kind: 'root' }];
  const current = () => stack[stack.length - 1];

  // GENERIC multi-line-quote state — not scoped to secret keys. Any `set <key> "..."`
  // whose value opens a double quote it does not close on the same line (PEM keys,
  // multi-line banners/replacemsg bodies, comment fields) is followed by raw
  // continuation lines that are NOT directives. Without suspending structural
  // matching here, a continuation line that happens to trim to `end`/`next`, or
  // start with `config `/`edit `, is misread as real structure and desyncs the
  // stack. Fails CLOSED: closing is only recognized on a line containing an
  // unescaped quote; anything ambiguous stays "still inside".
  let inMultilineValue = false;

  for (const rawLine of text.replace(/\r/g, '').split('\n')) {
    try {
      if (inMultilineValue) {
        if (countUnescapedQuotes(rawLine) >= 1) inMultilineValue = false;
        continue;
      }

      const line = rawLine.trim();
      if (line === '') continue;

      let m;

      if ((m = line.match(/^config\s+(.+)$/i))) {
        const name = m[1].trim().replace(/"/g, '');
        const parent = current().node;
        if (!parent.blocks[name]) parent.blocks[name] = newNode();
        stack.push({ node: parent.blocks[name], kind: 'config' });
        continue;
      }

      if ((m = line.match(/^edit\s+(.+)$/i))) {
        const id = m[1].trim().replace(/^"|"$/g, '');
        // A missing `next` before the following `edit` would otherwise nest entries.
        if (current().kind === 'entry') stack.pop();
        const parent = current().node;
        const entry = newNode(id);
        parent.entries.push(entry);
        stack.push({ node: entry, kind: 'entry' });
        continue;
      }

      if (/^next$/i.test(line)) {
        if (current().kind === 'entry') stack.pop();
        continue;
      }

      if (/^end$/i.test(line)) {
        // An `end` closes a config block — and implicitly any entry left open by a
        // missing `next`.
        if (current().kind === 'entry') stack.pop();
        if (current().kind === 'config') stack.pop();
        continue;
      }

      if ((m = line.match(/^set\s+(\S+)\s*(.*)$/i))) {
        current().node.settings[m[1]] = tokenize(m[2]);
        if (countUnescapedQuotes(m[2]) % 2 === 1) inMultilineValue = true;
        continue;
      }

      // `unset x`, comment/banner lines, multi-line value continuations (base64 key
      // material etc.) and anything else: ignored on purpose.
    } catch (_err) {
      // A single bad line must never abort the parse.
    }
  }

  return root;
}

// Looks up a top-level block by its `config <path>` name, e.g. 'firewall policy'.
// Returns null when absent.
function findBlock(tree, path) {
  if (!tree || typeof tree !== 'object' || !tree.blocks) return null;
  const node = tree.blocks[path];
  return node || null;
}

/**
 * Depth-first search for EVERY block with this `config <path>` name, at any nesting
 * depth, in document order.
 *
 * Needed because nesting depends on VDOM mode: on a single-VDOM box
 * `show full-configuration` puts `config system global` at the top level, but on a
 * multi-VDOM box the same dump wraps sections in `config global ... end` and
 * `config vdom / edit <name> ... end`. A top-level-only lookup would return nothing
 * there and quietly produce an empty parsed config — which the Phase 6 applicability
 * engine reads as 'unknown' (conservative, but a total loss of signal).
 *
 * @returns {object[]} matching nodes (empty when none)
 */
function findBlocksDeep(tree, path) {
  const found = [];
  const visit = (node) => {
    if (!node || typeof node !== 'object') return;
    for (const [name, child] of Object.entries(node.blocks || {})) {
      if (name === path) found.push(child);
      visit(child);
    }
    for (const entry of node.entries || []) visit(entry);
  };
  visit(tree);
  return found;
}

// First deep match, or null.
function findBlockDeep(tree, path) {
  const all = findBlocksDeep(tree, path);
  return all.length > 0 ? all[0] : null;
}

// settings {key: string[]} → {key: string|string[]} (single-token values unwrapped).
function flattenSettings(node) {
  const out = {};
  if (!node || typeof node !== 'object' || !node.settings) return out;
  for (const [key, tokens] of Object.entries(node.settings)) {
    if (!Array.isArray(tokens)) continue;
    if (tokens.length === 0) out[key] = '';
    else if (tokens.length === 1) out[key] = tokens[0];
    else out[key] = tokens.slice();
  }
  return out;
}

// entries → [{name: <edit id>, ...settings}]. Mirrors the cmdb table-endpoint shape
// (array of objects keyed by `name`) so the SSH and REST adapters produce
// interchangeable `parsed` structures for the Phase 6 predicate engine's dot-paths.
function flattenEntries(node) {
  if (!node || !Array.isArray(node.entries)) return [];
  return node.entries.map((entry) => ({ name: entry.id, ...flattenSettings(entry) }));
}

// ---------------------------------------------------------------------------
// get system status
// ---------------------------------------------------------------------------

// Parses `get system status` output:
//   Version: FortiGate-100F v7.4.3,build2573,240201 (GA.F)
//   Serial-Number: FG100FTK00000000
//   Virtual domain configuration: multiple
//   Hostname: FW01
// → { version_string, build, model, serial, hostname, vdom_mode }
// Every field is null when not found. Never throws.
function parseSystemStatus(text) {
  const result = {
    version_string: null,
    build: null,
    model: null,
    serial: null,
    hostname: null,
    vdom_mode: null,
  };
  if (typeof text !== 'string' || text.length === 0) {
    console.warn('[Fortinet cliParser] parseSystemStatus: empty or non-string input');
    return result;
  }

  const clean = text.replace(/\r/g, '');

  const versionLine = clean.match(/^\s*Version:\s*(.+)$/im);
  if (versionLine) {
    const value = versionLine[1].trim();
    // "FortiGate-100F v7.4.3,build2573,240201 (GA.F)" — the version token starts at
    // the first `v<digit>`; everything before it is the model.
    const versionToken = value.match(/\bv\d[^\s]*/);
    if (versionToken) {
      result.version_string = versionToken[0];
      const model = value.slice(0, versionToken.index).trim();
      if (model) result.model = model;
    } else {
      // Unexpected shape — keep the whole line rather than losing it. parseVersion()
      // tolerates junk (returns [0]), and getVersion() rejects an unusable value.
      result.version_string = value;
    }
    const build = value.match(/build(\d+)/i);
    if (build) result.build = build[1];
  } else {
    console.warn(
      '[Fortinet cliParser] parseSystemStatus: no "Version:" line found — check the raw ' +
        '[Fortinet Debug] `get system status` output and adjust these patterns.'
    );
  }

  const serial = clean.match(/^\s*Serial-Number:\s*(\S+)/im);
  if (serial) result.serial = serial[1];

  const hostname = clean.match(/^\s*Hostname:\s*(\S+)/im);
  if (hostname) result.hostname = hostname[1];

  // 'disable' | 'enable' | 'multiple' | 'split-task' — DOC-DERIVED wording.
  const vdomMode = clean.match(/^\s*Virtual domain configuration:\s*(\S+)/im);
  if (vdomMode) {
    result.vdom_mode = vdomMode[1].toLowerCase();
  } else {
    console.warn(
      '[Fortinet cliParser] parseSystemStatus: no "Virtual domain configuration:" line found ' +
        '— assuming a single implicit VDOM. Check the raw [Fortinet Debug] `get system status` ' +
        'output and adjust this pattern if this device is actually multi-VDOM.'
    );
  }

  return result;
}

// True when `get system status` says multi-VDOM is active. Unknown/absent → false
// (i.e. behave exactly as the single-VDOM box this adapter has always assumed).
function isMultiVdom(statusInfo) {
  if (!statusInfo || !statusInfo.vdom_mode) return false;
  return statusInfo.vdom_mode !== 'disable';
}

// ---------------------------------------------------------------------------
// get vpn ssl monitor
// ---------------------------------------------------------------------------

// ⛔ Added 2026-07-19, doc-derived, NOT yet live-verified (see CLAUDE.md's
// Live Validation Status — a live Fortinet SSH device exists in this
// deployment; check [Fortinet Debug] output on first real poll and correct
// this if the real format differs). `get vpn ssl monitor` is FortiOS's
// documented operational command for listing active SSL-VPN sessions, under
// a "SSL VPN Login Users:" header, one numbered row per active session
// (index/user/auth-type/timeout/source-IP/...). Only the ROW COUNT is
// needed for this feature (a coarse "how many active sessions right now"
// signal, not full session detail), so this counts matching rows rather
// than parsing every field — a narrower, lower-risk surface than fully
// modeling the table.
//
// Returns null (NOT 0) when the "SSL VPN Login Users:" header itself isn't
// found at all — the caller MUST treat that as "unrecognized output, don't
// trust a count", never as "confirmed zero active sessions". Finding the
// header IS the signal that this is the right output shape; zero numbered
// rows after a found header is a legitimate, real zero.
function countActiveVpnSessions(text) {
  if (typeof text !== 'string') return null;
  const headerMatch = text.match(/SSL\s*VPN\s*Login\s*Users:/i);
  if (!headerMatch) return null;

  const afterHeader = text.slice(headerMatch.index + headerMatch[0].length);
  // Stop at the next "SSL VPN ...:" section header if present, so rows from
  // a DIFFERENT section (e.g. a raw "SSL VPN sessions:" detail table) aren't
  // double-counted alongside the login-users rows.
  const nextSectionMatch = afterHeader.match(/\n\s*SSL\s*VPN\s*[A-Za-z ]*:/i);
  const sectionText = nextSectionMatch ? afterHeader.slice(0, nextSectionMatch.index) : afterHeader;

  let count = 0;
  for (const line of sectionText.split('\n')) {
    // A numbered session row: starts with an integer index, followed by more
    // fields (username, etc.) — deliberately loose since the exact column
    // layout is unverified; a stray non-data line under the header (blank,
    // a re-printed column header) won't start with a bare integer.
    if (/^\s*\d+\s+\S+/.test(line)) count += 1;
  }
  return count;
}

// ---------------------------------------------------------------------------
// VDOM enumeration
// ---------------------------------------------------------------------------

// Parses `show system vdom` output → ['root', 'vd1', ...]. Returns null when the
// `config system vdom` block is absent entirely (command rejected / unsupported) —
// callers MUST read null as "could not enumerate", never as "no VDOMs".
function vdomNamesFromConfigText(text) {
  const block = findBlockDeep(parseConfigTree(text), 'system vdom');
  if (!block) return null;
  const names = block.entries
    .map((entry) => entry.id)
    .filter((name) => typeof name === 'string' && name.length > 0);
  return names.length > 0 ? names : null;
}

// FortiOS VDOM names are limited to letters/digits/underscore/hyphen. Anything else
// is either a parse artefact or an injection attempt against the `edit <name>` CLI
// command we build from this value — reject it rather than send it.
function isSafeVdomName(name) {
  return typeof name === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(name);
}

// ---------------------------------------------------------------------------
// show firewall policy
// ---------------------------------------------------------------------------

// FortiOS reference fields hold one-or-more object names. The REST cmdb API returns
// them as [{name: "..."}]; the CLI prints them as bare/quoted tokens. Mapping them to
// the REST shape lets the EXISTING parser.js parsePolicies() consume CLI output
// unchanged — one normalization path for both transports.
const LIST_FIELDS = new Set([
  'srcintf',
  'dstintf',
  'srcaddr',
  'dstaddr',
  'srcaddr6',
  'dstaddr6',
  'service',
  'application',
  'app-category',
  'app-group',
  'url-category',
  'groups',
  'users',
  'poolname',
  'fsso-groups',
  'internet-service-name',
  'internet-service-src-name',
  'internet-service-group',
  'custom-log-fields',
  'ntlm-enabled-browsers',
  'devices',
]);

// One `edit <id>` entry of `config firewall policy` → an object shaped like a REST
// cmdb policy result, so parser.parsePolicies() can normalize it.
function entryToPolicyObject(entry) {
  const policy = {};

  for (const [key, tokens] of Object.entries(entry.settings || {})) {
    if (!Array.isArray(tokens)) continue;
    if (LIST_FIELDS.has(key)) {
      policy[key] = tokens.map((token) => ({ name: token }));
    } else if (tokens.length === 0) {
      policy[key] = '';
    } else if (tokens.length === 1) {
      policy[key] = tokens[0];
    } else {
      policy[key] = tokens.join(' ');
    }
  }

  // `edit <id>` IS the policyid. The REST API returns it as a number.
  const idNumber = Number.parseInt(entry.id, 10);
  policy.policyid = Number.isNaN(idNumber) ? entry.id : idNumber;

  // `show` (unlike `show full-configuration`) omits every field left at its default.
  // FortiOS's default policy action is DENY, so an absent `set action` means deny —
  // NOT "unknown". Leaving it null would make the rule-analysis engine miss both
  // any/any findings and deny rules. DOC-DERIVED (FortiOS default), flagged in the
  // adapter report; `show full-configuration` prints it explicitly and can be used to
  // confirm on the first live box.
  if (policy.action === undefined) policy.action = 'deny';

  return policy;
}

/**
 * Extracts policies from `show firewall policy` (or `show full-configuration`) text.
 *
 * @param {string} text
 * @returns {object[]|null} REST-cmdb-shaped policy objects, or NULL when no
 *   `config firewall policy` block is present at all. NULL vs [] is load-bearing:
 *   [] means "the device really has zero policies", NULL means "this output is not a
 *   policy dump" (command rejected, truncated session, wrong VDOM context). The
 *   caller MUST NOT treat NULL as an empty ruleset — collectAndStore would DELETE the
 *   device's real rules and report success.
 */
function policiesFromConfigText(text) {
  if (typeof text !== 'string' || text.length === 0) return null;

  const block = findBlockDeep(parseConfigTree(text), 'firewall policy');
  if (!block) return null;

  const policies = [];
  for (const entry of block.entries) {
    try {
      policies.push(entryToPolicyObject(entry));
    } catch (err) {
      // One malformed policy block must not lose the other 400.
      console.warn(
        `[Fortinet cliParser] Failed to convert policy "edit ${entry && entry.id}" — skipping it: ${err.message}`
      );
    }
  }
  return policies;
}

// True when text plausibly IS a FortiOS configuration dump. Used to refuse storing a
// CLI rejection ("Unknown action 0", "command parse error") as if it were a config.
function looksLikeConfig(text) {
  if (typeof text !== 'string' || text.trim().length === 0) return false;
  return /^\s*config\s+\S+/im.test(text);
}

// FortiOS CLI rejections. Anchored to line starts so a `set comments "command parse
// error"` value can never trigger a false positive.
// `entry not found` added for VDOM-switch validation (`edit <vdom>` under
// `config vdom`) — the standard FortiOS rejection when the named table entry does
// not exist (e.g. a VDOM renamed/deleted between listing and pull). See ssh.js
// _getRulesMultiVdom()'s edit-output check.
const CLI_ERROR_REGEX =
  /(?:^|\n)\s*(?:Unknown action \d+|command parse error|Command fail\b|-1: Permission denied|node_check_object fail|The CLI command is not|Invalid VDOM name|entry not found)/i;

function looksLikeCliError(text) {
  if (typeof text !== 'string' || text.length === 0) return false;
  return CLI_ERROR_REGEX.test(text);
}

// ---------------------------------------------------------------------------
// Named object catalog (getObjects() — optional FirewallAdapter capability)
// ---------------------------------------------------------------------------
//
// Pure mapping only — no I/O. Feeds lib/engines/objectUsage.js's unused/duplicate
// object detection via ssh.js's getObjects() (see lib/adapters/interface.js's
// getObjects() contract comment for the exact return shape). Unlike
// policiesFromConfigText()'s consumer (getRules(), fail-loud), every caller of the
// functions below treats a failure/absence as "skip this piece, keep going" — see
// ssh.js's getObjects().
//
// DOC-DERIVED / not yet live-verified against a real FortiGate — same standing
// caveat as the rest of this file (CLAUDE.md "documentation lies, verify against
// live systems"). A live Fortinet SSH device exists in this deployment — check
// [Fortinet Debug] output on the first real getObjects() call and correct these
// field-name assumptions if the real config differs.

// Converts a dotted-decimal netmask ("255.255.255.0") into its CIDR prefix length
// (24), or null when the mask isn't a valid contiguous netmask (or isn't
// dotted-decimal at all). Never throws.
function ipMaskToPrefixLength(mask) {
  if (typeof mask !== 'string') return null;
  const parts = mask.trim().split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map((p) => Number(p));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;

  let bits = 0;
  let seenZero = false;
  for (const octet of octets) {
    for (let i = 7; i >= 0; i--) {
      const bit = (octet >> i) & 1;
      if (bit === 1) {
        if (seenZero) return null; // non-contiguous mask — not representable as a prefix length
        bits += 1;
      } else {
        seenZero = true;
      }
    }
  }
  return bits;
}

// Generic version of policiesFromConfigText() for any single config block (firewall
// address / addrgrp / service custom / service group, ...). Returns the block's
// entries via flattenEntries(), or NULL when no block of this name is present
// anywhere in the text at all (command rejected, wrong VDOM context, unexpected
// output) — distinct from an empty array, which means "the block exists and is
// genuinely empty". Unlike policiesFromConfigText(), NULL here is not fatal to a
// destructive DELETE+reinsert table — callers just log and skip.
function entriesFromConfigText(text, blockPath) {
  if (typeof text !== 'string' || text.length === 0) return null;
  const block = findBlockDeep(parseConfigTree(text), blockPath);
  if (!block) return null;
  return flattenEntries(block);
}

// Unwraps a flattenSettings() value that may be a bare string OR an array of tokens
// (flattenSettings only unwraps single-token values) into one string, taking the
// first token for genuinely-scalar fields (fqdn, start-ip, end-ip, protocol) that
// could still arrive as a 1-element array on some firmware.
function scalarToken(value) {
  if (Array.isArray(value)) return value.length > 0 ? String(value[0]) : null;
  if (value === undefined || value === null || value === '') return null;
  return String(value);
}

// `config firewall address` entry (from entriesFromConfigText()) → NamedAddress
// { name, type?, value }. See lib/adapters/interface.js's getObjects() contract.
// `type`/`subnet`/`start-ip`/`end-ip`/`fqdn` are the documented FortiOS CLI field
// names — not yet live-verified.
function addressEntryToNamedAddress(entry) {
  const name = entry && entry.name;
  if (!name) return null;

  const type = scalarToken(entry.type) ? scalarToken(entry.type).toLowerCase() : null;
  let value = null;

  if (type === 'fqdn') {
    value = scalarToken(entry.fqdn);
  } else if (type === 'iprange') {
    const start = scalarToken(entry['start-ip']);
    const end = scalarToken(entry['end-ip']);
    if (start && end) value = `${start}-${end}`;
  } else if (entry.subnet !== undefined) {
    // `set subnet <ip> <mask>` is two tokens, so flattenSettings() leaves it as a
    // 2-element array. A single-token/string subnet (already CIDR, or a firmware
    // variant that prints it differently) is passed through as-is rather than
    // guessed at.
    if (Array.isArray(entry.subnet) && entry.subnet.length === 2) {
      const [ip, mask] = entry.subnet;
      const prefix = ipMaskToPrefixLength(mask);
      value = prefix !== null ? `${ip}/${prefix}` : `${ip} ${mask}`;
    } else {
      value = scalarToken(entry.subnet);
    }
  } else if (!type && entry.fqdn) {
    // No explicit `set type` line (left at a non-default?) but a fqdn field is
    // present — defensive fallback rather than silently dropping the value.
    value = scalarToken(entry.fqdn);
  }

  return { name: String(name), type: type || undefined, value: value || null };
}

// `config firewall addrgrp` / `config firewall service group` entry → NamedGroup
// { name, members }. `set member "a" "b"` — flattenSettings() already turns a
// multi-token value into a plain string[], which IS the member NAME list directly
// (no `{name}` unwrapping needed here, unlike the REST cmdb shape).
function groupEntryToNamedGroup(entry) {
  const name = entry && entry.name;
  if (!name) return null;
  const raw = entry.member;
  const members = Array.isArray(raw) ? raw.map((m) => String(m)) : raw ? [String(raw)] : [];
  return { name: String(name), members };
}

// `config firewall service custom` entry → NamedService { name, value }. Derives
// e.g. "tcp/443" from protocol + tcp-portrange/udp-portrange when present; falls
// back to the bare protocol name (ICMP, ALL, ...) when neither portrange is set,
// or null when nothing usable is present.
function serviceEntryToNamedService(entry) {
  const name = entry && entry.name;
  if (!name) return null;

  const protocol = scalarToken(entry.protocol);
  const tcpRange = entry['tcp-portrange'];
  const udpRange = entry['udp-portrange'];
  const parts = [];
  if (tcpRange !== undefined) {
    const t = Array.isArray(tcpRange) ? tcpRange.join(',') : String(tcpRange);
    parts.push(`tcp/${t}`);
  }
  if (udpRange !== undefined) {
    const u = Array.isArray(udpRange) ? udpRange.join(',') : String(udpRange);
    parts.push(`udp/${u}`);
  }

  let value = null;
  if (parts.length > 0) value = parts.join(',');
  else if (protocol) value = protocol.toLowerCase();

  return { name: String(name), value };
}

// ---------------------------------------------------------------------------
// Secret redaction
// ---------------------------------------------------------------------------
//
// SECURITY — MANDATORY, see CLAUDE.md "Stored configs are REDACTED" and "Any NEW
// adapter that returns a raw text config MUST redact before returning it from
// getConfig()". A FortiOS `show full-configuration` carries admin password hashes
// (`set passwd ENC ...`), IPsec pre-shared keys (`set psksecret`), RADIUS/TACACS+
// secrets, SNMP communities and PEM private keys. That text is persisted verbatim
// into device_configs.config_raw, copied into config_backups.config_raw, served by
// the backup download route — and BOTH tables are GRANT SELECT'd to claude_readonly /
// nocvault_readonly, the exact roles CLAUDE.md bars from device_credentials. Nothing
// downstream redacts. It must happen here.
//
// Redaction is a fixed token, so it is deterministic — two pulls of an unchanged
// config redact identically and change detection is unaffected (configDiff.js diffs
// config_parsed, never config_raw).
//
// Fails CLOSED everywhere: an unexpected error redacts the whole line rather than
// risking a secret passing through.

const REDACTED = '<redacted>';

// Exact `set` keys whose value is a secret.
const SECRET_SET_KEYS = new Set([
  'passwd',
  'password',
  'psksecret',
  'psksecret-remote',
  'secret',
  'key',
  'private-key',
  'passphrase',
  'community',
  'auth-pwd',
  'priv-pwd',
  'authpasswd',
  'privpasswd',
  'ppk-secret',
  'keytab',
  'ldap-password',
  'group-password',
  'enc-password',
  'old-password',
  'new-password',
  'client-secret',
  'api-key',
  'auth-token',
  'token',
  'radius-server-secret',
  'sae-password',
  'wpa-key',
  'pre-shared-key',
  'preshared-key',
  'auth-password-l1',
  'auth-password-l2',
  'secondary-secret',
  'tertiary-secret',
]);

// Deliberately broad — over-redaction is harmless here (backups are for diff/audit,
// never restore — CLAUDE.md), under-redaction is a credential disclosure.
function isSecretKey(key) {
  const k = String(key || '').toLowerCase();
  if (SECRET_SET_KEYS.has(k)) return true;
  if (/pass(wd|word|phrase)/.test(k)) return true; // password2, ldap-password, ...
  if (/secret/.test(k)) return true; // psksecret, client-secret, ...
  if (/psk/.test(k)) return true;
  if (/keytab/.test(k)) return true;
  if (/-pwd$/.test(k)) return true; // auth-pwd, priv-pwd
  if (/^(.*-)?key\d*$/.test(k)) return true; // key, private-key, wpa-key, ssh-public-key1
  return false;
}

// Context-sensitive secrets: fields that are only secret inside a particular block.
// The SNMP v1/v2c community string is stored as `set name` inside
// `config system snmp community` — a plain key-name rule cannot catch it without
// redacting every `set name` in the entire config.
function isSecretInContext(key, blockPath) {
  const last = blockPath.length > 0 ? String(blockPath[blockPath.length - 1]).toLowerCase() : '';
  if (last === 'system snmp community' && String(key).toLowerCase() === 'name') return true;
  return false;
}

// Redacts one `set` line.
// → { line, opensMultiline, isSecret } — opensMultiline is true whenever THIS line's
//   value opened a quote it did not close (PEM private keys span many lines, but so
//   can a non-secret banner/replacemsg/comment body). isSecret says whether the value
//   itself was redacted. Both are reported unconditionally — not just for keys this
//   file recognizes as secret-shaped — so the caller can suspend structural matching
//   for ANY multi-line value while only suppressing output for the secret ones.
function redactSetLine(rawLine, blockPath) {
  const m = rawLine.match(/^(\s*set\s+(\S+)\s+)([\s\S]*)$/i);
  if (!m) return { line: rawLine, opensMultiline: false, isSecret: false };

  const prefix = m[1];
  const key = m[2];
  const value = m[3];

  // FortiOS marks EVERY encrypted secret with an `ENC` prefix, whatever the key is
  // called. This catch-all covers secret fields this file does not know about yet.
  const encMatch = value.match(/^(ENC\s+)([\s\S]*)$/i);
  if (encMatch) {
    return {
      line: `${prefix}ENC ${REDACTED}`,
      opensMultiline: countUnescapedQuotes(encMatch[2]) % 2 === 1,
      isSecret: true,
    };
  }

  if (isSecretKey(key) || isSecretInContext(key, blockPath)) {
    return {
      line: `${prefix}${REDACTED}`,
      opensMultiline: countUnescapedQuotes(value) % 2 === 1,
      isSecret: true,
    };
  }

  return {
    line: rawLine,
    opensMultiline: countUnescapedQuotes(value) % 2 === 1,
    isSecret: false,
  };
}

/**
 * Redacts every secret in a FortiOS config dump. MUST be applied before the text
 * leaves the adapter — nothing downstream redacts.
 *
 * Handles multi-line values: a PEM private key is printed as
 *     set private-key "-----BEGIN RSA PRIVATE KEY-----
 *     MIIEow...
 *     -----END RSA PRIVATE KEY-----
 *     "
 * A per-line redactor would blank the first line and leak every base64 line after it.
 * Continuation lines of a secret value are dropped entirely, up to the closing quote.
 * Continuation lines of a NON-secret multi-line value (banners, replacemsg bodies,
 * comment fields) pass through unredacted, but still suspend `config`/`end`/`set`
 * recognition — otherwise a continuation line that happens to read `end` could pop
 * `blockPath` early and desync which block a LATER line is considered "inside".
 *
 * @param {string} text
 * @returns {string}
 */
function redactConfig(text) {
  if (typeof text !== 'string' || text.length === 0) return '';

  const out = [];
  const blockPath = [];
  // GENERIC multi-line-quote state — NOT scoped to keys this file recognizes as
  // secret. `inMultiline` suspends ALL structural matching (config/end/set
  // recognition, blockPath push/pop) for ANY unterminated multi-line quoted `set`
  // value; `inMultilineSecret` additionally suppresses emitted lines (the original
  // secret-redaction behaviour).
  //
  // Why this matters: a non-secret multi-line value (a `config system replacemsg`
  // body, a banner, a multi-line comment field) can contain a raw line that trims to
  // exactly `end`, or starts with `config `. Before this fix, only secret-shaped
  // values suspended blockPath tracking — a non-secret multi-line body could pop/push
  // blockPath at the wrong point, so a LATER, genuinely secret-bearing line (e.g. an
  // SNMP community, recognized only while blockPath's last entry is
  // 'system snmp community' — see isSecretInContext) could silently stop being
  // recognized as "inside a secret context" and pass through unredacted.
  //
  // Fails CLOSED: a line is only treated as closing the multi-line value when it
  // contains an unescaped quote; anything ambiguous keeps structural matching (and,
  // for secrets, output) suspended.
  let inMultiline = false;
  let inMultilineSecret = false;

  for (const rawLine of text.replace(/\r/g, '').split('\n')) {
    try {
      if (inMultiline) {
        // Non-secret multi-line values pass through untouched (nothing to redact);
        // secret ones emit nothing, as before.
        if (!inMultilineSecret) out.push(rawLine);
        if (countUnescapedQuotes(rawLine) >= 1) {
          inMultiline = false;
          inMultilineSecret = false;
        }
        continue;
      }

      const line = rawLine.trim();
      let m;

      if ((m = line.match(/^config\s+(.+)$/i))) {
        blockPath.push(m[1].trim().replace(/"/g, ''));
        out.push(rawLine);
        continue;
      }

      if (/^end$/i.test(line)) {
        blockPath.pop();
        out.push(rawLine);
        continue;
      }

      if (/^set\s+/i.test(line)) {
        const redacted = redactSetLine(rawLine, blockPath);
        out.push(redacted.line);
        if (redacted.opensMultiline) {
          inMultiline = true;
          inMultilineSecret = redacted.isSecret;
        }
        continue;
      }

      out.push(rawLine);
    } catch (_err) {
      // Fail CLOSED: never let an unexpected line through unredacted.
      out.push(REDACTED);
    }
  }

  return out.join('\n');
}

// ---------------------------------------------------------------------------
// show full-configuration → structured object
// ---------------------------------------------------------------------------

/**
 * Builds the `parsed` object for getConfig() from a FortiOS full configuration.
 *
 * The keys ({global, interfaces, ssl_vpn, snmp, admins, ntp, dns, log_syslogd,
 * password_policy, fortiguard, autoupdate_schedule}) and the FortiOS field names
 * beneath them deliberately mirror what the REST adapter's getConfig() produces from
 * the cmdb endpoints, so a Phase 6 advisory_conditions dot-path predicate written for
 * a FortiGate works whether that device is collected over the API or over SSH.
 *
 * `ntp`/`dns`/`log_syslogd`/`password_policy`/`fortiguard`/`autoupdate_schedule` were
 * added 2026-07-19 to unlock 5 previously-`not_evaluable_from_config` compliance
 * checks in `lib/auditChecksSeed.js` (fortinet-ntp-configured, fortinet-dns-configured,
 * fortinet-logging-enabled, fortinet-password-min-length,
 * fortinet-fortiguard-updates-enabled), which read `ntp.ntpsync`, `dns.primary`,
 * `log_syslogd.status`, `password_policy.minimum-length`, `autoupdate_schedule.status`
 * respectively off this exact object shape.
 *
 * All 6 new sections are FLAT-ONLY, same as ssl_vpn/snmp above — only each block's own
 * direct `set` lines, via settingsOfFirst(). None of them descend into a nested
 * `config` sub-block. Deliberate, not an oversight: e.g. `config system ntp`'s nested
 * `config ntpserver` table (the list of NTP server hosts) is intentionally NOT
 * collected here, because the one compliance check this unlocks only needs the flat
 * `ntpsync` enable/disable toggle, not the server list. If a future check needs the
 * server list, add a dedicated `entriesOfAll('...')`-based key rather than overloading
 * this one.
 *
 * MUST be given ALREADY-REDACTED text (ssh.js does this) — defence in depth, so no
 * parsed field can ever capture a live secret.
 *
 * @param {string} redactedText
 * @returns {object}
 */
function parseFullConfiguration(redactedText) {
  const tree = parseConfigTree(redactedText);

  // Singleton sections: first deep match wins. Table sections: concatenate every
  // match, because in VDOM mode `config system interface` / `config system admin`
  // appear once per VDOM and taking only the first would hide the rest.
  const settingsOfFirst = (path) => flattenSettings(findBlockDeep(tree, path));
  const entriesOfAll = (path) =>
    findBlocksDeep(tree, path).reduce((acc, node) => acc.concat(flattenEntries(node)), []);

  return {
    global: settingsOfFirst('system global'),
    interfaces: entriesOfAll('system interface'),
    ssl_vpn: settingsOfFirst('vpn ssl settings'),
    snmp: settingsOfFirst('system snmp sysinfo'),
    admins: entriesOfAll('system admin'),
    // Added 2026-07-19 — flat-only, see the doc comment above for why the nested
    // `ntpserver` table under `system ntp` is deliberately not collected here.
    ntp: settingsOfFirst('system ntp'),
    dns: settingsOfFirst('system dns'),
    log_syslogd: settingsOfFirst('log syslogd setting'),
    password_policy: settingsOfFirst('system password-policy'),
    fortiguard: settingsOfFirst('system fortiguard'),
    autoupdate_schedule: settingsOfFirst('system autoupdate schedule'),
    collected_via: 'ssh',
  };
}

module.exports = {
  parseConfigTree,
  findBlock,
  findBlockDeep,
  findBlocksDeep,
  flattenSettings,
  flattenEntries,
  parseSystemStatus,
  isMultiVdom,
  countActiveVpnSessions,
  vdomNamesFromConfigText,
  isSafeVdomName,
  policiesFromConfigText,
  parseFullConfiguration,
  redactConfig,
  looksLikeConfig,
  looksLikeCliError,
  // getObjects() support (named object catalog)
  ipMaskToPrefixLength,
  entriesFromConfigText,
  addressEntryToNamedAddress,
  groupEntryToNamedGroup,
  serviceEntryToNamedService,
  // exported for testing / reuse, not part of the documented contract
  tokenize,
  countUnescapedQuotes,
  entryToPolicyObject,
  isSecretKey,
  redactSetLine,
  scalarToken,
};
