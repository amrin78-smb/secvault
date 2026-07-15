// lib/adapters/cisco_asa/parser.js
// Pure text-parsing functions for Cisco ASA CLI output. CommonJS ONLY.
//
// No I/O, no network, no DB — every function takes raw CLI text and returns
// plain data. All functions are exported for tests. Parsing is defensive
// everywhere: this was written without a live device (same situation as the
// Forcepoint SMC adapter — see CLAUDE.md "Field Name Verification"), so
// malformed/unexpected lines are skipped with a console.warn, never thrown.

'use strict';

const IPV4_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;
const PORT_OPERATORS = { eq: '', gt: '>', lt: '<', neq: '!=' };

function isIpv4(token) {
  return typeof token === 'string' && IPV4_REGEX.test(token);
}

// ---------------------------------------------------------------------------
// show version
// ---------------------------------------------------------------------------

// Parses `show version` output.
//   "Cisco Adaptive Security Appliance Software Version 9.18(4)15" → version_string
//   "Hardware:   ASA5516, 8192 MB RAM, ..."                        → model
//   "Device Manager Version 7.18(1)152"                            → build (extra/fallback info)
// → { version_string, model, build } (each null if not found)
function parseShowVersion(text) {
  const result = { version_string: null, model: null, build: null };
  if (typeof text !== 'string' || text.length === 0) {
    console.warn('[CiscoASA parser] parseShowVersion: empty or non-string input');
    return result;
  }

  const clean = text.replace(/\r/g, '');

  let match = clean.match(/Cisco Adaptive Security Appliance Software Version\s+([^\s,]+)/i);
  if (!match) {
    // Newer images sometimes render slightly different product wording —
    // fall back to any "... Software Version X" line.
    match = clean.match(/Software Version\s+([^\s,]+)/i);
  }
  if (match) result.version_string = match[1];

  const hardware = clean.match(/^Hardware:\s+([^,\s]+)/im);
  if (hardware) result.model = hardware[1];

  const deviceManager = clean.match(/Device Manager Version\s+([^\s,]+)/i);
  if (deviceManager) result.build = deviceManager[1];

  if (!result.version_string) {
    console.warn(
      '[CiscoASA parser] parseShowVersion: no software version line found in output — ' +
        'check the raw [CiscoASA Debug] log and adjust parser patterns.'
    );
  }

  return result;
}

// ---------------------------------------------------------------------------
// show running-config access-list
// ---------------------------------------------------------------------------

// Parses one address specification starting at tokens[i].
// Forms: any|any4|any6 | host x.x.x.x | x.x.x.x mask | object NAME | object-group NAME
// → { value: string, consumed: number } or null when tokens are exhausted.
function parseAddressSpec(tokens, i) {
  const token = tokens[i];
  if (token === undefined) return null;
  const lower = token.toLowerCase();

  if (lower === 'any' || lower === 'any4' || lower === 'any6') {
    return { value: lower, consumed: 1 };
  }
  if (lower === 'host') {
    return { value: tokens[i + 1] !== undefined ? tokens[i + 1] : 'host', consumed: 2 };
  }
  if (lower === 'object' || lower === 'object-group') {
    return { value: `${lower} ${tokens[i + 1] !== undefined ? tokens[i + 1] : ''}`.trim(), consumed: 2 };
  }
  if (lower === 'interface') {
    return { value: `interface ${tokens[i + 1] !== undefined ? tokens[i + 1] : ''}`.trim(), consumed: 2 };
  }
  if (isIpv4(token) && isIpv4(tokens[i + 1])) {
    return { value: `${token}/${tokens[i + 1]}`, consumed: 2 };
  }
  if (token.includes(':') || token.includes('/')) {
    // IPv6 literal or already-CIDR form
    return { value: token, consumed: 1 };
  }
  // Defensive fallback: unknown token — treat as a single-token address so the
  // rest of the line can still be parsed. The full line is preserved in raw_rule.
  return { value: token, consumed: 1 };
}

// Parses a port specification starting at tokens[i].
// Forms: eq X | gt X | lt X | neq X | range A B | (dest position only) object-group NAME
// → { text: string, consumed: number } or null when no port spec is present.
function parsePortSpec(tokens, i, allowObjectGroup) {
  const token = (tokens[i] || '').toLowerCase();
  if (token in PORT_OPERATORS) {
    const value = tokens[i + 1] !== undefined ? tokens[i + 1] : '';
    return { text: `${PORT_OPERATORS[token]}${value}`, consumed: 2 };
  }
  if (token === 'range') {
    const lo = tokens[i + 1] !== undefined ? tokens[i + 1] : '';
    const hi = tokens[i + 2] !== undefined ? tokens[i + 2] : '';
    return { text: `${lo}-${hi}`, consumed: 3 };
  }
  // After BOTH addresses are consumed, an object-group token can only be a
  // service group. Before the destination address it is ambiguous (could be
  // the destination network group), so it is only accepted when allowed.
  if (allowObjectGroup && token === 'object-group') {
    return { text: `object-group ${tokens[i + 1] !== undefined ? tokens[i + 1] : ''}`.trim(), consumed: 2 };
  }
  return null;
}

// Known `log` option tokens that may follow the log keyword on an ACE.
const LOG_OPTION_REGEX = /^(disable|default|debugging|informational|notifications|warnings|errors|critical|alerts|emergencies|interval|\d+)$/i;

// Parses a single extended ACE line into a NormalizedRule skeleton.
// rule_name / sequence_number / comment are filled by parseAccessListConfig.
// Returns null for lines that cannot be parsed (with a console.warn).
function parseExtendedAce(line, tokens, aclName) {
  // tokens: ['access-list', NAME, 'extended', ACTION, PROTO, ...]
  let i = 3;

  const actionRaw = (tokens[i] || '').toLowerCase();
  i += 1;
  if (actionRaw !== 'permit' && actionRaw !== 'deny') {
    console.warn(`[CiscoASA parser] Unrecognized ACE action "${actionRaw}" in ACL "${aclName}" — skipping line`);
    return null;
  }

  // Protocol: name/number, or object/object-group reference (protocol-service groups).
  let proto;
  const protoToken = (tokens[i] || '').toLowerCase();
  if (protoToken === 'object' || protoToken === 'object-group') {
    proto = `${protoToken} ${tokens[i + 1] !== undefined ? tokens[i + 1] : ''}`.trim();
    i += 2;
  } else {
    proto = protoToken;
    i += 1;
  }
  if (!proto) {
    console.warn(`[CiscoASA parser] ACE in ACL "${aclName}" has no protocol token — skipping line`);
    return null;
  }

  const src = parseAddressSpec(tokens, i);
  if (!src) {
    console.warn(`[CiscoASA parser] ACE in ACL "${aclName}" has no source address — skipping line`);
    return null;
  }
  i += src.consumed;

  // Optional SOURCE port spec (eq/gt/lt/neq/range only — object-group here is
  // ambiguous with a destination network group, so it is not accepted).
  const srcPort = parsePortSpec(tokens, i, false);
  if (srcPort) i += srcPort.consumed;

  const dst = parseAddressSpec(tokens, i);
  if (dst) i += dst.consumed;

  // Optional DESTINATION port spec (object-group allowed — both addresses are consumed).
  let dstPort = null;
  const dp = parsePortSpec(tokens, i, true);
  if (dp) {
    dstPort = dp;
    i += dp.consumed;
  }

  // Trailing flags: log [...], inactive, time-range NAME, icmp-types, etc.
  let inactive = false;
  let schedule = null;
  while (i < tokens.length) {
    const t = tokens[i].toLowerCase();
    if (t === 'inactive') {
      inactive = true;
      i += 1;
    } else if (t === 'time-range') {
      schedule = tokens[i + 1] !== undefined ? tokens[i + 1] : null;
      i += 2;
    } else if (t === 'log') {
      i += 1;
      while (i < tokens.length && LOG_OPTION_REGEX.test(tokens[i])) i += 1;
    } else {
      // Unrecognized trailing token (icmp type, etc.) — skip defensively;
      // the full line is preserved in raw_rule.
      i += 1;
    }
  }

  const services = [dstPort ? `${proto}/${dstPort.text}` : proto];

  return {
    rule_name: null, // filled by caller: `<acl_name>#<n>`
    rule_id_vendor: line,
    sequence_number: null, // filled by caller: global order
    enabled: !inactive,
    action: actionRaw === 'permit' ? 'allow' : 'deny',
    // ASA ACEs carry no zone/interface info themselves — interface binding
    // comes from `access-group <acl> in interface <ifname>`. Mapping ACLs to
    // interfaces via access-group is a future enhancement.
    src_zones: [],
    dst_zones: [],
    src_addresses: [src.value],
    dst_addresses: dst ? [dst.value] : [],
    services,
    applications: [],
    schedule,
    expiry_date: null,
    log_enabled: /\slog(\s|$)/i.test(line),
    comment: null, // filled by caller from preceding remark lines
    hit_count: 0, // merged later from parseHitCounts (default 0)
    raw_rule: { line, acl: aclName },
  };
}

// Parses full `show running-config access-list` output → NormalizedRule[].
// - Only `extended` ACEs are parsed; standard/webtype/ethertype ACLs are
//   skipped with a console.warn (once per ACL).
// - `remark` lines are skipped but attached to the following ACE as comment.
function parseAccessListConfig(text) {
  const rules = [];
  if (typeof text !== 'string' || text.length === 0) return rules;

  const pendingRemarks = {}; // acl name → [remark, ...]
  const perAclCount = {}; // acl name → count of parsed ACEs (for rule_name #n)
  const warnedAcls = new Set();
  let globalSequence = 0;

  for (const rawLine of text.replace(/\r/g, '').split('\n')) {
    const line = rawLine.trim();
    if (!line.startsWith('access-list ')) continue;

    const tokens = line.split(/\s+/);
    const aclName = tokens[1];
    if (!aclName) continue;
    const kind = (tokens[2] || '').toLowerCase();

    if (kind === 'remark') {
      const remark = tokens.slice(3).join(' ');
      if (!pendingRemarks[aclName]) pendingRemarks[aclName] = [];
      pendingRemarks[aclName].push(remark);
      continue;
    }

    if (kind !== 'extended') {
      // Extended ACLs only — standard (route-map style) and webtype
      // (clientless VPN) ACLs use different grammars and are out of scope.
      if (!warnedAcls.has(aclName)) {
        console.warn(
          `[CiscoASA parser] Skipping unsupported "${kind || '?'}" ACL "${aclName}" — only extended ACLs are parsed`
        );
        warnedAcls.add(aclName);
      }
      continue;
    }

    let rule = null;
    try {
      rule = parseExtendedAce(line, tokens, aclName);
    } catch (err) {
      console.warn(`[CiscoASA parser] Failed to parse ACE line "${line}": ${err.message}`);
    }
    if (!rule) continue;

    globalSequence += 1;
    perAclCount[aclName] = (perAclCount[aclName] || 0) + 1;
    rule.rule_name = `${aclName}#${perAclCount[aclName]}`;
    rule.sequence_number = globalSequence;

    const remarks = pendingRemarks[aclName];
    rule.comment = remarks && remarks.length > 0 ? remarks.join(' | ') : null;
    pendingRemarks[aclName] = [];

    rules.push(rule);
  }

  return rules;
}

// ---------------------------------------------------------------------------
// show access-list (hit counts)
// ---------------------------------------------------------------------------

// Normalizes an ACE line for hit-count matching between the running-config
// form and the `show access-list` form: strips "line N", the "(hitcnt=N)"
// suffix + trailing hash, and collapses whitespace.
function normalizeAceForMatch(line) {
  return String(line)
    .replace(/\s+line\s+\d+\s+/i, ' ')
    .replace(/\s*\(hitcnt=\d+\).*$/i, '')
    .replace(/\s+0x[0-9a-f]+\s*$/i, '')
    .replace(/\s+/g, ' ')
    .trim();
}

// Parses `show access-list` output → { [normalizedAceText]: hitcnt }.
// The first entry per normalized ACE wins: for object-group ACEs the parent
// (config-form) line appears before its expanded per-element lines, and it is
// the parent line whose text matches the running-config ACE.
// Known limitation: bare `log` in config renders as `log informational
// interval 300` in show access-list — such lines won't text-match and the
// rule keeps its default hit_count of 0.
function parseHitCounts(text) {
  const counts = {};
  if (typeof text !== 'string' || text.length === 0) return counts;

  for (const rawLine of text.replace(/\r/g, '').split('\n')) {
    const line = rawLine.trim();
    if (!line.startsWith('access-list ')) continue;
    const match = line.match(/\(hitcnt=(\d+)\)/i);
    if (!match) continue;

    const key = normalizeAceForMatch(line);
    if (!(key in counts)) {
      counts[key] = parseInt(match[1], 10) || 0;
    }
  }

  return counts;
}

// ---------------------------------------------------------------------------
// show running-config (full config → simple structured object)
// ---------------------------------------------------------------------------

// `ssh <keyword> ...` lines that are settings, not allowed-source entries.
const SSH_SETTING_KEYWORDS = new Set([
  'version',
  'timeout',
  'key-exchange',
  'cipher',
  'stricthostkeycheck',
  'pubkey-chain',
  'scopy',
]);

// Parses full `show running-config` output into a simple structured object
// for the Phase 6 dot-path predicate engine. Line-by-line and defensive —
// unknown lines are simply ignored.
//
// SECURITY: SNMP community strings are secrets. They are NEVER stored as
// values — each `snmp-server community ...` line contributes a '<redacted>'
// placeholder only. Likewise usernames are captured as names only, never
// their password hashes.
function parseRunningConfig(text) {
  const parsed = {
    hostname: null,
    interfaces: [],
    snmp: { enabled: false, communities: [] },
    http_server_enabled: false,
    ssh_sources: [],
    telnet_sources: [],
    usernames: [],
    version: null,
  };
  if (typeof text !== 'string' || text.length === 0) return parsed;

  let currentInterface = null;

  for (const rawLine of text.replace(/\r/g, '').split('\n')) {
    const indented = /^\s/.test(rawLine);
    const trimmed = rawLine.trim();
    if (trimmed === '') continue;

    // Interface sub-config lines (indented, inside an interface block).
    if (indented && currentInterface) {
      let m;
      if ((m = trimmed.match(/^nameif\s+(\S+)/i))) {
        currentInterface.nameif = m[1];
      } else if ((m = trimmed.match(/^security-level\s+(\d+)/i))) {
        currentInterface.security_level = parseInt(m[1], 10);
      } else if ((m = trimmed.match(/^ip address\s+(\S+)(?:\s+(\S+))?/i))) {
        currentInterface.ip = m[2] ? `${m[1]} ${m[2]}` : m[1];
      }
      continue;
    }

    // Any non-indented line ends the current interface block.
    if (!indented) currentInterface = null;

    let m;
    if ((m = trimmed.match(/^interface\s+(\S.*)$/i))) {
      currentInterface = { name: m[1].trim(), nameif: null, ip: null, security_level: null };
      parsed.interfaces.push(currentInterface);
    } else if ((m = trimmed.match(/^hostname\s+(\S+)/i))) {
      parsed.hostname = m[1];
    } else if ((m = trimmed.match(/^ASA Version\s+(\S.*)$/i))) {
      parsed.version = m[1].trim();
    } else if (/^snmp-server\s+/i.test(trimmed)) {
      parsed.snmp.enabled = true;
      if (/^snmp-server\s+community\s+/i.test(trimmed)) {
        // NEVER store the community string itself — redact.
        parsed.snmp.communities.push('<redacted>');
      }
    } else if (/^http\s+server\s+enable$/i.test(trimmed)) {
      parsed.http_server_enabled = true;
    } else if (/^ssh\s+/i.test(trimmed)) {
      const second = (trimmed.split(/\s+/)[1] || '').toLowerCase();
      if (!SSH_SETTING_KEYWORDS.has(second)) parsed.ssh_sources.push(trimmed);
    } else if (/^telnet\s+/i.test(trimmed)) {
      const second = (trimmed.split(/\s+/)[1] || '').toLowerCase();
      if (second !== 'timeout') parsed.telnet_sources.push(trimmed);
    } else if ((m = trimmed.match(/^username\s+(\S+)/i))) {
      // Names only — never the password hash that follows on the same line.
      if (!parsed.usernames.includes(m[1])) parsed.usernames.push(m[1]);
    }
  }

  return parsed;
}

module.exports = {
  parseShowVersion,
  parseAccessListConfig,
  parseHitCounts,
  parseRunningConfig,
  // exported for testing / reuse, not part of the documented contract
  normalizeAceForMatch,
  parseExtendedAce,
};
