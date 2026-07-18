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
// CLI output sanity checks
// ---------------------------------------------------------------------------

// Matches output whose FIRST token on a line is a CLI rejection. The ASA emits
// these when a command is unavailable in the current mode — most commonly when
// the session never reached privileged EXEC (no/!wrong enable password, or an
// SSH user below privilege 15), in which case `show running-config` returns an
// error instead of a config.
// Anchored to the start of a line so an indented `description ERROR: ...` or a
// `banner motd ...` line can never trigger a false positive.
const CLI_ERROR_REGEX =
  /(?:^|\n)\s*(?:ERROR:|Command authorization failed|%\s*(?:Invalid input|Incomplete command|Ambiguous command|Authorization failed))/i;

// True when CLI output is a command rejection rather than real data.
function looksLikeCliError(text) {
  if (typeof text !== 'string' || text.length === 0) return false;
  return CLI_ERROR_REGEX.test(text);
}

// True when text plausibly IS an ASA running-config. A real `show
// running-config` always carries at least one of these anchors near the top:
//   ASA Version 9.18(4)15 / hostname fw01 / interface GigabitEthernet0/0 / names
// Used to refuse storing an empty or truncated snapshot as if it were a config.
function looksLikeRunningConfig(text) {
  if (typeof text !== 'string' || text.trim().length === 0) return false;
  return /^\s*(?:ASA Version\s|hostname\s|interface\s|names\s*$)/im.test(text);
}

// ---------------------------------------------------------------------------
// Secret redaction
// ---------------------------------------------------------------------------
//
// SECURITY: `show running-config` carries password hashes, VPN pre-shared keys,
// SNMP communities and AAA shared secrets. The raw text is persisted verbatim
// into device_configs.config_raw, copied into config_backups.config_raw, served
// by the backup download route, and both tables are GRANT SELECT'd to the
// claude_readonly / nocvault_readonly diagnostic roles. It MUST be redacted
// before it leaves this adapter — see CLAUDE.md "Security".
//
// Redaction is a fixed token (not a hash), so it is deterministic: two pulls of
// an unchanged config redact identically. Change detection is unaffected either
// way — lib/engines/configDiff.js diffs config_parsed, never config_raw.

const REDACTED = '<redacted>';

// Each rule captures the non-secret prefix as $1 and the secret token as $2.
// Applied per line, first match wins. Only the secret token is replaced, so any
// trailing non-secret context (e.g. `address 1.2.3.4`) survives.
const REDACTION_RULES = [
  // enable password <hash> [encrypted|pbkdf2|level N]
  /^(\s*enable\s+password\s+)(\S+)/i,
  // passwd <hash> [encrypted]  — the telnet/SSH login password
  /^(\s*passwd\s+)(\S+)/i,
  // username <name> password <hash> [encrypted|nt-encrypted|pbkdf2] [privilege N]
  /^(\s*username\s+\S+\s+password\s+)(\S+)/i,
  // snmp-server host <if> <ip> [...] community <string>   (before the bare rule)
  /^(\s*snmp-server\s+host\s+.*?\bcommunity\s+)(\S+)/i,
  // snmp-server community <string>
  /^(\s*snmp-server\s+community\s+)(\S+)/i,
  // crypto isakmp key <key> address <ip>   (IKEv1 pre-shared key)
  /^(\s*crypto\s+isakmp\s+key\s+)(\S+)/i,
  // failover ipsec pre-shared-key <key>    (before the generic PSK rule)
  /^(\s*failover\s+ipsec\s+pre-shared-key\s+)(\S+)/i,
  // failover key <key>
  /^(\s*failover\s+key\s+)(\S+)/i,
  // [ikev1|ikev2] [remote-|local-]authentication pre-shared-key <key>
  /^(\s*(?:ikev[12]\s+)?(?:(?:remote|local)-authentication\s+)?pre-shared-key\s+)(\S+)/i,
  // ldap-login-password <pw>
  /^(\s*ldap-login-password\s+)(\S+)/i,
  // [ospf] message-digest-key <n> md5 <key>
  /^(\s*(?:ospf\s+)?message-digest-key\s+\d+\s+md5\s+)(\S+)/i,
  // [ospf] authentication-key <key>
  /^(\s*(?:ospf\s+)?authentication-key\s+)(\S+)/i,
  // ntp authentication-key <n> md5 <key>
  /^(\s*ntp\s+authentication-key\s+\d+\s+md5\s+)(\S+)/i,
  // key-string <key>  (key chains)
  /^(\s*key-string\s+)(\S+)/i,
  // aaa-server sub-mode: "  key <shared secret>" (RADIUS/TACACS+).
  // Indented + value-to-end-of-line keeps this off `key-exchange`/`key-chain`.
  /^(\s+key\s+)(\S+)\s*$/i,
  // aaa-server sub-mode: radius-common-pw <shared secret> (single-line RADIUS
  // form, distinct from the "key" sub-mode form above). Found missing in a
  // follow-up bug sweep (2026-07-17).
  /^(\s*radius-common-pw\s+)(\S+)/i,
  // Sub-mode "  password <pw>" (tunnel-group general-attributes, vpdn, mount).
  // `password` at column 0 is not valid ASA syntax (that is `passwd`), so
  // requiring indentation avoids colliding with anything else.
  /^(\s+password\s+)(\S+)/i,
];

// snmp-server user <name> <group> v3 [engineID <id>] auth <alg> <key> [priv <alg> [<bits>] <key>]
// Carries TWO secrets on one line, so it needs both replacements rather than
// the first-match-wins loop.
function redactSnmpV3User(line) {
  return line
    .replace(/(\bauth\s+\S+\s+)(\S+)/i, `$1${REDACTED}`)
    .replace(/(\bpriv\s+(?:aes\s+\d+\s+|3des\s+|des\s+)?)(\S+)/i, `$1${REDACTED}`);
}

// Redacts one config line. Fails CLOSED: any unexpected error redacts the whole
// line rather than risking a secret passing through.
function redactLine(line) {
  try {
    if (/^\s*snmp-server\s+user\s+/i.test(line)) return redactSnmpV3User(line);
    for (const rule of REDACTION_RULES) {
      if (rule.test(line)) return line.replace(rule, `$1${REDACTED}`);
    }
    return line;
  } catch (_err) {
    return REDACTED;
  }
}

// Redacts every secret-bearing line in a raw `show running-config` dump.
// MUST be applied before the text is returned from the adapter — nothing
// downstream redacts.
function redactConfig(text) {
  if (typeof text !== 'string' || text.length === 0) return '';
  return text
    .replace(/\r/g, '')
    .split('\n')
    .map(redactLine)
    .join('\n');
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
    // Minimal, low-risk WebVPN/AnyConnect presence signal only — added
    // 2026-07-19 to support a fleet-wide "VPN exposure" view without
    // requiring deep ASA VPN config modeling. Deliberately does NOT parse
    // tunnel-group/group-policy/anyconnect image/certificate lines — that
    // would need much deeper ASA config modeling than this file currently
    // supports. Field names/grammar are doc-derived from standard ASA
    // syntax, written without a live device — same caveat as every other
    // field in this file (see the top-of-file header comment).
    webvpn: {
      enabled: false, // true if a `webvpn` block exists AND has an `enable <interface>` line inside it
      enabled_interface: null, // the <interface> name from `enable <interface>`, e.g. "outside"
    },
  };
  if (typeof text !== 'string' || text.length === 0) return parsed;

  let currentInterface = null;
  // Tracks whether we're inside the single `webvpn` block — unlike
  // interfaces there is only ever one, so a boolean flag (not an array) is
  // enough. Mirrors currentInterface's block-tracking pattern exactly.
  let inWebvpnBlock = false;

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

    // WebVPN sub-config lines (indented, inside the webvpn block). Only
    // `enable <interface>` is recognized — see the field comment above for
    // why the rest of the block's grammar is deliberately out of scope.
    if (indented && inWebvpnBlock) {
      const m2 = trimmed.match(/^enable\s+(\S+)/i);
      if (m2) {
        parsed.webvpn.enabled = true;
        parsed.webvpn.enabled_interface = m2[1];
      }
      continue;
    }

    // Any non-indented line ends the current interface block and the webvpn block.
    if (!indented) {
      currentInterface = null;
      inWebvpnBlock = false;
    }

    let m;
    if ((m = trimmed.match(/^interface\s+(\S.*)$/i))) {
      currentInterface = { name: m[1].trim(), nameif: null, ip: null, security_level: null };
      parsed.interfaces.push(currentInterface);
    } else if (/^webvpn\s*$/i.test(trimmed)) {
      inWebvpnBlock = true;
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

// ---------------------------------------------------------------------------
// show running-config object / object-group  (named address/service catalog)
// ---------------------------------------------------------------------------
//
// Feeds lib/engines/objectUsage.js's "Unused/Duplicate Objects" feature — see
// lib/adapters/interface.js's getObjects() contract comment for the exact
// return shape. Same line-by-line, single-open-block style as
// parseRunningConfig()'s currentInterface/webvpn tracking above: a block
// starts at a non-indented `object ...`/`object-group ...` line and ends at
// the next non-indented line (whatever it is), mirrored exactly.
//
// No secrets live in object/object-group definitions — parsed from the
// UNREDACTED text, same as parseRunningConfig()'s other non-secret fields.

// Converts a dotted-decimal subnet mask to a CIDR prefix length. Returns null
// for anything that isn't a contiguous, valid netmask (non-IPv4, out-of-range
// octet, or a bit pattern that isn't a run of 1s followed by 0s) — callers
// fall back to the raw "<net> <mask>" string rather than guess a wrong prefix.
function maskToCidr(mask) {
  if (!isIpv4(mask)) return null;
  const octets = mask.split('.').map(Number);
  if (octets.some((o) => o < 0 || o > 255)) return null;
  let bits = '';
  for (const o of octets) bits += o.toString(2).padStart(8, '0');
  if (!/^1*0*$/.test(bits)) return null;
  const firstZero = bits.indexOf('0');
  return firstZero === -1 ? 32 : firstZero;
}

// Applies one indented sub-line to the currently open object/object-group
// block (mutates `block` in place). Unrecognized lines (fqdn, nat, port-object
// / inline network-object/service-object literals with no backing named
// object, description, etc.) are silently no-ops — only real single-value
// resolutions and real name REFERENCES are captured, per the getObjects()
// contract's "skip inline literals, don't invent a synthetic name" rule.
function parseObjectBlockLine(line, block) {
  let m;
  if (block.kind === 'object-network') {
    if ((m = line.match(/^host\s+(\S+)/i))) {
      block.value = m[1];
      block.type = 'host';
    } else if ((m = line.match(/^subnet\s+(\S+)\s+(\S+)/i))) {
      const cidr = maskToCidr(m[2]);
      block.value = cidr !== null ? `${m[1]}/${cidr}` : `${m[1]} ${m[2]}`;
      block.type = 'subnet';
    } else if ((m = line.match(/^range\s+(\S+)\s+(\S+)/i))) {
      block.value = `${m[1]}-${m[2]}`;
      block.type = 'range';
    }
  } else if (block.kind === 'object-service') {
    if ((m = line.match(/^service\s+(tcp|udp)\s+destination\s+eq\s+(\S+)/i))) {
      block.value = `${m[1].toLowerCase()}/${m[2]}`;
    } else if ((m = line.match(/^service\s+(tcp|udp)\s+destination\s+range\s+(\S+)\s+(\S+)/i))) {
      block.value = `${m[1].toLowerCase()}/${m[2]}-${m[3]}`;
    }
  } else if (block.kind === 'group-network') {
    if ((m = line.match(/^network-object\s+object\s+(\S+)/i))) {
      block.members.push(m[1]);
    } else if ((m = line.match(/^group-object\s+(\S+)/i))) {
      block.members.push(m[1]);
    }
    // `network-object host <ip>` / `network-object <net> <mask>` are inline
    // literals with no backing named object — nothing to add as a member.
  } else if (block.kind === 'group-service') {
    if ((m = line.match(/^service-object\s+object\s+(\S+)/i))) {
      block.members.push(m[1]);
    } else if ((m = line.match(/^group-object\s+(\S+)/i))) {
      block.members.push(m[1]);
    }
    // `port-object ...` / inline `service-object tcp|udp ...` — no backing
    // named object, nothing to add as a member.
  }
}

// Parses full `show running-config` (or any text containing
// object/object-group definitions) output → the getObjects() contract shape.
// Defensive per-line and per-block: a single malformed line/block is warned
// and skipped rather than aborting the whole catalog — see
// lib/adapters/interface.js's getObjects() comment for why a partial result
// is acceptable here (unlike getRules()/getConfig()).
function parseObjects(text) {
  const result = { addresses: [], addressGroups: [], services: [], serviceGroups: [] };
  if (typeof text !== 'string' || text.length === 0) return result;

  // The single currently-open object/object-group block, or null. Exactly
  // one at a time — mirrors parseRunningConfig()'s currentInterface pattern.
  let block = null;

  function closeBlock() {
    if (!block) return;
    try {
      if (block.kind === 'object-network') {
        result.addresses.push({ name: block.name, type: block.type, value: block.value });
      } else if (block.kind === 'object-service') {
        result.services.push({ name: block.name, value: block.value });
      } else if (block.kind === 'group-network') {
        result.addressGroups.push({ name: block.name, members: block.members });
      } else if (block.kind === 'group-service') {
        result.serviceGroups.push({ name: block.name, members: block.members });
      }
    } catch (err) {
      console.warn(`[CiscoASA parser] parseObjects: failed to finalize block "${block.name}": ${err.message}`);
    }
    block = null;
  }

  for (const rawLine of text.replace(/\r/g, '').split('\n')) {
    const indented = /^\s/.test(rawLine);
    const trimmed = rawLine.trim();
    if (trimmed === '') continue;

    if (indented && block) {
      try {
        parseObjectBlockLine(trimmed, block);
      } catch (err) {
        console.warn(
          `[CiscoASA parser] parseObjects: failed to parse sub-line "${trimmed}" in block "${block.name}": ${err.message}`
        );
      }
      continue;
    }

    // Any non-indented line ends the current block, same as
    // parseRunningConfig()'s currentInterface/webvpn reset.
    closeBlock();

    let m;
    if ((m = trimmed.match(/^object\s+network\s+(\S+)/i))) {
      block = { kind: 'object-network', name: m[1], value: null, type: null };
    } else if ((m = trimmed.match(/^object\s+service\s+(\S+)/i))) {
      block = { kind: 'object-service', name: m[1], value: null };
    } else if ((m = trimmed.match(/^object-group\s+network\s+(\S+)/i))) {
      block = { kind: 'group-network', name: m[1], members: [] };
    } else if ((m = trimmed.match(/^object-group\s+service\s+(\S+)/i))) {
      block = { kind: 'group-service', name: m[1], members: [] };
    }
  }
  closeBlock();

  return result;
}

module.exports = {
  parseShowVersion,
  parseAccessListConfig,
  parseHitCounts,
  parseRunningConfig,
  parseObjects,
  redactConfig,
  looksLikeCliError,
  looksLikeRunningConfig,
  // exported for testing / reuse, not part of the documented contract
  normalizeAceForMatch,
  parseExtendedAce,
  redactLine,
  maskToCidr,
  parseObjectBlockLine,
};
