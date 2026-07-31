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
// show vpn-sessiondb summary
// ---------------------------------------------------------------------------
//
// DOC-DERIVED — no live ASA device exists anywhere in this project's history
// (same caveat as every other field in this file — see the top-of-file header
// comment). `show vpn-sessiondb summary` is the well-known ASA CLI command
// for a whole-device, de-duplicated VPN session count — as opposed to
// `show vpn-sessiondb detail`, which lists individual sessions and would need
// much heavier per-session parsing for the same coarse answer. Its output is
// a table under a documented, stable column header:
//   "                               Active : Cumulative : Peak Concur : Inactive"
// with one row per VPN type (AnyConnect Client, Clientless VPN, IPsec IKEv1,
// IPsec IKEv2, Site-to-Site VPN, Email Proxy, ... — the exact SET of types
// varies by ASA software train, which is exactly why this does NOT hardcode
// a fixed label list), each row shaped "<label> : <int> : <int> : <int> :
// <int>" in that unchanging column order. This function matches that
// STRUCTURAL shape (label + exactly 4 colon-separated integers) rather than
// any specific label text, so an unseen VPN-type row on a newer/older
// firmware train still contributes to the total instead of being silently
// dropped by an incomplete label list.
//
// active_session_count = SUM of each row's Active (first) column ONLY.
// Deliberately NOT the device's own "Total Active and Inactive" summary
// line — that line's label is literally "Active AND Inactive" (a combined
// figure covering idle/inactive IPsec sessions too), which would silently
// overstate "how many sessions are active right now" if used directly. That
// line (plus "Total Cumulative") is still captured into the return value
// purely so a first live connection can cross-check this function's summed
// total against the device's own total — not used as the returned count.
//
// KNOWN RISK, undocumented until a live device confirms otherwise: if a real
// device's row format doesn't use colons between columns (e.g. pure
// whitespace alignment on some software train), rowCount stays 0 and this
// falls through to the "unrecognized output" null return — it does NOT
// silently report 0, which is the safe failure direction per this codebase's
// "never guess a confident-looking wrong value" rule. See getVpnSessionSummary()
// in index.js for the corresponding [CiscoASA Debug] log line to check first.
//
// Returns null (never 0) when NEITHER a recognizable row NOR the expected
// column header text is found at all — signals "unrecognized output", which
// the caller MUST NOT treat as a confirmed zero-sessions state. Returns a
// real 0 total when the header/table IS recognized but every row's Active
// column is genuinely 0 (a legitimate "no active VPN sessions right now").
function parseVpnSessionSummary(text) {
  if (typeof text !== 'string' || text.length === 0) {
    console.warn('[CiscoASA parser] parseVpnSessionSummary: empty or non-string input');
    return null;
  }

  const clean = text.replace(/\r/g, '');

  // Weak corroborating signal that this IS the expected table, used only to
  // decide whether a zero-row parse means "genuinely no rows" (header found,
  // e.g. VPN not configured on this device) vs "wrong output entirely" (no
  // header, no rows — likely an unrecognized firmware format).
  const hasExpectedHeader =
    /Active\s*:?\s*Cumulative/i.test(clean) || /VPN\s+Session\s+Summary/i.test(clean);

  // Global, multiline: "<label> : <int> : <int> : <int> : <int>", label is
  // any run of letters/digits/slashes/hyphens/colons/spaces (covers labels
  // like "IPsec IKEv1", "AnyConnect Client", "Site-to-Site VPN"). Anchored to
  // the whole line (^...$ with /m) so the plain-text column header itself
  // (no digits) can never match.
  const ROW_REGEX = /^\s*([A-Za-z][A-Za-z0-9/:'\- ]*?)\s*:\s*(\d+)\s*:\s*(\d+)\s*:\s*(\d+)\s*:\s*(\d+)\s*$/gm;

  const byCategory = {};
  let total = 0;
  let rowCount = 0;
  let match;
  while ((match = ROW_REGEX.exec(clean)) !== null) {
    const label = match[1].trim();
    const active = parseInt(match[2], 10);
    if (!label || Number.isNaN(active)) continue;
    byCategory[label] = active;
    total += active;
    rowCount += 1;
  }

  if (rowCount === 0 && !hasExpectedHeader) {
    console.warn(
      '[CiscoASA parser] parseVpnSessionSummary: no recognizable VPN-type rows or column header found'
    );
    return null;
  }

  const totalActiveInactiveMatch = clean.match(/Total\s+Active\s+and\s+Inactive\s*:?\s*(\d+)/i);
  const totalCumulativeMatch = clean.match(/Total\s+Cumulative\s*:?\s*(\d+)/i);

  return {
    active_session_count: total,
    by_category: byCategory,
    total_active_and_inactive: totalActiveInactiveMatch ? parseInt(totalActiveInactiveMatch[1], 10) : null,
    total_cumulative: totalCumulativeMatch ? parseInt(totalCumulativeMatch[1], 10) : null,
  };
}

// ---------------------------------------------------------------------------
// show vpn-sessiondb anyconnect  (per-user session DETAIL)
// ---------------------------------------------------------------------------
//
// ADDITIVE & BEST-EFFORT companion to parseVpnSessionSummary() above. The
// summary command yields the authoritative, already-shipped active_session_count;
// this parses `show vpn-sessiondb anyconnect` into the vendor-agnostic per-user
// session shape (see lib/engines/vpnSessions.js / the getVpnSessionSummary()
// contract). It must NEVER be allowed to affect the count — index.js calls it
// wrapped in try/catch and this function itself also fails closed, returning []
// on ANY doubt or parse trouble rather than throwing.
//
// DOC-DERIVED, NOT live-verified (same caveat as every other field in this
// file). ASA `show vpn-sessiondb anyconnect` prints an optional
// "Session Type: AnyConnect" header, then one blank-line-separated block per
// connected user. Each block is a set of aligned `Key : value` fields, and a
// single physical line can carry TWO columns, e.g.:
//   "Username     : jdoe        Index        : 12"
//   "Assigned IP  : 10.10.10.5  Public IP    : 203.0.113.7"
//   "Bytes Tx     : 15330       Bytes Rx     : 20112"
//   "Group Policy : GP_SSL      Tunnel Group : SSL_VPN"
//   "Login Time   : 14:23:05 UTC Wed Jul 30 2026"
//   "Duration     : 0h:05m:12s"
// so the line splitter below recognizes a second-column key only when it is
// preceded by 2+ spaces AND begins with a letter — which keeps colons INSIDE a
// value (the time "14:23:05", the "(1)AES-GCM" cipher notation, etc.) from
// being misread as new key boundaries. Any noise keys that do slip through are
// simply ignored by the mapping; only recognized keys populate the shape.

// Extracts every `Key : value` pair from one physical line of vpn-sessiondb
// detail output, handling the two-column layout. Returns [[key, value], ...].
// A fresh RegExp per call — never a shared g-flagged literal with sticky
// lastIndex (the classic exec()-in-a-loop footgun).
function parseSessiondbLinePairs(line) {
  const pairs = [];
  if (typeof line !== 'string' || line.length === 0) return pairs;
  // A key marker: at line start OR after 2+ spaces, a letter-led label made of
  // letters/digits/spaces/() . / _ - (non-greedy), then optional spaces, a
  // colon, and one optional separating space. `valueStart` is where the value
  // text begins; `matchStart` is where the (possibly leading) whitespace begins.
  const re = /(?:^|\s{2,})([A-Za-z][A-Za-z0-9()/._ -]*?)\s*:\s?/g;
  const markers = [];
  let m;
  while ((m = re.exec(line)) !== null) {
    markers.push({ key: m[1].trim(), matchStart: m.index, valueStart: re.lastIndex });
    // Guard against a zero-width match looping forever (defensive; the pattern
    // always consumes at least the colon, but be safe).
    if (re.lastIndex === m.index) re.lastIndex += 1;
  }
  for (let i = 0; i < markers.length; i += 1) {
    const valEnd = i + 1 < markers.length ? markers[i + 1].matchStart : line.length;
    const value = line.slice(markers[i].valueStart, valEnd).trim();
    if (markers[i].key) pairs.push([markers[i].key, value]);
  }
  return pairs;
}

// Parses an ASA duration string ("0h:05m:12s", "1d 4h:24m:39s") to whole
// seconds, or null when nothing recognizable is present.
function parseSessiondbDuration(str) {
  if (typeof str !== 'string' || str.length === 0) return null;
  let total = 0;
  let found = false;
  const d = str.match(/(\d+)\s*d/i);
  if (d) { total += parseInt(d[1], 10) * 86400; found = true; }
  const h = str.match(/(\d+)\s*h/i);
  if (h) { total += parseInt(h[1], 10) * 3600; found = true; }
  const min = str.match(/(\d+)\s*m(?![a-z])/i);
  if (min) { total += parseInt(min[1], 10) * 60; found = true; }
  const s = str.match(/(\d+)\s*s(?![a-z])/i);
  if (s) { total += parseInt(s[1], 10); found = true; }
  return found ? total : null;
}

// Parses a byte-count field (may carry commas) to an integer, or null.
function parseSessiondbBytes(v) {
  if (v === null || v === undefined) return null;
  const digits = String(v).replace(/[^0-9]/g, '');
  if (digits === '') return null;
  const n = parseInt(digits, 10);
  return Number.isFinite(n) ? n : null;
}

// Derives a short tunnel_type label from the block's Session Type and/or
// Protocol fields. Returns null when neither yields anything usable.
function shortTunnelType(sessionType, protocol) {
  const st = typeof sessionType === 'string' ? sessionType.trim() : '';
  if (st) return st.split(/\s+/)[0]; // "AnyConnect", "SSL-VPN", ...
  const p = typeof protocol === 'string' ? protocol.toLowerCase() : '';
  if (p.includes('anyconnect') || p.includes('ssl')) return 'AnyConnect';
  if (p.includes('ipsec') || p.includes('ikev')) return 'IPSec';
  return null;
}

// Parses `show vpn-sessiondb anyconnect` output → normalized session[] (see the
// section header above). Fails closed: returns [] on empty/non-string input or
// on ANY internal error, so it can NEVER break the authoritative session count.
function parseVpnSessiondbDetail(text) {
  const out = [];
  if (typeof text !== 'string' || text.length === 0) return out;
  try {
    const clean = text.replace(/\r/g, '');

    // Document-level "Session Type: X" header (ASA prints one before the
    // per-user blocks); used as a fallback tunnel_type when a block has no
    // Session Type field of its own.
    const stMatch = clean.match(/Session\s+Type\s*:\s*(.+)/i);
    const docSessionType = stMatch ? stMatch[1].trim() : null;

    for (const block of clean.split(/\n\s*\n/)) {
      const f = {};
      let any = false;
      for (const line of block.split('\n')) {
        for (const [k, v] of parseSessiondbLinePairs(line)) {
          const key = k.toLowerCase().replace(/[^a-z0-9]/g, '');
          if (key && v !== '') {
            f[key] = v;
            any = true;
          }
        }
      }
      if (!any) continue;

      const username = f.username || null;
      // Only treat a block as a real session when it carries a recognizable
      // identity or address — header/footer/summary blocks are skipped.
      if (!username && !f.assignedip && !f.publicip) continue;

      out.push({
        username,
        tunnel_type: shortTunnelType(f.sessiontype || docSessionType, f.protocol),
        source_ip: f.publicip || null,
        assigned_ip: f.assignedip || null,
        login_time: f.logintime || null,
        duration_seconds: parseSessiondbDuration(f.duration),
        bytes_in: parseSessiondbBytes(f.bytesrx),
        bytes_out: parseSessiondbBytes(f.bytestx),
        client: f.clienttype || f.clientversion || f.client || f.hostname || null,
        gateway: f.grouppolicy || f.tunnelgroup || null,
        raw: f,
      });
    }
  } catch (err) {
    console.warn(`[CiscoASA parser] parseVpnSessiondbDetail: unexpected failure, returning [] — ${err.message}`);
    return [];
  }
  return out;
}

// ---------------------------------------------------------------------------
// show vpn-sessiondb l2l  (IPSec site-to-site TUNNEL status)
// ---------------------------------------------------------------------------
//
// SEPARATE, self-contained companion to parseVpnSessiondbDetail() above. Where
// that parser handles remote-access AnyConnect USER sessions, this one parses
// `show vpn-sessiondb l2l` — the ASA CLI command that lists established
// LAN-to-LAN (site-to-site IPSec) TUNNELS, one block per peer. It feeds the
// OPTIONAL getVpnTunnels() adapter method (see index.js), which the engine
// worker calls and stores separately from getVpnSessionSummary()'s count.
//
// DOC-DERIVED, NOT live-verified (same caveat as every other field in this
// file — see the top-of-file header comment). ASA `show vpn-sessiondb l2l`
// prints an optional "Session Type: LAN-to-LAN" header, then one
// blank-line-separated block per tunnel. Each block is a set of aligned
// `Key : value` fields, and a single physical line can carry TWO columns —
// exactly the same layout parseVpnSessiondbDetail() handles — so this REUSES
// parseSessiondbLinePairs()/parseSessiondbBytes() rather than duplicating that
// logic. A representative block:
//   "Connection   : 203.0.113.9   Index        : 7"
//   "Protocol     : IKEv2 IPsec"
//   "Encryption   : IKEv2: (1)AES256  IPsec: (1)AES256"
//   "Bytes Tx     : 15330         Bytes Rx     : 20112"
//   "Login Time   : 14:23:05 UTC Wed Jul 30 2026"
//   "Duration     : 0h:05m:12s"
//   "Tunnel Group : 203.0.113.9"
//
// Fails CLOSED: returns [] on empty/non-string input or on ANY internal error,
// and returns [] (NOT an error) when the output contains no recognizable
// tunnel block — a legitimate "no site-to-site tunnels up right now" state.

// Derives an IKE-version label ('IKEv1' | 'IKEv2' | null) from a block's
// Protocol field (e.g. "IKEv1 IPsec", "IKEv2 IPsec", "IPsec"). Returns null
// when neither version marker is present.
function l2lIkeVersion(protocol) {
  const p = typeof protocol === 'string' ? protocol.toLowerCase() : '';
  if (p.includes('ikev2')) return 'IKEv2';
  if (p.includes('ikev1')) return 'IKEv1';
  return null;
}

// Parses `show vpn-sessiondb l2l` output → normalized tunnel[] (see the section
// header above). Each element:
//   { name, peer, status, ike_version, bytes_in, bytes_out, raw }
// Fails closed: [] on empty/non-string input or on ANY internal error.
function parseVpnSessiondbL2l(text) {
  const out = [];
  if (typeof text !== 'string' || text.length === 0) return out;
  try {
    const clean = text.replace(/\r/g, '');

    for (const block of clean.split(/\n\s*\n/)) {
      const f = {};
      let any = false;
      for (const line of block.split('\n')) {
        for (const [k, v] of parseSessiondbLinePairs(line)) {
          const key = k.toLowerCase().replace(/[^a-z0-9]/g, '');
          if (key && v !== '') {
            f[key] = v;
            any = true;
          }
        }
      }
      if (!any) continue;

      // A real tunnel block is identified by its peer address (the "Connection"
      // field). Header/footer/summary blocks (e.g. a lone "Session Type:" line)
      // carry no Connection and are skipped — mirrors parseVpnSessiondbDetail()'s
      // identity guard.
      const peer = f.connection || null;
      const tunnelGroup = f.tunnelgroup || null;
      if (!peer && !tunnelGroup) continue;

      out.push({
        // name: the tunnel-group name if present, else the peer.
        name: tunnelGroup || peer,
        peer,
        // A block appearing in `show vpn-sessiondb l2l` IS an established
        // session; there is no per-block "down" state in this table (down
        // tunnels simply do not appear). 'up' is the normalized status.
        status: 'up',
        ike_version: l2lIkeVersion(f.protocol),
        bytes_in: parseSessiondbBytes(f.bytesrx),
        bytes_out: parseSessiondbBytes(f.bytestx),
        raw: f,
      });
    }
  } catch (err) {
    console.warn(`[CiscoASA parser] parseVpnSessiondbL2l: unexpected failure, returning [] — ${err.message}`);
    return [];
  }
  return out;
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
  parseVpnSessionSummary,
  parseVpnSessiondbDetail,
  parseVpnSessiondbL2l,
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
  parseSessiondbLinePairs,
  parseSessiondbDuration,
  parseSessiondbBytes,
  shortTunnelType,
  l2lIkeVersion,
};
