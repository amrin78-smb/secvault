// lib/syslog/junos.js
//
// The Junos RFC 5424 + STRUCTURED-DATA grammar, kept separate from
// vendorParsers.js for the same reason cef.js is: it is a distinct, mostly
// self-describing frame rather than another key=value dialect, and the vendor
// mapping that consumes it is a different concern from the bytes.
//
// ⛔ EVERY RULE HERE WAS MEASURED against a 105-line corpus of real
// (anonymised) SRX output — 43 MSGIDs, 42 distinct event shapes, 145 distinct
// structured-data keys. Full analysis, including the per-line evidence for
// each ⛔ below: secvault-lab/findings/JUNIPER-SYSLOG.md.
//
// ⛔ THE CORPUS IS THIRD-PARTY AND ANONYMISED. It is a step up from
// documentation and it is NOT a live device. Where a choice here could not be
// settled from it, this file says so rather than guessing.

'use strict';

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------
//
// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID k="v" ...]
//
// ⛔ THE VERSION DIGIT IS ABSENT ON 11 OF 105 LINES, so it cannot be required.
// ⛔ 19 LINES CARRY NO STRUCTURED DATA AT ALL — the message is free prose
// (kmd IKE negotiation, kernel FW: filter lines). Those still parse; they
// simply have no SD map, which is a different thing from an empty one.
const HEADER_RE = new RegExp(
  '^<(\\d{1,3})>'            // PRI
  + '(\\d{1,2})?\\s*'        // VERSION — optional, 11/105 omit it
  + '(\\S+)\\s+'             // TIMESTAMP
  + '(\\S+)\\s+'             // HOSTNAME
  + '(\\S+)\\s+'             // APP-NAME  ('-' on 10 lines)
  + '(\\S+)\\s+'             // PROCID    (almost always '-')
  + '(\\S+)'                 // MSGID     ('-' on 18 lines)
  + '(?:\\s+([\\s\\S]*))?$'  // the rest: SD block and/or free text
);

// ⛔ ANCHORED ON THE MSGID VOCABULARY, **NEVER ON THE SD-ID**. The corpus's
// `junos@...` enterprise id is destroyed by anonymisation in FOUR incompatible
// ways, two of them containing the letter `x` (`junos@xxx.x.x.x.x.28`) — so it
// is not even numeric there — and 5 flow lines prove it is OPTIONAL on a real
// device anyway. A parser anchored on it would be untestable against the
// corpus AND wrong against a device that omits it.
// ⛔ `sshd`, `snmpd`, `mgd` AND `eventd` WERE REMOVED, and their presence
// contradicted this file's own reasoning 30 lines down. A generic
// `<38>1 ... web01 sshd 1234 - - Failed password for root` from any Linux host
// was claimed as JUNIPER — that web server then appeared on
// /devices/discovered as a Juniper candidate with the vendor prefilled. The
// `kernel` line below is declined for exactly this reason; `sshd` and `snmpd`
// are no less generic.
//
// ⛔ MEASURED FREE: removing all four leaves the corpus at 96 of 105 claimed,
// because every corpus line carrying those app-names is already claimed by
// JUNOS_MSGID_RE (`SSHD_LOGIN_FAILED`, `SNMPD_AUTH_FAILURE`). `mgd` and
// `eventd` had ZERO corpus lines at all — speculative additions against this
// file's own "says so rather than guessing" header.
//
// What remains is load-bearing: `kmd` anchors 5 free-text IKE lines that carry
// no MSGID, and `mib2d` one.
const JUNOS_APPS = new Set([
  'RT_FLOW', 'RT_IDP', 'RT_IDS', 'RT_UTM', 'RT_AAMW', 'RT_SECINTEL',
  'kmd', 'dot1xd', 'mib2d', 'rpd',
]);
const JUNOS_MSGID_RE = /^(?:RT_|APPTRACK_|WEBFILTER_|AV_|ANTISPAM_|CONTENT_FILTERING_|IDP_|SECINTEL_|KMD_|SSHD_|SNMPD_|SNMP_TRAP_|DOT1XD_|RPD_|UI_)[A-Z0-9_]+$/;

// ⛔ THE PACKET-FILTER LINES HAVE NO APP-NAME AND NO MSGID, and they carry a
// real 5-tuple that nothing else would collect:
//
//   <158>1 ... kernel - - - FW: gr-0/0/0.14 A udp 127.0.0.1 89.160.20.112 49153 49153
//   <158>1 ... - - - - node1.fpc0 PFE_FW_SYSLOG_IP: FW: reth5.175 A pim 67.43.156.1 ...
//
// Claimed on the Junos INTERFACE GRAMMAR after `FW:` — `ge-`/`xe-`/`et-`/`gr-`/
// `reth`/`ae`/`st0`/`fxp`/`lo0` with Junos's slot/pic/port or unit numbering.
// That shape is not something another vendor emits after a literal `FW:`.
const JUNOS_FW_FILTER_RE = /(?:^|\s)FW:\s+(?:(?:ge|xe|et|gr|ip|lt|mt|vt|si|st)-\d+\/\d+\/\d+|reth\d+|ae\d+|st0|fxp\d+|lo0)[.\d]*\s/;

/** True when a line looks like Junos STRUCTURED-DATA syslog. */
function looksJunosStructured(message) {
  if (typeof message !== 'string') return false;
  const m = HEADER_RE.exec(message);
  if (!m) return false;
  const app = m[5];
  const msgid = m[7];
  if (JUNOS_APPS.has(app)) return true;
  if (JUNOS_MSGID_RE.test(msgid)) return true;
  if (JUNOS_FW_FILTER_RE.test(message)) return true;
  // The SD-ID is the LAST resort, not the first, and only as a positive hint.
  if (/\[junos@/.test(message)) return true;

  // ⛔ NINE CORPUS LINES ARE DELIBERATELY NOT CLAIMED, and that is the correct
  // answer rather than a gap. They are free-prose daemon messages with no
  // APP-NAME, no MSGID and no structured data — `ip_mon_reth_scan`,
  // `ha_rto_stats_handler`, `dpdk_eth_devstart`, `nh_fabric_fill_jnhinfo` —
  // carrying not one field SecVault maps: no 5-tuple, no zone, no rule, no
  // action. Declining them costs nothing.
  //
  // ⛔ And one of them settles it:
  //     <43>1 ... host-1.example.local kernel - - - ... kernel: Can't assign requested address
  // That is a GENERIC KERNEL MESSAGE any Linux host emits. A detector loose
  // enough to claim it would attribute other vendors' — and non-firewall —
  // syslog to Juniper, and this file's own header is that a guessed vendor
  // silently mis-parses every field after it. An unattributed line is stored
  // unattributed, which is the same answer any unrecognised line gets.
  return false;
}

// ⛔ BRIEF (RFC 3164) JUNOS — DETECTED, DELIBERATELY NOT PARSED.
//
// `structured-data` is NOT the Junos default. Without
// `set system syslog host <ip> structured-data`, an SRX emits:
//
//     <14>Nov 19 09:37:51 SRX-GW1 RT_FLOW_SESSION_CREATE: session created ...
//
// The verifying corpus contains ZERO such lines, so no field mapping for them
// has been verified and writing one from documentation is what this codebase
// forbids.
//
// ⛔ BUT SILENCE IS THE WORST AVAILABLE ANSWER. A device whose format we do
// not recognise and a device sending nothing are indistinguishable from the
// inside — the failure shape CLAUDE.md names more than any other. So a brief
// line is RECOGNISED AS JUNOS and reported as a named, actionable gap
// ("this SRX is sending brief-format syslog; enable structured-data") rather
// than falling through to the unattributed bucket.
const JUNOS_BRIEF_RE = new RegExp(
  '^<\\d{1,3}>'
  + '[A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}\\s+'  // RFC 3164 stamp
  + '\\S+\\s+'                                                // hostname
  + '((?:RT_|APPTRACK_|WEBFILTER_|AV_|ANTISPAM_|IDP_|SECINTEL_|KMD_|SSHD_|UI_)[A-Z0-9_]+):'
);

function looksJunosBrief(message) {
  return typeof message === 'string' && JUNOS_BRIEF_RE.test(message);
}

// ---------------------------------------------------------------------------
// Structured data
// ---------------------------------------------------------------------------

/**
 * Parse the SD block(s) into one flat key→value map.
 *
 * ⛔ RFC 5424 ESCAPING IS REAL HERE AND SCANNING TO THE FIRST `]` IS WRONG.
 * The corpus's `system:2` line carries an escaped `\]` INSIDE a value, so a
 * first-`]` scan truncates a VPN event mid-field and silently drops every key
 * after it. `\"`, `\]` and `\\` are all unescaped on the way out.
 *
 * ⛔ TOLERATES TYPOGRAPHIC QUOTES. 6 corpus lines delimit values with U+201C /
 * U+201D across 15 keys (including `destination-interface-name` and
 * `rule-name`). That is almost certainly a documentation-paste artefact in the
 * corpus rather than something a device emits — but accepting them costs
 * nothing and Elastic's own pipeline leaves the curly quotes INSIDE the value
 * (`'”st0.0”'`), which is a wrong interface name in an index.
 *
 * @returns {{ sd: object|null, sdIds: string[], text: string|null }}
 *   `sd: null` means NO structured data was present at all — 19 of 105 lines.
 *   That is a different fact from an empty map and must not be collapsed.
 */
function parseStructuredData(rest) {
  if (typeof rest !== 'string' || rest === '') return { sd: null, sdIds: [], text: null };
  const sd = {};
  const sdIds = [];
  let i = 0;
  let found = false;

  while (i < rest.length) {
    if (rest[i] !== '[') break;
    i += 1;
    // ⛔ THE SD-ID IS OPTIONAL AND THIS USED TO CONSUME THE FIRST KEY=VALUE PAIR
    // WHEN IT WAS ABSENT. Measured on the corpus: 5 modern-vSRX lines carry no
    // `junos@...` id, so `source-address="10.1.1.100"` was eaten as the SD-ID
    // and `srcIp` came back NULL on RT_FLOW_SESSION_CREATE and
    // APPTRACK_SESSION_VOL_UPDATE; on the CLOSE lines the scan stopped at the
    // space INSIDE `reason="TCP CLIENT RST"`, losing `reason` and leaving
    // `CLIENT` and `RST"` as orphan tokens. Elastic's own expected.json
    // reports source.ip on all five, which is independent corroboration.
    //
    // ⛔ ON A MODERN vSRX FLEET THAT IS EVERY TRAFFIC ROW, not 5 of 105: the
    // id is a 2010s artefact. A traffic row with no source IP cannot feed
    // `log_hit` (CVE priority rule 2), segmentation, or any talker rollup.
    //
    // ⛔ THE TEST IS "CONTAINS NO `=`", which is Elastic's own pattern
    // (`\[([^=]+?\s)?`) and the findings document's section 8 step 3. It is
    // peeked and only then consumed — a token holding an `=` is a key=value
    // pair and belongs to the loop below, not to the id.
    let id = '';
    let j = i;
    while (j < rest.length && rest[j] !== ' ' && rest[j] !== ']') { id += rest[j]; j += 1; }
    if (id.indexOf('=') === -1) {
      sdIds.push(id);
      i = j;
    }
    found = true;

    while (i < rest.length && rest[i] !== ']') {
      while (i < rest.length && rest[i] === ' ') i += 1;
      if (i >= rest.length || rest[i] === ']') break;
      let key = '';
      while (i < rest.length && rest[i] !== '=' && rest[i] !== ']' && rest[i] !== ' ') {
        key += rest[i]; i += 1;
      }
      if (rest[i] !== '=') { if (rest[i] === ']') break; i += 1; continue; }
      i += 1; // past '='
      const q = rest[i];
      let val = '';
      if (q === '"' || q === '“' || q === '”') {
        i += 1;
        while (i < rest.length) {
          const ch = rest[i];
          // ⛔ The escape branch. Without it, `\]` ends the SD block early.
          if (ch === '\\' && i + 1 < rest.length) { val += rest[i + 1]; i += 2; continue; }
          if (ch === '"' || ch === '“' || ch === '”') { i += 1; break; }
          val += ch; i += 1;
        }
      } else {
        while (i < rest.length && rest[i] !== ' ' && rest[i] !== ']') { val += rest[i]; i += 1; }
      }
      // ⛔ A value present but EMPTY is absent information, not an empty
      // string — the call every parser in this directory makes.
      if (key) sd[key] = val === '' ? null : val;
    }
    if (rest[i] === ']') i += 1;
    while (i < rest.length && rest[i] === ' ') i += 1;
  }

  const text = i < rest.length ? rest.slice(i).trim() || null : null;
  // ⛔ AN SD BLOCK THAT YIELDED NO KEYS IS NOT AN SD BLOCK. Free prose opening
  // with a bracket (`[FW] something happened`) set `found` and returned
  // `sd: {}`, which breaks this function's own documented contract — `sd: null`
  // means NO structured data was present, a different fact from an empty map —
  // and, because the packet-filter path is gated on `sd === null`, it also
  // skipped `FW:` parsing on exactly such a line.
  const real = found && Object.keys(sd).length > 0;
  return { sd: real ? sd : null, sdIds: real ? sdIds : [], text: real ? text : rest.trim() || null };
}

/**
 * Split a Junos syslog line into its header parts plus structured data.
 * @returns {object|null} null when the line is not Junos-shaped at all.
 */
function parseJunosFrame(message) {
  const m = HEADER_RE.exec(message);
  if (!m) return null;
  const pri = Number(m[1]);
  const { sd, sdIds, text } = parseStructuredData(m[8] || '');
  const dash = (v) => (v === '-' || v === undefined ? null : v);
  return {
    pri: Number.isFinite(pri) ? pri : null,
    // ⛔ `PRI % 8`, NOT the raw PRI. Elastic stores the raw value in
    // `event.severity` (165 rather than 5), which is a facility+severity
    // composite read as a severity.
    severity: Number.isFinite(pri) ? pri % 8 : null,
    facility: Number.isFinite(pri) ? Math.floor(pri / 8) : null,
    version: m[2] ? Number(m[2]) : null,
    timestamp: dash(m[3]),
    hostname: dash(m[4]),
    appName: dash(m[5]),
    procId: dash(m[6]),
    msgId: dash(m[7]),
    sd,
    sdIds,
    text,
  };
}

module.exports = {
  HEADER_RE,
  JUNOS_APPS,
  JUNOS_MSGID_RE,
  JUNOS_BRIEF_RE,
  JUNOS_FW_FILTER_RE,
  looksJunosStructured,
  looksJunosBrief,
  parseStructuredData,
  parseJunosFrame,
};
