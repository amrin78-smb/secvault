// lib/syslog/vendorParsers.js
//
// Vendor payload extraction, applied to the `message` that syslogParser.js has
// already stripped the syslog frame from. Pure: no DB, no network, no clock.
//
// ⛔ EVERY FIELD MAPPING HERE WAS READ OFF REAL CAPTURED LOGS from this fleet
// (the preserved FWA archive, 2026-09-08), not from vendor documentation.
// CLAUDE.md: "Verify all field names against live responses before writing any
// parser — documentation lies." The exact sample lines are the fixtures in
// tests/vendorParsers.test.js, so the evidence lives next to the code.
//
// Verified sources:
//   Fortinet  FGT80FTK23018808 ("YCC"), FG200ETK18912640 ("OkeanosFOOD")
//   Palo Alto PAKFW-01 (10.248.12.11), TH-TUG-IDC-MAS (192.168.3.254)
//
// ⛔ Unknown means NULL. A field the log did not carry is null, never 0, ''
// or 'unknown'. `vendor` is null when detection is not confident — a guessed
// vendor silently mis-parses every field that follows it, which is worse than
// storing the raw message unparsed.

'use strict';

const net = require('node:net');

const { CEF_RE, parseCef, bySlotLabel } = require('./cef');

// The Junos RFC 5424 + structured-data grammar. Kept in its own module for the
// same reason cef.js is: it is a distinct frame, not another key=value dialect.
const {
  parseJunosFrame, looksJunosStructured, looksJunosBrief,
} = require('./junos');

// SonicOS Enhanced Syslog: the grammar and the `m=` dispatch catalogue. Split
// out for the same reason junos.js is — the tokenizer is not the loose
// key=value grammar the other vendors share.
const {
  sonicosBody, parseSonicosKv, splitSonicosAddress,
} = require('./sonicos');
const { classOf } = require('./sonicosCatalogue');

// Shared VPN auth vocabulary -- see that file for the pre-login trap.
const { classifyAuthOutcome } = require('./authOutcomes');

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

// Fortinet emits key=value starting with `date=` and always carries devid=.
const FORTINET_RE = /(^|\s)devid="?FG|(^|\s)devname="[^"]*"\s+devid=/;
// Palo Alto's payload is CSV whose 4th field is the log type, after a
// FUTURE_USE digit and a receive time.
// ⛔ CISCO ASA. Anchored on the `%ASA-<severity>-<msgid>:` banner, which is the
// one part of the format that is a stable published contract across firmware.
// Matched ANYWHERE in the message rather than at the start, because the banner
// follows a syslog header that `syslogParser` may or may not have stripped
// depending on whether the device was configured to emit one.
//
// ⛔ `-7-` (debug) and the `%ASA-session-` / `%ASA-auth-` variants exist; this
// matches the numeric form only, which is what the evidence in
// tests/fixtures/ciscoAsaSyslog.js covers.
const CISCO_ASA_RE = /%ASA-\d-(\d{6}):/;

const PALOALTO_RE = /^\d*,\d{4}\/\d{2}\/\d{2}\s\d{2}:\d{2}:\d{2},[^,]*,(TRAFFIC|THREAT|SYSTEM|CONFIG|HIPMATCH|GLOBALPROTECT|USERID|DECRYPTION|CORRELATION)\b/;

/**
 * @returns {string|null} a SecVault vendor slug, or null when not confident.
 *   Slugs match CLAUDE.md's canonical list (devices.vendor).
 */
function detectVendor(message) {
  if (typeof message !== 'string' || message.length === 0) return null;
  if (PALOALTO_RE.test(message)) return 'paloalto';
  if (FORTINET_RE.test(message)) return 'fortinet';
  if (CISCO_ASA_RE.test(message)) return 'cisco_asa';
  // ⛔ Sophos SFOS is also key=value, so it is tested AFTER Fortinet: the two
  // grammars are similar enough that an anchor loose enough to be tried first
  // could claim a Fortinet line. FortiOS spells it `logid=` and `type=`;
  // SFOS spells it `log_id=` and `log_type=`, and SFOS's is a quoted 12-digit
  // id. Both anchors are required — see looksSophos.
  if (looksSophos(message)) return 'sophos';
  // ⛔ CEF IS SELF-DESCRIBING, so the vendor comes out of the record rather
  // than out of a pattern we invent. A CEF line from a vendor SecVault does not
  // support returns null and is stored unattributed -- correct, and the same
  // answer any other unrecognised line gets.
  // ⛔ JUNIPER IS TESTED AFTER THE KEY=VALUE VENDORS AND BEFORE CEF, and the
  // ordering is free rather than load-bearing: none of the four anchors above
  // can match an RFC 5424 Junos frame (PALOALTO_RE needs a leading CSV stamp,
  // FORTINET_RE needs `devid=FG`, CISCO_ASA_RE needs the `%ASA-n-nnnnnn:`
  // banner, looksSophos needs `log_id=` AND `log_type=`), and no Junos line
  // carries any of them. It sits here so the cheap anchors run first.
  //
  // ⛔ BRIEF-FORMAT JUNOS IS CLAIMED TOO, AND THAT IS THE POINT. `structured-data`
  // is not the Junos default, so an SRX configured without it emits RFC 3164 lines this
  // parser cannot map. Returning null for those would make a misconfigured
  // firewall indistinguishable from one sending nothing — the failure shape
  // CLAUDE.md names more than any other. parseJuniper answers such a line with
  // a NAMED GAP instead of a guess.
  // ⛔ CEF IS TESTED BEFORE THE TWO NEWEST DETECTORS, AND IT USED TO BE AFTER
  // THEM — a regression this file's own rule four lines down already forbade:
  // "CEF IS SELF-DESCRIBING, so the vendor comes out of the record rather than
  // out of a pattern we invent." A CEF record whose extension happens to carry
  // `id=`, `sn=`, `fw=` and `pri=<digit>` satisfies looksSonicwall, so a valid
  // Check Point line was claimed as SonicWall and parsed by the wrong grammar:
  // measured, vendor checkpoint->sonicwall, action `drop`->null, both addresses
  // ->null, ruleName `Cleanup`->null, logClass traffic->null. A BLOCKED
  // connection then leaves the denied-traffic rollups, the threat view and
  // `log_hit` (priority-tree rule 2) at once.
  //
  // ⛔ The trigger was synthetic and the live exposure was zero — this fleet
  // runs no CEF device — but a self-describing record must outrank an invented
  // anchor on principle, and CEF_RE (/CEF:\d+\|/) is cheaper than either
  // detector it now precedes. ⛔ Its position relative to the four ABOVE is
  // unchanged and deliberately so: that ordering is live-verified.
  if (CEF_RE.test(message)) return cefVendorSlug(message);
  if (looksJunosStructured(message) || looksJunosBrief(message)) return 'juniper';
  // ⛔ SonicWall is tested AFTER Sophos and Fortinet for the same reason Sophos
  // is tested after Fortinet: three key=value grammars that a loose anchor
  // could confuse. Its own anchor is three keys that are each 220/220 in the
  // corpus (`sn=`, `fw=`, `pri=`), which no other vendor here emits together.
  if (looksSonicwall(message)) return 'sonicwall';
  // Deliberately no fallback. See this file's header.
  return null;
}

// ---------------------------------------------------------------------------
// log_class — the event's KIND, normalized across vendors
// ---------------------------------------------------------------------------
//
// Computed once here, stored on the row, and never re-derived by a query.
// Without it the VPN and threat dashboards matched `message LIKE '%subtype=
// "vpn"%'` against the raw table: 2.5s at 4M rows, and ~400s at the 7-day
// steady state of ~650M. Same fix, same reason, as LogVault's `srcip` column.
//
// ⛔ Returns null when the payload does not say. There is no 'other' bucket:
// an unclassified event is a gap in this mapping, and it should look like one.
//
// Classes observed live on this fleet: traffic, threat, vpn, utm, system, event.

function classifyPaloAlto(type) {
  if (typeof type !== 'string') return null;
  switch (type.toUpperCase()) {
    case 'TRAFFIC': return 'traffic';
    case 'THREAT': return 'threat';
    case 'GLOBALPROTECT': return 'vpn';
    case 'SYSTEM': return 'system';
    case 'CONFIG': return 'config';
    case 'USERID': return 'userid';
    case 'HIPMATCH': return 'hipmatch';
    case 'DECRYPTION': return 'decryption';
    case 'CORRELATION': return 'correlation';
    default: return null;
  }
}

function classifyFortinet(type, subtype) {
  const t = typeof type === 'string' ? type.toLowerCase() : null;
  const s = typeof subtype === 'string' ? subtype.toLowerCase() : null;
  if (t === null) return null;
  // FortiOS puts VPN under event/vpn, so the SUBTYPE decides here — classifying
  // on `type` alone would file VPN activity as generic 'event' and the VPN
  // dashboard would silently show nothing.
  if (t === 'event' && s === 'vpn') return 'vpn';
  if (t === 'traffic') return 'traffic';
  if (t === 'utm') return 'utm';
  if (t === 'event') return 'event';
  if (t === 'anomaly') return 'threat';
  return null;
}

// ---------------------------------------------------------------------------
// Fortinet: space-separated key=value, values optionally double-quoted
// ---------------------------------------------------------------------------

/**
 * Split a FortiOS log line into a plain object.
 * Handles quoted values containing spaces (`policyname="Allow web out"`) and
 * bare values (`srcport=57104`). Never throws.
 */
function parseKeyValue(message) {
  const out = {};
  if (typeof message !== 'string') return out;
  // key=value where value is "quoted" (allowing escaped quotes) or bare.
  const re = /([A-Za-z0-9_.-]+)=("(?:[^"\\]|\\.)*"|[^\s]*)/g;
  let m;
  while ((m = re.exec(message)) !== null) {
    const key = m[1];
    let val = m[2];
    if (val.length >= 2 && val.startsWith('"') && val.endsWith('"')) {
      val = val.slice(1, -1).replace(/\\"/g, '"');
    }
    // An explicitly empty value is absent information, not an empty string.
    out[key] = val === '' ? null : val;
  }
  return out;
}

// ⛔ Validate the STRING before converting. Number('  ') is 0, so a
// present-but-blank numeric field (srcport=" ") became a measured zero rather
// than null -- the hit_count DEFAULT 0 pattern in miniature. syslogParser.js
// already guards this exact trap when decoding PRI; this did not.
function toIntOrNull(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  if (!/^-?\d+$/.test(s)) return null;
  const n = Number(s);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

/**
 * FortiOS -> normalized event.
 *
 * ⛔ `eventtime` is a NANOSECOND epoch on the firmware in this fleet
 * (e.g. 1788282206708308100, 19 digits) and is paired with `tz="+0700"`. It is
 * far more precise than the date/time pair and carries no year ambiguity, so
 * it is preferred. Dividing by 1e6 gives milliseconds.
 */
function parseFortinet(message) {
  const f = parseKeyValue(message);

  let eventAt = null;
  // ⛔ Scale by DIGIT LENGTH, never a fixed divisor. The old guard accepted
  // 16-20 digits and always divided by 1e6, but 16 digits is a MICROsecond
  // epoch: a valid µs value parsed to 1970-01-21, silently backdating the row
  // out of every time-window query and every rollup bucket while leaving it
  // present. FortiOS emits seconds on 6.0 and earlier and nanoseconds on 6.2+,
  // so the tolerant range was right and the arithmetic was not.
  const ns = f.eventtime;
  if (ns && /^\d+$/.test(ns)) {
    const digits = ns.length;
    const divisor =
      digits === 19 ? 1e6      // nanoseconds  (what this fleet sends)
        : digits === 16 ? 1e3  // microseconds
          : digits === 13 ? 1  // milliseconds
            : digits === 10 ? 1 / 1000  // seconds
              : null;
    if (divisor !== null) {
      const ms = Number(ns) / divisor;
      if (Number.isFinite(ms)) {
        const d = new Date(Math.round(ms));
        if (!Number.isNaN(d.getTime())) eventAt = d;
      }
    }
  }
  if (eventAt === null && f.date && f.time) {
    // Fall back to date + time + the tz the device itself reported. If tz is
    // absent we do NOT invent one — an unanchored local time is exactly the
    // ambiguity that makes RFC 3164 painful, so leave it null.
    const tz = typeof f.tz === 'string' && /^[+-]\d{4}$/.test(f.tz)
      ? f.tz.slice(0, 3) + ':' + f.tz.slice(3)
      : null;
    if (tz) {
      const d = new Date(`${f.date}T${f.time}${tz}`);
      if (!Number.isNaN(d.getTime())) eventAt = d;
    }
  }

  // Hoisted: threatSeverity below needs it, and re-deriving it there could
  // drift from what is actually stored.
  const logClass = classifyFortinet(f.type, f.subtype);

  return {
    vendor: 'fortinet',
    eventAt,
    deviceName: f.devname || null,
    deviceSerial: f.devid || null,
    logType: f.type || null,
    // Normalized kind, stored once at ingest so no query has to re-derive it.
    logClass,
    logSubtype: f.subtype || null,
    level: f.level || null,
    action: f.action || null,
    // ⛔ VPN rows carry the remote peer as `remip=`, not `srcip=`, which is why
    // src_ip was NULL on 100% of Fortinet VPN rows — and why a per-source view
    // of failed logins had nothing to group by. `srcip` still wins where both
    // are present; this only fills a gap, it never overrides.
    srcIp: f.srcip || f.remip || null,
    dstIp: f.dstip || null,
    srcPort: toIntOrNull(f.srcport),
    dstPort: toIntOrNull(f.dstport),
    protocol: f.proto || null,
    service: f.service || null,
    application: f.app || null,
    srcInterface: f.srcintf || null,
    dstInterface: f.dstintf || null,
    // FortiOS traffic logs identify by INTERFACE, not by zone — there is no
    // zone field to read, so these stay null rather than borrowing the
    // interface name and pretending it is a zone.
    srcZone: null,
    dstZone: null,
    // ⛔ The rule linkage. policyid is the FortiOS policy number and poluuid is
    // the same UUID SecVault already stores on firewall_rules — this pair is
    // what will let log evidence produce real hit counts for the SSH transport,
    // which cannot report them via the API at all.
    ruleId: f.policyid === null || f.policyid === undefined ? null : String(f.policyid),
    ruleUuid: f.poluuid || null,
    ruleName: f.policyname || null,
    vdom: f.vd || null,
    // !! NEVER summable. FortiOS re-logs a long-lived session with a running
    // cumulative counter, so adding the rows counts the same bytes repeatedly
    // (measured: 87.6 Gbps implied fleet-wide). The per-event value is still
    // stored and is meaningful on its OWN; it just cannot be aggregated.
    bytesSummable: false,
    bytesSent: toIntOrNull(f.sentbyte),
    bytesReceived: toIntOrNull(f.rcvdbyte),
    sessionId: f.sessionid || null,
    // FortiOS names these directly, so there is no positional ambiguity.
    // ⛔ srccountry is often the literal "Reserved" -- that is FortiOS's own
    // word for an RFC1918 address, and it is kept verbatim rather than
    // rewritten to null or "Private". It is a real answer, not a missing one.
    srcUser: fortinetSrcUser(f),
    srcCountry: f.srccountry || null,
    dstCountry: f.dstcountry || null,
    urlCategory: f.appcat || null,
    urlHostname: f.hostname || f.sni || null,
    // ⛔ Only a REAL signature/virus name. `eventtype` is tempting here and
    // is wrong: on an app-ctrl row it reads "signature", which would fill the
    // threat-name column with a word that names nothing and would rank first
    // in every Top Threats report.
    threatName: meaningful(f.attack) || meaningful(f.virus) || null,
    // ⛔ `level` is FortiOS's SYSLOG severity, not a threat rating. Setting it
    // on every row stamped ordinary allowed traffic with a threat severity it
    // does not have -- measured live, ~5.5M rows/day of routine Fortinet
    // traffic carried threat_severity="notice"/"warning" while the equivalent
    // Palo Alto traffic rows correctly carried NULL, so any cross-vendor
    // "threats by severity" grouping was almost entirely fabricated.
    // Only populate it where a threat was actually assessed.
    threatSeverity:
      meaningful(f.attack) || meaningful(f.virus) || logClass === 'utm' || logClass === 'threat'
        ? f.level || null
        : null,
    // ⛔ VPN class only. FortiOS reports SSL-VPN auth through `action`, and
    // classifying a non-VPN row here would invent logins out of ordinary
    // traffic. Measured live over 12h on this fleet: 2,188 ssl-login-fail
    // against ZERO SSL-VPN successes — its success logids are absent, which is
    // a DEVICE-SIDE logging setting, not a gap SecVault can close. Any UI must
    // render that as "not reported", never as 0.
    //
    // ⛔ An earlier version of this comment said "~4 successes". That number
    // was CONTAMINATED, not sparse: every one of those rows was a site-to-site
    // IPsec tunnel coming up, counted as a user login because `tunnel-up` was
    // in the success set unconditionally. `tunneltype` is what separates the
    // two and MUST be passed — see authOutcomes.js.
    authOutcome: logClass === 'vpn'
      ? classifyAuthOutcome('fortinet', null, null, f.action, f.tunneltype)
      : null,
    // ⛔ VPN rows carry the remote peer as `remip=`, NOT `srcip=` — which is why
    // src_ip was NULL on 100% of Fortinet VPN rows.
    fields: f,
  };
}

// ---------------------------------------------------------------------------
// Palo Alto: positional CSV
// ---------------------------------------------------------------------------

// Field positions verified against captured TRAFFIC logs from PAKFW-01 and
// TH-TUG-IDC-MAS (PAN-OS 11.1). ⛔ These are POSITIONAL and differ per log
// TYPE — a THREAT row does not share TRAFFIC's layout past the common prefix,
// which is why only the common prefix plus TRAFFIC-verified indices are used.
const PAN_COMMON = {
  receiveTime: 1,
  serial: 2,
  type: 3,
  subtype: 4,
  generatedTime: 6,
  srcIp: 7,
  dstIp: 8,
  natSrcIp: 9,
  natDstIp: 10,
  ruleName: 11,
  srcUser: 12,
  dstUser: 13,
  application: 14,
  vsys: 15,
  srcZone: 16,
  dstZone: 17,
  srcInterface: 18,
  dstInterface: 19,
};
// ⛔ THREAT positions are DIFFERENT from TRAFFIC past index 30, and the two
// disagree about where COUNTRY lives (threat 38/39, traffic 41/42). Read off
// real captured THREAT rows from ITC-FW-MAIN on 2026-09-08, never from docs.
// A sample row, trimmed, with the indices that matter:
//   ...,30=block-url,31="www.bing.com/",32=(9999),
//      33=block-Deny Web-O365,34=informational,35=client-to-server,
//      36=<seqno>,37=<flags>,38=United States,39=Singapore
// ⛔ CORRECTED 2026-09-08, and the correction matters. `threatName` was read
// from index 33, which is the CATEGORY, not the name. Index 32 is the real
// "Threat/Content Name". Verified against captured vulnerability and spyware
// rows: 32 held "Phishing:bailliede.ru(109010001)" and "ISF SNMP
// Authentication Attempt(96504)" while 33 held "any".
//
// How the mistake happened is the part worth keeping. The map was first
// verified against a URL-FILTERING row, where index 32 is a bare "(9999)"
// placeholder and 33 looked like a plausible name — both readings fit that one
// subtype. CLAUDE.md already warns that PAN positions differ per log TYPE;
// they also differ in MEANING per SUBTYPE, and a single sample cannot show it.
//
// The cost of the bug: every real signature — phishing, malware and
// cryptomining detections — was stored as its URL category, so Top Threats
// showed "any" where it should have named the malware.
const PAN_THREAT = {
  url: 31,          // URL / filename
  threatName: 32,   // "Name(id)", e.g. Phishing:bailliede.ru(109010001)
  category: 33,     // URL/content category, e.g. "any", "social-networking"
  severity: 34,     // informational | low | medium | high | critical
  direction: 35,
  srcCountry: 38,
  dstCountry: 39,
};

// PAN writes a bare "(9999)" in the name field on URL-filtering rows: an id
// with no signature behind it. ⛔ That names nothing, so it becomes null rather
// than the top entry of every Top Threats chart.
// PAN-OS GLOBALPROTECT positional map.
//
// ⛔ VERIFIED AGAINST REAL CAPTURED LINES from TUM-FW-ACTIVE on 2026-09-09, not
// from documentation — three subtypes (portal-prelogin, gateway-hip-check,
// gateway-tunnel-latency) counted field by field. This is a SEPARATE map from
// PAN_COMMON precisely because PAN_COMMON is not common: from index 7 the
// layout is per log TYPE, which is why reading it on GlobalProtect rows
// produced srcIp="vsys1" and application="SM-A066B-<hostid>".
//
// ⛔ Index 27 is a QUOTED description that genuinely contains commas
// ("Pre-tunnel latency: 34ms, Post-tunnel latency: 26ms"), so this must be read
// with splitCsv() — a naive comma split shifts every field after it, including
// the status at 28.
const PAN_GLOBALPROTECT = {
  eventId: 8,      // portal-prelogin | portal-auth | gateway-auth | gateway-hip-check | ...
  stage: 9,        // before-login | login | host-info | tunnel | ...
  srcUser: 12,     // empty on pre-login rows, which is the tell that nobody authenticated
  srcRegion: 13,   // ISO-3166-1 alpha-2 (Fortinet emits full English names instead)
  machineName: 14,
  publicIp: 15,
  privateIp: 17,
  error: 26,
  description: 27, // QUOTED, contains commas
  status: 28,      // success | failure
};

// ⛔ ONLY these event ids are an AUTHENTICATION. Verified live, and the trap is
// real: `portal-prelogin` carries status=success on every row (the portal
// serving its pre-login page to an anonymous browser) and there were 3,399 of
// them in three hours. Reading `status` without gating on the event id would
// inflate "successful logins" by roughly an order of magnitude. The tell is
// that those rows carry no username at all.
//
// gateway-connected / gateway-register / gateway-setup-ipsec also carry
// success — they are later stages of the SAME login, so counting them turns
// one login into four.
const PAN_AUTH_EVENTS = new Set(['gateway-auth', 'portal-auth']);

// Subtypes whose byte counters are a non-overlapping total. 'end' is the
// session-close row; 'deny' is one-shot (there is no start/end pair for it),
// and excluding it left every "blocked traffic volume" figure reading zero.
// 'drop' is deliberately absent: those rows carry session_id 0 and may be
// repeat-aggregated, which is unverified against live data.
const PAN_SUMMABLE_SUBTYPES = new Set(['end', 'deny']);

// THREAT subtypes where positional index 31 is genuinely a URL. On 'file',
// 'data' and 'wildfire' rows the same index holds a FILENAME.
const PAN_URL_SUBTYPES = new Set(['url', 'spyware', 'vulnerability']);

const PAN_BARE_THREAT_ID = /^\(\d+\)$/;

const PAN_TRAFFIC = {
  sessionId: 22,
  repeatCount: 23,
  srcPort: 24,
  dstPort: 25,
  natSrcPort: 26,
  natDstPort: 27,
  flags: 28,
  protocol: 29,
  action: 30,
  bytesTotal: 31,
  bytesSent: 32,
  // Verified on the same captured rows: 37 is the URL category the firewall
  // assigned to the session, and 41/42 are the countries. ⛔ NOT the same
  // indices as PAN_THREAT above -- that is the whole reason both maps exist.
  urlCategory: 37,
  srcCountry: 41,
  dstCountry: 42,
  bytesReceived: 33,
  packets: 34,
};

/**
 * Split a CSV line honouring double-quoted fields (PAN-OS quotes any value
 * containing a comma — rule names and URLs routinely do). Never throws.
 */
function splitCsv(line) {
  const out = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuotes) {
      if (c === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; } else { inQuotes = false; }
      } else { cur += c; }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      out.push(cur); cur = '';
    } else { cur += c; }
  }
  out.push(cur);
  return out;
}

// Vendors write a literal placeholder when they have nothing to report.
// ⛔ That is the device SAYING "I do not know" -- so it must become null, not
// be stored as a value. Left as-is, "N/A" becomes the 5th busiest user on the
// Top Users chart, which is a fabricated fact dressed as a measurement.
// This is a NARROW list of unambiguous placeholders, not a general cleanup:
// anything not on it is kept verbatim, including FortiOS's "Reserved", which
// is a real answer about a private address rather than an absent one.
// ⛔ `null` added 2026-11-19 with the Sophos parser. SFOS writes the LITERAL
// FOUR CHARACTERS in a field named for a serial — `device_id=NULL` (unquoted)
// in the legacy format and `device_serial_id="NULL"` (quoted) in the standard
// one — on 100% of 6,341 captured lines. Without this, every Sophos row would
// store the string "NULL" as a device identity. Extended here rather than
// given a second per-vendor list, for the reason this file's header gives.
const NOT_AVAILABLE = new Set(['n/a', 'not-applicable', 'unknown', 'none', '-', 'null']);

function meaningful(v) {
  if (typeof v !== 'string') return v === undefined ? null : v;
  const t = v.trim();
  if (t === '') return null;
  return NOT_AVAILABLE.has(t.toLowerCase()) ? null : v;
}

// A bare IPv4 dotted quad, or an IPv6 literal.
const BARE_IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const BARE_IPV6 = /^[0-9a-f]*:[0-9a-f:]*$/i;

/**
 * The FortiOS user for an event, or null when the event names no user.
 *
 * ⛔ `user=` IS NOT ALWAYS A PERSON. On IPsec events FortiOS puts the PEER
 * GATEWAY ADDRESS there — the "user" of a site-to-site tunnel with no XAuth is
 * the peer itself, which is why those same rows carry `xauthuser="N/A"`.
 * Measured live 2026-09-10: ~4,000 Fortinet VPN rows in 12 hours (negotiate,
 * install_sa, delete_ipsec_sa, tunnel-stats) carried an address in `user`, and 8
 * distinct addresses had already reached the PERMANENT username list, where
 * they were indistinguishable from real accounts and fed three detections.
 *
 * ⛔ An address is not a NULL-shaped value, so `meaningful()` cannot catch it —
 * it is a real string that is simply the WRONG FACT. Storing it is this
 * codebase's failed-read-as-a-fact rule wearing a different hat.
 *
 * `xauthuser` is preferred because on an IPsec tunnel that DOES use XAuth it
 * holds the genuine account; on SSL-VPN rows it is absent, so `user` wins.
 */
function fortinetSrcUser(f) {
  const xauth = meaningful(f.xauthuser);
  if (xauth !== null && xauth !== undefined && String(xauth).trim() !== '') return xauth;
  const user = meaningful(f.user);
  if (user === null || user === undefined) return null;
  const t = String(user).trim();
  if (t === '') return null;
  return BARE_IPV4.test(t) || BARE_IPV6.test(t) ? null : user;
}

// A PAN threat name, or null when the field names nothing.
function panThreatName(v) {
  const m = meaningful(v);
  if (m === null) return null;
  return PAN_BARE_THREAT_ID.test(m.trim()) ? null : m;
}

function at(parts, idx) {
  if (idx === undefined || idx >= parts.length) return null;
  const v = parts[idx];
  return v === undefined || v === '' ? null : v;
}

/**
 * PAN-OS -> normalized event.
 * ⛔ `generatedTime` has NO timezone ("2026/07/09 10:23:12"), so it is read as
 * the collector's local zone, and `tzAssumed` says so. Only TRAFFIC rows get
 * the traffic-specific indices; other types keep the common prefix and leave
 * the rest null rather than reading the wrong column.
 */
function parsePaloAlto(message) {
  const p = splitCsv(message);
  const type = at(p, PAN_COMMON.type);
  const isTraffic = type === 'TRAFFIC';
  const isThreat = type === 'THREAT';
  // The two — and ONLY the two — log types whose positional layout this parser
  // has been verified against. See the gating note below.
  const isTrafficOrThreat = isTraffic || isThreat;
  const isGlobalProtect = type === 'GLOBALPROTECT';

  let eventAt = null;
  let tzAssumed = false;
  const gen = at(p, PAN_COMMON.generatedTime);
  if (gen && /^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}$/.test(gen)) {
    const d = new Date(gen.replace(/\//g, '-').replace(' ', 'T'));
    if (!Number.isNaN(d.getTime())) { eventAt = d; tzAssumed = true; }
  }

  return {
    vendor: 'paloalto',
    eventAt,
    tzAssumed,
    deviceName: null, // PAN-OS puts the hostname in the syslog header, not the CSV
    deviceSerial: at(p, PAN_COMMON.serial),
    logType: type,
    logClass: classifyPaloAlto(type),
    // ⛔ On GlobalProtect rows index 4 is the Threat/Content type ("0"), not a
    // subtype — the real one is the Event ID at index 8. Reading index 4 left
    // every VPN row's log_subtype as the string "0".
    logSubtype: isGlobalProtect
      ? meaningful(at(p, PAN_GLOBALPROTECT.eventId))
      : at(p, PAN_COMMON.subtype),
    level: null,
    // ⛔ Index 30 is the action on THREAT rows too, not just traffic, and it
    // is the difference between a threat that was BLOCKED and one merely
    // OBSERVED -- verified on captured rows: spyware carried "drop",
    // vulnerability carried "alert", url-filtering carried "block-url".
    // Gating it on isTraffic left every threat row with action null, so the
    // dashboards could not say whether anything was actually stopped.
    action: (isTraffic || isThreat) ? at(p, PAN_TRAFFIC.action) : null,
    // ⛔ EVERY PAN_COMMON READ BELOW IS GATED ON isTraffic || isThreat.
    // PAN_COMMON is NOT common: from index 7 onward the layout is per log
    // TYPE, and only TRAFFIC and THREAT share it. Reading it unconditionally
    // filled GLOBALPROTECT / SYSTEM / CONFIG / USERID / HIPMATCH rows with
    // real-looking values from the wrong columns -- verified against captured
    // rows already in the database:
    //   GLOBALPROTECT: srcIp="vsys1", dstIp="gateway-hip-check",
    //                  application="SM-A066B-<hostid>", srcZone="0.0.0.0"
    //   SYSTEM:        application=<the Description text>, srcUser="general"
    //                  (a MODULE name, fabricated onto the Top Users chart),
    //                  vdom=<sequence number>
    // Only indices 1/2/3/6 (receiveTime, serial, type, generatedTime) are
    // genuinely universal. Anything else stays NULL for a type whose layout
    // this parser has not been verified against -- unparsed is recoverable,
    // fabricated is not.
    // GlobalProtect carries the client's PUBLIC address at its own index 15.
    srcIp: isTrafficOrThreat
      ? at(p, PAN_COMMON.srcIp)
      : isGlobalProtect
        ? at(p, PAN_GLOBALPROTECT.publicIp)
        : null,
    dstIp: isTrafficOrThreat ? at(p, PAN_COMMON.dstIp) : null,
    // ⛔ Ports/protocol/session are valid on THREAT rows too -- the layout is
    // identical up to index 30, which is why `action` above already reads
    // there. Gating them on isTraffic left EVERY threat row with a null
    // dst_port (~900k/day), and dst_port is precisely what CLAUDE.md's
    // log_hit definition requires ("traffic ARRIVING ... on that port").
    srcPort: isTrafficOrThreat ? toIntOrNull(at(p, PAN_TRAFFIC.srcPort)) : null,
    dstPort: isTrafficOrThreat ? toIntOrNull(at(p, PAN_TRAFFIC.dstPort)) : null,
    protocol: isTrafficOrThreat ? at(p, PAN_TRAFFIC.protocol) : null,
    service: null,
    application: isTrafficOrThreat ? at(p, PAN_COMMON.application) : null,
    srcInterface: isTrafficOrThreat ? at(p, PAN_COMMON.srcInterface) : null,
    dstInterface: isTrafficOrThreat ? at(p, PAN_COMMON.dstInterface) : null,
    // PAN-OS does carry real zones, and SecVault already classifies zones per
    // device (zone_classifications), so these are worth keeping.
    srcZone: isTrafficOrThreat ? at(p, PAN_COMMON.srcZone) : null,
    dstZone: isTrafficOrThreat ? at(p, PAN_COMMON.dstZone) : null,
    // PAN-OS identifies the rule by NAME, not by a numeric id or uuid.
    ruleId: null,
    ruleUuid: null,
    ruleName: isTrafficOrThreat ? at(p, PAN_COMMON.ruleName) : null,
    vdom: isTrafficOrThreat ? at(p, PAN_COMMON.vsys) : null,
    // Only a non-overlapping total may be summed. A `start` row reports bytes
    // so far and would double-count against its own `end` row; a `deny` row is
    // one-shot (there is no matching pair), so its bytes are safe and were
    // previously excluded, leaving "blocked traffic volume" reading zero.
    // `drop` is deliberately NOT included: those rows carry session_id 0 and
    // may be repeat-aggregated, which is unverified.
    bytesSummable: isTraffic && PAN_SUMMABLE_SUBTYPES.has(
      String(at(p, PAN_COMMON.subtype) || '').toLowerCase()
    ),
    // ⛔ isTraffic ONLY, unlike the ports above, and the boundary is exactly
    // index 30. Everything up to and including `action` (22/24/25/29/30) is
    // the SHARED prefix and is valid on a threat row; from 31 onward the
    // layouts diverge -- on a THREAT row index 31 is the URL, 32 is the threat
    // NAME and 33 is the category. Reading bytes there would store a signature
    // string as a byte count.
    bytesSent: isTraffic ? toIntOrNull(at(p, PAN_TRAFFIC.bytesSent)) : null,
    bytesReceived: isTraffic ? toIntOrNull(at(p, PAN_TRAFFIC.bytesReceived)) : null,
    sessionId: isTrafficOrThreat ? at(p, PAN_TRAFFIC.sessionId) : null,
    // ⛔ Each of these is read from the map for THIS log type only. Reading a
    // threat index out of a traffic row (or the reverse) returns a real,
    // plausible, WRONG value -- traffic index 38 is a flags field, not a
    // country. Anything not present for this type stays null.
    srcUser: isTrafficOrThreat
      ? meaningful(at(p, PAN_COMMON.srcUser))
      : isGlobalProtect
        ? meaningful(at(p, PAN_GLOBALPROTECT.srcUser))
        : null,
    // ⛔ GlobalProtect emits ISO alpha-2 (US, TH) where Fortinet emits full
    // English names (United States). Kept verbatim here — the vendor's own
    // answer — because normalising is a consumer concern, not something the
    // parser should guess at.
    srcCountry: isTraffic
      ? at(p, PAN_TRAFFIC.srcCountry)
      : isThreat
        ? at(p, PAN_THREAT.srcCountry)
        : isGlobalProtect
          ? meaningful(at(p, PAN_GLOBALPROTECT.srcRegion))
          : null,
    dstCountry: isTraffic ? at(p, PAN_TRAFFIC.dstCountry)
      : isThreat ? at(p, PAN_THREAT.dstCountry) : null,
    // Threat rows carry a category too, at their OWN index. Keeping it means
    // the category is not lost now that threatName reads the real signature.
    // ⛔ meaningful() on BOTH branches. It was applied only to threat rows, so
    // the placeholder 'unknown' was nulled on one class and stored as a real
    // category on the other — live, 34 paloalto/traffic rows per 4 minutes
    // carried url_category='unknown'. A "Top Categories" chart spanning both
    // classes then counts the placeholder as a category, from one class only.
    urlCategory: isTraffic ? meaningful(at(p, PAN_TRAFFIC.urlCategory))
      : isThreat ? meaningful(at(p, PAN_THREAT.category)) : null,
    // ⛔ Index 31 is "URL **or Filename**" depending on subtype. On file/data/
    // wildfire rows it is a FILENAME, and storing that in a hostname column put
    // `audit.csv`, `Registry.pol` and a base64 digest into "Top hosts visited".
    // Only the subtypes where the field is genuinely a URL are kept.
    urlHostname: isThreat && PAN_URL_SUBTYPES.has(String(at(p, PAN_COMMON.subtype) || '').toLowerCase())
      ? meaningful(at(p, PAN_THREAT.url))
      : null,
    threatName: isThreat ? panThreatName(at(p, PAN_THREAT.threatName)) : null,
    threatSeverity: isThreat ? at(p, PAN_THREAT.severity) : null,
    // ⛔ Gated on the EVENT ID first, then status -- see authOutcomes.js. Reading
    // status alone would count every portal-prelogin page fetch as a login.
    authOutcome: isGlobalProtect
      ? classifyAuthOutcome("paloalto", at(p, PAN_GLOBALPROTECT.eventId), at(p, PAN_GLOBALPROTECT.status), null)
      : null,
    fields: null, // positional format — no key/value map to keep
  };
}

// PAN-OS and FortiOS use DIFFERENT severity vocabularies for the same idea,
// so a "threats by severity" chart that groups on the raw string splits one
// level across two labels. This maps both onto one ordered scale.
//
// ⛔ Returns null for anything unrecognized -- never a default level. A
// threat filed under the wrong severity is worse than one filed under none,
// and this is the same failed-read-is-not-a-measurement rule as everywhere
// else in this codebase.
const THREAT_SEVERITY_RANK = {
  // PAN-OS
  informational: 1, low: 2, medium: 3, high: 4, critical: 5,
  // FortiOS (`level=`)
  debug: 0, information: 1, notice: 1, warning: 2, error: 3, alert: 4, emergency: 5,
};

/**
 * @param {unknown} raw the vendor's own severity word
 * @returns {number|null} 0-5, or null when the word is not one we know
 */
function threatSeverityRank(raw) {
  if (typeof raw !== 'string') return null;
  const v = THREAT_SEVERITY_RANK[raw.trim().toLowerCase()];
  return typeof v === 'number' ? v : null;
}

/**
 * Detect and parse in one step.
 * @returns {object|null} normalized event, or null when the vendor is not
 *   recognised. The caller stores the raw message either way.
 */
// ---------------------------------------------------------------------------
// Cisco ASA
// ---------------------------------------------------------------------------
//
// ⛔ WRITTEN FROM THIRD-PARTY CAPTURES, NOT FROM A LIVE DEVICE, AND NOT FROM
// DOCUMENTATION. SecVault's fleet carries no ASA, so the evidence is
// logstash-patterns-core's Apache-2.0 regression fixtures, corroborated against
// Elastic's independently-maintained ones (not copied — they are ELv2). Full
// provenance, and what that evidence does NOT establish, is in
// tests/fixtures/ciscoAsaSyslog.js. The first real ASA is still a verification
// step.
//
// ⛔ ONLY THE MESSAGE IDS BELOW ARE PARSED, and that gating is deliberate —
// the same call parsePaloAlto makes about TRAFFIC/THREAT. The ASA emits
// hundreds of message IDs; claiming to parse one whose layout has never been
// seen would invent fields. An unrecognised id yields the ENVELOPE ONLY
// (vendor, severity, msgId) with every data field null, which is honestly
// "received, not understood" rather than a fabricated row.
const ASA_PARSED_IDS = new Set([
  '106001', '106006', '106023', '106100', '302013', '302014', '302015', '302016',
]);

// `<iface>:<ip>/<port>` — the form 302xxx and 106023 use.
const ASA_ENDPOINT = '([\\w.-]+):(\\d{1,3}(?:\\.\\d{1,3}){3})\\/(\\d+)';
// `<iface>/<ip>(<port>)` — the form 106100 uses instead. Same information,
// different punctuation; a single regex for both would match neither cleanly.
const ASA_ACL_ENDPOINT = '([\\w.-]+)\\/(\\d{1,3}(?:\\.\\d{1,3}){3})\\((\\d+)\\)';

const ASA_RE = {
  builtTeardown: new RegExp(
    `^(Built|Teardown)\\s+(?:(inbound|outbound)\\s+)?(\\w+)\\s+connection\\s+(\\d+)\\s+for\\s+`
    + `${ASA_ENDPOINT}(?:\\s*\\([^)]*\\))?(?:\\(([^)]*)\\))?\\s+to\\s+${ASA_ENDPOINT}`, 'i'),
  denyByGroup: new RegExp(
    `^Deny\\s+(\\w+)\\s+src\\s+${ASA_ENDPOINT}\\s+dst\\s+${ASA_ENDPOINT}`
    + `\\s+by\\s+access-group\\s+"([^"]+)"`, 'i'),
  accessList: new RegExp(
    `^access-list\\s+(\\S+)\\s+(permitted|denied)\\s+(\\w+)\\s+`
    + `${ASA_ACL_ENDPOINT}\\s*->\\s*${ASA_ACL_ENDPOINT}`, 'i'),
  inboundDenied: /^Inbound\s+(\w+)\s+connection\s+denied\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\/(\d+)\s+to\s+(\d{1,3}(?:\.\d{1,3}){3})\/(\d+)/i,
  denyFromTo: /^Deny\s+(?:inbound|outbound)\s+(\w+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\/(\d+)\s+to\s+(\d{1,3}(?:\.\d{1,3}){3})\/(\d+)/i,
  bytes: /\bbytes\s+(\d+)\b/i,
};

// ⛔ Message-ID PREFIX decides the class, never a keyword search on the text.
// 713xxx/402xxx are VPN/IPSEC, 1060xx and 3020xx are traffic. Anything else is
// NULL — there is no 'other' bucket in this codebase, and an unclassified event
// should look like the gap it is.
function classifyCiscoAsa(msgId) {
  if (typeof msgId !== 'string' || msgId.length < 3) return null;
  if (msgId.startsWith('106') || msgId.startsWith('302')) return 'traffic';
  if (msgId.startsWith('713') || msgId.startsWith('402') || msgId.startsWith('750')) return 'vpn';
  if (msgId.startsWith('605') || msgId.startsWith('611') || msgId.startsWith('113')) return 'auth';
  if (msgId.startsWith('199') || msgId.startsWith('211') || msgId.startsWith('411')) return 'system';
  return null;
}

/** Cisco ASA syslog -> the normalized event shape. */
function parseCiscoAsa(message) {
  const banner = typeof message === 'string' ? message.match(CISCO_ASA_RE) : null;
  if (!banner) return null;
  const msgId = banner[1];
  const sev = message.match(/%ASA-(\d)-\d{6}:/);
  // Everything after the banner is the message body.
  const body = message.slice(message.indexOf(banner[0]) + banner[0].length).trim();

  const out = {
    vendor: 'cisco_asa',
    // ⛔ The ASA's own syslog line carries NO year and no timezone, and this
    // parser does not invent one. eventAt stays null and the collector's
    // received_at is what anchors the row -- the same call the Fortinet parser
    // makes when `tz` is absent.
    eventAt: null,
    deviceName: null,
    deviceSerial: null,
    logType: msgId,
    logClass: classifyCiscoAsa(msgId),
    logSubtype: msgId,
    level: sev ? sev[1] : null,
    action: null,
    srcIp: null, dstIp: null, srcPort: null, dstPort: null,
    protocol: null, service: null, application: null,
    srcInterface: null, dstInterface: null,
    srcZone: null, dstZone: null,
    ruleId: null, ruleUuid: null, ruleName: null,
    srcUser: null,
    bytesSent: null, bytesReceived: null,
    threatName: null, threatSeverity: null,
    srcCountry: null, dstCountry: null,
    urlHostname: null, urlCategory: null,
    authOutcome: null,
  };

  // An id with no verified layout stops here: envelope only.
  if (!ASA_PARSED_IDS.has(msgId)) return out;

  let m;
  if ((m = body.match(ASA_RE.builtTeardown))) {
    const built = m[1].toLowerCase() === 'built';
    // ⛔ `Teardown` is a session ENDING, not a block. It maps to `close`, which
    // the shared ALLOWED_ACTIONS set already carries for exactly this reason on
    // FortiOS. Reading it as a denial would invert the meaning of the row.
    out.action = built ? 'start' : 'close';
    out.protocol = m[3];
    out.srcZone = m[5]; out.srcInterface = m[5];
    out.srcIp = m[6]; out.srcPort = toIntOrNull(m[7]);
    out.srcUser = m[8] || null;
    out.dstZone = m[9]; out.dstInterface = m[9];
    out.dstIp = m[10]; out.dstPort = toIntOrNull(m[11]);
    const b = body.match(ASA_RE.bytes);
    if (b) out.bytesSent = toIntOrNull(b[1]);
  } else if ((m = body.match(ASA_RE.denyByGroup))) {
    out.action = 'deny';
    out.protocol = m[1];
    out.srcZone = m[2]; out.srcInterface = m[2];
    out.srcIp = m[3]; out.srcPort = toIntOrNull(m[4]);
    out.dstZone = m[5]; out.dstInterface = m[5];
    out.dstIp = m[6]; out.dstPort = toIntOrNull(m[7]);
    // ⛔ THE RULE LINKAGE. This is the ASA's analogue of FortiOS `policyid`:
    // the access-group name is what ties a log line back to a stored rule.
    out.ruleName = m[8];
  } else if ((m = body.match(ASA_RE.accessList))) {
    out.ruleName = m[1];
    out.action = m[2].toLowerCase() === 'permitted' ? 'permit' : 'deny';
    out.protocol = m[3];
    out.srcZone = m[4]; out.srcInterface = m[4];
    out.srcIp = m[5]; out.srcPort = toIntOrNull(m[6]);
    out.dstZone = m[7]; out.dstInterface = m[7];
    out.dstIp = m[8]; out.dstPort = toIntOrNull(m[9]);
  } else if ((m = body.match(ASA_RE.inboundDenied)) || (m = body.match(ASA_RE.denyFromTo))) {
    // ⛔ Neither of these names an access-list, so ruleName stays NULL. A deny
    // whose rule we cannot identify is still a real deny; attributing it to a
    // guessed rule would be worse than leaving it unattributed.
    out.action = 'deny';
    out.protocol = m[1];
    out.srcIp = m[2]; out.srcPort = toIntOrNull(m[3]);
    out.dstIp = m[4]; out.dstPort = toIntOrNull(m[5]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// CEF-emitting vendors (Forcepoint NGFW, Check Point Log Exporter in CEF mode)
// ---------------------------------------------------------------------------
//
// The GRAMMAR lives in lib/syslog/cef.js and is shared. What is vendor-specific
// is only which slot carries which fact, and that was read off captured samples
// -- see tests/fixtures/cefSyslog.js, which also records that those fixtures are
// RECONSTRUCTIONS rather than verbatim captures, unlike the ASA ones.

// CEF `Device Vendor` -> SecVault slug. Keyed case-insensitively because the
// observed samples disagree with themselves: Forcepoint sends `FORCEPOINT`
// upper-case, Check Point sends `Check Point` with a space.
const CEF_VENDOR_SLUGS = new Map([
  ['forcepoint', 'forcepoint'],
  ['check point', 'checkpoint'],
  ['checkpoint', 'checkpoint'],
]);

function cefVendorSlug(message) {
  const c = parseCef(message);
  if (!c || typeof c.deviceVendor !== 'string') return null;
  return CEF_VENDOR_SLUGS.get(c.deviceVendor.trim().toLowerCase()) || null;
}

// ⛔ `proto` IS NOT CONSISTENT ACROSS VENDORS. Forcepoint sends the IP
// protocol NUMBER (6, 17); Check Point sends a name (tcp, udp). Both are
// normalised to a lowercase name, and anything unrecognised is passed through
// verbatim rather than guessed at -- an unknown protocol is a fact, not a gap.
const IP_PROTO_NAMES = new Map([['1', 'icmp'], ['6', 'tcp'], ['17', 'udp'], ['47', 'gre'], ['50', 'esp'], ['58', 'ipv6-icmp']]);

function normaliseProto(v) {
  if (v === null || v === undefined || v === '') return null;
  const s = String(v).trim().toLowerCase();
  return IP_PROTO_NAMES.get(s) || s;
}

/** A CEF record -> the normalized event shape. */
function parseCefEvent(message) {
  const c = parseCef(message);
  if (!c) return null;
  const vendor = CEF_VENDOR_SLUGS.get(String(c.deviceVendor || '').trim().toLowerCase()) || null;
  if (!vendor) return null;
  const e = c.extension || {};

  // ⛔ Resolved BY LABEL, never by slot position. Forcepoint uses cs1
  // (cs1Label=RuleID); Check Point uses cs2 (cs2Label=Rule Name). Reading cs1
  // unconditionally would take Check Point's NAT rule id for a rule name.
  const ruleName = bySlotLabel(e, /^\s*rule\s*_?\s*(name|id)\s*$/i);

  const act = typeof e.act === 'string' ? e.act.trim().toLowerCase() : null;

  return {
    vendor,
    // ⛔ `rt` is CEF's receive time in epoch MILLISECONDS. It is used only
    // when it is plainly a millisecond epoch; anything else leaves eventAt null
    // rather than risking the 1970 backdating that a wrong scale produces.
    eventAt: cefReceiptTime(e.rt),
    deviceName: e.deviceExternalId || e.dvchost || e.dvc || null,
    deviceSerial: null,
    logType: c.name || null,
    // Every fixture observed so far is connection traffic. An unrecognised CEF
    // record keeps a null class rather than being forced into a bucket.
    logClass: 'traffic',
    logSubtype: c.signatureId || null,
    level: c.severity || null,
    action: act,
    srcIp: e.src || null,
    dstIp: e.dst || null,
    srcPort: toIntOrNull(e.spt),
    dstPort: toIntOrNull(e.dpt),
    protocol: normaliseProto(e.proto),
    service: e.service_id || e.app || null,
    application: e.app || null,
    srcInterface: e.deviceInboundInterface || null,
    dstInterface: e.deviceOutboundInterface || null,
    srcZone: e.inzone || null,
    dstZone: e.outzone || null,
    ruleId: null,
    ruleUuid: e.rule_uid || null,
    ruleName: ruleName || null,
    srcUser: e.suser || e.duser || null,
    bytesSent: toIntOrNull(e['out']),
    bytesReceived: toIntOrNull(e['in']),
    threatName: null,
    threatSeverity: null,
    srcCountry: null,
    dstCountry: null,
    urlHostname: e.dhost || null,
    urlCategory: e.cat || null,
    authOutcome: null,
  };
}

/** CEF `rt` -> Date, or null. Milliseconds since the epoch, 13 digits. */
function cefReceiptTime(rt) {
  if (rt === null || rt === undefined) return null;
  const s = String(rt).trim();
  if (!/^\d{13}$/.test(s)) return null;      // only an unambiguous ms epoch
  const d = new Date(Number(s));
  return Number.isNaN(d.getTime()) ? null : d;
}

// ---------------------------------------------------------------------------
// Sophos SFOS: space-separated key=value, in TWO mutually incompatible formats
// ---------------------------------------------------------------------------
//
// ⛔ EVERY MAPPING BELOW IS FROM A VERBATIM LAB CAPTURE of SFOS 22.0.3
// MR-3-Build576 (2026-11-19): 3,168 lines in `Device standard format (legacy)`
// and 3,173 lines in `Standard syslog protocol`, taken SIMULTANEOUSLY from the
// same events via two syslog servers. So every claim here is a same-event
// comparison, not two readings of two populations. Full evidence and the
// reasoning for each refusal: secvault-lab/findings/FIELD-MAPPING.md.
//
// ⛔ BOTH FORMATS MUST BE SUPPORTED. SFOS 22 labels the key=value format that
// every published Sophos field reference describes as "(legacy)" and warns in
// its own UI that it "won't support the new firewall features in future
// versions". Writing only the documented one ships an adapter that silently
// loses fields on the firmware customers are being pushed towards.
//
// ⛔ AND THE LEGACY FORMAT IS MEASURABLY WORSE, which is why nothing here
// treats them as equals. Counting NON-EMPTY values over the same events:
// standard carries a zone on 2,950 rows against legacy's 2,063. Legacy omits
// zone fields ENTIRELY on Anti-Virus and Content Filtering events — exactly the
// rows the segmentation engine would want to attribute.

// Anchored on log_id + log_type, both present on 100% of all 6,341 captured
// lines in both formats, and log_id is additionally a BIJECTIVE dispatch key:
// 20 distinct ids, not one of which maps to more than a single
// (log_type / log_component / log_subtype) triple.
//
// ⛔ NOT anchored on `device=`. The FIRST key follows the PRI with no
// separator at all (`<30>device="..."`), so any pattern requiring preceding
// whitespace never matches it — which is how an earlier survey of this capture
// reported `device` as absent from 3,168 lines that all carry it.
const SOPHOS_LOG_ID_RE = /(?:^|[\s>])log_id="\d{10,14}"/;
const SOPHOS_LOG_TYPE_RE = /(?:^|[\s>])log_type="/;

function looksSophos(message) {
  return SOPHOS_LOG_ID_RE.test(message) && SOPHOS_LOG_TYPE_RE.test(message);
}

/**
 * Split an SFOS log line into a plain object.
 *
 * ⛔ THIS IS NOT `parseKeyValue` AND MUST NOT BE REPLACED BY IT. FortiOS quotes
 * every value containing a space; SFOS legacy does not:
 *
 *     ether_type=IPv4 (0x0800) bridge_name=""
 *
 * `parseKeyValue`'s bare-value branch is `[^\s]*`, so it yields
 * `ether_type=IPv4` and drops `(0x0800)` on the floor — measured on 2,102 of
 * the 3,168 captured legacy lines. A value therefore runs to the next ` key=`
 * rather than to the next space.
 *
 * ⛔ The reverse — pointing Fortinet at this looser grammar — is NOT done here.
 * It would change a live-verified parser on a 16-firewall fleet to fix a
 * problem Fortinet's own evidence does not show, and that needs its own
 * capture to justify. Two grammars because the two devices genuinely differ,
 * not two implementations of one question.
 *
 * Also tolerant of runs of whitespace: standard emits `packets_sent=2
 * packets_received=2` with TWO spaces.
 *
 * Never throws.
 */
function parseKeyValueSpanning(message) {
  const out = {};
  if (typeof message !== 'string') return out;
  // The PRI is not part of the key=value body. syslogParser.js normally strips
  // the frame before a vendor parser sees the payload, but a raw capture
  // carries it, and the orphan branch below would otherwise read
  // `<30>device="..."` as one unparseable token.
  const body = message.replace(/^<\d{1,3}>/, '');
  const re = /([A-Za-z0-9_.-]+)=("(?:[^"\\]|\\.)*"|[^\s]*)|(\S+)/g;
  const orphans = [];
  let m;
  let openBareKey = null;
  while ((m = re.exec(body)) !== null) {
    // A zero-length match would spin forever. Belt-and-braces: every
    // alternative here consumes at least one character.
    if (m.index === re.lastIndex) { re.lastIndex += 1; continue; }

    if (m[3] !== undefined) {
      // A token that is not part of any key=value pair. Measured over 3,318
      // captured legacy lines there are EXACTLY TWO kinds, and they must be
      // handled differently:
      //
      //   (0x0000) x2060, (0x0800) x58  -- the second half of
      //                                    `ether_type=IPv4 (0x0800)`
      //   N/A      x43                  -- a bare placeholder with NO KEY,
      //                                    e.g. `src_ip=172.16.16.2 N/A message="..."`
      //
      // ⛔ Absorbing EVERY following token into the previous value is what a
      // naive spanning grammar does, and it produced srcIp = "172.16.16.2 N/A"
      // — an address that is not an address. A fabricated value, which is
      // strictly worse than a truncated one.
      // ⛔ So a bare value continues ONLY into a PARENTHESISED token. That is
      // not a guess: it is the only multi-word unquoted shape this device has
      // been observed to emit. Anything else is recorded as unparsed rather
      // than merged or dropped.
      if (openBareKey !== null && /^\([^()\s]*\)$/.test(m[3])) {
        out[openBareKey] = `${out[openBareKey]} ${m[3]}`;
      } else {
        orphans.push(m[3]);
      }
      openBareKey = null;
      continue;
    }

    const key = m[1];
    let val = m[2];
    const quoted = val.length >= 2 && val.startsWith('"') && val.endsWith('"');
    if (quoted) val = val.slice(1, -1).replace(/\\"/g, '"');
    // An explicitly empty value is absent information, not an empty string —
    // the same call parseKeyValue makes.
    out[key] = val === '' ? null : val;
    // Only an UNQUOTED, non-empty value can be continued: a quoted value has
    // already stated where it ends.
    openBareKey = !quoted && val !== '' ? key : null;
  }
  // ⛔ Counted, never silently discarded. `$unparsed` cannot collide with a
  // real SFOS key, which must match [A-Za-z0-9_.-]+. Standard-format lines
  // produced ZERO orphans across 3,321 captured lines, so anything appearing
  // here is a legacy-format artefact and seeing it is the point.
  if (orphans.length) out.$unparsed = orphans;
  return out;
}

/**
 * SFOS `timezone=` is a ZONE NAME, not an offset.
 *
 * ⛔ Legacy splits the event time across THREE fields — `date=2026-11-19
 * time=06:39:44 timezone="GMT"` — and the zone is a NAME. The only value this
 * capture ever produced is GMT, because the lab appliance runs Europe/London;
 * what a box in another region emits is UNKNOWN and was not guessed at.
 *
 * ⛔ Zone abbreviations are ambiguous worldwide (IST is Irish, Indian AND
 * Israeli standard time), so only forms whose meaning is CERTAIN are resolved.
 * Anything else returns null and leaves eventAt null — an unanchored local
 * time is precisely the ambiguity that makes RFC 3164 painful, and CLAUDE.md
 * already records a whole-chart one-day error from formatting a timestamp in
 * the wrong zone on this very deployment (Asia/Bangkok, UTC+7).
 *
 * The standard format sidesteps all of this: `timestamp="2026-11-19T06:39:44
 * +0000"` is self-describing. One more reason to prefer it.
 */
function sophosZoneOffset(tz) {
  if (typeof tz !== 'string') return null;
  const t = tz.trim();
  if (/^[+-]\d{4}$/.test(t)) return `${t.slice(0, 3)}:${t.slice(3)}`;
  if (/^[+-]\d{2}:\d{2}$/.test(t)) return t;
  if (/^(?:GMT|UTC|Z)$/i.test(t)) return '+00:00';
  return null;
}

/**
 * SFOS log_type -> SecVault's normalized log_class.
 *
 * ⛔ Only the SIX classes actually observed are mapped. IDP (IPS), ATP, VPN,
 * authentication and SSL/TLS inspection are real SFOS log types that this
 * capture contains ZERO rows of — the lab appliance has no IPS signature
 * database at all (`IPS_CAT_VER="0"`, and eleven attack patterns plus a
 * 17-port version sweep produced nothing). They are UNVERIFIED, not absent,
 * and mapping them from documentation is exactly what this file's header
 * forbids. An unmapped type returns null, and a null log_class should look
 * like the gap it is.
 */
function classifySophos(logType) {
  if (typeof logType !== 'string') return null;
  switch (logType.trim().toLowerCase()) {
    case 'firewall': return 'traffic';
    // Both are SFOS's UTM engines, which is the bucket FortiOS's equivalent
    // rows already land in — `classifyFortinet` maps type="utm" the same way.
    case 'anti-virus': return 'utm';
    case 'content filtering': return 'utm';
    case 'event': return 'event';
    case 'system health': return 'system';
    default: return null;
  }
}

/**
 * SFOS -> normalized event. Handles BOTH syslog formats.
 */
function parseSophos(message) {
  const f = parseKeyValueSpanning(message);

  // ⛔ Format discriminator. `log_version` is present on 100% of the 3,173
  // captured standard lines and 0% of the 3,168 legacy lines. `timestamp` and
  // `device_model` corroborate it independently, and ANY ONE is accepted:
  // requiring all three would make a single future field rename fall through
  // to the WRONG grammar silently, which is the one failure mode that
  // mis-reads every field after it.
  const isStandard = f.log_version != null || f.timestamp != null || f.device_model != null;

  let eventAt = null;
  if (isStandard && typeof f.timestamp === 'string') {
    const d = new Date(f.timestamp.replace(/([+-]\d{2})(\d{2})$/, '$1:$2'));
    if (!Number.isNaN(d.getTime())) eventAt = d;
  } else if (f.date && f.time) {
    const off = sophosZoneOffset(f.timezone);
    if (off) {
      const d = new Date(`${f.date}T${f.time}${off}`);
      if (!Number.isNaN(d.getTime())) eventAt = d;
    }
  }

  // ⛔ THE SAME KEY NAMES DIFFERENT FACTS IN THE TWO FORMATS:
  //
  //     legacy    device="V01001C6CT6BFD5"       device_name="SF01V"   <- MODEL
  //     standard  device_name="V01001C6CT6BFD5"  device_model="SF01V"
  //
  // So a parser keyed on `device_name` returns the appliance identity on
  // standard and the MODEL STRING on legacy. Both are plausible, neither
  // errors, and nothing downstream could tell which it got. The format decides
  // this, never the key name.
  const identity = meaningful(isStandard ? f.device_name : f.device);

  // ⛔ IT IS THE HOSTNAME, NOT THE SERIAL — RESOLVED BY EXPERIMENT, 2026-11-19.
  // SFOS defaults the hostname to the serial, so the appliance reported the
  // same string for both and no amount of reading the capture could separate
  // them. The appliance was therefore RENAMED to `V01001C6CT6BFD5-test` and
  // re-captured: the value in BOTH formats followed the new hostname.
  // Fixtures: RENAMED in tests/fixtures/sophosSyslog.js.
  //
  // ⛔ So SFOS SYSLOG CARRIES NO SERIAL AT ALL, and deviceSerial is NULL by
  // measurement rather than by caution. The fields actually NAMED for one —
  // `device_id` (legacy) and `device_serial_id` (standard) — hold the literal
  // string NULL on 100% of all captured lines; `meaningful()` maps that to null
  // so those four characters can never be stored as a device identity. A
  // serial for a Sophos firewall must come from the SSH transport
  // (`system diagnostics show version-info`), never from a log row.
  //
  // ⛔ AND THE MODEL STRING IS NOT STABLE, so nothing may key on it. The same
  // appliance reported `SF01V` from 06:39 to 07:55 and `SFVH` from 08:09
  // onward, across a reboot, with no model change made. It is left in `fields`
  // and is deliberately not promoted to a normalized column.

  // ⛔ FROM `log_subtype`, NEVER `status`. Measured: legacy `status` carries
  // Allow=2,063 / Deny=39, but STANDARD's `status` carries only Successful=48
  // and Renew=1 — the traffic verdict is simply not in that field. Keying on
  // `status` leaves every standard-format row with a null action, and
  // `log_hit` (decision rule 2 of the CVE priority tree, ABOVE CVSS 9.0) could
  // then never fire for this vendor. `log_subtype` is Allowed=2,941/2,946 and
  // Denied=42/42 — identical across both formats.
  //
  // ⛔ ONLY A VERDICT BECOMES AN ACTION. `log_subtype` is also Usage, Admin,
  // System and Virus, none of which is a traffic decision. Emitting those
  // would put a verb into syslog_events.action that is in NEITHER of
  // actions.js's sets, which tests/vendorActions.test.js fails the build on —
  // correctly, because an unrecognised verb is neither allowed nor blocked.
  const subtype = typeof f.log_subtype === 'string' ? f.log_subtype.trim().toLowerCase() : null;
  const action = subtype === 'allowed' || subtype === 'denied' ? subtype : null;

  // ⛔ A SESSION EMITS TWO ROWS AND THE FIRST ONE'S COUNTERS ARE NOT A
  // MEASUREMENT. The pair shares con_id and differs by con_event Start/Stop.
  // Measured: of 1,031 legacy Start rows ALL carry sent_bytes=0 recv_bytes=0,
  // while of 1,033 standard Start rows NOT ONE carries a bytes field at all.
  // Standard is the honest format here — it omits what it has not counted —
  // and legacy's zeros are the `hit_count DEFAULT 0` bug arriving over syslog.
  //
  // ⛔ A THIRD STATE EXISTS: `Interim` (3 captured rows), a running mid-session
  // counter. Summing anything but Stop double-counts the same bytes, which is
  // the FortiOS cumulative-counter trap in a different shape.
  // ⛔ THE LEGACY FORMAT IS INCONSISTENT WITH ITSELF on the session id: its
  // Firewall rows spell it `connid` while its Content Filtering rows spell it
  // `con_id` (the standard format's spelling). Reading only `connid` dropped
  // the id from 856 of 3,055 paired events — caught by the cross-format
  // agreement check, not by reading either format on its own.
  const connEvent = meaningful(isStandard ? f.con_event : f.connevent);
  const atSessionEnd = connEvent === 'Stop';
  // Rows with NO con_event at all (Anti-Virus, Content Filtering) describe a
  // completed transaction, so their counters ARE real — they are kept, but not
  // marked summable, because they cover the same bytes the firewall session
  // rows already account for.
  const countersMeasured = atSessionEnd || connEvent === null;
  const rawSent = toIntOrNull(isStandard ? f.bytes_sent : f.sent_bytes);
  const rawRecv = toIntOrNull(isStandard ? f.bytes_received : f.recv_bytes);

  const logClass = classifySophos(f.log_type);
  // legacy `virus=`, standard `malware=`.
  const threatName = meaningful(isStandard ? f.malware : f.virus);
  // legacy `priority=`, standard `severity=`. Same vocabulary in both:
  // Information / Notice / Critical.
  const level = meaningful(isStandard ? f.severity : f.priority);

  // ⛔ `fw_rule_id` CARRIES A NO-RULE SENTINEL THAT DIFFERS BY FORMAT. On the
  // SAME events, legacy writes `fw_rule_id=0` where standard writes
  // `fw_rule_id="N/A"` (30 captured rows) — which is what proves 0 is a
  // sentinel rather than a rule numbered zero. Storing it fabricates a
  // reference to a rule that does not exist, and rule-hit correlation would
  // then attribute real traffic to it.
  const ruleIdRaw = meaningful(f.fw_rule_id);
  const ruleId = ruleIdRaw === null || ruleIdRaw === '0' ? null : String(ruleIdRaw);

  return {
    vendor: 'sophos',
    eventAt,
    deviceName: identity,
    deviceSerial: null,
    logType: meaningful(f.log_type),
    logClass,
    logSubtype: meaningful(f.log_subtype),
    level,
    action,
    srcIp: meaningful(f.src_ip),
    dstIp: meaningful(f.dst_ip),
    srcPort: toIntOrNull(f.src_port),
    dstPort: toIntOrNull(f.dst_port),
    protocol: meaningful(f.protocol),
    // SFOS traffic rows name no service object; the service is implied by the
    // port. Borrowing the application name here would be a different fact.
    service: null,
    // legacy `application=`, standard `app_name=`. SFOS resolves this even on
    // an UNDECRYPTED TLS session (verified: app_name="GitHub" on an https
    // request with DecryptHTTPS disabled), so it is SNI/signature-derived and
    // is available far more often than a payload-inspection field would be.
    application: meaningful(isStandard ? f.app_name : f.application),
    srcInterface: meaningful(f.in_interface),
    dstInterface: meaningful(f.out_interface),
    // ⛔ Zones are REAL on this vendor, unlike Fortinet where they do not exist
    // in the log at all — which is what makes a Sophos device usable by the
    // segmentation engine. But they are NOT universal: legacy leaves them
    // EMPTY on a rule-based deny (verified: `srczone=""` on a row that names
    // both interfaces and the matching rule) and omits them entirely on
    // Anti-Virus and Content Filtering rows. Empty is mapped to null by
    // meaningful(); no consumer may read a null zone as "no zone".
    srcZone: meaningful(isStandard ? f.src_zone : f.srczone),
    dstZone: meaningful(isStandard ? f.dst_zone : f.dstzone),
    ruleId,
    // SFOS carries no rule UUID in syslog. The XML API does not expose one
    // either — rules are identified by NAME and ordered by a linked list.
    ruleUuid: null,
    // ⛔ The rule NAME travels on the log row, on both allows and denies. That
    // is what makes rule-hit correlation possible for this vendor at all: the
    // XML API reports no hit counts whatsoever, so firewall_rules.hit_count is
    // permanently NULL (NOT MEASURED) for Sophos and log evidence is the only
    // source of rule usage.
    ruleName: meaningful(f.fw_rule_name),
    vdom: null,
    bytesSummable: atSessionEnd,
    bytesSent: countersMeasured ? rawSent : null,
    bytesReceived: countersMeasured ? rawRecv : null,
    sessionId: meaningful(isStandard ? f.con_id : (f.connid || f.con_id)),
    srcUser: meaningful(f.user_name),
    // ⛔ `R1` IS NOT AN ISO COUNTRY CODE. It is Sophos's own code for reserved
    // /private address space and appears on every RFC1918 source. It is kept
    // VERBATIM, following the precedent `meaningful()`'s own comment sets for
    // FortiOS's "Reserved": it is a real answer about a private address, not a
    // missing one. The consequence is that this column is NOT ISO-only, and a
    // renderer that assumes alpha-3 must handle it rather than print "R1" as
    // though it were a country.
    srcCountry: meaningful(isStandard ? f.src_country : f.src_country_code),
    dstCountry: meaningful(isStandard ? f.dst_country : f.dst_country_code),
    // ⛔ Web category, Content Filtering rows only — and the key is RENAMED:
    // legacy `category="Gambling"`, standard `http_category="Gambling"`.
    // Reading `category` for both populated it on legacy ONLY, i.e. the
    // opposite direction to the zone fields, so neither format is uniformly
    // richer and a per-field decision is unavoidable. Standard also prefixes
    // `user_agent`->`http_user_agent`, `status_code`->`http_status`,
    // `contenttype`->`content_type` and `transactionid`->`transaction_id`.
    urlCategory: meaningful(isStandard ? f.http_category : f.category),
    // legacy uses `domain=` on Content Filtering rows and `domainname=` on
    // Anti-Virus rows; standard uses `domain=` for both.
    urlHostname: meaningful(isStandard ? f.domain : (f.domain || f.domainname)),
    threatName,
    // ⛔ Only where a threat was ACTUALLY assessed. `priority`/`severity` is
    // SFOS's syslog severity and sits on every row including ordinary allowed
    // traffic; stamping it everywhere is what made ~5.5M Fortinet rows/day
    // carry a fabricated threat severity (see parseFortinet). utm is the class
    // SFOS's AV and web-filtering rows land in.
    threatSeverity: threatName !== null || logClass === 'utm' ? level : null,
    // ⛔ No VPN or authentication rows exist in this capture — SFOS emits them
    // as their own log types and the lab generated none. Claiming an auth
    // outcome from `status="Successful"` on an ADMIN login would file console
    // logins as VPN authentications, which is the wrong fact rather than a
    // missing one. Left null until a verified VPN sample exists.
    authOutcome: null,
    fields: f,
  };
}

// ---------------------------------------------------------------------------
// Juniper Junos (SRX) — RFC 5424 structured data
// ---------------------------------------------------------------------------
//
// The grammar lives in ./junos.js, separately, for the same reason cef.js does.
// This section is only the MAPPING from that frame onto SecVault's normalized
// event, and every rule below is cited to secvault-lab/findings/JUNIPER-SYSLOG.md
// section 3, which is the frozen contract derived from a 105-line corpus —
// 43 MSGIDs, 145 distinct structured-data keys.
//
// ⛔ THE CORPUS IS THIRD-PARTY AND ANONYMISED (Elastic's SRX integration
// fixtures), NOT a live appliance. It is a long way above documentation and it
// is not the live capture every other parser in this file was built from. Where
// the corpus could not settle a question, the answer here is null and the gap
// is named, never guessed.

/**
 * logClass for a Junos event. JUNIPER-SYSLOG.md section 3.1.
 *
 * ⛔ RT_UTM IS `utm`, INCLUDING AV_VIRUS_DETECTED_MT. Splitting the family
 * across `utm` and `threat` by MSGID would give a UTM dashboard that silently
 * omits virus detections — the family is the subsystem, not the severity.
 *
 * ⛔ NO JUNOS EVENT MAPS TO `config`, and that is a measured gap rather than a
 * decision: Junos emits configuration changes from `mgd` (UI_COMMIT,
 * UI_CFG_AUDIT_SET) and the corpus contains not one `mgd` line. Do not invent
 * a mapping for an app-name nobody has seen emit anything.
 */
function classifyJunos(appName, msgId, isFwFilter) {
  const app = typeof appName === 'string' ? appName : null;
  const id = typeof msgId === 'string' ? msgId : null;
  switch (app) {
    case 'RT_FLOW': return 'traffic';
    case 'RT_IDP': case 'RT_IDS': case 'RT_AAMW': case 'RT_SECINTEL': return 'threat';
    case 'RT_UTM': return 'utm';
    case 'kmd': return 'vpn';
    case 'sshd': case 'dot1xd': case 'snmpd': return 'event';
    case 'mib2d': case 'rpd': return 'system';
    default: break;
  }
  // ⛔ THE PACKET-FILTER LINES HAVE NO APP-NAME AND NO MSGID — they are
  // `kernel - - -` or `- - - -` — so nothing in the header can classify them
  // and the CALLER passes `isFwFilter` after matching the `FW:` tail. They are
  // `traffic`: they carry a real 5-tuple and an accept/discard verdict, and on
  // a device without RT_FLOW configured they are the ONLY traffic evidence
  // Junos emits. Leaving them unclassified dropped them out of every traffic
  // rollup while their fields parsed perfectly — a gap that looks like data.
  if (isFwFilter) return 'traffic';
  if (id === null || id === '-') return null;
  if (/^(RT_FLOW_|APPTRACK_)/.test(id)) return 'traffic';
  if (/^(RT_SCREEN_|IDP_|SECINTEL_)/.test(id)) return 'threat';
  if (/^(WEBFILTER_|AV_|ANTISPAM_|CONTENT_FILTERING_)/.test(id)) return 'utm';
  if (/^KMD_/.test(id)) return 'vpn';
  if (/^(SSHD_|DOT1XD_|SNMPD_)/.test(id)) return 'event';
  if (/^(SNMP_TRAP_|RPD_)/.test(id)) return 'system';
  return null;
}

// ⛔ RT_FLOW CARRIES NO `action` FIELD AT ALL — measured, 0 of 24 RT_FLOW and
// APPTRACK lines. The MSGID is the ONLY source of the verdict for the busiest
// event family this vendor has, so a parser that reads `action` and stops
// leaves every traffic row with a null action, and `log_hit` (decision rule 2
// of the CVE priority tree, ABOVE CVSS 9.0) could never fire for Juniper.
//
// ⛔ AND THE VERB EMITTED HERE IS OURS, NOT THE DEVICE'S. There is no vendor
// word to preserve, so these map onto actions.js's existing vocabulary rather
// than inventing `create`/`vol_update` spellings that are in neither set and
// would classify `unknown`. Nothing is lost: `logSubtype` keeps the exact
// MSGID, so CREATE, CLOSE and VOL_UPDATE remain distinguishable downstream.
const JUNOS_MSGID_ACTION = [
  [/^(RT_FLOW_SESSION|APPTRACK_SESSION)_DENY(_LS)?$/, 'deny'],
  [/^(RT_FLOW_SESSION|APPTRACK_SESSION)_(CREATE|CLOSE|ROUTE_UPDATE|VOL_UPDATE)(_LS)?$/, 'allow'],
  [/^WEBFILTER_URL_PERMITTED(_LS)?$/, 'permit'],
  [/^WEBFILTER_URL_BLOCKED(_LS)?$/, 'block'],
  // ⛔ `_MT` IS PART OF THE REAL MSGID and its absence made this rule DEAD —
  // it matched 0 of the corpus's MSGIDs while every other rule here matches
  // 1-8. It produced the right answer only because the event also carries
  // `action="drop"` and fell through to the field, i.e. the MSGID-first design
  // this whole section rests on was silently not applied to that family.
  [/^CONTENT_FILTERING_BLOCKED(_MT)?(_LS)?$/, 'block'],
  [/^AV_.*(DROPPED|DROP_FILE)(_MT)?(_LS)?$/, 'drop'],
];

/**
 * The traffic verdict. JUNIPER-SYSLOG.md section 3.2 / 4.14.
 *
 * ⛔ MSGID FIRST, `action` SECOND, and the order is the whole correctness of
 * it: an `action` field exists on RT_IDS/RT_IDP/RT_SECINTEL/RT_AAMW and names
 * what the SECURITY SERVICE did, while the MSGID on RT_FLOW/RT_UTM names what
 * the POLICY did. Reading `action` first would let an IDP `DROP` overwrite a
 * session the policy permitted.
 *
 * ⛔ A DETECTION IS NOT A VERDICT. `AV_VIRUS_DETECTED_MT` and
 * `ANTISPAM_SPAM_DETECTED_MT` say something was FOUND; neither says whether it
 * was passed or stopped, and `AV_VIRUS_DETECTED_MT` carries no `action` field
 * at all. They deliberately fall through to null rather than being assumed
 * blocked — an unrecognised verdict is neither allowed nor blocked, and
 * guessing `block` here would manufacture evidence on the UTM dashboard.
 * (ANTISPAM_SPAM_DETECTED_MT does carry `action="drop"` and so resolves on the
 * field, which is the device speaking rather than us inferring.)
 */
function junosAction(msgId, sd) {
  if (typeof msgId === 'string') {
    for (const [re, verb] of JUNOS_MSGID_ACTION) if (re.test(msgId)) return verb;
  }
  // ⛔ `meaningful()` maps Junos's `NONE` sentinel to null via NOT_AVAILABLE —
  // measured on 3 IDP_APPDDOS lines. "The IDP took no action" is not a traffic
  // decision and must not become one.
  const raw = sd ? meaningful(sd.action) : null;
  return typeof raw === 'string' ? raw.trim().toLowerCase() : null;
}

// ⛔ THE PACKET-FILTER TAIL IS POSITIONAL AND WAS COUNTED OFF THE CORPUS, not
// off the contract's prose (which numbers the fields ambiguously):
//
//   FW: gr-0/0/0.14 A udp 127.0.0.1 89.160.20.112 49153 49153
//        [0]        [1] [2]  [3]        [4]        [5]   [6]
//       interface  act proto srcIp     dstIp      sPort dPort
//
// ⛔ `0 0` FOR THE PORTS MEANS NOT APPLICABLE, NOT PORT ZERO — measured on the
// `pim` and `udp` lines that carry `(1 packets)`. Storing 0 would be this
// codebase's signature bug: a failed read recorded as a real value, and it
// would put phantom port-0 traffic into every per-port rollup.
const JUNOS_FW_TAIL_RE = /FW:\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+)\s+(\d+))?/;

// The filter action letter. A=accept, D=discard, R=reject — all three already
// have a home in actions.js, so nothing new is introduced for them.
const JUNOS_FW_ACTION = { A: 'accept', D: 'discard', R: 'reject' };

/** A port that is present, numeric and not the `0` N/A sentinel. */
function junosPort(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : null;
}

/** A byte counter: present and numeric, else NOT MEASURED. Never 0-by-default. */
function junosBytes(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/** The first `meaningful` value among several candidate keys. */
function firstOf(sd, ...keys) {
  if (!sd) return null;
  for (const k of keys) {
    const v = meaningful(sd[k]);
    if (v !== null && v !== undefined) return v;
  }
  return null;
}

/** A Junos structured-data syslog line -> the normalized event shape. */
function parseJuniper(message) {
  // ⛔ THE BRIEF-FORMAT GUARD IS FIRST, AND WITHOUT IT THIS FUNCTION PRODUCES
  // CONFIDENT GARBAGE. HEADER_RE is five whitespace-delimited fields after the
  // PRI, and an RFC 3164 line HAS five — so
  //     <14>Nov 19 09:37:51 SRX-GW1 RT_FLOW_SESSION_CREATE: session created
  // parses "successfully" as timestamp=`Nov`, hostname=`19`,
  // appName=`09:37:51`, procId=`SRX-GW1`. Every field after it would be wrong
  // and nothing would error. A shape that merely LOOKS parseable is exactly
  // the input a frame parser must refuse.
  //
  // ⛔ IT IS A NAMED GAP, NOT A null. `structured-data` is not the Junos
  // default, so this is the state of an SRX somebody has pointed at SecVault
  // without finishing the configuration — the single likeliest first contact
  // with this vendor. Returning null stores the line unattributed and the
  // operator sees a quiet fleet; this stores a Juniper row that says what to
  // switch on. Only the RFC 3164 hostname is taken, because its POSITION is
  // the RFC's and not a Junos field mapping — nothing unverified is claimed.
  if (looksJunosBrief(message)) {
    const m = /^<\d{1,3}>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s/.exec(message);
    return {
      vendor: 'juniper',
      eventAt: null,
      deviceName: m ? m[1] : null,
      deviceSerial: null,
      logType: null,
      logClass: null,
      logSubtype: null,
      level: null,
      action: null,
      srcIp: null, dstIp: null, srcPort: null, dstPort: null,
      protocol: null, service: null, application: null,
      srcInterface: null, dstInterface: null, srcZone: null, dstZone: null,
      ruleId: null, ruleUuid: null, ruleName: null, vdom: null,
      bytesSummable: false, bytesSent: null, bytesReceived: null,
      sessionId: null, srcUser: null, srcCountry: null, dstCountry: null,
      urlCategory: null, urlHostname: null,
      threatName: null, threatSeverity: null, authOutcome: null,
      fields: {
        $formatGap: 'junos_brief',
        $formatFix: 'set system syslog host <secvault> structured-data',
      },
    };
  }
  const frame = parseJunosFrame(message);
  if (!frame) return null;
  const sd = frame.sd;
  const f = sd ? { ...sd } : {};
  const msgId = frame.msgId;
  const appName = frame.appName;

  // ⛔ A ZONED HEADER WINS, THEN `epoch-time`, THEN A ZONELESS HEADER.
  //
  // JUNIPER-SYSLOG.md section 3.2 says to prefer `epoch-time` on RT_IDP (it is
  // present on 9 of 9). That is right about the REASON — the zoneless header
  // stamps cluster on RT_IDP, and inferring a zone for an instant the device
  // already stated is the mistake vpn_sessions' `login-time-utc` rule exists
  // to prevent — but applying it unconditionally COSTS PRECISION: `epoch-time`
  // is whole seconds, so `2020-03-02T23:13:03.193Z` came back as `...03.000Z`
  // and 193ms was discarded from a header that was already unambiguous.
  //
  // So the test is the ZONE, not the family: use the header whenever it
  // carries one, fall back to the epoch when it does not, and only then assume
  // a zone. Measured on the corpus: 12 of 105 stamps are zoneless, 4 of those
  // carry an epoch, and 8 reach the assumption below.
  //
  // ⛔ RT_AAMW's `timestamp` IS A DIFFERENT FIELD and is never used here
  // (JUNIPER-SYSLOG.md section 3.2).
  let eventAt = null;
  let zoneless = false;
  const stamp = typeof frame.timestamp === 'string' ? frame.timestamp : null;
  // ⛔ A DATE-ONLY FORM IS UTC, NOT LOCAL. ECMAScript parses `2013-01-19` as
  // UTC and `2013-01-19T15:18:17` as local, so a stamp with no TIME must not
  // be counted as zone-assumed — the flag would tell a consumer to correct for
  // the server offset on a value that is already UTC.
  const hasTime = stamp !== null && /T\d{2}:\d{2}/.test(stamp);
  const zoned = stamp !== null && (!hasTime || /(?:Z|[+-]\d{2}:?\d{2})$/.test(stamp));
  const epoch = sd ? Number(sd['epoch-time']) : NaN;
  if (zoned) {
    const d = new Date(stamp);
    if (!Number.isNaN(d.getTime())) eventAt = d;
  }
  // ⛔ A PLAUSIBILITY WINDOW ON THE EPOCH, because the field states no scale.
  // `epoch-time="1583190783193"` (milliseconds) multiplied by 1000 gives the
  // year 52139. The corpus verifies seconds on 9 of 9, so this is latent — but
  // the same precedent is in this file already: cefReceiptTime is used "only
  // when it is plainly a millisecond epoch; anything else leaves eventAt null
  // rather than risking the backdating a wrong scale produces".
  if (eventAt === null && Number.isFinite(epoch)
      && epoch > 946684800 && epoch < 4102444800) {
    eventAt = new Date(epoch * 1000);
  }
  if (eventAt === null && stamp !== null && !zoned) {
    // ⛔ THE FLAG IS SET ONLY WHEN THE LOCAL PARSE ACTUALLY SUCCEEDS. It used
    // to be assigned before the Date was tested, so a malformed stamp that
    // DID carry a zone (`2020-13-45T99:99:99Z`) came back with eventAt null
    // and the zone-assumed flag TRUE — one flag with two meanings, and false
    // in that case.
    const d = new Date(stamp);
    if (!Number.isNaN(d.getTime())) { eventAt = d; zoneless = true; }
  }

  // The packet-filter tail, for the lines that have no structured data at all.
  // ⛔ RESOLVED BEFORE `logClass`, because it is what decides it. These rows
  // have no APP-NAME and no MSGID, so the header alone classifies them as
  // nothing; computing the class first left three fully-populated 5-tuples
  // with logClass null, i.e. real traffic evidence that every traffic rollup
  // filters out while looking perfectly parsed.
  let fw = null;
  if (sd === null && typeof frame.text === 'string') {
    const m = JUNOS_FW_TAIL_RE.exec(frame.text);
    if (m) {
      // ⛔ DETECTION USES THE JUNOS INTERFACE GRAMMAR; THE PARSE DID NOT. The
      // tail was five bare `(\S+)` groups with no validation, so any claimed
      // SD-less line whose free text happened to contain `FW:` plus five
      // tokens fabricated a 5-tuple — `IKE negotiation failed FW: foo bar baz
      // qux quux` stored srcIp "qux" and dstIp "quux" and entered every
      // traffic rollup. The addresses are now required to BE addresses.
      const looksTuple = net.isIP(m[4]) && net.isIP(m[5]);
      fw = !looksTuple ? null : {
        iface: m[1],
        // ⛔ hasOwnProperty, NOT a bare index. `FW: ge-0/0/0.14 constructor udp …`
        // read through the prototype and made `action` a FUNCTION — and `|| null`
        // does not save it, because a function is truthy. It then reached
        // classifyAction and the database.
        act: Object.prototype.hasOwnProperty.call(JUNOS_FW_ACTION, m[2])
          ? JUNOS_FW_ACTION[m[2]] : null,
        proto: m[3],
        srcIp: m[4], dstIp: m[5], srcPort: m[6], dstPort: m[7],
      };
      f.$fwFilter = frame.text.trim();
    }
  }
  const logClass = classifyJunos(appName, msgId, fw !== null);

  // ⛔ THE PFE TAG IS THE DEVICE'S OWN WORD AND IS TAKEN WHERE IT EXISTS.
  // One shape is `kernel - - - FW: ...` (APP-NAME `kernel`) and the other is
  // `- - - - node1.fpc0 PFE_FW_SYSLOG_IP: FW: ...` (APP-NAME `-`, the tag in
  // the text). Overwriting a real `kernel` with a constant would discard what
  // the device said to make two rows look alike.
  //
  // ⛔ `FW_FILTER` IS SECVAULT'S LABEL, NOT A JUNOS MSGID, and it is the one
  // synthesised value on this row. It exists because these events carry no
  // MSGID at all and would otherwise be the only traffic rows in the product
  // with no subtype to group or filter on. Nothing downstream may present it
  // as a Junos event name.
  let fwLogType = null;
  if (fw) {
    const tag = /(?:^|\s)([A-Z][A-Z0-9_]{3,}):\s+FW:/.exec(frame.text);
    fwLogType = appName || (tag ? tag[1] : null);
  }

  // ⛔ FOUR KEY NAMES FOR ONE INTERFACE and TWO FOR EACH ZONE — RT_UTM spells
  // the zones `source-zone`/`destination-zone` while every other family spells
  // them `source-zone-name`/`destination-zone-name`. Reading only the long
  // form drops the zone from all 6 RT_UTM lines; reading only the short form
  // drops it from 61. Both are required, which is why they are listed rather
  // than normalised by a prefix rule that would also match something else.
  const srcZone = firstOf(sd, 'source-zone-name', 'source-zone');
  const dstZone = firstOf(sd, 'destination-zone-name', 'destination-zone');

  // ⛔ `nested-application` BEFORE `application`: the first is the specific app
  // (FACEBOOK-SOCIALRSS) where the second is only the protocol carrying it
  // (HTTP). Both are `UNKNOWN` on 54 instances, which `meaningful()` maps to
  // null, so the preference only ever applies when there is something to
  // prefer.
  const application = firstOf(sd, 'nested-application', 'application',
    'application-name', 'ddos-application-name');

  const threatName = firstOf(sd, 'attack-name', 'name', 'malware-info', 'feed-name');

  // ⛔ `threat-severity` IS A WORD ON RT_IDP (`HIGH`) AND A NUMBER ON
  // RT_SECINTEL (`10`) — two scales in one key name. Only the word form is
  // ranked; the numeric form is left as the device's own string rather than
  // being mapped onto a 1-5 ramp it was never on.
  const threatSeverity = firstOf(sd, 'threat-severity');

  // ⛔ `category` MEANS THREE DIFFERENT THINGS ACROSS FAMILIES and is a URL
  // category ONLY on RT_UTM WEBFILTER. On RT_SECINTEL it is the feed class
  // (`secintel`); taking it there would file threat-feed names into the
  // web-filtering category dimension.
  const isWebfilter = typeof msgId === 'string' && /^WEBFILTER_/.test(msgId);

  // ⛔ `url` HOLDS A MALWARE NAME ON AV_VIRUS_DETECTED_MT, not a URL. It is a
  // hostname ONLY on WEBFILTER. `obj` is the PATH and is never the host.
  const urlHostname = isWebfilter
    ? firstOf(sd, 'url')
    : firstOf(sd, 'http-host');

  return {
    vendor: 'juniper',
    eventAt,
    // ⛔ THE REAL COLUMN. See the SonicWall note below — this was a `fields`
    // key nothing reads, so `tz_assumed` was FALSE on the 8 corpus lines whose
    // zone we inferred from the server's own.
    tzAssumed: zoneless,
    // ⛔ HOSTNAME IS PRESENT ON 105/105 AND IS THE ONLY DEVICE IDENTITY HERE.
    deviceName: frame.hostname,
    // ⛔ NULL BY MEASUREMENT, NOT BY CAUTION: there is no serial, chassis-id,
    // model or platform field on ANY of the 145 structured-data keys in the
    // corpus. Junos syslog does not carry one. A serial for an SRX must come
    // from the adapter, and anything stored here would be invented.
    deviceSerial: null,
    logType: fw ? fwLogType : appName,
    logClass,
    logSubtype: fw ? 'FW_FILTER' : msgId,
    // ⛔ `PRI % 8`, already computed by the frame parser. Usable as a SEVERITY
    // and never as an action — Junos emits RT_FLOW_SESSION_DENY at the same
    // facility/severity as RT_FLOW_SESSION_CREATE.
    level: frame.severity,
    action: fw ? fw.act : junosAction(msgId, sd),
    srcIp: fw ? fw.srcIp : firstOf(sd, 'source-address', 'client-ip', 'local-address'),
    dstIp: fw ? fw.dstIp : firstOf(sd, 'destination-address', 'remote-address'),
    srcPort: fw ? junosPort(fw.srcPort) : junosPort(firstOf(sd, 'source-port')),
    dstPort: fw ? junosPort(fw.dstPort) : junosPort(firstOf(sd, 'destination-port')),
    // ⛔ THREE KEY NAMES OVER TWO VALUE DOMAINS: `protocol-id` is numeric,
    // `protocol-name` (RT_IDP) and `protocol` (CONTENT_FILTERING) are words.
    // normaliseProto already collapses both domains, which is why it is reused
    // rather than a second number->name table being written here.
    // ⛔ `protocol` (the bare key, CONTENT_FILTERING) IS NOT READ HERE. It holds
    // an APPLICATION protocol — `http` — and the findings document forbids it
    // by name: "mapping it to `protocol` puts `http` in a field whose other
    // values are `6` and `TCP`", giving every per-protocol rollup an `http`
    // bucket beside `tcp`. It is read into `service` below instead.
    protocol: fw ? normaliseProto(fw.proto) : normaliseProto(firstOf(sd, 'protocol-id', 'protocol-name')),
    // ⛔ On RT_IDP `service-name` is an IDP SERVICE CLASS (`SERVICE_IDP`), not
    // a Junos application object. It is still the closest analogue SecVault
    // has, so it is kept — but `application` is the field to trust there.
    service: firstOf(sd, 'service-name', 'protocol'),
    application,
    srcInterface: fw ? fw.iface : firstOf(sd, 'packet-incoming-interface',
      'source-interface-name', 'interface-name'),
    dstInterface: firstOf(sd, 'destination-interface-name'),
    srcZone,
    dstZone,
    // ⛔ `rule-name` IS RT_IDP'S IDP RULE and is NOT RT_FLOW's concept of one;
    // `rulebase-name` is the containing rulebase, not an id. Taking `rule-name`
    // outside RT_IDP would file an IDP rule number as a firewall policy id.
    ruleId: appName === 'RT_IDP' ? firstOf(sd, 'rule-name') : null,
    // ⛔ No UUID exists in any Junos event.
    ruleUuid: null,
    // ⛔ MAY BE PURELY NUMERIC (`"35"`), so nothing downstream may treat a
    // numeric ruleName as a missing one.
    ruleName: firstOf(sd, 'policy-name'),
    // ⛔ JUNOS HAS NO SINGLE VDOM ANALOGUE — the corpus shows FIVE unrelated
    // mechanisms (routing-instance, source-tenant, src-vrf-grp, tenant-id, and
    // the `_LS` logical-system MSGID suffix). The four NAMED fields are read in
    // the order a routing context is most specific; the `_LS` suffix is NOT
    // read as a vdom, because it says only THAT a logical system is in use and
    // never WHICH one, and a boolean dressed as a name is worse than a gap.
    // ⛔ `tenant-id` IS NOT READ. It is a Juniper ATP CLOUD tenant
    // (`ABC123456`), not a device partition — it appears on AAMW cloud reports
    // about an endpoint, which carry no 5-tuple and no firewall context. The
    // other three are routing contexts on the device itself; mixing a cloud
    // account id into the same column makes `vdom` two different kinds of
    // thing. It stays in `fields`.
    vdom: firstOf(sd, 'routing-instance', 'source-tenant', 'src-vrf-grp'),
    // ⛔ FALSE, ALWAYS, AND MEASURED: Junos byte counters are CUMULATIVE per
    // session, so APPTRACK emits VOL_UPDATE rows carrying a running total and
    // then a CLOSE carrying the final one. Summing the corpus over-counts by
    // **2.55x**. This is the FortiOS cumulative-counter trap in a second
    // vendor. It could only become true for CLOSE rows on a device with
    // APPTRACK volume updates switched off, which nothing in a log line says.
    bytesSummable: false,
    // ⛔ `bytes-from-client`/`bytes-from-server`, NEVER `uplink-tx-bytes`/
    // `uplink-rx-bytes` — those are a different counter on a different plane.
    // ⛔ ABSENT ON EVERY `*_CREATE` row, and absent means NOT MEASURED: a
    // session that has just been created has not moved bytes yet, and writing
    // 0 would be a measured zero that never happened.
    // ⛔ RT_IDP's COUNTERS ARE NOT A MEASUREMENT AND MUST NOT BE STORED AS 0.
    // All 5 IDP_ATTACK_LOG_EVENT lines carry `inbound-bytes="0"
    // outbound-bytes="0"`; an IPS attack log fires on DETECTION, so these are
    // almost certainly "not populated" rather than a measured zero — and the
    // corpus cannot tell the two apart, which under the tri-state rule means
    // NULL. Storing 0 reproduces exactly the behaviour the findings document
    // names as an Elastic defect. ⛔ RT_FLOW's `bytes-from-client` IS a real
    // measurement and a zero there is kept.
    bytesSent: appName === 'RT_IDP' ? null : junosBytes(firstOf(sd, 'bytes-from-client', 'outbound-bytes')),
    bytesReceived: appName === 'RT_IDP' ? null : junosBytes(firstOf(sd, 'bytes-from-server', 'inbound-bytes')),
    // ⛔ TWO KEY NAMES BY JUNOS VERSION: `session-id-32` on 31 lines (older),
    // `session-id` on 7 (modern vSRX). A parser reading one spelling loses the
    // session id on whichever half of the fleet runs the other release — the
    // same defect the Sophos `connid`/`con_id` split produced, found there only
    // by a cross-format agreement check.
    sessionId: firstOf(sd, 'session-id-32', 'session-id'),
    // ⛔ `username` IS NOT ALWAYS A USERNAME: DOT1XD puts a MAC ADDRESS there
    // and some events put a UPN (`user01@testuser.com`). It is stored as the
    // device reported it; `N/A` (36 lines) and `unknown-user` (2) are both in
    // NOT_AVAILABLE and so become null rather than two fake identities.
    srcUser: junosUser(firstOf(sd, 'username', 'source-name')),
    // ⛔ NO COUNTRY, GEO, REGION OR CITY FIELD EXISTS ON ANY OF THE 145 KEYS.
    // Junos syslog carries no geography at all. Any country for a Juniper event
    // is OURS, derived downstream by GeoIP — so recording one here would
    // attribute our own inference to the device.
    srcCountry: null,
    dstCountry: null,
    urlCategory: isWebfilter ? firstOf(sd, 'category') : null,
    urlHostname,
    threatName,
    // ⛔ Only where a threat was actually assessed, the same rule parseSophos
    // and parseFortinet follow: `level` is the syslog severity and sits on
    // every row including ordinary permitted traffic, so stamping it everywhere
    // manufactures a threat severity for the whole fleet's traffic.
    // (`firstOf` already yields null when the key is absent — this is the value,
    // not a gate. An earlier ternary here read as a guard and was not one.)
    threatSeverity,
    // ⛔ FROM THE MSGID, because Junos has no auth-outcome field. ⛔ There is
    // NO SUCCESSFUL-SSH-LOGIN EVENT in the corpus, so a success for sshd is
    // unverified and is not claimed: only the three outcomes actually observed
    // are mapped.
    authOutcome: junosAuthOutcome(msgId),
    fields: f,
  };
}

// ⛔ `unknown-user` IS AN ABSENCE THE DEVICE SPELLED OUT, and it is stripped
// HERE rather than by adding it to the shared NOT_AVAILABLE set. Junos writes
// it on IDP events where no user could be resolved; left through, it becomes a
// plausible-looking account name that shows up in user-attribution views as
// though somebody were logged in — a fabricated identity, which is this
// codebase's signature bug wearing a username.
//
// ⛔ NARROW ON PURPOSE. NOT_AVAILABLE is shared by every vendor parser in this
// file, and widening it to catch one Junos spelling would silently change how
// Fortinet, PAN-OS, Sophos and every CEF vendor read the same string. A
// vendor-specific sentinel belongs with the vendor.
function junosUser(v) {
  if (typeof v !== 'string') return v === undefined ? null : v;
  return v.trim().toLowerCase() === 'unknown-user' ? null : v;
}

// ⛔ MSGID-ONLY, AND ONLY THE THREE OBSERVED. `classifyAuthOutcome` is the
// shared vocabulary for vendors that emit an outcome WORD; Junos emits none,
// so there is nothing to hand it and inventing a word to feed it would put a
// guess through a function whose job is to resolve a measurement.
function junosAuthOutcome(msgId) {
  if (typeof msgId !== 'string') return null;
  if (msgId === 'SSHD_LOGIN_FAILED') return 'failure';
  if (msgId === 'SNMPD_AUTH_FAILURE') return 'failure';
  if (msgId === 'DOT1XD_USR_AUTHENTICATED') return 'success';
  return null;
}

// ---------------------------------------------------------------------------
// SonicWall SonicOS "Enhanced Syslog"
// ---------------------------------------------------------------------------
//
// The grammar lives in ./sonicos.js and the `m=` dispatch in
// ./sonicosCatalogue.js, separately, for the same reason junos.js and cef.js
// are. This section is only the MAPPING onto SecVault's normalized event.
//
// ⛔ THIRD-PARTY ANONYMISED CORPUS — Elastic's own SonicWall integration
// fixtures (220 lines, 55 keys, 44 message ids). NOT our capture, and no
// SonicWall device has ever been connected to SecVault. The SYNTAX is settled:
// our address splitter and Elastic's independent implementation agree on all
// **1,724 address facets across 220 events with zero mismatches**. What a key
// MEANS on a firmware nobody here has seen is not settled by that.
// Full analysis: secvault-lab/findings/SONICWALL-SYSLOG.md.

// ⛔ ANCHORED ON THREE KEYS THAT ARE ALL 220/220, NOT ON `id=firewall`.
// SonicOS emits the literal `id=firewall` on every line, so it looks like the
// perfect anchor — and 3 corpus lines carry `id=YYYYYY` because an anonymiser
// replaced it. A detector validating that VALUE would reject real lines on the
// strength of a redaction. `sn=`, `fw=` and `pri=` are each present on 220/220
// and the triple appears in no other vendor's grammar here.
const SONICWALL_RE = /(?=.*(?:^|\s)sn=)(?=.*(?:^|\s)fw=)(?=.*(?:^|\s)pri=\d)/;

function looksSonicwall(message) {
  if (typeof message !== 'string' || message.length === 0) return false;
  if (sonicosBody(message) === null) return false;
  return SONICWALL_RE.test(message);
}

// ⛔ `fw_action` IS THE ENFORCEMENT VERDICT AND IT IS ABSENT OR `NA` ON THE TWO
// EVENTS THAT MATTER MOST. Measured: `m=537` Connection Closed is `NA` on 37 of
// 45 and `m=98` Connection Opened is `NA` on 31 of 42, so reading this field
// and stopping leaves every SonicWall connection with a null action — and
// `log_hit` (decision rule 2 of the CVE priority tree, ABOVE CVSS 9.0) could
// never fire for this vendor.
//
// ⛔ `NA` IS NOT A VERDICT AND MUST NOT BECOME ONE. It means the field does not
// apply to this event type, not that the packet was neither allowed nor denied.
//
// ⛔ A CONNECTION-LIFECYCLE EVENT IS ITSELF THE EVIDENCE, which is exactly the
// call CLAUDE.md already records for Fortinet: "a session that was established
// and then ended as close/client-rst/server-rst … matching only `allow` would
// miss the most exposed service on the fleet". SonicOS opens `m=98` and closes
// `m=537` only for connections it PERMITTED; a denial is its own message id.
// So where `fw_action` states no verdict, those two ids supply one.
//
// ⛔ AND ONLY THOSE TWO. `m=97` (web hit) and `m=1382` (config change) also
// carry `NA`, and neither is a traffic decision — they stay null rather than
// being swept up by a looser rule.
const SONICWALL_LIFECYCLE_ALLOW = new Set(['98', '537']);

function sonicwallAction(fwAction, m) {
  const a = typeof fwAction === 'string' ? fwAction.trim().toLowerCase() : null;
  // ⛔ `mgmt` NAMES A PLANE, NOT A VERDICT. It says the appliance handled the
  // request itself; whether it was permitted lives in the message NAME
  // ("Web management request allowed"), which this parser does not read. Making
  // it an action would put a word in `syslog_events.action` that is in neither
  // of actions.js's sets — and an unrecognised verb is neither allowed nor
  // blocked, so it would read as `unknown` anyway while looking like a decision.
  if (a === 'drop' || a === 'forward') return a;
  if (a !== null && a !== '' && a !== 'na' && a !== 'mgmt') {
    // An unrecognised verdict is returned verbatim rather than dropped, so a
    // new firmware's vocabulary shows up as a test failure instead of silence.
    return a;
  }
  if (m !== null && SONICWALL_LIFECYCLE_ALLOW.has(String(m))) return 'allow';
  return null;
}

// ⛔ AUTH OUTCOME IS ENCODED IN THE MESSAGE ID ALONE — no field states it.
// Only the ids actually observed are mapped; SonicOS has ~1,700 and inventing
// entries for ids nobody has seen is the documentation trap this repo forbids.
const SONICWALL_AUTH = new Map([
  ['29', 'success'],   // Successful Admin Login
  ['30', 'failure'],   // Wrong Admin Password
]);

// ⛔ ONLY THE TWO THAT ARE ACTUALLY AUTHENTICATION OUTCOMES. The first draft
// also mapped `m=262` (Admin Logout), `m=994` (Config Mode Session Started)
// and `m=995`/`998` (Session End). Two problems, both real:
//
//   - A SESSION START OR END IS NOT AN AUTHENTICATION RESULT. Filing
//     "Config Mode Session Started" as a login SUCCESS inflates every
//     successful-authentication count for this vendor.
//   - `logout` IS NOT IN THE PRODUCT VOCABULARY. `classifyAuthOutcome` returns
//     only success/failure/null and `logSearch.js` declares `authOutcome` as
//     an enum of exactly those two — so a `logout` row was stored and then
//     UNFILTERABLE in log search, visible only in a CSV export.
//
// The session events keep their identity in `logSubtype` and `fields`, which
// is where a fact the normalized shape has no column for belongs.

// ⛔ SENTINELS THAT MUST BECOME NULL, each measured in the corpus. These are the
// device spelling out an ABSENCE, and storing them creates a fake username or a
// fake threat name that every downstream view treats as real.
const SONICWALL_NULL_VALUES = new Set(['unknown (sso failed)', 'n/a', '']);

function sonicwallMeaningful(v) {
  if (typeof v !== 'string') return v === undefined ? null : v;
  const t = v.trim();
  return SONICWALL_NULL_VALUES.has(t.toLowerCase()) ? null : (t === '' ? null : v);
}

// ⛔ `time=` IS ZONELESS ON 204 OF 220 LINES, and the 16 that are zoned carry a
// literal ` UTC` suffix. ⛔ THE SUFFIX IS PER LINE, NOT PER DEVICE: one
// appliance emitted BOTH forms 7h03m apart in a single capture, so a parser
// that decides the zone once per device gets one of those two batches wrong by
// the local offset. ⛔ And never the RFC 3164 header — it is a third timestamp
// that need not agree with this one.
const SONICWALL_TIME_RE = /^(\d{4})-(\d{2})-(\d{2})[\sT]+(\d{2}):(\d{2}):(\d{2})(?:\s+(\S+))?$/;

function parseSonicwallTime(raw) {
  if (typeof raw !== 'string') return { at: null, zoneAssumed: false };
  const m = SONICWALL_TIME_RE.exec(raw.trim());
  if (!m) return { at: null, zoneAssumed: false };
  const [, Y, Mo, D, H, Mi, Sec, zone] = m;

  // ⛔ THE REGEX VALIDATES THE SHAPE AND `new Date()` ROLLS OVER, so without a
  // round trip an out-of-range field becomes a confident, precise, WRONG
  // instant with nothing flagging it. Measured: `2022-02-30` stored as
  // 2022-03-02 (two days out), `2022-02-29` (not a leap year) as 02-28, and
  // `24:00:00` as the next midnight. It was inconsistent too — `2022-13-01`
  // DID yield null, because V8 uses a different parser once a field leaves the
  // ISO range, so the failure depended on which field was corrupt.
  const iso = `${Y}-${Mo}-${D}T${H}:${Mi}:${Sec}`;
  const isUtc = typeof zone === 'string' && zone.toUpperCase() === 'UTC';
  const d = new Date(isUtc ? `${iso}Z` : iso);
  if (Number.isNaN(d.getTime())) return { at: null, zoneAssumed: false };
  const part = isUtc
    ? [d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate(), d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds()]
    : [d.getFullYear(), d.getMonth() + 1, d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds()];
  const want = [Y, Mo, D, H, Mi, Sec].map(Number);
  if (part.some((n, i) => n !== want[i])) return { at: null, zoneAssumed: false };

  // ⛔ AN UNRECOGNISED TRAILING TOKEN IS ZONE-UNKNOWN, NOT A PARSE FAILURE.
  // The suffix match used to be an anchored, case-sensitive `UTC`, so `utc`,
  // `GMT` or `+07:00` dropped the timestamp ENTIRELY — `event_at` NULL on
  // 100% of that appliance's events, with nothing on the row saying why.
  // Whether SonicOS can emit those forms is unverified, which is exactly when
  // to keep the instant and flag the assumption rather than discard both.
  return { at: d, zoneAssumed: !isUtc };
}

// ⛔ `rule=` HAS TWO GRAMMARS AND ONE APPLIANCE EMITS BOTH, event-type-dependent
// — so a parser cannot pick a grammar per device and must test every value.
//   "15 (LAN->WAN)"        -> an ID plus a ZONE PAIR, no name
//   "Default Access Rule"  -> a NAME, no id
// ⛔ `ruleId` and `ruleName` are NEVER both available. Synthesising the missing
// one gives a ruleName of "15" or a ruleId of "Default Access Rule" — both lies.
const SONICWALL_RULE_RE = /^(\d+)\s*\(([^)]*)\)$/;

/** A SonicOS Enhanced Syslog line -> the normalized event shape. */
function parseSonicwall(message) {
  const body = sonicosBody(message);
  if (body === null) return null;
  const f = parseSonicosKv(body);

  const m = meaningful(f.m);
  const gcat = meaningful(f.gcat);
  const cls = classOf(m, gcat);

  const { at: eventAt, zoneAssumed } = parseSonicwallTime(f.time);
  // ⛔ The class SOURCE travels with the row. `vendor` is SonicWall's own
  // statement, `derived` is a class read off a message string by us, and `gcat`
  // is inferred from a coarse group. A reader must be able to tell them apart.
  if (cls.source !== null) f.$classSource = cls.source;

  // --- addresses -----------------------------------------------------------
  // ⛔ REFUSE, NEVER GUESS. A shape the splitter does not recognise is recorded
  // raw under `$badSrc`/`$badDst` and the address fields stay null. Assigning
  // `parts[0]` would store `fe80` as an IP.
  const sp = f.src !== undefined ? splitSonicosAddress(f.src) : null;
  const dp = f.dst !== undefined ? splitSonicosAddress(f.dst) : null;
  if (sp && !sp.ok) f.$badSrc = sp.raw;
  if (dp && !dp.ok) f.$badDst = dp.raw;

  // ⛔ IPv6 ARRIVES IN A PARALLEL KEY AND OVERRIDES THE EMPTY SLOT. SonicOS
  // never puts a colon-bearing address in `src=`, because that field is itself
  // colon-delimited; it leaves the IP slot empty and fills `srcV6=`.
  const srcV6 = meaningful(f.srcV6);
  const dstV6 = meaningful(f.dstV6);
  const srcIp = srcV6 !== null ? srcV6 : (sp && sp.ok ? sp.ip : null);
  const dstIp = dstV6 !== null ? dstV6 : (dp && dp.ok ? dp.ip : null);

  // ⛔ ON `m=713` THE SOURCE IS THE FIREWALL ITSELF — 53 of 220 corpus lines
  // (24%). The event describes a DROPPED PACKET the appliance sent, so its
  // direction is the reverse of the connection it belongs to.
  //
  // ⛔ THE ADDRESSES ARE STORED AS THE DEVICE REPORTED THEM AND ARE NOT SWAPPED.
  // The packet really did travel that way, and silently reversing it would make
  // our stored row disagree with the raw line, which is the one thing a
  // forensic record may not do. What IS added is a flag, so a "top talkers" or
  // "who reached this service" rollup can exclude reply-direction rows instead
  // of attributing a quarter of this device's events to the firewall.
  if (String(m) === '713') f.$replyDirection = true;

  // --- protocol / service --------------------------------------------------
  // ⛔ `proto=`'s SECOND COMPONENT IS EITHER A SERVICE NAME OR A PORT, and it
  // does NOT track `dstPort` (on m=713 the ports are reversed, §4.5). The
  // numeric form is a port and must never be stored as a service name.
  let protocol = null;
  let service = null;
  if (typeof f.proto === 'string' && f.proto !== '') {
    const slash = f.proto.indexOf('/');
    if (slash === -1) {
      protocol = normaliseProto(f.proto);
    } else {
      protocol = normaliseProto(f.proto.slice(0, slash));
      const tail = f.proto.slice(slash + 1);
      if (tail !== '' && !/^\d+$/.test(tail)) service = tail;
    }
  }

  // --- rule ----------------------------------------------------------------
  let ruleId = null;
  let ruleName = null;
  const ruleRaw = meaningful(f.rule);
  if (ruleRaw !== null) {
    const rm = SONICWALL_RULE_RE.exec(ruleRaw.trim());
    if (rm) {
      ruleId = rm[1];
      // ⛔ THE ZONE PAIR INSIDE `rule=` IS A THIRD ZONE VOCABULARY and it
      // DISAGREES with `srcZone=`/`dstZone=` on the same line — measured, a rule
      // filed `LAN->WAN` sits beside `srcZone=Trusted`, and `SSLVPN->SERVER`
      // beside `TEST`/`Trusted`. Three names for two zones. It is preserved in
      // `fields` rather than promoted, because which string matches the
      // appliance's own `show zone` cannot be settled from this corpus, and
      // guessing wrong makes SecVault's segmentation engine silently inert.
      f.$ruleZonePair = rm[2];
    } else {
      ruleName = ruleRaw;
    }
  }

  // --- bytes ---------------------------------------------------------------
  // ⛔ THE SINGLE MOST IMPORTANT FINDING FOR THIS VENDOR. `sent=`/`rcvd=` appear
  // on connection-OPEN and on abort events carrying REAL, SMALL, PLAUSIBLE
  // numbers — 52/60/64 bytes, which are TCP SYN sizes, and 46 for an RST. Not
  // one counter anywhere in the corpus is literally `0`, so there is no
  // zero-sentinel to filter: this is a partial count wearing a total's clothes,
  // which is worse than Sophos's session-start zeros.
  //
  // ⛔ IT IS A THREE-WAY COUNT. One socket reports `m=98 sent=52`, then
  // `m=1235 sent=52`, then `m=537 sent=334` — the SYN twice before the total.
  // Measured over a whole corpus file, a naive SUM(sent) reports 91,066 against
  // 86,898 real: **+4.8%, and the error is NOT a constant** — it scales with the
  // number of short connections and with how many RSTs the device emits, both
  // workload-dependent.
  //
  // ⛔ SO BYTES ARE READ ON `m=537` ONLY. Everything else stays in `fields` as a
  // per-packet observation and never enters a byte rollup.
  //
  // ⛔ ABSENT IS NOT ZERO, AND `m=537` ITSELF PROVES IT: one Connection Closed
  // carries `sent=284` with no `rcvd=` at all — a one-way UDP flow. Writing 0
  // there asserts "the server replied with nothing", which is probably true and
  // is NOT MEASURED.
  const isClose = String(m) === '537';
  // ⛔ THE STRICT HELPER THAT WAS ALREADY IN THIS FILE, not a local `Number()`.
  // A bare `Number()` turns `'  '` into 0 — a MEASURED ZERO on an `m=537`,
  // which is the exact thing the bytes comment twenty lines down forbids — and
  // accepts `0x40` as 64, `1e3` as 1000 and `-5` as a negative byte count.
  const num = toIntOrNull;

  // ⛔ `cdur=` IS MILLISECONDS AND `dur=` IS SECONDS — a 1000x difference on two
  // keys that look alike. Neither is promoted to a column; both stay in
  // `fields`, and this comment is here so the next reader does not treat
  // `cdur=334116` as four days.

  const usr = sonicwallMeaningful(f.usr);
  const ipscat = sonicwallMeaningful(f.ipscat);

  return {
    vendor: 'sonicwall',
    eventAt,
    // ⛔ THE REAL COLUMN, NOT A `fields` KEY. This used to be
    // `fields.$eventAtZoneless`, which NOTHING in the product reads — so
    // `syslog_events.tz_assumed`, the column whose whole purpose is to say the
    // zone was inferred, was written FALSE on 204 of 220 lines, and
    // `logExport.js` put `event_time_zone_assumed,no` into the forensic CSV.
    // `buildEvent` reads `p.tzAssumed`; that is the contract.
    tzAssumed: zoneAssumed,
    // ⛔ NO DEVICE NAME EXISTS ANYWHERE IN THIS FORMAT. `id=` is the constant
    // "firewall", `fw=` is the IP of the interface the EVENT CONCERNS (it varies
    // within one serial — keying on it splits one firewall into two), and the
    // RFC 3164 header carries a third address that matches neither. Elastic has
    // no device name either: `observer.name` is "firewall" on every event it
    // has ever indexed. The name must come from SecVault's own `devices` table
    // by source IP, exactly as the Sophos work does.
    deviceName: null,
    // ⛔ THE ONLY STABLE DEVICE IDENTITY. ⛔ Do NOT validate its shape: the
    // corpus's `sn=` values were replaced by an anonymiser with `000SERIAL`,
    // `XXXX`, `123456789` and others, so any length or charset rule built from
    // it would be built from redactions and would reject real appliances.
    deviceSerial: meaningful(f.sn),
    logType: 'enhanced',
    logClass: cls.logClass,
    // ⛔ The catalogue SUBCATEGORY, never `msg=`. `msg=` is free text whose
    // content changes with firmware, and on `m=713` it is a single U+FFFD
    // replacement character on all 53 lines.
    logSubtype: cls.logSubtype,
    // ⛔ `pri=`, NOT the `<PRI>` in the syslog header. They are different
    // numbers and the header one is a facility+severity composite.
    level: num(f.pri),
    action: sonicwallAction(f.fw_action, m),
    srcIp,
    dstIp,
    srcPort: sp && sp.ok ? sp.port : null,
    dstPort: dp && dp.ok ? dp.port : null,
    protocol,
    service,
    // ⛔ `appName=` ONLY, AND NEVER `app=`. They are different things on one
    // line: `app=` is a NUMERIC id (11 distinct values, and `app=5` coexists
    // with `appid=2900` on the same line — Elastic's own field docs call one
    // "Numeric application ID" and the other "Application ID", i.e. it does not
    // know either). Falling back to `app=` put a bare integer into the column
    // that holds `DNS` and `FACEBOOK-SOCIALRSS` for every other vendor, on 161
    // of 220 events. Both stay in `fields`; neither is an application NAME.
    //
    // ⛔ `appName='General UDP'` IS A NON-IDENTIFICATION — SonicOS's fallback
    // label for traffic its App Control signatures did not match. "General UDP"
    // means "some UDP". Storing it makes every unidentified flow look
    // identified, so the `General ` prefix is nulled.
    //
    // ⛔ `Service iMesh` IS KEPT, and the findings document lumps it with the
    // `General …` values. It names a real application; `General HTTPS` names a
    // protocol. The `app=` id for both sits in the 49xxx range, so that range
    // is NOT the discriminator the prefix is — and the 49000 boundary is
    // inferred from 4 samples and unverified anyway.
    application: (() => {
      const an = sonicwallMeaningful(f.appName);
      return an !== null && !/^general\s/i.test(an) ? an : null;
    })(),
    srcInterface: sp && sp.ok ? sp.iface : null,
    dstInterface: dp && dp.ok ? dp.iface : null,
    // ⛔ ZONES EXIST (120/220) BUT CARRY TWO KINDS OF VALUE: `Trusted`/
    // `Untrusted` are SonicOS zone SECURITY TYPES while `TEST` is a user-created
    // zone NAME. They are stored as reported; see `$ruleZonePair` above for why
    // nothing here may be claimed as the canonical zone for segmentation.
    srcZone: meaningful(f.srcZone),
    dstZone: meaningful(f.dstZone),
    ruleId,
    // ⛔ Present on 26/220, all `m=526`, all one value — and it ENDS IN THE
    // APPLIANCE SERIAL lowercased, so SonicOS object UUIDs embed the serial.
    // Unique within a device; nothing may assume fleet-wide meaning.
    ruleUuid: meaningful(f.uuid),
    ruleName,
    // ⛔ SonicOS's equivalent concept is a Multi-Instance virtual firewall, and
    // nothing in this format carries an instance identifier.
    vdom: null,
    bytesSummable: isClose,
    bytesSent: isClose ? num(f.sent) : null,
    bytesReceived: isClose ? num(f.rcvd) : null,
    // ⛔ NEITHER CANDIDATE IS A SESSION ID AND BOTH ARE TRAPS. `n=` is a LOG
    // MESSAGE COUNTER — 201 distinct values over 219 lines, and two different
    // connections share one value while one connection appears under different
    // values at open and close, so mapping it would make every event its own
    // session. `sess=` is the administrative session TYPE (`Web`, `API`,
    // `sslvpnc`), not an identifier. SonicOS carries no connection id here.
    sessionId: null,
    srcUser: usr,
    // ⛔ SonicOS emits no country field. Its Geo-IP Filter exists, but Elastic
    // supplies country from its OWN GeoIP database, not from the log — so any
    // country on a SonicWall event is ours, derived downstream.
    srcCountry: null,
    dstCountry: null,
    // ⛔ CAPITAL `Category=`, and NEVER `code=`. `code=` is that category's
    // numeric id on `m=14`/`m=97` and the ICMP CODE on `m=38` — both small
    // integers, indistinguishable without `m=`. It stays in `fields`.
    urlCategory: meaningful(f.Category),
    // ⛔ `dstname=` IS ONLY SAFELY A HOSTNAME WHEN `arg=` IS ALSO PRESENT, and
    // the gate is not caution — it is Elastic's own behaviour, for a reason its
    // pipeline states in a comment: on ANTI-VIRUS events `dstname` is an EMAIL
    // ATTACHMENT NAME. Those events are absent from this corpus, so the hazard
    // is documented by a second implementation and unverified here, which is
    // exactly when to take the narrower reading. Ungated, a virus-laden
    // attachment filename would be indexed as a website somebody visited.
    //
    // ⛔ Measured: all 7 corpus `dstname=` lines carry `arg=`, so this gate
    // costs nothing today and is a guard against an event type we have not
    // seen. The raw value stays in `fields` either way. ⛔ One of the 7 is an
    // IP literal (`89.160.20.112`), so this column is not always a NAME.
    urlHostname: meaningful(f.arg) !== null ? meaningful(f.dstname) : null,
    threatName: ipscat,
    // ⛔ TWO SAMPLES ONLY, AND THE DIRECTION IS INVERTED FROM EVERY OTHER VENDOR
    // HERE: `ipspri=3` sits beside `msg="…Priority: Low"`, so 3 is LOW and a
    // LOWER number is worse. Stored verbatim and deliberately NOT ranked —
    // threatSeverityRank would read it on the wrong end of the scale.
    threatSeverity: meaningful(f.ipspri),
    authOutcome: m !== null ? (SONICWALL_AUTH.get(String(m)) || null) : null,
    fields: f,
  };
}

function parseVendorPayload(message) {
  const vendor = detectVendor(message);
  if (vendor === 'fortinet') return parseFortinet(message);
  if (vendor === 'paloalto') return parsePaloAlto(message);
  if (vendor === 'cisco_asa') return parseCiscoAsa(message);
  if (vendor === 'sophos') return parseSophos(message);
  if (vendor === 'juniper') return parseJuniper(message);
  if (vendor === 'sonicwall') return parseSonicwall(message);
  if (vendor === 'forcepoint' || vendor === 'checkpoint') return parseCefEvent(message);
  return null;
}

module.exports = {
  detectVendor,
  classifyPaloAlto,
  classifyFortinet,
  parseVendorPayload,
  parseFortinet,
  parsePaloAlto,
  parseCiscoAsa,
  classifyCiscoAsa,
  parseSophos,
  classifySophos,
  parseJuniper,
  parseSonicwall,
  looksSonicwall,
  sonicwallAction,
  parseSonicwallTime,
  classifyJunos,
  junosAction,
  junosAuthOutcome,
  parseKeyValueSpanning,
  sophosZoneOffset,
  looksSophos,
  parseCefEvent,
  cefVendorSlug,
  normaliseProto,
  parseKeyValue,
  splitCsv,
  meaningful,
  threatSeverityRank,
  THREAT_SEVERITY_RANK,
  PAN_COMMON,
  PAN_TRAFFIC,
};
