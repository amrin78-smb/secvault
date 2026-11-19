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

const { CEF_RE, parseCef, bySlotLabel } = require('./cef');

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
  if (CEF_RE.test(message)) return cefVendorSlug(message);
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

function parseVendorPayload(message) {
  const vendor = detectVendor(message);
  if (vendor === 'fortinet') return parseFortinet(message);
  if (vendor === 'paloalto') return parsePaloAlto(message);
  if (vendor === 'cisco_asa') return parseCiscoAsa(message);
  if (vendor === 'sophos') return parseSophos(message);
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
  THREAT_SEVERITY_RANK,
  PAN_COMMON,
  PAN_TRAFFIC,
};
