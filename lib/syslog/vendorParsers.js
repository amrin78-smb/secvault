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

// Shared VPN auth vocabulary -- see that file for the pre-login trap.
const { classifyAuthOutcome } = require('./authOutcomes');

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

// Fortinet emits key=value starting with `date=` and always carries devid=.
const FORTINET_RE = /(^|\s)devid="?FG|(^|\s)devname="[^"]*"\s+devid=/;
// Palo Alto's payload is CSV whose 4th field is the log type, after a
// FUTURE_USE digit and a receive time.
const PALOALTO_RE = /^\d*,\d{4}\/\d{2}\/\d{2}\s\d{2}:\d{2}:\d{2},[^,]*,(TRAFFIC|THREAT|SYSTEM|CONFIG|HIPMATCH|GLOBALPROTECT|USERID|DECRYPTION|CORRELATION)\b/;

/**
 * @returns {string|null} a SecVault vendor slug, or null when not confident.
 *   Slugs match CLAUDE.md's canonical list (devices.vendor).
 */
function detectVendor(message) {
  if (typeof message !== 'string' || message.length === 0) return null;
  if (PALOALTO_RE.test(message)) return 'paloalto';
  if (FORTINET_RE.test(message)) return 'fortinet';
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
const NOT_AVAILABLE = new Set(['n/a', 'not-applicable', 'unknown', 'none', '-']);

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
function parseVendorPayload(message) {
  const vendor = detectVendor(message);
  if (vendor === 'fortinet') return parseFortinet(message);
  if (vendor === 'paloalto') return parsePaloAlto(message);
  return null;
}

module.exports = {
  detectVendor,
  classifyPaloAlto,
  classifyFortinet,
  parseVendorPayload,
  parseFortinet,
  parsePaloAlto,
  parseKeyValue,
  splitCsv,
  meaningful,
  threatSeverityRank,
  THREAT_SEVERITY_RANK,
  THREAT_SEVERITY_RANK,
  PAN_COMMON,
  PAN_TRAFFIC,
};
