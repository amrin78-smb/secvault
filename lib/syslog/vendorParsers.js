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

function toIntOrNull(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
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
  const ns = f.eventtime;
  if (ns && /^\d{16,20}$/.test(ns)) {
    const ms = Number(ns) / 1e6;
    if (Number.isFinite(ms)) {
      const d = new Date(Math.round(ms));
      if (!Number.isNaN(d.getTime())) eventAt = d;
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

  return {
    vendor: 'fortinet',
    eventAt,
    deviceName: f.devname || null,
    deviceSerial: f.devid || null,
    logType: f.type || null,
    // Normalized kind, stored once at ingest so no query has to re-derive it.
    logClass: classifyFortinet(f.type, f.subtype),
    logSubtype: f.subtype || null,
    level: f.level || null,
    action: f.action || null,
    srcIp: f.srcip || null,
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
    logSubtype: at(p, PAN_COMMON.subtype),
    level: null,
    action: isTraffic ? at(p, PAN_TRAFFIC.action) : null,
    srcIp: at(p, PAN_COMMON.srcIp),
    dstIp: at(p, PAN_COMMON.dstIp),
    srcPort: isTraffic ? toIntOrNull(at(p, PAN_TRAFFIC.srcPort)) : null,
    dstPort: isTraffic ? toIntOrNull(at(p, PAN_TRAFFIC.dstPort)) : null,
    protocol: isTraffic ? at(p, PAN_TRAFFIC.protocol) : null,
    service: null,
    application: at(p, PAN_COMMON.application),
    srcInterface: at(p, PAN_COMMON.srcInterface),
    dstInterface: at(p, PAN_COMMON.dstInterface),
    // PAN-OS does carry real zones, and SecVault already classifies zones per
    // device (zone_classifications), so these are worth keeping.
    srcZone: at(p, PAN_COMMON.srcZone),
    dstZone: at(p, PAN_COMMON.dstZone),
    // PAN-OS identifies the rule by NAME, not by a numeric id or uuid.
    ruleId: null,
    ruleUuid: null,
    ruleName: at(p, PAN_COMMON.ruleName),
    vdom: at(p, PAN_COMMON.vsys),
    // Only the session-close row is a non-overlapping total. A start row
    // reports the bytes so far and would double-count against its own end row.
    bytesSummable: isTraffic && String(at(p, PAN_COMMON.subtype) || '').toLowerCase() === 'end',
    bytesSent: isTraffic ? toIntOrNull(at(p, PAN_TRAFFIC.bytesSent)) : null,
    bytesReceived: isTraffic ? toIntOrNull(at(p, PAN_TRAFFIC.bytesReceived)) : null,
    sessionId: isTraffic ? at(p, PAN_TRAFFIC.sessionId) : null,
    fields: null, // positional format — no key/value map to keep
  };
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
  PAN_COMMON,
  PAN_TRAFFIC,
};
