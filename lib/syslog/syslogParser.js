// lib/syslog/syslogParser.js
//
// Pure syslog frame parsing — RFC 3164 (BSD, the common case) and RFC 5424.
// No DB, no network, no clock of its own (the caller injects `receivedAt`), so
// this is unit-testable and is covered by tests/syslogParser.test.js.
//
// ⛔ THE RULE THIS FILE EXISTS TO ENFORCE, which CLAUDE.md now states as a
// Critical Rule: a failed read is NOT a measurement. Every field here is
// nullable and stays NULL when the line does not actually carry it. A syslog
// parser is unusually tempting to write the other way — defaulting a missing
// timestamp to "now", an unrecognised vendor to "generic", an absent severity
// to 6 (info) — and every one of those turns "we could not tell" into a
// confident fact that a downstream query will treat as real. At ~93 million
// events a day, a wrong default is not a rounding error; it is a fabricated
// dataset.
//
// The parser NEVER throws. A line it cannot understand still yields an event
// with `message` set to the raw line and everything else null, because losing
// a log line is worse than storing an unparsed one.

'use strict';

// syslog PRI = facility * 8 + severity  (RFC 5424 §6.2.1)
const MAX_PRI = 191; // facility 23, severity 7

const SEVERITY_NAMES = [
  'emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug',
];

const MONTHS = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
};

// <PRI> at the very start. Anything else means the sender did not send a
// priority, which is legal-ish in the wild and must not be invented.
const PRI_RE = /^<(\d{1,3})>/;

// RFC 5424: version digit immediately after the PRI, then a space.
const V5424_RE = /^(\d{1,2})\s/;

// RFC 3164 timestamp: "MMM d HH:mm:ss" with day space-padded or zero-padded.
const TS3164_RE = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+/;

/**
 * Split a PRI value into facility + severity.
 * @returns {{facility: number|null, severity: number|null}} both null when the
 *   value is out of range — an out-of-range PRI is a malformed frame, not a
 *   facility-23 message.
 */
function decodePri(priText) {
  // ⛔ Validate the STRING before converting. Number('') is 0 and
  // Number('  ') is 0, so a blank PRI would decode to facility 0 /
  // severity 0 -- i.e. an EMERGENCY from the kernel facility, invented out
  // of an empty string. Caught by tests/syslogParser.test.js.
  if (typeof priText !== 'string' || !/^\d{1,3}$/.test(priText)) {
    return { facility: null, severity: null };
  }
  const pri = Number(priText);
  if (!Number.isInteger(pri) || pri < 0 || pri > MAX_PRI) {
    return { facility: null, severity: null };
  }
  return { facility: Math.floor(pri / 8), severity: pri % 8 };
}

/**
 * ⛔ RFC 3164 timestamps carry NO YEAR and NO TIMEZONE. That is the single
 * nastiest thing in this format, and guessing badly is worst exactly at a year
 * boundary: a device sending "Dec 31 23:59:58" that arrives at 00:00:01 on
 * Jan 1 must resolve to LAST year, not this one, or the event lands 12 months
 * in the future and every "last 7 days" query silently misses it.
 *
 * Resolution rule: assume the year that puts the event CLOSEST to when we
 * received it, allowing a small forward window for clock skew. If the result
 * is still implausibly far from `receivedAt`, return null rather than a
 * confident wrong timestamp — the caller keeps `received_at`, which is a fact
 * we actually observed.
 *
 * The absent timezone is interpreted as the COLLECTOR's local zone, which is
 * the conventional reading and the best available. `tzAssumed: true` is
 * returned so a caller can surface that this is an assumption.
 */
function resolveBsdTimestamp(month, day, hh, mm, ss, receivedAt) {
  const recv = receivedAt instanceof Date && !Number.isNaN(receivedAt.getTime())
    ? receivedAt
    : null;
  if (recv === null) return null;

  const candidates = [recv.getFullYear() - 1, recv.getFullYear(), recv.getFullYear() + 1];
  let best = null;
  let bestDelta = Infinity;
  for (const year of candidates) {
    const d = new Date(year, month, day, hh, mm, ss);
    if (Number.isNaN(d.getTime())) continue;
    // Feb 29 on a non-leap year rolls into Mar 1 — reject rather than accept a
    // date the sender did not send.
    if (d.getMonth() !== month || d.getDate() !== day) continue;
    const delta = Math.abs(d.getTime() - recv.getTime());
    if (delta < bestDelta) { bestDelta = delta; best = d; }
  }
  if (best === null) return null;

  // More than ~45 days away from receipt in either direction means our year
  // guess is not trustworthy. Prefer null over a plausible-looking lie.
  const FORTY_FIVE_DAYS_MS = 45 * 24 * 60 * 60 * 1000;
  if (bestDelta > FORTY_FIVE_DAYS_MS) return null;
  return best;
}

/**
 * Parse one syslog line.
 *
 * @param {string} line raw line, without transport framing
 * @param {Date} receivedAt when the collector observed it — REQUIRED, because
 *   RFC 3164 year resolution is meaningless without it
 * @returns {{
 *   facility: number|null, severity: number|null, severityName: string|null,
 *   eventAt: Date|null, tzAssumed: boolean, hostname: string|null,
 *   program: string|null, procId: string|null, msgId: string|null,
 *   structuredData: string|null, message: string, format: string,
 *   parseComplete: boolean
 * }}
 */
function parseSyslogLine(line, receivedAt) {
  const empty = {
    facility: null,
    severity: null,
    severityName: null,
    eventAt: null,
    tzAssumed: false,
    hostname: null,
    program: null,
    procId: null,
    msgId: null,
    structuredData: null,
    message: '',
    format: 'unknown',
    parseComplete: false,
  };

  if (typeof line !== 'string') return empty;
  // Strip trailing newline(s) and NUL padding in ONE pass. Doing it in two
  // passes failed on the real-world "message\0\0\n" shape: the NUL pattern was
  // anchored to end-of-string and the newline was still sitting there, so the
  // NULs survived into the stored message. Senders pad in both orders.
  const raw = line.replace(/[\0\r\n]+$/, '');
  if (raw.length === 0) return empty;

  const out = Object.assign({}, empty, { message: raw });

  const priMatch = PRI_RE.exec(raw);
  if (!priMatch) {
    // No PRI at all. Keep the whole line as the message; facility/severity
    // stay NULL rather than defaulting to user/info, which would let a
    // malformed frame masquerade as a real informational event.
    out.format = 'raw';
    return out;
  }

  const { facility, severity } = decodePri(priMatch[1]);
  out.facility = facility;
  out.severity = severity;
  out.severityName = severity === null ? null : SEVERITY_NAMES[severity];

  let rest = raw.slice(priMatch[0].length);

  // ---- RFC 5424 ----------------------------------------------------------
  const vMatch = V5424_RE.exec(rest);
  if (vMatch && vMatch[1] === '1') {
    out.format = 'rfc5424';
    rest = rest.slice(vMatch[0].length);
    // TIMESTAMP HOSTNAME APP-NAME PROCID MSGID  (NILVALUE '-' for any of them)
    const parts = rest.split(' ');
    const nil = (v) => (v === undefined || v === '-' ? null : v);
    const tsText = nil(parts.shift());
    out.hostname = nil(parts.shift());
    out.program = nil(parts.shift());
    out.procId = nil(parts.shift());
    out.msgId = nil(parts.shift());

    if (tsText) {
      const d = new Date(tsText); // RFC 5424 timestamps are ISO 8601 with offset
      out.eventAt = Number.isNaN(d.getTime()) ? null : d;
      // A 5424 timestamp carries its own offset, so nothing is assumed.
      out.tzAssumed = false;
    }

    let remainder = parts.join(' ');
    // STRUCTURED-DATA is either '-' or one-or-more [ ... ] elements.
    if (remainder.startsWith('-')) {
      out.structuredData = null;
      remainder = remainder.slice(1).replace(/^\s/, '');
    } else if (remainder.startsWith('[')) {
      const end = findStructuredDataEnd(remainder);
      if (end > 0) {
        out.structuredData = remainder.slice(0, end);
        remainder = remainder.slice(end).replace(/^\s/, '');
      }
    }
    out.message = remainder;
    out.parseComplete = out.eventAt !== null;
    return out;
  }

  // ---- RFC 3164 (BSD) ----------------------------------------------------
  const tsMatch = TS3164_RE.exec(rest);
  if (tsMatch) {
    out.format = 'rfc3164';
    const month = MONTHS[tsMatch[1].toLowerCase()];
    if (month !== undefined) {
      out.eventAt = resolveBsdTimestamp(
        month, Number(tsMatch[2]), Number(tsMatch[3]), Number(tsMatch[4]), Number(tsMatch[5]),
        receivedAt
      );
      // The format has no timezone; we read it as the collector's local zone.
      out.tzAssumed = out.eventAt !== null;
    }
    rest = rest.slice(tsMatch[0].length);

    // HOSTNAME is the next token — but only if it looks like a hostname/IP
    // rather than the start of the message. Several firewalls omit it.
    const sp = rest.indexOf(' ');
    if (sp > 0) {
      const candidate = rest.slice(0, sp);
      if (/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(candidate) && !candidate.endsWith(':')) {
        out.hostname = candidate;
        rest = rest.slice(sp + 1);
      }
    }

    // TAG[PID]: — optional, and only when it appears before any space.
    const tag = /^([A-Za-z0-9_./-]{1,32})(?:\[(\d+)\])?:\s?/.exec(rest);
    if (tag) {
      out.program = tag[1];
      out.procId = tag[2] === undefined ? null : tag[2];
      rest = rest.slice(tag[0].length);
    }

    out.message = rest;
    out.parseComplete = out.eventAt !== null;
    return out;
  }

  // PRI present but no recognisable timestamp. Very common from firewalls that
  // emit their own key=value payload straight after the PRI.
  out.format = 'pri-only';
  out.message = rest;
  return out;
}

// Walks balanced [ ... ] structured-data elements, honouring backslash escapes
// inside quoted PARAM-VALUEs so a `]` inside a value does not end the block.
function findStructuredDataEnd(text) {
  let i = 0;
  let depth = 0;
  let inQuotes = false;
  while (i < text.length) {
    const c = text[i];
    if (inQuotes) {
      if (c === '\\') { i += 2; continue; }
      if (c === '"') inQuotes = false;
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === '[') {
      depth++;
    } else if (c === ']') {
      depth--;
      if (depth === 0) return i + 1;
    }
    i++;
  }
  return -1; // unbalanced — caller leaves structuredData null
}

module.exports = {
  parseSyslogLine,
  decodePri,
  resolveBsdTimestamp,
  SEVERITY_NAMES,
  MAX_PRI,
};
