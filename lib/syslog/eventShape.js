// lib/syslog/eventShape.js
//
// The ONE place a parsed syslog line becomes a storable event.
//
// ── WHY THIS FILE EXISTS ──────────────────────────────────────────────────
// A field arriving in a log has to survive THREE hops to reach a column:
//
//   vendorParsers.js  ->  this mapping  ->  eventStore's COLUMNS/flattenRow
//
// Miss any one of them and the field does not error — it silently stores
// NULL, which reads exactly like "the device never sent it". That is the same
// failed-read-is-not-a-measurement bug this codebase keeps finding, and on
// 2026-09-08 it bit the eight new fields (country, user, URL category, threat
// name and so on): the parser and the store were both updated, this mapping
// was not, and 360,025 events were written with every new column null before
// anyone noticed.
//
// It lived inline in services/collector.js, which starts listeners on require
// and so cannot be unit-tested. Pulling it here makes the hop testable, and
// tests/eventShape.test.js now asserts that every field the store persists
// actually survives the trip.
//
// Pure: no DB, no sockets, no clock. Takes what it is given and returns a
// plain object. Never throws.

'use strict';

// Actions that mean the firewall REFUSED the traffic. Kept in one place so
// the retention policy and the rollups cannot disagree about what "denied"
// means.
// ⛔ Sourced from the shared set, not a local copy. A private list here is
// how the codebase ended up with four of them, disagreeing.
const { DENIED_ACTIONS: DENY_ACTIONS } = require('./actions');

// How much of the raw line to keep in the DATABASE. The archive keeps every
// line regardless — this only decides what stays searchable in SQL.
//
//   all      every line (the original behaviour, ~67% of the database)
//   security the raw line for security-relevant events only (default)
//   none     never store it
const RAW_MESSAGE_MODES = new Set(['all', 'security', 'none']);

/**
 * Should this event keep its raw line in the database?
 *
 * ⛔ Measured on the live fleet: `message` is 755 of 1,122 bytes per row —
 * 67% of the entire database — and for a FULLY PARSED event it is redundant,
 * because every field in it already has its own column. Dropping it for
 * ordinary allowed traffic is what makes 30-day retention fit.
 *
 * ⛔ But it is NOT dropped indiscriminately, and these exceptions are the
 * whole point:
 *   - UNPARSED lines keep it always. If we did not understand it, the raw
 *     text is the only record of what arrived, and this codebase's rule is
 *     that losing a line is worse than storing one we did not understand.
 *   - NON-TRAFFIC events (threat, vpn, system, utm) keep it. They are 1.6%
 *     of volume and carry vendor-specific detail the columns do not model.
 *   - DENIED traffic keeps it. A refusal is what an investigation looks at.
 *
 * Measured: those exceptions are 8.3% of the stream, so this keeps the raw
 * line exactly where it gets read and drops it for the 91.7% that is routine
 * allowed traffic — which the compressed archive still holds in full.
 *
 * @returns {boolean}
 */
function shouldKeepRawMessage(event, mode) {
  const m = RAW_MESSAGE_MODES.has(mode) ? mode : 'security';
  if (m === 'all') return true;
  if (m === 'none') return false;
  // Anything we could not attribute to a vendor is kept, unconditionally.
  if (!event || event.vendor === null || event.vendor === undefined) return true;
  if (event.logClass === null || event.logClass === undefined) return true;
  if (event.logClass !== 'traffic') return true;
  if (typeof event.action === 'string' && DENY_ACTIONS.has(event.action.toLowerCase())) return true;
  return false;
}

/**
 * @param {{line: string, sourceIp: string, receivedAt: Date}} raw
 * @param {object} frame  parseSyslogLine() output
 * @param {object|null} payload  parseVendorPayload() output, null if unparsed
 * @param {string|null} deviceId  resolved from the sender IP, null if unmatched
 * @param {string} [rawMessageMode] 'all' | 'security' | 'none'
 * @returns {object} the event shape eventStore.flattenRow() consumes
 */
function buildEvent(raw, frame, payload, deviceId, rawMessageMode) {
  const f = frame || {};
  const p = payload || null;

  // The vendor payload's own timestamp is preferred when it has one, because
  // it is unambiguous (Fortinet's nanosecond eventtime, PAN's generated time);
  // the frame timestamp is the fallback. Either may legitimately be null.
  const eventAt = (p && p.eventAt) || f.eventAt || null;
  const tzAssumed = p && p.eventAt ? Boolean(p.tzAssumed) : Boolean(f.tzAssumed);

  // ⛔ Read every vendor field through this helper. `p ? p.x : null` repeated
  // 30 times is where a field gets forgotten; one accessor means adding a
  // column is a single line in the list below.
  const v = (name) => (p && p[name] !== undefined ? p[name] : null);

  const event = {
    receivedAt: raw.receivedAt,
    eventAt,
    tzAssumed,
    sourceIp: raw.sourceIp,
    // NULL = the sender is not a managed device. Never invent one — an
    // unmanaged firewall logging to us is a finding, not noise.
    deviceId: deviceId || null,
    vendor: v('vendor'),
    facility: f.facility === undefined ? null : f.facility,
    severity: f.severity === undefined ? null : f.severity,
    hostname: (p && p.deviceName) || f.hostname || null,
    program: f.program === undefined ? null : f.program,

    action: v('action'),
    srcIp: v('srcIp'),
    dstIp: v('dstIp'),
    srcPort: v('srcPort'),
    dstPort: v('dstPort'),
    protocol: v('protocol'),
    application: v('application'),
    srcZone: v('srcZone'),
    dstZone: v('dstZone'),
    ruleId: v('ruleId'),
    ruleUuid: v('ruleUuid'),
    ruleName: v('ruleName'),
    bytesSent: v('bytesSent'),
    bytesReceived: v('bytesReceived'),
    logClass: v('logClass'),
    // Explicitly boolean, never null: the column is NOT NULL, and "we could
    // not tell" must resolve to "do not sum it", the safe direction.
    bytesSummable: Boolean(p && p.bytesSummable === true),

    // Added 2026-09-08 — see the header. All already parsed by both vendors.
    logSubtype: v('logSubtype'),
    srcUser: v('srcUser'),
    srcCountry: v('srcCountry'),
    dstCountry: v('dstCountry'),
    urlCategory: v('urlCategory'),
    urlHostname: v('urlHostname'),
    threatName: v('threatName'),
    threatSeverity: v('threatSeverity'),

    // ⛔ NULL here does NOT mean "no raw line existed". It means the line is
    // in the compressed archive rather than the database — see
    // shouldKeepRawMessage() above, and note the archive keeps EVERY line
    // unconditionally. The log-search UI must say so rather than rendering an
    // empty box, or a null reads as "nothing was received".
    message: null,
  };

  const rawLine = f.message || raw.line;
  if (shouldKeepRawMessage(event, rawMessageMode)) event.message = rawLine;
  return event;
}

module.exports = { buildEvent, shouldKeepRawMessage, RAW_MESSAGE_MODES, DENY_ACTIONS };
