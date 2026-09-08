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

/**
 * @param {{line: string, sourceIp: string, receivedAt: Date}} raw
 * @param {object} frame  parseSyslogLine() output
 * @param {object|null} payload  parseVendorPayload() output, null if unparsed
 * @param {string|null} deviceId  resolved from the sender IP, null if unmatched
 * @returns {object} the event shape eventStore.flattenRow() consumes
 */
function buildEvent(raw, frame, payload, deviceId) {
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

  return {
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

    // The raw line is always kept, even when nothing above parsed. Losing a
    // log line is worse than storing one we did not understand.
    message: f.message || raw.line,
  };
}

module.exports = { buildEvent };
