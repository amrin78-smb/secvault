'use strict';
// lib/syslog/logExport.js
//
// The CSV a log search leaves the product as. Pure rendering plus one fetch
// that is `searchEvents` with a bigger ceiling — the query, the bounds and the
// timeout behaviour are NOT re-implemented here.
//
// ── ⛔ THE FILE OUTLIVES THE SCREEN, WHICH CHANGES EVERY TRADE-OFF ────────
// /logs can afford to show a partial answer because the banner above it says
// so: "More matches exist beyond this page". A CSV carries no banner. It is
// mailed, attached to a ticket, opened in six weeks by somebody who never saw
// the search that produced it. So every "partial" state that the page RENDERS
// as a caveat, this file must instead REFUSE:
//
//   * more rows than the ceiling  -> refused, with the remedy named
//   * the query timed out         -> refused, and never an empty CSV
//   * the window was clamped      -> the caller is told, and says so
//
// ⛔ AN EMPTY-BUT-VALID CSV IS THE FAILED-READ-AS-A-FACT BUG IN FILE FORM, and
// it is the worst version of it in this codebase: "no rows matched" and "the
// search was killed at ten seconds" produce byte-identical files, and the
// reader has no way back to the difference. lib/syslog/logSearch.js already
// keeps those apart in its return value; this module's only job is to not
// throw that away on the way to disk.

const { csvRow, csvDocument } = require('../csv');
const { searchEvents, EXPORT_MAX_ROWS } = require('./logSearch');

/**
 * ISO-8601 UTC, always with the `Z`.
 *
 * ⛔ NOT A LOCAL-TIME STRING, and not the operator's display format. A
 * timestamp is the axis an investigation turns on; a spreadsheet opened in
 * another office must not be able to read it as a different instant. Excel
 * will treat this as text rather than a date, which is the right outcome here
 * — a date cell would be re-rendered in the reader's own locale and the
 * original would be gone.
 */
function isoUtc(value) {
  if (value === null || value === undefined || value === '') return '';
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString();
}

// ⛔ EVERY COLUMN THE SEARCH RETURNS, IN A DELIBERATE ORDER, AND `message`
// LAST. Dropping a field to make the sheet tidier would mean the export is a
// SUMMARY of the evidence rather than the evidence — and the fields most
// likely to look droppable (zones, byte counts, the URL category) are exactly
// the ones an investigator reaches for once the obvious ones have not
// answered the question.
const COLUMNS = [
  ['received_at_utc', (r) => isoUtc(r.receivedAt)],
  ['event_at_utc', (r) => isoUtc(r.eventAt)],
  // ⛔ THE CAVEAT TRAVELS WITH THE TIMESTAMP. The device gave no zone and the
  // collector's own was assumed; a reader who cannot see that will treat an
  // assumed time as a measured one.
  ['event_time_zone_assumed', (r) => (r.tzAssumed ? 'yes' : 'no')],
  ['device', (r, ctx) => ctx.deviceNames[r.deviceId] || ''],
  // Kept beside the name: a sender that matched no managed firewall has no
  // name, and the address is then the only identity it has.
  ['device_id', (r) => r.deviceId || ''],
  ['sender_ip', (r) => r.sourceIp || ''],
  ['vendor', (r) => r.vendor || ''],
  ['hostname', (r) => r.hostname || ''],
  ['severity', (r) => (r.severity === null || r.severity === undefined ? '' : r.severity)],
  ['log_class', (r) => r.logClass || ''],
  ['log_subtype', (r) => r.logSubtype || ''],
  ['action', (r) => r.action || ''],
  ['auth_outcome', (r) => r.authOutcome || ''],
  ['src_ip', (r) => r.srcIp || ''],
  ['src_port', (r) => (r.srcPort === null || r.srcPort === undefined ? '' : r.srcPort)],
  ['src_user', (r) => r.srcUser || ''],
  ['src_country', (r) => r.srcCountry || ''],
  ['src_zone', (r) => r.srcZone || ''],
  ['dst_ip', (r) => r.dstIp || ''],
  ['dst_port', (r) => (r.dstPort === null || r.dstPort === undefined ? '' : r.dstPort)],
  ['dst_country', (r) => r.dstCountry || ''],
  ['dst_zone', (r) => r.dstZone || ''],
  ['protocol', (r) => r.protocol || ''],
  ['application', (r) => r.application || ''],
  ['rule_name', (r) => r.ruleName || ''],
  ['rule_id', (r) => r.ruleId || ''],
  ['threat_name', (r) => r.threatName || ''],
  ['threat_severity', (r) => r.threatSeverity || ''],
  ['url_hostname', (r) => r.urlHostname || ''],
  ['url_category', (r) => r.urlCategory || ''],
  ['bytes_sent', (r) => (r.bytesSent === null || r.bytesSent === undefined ? '' : r.bytesSent)],
  ['bytes_received', (r) => (r.bytesReceived === null || r.bytesReceived === undefined ? '' : r.bytesReceived)],
  ['event_id', (r) => r.id || ''],
  ['message', (r) => (r.message === null || r.message === undefined ? '' : r.message)],
];

/**
 * Pure: rows -> a CSV document.
 *
 * ⛔ NO METADATA ROWS ABOVE THE HEADER, however much a forensic file wants
 * provenance. A leading "# query: ..." line is not CSV — Excel, pandas and
 * every other importer read it as the header row and the real header becomes
 * data. The query travels in the FILENAME and in `activity_log` instead, where
 * it cannot corrupt the parse.
 */
function renderEventsCsv(rows, opts = {}) {
  const ctx = { deviceNames: (opts && opts.deviceNames) || {} };
  const list = Array.isArray(rows) ? rows : [];
  const lines = [csvRow(COLUMNS.map((c) => c[0]))];
  for (const r of list) lines.push(csvRow(COLUMNS.map((c) => c[1](r, ctx))));
  // ⛔ BOM: the stated destination is a spreadsheet, and Excel ignores the
  // HTTP charset on a downloaded file. See lib/csv.js for why it is opt-in.
  return csvDocument(lines, { bom: true });
}

/**
 * A filesystem-safe name that says what the file holds.
 *
 * ⛔ THE WINDOW IS IN THE NAME, because it is the one filter a reader cannot
 * reconstruct from the contents — every other one is visible in the rows
 * themselves, but "why does this stop on Tuesday" is only answerable if the
 * range is stated. The most specific identifying filter joins it when there is
 * one; the rest would make the name unusable.
 */
function exportFilename(built, filters) {
  // ⛔ THE `Z` IS NOT DECORATION. The search FORM takes a zone-less
  // datetime-local and parses it in the SERVER's zone, while everything in the
  // file — the filename and every timestamp column — is UTC. So an operator on
  // the +07:00 reference deployment types 08:00 and gets a file named 0100,
  // which reads as a bug unless the name says which zone it is in. Marking it
  // is the cheap half of that; the alternative, naming the file in local time,
  // would put a different zone in the name than in the rows.
  const stamp = (d) => `${isoUtc(d).slice(0, 16).replace(/[-:]/g, '').replace('T', '-')}Z`;
  const f = filters && typeof filters === 'object' ? filters : {};
  const subject = [f.srcIp, f.srcUser, f.dstIp, f.deviceId && 'device']
    .find((v) => typeof v === 'string' && v.trim() !== '');
  const safe = subject ? `-${String(subject).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 40)}` : '';
  return `secvault-logs${safe}-${stamp(built.from)}_to_${stamp(built.to)}.csv`;
}

/**
 * Run the export.
 *
 * @returns one of
 *   `{ ok: true, csv, filename, rowCount, clamped, from, to, applied, rejected }`
 *   `{ ok: false, reason: 'too_many'|'timed_out', ... }`
 *
 * ⛔ A REFUSAL IS A RETURN VALUE, NOT A THROW. The caller has to render the
 * reason and the remedy, and an exception would arrive at the generic 500
 * handler as "something went wrong" — which for "narrow your window" is an
 * error message that hides the one thing the operator can act on.
 */
async function exportEvents(pool, filters, now, opts = {}) {
  const deviceNames = (opts && opts.deviceNames) || {};
  const max = Number.isFinite(opts.maxRows) && opts.maxRows > 0
    ? Math.trunc(opts.maxRows)
    : EXPORT_MAX_ROWS;

  // ⛔ `page` AND `limit` ARE DROPPED FROM THE CALLER'S FILTERS. The export is
  // the whole result set, not the page the operator happens to be looking at;
  // honouring a `page=3` here would silently hand them rows 101-150 in a file
  // named after the entire window.
  const { page, limit, ...rest } = filters && typeof filters === 'object' ? filters : {};

  const result = await searchEvents(
    pool,
    { ...rest, limit: max },
    now,
    { maxLimit: max }
  );

  // ⛔ NEVER A CSV. An empty file here would be read as "nothing matched".
  if (result.timedOut) {
    return { ok: false, reason: 'timed_out', detail: result.reason, timeoutMs: result.timeoutMs };
  }

  // `truncated` means searchEvents saw its limit+1 probe row, i.e. there is at
  // least one more match than the ceiling allows.
  if (result.truncated) {
    return {
      ok: false,
      reason: 'too_many',
      maxRows: max,
      detail:
        `This search matches more than ${max.toLocaleString()} events, and SecVault will not `
        + 'export a partial file: once a CSV leaves the product there is nothing on it to say it '
        + 'was cut short. Narrow the time window, or add a filter, and export again.',
    };
  }

  const built = { from: result.from, to: result.to };
  return {
    ok: true,
    csv: renderEventsCsv(result.rows, { deviceNames }),
    filename: exportFilename(built, rest),
    rowCount: result.rows.length,
    // ⛔ CARRIED, NOT SWALLOWED. The caller asked for a wider span than /logs
    // will search and got less; the file is complete for the window it NAMES,
    // and that window is not the one that was requested.
    clamped: result.clamped === true,
    from: result.from,
    to: result.to,
    applied: result.applied,
    rejected: result.rejected,
    ms: result.ms,
  };
}

module.exports = {
  exportEvents,
  renderEventsCsv,
  exportFilename,
  isoUtc,
  COLUMNS,
};
