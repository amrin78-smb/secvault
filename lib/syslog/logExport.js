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
// the search that produced it.
//
// ⛔ SO THE FILE IS NEVER PARTIAL WITHIN THE WINDOW IT NAMES. When the whole
// requested range cannot be read, the export returns a COMPLETE answer to a
// NARROWER question — every matching event between the stated bounds — rather
// than an incomplete answer to the one that was asked. The filename carries
// the range actually covered, and says when that is shorter than the request.
// "A complete file for six hours" is something an investigator can reason
// about; "some of the last twenty-three hours" is not.
//
// ── ⛔ AND THE COST IS THE WINDOW, NOT THE ROW COUNT ───────────────────
// Measured on the live fleet, one source address, `log_class='vpn'`:
//
//     1 hour  ->  123 rows in  0.25s
//    23 hours -> 2254 rows in 97s
//
// Superlinear, because recent partitions are hot in the buffer cache and older
// ones come off the disk the collector is writing to at ~1,000 rows/second.
// `syslog_events` carries NO index on src_ip and deliberately never will (see
// lib/syslog/logSearch.js), so a selective filter cannot skip the scan.
//
// ⛔ THE FIRST VERSION OF THIS FILE ASKED FOR `LIMIT 50001` IN ONE
// STATEMENT AND SO COULD NEVER STOP EARLY. The /logs page answers the same
// query in 12ms precisely BECAUSE it stops at 51 rows; asking for fifty
// thousand destroys that property, and every export of a result set smaller
// than the ceiling paid for a full-window scan and was then cancelled at ten
// seconds. The ceiling meant to bound the work was what caused it.
//
// So the window is walked in SLICES, newest first: each slice is its own
// bounded statement, the cheap hot data comes back first, and the run stops on
// whichever of three limits arrives first — the row ceiling, the wall-clock
// budget, or the start of the window.

const { csvRow, csvDocument } = require('../csv');
const { searchEvents, resolveWindow, EXPORT_MAX_ROWS } = require('./logSearch');

// One slice of the window per statement. An hour is what the measurement in
// the header supports: at 0.25s it sits two orders of magnitude inside the
// 10s statement timeout even on a much busier fleet, and it is a boundary an
// operator can read off a filename.
const SLICE_MS = 60 * 60 * 1000;

// ⛔ THE WALL-CLOCK BUDGET IS A BUDGET FOR THE WHOLE RUN, not per slice.
// Someone is waiting on a browser request, and the disk this scans is the one
// the collector is writing to. 45s is long enough to cover most of a working
// window at the measured rate and short enough that no proxy in front of the
// console gives up first. Exceeding it is NOT an error: it is the point at
// which the file stops being about the whole request and starts being a
// complete answer about a shorter one.
const BUDGET_MS = 45000;

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
function exportFilename(built, filters, opts = {}) {
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
  // ⛔ THE ONE THING A READER MUST NOT MISS. The file is complete for the
  // range in its name — but if that range is shorter than what was asked for,
  // nothing INSIDE the file can say so, and the stated range alone looks like
  // a deliberate choice. A filename is the one piece of metadata that survives
  // being mailed, renamed folders and a spreadsheet import.
  const mark = opts.shortened ? '-window-shortened' : '';
  return `secvault-logs${safe}-${stamp(built.from)}_to_${stamp(built.to)}${mark}.csv`;
}

/**
 * Run the export.
 *
 * @returns one of
 *   `{ ok: true, csv, filename, rowCount, clamped, from, to, applied, rejected }`
 *   `{ ok: false, reason: 'timed_out'|'rejected_filter', detail }`
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
  const budgetMs = Number.isFinite(opts.budgetMs) && opts.budgetMs > 0
    ? opts.budgetMs
    : BUDGET_MS;
  const sliceMs = Number.isFinite(opts.sliceMs) && opts.sliceMs > 0
    ? opts.sliceMs
    : SLICE_MS;
  const clock = typeof opts.clock === 'function' ? opts.clock : Date.now;

  // ⛔ `page` AND `limit` ARE DROPPED FROM THE CALLER'S FILTERS. The export is
  // the whole result set, not the page the operator happens to be looking at;
  // honouring a `page=3` here would silently hand them rows 101-150 in a file
  // named after the entire window.
  const { page, limit, ...rest } = filters && typeof filters === 'object' ? filters : {};

  // The requested window, resolved and clamped exactly as a search would be.
  const asked = resolveWindow(rest.from, rest.to, now);
  const started = clock();

  const rows = [];
  let applied = {};
  let rejected = {};
  // Walked NEWEST FIRST: the hot, recent partitions come back fastest, so a
  // run that runs out of budget has covered the part of the window an
  // investigator almost always wants first.
  let cursor = asked.to;
  let stopReason = 'complete';
  // ⛔ COUNTED, NOT INFERRED FROM `rows.length`. A slice that returns zero
  // rows is a COMPLETE answer about that hour; a slice that times out is no
  // answer at all. Judging "could anything be read" by the row count conflates
  // them, and the refusal below then tells an operator the most recent hour
  // could not be read when in fact it was read and was genuinely empty.
  let slicesRead = 0;

  while (cursor > asked.from) {
    const sliceFrom = new Date(Math.max(asked.from.getTime(), cursor.getTime() - sliceMs));
    const remaining = max - rows.length + 1; // +1 so the ceiling itself is detectable

    /* eslint-disable no-await-in-loop */
    const slice = await searchEvents(
      pool,
      { ...rest, from: sliceFrom, to: cursor, limit: remaining },
      now,
      { maxLimit: remaining }
    );
    /* eslint-enable no-await-in-loop */

    if (slice.timedOut) {
      // ⛔ A TIMED-OUT SLICE ENDS THE RUN AT ITS OWN BOUNDARY, and that
      // boundary is the slice's END, not its start: nothing inside the slice
      // was read, so claiming any of it would be claiming rows never seen.
      stopReason = 'timed_out';
      break;
    }

    applied = slice.applied;
    rejected = slice.rejected;
    slicesRead += 1;
    for (const r of slice.rows) rows.push(r);

    if (rows.length > max) {
      // ⛔ THE CEILING DROPS ROWS, SO THE CURSOR MUST NOT ADVANCE PAST THEM.
      // `cursor = sliceFrom` used to run BEFORE this check, claiming the whole
      // slice was covered after part of it had been discarded -- and because
      // `shortened` was derived from `coveredFrom > asked.from`, a ceiling that
      // fired on the LAST slice produced no mark at all. Measured: a default
      // one-hour search (DEFAULT_WINDOW_HOURS = 1 = exactly one slice) returned
      // 50 of 200 matches in a file named for the full hour, with
      // shortened:false on the filename, the header and the audit row.
      //
      // The honest boundary is the oldest row actually KEPT: rows arrive
      // `received_at DESC`, so everything newer than it is present and nothing
      // is claimed that was dropped.
      rows.length = max;
      stopReason = 'row_ceiling';
      const oldestKept = rows[rows.length - 1];
      const keptAt = oldestKept && oldestKept.receivedAt
        ? new Date(oldestKept.receivedAt)
        : null;
      cursor = keptAt && !Number.isNaN(keptAt.getTime()) ? keptAt : cursor;
      break;
    }

    cursor = sliceFrom;
    if (cursor > asked.from && clock() - started >= budgetMs) {
      stopReason = 'budget';
      break;
    }
  }

  // ⛔ A REJECTED FILTER IS A REFUSAL, NOT A WARNING, ON A FILE.
  // buildSearchQuery drops a malformed value and searches WITHOUT it, so
  // `srcIp=10.1.1` (a typo) returns every source address. /logs renders that as
  // a banner beside the results; a CSV has nowhere to put one, and it was going
  // out named `secvault-logs-10.1.1-...csv` -- named after a host it had not
  // filtered on, with `filters: {}` in the audit row. A file that answers a
  // wider question than its own name states is the worst thing this module can
  // produce, so it is refused and the operator fixes the value.
  if (rejected && Object.keys(rejected).length > 0) {
    const names = Object.entries(rejected).map(([k, v]) => `${k}="${v}"`).join(', ');
    return {
      ok: false,
      reason: 'rejected_filter',
      detail:
        `SecVault could not understand ${names}, and will not export a file that silently `
        + 'ignores it -- the result would cover far more than the filename says. Correct the '
        + 'value and export again.',
    };
  }

  // ⛔ THE ONLY OTHER REFUSAL IS "NOTHING AT ALL COULD BE READ", and it is
  // judged on SLICES READ, not on rows returned. A search whose slices came
  // back genuinely empty has been answered completely; telling that operator
  // "not even the most recent hour could be read" is false, and throws away a
  // correct answer.
  if (stopReason === 'timed_out' && slicesRead === 0) {
    return {
      ok: false,
      reason: 'timed_out',
      detail:
        `Not even the most recent hour of this search could be read within `
        + `SecVault's query limit. Raw events are indexed by device and time, not by address, `
        + 'application or rule, so a value with few matches is found by scanning. Narrow the '
        + 'window, or add a filter that matches more.',
    };
  }

  const coveredFrom = stopReason === 'complete' ? asked.from : cursor;
  // ⛔ DERIVED FROM THE STOP REASON, NEVER FROM THE TIMESTAMPS. Comparing
  // coveredFrom with asked.from cannot see a ceiling that fired on the last
  // slice -- the two are then equal while rows have been dropped, and the file
  // goes out unmarked. Any stop that is not `complete` means the file is
  // narrower than the request, and says so.
  const shortened = stopReason !== 'complete';

  return {
    ok: true,
    csv: renderEventsCsv(rows, { deviceNames }),
    // ⛔ NAMED FROM `applied`, NEVER FROM THE RAW REQUEST. A filter the
    // query rejected is not in `applied`, so it can no longer reach the
    // filename -- belt as well as the braces of the refusal above.
    filename: exportFilename({ from: coveredFrom, to: asked.to }, applied, { shortened }),
    rowCount: rows.length,
    // What the file actually covers, which is what its name states.
    from: coveredFrom,
    to: asked.to,
    // What was asked for, so the caller can say how they differ.
    requestedFrom: asked.from,
    requestedTo: asked.to,
    shortened,
    stopReason,
    // ⛔ CARRIED, NOT SWALLOWED. The caller asked for a wider span than /logs
    // will search at all and got less.
    clamped: asked.clamped === true,
    applied,
    rejected,
    ms: clock() - started,
  };
}

module.exports = {
  exportEvents,
  renderEventsCsv,
  exportFilename,
  isoUtc,
  COLUMNS,
};
