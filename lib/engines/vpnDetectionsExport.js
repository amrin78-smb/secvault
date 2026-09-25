'use strict';
// lib/engines/vpnDetectionsExport.js
//
// ONE VPN detection, as a CSV. Pure: a detection object as
// lib/engines/vpnDetections.js already returns it goes in, a document comes
// out. No pool, no clock it is not handed, no DB — the route does the reading
// and the auditing, this file does the rendering, and that split is what makes
// the shape of the file testable without a database.
//
// ── ⛔ THE FILE OUTLIVES THE TAB IT WAS DOWNLOADED FROM ───────────────────
// /vpn?vtab=detections can afford to render a hatched, hueless panel above an
// empty finding list, because the panel is right there saying the baseline is
// too thin for the question to be asked at all. A CSV carries no panel. It is
// attached to a ticket, mailed to a manager, opened in six weeks by somebody
// who never saw the screen. So everything the panel says must be INSIDE the
// file, in a form a spreadsheet and a script both read correctly:
//
//   1. `detection_status` is a COLUMN ON EVERY ROW. A zero-finding export of
//      an `insufficient_baseline` detection must never read as an all-clear —
//      that is CLAUDE.md's failed-read-as-a-fact rule, and a CSV is where it
//      is easiest to commit, because the absence of rows looks like a result.
//   2. BOTH ARRAYS ARE EXPORTED. `findings` alone is a shorter list that looks
//      complete, and `unverifiable` is precisely the material an operator has
//      to chase — the Panama brute-force candidate that only a success-blind
//      FortiGate ever saw does not stop existing because we cannot assert it.
//      `record_class` is what tells the two apart, in the FIRST column.
//   3. TRUNCATION IS DISCLOSED IN THE FILE. See the note-row section below.
//
// ── ⛔ WHY NOTE ROWS, AND WHY THEY ARE SAFE HERE ──────────────────────────
// lib/syslog/logExport.js refuses metadata rows and says why: a leading
// "# query: ..." line is not CSV, and every importer reads the first line as
// the header. That argument is about a line ABOVE the header, and it still
// holds — nothing is emitted above the header here either.
//
// A TRAILING row is a different thing: it parses as an ordinary record, so the
// document stays valid CSV. It is only dangerous if a reader can mistake it for
// a finding, which is why it is labelled in the SAME column that separates the
// two arrays (`record_class = 'note'`) and carries its text in `reason`. A
// consumer filtering `record_class == 'finding'` never sees it; a human reading
// the sheet sees it at the bottom, in the column they are already using to tell
// a verified finding from an unverifiable one.
//
// ⛔ AND THE DISCLOSURE COULD NOT LIVE ONLY IN A HEADER OR A FILENAME.
// `unverifiableTotal` can be several hundred against a listed sample of 25
// (393 measured live for off-hours on a one-day-old fleet). An HTTP header is
// gone the moment the file is saved, and a filename is renamed by the first
// person who forwards it. The COUNT is the claim — vpnDetections.js says so in
// its own MAX_UNVERIFIABLE_LISTED comment — so the count has to survive inside
// the artefact. The route sets the headers as well, for an API caller.
//
// ── ⛔ COLUMNS ARE PER DETECTION, AND THE SIX GENUINELY DIFFER ────────────
// `account_targeted` emits no `devices` and no success-claim verdict;
// `off_hours_success` emits no timestamp at all; `country_change` emits a pair
// of countries and a timeline instead of one country. Emitting a union of every
// field with blanks where a detection has nothing would make a reader believe
// the value was measured and found empty. So each detection declares its own
// column list, and a field a detection does not have is ABSENT, not blank.
//
// An empty CELL therefore means one thing only: this detection reports that
// field and its value here is unknown. `source_username_breadth` is the live
// example — it is null when the breadth read produced no row for the address,
// and it is rendered EMPTY rather than 0, because a source that attacked an
// unknown number of usernames has not attacked zero of them.

const { csvRow, csvDocument } = require('../csv');
// ⛔ The id list is IMPORTED, never copied. A second list of detection ids
// would drift the first time a seventh detection is added, and the copy that
// drifted would be the one refusing a legitimate export with "unknown
// detection". This module reads that file and never writes to it.
// ⛔ `MAX_UNVERIFIABLE_LISTED` IS DELIBERATELY NOT IMPORTED: vpnDetections.js
// does not export it, and hardcoding 25 here would be a second copy of a
// threshold that only the other file can change — it would drift silently and
// the note row would then state a cap that is not in force. The note says how
// many were listed and how many exist, which is the fact that matters; the cap
// itself is the engine's business.
const { DETECTION_IDS, STATUS } = require('./vpnDetections');

// Record classes, in the first column of every row.
const CLASS_FINDING = 'finding';
const CLASS_UNVERIFIABLE = 'unverifiable';
const CLASS_NOTE = 'note';

/**
 * ISO-8601 UTC, always with the `Z`.
 *
 * ⛔ NOT a local-time string. The same reasoning as logExport.js: a timestamp
 * is the axis an investigation turns on, and a sheet opened in another office
 * must not be able to read it as a different instant. Excel treats this as
 * text, which is the right outcome — a date cell would be re-rendered in the
 * reader's locale and the original would be gone.
 */
function isoUtc(value) {
  if (value === null || value === undefined || value === '') return '';
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString();
}

/**
 * A number, or EMPTY when it is not a number.
 *
 * ⛔ NEVER 0 FOR A NULL. `sourceUsernameBreadth` is null when SecVault has no
 * breadth row for that address, and `0` there would say the source attacked no
 * other username — the opposite of "we do not know how many". Same rule as
 * `hit_count`, in a spreadsheet cell.
 */
function numOrBlank(value) {
  if (value === null || value === undefined || value === '') return '';
  const n = Number(value);
  return Number.isFinite(n) ? String(n) : '';
}

/**
 * A boolean, as `yes`/`no`, or EMPTY when it is neither.
 *
 * ⛔ A MISSING BOOLEAN IS NOT `no`. `successClaimVerified` absent is "this
 * detection did not evaluate a success claim", and rendering that as `no`
 * would turn a field we never filled in into a negative measurement.
 */
function boolOrBlank(value) {
  if (value === true) return 'yes';
  if (value === false) return 'no';
  return '';
}

/**
 * A list, joined with `; `.
 *
 * ⛔ SEMICOLON, NOT COMMA. lib/csv.js quotes every cell so a comma would be
 * safe for the PARSE — but a reader splitting a device list by hand in a
 * spreadsheet formula cannot tell a separator from a device name containing
 * one. An EMPTY list renders empty, which is correct: "no blind devices" and
 * "no device list" both mean there is nothing to name here.
 */
function listOrBlank(value) {
  if (!Array.isArray(value) || value.length === 0) return '';
  return value
    .map((v) => (v === null || v === undefined ? '' : String(v)))
    .filter((v) => v !== '')
    .join('; ');
}

/** `blindDevices` is an object list; name each device, falling back to its id. */
function deviceRefs(value) {
  if (!Array.isArray(value) || value.length === 0) return '';
  return listOrBlank(value.map((d) => (d && (d.deviceName || d.deviceId)) || ''));
}

/**
 * country_change's in-window timeline, one observation per `;`.
 *
 * ⛔ CARRIED, not dropped. vpnDetections.js attaches it so "an operator can
 * disagree with the pair that was picked", and a reader who cannot see the
 * other observations has to take the chosen pair on trust — which is the
 * property this export exists to preserve rather than summarise away.
 *
 * ⛔ NOT NAMED `timeline`, AND THE NAME IS LOAD-BEARING.
 * tests/importIntegrity.test.js polices every name any lib/ or components/
 * module exports against every mention of it anywhere under app/ or
 * components/ — so exporting a bare `timeline` FAILED THE BUILD IN
 * components/devices/DeviceTrafficTab.js, which has destructured a local
 * `const [timeline, …]` out of a Promise.all since long before this file
 * existed (array destructuring is not one of the forms that guard recognises
 * as a local declaration). That test's own header warns that "the failure
 * lands in a different file from the cause"; this is that, and the fix is to
 * keep a shared namespace's exports SPECIFIC rather than to widen the guard.
 */
function countryTimeline(value) {
  if (!Array.isArray(value) || value.length === 0) return '';
  return value
    .map((t) => [isoUtc(t && t.at), (t && t.country) || '', (t && t.srcIp) || ''].join('|'))
    .join('; ');
}

// ── the envelope ─────────────────────────────────────────────────────────
//
// On EVERY row of EVERY detection, and each one always carries a value except
// `reason`.
//
// ⛔ `reason` IS THE ONE ENVELOPE COLUMN THAT CAN BE BLANK, AND THAT IS NOT
// THE "blank for a field the detection lacks" case. Every one of the six
// detections returns an `unverifiable` array, so `reason` belongs to all six;
// it is empty on a FINDING row because that row is not unverifiable, which is
// information rather than an absence. Omitting it from the two detections whose
// array is empty today would mean the column set changed the first time either
// grew one, and two exports of the same detection would not diff.
const ENVELOPE = [
  ['detection', (r, ctx) => ctx.detectionId],
  ['record_class', (r, ctx) => ctx.recordClass],
  ['reason', (r) => (r && r.reason) || ''],
  // ⛔ ON EVERY ROW, not in a header or a note. A file of 0 findings from a
  // detection that COULD NOT RUN and a file of 0 findings from one that ran and
  // found nothing are the same document without this column, and the first must
  // never be read as the second.
  ['detection_status', (r, ctx) => ctx.status],
  ['window_hours', (r, ctx) => numOrBlank(ctx.windowHours)],
  ['severity', (r) => (r && r.severity) || ''],
];

// ── per-detection columns ────────────────────────────────────────────────
//
// Keyed by the detection id. Each entry is exactly what that detection's own
// finding objects carry — read off lib/engines/vpnDetections.js's builders, not
// guessed at, and a field one builder does not emit is absent here.
const DETECTION_COLUMNS = Object.freeze({
  credential_spray: [
    ['src_ip', (r) => r.srcIp || ''],
    ['country', (r) => r.country || ''],
    // The detection's own distinction between "not located" and a blank cell.
    ['located', (r) => boolOrBlank(r.located)],
    ['vendors', (r) => listOrBlank(r.vendors)],
    ['devices', (r) => listOrBlank(r.devices)],
    ['usernames', (r) => numOrBlank(r.usernames)],
    // ⛔ TRAVELS WITH THE COUNT. The rollup caps a bucket's username array at
    // 50, so this count can be a FLOOR — and a reader who cannot see that will
    // quote it as exact.
    ['usernames_is_floor', (r) => boolOrBlank(r.usernamesIsFloor)],
    ['failures', (r) => numOrBlank(r.failures)],
    ['hours', (r) => numOrBlank(r.hours)],
    ['last_seen_at_utc', (r) => isoUtc(r.lastSeenAt)],
    ['success_claim_verified', (r) => boolOrBlank(r.successClaimVerified)],
    ['blind_devices', (r) => deviceRefs(r.blindDevices)],
    ['evidence', (r) => r.evidence || ''],
  ],
  brute_force: [
    ['username', (r) => r.username || ''],
    ['src_ip', (r) => r.srcIp || ''],
    ['country', (r) => r.country || ''],
    ['devices', (r) => listOrBlank(r.devices)],
    ['attempts_floor', (r) => numOrBlank(r.attemptsFloor)],
    ['attempts_is_floor', (r) => boolOrBlank(r.attemptsIsFloor)],
    ['hours', (r) => numOrBlank(r.hours)],
    ['first_seen_at_utc', (r) => isoUtc(r.firstSeenAt)],
    ['last_seen_at_utc', (r) => isoUtc(r.lastSeenAt)],
    // ⛔ EMPTY, never 0, when the breadth read produced no row — see numOrBlank.
    ['source_username_breadth', (r) => numOrBlank(r.sourceUsernameBreadth)],
    ['success_claim_verified', (r) => boolOrBlank(r.successClaimVerified)],
    ['blind_devices', (r) => deviceRefs(r.blindDevices)],
    ['evidence', (r) => r.evidence || ''],
  ],
  // ⛔ NO `devices`, NO `success_claim_verified`, NO `blind_devices`, NO
  // `country`. buildTargetedAccountDetection() emits none of them — it
  // aggregates the other way round, over every source — and a blank column
  // would say those were looked for and found absent.
  account_targeted: [
    ['username', (r) => r.username || ''],
    ['sources', (r) => numOrBlank(r.sources)],
    ['countries', (r) => numOrBlank(r.countries)],
    ['attempts_floor', (r) => numOrBlank(r.attemptsFloor)],
    ['attempts_is_floor', (r) => boolOrBlank(r.attemptsIsFloor)],
    ['hours', (r) => numOrBlank(r.hours)],
    ['last_seen_at_utc', (r) => isoUtc(r.lastSeenAt)],
    ['evidence', (r) => r.evidence || ''],
  ],
  new_country_for_user: [
    ['username', (r) => r.username || ''],
    ['country', (r) => r.country || ''],
    ['auth_hours', (r) => numOrBlank(r.authHours)],
    ['sources', (r) => listOrBlank(r.sources)],
    ['devices', (r) => listOrBlank(r.devices)],
    // ⛔ The baseline the "new" claim rests on, exported beside the claim. A
    // country is only new relative to a history, and `baselineDays: 0` is what
    // an unverifiable `no-user-baseline` row looks like.
    ['known_countries', (r) => listOrBlank(r.knownCountries)],
    ['baseline_days', (r) => numOrBlank(r.baselineDays)],
    ['caveat', (r) => r.caveat || ''],
    ['evidence', (r) => r.evidence || ''],
  ],
  country_change: [
    ['username', (r) => r.username || ''],
    ['gap_hours', (r) => numOrBlank(r.gapHours)],
    ['from_country', (r) => r.fromCountry || ''],
    ['to_country', (r) => r.toCountry || ''],
    ['from_src_ip', (r) => r.fromSrcIp || ''],
    ['to_src_ip', (r) => r.toSrcIp || ''],
    ['from_at_utc', (r) => isoUtc(r.fromAt)],
    ['to_at_utc', (r) => isoUtc(r.toAt)],
    ['device', (r) => r.device || ''],
    ['countries', (r) => listOrBlank(r.countries)],
    ['timeline', (r) => countryTimeline(r.timeline)],
    ['evidence', (r) => r.evidence || ''],
  ],
  // ⛔ NO TIMESTAMP COLUMN. buildOffHoursDetection() groups by (username,
  // hour-of-day) and keeps only the BUCKET COUNT — the individual bucket
  // instants are collapsed and are not in the finding. A `last_seen_at_utc`
  // here would have to be invented.
  off_hours_success: [
    ['username', (r) => r.username || ''],
    ['hour_utc', (r) => numOrBlank(r.hourUtc)],
    ['auth_hours', (r) => numOrBlank(r.authHours)],
    ['countries', (r) => listOrBlank(r.countries)],
    ['devices', (r) => listOrBlank(r.devices)],
    ['evidence', (r) => r.evidence || ''],
  ],
});

/** Is this a detection this module knows how to render? */
function isExportableDetection(id) {
  return typeof id === 'string'
    && DETECTION_IDS.includes(id)
    && Object.prototype.hasOwnProperty.call(DETECTION_COLUMNS, id);
}

/**
 * The header row for one detection.
 *
 * ⛔ Envelope first, so the two columns a reader needs before any number
 * (`record_class` and `detection_status`) are visible without scrolling right.
 */
function columnsFor(detectionId) {
  const own = DETECTION_COLUMNS[detectionId];
  if (!Array.isArray(own)) return null;
  return ENVELOPE.concat(own);
}

/**
 * The notes this document must carry, as {class:'note', reason} pseudo-records.
 *
 * Two of them, and each exists because the corresponding fact cannot be
 * reconstructed from the rows:
 *
 *  - the detection did not RUN (status is not `measured`). Zero rows plus this
 *    note is a statement; zero rows alone is a false all-clear.
 *  - the unverifiable list was SAMPLED. `unverifiableTotal` is the claim and
 *    the array is illustration, per vpnDetections.js's own rule.
 */
function noteRowsFor(detection) {
  const notes = [];
  const status = (detection && detection.status) || '';
  const listed = Array.isArray(detection && detection.unverifiable)
    ? detection.unverifiable.length
    : 0;
  const total = Number.isFinite(Number(detection && detection.unverifiableTotal))
    ? Number(detection.unverifiableTotal)
    : listed;
  const findings = Array.isArray(detection && detection.findings) ? detection.findings.length : 0;

  if (status !== STATUS.MEASURED) {
    notes.push({
      reason:
        `DETECTION DID NOT RUN: status "${status || 'unknown'}". `
        + `${findings} finding row(s) below. An empty or short list here is NOT an all-clear — `
        + 'this detection could not be evaluated, see the Detections tab for the baseline it needs.',
    });
  }
  if (total > listed) {
    notes.push({
      reason:
        `UNVERIFIABLE LIST SAMPLED: ${listed} of ${total} unverifiable item(s) are listed above. `
        + 'The COUNT is the claim; the rows are illustration. This file does not contain every '
        + 'unverifiable observation.',
    });
  }
  return notes;
}

/**
 * Pure: one detection -> a CSV document plus the counts that describe it.
 *
 * @param {object} detection a detection as vpnDetections.js returns it
 * @param {{windowHours?: number, generatedAt?: Date|string, bom?: boolean}} [opts]
 * @returns {{ok: true, csv, columns, detectionId, status, findingCount,
 *            unverifiableListed, unverifiableTotal, truncated, rowCount, notes}}
 *          or `{ok: false, reason}` for a detection this module cannot render.
 */
function renderDetectionCsv(detection, opts = {}) {
  const detectionId = detection && detection.id;
  if (!isExportableDetection(detectionId)) {
    // ⛔ A REFUSAL, never an empty document. A header-only CSV for an unknown
    // detection id would be indistinguishable from a detection that found
    // nothing, which is the whole failure this file is built to avoid.
    return { ok: false, reason: 'unknown-detection' };
  }
  const columns = columnsFor(detectionId);
  const findings = Array.isArray(detection.findings) ? detection.findings : [];
  const unverifiable = Array.isArray(detection.unverifiable) ? detection.unverifiable : [];
  const unverifiableTotal = Number.isFinite(Number(detection.unverifiableTotal))
    ? Number(detection.unverifiableTotal)
    : unverifiable.length;
  const status = detection.status || '';

  const ctxBase = {
    detectionId,
    status,
    windowHours: opts.windowHours,
  };
  const render = (item, recordClass) => {
    const ctx = { ...ctxBase, recordClass };
    return csvRow(columns.map(([, fn]) => fn(item || {}, ctx)));
  };

  // ⛔ HEADER FIRST AND ALWAYS, even with no data rows at all — csvDocument's
  // own rule: "the export is broken" and "nothing matched" must not look the
  // same. Findings then unverifiable then notes, so the strongest claims are
  // at the top and the caveats are where a reader stops.
  const lines = [csvRow(columns.map(([name]) => name))];
  for (const f of findings) lines.push(render(f, CLASS_FINDING));
  for (const u of unverifiable) lines.push(render(u, CLASS_UNVERIFIABLE));
  const notes = noteRowsFor(detection);
  for (const n of notes) lines.push(render(n, CLASS_NOTE));

  return {
    ok: true,
    // ⛔ BOM by default: the stated destination is a spreadsheet, these rows
    // name real people, and Excel ignores `charset=utf-8` on a downloaded file
    // — so a Thai or accented username would open as mojibake, which on an
    // identity export is a corrupted identifier rather than a cosmetic problem.
    csv: csvDocument(lines, { bom: opts.bom !== false }),
    columns: columns.map(([name]) => name),
    detectionId,
    status,
    findingCount: findings.length,
    unverifiableListed: unverifiable.length,
    unverifiableTotal,
    truncated: unverifiableTotal > unverifiable.length,
    // Data rows only — the header is not a row of the answer.
    rowCount: findings.length + unverifiable.length + notes.length,
    notes: notes.map((n) => n.reason),
  };
}

/**
 * A filesystem-safe name that says what the file holds.
 *
 * ⛔ THE DETECTION AND THE WINDOW ARE BOTH IN THE NAME. The window is the one
 * filter a reader cannot reconstruct from the contents — every value in the
 * file is inside it, but "why does this stop on Tuesday" is only answerable if
 * the range is stated. The detection id is there because three of these
 * exports share a column set closely enough to be confused once renamed.
 *
 * ⛔ The `Z` is not decoration: every timestamp in the file is UTC, and a name
 * in a different zone than the rows is how a reader concludes the export is
 * broken.
 */
function exportFilename({ detectionId, windowHours, generatedAt } = {}) {
  const safeId = String(detectionId || 'detection').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 40);
  const iso = isoUtc(generatedAt) || isoUtc(new Date());
  const stamp = `${iso.slice(0, 16).replace(/[-:]/g, '').replace('T', '-')}Z`;
  const hours = Number(windowHours);
  const win = Number.isFinite(hours) && hours > 0 ? `-${Math.trunc(hours)}h` : '';
  return `secvault-vpn-detection-${safeId}${win}-${stamp}.csv`;
}

module.exports = {
  renderDetectionCsv,
  exportFilename,
  isExportableDetection,
  columnsFor,
  noteRowsFor,
  DETECTION_COLUMNS,
  ENVELOPE,
  CLASS_FINDING,
  CLASS_UNVERIFIABLE,
  CLASS_NOTE,
  // Rendering helpers, exported so the "null is not zero" and "missing boolean
  // is not no" rules can be pinned directly rather than only through a whole
  // document.
  isoUtc,
  numOrBlank,
  boolOrBlank,
  listOrBlank,
  deviceRefs,
  countryTimeline,
};
