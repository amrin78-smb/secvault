'use strict';

// lib/syslog/spoolFile.js
//
// THE SPOOL FILE'S ON-DISK CONTRACT, AND THE DECISION OF WHAT SURVIVES A
// PARTIAL INSERT.
//
// ── ⛔ WHY THIS IS A MODULE AND NOT A BLOCK INSIDE services/collector.js ──
//
// `services/collector.js` binds sockets and starts timers at module load, so
// `tests/moduleLoad.test.js` lists it parse-only and NOTHING in it can be
// required by a test. Every durability guard it carries is therefore asserted
// against its SOURCE TEXT — and this repo has now watched a source-shape
// assertion pass over an inverted guard twice (`fixedVersionFromRanges`'s
// Fortinet scan, the `hasFixedVersionsSql` import line). The spool file is the
// one place in this product where a wrong decision destroys evidence that
// exists nowhere else, so the decision lives here, where a test can run it
// against a real temp directory and real bytes.
//
// ── ⛔ WHAT WENT WRONG (roadmap row 34) ───────────────────────────────────
//
// `insertEvents()` reported only an AGGREGATE `{stored, failedChunks}` with no
// record of WHICH 500-row chunks landed, so `processSpoolFile()` could do
// nothing but keep the WHOLE file and re-insert EVERY chunk next cycle —
// including the ones that had already committed. Quarantine needs BOTH
// `MIN_SPOOL_ATTEMPTS` (5) AND `SPOOL_RETRY_MS` (30 min), which at a 2s flush
// is ~900 retries of the entire file. The time-based budget correctly fixed a
// ten-second stranding bug and multiplied this by ~180x.
//
// ⛔ AND THE ARCHIVE AMPLIFIED IDENTICALLY, WHICH IS THE HALF THAT LOSES
// NOTHING AND COSTS MOST. `archive.appendRecords()` runs BEFORE the insert, so
// each of those ~900 retries appended another full gzip member of the same
// lines. At `SYSLOG_RAW_MESSAGE=security` that archive is the ONLY copy of the
// raw line for ~89% of the fleet's traffic, so the duplication lands in the
// one store that cannot be rebuilt from anywhere else.
//
// ⛔ SHRINKING THE FILE DOES NOT FIX THE ARCHIVE, AND THE COMMON CASE IS WHY.
// The ordinary failure is the database being briefly away, where EVERY chunk
// fails and the surviving set is the whole file — nothing shrinks, and the
// archive would still be re-appended ~900 times. So a record carries an
// `archived` marker once it is safely in a gzip member, and a replay appends
// only what is not yet there. The marker is written ONLY on a successful
// append, so the failure direction is a duplicate, never a gap.

const fs = require('fs');
const path = require('path');

// ⛔ The rewrite's scratch name must not end in `.ready`. Both spool scanners
// filter on that suffix, so a crash between write and rename would otherwise
// hand a half-written file to the very drain this exists to protect.
const PARTIAL_SUFFIX = '.partial';

/**
 * One spool record per line of JSON.
 *
 * ⛔ THE KEYS ARE ONE LETTER BECAUSE THE VOLUME IS REAL: at the measured
 * 810 events/sec a spool file holds ~1,600 records per 2s flush, and this
 * text is fsync'd before the database sees any of it.
 *
 * ⛔ `a` IS OMITTED WHEN FALSE, so a first write is byte-identical to what
 * this collector has always produced. An older build reading a newer file
 * simply ignores the key and re-archives — the safe direction.
 */
function serialiseRecords(records) {
  const out = [];
  for (const r of records) {
    const o = { l: r.line, s: r.sourceIp, t: r.receivedAt.toISOString() };
    if (r.archived === true) o.a = 1;
    out.push(JSON.stringify(o));
  }
  return out.join('\n');
}

/**
 * Parse a spool file's text.
 *
 * ⛔ Do NOT substitute `new Date()` for an unreadable timestamp. `received_at`
 * is the partition key and is documented as "when WE observed it"; stamping a
 * replayed record with the restart time silently moves it into the wrong daily
 * partition and misdates every "last N hours" query. A record whose own
 * timestamp is unreadable is SKIPPED AND COUNTED, never invented.
 *
 * @returns {{records: Array, corrupt: number}}
 */
function parseRecords(text) {
  const records = [];
  let corrupt = 0;
  for (const line of String(text).split('\n')) {
    if (!line) continue;
    let o;
    try {
      o = JSON.parse(line);
    } catch (_e) {
      // A single unparseable line is skipped, not allowed to poison the whole
      // file — the rest of the batch is still real evidence.
      continue;
    }
    const t = new Date(o.t);
    if (Number.isNaN(t.getTime())) { corrupt += 1; continue; }
    records.push({ line: o.l, sourceIp: o.s, receivedAt: t, archived: o.a === 1 || o.a === true });
  }
  return { records, corrupt };
}

function fsyncWrite(file, payload) {
  const fd = fs.openSync(file, 'w');
  try {
    fs.writeFileSync(fd, payload);
    fs.fsyncSync(fd);            // the whole point: on disk before the DB
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Write a NEW spool file: `.tmp`, fsync, atomic rename to `.ready`.
 * A crash mid-write can therefore never leave a half-line the drain would
 * treat as a real event.
 */
function writeSpoolFile(dir, records, stamp) {
  const name = stamp || `${Date.now()}_${process.pid}_${Math.floor(Math.random() * 1e6)}`;
  const tmp = path.join(dir, `${name}.tmp`);
  const ready = path.join(dir, `${name}.ready`);
  fsyncWrite(tmp, serialiseRecords(records));
  fs.renameSync(tmp, ready);
  return ready;
}

/**
 * Replace an EXISTING spool file's contents with `records`, atomically.
 *
 * ⛔ WRITE-THEN-RENAME, NEVER TRUNCATE-AND-REWRITE. This runs on a file whose
 * records are, by definition, the only copy of evidence the database has just
 * refused; a crash part-way through an in-place rewrite would destroy the ones
 * already written past. The rename is atomic on both platforms this ships to,
 * and on a throw the ORIGINAL file is still intact and still complete, so the
 * caller degrades to replaying all of it — the behaviour that existed before.
 */
function rewriteSpoolFile(file, records) {
  const tmp = `${file}${PARTIAL_SUFFIX}`;
  fsyncWrite(tmp, serialiseRecords(records));
  fs.renameSync(tmp, file);
  return records.length;
}

/**
 * What survives a partial insert, and does the file need rewriting?
 *
 * @param {Array} records      every record read from the file, in order
 * @param {number[]} failedIndexes indexes into `records` whose chunk failed
 * @param {{archivedNow?: boolean}} opts `archivedNow` = these records were
 *        appended to the archive by THIS pass and must not be appended again
 * @returns {{remaining: Array, rewrite: boolean, reason: string}}
 */
function planRetry(records, failedIndexes, opts) {
  const archivedNow = !!(opts && opts.archivedNow === true);
  const total = records.length;

  // ⛔ AN UNATTRIBUTABLE FAILURE KEEPS THE WHOLE FILE. If the insert cannot say
  // which records failed, the only safe answer is to replay all of them: the
  // amplification this module exists to stop is a cost, and dropping a record
  // the database never accepted is a loss. Degrade toward the old behaviour,
  // never toward a smaller file.
  if (!Array.isArray(failedIndexes)) {
    return { remaining: records, rewrite: false, reason: 'unattributable' };
  }
  const failed = new Set();
  for (const i of failedIndexes) {
    if (!Number.isInteger(i) || i < 0 || i >= total) {
      return { remaining: records, rewrite: false, reason: 'unattributable' };
    }
    failed.add(i);
  }
  if (failed.size === 0) return { remaining: [], rewrite: false, reason: 'complete' };

  // Built by walking the file in order, so the surviving records keep their
  // original sequence whatever order the indexes arrived in, and a repeated
  // index cannot duplicate a record.
  const remaining = [];
  for (let i = 0; i < total; i += 1) {
    if (!failed.has(i)) continue;
    remaining.push(archivedNow && records[i].archived !== true
      ? { ...records[i], archived: true }
      : records[i]);
  }

  // Rewrite only when the bytes would actually change. In the steady DB-outage
  // case — every chunk failing, everything already archived — this is false,
  // so a stranded file costs no write at all per 2s cycle.
  const shrank = remaining.length !== total;
  const marked = archivedNow && records.some((r) => r.archived !== true);
  return {
    remaining,
    rewrite: shrank || marked,
    reason: shrank ? 'partial' : (marked ? 'archived' : 'unchanged'),
  };
}

module.exports = {
  PARTIAL_SUFFIX,
  serialiseRecords,
  parseRecords,
  writeSpoolFile,
  rewriteSpoolFile,
  planRetry,
};
