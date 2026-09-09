// lib/syslog/archive.js
//
// Compressed raw-log archive — the storage model ManageEngine Firewall
// Analyzer used, measured directly from its own preserved archives on
// 2026-09-08: 315.8 GB on disk holding 4,186 GB of raw log text, a ratio of
// 13.3x.
//
// ── WHY A FILE AND NOT A COLUMN ───────────────────────────────────────────
// SecVault stores `message` as a plain column, 748 bytes average, and measured
// on the live fleet PostgreSQL stores it at 752 bytes — i.e. NO compression at
// all. That is not a misconfiguration: TOAST only compresses a value once the
// whole tuple crosses ~2 KB, and these rows are ~1 KB, so the text stays inline
// and verbatim.
//
// ⛔ And PostgreSQL could never reach 13.3x here even if it did compress. That
// ratio comes from compressing across LINES — thousands of near-identical log
// entries sharing one dictionary. A row can only ever compress against itself,
// which is worth 2-3x on a 750-byte string. The gap is architectural, not a
// tuning problem, so the fix has to be architectural too.
//
// ── THE FORMAT: CONCATENATED GZIP MEMBERS ─────────────────────────────────
// Each flush appends one COMPLETE, self-contained gzip member to the day's
// file. gzip defines a stream as a sequence of members, so `gunzip`, `zcat`,
// `zgrep` and Node's gunzip all read the result as one continuous file.
//
// ⛔ This is chosen for CRASH SAFETY over ratio. A single long-lived gzip
// stream compresses a few percent better and is unreadable if the process dies
// mid-write — which for an archive is the one failure that matters, because
// you discover it months later when you finally need the file. Per-flush
// members mean a crash can damage at most the final member, and everything
// before it still reads.
//
// ⛔ READING THESE FILES: use GNU gunzip/zcat/zgrep, or Node. .NET FRAMEWORK's
// GZipStream (which is what PowerShell 5.1 gives you) reads only the FIRST
// member and stops. Verifying a 15.5 MB archive that way reported 1,146 lines
// and a "0.1x ratio"; the same file through Node gave 231,567 lines and 11.1x.
// The archive was fine and the verifier was wrong -- a bug shape that reports
// data loss which has not happened, and would hide real loss just as happily.
//
// ⛔ ARCHIVING MUST NEVER BREAK INGEST. Every function here returns its error
// rather than throwing, and the collector treats a failed append as a logged
// warning, not a lost batch. The database is the primary store; this is the
// long-tail copy.

'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const DEFAULT_RETENTION_DAYS = 90;

/** UTC day key, matching the partition naming so a file lines up with a partition. */
function dayKey(date) {
  const d = date instanceof Date ? date : new Date();
  return d.toISOString().slice(0, 10).replace(/-/g, '');
}

function fileNameFor(date) {
  return `syslog-${dayKey(date)}.log.gz`;
}

// Only ever operates on files it recognises. A stray file in the directory is
// left alone rather than deleted — the same rule dropOldPartitions() follows.
const ARCHIVE_FILE_RE = /^syslog-(\d{8})\.log\.gz$/;

/**
 * Append a batch of raw lines to the day's archive.
 *
 * ⛔ Never throws. Returns `{ok, bytesRaw, bytesCompressed, file, error}` so
 * the caller can log and carry on. An archive that takes the collector down is
 * worse than no archive.
 *
 * @param {string} dir archive directory
 * @param {string[]} lines raw log lines, exactly as received
 * @param {Date} now used only to pick the day file
 */
function appendBatch(dir, lines, now) {
  const out = { ok: false, bytesRaw: 0, bytesCompressed: 0, file: null, error: null };
  if (!dir) { out.error = 'no archive directory configured'; return out; }
  if (!Array.isArray(lines) || lines.length === 0) { out.ok = true; return out; }

  try {
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, fileNameFor(now || new Date()));
    // One trailing newline per line so the decompressed file is line-oriented
    // and greppable exactly like the original syslog stream.
    const text = lines.join('\n') + '\n';
    const raw = Buffer.from(text, 'utf8');
    // level 6: the default. 9 costs roughly 3x the CPU for ~2% better ratio,
    // which at ~1,500 lines/second is not a trade worth making.
    const gz = zlib.gzipSync(raw, { level: 6 });

    // A single append of one complete member. Concatenated members remain a
    // valid gzip stream, so the day file is readable with ordinary tools.
    //
    // ⛔ fsync'd, not just written. Without it a crash can leave a TORN member
    // in the MIDDLE of the day file — the collector restarts into the same UTC
    // day and keeps appending, so the real post-crash layout is
    // [complete][complete][torn][complete][complete]. gunzip/zcat/zgrep stop
    // at the tear, making every complete member after it reachable only by
    // hand-scanning for 0x1f8b. This archive is the ONLY copy of the raw line
    // for the ~89% of traffic that SYSLOG_RAW_MESSAGE=security drops from the
    // database, so a silent mid-file tear is unrecoverable evidence loss that
    // would surface months later.
    const fd = fs.openSync(file, 'a');
    try {
      fs.writeSync(fd, gz);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }

    out.ok = true;
    out.file = file;
    out.bytesRaw = raw.length;
    out.bytesCompressed = gz.length;
  } catch (err) {
    out.error = err && err.message ? err.message : String(err);
  }
  return out;
}

/**
 * Append records to the archive, filing each one under ITS OWN UTC day.
 *
 * ⛔ WHY THIS EXISTS, AND WHY appendBatch(dir, lines, new Date()) IS WRONG FOR
 * A SPOOL FILE. The collector's caller used to pass `new Date()` — the moment
 * of the INSERT, not the moment the line arrived. Two entirely routine paths
 * put those in different UTC days:
 *   1. a spool file replayed at startup after an outage or a deploy, and
 *   2. any flush that crosses UTC midnight (guaranteed, once a day, forever).
 * The line then lands in a day file it does not belong to. This archive is the
 * ONLY copy of the raw text for the ~89% of traffic SYSLOG_RAW_MESSAGE=security
 * drops from the database, so a forensic `zgrep syslog-20260908.log.gz` for an
 * incident on the 8th silently returns fewer lines than really existed — no
 * error, no gap, just an under-count in the one place that cannot be
 * reconstructed. Same failed-read-as-a-fact shape as everything else here.
 *
 * `receivedAt` is the collector's own arrival stamp — the same value that
 * becomes syslog_events.received_at and picks the daily PARTITION — so the
 * archive file and the partition always describe the same set of lines.
 *
 * ⛔ Never throws. Returns the aggregate of the per-day appends; a day that
 * fails is reported in `error` while the other days still land, because
 * archiving must never break ingest.
 *
 * @param {string} dir archive directory
 * @param {{line: string, receivedAt: Date}[]} records as spooled
 * @param {Date} [fallback] day used for a record with no usable receivedAt
 */
function appendRecords(dir, records, fallback) {
  const out = { ok: false, bytesRaw: 0, bytesCompressed: 0, files: [], error: null };
  if (!dir) { out.error = 'no archive directory configured'; return out; }
  if (!Array.isArray(records) || records.length === 0) { out.ok = true; return out; }

  try {
    // Insertion-ordered map, so lines keep their arrival order inside a day
    // file and the common case (one day) is a single append, exactly as
    // before.
    const byDay = new Map();
    for (const r of records) {
      if (!r) continue;
      const t = r.receivedAt instanceof Date && !Number.isNaN(r.receivedAt.getTime())
        ? r.receivedAt
        : (fallback instanceof Date && !Number.isNaN(fallback.getTime()) ? fallback : new Date());
      const key = dayKey(t);
      let group = byDay.get(key);
      if (!group) { group = { date: t, lines: [] }; byDay.set(key, group); }
      group.lines.push(r.line);
    }

    let allOk = true;
    for (const group of byDay.values()) {
      const a = appendBatch(dir, group.lines, group.date);
      if (a.ok) {
        out.bytesRaw += a.bytesRaw;
        out.bytesCompressed += a.bytesCompressed;
        if (a.file) out.files.push(a.file);
      } else {
        allOk = false;
        if (!out.error) out.error = a.error;
      }
    }
    out.ok = allOk;
  } catch (err) {
    out.error = err && err.message ? err.message : String(err);
  }
  return out;
}

/**
 * Delete archive files older than the retention window.
 *
 * ⛔ Only ever deletes names matching ARCHIVE_FILE_RE, and only ones strictly
 * older than the cutoff — the same discipline as dropOldPartitions(). Anything
 * else in the directory is not ours and is left untouched.
 *
 * Never throws; returns what it removed and any error.
 */
function pruneArchive(dir, retentionDays, now) {
  const out = { removed: [], keptCount: 0, error: null };
  if (!dir) { out.error = 'no archive directory configured'; return out; }

  const days = Number.isFinite(Number(retentionDays)) && Number(retentionDays) >= 1
    ? Math.trunc(Number(retentionDays))
    : DEFAULT_RETENTION_DAYS;

  try {
    if (!fs.existsSync(dir)) return out;
    const cutoff = new Date((now instanceof Date ? now : new Date()).getTime() - days * 86400000);
    const cutoffKey = dayKey(cutoff);

    for (const name of fs.readdirSync(dir)) {
      const m = ARCHIVE_FILE_RE.exec(name);
      if (!m) continue;
      // String compare is safe and correct: YYYYMMDD sorts chronologically.
      if (m[1] < cutoffKey) {
        try {
          fs.unlinkSync(path.join(dir, name));
          out.removed.push(name);
        } catch (err) {
          out.error = `${name}: ${err.message}`;
        }
      } else {
        out.keptCount += 1;
      }
    }
  } catch (err) {
    out.error = err && err.message ? err.message : String(err);
  }
  return out;
}

/**
 * What the archive currently holds. Used by the collector's startup banner and
 * by the ingest-health view, so the archive's real size and ratio are visible
 * rather than assumed.
 */
function archiveStats(dir) {
  const out = { files: 0, bytes: 0, oldest: null, newest: null, error: null };
  if (!dir) { out.error = 'no archive directory configured'; return out; }
  try {
    if (!fs.existsSync(dir)) return out;
    for (const name of fs.readdirSync(dir)) {
      const m = ARCHIVE_FILE_RE.exec(name);
      if (!m) continue;
      out.files += 1;
      try { out.bytes += fs.statSync(path.join(dir, name)).size; } catch { /* raced with prune */ }
      if (out.oldest === null || m[1] < out.oldest) out.oldest = m[1];
      if (out.newest === null || m[1] > out.newest) out.newest = m[1];
    }
  } catch (err) {
    out.error = err && err.message ? err.message : String(err);
  }
  return out;
}

module.exports = {
  appendBatch,
  appendRecords,
  pruneArchive,
  archiveStats,
  fileNameFor,
  dayKey,
  ARCHIVE_FILE_RE,
  DEFAULT_RETENTION_DAYS,
};
