'use strict';
//
// scripts/fwaArchive.js — read the preserved ManageEngine Firewall Analyzer
// archive, dependency-free.
//
// ⛔ WHY A HAND-ROLLED ZIP READER. package.json has NO devDependencies by
// deliberate policy (Update-SecVault.ps1 runs `npm ci` on a firewall-management
// box), and node has no built-in ZIP container reader — only zlib, which is the
// COMPRESSION, not the archive format. A one-off migration is the worst possible
// reason to add a runtime dependency that then ships to every install for ever.
// The ZIP container is a documented format and the part we need is small: find
// the central directory, walk it, and stream each entry through inflateRaw.
//
// ⛔ IT REFUSES WHAT IT CANNOT READ RATHER THAN GUESSING. ZIP64, encryption and
// unknown compression methods each throw by name. An archive this size will
// contain something unexpected, and a reader that silently skipped it would
// under-count the history by an amount nobody could measure afterwards.
//
// Read-only. Nothing in this file writes to the database or to disk.

const fs = require('node:fs');
const zlib = require('node:zlib');

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;
const ZIP64_EOCD_LOCATOR_SIG = 0x07064b50;

// The EOCD is at the very end unless there is a trailing comment, which is
// capped at 64 KB by the format.
const EOCD_SCAN_BYTES = 66_000;

function findEocd(fd, fileSize) {
  const scan = Math.min(EOCD_SCAN_BYTES, fileSize);
  const buf = Buffer.alloc(scan);
  fs.readSync(fd, buf, 0, scan, fileSize - scan);
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      return {
        entries: buf.readUInt16LE(i + 10),
        cdSize: buf.readUInt32LE(i + 12),
        cdOffset: buf.readUInt32LE(i + 16),
        // A ZIP64 locator sits immediately before the EOCD when present.
        zip64: i >= 20 && buf.readUInt32LE(i - 20) === ZIP64_EOCD_LOCATOR_SIG,
      };
    }
  }
  return null;
}

/**
 * Entries in one zip: {name, method, compressedSize, uncompressedSize, localOffset}.
 * ⛔ Reads the CENTRAL DIRECTORY, not the local headers. A local header may
 * carry zeroed sizes with the real values in a trailing data descriptor
 * (streamed writers do this, and FWA rotates logs as it writes them); the
 * central directory is authoritative.
 */
function listEntries(filePath) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const { size } = fs.fstatSync(fd);
    if (size === 0) throw new Error('zero-length archive');
    const eocd = findEocd(fd, size);
    if (!eocd) throw new Error('no end-of-central-directory record — not a zip, or truncated');
    if (eocd.zip64) throw new Error('ZIP64 archive — this reader does not handle it');

    const cd = Buffer.alloc(eocd.cdSize);
    fs.readSync(fd, cd, 0, eocd.cdSize, eocd.cdOffset);

    const out = [];
    let p = 0;
    for (let n = 0; n < eocd.entries; n++) {
      if (cd.readUInt32LE(p) !== CD_SIG) throw new Error(`central directory entry ${n} has a bad signature`);
      const flags = cd.readUInt16LE(p + 8);
      if (flags & 0x1) throw new Error(`entry ${n} is encrypted`);
      const method = cd.readUInt16LE(p + 10);
      const compressedSize = cd.readUInt32LE(p + 20);
      const uncompressedSize = cd.readUInt32LE(p + 24);
      const nameLen = cd.readUInt16LE(p + 28);
      const extraLen = cd.readUInt16LE(p + 30);
      const commentLen = cd.readUInt16LE(p + 32);
      const localOffset = cd.readUInt32LE(p + 42);
      const name = cd.toString('utf8', p + 46, p + 46 + nameLen);
      if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff) {
        throw new Error(`entry ${name} uses ZIP64 size fields`);
      }
      out.push({ name, method, compressedSize, uncompressedSize, localOffset });
      p += 46 + nameLen + extraLen + commentLen;
    }
    return out;
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Where an entry's DATA begins. The local header repeats the name and carries
 * its own extra field, whose length routinely differs from the central
 * directory's — so this must be read, never computed from the CD.
 */
function dataOffset(fd, entry) {
  const head = Buffer.alloc(30);
  fs.readSync(fd, head, 0, 30, entry.localOffset);
  if (head.readUInt32LE(0) !== LOCAL_SIG) throw new Error(`bad local header for ${entry.name}`);
  return entry.localOffset + 30 + head.readUInt16LE(26) + head.readUInt16LE(28);
}

/**
 * Stream one entry, calling onLine for each text line.
 *
 * ⛔ STREAMED, NEVER BUFFERED WHOLE. The largest entries measured in this
 * archive are ~1.4 GB uncompressed; reading one into a string would blow the
 * heap and, worse, would do so only on the few biggest files — a failure that
 * appears hours into a batch run.
 *
 * ⛔ A partial line is carried across chunk boundaries. Splitting each chunk
 * independently would silently corrupt one event per chunk, which at this
 * volume is millions of quietly malformed records.
 */
function streamEntryLines(filePath, entry, onLine) {
  return new Promise((resolve, reject) => {
    if (entry.method !== 0 && entry.method !== 8) {
      reject(new Error(`${entry.name}: unsupported compression method ${entry.method}`));
      return;
    }
    let fd;
    try {
      fd = fs.openSync(filePath, 'r');
    } catch (err) { reject(err); return; }

    let start;
    try {
      start = dataOffset(fd, entry);
    } catch (err) { fs.closeSync(fd); reject(err); return; }

    const raw = fs.createReadStream(null, {
      fd,
      start,
      end: start + entry.compressedSize - 1,
      autoClose: true,
    });
    const src = entry.method === 8 ? raw.pipe(zlib.createInflateRaw()) : raw;

    let tail = '';
    let lines = 0;
    src.on('data', (chunk) => {
      const text = tail + chunk.toString('latin1');
      const parts = text.split('\n');
      tail = parts.pop();
      for (const line of parts) {
        const t = line.endsWith('\r') ? line.slice(0, -1) : line;
        if (t.length === 0) continue;
        lines++;
        onLine(t);
      }
    });
    src.on('error', reject);
    src.on('end', () => {
      if (tail.trim().length > 0) { lines++; onLine(tail.endsWith('\r') ? tail.slice(0, -1) : tail); }
      resolve(lines);
    });
  });
}

// FWA lays the archive out as <sender>/<sender>_YYYY_MM_DD_HH_MM_SS.zip, and
// each entry inside is named YYYY_MM_DD_HH_MM_SS (the rotation moment).
//
// ⛔ THIS IS THE ONLY PLACE A YEAR COMES FROM. RFC 3164 timestamps inside the
// logs carry no year and no timezone — the trap this codebase already
// documents for VPN login times. The filename is FWA's own statement of when it
// wrote the file, so it anchors the year; anything that cannot be anchored is
// COUNTED and reported, never guessed into the current year.
const STAMP_RE = /(\d{4})_(\d{2})_(\d{2})_(\d{2})_(\d{2})_(\d{2})/;

function stampFromName(name) {
  const m = STAMP_RE.exec(name);
  if (!m) return null;
  const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  return Number.isNaN(d.getTime()) ? null : d;
}

/** The sender is the directory name, and the filename repeats it. */
function senderFromPath(relPath) {
  const parts = relPath.split(/[\\/]/).filter(Boolean);
  return parts.length > 1 ? parts[0] : null;
}

module.exports = {
  listEntries,
  streamEntryLines,
  stampFromName,
  senderFromPath,
  EOCD_SCAN_BYTES,
};
