'use strict';
// Pins the compressed raw-log archive — the storage model measured directly
// out of ManageEngine Firewall Analyzer's own preserved archives on
// 2026-09-08: 315.8 GB on disk holding 4,186 GB of raw text, a ratio of 13.3x.
//
// SecVault's database stores the same text at 1.0x (measured: 748 bytes of
// message, 752 bytes stored), because TOAST only compresses once a tuple
// crosses ~2 KB and these rows are ~1 KB. Real fleet traffic gzips at 10.8x,
// so this file is worth ~90 GB/day.
//
// Two properties matter more than the ratio:
//   1. The file must still be READABLE after a crash. Each flush appends one
//      complete gzip member; a torn tail must not destroy everything before it.
//      This is the failure you discover months later, when you finally need it.
//   2. Pruning must only ever touch files it recognises.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const {
  appendBatch, pruneArchive, archiveStats, fileNameFor, dayKey, ARCHIVE_FILE_RE,
} = require('../lib/syslog/archive');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sv-archive-'));
}

const DAY = new Date('2026-09-08T10:00:00Z');

describe('archive: the file is a valid, readable gzip stream', () => {
  it('⛔ concatenated members from many flushes read back as ONE file', () => {
    // The whole format rests on this. gzip defines a stream as a SEQUENCE of
    // members, so appending independent members stays readable by gunzip,
    // zcat and zgrep — which is what makes per-flush appends safe.
    const dir = tmpDir();
    try {
      for (let f = 0; f < 5; f++) {
        const lines = Array.from({ length: 100 }, (_, i) => `flush${f} line${i}`);
        assert.equal(appendBatch(dir, lines, DAY).ok, true);
      }
      const file = path.join(dir, fileNameFor(DAY));
      const back = zlib.gunzipSync(fs.readFileSync(file)).toString('utf8');
      const lines = back.split('\n').filter(Boolean);
      assert.equal(lines.length, 500, 'every line from every flush must survive');
      assert.equal(lines[0], 'flush0 line0');
      assert.equal(lines[499], 'flush4 line99');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('⛔ a torn final member does not destroy the members before it', () => {
    // The crash case. A single long-lived gzip stream would be unreadable
    // end-to-end; per-flush members mean everything already written still
    // reads, and only the interrupted tail is lost.
    const dir = tmpDir();
    try {
      appendBatch(dir, ['good line 1', 'good line 2'], DAY);
      appendBatch(dir, ['good line 3'], DAY);
      const file = path.join(dir, fileNameFor(DAY));
      // Simulate a crash mid-append: a truncated member glued on the end.
      const partial = zlib.gzipSync(Buffer.from('torn line\n')).subarray(0, 12);
      fs.appendFileSync(file, partial);

      // Node's gunzipSync rejects the trailing garbage, so a reader must be
      // able to recover the intact prefix. That is exactly what a real
      // recovery would do, so assert it is possible.
      const buf = fs.readFileSync(file);
      let recovered = '';
      let offset = 0;
      while (offset < buf.length) {
        try {
          const inflator = new zlib.Gunzip();
          const chunk = zlib.gunzipSync(buf.subarray(offset));
          recovered += chunk.toString('utf8');
          break;
        } catch {
          // Walk back to the last complete member boundary.
          const next = buf.indexOf(Buffer.from([0x1f, 0x8b]), offset + 2);
          if (next === -1) break;
          recovered += zlib.gunzipSync(buf.subarray(offset, next)).toString('utf8');
          offset = next;
        }
      }
      assert.match(recovered, /good line 1/);
      assert.match(recovered, /good line 3/, 'members before the tear must survive');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('names files by UTC day so they line up with the table partitions', () => {
    assert.equal(fileNameFor(new Date('2026-09-08T23:59:59Z')), 'syslog-20260908.log.gz');
    assert.equal(fileNameFor(new Date('2026-09-09T00:00:01Z')), 'syslog-20260909.log.gz');
    assert.equal(dayKey(new Date('2026-01-02T00:00:00Z')), '20260102');
  });

  it('reports the compression it actually achieved', () => {
    const dir = tmpDir();
    try {
      const lines = Array.from({ length: 2000 }, (_, i) =>
        `date=2026-09-08 devname="FG" srcip=10.0.0.${i % 250} action="accept" app="SSL"`);
      const r = appendBatch(dir, lines, DAY);
      assert.ok(r.bytesRaw > 0 && r.bytesCompressed > 0);
      assert.ok(r.bytesCompressed < r.bytesRaw, 'it must actually compress');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('⛔ archive: never throws, because ingest must survive it', () => {
  it('returns an error instead of throwing when the directory is unusable', () => {
    // A full or unmounted archive volume must degrade to a logged warning, not
    // take the collector down. The database is the primary store.
    const r = appendBatch('\0::invalid::', ['x'], DAY);
    assert.equal(r.ok, false);
    assert.ok(r.error);
  });

  it('handles a missing directory, empty batch and junk input', () => {
    assert.equal(appendBatch(null, ['x'], DAY).ok, false);
    const dir = tmpDir();
    try {
      assert.equal(appendBatch(dir, [], DAY).ok, true, 'an empty batch is a no-op, not a failure');
      assert.equal(appendBatch(dir, null, DAY).ok, true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('pruning a directory that does not exist is not an error', () => {
    const r = pruneArchive(path.join(os.tmpdir(), 'sv-does-not-exist-' + Date.now()), 30, DAY);
    assert.equal(r.error, null);
    assert.deepEqual(r.removed, []);
  });
});

describe('archive: pruning only touches its own files', () => {
  it('⛔ leaves files it does not recognise strictly alone', () => {
    // Same discipline as dropOldPartitions(): a stray file in the directory is
    // somebody else's, and deleting it is not this job's business.
    const dir = tmpDir();
    try {
      fs.writeFileSync(path.join(dir, 'syslog-20200101.log.gz'), 'old');
      fs.writeFileSync(path.join(dir, 'important-notes.txt'), 'keep me');
      fs.writeFileSync(path.join(dir, 'syslog-backup.tar'), 'keep me too');
      const r = pruneArchive(dir, 30, DAY);
      assert.deepEqual(r.removed, ['syslog-20200101.log.gz']);
      assert.ok(fs.existsSync(path.join(dir, 'important-notes.txt')));
      assert.ok(fs.existsSync(path.join(dir, 'syslog-backup.tar')));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('keeps everything inside the retention window', () => {
    const dir = tmpDir();
    try {
      // 10 days before DAY, with a 30-day window — must survive.
      fs.writeFileSync(path.join(dir, 'syslog-20260829.log.gz'), 'recent');
      fs.writeFileSync(path.join(dir, 'syslog-20250101.log.gz'), 'ancient');
      const r = pruneArchive(dir, 30, DAY);
      assert.deepEqual(r.removed, ['syslog-20250101.log.gz']);
      assert.equal(r.keptCount, 1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('⛔ falls back to the documented default rather than deleting everything', () => {
    // A retention of 0 or NaN reaching the cutoff maths would wipe the archive.
    const dir = tmpDir();
    try {
      fs.writeFileSync(path.join(dir, 'syslog-20260901.log.gz'), 'week old');
      for (const bad of [0, -1, null, undefined, NaN, 'x']) {
        const r = pruneArchive(dir, bad, DAY);
        assert.deepEqual(r.removed, [], `retention=${JSON.stringify(bad)} must not delete recent files`);
      }
      assert.ok(fs.existsSync(path.join(dir, 'syslog-20260901.log.gz')));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('the filename pattern only matches an 8-digit day key', () => {
    assert.ok(ARCHIVE_FILE_RE.test('syslog-20260908.log.gz'));
    for (const bad of ['syslog-2026098.log.gz', 'syslog-.log.gz', 'syslog-20260908.log', 'x-20260908.log.gz']) {
      assert.equal(ARCHIVE_FILE_RE.test(bad), false, bad);
    }
  });
});

describe('archive: stats report what is really on disk', () => {
  it('counts files and reports the day range covered', () => {
    const dir = tmpDir();
    try {
      appendBatch(dir, ['a'], new Date('2026-09-06T00:00:00Z'));
      appendBatch(dir, ['b'], new Date('2026-09-08T00:00:00Z'));
      fs.writeFileSync(path.join(dir, 'not-ours.txt'), 'x');
      const st = archiveStats(dir);
      assert.equal(st.files, 2, 'only archive files are counted');
      assert.equal(st.oldest, '20260906');
      assert.equal(st.newest, '20260908');
      assert.ok(st.bytes > 0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
