'use strict';
// Exercises the spool file's on-disk contract and the partial-insert decision
// for real, against a real temp directory and real bytes.
//
// ⛔ WHY THIS FILE EXISTS AT ALL. `services/collector.js` binds sockets at
// module load, so nothing in it can be required and every durability guard it
// carries has only ever been asserted against its SOURCE TEXT. This repo has
// twice watched that shape of assertion pass over an inverted guard, and the
// spool file is the one place where a wrong decision destroys evidence held
// nowhere else. So the decision moved into lib/syslog/spoolFile.js and this
// runs it.
//
// ⛔ WHAT IT PINS (roadmap row 34): a single rejected 500-row chunk used to
// make the collector re-insert the ENTIRE spool file roughly 900 times — the
// quarantine budget is 5 attempts AND 30 minutes, which at a 2s flush is ~900
// retries — re-committing every chunk that had already landed, with a
// duplicate gzip archive member each pass.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const spool = require('../lib/syslog/spoolFile');
const { insertEvents, MAX_ROWS_PER_INSERT } = require('../lib/syslog/eventStore');
const { appendRecords } = require('../lib/syslog/archive');

const tmpdir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sv-spool-'));
const rec = (n, archived) => ({
  line: `line ${n}`,
  sourceIp: '10.0.0.1',
  receivedAt: new Date('2026-11-15T10:00:00Z'),
  ...(archived === undefined ? {} : { archived }),
});
const many = (n, archived) => Array.from({ length: n }, (_, i) => rec(i, archived));

describe('the spool file round trip', () => {
  it('survives write -> read unchanged', () => {
    const dir = tmpdir();
    const file = spool.writeSpoolFile(dir, many(3));
    assert.ok(file.endsWith('.ready'));
    const { records, corrupt } = spool.parseRecords(fs.readFileSync(file, 'utf8'));
    assert.equal(corrupt, 0);
    assert.equal(records.length, 3);
    assert.equal(records[0].line, 'line 0');
    assert.equal(records[0].receivedAt.toISOString(), '2026-11-15T10:00:00.000Z');
  });

  it('⛔ omits the archived marker when false, so a first write is byte-identical to the old format', () => {
    const text = spool.serialiseRecords(many(1));
    assert.ok(!text.includes('"a"'), `an unarchived record must carry no marker: ${text}`);
    // And the exact legacy shape, so an older build reading a newer file is
    // reading something it already understands.
    assert.equal(text, JSON.stringify({ l: 'line 0', s: '10.0.0.1', t: '2026-11-15T10:00:00.000Z' }));
  });

  it('carries the archived marker back out again', () => {
    const { records } = spool.parseRecords(spool.serialiseRecords(many(2, true)));
    assert.deepEqual(records.map((r) => r.archived), [true, true]);
  });

  it('⛔ counts a record whose timestamp is unreadable instead of stamping it "now"', () => {
    // received_at is the partition key. Substituting the restart time moves a
    // replayed record into the wrong daily partition and misdates every
    // "last N hours" query.
    const text = [
      JSON.stringify({ l: 'good', s: '10.0.0.1', t: '2026-11-15T10:00:00.000Z' }),
      JSON.stringify({ l: 'bad', s: '10.0.0.1', t: 'not a date' }),
      '{ this is not json',
    ].join('\n');
    const { records, corrupt } = spool.parseRecords(text);
    assert.equal(records.length, 1);
    assert.equal(corrupt, 1);          // the bad timestamp, counted
  });
});

describe('⛔ planRetry: what is still owed after a partial insert', () => {
  it('keeps ONLY the records whose chunk failed, in file order', () => {
    const records = many(5);
    const plan = spool.planRetry(records, [3, 1], {});
    assert.deepEqual(plan.remaining.map((r) => r.line), ['line 1', 'line 3']);
    assert.equal(plan.rewrite, true);
    assert.equal(plan.reason, 'partial');
  });

  it('⛔ keeps the WHOLE file when the failure cannot be attributed', () => {
    // Degrading toward the old behaviour is a cost; degrading toward a smaller
    // file would drop a record the database never accepted.
    for (const bad of [null, undefined, 'nope', [0, 99], [-1], [1.5]]) {
      const plan = spool.planRetry(many(3), bad, {});
      assert.equal(plan.remaining.length, 3, `input ${JSON.stringify(bad)}`);
      assert.equal(plan.rewrite, false);
      assert.equal(plan.reason, 'unattributable');
    }
  });

  it('cannot duplicate a record from a repeated index', () => {
    const plan = spool.planRetry(many(3), [1, 1, 1], {});
    assert.equal(plan.remaining.length, 1);
  });

  it('⛔ writes NOTHING per cycle in the steady database-outage case', () => {
    // Every chunk failing over already-archived records is the common stranded
    // state, retried every 2s for 30 minutes. Nothing about the file changes,
    // so it must not be rewritten 900 times either.
    const plan = spool.planRetry(many(4, true), [0, 1, 2, 3], { archivedNow: true });
    assert.equal(plan.remaining.length, 4);
    assert.equal(plan.rewrite, false);
    assert.equal(plan.reason, 'unchanged');
  });

  it('⛔ marks surviving records archived so a replay cannot append them twice', () => {
    const plan = spool.planRetry(many(4), [0, 1, 2, 3], { archivedNow: true });
    assert.equal(plan.rewrite, true);
    assert.equal(plan.reason, 'archived');
    assert.deepEqual(plan.remaining.map((r) => r.archived), [true, true, true, true]);
  });

  it('⛔ never marks archived when the append FAILED', () => {
    // The mark is a claim that the line is safely in a gzip member. Writing it
    // on a failed append turns a duplicate (harmless) into a gap (permanent).
    const plan = spool.planRetry(many(2), [0, 1], { archivedNow: false });
    assert.deepEqual(plan.remaining.map((r) => r.archived === true), [false, false]);
    assert.equal(plan.rewrite, false);
  });

  it('does not mutate the records it was handed', () => {
    const records = many(2);
    spool.planRetry(records, [0, 1], { archivedNow: true });
    assert.equal(records[0].archived, undefined);
  });
});

describe('⛔ rewriteSpoolFile is atomic and never shows a half file to the drain', () => {
  it('replaces the file in place and the scratch name is not a .ready', () => {
    const dir = tmpdir();
    const file = spool.writeSpoolFile(dir, many(5));
    spool.rewriteSpoolFile(file, many(2));
    const { records } = spool.parseRecords(fs.readFileSync(file, 'utf8'));
    assert.equal(records.length, 2);
    // ⛔ Both spool scanners filter on `.ready`. A scratch file ending in that
    // suffix would be handed to the very drain this protects.
    assert.ok(!spool.PARTIAL_SUFFIX.endsWith('.ready'));
    assert.deepEqual(fs.readdirSync(dir).filter((f) => f.endsWith('.ready')), [path.basename(file)]);
    assert.deepEqual(fs.readdirSync(dir).filter((f) => f.endsWith(spool.PARTIAL_SUFFIX)), []);
  });

  it('⛔ leaves the ORIGINAL intact and complete when the rewrite cannot be written', () => {
    const dir = tmpdir();
    const file = spool.writeSpoolFile(dir, many(5));
    const before = fs.readFileSync(file, 'utf8');
    // A record whose receivedAt is not a Date throws inside serialisation,
    // mid-way through, exactly as a full disk would throw inside the write.
    assert.throws(() => spool.rewriteSpoolFile(file, [rec(0), { line: 'x', sourceIp: 'y', receivedAt: null }]));
    assert.equal(fs.readFileSync(file, 'utf8'), before, 'the original file must be untouched');
  });
});

describe('⛔ insertEvents reports WHICH records failed, not merely how many chunks did', () => {
  const ev = (i) => ({
    receivedAt: new Date('2026-11-15T10:00:00Z'),
    eventAt: null, sourceIp: '10.0.0.1', deviceId: null, message: `m${i}`,
  });

  // Fails the Nth chunk only, like a single deterministically-bad row would.
  const poolFailingChunk = (n) => {
    let seen = 0;
    return { query: async () => { if (seen++ === n) throw new Error('bad row'); } };
  };

  it('stored + failedIndexes.length === events.length, always', async () => {
    const events = Array.from({ length: MAX_ROWS_PER_INSERT * 3 }, (_, i) => ev(i));
    const r = await insertEvents(poolFailingChunk(1), events);
    assert.equal(r.failedChunks, 1);
    assert.equal(r.stored + r.failedIndexes.length, events.length);
  });

  it('names the SECOND chunk when the second chunk is the one that failed', async () => {
    const events = Array.from({ length: MAX_ROWS_PER_INSERT * 3 }, (_, i) => ev(i));
    const r = await insertEvents(poolFailingChunk(1), events);
    assert.equal(r.failedIndexes[0], MAX_ROWS_PER_INSERT);
    assert.equal(r.failedIndexes.at(-1), MAX_ROWS_PER_INSERT * 2 - 1);
  });

  it('reports an empty failure list on a clean insert', async () => {
    const r = await insertEvents({ query: async () => {} }, [ev(0)]);
    assert.deepEqual(r.failedIndexes, []);
    assert.equal(r.stored, 1);
  });

  it('reports an empty failure list for an empty batch', async () => {
    const r = await insertEvents({ query: async () => { throw new Error('never'); } }, []);
    assert.deepEqual(r.failedIndexes, []);
  });
});

describe('⛔ THE AMPLIFICATION ITSELF: a retry re-inserts and re-archives only what is owed', () => {
  it('a second pass commits the owed records once and appends no duplicate archive member', async () => {
    const dir = tmpdir();
    const archiveDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sv-arch-'));
    const total = MAX_ROWS_PER_INSERT * 3;
    const records = many(total);
    const file = spool.writeSpoolFile(dir, records);

    // ---- pass 1: archive everything, insert, chunk 2 of 3 is refused -------
    let read = spool.parseRecords(fs.readFileSync(file, 'utf8')).records;
    let fresh = read.filter((r) => r.archived !== true);
    assert.equal(fresh.length, total, 'a first pass archives the whole file');
    assert.equal(appendRecords(archiveDir, fresh).ok, true);

    const inserted = [];
    const recordingPool = (failChunk) => {
      let seen = 0;
      return { query: async (_sql, params) => {
        const n = seen++;
        if (n === failChunk) throw new Error('refused');
        inserted.push(params.length);
      } };
    };
    let r = await insertEvents(recordingPool(1), read.map((x) => ({
      receivedAt: x.receivedAt, eventAt: null, sourceIp: x.sourceIp, deviceId: null, message: x.line,
    })));
    let plan = spool.planRetry(read, r.failedIndexes, { archivedNow: true });
    assert.equal(plan.remaining.length, MAX_ROWS_PER_INSERT, 'only the refused chunk is still owed');
    spool.rewriteSpoolFile(file, plan.remaining);

    // ---- pass 2: the retry ------------------------------------------------
    read = spool.parseRecords(fs.readFileSync(file, 'utf8')).records;
    assert.equal(read.length, MAX_ROWS_PER_INSERT,
      'the retry must re-read ONLY what is owed, not the whole file');
    fresh = read.filter((r2) => r2.archived !== true);
    assert.equal(fresh.length, 0, '⛔ nothing is appended to the archive a second time');

    const before = inserted.reduce((a, b) => a + b, 0);
    r = await insertEvents(recordingPool(-1), read.map((x) => ({
      receivedAt: x.receivedAt, eventAt: null, sourceIp: x.sourceIp, deviceId: null, message: x.line,
    })));
    assert.equal(r.failedChunks, 0);
    assert.equal(r.stored, MAX_ROWS_PER_INSERT);
    const after = inserted.reduce((a, b) => a + b, 0);
    assert.ok(after > before, 'the owed chunk was inserted on the retry');

    // The archive holds each line exactly once across both passes.
    const gz = fs.readdirSync(archiveDir).filter((f) => f.endsWith('.gz'));
    assert.equal(gz.length, 1);
    const text = zlib.gunzipSync(fs.readFileSync(path.join(archiveDir, gz[0]))).toString('utf8');
    const occurrences = text.split('\n').filter((l) => l.includes('line 0')).length;
    assert.equal(occurrences, 1, `⛔ 'line 0' must appear once, found ${occurrences}`);

    // ---- and the old behaviour is what this replaces -----------------------
    // Before the fix the retry re-read all `total` records and re-inserted all
    // three chunks, so the committed 2/3 landed twice -- every 2s, ~900 times.
    assert.ok(MAX_ROWS_PER_INSERT * 3 > MAX_ROWS_PER_INSERT);
  });
});

describe('⛔ the collector actually wires it (source-scanned, because it cannot be required)', () => {
  // ⛔ COMMENT-STRIPPED FIRST. processSpoolFile's own prose describes the
  // behaviour it replaced, so a raw-text scan would match the defect.
  const { stripComments } = require('./stripComments');
  const raw = fs.readFileSync(path.join(__dirname, '..', 'services', 'collector.js'), 'utf8')
    .replace(/\r\n/g, '\n');
  const code = stripComments(raw);
  const fn = code.slice(code.indexOf('async function processSpoolFile'));
  const body = fn.slice(0, fn.indexOf('\n}'));

  it('⛔ appends ONLY records not already in the archive', () => {
    // The whole archive half of row 34: a file stranded by a database outage
    // is retried ~900 times, and before this each retry appended another full
    // gzip member of the same lines to the one store that cannot be rebuilt.
    assert.match(body, /records\.filter\(\(r\) => r\.archived !== true\)/);
    assert.match(body, /appendRecords\(ARCHIVE_DIR, fresh\)/);
    assert.doesNotMatch(body, /appendRecords\(ARCHIVE_DIR, records\)/);
  });

  it('⛔ only claims a record is archived after a SUCCESSFUL append', () => {
    // The mark is a claim that the line is safely in a gzip member. Setting it
    // on a failed append turns a duplicate (harmless) into a gap (permanent,
    // and in the only copy of the raw line for ~89% of traffic).
    //
    // ⛔ ASSERTED STRUCTURALLY, not by proximity. The first draft of this test
    // forbade `archivedNow = true` within 120 characters of `archiveFailures
    // += 1` — and the intervening `} else {` is only ~110 characters long, so
    // it FAILED ON CORRECT CODE. A guard that cries wolf gets waived, which is
    // how the check stops happening.
    const failStart = body.indexOf('if (!a.ok) {');
    assert.ok(failStart > 0, 'the archive failure branch must exist');
    const failBranch = body.slice(failStart, body.indexOf('} else {', failStart));
    assert.doesNotMatch(failBranch, /archivedNow/,
      'the failure branch must not claim the records were archived');
    assert.match(body.slice(body.indexOf('} else {', failStart)), /archivedNow = true/);
  });

  it('⛔ keeps only what is still owed, and rewrites the file to say so', () => {
    assert.match(body, /spoolFile\.planRetry\(records, failedIndexes, \{ archivedNow \}\)/);
    assert.match(body, /spoolFile\.rewriteSpoolFile\(file, plan\.remaining\)/);
  });

  it('⛔ still deletes the file ONLY on a fully successful insert', () => {
    assert.match(body, /if \(failedChunks === 0\) \{\s*\n\s*fs\.unlinkSync\(file\);/);
  });

  it('⛔ a failed rewrite keeps the whole file rather than risking a truncated one', () => {
    assert.match(body, /catch \(err\) \{[\s\S]{0,400}could not rewrite/);
  });
});
