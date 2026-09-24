'use strict';
// tests/logExport.test.js
//
// Pins lib/syslog/logExport.js — the CSV a log search leaves the product as.
//
// ⛔ THE CASE THIS FILE EXISTS FOR IS THE ONE THAT PRODUCES A FILE ANYWAY.
// /logs can render a partial answer because a banner above it says so. A CSV
// carries no banner: it is mailed, attached to a ticket, opened in six weeks
// by someone who never saw the search. So a timed-out search and a
// beyond-the-ceiling search must REFUSE, and the failure that would slip
// through review is the one where they quietly serve an empty-but-valid file
// instead — byte-identical to "nothing matched", with no way back to the
// difference. Both are asserted on the returned shape AND on the absence of a
// `csv` key, because a refusal that still carries a document is a refusal the
// route could accidentally serve.
//
// ⛔ AND THE MESSAGE COLUMN IS ATTACKER-CONTROLLED BY CONSTRUCTION. It is the
// raw syslog line, written by whoever sent the packet. A cell beginning `=`
// executes on open in Excel; that is not a hypothetical here, it is the normal
// shape of the data.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  exportEvents,
  renderEventsCsv,
  exportFilename,
  isoUtc,
  COLUMNS,
} = require('../lib/syslog/logExport');
const { EXPORT_MAX_ROWS } = require('../lib/syslog/logSearch');
const { UTF8_BOM } = require('../lib/csv');

const NOW = new Date('2026-09-24T12:00:00.000Z');

function eventRow(over = {}) {
  return {
    id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    receivedAt: new Date('2026-09-24T09:04:18.380Z'),
    eventAt: new Date('2026-09-24T09:04:18.000Z'),
    tzAssumed: false,
    sourceIp: '192.168.7.1',
    deviceId: 'dev-1',
    vendor: 'fortinet',
    severity: 5,
    hostname: 'fw01',
    action: 'close',
    authOutcome: 'failure',
    srcIp: '93.88.206.223',
    dstIp: '10.1.1.1',
    srcPort: 44321,
    dstPort: 10443,
    protocol: 'tcp',
    application: 'ssl',
    srcZone: 'wan',
    dstZone: 'dmz',
    ruleName: 'VPN-IN',
    ruleId: '42',
    logClass: 'vpn',
    logSubtype: 'vpn',
    srcUser: 'admin',
    srcCountry: 'Poland',
    dstCountry: 'Thailand',
    urlCategory: null,
    urlHostname: null,
    threatName: null,
    threatSeverity: null,
    bytesSent: 120,
    bytesReceived: 0,
    message: 'date=2026-09-24 action=login-fail user="admin"',
    ...over,
  };
}

// A pool whose search returns whatever the handler says. Mirrors the stub
// shape tests/logSearch.test.js uses — nothing here talks to a database.
function stubPool(rows, opts = {}) {
  return {
    query: async () => { throw new Error('must not use pool.query — the timeout would leak'); },
    connect: async () => ({
      query: async (sql) => {
        const q = String(sql).trim();
        if (/^(BEGIN|COMMIT|ROLLBACK|SET LOCAL)/i.test(q)) return { rows: [] };
        if (opts.timeout) {
          const e = new Error('canceling statement due to statement timeout');
          e.code = '57014';
          throw e;
        }
        return { rows };
      },
      release() {},
    }),
  };
}

// searchEvents maps snake_case DB rows to camelCase. The stub returns DB shape.
function dbRow(over = {}) {
  const r = eventRow(over);
  return {
    id: r.id, received_at: r.receivedAt, event_at: r.eventAt, tz_assumed: r.tzAssumed,
    source_ip: r.sourceIp, device_id: r.deviceId, vendor: r.vendor, severity: r.severity,
    hostname: r.hostname, action: r.action, auth_outcome: r.authOutcome, src_ip: r.srcIp,
    dst_ip: r.dstIp, src_port: r.srcPort, dst_port: r.dstPort, protocol: r.protocol,
    application: r.application, src_zone: r.srcZone, dst_zone: r.dstZone,
    rule_name: r.ruleName, rule_id: r.ruleId, log_class: r.logClass,
    log_subtype: r.logSubtype, src_user: r.srcUser, src_country: r.srcCountry,
    dst_country: r.dstCountry, url_category: r.urlCategory, url_hostname: r.urlHostname,
    threat_name: r.threatName, threat_severity: r.threatSeverity,
    bytes_sent: r.bytesSent, bytes_received: r.bytesReceived, message: r.message,
  };
}

const lines = (csv) => csv.replace(UTF8_BOM, '').trimEnd().split('\r\n');

describe('the CSV document', () => {
  it('always has a header, even with nothing to report', () => {
    // ⛔ "The export is broken" and "nothing matched" must not produce the
    // same file. A header-only CSV is a real, readable answer.
    const csv = renderEventsCsv([]);
    assert.equal(lines(csv).length, 1);
    assert.match(lines(csv)[0], /^"received_at_utc"/);
  });

  it('neutralises a formula in the raw log line', () => {
    // The message is written by whoever sent the packet.
    const csv = renderEventsCsv([eventRow({ message: '=cmd|\' /C calc\'!A0' })]);
    assert.match(csv, /"'=cmd/, 'a leading = reached the cell unescaped');
  });

  it('neutralises one hidden behind whitespace Excel strips first', () => {
    // ⛔ Excel strips \t\r\n and THEN reads the leading character, so a naive
    // check on index 0 of the raw string is defeated by "\t=...".
    const csv = renderEventsCsv([eventRow({ message: '\t=HYPERLINK("http://x")' })]);
    assert.match(csv, /"'\s?=HYPERLINK/, 'a tab-prefixed formula survived');
    assert.ok(!/\t/.test(csv), 'a tab reached the document');
  });

  it('never lets a value break out of its row', () => {
    const csv = renderEventsCsv([eventRow({ message: 'a"b,c\nd' })]);
    assert.equal(lines(csv).length, 2, 'an embedded newline split the record');
    assert.match(csv, /"a""b,c d"/);
  });

  it('carries the UTF-8 BOM, because the destination is a spreadsheet', () => {
    // Excel ignores charset=utf-8 on a downloaded file; a Thai or accented
    // username then opens as mojibake, which on evidence is a corrupted
    // identifier rather than a cosmetic problem.
    assert.ok(renderEventsCsv([]).startsWith(UTF8_BOM));
  });

  it('terminates records with CRLF', () => {
    assert.ok(renderEventsCsv([eventRow()]).includes('\r\n'));
  });
});

describe('timestamps say which instant they mean', () => {
  it('is ISO-8601 UTC with the Z', () => {
    assert.equal(isoUtc(new Date('2026-09-24T09:04:18.380Z')), '2026-09-24T09:04:18.380Z');
  });

  it('is empty, never epoch 0, for a missing or unusable value', () => {
    // `new Date(null)` is epoch 0 — a well-formed 1970 timestamp is worse than
    // a blank cell, because it reads as a measurement.
    for (const bad of [null, undefined, '', 'nope']) assert.equal(isoUtc(bad), '');
  });

  it('carries the assumed-timezone caveat as its own column', () => {
    // ⛔ The device gave no zone and the collector's own was assumed. A reader
    // who cannot see that treats an assumed time as a measured one.
    const idx = COLUMNS.findIndex((c) => c[0] === 'event_time_zone_assumed');
    assert.ok(idx >= 0, 'the caveat column is gone');
    assert.equal(COLUMNS[idx][1](eventRow({ tzAssumed: true }), { deviceNames: {} }), 'yes');
    assert.equal(COLUMNS[idx][1](eventRow({ tzAssumed: false }), { deviceNames: {} }), 'no');
  });
});

describe('the columns are the evidence, not a summary of it', () => {
  it('keeps the raw message, last', () => {
    assert.equal(COLUMNS[COLUMNS.length - 1][0], 'message');
  });

  it('carries every field the search returns', () => {
    // ⛔ A field quietly dropped from this list makes the export a SUMMARY of
    // the evidence while still being called an export — and the fields that
    // look most droppable (zones, byte counts, URL category) are the ones an
    // investigator reaches for once the obvious ones have not answered it.
    const names = COLUMNS.map((c) => c[0]);
    for (const required of [
      'received_at_utc', 'event_at_utc', 'device', 'sender_ip', 'vendor', 'hostname',
      'severity', 'log_class', 'log_subtype', 'action', 'auth_outcome', 'src_ip',
      'src_port', 'src_user', 'src_country', 'src_zone', 'dst_ip', 'dst_port',
      'dst_country', 'dst_zone', 'protocol', 'application', 'rule_name', 'rule_id',
      'threat_name', 'threat_severity', 'url_hostname', 'url_category',
      'bytes_sent', 'bytes_received', 'event_id', 'message',
    ]) {
      assert.ok(names.includes(required), `the export dropped ${required}`);
    }
  });

  it('names the device when it can, and keeps the id when it cannot', () => {
    const csv = renderEventsCsv([eventRow()], { deviceNames: { 'dev-1': 'TSR-TL' } });
    assert.match(csv, /"TSR-TL"/);
    const anon = renderEventsCsv([eventRow({ deviceId: null })]);
    assert.ok(anon.includes('""'), 'an unmatched sender must still export');
  });
});

// A pool that answers each SLICE from a handler, so a test can make one slice
// time out, or count how the window was walked. params[0]/[1] are from/to.
function slicingPool(handler) {
  const seen = [];
  return {
    seen,
    query: async () => { throw new Error('must not use pool.query'); },
    connect: async () => ({
      query: async (sql, params) => {
        const q = String(sql).trim();
        if (/^(BEGIN|COMMIT|ROLLBACK|SET LOCAL)/i.test(q)) return { rows: [] };
        const slice = { from: params[0], to: params[1], limit: params[params.length - 2] };
        seen.push(slice);
        const out = handler(slice, seen.length);
        if (out === 'timeout') {
          const e = new Error('canceling statement due to statement timeout');
          e.code = '57014';
          throw e;
        }
        return { rows: out };
      },
      release() {},
    }),
  };
}

describe('the window is walked in slices, newest first', () => {
  // ⛔ THE MEASUREMENT THIS EXISTS FOR: one source address over
  // log_class='vpn' on the live fleet took 0.25s for ONE HOUR and 97s for 23 —
  // superlinear, because recent partitions are hot and older ones come off the
  // disk the collector is writing to. A single `LIMIT 50001` statement can
  // never stop early, so it paid the whole scan and was cancelled at 10s. The
  // same query on /logs answers in 12ms BECAUSE it stops at 51 rows.
  const ASK = { from: '2026-09-24T06:00:00Z', to: '2026-09-24T12:00:00Z' };

  it('asks for the most recent hour first', async () => {
    const pool = slicingPool(() => []);
    await exportEvents(pool, ASK, NOW, { sliceMs: 3600000 });
    assert.equal(pool.seen[0].to.toISOString(), '2026-09-24T12:00:00.000Z');
    assert.equal(pool.seen[0].from.toISOString(), '2026-09-24T11:00:00.000Z');
  });

  it('walks the whole window when it can, and marks nothing', async () => {
    const pool = slicingPool(() => []);
    const out = await exportEvents(pool, ASK, NOW, { sliceMs: 3600000 });
    assert.equal(out.ok, true);
    assert.equal(pool.seen.length, 6, 'six one-hour slices for a six-hour window');
    assert.equal(out.shortened, false);
    assert.equal(out.stopReason, 'complete');
    assert.equal(out.from.toISOString(), '2026-09-24T06:00:00.000Z');
    assert.ok(!out.filename.includes('window-shortened'));
  });

  it('never asks beyond the requested start', async () => {
    const pool = slicingPool(() => []);
    await exportEvents(pool, ASK, NOW, { sliceMs: 5 * 3600000 });
    const earliest = pool.seen[pool.seen.length - 1].from;
    assert.equal(earliest.toISOString(), '2026-09-24T06:00:00.000Z');
  });
});

describe('when the whole window cannot be read', () => {
  const ASK = { from: '2026-09-24T00:00:00Z', to: '2026-09-24T12:00:00Z' };

  it('a later slice timing out yields a COMPLETE file for a shorter window', async () => {
    // ⛔ NOT A REFUSAL, AND NOT A PARTIAL FILE. Two slices were read
    // in full, so the answer "every matching event between 10:00 and 12:00" is
    // complete — it is a complete answer to a NARROWER question, which is
    // something an investigator can reason about. "Some of the last twelve
    // hours" is not.
    const pool = slicingPool((slice, n) => (n <= 2 ? [dbRow()] : 'timeout'));
    const out = await exportEvents(pool, ASK, NOW, { sliceMs: 3600000 });
    assert.equal(out.ok, true);
    assert.equal(out.rowCount, 2);
    assert.equal(out.stopReason, 'timed_out');
    assert.equal(out.shortened, true);
    assert.equal(out.from.toISOString(), '2026-09-24T10:00:00.000Z');
    assert.equal(out.to.toISOString(), '2026-09-24T12:00:00.000Z');
    assert.equal(out.requestedFrom.toISOString(), '2026-09-24T00:00:00.000Z');
  });

  it('the covered range starts at the last slice READ, never the one that failed', async () => {
    // Nothing inside the failed slice was seen, so claiming any of it would be
    // claiming rows that were never read.
    const pool = slicingPool((slice, n) => (n === 1 ? [dbRow()] : 'timeout'));
    const out = await exportEvents(pool, ASK, NOW, { sliceMs: 3600000 });
    assert.equal(out.from.toISOString(), '2026-09-24T11:00:00.000Z');
  });

  it('refuses ONLY when not one slice could be read', async () => {
    // ⛔ The single case with no window to name. Everything else is a
    // file; this is the one shape where a CSV would be a lie.
    const pool = slicingPool(() => 'timeout');
    const out = await exportEvents(pool, ASK, NOW, { sliceMs: 3600000 });
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'timed_out');
    assert.ok(!('csv' in out), 'a refusal carried a document the route could serve');
  });

  it('stops at the row ceiling and says the window was shortened', async () => {
    const pool = slicingPool(() => [dbRow(), dbRow(), dbRow()]);
    const out = await exportEvents(pool, ASK, NOW, { sliceMs: 3600000, maxRows: 4 });
    assert.equal(out.ok, true);
    assert.equal(out.rowCount, 4, 'the probe row is dropped, not exported');
    assert.equal(out.stopReason, 'row_ceiling');
    assert.equal(out.shortened, true);
    assert.match(out.filename, /-window-shortened\.csv$/);
  });

  it('stops when the wall-clock budget is spent', async () => {
    let t = 0;
    const pool = slicingPool(() => [dbRow()]);
    // Each slice costs 20s of the 45s budget.
    const out = await exportEvents(pool, ASK, NOW, {
      sliceMs: 3600000,
      budgetMs: 45000,
      clock: () => { const v = t; t += 20000; return v; },
    });
    assert.equal(out.ok, true);
    assert.equal(out.stopReason, 'budget');
    assert.equal(out.shortened, true);
    assert.match(out.filename, /-window-shortened\.csv$/);
  });

  it('a shortened run still produces a readable, complete CSV', async () => {
    const pool = slicingPool((slice, n) => (n <= 1 ? [dbRow()] : 'timeout'));
    const out = await exportEvents(pool, ASK, NOW, { sliceMs: 3600000 });
    const parsed = lines(out.csv);
    assert.equal(parsed.length, 2, 'header plus the one row that was read');
  });
});

describe('the coverage claim survives the row ceiling', () => {
  // ⛔ THE DEFECT THIS BLOCK EXISTS FOR, FOUND BY REVIEW 2026-09-24.
  // `cursor` advanced to the slice start BEFORE the ceiling check, so the run
  // claimed a whole slice after discarding part of it -- and `shortened` was
  // derived from `coveredFrom > asked.from`, which cannot see a ceiling that
  // fires on the LAST slice. The default /logs search is exactly that shape
  // (DEFAULT_WINDOW_HOURS = 1 = one slice), so it produced an unmarked partial
  // file named for the full hour. The earlier test passed because its ceiling
  // fired on slice 2 of 12 -- the favourable case.

  const ASK = { from: '2026-09-24T11:00:00Z', to: '2026-09-24T12:00:00Z' }; // ONE slice

  function timedPool(total) {
    // Rows one second apart, newest first, as searchEvents returns them.
    return slicingPool((slice) => Array.from(
      { length: Math.min(total, slice.limit) },
      (_, i) => dbRow({ receivedAt: new Date(Date.parse(ASK.to) - 60000 - i * 1000) })
    ));
  }

  it('marks a ceiling that fires on the LAST slice', async () => {
    const out = await exportEvents(timedPool(200), ASK, NOW, { sliceMs: 3600000, maxRows: 50 });
    assert.equal(out.rowCount, 50);
    assert.equal(out.stopReason, 'row_ceiling');
    assert.equal(out.shortened, true, 'a truncated file went out unmarked');
    assert.match(out.filename, /-window-shortened\.csv$/);
  });

  it('never claims a row it discarded', async () => {
    const out = await exportEvents(timedPool(200), ASK, NOW, { sliceMs: 3600000, maxRows: 50 });
    // Everything in the file must fall inside the range the file NAMES.
    const stamps = lines(out.csv).slice(1).map((l) => l.slice(1, 25));
    for (const t of stamps) {
      assert.ok(t >= out.from.toISOString(), `row at ${t} is older than the stated start ${out.from.toISOString()}`);
      assert.ok(t <= out.to.toISOString(), `row at ${t} is newer than the stated end`);
    }
    // And the stated start must be LATER than the slice start, because rows
    // before it were dropped.
    assert.ok(
      out.from.getTime() > Date.parse(ASK.from),
      'the covered range still starts at the slice boundary, claiming discarded rows'
    );
  });

  it('shortened is a fact about the RUN, not a timestamp comparison', async () => {
    const out = await exportEvents(timedPool(200), ASK, NOW, { sliceMs: 3600000, maxRows: 50 });
    assert.notEqual(out.stopReason, 'complete');
    assert.equal(out.shortened, true);
  });
});

describe('a filter the query could not understand', () => {
  it('REFUSES rather than exporting a wider answer under a narrower name', async () => {
    // ⛔ buildSearchQuery drops a malformed value and searches WITHOUT it,
    // so `srcIp=10.1.1` returns every source address. It used to produce a file
    // called `secvault-logs-10.1.1-....csv` with `filters: {}` in the audit row
    // -- named after a host it had not filtered on.
    const out = await exportEvents(slicingPool(() => [dbRow()]), { srcIp: '10.1.1' }, NOW);
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'rejected_filter');
    assert.ok(!('csv' in out), 'a refusal carried a document');
    assert.match(out.detail, /10\.1\.1/, 'the refusal must name the value that was wrong');
  });

  it('the filename can never carry a filter that was not applied', async () => {
    const out = await exportEvents(slicingPool(() => [dbRow()]), { srcUser: 'jsmith' }, NOW);
    assert.equal(out.ok, true);
    assert.match(out.filename, /-jsmith-/);
  });
});

describe('empty is not the same as unreadable', () => {
  it('slices that came back EMPTY are a complete answer, not a refusal', async () => {
    // ⛔ The gate used to be `rows.length === 0`, which is also true when
    // every slice answered honestly with nothing. The operator was then told
    // "not even the most recent hour could be read" -- false -- and a correct
    // empty result was thrown away.
    const pool = slicingPool((slice, n) => (n <= 2 ? [] : 'timeout'));
    const out = await exportEvents(pool, { from: '2026-09-24T00:00:00Z', to: '2026-09-24T12:00:00Z' },
      NOW, { sliceMs: 3600000 });
    assert.equal(out.ok, true, 'two readable empty hours were reported as unreadable');
    assert.equal(out.rowCount, 0);
    assert.equal(out.stopReason, 'timed_out');
    assert.equal(out.shortened, true);
  });

  it('still refuses when not one slice completed', async () => {
    const out = await exportEvents(slicingPool(() => 'timeout'),
      { from: '2026-09-24T00:00:00Z', to: '2026-09-24T12:00:00Z' }, NOW, { sliceMs: 3600000 });
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'timed_out');
  });
});

describe('the filename says what the file holds', () => {
  const built = { from: new Date('2026-09-23T10:00:00Z'), to: new Date('2026-09-24T09:35:00Z') };

  it('states the window, which is the one filter the rows cannot show', () => {
    const name = exportFilename(built, {});
    // The `Z` is required: the form takes local time, the file is UTC.
    assert.match(name, /^secvault-logs-20260923-1000Z_to_20260924-0935Z\.csv$/);
  });

  it('names the subject when there is a single one', () => {
    assert.match(exportFilename(built, { srcIp: '93.88.206.223' }), /-93\.88\.206\.223-/);
    assert.match(exportFilename(built, { srcUser: 'admin' }), /-admin-/);
  });

  it('cannot be talked into a path or a shell character', () => {
    const name = exportFilename(built, { srcUser: '../../etc/passwd; rm -rf /' });
    assert.ok(!name.includes('/'), 'a path separator reached the filename');
    assert.ok(!name.includes(';'), 'a shell separator reached the filename');
    assert.ok(!name.includes('"'), 'a quote could break out of the Content-Disposition header');
    assert.match(name, /\.csv$/);
  });
});
