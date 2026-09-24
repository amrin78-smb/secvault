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

describe('what the export refuses to produce', () => {
  it('refuses a timed-out search instead of an empty file', async () => {
    const out = await exportEvents(stubPool([], { timeout: true }), { srcIp: '1.2.3.4' }, NOW);
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'timed_out');
    // ⛔ THE POINT: no document at all. An empty CSV here reads as "nothing
    // matched", and the reader has no route back to "the query was killed".
    assert.ok(!('csv' in out), 'a refusal carried a document the route could serve');
  });

  it('refuses rather than truncating past the ceiling', async () => {
    // searchEvents fetches limit+1; seeing that extra row means more exist.
    const rows = Array.from({ length: EXPORT_MAX_ROWS + 1 }, () => dbRow());
    const out = await exportEvents(stubPool(rows), {}, NOW);
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'too_many');
    assert.equal(out.maxRows, EXPORT_MAX_ROWS);
    assert.ok(!('csv' in out));
    assert.match(out.detail, /Narrow the time window/i);
  });

  it('exports right up to the ceiling', async () => {
    const rows = Array.from({ length: 3 }, () => dbRow());
    const out = await exportEvents(stubPool(rows), {}, NOW, { maxRows: 3 });
    assert.equal(out.ok, true);
    assert.equal(out.rowCount, 3);
  });
});

describe('the export is the result set, not the page', () => {
  it('drops page and limit from the caller filters', async () => {
    let sawSql = null;
    const pool = {
      query: async () => { throw new Error('must not use pool.query'); },
      connect: async () => ({
        query: async (sql, params) => {
          const q = String(sql).trim();
          if (/^(BEGIN|COMMIT|ROLLBACK|SET LOCAL)/i.test(q)) return { rows: [] };
          sawSql = { sql: q, params };
          return { rows: [dbRow()] };
        },
        release() {},
      }),
    };
    const out = await exportEvents(pool, { srcIp: '1.2.3.4', page: '7', limit: '25' }, NOW);
    assert.equal(out.ok, true);
    // OFFSET is the last parameter; honouring page=7 would make it non-zero
    // and hand back rows from the middle of the range in a file named after
    // all of it.
    assert.equal(sawSql.params[sawSql.params.length - 1], 0, 'the export paged');
    // And limit=25 must not have capped it to a screenful.
    assert.ok(
      sawSql.params[sawSql.params.length - 2] > 1000,
      'the export honoured the page size instead of the export ceiling'
    );
  });

  it('carries a clamped window rather than swallowing it', async () => {
    const out = await exportEvents(
      stubPool([dbRow()]),
      { from: '2020-01-01T00:00', to: '2026-09-24T12:00' },
      NOW
    );
    assert.equal(out.ok, true);
    assert.equal(out.clamped, true, 'the file names a narrower window than was asked for');
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
