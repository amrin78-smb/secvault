'use strict';
// Pins the syslog storage layer's SQL building and value coercion.
//
// This runs ~1,100 times a second. Two things here are the kind that are
// silently wrong under load rather than loudly wrong in review:
//   - the bind-parameter arithmetic (PostgreSQL caps a statement at 65535
//     parameters; exceed it and the batch fails at 3am, not in testing)
//   - the partition boundary maths (a wrong bound means an INSERT with no
//     partition to land in, which fails the whole flush)

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  COLUMNS,
  MAX_ROWS_PER_INSERT,
  partitionNameFor,
  buildPartitionSql,
  buildInsertSql,
  flattenRow,
  chunk,
  toInetOrNull,
  toPortOrNull,
} = require('../lib/syslog/eventStore');

describe('eventStore: partitions', () => {
  it('names a partition from the UTC day, not local time', () => {
    // 2026-09-08T23:30:00Z is already the 9th in +07:00. Partitions are UTC so
    // a boundary is the same instant everywhere and does not move under DST.
    assert.equal(partitionNameFor(new Date('2026-09-08T23:30:00Z')), 'syslog_events_20260908');
    assert.equal(partitionNameFor(new Date('2026-09-09T00:00:00Z')), 'syslog_events_20260909');
  });

  it('builds a one-day range whose upper bound is the NEXT day', () => {
    // Range partitions are [FROM, TO) — an off-by-one here leaves a whole day
    // of events with nowhere to go.
    const { name, sql } = buildPartitionSql(new Date('2026-09-08T12:00:00Z'));
    assert.equal(name, 'syslog_events_20260908');
    assert.match(sql, /FROM \('2026-09-08'\) TO \('2026-09-09'\)/);
    assert.match(sql, /^CREATE TABLE IF NOT EXISTS syslog_events_20260908 PARTITION OF syslog_events/);
  });

  it('handles a month and a year boundary', () => {
    assert.match(buildPartitionSql(new Date('2026-09-30T00:00:00Z')).sql,
      /FROM \('2026-09-30'\) TO \('2026-10-01'\)/);
    assert.match(buildPartitionSql(new Date('2026-12-31T00:00:00Z')).sql,
      /FROM \('2026-12-31'\) TO \('2027-01-01'\)/);
  });

  it('handles a leap day', () => {
    assert.match(buildPartitionSql(new Date('2028-02-28T00:00:00Z')).sql,
      /FROM \('2028-02-28'\) TO \('2028-02-29'\)/);
    assert.match(buildPartitionSql(new Date('2028-02-29T00:00:00Z')).sql,
      /FROM \('2028-02-29'\) TO \('2028-03-01'\)/);
  });

  it('is IF NOT EXISTS, so the hourly maintenance pass is idempotent', () => {
    assert.match(buildPartitionSql(new Date()).sql, /IF NOT EXISTS/);
  });
});

describe('eventStore: INSERT building stays inside the bind-parameter cap', () => {
  it('numbers placeholders continuously across rows', () => {
    const sql = buildInsertSql(2);
    assert.match(sql, /VALUES \(\$1,/);
    // Row 2 must continue from where row 1 stopped, not restart at $1.
    assert.ok(sql.includes(`$${COLUMNS.length + 1}`), 'second row must continue the numbering');
    const highest = COLUMNS.length * 2;
    assert.ok(sql.includes(`$${highest})`), `highest placeholder should be $${highest}`);
  });

  it('⛔ a full-size batch stays under PostgreSQL 65535-parameter limit', () => {
    const params = COLUMNS.length * MAX_ROWS_PER_INSERT;
    assert.ok(
      params < 65535,
      `${COLUMNS.length} cols x ${MAX_ROWS_PER_INSERT} rows = ${params} params, which must stay under 65535`
    );
  });

  it('refuses a non-positive row count instead of emitting broken SQL', () => {
    for (const bad of [0, -1, 1.5, null, undefined, 'x']) {
      assert.throws(() => buildInsertSql(bad), `rowCount ${JSON.stringify(bad)}`);
    }
  });

  it('chunk() splits to the batch size and loses nothing', () => {
    const arr = Array.from({ length: 1201 }, (_, i) => i);
    const groups = chunk(arr, MAX_ROWS_PER_INSERT);
    assert.equal(groups.length, 3);
    assert.equal(groups.reduce((n, g) => n + g.length, 0), 1201);
    assert.equal(groups[2].length, 201);
  });
});

describe('eventStore: value coercion returns NULL, never a substitute', () => {
  it('accepts real IPv4 and IPv6', () => {
    assert.equal(toInetOrNull('10.248.5.55'), '10.248.5.55');
    assert.equal(toInetOrNull(' 172.24.0.26 '), '172.24.0.26');
    assert.equal(toInetOrNull('fe80::8e36:7aff:fe21:9dca'), 'fe80::8e36:7aff:fe21:9dca');
  });

  it('⛔ rejects a malformed address rather than substituting 0.0.0.0', () => {
    // An INET column rejects bad input and would abort the WHOLE batch, so a
    // firewall logging a hostname where an IP belongs must yield NULL.
    for (const bad of ['not-an-ip', '999.1.1.1', '10.0.0', '', null, undefined, 42, 'srv-01.local']) {
      assert.equal(toInetOrNull(bad), null, `${JSON.stringify(bad)} must be null`);
    }
  });

  it('rejects an out-of-range port as a mis-parse, not a port', () => {
    assert.equal(toPortOrNull('443'), 443);
    assert.equal(toPortOrNull(0), 0, 'port 0 is a real value');
    assert.equal(toPortOrNull(65535), 65535);
    for (const bad of [65536, -1, 'abc', null, undefined, '']) {
      assert.equal(toPortOrNull(bad), null, `${JSON.stringify(bad)} must be null`);
    }
  });
});

describe('eventStore: flattenRow', () => {
  const base = {
    receivedAt: new Date('2026-09-08T10:00:00Z'),
    sourceIp: '10.248.12.11',
    message: 'raw line',
  };

  it('produces exactly one parameter per column, in order', () => {
    const row = flattenRow(base);
    assert.equal(row.length, COLUMNS.length);
    assert.equal(row[COLUMNS.indexOf('received_at')], base.receivedAt);
    assert.equal(row[COLUMNS.indexOf('source_ip')], '10.248.12.11');
    assert.equal(row[COLUMNS.indexOf('message')], 'raw line');
  });

  it('leaves every unknown field NULL rather than inventing one', () => {
    const row = flattenRow(base);
    for (const col of ['event_at', 'device_id', 'vendor', 'action', 'src_ip', 'rule_id', 'bytes_sent']) {
      assert.equal(row[COLUMNS.indexOf(col)], null, `${col} must be null when absent`);
    }
  });

  it('⛔ a NULL message SURVIVES as NULL, never as an empty string', () => {
    // CHANGED 2026-09-08 with the compressed archive. `message` used to be NOT
    // NULL, so this coerced null to '' to keep the batch insertable. It is
    // nullable now and the null carries meaning: the raw line is in the
    // archive, not the database.
    //
    // ⛔ Coercing it back to '' would recreate an empty-string SENTINEL —
    // invisible to `message IS NULL`, and indistinguishable from a genuinely
    // empty log line. That is the fabricated-value pattern this codebase bans.
    for (const m of [null, undefined]) {
      const row = flattenRow(Object.assign({}, base, { message: m }));
      assert.equal(row[COLUMNS.indexOf('message')], null);
    }
    // A line that really was empty stays an empty string — a different fact.
    assert.equal(
      flattenRow(Object.assign({}, base, { message: '' }))[COLUMNS.indexOf('message')], ''
    );
  });

  it('coerces tz_assumed to a real boolean', () => {
    assert.equal(flattenRow(base)[COLUMNS.indexOf('tz_assumed')], false);
    assert.equal(flattenRow(Object.assign({}, base, { tzAssumed: true }))[COLUMNS.indexOf('tz_assumed')], true);
    // Anything not exactly true is false — never a truthy string reaching a
    // boolean column.
    assert.equal(flattenRow(Object.assign({}, base, { tzAssumed: 'yes' }))[COLUMNS.indexOf('tz_assumed')], false);
  });

  it('drops a malformed src_ip to null without losing the rest of the row', () => {
    const row = flattenRow(Object.assign({}, base, { srcIp: 'workstation-42', dstIp: '8.8.8.8' }));
    assert.equal(row[COLUMNS.indexOf('src_ip')], null);
    assert.equal(row[COLUMNS.indexOf('dst_ip')], '8.8.8.8');
    assert.equal(row[COLUMNS.indexOf('message')], 'raw line');
  });
});
