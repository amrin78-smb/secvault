'use strict';
// Pins raw log search — the one place in SecVault that reads syslog_events
// directly instead of a rollup, because an aggregate has already thrown away
// the individual event an investigation needs.
//
// Three properties carry the weight here, and all three are safety rather than
// features:
//
//  1. A TIME WINDOW IS MANDATORY AND BOUNDED. At ~133 GB/day an unbounded
//     search is not a slow query, it is an outage for the ~1,500 rows/second
//     ingest sharing the disk.
//  2. TRUNCATION IS REPORTED. "Here are 100 of many" and "here are the only
//     100" are different answers to an investigator, and only one is true.
//  3. A MALFORMED FILTER IS REJECTED LOUDLY. Silently dropping "srcIp=10.1.1"
//     returns every host's traffic and reads as a confident answer about the
//     one host that was asked about.
//
// This file also carries the injection guard: it is the only query in the
// codebase built from user-supplied filters, on a security product.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

// ⛔ THE STUB MUST MODEL THE REAL POOL, INCLUDING connect(). searchEvents takes a
// dedicated client so it can `SET LOCAL statement_timeout` inside a transaction —
// pool.query hands back an arbitrary connection, so a timeout set that way leaks
// onto unrelated queries or applies to none. A stub with only `query` let the
// tests pass against a shape production does not have.
//
// BEGIN / SET LOCAL / COMMIT / ROLLBACK are answered here and NOT passed to the
// caller's handler, so an assertion about "the SQL searchEvents built" still sees
// only the search itself.
function stubPool(handler) {
  const passthrough = (sql) => /^(BEGIN|COMMIT|ROLLBACK|SET LOCAL)/i.test(String(sql).trim());
  return {
    query: async (sql, params) => (passthrough(sql) ? { rows: [] } : handler(sql, params)),
    connect: async () => ({
      query: async (sql, params) => (passthrough(sql) ? { rows: [] } : handler(sql, params)),
      release() {},
    }),
  };
}
const {
  buildSearchQuery,
  searchEvents,
  resolveWindow,
  clampLimit,
  MAX_LIMIT,
  DEFAULT_LIMIT,
  MAX_WINDOW_DAYS,
} = require('../lib/syslog/logSearch');

const NOW = new Date('2026-09-08T12:00:00.000Z');

describe('logSearch: the window is always bounded', () => {
  it('⛔ defaults to a recent window rather than everything', () => {
    const { from, to } = resolveWindow(undefined, undefined, NOW);
    assert.ok(to <= NOW);
    assert.ok(from < to);
    assert.equal((to - from) / 3600000, 1, 'one hour by default');
  });

  it('⛔ clamps a range wider than raw retention, and says it clamped', () => {
    const { from, to, clamped } = resolveWindow('2020-01-01T00:00:00Z', NOW, NOW);
    assert.equal(clamped, true, 'the UI must be able to say the range was shortened');
    assert.equal((to - from) / 86400000, MAX_WINDOW_DAYS);
  });

  it('does not claim to have clamped a window that fits', () => {
    const { clamped } = resolveWindow('2026-09-08T09:00:00Z', NOW, NOW);
    assert.equal(clamped, false);
  });

  it('⛔ an inverted or junk range still yields a forward, bounded window', () => {
    for (const [f, t] of [
      ['2026-09-08T13:00:00Z', '2026-09-08T10:00:00Z'],
      ['nonsense', 'also-nonsense'],
      ['', ''],
      [null, undefined],
    ]) {
      const { from, to } = resolveWindow(f, t, NOW);
      assert.ok(to > from, `${f}..${t} must not invert`);
      assert.ok((to - from) / 86400000 <= MAX_WINDOW_DAYS);
    }
  });

  it('every built query carries both window bounds as the first two binds', () => {
    const b = buildSearchQuery({}, NOW);
    assert.match(b.sql, /received_at >= \$1/);
    assert.match(b.sql, /received_at < \$2/);
    assert.ok(b.params[0] instanceof Date);
    assert.ok(b.params[1] instanceof Date);
  });
});

describe('logSearch: results are capped and the cap is honest', () => {
  it('clamps the limit into range', () => {
    assert.equal(clampLimit(999999), MAX_LIMIT);
    assert.equal(clampLimit(0), 1);
    assert.equal(clampLimit(-5), 1);
    // ⛔ Reads the constant rather than repeating it. This asserted a
    // literal 100 and broke the moment the default page size changed to 25 —
    // the behaviour under test is 'an unparseable limit falls back to the
    // default', not 'the default is 100'.
    assert.equal(clampLimit('abc'), DEFAULT_LIMIT);
    assert.equal(clampLimit(250), 250);
  });

  it('asks for limit + 1 so "more exist" is detectable without a COUNT', () => {
    // ⛔ Never a COUNT: measured 43 SECONDS for an exact count of a ONE-HOUR
    // window (1,657,462 rows). The +1 probe is the only affordable way to know
    // a next page exists.
    const b = buildSearchQuery({ limit: 50 }, NOW);
    const limitParam = b.params[b.params.length - 2];
    const offsetParam = b.params[b.params.length - 1];
    assert.equal(limitParam, 51);
    assert.equal(offsetParam, 0, 'page 1 starts at offset 0');
    assert.doesNotMatch(b.sql, /\bcount\s*\(/i, 'this query must never count');
  });

  it('⛔ reports truncation and does NOT return the probe row', async () => {
    const limit = 3;
    const pool = stubPool(async () => ({ rows: Array.from({ length: limit + 1 }, (_, i) => ({ id: i, message: 'x' })) }));
    const r = await searchEvents(pool, { limit }, NOW);
    assert.equal(r.truncated, true, 'the caller must be told there are more');
    assert.equal(r.rows.length, limit, 'the +1 probe row must not be shown');
  });

  it('does not claim truncation when the results fit', async () => {
    const pool = stubPool(async () => ({ rows: [{ id: 1, message: 'x' }] }));
    const r = await searchEvents(pool, { limit: 10 }, NOW);
    assert.equal(r.truncated, false);
    assert.equal(r.rows.length, 1);
  });
});

describe('logSearch: malformed filters are rejected, never silently dropped', () => {
  it('⛔ rejects a malformed IP instead of returning every host', () => {
    const b = buildSearchQuery({ srcIp: '10.1.1' }, NOW);
    assert.equal(b.rejected.srcIp, '10.1.1');
    // src_ip legitimately appears in the SELECT list, so check the predicates.
    const where = b.sql.slice(b.sql.indexOf('WHERE'), b.sql.indexOf('ORDER BY'));
    assert.doesNotMatch(where, /src_ip/, 'no predicate may be emitted for a rejected value');
    assert.equal(b.applied.srcIp, undefined);
    assert.equal(b.params.length, 4, 'only the two window bounds, the limit and the offset');
  });

  it('rejects an out-of-range port and a malformed device id', () => {
    const b = buildSearchQuery({ dstPort: '99999', deviceId: 'not-a-uuid' }, NOW);
    assert.equal(b.rejected.dstPort, '99999');
    assert.equal(b.rejected.deviceId, 'not-a-uuid');
  });

  it('accepts a bare address as equality and a CIDR as containment', () => {
    assert.match(buildSearchQuery({ srcIp: '10.248.70.50' }, NOW).sql, /src_ip = \$3::inet/);
    assert.match(buildSearchQuery({ srcIp: '10.248.0.0/16' }, NOW).sql, /src_ip <<= \$3::inet/);
  });

  it('ignores blank filters without recording them as rejected', () => {
    const b = buildSearchQuery({ srcIp: '', action: '   ', q: '' }, NOW);
    assert.deepEqual(b.rejected, {});
    assert.deepEqual(b.applied, {});
  });
});

describe('⛔ logSearch: every value is a bind parameter', () => {
  // The only query in this codebase assembled from user-supplied filters, on a
  // security product. A string-interpolation slip here is an injection.
  it('never puts a filter value into the SQL text', () => {
    const nasty = "'; DROP TABLE syslog_events; --";
    const b = buildSearchQuery(
      { action: nasty, ruleName: nasty, q: nasty, application: nasty, srcUser: nasty },
      NOW
    );
    assert.doesNotMatch(b.sql, /DROP TABLE/i);
    assert.ok(!b.sql.includes(nasty));
    assert.ok(b.params.some((p) => String(p).includes('DROP TABLE')), 'it is carried as a bind');
  });

  it('only ever emits column names from its own whitelist', () => {
    // An unknown filter key must not become a column reference.
    const b = buildSearchQuery({ 'evil; --': 'x', notAFilter: 'y' }, NOW);
    assert.doesNotMatch(b.sql, /evil/);
    assert.doesNotMatch(b.sql, /notAFilter/);
    assert.deepEqual(b.applied, {});
  });

  it('escapes LIKE metacharacters so a literal % does not match everything', () => {
    // Without escaping, searching for "100%" silently becomes "match anything".
    const b = buildSearchQuery({ q: '100%_x' }, NOW);
    const bound = b.params.find((p) => typeof p === 'string' && p.includes('100'));
    assert.equal(bound, '%100\\%\\_x%');
  });
});

describe('logSearch: the row shape keeps its caveats', () => {
  it('carries tzAssumed through, because investigations turn on timestamps', async () => {
    const pool = stubPool(async () => ({
      rows: [{ id: 1, message: 'x', tz_assumed: true, src_port: '443', bytes_sent: null }],
    }));
    const r = await searchEvents(pool, {}, NOW);
    assert.equal(r.rows[0].tzAssumed, true);
    assert.equal(r.rows[0].srcPort, 443, 'numeric strings become numbers');
    assert.equal(r.rows[0].bytesSent, null, 'an absent byte count stays null, never 0');
  });

  it('⛔ lets a query error propagate rather than returning an empty result', async () => {
    // "0 results" from a failed query reads as "that traffic never happened".
    const pool = stubPool(async () => { throw new Error('relation does not exist'); });
    await assert.rejects(() => searchEvents(pool, {}, NOW), /relation does not exist/);
  });
});

describe('⛔ log search pages without ever counting', () => {
  // An exact COUNT over even a one-hour window was measured at 43 SECONDS on
  // the live fleet (1,657,462 rows). Paging here therefore has no total, and
  // the UI renders "Page 3" rather than a "of 47" nobody verified.
  const { clampPage, MAX_PAGE } = require('../lib/syslog/logSearch');

  it('turns a page number into a bounded OFFSET', () => {
    for (const [page, limit, wantOffset] of [
      [1, 100, 0], [2, 100, 100], [3, 50, 100], [undefined, 100, 0],
    ]) {
      const b = buildSearchQuery({ page, limit }, NOW);
      assert.equal(b.offset, wantOffset, `page=${page} limit=${limit}`);
    }
  });

  it('⛔ caps how deep OFFSET can go', () => {
    // A hand-edited ?page=999999 must not become a multi-million-row OFFSET
    // scan against the table the collector is writing to at ~1,500 rows/sec.
    assert.equal(clampPage('999999'), MAX_PAGE);
    assert.equal(buildSearchQuery({ page: '999999', limit: 500 }, NOW).offset, (MAX_PAGE - 1) * 500);
  });

  it('treats junk page values as page 1 rather than an empty view', () => {
    for (const bad of ['abc', '-2', '0', '', null, undefined, ['3', '9']]) {
      const want = Array.isArray(bad) ? 3 : 1;
      assert.equal(clampPage(bad), want, JSON.stringify(bad));
    }
  });

  it('emits LIMIT and OFFSET as bound parameters, never inline', () => {
    const b = buildSearchQuery({ page: 4, limit: 25 }, NOW);
    assert.match(b.sql, /LIMIT \$\d+ OFFSET \$\d+/);
    assert.doesNotMatch(b.sql, /OFFSET 75/);
  });

  it('reports hasMore from the probe row and does not return it', async () => {
    const pool = stubPool(async () => ({ rows: Array.from({ length: 11 }, (_, i) => ({ id: i, message: 'x' })) }));
    const r = await searchEvents(pool, { limit: 10, page: 2 }, NOW);
    assert.equal(r.hasMore, true);
    assert.equal(r.rows.length, 10);
    assert.equal(r.page, 2);
  });

  it('reports hasMore false on the last page', async () => {
    const pool = stubPool(async () => ({ rows: [{ id: 1, message: 'x' }] }));
    const r = await searchEvents(pool, { limit: 10 }, NOW);
    assert.equal(r.hasMore, false);
  });
});

describe('⛔ a stopped search is not an empty one', () => {
  // A query cancelled by statement_timeout returns zero rows. Rendering that as
  // "nothing matched" would let an investigator conclude a host never connected
  // when the question was simply never answered — this codebase's signature bug
  // on the one page where it is least survivable.
  const canceled = () => {
    const e = new Error('canceling statement due to statement timeout');
    e.code = '57014';
    return e;
  };

  it('reports timedOut with a reason, and does NOT return an empty result set', async () => {
    const pool = stubPool(async () => { throw canceled(); });
    const r = await searchEvents(pool, {}, NOW);
    assert.equal(r.timedOut, true, 'the caller must be able to tell this apart from no matches');
    assert.equal(r.rows.length, 0);
    assert.match(r.reason, /NOT a statement that no matching traffic exists/i);
    assert.equal(r.truncated, false);
  });

  it('a successful search is explicitly NOT timed out', async () => {
    const pool = stubPool(async () => ({ rows: [{ id: 1, message: 'x' }] }));
    const r = await searchEvents(pool, {}, NOW);
    assert.equal(r.timedOut, false, 'absent would be falsy too — it is set explicitly');
  });

  it('⛔ a NON-timeout error still propagates, and is never dressed as a timeout', async () => {
    const pool = stubPool(async () => { throw new Error('relation does not exist'); });
    await assert.rejects(() => searchEvents(pool, {}, NOW), /relation does not exist/);
  });

  it('⛔ the timeout is applied with SET LOCAL on a dedicated client', async () => {
    const seen = [];
    const handler = async () => ({ rows: [] });
    const pool = {
      query: async () => { throw new Error('searchEvents must not use pool.query — the timeout would leak'); },
      connect: async () => ({
        query: async (sql, params) => { seen.push(String(sql).trim().split('\n')[0]); 
          return /^(BEGIN|COMMIT|ROLLBACK|SET LOCAL)/i.test(String(sql).trim()) ? { rows: [] } : handler(sql, params); },
        release() {},
      }),
    };
    await searchEvents(pool, {}, NOW);
    assert.ok(seen.some((q) => /^BEGIN/i.test(q)), 'SET LOCAL needs a transaction');
    assert.ok(seen.some((q) => /^SET LOCAL statement_timeout/i.test(q)), 'the timeout must actually be set');
    assert.ok(seen.some((q) => /^COMMIT/i.test(q)));
  });

  it('⛔ the client is released even when the query throws', async () => {
    let released = 0;
    const pool = {
      query: async () => { throw new Error('must not be used'); },
      connect: async () => ({
        query: async (sql) => {
          if (/^(BEGIN|SET LOCAL|ROLLBACK)/i.test(String(sql).trim())) return { rows: [] };
          throw canceled();
        },
        release() { released += 1; },
      }),
    };
    const r = await searchEvents(pool, {}, NOW);
    assert.equal(r.timedOut, true);
    assert.equal(released, 1, 'a leaked connection on every expensive search would exhaust the pool');
  });
});
