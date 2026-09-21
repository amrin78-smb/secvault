'use strict';
// tests/trafficReport.test.js
//
// ⛔ THE WINDOW IS THE WHOLE RISK. This report offers a date range, and the
// rollups behind it are trimmed to SYSLOG_DETAIL_RETENTION_DAYS. A range
// reaching past that has NO DATA to find — which is not the same as no traffic,
// and answering a 90-day question with 30 days of numbers under a heading that
// says 90 is exactly the quiet wrongness this product exists to avoid.
//
// So resolveWindow is pure and every clamp it applies is pinned here, along
// with the fact that it reports what was REQUESTED beside what was COVERED.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { resolveWindow, detailRetentionDays } = require('../lib/reports/trafficWindow');
const { buildTrafficActivityData, coverageSentence, fmtBytes } = require('../lib/reports/trafficActivity');

const NOW = new Date('2026-09-21T12:00:00Z');
const H = 3600000;

describe('⛔ the window is clamped, and the clamp is reported', () => {
  it('a range inside retention is untouched', () => {
    const w = resolveWindow('2026-09-20T00:00:00Z', '2026-09-21T00:00:00Z', NOW, 30);
    assert.equal(w.clamped, false);
    assert.deepEqual(w.reasons, []);
    assert.equal(w.hours, 24);
  });

  it('a range older than retention is moved forward AND says why', () => {
    const w = resolveWindow('2026-06-01T00:00:00Z', '2026-09-21T00:00:00Z', NOW, 30);
    assert.equal(w.clamped, true);
    assert.equal(w.from.getTime(), NOW.getTime() - 30 * 24 * H);
    // The requested range is kept so the document can print both.
    assert.equal(w.requestedFrom.toISOString(), '2026-06-01T00:00:00.000Z');
    assert.match(w.reasons.join(' '), /retained for 30 days/);
    assert.match(w.reasons.join(' '), /missing data, not quiet traffic/);
  });

  it('⛔ the retention figure comes from the environment, not a constant here', () => {
    const prev = process.env.SYSLOG_DETAIL_RETENTION_DAYS;
    try {
      process.env.SYSLOG_DETAIL_RETENTION_DAYS = '7';
      assert.equal(detailRetentionDays(), 7);
      const w = resolveWindow('2026-01-01T00:00:00Z', '2026-09-21T00:00:00Z', NOW);
      assert.equal(w.from.getTime(), NOW.getTime() - 7 * 24 * H, 'a deployment that lowered it is honoured');
    } finally {
      if (prev === undefined) delete process.env.SYSLOG_DETAIL_RETENTION_DAYS;
      else process.env.SYSLOG_DETAIL_RETENTION_DAYS = prev;
    }
  });

  it('an inverted range is swapped, not returned empty', () => {
    const w = resolveWindow('2026-09-21T00:00:00Z', '2026-09-20T00:00:00Z', NOW, 30);
    assert.equal(w.from < w.to, true);
    assert.match(w.reasons.join(' '), /swapped/);
  });

  it('⛔ the future is trimmed — it would render as a flat line reading like an outage', () => {
    const w = resolveWindow('2026-09-20T00:00:00Z', '2026-12-01T00:00:00Z', NOW, 30);
    assert.equal(w.to.getTime(), NOW.getTime());
    assert.match(w.reasons.join(' '), /future/);
  });

  it('a collapsed range becomes one hour rather than a blank report', () => {
    const w = resolveWindow('2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z', NOW, 30);
    assert.equal(w.hours >= 1, true);
    assert.match(w.reasons.join(' '), /collapsed/);
  });

  it('no input at all defaults to the last 24 hours, unclamped', () => {
    const w = resolveWindow(undefined, undefined, NOW, 30);
    assert.equal(w.hours, 24);
    assert.equal(w.clamped, false);
  });

  it('an unparseable date falls back rather than producing Invalid Date', () => {
    const w = resolveWindow('not-a-date', 'also-not', NOW, 30);
    assert.equal(Number.isNaN(w.from.getTime()), false);
    assert.equal(Number.isNaN(w.to.getTime()), false);
  });
});

describe('⛔ coverage is stated before the totals', () => {
  const base = (over = {}) => ({
    coverage: {
      devices: 16, logging: 15, silent: ['PAKFood'],
      bytesCapable: 10, bytesIncapable: ['OKF(F2)', 'TSR_EKM'], rows: [],
      ...over,
    },
  });

  it('names the silent firewalls AND refuses to interpret their silence', () => {
    const s = coverageSentence(base());
    assert.match(s, /15 of 16/);
    assert.match(s, /PAKFood/);
    // The whole point: a device that sent nothing is not a quiet device.
    assert.match(s, /may mean no traffic, or may mean they are not logging/);
  });

  it('explains WHY some devices cannot be summed for volume', () => {
    const s = coverageSentence(base());
    assert.match(s, /cumulative counter/);
    assert.match(s, /OKF\(F2\)/);
  });

  it('says nothing about silence when every firewall logged', () => {
    const s = coverageSentence(base({ logging: 16, silent: [], bytesIncapable: [] }));
    assert.match(s, /16 of 16/);
    assert.doesNotMatch(s, /sent nothing/);
  });

  it('an empty inventory is stated, not rendered as a clean result', () => {
    const s = coverageSentence(base({ devices: 0, logging: 0, silent: [], bytesIncapable: [] }));
    assert.match(s, /No active firewalls/);
  });
});

describe('⛔ an unmeasurable figure is an em dash, never a zero', () => {
  it('fmtBytes refuses null rather than printing 0 B', () => {
    assert.equal(fmtBytes(null), '—');
    assert.equal(fmtBytes(undefined), '—');
    assert.equal(fmtBytes('not a number'), '—');
    // A real zero is still a real measurement.
    assert.equal(fmtBytes(0), '0 B');
  });

  it('scales without losing the unit', () => {
    assert.match(fmtBytes(1536), /1\.5 KB/);
    assert.match(fmtBytes(3295305401882), /TB$/);
  });
});

describe('⛔ a device that does not exist is a mistake, not an empty report', () => {
  it('returns null so the route can 404 instead of titling a document after nothing', async () => {
    const pool = { query: async () => ({ rows: [] }) };
    const out = await buildTrafficActivityData(pool, { deviceId: '00000000-0000-0000-0000-000000000000' });
    assert.equal(out, null);
  });
});

describe('⛔ one failing section must not take the document down', () => {
  it('a throwing rollup becomes a NAMED gap, not a silently absent table', async () => {
    let call = 0;
    const pool = {
      query: async (sql) => {
        // the device lookup is not attempted (fleet scope); fail the talker rollup
        if (/syslog_talker_hourly/.test(sql)) throw new Error('relation does not exist');
        call++;
        return { rows: [] };
      },
    };
    const d = await buildTrafficActivityData(pool, {});
    assert.equal(d.failures.length, 1);
    assert.equal(d.failures[0].name, 'top sources');
    assert.match(d.failures[0].message, /relation does not exist/);
    // and the rest of the document still exists
    assert.ok(call > 0);
    assert.deepEqual(d.hosts, []);
  });
});
