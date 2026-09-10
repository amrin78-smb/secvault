'use strict';
// Pins the per-user VPN activity grid (lib/syslog/vpnPresence.js).
//
// ⛔ WHAT THESE TESTS ARE FOR. Per tests/README.md, a test here must cover the
// "we could not measure this" case, not just the pass and the fail — that is
// the one that regresses silently, because the wrong answer is a plausible
// picture rather than a crash. In a heatmap the failure mode is especially
// quiet: a user who was never measured and a user who genuinely did not log in
// both render as an empty square, and the empty square reads as an accusation.
// So the bulk of what follows is about which absences may be drawn as a zero.
//
// The second thing pinned here is the UNIT. This grid counts hours in which a
// user AUTHENTICATED. It is not connected time and cannot become connected time
// without a schema change; a future edit that relabels it would be a fabricated
// measurement, so the wording lives in the module and is asserted here.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  getVpnUserPresence,
  buildPresenceGrid,
  buildDayKeys,
  intensityLevel,
  INTENSITY_THRESHOLDS,
  MEASURED_STATES,
  MAX_WINDOW_DAYS,
} = require('../lib/syslog/vpnPresence');

// ── helpers ───────────────────────────────────────────────────────────────

const DAYS = ['2026-09-06', '2026-09-07', '2026-09-08', '2026-09-09', '2026-09-10'];

function grid(overrides = {}) {
  return buildPresenceGrid({
    dayKeys: DAYS,
    // 09-06 has no rollup row at all -> no logs arrived.
    coverageRows: [
      { day_key: '2026-09-07', hours_covered: 24, devices_reporting: 3 },
      { day_key: '2026-09-08', hours_covered: 24, devices_reporting: 3 },
      { day_key: '2026-09-09', hours_covered: 24, devices_reporting: 3 },
      { day_key: '2026-09-10', hours_covered: 3, devices_reporting: 3 },
    ],
    authDayRows: [
      // Logs arrived, but no successful VPN auth was recorded at all.
      { day_key: '2026-09-07', success_rows: 0, failure_rows: 900, truncated_rows: 0, auth_events: 900 },
      { day_key: '2026-09-08', success_rows: 40, failure_rows: 10, truncated_rows: 0, auth_events: 50 },
      // A day whose username arrays were capped.
      { day_key: '2026-09-09', success_rows: 40, failure_rows: 10, truncated_rows: 2, auth_events: 50 },
      { day_key: '2026-09-10', success_rows: 5, failure_rows: 1, truncated_rows: 0, auth_events: 6 },
    ],
    userRows: [{ username: 'alice', auth_hours: 12, auth_days: 2, devices: 1 }],
    cellRows: [
      { username: 'alice', day_key: '2026-09-09', auth_hours: 11, hours: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] },
      { username: 'alice', day_key: '2026-09-10', auth_hours: 1, hours: [0] },
    ],
    // Collection began part-way through 09-07, so 09-06 predates history.
    firstLogAt: '2026-09-07T04:00:00.000Z',
    ...overrides,
  });
}

function cellOf(result, day) {
  return result.users[0].cells.find((c) => c.day === day);
}

// ── the ramp ──────────────────────────────────────────────────────────────

describe('intensity ramp', () => {
  it('0 hours is level 0 — an absence of activity, never the faintest shade of it', () => {
    assert.equal(intensityLevel(0), 0);
    assert.equal(intensityLevel(null), 0);
    assert.equal(intensityLevel(undefined), 0);
  });

  it('is monotonic and bounded by the pinned thresholds', () => {
    assert.deepEqual(INTENSITY_THRESHOLDS, [1, 3, 6, 10, 16]);
    let prev = 0;
    for (let h = 0; h <= 24; h += 1) {
      const level = intensityLevel(h);
      assert.ok(level >= prev, `level fell at ${h}h`);
      assert.ok(level >= 0 && level <= 5, `level out of range at ${h}h`);
      prev = level;
    }
    assert.equal(intensityLevel(1), 1);
    assert.equal(intensityLevel(2), 1);
    assert.equal(intensityLevel(3), 2);
    assert.equal(intensityLevel(16), 5);
    assert.equal(intensityLevel(24), 5);
  });
});

// ── the columns ───────────────────────────────────────────────────────────

describe('day columns', () => {
  it('are UTC days, oldest first, ending on the day `now` falls in', () => {
    const keys = buildDayKeys(3, new Date('2026-09-10T23:30:00Z'));
    assert.deepEqual(keys, ['2026-09-08', '2026-09-09', '2026-09-10']);
  });

  it('⛔ uses UTC, not the server zone — a late-evening login must not land a column early', () => {
    // 2026-09-10T22:00Z is already 2026-09-11 in Asia/Bangkok, where the
    // reference deployment runs. The column must still be the 10th, because
    // every timestamp this app renders is UTC.
    assert.deepEqual(buildDayKeys(1, new Date('2026-09-10T22:00:00Z')), ['2026-09-10']);
  });

  it('clamps an absurd window instead of building 10,000 columns', () => {
    assert.equal(buildDayKeys(100000, new Date('2026-09-10T00:00:00Z')).length, MAX_WINDOW_DAYS);
    assert.equal(buildDayKeys(0, new Date('2026-09-10T00:00:00Z')).length, 1);
    assert.equal(buildDayKeys('nonsense', new Date('2026-09-10T00:00:00Z')).length, 30);
  });
});

// ── ⛔ zero vs not-measured: the reason this file exists ───────────────────

describe('⛔ a zero and a not-measured cell are different states', () => {
  it('draws a REAL zero only on a day that recorded a successful login', () => {
    const cell = cellOf(grid(), '2026-09-08');
    assert.equal(cell.state, 'zero');
    assert.equal(cell.hours, 0);
    assert.ok(MEASURED_STATES.has(cell.state));
    assert.match(cell.reason, /authenticated in none of them/);
  });

  it('⛔ never claims a zero on a day with no successful-login evidence', () => {
    // 09-07: 900 FAILED logins recorded, zero successes. Nobody could appear in
    // this grid that day however busy the VPN was, so an empty cell here says
    // nothing about the user. Asserting a zero would be the failed-read-as-a-
    // fact bug — and it is what this module did on its first live run against
    // 2026-09-08, when 17 hours of syslog from 14 firewalls produced no VPN
    // auth rows at all.
    const cell = cellOf(grid(), '2026-09-07');
    assert.equal(cell.state, 'no-vpn-logs');
    assert.equal(cell.hours, null);
    assert.ok(!MEASURED_STATES.has(cell.state));
    assert.match(cell.reason, /FAILED/);
    assert.match(cell.reason, /Not measured/i);
  });

  it('⛔ never claims a zero on a day no syslog arrived', () => {
    const cell = cellOf(grid({ firstLogAt: '2026-09-01T00:00:00.000Z' }), '2026-09-06');
    assert.equal(cell.state, 'no-logs');
    assert.equal(cell.hours, null);
    assert.match(cell.reason, /not a quiet day/);
  });

  it('⛔ never claims a zero before collection began', () => {
    const cell = cellOf(grid(), '2026-09-06');
    assert.equal(cell.state, 'pre-history');
    assert.equal(cell.hours, null);
    assert.match(cell.reason, /Before SecVault held any syslog/);
  });

  it('⛔ never claims a zero from a CAPPED username list', () => {
    // usernames_truncated means the array was capped: a user missing from it
    // may have been dropped rather than absent. Bob is absent from 09-09, a
    // day with 2 truncated buckets.
    const result = grid({
      userRows: [{ username: 'bob', auth_hours: 1, auth_days: 1, devices: 1 }],
      cellRows: [{ username: 'bob', day_key: '2026-09-10', auth_hours: 1, hours: [0] }],
    });
    const cell = result.users[0].cells.find((c) => c.day === '2026-09-09');
    assert.equal(cell.state, 'truncated');
    assert.equal(cell.hours, null);
    assert.match(cell.reason, /capped/);
  });

  it('marks a PRESENT user in a capped day as a floor, not a count', () => {
    const cell = cellOf(grid(), '2026-09-09');
    assert.equal(cell.state, 'active');
    assert.equal(cell.hours, 11);
    assert.equal(cell.lowerBound, true, 'a capped day can only under-report');
  });

  it('every unmeasured cell carries null hours and a reason — never 0, never a bare blank', () => {
    const result = grid();
    for (const cell of result.users[0].cells) {
      if (MEASURED_STATES.has(cell.state)) continue;
      assert.equal(cell.hours, null, `${cell.day} reported a number while unmeasured`);
      assert.equal(cell.level, null, `${cell.day} carried an intensity while unmeasured`);
      assert.ok(cell.reason && cell.reason.length > 20, `${cell.day} has no explanation`);
    }
  });

  it('counts only genuinely measured days per user', () => {
    // 09-06 pre-history, 09-07 no success evidence, 09-09 capped but ACTIVE
    // (an active cell is still a measurement), 09-08 zero, 09-10 active.
    assert.equal(grid().users[0].measuredDays, 3);
  });
});

describe('day metadata', () => {
  it('flags a partial day rather than calling it a gap', () => {
    const today = grid().days.find((d) => d.key === '2026-09-10');
    assert.equal(today.covered, true);
    assert.equal(today.partial, true, '3 of 24 hours is partial, not missing');
    assert.equal(today.hoursCovered, 3);
  });

  it('carries the plain sum(event_count) for a fan-out sanity check', () => {
    const day = grid().days.find((d) => d.key === '2026-09-09');
    assert.equal(day.authEvents, 50);
    assert.equal(day.successRows + day.failureRows, 50);
  });
});

// ── the queries ───────────────────────────────────────────────────────────

function stubPool() {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      const text = String(sql);
      calls.push({ sql: text, params });
      if (/first_log_at/.test(text)) {
        return { rows: [{ first_log_at: '2026-09-08T07:00:00.000Z', last_log_at: '2026-09-10T02:00:00.000Z' }] };
      }
      if (/hours_covered/.test(text)) {
        return { rows: [{ day_key: '2026-09-09', hours_covered: 24, devices_reporting: 5 }] };
      }
      if (/truncated_rows/.test(text)) {
        return { rows: [{ day_key: '2026-09-09', success_rows: 10, failure_rows: 3, truncated_rows: 0, auth_events: 13 }] };
      }
      if (/total_users/.test(text)) {
        return {
          rows: [
            { username: 'alice', auth_hours: 4, auth_days: 1, devices: 1, total_users: 42, first_seen_at: null, last_seen_at: null },
          ],
        };
      }
      if (/hour_of_day/.test(text)) {
        return { rows: [{ username: 'alice', day_key: '2026-09-09', auth_hours: 4, hours: [1, 2, 3, 4] }] };
      }
      // per-vendor success/failure
      return { rows: [{ vendor: 'fortinet', success_rows: 0, failure_rows: 1789 }] };
    },
  };
}

describe('getVpnUserPresence queries', () => {
  it('⛔ NEVER reads syslog_events', async () => {
    // The equivalent VPN question against the raw table was measured at 85.6
    // SECONDS over 24 HOURS (vpnAuthStats.js). Over 30 days it is an outage.
    const pool = stubPool();
    await getVpnUserPresence(pool, { days: 30, now: new Date('2026-09-10T02:00:00Z') });
    for (const c of pool.calls) {
      assert.doesNotMatch(c.sql, /syslog_events/, 'raw event table reached from the heatmap');
    }
  });

  it('bounds every syslog read by a window and parameterizes the device filter', async () => {
    const pool = stubPool();
    await getVpnUserPresence(pool, { days: 7, deviceId: 'ee052a62-f5c4-470e-acde-9985254f816b', now: new Date('2026-09-10T02:00:00Z') });
    const syslogCalls = pool.calls.filter((c) => /syslog_(vpn_auth|rollup)_hourly/.test(c.sql));
    assert.ok(syslogCalls.length >= 5);
    for (const c of syslogCalls) {
      // The unbounded call is the history probe, which is a min()/max() over a
      // small permanent rollup and is the only one allowed to be unbounded.
      if (!/first_log_at/.test(c.sql)) {
        assert.match(c.sql, /bucket_hour >= \$1::timestamptz/, 'unbounded time window');
      }
      assert.doesNotMatch(c.sql, /device_id = '/, 'device id interpolated into SQL');
      assert.match(c.sql, /\$\d/, 'query carries no parameters at all');
    }
  });

  it('⛔ never sums event_count in a query that unnests usernames', async () => {
    // Unnesting a text[] under a sum fans the row out once per username. On
    // this exact table that bug inflated the VPN failure count 8.2x.
    const pool = stubPool();
    await getVpnUserPresence(pool, { days: 30, now: new Date('2026-09-10T02:00:00Z') });
    for (const c of pool.calls) {
      if (!/unnest/.test(c.sql)) continue;
      assert.doesNotMatch(c.sql, /sum\s*\(/i, 'a sum sits in the same query as an unnest');
    }
  });

  it('reports how much history exists, so an empty window is explained', async () => {
    const pool = stubPool();
    const r = await getVpnUserPresence(pool, { days: 30, now: new Date('2026-09-10T02:00:00Z') });
    assert.equal(r.coverage.requestedExceedsHistory, true);
    assert.ok(r.coverage.historyDays < 30);
    assert.equal(r.coverage.totalUsers, 42, 'total user count survives the top-N cap');
    assert.equal(r.coverage.rankedUsers, 1);
  });

  it('names a vendor that reports failures but no successes', async () => {
    // A Fortinet-only selection renders an almost empty grid because FortiOS
    // logs SSL-VPN successes essentially not at all. Unlabelled, that reads as
    // "nobody uses this VPN".
    const pool = stubPool();
    const r = await getVpnUserPresence(pool, { days: 30, now: new Date('2026-09-10T02:00:00Z') });
    assert.deepEqual(r.coverage.successReportingGaps.map((v) => v.vendor), ['fortinet']);
  });

  it('⛔ states the unit as AUTHENTICATED, never CONNECTED', async () => {
    const pool = stubPool();
    const r = await getVpnUserPresence(pool, { days: 30, now: new Date('2026-09-10T02:00:00Z') });
    assert.match(r.notes.unit, /authenticated/i);
    assert.doesNotMatch(r.notes.unit, /^(?!.*not connected).*connected time/i);
    // The gap the operator actually asked about must be stated, with what would
    // close it, so a future edit cannot quietly drop the caveat.
    assert.match(r.notes.durationGap, /vpn_active_sessions/);
    assert.match(r.notes.durationGap, /re-authenticates/);
  });
});
