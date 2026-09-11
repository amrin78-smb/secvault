'use strict';
// Pins lib/engines/vpnTrafficAttribution.js — traffic attributed to a NAMED
// VPN USER.
//
// ⛔ WHAT THESE TESTS ARE FOR. Per tests/README.md a test here must cover the
// "we could not measure this" case, not only the pass and the fail. That rule
// is sharper in this module than anywhere else in the repo, because the wrong
// answer is not a wrong number: it is a real employee's name over another
// person's traffic. A VPN pool recycles addresses, so the naive join —
// "whoever most recently held this IP" — produces a confident, plausible,
// fabricated accusation. Every ambiguity below must therefore resolve to
// NOBODY and be COUNTED.
//
// ⛔ EVERY USERNAME, ADDRESS AND HOSTNAME HERE IS SYNTHETIC. No real employee
// name and no internal destination belongs in a fixture in this repo — see
// .ai-codex/gotchas.md's redaction rules. The shapes are real; the values are
// invented.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  getVpnUserTraffic,
  attributeTraffic,
  normalizeIp,
  DEFAULT_WINDOW_DAYS,
  DEFAULT_TOP_USERS,
  MAX_WINDOW_DAYS,
} = require('../lib/engines/vpnTrafficAttribution');

const HOUR = 3600000;
const T = (iso) => new Date(iso).getTime();

// A synthetic day. Hours are whole UTC hours so a bucket is unambiguous.
const H = {
  h00: T('2026-09-09T00:00:00Z'),
  h01: T('2026-09-09T01:00:00Z'),
  h02: T('2026-09-09T02:00:00Z'),
  h03: T('2026-09-09T03:00:00Z'),
  h04: T('2026-09-09T04:00:00Z'),
  h05: T('2026-09-09T05:00:00Z'),
};

function session(over = {}) {
  return {
    id: 's-1',
    deviceId: 'dev-1',
    deviceName: 'gw-alpha',
    username: 'user-a',
    assignedIp: '10.99.0.10',
    tenureStart: H.h00,
    tenureEnd: H.h05,
    isOpen: false,
    pollIntervalSeconds: 1800,
    ...over,
  };
}

function bucket(over = {}) {
  return {
    ip: '10.99.0.10',
    hourStart: H.h01,
    deviceId: 'dev-1',
    deviceName: 'gw-alpha',
    events: 100,
    denied: 0,
    bytesSent: 1000,
    bytesReceived: 2000,
    ...over,
  };
}

describe('attributeTraffic — the address is held, so the traffic is named', () => {
  it('attributes an hour fully inside one session to that user', () => {
    const out = attributeTraffic({ sessions: [session()], buckets: [bucket()] });
    assert.equal(out.users.length, 1);
    assert.equal(out.users[0].username, 'user-a');
    assert.equal(out.users[0].events, 100);
    assert.equal(out.users[0].attributedHours, 1);
    assert.equal(out.totals.eventsAttributed, 100);
    assert.equal(out.unattributed.gap.buckets, 0);
    assert.equal(out.unattributed.collision.buckets, 0);
    assert.equal(out.unattributed.partial_hour.buckets, 0);
  });

  it('carries denied counts and per-session rows alongside the user row', () => {
    const out = attributeTraffic({
      sessions: [session()],
      buckets: [bucket({ denied: 7 })],
    });
    assert.equal(out.users[0].denied, 7);
    assert.equal(out.sessions.length, 1);
    assert.equal(out.sessions[0].id, 's-1');
    assert.equal(out.sessions[0].events, 100);
  });
});

describe('⛔ IP REUSE — the bug this module exists to prevent', () => {
  // The same pool address, two different people, one after the other. This is
  // the ordinary case on a real gateway, not an edge case.
  const early = session({
    id: 's-early',
    username: 'user-a',
    tenureStart: H.h00,
    tenureEnd: H.h02,
  });
  const late = session({
    id: 's-late',
    username: 'user-b',
    tenureStart: H.h03,
    tenureEnd: H.h05,
  });

  it('gives each user only the hours their own session covered', () => {
    const out = attributeTraffic({
      sessions: [early, late],
      buckets: [
        bucket({ hourStart: H.h00, events: 10 }), // inside user-a
        bucket({ hourStart: H.h04, events: 40 }), // inside user-b
      ],
    });
    const byName = Object.fromEntries(out.users.map((u) => [u.username, u]));
    assert.equal(byName['user-a'].events, 10);
    assert.equal(byName['user-b'].events, 40);
  });

  it('does NOT hand the later user traffic from before they connected', () => {
    const out = attributeTraffic({
      sessions: [late],
      buckets: [bucket({ hourStart: H.h00, events: 999 })],
    });
    // Nobody known held the address then. 999 events happened; they belong to
    // no name, and the count survives so the gap is visible.
    assert.equal(out.users.length, 0);
    assert.equal(out.unattributed.gap.buckets, 1);
    assert.equal(out.unattributed.gap.events, 999);
    assert.equal(out.totals.eventsAttributed, 0);
  });

  it('treats the hand-over hour as unattributed, never as the nearest session', () => {
    // h02 is covered by user-a only up to 02:00 and by user-b only from 03:00,
    // so the 02:00-03:00 bucket is nobody's.
    const out = attributeTraffic({
      sessions: [early, late],
      buckets: [bucket({ hourStart: H.h02, events: 55 })],
    });
    assert.equal(out.users.length, 0);
    assert.equal(out.unattributed.gap.events, 55);
  });
});

describe('⛔ OVERLAP — two sessions on one address means NEITHER', () => {
  it('attributes to nobody and records the collision with both names', () => {
    const a = session({ id: 's-a', username: 'user-a', tenureStart: H.h00, tenureEnd: H.h05 });
    const b = session({ id: 's-b', username: 'user-b', tenureStart: H.h00, tenureEnd: H.h05 });
    const out = attributeTraffic({ sessions: [a, b], buckets: [bucket({ events: 500 })] });

    assert.equal(out.users.length, 0);
    assert.equal(out.sessions.length, 0);
    assert.equal(out.unattributed.collision.buckets, 1);
    assert.equal(out.unattributed.collision.events, 500);
    assert.equal(out.collisions.length, 1);
    assert.deepEqual(out.collisions[0].usernames.sort(), ['user-a', 'user-b']);
    assert.equal(out.collisions[0].sameUser, false);
  });

  it('still refuses to attribute when both sessions are the SAME user', () => {
    // A reconnection that reused the address. The ambiguity is benign — and it
    // is still an ambiguity, so the rule does not bend for it. The `sameUser`
    // flag is how the operator can tell the two kinds apart.
    const a = session({ id: 's-a', tenureStart: H.h00, tenureEnd: H.h05 });
    const b = session({ id: 's-b', tenureStart: H.h00, tenureEnd: H.h05 });
    const out = attributeTraffic({ sessions: [a, b], buckets: [bucket()] });
    assert.equal(out.users.length, 0);
    assert.equal(out.collisions[0].sameUser, true);
    assert.equal(out.unattributed.collision.buckets, 1);
  });

  it('detects a collision ACROSS devices, not only within one gateway', () => {
    // Two gateways can hand out overlapping pools. "Different firewalls, same
    // address, same hour" is exactly as ambiguous as one firewall doing it.
    const a = session({ id: 's-a', deviceId: 'dev-1', username: 'user-a' });
    const b = session({ id: 's-b', deviceId: 'dev-2', username: 'user-b' });
    const out = attributeTraffic({ sessions: [a, b], buckets: [bucket()] });
    assert.equal(out.unattributed.collision.buckets, 1);
    assert.equal(out.users.length, 0);
  });
});

describe('⛔ PARTIAL COVER — an hour the session held for only part of', () => {
  it('does not attribute an hour the session entered mid-way', () => {
    const s = session({ tenureStart: H.h01 + 20 * 60000, tenureEnd: H.h05 });
    const out = attributeTraffic({ sessions: [s], buckets: [bucket({ hourStart: H.h01, events: 33 })] });
    assert.equal(out.users.length, 0);
    assert.equal(out.unattributed.partial_hour.buckets, 1);
    assert.equal(out.unattributed.partial_hour.events, 33);
  });

  it('does not attribute the trailing hour of a still-open session', () => {
    // ⛔ An open session's tenure ends at last_seen_at, not at "now". Traffic
    // after the last confirmed observation is not yet demonstrably theirs.
    const s = session({ tenureStart: H.h00, tenureEnd: H.h02 + 10 * 60000, isOpen: true });
    const out = attributeTraffic({
      sessions: [s],
      buckets: [bucket({ hourStart: H.h01 }), bucket({ hourStart: H.h02 })],
    });
    assert.equal(out.users[0].attributedHours, 1); // h01 only
    assert.equal(out.unattributed.partial_hour.buckets, 1); // h02
  });
});

describe('⛔ BYTES — tri-state, never a fabricated zero', () => {
  it('reports NULL, not 0, when no bucket carried summable bytes', () => {
    const out = attributeTraffic({
      sessions: [session()],
      buckets: [bucket({ bytesSent: null, bytesReceived: null })],
    });
    const u = out.users[0];
    assert.equal(u.bytesSent, null);
    assert.equal(u.bytesReceived, null);
    assert.notEqual(u.bytesSent, 0);
    assert.equal(u.byteBuckets, 0);
    assert.equal(u.unmeasuredByteBuckets, 1);
    assert.equal(u.bytesArePartial, false);
    // The event count is still a real measurement — only the volume is absent.
    assert.equal(u.events, 100);
  });

  it('flags a mixed set as a LOWER BOUND rather than a total', () => {
    const out = attributeTraffic({
      sessions: [session()],
      buckets: [
        bucket({ hourStart: H.h01, bytesSent: 500, bytesReceived: 700 }),
        bucket({ hourStart: H.h02, bytesSent: null, bytesReceived: null }),
      ],
    });
    const u = out.users[0];
    assert.equal(u.bytesSent, 500);
    assert.equal(u.bytesArePartial, true);
    assert.equal(u.unmeasuredByteBuckets, 1);
  });

  it('a genuine 0 stays 0 and is distinguishable from unmeasured', () => {
    const out = attributeTraffic({
      sessions: [session()],
      buckets: [bucket({ bytesSent: 0, bytesReceived: 0 })],
    });
    assert.equal(out.users[0].bytesSent, 0);
    assert.equal(out.users[0].byteBuckets, 1);
    assert.equal(out.users[0].bytesArePartial, false);
  });
});

describe('⛔ DOUBLE COUNTING — more than one firewall logged the address', () => {
  it('flags multiDeviceCounted so a total is not read as unique flows', () => {
    const out = attributeTraffic({
      sessions: [session()],
      buckets: [
        bucket({ hourStart: H.h01, deviceId: 'dev-1', deviceName: 'gw-alpha' }),
        bucket({ hourStart: H.h01, deviceId: 'dev-2', deviceName: 'fw-beta' }),
      ],
    });
    assert.equal(out.users[0].multiDeviceCounted, true);
    assert.equal(out.users[0].loggingDeviceCount, 2);
    assert.equal(out.users[0].events, 200);
  });

  it('leaves the flag false for a single logging device', () => {
    const out = attributeTraffic({ sessions: [session()], buckets: [bucket()] });
    assert.equal(out.users[0].multiDeviceCounted, false);
  });
});

describe('input hygiene', () => {
  it('normalizeIp strips a /32 so both sides of the join agree', () => {
    assert.equal(normalizeIp('10.99.0.10/32'), '10.99.0.10');
    assert.equal(normalizeIp('10.99.0.10'), '10.99.0.10');
    assert.equal(normalizeIp(null), null);
    assert.equal(normalizeIp('   '), null);
  });

  it('a session with no username attributes nothing rather than a null row', () => {
    const out = attributeTraffic({
      sessions: [session({ username: null })],
      buckets: [bucket()],
    });
    assert.equal(out.users.length, 0);
    assert.equal(out.unattributed.gap.buckets, 1);
  });

  it('a session with no assigned address cannot claim any traffic', () => {
    const out = attributeTraffic({
      sessions: [session({ assignedIp: null })],
      buckets: [bucket()],
    });
    assert.equal(out.users.length, 0);
    assert.equal(out.unattributed.gap.events, 100);
  });

  it('survives empty input without inventing anything', () => {
    const out = attributeTraffic({});
    assert.deepEqual(out.users, []);
    assert.equal(out.totals.bucketsConsidered, 0);
  });
});

// ── the DB layer, against a stub pool ─────────────────────────────────────

function stubPool(plan) {
  const seen = [];
  return {
    seen,
    query(sql, params) {
      seen.push({ sql, params });
      if (/FROM vpn_sessions\)\s+AS session_rows|session_rows/.test(sql)) {
        return Promise.resolve({ rows: [plan.coverage] });
      }
      if (/assigned_ip IS NULL/.test(sql)) {
        return Promise.resolve({ rows: [{ unjoinable: plan.unjoinable || 0 }] });
      }
      if (/min\(v\.first_seen_at\)/.test(sql)) {
        return Promise.resolve({ rows: plan.deviceCoverage || [] });
      }
      if (/FROM vpn_sessions/.test(sql)) {
        return Promise.resolve({ rows: plan.sessions || [] });
      }
      if (/syslog_talker_hourly/.test(sql)) {
        return Promise.resolve({ rows: plan.buckets || [] });
      }
      throw new Error('unexpected query: ' + sql);
    },
  };
}

const COVERAGE_FULL = {
  session_rows: 12,
  history_start: '2026-08-01T00:00:00Z',
  earliest_login: '2026-08-01T00:00:00Z',
  latest_observation: '2026-09-09T06:00:00Z',
  traffic_start: '2026-08-01T00:00:00Z',
  traffic_end: '2026-09-09T06:00:00Z',
};

describe('⛔ COVERAGE — an absent measurement must not render as a zero', () => {
  it('an empty session history is NOT MEASURED, not "nobody used the VPN"', async () => {
    const pool = stubPool({
      coverage: {
        session_rows: 0,
        history_start: null,
        earliest_login: null,
        latest_observation: null,
        traffic_start: '2026-09-01T00:00:00Z',
        traffic_end: '2026-09-09T00:00:00Z',
      },
    });
    const out = await getVpnUserTraffic(pool, { days: 7 });
    assert.equal(out.measured, false);
    assert.equal(out.coverage.reason, 'no_session_history');
    assert.match(out.coverage.reasonText, /not evidence/i);
    assert.deepEqual(out.users, []);
  });

  it('a missing pool is reported, never treated as an empty fleet', async () => {
    const out = await getVpnUserTraffic(null, {});
    assert.equal(out.measured, false);
    assert.equal(out.coverage.reason, 'no_pool');
  });

  it('names BOTH bounds when the window is clipped', async () => {
    const pool = stubPool({
      coverage: {
        session_rows: 5,
        history_start: '2026-09-08T00:00:00Z', // history began 2 days ago
        earliest_login: '2026-09-08T00:00:00Z',
        latest_observation: '2026-09-09T06:00:00Z',
        traffic_start: '2026-09-05T00:00:00Z',
        traffic_end: '2026-09-09T06:00:00Z',
      },
      sessions: [],
    });
    const out = await getVpnUserTraffic(pool, { days: 30, until: '2026-09-09T06:00:00Z' });
    assert.equal(out.coverage.truncatedAtStart, true);
    assert.ok(out.coverage.bounds.includes('session_history_start'));
    assert.equal(out.window.from, '2026-09-08T00:00:00.000Z');
    assert.match(out.coverage.boundNote, /NOT MEASURED, not zero/);
    // Both bounds stay readable even when only one of them bit.
    assert.equal(out.coverage.sessionHistoryStart, '2026-09-08T00:00:00.000Z');
    assert.equal(out.coverage.trafficRollupStart, '2026-09-05T00:00:00.000Z');
  });

  it('reports the raw-retention bound when it is the later of the two', async () => {
    const pool = stubPool({
      coverage: {
        session_rows: 5,
        history_start: '2026-07-01T00:00:00Z',
        earliest_login: '2026-07-01T00:00:00Z',
        latest_observation: '2026-09-09T06:00:00Z',
        traffic_start: '2026-09-06T00:00:00Z',
        traffic_end: '2026-09-09T06:00:00Z',
      },
      sessions: [],
    });
    const out = await getVpnUserTraffic(pool, { days: 30, until: '2026-09-09T06:00:00Z' });
    assert.ok(out.coverage.bounds.includes('traffic_retention'));
    assert.equal(out.window.from, '2026-09-06T00:00:00.000Z');
  });

  it('counts sessions whose address the device never reported', async () => {
    const pool = stubPool({
      coverage: COVERAGE_FULL,
      sessions: [],
      unjoinable: 4,
    });
    const out = await getVpnUserTraffic(pool, { days: 7, until: '2026-09-09T06:00:00Z' });
    assert.equal(out.coverage.sessionsUnjoinable, 4);
    assert.equal(out.coverage.reason, 'no_assigned_addresses');
  });
});

describe('getVpnUserTraffic — end to end over the stub', () => {
  const plan = {
    coverage: COVERAGE_FULL,
    sessions: [
      {
        id: 's-1',
        device_id: 'dev-1',
        username: 'user-a',
        assigned_ip: '10.99.0.10',
        login_time: '2026-09-09T00:00:00Z',
        ended_at: null,
        last_seen_at: '2026-09-09T05:00:00Z',
        poll_interval_seconds: 1800,
        is_open: true,
        device_name: 'gw-alpha',
        device_vendor: 'paloalto',
      },
    ],
    buckets: [
      {
        bucket_hour: '2026-09-09T01:00:00Z',
        src_ip: '10.99.0.10/32',
        device_id: 'dev-1',
        event_count: '120',
        denied_count: '3',
        bytes_sent: '4096',
        bytes_received: '8192',
        device_name: 'gw-alpha',
      },
      {
        // Nobody held this address at 09:00 — a gap that must stay visible.
        bucket_hour: '2026-09-09T09:00:00Z',
        src_ip: '10.99.0.10/32',
        device_id: 'dev-1',
        event_count: '60',
        denied_count: '0',
        bytes_sent: null,
        bytes_received: null,
        device_name: 'gw-alpha',
      },
    ],
  };

  it('joins the rollup to the session and reports the gap beside it', async () => {
    const pool = stubPool(plan);
    const out = await getVpnUserTraffic(pool, { days: 7, until: '2026-09-09T12:00:00Z' });
    assert.equal(out.measured, true);
    assert.equal(out.users.length, 1);
    assert.equal(out.users[0].username, 'user-a');
    assert.equal(out.users[0].events, 120);
    assert.equal(out.users[0].bytesSent, 4096);
    assert.equal(out.unattributed.gap.events, 60);
    assert.deepEqual(out.coverage.vendors, ['paloalto']);
    assert.equal(out.coverage.poolAddresses, 1);
  });

  it('passes the pool addresses and both window bounds as parameters', async () => {
    const pool = stubPool(plan);
    await getVpnUserTraffic(pool, { days: 7, until: '2026-09-09T12:00:00Z' });
    const bucketQuery = pool.seen.find((q) => /FROM syslog_talker_hourly t/.test(q.sql));
    assert.ok(bucketQuery, 'the rollup was queried');
    assert.deepEqual(bucketQuery.params[2], ['10.99.0.10']);
    assert.ok(bucketQuery.params[3] > 0, 'a row ceiling is always applied');
  });

  it('⛔ an OMITTED option falls back to the default, not to the minimum', async () => {
    // Caught on the live fleet: `Number('')` is 0, which is finite, so an
    // absent `topUsers` clamped to 1 and the page drew one user out of 62 —
    // with `usersTotal` correctly reporting 62 right beside it. A plausible
    // table is the worst kind of wrong.
    const out = await getVpnUserTraffic(stubPool(plan), { until: '2026-09-09T12:00:00Z' });
    assert.equal(out.window.days, DEFAULT_WINDOW_DAYS);
    assert.equal(out.topUsers, DEFAULT_TOP_USERS);
    const blank = await getVpnUserTraffic(stubPool(plan), {
      until: '2026-09-09T12:00:00Z',
      days: '',
      topUsers: '   ',
    });
    assert.equal(blank.window.days, DEFAULT_WINDOW_DAYS);
    assert.equal(blank.topUsers, DEFAULT_TOP_USERS);
  });

  it('clamps the window rather than trusting caller input', async () => {
    const pool = stubPool(plan);
    const out = await getVpnUserTraffic(pool, { days: 9999, until: '2026-09-09T12:00:00Z' });
    assert.ok(out.window.days <= MAX_WINDOW_DAYS);
    const bad = await getVpnUserTraffic(stubPool(plan), { days: 'nonsense' });
    assert.equal(bad.window.days, DEFAULT_WINDOW_DAYS);
  });

  it('a username filter narrows the ANSWER, not the collision check', async () => {
    // Both sessions held 10.99.0.10 at the same time. Filtering to one user
    // must not make the address look unambiguous.
    const collide = {
      coverage: COVERAGE_FULL,
      sessions: [
        { ...plan.sessions[0], id: 's-1', username: 'user-a' },
        { ...plan.sessions[0], id: 's-2', username: 'user-b' },
      ],
      buckets: [plan.buckets[0]],
    };
    const out = await getVpnUserTraffic(stubPool(collide), {
      days: 7,
      until: '2026-09-09T12:00:00Z',
      username: 'user-a',
    });
    assert.equal(out.users.length, 0);
    assert.equal(out.unattributed.collision.buckets, 1);
  });
});

describe('⛔ COVERAGE IS PER GATEWAY, not fleet-wide', () => {
  // A gateway added late reports sessions the device says began weeks ago.
  // Judged against a fleet-wide history start those weeks look covered, and an
  // hour with one known session on the address reads as unambiguous — while
  // SecVault could not enumerate that gateway's sessions at all.
  const plan = {
    coverage: {
      session_rows: 9,
      history_start: '2026-09-01T00:00:00Z', // fleet-wide: an OLD gateway
      earliest_login: '2026-09-01T00:00:00Z',
      latest_observation: '2026-09-09T12:00:00Z',
      traffic_start: '2026-09-01T00:00:00Z',
      traffic_end: '2026-09-09T12:00:00Z',
    },
    // ...but THIS gateway was only added at 06:00 on the 9th.
    deviceCoverage: [{ device_id: 'dev-new', device_start: '2026-09-09T06:00:00Z' }],
    sessions: [
      {
        id: 's-new',
        device_id: 'dev-new',
        username: 'user-a',
        assigned_ip: '10.99.0.10',
        login_time: '2026-09-02T00:00:00Z', // the device's own claim
        ended_at: null,
        last_seen_at: '2026-09-09T12:00:00Z',
        poll_interval_seconds: 1800,
        is_open: true,
        device_name: 'gw-new',
        device_vendor: 'paloalto',
      },
    ],
    buckets: [
      // Before the gateway was ever polled: must NOT be attributed.
      {
        bucket_hour: '2026-09-03T10:00:00Z',
        src_ip: '10.99.0.10',
        device_id: 'dev-new',
        event_count: '400',
        denied_count: '0',
        bytes_sent: '10',
        bytes_received: '10',
        device_name: 'gw-new',
      },
      // After it: attributable.
      {
        bucket_hour: '2026-09-09T08:00:00Z',
        src_ip: '10.99.0.10',
        device_id: 'dev-new',
        event_count: '25',
        denied_count: '0',
        bytes_sent: '10',
        bytes_received: '10',
        device_name: 'gw-new',
      },
    ],
  };

  it('refuses hours before THIS gateway was first observed', async () => {
    const out = await getVpnUserTraffic(stubPool(plan), {
      days: 30,
      until: '2026-09-09T12:00:00Z',
    });
    assert.equal(out.users.length, 1);
    assert.equal(out.users[0].events, 25, 'only the covered hour is named');
    assert.equal(out.unattributed.gap.events, 400, 'the pre-coverage hour is unattributed');
    assert.equal(out.coverage.sessionsClippedByDeviceCoverage, 1);
    const s = out.sessions[0];
    assert.equal(s.loginTime, '2026-09-02T00:00:00.000Z', 'the device claim is preserved');
    assert.equal(s.attributionFrom, '2026-09-09T06:00:00.000Z');
    assert.equal(s.attributionClipped, true);
  });
});

describe('⛔ source-level rules that must not be edited away', () => {
  const SRC = fs.readFileSync(
    path.join(__dirname, '..', 'lib', 'engines', 'vpnTrafficAttribution.js'),
    'utf8'
  );

  it('never reads syslog_events', () => {
    // ~28M rows/day with no index on src_ip. An interactive page may not do
    // this, and a future edit that "improves" the drill-down by reaching for
    // the raw table must fail here first.
    assert.ok(!/\bsyslog_events\b(?![^\n]*(?:--|no index))/.test(
      SRC.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n')
    ), 'a SQL statement in this module references syslog_events');
  });

  it('casts every timestamp parameter explicitly', () => {
    for (const m of SRC.matchAll(/(login_time|ended_at|last_seen_at|bucket_hour)\s*[<>=]+\s*(\$\d+)(::[a-z]+)?/g)) {
      assert.equal(m[3], '::timestamptz', `${m[1]} compared to ${m[2]} without a ::timestamptz cast`);
    }
  });

  it('parameterises every value — no interpolation into SQL', () => {
    for (const lit of SRC.match(/`[^`]*`/g) || []) {
      if (!/\bSELECT\b/.test(lit)) continue;
      assert.ok(!/\$\{/.test(lit), 'a SQL literal interpolates a JS value');
    }
  });

  it('states the Palo-Alto-only scope in words the UI can render', () => {
    assert.match(SRC, /Only Palo Alto reports per-session VPN detail/);
  });
});

// ── ⛔ SCOPING A REFUSAL TO THE FILTERED SUBJECT ──────────────────────────
//
// The bug these pin, seen live: `?utUser=<one person>` rendered the FLEET's
// unattributed totals (166,892 events) and the FLEET's collision table — a list
// of other employees' accounts — as the answer to a question about one person.
// `?utUser=<nobody>` did the same AND claimed the traffic was theirs.
//
// Two failure directions to hold apart, and both are represented below:
//   * OVER-CLAIM — showing a filtered operator somebody else's traffic, or a
//     denominator that is not their own;
//   * VANISHING — a bucket that cannot be tied to the subject quietly
//     disappearing instead of staying in the fleet total. That one turns a
//     coverage gap into a clean result, which is this codebase's dominant bug.

const { scopeUnattributed } = require('../lib/engines/vpnTrafficAttribution');

describe('⛔ SCOPED REFUSALS — narrowing the view must not narrow the truth', () => {
  // user-a and user-b share 10.99.0.10 (a recycled pool address, overlapping
  // for one hour); user-c is a bystander on 10.99.0.20.
  const sA = session({ id: 's-a', username: 'user-a', assignedIp: '10.99.0.10', tenureStart: H.h00, tenureEnd: H.h05 });
  const sB = session({ id: 's-b', username: 'user-b', assignedIp: '10.99.0.10', tenureStart: H.h04 + 1800000, tenureEnd: H.h05 + HOUR });
  const sC = session({ id: 's-c', username: 'user-c', assignedIp: '10.99.0.20', tenureStart: H.h00, tenureEnd: H.h02 + 1800000 });

  const buckets = [
    bucket({ hourStart: H.h01, ip: '10.99.0.10', events: 100 }),            // -> user-a
    bucket({ hourStart: H.h04, ip: '10.99.0.10', events: 40 }),             // collision a/b
    bucket({ hourStart: H.h05, ip: '10.99.0.10', events: 30 }),             // -> user-b
    bucket({ hourStart: T('2026-09-09T09:00:00Z'), ip: '10.99.0.10', events: 7 }), // gap on .10
    bucket({ hourStart: H.h00, ip: '10.99.0.20', events: 50 }),             // -> user-c
    bucket({ hourStart: H.h02, ip: '10.99.0.20', events: 60 }),             // partial, user-c
    bucket({ hourStart: H.h03, ip: '10.99.0.20', events: 5 }),              // gap on .20
  ];
  const out = attributeTraffic({ sessions: [sA, sB, sC], buckets });

  it('the fleet figures are what they always were', () => {
    assert.equal(out.unattributed.collision.buckets, 1);
    assert.equal(out.unattributed.partial_hour.buckets, 1);
    assert.equal(out.unattributed.gap.buckets, 2);
  });

  it('ties a collision to a subject who was a PARTY to it', () => {
    const s = scopeUnattributed(out, [sA]);
    assert.equal(s.unattributed.collision.buckets, 1);
    assert.equal(s.unattributed.collision.events, 40);
    assert.equal(s.collisionsTotal, 1);
    assert.deepEqual(s.collisions[0].usernames.slice().sort(), ['user-a', 'user-b']);
  });

  it('does NOT tie another person of the fleet’s partial hour to the subject', () => {
    // user-c's mid-hour departure is user-c's ambiguity, on user-c's address.
    const s = scopeUnattributed(out, [sA]);
    assert.equal(s.unattributed.partial_hour.buckets, 0);
    assert.equal(s.unattributed.partial_hour.events, 0);
    // …and it has NOT vanished: the fleet total still carries it.
    assert.equal(out.unattributed.partial_hour.events, 60);
  });

  it('ties a gap by ADDRESS ONLY, because a gap belongs to nobody', () => {
    const a = scopeUnattributed(out, [sA]);
    assert.equal(a.unattributed.gap.buckets, 1, 'the gap on the address user-a held');
    assert.equal(a.unattributed.gap.events, 7);
    const c = scopeUnattributed(out, [sC]);
    assert.equal(c.unattributed.gap.events, 5, 'a different address, a different gap');
  });

  it('⛔ two subjects may both carry the same gap hour — never add them up', () => {
    // user-a and user-b both held 10.99.0.10, so the 09:00 gap on it ties to
    // both. Each statement is true on its own; their sum is not a quantity.
    const a = scopeUnattributed(out, [sA]);
    const b = scopeUnattributed(out, [sB]);
    assert.equal(a.unattributed.gap.events, 7);
    assert.equal(b.unattributed.gap.events, 7);
    assert.equal(out.unattributed.gap.events, 12, 'the fleet counts each bucket ONCE');
  });

  it('⛔ scope never exceeds fleet, for any subject', () => {
    for (const subject of [[sA], [sB], [sC], [sA, sB, sC]]) {
      const s = scopeUnattributed(out, subject);
      for (const k of ['partial_hour', 'collision', 'gap']) {
        assert.ok(s.unattributed[k].buckets <= out.unattributed[k].buckets, k + ' buckets');
        assert.ok(s.unattributed[k].events <= out.unattributed[k].events, k + ' events');
      }
    }
  });

  it('gives the subject their OWN denominator, not the fleet’s', () => {
    const s = scopeUnattributed(out, [sC]);
    // Only 10.99.0.20's three buckets: 50 + 60 + 5.
    assert.equal(s.bucketsConsidered, 3);
    assert.equal(s.eventsConsidered, 115);
    assert.equal(out.totals.eventsConsidered, 292, 'the fleet denominator is untouched');
  });

  it('an empty subject scopes to nothing rather than to everything', () => {
    const s = scopeUnattributed(out, []);
    assert.equal(s.unattributed.gap.events, 0);
    assert.equal(s.collisionsTotal, 0);
    assert.equal(s.eventsConsidered, 0);
    assert.equal(s.addresses, 0);
  });
});

describe('⛔ getVpnUserTraffic — a filter scopes the panel, never the attribution', () => {
  const plan = {
    coverage: COVERAGE_FULL,
    deviceCoverage: [],
    sessions: [
      {
        id: 's-a', device_id: 'dev-1', username: 'user-a', assigned_ip: '10.99.0.10',
        login_time: '2026-09-09T00:00:00Z', ended_at: '2026-09-09T05:00:00Z',
        last_seen_at: '2026-09-09T05:00:00Z', poll_interval_seconds: 1800, is_open: false,
        device_name: 'gw-alpha', device_vendor: 'paloalto',
      },
      {
        id: 's-b', device_id: 'dev-2', username: 'user-b', assigned_ip: '10.99.0.10',
        login_time: '2026-09-09T04:30:00Z', ended_at: '2026-09-09T06:00:00Z',
        last_seen_at: '2026-09-09T06:00:00Z', poll_interval_seconds: 1800, is_open: false,
        device_name: 'gw-beta', device_vendor: 'paloalto',
      },
      {
        id: 's-c', device_id: 'dev-1', username: 'user-c', assigned_ip: '10.99.0.20',
        login_time: '2026-09-09T00:00:00Z', ended_at: '2026-09-09T02:30:00Z',
        last_seen_at: '2026-09-09T02:30:00Z', poll_interval_seconds: 1800, is_open: false,
        device_name: 'gw-alpha', device_vendor: 'paloalto',
      },
    ],
    buckets: [
      { bucket_hour: '2026-09-09T01:00:00Z', src_ip: '10.99.0.10/32', device_id: 'dev-1', event_count: '100', denied_count: '0', bytes_sent: '10', bytes_received: '10', device_name: 'gw-alpha' },
      { bucket_hour: '2026-09-09T04:00:00Z', src_ip: '10.99.0.10/32', device_id: 'dev-1', event_count: '40', denied_count: '0', bytes_sent: null, bytes_received: null, device_name: 'gw-alpha' },
      { bucket_hour: '2026-09-09T09:00:00Z', src_ip: '10.99.0.10/32', device_id: 'dev-1', event_count: '7', denied_count: '0', bytes_sent: null, bytes_received: null, device_name: 'gw-alpha' },
      { bucket_hour: '2026-09-09T00:00:00Z', src_ip: '10.99.0.20/32', device_id: 'dev-1', event_count: '50', denied_count: '0', bytes_sent: '5', bytes_received: '5', device_name: 'gw-alpha' },
      { bucket_hour: '2026-09-09T02:00:00Z', src_ip: '10.99.0.20/32', device_id: 'dev-1', event_count: '60', denied_count: '0', bytes_sent: null, bytes_received: null, device_name: 'gw-alpha' },
    ],
  };
  const at = { days: 7, until: '2026-09-09T12:00:00Z' };

  it('no filter means no scope object at all — null, never an empty one', async () => {
    const out = await getVpnUserTraffic(stubPool(plan), at);
    assert.equal(out.scope, null);
    assert.equal(out.unattributed.collision.buckets, 1);
  });

  it('⛔ THE BUG: a user filter no longer reprints the fleet’s refusals', async () => {
    const out = await getVpnUserTraffic(stubPool(plan), { ...at, username: 'user-a' });
    // Fleet figures are still available and still complete…
    assert.equal(out.unattributed.partial_hour.events, 60);
    assert.equal(out.unattributed.gap.events, 7);
    assert.equal(out.collisionsTotal, 1);
    // …and the SCOPED ones are genuinely narrower.
    assert.equal(out.scope.active, true);
    assert.equal(out.scope.unattributed.partial_hour.events, 0, 'user-c’s partial hour is not user-a’s');
    assert.equal(out.scope.unattributed.collision.events, 40);
    assert.equal(out.scope.unattributed.gap.events, 7);
    assert.equal(out.scope.eventsConsidered, 147, 'only traffic on 10.99.0.10');
    assert.ok(out.scope.eventsConsidered < out.totals.eventsConsidered);
  });

  it('names another employee ONLY as the counterparty to the subject’s own collision', async () => {
    const out = await getVpnUserTraffic(stubPool(plan), { ...at, username: 'user-a' });
    assert.equal(out.scope.collisionsTotal, 1);
    assert.deepEqual(out.scope.collisions[0].usernames.slice().sort(), ['user-a', 'user-b']);
    // user-c is a real user with real unattributed traffic and must NOT appear.
    const namesShown = out.scope.collisions.flatMap((c) => c.usernames);
    assert.ok(!namesShown.includes('user-c'));
  });

  it('a subject with nothing unattributed says SO, and says it is measured', async () => {
    const clean = {
      ...plan,
      sessions: [plan.sessions[2]],
      buckets: [plan.buckets[3]],
    };
    const out = await getVpnUserTraffic(stubPool(clean), { ...at, username: 'user-c' });
    assert.equal(out.scope.unattributedBuckets, 0);
    assert.equal(out.scope.reason, 'nothing_unattributed_for_subject');
    assert.ok(out.scope.bucketsConsidered > 0, 'a measured zero, not an unmeasured one');
  });

  it('a subject whose addresses produced no traffic at all is NOT MEASURED', async () => {
    const quiet = { ...plan, buckets: [plan.buckets[3]] }; // only 10.99.0.20
    const out = await getVpnUserTraffic(stubPool(quiet), { ...at, username: 'user-a' });
    assert.equal(out.scope.reason, 'no_traffic_on_subject_addresses');
    assert.equal(out.scope.bucketsConsidered, 0);
    assert.equal(out.scope.unattributedEvents, 0);
  });

  it('a subject seen only in ambiguous hours reports THAT, not silence', async () => {
    // Every bucket on user-a's address is the collision hour: traffic exists,
    // none of it is attributable to them.
    const murky = { ...plan, buckets: [plan.buckets[1]] };
    const out = await getVpnUserTraffic(stubPool(murky), { ...at, username: 'user-a' });
    assert.equal(out.scope.hoursAttributed, 0);
    assert.equal(out.scope.reason, 'no_attributable_traffic_for_subject');
    assert.match(out.scope.reasonText, /Traffic was seen/);
  });

  it('⛔ an unknown username says the filter matched nothing — not "no traffic"', async () => {
    const out = await getVpnUserTraffic(stubPool(plan), { ...at, username: 'nosuchuser' });
    assert.equal(out.users.length, 0);
    assert.equal(out.scope.reason, 'filter_matched_no_sessions');
    assert.equal(out.scope.matchedSessions, 0);
    assert.equal(out.scope.addresses, 0);
    assert.equal(out.scope.unattributedEvents, 0);
    assert.equal(out.scope.collisionsTotal, 0, 'no employee names under a filter that matched nobody');
    assert.equal(out.scope.requestedUsername, 'nosuchuser');
    assert.equal(out.scope.username, null, 'nothing canonical to echo back');
    // The fleet answer still exists on the object — the UI labels it fleet-wide.
    assert.equal(out.unattributed.collision.buckets, 1);
  });

  it('⛔ an unknown gateway id says so too, rather than rendering zeros', async () => {
    const out = await getVpnUserTraffic(stubPool(plan), { ...at, deviceId: 'dev-nope' });
    assert.equal(out.scope.reason, 'filter_matched_no_sessions');
    assert.equal(out.scope.requestedDeviceId, 'dev-nope');
    assert.match(out.scope.reasonText, /NOT MEASURED/);
  });

  it('a gateway filter scopes to that gateway’s own sessions', async () => {
    const out = await getVpnUserTraffic(stubPool(plan), { ...at, deviceId: 'dev-2' });
    assert.equal(out.scope.matchedSessions, 1, 'only user-b is on gw-beta');
    assert.equal(out.scope.deviceName, 'gw-beta');
    assert.equal(out.scope.unattributed.collision.events, 40);
    assert.equal(out.scope.unattributed.partial_hour.events, 0);
  });

  it('a username filter does not claim a gateway the person may not be limited to', async () => {
    const out = await getVpnUserTraffic(stubPool(plan), { ...at, username: 'user-a' });
    assert.equal(out.scope.deviceName, null);
    assert.deepEqual(out.scope.gateways, ['gw-alpha']);
  });

  it('⛔ the filter is STILL applied after attribution — nothing is pushed into SQL', async () => {
    const pool = stubPool(plan);
    await getVpnUserTraffic(pool, { ...at, username: 'user-a', deviceId: 'dev-1' });
    const sessionQuery = pool.seen.find((q) => /FROM vpn_sessions v/.test(q.sql) && /ORDER BY v\.login_time/.test(q.sql));
    assert.ok(sessionQuery, 'the session set was queried');
    assert.equal(sessionQuery.params.length, 3, 'window start, window end and a row ceiling — no filter');
    assert.ok(!/username/i.test(sessionQuery.sql.replace(/v\.username,/, '')), 'the username is never a SQL predicate');
    assert.ok(!/device_id\s*=/.test(sessionQuery.sql), 'the device id never reaches the SQL');
    const bucketQuery = pool.seen.find((q) => /FROM syslog_talker_hourly t/.test(q.sql));
    assert.deepEqual(
      bucketQuery.params[2].slice().sort(),
      ['10.99.0.10', '10.99.0.20'],
      'EVERY pool address is still fetched, so a collision on a filtered-out session is still seen'
    );
  });
});
