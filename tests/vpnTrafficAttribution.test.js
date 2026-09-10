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
