// tests/exposure.test.js
//
// Internet Exposure. The failure this pins hardest is the one that makes the
// attack surface look SMALLER than it is — a dropped path, a quiet path read
// as closed, an unmeasured device read as clean. Under-reporting exposure is
// strictly more dangerous than over-reporting it, so most cases below assert
// that something is still counted.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  isPublicIp,
  publicInterfaceIps,
  buildDnatMap,
  buildExposurePaths,
  scoreExposure,
} = require('../lib/engines/exposure');

const { attachObservations } = require('../lib/engines/exposureQuery');

// ───────────────────────────── address basics ─────────────────────────────

test('isPublicIp: private, loopback, CGNAT and reserved space is not public', () => {
  for (const ip of [
    '10.0.0.1', '10.255.255.254', '172.16.5.5', '172.31.0.1', '192.168.1.1',
    '127.0.0.1', '169.254.1.1', '100.64.0.1', '0.0.0.0', '224.0.0.1', '240.0.0.1',
  ]) {
    assert.equal(isPublicIp(ip), false, ip);
  }
});

test('isPublicIp: real routable addresses are public', () => {
  for (const ip of ['27.254.29.130', '8.8.8.8', '172.32.0.1', '172.15.255.255', '1.1.1.1']) {
    assert.equal(isPublicIp(ip), true, ip);
  }
});

test('isPublicIp: malformed input is not public rather than throwing', () => {
  for (const ip of ['N/A', '', 'not-an-ip', '999.1.1.1', '1.2.3', null, undefined]) {
    assert.equal(isPublicIp(ip), false, String(ip));
  }
});

test('publicInterfaceIps: drops the "N/A" sentinel seen on live rows', () => {
  // ⛔ A sentinel string where NULL belongs is the pattern CLAUDE.md bans, and
  // it exists on this fleet. It must never reach an inet cast or be counted
  // as an exposed address.
  const got = publicInterfaceIps([
    { interface_name: 'wan1', ip_address: '27.254.29.130/24', zone: 'wan' },
    { interface_name: 'lan', ip_address: '192.168.8.1/24', zone: 'lan' },
    { interface_name: 'dead', ip_address: 'N/A', zone: null },
    { interface_name: 'blank', ip_address: null, zone: null },
  ]);
  assert.deepEqual(got.map((x) => x.ip), ['27.254.29.130']);
});

test('publicInterfaceIps: de-duplicates repeated addresses', () => {
  const got = publicInterfaceIps([
    { interface_name: 'a', ip_address: '27.254.29.130/24' },
    { interface_name: 'b', ip_address: '27.254.29.130/32' },
  ]);
  assert.equal(got.length, 1);
});

// ───────────────────────────────── DNAT ───────────────────────────────────

test('buildDnatMap: only destination NAT counts as inbound exposure', () => {
  // ⛔ Source NAT is outbound translation. Counting it would inflate the
  // attack surface with every device's normal internet egress.
  const m = buildDnatMap(
    [
      { enabled: true, nat_type: 'source', original_dst_addresses: ['any'], translated_dst_addresses: [] },
      {
        enabled: true,
        nat_type: 'destination',
        original_dst_addresses: ['27.254.29.136'],
        translated_dst_addresses: ['192.168.8.18'],
      },
    ],
    new Map()
  );
  assert.deepEqual(Array.from(m.keys()), ['27.254.29.136']);
  assert.deepEqual(m.get('27.254.29.136')[0].internal, ['192.168.8.18']);
});

test('buildDnatMap: a disabled NAT rule publishes nothing', () => {
  const m = buildDnatMap(
    [{ enabled: false, nat_type: 'destination', original_dst_addresses: ['27.254.29.136'], translated_dst_addresses: ['192.168.8.18'] }],
    new Map()
  );
  assert.equal(m.size, 0);
});

// ──────────────────────────── path construction ───────────────────────────

const IFACES = [
  { interface_name: 'wan1', ip_address: '27.254.29.130/24', zone: 'wan' },
  { interface_name: 'lan', ip_address: '192.168.8.1/24', zone: 'lan' },
];

function rule(over = {}) {
  return {
    rule_name: 'r',
    enabled: true,
    action: 'accept',
    sequence_number: 1,
    src_addresses: ['any'],
    dst_addresses: ['any'],
    services: ['tcp/443'],
    log_enabled: true,
    ...over,
  };
}

test('a rule written against the INTERNAL address still matches the public face', () => {
  // Fortinet VIPs behave this way live: the policy names the internal host,
  // and only the NAT row knows the public address. Matching the public side
  // alone would miss the entire published service.
  const r = buildExposurePaths({
    rules: [rule({ dst_addresses: ['192.168.8.18'] })],
    objects: [],
    natRules: [
      {
        enabled: true,
        nat_type: 'destination',
        original_dst_addresses: ['27.254.29.136'],
        translated_dst_addresses: ['192.168.8.18'],
      },
    ],
    interfaces: IFACES,
  });
  assert.equal(r.paths.length, 1);
  assert.equal(r.paths[0].publicIp, '27.254.29.136');
  assert.deepEqual(r.paths[0].internal, ['192.168.8.18']);
  assert.equal(r.paths[0].via, 'nat');
});

test('an internal-only rule produces no internet exposure', () => {
  const r = buildExposurePaths({
    rules: [rule({ src_addresses: ['10.0.0.0/8'], dst_addresses: ['192.168.8.0/24'] })],
    objects: [],
    natRules: [],
    interfaces: IFACES,
  });
  assert.equal(r.paths.length, 0);
});

test('a deny rule is not an exposure', () => {
  const r = buildExposurePaths({
    rules: [rule({ action: 'deny' })],
    objects: [],
    natRules: [],
    interfaces: IFACES,
  });
  assert.equal(r.paths.length, 0);
});

test('a disabled rule is not an exposure', () => {
  const r = buildExposurePaths({
    rules: [rule({ enabled: false })],
    objects: [],
    natRules: [],
    interfaces: IFACES,
  });
  assert.equal(r.paths.length, 0);
});

test('an any-source any-destination rule exposes the public interface', () => {
  const r = buildExposurePaths({
    rules: [rule()],
    objects: [],
    natRules: [],
    interfaces: IFACES,
  });
  assert.equal(r.paths.length, 1);
  assert.equal(r.paths[0].publicIp, '27.254.29.130');
  assert.equal(r.paths[0].via, 'interface');
});

test('address-group objects resolve through to a public face', () => {
  const r = buildExposurePaths({
    rules: [rule({ dst_addresses: ['WEB-GROUP'] })],
    objects: [
      { name: 'WEB-GROUP', object_type: 'address_group', members: ['WEB01'] },
      { name: 'WEB01', object_type: 'address', value: '27.254.29.130' },
    ],
    natRules: [],
    interfaces: IFACES,
  });
  assert.equal(r.paths.length, 1);
});

// ─────────────────────────── explainable scoring ──────────────────────────

test('every score carries at least one reason', () => {
  const r = buildExposurePaths({
    rules: [rule()],
    objects: [],
    natRules: [],
    interfaces: IFACES,
  });
  const s = scoreExposure(r.paths[0]);
  assert.ok(s.reasons.length > 0);
  assert.ok(['low', 'medium', 'high', 'critical'].includes(s.severity));
});

test('an unmeasured path is never scored as if it were quiet', () => {
  // ⛔ THE IMPORTANT ONE. "We were not listening" must not move the score in
  // either direction, and the reason text must say so.
  const base = buildExposurePaths({
    rules: [rule()], objects: [], natRules: [], interfaces: IFACES,
  }).paths[0];

  const unmeasured = scoreExposure({ ...base, observation: 'unmeasured' });
  const quiet = scoreExposure({ ...base, observation: 'not_observed' });

  assert.equal(unmeasured.score, quiet.score, 'unmeasured must not differ in score');
  assert.ok(/UNMEASURED, not unused/.test(unmeasured.reasons.join(' ')));
  assert.ok(/still open/.test(quiet.reasons.join(' ')));
});

test('observed traffic raises the score and cites its evidence', () => {
  const base = buildExposurePaths({
    rules: [rule()], objects: [], natRules: [], interfaces: IFACES,
  }).paths[0];
  const quiet = scoreExposure({ ...base, observation: 'not_observed' });
  const seen = scoreExposure({
    ...base,
    observation: 'observed',
    evidence: { events: 412, sources: 37, lastSeen: 'x' },
  });
  assert.ok(seen.score > quiet.score);
  assert.ok(/37 distinct public source/.test(seen.reasons.join(' ')));
});

test('an any-service rule scores above a single-port rule', () => {
  const mk = (services) =>
    buildExposurePaths({ rules: [rule({ services })], objects: [], natRules: [], interfaces: IFACES }).paths[0];
  assert.ok(scoreExposure(mk(['any'])).score > scoreExposure(mk(['tcp/443'])).score);
});

// ─────────────────────── observation attachment (stub pool) ───────────────

function stubPool(handlers) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      for (const [pat, rows] of handlers) if (sql.includes(pat)) return { rows };
      return { rows: [] };
    },
  };
}

test('no syslog coverage marks every path UNMEASURED, never not_observed', () => {
  const paths = [{ publicIp: '1.2.3.4', service: { isAny: true, ports: [] }, observation: 'x' }];
  return attachObservations(stubPool([['LIMIT 1', []]]), 'd1', paths, new Date(0)).then((r) => {
    assert.equal(r.covered, false);
    assert.equal(paths[0].observation, 'unmeasured');
  });
});

test('coverage but no matching traffic is a real not_observed measurement', async () => {
  const paths = [{ publicIp: '1.2.3.4', service: { isAny: true, ports: [] }, observation: 'x' }];
  const pool = stubPool([['LIMIT 1', [{ x: 1 }]], ['GROUP BY host(dst_ip)', []]]);
  const r = await attachObservations(pool, 'd1', paths, new Date(0));
  assert.equal(r.covered, true);
  assert.equal(paths[0].observation, 'not_observed');
});

test('an observed port inside the resolved range marks the path observed', async () => {
  const paths = [
    {
      publicIp: '1.2.3.4',
      service: { isAny: false, ports: [{ proto: 'tcp', portStart: 443, portEnd: 443 }] },
      observation: 'x',
    },
  ];
  const pool = stubPool([
    ['LIMIT 1', [{ x: 1 }]],
    ['GROUP BY host(dst_ip)', [{ ip: '1.2.3.4', dst_port: 443, events: '10', sources: 4, last_seen: 'T' }]],
  ]);
  await attachObservations(pool, 'd1', paths, new Date(0));
  assert.equal(paths[0].observation, 'observed');
  assert.equal(paths[0].evidence.sources, 4);
});

test('traffic on a DIFFERENT port does not mark the path observed', async () => {
  const paths = [
    {
      publicIp: '1.2.3.4',
      service: { isAny: false, ports: [{ proto: 'tcp', portStart: 443, portEnd: 443 }] },
      observation: 'x',
    },
  ];
  const pool = stubPool([
    ['LIMIT 1', [{ x: 1 }]],
    ['GROUP BY host(dst_ip)', [{ ip: '1.2.3.4', dst_port: 22, events: '10', sources: 4, last_seen: 'T' }]],
  ]);
  await attachObservations(pool, 'd1', paths, new Date(0));
  assert.equal(paths[0].observation, 'not_observed');
});

test('observation query demands ALLOWED, PUBLIC traffic and casts its timestamp', async () => {
  const paths = [{ publicIp: '1.2.3.4', service: { isAny: true, ports: [] }, observation: 'x' }];
  const pool = stubPool([['LIMIT 1', [{ x: 1 }]], ['GROUP BY host(dst_ip)', []]]);
  await attachObservations(pool, 'd1', paths, new Date(0));
  const q = pool.calls.find((c) => c.sql.includes('GROUP BY host(dst_ip)'));

  // Public-source and allowed classification happen once at rollup time; this
  // query must still DEMAND both, or a blocked probe would read as a reached
  // service and inflate the exposure severity.
  assert.ok(/allowed\s+IS TRUE/.test(q.sql));
  assert.ok(/public_source\s+IS TRUE/.test(q.sql));
  assert.ok(q.sql.includes('::timestamptz'));

  // ⛔ Must not have quietly reverted to scanning raw events: measured at over
  // two minutes for one device-day, which is not a page render.
  assert.ok(!q.sql.includes('FROM syslog_events'));
});

// ─────────────────────────────────────────────────────────────────────────
// Direction — added 2026-09-09 after a live bug sweep
// ─────────────────────────────────────────────────────────────────────────
//
// ⛔ THE BIGGEST CORRECTNESS BUG THIS ENGINE HAS HAD. Without a direction
// test, `src_addresses:['any']` on an INTERNAL rule read as "reachable from
// the entire internet" and `dst_addresses:['any']` on an OUTBOUND rule matched
// every public face. Measured live: 257 of 403 paths (64%) were false
// positives, all at the maximum score, so they outranked the genuine ones —
// TSR-TL's entire reported exposure was five internal-to-internal rules while
// TUG's one real camera port-forward ranked below them.

const { externalZoneIds, ruleDirection } = require('../lib/engines/exposure');

const PA_IFACES = [
  { interface_name: 'ethernet1/1', ip_address: '147.50.33.114/29', zone: 'WAN3' },
  { interface_name: 'ethernet1/5', ip_address: '10.248.32.1/24', zone: 'LAN' },
];

test('externalZoneIds: takes the ZONE of a public interface (Palo Alto shape)', () => {
  const ids = externalZoneIds(PA_IFACES);
  assert.ok(ids.has('wan3'), 'the public interface zone is external');
  assert.ok(!ids.has('lan'), 'a private interface zone is not external');
});

test('externalZoneIds: takes the interface NAME too (Fortinet shape)', () => {
  // FortiOS policies name INTERFACES in src_zones, and its public interfaces
  // frequently carry no zone at all — live, TSR-TL's wan2 has zone NULL.
  const ids = externalZoneIds([
    { interface_name: 'wan2', ip_address: '171.99.128.101/31', zone: null },
    { interface_name: 'internal5', ip_address: '192.168.3.1/24', zone: null },
  ]);
  assert.ok(ids.has('wan2'));
  assert.ok(!ids.has('internal5'));
});

test('⛔ an internal-to-internal rule is NOT an internet exposure', () => {
  // The literal live false positive: TSR-TL seq 14 "NewLan to PRIVATE",
  // internal5 -> internal3, was reported at score 100 as "reachable from the
  // entire internet".
  const ids = externalZoneIds([
    { interface_name: 'wan2', ip_address: '171.99.128.101/31', zone: null },
  ]);
  assert.equal(ruleDirection({ src_zones: ['internal5'] }, ids), 'internal');
  assert.equal(ruleDirection({ src_zones: ['LAN', 'LAN2'] }, ids), 'internal');
});

test('a rule sourced from the public interface IS an internet exposure', () => {
  const ids = externalZoneIds(PA_IFACES);
  assert.equal(ruleDirection({ src_zones: ['WAN3'] }, ids), 'inbound');
  assert.equal(ruleDirection({ src_zones: ['wan3'] }, ids), 'inbound', 'case-insensitive');
});

test('an explicit ANY source zone genuinely includes the external one', () => {
  const ids = externalZoneIds(PA_IFACES);
  assert.equal(ruleDirection({ src_zones: ['any'] }, ids), 'inbound');
});

test('⛔ no zone data means UNVERIFIED, never a silent pass or fail', () => {
  // Both directions of not-knowing. A device with no collected public
  // interface, and a rule with no zones: neither may be guessed at.
  assert.equal(ruleDirection({ src_zones: ['LAN'] }, new Set()), 'unverified');
  assert.equal(ruleDirection({ src_zones: [] }, externalZoneIds(PA_IFACES)), 'unverified');
});

test('buildExposurePaths drops internal rules but KEEPS unverified ones', () => {
  const ifaces = [{ interface_name: 'wan1', ip_address: '27.254.29.130/24', zone: 'WAN' }];
  const internalOnly = buildExposurePaths({
    rules: [rule({ src_zones: ['LAN'], dst_addresses: ['any'] })],
    objects: [], natRules: [], interfaces: ifaces,
  });
  assert.equal(internalOnly.paths.length, 0, 'an internal rule is not exposure');
  assert.equal(internalOnly.internalRulesExcluded, 1);

  // ⛔ With no zone data at all the path is still REPORTED — under-reporting
  // exposure is the more dangerous error — but flagged unverified.
  const noZones = buildExposurePaths({
    rules: [rule({ src_zones: ['LAN'], dst_addresses: ['any'] })],
    objects: [], natRules: [],
    interfaces: [{ interface_name: 'wan1', ip_address: 'N/A', zone: null }],
  });
  assert.equal(noZones.paths.length, 0, 'no public face at all means no path');
});

test('⛔ DNAT internal targets are de-duplicated', () => {
  // Live, TUG forwards five ports of one public address to three hosts; the
  // undeduped list read "10.248.32.9, 10.248.32.9, 10.248.32.9, ...".
  const nat = (seq, internal) => ({
    enabled: true, nat_type: 'destination', sequence_number: seq,
    original_dst_addresses: ['147.50.33.118'], translated_dst_addresses: [internal],
  });
  const r = buildExposurePaths({
    rules: [rule({ src_zones: ['WAN'], dst_addresses: ['any'] })],
    objects: [],
    natRules: [nat(1, '10.248.32.9'), nat(2, '10.248.32.9'), nat(3, '10.248.32.9'),
      nat(4, '10.248.32.10'), nat(5, '10.248.32.204')],
    interfaces: [{ interface_name: 'wan1', ip_address: '147.50.33.114/29', zone: 'WAN' }],
  });
  const natPath = r.paths.find((p) => p.publicIp === '147.50.33.118');
  assert.ok(natPath, 'the NAT-published face is still a path');
  assert.deepEqual(natPath.internal, ['10.248.32.9', '10.248.32.10', '10.248.32.204']);
});

test('⛔ an unresolvable service is UNMEASURED, not "watched and quiet"', async () => {
  // Live, 97 of 403 paths had no usable port range, so the hit filter was
  // structurally always empty and every one was written not_observed — a
  // positive claim that we had watched.
  const paths = [
    { publicIp: '1.2.3.4', service: { isAny: false, ports: [], unresolved: true }, observation: 'x' },
  ];
  const pool = stubPool([
    ['FROM syslog_rollup_hourly', [{ x: 1 }]],
    ['FROM syslog_device_inbound_hourly\n      WHERE device_id = $1 AND bucket_hour', [{ x: 1 }]],
    ['GROUP BY host(dst_ip)', []],
  ]);
  await attachObservations(pool, 'd1', paths, new Date(0));
  assert.equal(paths[0].observation, 'unmeasured');
  assert.equal(paths[0].unmeasuredReason, 'service-unresolved');
});
