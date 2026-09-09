// tests/deviceDiscoveryReconcile.test.js
//
// A discovered sender that has SINCE been added to the inventory.
//
// The live bug, 2026-09-09: 10.204.6.1 (FG200ETK18912640_OkeanosFOOD) was
// discovered on the 8th, added as the managed device OKF(F2) at 03:52 on the
// 9th, and /devices/discovered still listed it under "These addresses match
// nothing SecVault knows". Two things made it survive:
//
//   1. correlateSender() checked device_ha_status.peer_mgmt_ip and
//      device_syslog_sources.source_ip, but NEVER devices.mgmt_ip — the most
//      obvious match of all.
//   2. devices.mgmt_ip is TEXT and discovered_devices.source_ip is INET, which
//      PostgreSQL renders '10.204.6.1/32'. A naive comparison of the two is
//      '10.204.6.1' vs '10.204.6.1/32' — always false, never an error. A type
//      mismatch that fails SILENTLY is exactly the shape tests/README.md says
//      to pin: the wrong answer is a plausible row, not a crash.
//
// Per tests/README.md the cases that matter most are the ones where SecVault
// CANNOT know something, so the "no address at all" and "device deleted again"
// cases are here alongside the happy path.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeAddress,
  correlateSender,
  getDiscoveredDevices,
} = require('../lib/engines/deviceDiscovery');

// The live fleet, 2026-09-09. mgmt_ip values are TEXT exactly as stored.
const DEVICES = [
  { device_id: 'd-okf', device_name: 'OKF(F2)', mgmt_ip: '10.204.6.1', snmp_host: null, active: true },
  { device_id: 'd-yc', device_name: 'Vietnam-YCC', mgmt_ip: '10.204.4.1', snmp_host: null, active: true },
  { device_id: 'd-itc', device_name: 'ITC-SK', mgmt_ip: '172.48.0.26', snmp_host: null, active: true },
  { device_id: 'd-idc', device_name: 'IDC FW', mgmt_ip: '192.168.3.254', snmp_host: null, active: true },
];

// device_ha_status.peer_mgmt_ip is TEXT. These are the real passive peers.
const HA = [
  { device_id: 'd-itc', device_name: 'ITC-SK', peer_mgmt_ip: '172.48.0.27', peer_serial: '023001020785' },
  { device_id: 'd-idc', device_name: 'IDC FW', peer_mgmt_ip: '192.168.3.251', peer_serial: '016201042291' },
];

describe('correlateSender: a sender that is now a managed device', () => {
  it('⛔ matches devices.mgmt_ip across the INET/TEXT boundary', () => {
    // THE bug. The row comes back from an INET column as '10.204.6.1/32';
    // devices.mgmt_ip is the bare TEXT '10.204.6.1'. Comparing them raw is
    // silently always false, so the page called a managed firewall unmanaged.
    const r = correlateSender(
      { source_ip: '10.204.6.1/32', observed_hostname: 'FG200ETK18912640_OkeanosFOOD' },
      HA,
      [],
      DEVICES
    );
    assert.equal(r.kind, 'managed');
    assert.equal(r.deviceId, 'd-okf');
    assert.equal(r.deviceName, 'OKF(F2)');
    assert.match(r.evidence, /OKF\(F2\)'s management address 10\.204\.6\.1/);
  });

  it('matches with or without the /32 the driver may or may not render', () => {
    for (const form of ['10.204.6.1', '10.204.6.1/32', ' 10.204.6.1 ']) {
      const r = correlateSender({ source_ip: form }, HA, [], DEVICES);
      assert.equal(r.kind, 'managed', `failed for ${JSON.stringify(form)}`);
      assert.equal(r.deviceName, 'OKF(F2)');
    }
  });

  it('⛔ a genuinely unmanaged sender is still reported as unmanaged', () => {
    // StarUnion, 10.248.40.254 — matches no device, no peer, no alias, and is
    // still sending. The whole point of the page. A fix that "resolved" this
    // one too would have hidden a real finding.
    const r = correlateSender({ source_ip: '10.248.40.254/32' }, HA, [], DEVICES);
    assert.equal(r.kind, 'unmanaged');
    assert.equal(r.deviceId, null);
  });

  it('⛔ EXACT ADDRESS ONLY — a mgmt_ip carrying a prefix claims nothing', () => {
    // mgmt_ip is free TEXT, so someone can type a subnet into it. Stripping the
    // mask off the TEXT side would let '10.204.6.0/24' swallow every sender in
    // that range and report each as a managed device — a silent mass
    // false-negative on the unmanaged list.
    const devices = [
      { device_id: 'd-x', device_name: 'Typo FW', mgmt_ip: '10.204.6.0/24', snmp_host: null, active: true },
    ];
    assert.equal(correlateSender({ source_ip: '10.204.6.1/32' }, [], [], devices).kind, 'unmanaged');
    assert.equal(correlateSender({ source_ip: '10.204.6.99/32' }, [], [], devices).kind, 'unmanaged');
  });

  it('⛔ a near-miss address does not match', () => {
    // 10.204.4.1 (Vietnam-YCC) and 10.204.6.1 (OKF) differ in one octet, and
    // both are on this fleet.
    const r = correlateSender({ source_ip: '10.204.5.1/32' }, HA, [], DEVICES);
    assert.equal(r.kind, 'unmanaged');
  });

  it('⛔ absent addresses NEVER match each other', () => {
    // The failed-read case. A sender with no address and a device with no
    // mgmt_ip must not become "managed" because null equals null — that would
    // invent a device match out of two missing facts.
    const devices = [
      { device_id: 'd-null', device_name: 'No address', mgmt_ip: null, snmp_host: null, active: true },
      { device_id: 'd-blank', device_name: 'Blank address', mgmt_ip: '   ', snmp_host: '', active: true },
    ];
    for (const src of [null, undefined, '', '   ']) {
      const r = correlateSender({ source_ip: src }, [], [], devices);
      assert.equal(r.kind, 'unmanaged', `matched on ${JSON.stringify(src)}`);
      assert.equal(r.deviceId, null);
    }
    // and a real sender is not matched by a device with no address either
    assert.equal(correlateSender({ source_ip: '10.204.6.1' }, [], [], devices).kind, 'unmanaged');
  });

  it('also matches snmp_host — the same two columns the collector uses', () => {
    // services/collector.js refreshDeviceMap() maps BOTH mgmt_ip and snmp_host
    // to a device. If discovery recognised fewer addresses than ingestion does,
    // the two would disagree about what "known" means.
    const devices = [
      { device_id: 'd-s', device_name: 'SNMP-only', mgmt_ip: '10.0.0.1', snmp_host: '10.9.9.9', active: true },
    ];
    const r = correlateSender({ source_ip: '10.9.9.9/32' }, [], [], devices);
    assert.equal(r.kind, 'managed');
    assert.match(r.evidence, /SNMP address 10\.9\.9\.9/);
  });

  it('⛔ an INACTIVE device is still managed, and says why the row persists', () => {
    // It is in the inventory, so it is not an unmanaged firewall — but the
    // collector only maps ACTIVE devices, so its logs really are still filed
    // unattributed. Saying only "managed" would leave the operator unable to
    // explain why the sender keeps reappearing.
    const devices = [
      { device_id: 'd-off', device_name: 'Retired FW', mgmt_ip: '10.204.6.1', snmp_host: null, active: false },
    ];
    const r = correlateSender({ source_ip: '10.204.6.1/32' }, [], [], devices);
    assert.equal(r.kind, 'managed');
    assert.match(r.evidence, /inactive/);
    assert.match(r.evidence, /unattributed/);
  });

  it('⛔ READ TIME: deleting the device makes the sender unmanaged again', () => {
    // The self-correcting property that made read-time the choice. There is no
    // FK from discovered_devices to a mgmt_ip match, so a STORED verdict would
    // have had nothing to null it out — the same "invisible forever even though
    // it is unmanaged again" bug the resurrect UPDATE already guards against.
    const row = { source_ip: '10.204.6.1/32' };
    assert.equal(correlateSender(row, HA, [], DEVICES).kind, 'managed');
    assert.equal(correlateSender(row, HA, [], []).kind, 'unmanaged');
  });

  it('an HA peer is still an HA peer, not a managed device', () => {
    // Peers keep their own group: they are NOT in devices.mgmt_ip, and offering
    // "Add to inventory" for one is how an operator duplicates a firewall.
    const r = correlateSender({ source_ip: '172.48.0.27/32' }, HA, [], DEVICES);
    assert.equal(r.kind, 'ha-peer');
    assert.equal(r.deviceName, 'ITC-SK');
  });

  it('a device address outranks a coincidental peer-serial match', () => {
    // If both fire, "this IS the device" is the stronger and less ambiguous
    // statement than "this looks like some device's peer".
    const ha = [
      { device_id: 'd-itc', device_name: 'ITC-SK', peer_mgmt_ip: null, peer_serial: 'SER123' },
    ];
    const r = correlateSender({ source_ip: '10.204.6.1', observed_serial: 'SER123' }, ha, [], DEVICES);
    assert.equal(r.kind, 'managed');
    assert.equal(r.deviceName, 'OKF(F2)');
  });

  it('stays backward compatible when no device list is supplied', () => {
    // correlateSender is called from the page, the API and the tests; a missing
    // 4th argument must degrade to the old behaviour, never throw.
    assert.equal(correlateSender({ source_ip: '10.204.6.1' }, HA, []).kind, 'unmanaged');
    assert.equal(correlateSender({ source_ip: '10.204.6.1' }, HA, [], null).kind, 'unmanaged');
  });
});

describe('normalizeAddress', () => {
  it('strips the mask ONLY where asked, and rejects what is left over', () => {
    assert.equal(normalizeAddress('10.204.6.1/32', { stripMask: true }), '10.204.6.1');
    // TEXT side: a mask is not stripped, so it can never match a host address.
    assert.equal(normalizeAddress('10.204.6.0/24'), null);
    assert.equal(normalizeAddress(null), null);
    assert.equal(normalizeAddress('  '), null);
    // IPv6 hex is case-insensitive; PostgreSQL and a device's own config need
    // not agree on the casing.
    assert.equal(normalizeAddress('2001:DB8::1/128', { stripMask: true }), '2001:db8::1');
  });
});

// --- the whole read path, with a stubbed pool -------------------------------

function stubPool(handlers) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      for (const [pat, rows] of handlers) {
        if (sql.includes(pat)) return { rows, rowCount: rows.length };
      }
      return { rows: [], rowCount: 0 };
    },
  };
}

const LIVE_HANDLERS = [
  [
    'FROM discovered_devices',
    [
      // The reported bug: added to the inventory 52 minutes after the last time
      // it was seen unmatched.
      { id: 'r-okf', source_ip: '10.204.6.1/32', observed_hostname: 'FG200ETK18912640_OkeanosFOOD', status: 'new' },
      // Genuinely unmanaged, still sending.
      { id: 'r-star', source_ip: '10.248.40.254/32', observed_hostname: 'StarUnion', status: 'new' },
      // An HA passive peer the operator already linked.
      { id: 'r-peer', source_ip: '172.48.0.27/32', observed_hostname: 'ITC-FW-BACKUP', status: 'linked' },
    ],
  ],
  ['FROM device_ha_status', HA],
  ['FROM device_syslog_sources', []],
  ['snmp_host, active', DEVICES],
];

describe('getDiscoveredDevices: reconciles against the real inventory', () => {
  it('⛔ reproduces the live fleet: exactly ONE unmanaged sender', () => {
    const pool = stubPool(LIVE_HANDLERS);
    return getDiscoveredDevices(pool).then((rows) => {
      const pending = rows.filter((r) => r.status === 'new');
      const unmanaged = pending.filter((r) => r.correlation.kind === 'unmanaged');
      const managed = pending.filter((r) => r.correlation.kind === 'managed');

      // The page said "Unmanaged firewalls (2)". It is 1: StarUnion.
      assert.equal(unmanaged.length, 1);
      assert.equal(unmanaged[0].observed_hostname, 'StarUnion');

      // ⛔ And the other one is NOT hidden — it is reported as managed, WITH
      // the device it matched. An operator who reviewed that address needs to
      // find out where it went.
      assert.equal(managed.length, 1);
      assert.equal(managed[0].correlation.deviceName, 'OKF(F2)');
      assert.equal(managed[0].correlation.deviceId, 'd-okf');
      assert.ok(managed[0].correlation.evidence.length > 10);
    });
  });

  it('⛔ it is READ-ONLY — no observation and no operator decision is written', () => {
    const pool = stubPool(LIVE_HANDLERS);
    return getDiscoveredDevices(pool).then(() => {
      for (const c of pool.calls) {
        assert.ok(
          !/\b(INSERT|UPDATE|DELETE)\b/i.test(c.sql),
          `getDiscoveredDevices must not write: ${c.sql.slice(0, 60)}`
        );
      }
      // and it really did ask the inventory
      assert.ok(pool.calls.some((c) => c.sql.includes('snmp_host, active')));
    });
  });

  it('⛔ does not CAST mgmt_ip to inet in SQL', () => {
    // devices.mgmt_ip is free TEXT. `d.mgmt_ip::inet = dd.source_ip` would
    // throw for the WHOLE query the first time one row held a hostname or a
    // typo, taking the page down instead of failing to match one sender. The
    // normalisation is in the pure function, where a bad value can only fail to
    // match.
    const pool = stubPool(LIVE_HANDLERS);
    return getDiscoveredDevices(pool).then(() => {
      const q = pool.calls.find((c) => c.sql.includes('snmp_host, active'));
      assert.ok(!/mgmt_ip\s*::\s*inet/i.test(q.sql));
      assert.ok(!/inet\s*\(\s*mgmt_ip/i.test(q.sql));
    });
  });

  it('an operator decision on a now-managed sender is left alone', () => {
    // status 'ignored'/'linked' is the operator's, and reconciliation is only
    // ever a read. The row keeps its decision AND gains the correlation.
    const pool = stubPool([
      [
        'FROM discovered_devices',
        [{ id: 'r-okf', source_ip: '10.204.6.1/32', status: 'ignored', decided_by: 'admin' }],
      ],
      ['FROM device_ha_status', []],
      ['FROM device_syslog_sources', []],
      ['snmp_host, active', DEVICES],
    ]);
    return getDiscoveredDevices(pool).then((rows) => {
      assert.equal(rows[0].status, 'ignored');
      assert.equal(rows[0].decided_by, 'admin');
      assert.equal(rows[0].correlation.kind, 'managed');
    });
  });
});
