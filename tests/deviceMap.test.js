'use strict';

// tests/deviceMap.test.js
//
// Pins lib/syslog/deviceMap.js — which source address attributes to which
// device. Extracted from services/collector.js because that file starts
// listeners on require and cannot be imported, the same reason eventShape.js
// was pulled out of it.
//
// ⛔ BOTH BEHAVIOURS HERE WERE FOUND BY RUNNING A SIX-VENDOR MOCK FLEET, not by
// reading the code. On a fleet of Fortinet and Palo Alto only, neither can
// occur: both vendors always have a mgmt_ip, and neither shares an address.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { buildDeviceMap } = require('../lib/syslog/deviceMap');

describe('⛔ a Forcepoint device has NO mgmt_ip, and must still be attributable', () => {
  it('smc_host resolves to the device', () => {
    // Measured before smc_host was consulted: 637 Forcepoint events, every one
    // stored with device_id NULL, because the map read mgmt_ip and snmp_host
    // only and a Forcepoint device legitimately has neither.
    const { map } = buildDeviceMap(
      [{ id: 'fp-1', mgmt_ip: null, snmp_host: null, smc_host: '10.99.0.71' }], []
    );
    assert.equal(map.get('10.99.0.71'), 'fp-1');
  });

  it('all three address columns are consulted', () => {
    const { map } = buildDeviceMap(
      [{ id: 'd1', mgmt_ip: '10.0.0.1', snmp_host: '10.0.0.2', smc_host: '10.0.0.3' }], []
    );
    for (const ip of ['10.0.0.1', '10.0.0.2', '10.0.0.3']) {
      assert.equal(map.get(ip), 'd1', ip);
    }
  });

  it('an empty or whitespace-only column is not an address', () => {
    const { map } = buildDeviceMap(
      [{ id: 'd1', mgmt_ip: '', snmp_host: '   ', smc_host: null }], []
    );
    assert.equal(map.size, 0);
  });
});

describe('⛔ an address claimed by more than one device attributes to NEITHER', () => {
  it('a shared SMC does not file every engine under one of them', () => {
    // ONE SMC MANAGES MANY ENGINES, so smc_host is routinely shared. A
    // last-writer-wins map would file all three devices' events under whichever
    // row came back last -- a fabricated attribution, indistinguishable from a
    // real one once stored, and worse than leaving the event unattributed.
    const { map, ambiguous } = buildDeviceMap([
      { id: 'fp-1', mgmt_ip: null, smc_host: '10.99.0.71' },
      { id: 'fp-2', mgmt_ip: null, smc_host: '10.99.0.71' },
      { id: 'fp-3', mgmt_ip: null, smc_host: '10.99.0.71' },
    ], []);
    assert.equal(map.has('10.99.0.71'), false,
      'a contested address must be ABSENT from the map, so events stay unattributed');
    assert.equal(ambiguous.length, 1);
    assert.deepEqual(ambiguous[0], { ip: '10.99.0.71', deviceIds: ['fp-1', 'fp-2', 'fp-3'] });
  });

  it('⛔ the ambiguity is REPORTED, never silently dropped', () => {
    // An operator needs to know WHY a device's events are unattributed.
    const { ambiguous } = buildDeviceMap([
      { id: 'a', snmp_host: '10.0.0.9' },
      { id: 'b', snmp_host: '10.0.0.9' },
    ], []);
    assert.equal(ambiguous.length, 1);
    assert.deepEqual(ambiguous[0].deviceIds, ['a', 'b']);
  });

  it('a collision does not poison that device\'s OTHER addresses', () => {
    // Only the contested address is withheld; each device is still reachable
    // by an address it alone claims.
    const { map } = buildDeviceMap([
      { id: 'a', mgmt_ip: '10.0.0.1', smc_host: '10.0.0.9' },
      { id: 'b', mgmt_ip: '10.0.0.2', smc_host: '10.0.0.9' },
    ], []);
    assert.equal(map.get('10.0.0.1'), 'a');
    assert.equal(map.get('10.0.0.2'), 'b');
    assert.equal(map.has('10.0.0.9'), false);
  });

  it('the same device claiming an address twice is NOT a collision', () => {
    // mgmt_ip === snmp_host is an ordinary configuration, not an ambiguity.
    const { map, ambiguous } = buildDeviceMap(
      [{ id: 'd1', mgmt_ip: '10.0.0.1', snmp_host: '10.0.0.1', smc_host: '10.0.0.1' }], []
    );
    assert.equal(map.get('10.0.0.1'), 'd1');
    assert.deepEqual(ambiguous, []);
  });
});

describe('⛔ an explicit alias outranks anything inferred', () => {
  it('a device_syslog_sources row RESOLVES an ambiguous address', () => {
    // It is an operator's deliberate statement about who sends from an address,
    // and it is the documented fix for a collision -- which is why the
    // ambiguity is reported rather than merely discarded.
    const { map, ambiguous } = buildDeviceMap([
      { id: 'fp-1', smc_host: '10.99.0.71' },
      { id: 'fp-2', smc_host: '10.99.0.71' },
    ], [{ id: 'fp-2', ip: '10.99.0.71' }]);
    assert.equal(map.get('10.99.0.71'), 'fp-2');
    assert.deepEqual(ambiguous, [], 'an address an alias resolved is no longer ambiguous');
  });

  it('an alias overrides an uncontested inventory address too', () => {
    const { map } = buildDeviceMap(
      [{ id: 'a', mgmt_ip: '10.0.0.1' }], [{ id: 'b', ip: '10.0.0.1' }]
    );
    assert.equal(map.get('10.0.0.1'), 'b');
  });
});

describe('malformed input never throws', () => {
  it('null, undefined and junk rows are tolerated', () => {
    for (const args of [[null, null], [undefined, undefined], [[null, undefined], [null]], ['x', 'y']]) {
      const r = buildDeviceMap(args[0], args[1]);
      assert.ok(r.map instanceof Map);
      assert.ok(Array.isArray(r.ambiguous));
    }
  });
});
