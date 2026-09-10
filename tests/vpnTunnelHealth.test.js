'use strict';
// Pins lib/engines/vpnTunnelHealth.js — fleet-wide site-to-site IPsec tunnel
// health, derived at READ time from the latest `vpn_ipsec_tunnels` snapshot.
//
// WHY THIS FILE EXISTS. Tunnel health is one of the easiest surfaces in this
// product to get wrong in the exact way CLAUDE.md calls the dominant bug: every
// failure mode here produces GOOD NEWS. A vendor that cannot report tunnels
// contributes zero down tunnels. A device whose collection has been failing for
// a month still holds a row saying "up". An unrecognised vendor verb, mapped
// onto `down`, invents an outage; mapped onto `up`, hides one. None of those
// throws, and every one of them renders as a confident number.
//
// So every test below is built around the "we could not measure this" case, per
// tests/README.md — the pass and fail cases are the easy half.
//
// ⛔ NO DATABASE. assembleTunnelHealth() is the pure half of the engine: it
// takes the three result sets getVpnTunnelHealth() fetches and an explicit
// `now`, and every judgement lives there. These tests drive it with fixtures
// and never construct a pool at all.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  assembleTunnelHealth,
  classifyTunnelStatus,
  classifyFreshness,
  classifyPeer,
  classifyCoverage,
  normalizePeer,
  tunnelSupport,
  VENDOR_TUNNEL_SUPPORT,
  DEFAULT_STALE_AFTER_MINUTES,
} = require('../lib/engines/vpnTunnelHealth');

const NOW = new Date('2026-09-10T15:00:00.000Z');
const MIN = 60 * 1000;

function minutesAgo(n) {
  return new Date(NOW.getTime() - n * MIN).toISOString();
}

// One LEFT JOIN row. `tunnel_id` null = the device has no tunnel rows at all,
// which is the shape the engine's own query produces and the case most of these
// tests are about.
function joinRow(device, tunnel) {
  return {
    id: device.id,
    name: device.name,
    vendor: device.vendor,
    mgmt_method: device.mgmt_method,
    site: device.site || null,
    asset_criticality: device.asset_criticality || 'normal',
    tunnel_id: tunnel ? tunnel.id : null,
    tunnel_name: tunnel ? tunnel.name : null,
    tunnel_peer: tunnel ? tunnel.peer : null,
    tunnel_status: tunnel ? tunnel.status : null,
    tunnel_ike_version: tunnel ? tunnel.ike_version || null : null,
    tunnel_bytes_in: tunnel && tunnel.bytes_in !== undefined ? tunnel.bytes_in : null,
    tunnel_bytes_out: tunnel && tunnel.bytes_out !== undefined ? tunnel.bytes_out : null,
    tunnel_collected_at: tunnel ? tunnel.collected_at : null,
  };
}

function assemble({ deviceRows = [], ifaceRows = [], pollRows = [], staleAfterMinutes = DEFAULT_STALE_AFTER_MINUTES }) {
  return assembleTunnelHealth({
    deviceRows,
    ifaceRows,
    pollRows,
    now: NOW,
    staleAfterMinutes,
    lookbackDays: 7,
  });
}

const FORTI = { id: 'dev-forti', name: 'Branch-FW', vendor: 'fortinet', mgmt_method: 'ssh' };
const PA = { id: 'dev-pa', name: 'DC-FW', vendor: 'paloalto', mgmt_method: 'api' };
const SANGFOR = { id: 'dev-sangfor', name: 'Edge-FW', vendor: 'sangfor', mgmt_method: 'ssh' };

// --------------------------------------------------------------------------
describe('status classification is tri-state and never guesses', () => {
  it('recognises only up and down, the two values SecVault’s own adapters write', () => {
    assert.equal(classifyTunnelStatus('up'), 'up');
    assert.equal(classifyTunnelStatus('UP'), 'up');
    assert.equal(classifyTunnelStatus(' down '), 'down');
  });

  it('an unrecognised vendor verb is unknown, NOT down', () => {
    // The real incident this guards: a vendor word being mapped onto a definite
    // state. Palo Alto's normalizer passes a state it does not recognise
    // through VERBATIM, so arbitrary strings genuinely reach this column.
    for (const verb of ['init', 'rekeying', 'negotiating', 'expiring', 'active', 'mature']) {
      assert.equal(
        classifyTunnelStatus(verb),
        'unknown',
        `"${verb}" must be unknown — mapping it to down invents an outage, to up hides one`
      );
    }
  });

  it('a missing or empty status is unknown, not down', () => {
    assert.equal(classifyTunnelStatus(null), 'unknown');
    assert.equal(classifyTunnelStatus(undefined), 'unknown');
    assert.equal(classifyTunnelStatus(''), 'unknown');
    assert.equal(classifyTunnelStatus('   '), 'unknown');
  });

  it('surfaces every unrecognised value verbatim so the enumeration can be widened on evidence', () => {
    const out = assemble({
      deviceRows: [
        joinRow(FORTI, { id: 't1', name: 'a', peer: '198.51.100.1', status: 'rekeying', collected_at: minutesAgo(5) }),
        joinRow(FORTI, { id: 't2', name: 'b', peer: '198.51.100.2', status: 'REKEYING', collected_at: minutesAgo(5) }),
      ],
    });
    assert.equal(out.unrecognisedStatuses.length, 1);
    assert.equal(out.unrecognisedStatuses[0].count, 2);
    assert.equal(out.unrecognisedStatuses[0].value, 'rekeying');
    assert.equal(out.fleet.tunnels.unknownStatus, 2);
    assert.equal(out.fleet.tunnels.down, 0);
    assert.equal(out.fleet.tunnels.up, 0);
  });

  it('a null status is unknown but is NOT reported as an unrecognised value', () => {
    // Nothing to add to an enumeration — the device said nothing at all.
    const out = assemble({
      deviceRows: [joinRow(FORTI, { id: 't1', name: 'a', peer: '198.51.100.1', status: null, collected_at: minutesAgo(5) })],
    });
    assert.equal(out.fleet.tunnels.unknownStatus, 1);
    assert.deepEqual(out.unrecognisedStatuses, []);
  });
});

// --------------------------------------------------------------------------
describe('staleness is a fact about SecVault, not about the tunnel', () => {
  it('a stale snapshot’s "up" becomes unmeasured, and keeps the last known state as evidence', () => {
    // The live case this is modelled on: TSR_EKC holds one tunnel row stamped
    // 2026-08-07 while its VPN poll fails every cycle. Rendering that as "1 up"
    // is a present-tense claim about a 34-day-old reading.
    const out = assemble({
      deviceRows: [
        joinRow(FORTI, {
          id: 't1',
          name: 'TSR-to-DC1',
          peer: '198.51.100.1',
          status: 'up',
          collected_at: minutesAgo(34 * 24 * 60),
        }),
      ],
    });
    const tunnel = out.devices[0].tunnels[0];
    assert.equal(tunnel.health, 'unmeasured');
    assert.equal(tunnel.lastKnownStatus, 'up', 'the device’s last answer is preserved as evidence');
    assert.equal(out.fleet.tunnels.up, 0, 'an expired "up" must not be counted as up');
    assert.equal(out.fleet.tunnels.unmeasured, 1);
    assert.equal(out.devices[0].snapshotFreshness, 'stale');
  });

  it('a stale snapshot’s "down" is ALSO unmeasured — the rule cuts both ways', () => {
    const out = assemble({
      deviceRows: [
        joinRow(FORTI, { id: 't1', name: 'x', peer: '198.51.100.1', status: 'down', collected_at: minutesAgo(600) }),
      ],
    });
    assert.equal(out.fleet.tunnels.down, 0);
    assert.equal(out.fleet.tunnels.unmeasured, 1);
    assert.equal(out.down.length, 0, 'a stale down is not an actionable outage, it is an unknown');
  });

  it('a device with no rows has freshness "none", not "fresh"', () => {
    // "Fresh" about data that does not exist is the failed-read-as-a-fact bug
    // wearing a timestamp.
    const out = assemble({ deviceRows: [joinRow(FORTI, null)] });
    assert.equal(out.devices[0].snapshotFreshness, 'none');
    assert.equal(out.devices[0].collectedAt, null);
  });

  it('an unparseable collection time is unknown age, not zero age', () => {
    assert.deepEqual(classifyFreshness(null, NOW), { freshness: 'unknown', ageMinutes: null });
    assert.deepEqual(classifyFreshness('not-a-date', NOW), { freshness: 'unknown', ageMinutes: null });
  });

  it('a future-stamped snapshot is clamped to zero age rather than reading as very fresh', () => {
    const { freshness, ageMinutes } = classifyFreshness(new Date(NOW.getTime() + 10 * MIN), NOW);
    assert.equal(freshness, 'fresh');
    assert.equal(ageMinutes, 0);
  });

  it('the boundary is inclusive of the window — exactly at the threshold is still fresh', () => {
    assert.equal(classifyFreshness(minutesAgo(120), NOW, 120).freshness, 'fresh');
    assert.equal(classifyFreshness(minutesAgo(121), NOW, 120).freshness, 'stale');
  });
});

// --------------------------------------------------------------------------
describe('"no tunnel rows" is never "no tunnels"', () => {
  it('a vendor with no tunnel collection is `unsupported`, not a healthy zero', () => {
    const out = assemble({ deviceRows: [joinRow(SANGFOR, null)] });
    assert.equal(out.devices[0].coverage, 'unsupported');
    assert.equal(out.devices[0].supportsTunnelCollection, false);
    assert.equal(out.fleet.devices.unsupported, 1);
    assert.equal(out.fleet.devices.claimable, 0, 'a device we cannot ask contributes no answer');
  });

  it('a capable vendor with zero rows and a recent successful poll is the STRONGER reading, and still not proof', () => {
    const out = assemble({
      deviceRows: [joinRow(FORTI, null)],
      pollRows: [{ device_id: FORTI.id, last_ok_at: minutesAgo(3), last_attempt_at: minutesAgo(3) }],
    });
    assert.equal(out.devices[0].coverage, 'no_rows_polled');
    assert.match(
      out.devices[0].coverageReason,
      /would look identical/,
      'the reason must state that a failed tunnel command on a reachable device is indistinguishable here'
    );
  });

  it('a capable vendor with zero rows and NO successful poll is unconfirmed — nothing may be claimed', () => {
    const out = assemble({
      deviceRows: [joinRow(FORTI, null)],
      // Attempted, never succeeded. This is the live shape of TSR_EKC.
      pollRows: [{ device_id: FORTI.id, last_ok_at: null, last_attempt_at: minutesAgo(3) }],
    });
    assert.equal(out.devices[0].coverage, 'no_rows_unconfirmed');
    assert.equal(out.fleet.devices.noRowsUnconfirmed, 1);
    assert.equal(out.fleet.devices.claimable, 0);
  });

  it('an unrecognised vendor is support_unknown — never assumed unsupported', () => {
    // `false` here would be a claim about a product we do not recognise.
    assert.equal(tunnelSupport('some_new_vendor', 'api'), null);
    const out = assemble({
      deviceRows: [joinRow({ id: 'd', name: 'New', vendor: 'some_new_vendor', mgmt_method: 'api' }, null)],
    });
    assert.equal(out.devices[0].coverage, 'support_unknown');
    assert.equal(out.fleet.devices.supportUnknown, 1);
  });

  it('a known vendor asked about an unknown transport answers false only when NO transport supports it', () => {
    // sangfor has one transport and it cannot report tunnels, so any transport
    // is a safe definite `false`.
    assert.equal(tunnelSupport('sangfor', 'api'), false);
    // fortinet's transports can, so which adapter would be dispatched matters
    // and is not knowable here → unknown, never a confident yes or no.
    assert.equal(tunnelSupport('fortinet', 'telnet'), null);
    assert.equal(tunnelSupport('fortinet', null), null);
  });

  it('classifyCoverage accepts either the DB row or the assembled shape', () => {
    // A caller handing over the object it happens to have must not silently get
    // a different answer.
    const poll = { lastOkAt: minutesAgo(1) };
    assert.equal(classifyCoverage({ vendor: 'sangfor', mgmt_method: 'ssh' }, 0, poll), 'unsupported');
    assert.equal(classifyCoverage({ vendor: 'sangfor', mgmtMethod: 'ssh' }, 0, poll), 'unsupported');
  });

  it('every active device appears, including the ones nothing can be collected from', () => {
    // Rule 5: a fleet view that silently omits the vendors SecVault cannot ask
    // reads as "all tunnels healthy".
    const out = assemble({
      deviceRows: [
        joinRow(SANGFOR, null),
        joinRow(PA, { id: 't1', name: 'a', peer: '198.51.100.9', status: 'up', collected_at: minutesAgo(2) }),
      ],
    });
    assert.equal(out.devices.length, 2);
    assert.equal(out.fleet.devices.total, 2);
    assert.equal(out.fleet.devices.claimable, 1, 'the denominator excludes the device that cannot be asked');
  });
});

// --------------------------------------------------------------------------
describe('"down since" is not derivable and is never implied', () => {
  it('every tunnel carries an explicitly null downSince with a stated reason', () => {
    const out = assemble({
      deviceRows: [
        joinRow(FORTI, { id: 't1', name: 'x', peer: '198.51.100.1', status: 'down', collected_at: minutesAgo(4) }),
      ],
    });
    const tunnel = out.down[0];
    assert.equal(tunnel.downSince, null);
    assert.match(tunnel.downSinceReason, /latest snapshot/i);
    // ⛔ collectedAt is when WE LOOKED, not when the tunnel dropped. It must
    // never be quietly reused as a failure time.
    assert.notEqual(tunnel.downSince, tunnel.collectedAt);
  });

  it('the notes say what a duration would actually require', () => {
    const out = assemble({ deviceRows: [] });
    assert.match(out.notes.downSince, /state-change/i);
    assert.match(out.notes.downSince, /syslog/i);
  });
});

// --------------------------------------------------------------------------
describe('peer resolution states what it could not match, rather than calling it external', () => {
  const IFACES = [
    { device_id: PA.id, ip_address: '198.51.100.9/29', device_name: PA.name },
    { device_id: PA.id, ip_address: '203.0.113.7/24', device_name: PA.name },
  ];

  it('strips the transport port Palo Alto appends to a peer', () => {
    // Live: `180.183.195.2:4500`. FortiOS strips it itself; PAN-OS does not.
    assert.equal(normalizePeer('180.183.195.2:4500'), '180.183.195.2');
    assert.equal(normalizePeer('198.51.100.9'), '198.51.100.9');
    assert.equal(normalizePeer('[2001:db8::1]:4500'), '2001:db8::1');
    assert.equal(normalizePeer('2001:db8::1'), '2001:db8::1', 'a bare IPv6 literal is left alone');
    assert.equal(normalizePeer(''), null);
    assert.equal(normalizePeer(null), null);
  });

  it('matches a peer to another managed firewall by its collected interface address', () => {
    const owners = new Map([['198.51.100.9', [PA.id]]]);
    const r = classifyPeer('198.51.100.9:4500', FORTI.id, owners);
    assert.equal(r.peerKind, 'managed_device');
    assert.deepEqual(r.peerDeviceIds, [PA.id]);
  });

  it('0.0.0.0 is a dial-up peer, not an unmatched one', () => {
    // A real recurring FortiOS value (`ipsec-client`). Calling it "unmatched"
    // would imply we looked for a far end that could have existed.
    const r = classifyPeer('0.0.0.0', FORTI.id, new Map());
    assert.equal(r.peerKind, 'dialup');
    assert.deepEqual(r.peerDeviceIds, []);
  });

  it('a peer that is the reporting device’s OWN interface is flagged, not counted as a fleet link', () => {
    const owners = new Map([['198.51.100.9', [FORTI.id]]]);
    assert.equal(classifyPeer('198.51.100.9', FORTI.id, owners).peerKind, 'self');
  });

  it('an absent or unparseable peer is unreadable, never "external"', () => {
    assert.equal(classifyPeer(null, FORTI.id, new Map()).peerKind, 'unreadable');
    assert.equal(classifyPeer('vpn.example.com', FORTI.id, new Map()).peerKind, 'unreadable');
  });

  it('reports how much of the fleet peer matching could even run against', () => {
    // ⛔ The load-bearing caveat: "not matched" depends entirely on
    // device_interfaces coverage, which is itself partial. Live, one firewall
    // has zero interface rows, so every tunnel pointing at it is unmatchable
    // however well known it is.
    const out = assemble({
      deviceRows: [
        joinRow(FORTI, { id: 't1', name: 'a', peer: '198.51.100.9', status: 'up', collected_at: minutesAgo(2) }),
        joinRow(FORTI, { id: 't2', name: 'b', peer: '192.0.2.55', status: 'up', collected_at: minutesAgo(2) }),
        joinRow(PA, null),
      ],
      ifaceRows: IFACES,
    });
    assert.equal(out.fleet.peering.managedDevice, 1);
    assert.equal(out.fleet.peering.unmatched, 1);
    assert.equal(out.fleet.peering.devicesWithInterfaceData, 1);
    assert.equal(out.fleet.peering.devicesTotal, 2);
    assert.match(out.notes.peering, /not that the far end is outside the fleet/i);
  });

  it('ignores a disabled interface the same way the topology map does', () => {
    // The engine's SQL filters `i.enabled = true`, so a disabled interface never
    // reaches the matcher. Pinned here as behaviour of the assembled result.
    const out = assemble({
      deviceRows: [
        joinRow(FORTI, { id: 't1', name: 'a', peer: '198.51.100.9', status: 'up', collected_at: minutesAgo(2) }),
      ],
      ifaceRows: [],
    });
    assert.equal(out.fleet.peering.unmatched, 1);
    assert.equal(out.fleet.peering.managedDevice, 0);
  });
});

// --------------------------------------------------------------------------
describe('fleet counts never borrow a number from a device that could not be measured', () => {
  it('counts up/down only over fresh snapshots, and totals every collected row', () => {
    const out = assemble({
      deviceRows: [
        joinRow(PA, { id: 't1', name: 'live-up', peer: '192.0.2.1', status: 'up', collected_at: minutesAgo(2) }),
        joinRow(PA, { id: 't2', name: 'live-down', peer: '192.0.2.2', status: 'down', collected_at: minutesAgo(2) }),
        joinRow(FORTI, { id: 't3', name: 'old-up', peer: '192.0.2.3', status: 'up', collected_at: minutesAgo(5000) }),
        joinRow(SANGFOR, null),
      ],
    });
    assert.deepEqual(out.fleet.tunnels, { total: 3, up: 1, down: 1, unknownStatus: 0, unmeasured: 1 });
    assert.equal(out.fleet.devices.total, 3);
    assert.equal(out.fleet.devices.claimable, 1);
    assert.equal(out.fleet.devices.reportingStale, 1);
    assert.equal(out.fleet.devices.unsupported, 1);
  });

  it('the down list is only what is currently reported down', () => {
    const out = assemble({
      deviceRows: [
        joinRow(PA, { id: 't1', name: 'now-down', peer: '192.0.2.2', status: 'down', collected_at: minutesAgo(2) }),
        joinRow(FORTI, { id: 't2', name: 'was-down', peer: '192.0.2.3', status: 'down', collected_at: minutesAgo(5000) }),
      ],
    });
    assert.equal(out.down.length, 1);
    assert.equal(out.down[0].name, 'now-down');
  });

  it('a byte counter the vendor never reported stays null, never 0', () => {
    // 0 says "no traffic crossed this tunnel", which Palo Alto never claimed.
    const out = assemble({
      deviceRows: [
        joinRow(PA, { id: 't1', name: 'a', peer: '192.0.2.1', status: 'up', collected_at: minutesAgo(2) }),
      ],
    });
    assert.equal(out.devices[0].tunnels[0].bytesIn, null);
    assert.equal(out.devices[0].tunnels[0].bytesOut, null);
  });

  it('a genuinely reported zero byte counter survives as 0', () => {
    const out = assemble({
      deviceRows: [
        joinRow(FORTI, {
          id: 't1', name: 'a', peer: '192.0.2.1', status: 'up', bytes_in: 0, bytes_out: 0, collected_at: minutesAgo(2),
        }),
      ],
    });
    assert.equal(out.devices[0].tunnels[0].bytesIn, 0);
  });

  it('handles empty and malformed inputs without throwing', () => {
    const empty = assemble({ deviceRows: [] });
    assert.equal(empty.fleet.devices.total, 0);
    assert.equal(empty.fleet.tunnels.total, 0);
    assert.equal(empty.fleet.devices.claimable, 0);
    assert.doesNotThrow(() =>
      assembleTunnelHealth({ deviceRows: null, ifaceRows: null, pollRows: null, now: NOW, staleAfterMinutes: 120, lookbackDays: 7 })
    );
  });
});

// --------------------------------------------------------------------------
describe('the vendor support map matches the adapters it claims to describe', () => {
  // ⛔ A LINT-SHAPED TEST, in the spirit of tests/moduleLoad.test.js. The map
  // is duplicated from the adapter layer on purpose (an ES-module/CommonJS
  // split makes importing lib/adapters/index.js from an engine the wrong
  // trade), and a duplicated registry that drifts is a silent runtime bug —
  // exactly what CLAUDE.md warns about for DEFAULT_METHOD. This reads the
  // adapter SOURCES rather than requiring them, so it needs no ssh2, no native
  // module and no database.
  const ADAPTER_FILE = {
    'forcepoint.smc': 'forcepoint/index.js',
    'fortinet.api': 'fortinet/index.js',
    'fortinet.ssh': 'fortinet/ssh.js',
    'paloalto.api': 'paloalto/index.js',
    'paloalto.ssh': 'paloalto/ssh.js',
    'checkpoint.api': 'checkpoint/index.js',
    'cisco_asa.ssh': 'cisco_asa/index.js',
    'sangfor.ssh': 'sangfor/index.js',
  };

  const DEFINES_METHOD = /^\s*async\s+getVpnTunnels\s*\(/m;

  it('declares exactly the vendor/method pairs the adapter registry does', () => {
    const declared = [];
    for (const [vendor, byMethod] of Object.entries(VENDOR_TUNNEL_SUPPORT)) {
      for (const method of Object.keys(byMethod)) declared.push(`${vendor}.${method}`);
    }
    assert.deepEqual(declared.sort(), Object.keys(ADAPTER_FILE).sort());
  });

  it('each declared value matches whether that adapter actually implements getVpnTunnels()', () => {
    for (const [key, file] of Object.entries(ADAPTER_FILE)) {
      const [vendor, method] = key.split('.');
      const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'adapters', file), 'utf8');
      const implemented = DEFINES_METHOD.test(src);
      assert.equal(
        VENDOR_TUNNEL_SUPPORT[vendor][method],
        implemented,
        `VENDOR_TUNNEL_SUPPORT.${key} says ${VENDOR_TUNNEL_SUPPORT[vendor][method]} but `
          + `lib/adapters/${file} ${implemented ? 'does' : 'does not'} implement getVpnTunnels()`
      );
    }
  });
});
