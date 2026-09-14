'use strict';
// Pins buildTunnelAnswer (lib/answers.js) — the one sentence that replaced the
// eight caveat paragraphs at the top of /vpn?vtab=tunnels.
//
// ⛔ THE POINT OF THE REWRITE WAS NOT BREVITY. The old panel was accurate and
// unreadable; the risk in making it readable is that a caveat gets shortened
// into a claim. These tests exist to make the split enforceable rather than
// advisory:
//
//   A caveat that CHANGES HOW YOU READ THE NUMBER must survive in the sentence
//   or the coverage line. A caveat that EXPLAINS THE MECHANISM may move into
//   the disclosure.
//
// So the test that matters most here is the one asserting that "no tunnel is
// down" NEVER comes back with tone `ok` while any firewall is unreadable —
// because a green all-clear computed over 12 of 16 firewalls, 139 of whose
// tunnels structurally cannot show a failure, is the single most dangerous
// sentence this screen could print.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { buildTunnelAnswer } = require('../lib/answers');

// A fleet where everything is readable and healthy.
const clean = (over) => ({
  fleet: {
    devices: {
      total: 4,
      claimable: 4,
      reportingFresh: 4,
      reportingStale: 0,
      reportingUnknownAge: 0,
      noRowsPolled: 0,
      noRowsUnconfirmed: 0,
      unsupported: 0,
      supportUnknown: 0,
    },
    tunnels: {
      total: 20,
      up: 20,
      down: 0,
      unknownStatus: 0,
      unmeasured: 0,
      downObservability: { blindDevices: 0, blindTunnels: 0, blindVendors: [] },
    },
    ...(over && over.fleetExtra),
  },
  ...over,
});

function withDevices(patch, tunnelPatch) {
  const base = clean();
  Object.assign(base.fleet.devices, patch || {});
  Object.assign(base.fleet.tunnels, tunnelPatch || {});
  return base;
}

describe('the headline', () => {
  it('leads with the down count when anything is down', () => {
    const a = buildTunnelAnswer(withDevices({}, { down: 3, up: 17 }));
    assert.equal(a.tone, 'critical');
    assert.match(a.lead, /3 tunnels are down/);
    assert.match(a.sentence, /4 of 4 firewalls with a current snapshot/);
  });

  it('uses singular wording for one tunnel', () => {
    const a = buildTunnelAnswer(withDevices({}, { down: 1 }));
    assert.match(a.lead, /1 tunnel is down/);
  });

  it('allows the all-clear only when the whole fleet was readable', () => {
    const a = buildTunnelAnswer(clean());
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
    assert.match(a.lead, /Every tunnel is up/);
  });
});

describe('⛔ a gap never becomes good news', () => {
  it('⛔ REFUSES tone `ok` while any firewall cannot report a down tunnel', () => {
    // The live case: 2 down, 139 tunnels on 11 Palo Altos that answer with
    // established SAs only. Even at zero down, this is not an all-clear.
    const a = buildTunnelAnswer(
      withDevices({}, {
        down: 0,
        downObservability: { blindDevices: 11, blindTunnels: 139, blindVendors: ['paloalto'] },
      })
    );
    assert.notEqual(a.tone, 'ok');
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /not a fleet all-clear/);
  });

  it('⛔ the down-blind COUNT is in the coverage line, not only in the disclosure', () => {
    // This is the caveat that changes how the "Tunnels down" tile reads. If it
    // is ever moved behind the disclosure, this test fails — which is the
    // whole reason it is written as an assertion rather than a comment.
    const a = buildTunnelAnswer(
      withDevices({}, {
        down: 0,
        downObservability: { blindDevices: 11, blindTunnels: 139, blindVendors: ['paloalto'] },
      })
    );
    assert.match(a.coverage, /139 tunnels on 11 firewalls cannot report a down tunnel at all/);
  });

  it('⛔ nothing measured is not "no tunnels are down"', () => {
    const a = buildTunnelAnswer(withDevices({ claimable: 0, reportingFresh: 0, unsupported: 4 }));
    assert.equal(a.tone, 'unknown');
    assert.match(a.lead, /No firewall has a current tunnel snapshot/);
    assert.match(a.sentence, /nothing can be said/);
  });

  it('a stale snapshot is a coverage gap, not a measurement', () => {
    const a = buildTunnelAnswer(withDevices({ claimable: 3, reportingFresh: 3, reportingStale: 1 }));
    assert.match(a.coverage, /1 firewall has only a stale snapshot/);
    assert.equal(a.tone, 'unknown');
  });

  it('lists several gaps as a readable list rather than a pile-up', () => {
    const a = buildTunnelAnswer(
      withDevices({
        total: 16, claimable: 10, reportingFresh: 10,
        reportingStale: 1, unsupported: 3, noRowsUnconfirmed: 2,
      })
    );
    assert.match(a.coverage, /, and /);
    assert.ok(a.coverage.endsWith('.'), 'coverage line should be a sentence');
  });

  it('a down count still wins the headline even with gaps present', () => {
    // Gaps qualify the number; they must not bury a real outage.
    const a = buildTunnelAnswer(
      withDevices({ claimable: 10, reportingFresh: 10, unsupported: 6 }, { down: 2 })
    );
    assert.equal(a.tone, 'critical');
    assert.match(a.lead, /2 tunnels are down/);
    assert.match(a.coverage, /6 cannot be asked at all/);
  });
});

describe('never throws on a missing or malformed result', () => {
  it('survives anything the engine could hand it', () => {
    for (const bad of [null, undefined, {}, { fleet: {} }, { fleet: { devices: {}, tunnels: {} } }]) {
      const a = buildTunnelAnswer(bad);
      assert.equal(typeof a.sentence, 'string');
      assert.equal(a.tone, 'unknown');
    }
  });
});
