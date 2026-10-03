'use strict';

// tests/ciscoAsaParser.test.js
//
// Pins lib/syslog/vendorParsers.js's Cisco ASA support against the CAPTURED
// lines in tests/fixtures/ciscoAsaSyslog.js. Read that file's header first: it
// records where the evidence came from, its licence, and — more importantly —
// what it does NOT establish.
//
// ⛔ THIS PARSER HAS NEVER SEEN A LIVE ASA. SecVault's fleet carries none, so
// the fixtures are a third party's regression captures. That is far better than
// documentation and strictly worse than a device. These tests prove the parser
// agrees with the captures; they do NOT prove a customer's firewall emits them.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { parseSyslogLine } = require('../lib/syslog/syslogParser');
const vendorParsers = require('../lib/syslog/vendorParsers');
const { buildEvent } = require('../lib/syslog/eventShape');
const { ALLOWED_ACTIONS, DENIED_ACTIONS } = require('../lib/syslog/actions');
const { ASA_FIXTURES, asaLine, asaWireLine } = require('./fixtures/ciscoAsaSyslog');

const NOW = new Date('2026-10-03T12:00:00Z');

describe('Cisco ASA: every captured fixture parses to the expected fields', () => {
  for (const f of ASA_FIXTURES) {
    it(`${f.id} — ${f.why}`, () => {
      const frame = parseSyslogLine(asaWireLine(f), NOW);
      assert.equal(vendorParsers.detectVendor(frame.message), 'cisco_asa');
      const p = vendorParsers.parseCiscoAsa(frame.message);
      assert.ok(p, 'parser returned null for a line it detected');
      assert.equal(p.vendor, 'cisco_asa');
      assert.equal(p.logSubtype, f.msgId);
      for (const [k, want] of Object.entries(f.expect)) {
        assert.deepEqual(p[k], want, `${k}: got ${JSON.stringify(p[k])}, expected ${JSON.stringify(want)}`);
      }
    });
  }
});

describe('⛔ Cisco ASA: detection is structural and never a fallback', () => {
  it('detects with or without the syslog header', () => {
    // A device may or may not be configured to emit an RFC 3164 header, so the
    // banner is matched wherever it appears rather than anchored at the start.
    const f = ASA_FIXTURES[0];
    assert.equal(vendorParsers.detectVendor(asaWireLine(f)), 'cisco_asa');
    assert.equal(vendorParsers.detectVendor(asaLine(f)), 'cisco_asa');
  });

  it('⛔ does NOT claim a Fortinet or Palo Alto line', () => {
    // The three detectors run in one chain; a loose ASA pattern would steal
    // traffic from the two vendors that ARE live-verified, which would be a
    // regression in the only syslog support this product has proven.
    const fgt = 'date=2026-10-03 time=12:00:00 devname="FG" devid="FGT60F0000000001" '
      + 'type="traffic" srcip=10.1.0.5 policyid=3 action="accept"';
    const pan = '1,2026/10/03 12:00:00,001801000000,TRAFFIC,end,2561,2026/10/03 12:00:00,'
      + '10.20.5.1,10.20.9.1,0.0.0.0,0.0.0.0,rule-x,,,ssl,vsys1,a,b,e1/1,e1/2,LOG,'
      + '2026/10/03 12:00:00,1,1,443,443,0,0,0x0,tcp,allow,0,0,0,0';
    assert.equal(vendorParsers.detectVendor(fgt), 'fortinet');
    assert.equal(vendorParsers.detectVendor(pan), 'paloalto');
  });

  it('⛔ an unrelated syslog line is still NULL, not ASA', () => {
    // "Deliberately no fallback" — an unmatched line must stay unattributed.
    for (const junk of [
      'Oct  3 12:00:00 host sshd[1]: Accepted password for root from 10.0.0.1',
      'kernel: [12345.678] something happened',
      '',
      'percent ASA is not a banner',
    ]) {
      assert.equal(vendorParsers.detectVendor(junk), null, `wrongly claimed: ${junk}`);
    }
  });
});

describe('⛔ Cisco ASA: an unverified message ID yields the ENVELOPE, never invented fields', () => {
  it('a message ID with no verified layout parses to nulls, not guesses', () => {
    // The ASA emits hundreds of IDs. Parsing one whose layout has never been
    // observed would fabricate fields that look exactly like measurements.
    const line = '%ASA-4-733100: [ Scanning] drop rate-1 exceeded. '
      + 'Current burst rate is 0 per second, max configured rate is 10';
    assert.equal(vendorParsers.detectVendor(line), 'cisco_asa');
    const p = vendorParsers.parseCiscoAsa(line);
    assert.equal(p.vendor, 'cisco_asa', 'the envelope is still returned');
    assert.equal(p.logSubtype, '733100', 'and it still records WHICH id arrived');
    for (const k of ['action', 'srcIp', 'dstIp', 'srcPort', 'dstPort', 'ruleName', 'protocol']) {
      assert.equal(p[k], null, `${k} must be null for an unverified message id`);
    }
  });

  it('\u26d4 the gate HOLDS even when the body WOULD have matched', () => {
    // The decisive case, and the first version of this test missed it. A body
    // that matches no regex parses to nulls whether or not the gate exists, so
    // asserting on one proves nothing about the gate -- a guard that cannot
    // fire. 302035 is a real ASA message id that is NOT in ASA_PARSED_IDS, and
    // its body is deliberately shaped exactly like the 302013 we DO parse.
    // Without the gate every field below would be populated from an id whose
    // layout has never been observed.
    const line = '%ASA-6-302035: Built inbound TCP connection 123 for '
      + 'outside:1.2.3.4/80 (1.2.3.4/80) to inside:5.6.7.8/99 (5.6.7.8/99)';
    assert.equal(vendorParsers.detectVendor(line), 'cisco_asa');
    const p = vendorParsers.parseCiscoAsa(line);
    assert.equal(p.logSubtype, '302035');
    assert.equal(p.action, null, 'an unverified id must not get an action');
    assert.equal(p.srcIp, null, 'an unverified id must not get a src address');
    assert.equal(p.dstIp, null);
    assert.equal(p.srcPort, null);

    // And the control: the SAME body under a VERIFIED id does populate, which
    // is what shows the nulls above come from the gate and not from a regex
    // that simply failed to match.
    const verified = line.replace('302035', '302013');
    const q = vendorParsers.parseCiscoAsa(verified);
    assert.equal(q.srcIp, '1.2.3.4', 'the control must parse, or this test proves nothing');
    assert.equal(q.action, 'start');
  });

  it('a line that is not ASA at all returns null outright', () => {
    assert.equal(vendorParsers.parseCiscoAsa('not an asa line'), null);
    assert.equal(vendorParsers.parseCiscoAsa(null), null);
  });
});

describe('⛔ Cisco ASA: actions come from the SHARED vocabulary', () => {
  it('every action emitted is one the rest of the product already understands', () => {
    // A private action string here would be invisible to the retention policy,
    // the rollups and log_hit — CLAUDE.md records the codebase having ended up
    // with four disagreeing copies of this set before it was shared.
    const seen = new Set();
    for (const f of ASA_FIXTURES) {
      const p = vendorParsers.parseCiscoAsa(asaLine(f));
      if (p && p.action) seen.add(p.action);
    }
    assert.ok(seen.size > 0, 'no actions were produced, so nothing was checked');
    for (const a of seen) {
      assert.ok(ALLOWED_ACTIONS.has(a) || DENIED_ACTIONS.has(a),
        `"${a}" is in neither ALLOWED_ACTIONS nor DENIED_ACTIONS`);
    }
  });

  it('⛔ Teardown is a CLOSE, never a deny', () => {
    // A session ending is not a block. Reading it as one would invert the
    // meaning of the row and manufacture denials out of normal traffic — the
    // same trap FortiOS `close` and PAN-OS `reset-both` sit either side of.
    const td = ASA_FIXTURES.find((f) => f.id.includes('teardown'));
    const p = vendorParsers.parseCiscoAsa(asaLine(td));
    assert.equal(p.action, 'close');
    assert.ok(ALLOWED_ACTIONS.has(p.action), 'close must be in the allowed set');
    assert.ok(!DENIED_ACTIONS.has(p.action), 'a teardown must never count as denied');
  });

  it('⛔ "denied" on an access-list IS a deny', () => {
    const line = '%ASA-4-106100: access-list acl-out denied tcp outside/1.2.3.4(1) -> '
      + 'inside/5.6.7.8(80) hit-cnt 1 first hit [0x0, 0x0]';
    const p = vendorParsers.parseCiscoAsa(line);
    assert.equal(p.action, 'deny');
    assert.ok(DENIED_ACTIONS.has(p.action));
    assert.equal(p.ruleName, 'acl-out');
  });
});

describe('⛔ Cisco ASA: the rule linkage, and its honest absence', () => {
  it('access-group and access-list names reach ruleName', () => {
    // This is the ASA's analogue of FortiOS policyid: without it no log line
    // can be tied back to a stored rule, and rule-hit correlation finds nothing.
    const withRule = ASA_FIXTURES.filter((f) => f.expect.ruleName);
    assert.ok(withRule.length >= 2, 'the fixtures must cover both name-carrying forms');
    for (const f of withRule) {
      assert.equal(vendorParsers.parseCiscoAsa(asaLine(f)).ruleName, f.expect.ruleName);
    }
  });

  it('⛔ a deny that names no access-list leaves ruleName NULL', () => {
    // A deny we cannot attribute is still a real deny. Attributing it to a
    // guessed rule would be worse than leaving it unattributed — a fabricated
    // rule hit is indistinguishable from a measured one once stored.
    const noRule = ASA_FIXTURES.filter((f) => Object.hasOwn(f.expect, 'ruleName') && f.expect.ruleName === null);
    assert.ok(noRule.length >= 1, 'nothing exercises the unattributable deny');
    for (const f of noRule) {
      const p = vendorParsers.parseCiscoAsa(asaLine(f));
      assert.equal(p.ruleName, null);
      assert.equal(p.action, 'deny', 'it is still recorded as a deny');
    }
  });
});

describe('⛔ Cisco ASA: no timestamp is invented', () => {
  it('eventAt stays null — the ASA line carries no year and no timezone', () => {
    // The same call parseFortinet makes when `tz` is absent. received_at is
    // what anchors the row; guessing a year would silently misfile it.
    for (const f of ASA_FIXTURES) {
      assert.equal(vendorParsers.parseCiscoAsa(asaLine(f)).eventAt, null);
    }
  });

  it('the event shape still gets a usable time from received_at', () => {
    const f = ASA_FIXTURES[0];
    const raw = { line: asaWireLine(f), sourceIp: '10.99.0.51', receivedAt: NOW };
    const frame = parseSyslogLine(raw.line, NOW);
    const ev = buildEvent(raw, frame, vendorParsers.parseVendorPayload(frame.message), 'dev-1', 'security');
    assert.equal(ev.vendor, 'cisco_asa');
    assert.equal(ev.deviceId, 'dev-1');
    assert.equal(ev.receivedAt, NOW);
  });
});

describe('⛔ Cisco ASA: log class comes from the message ID, not a keyword search', () => {
  it('traffic, vpn and unknown are distinguished', () => {
    assert.equal(vendorParsers.classifyCiscoAsa('302013'), 'traffic');
    assert.equal(vendorParsers.classifyCiscoAsa('106023'), 'traffic');
    assert.equal(vendorParsers.classifyCiscoAsa('713172'), 'vpn');
    assert.equal(vendorParsers.classifyCiscoAsa('402117'), 'vpn');
  });

  it('⛔ an unrecognised prefix is NULL — there is no "other" bucket', () => {
    // An unclassified event should look like the gap in this mapping that it is.
    assert.equal(vendorParsers.classifyCiscoAsa('999999'), null);
    assert.equal(vendorParsers.classifyCiscoAsa(''), null);
    assert.equal(vendorParsers.classifyCiscoAsa(null), null);
  });
});
