'use strict';

// tests/cefParser.test.js
//
// Pins lib/syslog/cef.js (the grammar) and vendorParsers' CEF-backed support
// for Forcepoint NGFW and Check Point Log Exporter.
//
// ⛔ THE FIXTURES ARE RECONSTRUCTIONS, NOT CAPTURES. Read the header of
// tests/fixtures/cefSyslog.js: no Apache-licensed Forcepoint or Check Point
// captures were found, so those lines are our own reconstruction of a structure
// corroborated across independent sources. That is a WEAKER class of evidence
// than tests/fixtures/ciscoAsaSyslog.js, and a disagreement with a real device
// is resolved in the device's favour.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const cef = require('../lib/syslog/cef');
const vendorParsers = require('../lib/syslog/vendorParsers');
const { parseSyslogLine } = require('../lib/syslog/syslogParser');
const { CEF_FIXTURES, cefWireLine } = require('./fixtures/cefSyslog');

const NOW = new Date('2026-10-04T12:00:00Z');

describe('CEF grammar: the three things a naive parser gets wrong', () => {
  it('⛔ an extension value may CONTAIN SPACES', () => {
    // Forcepoint really sends `deviceExternalId=NGFW2 node 1 dvchost=...`.
    // Splitting the extension on whitespace yields "NGFW2" plus two tokens of
    // garbage, and the garbage looks like data.
    const c = cef.parseCef('CEF:0|V|P|1|1|n|0|deviceExternalId=NGFW2 node 1 dvchost=10.0.0.1 spt=53');
    assert.equal(c.extension.deviceExternalId, 'NGFW2 node 1');
    assert.equal(c.extension.dvchost, '10.0.0.1');
    assert.equal(c.extension.spt, '53');
  });

  it('⛔ `=` is ESCAPED inside a value', () => {
    // Check Point sends `originsicname=CN\=gate2,O\=...`. Splitting on a bare
    // `=` cuts the value in half and invents a key called `O\`.
    const c = cef.parseCef('CEF:0|V|P|1|1|n|0|originsicname=CN\\=gate2,O\\=example..abc src=10.0.0.1');
    assert.equal(c.extension.originsicname, 'CN=gate2,O=example..abc');
    assert.equal(c.extension.src, '10.0.0.1');
    assert.ok(!('O\\' in c.extension), 'an escaped = must not create a key');
  });

  it('⛔ `|` is ESCAPED inside a header field', () => {
    // The header is POSITIONAL, so an unescaped split shifts every later field
    // left by one — the severity then reads as a signature name, which looks
    // like data rather than failing.
    const c = cef.parseCef('CEF:0|Acme\\|Corp|Fire\\|wall|1.0|100|Some\\|Name|5|src=10.0.0.1');
    assert.equal(c.deviceVendor, 'Acme|Corp');
    assert.equal(c.deviceProduct, 'Fire|wall');
    assert.equal(c.name, 'Some|Name');
    assert.equal(c.severity, '5');
    assert.equal(c.extension.src, '10.0.0.1');
  });

  it('⛔ an escaped BACKSLASH before a delimiter is not an escape of it', () => {
    // `\\|` is a literal backslash THEN a real delimiter. A lookbehind for
    // "not preceded by a backslash" gets this backwards and swallows the pipe.
    const c = cef.parseCef('CEF:0|V|ends-with-backslash\\\\|1|1|n|0|src=10.0.0.1');
    assert.equal(c.deviceProduct, 'ends-with-backslash\\');
    assert.equal(c.deviceVersion, '1');
    assert.equal(c.extension.src, '10.0.0.1');
  });

  it('a record with too few header fields is REFUSED, never padded', () => {
    // Padding would silently relabel every field after the gap.
    assert.equal(cef.parseCef('CEF:0|V|P|1|1'), null);
    assert.equal(cef.parseCef('not cef at all'), null);
    assert.equal(cef.parseCef(null), null);
  });

  it('an explicitly empty value is NULL, not an empty string', () => {
    // The same call parseKeyValue makes: absent information, not a measurement.
    const c = cef.parseCef('CEF:0|V|P|1|1|n|0|src= dst=10.0.0.2');
    assert.equal(c.extension.src, null);
    assert.equal(c.extension.dst, '10.0.0.2');
  });
});

describe('⛔ CEF custom slots resolve BY LABEL, never by position', () => {
  it('the same code finds the rule in cs1 for one vendor and cs2 for another', () => {
    // This is what lets ONE parser serve several vendors. Forcepoint:
    // cs1Label=RuleID. Check Point: cs2Label=Rule Name. Reading cs1
    // unconditionally takes Check Point's NAT rule id for a rule name — a
    // wrong value that looks entirely plausible.
    const fp = cef.parseCef('CEF:0|FORCEPOINT|Firewall|6.8|1|n|0|cs1Label=RuleID cs1=2100123.2 cs2Label=NatRuleId cs2=2099555.1');
    const cp = cef.parseCef('CEF:0|Check Point|VPN-1|x|Log|n|Unknown|cs1Label=NAT rule cs1=99 cs2Label=Rule Name cs2=Allow-DNS-Out');
    const pat = /^\s*rule\s*_?\s*(name|id)\s*$/i;
    assert.equal(cef.bySlotLabel(fp.extension, pat), '2100123.2');
    assert.equal(cef.bySlotLabel(cp.extension, pat), 'Allow-DNS-Out');
  });

  it('a slot with no matching label yields null, not a guess', () => {
    const c = cef.parseCef('CEF:0|V|P|1|1|n|0|cs1Label=Something Else cs1=xyz');
    assert.equal(cef.bySlotLabel(c.extension, /rule/i), null);
  });

  it('a label whose slot is empty is not returned', () => {
    const c = cef.parseCef('CEF:0|V|P|1|1|n|0|cs1Label=RuleID cs1=');
    assert.equal(cef.bySlotLabel(c.extension, /rule/i), null);
  });
});

describe('CEF vendors: every fixture maps to the expected event', () => {
  for (const f of CEF_FIXTURES) {
    it(`${f.id} — ${f.why}`, () => {
      const frame = parseSyslogLine(cefWireLine(f), NOW);
      assert.equal(vendorParsers.detectVendor(frame.message), f.vendor);
      const p = vendorParsers.parseVendorPayload(frame.message);
      assert.ok(p, 'dispatch returned nothing for a line it claimed');
      for (const [k, want] of Object.entries(f.expect)) {
        assert.deepEqual(p[k], want, `${k}: got ${JSON.stringify(p[k])}`);
      }
    });
  }
});

describe('⛔ CEF detection claims only vendors SecVault supports', () => {
  it('an unknown CEF vendor is NOT claimed', () => {
    // SecVault supports six vendors. A CEF line from a seventh is stored
    // unattributed — the same answer any other unrecognised line gets — rather
    // than inventing a vendor the rest of the product cannot act on.
    const line = 'CEF:0|SomeOtherVendor|Appliance|1.0|1|Event|5|src=10.0.0.1 dst=10.0.0.2';
    assert.equal(vendorParsers.detectVendor(line), null);
    assert.equal(vendorParsers.parseCefEvent(line), null);
  });

  it('vendor matching is case- and spacing-tolerant, because the samples disagree', () => {
    // Forcepoint sends FORCEPOINT upper-case; Check Point sends "Check Point"
    // with a space. Both are the same product to us.
    for (const [v, want] of [['FORCEPOINT', 'forcepoint'], ['Forcepoint', 'forcepoint'],
      ['Check Point', 'checkpoint'], ['CheckPoint', 'checkpoint']]) {
      assert.equal(vendorParsers.cefVendorSlug(`CEF:0|${v}|P|1|1|n|0|src=10.0.0.1`), want, v);
    }
  });

  it('⛔ a CEF line does not steal traffic from the live-verified vendors', () => {
    // Fortinet and Palo Alto are the only two verified against real devices;
    // a loose CEF check that claimed their lines would be a regression in the
    // only syslog support this product has actually proven.
    const fgt = 'date=2026-10-04 time=12:00:00 devname="FG" devid="FGT60F0000000001" '
      + 'type="traffic" srcip=10.1.0.5 policyid=3 action="accept"';
    assert.equal(vendorParsers.detectVendor(fgt), 'fortinet');
  });
});

describe('⛔ CEF: protocol and time are normalised honestly', () => {
  it('Forcepoint sends a protocol NUMBER, Check Point a name — both normalise', () => {
    assert.equal(vendorParsers.normaliseProto('6'), 'tcp');
    assert.equal(vendorParsers.normaliseProto('17'), 'udp');
    assert.equal(vendorParsers.normaliseProto('tcp'), 'tcp');
    assert.equal(vendorParsers.normaliseProto('TCP'), 'tcp');
  });

  it('⛔ an unrecognised protocol passes through verbatim, it is not dropped', () => {
    // An unknown protocol is a fact about the traffic, not a gap in it.
    assert.equal(vendorParsers.normaliseProto('132'), '132');
    assert.equal(vendorParsers.normaliseProto(''), null);
    assert.equal(vendorParsers.normaliseProto(null), null);
  });

  it('⛔ `rt` is used ONLY when it is plainly a millisecond epoch', () => {
    // A wrong scale backdates the row to 1970 — present in the table and
    // outside every time window, which is worse than no timestamp. The same
    // lesson the Fortinet eventtime digit-length rule encodes.
    const ms = vendorParsers.parseCefEvent('CEF:0|FORCEPOINT|F|1|1|n|0|rt=1528095651000 src=10.0.0.1');
    assert.ok(ms.eventAt instanceof Date);
    assert.ok(ms.eventAt.getUTCFullYear() >= 2018);

    for (const bad of ['1528095651', '15280956510000000', 'not-a-time', '']) {
      const p = vendorParsers.parseCefEvent(`CEF:0|FORCEPOINT|F|1|1|n|0|rt=${bad} src=10.0.0.1`);
      assert.equal(p.eventAt, null, `rt=${bad} must not produce a timestamp`);
    }
  });
});
