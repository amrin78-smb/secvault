'use strict';

// tests/fixtures/cefSyslog.js
//
// CEF fixtures for Forcepoint NGFW and Check Point Log Exporter.
//
// ⛔ READ THIS BEFORE TRUSTING THEM: THESE ARE A WEAKER CLASS OF EVIDENCE THAN
// tests/fixtures/ciscoAsaSyslog.js, AND THE DIFFERENCE IS DELIBERATE.
//
// The ASA fixtures are VERBATIM CAPTURES, vendored from an Apache-2.0 project.
// These are NOT. No Apache-licensed Forcepoint or Check Point captures were
// found (logstash-patterns-core carries only Cisco and SuSE), and the sources
// that do publish samples are either Elastic License 2.0 or ordinary
// documentation. So these lines are OUR OWN RECONSTRUCTIONS of a structure
// observed across several independent sources — not copies of any one of them.
//
// WHAT THAT BUYS AND WHAT IT COSTS. It is legally clean and it still beats
// writing from a single vendor document, because the structure below is
// corroborated by sources that do not share an author. But a reconstruction can
// encode OUR misreading in a way a capture cannot, so a disagreement between
// this file and a real device must be resolved in the DEVICE's favour without
// argument.
//
// ── STRUCTURE OBSERVED AT (all 2026-10-04) ───────────────────────────────
//   Forcepoint NGFW CEF
//     - Sekoia integration docs, which publish raw sample events:
//       https://docs.sekoia.com/integration/categories/network_security/forcepoint_ngfw/
//       gave `cs1Label=RuleID cs1=2100123.2`, `cs2Label=NatRuleId`,
//       signature ids 70018 Connection_Allowed / 70019 Connection_Discarded,
//       and `deviceExternalId=NGFW2 node 1` — a value CONTAINING SPACES.
//     - Forcepoint's own "Log fields forwarded in CEF format by SMC" article,
//       which independently gives the same header and the same cs1=RULE_ID
//       mapping: https://support.forcepoint.com/s/article/Log-fields-that-are-forwarded-in-CEF-format
//   Check Point CEF
//     - A published sample carrying `cs2Label=Rule Name cs2=Implicit Cleanup`
//       and `originsicname=CN\=gate2,O\=...` — an ESCAPED `=` inside a value.
//     - Corroborated against elastic/integrations' checkpoint fixtures for the
//       NATIVE format's field names (layer_name, rule_action, rule_uid,
//       loguid, originsicname). ⛔ Elastic's files are Elastic License 2.0 and
//       nothing was copied from them; they were read for corroboration only.
//
// ⛔ THE CRITICAL FINDING THESE FIXTURES ENCODE: the `cs<N>` slots are
// VENDOR-ASSIGNED. Forcepoint puts its rule id in cs1, Check Point its rule
// NAME in cs2. A parser that reads cs1 unconditionally would take Check Point's
// NAT rule id for a rule name — a wrong value that looks completely plausible.
// That is why lib/syslog/cef.js resolves every slot through its Label.
//
// ⛔ CHECK POINT HAS THREE EXPORT FORMATS, NOT TWO: this CEF one, a
// semicolon-delimited `key:"value";` native form, and a pipe-delimited
// `key=value|` form. Only CEF is handled here. Detection must therefore never
// assume a Check Point device speaks CEF.

const CEF_FIXTURES = [
  {
    id: 'forcepoint-connection-allowed',
    vendor: 'forcepoint',
    why: 'the baseline allow; proto is a NUMBER (6), not the string CEF nominally expects',
    line: 'CEF:0|FORCEPOINT|Firewall|6.8.6|70018|Connection_Allowed|0|'
      + 'deviceExternalId=NGFW1 node 1 dvchost=10.99.0.71 dvc=10.99.0.71 '
      + 'src=10.70.1.20 dst=203.0.113.44 spt=59358 dpt=443 proto=6 act=Allow '
      + 'deviceInboundInterface=1 deviceOutboundInterface=0 '
      + 'cs1Label=RuleID cs1=2100123.2',
    expect: {
      vendor: 'forcepoint', action: 'allow',
      srcIp: '10.70.1.20', dstIp: '203.0.113.44', srcPort: 59358, dstPort: 443,
      protocol: 'tcp', ruleName: '2100123.2', logClass: 'traffic',
    },
  },
  {
    id: 'forcepoint-connection-discarded',
    vendor: 'forcepoint',
    why: 'the deny side, and the space-containing deviceExternalId that breaks naive splitting',
    line: 'CEF:0|FORCEPOINT|Firewall|6.8.5|70019|Connection_Discarded|0|'
      + 'deviceExternalId=NGFW2 node 1 dvchost=10.99.0.71 dvc=10.99.0.71 '
      + 'src=10.70.1.55 dst=203.0.113.9 spt=138 dpt=138 proto=17 act=Discard '
      + 'cs1Label=RuleID cs1=2100999.7 cs2Label=NatRuleId cs2=2099555.1',
    expect: {
      vendor: 'forcepoint', action: 'discard',
      srcIp: '10.70.1.55', dstIp: '203.0.113.9', srcPort: 138, dstPort: 138,
      protocol: 'udp', ruleName: '2100999.7', logClass: 'traffic',
      deviceName: 'NGFW2 node 1',
    },
  },
  {
    id: 'checkpoint-cef-accept',
    vendor: 'checkpoint',
    why: 'rule name lives in cs2 here, NOT cs1 — the reason slots resolve by label',
    line: 'CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|domain-udp|Unknown|'
      + 'act=Accept deviceDirection=0 rt=1528095651000 src=10.80.1.5 dst=10.80.9.1 '
      + 'spt=49005 dpt=53 proto=udp service_id=domain-udp '
      + 'cs2Label=Rule Name cs2=Allow-DNS-Out layer_name=Network rule_action=Accept '
      + 'origin=10.99.0.41 originsicname=CN\\=gate2,O\\=example..wj6ide',
    expect: {
      vendor: 'checkpoint', action: 'accept',
      srcIp: '10.80.1.5', dstIp: '10.80.9.1', srcPort: 49005, dstPort: 53,
      protocol: 'udp', ruleName: 'Allow-DNS-Out', logClass: 'traffic',
    },
  },
  {
    id: 'checkpoint-cef-drop',
    vendor: 'checkpoint',
    why: 'the deny side; Check Point says Drop where Forcepoint says Discard',
    line: 'CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|https|Unknown|'
      + 'act=Drop deviceDirection=0 src=203.0.113.77 dst=10.80.9.1 '
      + 'spt=51110 dpt=443 proto=tcp service_id=https '
      + 'cs2Label=Rule Name cs2=Cleanup layer_name=Network rule_action=Drop '
      + 'origin=10.99.0.41',
    expect: {
      vendor: 'checkpoint', action: 'drop',
      srcIp: '203.0.113.77', dstIp: '10.80.9.1', srcPort: 51110, dstPort: 443,
      protocol: 'tcp', ruleName: 'Cleanup', logClass: 'traffic',
    },
  },
];

/** The on-the-wire form, with the syslog PRI a device prepends. */
function cefWireLine(fixture, { pri = 134 } = {}) {
  return `<${pri}>${fixture.line}`;
}

module.exports = { CEF_FIXTURES, cefWireLine };
