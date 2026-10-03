'use strict';

// tests/fixtures/ciscoAsaSyslog.js
//
// Captured Cisco ASA syslog lines, used as the ONLY evidence the ASA parser was
// written against.
//
// ── PROVENANCE, AND WHY IT IS RECORDED PER FIXTURE ────────────────────────
//
// This repo's rule is that every vendor field mapping is read off REAL CAPTURED
// LOGS, never from vendor documentation, because documentation lies. SecVault's
// own fleet carries no Cisco ASA (5 Fortinet + 11 Palo Alto, measured
// 2026-10-03), so there is nothing local to capture from. These lines come from
// a third party's regression fixtures instead.
//
//   SOURCE   logstash-plugins/logstash-patterns-core
//            spec/patterns/firewalls_spec.rb
//            https://github.com/logstash-plugins/logstash-patterns-core
//   LICENCE  Apache License 2.0  (verified 2026-10-03 against the repo's LICENSE)
//   TAKEN    2026-10-03
//
// ⛔ ELASTIC'S FIXTURES WERE DELIBERATELY NOT COPIED. elastic/integrations ships
// `.log` files for cisco_asa too, but that repository is **Elastic License 2.0**,
// not Apache, so nothing from it is vendored here. It was used only to
// CORROBORATE: Elastic's capture and the Apache-licensed one above are different
// projects under different licences, and both show `%ASA-6-302013: Built
// outbound TCP connection 11757 for outside:...` with identical structure. Two
// independent captures agreeing is materially stronger evidence than either
// alone, and is the closest substitute available for a live device.
//
// ⛔ WHAT THIS EVIDENCE DOES **NOT** ESTABLISH, and must not be read as:
//   - that a given customer's ASA emits these message IDs at all (which are
//     emitted depends on the configured logging level and enabled features);
//   - that the format is identical on their firmware;
//   - anything whatsoever about Check Point, Sangfor or Forcepoint.
// The first ASA SecVault actually sees is still a VERIFICATION STEP, exactly as
// it would be for a new device adapter. `.ai-codex/connectors.md` records this.
//
// ⛔ REAL-WORLD IRREGULARITIES ARE KEPT ON PURPOSE. The 302013 line carries a
// username inside the NAT parenthetical — `(100.66.205.104/80)(some.user)` —
// which no documentation shows and which a parser written from documentation
// would break on. Removing such lines to make the fixtures tidy would discard
// the whole reason for preferring captures over prose.

/**
 * Each entry: the raw line plus what a correct parser must extract from it.
 * `expect` lists only fields this evidence actually supports — a field absent
 * from a message is NULL, never guessed.
 */
const ASA_FIXTURES = [
  {
    id: '106023-deny-by-access-group',
    why: 'carries the ACCESS-GROUP name: the rule linkage, ASA\'s analogue of FortiOS policyid',
    line: 'Deny tcp src outside:192.168.1.1/50240 dst inside:192.168.1.2/23 '
      + 'by access-group "S_OUTSIDE_TO_INSIDE" [0x54c7fa80, 0x0]',
    msgId: '106023',
    expect: {
      action: 'deny', protocol: 'tcp',
      srcIp: '192.168.1.1', srcPort: 50240, srcZone: 'outside',
      dstIp: '192.168.1.2', dstPort: 23, dstZone: 'inside',
      ruleName: 'S_OUTSIDE_TO_INSIDE', logClass: 'traffic',
    },
  },
  {
    id: '106100-access-list-permitted',
    why: 'carries the ACCESS-LIST name AND a hit count — the strongest rule evidence the ASA emits',
    line: 'access-list inside permitted tcp inside/10.10.123.45(51763) -> '
      + 'outside/192.168.67.89(80) hit-cnt 1 first hit [0x62c4905, 0x0]',
    msgId: '106100',
    expect: {
      action: 'permit', protocol: 'tcp',
      srcIp: '10.10.123.45', srcPort: 51763, srcZone: 'inside',
      dstIp: '192.168.67.89', dstPort: 80, dstZone: 'outside',
      ruleName: 'inside', logClass: 'traffic',
    },
  },
  {
    id: '106100-access-list-interval',
    why: 'same message, the OTHER hit-cnt suffix form (interval rather than "first hit")',
    line: 'access-list outside-entry permitted tcp outside/10.11.12.13(54726) -> '
      + 'inside/192.168.17.18(80) hit-cnt 1 300-second interval [0x32b3835, 0x0]',
    msgId: '106100',
    expect: {
      action: 'permit', protocol: 'tcp',
      srcIp: '10.11.12.13', srcPort: 54726, srcZone: 'outside',
      dstIp: '192.168.17.18', dstPort: 80, dstZone: 'inside',
      ruleName: 'outside-entry', logClass: 'traffic',
    },
  },
  {
    id: '302013-built-outbound-with-username',
    why: 'the NAT parenthetical can carry a USERNAME, which documentation never shows',
    line: 'Built outbound TCP connection 11757 for outside:100.66.205.104/80 '
      + '(100.66.205.104/80)(some.user) to inside:172.31.98.44/1772 (172.31.98.44/1772)',
    msgId: '302013',
    expect: {
      action: 'start', protocol: 'TCP',
      srcIp: '100.66.205.104', srcPort: 80, srcZone: 'outside',
      dstIp: '172.31.98.44', dstPort: 1772, dstZone: 'inside',
      srcUser: 'some.user', logClass: 'traffic',
    },
  },
  {
    id: '302013-built-outbound-plain',
    why: 'the same message WITHOUT a username, so the optional group is genuinely optional',
    line: 'Built outbound TCP connection 11757 for outside:192.168.205.104/80 '
      + '(192.168.205.104/80) to inside:172.31.98.44/1772 (172.31.98.44/1772)',
    msgId: '302013',
    expect: {
      action: 'start', protocol: 'TCP',
      srcIp: '192.168.205.104', srcPort: 80, srcZone: 'outside',
      dstIp: '172.31.98.44', dstPort: 1772, dstZone: 'inside',
      srcUser: null, logClass: 'traffic',
    },
  },
  {
    id: '302014-teardown',
    why: 'carries BYTES and a teardown reason; "Teardown" is a close, never a deny',
    line: 'Teardown TCP connection 11749 for outside:192.168.211.242/80 to '
      + 'inside:172.31.98.44/1758 duration 0:01:07 bytes 38110 TCP Reset-I',
    msgId: '302014',
    expect: {
      action: 'close', protocol: 'TCP',
      srcIp: '192.168.211.242', srcPort: 80, srcZone: 'outside',
      dstIp: '172.31.98.44', dstPort: 1758, dstZone: 'inside',
      bytesSent: 38110, logClass: 'traffic',
    },
  },
  {
    id: '106001-inbound-denied',
    why: 'a deny with NO access-list name — ruleName must stay NULL, not be invented',
    line: 'Inbound TCP connection denied from 192.168.2.2/43803 to 10.10.10.10/14322 '
      + 'flags SYN on interface out111',
    msgId: '106001',
    expect: {
      action: 'deny', protocol: 'TCP',
      srcIp: '192.168.2.2', srcPort: 43803,
      dstIp: '10.10.10.10', dstPort: 14322,
      ruleName: null, logClass: 'traffic',
    },
  },
  {
    id: '106006-deny-inbound-udp',
    why: 'a second deny shape, no ports-in-parens and no access-list',
    line: 'Deny inbound UDP from 192.168.2.2/65020 to 10.10.10.10/65021 on interface fw111',
    msgId: '106006',
    expect: {
      action: 'deny', protocol: 'UDP',
      srcIp: '192.168.2.2', srcPort: 65020,
      dstIp: '10.10.10.10', dstPort: 65021,
      ruleName: null, logClass: 'traffic',
    },
  },
  {
    id: '713172-vpn',
    why: 'a VPN-class message, so logClass must NOT be traffic',
    line: 'Group = 212.9.5.245, IP = 212.9.5.245, Automatic NAT Detection Status:',
    msgId: '713172',
    expect: { logClass: 'vpn', srcIp: null, dstIp: null, action: null },
  },
  {
    id: '402117-ipsec',
    why: 'IPSEC class; addresses present but this is not a policy decision, so action stays NULL',
    line: 'IPSEC: Received a non-IPSec packet (protocol= ICMP) from 10.5.1.127 to 192.168.6.102.',
    msgId: '402117',
    expect: { logClass: 'vpn', action: null },
  },
];

/** Wrap a fixture body in the ASA syslog envelope, as a device emits it. */
function asaLine(fixture, { severity = 6, host = 'asa-fw-01', pid = 999 } = {}) {
  return `%ASA-${severity}-${fixture.msgId}: ${fixture.line}`;
}

/** The full on-the-wire form, including the RFC 3164 header a device prepends. */
function asaWireLine(fixture, opts = {}) {
  const { pri = 166, stamp = 'Oct 10 2018 12:34:56', host = 'asa-fw-01', tag = 'CiscoASA[999]' } = opts;
  return `<${pri}>${stamp} ${host} ${tag}: ${asaLine(fixture, opts)}`;
}

module.exports = { ASA_FIXTURES, asaLine, asaWireLine };
