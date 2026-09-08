'use strict';
// Vendor payload extraction, pinned against REAL CAPTURED LOG LINES.
//
// ⛔ Every fixture below was read out of this fleet's own preserved Firewall
// Analyzer archive on 2026-09-08 — not written from vendor documentation.
// CLAUDE.md's rule is "verify all field names against live responses before
// writing any parser — documentation lies", and these fixtures ARE that
// verification, kept next to the code so the evidence cannot drift away from
// it. If a parser changes, it must still satisfy a line a real firewall
// actually sent.
//
// Sources: FGT80FTK23018808 ("YCC"), FG200ETK18912640 ("OkeanosFOOD"),
//          PAKFW-01 (10.248.12.11), TH-TUG-IDC-MAS (192.168.3.254).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  detectVendor,
  parseVendorPayload,
  parseFortinet,
  parsePaloAlto,
  parseKeyValue,
  splitCsv,
  classifyPaloAlto,
  classifyFortinet,
} = require('../lib/syslog/vendorParsers');

// --- real captured payloads (syslog frame already stripped) -----------------

const FORTI_ACCEPT =
  'date=2026-09-02 time=00:03:26 devname="YCC" devid="FGT80FTK23018808" ' +
  'eventtime=1788282206708308100 tz="+0700" logid="0000000020" type="traffic" ' +
  'subtype="forward" level="notice" vd="root" srcip=172.18.136.143 srcport=57104 ' +
  'srcintf="internal" srcintfrole="lan" dstip=171.244.28.208 dstport=51212 ' +
  'dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Vietnam" ' +
  'sessionid=2830 proto=6 action="accept" policyid=7 policytype="policy" ' +
  'poluuid="db15d0f8-5ec9-51ee-f641-6792d6949c8f" sentbyte=1200 rcvdbyte=3400';

const FORTI_DENY =
  'date=2026-09-02 time=00:03:28 devname="YCC" devid="FGT80FTK23018808" ' +
  'eventtime=1788282208118632380 tz="+0700" logid="0001000014" type="traffic" ' +
  'subtype="local" level="notice" vd="root" srcip=172.18.136.247 srcport=39815 ' +
  'srcintf="internal" dstip=172.18.136.1 dstport=53 dstintf="root" ' +
  'sessionid=16066371 proto=17 action="deny" policyid=0 ' +
  'policytype="local-in-policy" service="DNS" app="Domain Name System"';

const PAN_TRAFFIC =
  '1,2026/07/09 10:23:12,024101008010,TRAFFIC,end,2817,2026/07/09 10:23:12,' +
  '10.248.5.55,146.88.61.18,83.118.104.74,146.88.61.18,Local-to-Internet-ANY-Review,,,' +
  'quic-base,vsys1,Trust,Untrust,ethernet1/11,ethernet1/1,01-LogPush-Panorama,' +
  '2026/07/09 10:23:12,514964,1,49308,443,58356,443,0x400053,udp,allow,21947,6700,15247,55';

describe('vendorParsers: detection is confident or null, never a guess', () => {
  it('identifies Fortinet from a real line', () => {
    assert.equal(detectVendor(FORTI_ACCEPT), 'fortinet');
    assert.equal(detectVendor(FORTI_DENY), 'fortinet');
  });

  it('identifies Palo Alto from a real line', () => {
    assert.equal(detectVendor(PAN_TRAFFIC), 'paloalto');
  });

  it('returns null for anything it does not recognise', () => {
    // ⛔ No "generic" fallback. A guessed vendor mis-parses every field after
    // it, which is worse than storing the message unparsed.
    for (const junk of ['', 'kernel: out of memory', 'random text', null, undefined, 42, {}]) {
      assert.equal(detectVendor(junk), null, `${JSON.stringify(junk)} must not be claimed`);
    }
  });

  it('parseVendorPayload returns null for an unrecognised vendor', () => {
    assert.equal(parseVendorPayload('sshd[1]: accepted password'), null);
  });
});

describe('vendorParsers: Fortinet key=value', () => {
  it('extracts the traffic fields off a real accept line', () => {
    const e = parseFortinet(FORTI_ACCEPT);
    assert.equal(e.vendor, 'fortinet');
    assert.equal(e.deviceName, 'YCC');
    assert.equal(e.deviceSerial, 'FGT80FTK23018808');
    assert.equal(e.action, 'accept');
    assert.equal(e.srcIp, '172.18.136.143');
    assert.equal(e.dstIp, '171.244.28.208');
    assert.equal(e.srcPort, 57104);
    assert.equal(e.dstPort, 51212);
    assert.equal(e.protocol, '6');
    assert.equal(e.vdom, 'root');
    assert.equal(e.bytesSent, 1200);
    assert.equal(e.bytesReceived, 3400);
  });

  it('⛔ extracts the rule linkage that will drive real hit counts', () => {
    // This pair is the whole reason syslog fixes the hit_count gap for the
    // SSH transport, which cannot report hits via the API at all.
    const e = parseFortinet(FORTI_ACCEPT);
    assert.equal(e.ruleId, '7');
    assert.equal(e.ruleUuid, 'db15d0f8-5ec9-51ee-f641-6792d6949c8f');
  });

  it('keeps policyid "0" as a real value, not as absent', () => {
    // local-in-policy denies carry policyid=0. That is a genuine policy
    // reference, and dropping it via a falsy check would lose every
    // implicit-deny event.
    const e = parseFortinet(FORTI_DENY);
    assert.equal(e.ruleId, '0');
    assert.equal(e.action, 'deny');
    assert.equal(e.service, 'DNS');
  });

  it('prefers the nanosecond eventtime over the date/time pair', () => {
    const e = parseFortinet(FORTI_ACCEPT);
    assert.ok(e.eventAt instanceof Date);
    // 1788282206708308100 ns -> 1788282206708.3081 ms
    assert.equal(e.eventAt.getTime(), Math.round(1788282206708308100 / 1e6));
  });

  it('falls back to date+time only when the device reported its tz', () => {
    const withTz = parseFortinet('date=2026-09-02 time=00:03:26 tz="+0700" devid="FGX" action="accept"');
    assert.ok(withTz.eventAt instanceof Date);
    assert.equal(withTz.eventAt.toISOString(), '2026-09-01T17:03:26.000Z');

    // ⛔ No tz means an unanchored local time. Null beats a guessed offset.
    const noTz = parseFortinet('date=2026-09-02 time=00:03:26 devid="FGX" action="accept"');
    assert.equal(noTz.eventAt, null);
  });

  it('handles quoted values containing spaces', () => {
    const e = parseKeyValue('policyname="Allow web out" action="accept"');
    assert.equal(e.policyname, 'Allow web out');
    assert.equal(e.action, 'accept');
  });

  it('treats an explicitly empty value as absent, not as an empty string', () => {
    const e = parseKeyValue('srcip= dstip=1.2.3.4');
    assert.equal(e.srcip, null);
    assert.equal(e.dstip, '1.2.3.4');
  });

  it('returns nulls rather than throwing on a non-Fortinet payload', () => {
    const e = parseFortinet('nothing here resembles a fortigate log');
    assert.equal(e.action, null);
    assert.equal(e.ruleId, null);
    assert.equal(e.eventAt, null);
  });
});

describe('vendorParsers: Palo Alto positional CSV', () => {
  it('reads the verified TRAFFIC field positions off a real line', () => {
    const e = parsePaloAlto(PAN_TRAFFIC);
    assert.equal(e.vendor, 'paloalto');
    assert.equal(e.deviceSerial, '024101008010');
    assert.equal(e.logType, 'TRAFFIC');
    assert.equal(e.logSubtype, 'end');
    assert.equal(e.srcIp, '10.248.5.55');
    assert.equal(e.dstIp, '146.88.61.18');
    assert.equal(e.srcPort, 49308);
    assert.equal(e.dstPort, 443);
    assert.equal(e.protocol, 'udp');
    assert.equal(e.action, 'allow');
    assert.equal(e.application, 'quic-base');
    assert.equal(e.srcZone, 'Trust');
    assert.equal(e.dstZone, 'Untrust');
    assert.equal(e.vdom, 'vsys1');
    assert.equal(e.bytesSent, 6700);
    assert.equal(e.bytesReceived, 15247);
    assert.equal(e.sessionId, '514964');
  });

  it('⛔ reads the rule NAME from index 11 — PAN-OS has no rule id in the log', () => {
    const e = parsePaloAlto(PAN_TRAFFIC);
    assert.equal(e.ruleName, 'Local-to-Internet-ANY-Review');
    assert.equal(e.ruleId, null, 'PAN-OS identifies rules by name only');
    assert.equal(e.ruleUuid, null);
  });

  it('marks the timestamp as ASSUMED, because the CSV carries no offset', () => {
    const e = parsePaloAlto(PAN_TRAFFIC);
    assert.ok(e.eventAt instanceof Date);
    assert.equal(e.tzAssumed, true);
  });

  it('does not read TRAFFIC-only columns from a non-TRAFFIC row', () => {
    // A THREAT row does not share TRAFFIC's layout past index 30.
    //
    // ⛔ CORRECTED 2026-09-08: this originally asserted `action` must be null
    // on a threat row too. That was wrong, and it was wrong in the expensive
    // direction — verified against captured rows, index 30 IS the action on
    // threat rows ("drop" on a blocked phishing lookup, "alert" on an IPS
    // detection). Suppressing it left every threat row unable to say whether
    // anything had actually been STOPPED.
    //
    // The columns below genuinely are traffic-only and must stay null: index
    // 31+ is bytes on a traffic row and URL/threat-name on a threat row.
    const threat = PAN_TRAFFIC.replace(',TRAFFIC,end,', ',THREAT,url,');
    const e = parsePaloAlto(threat);
    assert.equal(e.logType, 'THREAT');
    assert.equal(e.srcPort, null);
    assert.equal(e.bytesSent, null, 'index 32 is the threat NAME on this row, not bytes');
    assert.equal(e.bytesReceived, null);
    // The common prefix is still safe to read.
    assert.equal(e.srcIp, '10.248.5.55');
    assert.equal(e.ruleName, 'Local-to-Internet-ANY-Review');
  });

  it('handles a quoted field containing a comma', () => {
    const parts = splitCsv('a,"b,c",d');
    assert.deepEqual(parts, ['a', 'b,c', 'd']);
  });

  it('handles a doubled quote inside a quoted field', () => {
    assert.deepEqual(splitCsv('a,"say ""hi""",b'), ['a', 'say "hi"', 'b']);
  });

  it('returns nulls for a short/truncated row rather than throwing', () => {
    const e = parsePaloAlto('1,2026/07/09 10:23:12,SERIAL,TRAFFIC');
    assert.equal(e.logType, 'TRAFFIC');
    assert.equal(e.srcIp, null);
    assert.equal(e.action, null);
  });
});

describe('vendorParsers: zones are read only where the vendor actually sends them', () => {
  it('Fortinet traffic logs carry interfaces, not zones — so zones stay null', () => {
    const e = parseFortinet(FORTI_ACCEPT);
    assert.equal(e.srcInterface, 'internal');
    assert.equal(e.dstInterface, 'wan1');
    assert.equal(e.srcZone, null, 'must not pass an interface name off as a zone');
    assert.equal(e.dstZone, null);
  });
});

describe('vendorParsers: log_class is computed once at ingest', () => {
  it('maps Palo Alto log types to normalized classes', () => {
    assert.equal(classifyPaloAlto('TRAFFIC'), 'traffic');
    assert.equal(classifyPaloAlto('THREAT'), 'threat');
    assert.equal(classifyPaloAlto('GLOBALPROTECT'), 'vpn');
    assert.equal(classifyPaloAlto('SYSTEM'), 'system');
  });

  it('⛔ maps FortiOS VPN on the SUBTYPE, not the type', () => {
    // FortiOS files VPN under type="event" subtype="vpn". Classifying on type
    // alone would bucket it as generic 'event' and the VPN view would show
    // nothing at all, with no error to notice.
    assert.equal(classifyFortinet('event', 'vpn'), 'vpn');
    assert.equal(classifyFortinet('event', 'system'), 'event');
    assert.equal(classifyFortinet('traffic', 'forward'), 'traffic');
    assert.equal(classifyFortinet('utm', 'virus'), 'utm');
  });

  it('returns null for an unrecognised kind rather than an "other" bucket', () => {
    // An unclassified event is a GAP IN THIS MAPPING and should look like one.
    for (const v of [undefined, null, '', 'WHAT', 42, {}]) {
      assert.equal(classifyPaloAlto(v), null, `paloalto ${JSON.stringify(v)}`);
      assert.equal(classifyFortinet(v, v), null, `fortinet ${JSON.stringify(v)}`);
    }
  });

  it('attaches logClass to the parsed event for both vendors', () => {
    assert.equal(parseFortinet(FORTI_ACCEPT).logClass, 'traffic');
    assert.equal(parsePaloAlto(PAN_TRAFFIC).logClass, 'traffic');
  });
});

describe('vendorParsers: bytes_summable — which byte counters can be added up', () => {
  // ⛔ Naively summing bytes gave one device 50,565 GB in two hours (55 Gbps).
  // Measured cause: FortiOS re-logs a long-lived session with a RUNNING
  // cumulative counter — the same SMB session appeared as 671.3, 672.2, 673.0,
  // 673.8 and 674.6 GB in consecutive events. PAN-OS logs a session once at
  // close. So one vendor's bytes are summable and the other's are not.

  it('marks a Palo Alto session-CLOSE row as summable', () => {
    const e = parsePaloAlto(PAN_TRAFFIC); // subtype 'end'
    assert.equal(e.bytesSummable, true);
    assert.equal(e.bytesSent, 6700);
  });

  it('⛔ marks a Palo Alto session-START row as NOT summable', () => {
    // A start row reports bytes so far and would double-count against the end
    // row for the same session.
    const start = PAN_TRAFFIC.replace(',TRAFFIC,end,', ',TRAFFIC,start,');
    assert.equal(parsePaloAlto(start).bytesSummable, false);
  });

  it('⛔ marks every Fortinet row as NOT summable', () => {
    // The per-event value is still stored and is meaningful on its own; it
    // just cannot be aggregated across events.
    const e = parseFortinet(FORTI_ACCEPT);
    assert.equal(e.bytesSummable, false);
    assert.equal(e.bytesSent, 1200, 'the value is still captured, just not summable');
    assert.equal(parseFortinet(FORTI_DENY).bytesSummable, false);
  });

  it('does not mark a non-traffic Palo Alto row summable', () => {
    const threat = PAN_TRAFFIC.replace(',TRAFFIC,end,', ',THREAT,url,');
    assert.equal(parsePaloAlto(threat).bytesSummable, false);
  });
});
