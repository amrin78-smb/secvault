'use strict';
// Pins the fields added on 2026-09-08 — country, user, URL category, threat
// name and severity — that both vendors were already sending and SecVault was
// discarding.
//
// ⛔ EVERY FIXTURE BELOW IS A REAL LINE captured from this fleet's live stream
// on 2026-09-08, not a hand-written approximation and not an example from
// vendor documentation. That is CLAUDE.md's "documentation lies" rule, and it
// matters more here than anywhere else in the parser: PAN-OS positional
// indices for COUNTRY differ between a TRAFFIC row (41/42) and a THREAT row
// (38/39). Reading one map against the other returns a real, plausible, WRONG
// value rather than an error — traffic index 38 is empty and index 39 is a
// sequence number, neither of which looks like a bug in a chart.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { parseVendorPayload, threatSeverityRank } = require('../lib/syslog/vendorParsers');

// Captured from ITC-FW-MAIN (PAN-OS 11.1), THREAT/url subtype.
const PAN_THREAT =
  '1,2026/09/08 16:45:31,023001020729,THREAT,url,2817,2026/09/08 16:45:31,' +
  '172.48.14.115,23.215.7.17,119.110.198.148,23.215.7.17,Permit_O365_BlockGroup2,,,' +
  'ssl,vsys1,LAN,WAN,ethernet1/2,ethernet1/1,Forward to Panorama,2026/09/08 16:45:33,' +
  '227850,1,58959,443,43025,443,0x403400,tcp,block-url,"www.bing.com/",(9999),' +
  'block-Deny Web-O365,informational,client-to-server,7648579439873684805,' +
  '0x8000000000000000,United States,Singapore,,,0,,,0';

// Captured from TUM-FW-ACTIVE (PAN-OS 11.1), TRAFFIC/end subtype.
const PAN_TRAFFIC =
  '1,2026/09/08 16:35:36,023001020713,TRAFFIC,end,2817,2026/09/08 16:35:36,' +
  '172.32.90.79,4.231.66.184,119.110.198.132,4.231.66.184,LAN to Allow_url,,,' +
  'ssl,vsys1,LAN,WAN,ethernet1/2,ethernet1/1,TU_Syslog,2026/09/08 16:35:36,' +
  '236142,1,60046,443,18623,443,0x40041c,tcp,allow,18587,6285,12302,35,' +
  '2026/09/08 16:35:21,1,computer-and-internet-info,,7668167892928932982,0x0,' +
  'United States,European Union,,17,18,tcp-fin,0,0,0,0,,TUM-FW-ACTIVE';

// Captured from FG80F-TSR_HQ, utm/app-ctrl — carries a real logged-in user.
const FORTI_UTM =
  'date=2026-09-08 time=16:45:33 devname="FG80F-TSR_HQ" devid="FGT80FTK21025346" ' +
  'eventtime=1788860733356620909 tz="+0700" logid="1059028704" type="utm" ' +
  'subtype="app-ctrl" eventtype="signature" level="information" vd="root" appid=15895 ' +
  'user="tsr0017" authserver="tsr0017" srcip=10.248.70.50 srccountry="Reserved" ' +
  'dstip=155.102.13.26 dstcountry="Thailand" srcport=61206 dstport=443 ' +
  'srcintf="a" srcintfrole="lan" dstintf="wan2" dstintfrole="wan" proto=6 service="SSL" ' +
  'direction="outgoing" policyid=21 poluuid="3fe7277a-f578-51ef-7626-90e881c6337b" ' +
  'policytype="policy" sessionid=122822417 applist="monitor-app" action="pass" ' +
  'appcat="Network.Service" app="SSL" hostname="sausage-global-cdn.sausage.xd.com" ' +
  'incidentserialno=166851061 url="/" msg="Network.Service: SSL" apprisk="elevated"';

// Captured from YCC, plain forwarded traffic — no user, no application.
const FORTI_TRAFFIC =
  'date=2026-09-08 time=16:35:37 devname="YCC" devid="FGT80FTK23018808" ' +
  'eventtime=1788860136228264179 tz="+0700" logid="0000000013" type="traffic" ' +
  'subtype="forward" level="notice" vd="root" srcip=172.18.136.244 srcport=8567 ' +
  'srcintf="internal" srcintfrole="lan" dstip=14.238.110.168 dstport=8752 ' +
  'dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="Vietnam" ' +
  'sessionid=27116513 proto=17 action="accept" policyid=7 policytype="policy" ' +
  'poluuid="db15d0f8-5ec9-51ee-f641-6792d6949c8f" policyname="chotruycap" ' +
  'service="udp/8752" trandisp="snat" transip=123.25.240.15 transport=8567 ' +
  'appcat="unscanned" duration=212 sentbyte=403 rcvdbyte=331 sentpkt=4 rcvdpkt=4';

describe('PAN-OS: country comes from the map for THIS log type', () => {
  it('reads country from 41/42 on a TRAFFIC row', () => {
    const e = parseVendorPayload(PAN_TRAFFIC);
    assert.equal(e.vendor, 'paloalto');
    assert.equal(e.srcCountry, 'United States');
    assert.equal(e.dstCountry, 'European Union');
  });

  it('reads country from 38/39 on a THREAT row', () => {
    const e = parseVendorPayload(PAN_THREAT);
    assert.equal(e.srcCountry, 'United States');
    assert.equal(e.dstCountry, 'Singapore');
  });

  it('⛔ a THREAT row does not pick up the TRAFFIC country indices', () => {
    // Traffic index 41 on this threat row is empty and 42 is a "0". If the
    // maps were confused, the widget would show a country named "0".
    const e = parseVendorPayload(PAN_THREAT);
    assert.notEqual(e.srcCountry, '0');
    assert.notEqual(e.dstCountry, '0');
  });

  it('⛔ a TRAFFIC row does not pick up the THREAT country indices', () => {
    // Traffic index 39 is the sequence number 7668167892928932982.
    const e = parseVendorPayload(PAN_TRAFFIC);
    assert.notEqual(e.dstCountry, '7668167892928932982');
    assert.equal(e.dstCountry, 'European Union');
  });
});

describe('PAN-OS: threat, URL and user fields', () => {
  it('extracts the vendor severity word and the category from a url row', () => {
    // ⛔ CORRECTED 2026-09-08: this originally asserted threatName ===
    // 'block-Deny Web-O365'. That is the CATEGORY (index 33), not the name.
    // On this url-filtering row index 32 is a bare "(9999)" — an id with no
    // signature behind it — so the honest threat name is NULL, and the
    // category is kept in its own field. See the PAN_THREAT block in
    // vendorParsers.js for how the original mistake was made.
    const e = parseVendorPayload(PAN_THREAT);
    assert.equal(e.threatName, null);
    assert.equal(e.urlCategory, 'block-Deny Web-O365');
    assert.equal(e.threatSeverity, 'informational');
    assert.equal(e.logSubtype, 'url');
  });

  it('extracts the URL from a threat row and the category from a traffic row', () => {
    assert.equal(parseVendorPayload(PAN_THREAT).urlHostname, 'www.bing.com/');
    assert.equal(parseVendorPayload(PAN_TRAFFIC).urlCategory, 'computer-and-internet-info');
  });

  it('⛔ leaves threat fields null on a traffic row rather than reading bytes', () => {
    // Traffic index 33 is bytes_received (12302). A threat-name column full of
    // byte counts would be nonsense that still renders.
    const e = parseVendorPayload(PAN_TRAFFIC);
    assert.equal(e.threatName, null);
    assert.equal(e.threatSeverity, null);
    assert.equal(e.urlHostname, null);
  });

  it('an absent user is null, not an empty string', () => {
    // Both captured rows have empty user fields; this fleet only populates
    // them where User-ID is configured (measured: 6,477 of 700,031 events).
    assert.equal(parseVendorPayload(PAN_TRAFFIC).srcUser, null);
    assert.equal(parseVendorPayload(PAN_THREAT).srcUser, null);
  });
});

describe('FortiOS: the same fields, by key rather than position', () => {
  it('extracts user, countries, category and hostname', () => {
    const e = parseVendorPayload(FORTI_UTM);
    assert.equal(e.vendor, 'fortinet');
    assert.equal(e.srcUser, 'tsr0017');
    assert.equal(e.dstCountry, 'Thailand');
    assert.equal(e.urlCategory, 'Network.Service');
    assert.equal(e.urlHostname, 'sausage-global-cdn.sausage.xd.com');
    assert.equal(e.logSubtype, 'app-ctrl');
  });

  it('⛔ keeps FortiOS\'s literal "Reserved" for a private source address', () => {
    // "Reserved" is FortiOS's own word for RFC1918. Rewriting it to null would
    // discard a real answer; rewriting it to "Private" would invent a word the
    // device never said.
    assert.equal(parseVendorPayload(FORTI_UTM).srcCountry, 'Reserved');
    assert.equal(parseVendorPayload(FORTI_TRAFFIC).srcCountry, 'Reserved');
  });

  it('⛔ does not fall back to eventtype for the threat name', () => {
    // This row's eventtype is "signature", which names nothing. Accepting it
    // would make "signature" the top entry of every Top Threats report.
    const e = parseVendorPayload(FORTI_UTM);
    assert.equal(e.threatName, null);
  });

  it('carries the policy name so Fortinet rules are identifiable', () => {
    assert.equal(parseVendorPayload(FORTI_TRAFFIC).ruleName, 'chotruycap');
  });

  it('a traffic row with no user leaves it null', () => {
    assert.equal(parseVendorPayload(FORTI_TRAFFIC).srcUser, null);
  });
});

describe('threatSeverityRank: one scale across two vendor vocabularies', () => {
  it('ranks both vendors onto the same ordered scale', () => {
    assert.equal(threatSeverityRank('critical'), 5);
    assert.equal(threatSeverityRank('emergency'), 5);
    assert.equal(threatSeverityRank('informational'), 1);
    assert.equal(threatSeverityRank('information'), 1);
    assert.ok(threatSeverityRank('high') > threatSeverityRank('low'));
    assert.ok(threatSeverityRank('alert') > threatSeverityRank('warning'));
  });

  it('is case- and whitespace-insensitive', () => {
    assert.equal(threatSeverityRank('  CRITICAL '), 5);
  });

  it('⛔ returns null for an unknown word rather than a default level', () => {
    // A threat filed under a guessed severity is worse than one filed under
    // none: it silently changes where it sorts in a prioritized list.
    for (const bad of ['', 'urgent', 'sev1', null, undefined, 3, {}]) {
      assert.equal(threatSeverityRank(bad), null, JSON.stringify(bad));
    }
  });
});

describe('⛔ PAN threat rows: the signature name, not the category', () => {
  // The map originally read `threatName` from index 33 — the CATEGORY — and
  // was "verified" against a URL-FILTERING row, where index 32 is a bare
  // "(9999)" placeholder so both readings looked plausible. On a real IPS row
  // they are not: index 32 carries the signature, index 33 carries "any".
  //
  // The cost was that every phishing, malware and cryptomining detection on
  // the fleet was stored as its URL category, so Top Threats named none of
  // them. CLAUDE.md warns PAN positions differ per log TYPE; these fixtures
  // pin that they differ in MEANING per SUBTYPE too, which one sample of one
  // subtype cannot reveal.

  // Real captured spyware row (SMT-FW-MAIN) — a blocked phishing DNS lookup.
  const SPYWARE =
    '1,2026/09/08 17:18:02,023001021706,THREAT,spyware,2817,2026/09/08 17:18:02,' +
    '172.24.0.26,8.8.8.8,119.110.198.100,8.8.8.8,Vlan0,,,dns-base,vsys1,LAN,WAN,' +
    'ethernet1/2,ethernet1/1,Forward to Panorama,2026/09/08 17:18:03,187553,1,' +
    '34259,53,43891,53,0x407000,udp,drop,"bailliede.ru",' +
    'Phishing:bailliede.ru(109010001),any,low,client-to-server,' +
    '7648486543962866192,0x8000000000000000,172.16.0.0-172.31.255.255,United States';

  // Real captured vulnerability row (TUF-FW-ACTIVE) — an IPS alert, not blocked.
  const VULN =
    '1,2026/09/08 17:14:42,023001020727,THREAT,vulnerability,2817,2026/09/08 17:14:42,' +
    '172.40.202.78,172.32.22.215,101.109.194.246,172.32.22.215,LocalPeplink-AllowTOT,,,' +
    'snmpv1-get-request,vsys1,LAN,Local Internet,ae1,ethernet1/4,Panorama,' +
    '2026/09/08 17:24:58,102787,1,49665,161,58469,161,0x80426000,udp,alert,,' +
    'ISF SNMP Authentication Attempt(96504),any,informational,client-to-server,' +
    '7648554868319390078,0x0,United States,United States';

  it('reads the real signature name from index 32', () => {
    assert.equal(parseVendorPayload(SPYWARE).threatName, 'Phishing:bailliede.ru(109010001)');
    assert.equal(parseVendorPayload(VULN).threatName, 'ISF SNMP Authentication Attempt(96504)');
  });

  it('⛔ does NOT store the category as the threat name', () => {
    // Both rows carry "any" at index 33. If that ever comes back as the threat
    // name, the bug has returned.
    for (const line of [SPYWARE, VULN]) {
      assert.notEqual(parseVendorPayload(line).threatName, 'any');
    }
  });

  it('keeps the category, in its own field', () => {
    assert.equal(parseVendorPayload(SPYWARE).urlCategory, 'any');
    assert.equal(parseVendorPayload(VULN).urlCategory, 'any');
  });

  it('⛔ captures the action, which says whether the threat was STOPPED', () => {
    // "drop" and "alert" are a security distinction, not a detail: one was
    // blocked, one was only observed. This was null on every threat row while
    // the action index was gated on isTraffic.
    assert.equal(parseVendorPayload(SPYWARE).action, 'drop');
    assert.equal(parseVendorPayload(VULN).action, 'alert');
  });

  it('keeps severity and the offending host alongside', () => {
    const s = parseVendorPayload(SPYWARE);
    assert.equal(s.threatSeverity, 'low');
    assert.equal(s.urlHostname, 'bailliede.ru');
    assert.equal(parseVendorPayload(VULN).threatSeverity, 'informational');
  });

  it('⛔ a bare "(9999)" URL-filtering id names nothing, so it is null', () => {
    // PAN writes a naked id with no signature behind it on url rows. Left as-is
    // it would be the single most common "threat name" on the fleet.
    const URL_ROW = PAN_THREAT.replace(
      'block-url,"www.bing.com/",(9999),block-Deny Web-O365',
      'block-url,"www.bing.com/",(9999),block-Deny Web-O365'
    );
    const e = parseVendorPayload(URL_ROW);
    assert.equal(e.threatName, null, 'a bare (id) must not become a threat name');
    assert.equal(e.urlCategory, 'block-Deny Web-O365', 'its category is still kept');
  });
});
