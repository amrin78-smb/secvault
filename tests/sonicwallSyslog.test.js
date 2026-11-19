// tests/sonicwallSyslog.test.js
//
// The SonicOS grammar (lib/syslog/sonicos.js), the `m=` dispatch catalogue
// (lib/syslog/sonicosCatalogue.js) and the vendor mapping (parseSonicwall in
// lib/syslog/vendorParsers.js), against the 220-line corpus in
// tests/fixtures/sonicwallSyslog.js.
//
// ⛔ WHAT A TEST HERE IS FOR (CLAUDE.md, Testing): nearly every bug this
// codebase has shipped is A FAILED READ RECORDED AS AN AFFIRMATIVE VALUE. This
// vendor has an unusually sharp instance of it — SonicOS puts REAL, SMALL,
// PLAUSIBLE byte counts on connection-OPEN events, so unlike Sophos's
// session-start zeros there is no sentinel to notice. The byte cases below
// carry the most weight for that reason.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const F = require('./fixtures/sonicwallSyslog.js');
const {
  sonicosBody, parseSonicosKv, splitSonicosAddress, splitSonicosNat, validIpv4,
} = require('../lib/syslog/sonicos.js');
const { classOf, BY_ID, DERIVED, VENDOR_PAIRS, GCAT_CLASS } = require('../lib/syslog/sonicosCatalogue.js');
const {
  detectVendor, parseVendorPayload, parseSonicwall, looksSonicwall,
  sonicwallAction, parseSonicwallTime,
} = require('../lib/syslog/vendorParsers.js');
const { classifyAction } = require('../lib/syslog/actions.js');

const kvOf = (l) => parseSonicosKv(sonicosBody(l) || '');
const withM = (m) => F.ALL.filter((l) => kvOf(l).m === String(m));
const find = (re) => {
  const l = F.ALL.find((x) => re.test(x));
  assert.ok(l, `no fixture line matching ${re}`);
  return l;
};
const ev = (re) => parseSonicwall(find(re));
const all = () => F.ALL.map((l) => parseSonicwall(l));

// ---------------------------------------------------------------------------
// 1. Detection
// ---------------------------------------------------------------------------

test('every corpus line is detected as sonicwall', () => {
  assert.equal(F.ALL.length, 220);
  for (const l of F.ALL) assert.equal(detectVendor(l), 'sonicwall', l.slice(0, 80));
});

test('detection anchors on keys, never on the value of id=', () => {
  // ⛔ SonicOS emits the literal `id=firewall` on every line, which looks like
  // the perfect anchor — and 3 corpus lines carry `id=YYYYYY` because an
  // anonymiser replaced it. A detector validating that value would reject real
  // lines on the strength of a redaction.
  const redacted = F.ALL.filter((l) => /(?:^|\s)id=(?!firewall)/.test(l));
  assert.ok(redacted.length >= 3, `expected >=3 redacted id= lines, got ${redacted.length}`);
  for (const l of redacted) assert.equal(detectVendor(l), 'sonicwall');
});

test('a line missing any of the three anchor keys is not claimed', () => {
  assert.equal(looksSonicwall('id=firewall sn=X fw=1.2.3.4'), false, 'no pri=');
  assert.equal(looksSonicwall('id=firewall sn=X pri=6'), false, 'no fw=');
  assert.equal(looksSonicwall('id=firewall fw=1.2.3.4 pri=6'), false, 'no sn=');
  assert.equal(looksSonicwall(''), false);
  assert.equal(looksSonicwall(null), false);
});

test('no other vendor parser claims a SonicWall line, and vice versa', () => {
  // ⛔ Three key=value grammars now live in this file; a collision mis-parses
  // every field after it.
  for (const l of F.ALL) assert.equal(detectVendor(l), 'sonicwall');
  const fortinet = 'date=2026-11-19 time=10:00:00 devname="FG" devid=FG200E logid="0001" type="traffic"';
  assert.notEqual(detectVendor(fortinet), 'sonicwall');
});

// ---------------------------------------------------------------------------
// 2. The tokenizer
// ---------------------------------------------------------------------------

test('single-quoted values are parsed — appName uses them and nothing else does', () => {
  // ⛔ A tokenizer that knows only `"` reads `appName='General` and leaves
  // `UDP'` as a stray token.
  const kv = kvOf(find(/appName='Service iMesh'/));
  assert.equal(kv.appName, 'Service iMesh');
});

test('interior whitespace in a quoted value is preserved', () => {
  const kv = kvOf(find(/msg="Possible TCP Flood/));
  assert.match(kv.msg, /^Possible TCP Flood on IF /);
  assert.ok(kv.msg.includes(' '), 'the value is one token, spaces and all');
});

test('a duplicate key keeps the FIRST and records the loser', () => {
  // ⛔ One corpus line carries msg= twice. Silently dropping one invents away a
  // collision; overwriting would disagree with Elastic, which also takes first.
  const dup = F.ALL.map(kvOf).filter((kv) => kv['$dup:msg'] !== undefined);
  assert.equal(dup.length, 1, 'exactly one corpus line has a duplicate msg=');
  assert.ok(dup[0].msg !== undefined && dup[0]['$dup:msg'] !== undefined);
  assert.notEqual(dup[0].msg, dup[0]['$dup:msg'], 'the two values really differ');
});

test('the body anchor finds id= after any header shape', () => {
  assert.equal(sonicosBody('id=firewall sn=X'), 'id=firewall sn=X');
  assert.equal(sonicosBody('<134>Oct 10 10:00:00 1.2.3.4 id=firewall sn=X'), 'id=firewall sn=X');
  assert.equal(sonicosBody('no anchor here'), null);
});

// ---------------------------------------------------------------------------
// 3. The compound address — the field whose mis-split fabricates an IP
// ---------------------------------------------------------------------------

test('all four arities split, and no corpus address is refused', () => {
  let seen = 0;
  for (const l of F.ALL) {
    const kv = kvOf(l);
    for (const k of ['src', 'dst']) {
      if (kv[k] === undefined) continue;
      seen += 1;
      assert.equal(splitSonicosAddress(kv[k]).ok, true, `refused ${k}=${kv[k]}`);
    }
  }
  assert.equal(seen, 431, 'the measured number of compound addresses');
});

test('an EMPTY port slot is null, never port 0', () => {
  // ⛔ 16 corpus occurrences are `ip::iface`. Writing 0 is a measured value
  // that never happened, and it lands in every per-port rollup.
  const r = splitSonicosAddress('172.16.2.2::X0');
  assert.deepEqual([r.ok, r.ip, r.port, r.iface], [true, '172.16.2.2', null, 'X0']);
});

test('an EMPTY ip slot is null and the IPv6 comes from the parallel key', () => {
  // ⛔ SonicOS NEVER puts a colon-bearing IPv6 in src=, because the field is
  // itself colon-delimited. It empties the slot and fills srcV6=.
  const r = splitSonicosAddress(':28503:WAN:SOURCEHOST');
  assert.deepEqual([r.ok, r.ip, r.port, r.iface, r.host], [true, null, 28503, 'WAN', 'SOURCEHOST']);
  const e = ev(/src=:28503:WAN:SOURCEHOST/);
  assert.equal(e.srcIp, '2a02:cf40:add:4002:91f2:a9b2:e09a:6fc6');
  assert.equal(e.srcPort, 28503);
  assert.equal(e.srcInterface, 'WAN');
});

test('a compressed IPv6 is REFUSED — the interface pattern is what catches it', () => {
  // ⛔ THE DECISIVE VALIDATION. `::1` splits to ['', '', '1'] — three parts,
  // empty ip, empty port, and a part[2] that would be read as an interface
  // named "1". Only `^[A-Za-z]` refuses it.
  const r = splitSonicosAddress('::1');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'bad_interface');
});

test('a part[0] that is not IPv4 is REFUSED, never stored as an address', () => {
  // ⛔ `fe80::1` splits to ['fe80','','1']; storing 'fe80' as an IP is the bug.
  const r = splitSonicosAddress('fe80::1');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'bad_ip');
  assert.equal(splitSonicosAddress('2a02:cf40:add:4002:91f2:a9b2:e09a:6fc6').reason, 'too_many_parts');
});

test('a refused address leaves the fields null and records the raw value', () => {
  const e = parseSonicwall('id=firewall sn=X fw=1.2.3.4 pri=6 m=98 time="2022-05-16 08:19:02" src=fe80::1');
  assert.equal(e.srcIp, null);
  assert.equal(e.srcPort, null);
  assert.equal(e.fields.$badSrc, 'fe80::1');
});

test('a leading-zero octet is not a valid IPv4', () => {
  // ⛔ `010.1.1.1` is read as OCTAL by some resolvers, so accepting it stores
  // an address that means something else elsewhere — the trap consoleUrl.js
  // already carries.
  assert.equal(validIpv4('10.1.1.1'), true);
  assert.equal(validIpv4('010.1.1.1'), false);
  assert.equal(validIpv4('10.1.1.256'), false);
});

test('the NAT fields use a DIFFERENT grammar and bracket an IPv6 with a port', () => {
  // ⛔ Running them through the 4-part rule would read a port as an interface.
  assert.deepEqual(splitSonicosNat('10.0.0.96:1234'), { ok: true, ip: '10.0.0.96', port: 1234 });
  assert.deepEqual(splitSonicosNat('10.0.0.96'), { ok: true, ip: '10.0.0.96', port: null });
  assert.deepEqual(splitSonicosNat('[2a02:cf40::1]:1234'), { ok: true, ip: '2a02:cf40::1', port: 1234 });
  assert.equal(splitSonicosNat('not_an_IP').ok, false);
});

// ---------------------------------------------------------------------------
// 4. The m= catalogue
// ---------------------------------------------------------------------------

test('the catalogue separates vendor-stated from derived classes', () => {
  // ⛔ 349 ids come from SonicWall's own published reference; 21 more are read
  // off a message STRING by us. Collapsing the two is how a guess gets quoted
  // as a vendor fact.
  assert.equal(classOf('537', null).source, 'vendor');
  assert.equal(classOf('526', null).source, 'derived');
  assert.equal(classOf('98', null).logClass, 'traffic');
  assert.equal(classOf('14', null).logClass, 'utm');
  assert.equal(classOf('608', null).logClass, 'threat');
  assert.equal(classOf('1382', null).logClass, 'config');
});

test('no derived entry is shadowed by a vendor entry', () => {
  // ⛔ m=713 was in this list once and is in the VENDOR table — a dead entry
  // that misreported a vendor-stated class as one we read off a string.
  const vendor = new Set();
  for (const [, , , ids] of VENDOR_PAIRS) for (const i of ids) vendor.add(String(i));
  const shadowed = DERIVED.filter(([id]) => vendor.has(String(id)));
  assert.deepEqual(shadowed, [], 'a shadowed derived entry can never be returned');
  assert.equal(classOf('713', null).source, 'vendor');
});

test('gcat rescues only groups that map to exactly ONE class', () => {
  // ⛔ The three omissions are the point. gcat=3 Security Services splits
  // threat/utm with no majority; gcat=5 Firewall Settings is system except
  // Flood Protection; gcat=2 Log is `config` by content yet is observed on 5
  // WEB SITE HIT lines, so mapping it would file browsing as config changes.
  assert.equal(classOf('999999', '6').logClass, 'traffic');
  assert.equal(classOf('999999', '6').source, 'gcat');
  for (const g of ['2', '3', '5']) {
    assert.equal(classOf('999999', g).logClass, null, `gcat=${g} must refuse`);
    assert.equal(GCAT_CLASS.has(g), false);
  }
});

test('an unknown id with no gcat REFUSES rather than defaulting', () => {
  const r = classOf('999999', null);
  assert.equal(r.logClass, null);
  assert.equal(r.source, null);
});

test('gcat supplies no logSubtype — it names a group, not a subcategory', () => {
  assert.equal(classOf('999999', '6').logSubtype, null);
});

test('219 of 220 lines resolve a class, and the one that does not is honest', () => {
  const e = all();
  const unclassified = e.filter((x) => x.logClass === null);
  assert.equal(unclassified.length, 1);
  assert.equal(unclassified[0].fields.m, undefined, 'the only refusal is the line with no m= at all');
});

test('the class SOURCE travels on every classified row', () => {
  for (const x of all()) {
    if (x.logClass === null) continue;
    assert.ok(['vendor', 'derived', 'gcat'].includes(x.fields.$classSource));
  }
});

// ---------------------------------------------------------------------------
// 5. action — the field feeding log_hit
// ---------------------------------------------------------------------------

test('NA is not a verdict and must not become one', () => {
  assert.equal(sonicwallAction('NA', null), null);
  assert.equal(sonicwallAction('', null), null);
  assert.equal(sonicwallAction(undefined, null), null);
});

test('a connection-lifecycle id supplies the verdict fw_action withholds', () => {
  // ⛔ Measured: m=537 is NA on 37 of 45 and m=98 is NA on 31 of 42. Reading
  // fw_action and stopping leaves every SonicWall connection null, and log_hit
  // — decision rule 2 of the CVE priority tree, ABOVE CVSS 9.0 — could never
  // fire for this vendor. SonicOS opens and closes only connections it
  // PERMITTED; a denial is its own message id.
  assert.equal(sonicwallAction('NA', '537'), 'allow');
  assert.equal(sonicwallAction('NA', '98'), 'allow');
  assert.equal(sonicwallAction(undefined, '98'), 'allow');
  const naClose = withM(537).map(parseSonicwall).filter((e) => e.fields.fw_action === 'NA');
  assert.ok(naClose.length >= 30);
  for (const e of naClose) assert.equal(e.action, 'allow');
});

test('and ONLY those two ids — a web hit or a config change stays null', () => {
  // ⛔ m=97 and m=1382 also carry NA and neither is a traffic decision.
  assert.equal(sonicwallAction('NA', '97'), null);
  assert.equal(sonicwallAction('NA', '1382'), null);
});

test('fw_action WINS over the message id where it states a verdict', () => {
  assert.equal(sonicwallAction('drop', '98'), 'drop');
  assert.equal(sonicwallAction('forward', '537'), 'forward');
});

test('mgmt names a PLANE, not a verdict, and is nulled', () => {
  // ⛔ Whether the request was permitted lives in the message NAME ("Web
  // management request allowed"), which this parser does not read.
  assert.equal(sonicwallAction('mgmt', '526'), null);
  const mgmt = withM(526).map(parseSonicwall);
  assert.ok(mgmt.length >= 25);
  for (const e of mgmt) assert.equal(e.action, null);
});

test('every action emitted is in actions.js vocabulary', () => {
  const seen = new Set();
  for (const e of all()) {
    if (e.action === null) continue;
    seen.add(e.action);
    assert.notEqual(classifyAction(e.action), 'unknown', `unrecognised verb: ${e.action}`);
  }
  assert.deepEqual([...seen].sort(), ['allow', 'drop', 'forward']);
  assert.equal(classifyAction('forward'), 'allowed');
  assert.equal(classifyAction('drop'), 'blocked');
});

test('an unrecognised fw_action is returned verbatim, not swallowed', () => {
  // ⛔ So a new firmware's vocabulary shows up as a test failure rather than
  // as silence.
  assert.equal(sonicwallAction('quarantine', '98'), 'quarantine');
});

// ---------------------------------------------------------------------------
// 6. ⛔ THE BYTE COUNTERS — the sharpest trap this vendor has
// ---------------------------------------------------------------------------

test('bytes are read on m=537 ONLY', () => {
  for (const e of all()) {
    const m = e.fields.m;
    if (m === '537') continue;
    assert.equal(e.bytesSent, null, `m=${m} must not report bytesSent`);
    assert.equal(e.bytesReceived, null, `m=${m} must not report bytesReceived`);
    assert.equal(e.bytesSummable, false);
  }
});

test('a connection-OPEN event carries a REAL number and it is NOT a total', () => {
  // ⛔ Worse than Sophos's session-start zeros: a zero is at least recognisable
  // as a non-measurement. SonicOS emits 52/60/64 — TCP SYN sizes — so there is
  // no sentinel to filter on. Not one counter in the corpus is literally 0.
  const opens = withM(98).map((l) => kvOf(l)).filter((kv) => kv.sent !== undefined);
  assert.ok(opens.length >= 30);
  for (const kv of opens) {
    const n = Number(kv.sent);
    assert.ok(n >= 52 && n <= 64, `m=98 sent=${n} is a packet, not a total`);
    assert.notEqual(n, 0, 'there is no zero sentinel to rely on');
  }
  for (const e of withM(98).map(parseSonicwall)) assert.equal(e.bytesSent, null);
});

test('the same socket is counted three times across three message ids', () => {
  // ⛔ m=98 sent=52, then m=1235 sent=52, then m=537 sent=334 — the SYN twice
  // before the connection total.
  const socket = '10.0.0.96:54606:X1';
  const rows = F.ALL.filter((l) => kvOf(l).src === socket).map((l) => {
    const kv = kvOf(l);
    return { m: kv.m, sent: kv.sent };
  });
  const ids = rows.map((r) => r.m);
  assert.ok(ids.includes('98') && ids.includes('1235') && ids.includes('537'),
    `expected the three-way count on ${socket}, saw ${ids}`);
  const naive = rows.reduce((a, r) => a + Number(r.sent || 0), 0);
  const real = rows.filter((r) => r.m === '537').reduce((a, r) => a + Number(r.sent || 0), 0);
  assert.ok(naive > real, `naive ${naive} must exceed the m=537 total ${real}`);
});

test('the over-report is real and is what bytesSummable prevents', () => {
  // ⛔ Measured across the AWS corpus file: naive SUM(sent) 91,066 against
  // 86,898 real — +4.8%, and NOT a constant: it scales with short connections
  // and with how many RSTs the device emits, both workload-dependent.
  const kvs = F.SONICOS70_AWS.map(kvOf);
  const naive = kvs.reduce((a, kv) => a + Number(kv.sent || 0), 0);
  const gated = kvs.filter((kv) => kv.m === '537').reduce((a, kv) => a + Number(kv.sent || 0), 0);
  assert.ok(naive > gated);
  const overPct = ((naive - gated) / gated) * 100;
  assert.ok(overPct > 3 && overPct < 7, `expected ~4.8% over-report, measured ${overPct.toFixed(1)}%`);
});

test('an absent counter on m=537 is NOT MEASURED, never zero', () => {
  // ⛔ m=537 itself proves it: one Connection Closed carries sent= with no
  // rcvd= at all — a one-way UDP flow. Writing 0 asserts "the server replied
  // with nothing", which is probably true and is not measured.
  const oneWay = withM(537).map(parseSonicwall)
    .filter((e) => e.bytesSent !== null && e.fields.rcvd === undefined);
  assert.ok(oneWay.length >= 1, 'the corpus has a one-way UDP close');
  for (const e of oneWay) assert.equal(e.bytesReceived, null);
  const noneAtAll = withM(537).map(parseSonicwall)
    .filter((e) => e.fields.sent === undefined && e.fields.rcvd === undefined);
  assert.ok(noneAtAll.length >= 1);
  for (const e of noneAtAll) {
    assert.equal(e.bytesSent, null);
    assert.equal(e.bytesReceived, null);
    assert.equal(e.bytesSummable, true, 'it is still a close event — only the counters are absent');
  }
});

// ---------------------------------------------------------------------------
// 7. Keys that change meaning between event types
// ---------------------------------------------------------------------------

test('code= is never promoted — it is a URL category id AND an ICMP code', () => {
  // ⛔ The sharpest of the three, because both readings are small integers:
  // code=3 on m=38 is an ICMP code and would be a plausible CFS category id.
  // There is no way to tell them apart without m=.
  const icmp = ev(/m=38 /);
  assert.equal(icmp.fields.code !== undefined, true, 'the raw value is kept');
  assert.equal(icmp.urlCategory, null, 'an ICMP code must never become a URL category');
});

test('urlCategory comes from capital Category=, on 7 lines', () => {
  assert.equal(all().filter((e) => e.urlCategory !== null).length, 7);
  assert.equal(ev(/Category="Information Technology\/Computers"/).urlCategory,
    'Information Technology/Computers');
});

test('urlHostname is gated on arg= being present', () => {
  // ⛔ Elastic's own behaviour, for a reason its pipeline states: on ANTI-VIRUS
  // events dstname is an EMAIL ATTACHMENT NAME. Those events are absent here,
  // so the hazard is documented by a second implementation and unverified —
  // which is exactly when to take the narrower reading.
  assert.equal(all().filter((e) => e.urlHostname !== null).length, 7);
  const e = parseSonicwall('id=firewall sn=X fw=1.2.3.4 pri=6 m=97 time="2022-05-16 08:19:02" dstname=virus.exe');
  assert.equal(e.urlHostname, null, 'no arg= means dstname is not safely a hostname');
  assert.equal(e.fields.dstname, 'virus.exe', 'but the raw value is kept');
});

test('on m=713 the SOURCE is the firewall and the row is flagged, not swapped', () => {
  // ⛔ 53 of 220 lines (24%). The event describes a DROPPED PACKET the
  // appliance sent, so its direction is the reverse of the connection.
  // Addresses are stored as the device reported them — silently reversing them
  // would make the stored row disagree with the raw line, which a forensic
  // record may not do — and the flag lets a top-talkers rollup exclude them
  // instead of attributing a quarter of this device's events to the firewall.
  const aborts = withM(713).map(parseSonicwall);
  assert.equal(aborts.length, 53);
  for (const e of aborts) assert.equal(e.fields.$replyDirection, true);
  const other = all().filter((e) => e.fields.m !== '713');
  for (const e of other) assert.equal(e.fields.$replyDirection, undefined);
  const one = aborts[0];
  assert.equal(one.srcIp, kvOf(withM(713)[0]).src.split(':')[0], 'stored exactly as reported');
});

test('proto= yields a service only when the tail is NOT numeric', () => {
  // ⛔ The numeric form is a PORT, and it does not track dstPort — on m=713 the
  // ports are reversed. Storing it as a service name would be a lie twice over.
  const e = parseSonicwall('id=firewall sn=X fw=1.2.3.4 pri=6 m=537 time="2022-05-16 08:19:02" proto=udp/8800');
  assert.equal(e.protocol, 'udp');
  assert.equal(e.service, null);
  const named = parseSonicwall('id=firewall sn=X fw=1.2.3.4 pri=6 m=537 time="2022-05-16 08:19:02" proto=tcp/https');
  assert.equal(named.protocol, 'tcp');
  assert.equal(named.service, 'https');
});

// ---------------------------------------------------------------------------
// 8. Identity, rules and what SonicOS does not carry
// ---------------------------------------------------------------------------

test('deviceName is null on every line — no source exists', () => {
  // ⛔ id= is the constant "firewall"; fw= is the IP of the interface the EVENT
  // CONCERNS and varies within one serial, so keying on it splits one firewall
  // into two; the RFC 3164 header is a third address matching neither. Elastic
  // has no device name either.
  for (const e of all()) assert.equal(e.deviceName, null);
});

test('deviceSerial is sn=, and its SHAPE is never validated', () => {
  // ⛔ The anonymiser replaced these with 000SERIAL, XXXX, 123456789 and
  // others. Any length or charset rule built from the corpus would be built
  // from redactions and would reject real appliances.
  assert.equal(all().filter((e) => e.deviceSerial !== null).length, 220);
  const serials = new Set(all().map((e) => e.deviceSerial));
  assert.ok(serials.size >= 5, 'several distinct, deliberately non-serial-shaped values');
  assert.ok([...serials].some((s) => !/^[0-9A-F]{12}$/.test(s)), 'and not all are 12 hex');
});

test('sessionId is null — both candidates are traps', () => {
  // ⛔ n= is a LOG MESSAGE COUNTER (201 distinct over 219 lines; two
  // connections share one value, one connection appears under two), so mapping
  // it makes every event its own session. sess= is the admin session TYPE.
  for (const e of all()) assert.equal(e.sessionId, null);
  const withN = all().filter((e) => e.fields.n !== undefined);
  assert.ok(withN.length > 200, 'n= is present and deliberately unused');
});

test('countries and vdom are null — SonicOS emits neither', () => {
  for (const e of all()) {
    assert.equal(e.srcCountry, null);
    assert.equal(e.dstCountry, null);
    assert.equal(e.vdom, null);
  }
});

test('rule= has two grammars and the id/name pair is never synthesised', () => {
  // ⛔ One appliance emits BOTH, event-type-dependent, so a parser cannot pick
  // a grammar per device. ruleId and ruleName are never both available, and a
  // ruleName of "15" or a ruleId of "Default Access Rule" are both lies.
  const numeric = ev(/rule="15 \(WAN->WAN\)"/);
  assert.equal(numeric.ruleId, '15');
  assert.equal(numeric.ruleName, null);
  assert.equal(numeric.fields.$ruleZonePair, 'WAN->WAN');
  const named = ev(/rule="Default Access Rule"/);
  assert.equal(named.ruleId, null);
  assert.equal(named.ruleName, 'Default Access Rule');
  assert.equal(named.fields.$ruleZonePair, undefined);
  for (const e of all()) {
    assert.ok(!(e.ruleId !== null && e.ruleName !== null), 'never both');
  }
});

test("the rule's zone pair is kept in fields and never promoted to a zone", () => {
  // ⛔ A THIRD zone vocabulary that DISAGREES with srcZone=/dstZone= on the
  // same line: a rule filed LAN->WAN sits beside srcZone=Trusted. Which string
  // matches the appliance's own `show zone` cannot be settled from this corpus,
  // and guessing wrong makes segmentation silently inert.
  const e = ev(/rule="15 \(LAN->WAN\)"/);
  assert.equal(e.fields.$ruleZonePair, 'LAN->WAN');
  assert.notEqual(e.srcZone, 'LAN');
});

test('application is appName only — never the numeric app= id', () => {
  // ⛔ app= is a NUMERIC id and coexists with appid= holding a different
  // number. Falling back to it put a bare integer into the column that holds
  // DNS and FACEBOOK-SOCIALRSS for every other vendor, on 161 of 220 events.
  const named = all().filter((e) => e.application !== null);
  assert.equal(named.length, 2);
  for (const e of named) assert.equal(e.application, 'Service iMesh');
  for (const e of all()) {
    if (e.application !== null) assert.ok(!/^\d+$/.test(e.application));
  }
});

test("a 'General …' appName is a NON-identification and is nulled", () => {
  // ⛔ SonicOS's fallback label for traffic App Control did not match.
  // "General UDP" means "some UDP"; storing it makes every unidentified flow
  // look identified.
  const e = ev(/appName='General UDP'/);
  assert.equal(e.application, null);
  assert.equal(e.fields.appName, 'General UDP', 'the raw label is kept');
});

test('sentinel user and threat values become null', () => {
  const sso = all().filter((e) => e.fields.usr === 'Unknown (SSO failed)');
  assert.ok(sso.length >= 5);
  for (const e of sso) assert.equal(e.srcUser, null);
  const na = all().filter((e) => e.fields.ipscat === 'N/A');
  assert.ok(na.length >= 1);
  for (const e of na) assert.equal(e.threatName, null);
});

test('threat severity is stored verbatim and deliberately NOT ranked', () => {
  // ⛔ Two samples, and the direction is INVERTED from every other vendor here:
  // ipspri=3 sits beside msg="…Priority: Low", so 3 is LOW and lower is worse.
  const sev = all().filter((e) => e.threatSeverity !== null);
  assert.equal(sev.length, 2);
  for (const e of sev) assert.equal(typeof e.threatSeverity, 'string');
});

// ---------------------------------------------------------------------------
// 9. Time
// ---------------------------------------------------------------------------

test('every line gets an eventAt', () => {
  for (const e of all()) {
    assert.ok(e.eventAt instanceof Date, 'no eventAt');
    assert.ok(!Number.isNaN(e.eventAt.getTime()));
  }
});

test('a UTC suffix is honoured PER LINE, not per device', () => {
  // ⛔ One appliance emitted BOTH forms 7h03m apart in a single capture, so a
  // parser deciding the zone once per device gets one batch wrong by the local
  // offset.
  const utc = parseSonicwallTime('2022-05-16 08:19:02 UTC');
  assert.equal(utc.at.toISOString(), '2022-05-16T08:19:02.000Z');
  assert.equal(utc.zoneless, false);
  const bare = parseSonicwallTime('2022-05-16 08:19:02');
  assert.equal(bare.zoneless, true);
  const serials = new Set(F.ALL.filter((l) => / UTC"/.test(l)).map((l) => kvOf(l).sn));
  const bareSerials = new Set(F.ALL.filter((l) => !/ UTC"/.test(l)).map((l) => kvOf(l).sn));
  assert.ok([...serials].some((s) => bareSerials.has(s)),
    'at least one appliance emits BOTH forms — the reason the rule is per line');
});

test('an assumed zone is RECORDED on exactly the zoneless lines', () => {
  // ⛔ Otherwise an assumption is indistinguishable from a stamp the device
  // actually zoned.
  const flagged = all().filter((e) => e.fields.$eventAtZoneless === true);
  assert.equal(flagged.length, 204);
  const zoned = all().filter((e) => e.fields.$eventAtZoneless === undefined);
  assert.equal(zoned.length, 16);
});

test('all four header shapes are accepted and none is required', () => {
  // ⛔ Measured: `<PRI>` alone on 154, a full RFC 3164 stamp on 54, a BARE HOST
  // with no timestamp on 8, and NOTHING AT ALL on 4. ⛔ A `<PRI>` and an RFC
  // 3164 header NEVER co-occur, so a parser expecting both finds neither.
  // The only invariant is that the payload begins at the first `id=`.
  const shape = (l) => {
    const pre = l.slice(0, l.indexOf('id='));
    if (pre === '') return 'none';
    if (/^<\d+>\s*$/.test(pre)) return 'pri';
    if (/^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s*$/.test(pre)) return 'rfc3164';
    if (/^\d{1,3}(?:\.\d{1,3}){3}\s*$/.test(pre)) return 'bare_host';
    return 'other';
  };
  const counts = {};
  for (const l of F.ALL) counts[shape(l)] = (counts[shape(l)] || 0) + 1;
  assert.deepEqual(counts, { pri: 154, rfc3164: 54, bare_host: 8, none: 4 });
  // ⛔ The bare-host shape is the one that breaks naive RFC 3164 parsers: a
  // strict `TIMESTAMP HOSTNAME` grok fails and most implementations then drop
  // the line or shift every field by one token.
  for (const l of F.ALL) assert.equal(detectVendor(l), 'sonicwall');
});

test('the RFC 3164 header timestamp is never used', () => {
  // ⛔ It is a third timestamp that need not agree with time=.
  const headered = F.ALL.filter((l) => /^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s/.test(l));
  assert.equal(headered.length, 54);
  for (const l of headered) {
    const e = parseSonicwall(l);
    assert.equal(e.eventAt.toISOString(), parseSonicwallTime(kvOf(l).time).at.toISOString());
  }
});

test('an unparseable time is null, never now()', () => {
  assert.equal(parseSonicwallTime('not a time').at, null);
  assert.equal(parseSonicwallTime(undefined).at, null);
});

// ---------------------------------------------------------------------------
// 10. Auth and the dispatcher
// ---------------------------------------------------------------------------

test('auth outcome comes from the message id — no field states it', () => {
  assert.equal(ev(/ m=29 /).authOutcome, 'success');
  assert.equal(ev(/ m=30 /).authOutcome, 'failure');
  assert.equal(ev(/ m=262 /).authOutcome, 'logout');
  assert.equal(ev(/ m=98 /).authOutcome, null);
});

test('parseVendorPayload dispatches SonicWall and agrees with parseSonicwall', () => {
  for (const l of F.ALL) assert.deepEqual(parseVendorPayload(l), parseSonicwall(l));
});

test('every line reports vendor sonicwall and a level from pri=', () => {
  for (const e of all()) {
    assert.equal(e.vendor, 'sonicwall');
    assert.ok(Number.isFinite(e.level), 'pri= is 220/220');
    assert.ok(e.level >= 0 && e.level <= 7);
  }
});

test('the raw key=value set survives on fields', () => {
  const e = ev(/ m=1197 /);
  // ⛔ note= on m=1197 carries the entire PRE-NAT 5-tuple in free text while
  // src=/dst= carry the MAPPED addresses — two different address pairs on one
  // line, one of them only in prose. It must be preserved verbatim and never
  // parsed generically.
  assert.match(e.fields.note, /^Source: /);
  assert.ok(e.fields.c !== undefined, 'the ambiguous legacy category mask is kept, not promoted');
});
