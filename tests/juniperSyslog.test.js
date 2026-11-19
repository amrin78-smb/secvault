// tests/juniperSyslog.test.js
//
// The Junos grammar (lib/syslog/junos.js) and the Junos vendor mapping
// (parseJuniper in lib/syslog/vendorParsers.js), against the 105-line corpus
// in tests/fixtures/juniperSyslog.js.
//
// ⛔ WHAT A TEST HERE IS FOR (CLAUDE.md, Testing): nearly every bug this
// codebase has shipped is a FAILED READ RECORDED AS AN AFFIRMATIVE VALUE. So
// the cases below are weighted towards "the device did not say" — an absent
// port that must not become 0, an absent country that must not become a
// guess, a detection that must not become a verdict — rather than towards the
// happy path, which is the half that does not regress silently.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const F = require('./fixtures/juniperSyslog.js');
const {
  looksJunosStructured, looksJunosBrief, parseStructuredData, parseJunosFrame,
} = require('../lib/syslog/junos.js');
const {
  detectVendor, parseVendorPayload, parseJuniper, classifyJunos, junosAction,
  junosAuthOutcome,
} = require('../lib/syslog/vendorParsers.js');
const { classifyAction } = require('../lib/syslog/actions.js');

const find = (re) => {
  const l = F.ALL.find((x) => re.test(x));
  assert.ok(l, `fixture corpus has no line matching ${re}`);
  return l;
};
const ev = (re) => parseJuniper(find(re));
const claimed = () => F.ALL.filter((l) => detectVendor(l) === 'juniper');

// ---------------------------------------------------------------------------
// 1. Detection
// ---------------------------------------------------------------------------

test('every corpus line is framed, and 96 of 105 are claimed as Juniper', () => {
  for (const l of F.ALL) assert.ok(parseJunosFrame(l), `unframed: ${l.slice(0, 80)}`);
  assert.equal(claimed().length, 96);
});

test('the nine declined lines are free prose carrying no mapped field', () => {
  const declined = F.ALL.filter((l) => detectVendor(l) !== 'juniper');
  assert.equal(declined.length, 9);
  // ⛔ THE DECISIVE ONE. A generic kernel message any Linux host emits must
  // NOT be attributed to Juniper: a detector loose enough to claim it would
  // file other vendors' — and non-firewall — syslog as Junos, and a guessed
  // vendor silently mis-parses every field after it.
  assert.ok(declined.some((l) => /Can't assign requested address/.test(l)));
  for (const l of declined) {
    assert.equal(looksJunosStructured(l), false);
    assert.equal(parseVendorPayload(l), null);
  }
});

test('the packet-filter lines ARE claimed, on the interface grammar alone', () => {
  // They have no APP-NAME and no MSGID, so only `FW: <junos-interface>` can
  // identify them — and they carry the only 5-tuple a device without RT_FLOW
  // configured emits.
  const fw = F.ALL.filter((l) => /FW:\s/.test(l) && !/\[junos@/.test(l));
  assert.ok(fw.length >= 3);
  for (const l of fw) assert.equal(detectVendor(l), 'juniper');
});

test('detection never anchors on the SD-ID, which anonymisation destroyed', () => {
  // Four incompatible spellings exist in the corpus, two containing letters
  // (`junos@xxx.x.x.x.x.28`), and 5 real flow lines omit it entirely — so a
  // parser anchored on it is both untestable here and wrong on a real device.
  const noSdId = F.ALL.filter((l) => !/\[junos@/.test(l) && detectVendor(l) === 'juniper');
  assert.ok(noSdId.length >= 5, `only ${noSdId.length} claimed lines lack an SD-ID`);
});

// ---------------------------------------------------------------------------
// 2. Brief format — a NAMED GAP, never silence and never a guess
// ---------------------------------------------------------------------------

const BRIEF = '<14>Nov 19 09:37:51 SRX-GW1 RT_FLOW_SESSION_CREATE: session created 10.0.0.1/594->67.43.156.13/80';

test('brief-format Junos is detected and reported as a configuration gap', () => {
  assert.equal(looksJunosBrief(BRIEF), true);
  assert.equal(detectVendor(BRIEF), 'juniper');
  const e = parseVendorPayload(BRIEF);
  assert.equal(e.vendor, 'juniper');
  assert.equal(e.deviceName, 'SRX-GW1');
  assert.equal(e.fields.$formatGap, 'junos_brief');
  assert.match(e.fields.$formatFix, /structured-data/);
});

test('a brief line yields NO mapped fields rather than mis-parsed ones', () => {
  // ⛔ THE REASON THE GUARD EXISTS. RFC 3164 also has five whitespace fields
  // after the PRI, so the 5424 header regex "succeeds" on it and would report
  // timestamp=`Nov`, hostname=`19`, appName=`09:37:51`. Every field after that
  // is confident garbage and nothing errors.
  const e = parseVendorPayload(BRIEF);
  for (const k of ['eventAt', 'logType', 'logClass', 'logSubtype', 'action',
    'srcIp', 'dstIp', 'srcPort', 'dstPort', 'protocol', 'srcZone', 'ruleName']) {
    assert.equal(e[k], null, `${k} should be null on a brief line, got ${e[k]}`);
  }
  assert.notEqual(e.deviceName, '19');
});

test('no corpus line is mistaken for brief format', () => {
  for (const l of F.ALL) assert.equal(looksJunosBrief(l), false);
});

// ---------------------------------------------------------------------------
// 3. The frame
// ---------------------------------------------------------------------------

test('severity is PRI % 8, never the raw PRI', () => {
  // Elastic stores the raw composite (165) in event.severity, which is a
  // facility+severity pair read as a severity.
  const fr = parseJunosFrame(find(/IDP_ATTACK_LOG_EVENT/));
  assert.equal(fr.pri, 165);
  assert.equal(fr.severity, 5);
  assert.equal(fr.facility, 20);
});

test('the version digit is optional — 11 corpus lines omit it', () => {
  const noVersion = F.ALL.filter((l) => parseJunosFrame(l).version === null);
  assert.ok(noVersion.length >= 11, `expected >=11 version-less lines, got ${noVersion.length}`);
  for (const l of noVersion) assert.ok(parseJunosFrame(l).hostname);
});

test('absent structured data is null, which is not an empty map', () => {
  // ⛔ 19 of 105 lines carry no SD at all. `{}` would mean "an SD block was
  // present and held nothing", a different fact, and would make a caller
  // testing `sd && ...` take the wrong branch.
  const none = F.ALL.filter((l) => parseJunosFrame(l).sd === null);
  assert.ok(none.length >= 19, `expected >=19 SD-less lines, got ${none.length}`);
  assert.deepEqual(parseStructuredData('').sd, null);
  assert.deepEqual(parseStructuredData('[id a="1"]').sd, { a: '1' });
});

test('an escaped \\] does not truncate the SD block', () => {
  // ⛔ Scanning to the first `]` cuts this VPN event mid-value and silently
  // drops every key after it.
  // ⛔ BOTH KMD lines hold 11 keys; only ONE carries the escape, so the test
  // must target that one or it passes against a line with nothing to escape.
  const fr = parseJunosFrame(find(/local-initiator="[^"]*\\\]/));
  assert.equal(Object.keys(fr.sd).length, 11);
  assert.match(fr.sd['local-initiator'], /\[0\.\.7\]=/);
  // ⛔ PRESENCE, not truthiness: this key's value is legitimately EMPTY, and
  // an empty value is null by design. Asserting the value would be testing
  // the wrong thing — what the escape could destroy is the KEY.
  assert.ok('first-forwarding-class' in fr.sd, 'the LAST key must survive the escape');
});

test('typographic quotes are stripped from the value, not kept inside it', () => {
  // Elastic's own pipeline leaves them in, producing '”st0.0”' as an interface
  // name in an index.
  const fr = parseJunosFrame(find(/verdict-source=[“”]/));
  assert.equal(fr.sd['verdict-source'], 'cloud/blacklist/whitelist');
  for (const l of F.ALL) {
    const sd = parseJunosFrame(l).sd || {};
    for (const [k, v] of Object.entries(sd)) {
      if (typeof v === 'string') assert.ok(!/[“”]/.test(v), `${k} kept a curly quote: ${v}`);
    }
  }
});

test('a present-but-empty SD value is null, not an empty string', () => {
  assert.equal(parseStructuredData('[id a="" b="x"]').sd.a, null);
});

// ---------------------------------------------------------------------------
// 4. logClass
// ---------------------------------------------------------------------------

test('every claimed line gets a logClass', () => {
  // ⛔ A null class is a row that every class-filtered rollup silently drops
  // while its fields look perfectly parsed.
  for (const l of claimed()) {
    assert.ok(parseJuniper(l).logClass, `null logClass: ${l.slice(0, 90)}`);
  }
});

test('RT_UTM is utm INCLUDING virus detections, never split by MSGID', () => {
  // Splitting the family would give a UTM dashboard that silently omits
  // AV_VIRUS_DETECTED_MT.
  assert.equal(classifyJunos('RT_UTM', 'AV_VIRUS_DETECTED_MT'), 'utm');
  assert.equal(classifyJunos('RT_UTM', 'WEBFILTER_URL_BLOCKED'), 'utm');
  assert.equal(ev(/AV_VIRUS_DETECTED_MT \[/).logClass, 'utm');
});

test('the packet-filter lines are traffic, and are labelled as ours', () => {
  const e = ev(/FW:\s+gr-0\/0\/0\.14/);
  assert.equal(e.logClass, 'traffic');
  // ⛔ The device's own APP-NAME is kept where it gave one.
  assert.equal(e.logType, 'kernel');
  // ⛔ `FW_FILTER` is SecVault's label — these events carry no MSGID at all.
  assert.equal(e.logSubtype, 'FW_FILTER');
  // The PFE tag is taken from the text when APP-NAME is '-'.
  assert.equal(ev(/PFE_FW_SYSLOG_IP: FW:\s+reth5/).logType, 'PFE_FW_SYSLOG_IP');
});

test('an unknown app with no MSGID is unclassified, not bucketed', () => {
  assert.equal(classifyJunos('wibbled', null, false), null);
  assert.equal(classifyJunos('-', '-', false), null);
});

// ---------------------------------------------------------------------------
// 5. action — the field feeding log_hit, decision rule 2 of the CVE tree
// ---------------------------------------------------------------------------

test('RT_FLOW carries no action field, so the MSGID is the only source', () => {
  // ⛔ Measured: 0 of 24 RT_FLOW/APPTRACK lines carry `action=`. A parser that
  // reads the field and stops leaves this vendor's busiest family with a null
  // action, and log_hit could never fire for Juniper.
  const flow = F.ALL.filter((l) => /\sRT_FLOW\s/.test(l));
  assert.ok(flow.length >= 20);
  for (const l of flow) assert.equal(/\saction="/.test(l), false);
  assert.equal(ev(/RT_FLOW_SESSION_DENY \[/).action, 'deny');
  assert.equal(ev(/RT_FLOW_SESSION_CREATE \[/).action, 'allow');
  assert.equal(ev(/RT_FLOW_SESSION_CLOSE \[/).action, 'allow');
  assert.equal(ev(/APPTRACK_SESSION_VOL_UPDATE/).action, 'allow');
});

test('the _LS logical-system suffix does not break the verdict', () => {
  assert.equal(ev(/RT_FLOW_SESSION_DENY_LS/).action, 'deny');
  assert.equal(ev(/APPTRACK_SESSION_CLOSE_LS/).action, 'allow');
});

test('the MSGID outranks the action field', () => {
  // ⛔ `action` on RT_IDP/RT_IDS names what the SECURITY SERVICE did; the
  // MSGID on RT_FLOW/RT_UTM names what the POLICY did. Reading the field
  // first would let an IDP drop overwrite a session the policy permitted.
  assert.equal(junosAction('RT_FLOW_SESSION_CREATE', { action: 'DROP' }), 'allow');
  assert.equal(junosAction('WEBFILTER_URL_BLOCKED', { action: 'PERMIT' }), 'block');
  assert.equal(junosAction(null, { action: 'BLOCK' }), 'block');
});

test('a DETECTION is not a verdict', () => {
  // ⛔ AV_VIRUS_DETECTED_MT says something was FOUND and carries no action
  // field. Assuming `block` would manufacture evidence on the UTM dashboard.
  const e = ev(/AV_VIRUS_DETECTED_MT \[/);
  assert.equal(e.action, null);
  assert.equal(e.threatName, 'EICAR-Test-File');
  // ANTISPAM does carry action="drop" — that is the device speaking.
  assert.equal(ev(/ANTISPAM_SPAM_DETECTED_MT/).action, 'drop');
});

test('the NONE sentinel becomes null, not an action', () => {
  // "The IDP took no action" is not a traffic decision.
  assert.equal(junosAction(null, { action: 'NONE' }), null);
  assert.equal(ev(/IDP_APPDDOS_APP_ATTACK_EVENT \[/).action, null);
});

test('alarm-without-drop is ALLOWED, although the word contains "drop"', () => {
  // ⛔ The screen detected a SYN flood, raised an alarm and did NOT drop — so
  // the traffic reached the host. Classifying it denied (or leaving it
  // unknown) hides an attack that landed.
  const e = ev(/RT_SCREEN_TCP_DST_IP/);
  assert.equal(e.action, 'alarm-without-drop');
  assert.equal(classifyAction(e.action), 'allowed');
});

test('every action this parser emits is in actions.js vocabulary', () => {
  // ⛔ An unrecognised verb is neither allowed nor blocked — it fails SAFE for
  // log_hit and UNSAFE for raw-message retention, so the gap is invisible in
  // one direction and lossy in the other.
  const seen = new Set();
  for (const l of claimed()) {
    const a = parseJuniper(l).action;
    if (a === null) continue;
    seen.add(a);
    assert.notEqual(classifyAction(a), 'unknown', `unrecognised verb: ${a}`);
  }
  assert.ok(seen.size >= 6, `expected a spread of verbs, saw ${[...seen]}`);
});

test('the filter action letter maps A/D/R, and an unknown letter is null', () => {
  assert.equal(ev(/FW:\s+gr-0\/0\/0\.14/).action, 'accept');
  assert.equal(classifyAction('accept'), 'allowed');
});

// ---------------------------------------------------------------------------
// 6. The 5-tuple, and the absences inside it
// ---------------------------------------------------------------------------

test('the packet-filter tail yields a real 5-tuple', () => {
  const e = ev(/FW:\s+gr-0\/0\/0\.14/);
  assert.equal(e.srcIp, '127.0.0.1');
  assert.equal(e.dstIp, '89.160.20.112');
  assert.equal(e.srcPort, 49153);
  assert.equal(e.dstPort, 49153);
  assert.equal(e.protocol, 'udp');
  assert.equal(e.srcInterface, 'gr-0/0/0.14');
});

test('port 0 on a packet-filter line is NOT APPLICABLE, never port zero', () => {
  // ⛔ Storing 0 is this codebase's signature bug and would put phantom
  // port-0 traffic into every per-port rollup.
  const e = ev(/FW:\s+reth5\.175\s+A\s+pim/);
  assert.equal(e.srcPort, null);
  assert.equal(e.dstPort, null);
  assert.equal(e.protocol, 'pim');
});

test('protocol resolves across three key names and two value domains', () => {
  assert.equal(ev(/RT_FLOW_SESSION_CREATE \[/).protocol, 'icmp'); // protocol-id="1"
  assert.equal(ev(/IDP_ATTACK_LOG_EVENT/).protocol, 'tcp');       // protocol-name="TCP"
  assert.equal(ev(/CONTENT_FILTERING_BLOCKED/).protocol, 'http'); // protocol="http"
});

test('zones resolve across BOTH key spellings', () => {
  // ⛔ RT_UTM says source-zone/destination-zone; everything else says
  // source-zone-name/destination-zone-name. Reading one spelling loses the
  // zone on the other family entirely.
  assert.equal(ev(/RT_FLOW_SESSION_CREATE \[/).srcZone, 'vpn');
  assert.equal(ev(/ANTISPAM_SPAM_DETECTED_MT/).srcZone, 'trust');
  assert.equal(ev(/ANTISPAM_SPAM_DETECTED_MT/).dstZone, 'untrust');
  const withZone = claimed().filter((l) => parseJuniper(l).srcZone !== null);
  assert.equal(withZone.length, 67);
});

test('sessionId resolves across BOTH key spellings', () => {
  // ⛔ session-id-32 (older) and session-id (modern vSRX). Reading one loses
  // the id on whichever half of the fleet runs the other release — the Sophos
  // connid/con_id split in a second vendor.
  assert.equal(ev(/session-id-32="6093"/).sessionId, '6093');
  assert.equal(ev(/\ssession-id="298"/).sessionId, '298');
  assert.equal(claimed().filter((l) => parseJuniper(l).sessionId !== null).length, 38);
});

// ---------------------------------------------------------------------------
// 7. What Junos does NOT carry
// ---------------------------------------------------------------------------

test('deviceSerial is null on every line, by measurement', () => {
  // ⛔ No serial, chassis-id, model or platform field exists on ANY of the 145
  // structured-data keys. It must come from the adapter, never a log row.
  for (const l of claimed()) assert.equal(parseJuniper(l).deviceSerial, null);
});

test('countries are null on every line — Junos carries no geography', () => {
  // ⛔ Any country for a Juniper event is OURS, derived downstream by GeoIP.
  // Recording one here attributes our inference to the device.
  for (const l of claimed()) {
    const e = parseJuniper(l);
    assert.equal(e.srcCountry, null);
    assert.equal(e.dstCountry, null);
  }
});

test('ruleUuid is null, and ruleId is RT_IDP only', () => {
  // ⛔ RT_IDP's rule-name is an IDP rule; taking it elsewhere would file it as
  // a firewall policy id. ruleName may be purely numeric, which is not absent.
  assert.equal(ev(/IDP_ATTACK_LOG_EVENT/).ruleId, '3');
  assert.equal(ev(/RT_FLOW_SESSION_CREATE \[/).ruleId, null);
  for (const l of claimed()) assert.equal(parseJuniper(l).ruleUuid, null);
  assert.equal(claimed().filter((l) => parseJuniper(l).ruleId !== null).length, 9);
});

test('bytes are never summable, and absent counters stay null', () => {
  // ⛔ Junos byte counters are CUMULATIVE per session: APPTRACK emits
  // VOL_UPDATE rows carrying a running total and a CLOSE carrying the final
  // one. Summing the corpus over-counts by 2.55x — the FortiOS trap again.
  for (const l of claimed()) assert.equal(parseJuniper(l).bytesSummable, false);
  const close = ev(/APPTRACK_SESSION_CLOSE \[/);
  assert.equal(close.bytesSent, 144);
  assert.equal(close.bytesReceived, 104);
  // ⛔ Absent on every CREATE, and absent means NOT MEASURED — a session that
  // has just been created has not moved bytes yet, so 0 would be a measured
  // zero that never happened.
  const create = ev(/RT_FLOW_SESSION_CREATE \[/);
  assert.equal(create.bytesSent, null);
  assert.equal(create.bytesReceived, null);
});

test('the _LS suffix is not read as a vdom name', () => {
  // ⛔ It says THAT a logical system is in use and never WHICH one. A boolean
  // dressed as a name is worse than a gap.
  assert.equal(ev(/APPTRACK_SESSION_CLOSE_LS/).vdom, null);
});

// ---------------------------------------------------------------------------
// 8. The keys that mean different things in different families
// ---------------------------------------------------------------------------

test('url is a hostname on WEBFILTER and a MALWARE NAME on AV', () => {
  // ⛔ The single most dangerous key in this mapping.
  assert.equal(ev(/WEBFILTER_URL_BLOCKED \[/).urlHostname, 'www.baidu.com');
  const av = ev(/AV_VIRUS_DETECTED_MT \[/);
  assert.match(find(/AV_VIRUS_DETECTED_MT \[/), /url="EICAR-Test-File"/);
  assert.equal(av.urlHostname, null, 'a malware name must never enter urlHostname');
});

test('category is a URL category on WEBFILTER only', () => {
  // ⛔ On RT_SECINTEL `category="secintel"` is the feed class. Taking it there
  // files threat-feed names into the web-filtering dimension.
  assert.equal(ev(/WEBFILTER_URL_BLOCKED \[/).urlCategory, 'cat1');
  assert.match(find(/SECINTEL_ACTION_LOG/), /category="secintel"/);
  assert.equal(ev(/SECINTEL_ACTION_LOG/).urlCategory, null);
  assert.equal(ev(/RT_FLOW_SESSION_CREATE \[/).urlCategory, null);
});

test('threat severity is a word on RT_IDP and a number on RT_SECINTEL', () => {
  assert.equal(ev(/IDP_ATTACK_LOG_EVENT/).threatSeverity, 'HIGH');
  // ⛔ Two scales in one key name. Neither is mapped onto the other.
  assert.equal(ev(/SECINTEL_ACTION_LOG/).threatSeverity, '0');
});

test('threat severity is never stamped on ordinary permitted traffic', () => {
  // ⛔ `level` is the syslog severity and sits on every row. Stamping it
  // everywhere is what gave ~5.5M Fortinet rows/day a fabricated severity.
  assert.equal(ev(/RT_FLOW_SESSION_CREATE \[/).threatSeverity, null);
});

test('nested-application is preferred over the protocol-level application', () => {
  // `application` is HTTP where `nested-application` is the specific app.
  const line = find(/nested-application="FACEBOOK-SOCIALRSS"/);
  assert.match(line, /\sapplication="HTTP"/);
  assert.equal(parseJuniper(line).application, 'FACEBOOK-SOCIALRSS');
  // ⛔ BUT A SENTINEL NESTED VALUE MUST FALL THROUGH, not win. `N/A` is the
  // common case (5 of 7 lines that carry the key), and preferring it blindly
  // would blank the application on every one of them.
  const na = find(/nested-application="N\/A"\s+policy-name/);
  assert.equal(parseJuniper(na).application, 'HTTP');
});

test('UNKNOWN and N/A sentinels become null, never fake values', () => {
  const e = ev(/RT_FLOW_SESSION_CREATE \[/);
  assert.match(find(/RT_FLOW_SESSION_CREATE \[/), /application="UNKNOWN"/);
  assert.equal(e.application, null);
  assert.match(find(/RT_FLOW_SESSION_CREATE \[/), /username="N\/A"/);
  assert.equal(e.srcUser, null);
  // ⛔ `unknown-user` too — an absence the device spelled out. Left through it
  // becomes a plausible account name in user-attribution views.
  assert.match(find(/IDP_ATTACK_LOG_EVENT/), /username="unknown-user"/);
  assert.equal(ev(/IDP_ATTACK_LOG_EVENT/).srcUser, null);
  // A real username is untouched.
  assert.equal(ev(/WEBFILTER_URL_BLOCKED \[/).srcUser, 'user01');
});

// ---------------------------------------------------------------------------
// 9. Time
// ---------------------------------------------------------------------------

test('every claimed line gets an eventAt', () => {
  for (const l of claimed()) {
    const e = parseJuniper(l);
    assert.ok(e.eventAt instanceof Date, `no eventAt: ${l.slice(0, 80)}`);
    assert.ok(!Number.isNaN(e.eventAt.getTime()));
  }
});

test('a ZONED header wins over epoch-time, keeping sub-second precision', () => {
  // ⛔ epoch-time is whole seconds, so preferring it unconditionally on RT_IDP
  // discarded 193ms from a header that was already unambiguous.
  assert.equal(ev(/IDP_ATTACK_LOG_EVENT/).eventAt.toISOString(), '2020-03-02T23:13:03.193Z');
});

test('epoch-time rescues a zoneless header, and no zone is then assumed', () => {
  const e = ev(/IDP_APPDDOS_APP_ATTACK_EVENT \[/);
  assert.equal(e.eventAt.getTime(), 1319419711 * 1000);
  assert.ok(!e.fields.$eventAtZoneless, 'no zone was assumed, so nothing to flag');
});

test('an assumed zone is RECORDED, on exactly the 8 lines that need it', () => {
  // ⛔ Otherwise an assumption is indistinguishable from a stamp the device
  // actually zoned.
  const flagged = claimed().filter((l) => parseJuniper(l).fields.$eventAtZoneless === true);
  assert.equal(flagged.length, 8);
  for (const l of flagged) assert.equal(/(?:Z|[+-]\d{2}:?\d{2})\s/.test(l), false);
});

// ---------------------------------------------------------------------------
// 10. Auth, and the dispatcher
// ---------------------------------------------------------------------------

test('auth outcomes come from the MSGID, and success is not invented for sshd', () => {
  assert.equal(junosAuthOutcome('SSHD_LOGIN_FAILED'), 'failure');
  assert.equal(junosAuthOutcome('SNMPD_AUTH_FAILURE'), 'failure');
  assert.equal(junosAuthOutcome('DOT1XD_USR_AUTHENTICATED'), 'success');
  // ⛔ No successful-SSH-login event exists in the corpus, so none is mapped.
  assert.equal(junosAuthOutcome('SSHD_LOGIN_SUCCEEDED'), null);
  assert.equal(junosAuthOutcome(null), null);
});

test('parseVendorPayload dispatches Juniper and agrees with parseJuniper', () => {
  for (const l of claimed()) {
    assert.deepEqual(parseVendorPayload(l), parseJuniper(l));
  }
});

test('every claimed line reports vendor juniper and a device name', () => {
  for (const l of claimed()) {
    const e = parseJuniper(l);
    assert.equal(e.vendor, 'juniper');
    assert.ok(e.deviceName, `no deviceName: ${l.slice(0, 80)}`);
  }
});

test('the raw structured data survives on fields', () => {
  // 145 keys, most unmapped — the evidence must not be thrown away.
  const e = ev(/IDP_ATTACK_LOG_EVENT/);
  assert.equal(e.fields['rulebase-name'], 'IPS');
  assert.equal(e.fields['export-id'], '20175');
});

test('no other vendor parser claims a Junos line', () => {
  // ⛔ A vendor collision mis-parses every field after it.
  for (const l of claimed()) assert.equal(detectVendor(l), 'juniper');
});

// ---------------------------------------------------------------------------
// 11. The seam a syslog-only vendor opens
// ---------------------------------------------------------------------------

test('juniper is addable as a MONITORING-ONLY vendor, with no adapter', () => {
  // ⛔ THIS TEST REPLACES ONE THAT ASSERTED THE OPPOSITE, and the replacement
  // is the point rather than an edit. v2.234.0 shipped a verified Juniper
  // parser and `juniper` was deliberately absent from VENDOR_META, so the
  // firewall could not be ADDED AT ALL: its events were stored with
  // `device_id NULL`, it appeared only on /devices/discovered, and
  // evidenceWindow, capacityForecast and changeOutcome each excluded it by
  // their deliberate `device_id IS NOT NULL` filters. A firewall the product
  // could read and could not name. v2.236.0 closed that with a monitoring-only
  // device kind; a test asserting the gap still exists must not outlive it.
  const { VENDOR_META } = require('../components/devices/vendorMeta.js');
  const { ADAPTERS } = require('../lib/adapters');
  const { MONITORING_ONLY_METHOD } = require('../lib/monitoringOnly');
  assert.ok(VENDOR_META.juniper, 'juniper must be addable');
  assert.equal(VENDOR_META.juniper.monitoringOnly, true);
  // ⛔ AND STILL NO ADAPTER. Being addable must not come to mean being
  // collectable — the whole safety argument rests on that staying true.
  assert.equal(ADAPTERS.juniper, undefined);
  assert.deepEqual(Object.keys(VENDOR_META.juniper.accessMethods), [MONITORING_ONLY_METHOD]);
  assert.equal(detectVendor(find(/RT_FLOW_SESSION_CREATE \[/)), 'juniper');
});

test('the discovered-devices adopt link refuses to prefill an unmanageable vendor', () => {
  // ⛔ THE SEAM THAT ASYMMETRY OPENS. DeviceForm does
  // `VENDOR_META[vendor] || VENDOR_META.forcepoint`, so an unknown slug does
  // not fail — it renders the FORCEPOINT form with this firewall's address
  // already in it. Until a syslog-only vendor existed, every slug
  // detectVendor could return was also in VENDOR_META and that fallback was
  // unreachable.
  const src = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '../components/devices/DiscoveredDeviceActions.js'),
    'utf8'
  ).replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
  assert.match(src, /hasOwnProperty\.call\(VENDOR_META,\s*vendor\)/,
    'the adopt link must test VENDOR_META membership, not merely truthiness');
  assert.match(src, /vendor:\s*manageable\s*\?\s*vendor\s*:\s*''/,
    'an unmanageable vendor must be dropped from the prefill');
  // ⛔ And the operator must be TOLD, or a silently missing prefill reads as a
  // bug in the detection rather than a stated limit.
  assert.match(src, /cannot manage \$\{vendor\} devices yet/);
});

test('DeviceForm still carries the silent fallback this guard compensates for', () => {
  // ⛔ A NAMED RESIDUAL, not a claim of coverage: a hand-typed
  // /devices/new?vendor=juniper still renders the Forcepoint form. The guard
  // above closes the only path the product itself offers. If DeviceForm is
  // ever made to refuse an unknown vendor outright, delete this test in the
  // same commit — a test asserting a defect still exists must not outlive it.
  const src = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '../components/devices/DeviceForm.js'), 'utf8'
  );
  assert.match(src, /VENDOR_META\[vendor\] \|\| VENDOR_META\.forcepoint/);
});
