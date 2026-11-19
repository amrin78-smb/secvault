'use strict';
// Sophos SFOS syslog parsing, pinned against REAL CAPTURED LOG LINES.
//
// ⛔ Every fixture is a verbatim line from a live SFOS 22.0.3 MR-3-Build576
// appliance (2026-11-19), not written from vendor documentation. CLAUDE.md's
// rule is "verify all field names against live responses before writing any
// parser — documentation lies", and SFOS is the sharpest case of that yet:
// the key=value format every published Sophos field reference describes is
// marked "(legacy)" by SFOS 22 itself, which warns it "won't support the new
// firewall features in future versions".
//
// ⛔ THE CROSS-FORMAT TEST AT THE BOTTOM IS THE LOAD-BEARING ONE. Both formats
// were captured SIMULTANEOUSLY from the same events, so a mapping that is
// wrong in one format shows up as a disagreement between two renderings of one
// packet. It found two real bugs that reading either format alone did not.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  detectVendor,
  parseVendorPayload,
  parseSophos,
  classifySophos,
  parseKeyValueSpanning,
  parseKeyValue,
  sophosZoneOffset,
} = require('../lib/syslog/vendorParsers');
const { classifyAction } = require('../lib/syslog/actions');
const { LEGACY, STANDARD, RENAMED } = require('./fixtures/sophosSyslog');

const legacyLines = Object.values(LEGACY);
const standardLines = Object.values(STANDARD);
const allLines = [...legacyLines, ...standardLines];

describe('Sophos — detection', () => {
  it('claims every captured line, in both formats', () => {
    for (const l of allLines) assert.equal(detectVendor(l), 'sophos');
    assert.ok(legacyLines.length >= 20 && standardLines.length >= 20);
  });

  // ⛔ The first key follows the PRI with NO separator (`<30>device="..."`), so
  // an anchor requiring preceding whitespace never matches it. A survey of this
  // very capture once reported `device` as absent from 3,168 lines that all
  // carry it, for exactly that reason.
  it('matches a key that sits immediately after the PRI', () => {
    const l = legacyLines[0];
    assert.match(l, /^<\d+>device=/);
    assert.equal(detectVendor(l), 'sophos');
  });

  // ⛔ FortiOS is also key=value. An anchor loose enough to claim a Fortinet
  // line would mis-parse every field on it, silently.
  it('does not claim a Fortinet line', () => {
    const forti = 'date=2026-09-08 time=10:00:00 devname="FW" devid="FG200ETK18912640" '
      + 'logid="0000000013" type="traffic" subtype="forward" srcip=10.0.0.1';
    assert.equal(detectVendor(forti), 'fortinet');
  });

  it('does not claim a line that merely contains a log_id', () => {
    assert.equal(detectVendor('something log_id="010101600001" but no log type'), null);
  });

  it('routes through parseVendorPayload', () => {
    assert.equal(parseVendorPayload(legacyLines[0]).vendor, 'sophos');
    assert.equal(parseVendorPayload(standardLines[0]).vendor, 'sophos');
  });
});

describe('Sophos — the key=value grammar is NOT FortiOS\'s', () => {
  // ⛔ 2,102 of 3,168 captured legacy lines carry `ether_type=IPv4 (0x0800)`:
  // an UNQUOTED value containing a space. parseKeyValue's bare-value branch is
  // `[^\s]*`, so it silently drops `(0x0800)`.
  it('keeps an unquoted value that contains a space', () => {
    const line = 'a=1 ether_type=IPv4 (0x0800) bridge_name="" b=2';
    assert.equal(parseKeyValueSpanning(line).ether_type, 'IPv4 (0x0800)');
    assert.equal(parseKeyValue(line).ether_type, 'IPv4', 'the Fortinet grammar truncates — this is why a second one exists');
  });

  it('keeps it on every real captured line too', () => {
    for (const l of allLines) {
      const v = parseKeyValueSpanning(l).ether_type;
      if (v) assert.match(v, /^\w+ \(0x[0-9a-f]{4}\)$/i);
    }
  });

  it('reads a bare empty value as absent, not as the next token', () => {
    const f = parseKeyValueSpanning('src_mac= dst_mac= src_ip=1.2.3.4');
    assert.equal(f.src_mac, null);
    assert.equal(f.dst_mac, null);
    assert.equal(f.src_ip, '1.2.3.4');
  });

  it('tolerates runs of whitespace between pairs', () => {
    const f = parseKeyValueSpanning('packets_sent=2  packets_received=2');
    assert.equal(f.packets_sent, '2');
    assert.equal(f.packets_received, '2');
  });

  it('never throws and never hangs on malformed input', () => {
    for (const bad of ['', '=', 'a=', '=1', 'a==b', '<30>', 'a=b=c d=e']) {
      assert.doesNotThrow(() => parseKeyValueSpanning(bad));
    }
    assert.deepEqual(parseKeyValueSpanning(null), {});
  });
});

describe('Sophos — device identity inverts between the formats', () => {
  // ⛔ legacy  device="<identity>"      device_name="SF01V"  (the MODEL)
  //    standard device_name="<identity>" device_model="SF01V"
  // A parser keyed on `device_name` returns the model on one and the appliance
  // on the other. Both are plausible strings; neither errors.
  it('reads the appliance identity from the right key in each format', () => {
    const l = parseSophos(LEGACY['010101600001']);
    const s = parseSophos(STANDARD['010101600001']);
    assert.equal(l.deviceName, s.deviceName);
    assert.notEqual(l.deviceName, 'SF01V', 'legacy device_name is the MODEL, not the appliance');
    assert.equal(parseKeyValueSpanning(LEGACY['010101600001']).device_name, 'SF01V');
  });

  // ⛔ RESOLVED BY EXPERIMENT. SFOS defaults the hostname to the serial, so the
  // appliance reported one string for both and reading the capture could not
  // separate them. It was renamed and re-captured; the value followed the
  // hostname in BOTH formats. That is why deviceSerial is null by measurement
  // rather than by caution — SFOS syslog carries no serial at all, and one has
  // to come from the SSH transport.
  it('reports the HOSTNAME, proven by renaming the appliance', () => {
    for (const fmt of ['legacy', 'standard']) {
      const e = parseSophos(RENAMED[fmt]);
      assert.equal(e.deviceName, 'V01001C6CT6BFD5-test', `${fmt} did not follow the rename`);
      assert.equal(e.deviceSerial, null);
    }
  });

  // ⛔ The same appliance reported SF01V for the first 76 minutes of capture and
  // SFVH thereafter, across a reboot, with no model change made. Nothing may
  // key on it, which is why it is left in `fields` and never promoted.
  it('does not promote the unstable model string to a normalized field', () => {
    const early = parseKeyValueSpanning(LEGACY['010101600001']).device_name;
    const late = parseKeyValueSpanning(RENAMED.legacy).device_name;
    assert.notEqual(early, late, 'the capture should show the model changing');
    const e = parseSophos(RENAMED.legacy);
    for (const [k, v] of Object.entries(e)) {
      if (k === 'fields') continue;
      assert.notEqual(v, early, `${k} carries the model string`);
      assert.notEqual(v, late, `${k} carries the model string`);
    }
  });

  // ⛔ The fields actually NAMED for a serial carry the literal string NULL on
  // 100% of captured lines — a present field with no value in it.
  it('never stores the literal string NULL as an identity', () => {
    for (const l of allLines) {
      const e = parseSophos(l);
      assert.notEqual(e.deviceName, 'NULL');
      assert.equal(e.deviceSerial, null);
    }
  });
});

describe('Sophos — no fabricated values anywhere', () => {
  it('maps every null sentinel to null across every captured line', () => {
    const sentinels = new Set(['NULL', 'None', 'N/A', '']);
    for (const l of allLines) {
      const e = parseSophos(l);
      for (const [k, v] of Object.entries(e)) {
        if (k === 'fields') continue;
        if (typeof v === 'string') assert.ok(!sentinels.has(v), `${k} = ${JSON.stringify(v)}`);
      }
    }
  });

  // ⛔ On the SAME event legacy writes `fw_rule_id=0` where standard writes
  // `fw_rule_id="N/A"` — which is what proves 0 is a sentinel and not a rule
  // numbered zero. Storing it would attribute real traffic to a rule that does
  // not exist.
  it('treats fw_rule_id 0 and N/A alike as "no rule matched"', () => {
    const l = parseSophos(LEGACY['010202601001']);   // Invalid Traffic / Denied
    const s = parseSophos(STANDARD['010202601001']);
    assert.equal(parseKeyValueSpanning(LEGACY['010202601001']).fw_rule_id, '0');
    assert.equal(parseKeyValueSpanning(STANDARD['010202601001']).fw_rule_id, 'N/A');
    assert.equal(l.ruleId, null);
    assert.equal(s.ruleId, null);
  });
});

describe('Sophos — session counters', () => {
  const connEventOf = (e) => e.fields.connevent || e.fields.con_event || null;

  // ⛔ A session emits TWO rows sharing con_id. Of 1,031 captured legacy Start
  // rows ALL carry sent_bytes=0; of 1,033 standard Start rows NOT ONE carries a
  // bytes field. Legacy's zeros are the hit_count DEFAULT 0 bug over syslog.
  it('reports no counters at all on a session-start row', () => {
    for (const l of allLines) {
      const e = parseSophos(l);
      if (connEventOf(e) !== 'Start') continue;
      assert.equal(e.bytesSent, null);
      assert.equal(e.bytesReceived, null);
      assert.equal(e.bytesSummable, false);
    }
  });

  // ⛔ A third state exists — Interim, a running mid-session counter. Summing
  // anything but Stop double-counts, which is the FortiOS cumulative-counter
  // trap in a different shape.
  it('marks only a session END summable', () => {
    for (const l of allLines) {
      const e = parseSophos(l);
      assert.equal(e.bytesSummable, connEventOf(e) === 'Stop');
    }
  });
});

describe('Sophos — the traffic verdict is in log_subtype, not status', () => {
  // ⛔ Legacy `status` carries Allow/Deny; STANDARD's carries only
  // Successful/Renew. Keying on `status` leaves every standard row with a null
  // action, and log_hit — decision rule 2 of the CVE priority tree, above
  // CVSS 9.0 — could then never fire for this vendor.
  it('finds the same verdict in both formats', () => {
    const l = parseSophos(LEGACY['010101600001']);
    const s = parseSophos(STANDARD['010101600001']);
    assert.equal(l.action, 'allowed');
    assert.equal(s.action, 'allowed');
    assert.equal(parseKeyValueSpanning(STANDARD['010101600001']).status, undefined,
      'the standard format carries no allow/deny in `status` — that is the whole point');
  });

  it('emits a deny verdict in both formats', () => {
    assert.equal(parseSophos(LEGACY['010102600002']).action, 'denied');
    assert.equal(parseSophos(STANDARD['010102600002']).action, 'denied');
  });

  // ⛔ log_subtype is ALSO Usage, Admin, System and Virus. Emitting those as
  // actions would put a verb in syslog_events.action that is in neither of
  // actions.js's sets — neither allowed nor blocked.
  it('never emits an action that cannot be classified', () => {
    for (const l of allLines) {
      const e = parseSophos(l);
      if (e.action === null) continue;
      assert.notEqual(classifyAction(e.action), 'unknown', `unclassifiable action ${e.action}`);
    }
  });

  it('emits no action on a non-verdict row', () => {
    const health = parseSophos(LEGACY['127626618031']);   // System Health / CPU / Usage
    assert.equal(health.logSubtype, 'Usage');
    assert.equal(health.action, null);
  });
});

describe('Sophos — timestamps', () => {
  it('reads an event time from every captured line, in both formats', () => {
    for (const l of allLines) {
      const e = parseSophos(l);
      assert.ok(e.eventAt instanceof Date && !Number.isNaN(e.eventAt.getTime()));
    }
  });

  // ⛔ The legacy format splits the time across date/time/timezone and the zone
  // is a NAME, not an offset. Abbreviations are ambiguous worldwide (IST is
  // Irish, Indian AND Israeli standard time), so an unresolvable zone must
  // leave eventAt null rather than anchor the time somewhere invented.
  it('resolves only zones whose meaning is certain', () => {
    assert.equal(sophosZoneOffset('GMT'), '+00:00');
    assert.equal(sophosZoneOffset('UTC'), '+00:00');
    assert.equal(sophosZoneOffset('+0700'), '+07:00');
    assert.equal(sophosZoneOffset('+07:00'), '+07:00');
    for (const ambiguous of ['IST', 'CST', 'BST', 'ICT', '', 'nonsense']) {
      assert.equal(sophosZoneOffset(ambiguous), null, `${ambiguous} must not be guessed`);
    }
  });

  it('leaves eventAt null rather than anchoring an unresolvable zone', () => {
    const line = LEGACY['010101600001'].replace('timezone="GMT"', 'timezone="IST"');
    assert.equal(parseSophos(line).eventAt, null);
  });
});

describe('Sophos — log_class', () => {
  it('maps only the classes actually observed', () => {
    assert.equal(classifySophos('Firewall'), 'traffic');
    assert.equal(classifySophos('Anti-Virus'), 'utm');
    assert.equal(classifySophos('Content Filtering'), 'utm');
    assert.equal(classifySophos('Event'), 'event');
    assert.equal(classifySophos('System Health'), 'system');
  });

  // ⛔ IDP, ATP, VPN and authentication are real SFOS log types that the
  // verifying capture contains ZERO rows of — the lab appliance has no IPS
  // signature database at all. They are UNVERIFIED, not absent, and mapping
  // them from documentation is what this file's header forbids.
  it('returns null for a type no capture has verified', () => {
    for (const unseen of ['IDP', 'ATP', 'VPN', 'Authentication', 'SSLVPN', '', 'nonsense']) {
      assert.equal(classifySophos(unseen), null);
    }
    assert.equal(classifySophos(null), null);
  });

  it('classifies every captured line', () => {
    for (const l of allLines) assert.notEqual(parseSophos(l).logClass, null);
  });
});

describe('Sophos — the two formats describe the same event', () => {
  // ⛔ THIS IS THE TEST THAT EARNS ITS KEEP. Both captures are the same packets
  // rendered two ways, so any field whose mapping is wrong in ONE format
  // disagrees here. It caught `connid` vs `con_id` (the legacy format is
  // inconsistent with ITSELF — Firewall rows say `connid`, Content Filtering
  // rows say `con_id`) and `category` vs `http_category`.
  const shared = Object.keys(LEGACY).filter((id) => STANDARD[id]);

  it('pairs most log_ids across the two captures', () => {
    assert.ok(shared.length >= 20, `only ${shared.length} paired`);
  });

  const MUST_AGREE = ['vendor', 'deviceName', 'logType', 'logClass', 'logSubtype',
    'level', 'action', 'srcIp', 'dstIp', 'srcPort', 'dstPort', 'protocol',
    'srcInterface', 'dstInterface', 'ruleId', 'ruleName', 'sessionId',
    'urlCategory', 'urlHostname', 'threatName', 'application'];

  it('agrees on every field that is not a known format difference', () => {
    for (const id of shared) {
      const l = parseSophos(LEGACY[id]);
      const s = parseSophos(STANDARD[id]);
      for (const f of MUST_AGREE) {
        assert.deepEqual(l[f], s[f], `log_id ${id} field ${f}: ${JSON.stringify(l[f])} vs ${JSON.stringify(s[f])}`);
      }
    }
  });

  // ⛔ Regression for the two bugs the pairing found. Named explicitly because
  // a count alone cannot say WHICH fields were fixed.
  it('reads the session id from both legacy spellings', () => {
    const cf = parseSophos(LEGACY['050902616002']);       // Content Filtering
    assert.equal(parseKeyValueSpanning(LEGACY['050902616002']).connid, undefined,
      'this legacy row spells it con_id, not connid — that is the bug');
    assert.notEqual(cf.sessionId, null);
  });

  it('reads the web category from both spellings', () => {
    assert.equal(parseSophos(LEGACY['050902616002']).urlCategory, 'Gambling');
    assert.equal(parseSophos(STANDARD['050902616002']).urlCategory, 'Gambling');
  });
});

describe('Sophos — what each format loses', () => {
  // ⛔ NEITHER FORMAT DOMINATES, and the adapter must not pretend one does.
  it('legacy omits zones on a Content Filtering row; standard carries them', () => {
    assert.equal(parseSophos(LEGACY['050902616002']).srcZone, null);
    assert.equal(parseSophos(STANDARD['050902616002']).srcZone, 'DMZ');
  });

  // ⛔ The mirror image: standard's omit-empty design cannot express a MEASURED
  // zero. `recv_bytes=0` on a Stop row is a completed session that received
  // nothing; standard drops the field, so a real zero and an uncounted field
  // become indistinguishable.
  it('standard cannot express a measured zero that legacy states outright', () => {
    const line = LEGACY['010101600001'];
    const f = parseKeyValueSpanning(line);
    assert.ok('recv_bytes' in f, 'legacy states the counter even when it is zero');
  });
});
