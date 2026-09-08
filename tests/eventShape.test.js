'use strict';
// Guards the hop that silently ate eight columns on 2026-09-08.
//
// A field has to survive THREE places to reach the database:
//   vendorParsers.js  ->  eventShape.buildEvent()  ->  eventStore COLUMNS/flattenRow
// Miss one and nothing throws — the column just stores NULL, which is
// indistinguishable from "the device never sent it". The parser and the store
// were both updated for the new fields; this middle hop was not, and 360,025
// events were written with every new column null before the gap was spotted.
//
// ⛔ The last test in this file is the important one: it walks a REAL captured
// log line end to end and asserts that every column the store persists is
// actually reachable from the parser. Adding a column without wiring the hop
// fails there, in the build, instead of in production three hours later.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { buildEvent } = require('../lib/syslog/eventShape');
const { parseSyslogLine } = require('../lib/syslog/syslogParser');
const { parseVendorPayload } = require('../lib/syslog/vendorParsers');
const { COLUMNS, flattenRow } = require('../lib/syslog/eventStore');

const RECEIVED = new Date('2026-09-08T09:45:33.000Z');

// A real FortiOS utm/app-ctrl line: carries user, both countries, category and
// hostname, so it exercises every field added on 2026-09-08 bar the PAN-only
// threat pair.
const FORTI_LINE =
  '<189>date=2026-09-08 time=16:45:33 devname="FG80F-TSR_HQ" devid="FGT80FTK21025346" ' +
  'eventtime=1788860733356620909 tz="+0700" logid="1059028704" type="utm" ' +
  'subtype="app-ctrl" eventtype="signature" level="information" vd="root" appid=15895 ' +
  'user="tsr0017" authserver="tsr0017" srcip=10.248.70.50 srccountry="Reserved" ' +
  'dstip=155.102.13.26 dstcountry="Thailand" srcport=61206 dstport=443 ' +
  'srcintf="a" dstintf="wan2" proto=6 service="SSL" policyid=21 ' +
  'poluuid="3fe7277a-f578-51ef-7626-90e881c6337b" policyname="Allow_Web" ' +
  'sessionid=122822417 action="pass" appcat="Network.Service" app="SSL" ' +
  'hostname="sausage-global-cdn.sausage.xd.com" msg="Network.Service: SSL"';

function shapeOf(line, sourceIp, deviceId) {
  const raw = { line, sourceIp: sourceIp || '10.248.65.1', receivedAt: RECEIVED };
  const frame = parseSyslogLine(raw.line, raw.receivedAt);
  return buildEvent(raw, frame, parseVendorPayload(frame.message), deviceId || null);
}

describe('eventShape: the vendor fields reach the event', () => {
  it('carries every field added on 2026-09-08 through from the parser', () => {
    const e = shapeOf(FORTI_LINE);
    assert.equal(e.srcUser, 'tsr0017');
    assert.equal(e.srcCountry, 'Reserved');
    assert.equal(e.dstCountry, 'Thailand');
    assert.equal(e.urlCategory, 'Network.Service');
    assert.equal(e.urlHostname, 'sausage-global-cdn.sausage.xd.com');
    assert.equal(e.logSubtype, 'app-ctrl');
    assert.equal(e.threatSeverity, 'information');
  });

  it('still carries the original fields', () => {
    const e = shapeOf(FORTI_LINE);
    assert.equal(e.vendor, 'fortinet');
    assert.equal(e.action, 'pass');
    assert.equal(e.srcIp, '10.248.70.50');
    assert.equal(e.dstPort, 443);
    assert.equal(e.ruleName, 'Allow_Web');
    assert.equal(e.ruleId, '21');
    assert.equal(e.logClass, 'utm');
  });
});

describe('eventShape: an unparsed line is still a storable event', () => {
  const JUNK = '<13>this is not a firewall log at all';

  it('⛔ keeps the raw line and leaves every vendor field null', () => {
    // A line we could not parse is still evidence. Dropping it would make the
    // fleet look quieter than it is.
    const e = shapeOf(JUNK);
    assert.ok(e.message.length > 0, 'the raw line must survive');
    assert.equal(e.vendor, null, 'no guessed vendor — there is no "generic" bucket');
    for (const k of [
      'action', 'srcIp', 'dstIp', 'application', 'ruleName', 'logClass',
      'srcUser', 'srcCountry', 'dstCountry', 'urlCategory', 'urlHostname',
      'threatName', 'threatSeverity', 'logSubtype',
    ]) {
      assert.equal(e[k], null, `${k} must be null, never a substitute`);
    }
  });

  it('⛔ bytesSummable is false, never null, when nothing parsed', () => {
    // The column is NOT NULL and "we could not tell" must resolve to "do not
    // sum it" — the safe direction. A null here would fail the insert outright.
    assert.equal(shapeOf(JUNK).bytesSummable, false);
  });

  it('an unmatched sender stores a null device rather than being dropped', () => {
    const e = shapeOf(FORTI_LINE, '203.0.113.9', null);
    assert.equal(e.deviceId, null);
    assert.equal(e.sourceIp, '203.0.113.9');
    assert.equal(e.vendor, 'fortinet', 'still fully parsed');
  });

  it('passes a matched device through unchanged', () => {
    const e = shapeOf(FORTI_LINE, '10.248.65.1', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    assert.equal(e.deviceId, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
  });

  it('never throws on a malformed frame', () => {
    for (const line of ['', '<>', '<999>', 'x'.repeat(5000)]) {
      assert.doesNotThrow(() => shapeOf(line));
    }
  });
});

describe('⛔ every stored column is reachable from a real log line', () => {
  // THE regression guard. Add a column to eventStore.COLUMNS without wiring
  // eventShape, and this fails — instead of silently writing NULLs forever.
  //
  // Columns legitimately absent from a Fortinet utm line are listed with the
  // reason. Anything NOT on that list must be populated by the fixture, which
  // forces a new column to be either genuinely wired or consciously excused.
  const EXPECTED_NULL = {
    src_zone: 'FortiOS logs identify by interface; it has no zone field',
    dst_zone: 'same',
    threat_name: 'app-ctrl is not an attack or a virus, so there is no name',
    bytes_sent: 'a utm row carries no byte counters',
    bytes_received: 'same',
    device_id: 'the fixture deliberately passes an unmatched sender',
    program: 'FortiOS opens with the PRI then bare key=value — there is no syslog tag',
  };

  it('populates every column that this vendor line can populate', () => {
    const e = shapeOf(FORTI_LINE);
    const row = flattenRow(e);
    assert.equal(row.length, COLUMNS.length, 'COLUMNS and flattenRow are positional');

    const missing = [];
    COLUMNS.forEach((col, i) => {
      if (EXPECTED_NULL[col]) return;
      const val = row[i];
      if (val === null || val === undefined) missing.push(col);
    });
    assert.deepEqual(
      missing, [],
      'these columns stored NULL from a line that carries them — the ' +
      'parser -> eventShape -> eventStore hop is broken for them'
    );
  });

  it('the excused list stays honest', () => {
    // Guards the guard: an excuse for a column that no longer exists means the
    // list has drifted and may now be excusing the wrong thing.
    for (const col of Object.keys(EXPECTED_NULL)) {
      assert.ok(COLUMNS.includes(col), `${col} is excused but is not a column`);
    }
  });
});

describe('⛔ raw-line retention: keeps it exactly where investigations look', () => {
  // `message` is 755 of 1,122 bytes per row on the live fleet — 67% of the
  // whole database — and for a fully parsed event every field in it already
  // has its own column. Dropping it for ordinary allowed traffic is what makes
  // 30-day retention fit. The exceptions below are the entire point, and the
  // compressed archive keeps EVERY line regardless of any of this.
  const { shouldKeepRawMessage } = require('../lib/syslog/eventShape');

  it('drops it only for parsed, allowed, ordinary traffic', () => {
    assert.equal(
      shouldKeepRawMessage({ vendor: 'fortinet', logClass: 'traffic', action: 'accept' }, 'security'),
      false
    );
  });

  it('⛔ ALWAYS keeps it for a line nothing could parse', () => {
    // If we did not understand it, the raw text is the only record of what
    // arrived. This is the one exception that must never be optimised away.
    assert.equal(shouldKeepRawMessage({ vendor: null, logClass: null }, 'security'), true);
    assert.equal(shouldKeepRawMessage({}, 'security'), true);
    assert.equal(shouldKeepRawMessage(null, 'security'), true);
  });

  it('keeps it for denied traffic, whatever the vendor calls the refusal', () => {
    for (const a of ['deny', 'drop', 'block', 'block-url', 'reset-both', 'RESET-CLIENT']) {
      assert.equal(
        shouldKeepRawMessage({ vendor: 'paloalto', logClass: 'traffic', action: a }, 'security'),
        true, a
      );
    }
  });

  it('keeps it for every non-traffic class', () => {
    for (const c of ['threat', 'vpn', 'system', 'utm', 'event']) {
      assert.equal(shouldKeepRawMessage({ vendor: 'fortinet', logClass: c }, 'security'), true, c);
    }
  });

  it('keeps it when the class could not be determined', () => {
    // An unclassified event is one we understood less than we thought.
    assert.equal(
      shouldKeepRawMessage({ vendor: 'fortinet', logClass: null, action: 'accept' }, 'security'),
      true
    );
  });

  it('honours the all and none modes', () => {
    const allowed = { vendor: 'fortinet', logClass: 'traffic', action: 'accept' };
    const unparsed = { vendor: null, logClass: null };
    assert.equal(shouldKeepRawMessage(allowed, 'all'), true);
    assert.equal(shouldKeepRawMessage(unparsed, 'none'), false, 'none means none');
  });

  it('⛔ falls back to `security` on an unrecognised mode, never to `none`', () => {
    // A typo in the env var must not silently start discarding evidence.
    for (const bad of ['', 'off', 'SECURITY!', undefined, null, 42, {}]) {
      assert.equal(
        shouldKeepRawMessage({ vendor: null, logClass: null }, bad), true,
        `mode=${JSON.stringify(bad)} must still keep an unparsed line`
      );
    }
  });

  it('buildEvent applies the policy end to end', () => {
    const raw = { line: FORTI_LINE, sourceIp: '10.248.65.1', receivedAt: RECEIVED };
    const frame = parseSyslogLine(raw.line, raw.receivedAt);
    const payload = parseVendorPayload(frame.message);
    // This fixture is utm, so it is kept under the security policy.
    assert.ok(buildEvent(raw, frame, payload, null, 'security').message);
    assert.equal(buildEvent(raw, frame, payload, null, 'none').message, null);
    assert.ok(buildEvent(raw, frame, payload, null, 'all').message);
  });
});
