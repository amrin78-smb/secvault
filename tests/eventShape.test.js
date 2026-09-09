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
    auth_outcome:
      'this fixture is a utm row, not a VPN authentication — auth_outcome is ' +
      'deliberately null outside log_class=vpn, and the GlobalProtect tests ' +
      'below cover the populated case end to end',
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

describe('⛔ a dropped raw line stores NULL, never an empty string', () => {
  // An empty-string sentinel would be invisible to `message IS NULL` and
  // indistinguishable from a genuinely empty log line — the same fabricated
  // value this codebase bans everywhere else. flattenRow coerced null to ''
  // while the column was NOT NULL; the column is nullable now.
  it('passes a dropped message through as null', () => {
    const raw = { line: FORTI_LINE, sourceIp: '10.0.0.1', receivedAt: RECEIVED };
    const frame = parseSyslogLine(raw.line, raw.receivedAt);
    const e = buildEvent(raw, frame, parseVendorPayload(frame.message), null, 'none');
    const row = flattenRow(e);
    const i = COLUMNS.indexOf('message');
    assert.equal(row[i], null, 'must be SQL NULL, not an empty string');
  });

  it('still stores a kept message as its real text', () => {
    const raw = { line: FORTI_LINE, sourceIp: '10.0.0.1', receivedAt: RECEIVED };
    const frame = parseSyslogLine(raw.line, raw.receivedAt);
    const e = buildEvent(raw, frame, parseVendorPayload(frame.message), null, 'all');
    const row = flattenRow(e);
    const i = COLUMNS.indexOf('message');
    assert.ok(typeof row[i] === 'string' && row[i].length > 0);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// INET coercion — added 2026-09-09 after a live bug sweep
// ─────────────────────────────────────────────────────────────────────────

const { toInetOrNull } = require('../lib/syslog/eventStore');

it('⛔ a MAC address is NOT an IPv6 address', () => {
  // The old guard was /^[0-9a-fA-F:]+$/, which a MAC and a bare clock fragment
  // both satisfy. PostgreSQL rejects them — verified live:
  //   SELECT '00:11:22:33:44:55'::inet;  -- ERROR: invalid input syntax
  // and because rows insert in chunks, ONE such value aborted its whole
  // 500-row chunk and then stranded the spool file permanently. Both shapes
  // are exactly what a positional mis-parse produces.
  for (const v of ['00:11:22:33:44:55', '12:34:56', 'ffffff:1', 'a:::b', '1:2:3:4:5:6:7:8:9']) {
    assert.equal(toInetOrNull(v), null, v);
  }
});

it('a zone index is rejected — valid to the kernel, invalid to INET', () => {
  assert.equal(toInetOrNull('fe80::1%eth0'), null);
});

it('real addresses still pass through unchanged', () => {
  for (const v of [
    '192.168.1.1', '::1', 'fe80::1', '2001:db8::8a2e:370:7334',
    '::ffff:192.0.2.1', '1:2:3:4:5:6:7:8',
  ]) {
    assert.equal(toInetOrNull(v), v, v);
  }
});

it('malformed IPv4 is null rather than a coerced guess', () => {
  for (const v of ['999.1.1.1', '1.2.3', 'not-an-ip', 'N/A', '', null, undefined]) {
    assert.equal(toInetOrNull(v), null, String(v));
  }
});

// ─────────────────────────────────────────────────────────────────────────
// VPN auth outcome — the three-hop guard, applied to a new column
// ─────────────────────────────────────────────────────────────────────────
//
// A field must survive parser -> buildEvent -> eventStore COLUMNS/flattenRow.
// Miss one hop and nothing throws; the column just stores NULL, which is
// indistinguishable from "the device never sent it". That is precisely how
// 360,025 events were written with eight null columns on 2026-09-08.

const { parseSyslogLine: parseFrame } = require('../lib/syslog/syslogParser');
const { parseVendorPayload: parsePayload } = require('../lib/syslog/vendorParsers');
const { COLUMNS: STORE_COLUMNS, flattenRow: toRow } = require('../lib/syslog/eventStore');

// A real GlobalProtect authentication failure, in the exact shape captured
// live from TUM-FW-ACTIVE.
const GP_AUTH_FAIL =
  '1,2026/09/09 08:03:37,023001020713,GLOBALPROTECT,0,2817,2026/09/09 08:03:37,vsys1,' +
  'gateway-auth,login,,,jdoe,BG,,93.152.210.31,0.0.0.0,0.0.0.0,0.0.0.0,,,,,,1,,,' +
  '"Authentication failed: Invalid username or password",failure,,0,,0,GW';

// The pre-login page fetch that carries status=success and is NOT a login.
const GP_PRELOGIN =
  '1,2026/09/09 08:03:37,023001020713,GLOBALPROTECT,0,2817,2026/09/09 08:03:37,vsys1,' +
  'portal-prelogin,before-login,,,,US,,145.79.182.14,0.0.0.0,0.0.0.0,0.0.0.0,,,Browser,' +
  'Browser,,1,,,,success,,0,,0,SSLVPN-PORTAL';

function storeRow(line) {
  const raw = { line, sourceIp: '1.2.3.4', receivedAt: new Date('2026-09-09T01:03:37Z') };
  const frame = parseFrame(line, raw.receivedAt);
  const payload = parsePayload(frame.message);
  const row = toRow(buildEvent(raw, frame, payload, null, 'security'));
  const get = (c) => row[STORE_COLUMNS.indexOf(c)];
  return { get };
}

it('⛔ a GlobalProtect auth failure survives all three hops', () => {
  const r = storeRow(GP_AUTH_FAIL);
  assert.equal(r.get('auth_outcome'), 'failure');
  // These four were ALL null before the GlobalProtect map existed, because
  // PAN_COMMON was gated off for this log type and GP uses different indices.
  assert.equal(r.get('src_country'), 'BG');
  assert.equal(r.get('src_user'), 'jdoe');
  assert.equal(r.get('src_ip'), '93.152.210.31');
  assert.equal(r.get('log_class'), 'vpn');
  // ⛔ index 4 is the Threat/Content type ("0") on GP rows; the real subtype is
  // the Event ID at index 8.
  assert.equal(r.get('log_subtype'), 'gateway-auth');
});

it('⛔ a pre-login page fetch is NOT a successful login', () => {
  // THE trap. PAN-OS writes status=success on portal-prelogin rows — the portal
  // serving its page to an anonymous browser, 3,399 of them in three hours.
  // Reading status without gating on the event id inflates "successful logins"
  // by roughly an order of magnitude. The tell is the absent username.
  const r = storeRow(GP_PRELOGIN);
  assert.equal(r.get('auth_outcome'), null, 'pre-login must not count as a login');
  assert.equal(r.get('src_user'), null);
  // It is still stored, and still located — it just is not an authentication.
  assert.equal(r.get('src_country'), 'US');
  assert.equal(r.get('log_class'), 'vpn');
});

it('auth_outcome is a real stored column, not just a parsed field', () => {
  // Guards the hop that has been missed before: the column must exist in
  // COLUMNS, or flattenRow silently drops the value.
  assert.ok(STORE_COLUMNS.includes('auth_outcome'));
});
