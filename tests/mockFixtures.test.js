'use strict';

// tests/mockFixtures.test.js
//
// Pins scripts/seedMockFleet.js and scripts/mockSyslog.js — the staging mock
// environment.
//
// ⛔ THE GENERATOR MUST BE CHECKED AGAINST THE REAL PARSER, NOT READ. The first
// draft of `paloAltoLine` produced output `detectVendor()` returned null for,
// on two counts: an ISO `YYYY-MM-DD` receive time where `PALOALTO_RE` requires
// SLASHES, and no valid RFC 3164 header, so the anchored regex never saw the
// CSV at the start of the message. Both lines LOOKED like PAN-OS logs.
//
// ⛔ AND THE FAILURE WOULD HAVE BEEN SILENT. The collector still STORES an
// unattributed event — correctly, since an unmatched sender is still evidence —
// so nothing errors. The mock fleet would simply have appeared to produce no
// Palo Alto traffic at all, and the obvious conclusion would have been that the
// collector or the rollups were broken.

const { describe, it, test } = require('node:test');
const assert = require('node:assert/strict');

const { parseSyslogLine } = require('../lib/syslog/syslogParser');
const vendorParsers = require('../lib/syslog/vendorParsers');
const { fortinetLine, paloAltoLine, parseArgs, SENDERS } = require('../scripts/mockSyslog');
const { assertSafeTarget, DEVICES, NAME_PREFIX } = require('../scripts/seedMockFleet');

const NOW = new Date('2026-10-01T16:30:00+07:00');

function vendorOf(raw) {
  const frame = parseSyslogLine(raw, NOW);
  return vendorParsers.detectVendor((frame && frame.message) || raw);
}

describe('⛔ mock syslog is parsed by the REAL parsers, not merely plausible', () => {
  it('every generated Fortinet line detects as fortinet', () => {
    for (let i = 0; i < 50; i++) {
      assert.equal(vendorOf(fortinetLine(NOW)), 'fortinet');
    }
  });

  it('every generated Palo Alto line detects as paloalto', () => {
    // The regression. Two format details decide this and neither is visible by
    // reading the line: slashes in the receive time, and an RFC 3164 header so
    // the anchored regex sees the CSV at the start of the MESSAGE.
    for (let i = 0; i < 50; i++) {
      assert.equal(vendorOf(paloAltoLine(NOW)), 'paloalto');
    }
  });

  it('the Palo Alto frame really parses as rfc3164, not pri-only', () => {
    // pri-only means the header was NOT stripped, which is how the detection
    // broke. Fortinet is pri-only by design — FortiOS sends no RFC 3164 header.
    assert.equal(parseSyslogLine(paloAltoLine(NOW), NOW).format, 'rfc3164');
    assert.equal(parseSyslogLine(fortinetLine(NOW), NOW).format, 'pri-only');
  });

  it('⛔ each vendor carries the rule identifier ITS correlation path uses', () => {
    // These are different paths on purpose, so the mock fleet exercises both
    // grades of log-derived usage: an ID match authorises a deletion, a NAME
    // match deliberately does not.
    const f = vendorParsers.parseFortinet(parseSyslogLine(fortinetLine(NOW), NOW).message);
    assert.ok(f.ruleId, 'Fortinet must carry policyid -> ruleId, or nothing correlates by ID');

    const p = vendorParsers.parsePaloAlto(parseSyslogLine(paloAltoLine(NOW), NOW).message);
    assert.ok(p.ruleName, 'Palo Alto must carry a rule name, or nothing correlates by name');
  });

  it('\u26d4 the generated identifiers MATCH the seeded rules, not merely exist', () => {
    // Presence is not alignment. A policyid or rule name that corresponds to no
    // seeded rule parses perfectly and correlates to nothing, so every rule
    // would read as having no traffic -- an `unused` finding manufactured out of
    // a mismatch between two of my own files.
    const fgt = DEVICES.find((d) => d.mgmt_ip === SENDERS.fortinet);
    const pan = DEVICES.find((d) => d.mgmt_ip === SENDERS.paloalto);
    // Fortinet correlates on the vendor's own rule id; the seed writes
    // rule_id_vendor = String(seq).
    const seededIds = new Set(fgt.rules.map((r) => String(r.seq)));
    // Palo Alto correlates on the rule NAME.
    const seededNames = new Set(pan.rules.map((r) => r.name));

    const seenIds = new Set();
    const seenNames = new Set();
    for (let i = 0; i < 300; i++) {
      seenIds.add(vendorParsers.parseFortinet(parseSyslogLine(fortinetLine(NOW), NOW).message).ruleId);
      seenNames.add(vendorParsers.parsePaloAlto(parseSyslogLine(paloAltoLine(NOW), NOW).message).ruleName);
    }
    for (const id of seenIds) {
      assert.ok(seededIds.has(String(id)), `policyid ${id} matches no seeded rule_id_vendor`);
    }
    for (const n of seenNames) {
      assert.ok(seededNames.has(n), `rule name ${n} matches no seeded rule_name`);
    }
  });

  it('the sender addresses match the seeded devices, or nothing attributes', () => {
    // An event whose source IP matches no device is stored with device_id NULL —
    // right behaviour, and it would make the mock fleet look silent.
    const ips = DEVICES.map((d) => d.mgmt_ip);
    assert.ok(ips.includes(SENDERS.fortinet), 'the Fortinet sender is not a seeded device');
    assert.ok(ips.includes(SENDERS.paloalto), 'the Palo Alto sender is not a seeded device');
  });

  it('a generated line carries an action from the REAL vocabulary', () => {
    // CLAUDE.md: FortiGate logs an established-then-ended session as
    // close/client-rst, never `allow`; PAN-OS's reset-both is a BLOCK. A
    // generator emitting only `allow`/`deny` would never exercise either.
    const actions = new Set();
    for (let i = 0; i < 200; i++) {
      actions.add(vendorParsers.parseFortinet(parseSyslogLine(fortinetLine(NOW), NOW).message).action);
    }
    assert.ok(actions.has('close') || actions.has('client-rst'),
      `expected a session-close action among ${[...actions].join(',')}`);
  });
});

describe('⛔ mockSyslog cannot be told to run unbounded by a typo', () => {
  test('a non-numeric option is refused, and the message echoes what was typed', () => {
    // `Number('fast')` is NaN, and every comparison against NaN is false — so a
    // coerced value would silently remove the bound the flag exists to set.
    assert.throws(() => parseArgs(['--count', 'fast']), /must be a positive number.*fast/);
    assert.throws(() => parseArgs(['--rate', '0']), /must be a positive number/);
    assert.throws(() => parseArgs(['--port', '-1']), /must be a positive number/);
  });

  test('defaults are loopback and the unprivileged port', () => {
    const o = parseArgs([]);
    assert.equal(o.host, '127.0.0.1', 'must not default to a broadcast or LAN address');
    assert.equal(o.port, 1514, 'must not default to privileged 514');
    assert.ok(o.count > 0 && Number.isFinite(o.count), 'must be finite by default');
  });
});

describe('⛔ the seed refuses anything that is not plainly a test database', () => {
  test('production host is refused even with --i-know', () => {
    assert.throws(
      () => assertSafeTarget('postgres://u:p@192.168.7.69:5432/secvault_mock', true),
      /production fleet server/
    );
  });

  test('a database not declaring itself a test is refused', () => {
    assert.throws(
      () => assertSafeTarget('postgres://u:p@127.0.0.1:5432/secvault', true),
      /does not declare itself a test database/
    );
  });

  test('a test database without the explicit confirmation is refused', () => {
    assert.throws(
      () => assertSafeTarget('postgres://u:p@127.0.0.1:5432/secvault_mock', false),
      /pass --i-know/
    );
  });

  test('all three satisfied is accepted', () => {
    const t = assertSafeTarget('postgres://u:p@127.0.0.1:5432/secvault_mock', true);
    assert.equal(t.dbName, 'secvault_mock');
  });

  test('a missing or unparseable URL is refused, not defaulted', () => {
    assert.throws(() => assertSafeTarget('', true), /not set/);
    assert.throws(() => assertSafeTarget('not a url', true), /could not be parsed/);
  });
});

describe('the seeded fleet is deliberately uneven', () => {
  // A uniformly healthy fleet exercises only the green path, which is the one
  // place this product has never had a bug.
  it('every device is identifiable as mock on sight', () => {
    for (const d of DEVICES) assert.ok(d.name.startsWith(NAME_PREFIX), d.name);
  });

  it('⛔ one device reports NO hit counts at all', () => {
    // The Fortinet-over-SSH shape. `unused` must not be claimed from it.
    assert.ok(DEVICES.some((d) => d.hitCounts === null && d.rules.length > 0),
      'without this, nothing exercises unmeasured-vs-measured-zero');
  });

  it('⛔ one device has a MEASURED zero among real counts', () => {
    const measured = DEVICES.find((d) => Array.isArray(d.hitCounts));
    assert.ok(measured, 'nothing exercises a real hit count');
    assert.ok(measured.hitCounts.includes(0), 'a measured zero is the other half of the tri-state');
  });

  it('⛔ one device has nothing collected at all', () => {
    const gap = DEVICES.find((d) => d.collected === false);
    assert.ok(gap, 'nothing exercises the coverage-gap path');
    assert.equal(gap.rules.length, 0);
    assert.equal(gap.config, null);
    assert.equal(gap.version, null);
  });

  it('⛔ one device has an unreadable version string', () => {
    const bad = DEVICES.find((d) => d.version && d.tuple === null);
    assert.ok(bad, 'nothing exercises unreadable_running_version in the upgrade planner');
  });
});
