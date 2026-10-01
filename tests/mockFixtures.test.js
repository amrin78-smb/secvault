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
const { fortinetLine, paloAltoLine, parseArgs, SENDERS, DENY_POLICY_ID, PAN_RULES } =
  require('../scripts/mockSyslog');
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

describe('⛔ a logged action must agree with the rule that produced it', () => {
  // The first version picked rule and action INDEPENDENTLY, so `Deny-All` logged
  // `accept` and `default-deny` logged `allow` -- measured live, 149 hits of it.
  // That is not merely unrealistic: /segmentation reads exactly this evidence to
  // decide whether a deny-intent zone pair is actually carrying traffic, so the
  // generator would have manufactured a violation that exists only because of the
  // generator. Fabricated evidence is worse than no evidence.
  const DENIED = new Set(['deny', 'drop', 'reset-both']);

  function seededRules(ip) {
    return DEVICES.find((d) => d.mgmt_ip === ip).rules;
  }

  it('\u26d4 the generator\'s intent tables match the SEEDER\'s rules', () => {
    // Cross-checked against the seeder rather than restated, so the two cannot
    // drift into disagreeing about which rules deny.
    const fgt = seededRules(SENDERS.fortinet);
    const denyIds = fgt.filter((r) => r.action === 'deny').map((r) => r.seq);
    assert.deepEqual(denyIds, [DENY_POLICY_ID],
      `the seeder's deny rule(s) are ${denyIds.join(',')} but the generator thinks it is ${DENY_POLICY_ID}`);

    const pan = seededRules(SENDERS.paloalto);
    for (const r of PAN_RULES) {
      const seeded = pan.find((x) => x.name === r.name);
      assert.ok(seeded, `generator logs PAN rule "${r.name}" which the seeder does not define`);
      assert.equal(r.allow, seeded.action === 'allow',
        `"${r.name}": generator says allow=${r.allow}, seeder says action=${seeded.action}`);
    }
  });

  it('a Fortinet deny rule never logs an accepting action', () => {
    let seen = 0;
    for (let i = 0; i < 2000; i++) {
      const line = fortinetLine(NOW);
      const ev = vendorParsers.parseFortinet(parseSyslogLine(line, NOW).message);
      if (String(ev.ruleId) !== String(DENY_POLICY_ID)) continue;
      seen++;
      assert.ok(ev.action !== 'accept',
        `rule ${DENY_POLICY_ID} is Deny-All and must never log accept`);
    }
    assert.ok(seen > 0, 'the deny rule never appeared, so nothing was checked');
  });

  it('a Fortinet allow rule never logs deny', () => {
    let seen = 0;
    for (let i = 0; i < 2000; i++) {
      const line = fortinetLine(NOW);
      const ev = vendorParsers.parseFortinet(parseSyslogLine(line, NOW).message);
      if (String(ev.ruleId) === String(DENY_POLICY_ID)) continue;
      seen++;
      assert.ok(ev.action !== 'deny',
        `rule ${ev.ruleId} is an allow rule and must never log deny`);
    }
    assert.ok(seen > 0, 'no allow rule appeared, so nothing was checked');
  });

  it('\u26d4 default-deny never logs allow, and an allow rule never logs a bare deny', () => {
    const byRule = new Map();
    for (let i = 0; i < 3000; i++) {
      const ev = vendorParsers.parsePaloAlto(parseSyslogLine(paloAltoLine(NOW), NOW).message);
      if (!byRule.has(ev.ruleName)) byRule.set(ev.ruleName, new Set());
      byRule.get(ev.ruleName).add(ev.action);
    }
    for (const r of PAN_RULES) {
      const actions = byRule.get(r.name);
      assert.ok(actions && actions.size, `rule ${r.name} never appeared`);
      if (r.allow) {
        assert.ok(!actions.has('deny') && !actions.has('drop'),
          `allow rule ${r.name} logged ${[...actions].join(',')}`);
      } else {
        assert.ok(!actions.has('allow'),
          `DENY rule ${r.name} logged allow -- /segmentation would read that as a live violation`);
        for (const a of actions) {
          assert.ok(DENIED.has(a), `deny rule ${r.name} logged non-denying action ${a}`);
        }
      }
    }
  });

  it('reset-both is permitted on an ALLOW rule, because PAN-OS really does that', () => {
    // Its IPS resetting both ends. Excluding it would be the opposite error:
    // trimming real vendor behaviour out of the fixtures.
    let found = false;
    for (let i = 0; i < 3000 && !found; i++) {
      const ev = vendorParsers.parsePaloAlto(parseSyslogLine(paloAltoLine(NOW), NOW).message);
      const r = PAN_RULES.find((x) => x.name === ev.ruleName);
      if (r && r.allow && ev.action === 'reset-both') found = true;
    }
    assert.ok(found, 'no allow rule ever logged reset-both, so that real case is untested');
  });
});

describe('⛔ all three Fortinet timestamp paths are exercised', () => {
  // The first draft exercised NONE of them: it emitted date= and time= with no
  // tz= and no eventtime=, so `parseFortinet` correctly refused to invent a zone
  // and EVERY mock Fortinet event carried a null eventAt. Right behaviour by the
  // parser, and it meant the mock fleet never tested the timestamp logic at all.
  function sample(n) {
    const out = { ns: 0, fallback: 0, nul: 0 };
    for (let i = 0; i < n; i++) {
      const line = fortinetLine(new Date());
      const ev = vendorParsers.parseFortinet(parseSyslogLine(line, NOW).message);
      if (!ev.eventAt) out.nul++;
      else if (/eventtime=/.test(line)) out.ns++;
      else out.fallback++;
    }
    return out;
  }

  it('the preferred eventtime path, the date+tz fallback, and a NULL all occur', () => {
    const r = sample(1500);
    assert.ok(r.ns > 0, 'no line carried a usable eventtime \u2014 the preferred path is untested');
    assert.ok(r.fallback > 0, 'no line fell back to date+time+tz \u2014 that path is untested');
    assert.ok(r.nul > 0,
      '\u26d4 no line produced a NULL eventAt \u2014 the refusal to invent a timezone is untested, '
      + 'and that is the case this codebase gets wrong');
  });

  it('\u26d4 eventtime is 19 digits, so it scales as NANOseconds', () => {
    // parseFortinet scales by DIGIT LENGTH. A 16-digit value is read as
    // microseconds and resolves to 1970-01-21 \u2014 present in the table and
    // outside every time window and rollup bucket. A wrong-length epoch is
    // worse than no epoch.
    let checked = 0;
    for (let i = 0; i < 400 && checked < 5; i++) {
      const line = fortinetLine(new Date());
      const m = line.match(/eventtime=(\d+)/);
      if (!m) continue;
      checked++;
      assert.equal(m[1].length, 19, `eventtime must be 19 digits, got ${m[1].length}`);
      const ev = vendorParsers.parseFortinet(parseSyslogLine(line, NOW).message);
      assert.ok(ev.eventAt, 'a 19-digit eventtime must resolve');
      assert.ok(ev.eventAt.getUTCFullYear() >= 2026,
        `resolved to ${ev.eventAt.toISOString()} \u2014 the divisor is wrong`);
    }
    assert.ok(checked > 0, 'no eventtime was ever emitted, so nothing was checked');
  });

  it('a NULL eventAt is never backfilled with a guess', () => {
    // Belt and braces on the parser's own contract: when the generator omits
    // both, nothing downstream may invent a time.
    const line = fortinetLine(NOW).replace(/eventtime=\d+ /, '').replace(/tz="[^"]*" /, '');
    const ev = vendorParsers.parseFortinet(parseSyslogLine(line, NOW).message);
    assert.equal(ev.eventAt, null, 'an unanchored local time must stay null, never become now()');
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

describe('⛔ the seeder\'s SQL matches the real schema, not a remembered one', () => {
  // Nothing in `npm test` can run the seeder — it needs a database, and the dev
  // box has no role to connect as. So the one failure that would waste the first
  // real attempt is pinned statically instead: a column name that does not
  // exist. Already hit once this project (`rule_action` where the column is
  // `action`), and it is the v2.86.1 outage shape — a wrong column name builds
  // clean, passes every static check, and fails only when the query runs.
  const fs = require('node:fs');
  const path = require('node:path');
  const ROOT = path.join(__dirname, '..');
  const schema = fs.readFileSync(path.join(ROOT, 'lib/schema.sql'), 'utf8');
  const seed = fs.readFileSync(path.join(ROOT, 'scripts/seedMockFleet.js'), 'utf8');

  function columnsOf(table) {
    const cols = new Set();
    const m = schema.match(new RegExp(`CREATE TABLE IF NOT EXISTS\\s+${table}\\s*\\(([\\s\\S]*?)\\n\\);`, 'i'));
    if (m) {
      for (const line of m[1].split('\n')) {
        const t = line.trim();
        if (!t || t.startsWith('--')) continue;
        if (/^(PRIMARY|FOREIGN|UNIQUE|CHECK|CONSTRAINT|EXCLUDE)\b/i.test(t)) continue;
        const c = t.match(/^"?([a-z_][a-z0-9_]*)"?\s/i);
        if (c) cols.add(c[1].toLowerCase());
      }
    }
    // ADD COLUMN matters as much as the CREATE body — CLAUDE.md's own trap is a
    // column added to an existing table, where the CREATE still looks right.
    const alter = new RegExp(`ALTER TABLE\\s+${table}\\s+ADD COLUMN IF NOT EXISTS\\s+"?([a-z_][a-z0-9_]*)"?`, 'gi');
    let a;
    while ((a = alter.exec(schema))) cols.add(a[1].toLowerCase());
    return cols;
  }

  const inserts = [];
  const re = /INSERT INTO\s+([a-z_]+)\s*\(([^)]*)\)/gi;
  let m;
  while ((m = re.exec(seed))) {
    inserts.push({
      table: m[1].toLowerCase(),
      cols: m[2].split(',')
        .map((c) => c.trim().replace(/\s+/g, ' ').split(' ')[0].toLowerCase())
        .filter(Boolean),
    });
  }

  it('the scan actually found the seeder\'s INSERTs', () => {
    // Without this the loop below is a guard that cannot fire: a regex that
    // matches nothing passes every assertion it never runs.
    assert.ok(inserts.length >= 4,
      `expected at least 4 INSERT statements, found ${inserts.length} — the scan is broken, not the seeder`);
    const tables = inserts.map((i) => i.table);
    for (const t of ['devices', 'device_versions', 'device_configs', 'firewall_rules']) {
      assert.ok(tables.includes(t), `the seeder no longer inserts into ${t}`);
    }
  });

  for (const { table, cols } of inserts) {
    it(`every column the seeder writes to ${table} exists in schema.sql`, () => {
      const declared = columnsOf(table);
      assert.ok(declared.size > 0, `${table} is not declared in schema.sql at all`);
      const missing = cols.filter((c) => !declared.has(c));
      assert.deepEqual(missing, [],
        `${table}: these columns do not exist in schema.sql -> ${missing.join(', ')}`);
    });
  }
});
