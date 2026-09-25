'use strict';
// tests/csvInjection.test.js
//
// ⛔ A CSV EXPORT IS AN EXECUTION SURFACE, AND THIS PRODUCT'S CELLS COME FROM
// OUTSIDE IT. Excel, LibreOffice and Google Sheets evaluate a cell beginning
// `=`, `+`, `-` or `@` as a FORMULA on open. The compliance fleet export carries
// device names and vendors read off firewall configuration, and the per-device
// export carries check names and finding reasons — none of which SecVault
// authored. So an operator downloading a compliance report was one click away
// from running whatever a firewall's object names said to run.
//
// `app/api/compliance/fleet/route.js` defined its OWN `csvEscape` that predated
// lib/csv.js: it quoted CONDITIONALLY and neutralised nothing. Migrated
// 2026-09-25. This file pins both halves of that fix:
//
//   1. the route no longer carries a local escape, and its cells go through the
//      shared one (a source check — nothing in `npm test` can load an `app/`
//      route, which is why the defect survived every other gate); and
//   2. the shared escape actually neutralises, asserted on the exact inputs an
//      attacker would use.
//
// ⛔ AND IT RATCHETS. Seven other routes still hand-roll the same conditional
// escape (see KNOWN_UNMIGRATED). This file does not fail the build over them —
// that would be a red suite over a pre-existing condition nobody is working on
// — but it DOES fail on an EIGHTH. A new export written by copying its
// neighbour is exactly how this class of defect spreads, and a list with a
// reason beside each entry is how the remaining work stays visible instead of
// becoming folklore.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { csvEscape, csvRow, csvDocument } = require('../lib/csv');

const REPO = path.join(__dirname, '..');
const FLEET_ROUTE = 'app/api/compliance/fleet/route.js';

function read(rel) {
  return fs.readFileSync(path.join(REPO, rel), 'utf8');
}

// ── 1. THE ROUTE ──────────────────────────────────────────────────────────

describe('compliance fleet CSV export uses the shared escape', () => {
  const src = read(FLEET_ROUTE);

  it('defines no local escape of its own', () => {
    // Any shape of local definition, not just the one that was there: an arrow
    // assigned to a const would reintroduce the identical hazard while
    // sailing past a test that only looked for `function csvEscape`.
    assert.ok(
      !/function\s+csvEscape\s*\(/.test(src),
      `${FLEET_ROUTE} defines a local csvEscape() — use lib/csv.js`
    );
    assert.ok(
      !/(?:const|let|var)\s+csvEscape\s*=/.test(src),
      `${FLEET_ROUTE} assigns a local csvEscape — use lib/csv.js`
    );
  });

  it('imports the shared escape from lib/csv', () => {
    assert.match(src, /from\s+'(?:\.\.\/)+lib\/csv'/);
  });

  it('routes every cell through csvRow, not a raw join', () => {
    // ⛔ The dangerous half is not the missing import, it is a cell that
    // reaches the document WITHOUT passing through the escape. A leftover
    // `[...].join(',')` over raw values would compile, export, and execute.
    assert.ok(/csvRow\(/.test(src), 'buildCsv no longer calls csvRow');
    const joins = src.match(/\.join\(\s*','\s*\)/g) || [];
    assert.deepEqual(
      joins,
      [],
      `${FLEET_ROUTE} still joins values with ',' by hand: ${joins.length} site(s)`
    );
  });

  it('keeps the exported columns and their order exactly', () => {
    // The migration was allowed to change how a cell is ENCODED and nothing
    // else. A customer's saved export, and anything scripted against it, must
    // still find the same columns in the same places — including the absent
    // `SANS %`, which this file has never carried and which is not this
    // commit's to add.
    const m = src.match(/const headers = \[([^\]]*)\]/);
    assert.ok(m, 'could not find the header list');
    const headers = m[1]
      .split(',')
      .map((s) => s.trim().replace(/^'|'$/g, ''))
      .filter(Boolean);
    assert.deepEqual(headers, [
      'Device',
      'Vendor',
      'Last Run',
      'PCI DSS %',
      'ISO 27001 %',
      'CIS v8 %',
      'NIST %',
    ]);
  });
});

// ── 2. THE SHARED ESCAPE, ON THE INPUTS THAT MATTER ───────────────────────

describe('shared csvEscape neutralises spreadsheet formulas', () => {
  it('prefixes an apostrophe to each of the four formula leads', () => {
    // All four, individually — `=` is the one everybody remembers and `-` is
    // the one that gets dropped as "that is just a negative number".
    assert.equal(csvEscape('=cmd|\' /c calc\'!A1'), `"'=cmd|' /c calc'!A1"`);
    assert.equal(csvEscape('+1'), `"'+1"`);
    assert.equal(csvEscape('-1'), `"'-1"`);
    assert.equal(csvEscape('@x'), `"'@x"`);
  });

  it('neutralises a lead hidden behind whitespace', () => {
    // ⛔ `^\s*`, not `^`. Excel strips leading whitespace before deciding
    // whether a cell is a formula, so a naive index-0 test hands the attacker
    // a one-space bypass. The whitespace is KEPT — the apostrophe is what
    // neutralises, and quietly deleting characters from an attacker-controlled
    // value tidies the evidence rather than protecting the reader.
    assert.equal(csvEscape('  =cmd'), `"'  =cmd"`);
    assert.equal(csvEscape('\t=cmd'), `"' =cmd"`); // tab folds to a space first
    assert.equal(csvEscape('\n=cmd'), `"' =cmd"`);
  });

  it('leaves an ordinary value alone apart from quoting it', () => {
    assert.equal(csvEscape('DMZ-FW-01'), '"DMZ-FW-01"');
    assert.equal(csvEscape('a=b'), '"a=b"'); // `=` not at the head is not a formula
    assert.equal(csvEscape(0), '"0"');
    assert.equal(csvEscape(null), '""');
    assert.equal(csvEscape(undefined), '""');
  });

  it('quotes a separator and doubles a quote', () => {
    assert.equal(csvEscape('Bangkok, HQ'), '"Bangkok, HQ"');
    assert.equal(csvEscape('say "hi"'), '"say ""hi"""');
    // A value carrying both, plus a formula lead: the apostrophe goes before
    // the payload and inside the quoting, never outside it.
    assert.equal(csvEscape('=a,"b"'), `"'=a,""b"""`);
  });

  it('always quotes, even when nothing requires it', () => {
    // ⛔ This is why the local copy had to go rather than be patched. Quoting
    // conditionally means deciding per value whether it holds a separator, and
    // one wrong call shifts every column after it — a compliance score filed
    // against the wrong firewall, silently.
    for (const v of ['plain', 1, true, '']) {
      const out = csvEscape(v);
      assert.ok(out.startsWith('"') && out.endsWith('"'), `not quoted: ${out}`);
    }
  });

  it('never lets a row break into two physical lines', () => {
    const out = csvRow(['a\r\nb', 'c\nd']);
    assert.ok(!out.includes('\n'));
    assert.ok(!out.includes('\r'));
  });

  it('emits a header even with no data rows', () => {
    // "the export is broken" and "nothing matched" must not look the same.
    const doc = csvDocument([csvRow(['Device', 'Vendor'])]);
    assert.equal(doc, '"Device","Vendor"\r\n');
  });
});

// ── 3. THE RATCHET ────────────────────────────────────────────────────────

// Every route that still defines its own conditional escape, with WHY it is
// tolerated rather than silently suppressed. Each one is the same hazard as the
// fleet route's was; all of them are reachable by an authenticated operator,
// and all of their cells originate in firewall configuration.
const KNOWN_UNMIGRATED = {
  'app/api/compliance/[deviceId]/route.js':
    'check names, detail, remediation guidance, matched rule names',
  'app/api/devices/[id]/analysis/route.js': 'rule names, finding detail, remediation',
  'app/api/devices/[id]/reorder-recommendation/route.js': 'rule names, vendor rule ids',
  'app/api/devices/[id]/rules/route.js':
    'the whole ruleset — names, comments, zones, addresses, services',
  'app/api/devices/[id]/snmp/route.js': 'numeric samples only, but the same escape',
  'app/api/devices/[id]/vpn/route.js': 'numeric samples only, but the same escape',
  'app/api/vpn/fleet/route.js': 'device names and vendors',
};

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.next' || entry.name === '.git') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

describe('no NEW hand-rolled CSV escape', () => {
  it('every local csvEscape is one of the known, named ones', () => {
    const found = [];
    for (const root of ['app', 'lib', 'services', 'components', 'scripts']) {
      const dir = path.join(REPO, root);
      if (!fs.existsSync(dir)) continue;
      for (const full of walk(dir)) {
        const rel = path.relative(REPO, full).split(path.sep).join('/');
        if (rel === 'lib/csv.js') continue; // the shared implementation itself
        const src = fs.readFileSync(full, 'utf8');
        // A DEFINITION, not a call — `const { csvEscape } = require('../csv')`
        // is the correct thing and must not be flagged.
        if (/function\s+csvEscape\s*\(/.test(src) || /(?:const|let|var)\s+csvEscape\s*=\s*(?:\(|function|async)/.test(src)) {
          found.push(rel);
        }
      }
    }
    const unexpected = found.filter((f) => !(f in KNOWN_UNMIGRATED));
    assert.deepEqual(
      unexpected,
      [],
      `New hand-rolled CSV escape(s): ${unexpected.join(', ')}. ` +
        'Use lib/csv.js — it always quotes and neutralises a leading =, +, - or @.'
    );
    // ⛔ The fleet route is asserted OUT of the known list, so a revert cannot
    // land quietly under the ratchet's tolerance.
    assert.ok(!found.includes(FLEET_ROUTE), `${FLEET_ROUTE} has regressed to a local escape`);
  });

  it('the known list names no file that has already been migrated', () => {
    // A stale exemption reads as outstanding work that is already done, and
    // the next reader trusts the list instead of the code.
    for (const rel of Object.keys(KNOWN_UNMIGRATED)) {
      const src = read(rel);
      assert.ok(
        /function\s+csvEscape\s*\(/.test(src),
        `${rel} no longer hand-rolls csvEscape — remove it from KNOWN_UNMIGRATED`
      );
    }
  });
});
