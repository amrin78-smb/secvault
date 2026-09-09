// tests/cidrUtils.test.js
//
// ⛔ WHY THIS EXISTS. `app-error.log` on the production server was flooded with
//
//     [cidrUtils] "24" looks like an IPv4 literal/CIDR but failed to parse ...
//     [cidrUtils] "1"  ... same
//
// 253 of them over the live fleet. The obvious reading — and the one I reached
// for first — was that something upstream was splitting an address into
// fragments and passing the pieces in. It was not. Nothing upstream fragments
// anything.
//
// `parseIpRange()` splits ANY value on the first '-' and probes both halves,
// because `objectResolver.resolveAddressEntry()` speculatively tries a literal
// parse before falling back to an object-name lookup. Palo Alto address OBJECT
// NAMES routinely contain dashes — `SERVER-24`, `WIFI-23`, `PAM-1`,
// `172.16.12.0-24` — so the half `24` reached a parser whose IP_SHAPED regex
// used `(\.[0-9]+)*`, allowing ZERO dots, and a bare integer was therefore
// judged "a malformed IP" rather than "not an IP".
//
// ⛔ NOTHING WAS BEING SKIPPED. That was proven, not assumed: resolution output
// over all 1,716 rules of all 16 devices hashed identically before and after
// the fix, with warnings going 253 -> 0. Those names resolve one step later
// through the object lookup. The bug was a misdiagnosis emitted by the parser,
// which is why the fix had to change WHAT WARNS and not what parses.
//
// These tests pin both halves of that: a name is silent, a genuinely malformed
// range still complains, and the strict parse is unchanged.

'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const { parseCidrOrIp, parseIpRange, cidrContains } = require('../lib/engines/cidrUtils');

// Capture console.warn so "did it warn?" is an assertion rather than a
// judgement call about log noise.
let warnings = [];
const realWarn = console.warn;
beforeEach(() => {
  warnings = [];
  console.warn = (msg) => warnings.push(String(msg));
});
afterEach(() => {
  console.warn = realWarn;
});

describe('cidrUtils: an object name is not a malformed IP', () => {
  // Every one of these is a REAL Palo Alto address-object name from the live
  // fleet. They are the exact inputs that produced the log flood.
  const REAL_OBJECT_NAMES = [
    'SERVER-24',
    'WIFI-23',
    'PAM-1',
    'PAM-2',
    'TUMN-2',
    'TESI_156.54.168.1-6',
    'net-10.160.243.0-24',
    'Meraki SW 172.16.2.1-18',
    '172.16.12.0-24',
  ];

  for (const name of REAL_OBJECT_NAMES) {
    it(`"${name}" resolves to null SILENTLY`, () => {
      assert.equal(parseIpRange(name), null, 'must not parse as a range');
      assert.deepEqual(
        warnings,
        [],
        `warned about an object name: ${warnings.join(' | ')}`
      );
    });
  }

  it('a bare integer is not IP-shaped, so it never warns', () => {
    // ⛔ The second, separately-justified half of the fix: IP_SHAPED now
    // requires at least one dot. A lone "24" is not an IPv4 literal by any
    // reading, so its failure to parse is not "a subtly malformed address".
    // This also covers callers that legitimately probe one token lifted from
    // wider text — paloalto/sshParser.js hands every column of
    // `show interface all` to the parser, numeric columns included.
    for (const v of ['1', '2', '6', '24', '4095']) {
      assert.equal(parseCidrOrIp(v), null);
    }
    assert.deepEqual(warnings, []);
  });
});

describe('cidrUtils: a genuinely malformed range still complains', () => {
  it('⛔ warns ONCE about the whole string, not about a fragment', () => {
    // The point of the fix is not silence. A value that really was meant to be
    // a range and is wrong must still be reported — otherwise the fix would
    // have traded log noise for a blind spot.
    assert.equal(parseIpRange('10.0.0.1-10.0.0.999'), null);
    assert.equal(warnings.length, 1, 'expected exactly one warning');
    assert.match(warnings[0], /10\.0\.0\.1-10\.0\.0\.999/, 'must name the WHOLE value');
  });

  it('a backwards range is malformed too', () => {
    assert.equal(parseIpRange('10.0.0.9-10.0.0.1'), null);
    assert.equal(warnings.length, 1);
  });
});

describe('cidrUtils: the fix narrowed what WARNS, never what PARSES', () => {
  it('valid addresses and CIDRs still parse', () => {
    assert.ok(parseCidrOrIp('10.0.0.1'));
    assert.ok(parseCidrOrIp('10.0.0.0/24'));
    assert.ok(parseCidrOrIp('0.0.0.0/0'));
    assert.deepEqual(warnings, []);
  });

  it('strict octet and prefix validation is untouched', () => {
    // These are still rejected — the parser did not get more permissive.
    assert.equal(parseCidrOrIp('10.0.0.256'), null);
    assert.equal(parseCidrOrIp('10.0.0.0/33'), null);
    assert.equal(parseCidrOrIp('1.2.3.4.5'), null);
  });

  it('a valid range still parses, and containment still works', () => {
    const r = parseIpRange('10.0.0.1-10.0.0.10');
    assert.ok(r, 'a real range must still parse');
    assert.deepEqual(warnings, []);
    assert.equal(cidrContains('10.0.0.0/24', '10.0.0.5'), true);
  });

  it('⛔ a failed parse returns null — never a default that looks like an answer', () => {
    // The rule this whole file serves: not comparable is not the same as
    // "compares to 0.0.0.0" or "matches nothing". Callers rely on null to keep
    // their tri-state honest, so an unresolved entry never becomes a no-match.
    for (const v of ['any', 'all', '2001:db8::1', 'N/A', '', 'Some Group Name']) {
      assert.equal(parseCidrOrIp(v), null);
    }
  });
});
