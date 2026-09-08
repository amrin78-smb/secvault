'use strict';
// Pins the collector's port-list parsing.
//
// THE INCIDENT this exists for: the collector originally bound a single port
// (514). Host-wide UDP was ~1,373/sec under Firewall Analyzer and ~7.5/sec
// after the switch. Nothing errored. FWA had listened on BOTH 514 and 1514,
// ManageEngine's documented default for Firewall Analyzer is UDP 1514, and
// most of the fleet was still sending there — into a port nothing was holding.
//
// ⛔ The OS discards datagrams sent to an unbound UDP port SILENTLY. "We are
// listening and nobody is sending" and "we are not listening where they are
// sending" are indistinguishable from inside the process. That is why the
// default is a list, and why a partly-invalid list must never leave the
// collector deaf.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { parsePortList, intSetting } = require('../lib/syslog/collectorConfig');

const DEFAULTS = [514, 1514];

describe('collectorConfig: parsePortList', () => {
  it('defaults to BOTH 514 and 1514 when unset', () => {
    for (const empty of [undefined, null, '', '   ']) {
      const r = parsePortList(empty, DEFAULTS);
      assert.deepEqual(r.ports, [514, 1514], `${JSON.stringify(empty)} must fall back to both ports`);
      assert.equal(r.usedDefault, true);
    }
  });

  it('parses a single port', () => {
    assert.deepEqual(parsePortList('514', DEFAULTS).ports, [514]);
  });

  it('parses a comma-separated list, tolerating whitespace', () => {
    assert.deepEqual(parsePortList('514,1514', DEFAULTS).ports, [514, 1514]);
    assert.deepEqual(parsePortList(' 514 , 1514 , 5514 ', DEFAULTS).ports, [514, 1514, 5514]);
  });

  it('collapses duplicates, which would otherwise EADDRINUSE against ourselves', () => {
    assert.deepEqual(parsePortList('514,514,1514', DEFAULTS).ports, [514, 1514]);
  });

  it('⛔ keeps the VALID entries when one is a typo, rather than going deaf', () => {
    const r = parsePortList('514,notaport,1514', DEFAULTS);
    assert.deepEqual(r.ports, [514, 1514], 'a single bad entry must not discard the good ones');
    assert.deepEqual(r.rejected, ['notaport']);
    assert.equal(r.usedDefault, false);
  });

  it('rejects out-of-range and non-integer ports', () => {
    const r = parsePortList('0,65536,-1,80.5,1e3', DEFAULTS);
    assert.deepEqual(r.ports, DEFAULTS, 'nothing usable, so fall back');
    assert.equal(r.usedDefault, true);
    assert.ok(r.rejected.length >= 4);
  });

  it('rejects a numeric-looking string that is not purely digits', () => {
    // Number('514abc') is NaN but Number(' 514 ') is 514 — the difference
    // matters, so the check is on the string, before any conversion.
    const r = parsePortList('514abc', DEFAULTS);
    assert.deepEqual(r.ports, DEFAULTS);
    assert.deepEqual(r.rejected, ['514abc']);
  });

  it('⛔ never returns an empty port list — that would listen nowhere and look healthy', () => {
    for (const junk of ['', 'x', ',,,', '0', '99999', undefined]) {
      const r = parsePortList(junk, DEFAULTS);
      assert.ok(r.ports.length > 0, `${JSON.stringify(junk)} must still yield a listening port`);
    }
  });

  it('accepts the boundary ports', () => {
    assert.deepEqual(parsePortList('1,65535', DEFAULTS).ports, [1, 65535]);
  });
});

describe('collectorConfig: intSetting', () => {
  it('uses the default when unset, and reports that it did', () => {
    const r = intSetting(undefined, 2000, 250, 60000);
    assert.equal(r.value, 2000);
    assert.equal(r.usedDefault, true);
  });

  it('accepts an in-range value', () => {
    const r = intSetting('5000', 2000, 250, 60000);
    assert.equal(r.value, 5000);
    assert.equal(r.usedDefault, false);
  });

  it('falls back with a REASON when out of range or unparseable', () => {
    assert.equal(intSetting('10', 2000, 250, 60000).reason, 'below 250');
    assert.equal(intSetting('999999', 2000, 250, 60000).reason, 'above 60000');
    assert.equal(intSetting('soon', 2000, 250, 60000).reason, 'not a number');
    // The reason exists so a misconfiguration is visible in the log rather
    // than silently becoming the default.
    for (const bad of ['10', '999999', 'soon']) {
      assert.equal(intSetting(bad, 2000, 250, 60000).value, 2000);
    }
  });
});
