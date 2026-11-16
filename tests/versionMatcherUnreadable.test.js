'use strict';

// tests/versionMatcherUnreadable.test.js
//
// Roadmap row 51 — the one `parseVersion` call site where a FABRICATED ZERO
// became a vulnerability verdict.
//
// ⛔ WHAT THE ZERO DOES, MEASURED RATHER THAN ARGUED. `parseVersion` returns
// `[0,0,0,0]` for anything it cannot read, and `isInRange` checks the BOUNDS
// for readability but never the candidate. So against a min-bounded range the
// unreadable device is NOT AFFECTED — a firewall reading as clean because
// nobody could parse its version — and against a max-only range it is
// AFFECTED, a false positive. The first direction is the dangerous one and is
// this codebase's signature bug landing on the CVE path.
//
// ⛔ NO DATABASE — stub pools, the convention in this suite.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { runMatchForAllDevices } = require('../lib/engines/versionMatcher');
const { parseVersion, isInRange, isVersionReadable } = require('../lib/engines/versionComparator');
// ⛔ The shared stripper — see tests/stripOrder.test.js for what the other
// order eats, and why rolling a local pair of regexes is refused here.
const { stripComments } = require('./stripComments');

const UNREADABLE = 'FortiGate-200E';

const DEVICES = [
  { id: 'dev-readable', vendor: 'fortinet', asset_criticality: 'medium' },
  { id: 'dev-unreadable', vendor: 'fortinet', asset_criticality: 'medium' },
];

// One advisory with a MIN bound — the shape that silently clears the device.
const ADVISORIES = [{
  id: 'adv-1',
  cve_id: 'CVE-2026-00001',
  vendor: 'fortinet',
  cvss_score: 9.8,
  kev_listed: true,
  matchability: 'matched',
  affected_version_ranges: [{ min: '7.0.0', max: '7.4.4', exclude_fixed: false }],
  fixed_in_versions: ['7.4.5'],
}];

function makeStubPool() {
  const clientSql = [];
  const clientParams = [];
  const pool = {
    async query(sql, params) {
      const s = String(sql);
      if (/FROM\s+devices\s+WHERE\s+active/i.test(s)) return { rows: DEVICES.map((d) => ({ ...d })) };
      if (/FROM\s+device_versions/i.test(s)) {
        if (params && params[0] === 'dev-readable') return { rows: [{ version_string: 'v7.4.3,build2573' }] };
        if (params && params[0] === 'dev-unreadable') return { rows: [{ version_string: UNREADABLE }] };
        return { rows: [] };
      }
      if (/FROM\s+advisories/i.test(s)) return { rows: ADVISORIES.map((a) => ({ ...a })) };
      return { rows: [] };
    },
    async connect() {
      return {
        async query(sql, params) { clientSql.push(String(sql)); clientParams.push(params); return { rows: [] }; },
        release() {},
      };
    },
  };
  return { pool, clientSql, clientParams };
}

describe('⛔ an unreadable device version is not a device we have cleared', () => {
  it('⛔ THE HAZARD IS REAL AND POINTS BOTH WAYS — measured, not argued', () => {
    assert.equal(isVersionReadable('fortinet', UNREADABLE), false);
    assert.deepEqual(parseVersion('fortinet', UNREADABLE), [0, 0, 0, 0]);
    // Below every real min: a silent NOT AFFECTED on the firewall nobody could read.
    assert.equal(isInRange('fortinet', [0, 0, 0, 0], '7.0.0', '7.4.4', false, []), false);
    // Below every max on a max-only range: a false positive.
    assert.equal(isInRange('fortinet', [0, 0, 0, 0], null, '7.4.4', false, []), true);
  });

  it('⛔ the device is SKIPPED and the reason names the string', async () => {
    const { pool } = makeStubPool();
    const result = await runMatchForAllDevices(pool);
    const err = result.errors.find((e) => e.device_id === 'dev-unreadable');
    assert.ok(err, 'a device that could not be assessed must be reported, never dropped quietly');
    assert.match(err.error, /could not be parsed/);
    assert.match(err.error, /FortiGate-200E/, 'the operator needs the string to fix the parser');
    assert.match(err.error, /NOT assessed/);
  });

  it('⛔ it is never counted as assessed, and never silently cleared', async () => {
    const { pool, clientParams } = makeStubPool();
    const result = await runMatchForAllDevices(pool);
    assert.equal(result.assessed, 1, 'only the readable device was assessed');
    // ⛔ The reconciliation DELETE must never run for it. `continue` happens
    // before the transaction opens, so a device that becomes unreadable keeps
    // the assessments it already had rather than having them cleared by a run
    // that learned nothing about it.
    const touched = clientParams.filter(Boolean).flat();
    assert.ok(!touched.includes('dev-unreadable'),
      'no statement may touch a device this run could not assess');
  });

  it('a readable device in the same run is unaffected', async () => {
    // ⛔ The guard must not take the fleet down with the one firewall it
    // refuses. A guard that over-fires gets waived, and then stops firing.
    const { pool, clientParams } = makeStubPool();
    const result = await runMatchForAllDevices(pool);
    assert.equal(result.errors.filter((e) => e.device_id === 'dev-readable').length, 0);
    assert.ok(clientParams.filter(Boolean).flat().includes('dev-readable'));
  });

  it('⛔ an unreadable FIX candidate is dropped by a decision, not by arithmetic', () => {
    // It parsed to [0,0,0,0], which could never beat a real device tuple in
    // the `> 0` comparison — so it was already dropped, by accident. That
    // held only while the device tuple was non-zero, which is exactly what
    // this file stops being guaranteed elsewhere.
    const src = stripComments(require('node:fs').readFileSync(
      require('node:path').join(__dirname, '..', 'lib', 'engines', 'versionMatcher.js'), 'utf8'
    ));
    assert.match(src, /if \(!isVersionReadable\(device\.vendor, candidate\)\) continue;/);
    assert.match(src, /if \(!isVersionReadable\(device\.vendor, versionRow\.version_string\)\)/);
  });
});
