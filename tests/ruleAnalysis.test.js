'use strict';
// Pins the hit_count tri-state introduced in v2.63.0.
//
// THE INCIDENT: hit_count was `NOT NULL DEFAULT 0`, and Palo Alto's hit-count
// command was malformed so PAN-OS rejected it on every call. The enrichment's
// catch swallowed that (correctly -- a hit count is additive and must never
// fail a rule pull), so every rule kept 0. ruleAnalysis read
// `Number(rule.hit_count) === 0` and emitted `unused`. Result: all 1,278
// unused findings in the fleet were fabricated from a failed read -- 100% of
// them, with no real ones mixed in.
//
// The load-bearing case is `null`, and the sneaky one is the STRING "0":
// hit_count is a bigint, and node-postgres hands bigints back as strings, so
// a real measured zero arrives as "0" and must still produce the finding.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { analyzeRules } = require('../lib/engines/ruleAnalysis');

function ruleWith(overrides) {
  return Object.assign(
    {
      id: 'rule-1',
      rule_name: 'test-rule',
      sequence_number: 1,
      enabled: true,
      action: 'allow',
      src_zones: [],
      dst_zones: [],
      src_addresses: ['10.0.0.1'],
      dst_addresses: ['10.0.0.2'],
      services: ['tcp/8080'],
      applications: [],
      schedule: null,
      expiry_date: null,
      log_enabled: true,
      comment: null,
      hit_count: null,
      vdom: null,
    },
    overrides
  );
}

async function unusedFindingsFor(hitCount) {
  const findings = await analyzeRules([ruleWith({ hit_count: hitCount })], {});
  const list = Array.isArray(findings) ? findings : findings.findings || [];
  return list.filter((f) => f.finding_type === 'unused');
}

describe('ruleAnalysis: `unused` requires a MEASURED zero', () => {
  it('does NOT flag a rule whose hit_count is null (vendor cannot measure hits)', async () => {
    assert.equal(
      (await unusedFindingsFor(null)).length,
      0,
      'null means NOT MEASURED. Fortinet SSH, Sangfor and Palo Alto SSH all report ' +
        'null; treating that as "zero hits" is what fabricated 1,278 findings.'
    );
  });

  it('does NOT flag a rule whose hit_count is undefined', async () => {
    assert.equal((await unusedFindingsFor(undefined)).length, 0);
  });

  it('DOES flag a rule the device genuinely reported zero hits for', async () => {
    assert.equal((await unusedFindingsFor(0)).length, 1);
  });

  it('DOES flag a measured zero arriving as the STRING "0" (bigint over pg)', async () => {
    assert.equal(
      (await unusedFindingsFor('0')).length,
      1,
      'node-postgres returns bigint as a string. A real zero must not be lost to a type check.'
    );
  });

  it('does NOT flag a rule with real traffic, counted as a string', async () => {
    assert.equal((await unusedFindingsFor('742')).length, 0);
  });

  it('does NOT flag a rule with real traffic, counted as a number', async () => {
    assert.equal((await unusedFindingsFor(742)).length, 0);
  });

  it('no longer blames the vendor in the finding text', async () => {
    const [finding] = await unusedFindingsFor(0);
    assert.ok(finding, 'expected a finding for a measured zero');
    assert.doesNotMatch(
      finding.detail,
      /may be unavailable|Known Limitations/i,
      'the old text hedged that hit data "may be unavailable" because the engine could ' +
        'not tell. It can now: an unmeasured rule produces no finding at all, so the ' +
        'finding that IS produced should state the fact plainly.'
    );
  });
});
