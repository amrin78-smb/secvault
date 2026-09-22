'use strict';
// tests/complianceZoneRoleRead.test.js
//
// ⛔ A FAILED READ OF *OUR* TABLE, PRINTED AS A FACT ABOUT *THEIR* FIREWALL.
// Two compliance evaluators depend on `zone_classifications`, an operator-
// supplied table. `runComplianceAuditForDevice` loaded it best-effort and, on
// any error, left `{}` behind — which is exactly the value that means "this
// device has no classified zones yet". So a database blip produced a finding
// reading "none of this firewall's zones have been classified as external yet.
// Classify this device's zones..." on a device whose zones may all be
// classified: SecVault's own outage handed to the customer as an action item,
// with no trace anywhere that a read had failed.
//
// That is this codebase's signature bug in its most expensive form — not a
// wrong number, but a confident instruction to do work that is already done.
//
// The second half of this file is the neighbouring defect: zone names were
// lower-cased but never TRIMMED, on either side of the comparison. One stray
// space an operator typed made the two sets disjoint, and a check whose scope
// matched nothing reported a perfectly plausible `na`.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  evaluateRulesetPropertyCheck,
  runComplianceAuditForDevice,
} = require('../lib/engines/configAuditor');

const DEVICE_ID = '710506de-d602-459e-8fa1-40b7a318dcd4';

const CHECK = {
  id: 'check-uuid-1',
  check_id: 'rule-no-external-to-internal-access',
  name: 'No direct External-to-Internal access',
  standards: ['NIST'],
  severity: 'high',
  remediation_guidance: 'Put a DMZ in between.',
  predicate_config: {
    predicate_type: 'ruleset_property',
    property: 'no_external_to_internal_access',
  },
};

const RULES = [
  { id: 'r1', src_zones: ['untrust'], dst_zones: ['trust'], action: 'allow', enabled: true },
];
const ZONES = { untrust: 'external', trust: 'internal' };

// ── the read-failure state ──────────────────────────────────────────────────

describe('⛔ an UNREADABLE zone map and an UNCLASSIFIED device are different facts', () => {
  it('a failed read says SecVault could not read it, and blames nobody', () => {
    for (const unreadable of [null, undefined]) {
      const r = evaluateRulesetPropertyCheck(CHECK, RULES, unreadable, {});
      assert.equal(r.status, 'na');
      assert.match(r.detail, /could not read/i);
      assert.match(r.detail, /SecVault-side|SecVault could not/i);
      // ⛔ THE ASSERTION THAT MATTERS: it must not tell the operator to go and
      // do something that may already be done.
      assert.equal(/haven't been classified/.test(r.detail), false,
        'a failed read must not be reported as the operator not having classified anything');
      assert.equal(/Manage tab/.test(r.detail), false);
    }
  });

  it('an EMPTY map keeps its own, genuinely actionable wording', () => {
    // The distinction only exists while both sides keep distinct sentences.
    const r = evaluateRulesetPropertyCheck(CHECK, RULES, {}, {});
    assert.equal(r.status, 'na');
    assert.match(r.detail, /haven't been classified/);
    assert.equal(/could not read/i.test(r.detail), false);
  });

  it('neither state is ever a pass, and neither moves the score', () => {
    // ⛔ `na` on both sides: one is our limitation, the other is a missing
    // input nothing on the firewall would fix. Scoring either would count a
    // question SecVault cannot pose against the device.
    for (const map of [null, {}]) {
      assert.equal(evaluateRulesetPropertyCheck(CHECK, RULES, map, {}).status, 'na');
    }
  });

  it('a classified device still answers normally', () => {
    // The other half: a guard that returns `na` for everything also passes
    // every test above.
    const clean = evaluateRulesetPropertyCheck(CHECK, RULES, ZONES, {});
    assert.equal(clean.status, 'pass');
    const dirty = evaluateRulesetPropertyCheck(CHECK, RULES, ZONES, { external_exposure: ['r1'] });
    assert.equal(dirty.status, 'fail');
    assert.deepEqual(dirty.matchedRuleIds, ['r1']);
  });
});

describe('⛔ zone names are TRIMMED on BOTH sides of the comparison', () => {
  it('an operator-typed space does not silently empty the check', () => {
    const padded = { ' untrust': 'external', 'trust ': 'internal' };
    const r = evaluateRulesetPropertyCheck(CHECK, RULES, padded, { external_exposure: ['r1'] });
    assert.equal(r.status, 'fail', 'a stray space must not turn a real finding into "not classified"');
  });

  it('a padded ROLE value matches too', () => {
    const r = evaluateRulesetPropertyCheck(
      CHECK, RULES, { untrust: ' External ', trust: 'INTERNAL' }, { external_exposure: ['r1'] }
    );
    assert.equal(r.status, 'fail');
  });

  it('and a genuinely unrelated zone name still does not match', () => {
    // Trimming must not become matching-anything.
    const r = evaluateRulesetPropertyCheck(CHECK, RULES, { dmz: 'external' }, {});
    assert.equal(r.status, 'na');
  });
});

// ── the plumbing: the audit run must PASS the failure through ───────────────

// A pool stub that answers every query runComplianceAuditForDevice makes, and
// lets one of them be made to throw. `connect()` hands back a client whose
// INSERTs are recorded, because the finding DETAIL is what this file is about.
function auditPool({ zonesThrow = false } = {}) {
  const inserted = [];
  const answer = (sql) => {
    if (/FROM devices WHERE id/i.test(sql)) return { rows: [{ id: DEVICE_ID, vendor: 'paloalto' }] };
    if (/FROM audit_checks/i.test(sql)) return { rows: [CHECK] };
    if (/COUNT\(\*\)/i.test(sql)) return { rows: [{ count: RULES.length }] };
    if (/FROM zone_classifications/i.test(sql)) {
      if (zonesThrow) throw new Error('connection terminated unexpectedly');
      return { rows: [{ zone_name: 'untrust', role: 'external' }, { zone_name: 'trust', role: 'internal' }] };
    }
    if (/FROM rule_analysis_results/i.test(sql)) return { rows: [] };
    if (/FROM firewall_rules/i.test(sql)) return { rows: RULES };
    if (/FROM device_configs/i.test(sql)) return { rows: [{ config_parsed: { a: 1 } }] };
    return { rows: [] };
  };
  return {
    inserted,
    query: async (sql) => answer(String(sql)),
    connect: async () => ({
      query: async (sql, params) => {
        if (/INSERT INTO audit_findings/i.test(String(sql))) {
          inserted.push({ status: params[2], detail: params[3] });
          return { rows: [{ id: 'f1', device_id: DEVICE_ID, check_id: params[1], status: params[2], detail: params[3], matched_rule_ids: params[4], detected_at: new Date() }] };
        }
        return { rows: [] };
      },
      release: () => {},
    }),
  };
}

describe('⛔ the audit run distinguishes the two states end to end', () => {
  it('a zone-classification read FAILURE reaches the finding as a read failure', async () => {
    // ⛔ The engine used to swallow this into `{}`. The finding then carried the
    // operator instruction, which is the whole defect — so asserting on the
    // stored DETAIL is the only way to see it.
    const pool = auditPool({ zonesThrow: true });
    const { findings } = await runComplianceAuditForDevice(DEVICE_ID, pool);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].status, 'na');
    assert.match(findings[0].detail, /could not read/i);
    assert.equal(/haven't been classified/.test(findings[0].detail), false,
      'the audit must not convert its own read failure into an operator to-do');
  });

  it('and a SUCCESSFUL read still evaluates the check for real', async () => {
    const pool = auditPool();
    const { findings } = await runComplianceAuditForDevice(DEVICE_ID, pool);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].status, 'pass',
      'with zones classified and no external_exposure findings, the check passes');
  });

  it('a failed read still writes the finding — it is never dropped', async () => {
    // ⛔ Suppressing it would render a device whose classifications could not
    // be read identically to one where the check does not exist.
    const pool = auditPool({ zonesThrow: true });
    await runComplianceAuditForDevice(DEVICE_ID, pool);
    assert.equal(pool.inserted.length, 1);
    assert.equal(pool.inserted[0].status, 'na');
  });
});
