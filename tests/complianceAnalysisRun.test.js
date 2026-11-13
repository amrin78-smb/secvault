'use strict';

// ⛔ ROADMAP ROW 27: EIGHT `rule_scan` CHECKS PLUS `rule-no-external-to-internal-access`
// RETURNED `pass` ON A DEVICE WHOSE RULE ANALYSIS HAD NEVER RUN.
//
// Both evaluators decide from `rule_analysis_results`, where ZERO ROWS has two causes:
// ruleAnalysis.js ran and found nothing, or ruleAnalysis.js never ran. The 2026-09-09 guard
// wrote that sentence out and then tested only the SIZE CAP -- the never-ran case for one
// ruleset shape. The whole-run case was open at every ruleset size, so a never-analysed
// firewall collected NINE free passes and its compliance score went UP. Same shape as the
// v2.94.0 fix on /devices, where OKF(F2) scored 100/100 for never having been collected.
//
// These tests pin the OUTCOME (which status, on which inputs) rather than the mechanism,
// because the shipped defect passed a suite that only ever asserted the mechanism.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  evaluateRuleScanCheck,
  evaluateRulesetPropertyCheck,
  analysisRanState,
  ruleScanNoRunDetail,
  loadAnalysisRunState,
} = require('../lib/engines/configAuditor');

function scanCheck(findingTypes) {
  return {
    check_id: 'rule-no-shadowed-rules',
    name: 'No shadowed rules',
    predicate_config: { predicate_type: 'rule_scan', finding_types: findingTypes },
  };
}

function exposureCheck() {
  return {
    check_id: 'rule-no-external-to-internal-access',
    name: 'No external-to-internal access',
    predicate_config: {
      predicate_type: 'ruleset_property',
      property: 'no_external_to_internal_access',
    },
  };
}

const EXPOSED_RULE = {
  action: 'allow',
  enabled: true,
  src_zones: ['wan'],
  dst_zones: ['lan'],
  services: ['any'],
  src_addresses: ['any'],
  dst_addresses: ['any'],
};
const ZONES = { wan: 'external', lan: 'internal' };

describe('analysisRanState: three states, and only a literal boolean is an answer', () => {
  it('maps true to ran and false to never', () => {
    assert.equal(analysisRanState(true), 'ran');
    assert.equal(analysisRanState(false), 'never');
  });

  it('maps everything else to unknown — a typo or an omission must never read as "ran"', () => {
    for (const v of [null, undefined, 0, 1, '', 'true', 'ran', 'yes', {}, [], NaN]) {
      assert.equal(
        analysisRanState(v),
        'unknown',
        `${JSON.stringify(v)} must not be accepted as a completed run`
      );
    }
  });
});

describe('rule_scan: zero findings with no completed run is na, never pass', () => {
  it('is na when no analysis run has ever completed', () => {
    const out = evaluateRuleScanCheck(scanCheck(['shadow']), {}, [], false);
    assert.equal(out.status, 'na', 'zero findings from no run is NOT MEASURED, not clean');
    assert.deepEqual(out.matchedRuleIds, []);
  });

  it('is na when the run state could not be read', () => {
    assert.equal(evaluateRuleScanCheck(scanCheck(['shadow']), {}, [], null).status, 'na');
  });

  it('is na — never pass — when the argument is omitted entirely', () => {
    // Fails CLOSED: a caller that forgets the parameter must not be able to reach the
    // free pass this guard exists to prevent.
    const out = evaluateRuleScanCheck(scanCheck(['shadow']), {}, []);
    assert.equal(out.status, 'na');
    assert.notEqual(out.status, 'pass');
  });

  it('passes on zero findings once a run HAS completed — the no-regression case', () => {
    const out = evaluateRuleScanCheck(scanCheck(['shadow']), { unused: ['r-1'] }, [], true);
    assert.equal(out.status, 'pass');
  });

  it('⛔ still FAILS on a present finding whatever the run state says', () => {
    // A stored finding is a MEASUREMENT. Returning na here would suppress a real, evidenced
    // violation to protest a bookkeeping disagreement — the opposite of this guard's purpose.
    for (const ran of [false, null, undefined]) {
      const out = evaluateRuleScanCheck(scanCheck(['shadow']), { shadow: ['r-7'] }, [], ran);
      assert.equal(out.status, 'fail', `a present finding must still fail (analysisRan=${ran})`);
      assert.deepEqual(out.matchedRuleIds, ['r-7']);
    }
  });

  it('⛔ still WARNS on a curated-data problem whatever the run state says', () => {
    // An empty finding_types list is a fact about the CHECK, true of every device. Gating it
    // behind the run state would hide a broken check definition on a fleet that has not been
    // analysed — suppressing the one finding an administrator can actually fix.
    for (const ran of [false, null, true]) {
      assert.equal(
        evaluateRuleScanCheck(scanCheck([]), {}, [], ran).status,
        'warning',
        `an empty finding_types list must stay visible (analysisRan=${ran})`
      );
    }
  });
});

describe('no_external_to_internal_access: the same hole, the same guard', () => {
  it('is na with classified zones but no completed run', () => {
    const out = evaluateRulesetPropertyCheck(exposureCheck(), [EXPOSED_RULE], ZONES, {}, false);
    assert.equal(
      out.status,
      'na',
      'claiming "no rule spans External to Internal" about an unanalysed device is a fabricated pass'
    );
  });

  it('is na when the run state could not be read', () => {
    assert.equal(
      evaluateRulesetPropertyCheck(exposureCheck(), [EXPOSED_RULE], ZONES, {}, null).status,
      'na'
    );
  });

  it('is na — never pass — when the argument is omitted', () => {
    assert.equal(
      evaluateRulesetPropertyCheck(exposureCheck(), [EXPOSED_RULE], ZONES, {}).status,
      'na'
    );
  });

  it('passes once a run has completed and recorded no exposure', () => {
    assert.equal(
      evaluateRulesetPropertyCheck(exposureCheck(), [EXPOSED_RULE], ZONES, {}, true).status,
      'pass'
    );
  });

  it('⛔ still fails on a recorded external_exposure finding whatever the run state says', () => {
    for (const ran of [false, null, undefined]) {
      const out = evaluateRulesetPropertyCheck(
        exposureCheck(), [EXPOSED_RULE], ZONES, { external_exposure: ['r-9'] }, ran
      );
      assert.equal(out.status, 'fail', `analysisRan=${ran}`);
      assert.deepEqual(out.matchedRuleIds, ['r-9']);
    }
  });
});

describe('the two na sentences are not interchangeable', () => {
  it('names an action for never-ran and a fault for unreadable', () => {
    const never = ruleScanNoRunDetail({ name: 'No shadowed rules' }, 'never');
    const unknown = ruleScanNoRunDetail({ name: 'No shadowed rules' }, 'unknown');

    assert.match(never, /never completed a rule analysis run/);
    assert.match(never, /NOT MEASURED, not clean/);
    assert.match(never, /Run an analysis/, 'the operator must be told what to do');

    assert.match(unknown, /could not determine/);
    assert.match(unknown, /SecVault-side read failure/);
    assert.doesNotMatch(
      unknown,
      /never completed a rule analysis run/,
      'a read failure must not be reported as a confirmed absence of any run'
    );
    assert.notEqual(never, unknown, 'the two send an operator to different places');
  });

  it('neither sentence claims the check would have passed', () => {
    for (const state of ['never', 'unknown']) {
      const d = ruleScanNoRunDetail({ name: 'No shadowed rules' }, state);
      assert.doesNotMatch(d, /\bpassed\b/, `${state} must not read as a pass`);
    }
  });
});

describe('loadAnalysisRunState: a failed read is null, never a verdict', () => {
  it('returns true when device_risk_history holds a row', async () => {
    const pool = { query: async () => ({ rows: [{ count: 3 }] }) };
    assert.equal(await loadAnalysisRunState('d-1', pool), true);
  });

  it('returns false on zero rows', async () => {
    const pool = { query: async () => ({ rows: [{ count: 0 }] }) };
    assert.equal(await loadAnalysisRunState('d-1', pool), false);
  });

  it('returns null when the query throws — not false, and never true', async () => {
    const pool = { query: async () => { throw new Error('connection terminated'); } };
    const out = await loadAnalysisRunState('d-1', pool);
    assert.equal(out, null);
    assert.notEqual(out, true, 'true would reinstate the fabricated pass');
    assert.notEqual(out, false, 'false would tell an operator their analysis never ran');
  });

  it('returns null on an unreadable count rather than coercing it', async () => {
    for (const rows of [[], [{ count: null }], [{ count: 'many' }], [{}]]) {
      assert.equal(await loadAnalysisRunState('d-1', { query: async () => ({ rows }) }), null);
    }
  });

  it('⛔ reads device_risk_history, NOT rule_analysis_results', async () => {
    // rule_analysis_results' zero-row state IS the ambiguity being resolved, so it cannot be
    // its own evidence. device_risk_history is the signal lib/deviceContext.js already uses.
    let sql = '';
    const pool = { query: async (q) => { sql = q; return { rows: [{ count: 1 }] }; } };
    await loadAnalysisRunState('d-1', pool);
    assert.match(sql, /device_risk_history/);
    assert.doesNotMatch(sql, /rule_analysis_results/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Separate decision, same release: the manual compliance-report trigger's gate.

describe('⛔ POST /api/compliance/report/generate is manage_settings, not operate', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const ROUTE = path.join(
    __dirname, '..', 'app', 'api', 'compliance', 'report', 'generate', 'route.js'
  );
  // Strip comments first: this file's own prose names both capabilities, and a raw-source
  // scan would read the explanation as the implementation — the mistake
  // deviceScopeCoverage.test.js records making against lib/notificationChannels.js.
  const code = fs.readFileSync(ROUTE, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');

  it('gates on MANAGE_SETTINGS', () => {
    // It MAILS a fleet-wide compliance PDF to a recipient list only manage_settings can read
    // or configure. CLAUDE.md gates GET /api/reports/schedules on that capability because the
    // list "names the recipients of fleet-wide security documents"; triggering a send to it
    // cannot need less than reading it.
    assert.match(code, /can\(session,\s*MANAGE_SETTINGS\)/);
    assert.match(code, /forbiddenResponse\(MANAGE_SETTINGS\)/);
  });

  it('⛔ does not gate on OPERATE anywhere', () => {
    // Where it sat until 2026-11-13, while the comment above it claimed "admin-gated" —
    // operate is held by every role, including the lowest.
    assert.doesNotMatch(code, /\bOPERATE\b/);
  });

  it('still routes through the ONE shared dispatch path', () => {
    // A second implementation would drift from the scheduled monthly job's idempotency.
    assert.match(code, /dispatchMonthlyReport/);
  });
});
