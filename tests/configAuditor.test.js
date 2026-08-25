'use strict';
// Pins the `warning` vs `na` boundary in the compliance engine (v2.64.1).
//
// THE INCIDENT: `predicate_type: 'not_evaluable_from_config'` is how the
// curated check library declares "SecVault cannot pose this question from a
// static config snapshot at all" (the fact is inherently per-rule, or it needs
// telemetry a config never holds). Until 2026-08-25 that spelling was not
// recognised by anything, so it fell through to evaluatePredicate()'s
// `default: return 'unknown'` and became a `warning` — which IS in the score
// denominator. Measured on the live 16-device fleet: 43 of 61 warnings were
// this, i.e. SecVault scoring customers' devices down for SecVault's own
// coverage gaps. Fleet score went 46% -> 51% when they moved to `na`, with no
// check changing between pass and fail — only the denominator.
//
// That is the same bug class as hit_count's old `NOT NULL DEFAULT 0`: OUR
// inability to measure, recorded as a negative fact about the DEVICE. So the
// two states must never be conflated:
//
//   warning = a fact about THIS DEVICE  -> COUNTS toward the score
//   na      = a fact about SECVAULT     -> EXCLUDED from the score
//
// The second load-bearing invariant here is `pass_when`, which decides which
// evaluatePredicate() outcome means PASS. Half the checks test a GOOD
// condition (pass_when:'yes') and half test a BAD one (pass_when:'no'), so a
// missing/misspelled value silently defaulting to 'yes' would invert pass and
// fail with nothing thrown and nothing logged.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  evaluateCheck,
  statusFromResult,
  evaluateRuleScanCheck,
  evaluateRulesetPropertyCheck,
  runComplianceAuditForDevice,
} = require('../lib/engines/configAuditor');

// One audit_checks row. predicate_config is already-parsed jsonb by the time
// any of these functions see it.
function checkWith(predicateConfig, overrides) {
  return Object.assign(
    {
      id: '00000000-0000-0000-0000-0000000000aa',
      check_id: 'test-check-1',
      name: 'Test check',
      standards: ['CIS_V8'],
      severity: 'medium',
      vendor: null,
      remediation_guidance: 'Do the thing.',
      predicate_config: predicateConfig,
    },
    overrides
  );
}

// One firewall_rules row, in the shape runComplianceAuditForDevice SELECTs for
// ruleset_property evaluation.
function ruleWith(overrides) {
  return Object.assign(
    {
      action: 'allow',
      src_addresses: ['10.0.0.1'],
      dst_addresses: ['10.0.0.2'],
      services: ['tcp/443'],
      enabled: true,
      src_zones: ['lan'],
      dst_zones: ['wan'],
    },
    overrides
  );
}

// A config a device really did give us, so "we could not resolve this value"
// is genuinely a fact about the device and not about collection.
const COLLECTED_CONFIG = { system: { http: 'disable' }, log_syslogd: { status: 'enable' } };

describe('configAuditor: `not_evaluable_from_config` is SECVAULT\'s limitation -> na, never warning', () => {
  it('resolves na for the seed shape that carries a reason and a placeholder pass_when', () => {
    const { status } = evaluateCheck(
      checkWith({
        predicate_type: 'not_evaluable_from_config',
        reason: 'IPS-sensor assignment is per-policy, outside device_configs.config_parsed.',
        pass_when: 'yes',
      }),
      COLLECTED_CONFIG
    );
    assert.equal(
      status,
      'na',
      'a warning here puts SecVault\'s own coverage gap into the customer\'s score denominator — ' +
        'that was 43 of the fleet\'s 61 warnings before 2026-08-25.'
    );
  });

  it('resolves na when the check definition carries no reason', () => {
    const { status } = evaluateCheck(
      checkWith({ predicate_type: 'not_evaluable_from_config', pass_when: 'yes' }),
      COLLECTED_CONFIG
    );
    assert.equal(status, 'na');
  });

  it('resolves na when the check definition carries no pass_when at all', () => {
    const { status } = evaluateCheck(
      checkWith({ predicate_type: 'not_evaluable_from_config', reason: 'Needs telemetry.' }),
      COLLECTED_CONFIG
    );
    assert.equal(
      status,
      'na',
      'pass_when is a placeholder on these rows and is never consulted; its absence must not ' +
        'divert the check into the invalid-pass_when warning.'
    );
  });

  it('is decided BEFORE the pass_when guard, so garbage pass_when is still na', () => {
    const { status, detail } = evaluateCheck(
      checkWith({
        predicate_type: 'not_evaluable_from_config',
        reason: 'License status comes from an op command, not the config tree.',
        pass_when: 'MAYBE',
      }),
      COLLECTED_CONFIG
    );
    assert.equal(status, 'na');
    assert.doesNotMatch(
      detail,
      /pass_when/,
      'validating a polarity that can never be applied is noise — order of the two guards is ' +
        'deliberate, not incidental.'
    );
  });

  it('still SURFACES the reason to the operator — na drops it from the score, not from the UI', () => {
    const { detail } = evaluateCheck(
      checkWith({
        predicate_type: 'not_evaluable_from_config',
        reason: '"unused" requires traffic/hit-count data a static snapshot never has.',
        pass_when: 'yes',
      }),
      COLLECTED_CONFIG
    );
    assert.match(
      detail,
      /requires traffic\/hit-count data/,
      'these become manual-verification items; hiding them would be a worse failure than ' +
        'mis-scoring them.'
    );
  });

  it('is na regardless of what was (or was not) collected — it is not a collection problem', () => {
    for (const config of [COLLECTED_CONFIG, null, undefined, {}, 'not-an-object']) {
      const { status } = evaluateCheck(
        checkWith({ predicate_type: 'not_evaluable_from_config', pass_when: 'yes' }),
        config
      );
      assert.equal(status, 'na', `config ${JSON.stringify(config)} should not change the verdict`);
    }
  });
});

describe('configAuditor: pass_when polarity never silently defaults', () => {
  // Anything that is not EXACTLY the string 'yes' or 'no'.
  const BAD = [
    ['undefined (field absent)', undefined],
    ['null', null],
    ['the empty string', ''],
    ['a misspelling', 'maybe'],
    ['the wrong case', 'YES'],
    ['a boolean instead of a string', true],
  ];

  for (const [label, passWhen] of BAD) {
    it(`warns (not passes, not fails) when pass_when is ${label}`, () => {
      const { status, detail } = evaluateCheck(
        checkWith({ predicate_type: 'feature_enabled', path: 'log_syslogd.status', pass_when: passWhen }),
        COLLECTED_CONFIG
      );
      assert.equal(
        status,
        'warning',
        'assuming a polarity would invert pass/fail for every check that tests a BAD condition ' +
          '(admin_access_from_zone, pass_when:\'no\') with no error anywhere.'
      );
      assert.match(
        detail,
        /check definition, not this device/,
        'the operator must be told this is curated-data breakage, not their firewall.'
      );
    });
  }

  it('an unparseable check definition is still a warning, not na — it IS in the denominator', () => {
    const { status } = evaluateCheck(checkWith({ predicate_type: 'feature_enabled' }), COLLECTED_CONFIG);
    assert.equal(
      status,
      'warning',
      'a broken check is a real question we failed to ask of a config we DID collect. Only ' +
        'questions that cannot be posed at all get excluded from the score.'
    );
  });

  it('a pass_when:"yes" check passes when the predicate says yes', () => {
    const { status } = evaluateCheck(
      checkWith({ predicate_type: 'feature_enabled', path: 'log_syslogd.status', pass_when: 'yes' }),
      COLLECTED_CONFIG
    );
    assert.equal(status, 'pass');
  });

  it('a pass_when:"yes" check fails when the predicate says no', () => {
    const { status } = evaluateCheck(
      checkWith({ predicate_type: 'feature_enabled', path: 'log_syslogd.status', pass_when: 'yes' }),
      { log_syslogd: { status: 'disable' } }
    );
    assert.equal(status, 'fail');
  });

  it('an INVERTED check (pass_when:"no") passes when the predicate says no', () => {
    const { status } = evaluateCheck(
      checkWith({
        predicate_type: 'config_value_equals',
        path: 'system.http',
        value: 'enable',
        pass_when: 'no',
      }),
      COLLECTED_CONFIG
    );
    assert.equal(
      status,
      'pass',
      'HTTP management is NOT enabled, which is the compliant answer. This is the direction a ' +
        'silently-defaulted pass_when would get exactly backwards.'
    );
  });

  it('an INVERTED check (pass_when:"no") fails when the predicate says yes', () => {
    const { status } = evaluateCheck(
      checkWith({
        predicate_type: 'config_value_equals',
        path: 'system.http',
        value: 'enable',
        pass_when: 'no',
      }),
      { system: { http: 'enable' } }
    );
    assert.equal(status, 'fail');
  });
});

describe('configAuditor: statusFromResult maps tri-state x polarity to four-state', () => {
  const MATRIX = [
    ['yes', 'yes', 'pass'],
    ['no', 'yes', 'fail'],
    ['unknown', 'yes', 'warning'],
    ['yes', 'no', 'fail'],
    ['no', 'no', 'pass'],
    ['unknown', 'no', 'warning'],
  ];

  for (const [result, passWhen, expected] of MATRIX) {
    it(`predicate "${result}" with pass_when "${passWhen}" -> ${expected}`, () => {
      assert.equal(statusFromResult(result, passWhen), expected);
    });
  }

  it('never resolves an unknown to a definite pass or fail, whichever polarity is asked', () => {
    assert.equal(statusFromResult('unknown', 'yes'), 'warning');
    assert.equal(statusFromResult('unknown', 'no'), 'warning');
  });
});

describe('configAuditor: an indeterminate answer from a config we DID collect is the DEVICE\'s limitation -> warning', () => {
  it('warns when a real predicate resolves unknown against a real config', () => {
    const { status, detail } = evaluateCheck(
      checkWith({ predicate_type: 'feature_enabled', path: 'log_syslogd.status', pass_when: 'yes' }),
      { log_syslogd: { status: 'sometimes' } }
    );
    assert.equal(status, 'warning');
    assert.match(detail, /Could not determine/);
  });

  it('warns (not na) for an unrecognised predicate_type that is not the declared not_evaluable spelling', () => {
    const { status } = evaluateCheck(
      checkWith({ predicate_type: 'invented_predicate', pass_when: 'yes' }),
      COLLECTED_CONFIG
    );
    assert.equal(
      status,
      'warning',
      'only the ONE declared spelling means "unanswerable by construction". A typo in curated ' +
        'data must stay visible in the score rather than quietly leaving it.'
    );
  });
});

describe('configAuditor: rule_scan separates a curated-data problem from a coverage problem', () => {
  it('warns on an empty finding_types list — a CURATED-DATA problem, never a vacuous pass', () => {
    const { status, detail, matchedRuleIds } = evaluateRuleScanCheck(checkWith({ finding_types: [] }), {});
    assert.equal(status, 'warning');
    assert.match(detail, /check definition, not this device/);
    assert.deepEqual(matchedRuleIds, []);
  });

  it('warns when predicate_config is missing entirely', () => {
    const check = checkWith(undefined);
    delete check.predicate_config;
    assert.equal(evaluateRuleScanCheck(check, {}).status, 'warning');
  });

  it('passes when the device has rules but none carry the scanned finding types', () => {
    const { status, matchedRuleIds } = evaluateRuleScanCheck(
      checkWith({ finding_types: ['any_any', 'overly_permissive'] }),
      { unused: ['rule-9'] }
    );
    assert.equal(status, 'pass', 'every rule_scan check is "this bad pattern should not exist".');
    assert.deepEqual(matchedRuleIds, []);
  });

  it('fails and reports each offending rule ONCE when one rule carries two scanned types', () => {
    const { status, matchedRuleIds } = evaluateRuleScanCheck(
      checkWith({ finding_types: ['any_any', 'overly_permissive'] }),
      { any_any: ['rule-1', 'rule-2'], overly_permissive: ['rule-2', 'rule-3'] }
    );
    assert.equal(status, 'fail');
    assert.deepEqual(matchedRuleIds, ['rule-1', 'rule-2', 'rule-3'], 'rule-2 must not be double-counted');
  });
});

describe('configAuditor: ruleset_property separates a curated-data problem from a coverage problem', () => {
  it('warns on an unrecognised property — a CURATED-DATA problem (counts toward the score)', () => {
    const { status, detail } = evaluateRulesetPropertyCheck(
      checkWith({ property: 'invented_property' }),
      [ruleWith({})]
    );
    assert.equal(status, 'warning', 'never a silent false pass or fail for a check we mis-typed.');
    assert.match(detail, /check definition, not this device/);
  });

  it('is na when the device\'s zones are not classified — a COVERAGE problem (excluded from the score)', () => {
    const { status, matchedRuleIds } = evaluateRulesetPropertyCheck(
      checkWith({ property: 'no_external_to_internal_access' }),
      [ruleWith({ src_zones: ['wan'], dst_zones: ['lan'] })],
      {}, // zone_classifications starts EMPTY on every fresh install
      {}
    );
    assert.equal(
      status,
      'na',
      'reporting pass because zero rules HAPPENED to match, when the real reason is "we cannot ' +
        'tell", would show every device fleet-wide as compliant from day one.'
    );
    assert.deepEqual(matchedRuleIds, []);
  });

  it('is na when only one side of the External/Internal pair is classified', () => {
    const { status } = evaluateRulesetPropertyCheck(
      checkWith({ property: 'no_external_to_internal_access' }),
      [ruleWith({ src_zones: ['wan'], dst_zones: ['lan'] })],
      { wan: 'external' },
      {}
    );
    assert.equal(status, 'na');
  });

  it('passes only once both zone roles exist AND no external_exposure finding was recorded', () => {
    const { status } = evaluateRulesetPropertyCheck(
      checkWith({ property: 'no_external_to_internal_access' }),
      [ruleWith({ src_zones: ['wan'], dst_zones: ['lan'] })],
      { wan: 'external', lan: 'internal' },
      {}
    );
    assert.equal(status, 'pass');
  });

  it('fails, reusing ruleAnalysis\'s already-decided external_exposure findings', () => {
    const { status, matchedRuleIds } = evaluateRulesetPropertyCheck(
      checkWith({ property: 'no_external_to_internal_access' }),
      [ruleWith({ src_zones: ['wan'], dst_zones: ['lan'] })],
      { wan: 'external', lan: 'internal' },
      { external_exposure: ['rule-7'] }
    );
    assert.equal(status, 'fail');
    assert.deepEqual(matchedRuleIds, ['rule-7']);
  });

  it('recognises Cisco ASA\'s `deny ip any any` as an explicit deny-all', () => {
    const { status } = evaluateRulesetPropertyCheck(checkWith({ property: 'has_explicit_deny_all' }), [
      ruleWith({ action: 'deny', src_addresses: ['any'], dst_addresses: ['any'], services: ['ip'] }),
    ]);
    assert.equal(
      status,
      'pass',
      '"ip" is ASA\'s all-protocols token and is a service wildcard; without it the single most ' +
        'common real ASA deny-all pattern reported FAIL on a compliant device.'
    );
  });

  it('does not count a DISABLED catch-all deny as an explicit deny-all', () => {
    const { status } = evaluateRulesetPropertyCheck(checkWith({ property: 'has_explicit_deny_all' }), [
      ruleWith({
        action: 'deny',
        enabled: false,
        src_addresses: ['any'],
        dst_addresses: ['any'],
        services: ['any'],
      }),
    ]);
    assert.equal(status, 'fail');
  });

  it('recognises FortiOS\'s own built-in ALL_ICMP object as blocking ICMP', () => {
    const { status } = evaluateRulesetPropertyCheck(checkWith({ property: 'blocks_icmp' }), [
      ruleWith({ action: 'deny', services: ['ALL_ICMP'] }),
    ]);
    assert.equal(
      status,
      'pass',
      '\\bicmp\\b does not fire between "_" and "I", so the old pattern failed FortiOS\'s own ' +
        'out-of-the-box ICMP block.'
    );
  });

  it('does not treat an unrelated service name merely containing "icmp" as an ICMP block', () => {
    const { status } = evaluateRulesetPropertyCheck(checkWith({ property: 'blocks_icmp' }), [
      ruleWith({ action: 'deny', services: ['richmp-service'] }),
    ]);
    assert.equal(status, 'fail');
  });

  it('reports fail — NOT na — for an empty rule list: the no-ruleset guard lives in the caller', () => {
    // Documenting the seam, not endorsing it. runComplianceAuditForDevice
    // short-circuits ruleCount === 0 to 'na' BEFORE calling this function
    // (pinned below), so this pure function is only ever reached with rules
    // present. Anyone calling it directly must apply that guard themselves.
    assert.equal(
      evaluateRulesetPropertyCheck(checkWith({ property: 'has_explicit_deny_all' }), []).status,
      'fail'
    );
  });
});

describe('configAuditor: the evaluators never throw on malformed curated data', () => {
  const CONFIGS = [null, undefined, {}, [], 'a string', 42, { deeply: { nested: [1, 2, 3] } }];
  const PREDICATE_CONFIGS = [
    undefined,
    null,
    {},
    { predicate_type: 'config_value_matches', path: 'a.b', pattern: '([', pass_when: 'yes' },
    { predicate_type: 'config_key_exists', pass_when: 'yes' },
    { predicate_type: 'unknown_type', pass_when: 'no' },
  ];

  it('evaluateCheck survives every combination of malformed predicate_config and config', () => {
    for (const predicateConfig of PREDICATE_CONFIGS) {
      for (const config of CONFIGS) {
        const out = evaluateCheck(checkWith(predicateConfig), config);
        assert.ok(
          ['pass', 'fail', 'warning', 'na'].includes(out.status),
          `unexpected status ${out.status}`
        );
        assert.equal(typeof out.detail, 'string');
      }
    }
  });

  it('evaluateRuleScanCheck survives a missing/garbage findings map', () => {
    for (const map of [undefined, null, {}, { any_any: null }]) {
      const out = evaluateRuleScanCheck(checkWith({ finding_types: ['any_any'] }), map || {});
      assert.ok(['pass', 'fail', 'warning'].includes(out.status));
    }
  });

  it('evaluateRulesetPropertyCheck survives rules with missing/garbage fields', () => {
    const rules = [
      {},
      ruleWith({ action: null, services: null, src_addresses: null, dst_addresses: null }),
      ruleWith({ services: 'not-an-array', src_zones: 'not-an-array' }),
      ruleWith({ action: '  DENY  ', src_addresses: ['  '], dst_addresses: [], services: ['ANY'] }),
    ];
    for (const property of ['has_explicit_deny_all', 'blocks_icmp', 'no_external_to_internal_access']) {
      const out = evaluateRulesetPropertyCheck(checkWith({ property }), rules, {}, {});
      assert.ok(['pass', 'fail', 'warning', 'na'].includes(out.status));
    }
  });

  it('statusFromResult returns a valid status for junk inputs', () => {
    assert.equal(statusFromResult(undefined, 'yes'), 'fail');
    assert.equal(statusFromResult('unknown', undefined), 'warning');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// One stub-pool test, because the "nothing was collected" half of the
// warning-vs-na rule lives in the DB wrapper, not in the pure evaluators: a
// config-predicate check with no config, and any rule-based check with no
// ruleset, must be `na` (SecVault has nothing to look at) and never `fail`.
// No DB — the stub answers by matching the SQL it is handed.
function stubPool({ configParsed = null, checks = [], ruleCount = 0, rules = [], zones = [] }) {
  const inserted = [];
  const client = {
    async query(sql, params) {
      if (sql.includes('INSERT INTO audit_findings')) {
        const row = {
          id: `finding-${inserted.length}`,
          device_id: params[0],
          check_id: params[1],
          status: params[2],
          detail: params[3],
          matched_rule_ids: params[4],
          detected_at: new Date(0),
        };
        inserted.push(row);
        return { rows: [row] };
      }
      return { rows: [] };
    },
    release() {},
  };
  const pool = {
    async query(sql) {
      if (sql.includes('FROM devices')) return { rows: [{ id: 'device-1', vendor: 'fortinet' }] };
      if (sql.includes('FROM device_configs')) {
        return { rows: configParsed === null ? [] : [{ config_parsed: configParsed }] };
      }
      if (sql.includes('FROM audit_checks')) return { rows: checks };
      if (sql.includes('COUNT(*)')) return { rows: [{ count: ruleCount }] };
      if (sql.includes('FROM firewall_rules')) return { rows };
      if (sql.includes('FROM rule_analysis_results')) return { rows: [] };
      if (sql.includes('FROM zone_classifications')) return { rows: zones };
      return { rows: [] };
    },
    async connect() {
      return client;
    },
  };
  return { pool, inserted };
}

describe('configAuditor: nothing collected is na, never fail (wrapper-level guard)', () => {
  const CHECKS = [
    checkWith({ predicate_type: 'config_key_exists', path: 'ntp.server', pass_when: 'yes' }, {
      id: 'check-config',
      check_id: 'cfg',
      name: 'NTP configured',
    }),
    checkWith({ predicate_type: 'rule_scan', finding_types: ['any_any'] }, {
      id: 'check-scan',
      check_id: 'scan',
      name: 'No any-any rules',
    }),
    checkWith({ predicate_type: 'ruleset_property', property: 'has_explicit_deny_all' }, {
      id: 'check-prop',
      check_id: 'prop',
      name: 'Explicit deny-all exists',
    }),
  ];

  it('marks every check na on a device with no config and no rules collected yet', async () => {
    const { pool } = stubPool({ configParsed: null, checks: CHECKS, ruleCount: 0 });
    const { findings } = await runComplianceAuditForDevice('device-1', pool);
    assert.equal(findings.length, 3);
    for (const finding of findings) {
      assert.equal(
        finding.status,
        'na',
        `${finding.check_id_slug} scored a device down for data SecVault never collected`
      );
    }
  });

  it('still evaluates config checks for real when the config exists but the ruleset does not', async () => {
    const { pool } = stubPool({
      configParsed: { ntp: { server: '10.0.0.1' } },
      checks: CHECKS,
      ruleCount: 0,
    });
    const { findings } = await runComplianceAuditForDevice('device-1', pool);
    const byCheck = Object.fromEntries(findings.map((f) => [f.check_id_slug, f.status]));
    assert.equal(byCheck.cfg, 'pass', 'a missing ruleset must not blanket-na a config check');
    assert.equal(byCheck.scan, 'na');
    assert.equal(byCheck.prop, 'na', 'no ruleset means the deny-all question cannot be posed');
  });
});
