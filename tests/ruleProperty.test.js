'use strict';
// tests/ruleProperty.test.js
//
// ⛔ THE FOURTH EVALUATOR SHAPE, AND THE ONE THAT TURNS `na` INTO ANSWERS.
// Three compliance checks were declared `not_evaluable_from_config` for one
// structural reason: the predicate engine followed a single fixed dot-path into
// `device_configs.config_parsed`, and the fact they ask about is attached to
// EVERY RULE. `rule_property` is the missing universal quantifier.
//
// ⛔ THE RISK IS NOT "does it find violations" — it is "does it invent them".
// Measured on the live fleet 2026-09-22: 33 of 1,586 Palo Alto rules are pushed
// from Panorama, where a security-profile group can be attached out of this
// firewall's sight. Reading their silence as "no profile" would manufacture 33
// findings from a place SecVault cannot see. Most of what follows is about the
// cases that must NOT become a finding, and the ones that must not become a
// pass either.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { evaluateRulePropertyCheck } = require('../lib/engines/configAuditor');

const CHECK = {
  name: 'Security profiles applied',
  predicate_config: {
    predicate_type: 'rule_property',
    subject: 'a security profile',
    applies_to: { action: 'allow', enabled_only: true },
    require_any_path: ['profile-setting.group', 'profile-setting.profiles'],
    undecidable_when_key: '@_panorama',
    undecidable_reason: 'it is pushed from Panorama',
  },
};

const withCfg = (extra) => ({
  ...CHECK,
  predicate_config: { ...CHECK.predicate_config, ...extra },
});

let seq = 0;
function rule(raw, over = {}) {
  seq += 1;
  return {
    id: `r${seq}`,
    rule_name: `rule-${seq}`,
    action: 'allow',
    enabled: true,
    src_zones: ['untrust'],
    dst_zones: ['trust'],
    raw_rule: raw,
    ...over,
  };
}
const withProfiles = () => rule({ 'profile-setting': { profiles: { virus: { member: 'default' } } } });
const withGroup = () => rule({ 'profile-setting': { group: { member: 'strict' } } });
const bare = () => rule({ action: 'allow' });
const panorama = () => rule({ action: 'allow', '@_panorama': 'yes' });

const ZONES = { untrust: 'external', trust: 'internal' };

describe('the two compliant shapes both pass', () => {
  it('individually-attached profiles and a profile group are equally valid', () => {
    // 975 live rules use `profiles`, 88 use `group`. Accepting only one would
    // fail 88 correctly-configured rules.
    const r = evaluateRulePropertyCheck(CHECK, [withProfiles(), withGroup()], ZONES);
    assert.equal(r.status, 'pass');
    assert.match(r.detail, /all 2 applicable rule\(s\)/);
  });

  it('a rule genuinely without the setting is a definite failure, and is NAMED', () => {
    const bad = bare();
    const r = evaluateRulePropertyCheck(CHECK, [withProfiles(), bad], ZONES);
    assert.equal(r.status, 'fail');
    assert.match(r.detail, /1 of 2 applicable/);
    assert.match(r.detail, new RegExp(bad.rule_name), 'a count with no names is not actionable');
    assert.deepEqual(r.matchedRuleIds, [bad.id]);
  });

  it('⛔ the sentence reads correctly — `subject` carries its own article', () => {
    // Shipped as "have no a security profile" in v2.167.0 and was visible on
    // nine live firewalls. A template that concatenates a determiner in front
    // of a phrase that already has one is the kind of defect every test here
    // passed straight over, because they all asserted counts.
    const r = evaluateRulePropertyCheck(CHECK, [bare()], ZONES);
    assert.equal(/no a |no an /.test(r.detail), false, r.detail);
    assert.match(r.detail, /are missing a security profile/);
    // The pass and warning sentences read the subject too.
    assert.match(
      evaluateRulePropertyCheck(CHECK, [withGroup()], ZONES).detail,
      /carry a security profile/
    );
  });
});

describe('⛔ a rule we cannot judge is never a finding and never a pass', () => {
  it('a Panorama-pushed rule with no profile is UNDECIDABLE, not a violation', () => {
    // The whole correctness argument. Its group may be attached in Panorama.
    const r = evaluateRulePropertyCheck(CHECK, [withProfiles(), panorama()], ZONES);
    assert.equal(r.status, 'warning', 'not fail — we did not observe an absence');
    assert.match(r.detail, /could not be judged/);
    assert.match(r.detail, /Panorama/);
  });

  it('⛔ and it does not become a pass either, even when every other rule is clean', () => {
    // An all-clear is forbidden while coverage is incomplete.
    const r = evaluateRulePropertyCheck(CHECK, [panorama()], ZONES);
    assert.equal(r.status, 'warning');
    assert.equal(/passed/.test(r.detail), false);
  });

  it('a missing raw_rule is undecidable, never "no profile"', () => {
    // An adapter that could not supply the verbatim rule tells us nothing
    // about what is attached to it.
    for (const raw of [null, undefined, 'not-an-object', 42]) {
      const r = evaluateRulePropertyCheck(CHECK, [rule(raw)], ZONES);
      assert.equal(r.status, 'warning', `raw_rule=${JSON.stringify(raw)} must not fail the rule`);
    }
  });

  it('⛔ a definite violation OUTRANKS an undecidable one', () => {
    // Rules we cannot judge must not bury rules we can: reporting `warning`
    // while real rules definitely lack a profile hides the finding behind a
    // caveat.
    const r = evaluateRulePropertyCheck(CHECK, [bare(), panorama()], ZONES);
    assert.equal(r.status, 'fail');
    assert.match(r.detail, /1 of 2 applicable/);
    assert.match(r.detail, /1 further rule\(s\) could not be judged/,
      'the undecidable one is still disclosed, not dropped');
  });
});

describe('⛔ present-but-empty is not configured', () => {
  it('an empty object, empty string or empty array is not a profile', () => {
    // A vendor emitting `profile-setting: {}` has said the field carries
    // nothing. Reading that as configured turns an empty element into a pass.
    for (const empty of [{}, '', []]) {
      const r = evaluateRulePropertyCheck(
        withCfg({ require_any_path: ['profile-setting'] }),
        [rule({ 'profile-setting': empty })],
        ZONES
      );
      assert.equal(r.status, 'fail', `${JSON.stringify(empty)} must not count as set`);
    }
  });

  it('but a populated value of any type counts', () => {
    const r = evaluateRulePropertyCheck(
      withCfg({ require_any_path: ['ips-sensor'] }),
      [rule({ 'ips-sensor': 'default' })],
      ZONES
    );
    assert.equal(r.status, 'pass');
  });
});

describe('⛔ nothing to assess is `na`, never a pass', () => {
  it('no applicable rules resolves na, not a clean score over an empty set', () => {
    // "0 of 0 rules are missing a profile" rendered as a pass is a clean
    // result computed from nothing.
    const r = evaluateRulePropertyCheck(CHECK, [rule({}, { action: 'deny' })], ZONES);
    assert.equal(r.status, 'na');
    assert.match(r.detail, /nothing to assess/);
  });

  it('disabled rules are excluded from the question', () => {
    const r = evaluateRulePropertyCheck(CHECK, [bare(), bare()].map((x) => ({ ...x, enabled: false })), ZONES);
    assert.equal(r.status, 'na', 'a disabled rule permits nothing');
  });

  it('and an empty ruleset is na rather than a pass', () => {
    assert.equal(evaluateRulePropertyCheck(CHECK, [], ZONES).status, 'na');
  });
});

describe('⛔ a zone-scoped question needs classified zones, and says so', () => {
  const zoned = withCfg({ applies_to: { action: 'allow', enabled_only: true, src_zone_role: 'external' } });

  it('unclassified zones give an ACTIONABLE na, not a guess and not a pass', () => {
    // Only 5 of the reference fleet's 16 firewalls have classified zones.
    // Guessing which zone faces the internet from its name is the
    // "documentation lies" trap aimed at a customer's own naming.
    const r = evaluateRulePropertyCheck(zoned, [bare()], {});
    assert.equal(r.status, 'na');
    assert.match(r.detail, /classified as external yet/);
    assert.match(r.detail, /Classify this device's zones/,
      'the reason must name the thing the operator can fix');
  });

  it('with zones classified, only externally-sourced rules are judged', () => {
    const internalOnly = rule({ action: 'allow' }, { src_zones: ['trust'] });
    const external = bare();
    const r = evaluateRulePropertyCheck(zoned, [internalOnly, external], ZONES);
    assert.equal(r.status, 'fail');
    assert.equal(r.matchedRuleIds.length, 1);
    assert.deepEqual(r.matchedRuleIds, [external.id], 'the internal-only rule is out of scope');
  });

  it('⛔ `any` as a source zone INCLUDES the external one', () => {
    // Matching `any` literally would understate exposure — the dangerous
    // direction on a security report.
    const r = evaluateRulePropertyCheck(zoned, [rule({ action: 'allow' }, { src_zones: ['any'] })], ZONES);
    assert.equal(r.status, 'fail', 'a rule open to any source is open to the internet');
  });
});

describe('⛔ a broken check definition is the check\'s problem, not the device\'s', () => {
  it('no require_any_path is a warning naming the definition', () => {
    for (const bad of [undefined, [], 'nope']) {
      const r = evaluateRulePropertyCheck(withCfg({ require_any_path: bad }), [bare()], ZONES);
      assert.equal(r.status, 'warning');
      assert.match(r.detail, /not with this firewall/);
    }
  });

  it('a path into a non-object does not throw', () => {
    const r = evaluateRulePropertyCheck(
      withCfg({ require_any_path: ['a.b.c.d'] }),
      [rule({ a: 'scalar' })],
      ZONES
    );
    assert.equal(r.status, 'fail');
  });
});

describe('reproduces the live fleet', () => {
  it('PAKFood: 27 Panorama rules, no definite violation -> warning', () => {
    const rules = Array.from({ length: 27 }, () => panorama());
    const r = evaluateRulePropertyCheck(CHECK, rules, ZONES);
    assert.equal(r.status, 'warning');
    assert.match(r.detail, /27 of 27 could not be judged/);
  });

  it('IDC FW: 447 applicable, 415 without a log-forwarding profile -> fail', () => {
    const logCheck = withCfg({
      subject: 'a log-forwarding profile',
      require_any_path: ['log-setting'],
    });
    const rules = [
      ...Array.from({ length: 415 }, () => bare()),
      ...Array.from({ length: 32 }, () => rule({ 'log-setting': 'default' })),
    ];
    const r = evaluateRulePropertyCheck(logCheck, rules, ZONES);
    assert.equal(r.status, 'fail');
    assert.match(r.detail, /415 of 447 applicable/);
  });

  it('HRIS: every applicable rule logs -> pass', () => {
    const logCheck = withCfg({ subject: 'a log-forwarding profile', require_any_path: ['log-setting'] });
    const rules = Array.from({ length: 38 }, () => rule({ 'log-setting': 'default' }));
    assert.equal(evaluateRulePropertyCheck(logCheck, rules, ZONES).status, 'pass');
  });
});
