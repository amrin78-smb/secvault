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

describe('⛔ a rule whose source zone was never reported must not VANISH', () => {
  const zoned = withCfg({ applies_to: { action: 'allow', enabled_only: true, src_zone_role: 'external' } });

  // `firewall_rules.src_zones` is NULLABLE, and a rule the device reported no
  // source interface for used to fall out of the applicable set entirely —
  // neither judged nor counted nor disclosed. It did not become a warning, it
  // became invisible, and a check whose whole scope disappeared that way
  // reported `na` ("nothing to assess") on a firewall with plenty to assess.
  for (const missing of [null, undefined, [], '', '   ', ['  ']]) {
    it(`src_zones=${JSON.stringify(missing)} is UNCONSTRAINED, so the rule is in scope`, () => {
      const orphan = rule({ action: 'allow' }, { src_zones: missing });
      const r = evaluateRulePropertyCheck(zoned, [orphan], ZONES);
      // ⛔ NOT `na`. "Nothing to assess" here was a rule quietly removing
      // itself from its own check.
      assert.notEqual(r.status, 'na', 'the rule must not disappear from the scope');
      assert.equal(r.status, 'fail');
      assert.deepEqual(r.matchedRuleIds, [orphan.id]);
    });
  }

  it('⛔ the live shape: an internet-edge policy with no IPS and no srcintf FAILS', () => {
    // An unreported source zone is unconstrained for exactly the reason `any`
    // is: matching it literally UNDERSTATES exposure, and on a security report
    // a hole reported as closed is a false assurance, not a missed finding.
    const edge = rule({ action: 'allow' }, { src_zones: null, rule_name: 'edge-no-ips' });
    const inside = rule({ 'ips-sensor': 'default', 'utm-status': 'enable' }, { src_zones: ['untrust'] });
    const r = evaluateRulePropertyCheck(
      withCfg({
        subject: 'an ACTIVE IPS sensor',
        applies_to: { action: 'allow', enabled_only: true, src_zone_role: 'external' },
        require_any_path: undefined,
        require_all_path: ['ips-sensor', 'utm-status'],
      }),
      [edge, inside], ZONES
    );
    assert.equal(r.status, 'fail');
    assert.match(r.detail, /1 of 2 applicable/);
    assert.match(r.detail, /edge-no-ips/);
  });

  it('a rule sourced from a DIFFERENT, classified zone is still out of scope', () => {
    // The counterpart — widening on an unknown must not widen on a known.
    const internal = rule({ action: 'allow' }, { src_zones: ['trust'] });
    assert.equal(evaluateRulePropertyCheck(zoned, [internal], ZONES).status, 'na');
  });
});

describe('⛔ zone names are TRIMMED, not just lower-cased', () => {
  const zoned = withCfg({ applies_to: { action: 'allow', enabled_only: true, src_zone_role: 'external' } });

  it('a space an operator typed into zone_classifications does not empty the scope', () => {
    // `zone_classifications.zone_name` is typed by hand. Lower-casing without
    // trimming made the two sides disjoint, so requiredZones matched NOTHING
    // and every rule silently left the check's scope — invisible, because the
    // result was a plausible `na`.
    const r = evaluateRulePropertyCheck(zoned, [bare()], { ' untrust ': 'external' });
    assert.notEqual(r.status, 'na', 'a stray space must not remove every rule from the scope');
    assert.equal(r.status, 'fail');
  });

  it('a space on the DEVICE side matches too, and so does a padded role', () => {
    const padded = rule({ action: 'allow' }, { src_zones: [' UNTRUST '] });
    assert.equal(evaluateRulePropertyCheck(zoned, [padded], ZONES).status, 'fail');
    assert.equal(evaluateRulePropertyCheck(zoned, [bare()], { untrust: ' External ' }).status, 'fail');
  });
});

describe('⛔ an unrecognised applies_to key is REFUSED, not ignored', () => {
  it('a curated typo cannot silently widen the question', () => {
    // `dst_zone_role` for `src_zone_role` used to be dropped on the floor: the
    // scope was never applied, the check answered "every enabled allow rule"
    // under an internet-facing name, and returned a confident fail. On the
    // live 447-rule Palo Alto that is a 415-violation finding with nothing
    // anywhere saying the scope went missing.
    const typo = withCfg({
      applies_to: { action: 'allow', enabled_only: true, dst_zone_role: 'external' },
    });
    const r = evaluateRulePropertyCheck(typo, [bare(), bare(), bare()], ZONES);
    assert.equal(r.status, 'warning');
    assert.match(r.detail, /dst_zone_role/, 'the unrecognised key must be named');
    assert.match(r.detail, /not with this firewall/, 'a curated-data problem is not the device’s fault');
    assert.deepEqual(r.matchedRuleIds, []);
    // ⛔ And it is NOT a confident answer about a wider question.
    assert.equal(/failed/.test(r.detail), false);
    assert.equal(/passed/.test(r.detail), false);
  });

  it('every key the evaluator actually reads is still accepted', () => {
    // The other half: a guard that refuses everything also passes the test
    // above. All three known keys together must still evaluate.
    const full = withCfg({
      applies_to: { action: 'allow', enabled_only: true, src_zone_role: 'external' },
    });
    assert.equal(evaluateRulePropertyCheck(full, [withGroup()], ZONES).status, 'pass');
    assert.equal(
      evaluateRulePropertyCheck(withCfg({ applies_to: {} }), [withGroup()], ZONES).status, 'pass'
    );
  });

  it('a MALFORMED applies_to is a definition problem, not an empty scope', () => {
    // An absent scope legitimately means "every rule". A scope that was
    // DECLARED and could not be read is the same failure as a typo'd key:
    // silently treating it as absent answers a wider question under this
    // check's name.
    for (const bad of [['action'], 'allow', 42, true]) {
      const r = evaluateRulePropertyCheck(withCfg({ applies_to: bad }), [bare()], ZONES);
      assert.equal(r.status, 'warning', `applies_to=${JSON.stringify(bad)}`);
      assert.match(r.detail, /not with this firewall/);
    }
    // ...while an absent one still means every rule, and still evaluates.
    for (const absent of [undefined, null]) {
      assert.equal(
        evaluateRulePropertyCheck(withCfg({ applies_to: absent }), [bare()], ZONES).status,
        'fail'
      );
    }
  });
});

describe('⛔ an unclassified device and an UNREADABLE one do not share a sentence', () => {
  const zoned = withCfg({ applies_to: { action: 'allow', enabled_only: true, src_zone_role: 'external' } });

  it('a FAILED zone-classification read says so, and does not blame the operator', () => {
    // The read failure used to arrive here as `{}`, indistinguishable from "no
    // zone has been classified" — so the finding told the operator to go and
    // classify zones that may already all be classified, on the strength of a
    // read SecVault could not complete. A failed read rendered as a fact about
    // the customer's firewall, and handing them an action item for our outage.
    const r = evaluateRulePropertyCheck(zoned, [bare()], null);
    assert.equal(r.status, 'na');
    assert.match(r.detail, /could not read/i);
    assert.match(r.detail, /SecVault-side/i);
    // ⛔ It must NOT be the instruction the unclassified case gives.
    assert.equal(/Classify this device's zones/.test(r.detail), false,
      'a read failure must not be reported as an operator omission');
    assert.equal(r.detail, evaluateRulePropertyCheck(zoned, [bare()], undefined).detail);
  });

  it('and an EMPTY map still gives the actionable "classify your zones" na', () => {
    // The distinction only exists if both sides keep their own wording.
    const r = evaluateRulePropertyCheck(zoned, [bare()], {});
    assert.equal(r.status, 'na');
    assert.match(r.detail, /Classify this device's zones/);
    assert.equal(/could not read/i.test(r.detail), false);
  });
});

describe('⛔ the Panorama guard is INERT over SSH, and the finding must say so', () => {
  // `undecidable_when_key: '@_panorama'` is an XML ATTRIBUTE. The `@_` prefix
  // exists only because the API transport parses XML with
  // attributeNamePrefix '@_'; the PAN-OS SSH transport builds raw_rule from a
  // brace-parsed config and emits NO `@_*` key at all — while still collecting
  // pre-rulebase/post-rulebase, i.e. Panorama-pushed rules with no origin
  // marker on them. Same firewall, same rules: over `api` those rules are
  // undecidable, over `ssh` they are named as definite failures.
  const apiShaped = (attrs) => rule({ '@_name': `r${Math.random()}`, ...attrs });
  const sshShaped = (attrs) => rule({ ...attrs });

  it('over the API transport, nothing changes — the marker namespace is present', () => {
    const r = evaluateRulePropertyCheck(CHECK, [apiShaped({ action: 'allow' })], ZONES);
    assert.equal(r.status, 'fail');
    assert.equal(r.originMarkerUnobservable, false);
    assert.equal(/origin metadata/.test(r.detail), false,
      'a transport that reports the marker needs no caveat');
  });

  it('over the SSH transport the count is still reported, but NOT as certain', () => {
    // ⛔ The finding is kept: a real absence observed on a real rule is a real
    // finding, and burying it behind a caveat is the mistake the
    // definite-outranks-undecidable rule already refuses to make. What is
    // removed is the CERTAINTY.
    const r = evaluateRulePropertyCheck(CHECK, [sshShaped({ action: 'allow' }), sshShaped({ action: 'allow' })], ZONES);
    assert.equal(r.status, 'fail');
    assert.equal(r.originMarkerUnobservable, true);
    assert.match(r.detail, /2 of 2 applicable/, 'the finding is not suppressed');
    assert.match(r.detail, /origin metadata/, 'the limitation must be stated');
    assert.match(r.detail, /upper bound/, 'and what to do with the number');
  });

  it('⛔ ONE marker-namespace key anywhere is enough to prove the channel works', () => {
    // A firewall with genuinely no Panorama-pushed rules is a normal, correct
    // state and must NOT attract the caveat — so the trigger is the absence of
    // the whole `@_*` NAMESPACE, never the absence of `@_panorama` itself.
    const r = evaluateRulePropertyCheck(
      CHECK, [apiShaped({ action: 'allow' }), apiShaped({ action: 'allow' })], ZONES
    );
    assert.equal(r.originMarkerUnobservable, false);
  });

  it('a PASS carries no caveat — presence was observed on every rule', () => {
    const r = evaluateRulePropertyCheck(CHECK, [sshShaped({ 'profile-setting': { group: { member: 's' } } })], ZONES);
    assert.equal(r.status, 'pass');
    assert.equal(/origin metadata/.test(r.detail), false);
  });

  it('a check declaring NO marker is never caveated', () => {
    // Nothing is being claimed about central management, so there is no
    // certainty to withdraw.
    const noMarker = withCfg({ undecidable_when_key: undefined, undecidable_reason: undefined });
    const r = evaluateRulePropertyCheck(noMarker, [sshShaped({ action: 'allow' })], ZONES);
    assert.equal(r.status, 'fail');
    assert.equal(r.originMarkerUnobservable, false);
    assert.equal(/origin metadata/.test(r.detail), false);
  });

  it('a PLAIN-named marker is treated as observable — it has no separate channel', () => {
    // `@_panorama` is special because `@_` is a PARSER namespace one transport
    // produces and the other never does. A plain key like `origin` is an
    // ordinary field of a rule object that was captured verbatim, so its
    // absence IS the observation and caveating it would caveat every clean
    // answer for ever.
    const plain = withCfg({ undecidable_when_key: 'origin' });
    const r = evaluateRulePropertyCheck(plain, [sshShaped({ action: 'allow' })], ZONES);
    assert.equal(r.status, 'fail');
    assert.equal(r.originMarkerUnobservable, false);
  });
});
