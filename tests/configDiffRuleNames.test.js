'use strict';
// tests/configDiffRuleNames.test.js
//
// ⛔ THE CHANGES PAGE NAMED A RULE THAT DOES NOT EXIST.
//
// `classifyPath` took the first dot-separated segment after
// `rulebase.security.rules.` and called it the rule name. A PAN-OS rule name
// may contain dots, so the live rule `Allow_URL_tfcc.fisheries.go.th` was
// reported as a rule called `Allow_URL_tfcc` — a confident, plausible, wrong
// fact on the one page an operator reads to find out what changed on a
// firewall. Measured on the live fleet: 47 of 1,780 rules carry a dot.
//
// ⛔ AND A GOOD READ WAS BEING RECORDED AS A FAILURE. `PATH_SHAPE_VIOLATION`
// was `/[\s{}]/` — ANY whitespace — on the assumption that a real path never
// contains a space. Live rule names include `65.32 allow all`, `Batch Scan for
// 27.254.123.18` and `HR TO Jobsdb.`; every one of them rendered as
// "(unreadable path — see full diff for details)". That is this codebase's
// signature bug pointing the other way: not a failed read reported as a fact,
// but a perfectly good fact reported as a failed read. Both directions destroy
// the operator's ability to trust the page.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { classifyDiff } = require('../lib/engines/configDiff');

const RULES = 'tree.rulebase.security.rules.';

// Render one added path the way the page would, and hand back whatever label
// the UI would actually show for it.
function shownFor(path, value = { 'ip-netmask': '10.0.0.1/32' }) {
  const c = classifyDiff({ added: [{ path, value }], removed: [], modified: [] });
  const rule = c.ruleChanges && c.ruleChanges[0];
  if (rule) {
    return { kind: 'rule', name: rule.ruleName, field: rule.changes[0].field };
  }
  const section = c.sections && c.sections[0];
  const entry = section && section.entries && section.entries[0];
  return { kind: 'section', name: entry ? entry.path : null };
}

describe('⛔ a rule name containing dots survives intact', () => {
  it('the live case: Allow_URL_tfcc.fisheries.go.th', () => {
    const got = shownFor(`${RULES}Allow_URL_tfcc.fisheries.go.th`, { action: 'allow' });
    assert.equal(got.kind, 'rule');
    assert.equal(got.name, 'Allow_URL_tfcc.fisheries.go.th',
      'naming a rule that does not exist is worse than naming none');
    assert.equal(got.field, null, 'the whole rule was added; no field changed');
  });

  it('a field after a dotted name is still recognised as the field', () => {
    const got = shownFor(`${RULES}Allow_URL_tfcc.fisheries.go.th.source`, ['10.0.0.0/8']);
    assert.equal(got.name, 'Allow_URL_tfcc.fisheries.go.th');
    assert.equal(got.field, 'source');
  });

  it('a multi-segment field after a dotted name stays whole', () => {
    const got = shownFor(`${RULES}My.Dotted.Rule.profile-setting.profiles`, { virus: 'x' });
    assert.equal(got.name, 'My.Dotted.Rule');
    assert.equal(got.field, 'profile-setting.profiles');
  });

  it('an ordinary undotted name is unchanged', () => {
    const got = shownFor(`${RULES}Allow-AI_Tools.action`, 'deny');
    assert.equal(got.name, 'Allow-AI_Tools');
    assert.equal(got.field, 'action');
  });

  it('⛔ the search starts AFTER the name, so a rule named after a field works', () => {
    // The segment straight after the marker is always the name, even when the
    // customer named their rule `service` or `action`.
    const got = shownFor(`${RULES}action.source`, ['any']);
    assert.equal(got.name, 'action');
    assert.equal(got.field, 'source');
  });

  it('the opaque XML/API entry[N] shape still falls through, as before', () => {
    // No name is recoverable from an array index, and inventing one would be
    // the whole defect this file is about, in reverse.
    const got = shownFor(`${RULES}entry[4]`, { action: 'allow' });
    assert.equal(got.kind, 'section', 'an unresolvable index is not a named rule');
  });
});

describe('⛔ a space is a legal character, not evidence of corruption', () => {
  for (const name of [
    '65.32 allow all',
    'Batch Scan for 27.254.123.18',
    'HR TO Jobsdb.',
    'DMZ_HEC TO SDC2.191',
  ]) {
    it(`renders "${name}" rather than calling it unreadable`, () => {
      const got = shownFor(`tree.address.${name}`);
      assert.doesNotMatch(String(got.name), /unreadable/,
        'a real, readable firewall change reported as garbage');
      assert.match(String(got.name), /allow all|Batch Scan|Jobsdb|SDC2/);
    });
  }
});

describe('⛔ what genuinely IS corruption is still refused', () => {
  // These are brace-grammar capture bleeding into the path, not names.
  const corrupt = [
    ['a brace', 'tree.address.foo { ip-netmask 1.2.3.0/24; } baz'],
    ['a newline', `tree.address.line one${String.fromCharCode(10)}line two`],
    ['a tab', `tree.address.a${String.fromCharCode(9)}b`],
    ['a run of spaces', 'tree.address.double  space'],
  ];
  for (const [label, path] of corrupt) {
    it(`${label} still yields the honest placeholder`, () => {
      const got = shownFor(path);
      assert.match(String(got.name), /unreadable path/,
        'a truncated garbage fragment reads as if it might be a real path');
    });
  }

  it('⛔ the placeholder never lands in the RULE NAME column either', () => {
    // It used to: a rule whose name contained a space took this branch, and
    // "(unreadable path — see full diff for details)" was shown where a rule
    // name belongs, in a table of firewall rule changes.
    const got = shownFor(`${RULES}65.32 allow all`, { action: 'allow' });
    assert.equal(got.kind, 'rule');
    assert.equal(got.name, '65.32 allow all');
  });
});
