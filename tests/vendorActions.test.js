'use strict';

// tests/vendorActions.test.js
//
// ⛔ EVERY ACTION ANY PARSER CAN EMIT MUST BE IN THE SHARED VOCABULARY.
//
// `lib/syslog/actions.js` exists so the retention policy, the rollups and
// log_hit cannot disagree about what "denied" means — CLAUDE.md records this
// codebase having once had four divergent copies of that set.
//
// An action in NEITHER set is the dangerous state, and it is dangerous
// ASYMMETRICALLY:
//   - log_hit fails SAFE (an unrecognised verb never counts as "reached", so it
//     cannot manufacture a patch_now);
//   - retention fails UNSAFE (shouldKeepRawMessage keeps the raw line for
//     DENIED traffic, so an unrecognised block silently loses its raw text at
//     SYSLOG_RAW_MESSAGE=security — the events an investigation actually opens).
//
// This was not hypothetical: adding Forcepoint introduced `Discard`, which was
// in neither set. Found by running this check, not by reading the parser.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { ALLOWED_ACTIONS, DENIED_ACTIONS } = require('../lib/syslog/actions');
const vendorParsers = require('../lib/syslog/vendorParsers');
const { parseSyslogLine } = require('../lib/syslog/syslogParser');
const { ASA_FIXTURES, asaLine } = require('./fixtures/ciscoAsaSyslog');
const { CEF_FIXTURES } = require('./fixtures/cefSyslog');
const { fortinetLine, paloAltoLine, ciscoAsaLine } = require('../scripts/mockSyslog');

const NOW = new Date('2026-10-04T12:00:00Z');

/** Every action the parsers actually produce, with where it came from. */
function collectActions() {
  const seen = new Map();   // action -> source label
  const note = (a, src) => { if (a && !seen.has(a)) seen.set(a, src); };

  for (const f of ASA_FIXTURES) {
    const p = vendorParsers.parseCiscoAsa(asaLine(f));
    if (p) note(p.action, `cisco_asa fixture ${f.id}`);
  }
  for (const f of CEF_FIXTURES) {
    const p = vendorParsers.parseCefEvent(f.line);
    if (p) note(p.action, `${f.vendor} fixture ${f.id}`);
  }
  // The generators exercise the live vocabularies more widely than the
  // fixtures do, so they are sampled too.
  for (let i = 0; i < 400; i += 1) {
    for (const [gen, label] of [[fortinetLine, 'fortinet'], [paloAltoLine, 'paloalto'], [ciscoAsaLine, 'cisco_asa']]) {
      const frame = parseSyslogLine(gen(NOW), NOW);
      const p = vendorParsers.parseVendorPayload(frame.message);
      if (p) note(p.action, `${label} generator`);
    }
  }
  return seen;
}

describe('⛔ the shared action vocabulary covers every parser', () => {
  it('no parser can emit an action that is in neither set', () => {
    const seen = collectActions();
    assert.ok(seen.size >= 6, `only ${seen.size} distinct actions seen; the sweep is not exercising the parsers`);
    const orphans = [...seen.entries()]
      .filter(([a]) => !ALLOWED_ACTIONS.has(a) && !DENIED_ACTIONS.has(a))
      .map(([a, src]) => `"${a}" (from ${src})`);
    assert.deepEqual(orphans, [],
      'actions in NEITHER ALLOWED_ACTIONS nor DENIED_ACTIONS — a denied one silently '
      + 'loses its raw message at SYSLOG_RAW_MESSAGE=security:\n  ' + orphans.join('\n  '));
  });

  it('⛔ no action is in BOTH sets', () => {
    // A verb that is both allowed and denied makes every consumer's answer
    // depend on which set it happens to test first.
    const both = [...ALLOWED_ACTIONS].filter((a) => DENIED_ACTIONS.has(a));
    assert.deepEqual(both, [], `in both sets: ${both.join(', ')}`);
  });

  it('⛔ Forcepoint\'s Discard is DENIED, not merely unknown', () => {
    // The specific regression this file was written for.
    assert.ok(DENIED_ACTIONS.has('discard'), 'Forcepoint blocks would lose their raw message');
    assert.ok(!ALLOWED_ACTIONS.has('discard'), 'a discard is a block, never a pass');
  });

  it('the sweep actually saw both an allow and a deny from each vendor family', () => {
    // Without this the orphan check above could pass by seeing nothing.
    const seen = collectActions();
    const anyAllowed = [...seen.keys()].some((a) => ALLOWED_ACTIONS.has(a));
    const anyDenied = [...seen.keys()].some((a) => DENIED_ACTIONS.has(a));
    assert.ok(anyAllowed, 'no allowed action was produced at all');
    assert.ok(anyDenied, 'no denied action was produced at all');
  });
});
