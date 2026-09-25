'use strict';
// tests/matchedRuleEvidence.test.js
//
// ⛔ "MATCHED NOTHING" AND "MATCHED RULES WE CAN NO LONGER NAME" EXPORTED AS
// THE SAME EMPTY CELL — in the EVIDENCE column of a compliance CSV an auditor
// reads, and as the same blank space on the check detail page.
//
// `audit_findings.matched_rule_ids` snapshots `firewall_rules.id` at audit
// time; `firewall_rules` is fully DELETE+reinserted on every collection, so
// those ids are regenerated wholesale on the next pull. Every call site
// resolved them with `.map(id => map.get(id)).filter(Boolean)` (or an
// `id = ANY($1)` that just returned fewer rows), so an unresolvable id — and a
// rule collected with a NULL `rule_name` — vanished leaving no trace and no
// count. CLAUDE.md's most-repeated bug class, in the highest-stakes column in
// the product.
//
// Measured on the live fleet 2026-09-25, BEFORE the fix: 404 audit_findings,
// 77 carrying matched rule ids, 1,473 ids in total, and **0 unresolvable** —
// because the audit runs inside the same collection cycle that reinserts the
// rules, so the window is seconds wide today. Zero live impact measured; the
// defect is a property of the code, not of a number on that day's fleet. Which
// is exactly why it needs a test: nothing in production would have shown it.
//
// Per tests/README.md, the case that matters most here is the "we could not
// measure this" one, and it is the one every assertion below is built around.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  resolveMatchedRules,
  matchedRulesNote,
  matchedRulesReason,
  matchedRulesCell,
} = require('../lib/matchedRuleEvidence');

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';

// The CSV route's lookup shape: Map(id -> rule_name).
const names = (pairs) => new Map(pairs);
// The two pages' lookup shape: Map(id -> whole rule row).
const rows = (pairs) => new Map(pairs.map(([id, name]) => [id, { id, rule_name: name, action: 'allow' }]));

describe('resolveMatchedRules — the count of what we cannot name is never lost', () => {
  it('counts an id that is not in the ruleset held now, and does not list it as a name', () => {
    const r = resolveMatchedRules([A, B, C], names([[A, 'Allow_DMZ_HTTPS']]));
    assert.deepEqual(r.names, ['Allow_DMZ_HTTPS']);
    assert.equal(r.total, 3);
    assert.equal(r.namedCount, 1);
    assert.equal(r.notInRuleset, 2);
    assert.equal(r.unnamedTotal, 2);
  });

  it('counts a rule that IS in the ruleset but was collected without a name', () => {
    // Distinct from the case above and must stay distinct: one is a question
    // about the ruleset, the other about a single rule the vendor left unnamed.
    const r = resolveMatchedRules([A, B], names([[A, 'Named'], [B, null]]));
    assert.deepEqual(r.names, ['Named']);
    assert.equal(r.notInRuleset, 0);
    assert.equal(r.unnamedInRuleset, 1);
    assert.equal(r.unnamedTotal, 1);
  });

  it('treats an empty or whitespace rule_name as no name, not as a name', () => {
    // A '' name joined into a semicolon list is an INVISIBLE entry — the same
    // empty cell this module exists to prevent, one layer down.
    const r = resolveMatchedRules([A, B], names([[A, ''], [B, '   ']]));
    assert.deepEqual(r.names, []);
    assert.equal(r.unnamedInRuleset, 2);
    assert.equal(r.unnamedTotal, 2);
  });

  it('buckets an unusable id separately from one that is simply absent', () => {
    const r = resolveMatchedRules([A, null, '', 7], names([[A, 'Named']]));
    assert.equal(r.total, 4);
    assert.equal(r.unusableId, 3);
    assert.equal(r.notInRuleset, 0, 'a null id is not a claim about the ruleset');
    assert.equal(r.unnamedTotal, 3);
  });

  it('reports EVERY id as unnameable when the lookup map is missing entirely', () => {
    // A failed bulk lookup must not read as "this check matched nothing".
    for (const lookup of [null, undefined, {}, new Map()]) {
      const r = resolveMatchedRules([A, B], lookup);
      assert.equal(r.total, 2);
      assert.equal(r.namedCount, 0);
      assert.equal(r.unnamedTotal, 2);
    }
  });

  it('reads both lookup shapes identically — Map(id -> name) and Map(id -> row)', () => {
    // Two call-site shapes, ONE implementation of the count. Two files deciding
    // this independently is how the audit document and the screen disagree.
    const fromNames = resolveMatchedRules([A, B], names([[A, 'R1'], [B, null]]));
    const fromRows = resolveMatchedRules([A, B], rows([[A, 'R1'], [B, null]]));
    assert.deepEqual(fromRows, fromNames);
  });

  it('records nothing to caveat when the finding matched no rules', () => {
    for (const ids of [[], null, undefined, 'not-an-array']) {
      const r = resolveMatchedRules(ids, names([[A, 'R1']]));
      assert.equal(r.total, 0);
      assert.equal(r.unnamedTotal, 0);
      assert.equal(matchedRulesNote(r), null);
    }
  });

  it('keeps the names in the order the finding recorded the ids', () => {
    const r = resolveMatchedRules([C, A], names([[A, 'second'], [C, 'first']]));
    assert.deepEqual(r.names, ['first', 'second']);
  });
});

describe('the note states a count and stops short of a cause', () => {
  it('names each reason with its own number', () => {
    const note = matchedRulesNote(resolveMatchedRules([A, B, C], names([[B, null]])));
    assert.equal(
      note,
      '3 of 3 matched rules could not be named (2 not in the current ruleset, 1 collected without a name)'
    );
  });

  it('is null when every recorded id resolved to a name', () => {
    assert.equal(matchedRulesNote(resolveMatchedRules([A], names([[A, 'R1']]))), null);
  });

  it('never claims the rules were deleted, removed, or are gone', () => {
    // ⛔ We know only that an id does not resolve. A failed collection, a
    // partial pull, a re-added device and a genuine deletion all look the same
    // from here, and naming one of them would be a fabricated fact standing in
    // for a missing one.
    // The NOTE is the quotable half — it travels alone into a CSV cell and a
    // table footer, so it must carry no cause at all.
    const r = resolveMatchedRules([A, B], new Map());
    const note = matchedRulesNote(r).toLowerCase();
    for (const forbidden of ['delete', 'remove', 'no longer exist', 'gone', 'missing']) {
      assert.ok(!note.includes(forbidden), `note must not claim "${forbidden}": ${note}`);
    }
    // The REASON may mention removal only to DENY it, so the words are checked
    // in context rather than banned — a ban here would have deleted the one
    // sentence stopping a reader closing a finding that is still live.
    const reason = matchedRulesReason(r).toLowerCase();
    for (const m of reason.matchAll(/remove[a-z]*|delete[a-z]*/g)) {
      const before = reason.slice(Math.max(0, m.index - 40), m.index);
      assert.match(before, /\bnot\b/, `"${m[0]}" must appear negated, not asserted: ...${before}${m[0]}`);
    }
  });

  it('never prints a rule id where a name would go', () => {
    // A bare UUID reads as a name to anyone who has not seen a rule id before.
    const r = resolveMatchedRules([A, B], new Map());
    const text = `${matchedRulesCell(r)} ${matchedRulesReason(r)}`;
    assert.ok(!text.includes(A) && !text.includes(B));
  });

  it('says the ids may still be live on the firewall and that a re-run settles it', () => {
    const reason = matchedRulesReason(resolveMatchedRules([A], new Map()));
    assert.match(reason, /not a statement that those rules were removed from the firewall/i);
    assert.match(reason, /re-run the audit/i);
  });

  it('has no reason text when there is nothing to caveat', () => {
    assert.equal(matchedRulesReason(resolveMatchedRules([A], names([[A, 'R1']]))), null);
  });
});

describe('the CSV evidence cell — the two cases can no longer be confused', () => {
  it('⛔ THE DEFECT: "matched nothing" and "matched 3 we cannot name" differ', () => {
    const matchedNothing = matchedRulesCell(resolveMatchedRules([], names([])));
    const matchedButUnnameable = matchedRulesCell(resolveMatchedRules([A, B, C], new Map()));
    assert.equal(matchedNothing, '');
    assert.notEqual(matchedButUnnameable, '');
    assert.notEqual(matchedButUnnameable, matchedNothing);
    assert.ok(matchedButUnnameable.includes('3 of 3'), matchedButUnnameable);
  });

  it('leaves the cell empty ONLY when the check matched no rules', () => {
    assert.equal(matchedRulesCell(resolveMatchedRules([], new Map())), '');
    assert.equal(matchedRulesCell(resolveMatchedRules(null, new Map())), '');
    // Everything else says something.
    assert.notEqual(matchedRulesCell(resolveMatchedRules([A], new Map())), '');
    assert.notEqual(matchedRulesCell(resolveMatchedRules([A], names([[A, null]]))), '');
  });

  it('is byte-identical to the old output when every id resolves', () => {
    // This file is saved, scripted against and attached to audits. The fully
    // resolvable case — which is 100% of the live fleet today — must not move.
    const cell = matchedRulesCell(resolveMatchedRules([A, B], names([[A, 'R1'], [B, 'R2']])));
    assert.equal(cell, 'R1; R2');
  });

  it('keeps the names it has and appends the count of the ones it does not', () => {
    const cell = matchedRulesCell(resolveMatchedRules([A, B, C], names([[A, 'R1']])));
    assert.equal(
      cell,
      'R1 [2 of 3 matched rules could not be named (2 not in the current ruleset)]'
    );
  });

  it('brackets the note so it cannot be read as a rule name', () => {
    // A consumer splitting on '; ' must not silently acquire the caveat as a
    // fourth rule name.
    const cell = matchedRulesCell(resolveMatchedRules([A, B], names([[A, 'R1']])));
    const parts = cell.split('; ');
    assert.equal(parts.length, 1, 'the note must not introduce a new "; " field');
    assert.ok(cell.endsWith(']'));
  });

  it('stays ASCII — this export deliberately carries no BOM', () => {
    const cell = matchedRulesCell(resolveMatchedRules([A, B, C], names([[B, null]])));
    // eslint-disable-next-line no-control-regex
    assert.ok(/^[\x20-\x7e]*$/.test(cell), `non-ASCII in CSV cell: ${cell}`);
  });

  it('cannot start with a spreadsheet formula character', () => {
    // The shared escape in lib/csv.js neutralises these, but a cell this module
    // BUILDS should not be leaning on that as its only defence.
    const cell = matchedRulesCell(resolveMatchedRules([A], new Map()));
    assert.ok(!['=', '+', '-', '@'].includes(cell[0]), cell);
  });
});

describe('singular/plural reads correctly for a single matched rule', () => {
  it('says "matched rule", not "matched rules", when one rule was matched', () => {
    const note = matchedRulesNote(resolveMatchedRules([A], new Map()));
    assert.equal(note, '1 of 1 matched rule could not be named (1 not in the current ruleset)');
  });
});
