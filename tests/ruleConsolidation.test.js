'use strict';
// tests/ruleConsolidation.test.js
//
// Pins lib/engines/ruleConsolidation.js — rules that differ in exactly ONE
// field, and whether merging them would change policy.
//
// ⛔ THE CASE THIS FILE MOSTLY EXISTS FOR IS THE THIRD ONE, NOT THE FIRST TWO.
// Grouping is easy to get right and easy to see when it is wrong: a wrong group
// is visibly a wrong group. The interference verdict is neither. A group wrongly
// called `safe_to_merge` renders as a tidy, plausible, actionable cleanup
// suggestion; an operator makes the change on the firewall; the row count goes
// down exactly as promised; and traffic that was denied is now allowed, with
// every signal in this product still green. Nothing crashes and no number looks
// odd. That is CLAUDE.md's failed-read-as-a-fact class aimed at a firewall
// change, which is why `undetermined -> needs_review` gets its own describe
// block and is asserted from several directions.
//
// The fixture shape is the live fleet as measured 2026-09-25: enabled rules,
// contiguous integer sequence numbers, no vdoms, address fields that are almost
// always OBJECT NAMES rather than literals.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  findConsolidationGroups, canonicalKey, checkInterference, summariseConsolidation,
  MERGE_CLAIM, VERDICTS,
  RAW_KEY_SIGNIFICANT, RAW_KEY_IGNORED, ATTRIBUTE_KEY_PREFIX, NEUTRAL_TOKEN,
  canonicalRawValue, classifyRawRuleKeys, hasNegationMarker,
} = require('../lib/engines/ruleConsolidation');

const DEV = 'dev-1';

/** A rule with sane defaults; override anything. */
function rule(over) {
  return {
    id: over.id,
    device_id: DEV,
    vdom: null,
    enabled: true,
    action: 'allow',
    src_zones: ['trust'],
    dst_zones: ['untrust'],
    src_addresses: ['10.0.0.0/24'],
    dst_addresses: ['10.1.0.0/24'],
    services: ['tcp/443'],
    applications: null,
    schedule: null,
    log_enabled: true,
    nat_enabled: false,
    expiry_date: null,
    rule_name: over.id,
    rule_id_vendor: over.id,
    comment: null,
    ...over,
  };
}

const NO_OBJECTS = { objects: [] };

// ═══════════════════════════════════════════════════════════════════════
describe('grouping — exactly one field may vary', () => {
  it('groups rules differing only in destination', () => {
    const rules = [
      rule({ id: 'r1', sequence_number: 1, dst_addresses: ['10.1.0.0/24'] }),
      rule({ id: 'r2', sequence_number: 2, dst_addresses: ['10.2.0.0/24'] }),
      rule({ id: 'r3', sequence_number: 3, dst_addresses: ['10.3.0.0/24'] }),
    ];
    const groups = findConsolidationGroups(rules, NO_OBJECTS);
    assert.equal(groups.length, 1);
    assert.equal(groups[0].varyingField, 'dst_addresses');
    assert.equal(groups[0].varyingFieldLabel, 'destination');
    assert.equal(groups[0].size, 3);
    assert.equal(groups[0].removableRows, 2);
  });

  it('groups rules differing only in source, and only in service', () => {
    const src = findConsolidationGroups([
      rule({ id: 'a', sequence_number: 1, src_addresses: ['10.0.1.0/24'] }),
      rule({ id: 'b', sequence_number: 2, src_addresses: ['10.0.2.0/24'] }),
    ], NO_OBJECTS);
    assert.equal(src.length, 1);
    assert.equal(src[0].varyingField, 'src_addresses');

    const svc = findConsolidationGroups([
      rule({ id: 'a', sequence_number: 1, services: ['tcp/443'] }),
      rule({ id: 'b', sequence_number: 2, services: ['tcp/8443'] }),
    ], NO_OBJECTS);
    assert.equal(svc.length, 1);
    assert.equal(svc[0].varyingField, 'services');
  });

  it('⛔ rules differing in TWO fields do NOT group', () => {
    const groups = findConsolidationGroups([
      rule({ id: 'a', sequence_number: 1, dst_addresses: ['10.1.0.0/24'], services: ['tcp/443'] }),
      rule({ id: 'b', sequence_number: 2, dst_addresses: ['10.2.0.0/24'], services: ['tcp/8443'] }),
    ], NO_OBJECTS);
    assert.deepEqual(groups, []);
  });

  it('a difference in action, zones, logging, NAT, schedule or expiry blocks the group', () => {
    const variants = [
      { action: 'deny' },
      { src_zones: ['dmz'] },
      { dst_zones: ['dmz'] },
      { log_enabled: false },
      { nat_enabled: true },
      { schedule: 'workhours' },
      { expiry_date: '2027-01-01T00:00:00Z' },
      { applications: ['ssl'] },
    ];
    for (const v of variants) {
      const groups = findConsolidationGroups([
        rule({ id: 'a', sequence_number: 1, dst_addresses: ['10.1.0.0/24'] }),
        rule({ id: 'b', sequence_number: 2, dst_addresses: ['10.2.0.0/24'], ...v }),
      ], NO_OBJECTS);
      assert.deepEqual(groups, [], `differing ${Object.keys(v)[0]} must not group`);
    }
  });

  it('allow/permit/accept are ONE action, as are deny/drop/reject/block', () => {
    const groups = findConsolidationGroups([
      rule({ id: 'a', sequence_number: 1, action: 'allow', dst_addresses: ['10.1.0.0/24'] }),
      rule({ id: 'b', sequence_number: 2, action: 'permit', dst_addresses: ['10.2.0.0/24'] }),
    ], NO_OBJECTS);
    assert.equal(groups.length, 1);
  });

  it('⛔ name, comment, tags and hit_count are NOT part of the key — and the cost is reported', () => {
    const groups = findConsolidationGroups([
      rule({
        id: 'a', sequence_number: 1, dst_addresses: ['10.1.0.0/24'],
        rule_name: 'HR to payroll', comment: 'ticket 4412', tags: ['hr'], hit_count: 900,
      }),
      rule({
        id: 'b', sequence_number: 2, dst_addresses: ['10.2.0.0/24'],
        rule_name: 'HR to benefits', comment: 'ticket 8891', tags: ['ops'], hit_count: null,
      }),
    ], NO_OBJECTS);
    assert.equal(groups.length, 1);
    assert.deepEqual(groups[0].distinctNames, ['HR to payroll', 'HR to benefits']);
    assert.equal(groups[0].losesDistinctComments, true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
describe('canonicalKey — order-insensitive for set-valued fields', () => {
  it('⛔ ["A","B"] and ["B","A"] are the same address set', () => {
    const a = rule({ id: 'a', sequence_number: 1, src_addresses: ['LAN', 'DMZ'] });
    const b = rule({ id: 'b', sequence_number: 2, src_addresses: ['DMZ', 'LAN'] });
    assert.equal(canonicalKey(a, 'dst_addresses'), canonicalKey(b, 'dst_addresses'));
  });

  it('is case- and whitespace-insensitive, and de-duplicates', () => {
    const a = rule({ id: 'a', sequence_number: 1, services: [' TCP/443 ', 'tcp/443'] });
    const b = rule({ id: 'b', sequence_number: 2, services: ['tcp/443'] });
    assert.equal(canonicalKey(a, 'dst_addresses'), canonicalKey(b, 'dst_addresses'));
  });

  it('and set order really does not split a real group', () => {
    const groups = findConsolidationGroups([
      rule({ id: 'a', sequence_number: 1, src_addresses: ['LAN', 'DMZ'], dst_addresses: ['A'] }),
      rule({ id: 'b', sequence_number: 2, src_addresses: ['DMZ', 'LAN'], dst_addresses: ['B'] }),
    ], NO_OBJECTS);
    assert.equal(groups.length, 1);
    assert.equal(groups[0].size, 2);
  });

  it('⛔ null, [] and ["any"] all key as the same wildcard', () => {
    const base = { sequence_number: 1, dst_addresses: ['x'] };
    const k = (v) => canonicalKey(rule({ id: 'a', ...base, src_zones: v }), 'dst_addresses');
    assert.equal(k(null), k([]));
    assert.equal(k([]), k(['any']));
    assert.equal(k(['any']), k(['ALL']));
  });

  it('different devices produce different keys', () => {
    const a = rule({ id: 'a', sequence_number: 1 });
    const b = rule({ id: 'b', sequence_number: 1, device_id: 'dev-2' });
    assert.notEqual(canonicalKey(a, 'dst_addresses'), canonicalKey(b, 'dst_addresses'));
  });

  it('different vdoms produce different keys', () => {
    const a = rule({ id: 'a', sequence_number: 1, vdom: 'root' });
    const b = rule({ id: 'b', sequence_number: 1, vdom: 'guest' });
    assert.notEqual(canonicalKey(a, 'dst_addresses'), canonicalKey(b, 'dst_addresses'));
  });
});

// ═══════════════════════════════════════════════════════════════════════
describe('⛔ interference — the safety property', () => {
  // Adjacent: 1 and 2, nothing between.
  it('adjacent rules are safe_to_merge', () => {
    const groups = findConsolidationGroups([
      rule({ id: 'a', sequence_number: 1, dst_addresses: ['10.1.0.0/24'] }),
      rule({ id: 'b', sequence_number: 2, dst_addresses: ['10.2.0.0/24'] }),
    ], NO_OBJECTS);
    assert.equal(groups.length, 1);
    assert.equal(groups[0].verdict, VERDICTS.SAFE);
    assert.equal(groups[0].adjacent, true);
    assert.equal(groups[0].examined, 0);
  });

  it('⛔ a MATCHING intervening rule makes it needs_review AND NAMES THE RULE', () => {
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      // Sits between, denies the very traffic rule `b` carries.
      rule({
        id: 'blocker', sequence_number: 20, action: 'deny',
        src_addresses: ['10.0.0.0/24'], dst_addresses: ['10.2.0.0/24'], services: ['tcp/443'],
      }),
      rule({ id: 'b', sequence_number: 40, dst_addresses: ['10.2.0.0/24'] }),
    ];
    const groups = findConsolidationGroups(rules, NO_OBJECTS);
    assert.equal(groups.length, 1);
    const g = groups[0];
    assert.equal(g.verdict, VERDICTS.REVIEW);
    assert.equal(g.adjacent, false);
    assert.equal(g.interfering.length, 1);
    assert.equal(g.interfering[0].rule.id, 'blocker');
    // And it names WHICH member would be moved past it — the one below it.
    assert.equal(g.interfering[0].movedRule.id, 'b');
    assert.equal(g.undetermined.length, 0);
  });

  it('a NON-matching intervening rule leaves it safe_to_merge', () => {
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      // Provably disjoint destination — cannot touch either member's traffic.
      rule({
        id: 'elsewhere', sequence_number: 20, action: 'deny',
        src_addresses: ['10.0.0.0/24'], dst_addresses: ['192.168.55.0/24'], services: ['tcp/443'],
      }),
      rule({ id: 'b', sequence_number: 40, dst_addresses: ['10.2.0.0/24'] }),
    ];
    const groups = findConsolidationGroups(rules, NO_OBJECTS);
    assert.equal(groups[0].verdict, VERDICTS.SAFE);
    assert.equal(groups[0].examined, 1, 'the rule was actually examined, not skipped');
    assert.equal(groups[0].adjacent, false);
  });

  it('a disjoint SERVICE is enough on its own', () => {
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      rule({
        id: 'other-port', sequence_number: 20, action: 'deny',
        src_addresses: ['10.0.0.0/24'], dst_addresses: ['10.2.0.0/24'], services: ['tcp/22'],
      }),
      rule({ id: 'b', sequence_number: 40, dst_addresses: ['10.2.0.0/24'] }),
    ];
    assert.equal(findConsolidationGroups(rules, NO_OBJECTS)[0].verdict, VERDICTS.SAFE);
  });

  it('⛔ an intervening ANY rule interferes — a wildcard matches everything', () => {
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      rule({
        id: 'catchall', sequence_number: 20, action: 'deny',
        src_addresses: ['any'], dst_addresses: ['any'], services: ['any'],
      }),
      rule({ id: 'b', sequence_number: 40, dst_addresses: ['10.2.0.0/24'] }),
    ];
    const g = findConsolidationGroups(rules, NO_OBJECTS)[0];
    assert.equal(g.verdict, VERDICTS.REVIEW);
    assert.equal(g.interfering[0].rule.id, 'catchall');
  });

  it('⛔ a SAME-ACTION intervening rule still needs review — profiles and logging are not modelled', () => {
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      rule({
        id: 'same-action', sequence_number: 20, action: 'allow', log_enabled: false,
        src_addresses: ['10.0.0.0/24'], dst_addresses: ['10.2.0.0/24'], services: ['tcp/443'],
      }),
      rule({ id: 'b', sequence_number: 40, dst_addresses: ['10.2.0.0/24'] }),
    ];
    assert.equal(findConsolidationGroups(rules, NO_OBJECTS)[0].verdict, VERDICTS.REVIEW);
  });

  it('a rule ABOVE the merge position or BELOW the last member is not intervening', () => {
    const rules = [
      rule({
        id: 'above', sequence_number: 1, action: 'deny',
        src_addresses: ['any'], dst_addresses: ['any'], services: ['any'],
      }),
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      rule({ id: 'b', sequence_number: 11, dst_addresses: ['10.2.0.0/24'] }),
      rule({
        id: 'below', sequence_number: 99, action: 'deny',
        src_addresses: ['any'], dst_addresses: ['any'], services: ['any'],
      }),
    ];
    const g = findConsolidationGroups(rules, NO_OBJECTS)[0];
    assert.equal(g.verdict, VERDICTS.SAFE);
    assert.equal(g.examined, 0);
  });

  it('⛔ only the members BELOW an intervening rule move past it', () => {
    // `mid` sits between members a(10) and b(30) but ABOVE c(40) too. Only the
    // members below it move; a member above it is untouched by it.
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      rule({
        id: 'mid', sequence_number: 20, action: 'deny',
        src_addresses: ['10.0.0.0/24'], dst_addresses: ['10.3.0.0/24'], services: ['tcp/443'],
      }),
      rule({ id: 'b', sequence_number: 30, dst_addresses: ['10.2.0.0/24'] }),
      rule({ id: 'c', sequence_number: 40, dst_addresses: ['10.3.0.0/24'] }),
    ];
    const g = findConsolidationGroups(rules, NO_OBJECTS)[0];
    assert.equal(g.size, 3);
    assert.equal(g.verdict, VERDICTS.REVIEW);
    assert.equal(g.interfering[0].movedRule.id, 'c', 'the member whose traffic mid blocks');
  });

  it('⛔ ...and a member ABOVE an intervening rule does NOT make the group reviewable', () => {
    // The mirror of the case above, and the one that pins the direction. `mid`
    // overlaps member `a`, which sits ABOVE it and therefore does not move —
    // `a` already won that traffic at position 10 and still does after the
    // merge. Only `b` moves, and `mid` cannot match `b`'s traffic. Comparing
    // every member against every intervening rule instead of only the ones that
    // MOVE would report this as needing review, which is a correct-but-useless
    // engine: on a real ruleset almost every group has some member overlapping
    // something above it, and a verdict that is always `needs_review` carries
    // no information at all.
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      rule({
        id: 'mid', sequence_number: 20, action: 'deny',
        src_addresses: ['10.0.0.0/24'], dst_addresses: ['10.1.0.0/24'], services: ['tcp/443'],
      }),
      rule({ id: 'b', sequence_number: 30, dst_addresses: ['10.2.0.0/24'] }),
    ];
    const g = findConsolidationGroups(rules, NO_OBJECTS)[0];
    assert.equal(g.verdict, VERDICTS.SAFE);
    assert.equal(g.examined, 1, 'it was examined — just not against a rule that moves');
    assert.equal(g.adjacent, false);
  });

  it('checkInterference is callable standalone', () => {
    const a = rule({ id: 'a', sequence_number: 1, dst_addresses: ['10.1.0.0/24'] });
    const b = rule({ id: 'b', sequence_number: 2, dst_addresses: ['10.2.0.0/24'] });
    const out = checkInterference([a, b], [a, b], { objects: [] });
    assert.equal(out.verdict, VERDICTS.SAFE);
    assert.equal(out.mergePosition, 1);
  });

  it('⛔ the merge position is the LOWEST sequence number in the group', () => {
    const a = rule({ id: 'a', sequence_number: 40, dst_addresses: ['10.1.0.0/24'] });
    const b = rule({ id: 'b', sequence_number: 10, dst_addresses: ['10.2.0.0/24'] });
    // Handed in the wrong order on purpose.
    const out = checkInterference([a, b], [a, b], { objects: [] });
    assert.equal(out.mergePosition, 10);
  });
});

// ═══════════════════════════════════════════════════════════════════════
describe('⛔ UNDETERMINABLE interference falls CLOSED', () => {
  // ⛔ This is the block that matters. Every case below is one where the engine
  // cannot decide whether policy would change. Each must be `needs_review`.
  // Falling open here proposes a firewall change that silently alters policy.

  it('an UNRESOLVED OBJECT NAME on the intervening rule → needs_review, never safe', () => {
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      rule({
        id: 'mystery', sequence_number: 20, action: 'deny',
        // "SERVERS-NET" is an object name and no catalogue was supplied, so its
        // real extent is unknown — it MIGHT be 10.2.0.0/24.
        src_addresses: ['10.0.0.0/24'], dst_addresses: ['SERVERS-NET'], services: ['tcp/443'],
      }),
      rule({ id: 'b', sequence_number: 40, dst_addresses: ['10.2.0.0/24'] }),
    ];
    const g = findConsolidationGroups(rules, NO_OBJECTS)[0];
    assert.equal(g.verdict, VERDICTS.REVIEW);
    assert.equal(g.interfering.length, 0, 'not an overlap — an unknown');
    assert.equal(g.undetermined.length, 1);
    assert.equal(g.undetermined[0].rule.id, 'mystery');
    assert.equal(g.undetermined[0].reason, 'overlap_could_not_be_determined');
  });

  it('...and RESOLVING that same object flips it to safe_to_merge', () => {
    // The mirror of the case above: identical rules, plus the catalogue. This
    // pins that `needs_review` above came from the MISSING OBJECT and not from
    // some unrelated refusal — a falls-closed test that would pass with the
    // engine hardwired to `needs_review` proves nothing.
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      rule({
        id: 'mystery', sequence_number: 20, action: 'deny',
        src_addresses: ['10.0.0.0/24'], dst_addresses: ['SERVERS-NET'], services: ['tcp/443'],
      }),
      rule({ id: 'b', sequence_number: 40, dst_addresses: ['10.2.0.0/24'] }),
    ];
    const objects = [
      { device_id: DEV, object_type: 'address', name: 'SERVERS-NET', value: '192.168.77.0/24' },
    ];
    const g = findConsolidationGroups(rules, { objects })[0];
    assert.equal(g.verdict, VERDICTS.SAFE);
    assert.equal(g.undetermined.length, 0);

    // And when the object turns out to BE the moved traffic, it interferes.
    const overlapping = [
      { device_id: DEV, object_type: 'address', name: 'SERVERS-NET', value: '10.2.0.0/24' },
    ];
    const g2 = findConsolidationGroups(rules, { objects: overlapping })[0];
    assert.equal(g2.verdict, VERDICTS.REVIEW);
    assert.equal(g2.interfering[0].rule.id, 'mystery');
  });

  it('an unresolved name on the MEMBER side is equally undeterminable', () => {
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      rule({
        id: 'mid', sequence_number: 20, action: 'deny',
        src_addresses: ['10.0.0.0/24'], dst_addresses: ['10.9.0.0/24'], services: ['tcp/443'],
      }),
      rule({ id: 'b', sequence_number: 40, dst_addresses: ['BRANCH-SUBNETS'] }),
    ];
    const g = findConsolidationGroups(rules, NO_OBJECTS)[0];
    assert.equal(g.verdict, VERDICTS.REVIEW);
    assert.equal(g.undetermined.length, 1);
  });

  it('an FQDN address object is undeterminable, not disjoint', () => {
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      rule({
        id: 'fqdn', sequence_number: 20, action: 'deny',
        src_addresses: ['10.0.0.0/24'], dst_addresses: ['WEB-HOST'], services: ['tcp/443'],
      }),
      rule({ id: 'b', sequence_number: 40, dst_addresses: ['10.2.0.0/24'] }),
    ];
    const objects = [
      { device_id: DEV, object_type: 'address', name: 'WEB-HOST', value: 'portal.example.com' },
    ];
    const g = findConsolidationGroups(rules, { objects })[0];
    assert.equal(g.verdict, VERDICTS.REVIEW);
    assert.equal(g.undetermined.length, 1);
  });

  it('an unresolved SERVICE name is undeterminable', () => {
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      rule({
        id: 'svc', sequence_number: 20, action: 'deny',
        src_addresses: ['10.0.0.0/24'], dst_addresses: ['10.2.0.0/24'], services: ['CORP-APPS'],
      }),
      rule({ id: 'b', sequence_number: 40, dst_addresses: ['10.2.0.0/24'] }),
    ];
    const g = findConsolidationGroups(rules, NO_OBJECTS)[0];
    assert.equal(g.verdict, VERDICTS.REVIEW);
    assert.equal(g.undetermined.length, 1);
  });

  it('⛔ a NEGATED field on an intervening rule is undeterminable — negation inverts the extent', () => {
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      rule({
        id: 'negated', sequence_number: 20, action: 'deny',
        // Literally disjoint — but the raw rule says the destination is NEGATED,
        // so the real extent is "everything except this", which includes the
        // moved traffic. Reading the literal list here would be exactly backwards.
        src_addresses: ['10.0.0.0/24'], dst_addresses: ['192.168.99.0/24'], services: ['tcp/443'],
        raw_rule: { 'dstaddr-negate': 'enable' },
      }),
      rule({ id: 'b', sequence_number: 40, dst_addresses: ['10.2.0.0/24'] }),
    ];
    const g = findConsolidationGroups(rules, NO_OBJECTS)[0];
    assert.equal(g.verdict, VERDICTS.REVIEW);
    assert.equal(g.undetermined.length, 1);

    // A negate flag that is OFF must not poison the check.
    rules[1].raw_rule = { 'dstaddr-negate': 'disable' };
    assert.equal(findConsolidationGroups(rules, NO_OBJECTS)[0].verdict, VERDICTS.SAFE);
  });

  it('⛔ an intervening rule with NO sequence number is undeterminable, not absent', () => {
    // It might sit inside the span and we cannot tell. Assuming it is outside
    // would be a failed read recorded as a fact, in the flattering direction.
    const a = rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] });
    const b = rule({ id: 'b', sequence_number: 11, dst_addresses: ['10.2.0.0/24'] });
    const floating = rule({ id: 'floating', sequence_number: null, action: 'deny' });
    const out = checkInterference([a, b], [a, b, floating], { objects: [] });
    assert.equal(out.verdict, VERDICTS.REVIEW);
    assert.equal(out.undetermined[0].reason, 'intervening_rule_has_no_sequence_number');

    // ...but a DISABLED one still cannot interfere, sequence or no sequence.
    floating.enabled = false;
    assert.equal(checkInterference([a, b], [a, b, floating], { objects: [] }).verdict, VERDICTS.SAFE);
  });

  it('⛔ a group member with no sequence number is undeterminable in checkInterference', () => {
    // findConsolidationGroups never builds such a group (see below), but a
    // direct caller can, and the verdict must still fall closed.
    const a = rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] });
    const b = rule({ id: 'b', sequence_number: null, dst_addresses: ['10.2.0.0/24'] });
    const out = checkInterference([a, b], [a, b], { objects: [] });
    assert.equal(out.verdict, VERDICTS.REVIEW);
    assert.equal(out.undetermined[0].reason, 'member_has_no_sequence_number');
  });

  it('an unsequenced rule is never made a group MEMBER — an unactionable candidate is noise', () => {
    const groups = findConsolidationGroups([
      rule({ id: 'a', sequence_number: null, dst_addresses: ['10.1.0.0/24'] }),
      rule({ id: 'b', sequence_number: null, dst_addresses: ['10.2.0.0/24'] }),
    ], NO_OBJECTS);
    assert.deepEqual(groups, []);
  });
});

// ═══════════════════════════════════════════════════════════════════════
describe('disabled rules', () => {
  it('⛔ a disabled rule is never a group MEMBER — merging it saves nothing real', () => {
    const groups = findConsolidationGroups([
      rule({ id: 'a', sequence_number: 1, dst_addresses: ['10.1.0.0/24'] }),
      rule({ id: 'b', sequence_number: 2, dst_addresses: ['10.2.0.0/24'], enabled: false }),
    ], NO_OBJECTS);
    assert.deepEqual(groups, [], 'one enabled rule is not a group');
  });

  it('⛔ a disabled rule CANNOT INTERFERE either — it matches nothing', () => {
    const rules = [
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
      // Would interfere if it were in force. It is not.
      rule({
        id: 'parked', sequence_number: 20, enabled: false, action: 'deny',
        src_addresses: ['any'], dst_addresses: ['any'], services: ['any'],
      }),
      rule({ id: 'b', sequence_number: 40, dst_addresses: ['10.2.0.0/24'] }),
    ];
    const g = findConsolidationGroups(rules, NO_OBJECTS)[0];
    assert.equal(g.verdict, VERDICTS.SAFE);
    assert.equal(g.examined, 0);
    assert.equal(g.adjacent, true, 'nothing enabled sits between them');

    // Enable it and the same group flips — pins that the skip is the reason.
    rules[1].enabled = true;
    assert.equal(findConsolidationGroups(rules, NO_OBJECTS)[0].verdict, VERDICTS.REVIEW);
  });
});

// ═══════════════════════════════════════════════════════════════════════
describe('scoping and degenerate groups', () => {
  it('⛔ rules on DIFFERENT DEVICES never group', () => {
    const groups = findConsolidationGroups([
      rule({ id: 'a', sequence_number: 1, dst_addresses: ['10.1.0.0/24'] }),
      rule({ id: 'b', sequence_number: 2, dst_addresses: ['10.2.0.0/24'], device_id: 'dev-2' }),
    ], {});
    assert.deepEqual(groups, []);
  });

  it('⛔ rules in different VDOMs never group', () => {
    const groups = findConsolidationGroups([
      rule({ id: 'a', sequence_number: 1, vdom: 'root', dst_addresses: ['10.1.0.0/24'] }),
      rule({ id: 'b', sequence_number: 2, vdom: 'guest', dst_addresses: ['10.2.0.0/24'] }),
    ], NO_OBJECTS);
    assert.deepEqual(groups, []);
  });

  it('⛔ a group of 1 is not reported', () => {
    assert.deepEqual(findConsolidationGroups([rule({ id: 'a', sequence_number: 1 })], NO_OBJECTS), []);
    assert.deepEqual(findConsolidationGroups([], NO_OBJECTS), []);
  });

  it('⛔ removableRows is size - 1, never size', () => {
    const rules = [1, 2, 3, 4].map((n) => rule({
      id: `r${n}`, sequence_number: n, dst_addresses: [`10.${n}.0.0/24`],
    }));
    const g = findConsolidationGroups(rules, NO_OBJECTS)[0];
    assert.equal(g.size, 4);
    assert.equal(g.removableRows, 3);
  });

  it('⛔ two IDENTICAL rules are not a consolidation — that is `redundant`, and it is reported once, not three times', () => {
    const groups = findConsolidationGroups([
      rule({ id: 'a', sequence_number: 1 }),
      rule({ id: 'b', sequence_number: 2 }),
    ], NO_OBJECTS);
    assert.deepEqual(groups, [], 'the "varying" field does not actually vary in any of the three');
  });

  it('⛔ a rule whose VARYING field is already `any` is not a merge candidate', () => {
    const groups = findConsolidationGroups([
      rule({ id: 'a', sequence_number: 1, dst_addresses: ['any'] }),
      rule({ id: 'b', sequence_number: 2, dst_addresses: ['10.2.0.0/24'] }),
    ], NO_OBJECTS);
    assert.deepEqual(groups, []);
  });

  it('mergedValue is the union of the varying field, de-duplicated and sorted', () => {
    const g = findConsolidationGroups([
      rule({ id: 'a', sequence_number: 1, dst_addresses: ['B', 'A'] }),
      rule({ id: 'b', sequence_number: 2, dst_addresses: ['C', 'A'] }),
    ], NO_OBJECTS)[0];
    assert.deepEqual(g.mergedValue, ['A', 'B', 'C']);
  });

  it('the input array and its rules are never mutated', () => {
    const rules = [
      rule({ id: 'b', sequence_number: 40, dst_addresses: ['10.2.0.0/24'] }),
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
    ];
    const before = JSON.stringify(rules);
    findConsolidationGroups(rules, NO_OBJECTS);
    assert.equal(JSON.stringify(rules), before);
    assert.equal(rules[0].id, 'b', 'order untouched');
  });
});

// ═══════════════════════════════════════════════════════════════════════
describe('malformed input does not throw', () => {
  it('survives non-arrays, nulls and junk', () => {
    const bad = [
      undefined, null, 'nonsense', 42, {}, [],
      [null, undefined, 'x'],
      [{ id: 'x' }],
      [rule({ id: 'a', sequence_number: 1, src_addresses: 'not-an-array' }),
        rule({ id: 'b', sequence_number: 2, src_addresses: { weird: true } })],
      [rule({ id: 'a', sequence_number: '1', dst_addresses: ['10.1.0.0/24'] }),
        rule({ id: 'b', sequence_number: '2', dst_addresses: ['10.2.0.0/24'] })],
      [rule({ id: 'a', sequence_number: NaN }), rule({ id: 'b', sequence_number: Infinity })],
    ];
    for (const input of bad) {
      assert.doesNotThrow(() => {
        const g = findConsolidationGroups(input, NO_OBJECTS);
        assert.ok(Array.isArray(g));
        summariseConsolidation(g);
      }, `input: ${JSON.stringify(input)}`);
    }
    assert.doesNotThrow(() => canonicalKey(null, 'dst_addresses'));
    assert.doesNotThrow(() => canonicalKey(undefined, 'services'));
    assert.doesNotThrow(() => checkInterference(null, null));
    assert.doesNotThrow(() => checkInterference('x', 7, {}));
    assert.doesNotThrow(() => summariseConsolidation(null));
    assert.doesNotThrow(() => summariseConsolidation('nope'));
  });

  it('⛔ a non-array field is read as a ONE-ITEM SET, never as a wildcard', () => {
    // The dangerous failure would be reading an unreadable field as `any` and
    // then concluding an intervening rule matches nothing — or everything.
    const rules = [
      rule({ id: 'a', sequence_number: 1, dst_addresses: 'DMZ-NET' }),
      rule({ id: 'b', sequence_number: 2, dst_addresses: 'LAN-NET' }),
    ];
    const g = findConsolidationGroups(rules, NO_OBJECTS);
    assert.equal(g.length, 1, 'still groupable — a scalar is a set of one');
    assert.deepEqual(g[0].mergedValue, ['DMZ-NET', 'LAN-NET']);
  });

  it('a string sequence number still orders correctly', () => {
    const g = findConsolidationGroups([
      rule({ id: 'a', sequence_number: '9', dst_addresses: ['10.1.0.0/24'] }),
      rule({ id: 'b', sequence_number: '10', dst_addresses: ['10.2.0.0/24'] }),
    ], NO_OBJECTS)[0];
    // Numeric, not lexicographic: 9 then 10.
    assert.equal(g.mergePosition, 9);
    assert.deepEqual(g.rules.map((r) => r.id), ['a', 'b']);
  });
});

// ═══════════════════════════════════════════════════════════════════════
describe('summariseConsolidation', () => {
  const fixture = [
    // Safe: adjacent.
    rule({ id: 's1', sequence_number: 1, dst_addresses: ['10.1.0.0/24'] }),
    rule({ id: 's2', sequence_number: 2, dst_addresses: ['10.2.0.0/24'] }),
    // Needs review: an unresolved intervening rule.
    rule({ id: 'n1', sequence_number: 10, services: ['tcp/22'], dst_addresses: ['10.5.0.0/24'] }),
    rule({
      id: 'mid', sequence_number: 11, action: 'deny',
      src_addresses: ['10.0.0.0/24'], dst_addresses: ['UNKNOWN-NET'], services: ['any'],
    }),
    rule({ id: 'n2', sequence_number: 12, services: ['tcp/2222'], dst_addresses: ['10.5.0.0/24'] }),
  ];

  it('separates the candidate total from the checked total', () => {
    const s = summariseConsolidation(findConsolidationGroups(fixture, NO_OBJECTS));
    assert.equal(s.groups, 2);
    assert.equal(s.devices, 1);
    assert.equal(s.removableRows, 2);
    assert.equal(s.safeGroups, 1);
    assert.equal(s.safeRemovableRows, 1);
    assert.equal(s.needsReviewGroups, 1);
    assert.equal(s.needsReviewRemovableRows, 1);
    assert.equal(s.undeterminedGroups, 1);
    assert.equal(s.adjacentGroups, 1);
    assert.equal(s.byField.dst_addresses.groups, 1);
    assert.equal(s.byField.services.groups, 1);
    // ⛔ The candidate total is never the safe total.
    assert.notEqual(s.removableRows, s.safeRemovableRows);
  });

  it('an empty fleet summarises to zeroes, not to NaN', () => {
    const s = summariseConsolidation([]);
    assert.equal(s.groups, 0);
    assert.equal(s.removableRows, 0);
    assert.equal(s.safeRemovableRows, 0);
    assert.deepEqual(s.byField, {});
  });

  it('⛔ the claim never says a merge is verified safe', () => {
    const s = summariseConsolidation([]);
    assert.equal(s.claim, MERGE_CLAIM);
    for (const word of ['verified safe', 'guarantee', 'no risk', 'automatically']) {
      assert.ok(!MERGE_CLAIM.toLowerCase().includes(word), `claim must not say "${word}"`);
    }
    assert.ok(/proposal/i.test(MERGE_CLAIM));
  });
});

// ═══════════════════════════════════════════════════════════════════════
// ⛔ `raw_rule` — THE FIELDS `firewall_rules` HAS NO COLUMN FOR
//
// The canonical key used to span only the columns. Measured on the live fleet
// 2026-09-26, that made 7 of 41 `safe_to_merge` groups NOT the same rule at all
// — each one an actionable, plausible proposal to merge two rules the firewall
// treats differently. Every fixture below is a live shape.
describe('⛔ canonicalKey — raw_rule keys that decide matching or enforcement', () => {
  /** Two adjacent rules differing only in destination, plus per-rule raw_rule. */
  function pair(rawA, rawB) {
    return findConsolidationGroups([
      rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'], raw_rule: rawA }),
      rule({ id: 'b', sequence_number: 11, dst_addresses: ['10.2.0.0/24'], raw_rule: rawB }),
    ], NO_OBJECTS);
  }

  it('⛔ PAN-OS source-user: a named user and "any" are NOT the same rule (TUM(TUTH1) #126/#127)', () => {
    // Live: merging these grants #126's destination to EVERY user, or strips
    // #127's access from everyone but one. It was reported `safe_to_merge`.
    assert.deepEqual(
      pair({ 'source-user': { member: 'dlt_tum_suppakronc' } }, { 'source-user': 'any' }),
      []
    );
  });

  it('⛔ FortiOS UTM inspection present on one rule and absent on the other (OKF(F2) #26/#28)', () => {
    for (const key of ['utm-status', 'av-profile', 'ips-sensor', 'webfilter-profile',
      'ssl-ssh-profile', 'application-list', 'dnsfilter-profile', 'profile-protocol-options']) {
      assert.deepEqual(pair({ [key]: 'default' }, {}), [], `${key} must block the group`);
    }
  });

  it('⛔ PAN-OS profile-setting differing by a whole spyware profile (TUG #5/#6)', () => {
    const withSpyware = {
      'profile-setting': {
        profiles: {
          virus: { member: 'default' }, spyware: { member: 'default' },
          vulnerability: { member: 'default' },
        },
      },
    };
    const without = {
      'profile-setting': {
        profiles: { virus: { member: 'default' }, vulnerability: { member: 'default' } },
      },
    };
    assert.deepEqual(pair(withSpyware, without), []);
  });

  it('⛔ the logging keys no column carries: log-start, log-setting, logtraffic', () => {
    // The stated intent was ALREADY defeated: `log_enabled` is in the key so a
    // logged rule never merges with an unlogged one, yet live `safe_to_merge`
    // groups differed in PAN-OS log-start (IDC FW #414/#415) and FortiOS
    // logtraffic (TSR_EKM #33/#57).
    assert.deepEqual(pair({ 'log-start': 'yes' }, {}), []);
    assert.deepEqual(pair({ 'log-setting': 'tu_syslog' }, {}), []);
    assert.deepEqual(pair({ logtraffic: 'all' }, {}), []);
  });

  it('⛔ and `all` is NOT in the neutral family — that exclusion is load-bearing', () => {
    // FortiOS logtraffic `all` logs every session; the absent default logs only
    // UTM events. Folding them would merge a fully-logged rule with a partly
    // logged one, which is the whole class of mistake this section prevents.
    assert.equal(canonicalRawValue('all'), 'all');
    assert.notEqual(canonicalRawValue('all'), NEUTRAL_TOKEN);
    assert.equal(canonicalRawValue('any'), NEUTRAL_TOKEN);
  });

  it('⛔ matching keys with no column at all: category, HIP, rule-type, groups, NAT pool', () => {
    assert.deepEqual(pair({ category: { member: 'gambling' } }, {}), []);
    assert.deepEqual(pair({ 'source-hip': { member: 'corp-managed' } }, {}), []);
    assert.deepEqual(pair({ 'destination-hip': { member: 'corp-managed' } }, {}), []);
    assert.deepEqual(pair({ 'rule-type': 'intrazone' }, {}), []);
    assert.deepEqual(pair({ groups: [{ name: 'vpn-users' }] }, {}), []);
    assert.deepEqual(pair({ poolname: 'wan1-pool' }, {}), []);
    assert.deepEqual(pair({ option: { 'disable-server-response-inspection': 'yes' } }, {}), []);
  });

  // ─────────────────────────────────────────────────────────────────────
  it('⛔ A BLANKET HASH WOULD COLLAPSE THE FEATURE — identity keys must NOT split', () => {
    // Every one of these differs on every rule of a real PAN-OS or FortiOS
    // pull. Keying them would produce ZERO groups on the whole fleet, silently.
    const groups = pair(
      {
        '@_name': 'rule-a', '@_uuid': 'aaaa', '@_loc': 'PA-220-x', '@_panorama': 'yes',
        uuid: 'u-1', policyid: 1, name: 'policy 1', comments: 'first',
        description: 'first', tag: { member: 'red' }, 'group-tag': 'grp',
      },
      {
        '@_name': 'rule-b', '@_uuid': 'bbbb', '@_loc': 'PA-220-y', '@_panorama': 'no',
        uuid: 'u-2', policyid: 2, name: 'policy 2', comments: 'second',
        description: 'second', tag: { member: 'blue' }, 'group-tag': 'other',
      }
    );
    assert.equal(groups.length, 1, 'identity and label keys must never split a real group');
    assert.equal(groups[0].size, 2);
  });

  it('⛔ a field a COLUMN already models does not split the group twice', () => {
    // `from`/`to`/`source`/`destination`/`service`/`action`/`disabled`/`schedule`
    // and FortiOS's `srcintf`/`dstintf`/`srcaddr`/`dstaddr`/`status`/`nat` are
    // the SOURCE of columns that are already in the key. Keying the raw copy as
    // well would be the same fact twice — and `nat` was missed on the first
    // pass, which put every FortiOS rule carrying it into review until a live
    // probe named it.
    const groups = pair(
      { destination: { member: 'net-a' }, dstaddr: [{ name: 'net-a' }], nat: 'enable' },
      { destination: { member: 'net-b' }, dstaddr: [{ name: 'net-b' }], nat: 'enable' }
    );
    assert.equal(groups.length, 1);
  });

  it('⛔ an explicit vendor DEFAULT keys the same as an absent key', () => {
    // Live: PAN-OS writes `negate-source: no` on 131 of 1,601 rules and omits it
    // on the rest; `destination-hip: any` on 1,197 while 404 carry nothing. Key
    // those apart and a real group splits for a spelling difference.
    assert.equal(pair({ 'negate-source': 'no' }, {}).length, 1);
    assert.equal(pair({ 'destination-hip': { member: 'any' } }, {}).length, 1);
    assert.equal(pair({ 'log-start': 'no' }, {}).length, 1);
    assert.equal(pair({ 'utm-status': 'disable' }, {}).length, 1);
    for (const v of [null, undefined, '', 'no', 'none', 'false', '0', 'disable', 'disabled',
      'off', 'unset', 'any', 'ANY', ' No ']) {
      assert.equal(canonicalRawValue(v), NEUTRAL_TOKEN, `${JSON.stringify(v)} is neutral`);
    }
  });

  it('⛔ Panorama uncommitted-change attributes and #text wrapping do not split (IDC FW #54..#72)', () => {
    // Live shape: the SAME value, one copy wrapped in @_time/@_admin/@_dirtyId
    // and its text pushed into #text. Without stripping them, five identical
    // rules split into two groups for pure metadata.
    const plain = {
      'source-user': { member: 'any' },
      'profile-setting': { profiles: { virus: { member: 'default' } } },
      'log-start': 'yes',
    };
    const attributed = {
      'source-user': {
        '@_time': '2026/08/07 14:43:44',
        member: { '#text': 'any', '@_time': '2026/08/07 14:43:44', '@_admin': 'Naron' },
        '@_admin': 'Naron', '@_dirtyId': '78',
      },
      'profile-setting': {
        '@_time': '2026/08/07 14:43:44',
        profiles: {
          virus: { member: { '#text': 'default', '@_dirtyId': '78' }, '@_dirtyId': '78' },
        },
        '@_dirtyId': '78',
      },
      'log-start': { '#text': 'yes', '@_admin': 'Naron' },
    };
    assert.equal(pair(plain, attributed).length, 1);
    assert.equal(canonicalRawValue(plain['log-start']), canonicalRawValue(attributed['log-start']));
  });

  it('member ORDER inside a raw value does not matter — these are sets', () => {
    assert.equal(
      canonicalRawValue({ member: ['b', 'a'] }),
      canonicalRawValue({ member: ['a', 'b'] })
    );
    assert.equal(
      pair({ category: { member: ['x', 'y'] } }, { category: { member: ['y', 'x'] } }).length,
      1
    );
  });

  // ─────────────────────────────────────────────────────────────────────
  it('⛔ AN UNCLASSIFIED KEY FORCES needs_review AND IS NAMED — it never splits silently', () => {
    const groups = pair({ 'brand-new-vendor-field': 'quarantine' }, {});
    assert.equal(groups.length, 1, 'an unknown key must not make the candidate disappear');
    assert.equal(groups[0].verdict, VERDICTS.REVIEW);
    assert.equal(groups[0].adjacent, false);
    const u = groups[0].undetermined.filter((x) => x.reason === 'unclassified_raw_rule_key');
    assert.equal(u.length, 1);
    // ⛔ The KEY is reported. The fix is to classify it, not to widen anything,
    // and an operator who cannot see which key it was cannot ask for that.
    assert.equal(u[0].field, 'brand-new-vendor-field');
  });

  it('⛔ ...and it cannot be reached by hiding behind a classified sibling', () => {
    const groups = pair(
      { 'log-start': 'yes', 'brand-new-vendor-field': 'x' },
      { 'log-start': 'yes', 'brand-new-vendor-field': 'x' }
    );
    assert.equal(groups.length, 1);
    assert.equal(groups[0].verdict, VERDICTS.REVIEW);
  });

  it('classifyRawRuleKeys drops neutral significant keys and tolerates junk', () => {
    assert.deepEqual(classifyRawRuleKeys({ raw_rule: { 'log-start': 'no' } }).significant, []);
    assert.deepEqual(
      classifyRawRuleKeys({ raw_rule: { 'log-start': 'yes' } }).significant,
      [['log-start', 'yes']]
    );
    for (const raw of [null, undefined, 'a string', 42, ['an array'], true]) {
      assert.deepEqual(
        classifyRawRuleKeys({ raw_rule: raw }),
        { significant: [], unclassified: [] }
      );
    }
    assert.deepEqual(classifyRawRuleKeys(null), { significant: [], unclassified: [] });
  });

  it('⛔ the three buckets are DISJOINT and every entry carries a reason', () => {
    for (const k of Object.keys(RAW_KEY_SIGNIFICANT)) {
      assert.equal(k, k.toLowerCase(), `${k} must be lower-cased to be found`);
      assert.ok(!Object.prototype.hasOwnProperty.call(RAW_KEY_IGNORED, k),
        `${k} is in BOTH buckets — which one wins would then be source order`);
      assert.ok(String(RAW_KEY_SIGNIFICANT[k]).length > 8, `${k} needs a stated reason`);
      assert.ok(!k.startsWith(ATTRIBUTE_KEY_PREFIX), `${k} would be dropped by the attribute rule`);
    }
    for (const k of Object.keys(RAW_KEY_IGNORED)) {
      assert.equal(k, k.toLowerCase(), `${k} must be lower-cased to be found`);
      assert.ok(String(RAW_KEY_IGNORED[k]).length > 3, `${k} needs a stated reason`);
    }
    // ⛔ The negate family must be SIGNIFICANT, not ignored: it inverts an
    // extent, which is the one thing that makes a disjointness proof backwards.
    for (const k of ['negate-source', 'negate-destination', 'srcaddr-negate',
      'dstaddr-negate', 'service-negate']) {
      assert.ok(Object.prototype.hasOwnProperty.call(RAW_KEY_SIGNIFICANT, k),
        `${k} must be significant`);
    }
  });

  it('keys are matched case-insensitively, so a vendor changing case cannot re-open the gap', () => {
    assert.deepEqual(classifyRawRuleKeys({ raw_rule: { 'LOG-START': 'yes' } }).unclassified, []);
    assert.deepEqual(classifyRawRuleKeys({ raw_rule: { Uuid: 'x' } }).unclassified, []);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// ⛔ NEGATION IS A PROPERTY OF THE RULE, NOT OF ITS NEIGHBOURS
//
// hasNegationMarker was reachable only through mightMatchSameTraffic, which runs
// only for an INTERVENING rule — so a negated MEMBER with nothing between it and
// its partner produced `examined === 0` and a clean `safe_to_merge`. 20 of the
// live fleet's 92 groups took that path.
describe('⛔ a negated MEMBER is never cleared, whatever sits between', () => {
  it('two ADJACENT members, one negated, are not even the same rule', () => {
    // The canonical key is the FIRST of the two guards: `negate-source` is
    // significant, so "source NOT in X" and "source IN X" no longer group.
    assert.deepEqual(findConsolidationGroups([
      rule({
        id: 'neg', sequence_number: 10, dst_addresses: ['10.1.0.0/24'],
        raw_rule: { 'negate-source': 'yes' },
      }),
      rule({ id: 'plain', sequence_number: 11, dst_addresses: ['10.2.0.0/24'] }),
    ], NO_OBJECTS), []);
  });

  it('⛔ and when BOTH are negated identically they group — and are STILL needs_review', () => {
    // This is the half the canonical key cannot do. `examined` is 0: there is
    // nothing between them, so the position check has nothing to say, and the
    // old code called that safe. A merge writes NOT(A ∪ B), which is not what
    // the two rules match (NOT A ∪ NOT B).
    const groups = findConsolidationGroups([
      rule({
        id: 'n1', sequence_number: 10, dst_addresses: ['10.1.0.0/24'],
        raw_rule: { 'negate-source': 'yes' },
      }),
      rule({
        id: 'n2', sequence_number: 11, dst_addresses: ['10.2.0.0/24'],
        raw_rule: { 'negate-source': 'yes' },
      }),
    ], NO_OBJECTS);
    assert.equal(groups.length, 1);
    assert.equal(groups[0].examined, 0);
    assert.equal(groups[0].verdict, VERDICTS.REVIEW);
    assert.equal(groups[0].adjacent, false, 'adjacent must not survive an undetermined check');
    assert.deepEqual(
      groups[0].undetermined.map((u) => u.reason),
      ['member_field_is_negated', 'member_field_is_negated']
    );
  });

  it('⛔ checkInterference refuses a negated member with an EMPTY pool', () => {
    // The pool is where every other guard lives. With nothing in it the only
    // thing that can fall closed is a property of the members themselves.
    const a = rule({
      id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'],
      raw_rule: { 'dstaddr-negate': 'enable' },
    });
    const b = rule({ id: 'b', sequence_number: 11, dst_addresses: ['10.2.0.0/24'] });
    const out = checkInterference([a, b], [], { objects: [] });
    assert.equal(out.verdict, VERDICTS.REVIEW);
    assert.equal(out.examined, 0);
    assert.equal(out.undetermined[0].reason, 'member_field_is_negated');
    assert.equal(out.undetermined[0].rule.id, 'a');
  });

  it('a negate flag that is OFF still does not poison a member', () => {
    const a = rule({
      id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'],
      raw_rule: { 'dstaddr-negate': 'disable' },
    });
    const b = rule({
      id: 'b', sequence_number: 11, dst_addresses: ['10.2.0.0/24'],
      raw_rule: { 'dstaddr-negate': 'disable' },
    });
    assert.equal(checkInterference([a, b], [], { objects: [] }).verdict, VERDICTS.SAFE);
  });

  it('⛔ an XML TEXT NODE is read as its text, not as an object (TFM-RN #12)', () => {
    // Live: `{"#text":"no","@_loc":"PA-220-Ranode"}`. Stringified, it is not the
    // literal "no", so the old code read it as NEGATED. That over-reports — it
    // falls closed — but a count nobody can trust is still not a count.
    assert.equal(hasNegationMarker({
      raw_rule: { 'negate-destination': { '#text': 'no', '@_loc': 'PA-220-Ranode' } },
    }), false);
    // ...and the same shape carrying `yes` IS still negated.
    assert.equal(hasNegationMarker({
      raw_rule: { 'negate-destination': { '#text': 'yes', '@_loc': 'PA-220-Ranode' } },
    }), true);
    assert.equal(hasNegationMarker({ raw_rule: { 'negate-source': 'yes' } }), true);
    assert.equal(hasNegationMarker({ raw_rule: {} }), false);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// ⛔ A DUPLICATE SEQUENCE NUMBER IS NOT "OUTSIDE THE SPAN"
//
// `cs <= mergePosition || cs >= maxSeq` is sound only if sequence numbers are
// unique per device+vdom, and nothing in this codebase checks that. Measured
// 2026-09-26: zero duplicates on the live fleet — so this is a guard for the
// collection that goes wrong later, which is exactly when a cleanup proposal
// must not be trusted.
describe('⛔ duplicate sequence numbers inside the span', () => {
  const a = () => rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] });
  const b = () => rule({ id: 'b', sequence_number: 12, dst_addresses: ['10.2.0.0/24'] });
  /** A deny whose destination is the SECOND member's — it would interfere. */
  const deny = (seq) => rule({
    id: `deny${seq}`, sequence_number: seq, action: 'deny',
    src_addresses: ['10.0.0.0/24'], dst_addresses: ['10.2.0.0/24'], services: ['tcp/443'],
  });

  it('a non-member sharing the FIRST member position is undetermined, not absent', () => {
    const [m1, m2, d] = [a(), b(), deny(10)];
    const out = checkInterference([m1, m2], [m1, m2, d], { objects: [] });
    assert.equal(out.verdict, VERDICTS.REVIEW);
    assert.equal(out.adjacent, false,
      'the UI would otherwise print "Nothing enabled sits between these rules."');
    assert.deepEqual(out.undetermined.map((u) => u.reason), ['duplicate_sequence_number_in_span']);
  });

  it('...and one sharing the LAST member position too', () => {
    const [m1, m2, d] = [a(), b(), deny(12)];
    const out = checkInterference([m1, m2], [m1, m2, d], { objects: [] });
    assert.equal(out.verdict, VERDICTS.REVIEW);
    assert.deepEqual(out.undetermined.map((u) => u.reason), ['duplicate_sequence_number_in_span']);
  });

  it('a rule genuinely ABOVE or BELOW the span is still skipped, not reviewed', () => {
    for (const seq of [9, 13]) {
      const [m1, m2, d] = [a(), b(), deny(seq)];
      const out = checkInterference([m1, m2], [m1, m2, d], { objects: [] });
      assert.equal(out.verdict, VERDICTS.SAFE, `a rule at ${seq} is outside [10,12]`);
      assert.equal(out.examined, 0);
    }
  });

  it('a rule strictly INSIDE the span is still examined normally', () => {
    const [m1, m2, d] = [a(), b(), deny(11)];
    const out = checkInterference([m1, m2], [m1, m2, d], { objects: [] });
    assert.equal(out.examined, 1);
    assert.equal(out.verdict, VERDICTS.REVIEW);
    assert.equal(out.interfering[0].reason, 'matches_moved_traffic');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// ⛔ AN EMPTY EXTENT IS NOT A DISJOINT ONE
//
// dimensionOverlap's own doc says 'no' "requires BOTH sides fully resolved and
// provably disjoint". An address GROUP whose `members` is [] satisfies that to
// the letter: the group itself resolved, so nothing lands in unresolvedNames —
// and it contributes no range either. `storeObjects` writes [] for a group the
// adapter did not return, and two such groups exist live (Vietnam-YCC, OKF(F2)),
// so a PARTIAL object read produced a confident "provably disjoint".
describe('⛔ an object group whose members could not be enumerated', () => {
  const members = () => [
    rule({ id: 'a', sequence_number: 10, dst_addresses: ['10.1.0.0/24'] }),
    rule({ id: 'b', sequence_number: 40, dst_addresses: ['10.2.0.0/24'] }),
  ];

  it('an EMPTY address group on an intervening rule is undeterminable, never disjoint', () => {
    const m = members();
    const mid = rule({
      id: 'mid', sequence_number: 20, action: 'deny',
      src_addresses: ['EMPTY-GRP'], dst_addresses: ['10.2.0.0/24'], services: ['tcp/443'],
    });
    const out = checkInterference(m, [...m, mid], {
      objects: [{
        id: 'o1', object_type: 'address_group', name: 'EMPTY-GRP', value: null, members: [],
      }],
    });
    assert.equal(out.verdict, VERDICTS.REVIEW);
    assert.equal(out.examined, 1);
    assert.equal(out.interfering.length, 0);
    assert.equal(out.undetermined[0].reason, 'overlap_could_not_be_determined');
  });

  it('an EMPTY service group is undeterminable too', () => {
    const m = members();
    const mid = rule({
      id: 'mid', sequence_number: 20, action: 'deny',
      src_addresses: ['10.0.0.0/24'], dst_addresses: ['10.2.0.0/24'], services: ['EMPTY-SVC'],
    });
    const out = checkInterference(m, [...m, mid], {
      objects: [{
        id: 'o1', object_type: 'service_group', name: 'EMPTY-SVC', value: null, members: [],
      }],
    });
    assert.equal(out.verdict, VERDICTS.REVIEW);
    assert.equal(out.undetermined[0].reason, 'overlap_could_not_be_determined');
  });

  it('⛔ ...and a POPULATED group still resolves and can still clear the group', () => {
    // The fix must not blanket-unknown every object reference — that would make
    // the engine silent rather than conservative, and nothing would ever clear.
    const m = members();
    const mid = rule({
      id: 'mid', sequence_number: 20, action: 'deny',
      src_addresses: ['FULL-GRP'], dst_addresses: ['10.2.0.0/24'], services: ['tcp/443'],
    });
    const out = checkInterference(m, [...m, mid], {
      objects: [
        {
          id: 'o1', object_type: 'address_group', name: 'FULL-GRP', value: null,
          members: ['HOST-1'],
        },
        {
          id: 'o2', object_type: 'address', name: 'HOST-1', value: '192.168.77.5/32',
          members: null,
        },
      ],
    });
    assert.equal(out.verdict, VERDICTS.SAFE);
    assert.equal(out.examined, 1);
  });
});
