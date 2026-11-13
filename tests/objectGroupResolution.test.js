'use strict';

// ⛔ ROADMAP ROW 26: AN UN-EXPANDED OBJECT GROUP RESOLVED TO A CONFIDENT `no-match`.
//
// `resolveAddressEntry`/`resolveServiceEntry` left their group branch by three different
// doors — a cycle, MAX_GROUP_DEPTH, and a `members` list that was never enumerated — and
// flagged NONE of them. `matchesAddress`/`matchesService` then returned a DEFINITIVE
// exclusion built from an object nobody read. The in-code comment justified the branch for
// the CYCLE case only, which is the one case where it is actually correct.
//
// This is the resolver `topology.js`, `exposure.js`, `applicationView.js` and
// `applicationRetire.js` all reuse unchanged, so a wrong tri-state here is wrong in four
// engines at once. The identical fix had already been made one file over in
// `ruleConsolidation`'s `dimensionOverlap` on 2026-09-26 ("a zero-range non-wildcard extent
// is `unknown`, NOT `no`") and was never applied here.
//
// These tests assert the OUTCOME — which of the three tri-state values comes back — not that
// any particular branch exists.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  buildObjectMap,
  resolveAddressField,
  resolveServiceField,
  matchesAddress,
  matchesService,
  groupExpansionBlock,
  groupUnresolvedLabel,
  MAX_GROUP_DEPTH,
} = require('../lib/engines/objectResolver');

// 10.1.2.3 as a uint32, the query address used throughout.
const QUERY_IP = (10 * 2 ** 24) + (1 * 2 ** 16) + (2 * 2 ** 8) + 3;

const addrMap = (objects) => buildObjectMap(objects, ['address', 'address_group']);
const svcMap = (objects) => buildObjectMap(objects, ['service', 'service_group']);

describe('an address group whose membership was never expanded is `unresolved`', () => {
  it('⛔ an EMPTY members array is unresolved, not a confident exclusion', () => {
    // The dangerous output: `deny` / "not internet-facing" / "no violation", asserted from a
    // group nobody read. Nothing in this system can tell an enumerated-empty group from an
    // un-enumerated one (every adapter builds an array either way), so the safe side wins.
    const map = addrMap([{ object_type: 'address_group', name: 'TELEMETRY', members: [] }]);
    const resolved = resolveAddressField(['TELEMETRY'], map);
    assert.equal(matchesAddress(resolved, QUERY_IP), 'unresolved');
    assert.equal(resolved.unresolvedNames.length, 1);
    assert.match(resolved.unresolvedNames[0], /TELEMETRY/);
  });

  it('a missing / non-array members value is unresolved', () => {
    for (const members of [undefined, null, 'web1,web2', {}, 0]) {
      const map = addrMap([{ object_type: 'address_group', name: 'G', members }]);
      assert.equal(
        matchesAddress(resolveAddressField(['G'], map), QUERY_IP),
        'unresolved',
        `members=${JSON.stringify(members)} must not produce a definitive answer`
      );
    }
  });

  it('⛔ nesting deeper than MAX_GROUP_DEPTH is unresolved — members exist and were not read', () => {
    // Distinct from a cycle: this chain never revisits a group, so nothing was accumulated
    // beyond the cap and the extent is genuinely incomplete.
    const objects = [];
    const depth = MAX_GROUP_DEPTH + 5;
    for (let i = 0; i < depth; i += 1) {
      objects.push({ object_type: 'address_group', name: `G${i}`, members: [`G${i + 1}`] });
    }
    objects.push({ object_type: 'address', name: `G${depth}`, value: '10.1.2.3/32' });

    const resolved = resolveAddressField(['G0'], addrMap(objects));
    assert.equal(
      matchesAddress(resolved, QUERY_IP),
      'unresolved',
      'the leaf really does contain the query address, and the walk never reached it'
    );
    assert.ok(
      resolved.unresolvedNames.some((n) => /not expanded/.test(n)),
      'the reason must say the chain was not walked, not merely that something failed'
    );
  });

  it('a TRUE CYCLE stays silent, because its members were already accumulated', () => {
    // ⛔ The one case the original branch was right about, and the regression test for the
    // fix: refusing to walk back into a visited group loses no information, so turning every
    // cycle into `unresolved` would make a legitimate verdict unverifiable.
    const map = addrMap([
      { object_type: 'address_group', name: 'A', members: ['HOST', 'B'] },
      { object_type: 'address_group', name: 'B', members: ['A'] },
      { object_type: 'address', name: 'HOST', value: '10.1.2.3/32' },
    ]);
    const resolved = resolveAddressField(['A'], map);
    assert.equal(matchesAddress(resolved, QUERY_IP), 'match');
    assert.deepEqual(resolved.unresolvedNames, [], 'a cycle must not manufacture a caveat');
  });

  it('a normally-populated group still resolves to a definite answer', () => {
    // The other half: a guard that returns `unresolved` for everything passes every test above.
    const map = addrMap([
      { object_type: 'address_group', name: 'WEB', members: ['W1', 'W2'] },
      { object_type: 'address', name: 'W1', value: '10.1.2.0/24' },
      { object_type: 'address', name: 'W2', value: '192.168.5.0/24' },
    ]);
    const hit = resolveAddressField(['WEB'], map);
    assert.equal(matchesAddress(hit, QUERY_IP), 'match');
    assert.deepEqual(hit.unresolvedNames, []);

    const miss = resolveAddressField(['W2'], map);
    assert.equal(matchesAddress(miss, QUERY_IP), 'no-match', 'a real exclusion must survive');
    assert.deepEqual(miss.unresolvedNames, []);
  });
});

describe('service groups carry the identical defect and the identical fix', () => {
  it('⛔ an empty service group is unresolved, not no-match', () => {
    const map = svcMap([{ object_type: 'service_group', name: 'SVCG', members: [] }]);
    assert.equal(matchesService(resolveServiceField(['SVCG'], map), 'tcp', 443), 'unresolved');
  });

  it('deeper than MAX_GROUP_DEPTH is unresolved', () => {
    const objects = [];
    const depth = MAX_GROUP_DEPTH + 3;
    for (let i = 0; i < depth; i += 1) {
      objects.push({ object_type: 'service_group', name: `S${i}`, members: [`S${i + 1}`] });
    }
    objects.push({ object_type: 'service', name: `S${depth}`, value: 'tcp/443' });
    assert.equal(
      matchesService(resolveServiceField(['S0'], svcMap(objects)), 'tcp', 443),
      'unresolved'
    );
  });

  it('a populated service group still answers definitely, both ways', () => {
    const map = svcMap([
      { object_type: 'service_group', name: 'WEBSVC', members: ['HTTPS'] },
      { object_type: 'service', name: 'HTTPS', value: 'tcp/443' },
    ]);
    const resolved = resolveServiceField(['WEBSVC'], map);
    assert.equal(matchesService(resolved, 'tcp', 443), 'match');
    assert.equal(matchesService(resolved, 'tcp', 22), 'no-match');
  });
});

describe('groupExpansionBlock / groupUnresolvedLabel', () => {
  it('names the three blocks and only the three', () => {
    const g = (members, name = 'G') => ({ object_type: 'address_group', name, members });
    assert.equal(groupExpansionBlock(g(['x']), new Set(['G']), 0), 'cycle');
    assert.equal(groupExpansionBlock(g(['x']), new Set(), MAX_GROUP_DEPTH), 'depth');
    assert.equal(groupExpansionBlock(g(null), new Set(), 0), 'not_enumerated');
    assert.equal(groupExpansionBlock(g([]), new Set(), 0), 'not_enumerated');
    assert.equal(groupExpansionBlock(g(['x']), new Set(), 0), null, 'a normal group is not blocked');
  });

  it('⛔ the cycle is the ONLY block that produces no caveat', () => {
    assert.equal(groupUnresolvedLabel('G', 'cycle'), null);
    for (const block of ['depth', 'not_enumerated']) {
      const label = groupUnresolvedLabel('G', block);
      assert.equal(typeof label, 'string');
      assert.match(label, /^G /, 'the caveat must name the group an operator has to go and look at');
    }
  });

  it('the depth and not-enumerated reasons are worded apart', () => {
    assert.notEqual(
      groupUnresolvedLabel('G', 'depth'),
      groupUnresolvedLabel('G', 'not_enumerated'),
      'one is a SecVault walk limit, the other is missing collection — different first steps'
    );
  });

  it('⛔ the not-enumerated reason does not claim the group is empty', () => {
    // It genuinely may be empty. Asserting either way would be the confident wrong answer
    // this whole fix exists to remove.
    assert.match(groupUnresolvedLabel('G', 'not_enumerated'), /cannot tell which/);
  });

  it('the cap boundary is inclusive on the blocking side', () => {
    const g = { object_type: 'address_group', name: 'G', members: ['x'] };
    assert.equal(groupExpansionBlock(g, new Set(), MAX_GROUP_DEPTH - 1), null);
    assert.equal(groupExpansionBlock(g, new Set(), MAX_GROUP_DEPTH), 'depth');
  });
});
