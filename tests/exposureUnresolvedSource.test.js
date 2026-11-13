'use strict';

// ⛔ ROADMAP ROW 42: A RULE WHOSE SOURCE RESOLVED TO NOTHING WAS DROPPED AS "NOT
// INTERNET-FACING", AND THE COUNTER THAT WOULD HAVE DISCLOSED IT WAS UNREACHABLE.
//
// `sourceHasPublic` was true only via `isAny` or a RESOLVED non-private range, so a source
// of object names matching no `network_objects` row yielded `ranges: []` with
// `unresolvedNames` populated — matchesAddress's own 'unresolved' state — and hit the same
// `continue` as a rule proven internal-only. `unresolvedRules++` sat AFTER that `continue`,
// so a dropped rule was never even counted.
//
// This file's own header calls under-reporting exposure the more dangerous error, and the
// path object already carried `directionVerified: false` for exactly this reason on a
// different input. These tests pin the OUTCOME: the path appears, it is flagged, and it
// scores nothing for a source nobody could read.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { buildExposurePaths, scoreExposure } = require('../lib/engines/exposure');

const IFACES = [{
  interfaceName: 'wan1',
  zone: 'untrust',
  ipAddress: '203.0.113.10/32',
  ip_address: '203.0.113.10/32',
}];

function inboundRule(src, extra = {}) {
  return {
    rule_id_vendor: 'r-1',
    rule_name: 'inbound-web',
    enabled: true,
    action: 'allow',
    sequence_number: 1,
    src_zones: ['untrust'],
    dst_zones: ['trust'],
    src_addresses: src,
    dst_addresses: ['any'],
    services: ['tcp/443'],
    log_enabled: true,
    ...extra,
  };
}

const build = (rules, objects = []) =>
  buildExposurePaths({ rules, objects, natRules: [], interfaces: IFACES });

describe('a rule whose source cannot be resolved is reported, not dropped', () => {
  it('⛔ produces a path instead of silently disappearing', () => {
    // GHOST_GROUP matches no network_objects row of any type — the live shape on the three
    // devices (PAKFood, TSR_EKC, TSR-TL) that have no network_objects rows at all.
    const { paths } = build([inboundRule(['GHOST_GROUP'])]);
    assert.equal(paths.length, 1, 'an unresolvable source must not read as "not internet-facing"');
    assert.equal(paths[0].publicIp, '203.0.113.10');
  });

  it('flags the path rather than claiming it is confirmed', () => {
    const { paths } = build([inboundRule(['GHOST_GROUP'])]);
    assert.equal(paths[0].sourceResolved, false);
  });

  it('⛔ counts the rule — the counter used to sit after the `continue` that dropped it', () => {
    const { unresolvedRules } = build([inboundRule(['GHOST_GROUP'])]);
    assert.equal(unresolvedRules, 1);
  });

  it('keeps the two caveats apart: an unresolved source is not an unverified direction', () => {
    // Collapsing them would send an operator to collect zone data when the real gap is
    // network objects, or the reverse.
    const { paths } = build([inboundRule(['GHOST_GROUP'])]);
    assert.equal(paths[0].sourceResolved, false);
    assert.equal(paths[0].directionVerified, true, 'zone data WAS collected here');
  });
});

describe('a resolvable source still answers definitely, both ways', () => {
  it('a wholly-private resolved source is still excluded', () => {
    // The other half: a fix that reported everything would pass every test above.
    const objects = [{ object_type: 'address', name: 'LAN', value: '10.0.0.0/8' }];
    const { paths, unresolvedRules } = build([inboundRule(['LAN'])], objects);
    assert.equal(paths.length, 0, 'a source proven to be private is not internet exposure');
    assert.equal(unresolvedRules, 0, 'and it is not reported as a resolution gap');
  });

  it('a resolved public source produces a confirmed path', () => {
    const objects = [{ object_type: 'address', name: 'PARTNER', value: '198.51.100.0/24' }];
    const { paths } = build([inboundRule(['PARTNER'])], objects);
    assert.equal(paths.length, 1);
    assert.equal(paths[0].sourceResolved, true);
  });

  it('an ANY source is confirmed, not flagged', () => {
    const { paths } = build([inboundRule(['any'])]);
    assert.equal(paths.length, 1);
    assert.equal(paths[0].sourceIsAny, true);
    assert.equal(paths[0].sourceResolved, true);
  });
});

describe('scoreExposure: an unresolved source adds nothing and says why', () => {
  const basePath = {
    publicIp: '203.0.113.10',
    directionVerified: true,
    sourceIsAny: false,
    service: { isAny: false, unresolved: false, label: 'tcp/443' },
    logEnabled: true,
    observation: 'unmeasured',
    unmeasuredReason: null,
    evidence: null,
    internal: null,
  };

  it('⛔ scores LOWER than the same path with a resolved public source', () => {
    const resolved = scoreExposure({ ...basePath, sourceResolved: true });
    const unresolved = scoreExposure({ ...basePath, sourceResolved: false });
    assert.ok(
      unresolved.score < resolved.score,
      `an unreadable extent must not score as risk (${unresolved.score} vs ${resolved.score})`
    );
  });

  it('⛔ never claims the source is restricted-but-public', () => {
    // That sentence is a claim about an extent nobody could read. Falling into the `else`
    // branch would have asserted it.
    const { reasons } = scoreExposure({ ...basePath, sourceResolved: false });
    assert.ok(
      reasons.some((r) => /Source UNRESOLVED/.test(r)),
      'the caveat must be stated, not implied'
    );
    assert.ok(
      !reasons.some((r) => /restricted to specific ranges/.test(r)),
      'must not assert an extent it could not read'
    );
    assert.ok(
      !reasons.some((r) => /reachable from the entire internet/.test(r)),
      'and must not assert the opposite either'
    );
  });

  it('states why it is shown at all', () => {
    const { reasons } = scoreExposure({ ...basePath, sourceResolved: false });
    const r = reasons.find((x) => /Source UNRESOLVED/.test(x));
    assert.match(r, /under-reporting exposure/);
    assert.match(r, /not knowing is not evidence/);
  });

  it('an ANY source still scores its 40 when the source IS resolved', () => {
    const { score, reasons } = scoreExposure({
      ...basePath, sourceResolved: true, sourceIsAny: true,
    });
    assert.ok(score >= 40, 'the no-regression case');
    assert.ok(reasons.some((r) => /Source is ANY/.test(r)));
  });
});
