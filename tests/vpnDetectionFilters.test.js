'use strict';
// tests/vpnDetectionFilters.test.js
//
// Pins lib/vpnDetectionFilters.js — the narrowing behind /vpn?vtab=detections.
//
// ⛔ WHY A FILTER NEEDS TESTS AT ALL. Every wrong answer here is a SHORTER LIST
// THAT LOOKS COMPLETE, which is this repo's most-repeated failure wearing a
// filter's clothes. Nothing throws, nothing renders oddly; an operator filters
// by country, sees three rows instead of eleven, and concludes the other eight
// attacks did not happen.
//
// The specific hazard is that the six detections carry country in THREE
// different shapes — `country`, `countries[]`, and a from/to PAIR — so a filter
// written against the first shape silently drops half the detections out of
// every country query.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  matchesFilters,
  filtersActive,
  countriesIn,
  countriesOf,
} = require('../lib/vpnDetectionFilters');

// One finding of each country SHAPE the engine actually emits.
const SPRAY = { severity: 'critical', srcIp: '93.152.210.31', country: 'Bulgaria', devices: [{ deviceName: 'IDC FW' }] };
const BRUTE = { severity: 'high', username: 'admin', srcIp: '2.27.98.43', country: 'Germany' };
const TARGETED = { severity: 'medium', username: 'romain.deguitre', countries: ['Poland', 'Canada'] };
const CHANGE = { severity: 'low', username: 'jdoe', fromCountry: 'Thailand', toCountry: 'Switzerland', fromSrcIp: '1.1.1.1', toSrcIp: '2.2.2.2' };
const OFF_HOURS = { severity: 'low', username: 'sistema', hourUtc: 3, countries: ['Thailand'] };
// ⛔ The live case with no geography at all: the firewall reported no country.
const NO_COUNTRY = { severity: 'high', username: 'test', srcIp: '10.0.0.5' };

describe('countriesOf — all three shapes, or three detections vanish', () => {
  it('reads a plain country', () => assert.deepEqual(countriesOf(SPRAY), ['Bulgaria']));
  it('reads a countries[] array', () => assert.deepEqual(countriesOf(TARGETED), ['Poland', 'Canada']));
  it('reads a from/to pair', () => assert.deepEqual(countriesOf(CHANGE), ['Thailand', 'Switzerland']));
  it('returns nothing for a finding with no geography', () => assert.deepEqual(countriesOf(NO_COUNTRY), []));
  it('never throws on junk', () => {
    for (const bad of [null, undefined, 0, '', [], 'nope', { countries: 'not-an-array' }]) {
      assert.doesNotThrow(() => countriesOf(bad));
      assert.deepEqual(countriesOf(bad), []);
    }
  });
  it('ignores empty and whitespace-only country strings', () => {
    assert.deepEqual(countriesOf({ country: '   ', countries: ['', 'Spain'] }), ['Spain']);
  });
});

describe('matchesFilters — severity', () => {
  it('keeps an exact match and drops the rest', () => {
    assert.equal(matchesFilters(SPRAY, { severity: 'critical' }), true);
    assert.equal(matchesFilters(BRUTE, { severity: 'critical' }), false);
  });
  it('an unset severity filter keeps everything', () => {
    for (const f of [SPRAY, BRUTE, TARGETED, CHANGE, NO_COUNTRY]) {
      assert.equal(matchesFilters(f, { severity: '' }), true);
    }
  });
});

describe('matchesFilters — country, across every shape', () => {
  it('matches a plain country', () => {
    assert.equal(matchesFilters(SPRAY, { country: 'Bulgaria' }), true);
    assert.equal(matchesFilters(SPRAY, { country: 'Germany' }), false);
  });

  it('⛔ matches inside countries[] — the account-targeted and off-hours shape', () => {
    // Written against `country` alone, this returns false and account_targeted
    // disappears from every country filter.
    assert.equal(matchesFilters(TARGETED, { country: 'Canada' }), true);
    assert.equal(matchesFilters(OFF_HOURS, { country: 'Thailand' }), true);
  });

  it('⛔ matches EITHER END of a country change', () => {
    // A country-change finding is about a pair. Matching only `fromCountry`
    // would hide "somebody authenticated into Switzerland" from a Switzerland
    // filter — which is the direction a reader actually cares about.
    assert.equal(matchesFilters(CHANGE, { country: 'Thailand' }), true);
    assert.equal(matchesFilters(CHANGE, { country: 'Switzerland' }), true);
    assert.equal(matchesFilters(CHANGE, { country: 'Poland' }), false);
  });

  it('⛔ a finding naming NO country is EXCLUDED, not passed through', () => {
    // "We do not know where this came from" is not a match for "Switzerland".
    // Letting it through would file an unlocatable finding under a heading that
    // claims a location for it. The cost — that narrowing hides findings whose
    // country the firewall never reported — is why the caller prints
    // "showing N of M" rather than N alone.
    assert.equal(matchesFilters(NO_COUNTRY, { country: 'Switzerland' }), false);
    // ...and it survives when no country filter is set.
    assert.equal(matchesFilters(NO_COUNTRY, { country: '' }), true);
  });

  it('is exact, not substring — "Chad" must not match "Chile"', () => {
    assert.equal(matchesFilters({ country: 'Chile' }, { country: 'Ch' }), false);
  });
});

describe('matchesFilters — free-text search', () => {
  it('finds a username, an address and a country', () => {
    assert.equal(matchesFilters(BRUTE, { q: 'admin' }), true);
    assert.equal(matchesFilters(BRUTE, { q: '2.27.98' }), true);
    assert.equal(matchesFilters(BRUTE, { q: 'germany' }), true);
  });

  it('searches BOTH addresses of a country change', () => {
    assert.equal(matchesFilters(CHANGE, { q: '2.2.2.2' }), true);
  });

  it('reaches a device name inside the devices[] objects', () => {
    // devices[] holds {deviceId, deviceName, vendor}, not strings. Joining the
    // objects directly yields "[object Object]" and the search silently never
    // matches a firewall name.
    assert.equal(matchesFilters(SPRAY, { q: 'idc' }), true);
  });

  it('is case-insensitive and trims', () => {
    assert.equal(matchesFilters(BRUTE, { q: '  ADMIN  ' }), true);
  });

  it('drops a finding that matches nothing', () => {
    assert.equal(matchesFilters(BRUTE, { q: 'nonesuch' }), false);
  });
});

describe('matchesFilters — the filters combine with AND', () => {
  it('all set filters must hold', () => {
    assert.equal(matchesFilters(BRUTE, { q: 'admin', severity: 'high', country: 'Germany' }), true);
    assert.equal(matchesFilters(BRUTE, { q: 'admin', severity: 'low', country: 'Germany' }), false);
    assert.equal(matchesFilters(BRUTE, { q: 'admin', severity: 'high', country: 'Poland' }), false);
  });

  it('no filters at all keeps everything, and never throws', () => {
    for (const none of [null, undefined, {}, { q: '', country: '', severity: '' }]) {
      assert.equal(matchesFilters(BRUTE, none), true);
    }
  });
});

describe('filtersActive', () => {
  it('is false for nothing set', () => {
    for (const none of [null, undefined, {}, { q: '   ', country: '', severity: '' }]) {
      assert.equal(filtersActive(none), false);
    }
  });
  it('is true for any single filter', () => {
    assert.equal(filtersActive({ q: 'x' }), true);
    assert.equal(filtersActive({ country: 'Chad' }), true);
    assert.equal(filtersActive({ severity: 'low' }), true);
  });
});

describe('countriesIn — the dropdown is derived, never typed', () => {
  const DETECTIONS = [
    { findings: [SPRAY, BRUTE], unverifiable: [] },
    { findings: [TARGETED], unverifiable: [CHANGE] },
    { findings: [NO_COUNTRY], unverifiable: [] },
  ];

  it('collects every country from every shape, sorted and deduped', () => {
    assert.deepEqual(
      countriesIn(DETECTIONS),
      ['Bulgaria', 'Canada', 'Germany', 'Poland', 'Switzerland', 'Thailand']
    );
  });

  it('⛔ reads `unverifiable` too, not just `findings`', () => {
    // Those items are shown on the page. A dropdown built from findings alone
    // offers no option for a country that appears only among the observations
    // we could not judge — so filtering for it silently returns nothing.
    assert.ok(countriesIn(DETECTIONS).includes('Switzerland'));
    const findingsOnly = [{ findings: [SPRAY], unverifiable: [CHANGE] }];
    assert.ok(countriesIn(findingsOnly).includes('Thailand'));
  });

  it('never throws on a malformed detection list', () => {
    for (const bad of [null, undefined, 'nope', [null], [{}], [{ findings: 'x' }]]) {
      assert.doesNotThrow(() => countriesIn(bad));
      assert.ok(Array.isArray(countriesIn(bad)));
    }
  });
});
