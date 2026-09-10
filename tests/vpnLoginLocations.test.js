// tests/vpnLoginLocations.test.js
//
// The country fold behind /vpn → Login Locations → "Unusual sources".
//
// ⛔ WHY THIS IS WORTH A TEST. The flat list reached 247 flagged addresses on
// the live fleet and was replaced by an 11-row country accordion. Every failure
// mode of a fold like that is silent: a country counted twice because two
// vendors spell it differently, a group whose remainder is dropped with no "of
// N", an unlocated source quietly absorbed into a real country, or a bar drawn
// at the bottom of a severity ramp when there was no denominator to compare
// against. None of those throw. Each renders a confident, plausible, wrong
// picture — this codebase's most-repeated bug class, in paint.
//
// ⛔ It also pins that the fold is PRESENTATION ONLY. findUsernameSprayers() is
// the only thing that decides what is flagged, and the per-vendor gate in
// findFailureOnlyCountries() is the only thing that decides what is asserted.
// A regression that changed either from inside the grouping would change the
// product's claims, not its layout.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  groupSourcesByCountry,
  heatBand,
  findUsernameSprayers,
  normalizeCountry,
  SOURCES_PER_COUNTRY,
  MIN_USERNAMES_FOR_SPRAY,
} = require('../lib/syslog/vpnAuthStats');

// A flagged source, shaped exactly as getVpnLoginLocations() emits one.
function src(srcIp, country, failure, usernames, extra = {}) {
  return {
    srcIp,
    country,
    vendor: 'paloalto',
    success: 0,
    failure,
    usernames,
    usernamesTruncated: false,
    lastSeenAt: new Date('2026-09-10T00:00:00Z'),
    total: failure,
    ...extra,
  };
}

describe('groupSourcesByCountry — the fold itself', () => {
  it('folds many addresses into one row per country, ordered by failures', () => {
    const g = groupSourcesByCountry([
      src('1.1.1.1', 'United Kingdom', 21, 21),
      src('2.2.2.2', 'Bulgaria', 1680, 834),
      src('3.3.3.3', 'United Kingdom', 12, 9),
      src('4.4.4.4', 'United States', 137, 15),
    ]);

    assert.deepEqual(
      g.countries.map((c) => c.country),
      ['Bulgaria', 'United States', 'United Kingdom']
    );
    assert.equal(g.totalCountries, 3);
    assert.equal(g.totalSources, 4);
    assert.equal(g.totalFailures, 1680 + 137 + 21 + 12);
    assert.equal(g.maxFailures, 1680);
    assert.equal(g.countries[2].sourceCount, 2);
    assert.equal(g.countries[2].failure, 33);
  });

  it('groups on the NORMALISED country, so the United States is one row', () => {
    // ⛔ The live regression this guards: Palo Alto emits ISO-3166-1 alpha-2
    // ("US"), FortiOS emits the full English name ("United States"). Grouping
    // on the raw vendor field split one country into two rows and under-stated
    // both halves. getVpnLoginLocations() normalises before this function sees
    // the rows; passing the raw values through normalizeCountry() here proves
    // the two spellings land on ONE key.
    const g = groupSourcesByCountry([
      src('5.5.5.5', normalizeCountry('US'), 100, 40),
      src('6.6.6.6', normalizeCountry('United States'), 50, 20),
    ]);
    assert.equal(g.countries.length, 1);
    assert.equal(g.countries[0].country, 'United States');
    assert.equal(g.countries[0].sourceCount, 2);
    assert.equal(g.countries[0].failure, 150);
  });

  it('conserves every flagged source — the fold decides nothing', () => {
    // ⛔ Layout must not become a second filter. If the number of addresses
    // reachable through the accordion ever differs from the number flagged,
    // the page is hiding evidence while claiming to summarise it.
    const flagged = [
      src('1.1.1.1', 'Sweden', 21, 13),
      src('2.2.2.2', 'Canada', 26, 24),
      src('3.3.3.3', null, 9, 8),
    ];
    const g = groupSourcesByCountry(flagged, { perCountry: 100 });
    const seen = g.countries.flatMap((c) => c.sources.map((s) => s.srcIp));
    assert.equal(seen.length, flagged.length);
    assert.deepEqual(new Set(seen), new Set(flagged.map((s) => s.srcIp)));
    assert.equal(
      g.countries.reduce((n, c) => n + c.hiddenSources, 0),
      0
    );
  });
});

describe('groupSourcesByCountry — the worst offender stays visible', () => {
  it('previews each country worst-first, even when the group is truncated', () => {
    // ⛔ THE POINT OF THE REDESIGN. One Bulgarian address ran 1,680 failures
    // against 834 usernames while the United States contributed 172 separate
    // addresses. Burying the single most dangerous address two clicks deep to
    // stop the scrolling would be a worse product than the scrolling.
    const many = [];
    for (let i = 0; i < 40; i += 1) many.push(src(`10.0.0.${i}`, 'United States', 5 + i, 6));
    many.push(src('93.152.210.31', 'United States', 1680, 834));

    const g = groupSourcesByCountry(many, { perCountry: 3 });
    const us = g.countries[0];
    assert.equal(us.worst.srcIp, '93.152.210.31');
    assert.equal(us.worst.failure, 1680);
    assert.equal(us.worst.usernames, 834);
    // The listed sources are worst-first too, so expanding never re-sorts.
    assert.equal(us.sources[0].srcIp, '93.152.210.31');
    assert.equal(us.sources.length, 3);
  });

  it('states the remainder instead of truncating silently', () => {
    // ⛔ A cut list that does not say it was cut is indistinguishable from a
    // complete one, and the reader has no way to know an address was dropped.
    const many = [];
    for (let i = 0; i < 30; i += 1) many.push(src(`10.0.0.${i}`, 'Germany', 10 + i, 6));
    const g = groupSourcesByCountry(many, { perCountry: 10 });
    assert.equal(g.countries[0].sourceCount, 30);
    assert.equal(g.countries[0].sources.length, 10);
    assert.equal(g.countries[0].hiddenSources, 20);
    // sourceCount is the TRUTH, sources.length is what fits on screen.
    assert.equal(
      g.countries[0].sources.length + g.countries[0].hiddenSources,
      g.countries[0].sourceCount
    );
  });

  it('defaults to a real per-country cap and clamps a junk one to >= 1', () => {
    assert.ok(SOURCES_PER_COUNTRY >= 1);
    const rows = [src('1.1.1.1', 'Canada', 9, 9), src('2.2.2.2', 'Canada', 8, 8)];
    for (const bad of [0, -5, 'nonsense', null, undefined, NaN]) {
      const g = groupSourcesByCountry(rows, { perCountry: bad });
      assert.ok(g.countries[0].sources.length >= 1, `perCountry=${String(bad)} listed nothing`);
      assert.equal(
        g.countries[0].sources.length + g.countries[0].hiddenSources,
        2,
        `perCountry=${String(bad)} lost a source`
      );
    }
  });
});

describe('groupSourcesByCountry — "we could not measure this"', () => {
  it('gives an unlocated source its OWN group, never a real country', () => {
    // ⛔ The failed-read-as-a-fact rule applied to geography. The firewall
    // attached no country and SecVault holds no GeoIP database of its own, so
    // there is no country to put this in. Folding it into the nearest real one
    // — or inventing an "Unknown" country that sits in the ranking looking like
    // a place — would report our blindness as a location.
    const g = groupSourcesByCountry([
      src('1.1.1.1', 'Bulgaria', 100, 50),
      src('2.2.2.2', null, 40, 30),
      src('3.3.3.3', '   ', 10, 9),
      src('4.4.4.4', undefined, 5, 7),
    ]);

    const unlocated = g.countries.filter((c) => !c.located);
    assert.equal(unlocated.length, 1, 'every unlocated source belongs to ONE group');
    assert.equal(unlocated[0].country, null, 'no invented country name');
    assert.equal(unlocated[0].sourceCount, 3);
    assert.equal(unlocated[0].failure, 55);

    const bg = g.countries.find((c) => c.country === 'Bulgaria');
    assert.equal(bg.sourceCount, 1, 'Bulgaria absorbed an unlocated address');
    assert.equal(bg.located, true);
  });

  it('ranks the unlocated group by its failures, never pinned to the bottom', () => {
    // Its failures ARE measured; only its location is not. Sinking it would let
    // a large unattributed burst hide below several small countries.
    const g = groupSourcesByCountry([
      src('1.1.1.1', 'Estonia', 19, 17),
      src('2.2.2.2', null, 900, 400),
      src('3.3.3.3', 'Czechia', 59, 21),
    ]);
    assert.equal(g.countries[0].located, false);
    assert.equal(g.countries[0].failure, 900);
  });

  it('returns an empty, zeroed shape for no input rather than throwing', () => {
    for (const empty of [[], null, undefined, 'not an array']) {
      const g = groupSourcesByCountry(empty);
      assert.deepEqual(g.countries, []);
      assert.equal(g.totalCountries, 0);
      assert.equal(g.totalSources, 0);
      assert.equal(g.totalFailures, 0);
      assert.equal(g.maxFailures, 0);
    }
  });
});

describe('heatBand — the bar colour', () => {
  it('bands a country by its share of the worst country in the window', () => {
    assert.equal(heatBand(1000, 1000), 'critical');
    assert.equal(heatBand(500, 1000), 'critical'); // boundary: >= 50%
    assert.equal(heatBand(499, 1000), 'high');
    assert.equal(heatBand(200, 1000), 'high'); // boundary: >= 20%
    assert.equal(heatBand(199, 1000), 'medium');
    assert.equal(heatBand(50, 1000), 'medium'); // boundary: >= 5%
    assert.equal(heatBand(49, 1000), 'low');
    assert.equal(heatBand(1, 1000), 'low');
  });

  it('returns NULL, not "low", when there is no denominator', () => {
    // ⛔ 'low' is a measurement: "small compared to the worst". With no maximum
    // there is nothing to compare against, and drawing the bottom of a ramp
    // would render "no basis for comparison" as "lowest risk" — a reassuring
    // colour manufactured out of missing data. The caller draws null hueless.
    assert.equal(heatBand(10, 0), null);
    assert.equal(heatBand(0, 100), null);
    assert.equal(heatBand(10, null), null);
    assert.equal(heatBand(null, 100), null);
    assert.equal(heatBand(NaN, 100), null);
    assert.equal(heatBand(10, 'nonsense'), null);
  });

  it('never returns a band outside the shared severity ramp', () => {
    // ⛔ The hue is looked up in components/analysis/severityRamp.js. A band
    // name that file does not know renders as no colour at all, so the set of
    // values this can produce is part of the contract.
    const allowed = new Set(['critical', 'high', 'medium', 'low', null]);
    for (let f = 0; f <= 1000; f += 7) {
      assert.ok(allowed.has(heatBand(f, 1000)), `unexpected band for ${f}`);
    }
  });

  it('bands every country a real grouping produces', () => {
    const g = groupSourcesByCountry([
      src('1.1.1.1', 'Bulgaria', 1680, 834),
      src('2.2.2.2', 'United States', 3051, 15),
      src('3.3.3.3', 'Estonia', 19, 17),
    ]);
    assert.equal(g.countries[0].band, 'critical'); // United States, the max
    assert.equal(g.countries[1].band, 'critical'); // Bulgaria, 55% of it
    assert.equal(g.countries[2].band, 'low'); // Estonia, 0.6%
  });
});

describe('the fold does not touch what is flagged', () => {
  it('leaves findUsernameSprayers as the only gate', () => {
    // ⛔ The spray rule: many DISTINCT usernames from one address, none
    // successful. A user mistyping a password fails against ONE username.
    // Grouping must never widen or narrow this — a country row is a view of
    // the flagged set, not a second opinion on it.
    const all = [
      src('1.1.1.1', 'Bulgaria', 1680, MIN_USERNAMES_FOR_SPRAY + 1), // flagged
      src('2.2.2.2', 'Thailand', 900, 1), // one username: a real user, not a spray
      src('3.3.3.3', 'Thailand', 40, 50, { success: 3 }), // a success: not a spray
    ];
    const flagged = findUsernameSprayers(all);
    assert.deepEqual(flagged.map((s) => s.srcIp), ['1.1.1.1']);

    const g = groupSourcesByCountry(flagged);
    assert.equal(g.totalSources, 1);
    assert.deepEqual(g.countries.map((c) => c.country), ['Bulgaria']);
    // Thailand — where the real users are — must not appear because the fold
    // was handed only the flagged set.
    assert.equal(g.countries.some((c) => c.country === 'Thailand'), false);
  });
});
