'use strict';
// Pins hardware end-of-life matching and the central-feed consumer.
//
// ⛔ WHAT THIS PROTECTS. The feature answers "when does the vendor stop
// supporting this chassis". Measured against the live catalogue on 2026-09-17 it
// can answer that for only 2 of the 16 firewalls on the reference fleet — every
// miss being current-generation hardware. So the single most important property
// is that the OTHER FOURTEEN are reported as UNKNOWN and never as "no
// end-of-support", because an absence rendered as an affirmative fact is this
// codebase's signature bug, and here it would be pointed at the exact question
// the customer bought the feature to answer.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { normalizeForMatch, vendorLabelFor, NORMALIZER_VERSION } = require('../lib/eolNormalize');
const { verifyFeed, toCatalogueRows } = require('../lib/feeds/eolFeed');
const {
  EOL_STATE, buildIndex, resolveDevice, resolveFleet,
} = require('../lib/engines/hardwareEol');

const NOW = new Date('2026-09-17T00:00:00Z');

// Shaped exactly like the live feed's rows.
const CATALOGUE = [
  { vendor: 'Palo Alto', modelRaw: 'PA-3220', aliases: [], supportEndDate: '2028-08-31', confidence: 'high' },
  { vendor: 'Fortinet', modelRaw: 'FortiGate 200E', aliases: ['FG-200E'], supportEndDate: '2030-10-13', confidence: 'high' },
  { vendor: 'Fortinet', modelRaw: 'FortiGate 60E', aliases: [], supportEndDate: '2024-01-31', confidence: 'high' },
];

const dev = (vendor, model) => ({ id: 'x', name: 'fw', vendor, model });

describe('the matching contract', () => {
  it('⛔ collapses the hyphen/space difference between us and the feed', () => {
    // SecVault stores `FortiGate-60F`; the catalogue stores `FortiGate 100E`.
    // The punctuation strip is what makes those comparable at all, and it is the
    // single thing most likely to be "tidied" by someone who has not read this.
    assert.equal(normalizeForMatch('Fortinet', 'FortiGate-200E'), 'fortigate200e');
    assert.equal(normalizeForMatch('Fortinet', 'FortiGate 200E'), 'fortigate200e');
    assert.equal(normalizeForMatch('Fortinet', 'fortigate200e'), 'fortigate200e');
  });

  it('⛔ the VENDOR LABEL is passed, never the slug', () => {
    // The vendor-prefix strip compares against the START of the model, so a seed
    // row spelled "Palo Alto PA-3220" keeps its prefix if we pass `paloalto` —
    // producing a key that matches nothing, silently.
    assert.equal(vendorLabelFor('paloalto'), 'Palo Alto');
    assert.equal(
      normalizeForMatch(vendorLabelFor('paloalto'), 'Palo Alto PA-3220'),
      normalizeForMatch(vendorLabelFor('paloalto'), 'PA-3220')
    );
  });

  it('an unknown slug yields no label rather than a guess', () => {
    assert.equal(vendorLabelFor('nonesuch'), null);
  });

  it('pins the normalizer version shared with the hub', () => {
    // ⛔ Three copies of this logic exist (here, nocvault-eol, NetVault). A
    // one-sided behavioural change does not throw — it silently stops matching
    // some models. If this number changes here it must change in all three.
    assert.equal(NORMALIZER_VERSION, 4);
  });
});

describe('⛔ absence is UNKNOWN, never "no end-of-support"', () => {
  const index = buildIndex(CATALOGUE);

  it('a model not in the catalogue is unknown', () => {
    const r = resolveDevice(dev('paloalto', 'PA-460'), index, NOW);
    assert.equal(r.state, EOL_STATE.UNKNOWN);
    assert.equal(r.supportEndDate, null);
  });

  it('⛔ and the wording never reassures', () => {
    // The reason an operator reads must say what we do NOT know. "No EOL date"
    // would be a claim; "we cannot tell which" is the fact.
    const r = resolveDevice(dev('fortinet', 'FortiGate-60F'), index, NOW);
    assert.match(r.reason, /cannot tell which/);
    assert.match(r.reason, /reported as unknown/);
    assert.ok(!/you are fine|no end-of-support date for/i.test(r.reason.replace(/published no end-of-support date for it yet/, '')));
  });

  it('⛔ a device with NO MODEL is its own state', () => {
    // "We never collected a model" is a SecVault coverage gap the operator can
    // fix; "not in the catalogue" is one they cannot. Collapsing them hides a
    // broken collector behind a data-coverage excuse.
    for (const m of [null, undefined, '', '   ']) {
      const r = resolveDevice(dev('fortinet', m), index, NOW);
      assert.equal(r.state, EOL_STATE.NO_MODEL);
      assert.notEqual(r.state, EOL_STATE.UNKNOWN);
    }
  });

  it('⛔ a catalogue row whose date will not parse is UNKNOWN, not fine', () => {
    const idx = buildIndex([{ vendor: 'Fortinet', modelRaw: 'FortiGate 99X', aliases: [], supportEndDate: 'soon' }]);
    const r = resolveDevice(dev('fortinet', 'FortiGate-99X'), idx, NOW);
    assert.equal(r.state, EOL_STATE.UNKNOWN);
  });

  it('no_date_published is a DISTINCT state from unknown', () => {
    // Built before the hub emits it, so adding it later needs no UI change.
    const idx = buildIndex([{
      vendor: 'Palo Alto', modelRaw: 'PA-460', aliases: [],
      supportEndDate: null, noDatePublished: true, checkedAt: '2026-09-01',
    }]);
    const r = resolveDevice(dev('paloalto', 'PA-460'), idx, NOW);
    assert.equal(r.state, EOL_STATE.NO_DATE_PUBLISHED);
    assert.notEqual(r.state, EOL_STATE.UNKNOWN);
    assert.match(r.reason, /2026-09-01/);
  });
});

describe('dated devices', () => {
  const index = buildIndex(CATALOGUE);

  it('resolves a real date and the days remaining', () => {
    const r = resolveDevice(dev('paloalto', 'PA-3220'), index, NOW);
    assert.equal(r.state, EOL_STATE.DATED);
    assert.equal(r.supportEndDate, '2028-08-31');
    assert.equal(r.pastEnd, false);
    assert.ok(r.daysRemaining > 700);
  });

  it('flags a chassis already past end-of-support', () => {
    const r = resolveDevice(dev('fortinet', 'FortiGate-60E'), index, NOW);
    assert.equal(r.pastEnd, true);
    assert.ok(r.daysRemaining < 0);
    assert.match(r.reason, /passed end-of-support/);
  });

  it('flags one approaching within a year, but not one further out', () => {
    const idx = buildIndex([
      { vendor: 'Fortinet', modelRaw: 'FortiGate 1A', aliases: [], supportEndDate: '2027-01-01' },
      { vendor: 'Fortinet', modelRaw: 'FortiGate 2A', aliases: [], supportEndDate: '2030-01-01' },
    ]);
    assert.equal(resolveDevice(dev('fortinet', 'FortiGate-1A'), idx, NOW).approaching, true);
    assert.equal(resolveDevice(dev('fortinet', 'FortiGate-2A'), idx, NOW).approaching, false);
  });

  it('⛔ matches on an ALIAS, not only the canonical spelling', () => {
    // The aliases exist because one chassis is spelled several ways across
    // vendor tables and SKUs. Indexing only matches[0] silently drops exactly
    // the spellings they were added to catch.
    const r = resolveDevice(dev('fortinet', 'FG-200E'), index, NOW);
    assert.equal(r.state, EOL_STATE.DATED);
    assert.equal(r.supportEndDate, '2030-10-13');
  });
});

describe('⛔ fleet coverage forbids an all-clear', () => {
  it('reports incomplete whenever anything could not be answered', () => {
    // "0 firewalls past end-of-support" over a catalogue that matched 2 of 16 is
    // true and useless. lib/evidence.js already forbids an all-clear while
    // coverage is incomplete; this is what it keys on.
    const fleet = resolveFleet([
      dev('paloalto', 'PA-3220'), dev('paloalto', 'PA-460'), dev('fortinet', 'FortiGate-60F'),
    ], CATALOGUE, NOW);
    assert.equal(fleet.pastEnd, 0);
    assert.equal(fleet.incomplete, true, 'a fleet with unknowns claimed to be complete');
    assert.equal(fleet.counts.unknown, 2);
    assert.equal(fleet.coveragePct, 33);
  });

  it('is complete only when every device was answered', () => {
    const fleet = resolveFleet([dev('paloalto', 'PA-3220')], CATALOGUE, NOW);
    assert.equal(fleet.incomplete, false);
    assert.equal(fleet.coveragePct, 100);
  });

  it('⛔ an EMPTY fleet has null coverage, not 0%', () => {
    // A percentage over nothing is not zero.
    assert.equal(resolveFleet([], CATALOGUE, NOW).coveragePct, null);
  });
});

describe('⛔ the feed is verified before a single row is written', () => {
  const body = Buffer.from('{"models":[]}');
  const sha = require('crypto').createHash('sha256').update(body).digest('hex');

  it('refuses a body with no signature header', () => {
    const v = verifyFeed(body, { 'x-feed-sha256': sha });
    assert.equal(v.ok, false);
    assert.match(v.reason, /no signature/);
  });

  it('refuses a body that does not match its own checksum', () => {
    const v = verifyFeed(body, { 'x-feed-sha256': 'ff'.repeat(32), 'x-feed-signature': 'AA==' });
    assert.equal(v.ok, false);
    assert.match(v.reason, /checksum/);
    assert.match(v.reason, /truncated or altered/);
  });

  it('refuses a signature that does not verify', () => {
    const v = verifyFeed(body, { 'x-feed-sha256': sha, 'x-feed-signature': Buffer.alloc(64).toString('base64') });
    assert.equal(v.ok, false);
    assert.match(v.reason, /did not verify/);
  });

  it('never throws on a malformed signature', () => {
    assert.doesNotThrow(() => verifyFeed(body, { 'x-feed-signature': 'not-base64-!!!' }));
  });
});

describe('what the consumer keeps from the feed', () => {
  const models = [
    { vendor: 'Fortinet', matches: ['FortiGate 200E'], support_end_date: '2030-10-13', confidence: 'high' },
    { vendor: 'Palo Alto', matches: ['PA-3220'], support_end_date: '2028-08-31' },
    { vendor: 'Netgear', matches: ['GS724T'], support_end_date: '2025-01-01' },
    { vendor: 'Fortinet', matches: ['FortiGate 999'], support_end_date: null, os_eol_date: null },
    { vendor: 'Fortinet', matches: [], support_end_date: '2030-01-01' },
  ];

  it('keeps only this product\'s vendors', () => {
    const rows = toCatalogueRows(models);
    assert.ok(rows.some((r) => r.vendor === 'Fortinet'));
    assert.ok(rows.some((r) => r.vendor === 'Palo Alto'));
    assert.ok(!rows.some((r) => r.vendor === 'Netgear'), 'kept a vendor this product does not manage');
  });

  it('⛔ SKIPS a dateless row rather than storing nulls', () => {
    // Stored, it would resolve to "unknown" anyway — but it would ALSO make the
    // catalogue look like it covers that model, collapsing "we have no data"
    // into "we looked and there is nothing". Those are the two states this whole
    // feature turns on.
    const rows = toCatalogueRows(models);
    assert.ok(!rows.some((r) => r.modelRaw === 'FortiGate 999'));
  });

  it('keeps a no_date_published row even though it has no date', () => {
    const rows = toCatalogueRows([
      { vendor: 'Fortinet', matches: ['FortiGate 60F'], support_end_date: null, no_date_published: true },
    ]);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].noDatePublished, true);
  });

  it('survives junk rows without throwing', () => {
    assert.doesNotThrow(() => toCatalogueRows([null, {}, { vendor: 'Fortinet' }, { matches: ['x'] }]));
    assert.equal(toCatalogueRows(null).length, 0);
  });
});
