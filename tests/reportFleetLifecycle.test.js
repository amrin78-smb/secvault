'use strict';
// Pins lib/reports/fleetLifecycle.js — the R7 "Fleet Lifecycle & Support" PDF.
//
// ⛔ WHAT THESE TESTS ARE ACTUALLY FOR.
//
// This document's job is to stop a support contract lapsing, and the way a
// contract lapses is not that somebody misread a date. It is that the date was
// never readable, the row looked like every other row with no date in it, and
// the renewal was never raised.
//
// `device_licenses` is TRI-STATE on expiry:
//
//     a parsed date                       -> a deadline
//     NULL + expires_raw 'Never'          -> PERPETUAL. Nothing to renew, ever.
//     NULL + anything else                -> UNKNOWN. Somebody has to go and look.
//
// Collapsing the last two is silent. Nothing throws, the page is short and
// confident, and the reader budgets for what they can see. So the central
// assertion in this file is an INEQUALITY — perpetual and unknown must not
// produce the same string — because a test that only checks "unknown renders
// something" passes happily while both render a blank.
//
// The same shape recurs three more times and each has its own test: a
// `version_compat_ok` of NULL is not a match; a firewall SecVault cannot ask
// for a licence is not a firewall with no licences; and PostgreSQL's ASC-is-
// NULLS-FIRST default must not head a "soonest first" renewal list with every
// undated row.
//
// No database. The stub pool returns canned rows and records every statement it
// was handed, so the ORDER BY can be asserted as text rather than hoped for.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { contentStreams } = require('../lib/reports/pdfCompare');
const {
  NOT_MEASURED_MARK,
  PERPETUAL_TEXT,
  NOT_LICENSED_TEXT,
  expiryCell,
  compatCell,
  factCoverage,
  coverageReason,
  compareRenewals,
  headlineSentence,
  daysText,
  buildFleetLifecycleData,
  renderFleetLifecyclePdf,
  generateFleetLifecyclePdf,
} = require('../lib/reports/fleetLifecycle');

// ── reading the PDF back ──────────────────────────────────────────────────

/**
 * pdfkit writes every glyph run as a HEX STRING inside a TJ array, so the words
 * are not visible as ASCII anywhere in the file. Decode each `<hex>` token in
 * document order and concatenate.
 *
 * ⛔ Concatenated with NO separator on purpose: kerning splits a single word
 * across several tokens, and inserting a space here would break every phrase
 * assertion below into unmatchable fragments.
 */
function pdfText(buf) {
  let out = '';
  for (const stream of contentStreams(buf)) {
    const re = /<([0-9a-fA-F]+)>/g;
    let m;
    while ((m = re.exec(stream)) !== null) {
      const hex = m[1];
      if (hex.length % 2 !== 0) continue;
      for (let i = 0; i < hex.length; i += 2) {
        out += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
      }
    }
  }
  return out;
}

/** Whitespace-insensitive contains, because pdfkit breaks lines where it likes. */
function says(text, phrase) {
  const norm = (s) => s.replace(/\s+/g, ' ');
  return norm(text).includes(norm(phrase));
}

// ── the fixture ───────────────────────────────────────────────────────────
//
// Shaped after the live reference fleet, which genuinely carries every state
// this file cares about: Palo Alto over the API reports all four facts, Fortinet
// over SSH reports licences/HA/content but NOT disk, and one firewall is a
// vendor SecVault cannot ask for any of them.

const DEV_PA = '11111111-1111-1111-1111-111111111111';
const DEV_FG = '22222222-2222-2222-2222-222222222222';
const DEV_ASA = '33333333-3333-3333-3333-333333333333';

// DATE columns arrive from node-pg as LOCAL-midnight Dates, so the fixture
// builds them the same way rather than from a UTC ISO string.
const d = (y, m, day) => new Date(y, m - 1, day);

const NOW = new Date(2026, 8, 15, 12, 0, 0); // 2026-09-15, local

function fixture(overrides = {}) {
  return Object.assign({
    devices: [
      {
        id: DEV_PA, name: 'IDC FW', vendor: 'paloalto', mgmt_method: 'api', mgmt_ip: '10.0.0.1',
        site: 'IDC', active: true, asset_criticality: 'critical',
        last_collected_at: new Date('2026-09-15T01:00:00Z'), last_connectivity_ok: true,
      },
      {
        id: DEV_FG, name: 'TSR_EKM', vendor: 'fortinet', mgmt_method: 'ssh', mgmt_ip: '10.0.0.2',
        site: 'TSR', active: true, asset_criticality: 'high',
        last_collected_at: new Date('2026-09-15T01:00:00Z'), last_connectivity_ok: true,
      },
      // ⛔ A vendor with NO lifecycle adapter methods at all. It must appear in
      // this report as NOT MEASURED — never as a firewall with no licences, and
      // never omitted.
      {
        id: DEV_ASA, name: 'DC-ASA', vendor: 'cisco_asa', mgmt_method: 'ssh', mgmt_ip: '10.0.0.3',
        site: 'DC', active: true, asset_criticality: 'medium',
        last_collected_at: new Date('2026-09-15T01:00:00Z'), last_connectivity_ok: true,
      },
    ],
    licenses: [
      // A real date, inside the 60-day window.
      { id: 'l1', device_id: DEV_PA, feature: 'Threat Prevention', description: 'Threat', serial: 'S1', expires_at: d(2026, 10, 16), expires_raw: 'October 16, 2026', expired: false, collected_at: NOW },
      { id: 'l2', device_id: DEV_PA, feature: 'Premium', description: '24 x 7 phone support', serial: 'S1', expires_at: d(2026, 10, 16), expires_raw: 'October 16, 2026', expired: false, collected_at: NOW },
      // A real date, comfortably outside it.
      { id: 'l3', device_id: DEV_PA, feature: 'GlobalProtect', description: 'GP', serial: 'S1', expires_at: d(2029, 7, 24), expires_raw: 'Tue Jul 24 2029', expired: false, collected_at: NOW },
      // ⛔ PERPETUAL. A POSITIVE answer from the device: it never expires.
      { id: 'l4', device_id: DEV_PA, feature: 'Virtual Systems', description: 'vsys', serial: 'S1', expires_at: null, expires_raw: 'Never', expired: false, collected_at: NOW },
      // ⛔ UNKNOWN. The row this whole file exists to protect. Same NULL
      // expires_at as the row above it and a completely different meaning.
      { id: 'l5', device_id: DEV_FG, feature: 'FortiCare Support', description: 'Fortinet SPRT contract', serial: 'F1', expires_at: null, expires_raw: 'sometime in Q3', expired: null, collected_at: NOW },
      // ⛔ NOT LICENSED. FortiOS's 'n/a' — a definite fact, nothing to renew.
      { id: 'l6', device_id: DEV_FG, feature: 'OT Threat', description: 'OT', serial: 'F1', expires_at: null, expires_raw: 'n/a', expired: null, collected_at: NOW },
      // Already lapsed.
      { id: 'l7', device_id: DEV_FG, feature: 'Hardware RMA', description: 'Fortinet HDWR contract', serial: 'F1', expires_at: d(2025, 7, 17), expires_raw: 'July 17, 2025', expired: true, collected_at: NOW },
    ],
    ha: [
      // ⛔ In HA, everything reported up and synchronized, and version_compat_ok
      // NULL — the device reported no compatibility block. That is NOT a match.
      // ⛔ last_nonfunctional_reason is NULL because the collector deliberately
      // withholds a 'User requested' suspension: it is an admin action on an
      // otherwise healthy pair, not a fault.
      { device_id: DEV_PA, enabled: true, mode: 'Active-Passive', local_state: 'active', peer_state: 'passive', peer_mgmt_ip: '10.0.0.9', peer_connection_status: 'up', config_sync_state: 'synchronized', last_nonfunctional_reason: null, version_compat_ok: null, version_compat: null, collected_at: NOW },
      { device_id: DEV_FG, enabled: false, mode: null, local_state: null, peer_state: null, peer_mgmt_ip: null, peer_connection_status: null, config_sync_state: null, last_nonfunctional_reason: null, version_compat_ok: null, version_compat: null, collected_at: NOW },
    ],
    disks: [
      { device_id: DEV_PA, filesystem: '/dev/sda5', mounted_on: '/opt/panlogs', size_raw: '124G', used_raw: '117G', avail_raw: '1.2G', use_percent: 95, collected_at: NOW },
      { device_id: DEV_PA, filesystem: '/dev/sda2', mounted_on: '/', size_raw: '9.5G', used_raw: '4.1G', avail_raw: '4.9G', use_percent: 46, collected_at: NOW },
    ],
    content: [
      { device_id: DEV_PA, component: 'app', version: '9133-10186', released_at: new Date('2026-08-06T20:40:54Z'), collected_at: NOW },
      { device_id: DEV_PA, component: 'av', version: '5674-6201', released_at: new Date('2026-09-13T11:03:40Z'), collected_at: NOW },
      // ⛔ No release date. Its age is UNKNOWABLE, and unknowable is not young.
      { device_id: DEV_PA, component: 'url_filtering', version: '20260915.20028', released_at: null, collected_at: NOW },
      { device_id: DEV_FG, component: 'av', version: '93.07919', released_at: new Date('2026-09-15T06:20:34Z'), collected_at: NOW },
    ],
    versions: [
      { device_id: DEV_PA, version_string: '11.1.2-h3', build: null, model: 'PA-3220', collected_at: NOW },
      { device_id: DEV_FG, version_string: 'v7.4.3,build2573', build: '2573', model: 'FG-100F', collected_at: NOW },
    ],
    // Set to a message to make the named read throw.
    licenseThrows: null,
    haThrows: null,
  }, overrides);
}

/**
 * The stub pool. Matches on the statement text and records everything it saw,
 * so the ORDER BY that keeps undated rows out of the head of a "soonest first"
 * list is asserted rather than trusted.
 */
function makePool(f) {
  const seen = [];
  return {
    seen,
    async query(text, params) {
      seen.push({ text, params });
      if (/FROM devices/.test(text)) {
        if (params && params[0]) return { rows: f.devices.filter((x) => x.id === params[0]) };
        return { rows: f.devices };
      }
      if (/FROM device_licenses/.test(text)) {
        if (f.licenseThrows) throw new Error(f.licenseThrows);
        return { rows: f.licenses };
      }
      if (/FROM device_ha_status/.test(text)) {
        if (f.haThrows) throw new Error(f.haThrows);
        return { rows: f.ha };
      }
      if (/FROM device_disk_usage/.test(text)) return { rows: f.disks };
      if (/FROM device_content_versions/.test(text)) return { rows: f.content };
      if (/FROM device_versions/.test(text)) return { rows: f.versions };
      throw new Error(`stub pool: unexpected statement\n${text}`);
    },
  };
}

const byName = (data, name) => data.devices.find((x) => x.name === name);

// ── the expiry tri-state: the central hazard ──────────────────────────────

describe('perpetual and unknown expiry are not the same thing', () => {
  it('⛔ a perpetual licence and an unreadable one produce DIFFERENT output', () => {
    // Identical on the column that a naive renderer would read: expires_at NULL
    // on both. The ONLY difference is expires_raw, and it is the whole story.
    const perpetual = expiryCell({ expires_at: null, expires_raw: 'Never' }, 'perpetual');
    const unknown = expiryCell({ expires_at: null, expires_raw: 'sometime in Q3' }, 'unknown');

    assert.notEqual(
      perpetual.text, unknown.text,
      'a licence that never expires and one whose expiry could not be read must never render alike'
    );
    assert.equal(perpetual.kind, 'perpetual');
    assert.equal(unknown.kind, 'unknown');
    assert.equal(perpetual.text, PERPETUAL_TEXT);
    // The unknown cell must READ as unknown, not as an empty or reassuring cell.
    assert.match(unknown.text, /Unknown/);
    assert.ok(unknown.text.includes(NOT_MEASURED_MARK));
    // ⛔ And it must quote the firewall's own words, or the only way to act on
    // the row is to log into the device.
    assert.ok(unknown.text.includes('sometime in Q3'));
  });

  it('⛔ "not licensed" is a fourth state, distinct from both of the above', () => {
    const notLicensed = expiryCell({ expires_at: null, expires_raw: 'n/a' }, 'not_licensed');
    const unknown = expiryCell({ expires_at: null, expires_raw: 'n/a' }, 'unknown');
    assert.equal(notLicensed.text, NOT_LICENSED_TEXT);
    assert.notEqual(notLicensed.text, unknown.text);
    assert.notEqual(notLicensed.text, PERPETUAL_TEXT);
  });

  it('a real date renders as a date and nothing else', () => {
    const cell = expiryCell({ expires_at: d(2026, 10, 16), expires_raw: 'October 16, 2026' }, 'expiring');
    assert.equal(cell.kind, 'date');
    assert.equal(cell.text, '2026-10-16');
  });

  it('⛔ an "expired" verdict with NO date behind it is UNKNOWN, not a date', () => {
    // licenseStatus() returns 'expired' from the device's own flag with
    // daysRemaining null. "The box says this lapsed and we do not know when" is
    // not a deadline and must not be drawn as one.
    const cell = expiryCell({ expires_at: null, expires_raw: 'contract ended' }, 'expired');
    assert.equal(cell.kind, 'unknown');
    assert.match(cell.text, /Unknown/);
  });

  it('⛔ the three states survive all the way onto the page, as three strings', async () => {
    const buf = await generateFleetLifecyclePdf(makePool(fixture()), { now: NOW });
    const text = pdfText(buf);
    assert.ok(says(text, 'Perpetual'), 'perpetual must be spelled out');
    assert.ok(says(text, 'Unknown'), 'unknown must be spelled out');
    assert.ok(
      says(text, 'It is NOT perpetual and it is NOT fine'),
      'the legend must refuse both misreadings in as many words'
    );
    assert.ok(
      says(text, 'Expiry date UNREADABLE'),
      'the cover must carry the unreadable-expiry count, beside the expiring count'
    );
  });

  it('counts the four expiry states separately and never folds unknown into expiring', async () => {
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW });
    const t = data.totals;
    assert.equal(t.licenses, 7);
    assert.equal(t.licensesExpired, 1);      // Hardware RMA, lapsed 2025
    assert.equal(t.licensesExpiring, 2);     // both 2026-10-16 entitlements
    assert.equal(t.licensesOk, 1);           // 2029
    assert.equal(t.licensesPerpetual, 1);
    assert.equal(t.licensesUnknownExpiry, 1);
    assert.equal(t.licensesNotLicensed, 1);
    assert.equal(
      t.licensesExpired + t.licensesExpiring + t.licensesOk + t.licensesPerpetual
        + t.licensesUnknownExpiry + t.licensesNotLicensed,
      t.licenses,
      'the states must partition the entitlements exactly - nothing may be double counted or lost'
    );
  });

  it("⛔ 'not licensed' is excluded from the renewal table but COUNTED, not silently dropped", async () => {
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW });
    const inTable = data.renewals.some((g) => g.rows.some((r) => r.feature === 'OT Threat'));
    assert.equal(inTable, false, 'there is nothing to renew for an entitlement the box does not hold');
    assert.equal(data.totals.licensesNotLicensed, 1, 'and the table being shorter must be explained by a number');

    const buf = await renderFleetLifecyclePdf(data);
    assert.ok(
      says(pdfText(buf), 'the table is shorter for a stated reason'),
      'the exclusion must be stated on the page, not left invisible'
    );
  });
});

// ── ordering ──────────────────────────────────────────────────────────────

describe('the renewal timeline is soonest-first with undated rows LAST', () => {
  it('⛔ an unknown expiry sorts LAST, never first', async () => {
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW });
    const kinds = data.renewals.map((g) => g.expiry.kind);
    const firstUndated = kinds.findIndex((k) => k !== 'date');
    assert.ok(firstUndated > 0, 'at least one dated row must come before any undated one');
    // Every row from the first undated one onward must also be undated: no
    // dated row may be buried below an undated one.
    assert.ok(
      kinds.slice(firstUndated).every((k) => k !== 'date'),
      'dated and undated rows must not interleave'
    );
    assert.notEqual(kinds[0], 'unknown', 'an unreadable expiry is not the most urgent row on the list');
    assert.equal(kinds[kinds.length - 1] === 'date', false);
  });

  it('dated rows are ascending, so an already-expired contract leads', async () => {
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW });
    const dated = data.renewals.filter((g) => g.expiry.kind === 'date');
    assert.equal(dated[0].status, 'expired');
    const times = dated.map((g) => new Date(g.expiresAt).getTime());
    assert.deepEqual(times, [...times].sort((a, b) => a - b));
  });

  it('⛔ the SQL itself says NULLS LAST - PostgreSQL ASC defaults to NULLS FIRST', async () => {
    const pool = makePool(fixture());
    await buildFleetLifecycleData(pool, { now: NOW });
    const q = pool.seen.find((s) => /FROM device_licenses/.test(s.text));
    assert.ok(q, 'the licence read must have happened');
    assert.match(
      q.text, /ORDER BY[\s\S]*expires_at ASC NULLS LAST/,
      'without NULLS LAST the database heads a "soonest first" list with every undated row'
    );
  });

  it('the comparator puts unknown ahead of perpetual among undated rows', () => {
    // Both are undated; only one needs a human. The one that needs a human goes
    // first, and BOTH go after every dated row.
    const unknown = { expiresAt: null, status: 'unknown', deviceName: 'B' };
    const perpetual = { expiresAt: null, status: 'perpetual', deviceName: 'A' };
    const dated = { expiresAt: d(2030, 1, 1), status: 'ok', deviceName: 'C' };
    assert.ok(compareRenewals(unknown, perpetual) < 0);
    assert.ok(compareRenewals(dated, unknown) < 0);
    assert.ok(compareRenewals(unknown, dated) > 0);
  });
});

// ── the "we could not measure this" case ──────────────────────────────────

describe('a firewall SecVault cannot ask is not a firewall with nothing to renew', () => {
  it('⛔ a device with no device_licenses rows is present, counted, and NOT reported as fine', async () => {
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW });
    const asa = byName(data, 'DC-ASA');
    assert.ok(asa, 'the firewall must not be omitted from the report');

    // Not "no licences". Not "ok". Not zero.
    assert.equal(asa.coverage.licenses, 'not_supported');
    assert.equal(asa.licenses.length, 0);
    assert.equal(
      asa.worstLicense.status, 'unknown',
      'an empty licence list must resolve to unknown, never to ok'
    );
    assert.notEqual(asa.worstLicense.status, 'ok');

    // ⛔ And it must be COUNTED, or the cover reads as complete coverage.
    assert.ok(data.totals.devicesNoLicenseData >= 1);
    const gap = data.coverageGaps.find((g) => g.fact === 'licenses');
    assert.equal(gap.notSupported, 1);
    assert.equal(gap.collected, 2);
  });

  it('⛔ the coverage section names it on the page, with the reason', async () => {
    const buf = await generateFleetLifecyclePdf(makePool(fixture()), { now: NOW });
    const text = pdfText(buf);
    assert.ok(says(text, 'DC-ASA'), 'the firewall must be named');
    assert.ok(says(text, 'What SecVault cannot see, on which firewalls, and why'));
    assert.ok(says(text, 'Cannot be asked'));
    assert.ok(
      says(text, 'it is never reported as having no licences and it is never left out'),
      'the rule must be stated, not merely followed'
    );
  });

  it('⛔ "cannot be asked" and "can be asked but returned nothing" are different states', () => {
    // The second is a COLLECTION FAILURE on a capable firewall, and it is the
    // one that silently shortens a renewal list — it looks exactly like the
    // first in an empty table and has a completely different owner.
    assert.equal(factCoverage(false, false, true), 'not_supported');
    assert.equal(factCoverage(true, false, true), 'not_collected');
    assert.equal(factCoverage(true, true, true), 'collected');
    assert.equal(factCoverage(null, false, true), 'unknown');
    assert.notEqual(
      coverageReason('licenses', 'not_supported', 'cisco_asa', 'ssh'),
      coverageReason('licenses', 'not_collected', 'cisco_asa', 'ssh')
    );
    assert.match(coverageReason('licenses', 'not_collected', 'fortinet', 'ssh'), /collection failure/i);
  });

  it('⛔ a FAILED read outranks everything: no rows from a failed query is NOT "no rows"', () => {
    // The single most dangerous value this function could return is
    // 'not_supported' or 'collected' for a query that threw.
    assert.equal(factCoverage(true, false, false), 'unknown');
    assert.equal(factCoverage(false, false, false), 'unknown');
    assert.equal(factCoverage(true, true, false), 'unknown');
  });

  it('⛔ a licence read that THROWS leaves every firewall unknown and says so', async () => {
    const data = await buildFleetLifecycleData(
      makePool(fixture({ licenseThrows: 'connection terminated' })),
      { now: NOW }
    );
    assert.equal(data.totals.licenses, 0);
    for (const dev of data.devices) {
      assert.equal(dev.coverage.licenses, 'unknown', 'a failed read is not an empty result');
    }
    assert.equal(data.sectionErrors.length, 1);
    assert.match(data.sectionErrors[0].message, /NOT claiming/);

    const text = pdfText(await renderFleetLifecyclePdf(data));
    assert.ok(says(text, 'Parts of this report could not be gathered'));
    assert.ok(
      says(text, 'This is NOT a statement that nothing expires'),
      'an empty renewal table after a failed read must refuse the obvious reading'
    );
  });

  it('a Fortinet over SSH reports licences and HA but NOT disk, and the report says which', async () => {
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW });
    const fg = byName(data, 'TSR_EKM');
    assert.equal(fg.coverage.licenses, 'collected');
    assert.equal(fg.coverage.ha, 'collected');
    // ⛔ Derived from the adapter registry, not from a table typed into the
    // report — which is what stops this sentence outliving the code.
    assert.equal(fg.coverage.disk, 'not_supported');
    assert.equal(fg.disk.status, 'unknown');
    assert.equal(fg.disk.usePercent, null);
  });
});

// ── HA ────────────────────────────────────────────────────────────────────

describe('HA state is reported without filling in silences', () => {
  it('⛔ version_compat_ok = null is NOT rendered as OK', () => {
    const match = compatCell(true);
    const mismatch = compatCell(false);
    const unreported = compatCell(null);
    assert.equal(match.text, 'Match');
    assert.equal(mismatch.text, 'MISMATCH');
    assert.notEqual(unreported.text, match.text);
    assert.notEqual(unreported.color, match.color);
    assert.match(unreported.text, /Not reported/);
    assert.ok(unreported.text.includes(NOT_MEASURED_MARK));
    // undefined must behave the same as null — a row read from a partial
    // SELECT has no compat key at all.
    assert.equal(compatCell(undefined).text, unreported.text);
  });

  it('⛔ a pair that never reported compatibility is counted, and the page says a silence is not a match', async () => {
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW });
    assert.equal(data.totals.haCompatUnreported, 1, 'the PA pair reported no compatibility block');
    assert.equal(data.totals.haCompatMismatch, 0);

    const text = pdfText(await renderFleetLifecyclePdf(data));
    assert.ok(
      says(text, 'That is shown as NOT REPORTED, not as a match'),
      'the document must refuse to read the silence as a match, in as many words'
    );
  });

  it('⛔ a User-requested suspension is NOT reported as a fault', async () => {
    // This is how it arrives: the collector deliberately keeps a 'User
    // requested' suspension out of last_nonfunctional_reason, because it is an
    // admin action on an otherwise healthy pair. The report must therefore call
    // this pair HEALTHY — and must say WHY, or a reader who knows a member was
    // suspended concludes the report missed it.
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW });
    const pa = byName(data, 'IDC FW');
    assert.equal(pa.ha.status, 'healthy');
    assert.deepEqual(pa.ha.reasons, []);
    assert.equal(data.totals.haDegraded, 0);

    const text = pdfText(await renderFleetLifecyclePdf(data));
    assert.ok(
      says(text, 'A suspended HA member is not automatically a fault'),
      'the reader must be told why an admin-suspended pair reads healthy'
    );
    assert.ok(says(text, 'User requested'));
  });

  it('a genuine fault IS reported, with the firewall\'s own words', async () => {
    const f = fixture();
    f.ha = f.ha.map((r) => (r.device_id === DEV_PA
      ? { ...r, peer_connection_status: 'down', version_compat_ok: false, last_nonfunctional_reason: 'Link down' }
      : r));
    const data = await buildFleetLifecycleData(makePool(f), { now: NOW });
    const pa = byName(data, 'IDC FW');
    assert.equal(pa.ha.status, 'degraded');
    assert.equal(data.totals.haDegraded, 1);
    assert.equal(data.totals.haCompatMismatch, 1);
    const text = pdfText(await renderFleetLifecyclePdf(data));
    assert.ok(says(text, 'Link down'));
  });

  it('⛔ a firewall whose HA was never collected is not called "standalone"', async () => {
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW });
    const asa = byName(data, 'DC-ASA');
    assert.equal(asa.coverage.ha, 'not_supported');
    assert.equal(asa.ha.status, 'unknown');
    assert.notEqual(asa.ha.status, 'standalone', 'never asked is not "no HA configured"');
    // A Fortinet that DID answer "HA is off" is standalone — a collected fact.
    assert.equal(byName(data, 'TSR_EKM').ha.status, 'standalone');
  });
});

// ── disk and content ──────────────────────────────────────────────────────

describe('disk and content freshness keep the device\'s own values', () => {
  it('sizes stay as the firewall\'s own strings; only the percentage is numeric', async () => {
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW });
    const pa = byName(data, 'IDC FW');
    assert.equal(pa.disk.status, 'critical');
    assert.equal(pa.disk.usePercent, 95);
    assert.equal(pa.disk.row.size_raw, '124G');
    assert.equal(typeof pa.disk.row.avail_raw, 'string');
    const text = pdfText(await renderFleetLifecyclePdf(data));
    assert.ok(says(text, '124G'), 'the device\'s own size string must reach the page unmodified');
    assert.ok(
      says(text, 'not from SNMP'),
      'the provenance matters: these carry none of the generic-MIB confidence caveat'
    );
  });

  it('⛔ a content component with no release date is counted, not treated as current', async () => {
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW });
    const pa = byName(data, 'IDC FW');
    assert.equal(pa.contentNoReleaseDate, 1, 'url_filtering reports no release date');
    assert.equal(data.totals.contentNoReleaseDate, 1);
    // The verdict comes from the components that DID carry a date.
    assert.equal(pa.worstSignature.status, 'stale');
    const text = pdfText(await renderFleetLifecyclePdf(data));
    assert.ok(says(text, 'their age is unknown - not current'));
  });

  it('daysText never renders an unknown delta as a number', () => {
    assert.equal(daysText(null), NOT_MEASURED_MARK);
    assert.equal(daysText(undefined), NOT_MEASURED_MARK);
    assert.equal(daysText(0), 'today');
    assert.equal(daysText(31), 'in 31d');
    assert.equal(daysText(-425), '425d ago');
  });
});

// ── the headline ──────────────────────────────────────────────────────────

describe('the headline sentence', () => {
  const clean = {
    warnDays: 60, staleDays: 7, devices: 3,
    licensesExpired: 0, licensesExpiring: 0, licensesUnknownExpiry: 0,
    haDegraded: 0, haCompatUnreported: 0,
    diskCritical: 0, signaturesStale: 0,
    devicesNoLicenseData: 0, devicesNoHaData: 0, devicesNoDiskData: 0, devicesNoContentData: 0,
  };

  it('⛔ an all-clear is FORBIDDEN while coverage is incomplete', () => {
    const s = headlineSentence({ ...clean, devicesNoLicenseData: 4 });
    assert.ok(s.includes('THIS IS NOT A COMPLETE PICTURE'));
    assert.ok(s.includes('Nothing above is offered as an all-clear'));
    assert.ok(
      s.includes('absent from this document rather than absent from the estate'),
      'the sentence must say what the missing firewalls mean, not merely that they are missing'
    );
  });

  it('⛔ an unreadable expiry alone is enough to withdraw the all-clear', () => {
    const s = headlineSentence({ ...clean, licensesUnknownExpiry: 1 });
    assert.ok(s.includes('THIS IS NOT A COMPLETE PICTURE'));
    assert.ok(s.includes('could not read'));
  });

  it('only an entirely clean, entirely covered fleet gets an unqualified sentence', () => {
    const s = headlineSentence(clean);
    assert.ok(!s.includes('NOT A COMPLETE PICTURE'));
    assert.ok(s.includes('every expiry date was readable'));
  });

  it('leads with the urgent facts when there are any', () => {
    const s = headlineSentence({ ...clean, licensesExpired: 2, licensesExpiring: 5, haDegraded: 1 });
    assert.ok(s.includes('2 entitlements have already expired'));
    assert.ok(s.includes('5 expire within 60 days'));
    assert.ok(s.includes('1 HA pair is degraded'));
  });

  it('the live-shaped fixture produces a headline that refuses an all-clear', async () => {
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW });
    assert.ok(data.headline.includes('THIS IS NOT A COMPLETE PICTURE'));
  });
});

// ── the document itself ───────────────────────────────────────────────────

describe('the generated document', () => {
  it('returns a real PDF buffer for a realistic fleet', async () => {
    const buf = await generateFleetLifecyclePdf(makePool(fixture()), { now: NOW });
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.subarray(0, 4).toString('latin1'), '%PDF');
    assert.ok(buf.length > 5000, 'a report with four sections is not a few hundred bytes');
    const text = pdfText(buf);
    // Every section must be present, or a reader cannot tell a missing section
    // from an empty one.
    ['Summary', 'What this report can and cannot prove', 'Renewal timeline',
      'High availability and redundancy', 'Disk capacity', 'Content and signature freshness',
      'What SecVault cannot see, on which firewalls, and why', 'How this report was produced',
    ].forEach((s) => assert.ok(says(text, s), `missing section: ${s}`));
  });

  it('⛔ does not throw on an EMPTY fleet, and does not call it healthy', async () => {
    const pool = makePool(fixture({
      devices: [], licenses: [], ha: [], disks: [], content: [], versions: [],
    }));
    // No devices at all -> null, the documented "nothing in scope" answer,
    // rather than a confident empty report.
    const buf = await generateFleetLifecyclePdf(pool, { now: NOW });
    assert.equal(buf, null);
  });

  it('⛔ a fleet with devices but no lifecycle data at all still renders, as a coverage report', async () => {
    const buf = await generateFleetLifecyclePdf(
      makePool(fixture({ licenses: [], ha: [], disks: [], content: [], versions: [] })),
      { now: NOW }
    );
    assert.ok(Buffer.isBuffer(buf));
    const text = pdfText(buf);
    assert.ok(
      says(text, 'This is NOT a statement that nothing expires'),
      'an empty renewal table over an uncollected fleet is a coverage statement, not a renewal one'
    );
    assert.ok(says(text, 'THIS IS NOT A COMPLETE PICTURE'));
  });

  it('a named device that does not exist returns null, not an empty report', async () => {
    const buf = await generateFleetLifecyclePdf(makePool(fixture()), {
      now: NOW, deviceId: '99999999-9999-9999-9999-999999999999',
    });
    assert.equal(buf, null);
  });

  it('deviceId narrows the fleet report rather than producing a different document', async () => {
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW, deviceId: DEV_PA });
    assert.equal(data.scope, 'device');
    assert.equal(data.devices.length, 1);
    assert.equal(data.device.name, 'IDC FW');
    const buf = await renderFleetLifecyclePdf(data);
    assert.equal(buf.subarray(0, 4).toString('latin1'), '%PDF');
  });

  it('⛔ a cap is disclosed, never silent', async () => {
    const data = await buildFleetLifecycleData(makePool(fixture()), { now: NOW, maxRenewalRows: 1 });
    assert.ok(data.renewals.length > 1, 'the fixture must actually exceed the cap');
    const text = pdfText(await renderFleetLifecyclePdf(data));
    assert.ok(says(text, 'Showing 1 of'), 'a truncated list that looks complete is worse than a long one');
    // ⛔ And a cap of 0 must never be honoured — it would empty a section, which
    // on the page is indistinguishable from "nothing was found".
    const zero = await buildFleetLifecycleData(makePool(fixture()), { now: NOW, maxRenewalRows: 0 });
    assert.equal(zero.caps.maxRenewalRows, 1);
  });
});
