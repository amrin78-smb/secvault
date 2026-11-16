'use strict';
// Pins lib/osBranchData.js and the work-queue source built on it — "this
// firewall is affected AND is on a branch the vendor no longer commits to
// fixing".
//
// ⛔ THE BAND IS THE WHOLE RISK HERE, AND IT IS DECIDED BY EVIDENCE, NOT BY HOW
// BAD THE FINDING LOOKS. Every FortiOS and every Cisco IOS-XE date in the live
// corpus comes from endoflife.date, an aggregator. An upgrade scheduled — or
// deferred — on an aggregator's date needs a human to confirm the date first,
// so those items are `unmeasured` and land in `verify` however urgent they
// seem. Only Palo Alto's own published table earns `reported`, and therefore
// `act_now`. CLAUDE.md's rule, applied one engine further out: "`act_now` is a
// claim about evidence, and we do not have any."
//
// ⛔ AND NOTHING HERE MAY MOVE A PRIORITY BAND. The CVE priority decision tree
// is documented-before-changed by contract; this is a SECOND AXIS beside it.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { gatherOsLifecycle } = require('../lib/engines/workQueueData');
const { bandFor } = require('../lib/engines/workQueue');
const { BRANCH_CLAIM, EXTENDED_CLAIM } = require('../lib/osBranch');
const {
  loadOsBranchCorpus, loadDeviceBranchSupport, loadOpenAdvisoryCounts, loadUnfixableAdvisories,
} = require('../lib/osBranchData');

// ── stub pool ─────────────────────────────────────────────────────────────

function stubPool(handlers) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      for (const [re, rows] of handlers) {
        if (re.test(sql)) return { rows: typeof rows === 'function' ? rows(params) : rows, rowCount: 0 };
      }
      throw new Error(`unexpected query: ${sql.slice(0, 80)}`);
    },
  };
}

const CORPUS_ROWS = [
  {
    vendor: 'Palo Alto', product: 'PAN-OS', cycle: '10.0', release_date: '2020-07-16',
    support_end_date: '2022-07-16', extended_end_date: null, latest_version: null, lts: null,
    confidence: 'high', source: 'https://paloaltonetworks.com/eol', vendor_link: null,
    feed_version: '2026-11-16.1', applied_at: '2026-11-16T05:00:00Z',
  },
  {
    vendor: 'Palo Alto', product: 'PAN-OS', cycle: '11.1', release_date: '2023-11-03',
    support_end_date: '2027-05-03', extended_end_date: '2027-08-31', latest_version: null,
    lts: null, confidence: 'high', source: 'https://paloaltonetworks.com/eol', vendor_link: null,
    feed_version: '2026-11-16.1', applied_at: '2026-11-16T05:00:00Z',
  },
  {
    vendor: 'Palo Alto', product: 'PAN-OS', cycle: '10.1', release_date: '2021-05-31',
    support_end_date: '2024-12-01', extended_end_date: '2026-12-31', latest_version: null,
    lts: null, confidence: 'high', source: 'https://paloaltonetworks.com/eol', vendor_link: null,
    feed_version: '2026-11-16.1', applied_at: '2026-11-16T05:00:00Z',
  },
  {
    vendor: 'Fortinet', product: 'FortiOS', cycle: '7.0', release_date: '2021-03-30',
    support_end_date: '2024-03-30', extended_end_date: '2025-09-30', latest_version: null,
    lts: false, confidence: 'low', source: 'https://endoflife.date/api/fortios.json',
    vendor_link: 'https://docs.fortinet.com/eol', feed_version: '2026-11-16.1',
    applied_at: '2026-11-16T05:00:00Z',
  },
  // ⛔ A cycle branchOf can never return — in the live corpus as PAN-OS 9.0-XFR.
  {
    vendor: 'Palo Alto', product: 'PAN-OS', cycle: '9.0-XFR', release_date: '2019-09-19',
    support_end_date: '2020-09-19', extended_end_date: null, latest_version: null, lts: null,
    confidence: 'high', source: 'https://paloaltonetworks.com/eol', vendor_link: null,
    feed_version: '2026-11-16.1', applied_at: '2026-11-16T05:00:00Z',
  },
];

const DEVICE_ROWS = [
  { device_id: 'd-eol', device_name: 'OKF-FW', vendor: 'paloalto', asset_criticality: 'critical', version_string: '10.0.12-h3', version_collected_at: '2026-11-15T00:00:00Z' },
  { device_id: 'd-ok', device_name: 'HQ-FW', vendor: 'paloalto', asset_criticality: 'high', version_string: '11.1.4-h1', version_collected_at: '2026-11-15T00:00:00Z' },
  { device_id: 'd-ext', device_name: 'DC-FW', vendor: 'paloalto', asset_criticality: 'high', version_string: '10.1.14', version_collected_at: '2026-11-15T00:00:00Z' },
  { device_id: 'd-forti', device_name: 'BR-FW', vendor: 'fortinet', asset_criticality: 'medium', version_string: 'v7.0.14,build0601', version_collected_at: '2026-11-15T00:00:00Z' },
  { device_id: 'd-asa', device_name: 'ASA-1', vendor: 'cisco_asa', asset_criticality: 'low', version_string: '9.18(4)15', version_collected_at: '2026-11-15T00:00:00Z' },
  { device_id: 'd-noversion', device_name: 'NEW-FW', vendor: 'paloalto', asset_criticality: 'low', version_string: null, version_collected_at: null },
];

const ADVISORY_ROWS = [
  { device_id: 'd-eol', patch_now: 4, scheduled: 2, kev: 1, worst_cvss: 9.8 },
  { device_id: 'd-ok', patch_now: 1, scheduled: 0, kev: 0, worst_cvss: 7.5 },
  { device_id: 'd-ext', patch_now: 2, scheduled: 1, kev: 0, worst_cvss: 8.1 },
  { device_id: 'd-forti', patch_now: 3, scheduled: 0, kev: 2, worst_cvss: 9.1 },
];

const HANDLERS = [
  [/FROM os_branch_cycles/, CORPUS_ROWS],
  [/FROM devices d\s+LEFT JOIN LATERAL/, DEVICE_ROWS],
  [/FROM device_cve_assessments/, ADVISORY_ROWS],
];

const asOf = '2026-11-16';
const load = (overrides = {}) => loadUnfixableAdvisories(
  stubPool(overrides.handlers || HANDLERS),
  { asOf }
);

// ── the reads ─────────────────────────────────────────────────────────────

describe('loadOsBranchCorpus', () => {
  it('⛔ an EMPTY table is `neverSynced`, not a failure', async () => {
    const c = await loadOsBranchCorpus(stubPool([[/FROM os_branch_cycles/, []]]));
    assert.equal(c.total, 0);
    assert.equal(c.neverSynced, true);
  });

  it('⛔ a FAILED read THROWS — it must never look like an empty corpus', async () => {
    // Empty is a legitimate state (before the feed's first sync, and on every
    // site with no licence key) where every firewall correctly reads "branch
    // unknown". A failed read producing the same empty map would render the
    // identical screen while the corpus sat there intact.
    const pool = { query: async () => { throw new Error('relation does not exist'); } };
    await assert.rejects(() => loadOsBranchCorpus(pool), /relation does not exist/);
  });

  it('reads the dates as TEXT, never as a pg Date', async () => {
    const pool = stubPool(HANDLERS);
    await loadOsBranchCorpus(pool);
    assert.match(pool.calls[0].sql, /to_char\(support_end_date,\s*'YYYY-MM-DD'\)/);
    assert.match(pool.calls[0].sql, /to_char\(extended_end_date,\s*'YYYY-MM-DD'\)/);
  });

  it('counts the cycles that can never be matched', async () => {
    const c = await loadOsBranchCorpus(stubPool(HANDLERS));
    assert.equal(c.unmatchable, 1, 'PAN-OS 9.0-XFR');
    assert.equal(c.total, 5);
    assert.equal(c.feedVersion, '2026-11-16.1');
  });

  it('the lookup is keyed on all THREE of vendor, product and cycle', async () => {
    const c = await loadOsBranchCorpus(stubPool(HANDLERS));
    assert.ok(c.lookup({ vendor: 'Palo Alto', product: 'PAN-OS', cycle: '10.0' }));
    // FortiOS 7.0 exists; PAN-OS 7.0 does not. Keying on the cycle alone would
    // let one vendor's lifecycle answer for another's firewall.
    assert.equal(c.lookup({ vendor: 'Palo Alto', product: 'PAN-OS', cycle: '7.0' }), null);
    assert.ok(c.lookup({ vendor: 'Fortinet', product: 'FortiOS', cycle: '7.0' }));
  });
});

describe('loadDeviceBranchSupport', () => {
  it('classifies every active firewall and summarises by state', async () => {
    const s = await loadDeviceBranchSupport(stubPool(HANDLERS), { asOf });
    const by = Object.fromEntries(s.devices.map((d) => [d.deviceId, d.state]));
    assert.equal(by['d-eol'], 'eol');
    assert.equal(by['d-ok'], 'supported');
    assert.equal(by['d-ext'], 'extended_only');
    assert.equal(by['d-forti'], 'eol');
    assert.equal(by['d-asa'], 'unknown');
    assert.equal(by['d-noversion'], 'unknown');
    assert.equal(s.summary.counts.eol, 2);
    assert.equal(s.summary.counts.unknown, 2);
    assert.equal(s.summary.unknownByReason.product_not_covered, 1);
    assert.equal(s.summary.unknownByReason.no_version, 1);
  });

  it('⛔ ONE `asOf` for the whole fleet, so two firewalls cannot straddle a boundary', async () => {
    const s = await loadDeviceBranchSupport(stubPool(HANDLERS), { asOf });
    assert.equal(s.asOf, asOf);
  });

  it('⛔ takes the NEWEST collected version, with no `active` filter on it', async () => {
    const pool = stubPool(HANDLERS);
    await loadDeviceBranchSupport(pool, { asOf });
    const deviceSql = pool.calls.find((c) => /LEFT JOIN LATERAL/.test(c.sql)).sql;
    assert.match(deviceSql, /ORDER BY collected_at DESC/);
    // A firewall whose collection has failed for a month still has a last
    // known version; reporting its branch as unknown would hide a dead branch
    // behind a collection gap.
    assert.match(deviceSql, /LEFT JOIN LATERAL/);
  });
});

describe('loadOpenAdvisoryCounts', () => {
  it('⛔ a firewall with NO assessment rows is ABSENT, never zero', async () => {
    const c = await loadOpenAdvisoryCounts(stubPool(HANDLERS));
    assert.equal(c.byDevice.has('d-noversion'), false);
    assert.equal(c.assessedDevices, 4);
  });

  it('keeps patch_now and scheduled apart', async () => {
    const c = await loadOpenAdvisoryCounts(stubPool(HANDLERS));
    assert.deepEqual(c.byDevice.get('d-eol'), { patchNow: 4, scheduled: 2, kev: 1, worstCvss: 9.8 });
  });
});

describe('loadUnfixableAdvisories', () => {
  it('⛔ only eol and extended_only firewalls appear — supported and unknown do NOT', async () => {
    const r = await load();
    const ids = r.items.map((i) => i.deviceId).sort();
    assert.deepEqual(ids, ['d-eol', 'd-ext', 'd-forti']);
  });

  it('⛔ an unassessed firewall gets NULL counts, never 0', async () => {
    const r = await loadUnfixableAdvisories(stubPool([
      [/FROM os_branch_cycles/, CORPUS_ROWS],
      [/LEFT JOIN LATERAL/, [DEVICE_ROWS[0]]],
      [/FROM device_cve_assessments/, []],
    ]), { asOf });
    assert.equal(r.items.length, 1);
    assert.equal(r.items[0].openPatchNow, null);
    assert.equal(r.items[0].assessed, false);
  });
});

// ── the work-queue item ───────────────────────────────────────────────────

const itemsFor = async (overrides) => gatherOsLifecycle(null, await load(overrides));
const byDevice = (items, id) => items.find((i) => i.deviceIds[0] === id);

describe('gatherOsLifecycle — banding', () => {
  it('⛔ VENDOR-CONFIRMED eol + open patch-now => act_now', async () => {
    const items = await itemsFor();
    const it = byDevice(items, 'd-eol');
    assert.equal(it.evidence, 'reported');
    assert.equal(it.urgency, 'now');
    assert.equal(bandFor(it), 'act_now');
    assert.equal(it.severity, 'critical', 'a KEV listing among them');
  });

  it('⛔ an AGGREGATOR date can never reach act_now, however bad it looks', async () => {
    // d-forti is EOL with 3 patch-now advisories, 2 of them KEV — strictly
    // worse than d-eol on every axis except the one that decides the band.
    const items = await itemsFor();
    const it = byDevice(items, 'd-forti');
    assert.equal(it.evidence, 'unmeasured');
    assert.equal(bandFor(it), 'verify');
    assert.equal(it.severity, 'critical', 'the severity still tells the truth');
  });

  it('⛔ and the item SAYS the date is unconfirmed, in words', async () => {
    const items = await itemsFor();
    assert.match(byDevice(items, 'd-forti').why, /not confirmed by the vendor/);
    assert.ok(!/not confirmed by the vendor/.test(byDevice(items, 'd-eol').why));
  });

  it('⛔ a dead branch with NOTHING open is `scheduled`, not urgent', async () => {
    // Otherwise the fleet's whole upgrade backlog lands in act_now on the day
    // this feature ships, which is how a queue stops being used.
    const items = await itemsFor({
      handlers: [
        [/FROM os_branch_cycles/, CORPUS_ROWS],
        [/LEFT JOIN LATERAL/, [DEVICE_ROWS[0]]],
        [/FROM device_cve_assessments/, [{ device_id: 'd-eol', patch_now: 0, scheduled: 0, kev: 0, worst_cvss: null }]],
      ],
    });
    const it = items[0];
    assert.equal(it.urgency, 'soon');
    assert.equal(bandFor(it), 'scheduled');
    assert.match(it.why, /No advisory is currently banded patch-now/);
  });

  it('⛔ `extended_only` is NEVER act_now, even with open advisories', async () => {
    // A fix may still be obtainable with a contract, so the first step is
    // "check the contract", not "upgrade tonight".
    const items = await itemsFor();
    const it = byDevice(items, 'd-ext');
    assert.equal(it.urgency, 'soon');
    assert.equal(bandFor(it), 'scheduled');
    assert.match(it.action, /Confirm extended-support coverage/);
    assert.match(it.action, /before 2026-12-31/);
  });

  it('an UNASSESSED firewall on a dead branch is reported, and says so', async () => {
    const items = await itemsFor({
      handlers: [
        [/FROM os_branch_cycles/, CORPUS_ROWS],
        [/LEFT JOIN LATERAL/, [DEVICE_ROWS[0]]],
        [/FROM device_cve_assessments/, []],
      ],
    });
    assert.equal(items.length, 1);
    assert.match(items[0].why, /no CVE assessment on record/);
    assert.equal(bandFor(items[0]), 'scheduled');
  });
});

describe('gatherOsLifecycle — the item itself', () => {
  it('⛔ ONE ITEM PER FIREWALL, not per advisory', async () => {
    const items = await itemsFor();
    assert.equal(items.length, 3);
    assert.equal(new Set(items.map((i) => i.key)).size, 3);
    for (const it of items) assert.equal(it.deviceIds.length, 1);
  });

  it('⛔ `count` is ADVISORIES and `magnitude` is FIREWALLS — always 1', async () => {
    // Ranking on the advisory count would let one firewall with forty open
    // advisories outrank the rest of the fleet, which is the mis-ranking the
    // ingest source caused live.
    const items = await itemsFor();
    assert.equal(byDevice(items, 'd-eol').count, 4);
    for (const it of items) assert.equal(it.magnitude, 1);
  });

  it('⛔ the engine\'s own sentence is reused, with the dates in it', async () => {
    const it = byDevice(await itemsFor(), 'd-eol');
    assert.match(it.why, /PAN-OS 10\.0 left vendor support on 2022-07-16/);
  });

  it('⛔ an `eol` item carries BRANCH_CLAIM, so the remediation claim cannot drift', async () => {
    for (const id of ['d-eol', 'd-forti']) {
      assert.ok(byDevice(await itemsFor(), id).why.includes(BRANCH_CLAIM));
    }
  });

  it('⛔ an `extended_only` item carries the OTHER claim, and NOT the eol one', async () => {
    // "A patch on this branch is not available" is false for a customer holding
    // the extended-support contract. The first draft said it for both states
    // and this assertion is what found it.
    const it = byDevice(await itemsFor(), 'd-ext');
    assert.ok(it.why.includes(EXTENDED_CLAIM));
    assert.ok(!it.why.includes(BRANCH_CLAIM));
    assert.ok(!/cannot be fixed/.test(it.title), 'nor may the title say it');
  });

  it('⛔ and no item claims a fix is impossible', async () => {
    for (const it of await itemsFor()) {
      const text = `${it.title} ${it.why} ${it.action}`;
      for (const forbidden of [/unpatchable/i, /never be fixed/i, /impossible/i, /guarantee/i]) {
        assert.ok(!forbidden.test(text), `${forbidden} must not appear: ${text}`);
      }
    }
  });

  it('the title names the combination when there is one', async () => {
    const items = await itemsFor();
    assert.match(byDevice(items, 'd-eol').title, /4 patch-now advisories on OKF-FW cannot be fixed on PAN-OS 10\.0/);
    assert.match(byDevice(items, 'd-ext').title, /2 patch-now advisories on DC-FW sit on PAN-OS 10\.1, which has only extended support/);
  });

  it('states how SecVault will observe that it is done, and links to lifecycle', async () => {
    for (const it of await itemsFor()) {
      assert.match(it.done, /next version pull/);
      assert.equal(it.href, '/lifecycle');
      assert.equal(it.type, 'os_lifecycle');
    }
  });

  it('⛔ it issues NO query of its own when handed a precomputed result', async () => {
    // The outbound dispatcher gathers with no opts; this proves the precomputed
    // path is a real path and not a parameter nobody reads.
    const pool = { query: async () => { throw new Error('must not query'); } };
    const items = await gatherOsLifecycle(pool, await load());
    assert.equal(items.length, 3);
  });

  it('⛔ and it NEVER writes — no band, no assessment, nothing', async () => {
    const pool = stubPool(HANDLERS);
    await gatherOsLifecycle(pool, null);
    for (const c of pool.calls) {
      assert.ok(
        !/\b(UPDATE|INSERT|DELETE)\b/i.test(c.sql),
        `the OS lifecycle source must only read: ${c.sql.slice(0, 60)}`
      );
      // ⛔ A COMPARISON IS NOT AN ASSIGNMENT. The advisory read legitimately
      // FILTERS on priority_band; what must never appear is a write to it.
      assert.ok(
        !/\bSET\b[\s\S]{0,80}priority_band/i.test(c.sql),
        'the priority decision tree is documented-before-changed and is not touched here'
      );
    }
  });

  it('evaluates for itself when handed nothing', async () => {
    const items = await gatherOsLifecycle(stubPool(HANDLERS), null);
    assert.equal(items.length, 3);
  });
});
