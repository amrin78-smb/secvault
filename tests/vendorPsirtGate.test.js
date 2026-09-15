'use strict';
// Pins the inventory gate on vendor PSIRT feeds.
//
// ⛔ WHAT THIS PROTECTS. A vendor's own advisory feed is a bespoke integration
// whose advisories can only ever match that vendor's devices, so running one for
// a vendor nobody owns is pure cost — measured on the reference deployment, NVD
// alone was issuing ~2,000 failed CPE requests a week for four vendors with zero
// devices. But the same mechanism, wrong in the other direction, silently
// switches off CVE discovery. Every test here is about WHICH WAY IT FAILS.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  planVendorPsirts, inventoryVendors, registerVendorPsirt, VENDOR_PSIRTS, SKIPPED,
} = require('../lib/feeds/vendorPsirt');

const registry = {
  paloalto: { feedName: 'paloalto_psirt', run: async () => ({}) },
  fortinet: { feedName: 'fortinet_psirt', run: async () => ({}) },
};
const inv = (...vendors) => ({ ok: true, vendors: new Set(vendors) });

describe('planVendorPsirts', () => {
  it('runs a feed whose vendor is in the inventory', () => {
    const plan = planVendorPsirts(inv('paloalto', 'fortinet'), registry);
    assert.equal(plan.every((p) => p.shouldRun), true);
    assert.equal(plan.every((p) => p.reason === null), true, 'a run needs no explanation');
  });

  it('skips a feed whose vendor is absent, and says why', () => {
    const plan = planVendorPsirts(inv('paloalto'), registry);
    const ft = plan.find((p) => p.vendor === 'fortinet');
    assert.equal(ft.shouldRun, false);
    assert.match(ft.reason, /No active fortinet device/);
    // ⛔ The reason must state what still covers the vendor, or "skipped" reads
    // as "this vendor is no longer watched at all".
    assert.match(ft.reason, /NVD|CIRCL/);
    // ⛔ And that nothing already collected was thrown away.
    assert.match(ft.reason, /are kept/);
  });

  it('⛔ AN UNREADABLE INVENTORY RUNS EVERYTHING — it fails OPEN', () => {
    // The one place in this module where the safe direction is MORE work. A
    // database hiccup that silently disabled CVE discovery would leave the
    // product not doing its main job while every signal still looked healthy,
    // and the next sync would be indistinguishable from a good one.
    const plan = planVendorPsirts({ ok: false, error: 'connection refused' }, registry);
    assert.equal(plan.every((p) => p.shouldRun), true);
    for (const p of plan) assert.match(p.reason, /could not be read/);
  });

  it('a missing or malformed inventory result also fails open', () => {
    for (const bad of [null, undefined, {}, { ok: 'yes' }]) {
      const plan = planVendorPsirts(bad, registry);
      assert.equal(plan.every((p) => p.shouldRun), true, 'failed closed on ' + JSON.stringify(bad));
    }
  });

  it('⛔ an EMPTY inventory is NOT the same as an unreadable one', () => {
    // Empty says "skip every vendor feed". Unreadable says "we do not know".
    // Collapsing them makes a fresh install and a broken database behave
    // identically, in opposite directions from what each needs.
    const empty = planVendorPsirts(inv(), registry);
    const broken = planVendorPsirts({ ok: false, error: 'x' }, registry);
    assert.equal(empty.every((p) => p.shouldRun === false), true);
    assert.equal(broken.every((p) => p.shouldRun === true), true);
  });

  it('a vendor added later starts collecting with no configuration', () => {
    // The gate reads the inventory every cycle; there is nothing to switch on.
    assert.equal(
      planVendorPsirts(inv('paloalto'), registry).find((p) => p.vendor === 'fortinet').shouldRun,
      false
    );
    assert.equal(
      planVendorPsirts(inv('paloalto', 'fortinet'), registry).find((p) => p.vendor === 'fortinet').shouldRun,
      true
    );
  });

  it('an unregistered vendor in the inventory is simply not a feed', () => {
    // Owning a Check Point does not invent a Check Point feed.
    const plan = planVendorPsirts(inv('paloalto', 'checkpoint'), registry);
    assert.equal(plan.length, 2);
    assert.equal(plan.some((p) => p.vendor === 'checkpoint'), false);
  });
});

describe('inventoryVendors', () => {
  it('returns the distinct active vendors', async () => {
    const pool = { query: async () => ({ rows: [{ vendor: 'paloalto' }, { vendor: 'fortinet' }] }) };
    const r = await inventoryVendors(pool);
    assert.equal(r.ok, true);
    assert.deepEqual([...r.vendors].sort(), ['fortinet', 'paloalto']);
  });

  it('⛔ RETURNS the failure rather than throwing or returning an empty set', async () => {
    // An empty set is an instruction ("skip everything"). A failure is not, and
    // a caller cannot tell them apart once the distinction is lost here.
    const pool = { query: async () => { throw new Error('connection refused'); } };
    const r = await inventoryVendors(pool);
    assert.equal(r.ok, false);
    assert.match(r.error, /connection refused/);
    assert.equal(r.vendors, undefined, 'a failure must carry no vendor set to be mistaken for data');
  });

  it('asks only for ACTIVE devices', async () => {
    let sql = '';
    await inventoryVendors({ query: async (q) => { sql = q; return { rows: [] }; } });
    assert.match(sql, /active\s*=\s*true/);
  });
});

describe('the registry', () => {
  it('registers the two feeds that exist, keyed by the devices.vendor slug', () => {
    require('../lib/feeds/index.js');
    assert.deepEqual(Object.keys(VENDOR_PSIRTS).sort(), ['fortinet', 'paloalto']);
    assert.equal(VENDOR_PSIRTS.paloalto.feedName, 'paloalto_psirt');
    assert.equal(typeof VENDOR_PSIRTS.fortinet.run, 'function');
  });

  it('⛔ every registered key is a real vendor slug', () => {
    // A near-miss spelling ('palo_alto', 'checkpoint_ngfw') would compare
    // against the inventory forever without matching — i.e. silently mean
    // "never run", which is indistinguishable from the gate working correctly
    // when you own none of that vendor.
    const { VENDOR_META } = require('../components/devices/vendorMeta');
    require('../lib/feeds/index.js');
    for (const slug of Object.keys(VENDOR_PSIRTS)) {
      assert.ok(VENDOR_META[slug], slug + ' is not a vendor slug this product supports');
    }
  });

  it('registering is additive and does not disturb the others', () => {
    const before = Object.keys(VENDOR_PSIRTS).length;
    registerVendorPsirt('sangfor', 'sangfor_psirt', async () => ({}));
    assert.equal(Object.keys(VENDOR_PSIRTS).length, before + 1);
    delete VENDOR_PSIRTS.sangfor;
  });

  it('exports the skipped status the log and the badge both key on', () => {
    assert.equal(SKIPPED, 'skipped');
  });
});

describe('⛔ skipped is not coloured like a failure', () => {
  it('the dashboard badge maps it to muted, not warning', () => {
    // A correctly-skipped feed rendered amber puts a permanent warning on the
    // dashboard for the system working — and an operator who learns to ignore
    // an amber chip will ignore the one that matters.
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'app', '(dashboard)', 'page.js'), 'utf8'
    );
    const at = src.indexOf('function syncBadgeColor');
    assert.ok(at > 0, 'syncBadgeColor not found');
    const fn = src.slice(at, at + 1200);
    assert.ok(fn.includes('skipped'), 'syncBadgeColor does not handle the skipped status');
    assert.ok(/skipped[\s\S]{0,40}muted/.test(fn), 'skipped must map to muted, not fall through to warning');
  });
});
