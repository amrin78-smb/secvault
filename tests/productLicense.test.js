'use strict';
// Pins SecVault's commercial licence.
//
// ⛔ WHAT THIS PROTECTS, AND WHY IT IS NOT THE OBVIOUS THING. A licence check
// has two failure directions and they are not symmetric. Letting an unlicensed
// install through costs a sale. Wrongly refusing a PAYING customer — or worse,
// quietly withholding a security finding from them — costs the account and,
// on a firewall-management platform, potentially costs them a breach.
//
// So most of what is pinned here is the SECOND direction: that monitoring never
// stops, that an unreadable database cannot lock anyone out, that a failed
// device count is never read as "plenty of headroom", and that a rejected key
// never silently masquerades as "no key".

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const L = require('../lib/productLicense');

// ─────────────────────────────────────────────────────────────────────────────
// A stand-in for the NocVault licence generator. Reproduces the format read off
// netvault/lib/license.ts, so these tests fail if SecVault ever drifts from the
// thing that actually mints the keys.
// ─────────────────────────────────────────────────────────────────────────────
const SECRET = 'NocVault-License-Secret-2026-X9K';

function mint(payload, secret = SECRET) {
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-cbc', key, iv);
  let enc = c.update(JSON.stringify(payload), 'utf8', 'hex');
  enc += c.final('hex');
  return Buffer.from(iv.toString('hex') + ':' + enc).toString('base64');
}

const HASH = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
const DAY = 86400000;
const NOW = new Date('2026-09-16T00:00:00Z');
const iso = (offsetDays) => new Date(NOW.getTime() + offsetDays * DAY).toISOString().slice(0, 10);

const licence = (over = {}) => ({
  customer: 'Example Co',
  serverId: 'SCV-' + HASH,
  expiry: iso(365),
  modules: ['secvault'],
  maxDevices: 20,
  issuedAt: iso(0),
  ...over,
});

const verdict = (over = {}, deviceCount = 5) => L.getLicenseStatus({
  installDate: iso(-2),
  licenseKey: mint(licence(over)),
  localHash: HASH,
  deviceCount,
  now: NOW,
});

// ─────────────────────────────────────────────────────────────────────────────

describe('key format — compatibility with the NocVault generator', () => {
  it('accepts a key minted exactly the way the generator mints one', () => {
    const r = L.validateLicenseKey(mint(licence()), HASH, NOW);
    assert.equal(r.valid, true);
    assert.equal(r.payload.customer, 'Example Co');
    assert.equal(r.payload.maxDevices, 20);
  });

  it('⛔ accepts BOTH the SCV- and NCV- prefixes for the same machine', () => {
    // The prefix is a label; the 32-hex hash is the machine. Which prefix the
    // generator emits depends on a tool this repo does not contain, and
    // rejecting the other one would refuse every legitimately-issued key for a
    // reason no error message could explain. The PRODUCT boundary is `modules`,
    // checked separately and strictly — see below.
    for (const p of ['SCV', 'NCV', 'NV', 'SV']) {
      assert.equal(
        L.validateLicenseKey(mint(licence({ serverId: p + '-' + HASH })), HASH, NOW).valid,
        true,
        p + ' prefix rejected'
      );
    }
  });

  it('rejects a key minted with a different secret', () => {
    const r = L.validateLicenseKey(mint(licence(), 'some-other-secret'), HASH, NOW);
    assert.equal(r.valid, false);
    assert.equal(r.code, 'unreadable');
  });

  it('rejects junk without throwing', () => {
    for (const junk of ['', 'not-a-key', 'YWJj', null, undefined, '::::']) {
      const r = L.validateLicenseKey(junk, HASH, NOW);
      assert.equal(r.valid, false);
      assert.ok(r.error);
    }
  });
});

describe('⛔ the product boundary — a suite key is not a SecVault key', () => {
  it('refuses a key that does not list secvault', () => {
    const r = L.validateLicenseKey(
      mint(licence({ modules: ['netvault', 'logvault', 'ddivault', 'spanvault'] })), HASH, NOW
    );
    assert.equal(r.valid, false);
    assert.equal(r.code, 'wrong_product');
    assert.match(r.error, /licensed separately/i);
  });

  it('⛔ FAILS CLOSED on an empty module list — the opposite of the siblings', () => {
    // LogVault/DDIVault/SpanVault treat empty `modules` as "allow" so legacy
    // suite keys are never bricked. SecVault has never shipped a licence, so
    // there are no legacy keys to protect — and failing open here would turn
    // every NocVault key already in the field into a free SecVault licence.
    for (const modules of [[], null, undefined, 'secvault', {}]) {
      assert.equal(L.coversSecVault(modules), false, JSON.stringify(modules) + ' was accepted');
    }
    assert.equal(L.validateLicenseKey(mint(licence({ modules: [] })), HASH, NOW).code, 'wrong_product');
  });

  it('is not fooled by a near-miss module name', () => {
    for (const m of ['sec-vault', 'secvault2', 'sec vault', 'vault']) {
      assert.equal(L.coversSecVault([m]), false, m + ' matched');
    }
    // …but case and padding are not the customer's problem.
    for (const m of ['SecVault', '  secvault  ', 'SECVAULT']) {
      assert.equal(L.coversSecVault([m]), true, m + ' rejected');
    }
  });
});

describe('the machine boundary', () => {
  it('refuses a key issued for another server', () => {
    const r = L.validateLicenseKey(mint(licence({ serverId: 'SCV-' + 'f'.repeat(32) })), HASH, NOW);
    assert.equal(r.valid, false);
    assert.equal(r.code, 'wrong_server');
    assert.match(r.error, /Server ID/);
  });

  it('⛔ a failed hardware read does not collapse every machine onto one identity', () => {
    // NetVault's getMachineGuid() returns '' on failure and the id becomes a
    // hash of `hostname-` alone, so two machines that fail the same way AND
    // share a hostname share a licence. The MAC fallback keeps them distinct.
    const a = L.deriveServerId('fw-mgmt', '', 'aa:bb:cc:dd:ee:01');
    const b = L.deriveServerId('fw-mgmt', '', 'aa:bb:cc:dd:ee:02');
    assert.notEqual(a.serverId, b.serverId);
    assert.equal(a.weak, true);
    assert.equal(a.source, 'mac-address');
  });

  it('⛔ reports a weak fingerprint as weak rather than as a confident one', () => {
    assert.equal(L.deriveServerId('h', 'guid-123', 'mac').weak, false);
    assert.equal(L.deriveServerId('h', '', '').weak, true);
    assert.equal(L.deriveServerId('h', '', '').source, 'hostname-only');
  });

  it('is stable across calls with the same inputs', () => {
    assert.equal(
      L.deriveServerId('host', 'guid', 'mac').serverId,
      L.deriveServerId('host', 'guid', 'mac').serverId
    );
  });
});

describe('trial', () => {
  const trial = (installedDaysAgo, deviceCount = 5) => L.getLicenseStatus({
    installDate: iso(-installedDaysAgo), licenseKey: '', localHash: HASH, deviceCount, now: NOW,
  });

  it('a fresh install is in trial with 30 days', () => {
    assert.equal(trial(0).status, 'trial');
    assert.equal(trial(0).daysRemaining, 30);
    assert.equal(trial(29).status, 'trial');
  });

  it('runs into grace, then expires', () => {
    assert.equal(trial(31).status, 'grace');
    assert.equal(trial(44).status, 'grace');
    assert.equal(trial(45).status, 'expired');
  });

  it('⛔ THE TRIAL IS UNLIMITED ON FIREWALL COUNT', () => {
    // The thing being evaluated is whether SecVault can see a whole estate. A
    // trial capped at a handful of firewalls demonstrates the opposite of the
    // product. Thirty days is the limit.
    const v = trial(3, 500);
    assert.equal(v.maxDevices, null);
    assert.equal(L.canAddDevice(v).allowed, true);
  });

  it('⛔ AN UNKNOWN INSTALL DATE DOES NOT GRANT A FRESH TRIAL SILENTLY', () => {
    // NetVault returns the full trial length whenever install_date is missing,
    // which makes deleting one row an unlimited extension. Here the pure layer
    // returns null so the caller is forced to derive a date from evidence, and
    // the verdict that results SAYS the date could not be established.
    assert.equal(L.trialDaysRemaining('', NOW), null);
    assert.equal(L.trialDaysRemaining(null, NOW), null);
    assert.equal(L.trialDaysRemaining('not-a-date', NOW), null);
    const v = L.getLicenseStatus({ installDate: null, licenseKey: '', localHash: HASH, now: NOW });
    assert.equal(v.status, 'trial');
    assert.match(v.reason, /install date could not be established/i);
  });
});

describe('⛔ `invalid` is its own state, not a silent fallback to trial', () => {
  it('a key for the wrong server does not report as a healthy trial', () => {
    // NetVault falls through to the trial branch here, so a customer who pasted
    // a key for the wrong server is told "trial, 12 days remaining" and never
    // learns their key did nothing. The key was READ AND REJECTED; reporting
    // that as "no key" is a failed read recorded as a fact.
    const v = L.getLicenseStatus({
      installDate: iso(-2),
      licenseKey: mint(licence({ serverId: 'SCV-' + 'f'.repeat(32) })),
      localHash: HASH, deviceCount: 5, now: NOW,
    });
    assert.equal(v.status, 'invalid');
    assert.notEqual(v.status, 'trial');
    assert.match(v.reason, /different server/i);
  });

  it('each rejection carries a reason the customer can act on', () => {
    const cases = [
      [{ serverId: 'SCV-' + 'f'.repeat(32) }, 'wrong_server'],
      [{ modules: ['netvault'] }, 'wrong_product'],
      [{ expiry: 'gibberish' }, 'unreadable'],
    ];
    for (const [over, code] of cases) {
      const r = L.validateLicenseKey(mint(licence(over)), HASH, NOW);
      assert.equal(r.code, code);
      assert.ok(r.error && r.error.length > 20, code + ' has no usable reason');
    }
  });
});

describe('expiry and the yearly renewal', () => {
  it('a current key is active, and flags the renewal 60 days out', () => {
    assert.equal(verdict().status, 'active');
    assert.equal(verdict().renewalDue, false);
    assert.equal(verdict({ expiry: iso(59) }).renewalDue, true);
    assert.equal(verdict({ expiry: iso(61) }).renewalDue, false);
  });

  it('⛔ an expired key earns grace; a REJECTED key does not', () => {
    // Grace exists because a renewal runs through a purchase order. Nothing
    // about a wrong-server or wrong-product key resolves itself with time, so
    // extending grace to those would just delay the conversation.
    assert.equal(verdict({ expiry: iso(-1) }).status, 'grace');
    assert.equal(verdict({ expiry: iso(-13) }).status, 'grace');
    assert.equal(verdict({ expiry: iso(-20) }).status, 'expired');
    assert.equal(verdict({ modules: ['netvault'], expiry: iso(-20) }).status, 'invalid');
  });

  it('grace keeps the device allowance — it is still a real subscription', () => {
    assert.equal(verdict({ expiry: iso(-1) }).maxDevices, 20);
  });
});

describe('the device limit', () => {
  it('counts up to the limit and refuses the one past it', () => {
    assert.equal(L.canAddDevice(verdict({}, 19)).allowed, true);
    assert.equal(L.canAddDevice(verdict({}, 20)).allowed, false);
    assert.equal(L.canAddDevice(verdict({}, 20)).code, 'device_limit');
    assert.match(L.canAddDevice(verdict({}, 20)).reason, /covers 20 firewalls and 20 are already monitored/);
  });

  it('reports being over the limit without pretending otherwise', () => {
    const v = verdict({}, 25);
    assert.equal(v.withinDeviceLimit, false);
    assert.equal(v.devicesRemaining, -5);
  });

  it('⛔ AN ABSENT maxDevices IS UNLIMITED, NOT ZERO', () => {
    // `Number(null)` is 0 and 0 is finite, so a naive isFinite guard would turn
    // "this licence does not state a count" into "this licence covers no
    // firewalls" and lock a paying customer out of their own fleet.
    for (const raw of [null, undefined, '', 0, -1, 'unlimited', NaN]) {
      const v = verdict({ maxDevices: raw }, 500);
      assert.equal(v.maxDevices, null, JSON.stringify(raw) + ' produced a limit');
      assert.equal(L.canAddDevice(v).allowed, true);
    }
  });

  it('⛔ AN UNCOUNTABLE FLEET IS UNKNOWN — neither permission nor refusal', () => {
    // A failed COUNT reported as 0 reads as "plenty of headroom" and walks
    // straight past the limit; reported as "over" it locks out a paying
    // customer over a database blip. It means ASK AGAIN.
    const v = verdict({}, null);
    assert.equal(v.deviceCount, null);
    assert.equal(v.withinDeviceLimit, null);
    assert.equal(v.devicesRemaining, null);
    const d = L.canAddDevice(v);
    assert.equal(d.allowed, false);
    assert.equal(d.code, 'uncountable');
    assert.match(d.reason, /Try again/);
  });

  it('a non-integer count is treated as uncountable, not coerced', () => {
    // node-pg hands back COUNT as a STRING; '20' passed straight through would
    // compare lexically against a number and behave unpredictably.
    for (const bad of ['20', 20.5, {}, null, '']) {
      assert.equal(verdict({}, bad).deviceCount, null, JSON.stringify(bad) + ' was accepted as a count');
    }
    // An omitted count is uncountable too — the parameter defaults to null.
    assert.equal(
      L.getLicenseStatus({ installDate: iso(-2), licenseKey: mint(licence()), localHash: HASH, now: NOW }).deviceCount,
      null
    );
  });
});

describe('⛔ THE LINE THE PRODUCT WILL NOT CROSS', () => {
  it('monitoring is allowed in EVERY licence state, including expired', () => {
    // A firewall that silently stopped being assessed shows no CVEs, no failing
    // checks and no rule findings — it renders as the HEALTHIEST device on the
    // fleet. That is this codebase's most-repeated bug class with a commercial
    // motive attached, aimed at the customer least likely to be watching.
    assert.equal(L.monitoringAllowed(), true);
  });

  it('the source contains no path from licence state to withholding data', () => {
    // A guard against a future edit that "improves enforcement" by gating
    // collection or assessment. If this ever needs to change, the sentence in
    // CLAUDE.md has to change first.
    const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'productLicense.js'), 'utf8');
    assert.match(src, /function monitoringAllowed\(\)\s*\{\s*return true;\s*\}/);
  });

  it('expiry blocks administrative writes but not the analyst workflow', () => {
    assert.equal(L.writeAllowed(verdict()), true);
    assert.equal(L.writeAllowed(verdict({ expiry: iso(-1) })), true, 'grace must stay writable');
    assert.equal(L.writeAllowed(verdict({ expiry: iso(-20) })), false);
    assert.equal(L.writeAllowed(verdict({ modules: ['netvault'] })), false);
  });

  it('⛔ an UNKNOWN licence state permits writes — the billing gate fails OPEN', () => {
    // The opposite of the RBAC guard that sits one line above it in every route
    // that uses both. RBAC answers "is this person allowed" and must fail
    // closed. Licensing answers "has the invoice been paid", and a database
    // blip must never lock a paying customer out of their own platform.
    assert.equal(L.writeAllowed(null), true);
    assert.equal(L.writeAllowed(undefined), true);
  });

  it('the expired message tells the customer monitoring continues', () => {
    const s = L.licenceSentence(verdict({ expiry: iso(-20) }));
    assert.equal(s.tone, 'bad');
    assert.match(s.text, /Monitoring, assessment and alerting continue/);
  });
});

describe('the banner sentence', () => {
  it('names the number and the date rather than saying "expiring soon"', () => {
    const s = L.licenceSentence(verdict({ expiry: iso(30) }, 12));
    assert.match(s.text, /Example Co/);
    assert.match(s.text, new RegExp(iso(30)));
    assert.match(s.text, /Covers 20 firewalls, 12 in use/);
  });

  it('⛔ an undeterminable state is HUELESS, never green', () => {
    assert.equal(L.licenceSentence(null).tone, 'unknown');
    assert.equal(L.licenceSentence({ status: 'nonsense' }).tone, 'unknown');
  });

  it('a trial in its last week reads as a warning, earlier does not', () => {
    const t = (d) => L.licenceSentence(L.getLicenseStatus({
      installDate: iso(-(30 - d)), licenseKey: '', localHash: HASH, now: NOW,
    })).tone;
    assert.equal(t(20), 'info');
    assert.equal(t(5), 'warn');
  });
});

describe('the banner only speaks when there is something to do', () => {
  const { bannerFor } = L;

  it('⛔ its status literals cannot drift from STATUS', () => {
    // licenceBanner.js deliberately imports nothing (a client bundle cannot
    // load child_process), so it restates the status strings. This is the only
    // thing stopping the two copies diverging.
    const { BANNER_STATUS } = require('../lib/licenceBanner');
    assert.deepEqual(BANNER_STATUS, L.STATUS);
    assert.equal(bannerFor, require('../lib/licenceBanner').bannerFor, 'one definition only');
  });

  it('stays silent on a healthy trial and a healthy licence', () => {
    assert.equal(bannerFor({ status: 'trial', daysRemaining: 21, sentence: {} }), null);
    assert.equal(bannerFor({ status: 'active', renewalDue: false, sentence: {} }), null);
    assert.equal(bannerFor(null), null);
  });

  it('⛔ expired and invalid CANNOT be dismissed', () => {
    // Both need an administrator to act. A dismissed banner is how that reaches
    // nobody until someone tries to add a firewall and cannot.
    assert.equal(bannerFor({ status: 'expired', sentence: {} }).dismissible, false);
    assert.equal(bannerFor({ status: 'invalid', sentence: {} }).dismissible, false);
    assert.equal(bannerFor({ status: 'grace', sentence: {} }).dismissible, true);
  });
});
