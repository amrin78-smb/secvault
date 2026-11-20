// tests/cveVendorFilter.test.js
//
// ⛔ WHY THIS EXISTS. /vulnerability's Advisories and CVE Posture tabs each
// carried a hardcoded six-<option> vendor dropdown. Sophos shipped as the
// SEVENTH managed vendor in v2.233.0 and reached production in v2.236.1 — and
// neither filter ever offered it, so a Sophos advisory could be stored,
// matched, banded and counted while being unreachable from the one control on
// the page for narrowing to it. Nothing failed: the server side takes the
// `vendor` query param as a parameterised string and has always accepted
// `?vendor=sophos`. Only the dropdown was short.
//
// ⛔ THE LIST IS NOW DERIVED FROM THE REGISTRY (MANAGED_VENDOR_SLUGS), so the
// EIGHTH vendor cannot repeat this. What this file pins is that the derivation
// stays derived, and that it resolves to the right SET — a derivation from the
// wrong predicate would be just as wrong as a hardcoded list and much harder
// to see.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { VENDOR_META, MANAGED_VENDOR_SLUGS } = require('../components/devices/vendorMeta');
const { VENDOR_CPES } = require('../lib/feeds/nvd');

const REPO = path.join(__dirname, '..');
const TABS = [
  'components/vulnerability/AdvisoriesTab.js',
  'components/vulnerability/CvePostureTab.js',
];

const sorted = (a) => a.slice().sort();

describe('the CVE vendor filter offers exactly the vendors a CVE can be filed against', () => {
  it('⛔ MANAGED_VENDOR_SLUGS equals the VENDOR_CPES keys', () => {
    // ⛔ THE LOAD-BEARING ASSERTION, and deliberately against a registry in the
    // OTHER module system rather than against VENDOR_META again. A vendor is
    // filterable on these pages precisely when advisories can carry its slug,
    // which is what VENDOR_CPES decides. Checking the partition against itself
    // would pass for any predicate that happens to be self-consistent.
    assert.deepEqual(sorted(MANAGED_VENDOR_SLUGS), sorted(Object.keys(VENDOR_CPES)));
  });

  it('⛔ includes sophos — the omission this file was written for', () => {
    assert.ok(MANAGED_VENDOR_SLUGS.includes('sophos'));
  });

  it('⛔ EXCLUDES every monitoring-only vendor, and that is not an oversight', () => {
    // A syslog-only firewall has no adapter, no version parser and no CPEs, so
    // no advisory row can ever carry its slug. Offering it would be a control
    // that can only ever return "no results" — which an operator reads as
    // "this firewall has no vulnerabilities". Absent is the honest state.
    const monitoring = Object.keys(VENDOR_META).filter((s) => VENDOR_META[s].monitoringOnly);
    assert.ok(monitoring.length > 0, 'the partition must not be vacuous');
    for (const slug of monitoring) {
      assert.ok(!MANAGED_VENDOR_SLUGS.includes(slug), slug + ' must not be offered');
      assert.equal(VENDOR_CPES[slug], undefined, slug + ' must have no CPEs');
    }
  });

  it('⛔ is derived, not listed — neither tab hardcodes a vendor <option>', () => {
    // The defect was six literals. A future edit that "just adds Sophos" as a
    // seventh literal restores exactly the shape that went stale, so the
    // literal is what is banned, not the omission.
    for (const rel of TABS) {
      const src = fs.readFileSync(path.join(REPO, rel), 'utf8');
      for (const slug of Object.keys(VENDOR_META)) {
        assert.ok(
          !src.includes(`<option value="${slug}"`),
          `${rel} hardcodes an <option> for ${slug} — map over MANAGED_VENDOR_SLUGS instead`
        );
      }
      assert.ok(
        src.includes('MANAGED_VENDOR_SLUGS.map('),
        `${rel} must build its vendor options from MANAGED_VENDOR_SLUGS`
      );
      // ⛔ The dropdown and the Vendor column must name a vendor the SAME way.
      // Before this, the filter said "Fortinet" while every row under it said
      // "FortiGate" — the inconsistency vendorLabel()'s own docblock was
      // written to end, surviving in the control directly above the rows.
      assert.ok(
        /vendorLabel\(slug, \{ short: true \}\)/.test(src),
        `${rel} must label options with vendorLabel(slug, {short:true})`
      );
    }
  });
});
