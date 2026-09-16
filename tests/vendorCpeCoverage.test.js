'use strict';
// Pins the VENDOR_CPES table — which products this product calls "the firewall".
//
// ⛔ WHY THIS TEST EXISTS. Check Point collected SEVEN advisories for a firewall
// with a thirty-year CVE history, and nothing anywhere said so: the feed ran, the
// dashboard was green, and the Vulnerabilities page was simply almost empty. NVD
// files the Check Point gateway under ~15 product names accumulated across three
// decades of rebrands (FireWall-1 -> VPN-1 -> Security Gateway -> Quantum), and
// the table asked for four of them.
//
// There are two opposite ways to get this wrong and this file guards both:
//   UNDER-asking  — the original bug: a silent coverage hole that reads as "this
//                   firewall has no known vulnerabilities".
//   OVER-asking   — the tempting fix: a vendor-level wildcard. It works, it was
//                   tested live, and it pulls ~129 extra Check Point CVEs that
//                   are ZoneAlarm, Harmony, Capsule and SmartConsole — endpoint
//                   and consumer software that is not this device. Filing those
//                   against a firewall manufactures urgent work that is not real,
//                   which on an evidence-backed product is the worse failure.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'lib', 'feeds', 'nvd.js'), 'utf8');

// ⛔ The table is READ FROM THE MODULE, not regex-parsed out of the source. An
// earlier draft of this test parsed it with a regex that silently spanned vendor
// boundaries and reported 12 Check Point strings where there are 22 — a test
// that miscounts the thing it is guarding is worse than no test, because it
// fails for the wrong reason and gets "fixed" by loosening the assertion.
const { VENDOR_CPES: CPES } = require("../lib/feeds/nvd.js");

const ALL = Object.values(CPES).flat();

describe('the table is well-formed', () => {
  it('covers every supported vendor slug', () => {
    assert.deepEqual(
      Object.keys(CPES).sort(),
      ['checkpoint', 'cisco_asa', 'forcepoint', 'fortinet', 'paloalto', 'sangfor']
    );
  });

  it('every entry is a syntactically valid CPE 2.3 string', () => {
    for (const c of ALL) {
      assert.match(
        c,
        /^cpe:2\.3:[oah]:[a-z0-9_.-]+:[a-z0-9_.-]+(:\*){8}$/,
        c + ' is not a well-formed CPE 2.3 string'
      );
    }
  });

  it('has no duplicates', () => {
    for (const [vendor, list] of Object.entries(CPES)) {
      assert.equal(new Set(list).size, list.length, vendor + ' repeats a CPE string');
    }
  });

  it('every string names the vendor whose list it is in', () => {
    // A checkpoint string filed under sangfor would query the wrong vendor and
    // then store the results under the wrong `advisories.vendor`, which is
    // UNIQUE per cve_id and therefore not simply correctable later.
    const cpeVendor = { checkpoint: 'checkpoint', sangfor: 'sangfor', forcepoint: 'forcepoint' };
    for (const [slug, expected] of Object.entries(cpeVendor)) {
      for (const c of CPES[slug]) {
        assert.equal(c.split(':')[3], expected, c + ' is not a ' + expected + ' CPE');
      }
    }
  });
});

describe('⛔ NEVER a vendor-level wildcard', () => {
  it('no entry wildcards the PRODUCT field', () => {
    // The whole point of the table. `cpe:2.3:a:checkpoint:*` returns 129 CVEs,
    // most of which are endpoint and consumer software, and it was tested and
    // rejected. This is the shape a future "simplification" would take.
    for (const c of ALL) {
      const product = c.split(':')[4];
      assert.notEqual(product, '*', c + ' wildcards the product field');
      assert.notEqual(product, '', c + ' has an empty product field');
      assert.ok(product && product.length > 1, c + ' has a suspiciously short product');
    }
  });

  it('⛔ no Check Point ENDPOINT or CONSUMER product is queried', () => {
    // These are real Check Point products with real CVEs. None of them runs on
    // the firewall, and SecVault's Check Point adapter never talks to any of
    // them. Including one files an endpoint-agent vulnerability against a
    // firewall — a fabricated finding, dressed as an evidence-backed one.
    const NOT_THE_FIREWALL = [
      'zonealarm', 'harmony', 'capsule', 'sandblast', 'endpoint_security',
      'identity_agent', 'smartconsole', 'secureclient', 'ssl_network_extender',
      'remote_access_clients', 'integrity_client', 'session_authentication_agent',
    ];
    for (const c of CPES.checkpoint) {
      const product = c.split(':')[4];
      for (const banned of NOT_THE_FIREWALL) {
        assert.ok(
          !product.includes(banned),
          c + ' queries "' + banned + '", which is not the firewall'
        );
      }
    }
  });

  it('⛔ no Forcepoint NON-firewall product is queried', () => {
    // Forcepoint's CVE volume is dominated by email_security and web_security,
    // which are wholly separate products from the NGFW.
    for (const c of CPES.forcepoint) {
      const product = c.split(':')[4];
      for (const banned of ['email', 'web_security', 'data_loss', 'one_endpoint', 'cloud_security']) {
        assert.ok(!product.includes(banned), c + ' queries "' + banned + '", not the NGFW');
      }
    }
  });

  it('⛔ no Sangfor NON-firewall product is queried', () => {
    for (const c of CPES.sangfor) {
      const product = c.split(':')[4];
      for (const banned of ['vdi', 'atrust', 'operation_and_maintenance']) {
        assert.ok(!product.includes(banned), c + ' queries "' + banned + '", not the NGAF');
      }
    }
  });
});

describe('⛔ the gateway is covered under every name it has had', () => {
  it('Check Point carries the historic gateway product names', () => {
    // The original four-string list is what produced seven advisories. A future
    // tidy-up that drops "obsolete" names re-opens that hole for exactly the
    // customers running older appliances, who need them most.
    const products = CPES.checkpoint.map((c) => c.split(':')[4]);
    for (const required of ['firewall-1', 'vpn-1', 'security_gateway', 'gaia_os',
      'quantum_security_gateway_firmware']) {
      assert.ok(products.includes(required), 'Check Point no longer queries ' + required);
    }
    // firewall-1 alone is 43 of the ~107 measured CVEs.
    assert.ok(products.length >= 20, 'the Check Point list shrank to ' + products.length + ' products');
  });

  it('the MANAGEMENT plane is covered, because that is what the adapter connects to', () => {
    // CLAUDE.md: Check Point is reached via the management API on the management
    // SERVER, never the gateway. A management-server CVE is a CVE in something
    // SecVault authenticates to.
    const products = CPES.checkpoint.map((c) => c.split(':')[4]);
    assert.ok(
      products.some((p) => p.includes('management') || p === 'provider-1'),
      'no Check Point management-plane product is queried'
    );
    // Same reasoning for Forcepoint, which is SMC-only by design.
    assert.ok(
      CPES.forcepoint.some((c) => c.includes('management_center') || c.includes('security_manager')),
      'no Forcepoint SMC product is queried'
    );
  });

  it('⛔ the FlexEdge rebrand is still asked for even though it returns nothing', () => {
    // Measured 0 from both NVD and CIRCL on 2026-09-16. Kept deliberately: a
    // string that returns nothing costs one request per cycle, while a string we
    // removed costs the first advisory ever filed under the new brand.
    assert.ok(
      CPES.forcepoint.some((c) => c.includes('flexedge_secure_sd-wan')),
      'the FlexEdge rebrand CPE was removed — it will be needed the day it is used'
    );
  });
});

describe('the verification note travels with the data', () => {
  it('each Check Point string records the CVE count it was probed at', () => {
    // This codebase requires a live probe before a parser or query is written.
    // Recording the number beside the string is what lets the next person tell a
    // verified entry from a guessed one without re-probing all 22.
    const start = SRC.indexOf('  checkpoint: [');
    const block = SRC.slice(start, SRC.indexOf('\n  ],', start));
    const lines = block.split('\n').filter((l) => l.includes('cpe:2.3:'));
    const annotated = lines.filter((l) => /\/\/\s*\d+/.test(l));
    assert.equal(
      annotated.length, lines.length,
      (lines.length - annotated.length) + ' Check Point CPE strings carry no probed count'
    );
  });
});
