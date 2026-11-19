// tests/vendorRegistryParity.test.js
//
// ⛔ WHY THIS EXISTS. CLAUDE.md has stated this invariant since the
// access-method selector shipped — "Two registries, deliberately duplicated —
// keep them in step" — and NOTHING enforced it. The duplication is not
// accidental and cannot be removed: `components/devices/vendorMeta.js` is an ES
// module that client components (DeviceForm, CredentialForm) import, while
// `lib/adapters/index.js` is require()d by services/engine-worker.js under
// plain node, which cannot require ESM. So the same facts are written twice, in
// two module systems, and both files say in their own comments "keep the two in
// step" — which is a hope, not an invariant.
//
// Drift here is a SILENT RUNTIME BUG with no error anywhere:
//   • a slug in VENDOR_META but not ADAPTERS  → the Add Device form offers a
//     vendor that getAdapter() throws "Unsupported vendor" on at collection
//     time, long after the device row was written.
//   • a slug in ADAPTERS but not VENDOR_META  → vendorLabel() falls back to the
//     raw dispatch key, so the fleet table renders `cisco_asa`-style internals.
//   • an accessMethods key with no ADAPTERS entry → the form stores that
//     mgmt_method, dispatch does not recognise it, and getAdapter() silently
//     falls back to DEFAULT_METHOD — i.e. the operator picks SSH and gets the
//     API transport, with no error and a credential of the wrong shape.
//   • DEFAULT_METHOD disagreeing with defaultAccessMethod → the form
//     preselects one transport and legacy rows (mgmt_method null) collect over
//     the other.
//
// ⛔ These assertions are over EVERY vendor, not the newest one. The failure
// mode is a half-finished edit to a registry, and which vendor is half-finished
// is not knowable in advance.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { ADAPTERS, DEFAULT_METHOD } = require('../lib/adapters');

// Node resolves require() of an ES module natively on the dev box (Node 22),
// and this is already the convention tests/vendorPsirtGate.test.js uses for
// THIS EXACT FILE. `await import()` also works but forces every assertion into
// an async test and warns MODULE_TYPELESS_PACKAGE_JSON on each run.
const {
  VENDOR_META,
  VENDOR_SLUGS,
  VENDOR_SHORT_LABEL,
  ACCESS_METHODS,
  CREDENTIAL_TYPES,
  buildCredentialPlaintext,
} = require('../components/devices/vendorMeta');
const { MONITORING_ONLY_METHOD } = require('../lib/monitoringOnly');

const sorted = (o) => Object.keys(o).sort();

// ⛔ THE PARTITION, DERIVED FROM VENDOR_META RATHER THAN LISTED. A hardcoded
// list of monitoring-only slugs would be a third registry to keep in step with
// the two this file exists to compare, and it would go stale the moment a
// vendor is promoted to managed — silently, because the promoted vendor would
// keep being checked against the weaker rules.
const MANAGED_SLUGS = Object.keys(VENDOR_META)
  .filter((s) => !VENDOR_META[s].monitoringOnly).sort();
const MONITORING_SLUGS = Object.keys(VENDOR_META)
  .filter((s) => VENDOR_META[s].monitoringOnly).sort();

describe('the two vendor registries agree', () => {
  it('⛔ the slug sets are identical', () => {
    // Deliberately not a subset check in either direction: a slug missing from
    // either side is a bug, and they are different bugs (see the header).
    // ⛔ MANAGED vendors only. A MONITORING-ONLY vendor is in VENDOR_META and
    // deliberately NOT in ADAPTERS — it is in the inventory for its LOGS and
    // SecVault never opens a management connection to it. That asymmetry is
    // asserted from BOTH ends below rather than waived here: a managed vendor
    // may not silently lose its adapter, and a monitoring-only one may not
    // silently gain one without being promoted on purpose.
    assert.deepEqual(
      sorted(ADAPTERS),
      MANAGED_SLUGS,
      'ADAPTERS (lib/adapters/index.js) and the MANAGED half of VENDOR_META ' +
        '(components/devices/vendorMeta.js) list different vendor slugs'
    );
  });

  it('⛔ a monitoring-only vendor has NO adapter and NO default method', () => {
    // ⛔ THE OTHER END OF THE ASYMMETRY. Without this, deleting an adapter
    // would be "fixed" by marking its vendor monitoring-only and the build
    // would stay green while the fleet silently stopped being collected from.
    assert.ok(MONITORING_SLUGS.length > 0, 'the partition must not be vacuous');
    for (const slug of MONITORING_SLUGS) {
      assert.equal(ADAPTERS[slug], undefined, slug + ' must have no adapter');
      assert.equal(DEFAULT_METHOD[slug], undefined, slug + ' must have no DEFAULT_METHOD');
      const meta = VENDOR_META[slug];
      assert.deepEqual(Object.keys(meta.accessMethods), [MONITORING_ONLY_METHOD],
        slug + ' must offer exactly the syslog method and nothing else');
      assert.equal(meta.defaultAccessMethod, MONITORING_ONLY_METHOD);
      // ⛔ `credentialShape: 'none'` or buildCredentialPlaintext falls through
      // to its userpass branch and stores an EMPTY credential.
      assert.equal(meta.accessMethods[MONITORING_ONLY_METHOD].credentialShape, 'none');
      assert.equal(buildCredentialPlaintext(slug, MONITORING_ONLY_METHOD,
        { username: 'a', password: 'b' }), null,
        slug + ' must never build a credential');
    }
  });

  it('⛔ DEFAULT_METHOD covers exactly the same slugs', () => {
    assert.deepEqual(
      sorted(DEFAULT_METHOD),
      sorted(ADAPTERS),
      'DEFAULT_METHOD and ADAPTERS list different vendor slugs — a vendor with no ' +
        'DEFAULT_METHOD entry cannot collect from a legacy row whose mgmt_method is null'
    );
  });

  it('VENDOR_SLUGS is derived from VENDOR_META and has not been hand-maintained', () => {
    assert.deepEqual(VENDOR_SLUGS.slice().sort(), sorted(VENDOR_META));
  });

  // One test per vendor rather than a loop inside one test: a failure then
  // NAMES the vendor in the TAP output instead of reporting "the registries
  // disagree" and leaving the reader to find which one.
  for (const slug of MANAGED_SLUGS) {
    describe(slug, () => {
      it('⛔ the access-method keys match on both sides', () => {
        const meta = VENDOR_META[slug];
        assert.ok(meta.accessMethods, slug + ' declares no accessMethods');
        assert.deepEqual(
          sorted(ADAPTERS[slug] || {}),
          sorted(meta.accessMethods),
          'ADAPTERS.' + slug + "'s inner keys must equal VENDOR_META." +
            slug + '.accessMethods — the form stores the key it offers in ' +
            'devices.mgmt_method and dispatch has to honour that pick'
        );
      });

      it('⛔ the default access method matches on both sides', () => {
        assert.equal(
          DEFAULT_METHOD[slug],
          VENDOR_META[slug].defaultAccessMethod,
          'DEFAULT_METHOD.' + slug + ' and VENDOR_META.' + slug +
            '.defaultAccessMethod disagree — the form would preselect one ' +
            'transport while legacy rows collect over the other'
        );
      });

      it('⛔ the default access method is a real adapter key', () => {
        // Checked independently of the equality above: the two registries can
        // agree with each other and still both name a method no adapter
        // implements, which is an undispatchable vendor rather than drift.
        const byMethod = ADAPTERS[slug] || {};
        assert.ok(
          Object.prototype.hasOwnProperty.call(byMethod, DEFAULT_METHOD[slug]),
          'DEFAULT_METHOD.' + slug + ' is "' + DEFAULT_METHOD[slug] +
            '", which is not a key of ADAPTERS.' + slug
        );
        assert.equal(typeof byMethod[DEFAULT_METHOD[slug]], 'function');
      });

      it('every access method dispatches to an adapter class', () => {
        for (const method of Object.keys(ADAPTERS[slug] || {})) {
          assert.equal(
            typeof ADAPTERS[slug][method],
            'function',
            'ADAPTERS.' + slug + '.' + method + ' is not a constructor'
          );
        }
      });

      it('⛔ has a short label for narrow table columns', () => {
        // vendorLabel(slug, {short:true}) falls back to the full label and then
        // to the raw slug, so a missing entry renders an internal dispatch key
        // in the fleet table — the defect vendorLabel() was written to fix.
        assert.equal(
          typeof VENDOR_SHORT_LABEL[slug],
          'string',
          slug + ' has no VENDOR_SHORT_LABEL entry'
        );
        assert.ok(VENDOR_SHORT_LABEL[slug].length > 0);
      });

      it('declares a label, a connection shape and per-method credentials', () => {
        const meta = VENDOR_META[slug];
        assert.ok(meta.label && meta.label.length > 0, slug + ' has no label');
        assert.ok(
          meta.connection === 'smc' || meta.connection === 'mgmt',
          slug + ' has an unrecognised connection shape: ' + meta.connection
        );
        for (const [method, config] of Object.entries(meta.accessMethods)) {
          assert.ok(
            ACCESS_METHODS.includes(method),
            slug + '.' + method + ' is not in ACCESS_METHODS'
          );
          assert.ok(
            CREDENTIAL_TYPES.includes(config.credentialType),
            slug + '.' + method + ' credentialType "' + config.credentialType +
              '" is not in CREDENTIAL_TYPES — credStore would store a type ' +
              'nothing reads back'
          );
          assert.equal(
            typeof config.defaultPort,
            'number',
            slug + '.' + method + ' has no numeric defaultPort'
          );
        }
      });

      it('⛔ no VENDOR_SHORT_LABEL entry is orphaned', () => {
        // The other direction: a short label for a slug no registry carries is
        // a vendor that was removed from one place and not the other.
        assert.ok(VENDOR_META[slug], slug + ' has a short label but no VENDOR_META entry');
      });
    });
  }

  it('⛔ VENDOR_SHORT_LABEL carries no slug the registries do not', () => {
    assert.deepEqual(sorted(VENDOR_SHORT_LABEL), sorted(VENDOR_META));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Sophos (v2.232.0). The three facts below are measured, not conventional, and
// each has an obvious-looking "correction" that would break the product
// silently. connectors.md 13b is the evidence; this pins it.
// ─────────────────────────────────────────────────────────────────────────────
describe('⛔ sophos — the three registry facts that are not arbitrary', () => {
  it('has exactly ONE access method, api, although the adapter also speaks SSH', () => {
    // SSH alone cannot list rules on SFOS, so it is not a standalone way to
    // manage the device. The adapter uses it internally for getVersion /
    // getHaStatus / getDiskUsage and falls back to the rest_api credential.
    assert.deepEqual(Object.keys(ADAPTERS.sophos), ['api']);
    assert.deepEqual(Object.keys(VENDOR_META.sophos.accessMethods), ['api']);
  });

  it('⛔ credentialShape is userpass, NEVER apikey_or_userpass', () => {
    // SFOS has no API-key auth mode at all — the XML API authenticates with a
    // username and password inside the body of every request. An api-key field
    // would be a credential input that cannot work.
    const api = VENDOR_META.sophos.accessMethods.api;
    assert.equal(api.credentialShape, 'userpass');
    assert.notEqual(api.credentialShape, 'apikey_or_userpass');
    assert.equal(
      api.secretLabel,
      undefined,
      'a secretLabel implies a single-secret / api-key input, which SFOS has no auth mode for'
    );
  });

  it('⛔ defaultPort is 4444 (the SFOS web-admin port), not 443', () => {
    assert.equal(VENDOR_META.sophos.accessMethods.api.defaultPort, 4444);
  });

  it('uses the mgmt_ip/mgmt_port connection shape and the rest_api credential type', () => {
    assert.equal(VENDOR_META.sophos.connection, 'mgmt');
    assert.equal(VENDOR_META.sophos.accessMethods.api.credentialType, 'rest_api');
  });

  it('is labelled for the product, not the dispatch key', () => {
    assert.equal(VENDOR_META.sophos.label, 'Sophos Firewall (SFOS)');
    assert.equal(VENDOR_SHORT_LABEL.sophos, 'Sophos');
  });
});
