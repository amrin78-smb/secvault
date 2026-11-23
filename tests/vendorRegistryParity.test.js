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
  MANAGED_VENDOR_SLUGS,
  ACCESS_METHODS,
  CREDENTIAL_TYPES,
  buildCredentialPlaintext,
} = require('../components/devices/vendorMeta');
const { MONITORING_ONLY_METHOD, isMonitoringOnly } = require('../lib/monitoringOnly');

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

// ⛔ THE METHODS AN ADAPTER MUST EXIST FOR — accessMethods minus `syslog`.
//
// Since v2.237.0 every MANAGED vendor also offers `syslog`, meaning "this
// particular firewall has no management connection" (an operator who can read
// a FortiGate's logs but cannot log into it). That method deliberately has NO
// adapter, NO credential type and NO port, so comparing the raw accessMethods
// keys against ADAPTERS would now fail for every vendor at once.
//
// ⛔ IT IS SUBTRACTED HERE AND THEN ASSERTED SEPARATELY, NEVER SIMPLY WAIVED.
// `describe('⛔ syslog-only is a DEVICE state…')` below pins every property
// that makes the subtraction safe — above all that it is never a vendor's
// default, which would convert a legacy fleet to log-only in silence.
const connectableMethods = (slug) =>
  Object.keys(VENDOR_META[slug].accessMethods)
    .filter((m) => m !== MONITORING_ONLY_METHOD).sort();

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
          connectableMethods(slug),
          'ADAPTERS.' + slug + "'s inner keys must equal VENDOR_META." +
            slug + ".accessMethods MINUS '" + MONITORING_ONLY_METHOD +
            "' — the form stores the key it offers in devices.mgmt_method and " +
            'dispatch has to honour that pick. The one exception is the ' +
            'syslog method, which by design dispatches to nothing because ' +
            'SecVault never connects to such a device.'
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
        // ⛔ CONNECTABLE methods only. The syslog method has credentialType
        // null and defaultPort null ON PURPOSE — a port there would be written
        // to `mgmt_port` and would claim SecVault talks to something on it,
        // and a credentialType would have credStore store a secret for a
        // device nothing authenticates to. Its shape is asserted in full in
        // its own describe block below.
        for (const method of connectableMethods(slug)) {
          const config = meta.accessMethods[method];
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
// v2.237.0 — "add any brand as syslog-only".
//
// ⛔ WHAT THIS IS GUARDING. An operator can see a firewall in the discovered
// list and have no way to log into it. Before this, that firewall could only
// enter the inventory if its VENDOR had no adapter (`juniper`, `sonicwall`);
// a FortiGate nobody had credentials for had to stay out, so its syslog landed
// with `device_id NULL`. Now every managed vendor offers `mgmt_method =
// 'syslog'` as well.
//
// ⛔ THE DANGER IS NOT THE NEW METHOD, IT IS THE TWO FACTS IT SITS BETWEEN.
// `VENDOR_META[slug].monitoringOnly` says the VENDOR is unmanageable;
// `mgmt_method === 'syslog'` says ONE DEVICE is unmanaged. Collapse them in
// either direction and the product breaks in opposite ways:
//   • reading the vendor flag as the device state → a log-only FortiGate is
//     treated as fully assessed, i.e. silently the cleanest device on the
//     fleet (lib/monitoringOnly.js's own header is about exactly this);
//   • reading the device state as the vendor flag → `fortinet` drops out of
//     MANAGED_VENDOR_SLUGS, and with it the CVE vendor filter and VENDOR_CPES,
//     so every managed FortiGate stops being assessed because ONE of them has
//     no credentials.
// Both directions are asserted below.
// ─────────────────────────────────────────────────────────────────────────────
describe('⛔ syslog-only is a DEVICE state, not a vendor downgrade', () => {
  it('⛔ EVERY managed vendor offers it — a half-rolled-out registry is the bug this file exists for', () => {
    // If a vendor is ever deliberately excluded, it must be a NAMED exemption
    // with a reason here, never a silent omission: the operator meets the gap
    // as "this brand cannot be added at all", with nothing on screen saying
    // why, which is indistinguishable from the pre-v2.237.0 behaviour.
    assert.ok(MANAGED_VENDOR_SLUGS.length >= 7, 'the partition must not be vacuous');
    for (const slug of MANAGED_VENDOR_SLUGS) {
      assert.ok(
        Object.prototype.hasOwnProperty.call(
          VENDOR_META[slug].accessMethods, MONITORING_ONLY_METHOD
        ),
        slug + ' does not offer the ' + MONITORING_ONLY_METHOD + ' method, so a '
          + slug + ' firewall nobody can log into still cannot be added'
      );
    }
  });

  it('⛔ it is NEVER a vendor default — this one would stop a legacy fleet collecting', () => {
    // THE most dangerous single assertion in this file. DEFAULT_METHOD is what
    // getAdapter() falls back to when devices.mgmt_method is null or
    // unrecognised — which is every row written before the access-method
    // selector existed. A managed vendor whose default became `syslog` would
    // make collectAndStore() take its monitoring-only early return for that
    // whole fleet: no adapter call, no error, `last_collected_at` left NULL
    // for ever, and every device reading as deliberately log-only.
    for (const slug of MANAGED_VENDOR_SLUGS) {
      assert.notEqual(
        VENDOR_META[slug].defaultAccessMethod, MONITORING_ONLY_METHOD,
        slug + '.defaultAccessMethod must not be ' + MONITORING_ONLY_METHOD
      );
      assert.notEqual(
        DEFAULT_METHOD[slug], MONITORING_ONLY_METHOD,
        'DEFAULT_METHOD.' + slug + ' must not be ' + MONITORING_ONLY_METHOD
      );
    }
  });

  it('⛔ dispatch can never pick it: no adapter, for any vendor', () => {
    // getAdapter() guards on isMonitoringOnly() BEFORE it reaches the ADAPTERS
    // map, so this is belt-and-braces — but it is the half that holds if a
    // future caller reaches dispatch another way. An adapter registered under
    // this key would be a management connection to a device defined as having
    // none.
    for (const slug of Object.keys(ADAPTERS)) {
      assert.equal(
        ADAPTERS[slug][MONITORING_ONLY_METHOD], undefined,
        'ADAPTERS.' + slug + '.' + MONITORING_ONLY_METHOD + ' must not exist'
      );
    }
  });

  it('⛔ the method is recognised as monitoring-only on a MANAGED vendor', () => {
    // The device-level test must not consult the vendor at all. isMonitoringOnly
    // reads `mgmt_method` only, so this passes for `fortinet` exactly as it
    // does for `juniper` — which is the property the whole feature rests on.
    for (const slug of MANAGED_VENDOR_SLUGS) {
      assert.equal(
        isMonitoringOnly({ vendor: slug, mgmt_method: MONITORING_ONLY_METHOD }), true,
        'a ' + slug + ' device on ' + MONITORING_ONLY_METHOD + ' must read as monitoring-only'
      );
      // ...and a connectable method on the same vendor must NOT.
      assert.equal(
        isMonitoringOnly({ vendor: slug, mgmt_method: DEFAULT_METHOD[slug] }), false
      );
    }
  });

  it('⛔ offering it does NOT downgrade the vendor', () => {
    // The opposite error, and the more expensive one: `fortinet` must stay in
    // MANAGED_VENDOR_SLUGS (which drives the CVE vendor filter and is asserted
    // against VENDOR_CPES by tests/cveVendorFilter.test.js), must keep its
    // adapter, and must keep its DEFAULT_METHOD. One firewall without
    // credentials says nothing about the vendor's assessability.
    for (const slug of MANAGED_VENDOR_SLUGS) {
      assert.equal(VENDOR_META[slug].monitoringOnly, undefined,
        slug + ' must not carry the VENDOR-level monitoringOnly flag');
      assert.ok(ADAPTERS[slug], slug + ' must keep its adapter');
      assert.ok(DEFAULT_METHOD[slug], slug + ' must keep its DEFAULT_METHOD');
    }
    // And the monitoring-only vendors must NOT have crept into the managed set.
    for (const slug of MONITORING_SLUGS) {
      assert.ok(!MANAGED_VENDOR_SLUGS.includes(slug),
        slug + ' is monitoring-only and must not be in MANAGED_VENDOR_SLUGS');
    }
  });

  it('⛔ it takes no credential and claims no port, on every vendor that offers it', () => {
    // `credentialShape: 'none'` is load-bearing in two places that are easy to
    // miss: buildCredentialPlaintext() falls through to its userpass branch
    // without it and stores `{"username":"","password":""}` — an EMPTY
    // credential, which reads as "credentials were supplied and are blank" —
    // and POST /api/devices REFUSES a supplied credential on the strength of
    // this exact field.
    for (const slug of VENDOR_SLUGS) {
      const config = VENDOR_META[slug].accessMethods[MONITORING_ONLY_METHOD];
      if (!config) continue;
      assert.equal(config.credentialShape, 'none', slug);
      assert.equal(config.credentialType, null, slug + ' must declare no credentialType');
      assert.equal(config.defaultPort, null,
        slug + ' must declare no defaultPort — it would be written to mgmt_port');
      assert.equal(
        buildCredentialPlaintext(slug, MONITORING_ONLY_METHOD,
          { username: 'a', password: 'b', secret: 'c' }),
        null,
        slug + ' must never build a credential for ' + MONITORING_ONLY_METHOD
      );
    }
  });

  it('⛔ ONE shared config object, so no two vendors can describe it differently', () => {
    // Nine vendors each with their own literal would drift, and the drift
    // would be a vendor whose log-only method quietly carries a port or a
    // credential type. Identity, not deep equality.
    const offered = VENDOR_SLUGS
      .filter((s) => VENDOR_META[s].accessMethods[MONITORING_ONLY_METHOD]);
    assert.ok(offered.length >= 9, 'expected every vendor to offer it');
    const first = VENDOR_META[offered[0]].accessMethods[MONITORING_ONLY_METHOD];
    for (const slug of offered) {
      assert.equal(
        VENDOR_META[slug].accessMethods[MONITORING_ONLY_METHOD], first,
        slug + ' uses its own syslog config object instead of the shared one'
      );
    }
  });

  it('⛔ ACCESS_METHODS covers every method of EVERY vendor, not just the managed ones', () => {
    // Roadmap row 6: ACCESS_METHODS was ['smc','api','ssh'] from v2.236.0 to
    // v2.237.0 while its own comment called itself "the only mgmt_method
    // values that may be stored" and `juniper` stored 'syslog'. It survived
    // because the per-vendor loop above runs over MANAGED_SLUGS only, so no
    // monitoring-only vendor's method was ever checked against it — a guard
    // that could not fire over the single value it did not know.
    for (const slug of VENDOR_SLUGS) {
      for (const method of Object.keys(VENDOR_META[slug].accessMethods)) {
        assert.ok(
          ACCESS_METHODS.includes(method),
          slug + '.' + method + ' is not in ACCESS_METHODS'
        );
      }
    }
    // The other direction: a value nothing offers is a stale entry.
    const offeredEverywhere = new Set(
      VENDOR_SLUGS.flatMap((s) => Object.keys(VENDOR_META[s].accessMethods))
    );
    for (const method of ACCESS_METHODS) {
      assert.ok(offeredEverywhere.has(method),
        'ACCESS_METHODS lists "' + method + '", which no vendor offers');
    }
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
    // ⛔ CONNECTABLE methods, not every key: since v2.237.0 `syslog` sits
    // beside `api` here as it does on every managed vendor. The fact being
    // pinned is that SSH is not offered as a way to MANAGE this appliance,
    // which is unchanged — asserting the raw key list would make this test
    // fail every time the log-only method is rolled out to a vendor.
    assert.deepEqual(connectableMethods('sophos'), ['api']);
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
