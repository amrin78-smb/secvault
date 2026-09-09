'use strict';
// tests/adapterFailedReadContract.test.js
//
// Pins CLAUDE.md's adapter contract: **getRules() must THROW on a retrieval
// failure and must never return []**.
//
// ⛔ WHY THIS EXISTS. lib/adapters/index.js's collectAndStore() DELETEs a
// device's firewall_rules rows and only then reinserts whatever getRules()
// returned. So `[]` from a FAILED pull does not "collect nothing" — it wipes
// the real ruleset, wipes every Phase 5 finding that cascades from it, and
// reports rulesCount: 0 as a successful collection. This is the mechanism that
// wiped PAKFood's 33 rules in August 2026.
//
// `[]` may therefore mean exactly ONE thing: this device genuinely has no
// rules. Every adapter has to keep three states apart:
//
//   1. rules were read            → return them
//   2. the rulebase is REALLY empty, and we have positive evidence of that
//                                 → return []
//   3. the read FAILED, or succeeded but produced nothing usable
//                                 → THROW
//
// State 3 is the one that regresses silently, because `[]` is a plausible
// answer rather than a crash — the same failed-read-as-a-fact class as
// hit_count's old `DEFAULT 0`. Every adapter below gets all three cases.
//
// ⛔ PLAIN Error, NOT CapabilityUnavailableError, for every getRules() case
// here. CapabilityUnavailableError means "the transport succeeded and only an
// OPTIONAL capability was unreadable", and it deliberately stops the poller
// counting the failure against device reachability. A rulebase is not an
// optional capability — every firewall has one — so a device that cannot show
// SecVault its rules is a device SecVault cannot manage, and that must keep
// counting. (getLicenses()/getHaStatus()/getVpnSessionSummary() are where that
// error type belongs; they are not tested here.)
//
// NO DEVICE IS CONTACTED. The Palo Alto and Sangfor adapter tests replace the
// transport module / the single command-runner method with stubs; every other
// test is a pure parser call.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const { PaloaltoAdapter } = require('../lib/adapters/paloalto');
const paApi = require('../lib/adapters/paloalto/api');

const cpParser = require('../lib/adapters/checkpoint/parser');
const fpParser = require('../lib/adapters/forcepoint/parser');
const sfParser = require('../lib/adapters/sangfor/parser');
const { SangforAdapter } = require('../lib/adapters/sangfor');

// These adapters log loudly on every fallback path, which is correct in
// production and pure noise here.
const realWarn = console.warn;
const realLog = console.log;
function muteConsole() {
  console.warn = () => {};
  console.log = () => {};
}
function restoreConsole() {
  console.warn = realWarn;
  console.log = realLog;
}

// ---------------------------------------------------------------------------
// Palo Alto (XML/API transport) — the LIVE one: 10 devices use this transport.
// ---------------------------------------------------------------------------

const PA_API_METHODS = [
  'getSecurityRules',
  'getSecurityRulesAnyVsys',
  'showPushedSharedPolicy',
  'getEffectiveSecurityPolicy',
  'showSystemInfo',
  'getRuleHitCount',
];

let paSaved = null;

function stubPaApi(overrides) {
  const defaults = {
    // No `rules` key at all = PAN-OS answered `<response status="success">
    // <result/></response>`, i.e. the xpath resolved to NOTHING. That is not
    // an empty rulebase.
    getSecurityRules: async () => ({}),
    getSecurityRulesAnyVsys: async () => '',
    showPushedSharedPolicy: async () => '',
    getEffectiveSecurityPolicy: async () => ({ raw: '', result: {} }),
    // multi-vsys "on" => hit-count enrichment is skipped (counts stay NULL).
    showSystemInfo: async () => ({ system: { 'multi-vsys': 'on' } }),
    getRuleHitCount: async () => ({}),
  };
  Object.assign(paApi, defaults, overrides || {});
}

function paAdapter() {
  const adapter = new PaloaltoAdapter({
    device: { id: 'pa-test-device', mgmt_ip: '10.0.0.1', mgmt_port: 443 },
    pool: {},
  });
  // Never touches credStore/the DB/the network.
  adapter._getConn = async () => ({
    host: '10.0.0.1',
    port: 443,
    apiKey: 'stub',
    allowSelfSignedSsl: true,
  });
  return adapter;
}

// A rules container holding one real entry, in the shape parser.parseRules()
// reads (default-vsys config-get).
const PA_ONE_RULE = { rules: { entry: [{ '@_name': 'allow-web', action: 'allow' }] } };

// The Panorama pushed-shared-policy shape, in the nesting
// parser.parseRulesDeep()'s deep walk recognises (a `rules` key whose parent
// key is `security`). Live-verified shape, per api.js's own notes.
const PA_PUSHED_ONE_RULE = {
  policy: {
    panorama: {
      'pre-rulebase': {
        security: { rules: { entry: [{ '@_name': 'panorama-pushed', action: 'allow' }] } },
      },
    },
  },
};

describe('Palo Alto API transport getRules() — failed read vs empty rulebase', () => {
  beforeEach(() => {
    paSaved = {};
    for (const m of PA_API_METHODS) paSaved[m] = paApi[m];
    muteConsole();
  });

  afterEach(() => {
    for (const m of PA_API_METHODS) paApi[m] = paSaved[m];
    restoreConsole();
  });

  it('returns the rules when the default vsys has them', async () => {
    stubPaApi({ getSecurityRules: async () => PA_ONE_RULE });
    const rules = await paAdapter().getRules();
    assert.equal(rules.length, 1);
    assert.equal(rules[0].rule_name, 'allow-web');
  });

  it('a hit-count failure never fails the pull and leaves hit_count UNMEASURED', async () => {
    stubPaApi({
      getSecurityRules: async () => PA_ONE_RULE,
      showSystemInfo: async () => ({ system: { 'multi-vsys': 'off' } }),
      getRuleHitCount: async () => {
        throw new Error('command rejected');
      },
    });
    const rules = await paAdapter().getRules();
    assert.equal(rules.length, 1);
    // NULL, never 0 — "we could not measure" is not "no traffic matched".
    assert.equal(rules[0].hit_count, null);
  });

  it('THROWS when nothing answers anywhere — never returns [] (PAKFood, Aug 2026)', async () => {
    stubPaApi({
      getSecurityRulesAnyVsys: async () => {
        throw new Error('any-vsys probe timed out');
      },
      showPushedSharedPolicy: async () => {
        throw new Error('pushed-policy probe timed out');
      },
      getEffectiveSecurityPolicy: async () => {
        throw new Error('effective-policy probe timed out');
      },
    });
    await assert.rejects(() => paAdapter().getRules(), /Refusing to overwrite/);
  });

  it('THROWS a plain Error, not a CapabilityUnavailableError — a rulebase is not an optional capability', async () => {
    stubPaApi({
      getSecurityRulesAnyVsys: async () => {
        throw new Error('boom');
      },
    });
    await assert.rejects(
      () => paAdapter().getRules(),
      (err) => {
        assert.ok(err instanceof Error);
        // deviceWasReached is what isCapabilityUnavailable() checks; a rules
        // failure MUST keep counting against device reachability.
        assert.notEqual(err.deviceWasReached, true);
        assert.notEqual(err.name, 'CapabilityUnavailableError');
        return true;
      }
    );
  });

  it('a failing any-vsys probe no longer short-circuits the Panorama fallback tiers', async () => {
    // THE REGRESSION. The catch around the any-vsys probe used to
    // `return rules` — i.e. [] — which both asserted "this device has no
    // rules" AND skipped all three Panorama tiers below it, the very paths
    // that collect a centrally-managed device.
    stubPaApi({
      getSecurityRulesAnyVsys: async () => {
        throw new Error('any-vsys probe failed');
      },
      showPushedSharedPolicy: async () => PA_PUSHED_ONE_RULE,
    });
    const rules = await paAdapter().getRules();
    assert.equal(rules.length, 1);
    assert.equal(rules[0].rule_name, 'panorama-pushed');
  });

  it('returns [] for a genuinely empty rulebase — a present container holding no entries', async () => {
    // `<result><rules/></result>`: the container EXISTS and is empty. That is
    // positive evidence of an empty rulebase, unlike a missing container.
    stubPaApi({ getSecurityRules: async () => ({ rules: '' }) });
    const rules = await paAdapter().getRules();
    assert.deepEqual(rules, []);
  });

  it('THROWS when the container is present and empty but a fallback probe FAILED', async () => {
    // An open question must never be recorded as the answer "none".
    stubPaApi({
      getSecurityRules: async () => ({ rules: '' }),
      showPushedSharedPolicy: async () => {
        throw new Error('pushed-policy probe failed');
      },
    });
    await assert.rejects(() => paAdapter().getRules(), /Refusing to overwrite/);
  });

  it('THROWS when the config-get returned no rules container at all', async () => {
    // Every probe answers cleanly with nothing, but the primary xpath resolved
    // to nothing either — no evidence of an empty rulebase exists.
    stubPaApi({});
    await assert.rejects(() => paAdapter().getRules(), /no `rules` container at all/);
  });
});

// ---------------------------------------------------------------------------
// Check Point (Mgmt API) — code-confirmed only. There is NO live Check Point
// management server in this deployment, so these pin the parser's decisions,
// not a verified field mapping.
// ---------------------------------------------------------------------------

describe('Check Point parseRulebasePages() — failed read vs empty rulebase', () => {
  beforeEach(muteConsole);
  afterEach(restoreConsole);

  it('returns the rules from a well-formed page', () => {
    const rules = cpParser.parseRulebasePages([
      { rulebase: [{ name: 'r1', 'rule-number': 1, action: 'accept' }], total: 1, to: 1 },
    ]);
    assert.equal(rules.length, 1);
    assert.equal(rules[0].rule_name, 'r1');
  });

  it('returns [] for a genuinely empty rulebase (an EMPTY rulebase array is not malformed)', () => {
    assert.deepEqual(cpParser.parseRulebasePages([{ rulebase: [], total: 0, to: 0 }]), []);
  });

  it('THROWS on a null page — api.js returns null for any HTTP-200 with a non-JSON body', () => {
    // This page used to be `continue`d WITHOUT being counted, so malformedPages
    // stayed 0, the warning never fired, and the caller got a silent [].
    assert.throws(() => cpParser.parseRulebasePages([null]), /rule collection failed/i);
  });

  it('THROWS on a page whose rulebase field is missing or the wrong type', () => {
    assert.throws(() => cpParser.parseRulebasePages([{ total: 0 }]), /rule collection failed/i);
    assert.throws(
      () => cpParser.parseRulebasePages([{ rulebase: 'not-an-array' }]),
      /rule collection failed/i
    );
  });

  it('THROWS rather than returning a PARTIAL ruleset when one page of several is malformed', () => {
    // A partial rulebase is not a rulebase: collectAndStore DELETEs then
    // reinserts, so returning the survivors silently truncates the real one.
    assert.throws(
      () =>
        cpParser.parseRulebasePages([
          { rulebase: [{ name: 'r1', action: 'accept' }], total: 2, to: 1 },
          null,
        ]),
      /partial rulebase is not a rulebase/
    );
  });

  it('THROWS when no pages were supplied at all', () => {
    assert.throws(() => cpParser.parseRulebasePages([]), /no evidence/i);
  });
});

describe('Check Point Ordered Layers — never pick an access layer positionally', () => {
  beforeEach(muteConsole);
  afterEach(restoreConsole);

  const layer = (name, ruleNames) => ({
    layerUid: `uid-${name}`,
    layerName: name,
    pages: [
      {
        rulebase: ruleNames.map((n, i) => ({ name: n, 'rule-number': i + 1, action: 'accept' })),
        total: ruleNames.length,
        to: ruleNames.length,
      },
    ],
  });

  it('collects EVERY layer, not layers[0]', () => {
    // Storing layer 1 as the whole rulebase is the packages[0] bug one level
    // down: every rule in layers 2..n simply did not exist for SecVault.
    const rules = cpParser.parseLayeredRulebasePages([
      layer('Network', ['n1', 'n2']),
      layer('Application', ['a1']),
    ]);
    assert.deepEqual(
      rules.map((r) => r.rule_name),
      ['n1', 'n2', 'a1']
    );
  });

  it('renumbers sequence_number continuously across layers and keeps layer provenance', () => {
    // Check Point restarts rule-number at 1 inside each layer, so keeping the
    // per-layer numbers would put several rules at position 1.
    const rules = cpParser.parseLayeredRulebasePages([
      layer('Network', ['n1', 'n2']),
      layer('Application', ['a1']),
    ]);
    assert.deepEqual(
      rules.map((r) => r.sequence_number),
      [1, 2, 3]
    );
    assert.equal(rules[2].raw_rule._secvault_access_layer, 'Application');
  });

  it('leaves the single-layer case byte-identical to parseRulebasePages()', () => {
    const one = layer('Network', ['n1', 'n2']);
    assert.deepEqual(cpParser.parseLayeredRulebasePages([one]), cpParser.parseRulebasePages(one.pages));
  });

  it('THROWS when ANY layer is unreadable — never collects the readable layers alone', () => {
    assert.throws(
      () =>
        cpParser.parseLayeredRulebasePages([
          layer('Network', ['n1']),
          { layerUid: 'uid-broken', layerName: 'Broken', pages: [null] },
        ]),
      /rule collection failed/i
    );
  });

  it('THROWS when no layers were supplied at all', () => {
    assert.throws(() => cpParser.parseLayeredRulebasePages([]), /no evidence/i);
  });
});

// ---------------------------------------------------------------------------
// Forcepoint (SMC REST) — code-confirmed only, no live SMC in this deployment.
// ---------------------------------------------------------------------------

describe('Forcepoint parsePolicy() — failed read vs empty policy', () => {
  beforeEach(muteConsole);
  afterEach(restoreConsole);

  it('returns the rules from a well-formed policy element', () => {
    const rules = fpParser.parsePolicy({ rules: [{ name: 'r1', action: 'allow' }] }, [], []);
    assert.equal(rules.length, 1);
  });

  it('returns [] for a genuinely empty policy — the known field is PRESENT but empty', () => {
    assert.deepEqual(fpParser.parsePolicy({ rules: [] }, [], []), []);
    assert.deepEqual(fpParser.parsePolicy({ fw_ipv4_access_rules: [] }, [], []), []);
  });

  it('THROWS on a null policy element — smc.getPolicy() returns null for a non-JSON HTTP-200', () => {
    // Used to console.warn and return []. The comment in index.js named this
    // exact failure and then guarded only the catch branch.
    assert.throws(() => fpParser.parsePolicy(null, [], []), /failed read, not an empty rulebase/);
    assert.throws(() => fpParser.parsePolicy(undefined, [], []), /failed read, not an empty rulebase/);
    assert.throws(() => fpParser.parsePolicy('<html>proxy</html>', [], []), /failed read/);
  });

  it('THROWS when neither known rules field exists — a field-name change, not an empty policy', () => {
    assert.throws(() => fpParser.parsePolicy({ some_new_field: [] }, [], []), /field names may have changed/);
  });
});

// ---------------------------------------------------------------------------
// Sangfor (SSH) — code-confirmed only. No live NGAF has ever been connected to
// this codebase, so the guard below is deliberately NEGATIVE (detect a CLI
// rejection) and never a positive parse of what a valid config looks like.
// ---------------------------------------------------------------------------

describe('Sangfor detectCliRejection() — non-empty output is not success', () => {
  it('detects a Cisco-flavoured rejection banner', () => {
    assert.ok(sfParser.detectCliRejection("% Invalid input detected at '^' marker."));
    assert.ok(sfParser.detectCliRejection('% Unknown command.'));
  });

  it('detects a Huawei-flavoured rejection banner', () => {
    assert.ok(sfParser.detectCliRejection("Error: Unrecognized command found at '^' position."));
  });

  it('detects permission/authorisation refusals', () => {
    assert.ok(sfParser.detectCliRejection('Permission denied.'));
    assert.ok(sfParser.detectCliRejection('Command not found'));
  });

  it('returns null for empty or non-string input rather than guessing', () => {
    assert.equal(sfParser.detectCliRejection(''), null);
    assert.equal(sfParser.detectCliRejection(null), null);
    assert.equal(sfParser.detectCliRejection(undefined), null);
    assert.equal(sfParser.detectCliRejection(42), null);
  });

  it('does NOT false-positive on a real config that merely mentions the words', () => {
    // A false rejection is itself a discarded real config, so the guard is
    // bounded to the two shapes a CLI actually answers a refused command with.
    const config = [
      'hostname NGAF-01',
      'version 8.0.85',
      'interface eth0',
      ' ip address 10.0.0.1 255.255.255.0',
      'object-group service error-reporting',
      ' description invalid input from partner is denied here',
      'policy 1 name allow-web',
      ' action permit',
      'policy 2 name deny-all',
      ' action deny',
      'end',
    ].join('\n');
    assert.equal(sfParser.detectCliRejection(config), null);
  });
});

describe('Sangfor getRules()/getConfig() — a rejection banner is not a config', () => {
  const CONFIG_COMMAND_COUNT = 3; // show running-config / display current-configuration / show configuration

  function sangforAdapter(runOne) {
    const adapter = new SangforAdapter({
      device: { id: 'sf-test-device', mgmt_ip: '10.0.0.2', mgmt_port: 22 },
      pool: {},
    });
    // Never touches credStore or SSH.
    adapter._getConn = async () => ({ conn: { host: '10.0.0.2' }, options: {} });
    adapter._runOne = async (_conn, _options, command) => runOne(command);
    return adapter;
  }

  beforeEach(muteConsole);
  afterEach(restoreConsole);

  it('THROWS when every config command is rejected — never caches the banner as the config', async () => {
    const seen = [];
    const adapter = sangforAdapter((command) => {
      seen.push(command);
      return "% Invalid input detected at '^' marker.";
    });
    await assert.rejects(() => adapter.getRules(), /rejected by the device's CLI/);
    // ...and it kept trying the other dialects instead of stopping at the first
    // non-empty output — that fallback chain is the whole point of the list.
    assert.equal(seen.length, CONFIG_COMMAND_COUNT);
  });

  it('getConfig() THROWS too, so hasUsableConfig() never sees a banner as a config', async () => {
    // Downstream, a stored banner makes hasUsableConfig() TRUE and compliance
    // scores every predicate `fail` instead of `na` — SecVault's blind spot
    // recorded as a fault on the firewall.
    const adapter = sangforAdapter(() => 'Error: Unrecognized command found.');
    await assert.rejects(() => adapter.getConfig(), /rejected by the device's CLI/);
  });

  it('falls through a rejected dialect to the one the device DOES accept', async () => {
    const adapter = sangforAdapter((command) =>
      command === 'display current-configuration'
        ? 'hostname NGAF-01\npolicy 1 name allow-web\n action permit\nend\n'
        : "% Invalid input detected at '^' marker."
    );
    const config = await adapter.getConfig();
    assert.equal(config.parsed.source_command, 'display current-configuration');
    assert.ok(config.raw.includes('hostname NGAF-01'));
  });

  it('returns [] when a real config WAS read but holds no parseable rule blocks', async () => {
    // The honest empty case: the device answered, the answer is just not
    // something this (deliberately conservative) parser recognises as rules.
    const adapter = sangforAdapter(() => 'hostname NGAF-01\nversion 8.0.85\nend\n');
    assert.deepEqual(await adapter.getRules(), []);
  });

  it('THROWS when SSH itself fails — that IS reachability evidence', async () => {
    const adapter = sangforAdapter(() => {
      throw new Error('ETIMEDOUT');
    });
    await assert.rejects(
      () => adapter.getRules(),
      (err) => {
        assert.match(err.message, /rule collection failed/i);
        assert.notEqual(err.deviceWasReached, true);
        return true;
      }
    );
  });
});
