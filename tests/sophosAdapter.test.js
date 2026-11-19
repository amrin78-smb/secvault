'use strict';
// Sophos SFOS adapter, pinned against REAL CAPTURED DEVICE RESPONSES.
//
// ⛔ Every fixture is verbatim output from a live SFOS 22.0.3 MR-3-Build576
// appliance (2026-11-19). The XML entity names were discovered by PROBING 38
// candidates rather than read from documentation — 24 answered, 11 returned
// code 529, and that sweep is why this adapter has no getLicenses().
//
// The cases that matter most here are the REFUSALS. An adapter that returns a
// plausible wrong answer about a firewall is worse than one that declines, and
// three of this vendor's shapes make that easy to get wrong: an error arrives
// as HTTP 200, an empty collection looks like an error, and rule order is a
// linked list with no sequence number.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const api = require('../lib/adapters/sophos/api');
const parser = require('../lib/adapters/sophos/parser');
const consoleClient = require('../lib/adapters/sophos/console');
const SophosAdapter = require('../lib/adapters/sophos');
const { XML, ERRORS, CONSOLE } = require('./fixtures/sophosApi');

const read = (entity) => api.interpretResponse(api.parseXml(XML[entity]), entity);

describe('Sophos API — three response shapes, only one is an error', () => {
  it('reads real data', () => {
    const r = read('FirewallRule');
    assert.equal(r.records.length, 3);
    assert.equal(r.empty, false);
    assert.equal(r.apiVersion, '2200.1');
  });

  // ⛔ `<Status>No. of records Zero.</Status>` — note NO code attribute. This
  // is the device MEASURING that a collection is empty, which is a real state
  // on a newly provisioned appliance.
  it('reports a genuinely empty collection as empty, not as a failure', () => {
    const r = read('UnicastRoute');
    assert.equal(r.empty, true);
    assert.deepEqual(r.records, []);
  });

  // ⛔ THE BOUNDARY THIS WHOLE FILE EXISTS FOR. Both of these arrive as
  // HTTP 200. Read as an empty list, the first would make collectAndStore
  // DELETE a device's entire rulebase and store nothing in its place.
  it('throws — never returns empty — when the API is not enabled', () => {
    assert.throws(
      () => api.interpretResponse(api.parseXml(ERRORS.apiNotEnabled), 'FirewallRule'),
      /532/,
      'a 532 must name its cause, not read as an empty rulebase'
    );
  });

  // ⛔ A per-entity failure NESTS INSIDE a successful login, so status has to
  // be checked at both levels. Authentication succeeding says nothing about
  // whether the read succeeded.
  it('throws on a per-entity error even though the login succeeded', () => {
    assert.match(api.parseXml(ERRORS.unknownEntity).Response.Login.status, /Successful/);
    assert.throws(
      () => api.interpretResponse(api.parseXml(ERRORS.unknownEntity), 'Licence'),
      /529/
    );
  });

  it('throws when the entity is not echoed back at all', () => {
    assert.throws(
      () => api.interpretResponse(api.parseXml(XML.Zone), 'FirewallRule'),
      /no <FirewallRule> element/
    );
  });

  // ⛔ A single record must still arrive as an array: a rulebase with exactly
  // one rule is a real state, and code that iterated a bare object would walk
  // its KEYS as rules.
  it('returns a single record as a one-element array', () => {
    const r = read('AdminSettings');
    assert.ok(Array.isArray(r.records));
    assert.equal(r.records.length, 1);
  });
});

describe('Sophos API — the password never reaches an error string', () => {
  // ⛔ SFOS puts the credential INSIDE the request body, which means inside the
  // request URL. node-fetch embeds the full URL in its error messages, and
  // adapter errors surface in engine.log AND in the /api/devices/[id]/test
  // response body. paloalto/api.js records this exact leak happening.
  it('redacts the secret, the reqxml parameter and the XML element', () => {
    const secret = 'Sup3rSecret!';
    const leak = `request to https://10.0.0.1:4444/webconsole/APIController`
      + `?reqxml=%3CRequest%3E%3CPassword%3E${encodeURIComponent(secret)}%3C%2FPassword%3E failed`;
    const safe = api.redactSecrets(leak, [secret]);
    assert.ok(!safe.includes(secret));
    assert.ok(!safe.includes(encodeURIComponent(secret)));
    assert.match(safe, /reqxml=\*\*\*/);
  });

  // ⛔ The parameter scrub is the half that matters: it removes the credential
  // even when the caller forgot to pass the secret through, which is the case
  // that actually bites.
  it('scrubs reqxml even when told about no secrets at all', () => {
    const leak = 'GET https://h:4444/webconsole/APIController?reqxml=%3CPassword%3Ehunter2 failed';
    assert.ok(!api.redactSecrets(leak, []).includes('hunter2'));
  });

  it('redacts a raw XML body', () => {
    const safe = api.redactSecrets('<Login><Password>hunter2</Password></Login>', []);
    assert.ok(!safe.includes('hunter2'));
  });
});

describe('Sophos rules — order is a linked list with no sequence number', () => {
  const rules = parser.parseFirewallRules(read('FirewallRule').records);

  // ⛔ Verified on the appliance: Lab-Deny is Position=Top, the auto-added MTA
  // rule follows it, and Lab follows that. Nothing in the XML states 1/2/3.
  it('reconstructs the real order from the Position/After chain', () => {
    assert.deepEqual(rules.map((r) => r.rule_name),
      ['Lab-Deny', 'Auto added firewall policy for MTA', 'Lab']);
    assert.deepEqual(rules.map((r) => r.sequence_number), [1, 2, 3]);
  });

  // ⛔ Order decides every access-path, segmentation and shadow verdict, so a
  // chain that does not reconstruct is REFUSED rather than guessed at.
  const chainCases = [
    ['an unhandled Position value',
      [{ Name: 'a', Position: 'Bottom', NetworkPolicy: {} }], /Position="Bottom"/],
    ['no Top rule',
      [{ Name: 'a', Position: 'After', After: { Name: 'b' }, NetworkPolicy: {} }], /Top/],
    ['two Top rules',
      [{ Name: 'a', Position: 'Top', NetworkPolicy: {} },
       { Name: 'b', Position: 'Top', NetworkPolicy: {} }], /2 rules at Position="Top"/],
    ['two rules claiming the same predecessor',
      [{ Name: 'a', Position: 'Top', NetworkPolicy: {} },
       { Name: 'b', Position: 'After', After: { Name: 'a' }, NetworkPolicy: {} },
       { Name: 'c', Position: 'After', After: { Name: 'a' }, NetworkPolicy: {} }], /both follow/],
    ['a duplicate rule name',
      [{ Name: 'a', Position: 'Top', NetworkPolicy: {} },
       { Name: 'a', Position: 'After', After: { Name: 'a' }, NetworkPolicy: {} }], /two rules named/],
    ['an unreachable rule',
      [{ Name: 'a', Position: 'Top', NetworkPolicy: {} },
       { Name: 'b', Position: 'After', After: { Name: 'ghost' }, NetworkPolicy: {} }], /covers 1 of 2/],
  ];
  for (const [label, input, pattern] of chainCases) {
    it(`refuses to order a rulebase with ${label}`, () => {
      assert.throws(() => parser.parseFirewallRules(input), pattern);
    });
  }

  it('returns an empty list for an empty rulebase without inventing an order', () => {
    assert.deepEqual(parser.parseFirewallRules([]), []);
  });
});

describe('Sophos rules — an omitted element means ANY, not empty', () => {
  const byName = new Map(
    parser.parseFirewallRules(read('FirewallRule').records).map((r) => [r.rule_name, r])
  );

  // ⛔ The `Lab` rule permits any source, any destination and any service, and
  // carries NONE of those three elements. Mapping absence to [] understates
  // reachability, and a hole reported as closed is the dangerous direction on
  // a segmentation report.
  it('reads absent address and service elements as any', () => {
    const lab = byName.get('Lab');
    assert.deepEqual(lab.src_addresses, ['any']);
    assert.deepEqual(lab.dst_addresses, ['any']);
    assert.deepEqual(lab.services, ['any']);
    // ...while the zones it DOES state are kept.
    assert.deepEqual(lab.src_zones, ['DMZ']);
    assert.deepEqual(lab.dst_zones, ['WAN']);
  });

  it('reads a rule with no zones at all as any zone', () => {
    const mta = byName.get('Auto added firewall policy for MTA');
    assert.deepEqual(mta.src_zones, ['any']);
    assert.deepEqual(mta.dst_zones, ['any']);
    // ...and it DOES state services, which must survive.
    assert.deepEqual(mta.services, ['SMTP', 'SMTP(S)']);
  });

  // ⛔ A Drop rule carries NO WebFilter / ScanVirus / IntrusionPrevention
  // elements at all. Absence there is not-applicable, never "disabled".
  it('parses a Drop rule that omits every security-feature element', () => {
    const deny = byName.get('Lab-Deny');
    assert.equal(deny.action, 'drop');
    assert.equal(deny.log_enabled, true);
    assert.deepEqual(deny.services, ['TELNET']);
  });

  // ⛔ TRI-STATE NULL = NOT MEASURED. The XML API reports no hit counts
  // anywhere, so `unused` findings must never be derived from this.
  it('reports hit_count as not measured, never zero', () => {
    for (const r of byName.values()) assert.equal(r.hit_count, null);
  });

  it('uses the rule NAME as the vendor id, because nothing else is offered', () => {
    for (const r of byName.values()) assert.equal(r.rule_id_vendor, r.rule_name);
  });
});

describe('Sophos config redaction', () => {
  // ⛔ THE TEST THIS FILE WOULD BE INCOMPLETE WITHOUT. SFOS's AdminSettings
  // carries PasswordComplexityCheck, MinimumPasswordLength and
  // MinimumPasswordLengthValue — the exact fields a compliance check grades. A
  // substring matcher on /pass/i would blank all three while claiming to
  // protect something.
  it('redacts a secret without destroying the password POLICY settings', () => {
    const xml = '<AdminSettings>'
      + '<PasswordComplexityCheck>Enable</PasswordComplexityCheck>'
      + '<MinimumPasswordLength>Enable</MinimumPasswordLength>'
      + '<MinimumPasswordLengthValue>10</MinimumPasswordLengthValue>'
      + '<Password>hunter2</Password>'
      + '</AdminSettings>';
    const out = parser.redactConfigXml(xml);
    assert.ok(!out.includes('hunter2'), 'the secret must go');
    assert.match(out, /<PasswordComplexityCheck>Enable<\/PasswordComplexityCheck>/);
    assert.match(out, /<MinimumPasswordLengthValue>10<\/MinimumPasswordLengthValue>/);
  });

  it('redacts a secret carried on a tag that has attributes', () => {
    const out = parser.redactConfigXml('<Password transactionid="x">hunter2</Password>');
    assert.ok(!out.includes('hunter2'));
  });

  it('redacts an attribute form too', () => {
    assert.ok(!parser.redactConfigXml('<Server Password="hunter2"/>').includes('hunter2'));
  });

  it('is deterministic, so an unchanged config diffs clean', () => {
    const xml = '<a><Password>x</Password></a>';
    assert.equal(parser.redactConfigXml(xml), parser.redactConfigXml(xml));
  });

  it('leaves the real captured AdminSettings policy fields readable', () => {
    const out = parser.redactConfigXml(XML.AdminSettings);
    assert.match(out, /<MinimumPasswordLengthValue>10<\/MinimumPasswordLengthValue>/);
    assert.match(out, /<UnsucccessfulAttempt>5<\/UnsucccessfulAttempt>/);
  });
});

describe('Sophos zones and interfaces', () => {
  const zones = parser.parseZones(read('Zone').records);
  const byName = new Map(zones.map((z) => [z.name, z]));

  // ⛔ Zone NAME is not zone TYPE.
  it('keeps name and type apart', () => {
    assert.equal(byName.get('WiFi').type, 'LAN');
    assert.equal(byName.get('DMZ').type, 'DMZ');
  });

  // ⛔ WAN carries NO <ApplianceAccess> element. null means "not stated", NOT
  // "nothing is exposed" — the appliance had nothing enabled there to begin
  // with, so this capture cannot tell the two apart, and a compliance check
  // reading null as a pass would assert something nobody measured.
  it('reports an absent ApplianceAccess block as null, not as an empty object', () => {
    assert.equal(byName.get('WAN').applianceAccess, null);
    assert.notEqual(byName.get('LAN').applianceAccess, null);
  });

  // parseInterfaces returns the ARRAY; the adapter is what wraps it in
  // { interfaces } for the collectAndStore contract. Asserting the shape here
  // rather than coalescing past it — a `|| ` fallback would pass whichever
  // shape it got and hide a change in either.
  const ifaces = parser.parseInterfaces(read('Interface').records);
  it('returns a bare array, which the adapter wraps', () => {
    assert.ok(Array.isArray(ifaces));
  });

  it('converts the device mask to CIDR', () => {
    const port1 = ifaces.find((i) => i.name === 'Port1');
    assert.equal(port1.ipAddress, '172.16.16.16/24');
    assert.equal(port1.zone, 'LAN');
    assert.equal(port1.enabled, true);
  });

  // ⛔ A non-contiguous mask yields null, not a guessed prefix. An interface
  // silently reported as a single host would make the topology engine miss
  // every adjacency on its subnet.
  it('refuses a non-contiguous mask rather than guessing a prefix', () => {
    assert.equal(parser.cidrFromMask('10.0.0.1', '255.0.255.0'), null);
    assert.equal(parser.cidrFromMask('10.0.0.1', '255.255.255.0'), '10.0.0.1/24');
    assert.equal(parser.cidrFromMask('10.0.0.1', 'nonsense'), null);
  });
});

describe('Sophos objects', () => {
  it('expands a nested host group into member names', () => {
    const objs = parser.parseObjects({
      hosts: read('IPHost').records,
      hostGroups: read('IPHostGroup').records,
      services: read('Services').records,
      serviceGroups: read('ServiceGroup').records,
    });
    const g = objs.addressGroups.find((x) => x.name === 'Internet IPv4 group');
    assert.ok(g, 'the built-in group should be present');
    assert.equal(g.members.length, 12);
    assert.ok(objs.addresses.length > 0);
    assert.ok(objs.services.length > 0);
  });
});

describe('Sophos console — version', () => {
  const v = consoleClient.parseVersionInfo(CONSOLE.versionInfo);

  it('reads the version, build, model and serial', () => {
    assert.equal(v.version_string, 'SFOS 22.0.3 MR-3-Build576');
    assert.deepEqual(v.version_tuple, [22, 0, 3, 576]);
    assert.equal(v.build, '576');
    assert.equal(v.model, 'SFVH');
    assert.equal(v.serial, 'V01001C6CT6BFD5');
  });

  // ⛔ The BUILD is the fourth segment, not the MR number: MR-n tracks the
  // patch digit and carries nothing the patch does not.
  it('puts the build in the tuple, not the MR number', () => {
    const t = consoleClient.parseVersionInfo('Firmware Version:\tSFOS 22.0.2 MR-2-Build546');
    assert.deepEqual(t.version_tuple, [22, 0, 2, 546]);
  });

  // ⛔ No fabricated tuple. parseVersion() elsewhere returns [0,0,0,0] for an
  // unreadable string, and CLAUDE.md records what that cost on the CVE path.
  it('returns a null tuple for a version it cannot read', () => {
    assert.equal(consoleClient.parseVersionInfo('Firmware Version:\tnonsense').version_tuple, null);
    assert.equal(consoleClient.parseVersionInfo('').version_tuple, null);
  });

  // ⛔ SPLIT ON THE FIRST COLON, NOT ON TABS. `Report DB version:` is followed
  // by SPACES on the real appliance; a tab-split loses it silently.
  it('reads a row the firmware pads with spaces instead of tabs', () => {
    const f = consoleClient.parseLabelled(CONSOLE.versionInfo);
    assert.equal(f.get('Report DB version'), '22.006');
    assert.equal(f.get('Config DB version'), '22.006');
  });

  // ⛔ A label with no value is NULL, not ''.
  it('reads an empty labelled row as null', () => {
    const f = consoleClient.parseLabelled(CONSOLE.versionInfo);
    assert.ok(f.has('Firmware Loader version'));
    assert.equal(f.get('Firmware Loader version'), null);
  });

  // ⛔ `Web Proxy version: compiled` is not a number. A lenient numeric parse
  // turns that word into a confident 0.
  it('carries content versions as the device’s own strings', () => {
    const got = new Map(v.contentVersions.map((c) => [c.component, c.version]));
    assert.equal(got.get('Sophos X-Ops'), '1.0.0660');
    assert.equal(got.get('Avira AV'), '1.0.430160');
    assert.equal(got.get('Web Proxy version'), 'compiled');
    assert.ok(!got.has('Firmware Loader version'), 'an empty row contributes nothing');
    assert.ok(!got.has('Serial Number'), 'identity is not a content version');
  });
});

describe('Sophos console — HA, disk, memory', () => {
  // ⛔ {enabled:false} is a POSITIVE fact; null means could not determine, and
  // the caller then leaves the previous row intact.
  it('reads standalone as a measured fact', () => {
    const ha = consoleClient.parseHaStatus(CONSOLE.haDetails);
    assert.equal(ha.enabled, false);
    assert.equal(ha.versionCompatOk, null);
  });

  // ⛔ No ENABLED-HA sample exists — there was no second appliance — so no
  // parser for one is written and anything unrecognised is unknown.
  it('returns null for output it has no verified parser for', () => {
    assert.equal(consoleClient.parseHaStatus('HA is enabled. Mode: active-passive'), null);
    assert.equal(consoleClient.parseHaStatus(''), null);
  });

  // ⛔ PERCENTAGES ONLY — SFOS reports no sizes and no mount points, so the
  // size columns are NOT MEASURED rather than zero.
  it('reads partition percentages and reports no fabricated sizes', () => {
    const d = consoleClient.parseDiskUsage(CONSOLE.disk);
    assert.equal(d.filesystems.length, 3);
    const config = d.filesystems.find((f) => f.filesystem === 'configuration');
    assert.equal(config.usePercent, 14);
    for (const f of d.filesystems) {
      assert.equal(f.sizeRaw, null);
      assert.equal(f.usedRaw, null);
      assert.equal(f.availRaw, null);
      assert.equal(f.mountedOn, null);
    }
  });

  it('uses MemAvailable, and says so', () => {
    const m = consoleClient.parseMemory(CONSOLE.memory);
    // (4018216 - 1581256) / 4018216 = 60.6%
    assert.equal(m.memoryPercent, 60.6);
    assert.match(m.raw.formula, /MemAvailable/);
  });

  it('reports memory as unmeasured rather than guessing when the output is unreadable', () => {
    assert.equal(consoleClient.parseMemory('nothing here').memoryPercent, null);
  });

  // ⛔ `system diagnostics show cpu` is /proc/cpuinfo — a processor MODEL NAME,
  // not a load figure. Wiring it to a CPU metric reports hardware identity
  // where a percentage belongs.
  it('confirms the cpu command carries no utilisation figure', () => {
    assert.match(CONSOLE.cpu, /model name/);
    assert.ok(!/\d+(\.\d+)?%/.test(CONSOLE.cpu), 'no percentage exists in that output to read');
  });
});

describe('Sophos console — the reboot hazard', () => {
  // ⛔ The login menu's option 7 is "Shutdown/Reboot Device" and it takes a
  // bare digit; the console itself opens with `system restart` and
  // `system shutdown`. A stray keystroke does not fail a collection, it takes a
  // production firewall offline.
  it('only ever sends the Device Console digit to the menu', () => {
    assert.equal(consoleClient.ENTER_DEVICE_CONSOLE, '4');
  });

  // The invariant that survives refactoring: no command this module can issue
  // may be one that halts the appliance.
  it('has no halting verb anywhere in its command vocabulary', () => {
    const commands = [consoleClient.CMD_VERSION, consoleClient.CMD_HA,
      consoleClient.CMD_DISK, consoleClient.CMD_MEMORY];
    for (const c of commands) {
      assert.doesNotMatch(c, /\b(restart|shutdown|reboot|halt|reset|factory)\b/i, c);
      assert.match(c, /^[a-z]/, 'a command must never begin with a digit');
    }
  });

  it('matches both prompts the appliance presents, anchored at the end', () => {
    assert.match('Select Menu Number [0-7]: ', consoleClient.PROMPT_RE);
    assert.match('console> ', consoleClient.PROMPT_RE);
    assert.doesNotMatch('console> some output follows', consoleClient.PROMPT_RE);
  });
});

describe('Sophos adapter surface', () => {
  const proto = SophosAdapter.prototype;

  it('implements the required contract', () => {
    for (const m of ['testConnectivity', 'getVersion', 'getRules', 'getConfig']) {
      assert.equal(typeof proto[m], 'function', m);
    }
  });

  // ⛔ ABSENT, NOT STUBBED. Measured on BOTH transports: nine XML entity names
  // return 529, and both licence commands return Unknown Parameter. The
  // optional-capability contract says an absent method is how an adapter
  // declares what it cannot do, so /lifecycle shows Sophos as not collectable
  // rather than as "no renewals due".
  it('declares getLicenses unavailable by omitting it', () => {
    assert.equal(typeof proto.getLicenses, 'undefined');
    assert.equal(typeof proto.getSnmpMetrics, 'undefined');
  });

  it('implements the optional capabilities that were verified', () => {
    for (const m of ['getObjects', 'getInterfaces', 'getRoutingTable',
      'getHaStatus', 'getDiskUsage', 'getPerformanceMetrics']) {
      assert.equal(typeof proto[m], 'function', m);
    }
  });

  it('testConnectivity never throws, even with no credential at all', async () => {
    const adapter = new SophosAdapter({
      device: { id: 'x', mgmt_ip: '127.0.0.1' },
      pool: { query: async () => ({ rows: [] }) },
    });
    const r = await adapter.testConnectivity();
    assert.equal(r.ok, false);
    assert.equal(typeof r.message, 'string');
  });
});
