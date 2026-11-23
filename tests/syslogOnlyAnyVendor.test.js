// tests/syslogOnlyAnyVendor.test.js
//
// v2.237.0 — ANY brand can be added as syslog-only.
//
// ⛔ THE REQUEST THIS SERVES. An operator sees a firewall in /devices/discovered
// sending syslog and cannot log into it — no credentials, a device another team
// owns, an appliance mid-handover. Before this, such a firewall could only
// enter the inventory if its VENDOR had no adapter (`juniper`, `sonicwall`); a
// FortiGate nobody had credentials for had to stay out, so its events kept
// landing with `device_id NULL` and it existed only on the discovered list.
//
// ⛔ WHAT THESE TESTS ARE ACTUALLY PROTECTING, which is not the new dropdown
// entry. `lib/monitoringOnly.js` has said since v2.236.0 that such a device
// "produces NO CVEs, NO compliance failures and NO rule findings — it is
// silently the cleanest device on the fleet", and that it must therefore be
// "never hidden, never excluded from a coverage count, and never allowed to
// read as assessed". While only juniper/sonicwall could be log-only the vendor
// column was an accidental tell: neither has an adapter, so a reader could
// infer it. A log-only FortiGate offers NO such inference — its row is
// pixel-identical to a FortiGate that was assessed and came back clean — so
// this release had to add the visible half, and these tests pin it.
//
// ⛔ RENDERED, NOT SOURCE-SCANNED. Project memory
// (feedback_verify_outcome_not_mechanism) records that a source scan and an
// attribute check shipped three broken features in one day here, and
// roadmap row 4 already names three DiscoveredDeviceActions guards that stay
// green when the note is made unrenderable. The wrong answer for the marker is
// an EMPTY RENDER — invisible in source, obvious in markup — so the marker is
// mounted with react-dom/server and its words are read, using the same
// swc-on-require harness as tests/deltaBadge.test.js (no devDependency).

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const REPO = path.join(__dirname, '..');

const {
  MONITORING_ONLY_METHOD, MONITORING_ONLY_CLAIM, MONITORING_ONLY_REMEDY,
  isMonitoringOnly, refuseMonitoringOnlyConversion,
} = require('../lib/monitoringOnly');
const { ADAPTERS, DEFAULT_METHOD, getAdapter, collectAndStore } = require('../lib/adapters');
const {
  VENDOR_META, VENDOR_SLUGS, MANAGED_VENDOR_SLUGS, buildCredentialPlaintext,
  resolveAccessMethod,
} = require('../components/devices/vendorMeta');
const { decorate } = require('../lib/engines/deviceInventory');
const { deviceContextFacts } = require('../lib/deviceContext');

// A pool that fails the test if anything touches it. A log-only device must
// never produce a query, and "it wrote nothing" is not observable from a stub
// that silently accepts writes.
const refusingPool = () => ({
  query: async (sql) => {
    throw new Error('a monitoring-only device must issue no query; got: ' + String(sql).slice(0, 80));
  },
});

describe('⛔ a MANAGED vendor can be added log-only', () => {
  it('every managed vendor offers the syslog method', () => {
    // ⛔ EXACT, not `>= 7`. The intent is "every managed vendor", and a
    // `>=` threshold stops meaning that the moment a tenth vendor is added
    // without the method: the registry would be half-rolled-out and green.
    assert.equal(
      MANAGED_VENDOR_SLUGS.length,
      VENDOR_SLUGS.length - VENDOR_SLUGS.filter((v) => VENDOR_META[v].monitoringOnly).length,
      'the managed/monitoring-only partition does not cover every slug'
    );
    assert.ok(MANAGED_VENDOR_SLUGS.length > 0, 'the partition must not be vacuous');
    for (const slug of MANAGED_VENDOR_SLUGS) {
      const r = resolveAccessMethod(slug, MONITORING_ONLY_METHOD);
      assert.ok(r, slug + ' cannot resolve the ' + MONITORING_ONLY_METHOD + ' method');
      assert.equal(r.method, MONITORING_ONLY_METHOD,
        slug + ' silently resolved to a different method, so the form would '
        + 'store a management transport for a device nobody can log into');
    }
  });

  it('⛔ it takes NO credential — null, never an empty username/password', () => {
    // buildCredentialPlaintext falling through to its userpass branch stores
    // `{"username":"","password":""}`, which reads as "credentials were
    // supplied and are blank" rather than "this device has none by design".
    for (const slug of MANAGED_VENDOR_SLUGS) {
      assert.equal(
        buildCredentialPlaintext(slug, MONITORING_ONLY_METHOD,
          { username: 'u', password: 'p', secret: 's', authMode: 'userpass' }),
        null, slug);
    }
  });

  it('⛔ it claims no port, so mgmt_port cannot assert a service', () => {
    for (const slug of MANAGED_VENDOR_SLUGS) {
      assert.equal(
        resolveAccessMethod(slug, MONITORING_ONLY_METHOD).config.defaultPort, null, slug);
    }
  });

  it('⛔ being addable did NOT make it collectable', async () => {
    // The same guarantee the monitoring-only VENDORS have, now reached through
    // a vendor that owns a working adapter — which is the new risk: ADAPTERS
    // .fortinet exists, so dispatch has something to pick if the guard is lost.
    for (const slug of MANAGED_VENDOR_SLUGS) {
      const device = { id: 'd-' + slug, name: slug.toUpperCase(), vendor: slug,
        mgmt_method: MONITORING_ONLY_METHOD, mgmt_ip: '10.0.0.9' };
      const res = await collectAndStore(device, refusingPool());
      assert.equal(res.skipped, true, slug + ' was not skipped');
      assert.equal(res.skippedReason, 'monitoring_only', slug);
      assert.deepEqual(res.errors, [], slug + ' reported an error — it must SKIP, not FAIL');
      // ⛔ NOT zero. A log-only firewall with `rulesCount: 0` is a firewall
      // with an empty rulebase, which is a finding; null is "never looked".
      assert.equal(res.rulesCount, null, slug);
      assert.equal(res.version, null, slug);
      assert.equal(res.configCollected, false, slug);
    }
  });

  it('⛔ getAdapter names the STATE, not an unsupported vendor or method', () => {
    // It must not say "no adapter for access method syslog", which would send
    // somebody to write an adapter for a firewall nobody asked to connect to.
    for (const slug of MANAGED_VENDOR_SLUGS) {
      assert.throws(
        () => getAdapter({ id: 'x', name: 'FW', vendor: slug,
          mgmt_method: MONITORING_ONLY_METHOD }, {}),
        (err) => {
          assert.match(err.message, /monitoring-only/i, slug + ': ' + err.message);
          assert.doesNotMatch(err.message, /Unsupported vendor/i, slug);
          assert.doesNotMatch(err.message, /has no adapter for access method/i, slug);
          return true;
        }, slug);
    }
  });

  it('⛔ the SAME vendor still collects normally over its real transport', () => {
    // The opposite failure, and the expensive one: offering a log-only method
    // must not disturb dispatch for the managed fleet.
    for (const slug of MANAGED_VENDOR_SLUGS) {
      const adapter = getAdapter({ id: 'x', name: 'FW', vendor: slug,
        mgmt_method: DEFAULT_METHOD[slug], mgmt_ip: '10.0.0.1' }, {});
      assert.ok(adapter, slug + ' lost its adapter');
      assert.ok(ADAPTERS[slug][DEFAULT_METHOD[slug]], slug);
    }
  });

  it('⛔ a legacy row with mgmt_method NULL still collects — it is NOT log-only', () => {
    // DEFAULT_METHOD is the fallback for every row written before the
    // access-method selector existed. If `syslog` ever became a vendor
    // default, this is the test that goes red instead of a fleet silently
    // ceasing to be collected from with no error anywhere.
    for (const slug of MANAGED_VENDOR_SLUGS) {
      assert.equal(isMonitoringOnly({ vendor: slug, mgmt_method: null }), false, slug);
      assert.ok(
        getAdapter({ id: 'x', name: 'FW', vendor: slug, mgmt_method: null,
          mgmt_ip: '10.0.0.1' }, {}),
        slug + ' with a NULL mgmt_method no longer dispatches');
    }
  });
});

describe('⛔ it does NOT read as assessed — the inventory row', () => {
  // The hazard in one object. Every count below is absent because nothing was
  // ever run, and `decorate` must not turn any of them into a confident zero.
  const logOnlyRow = (vendor) => ({
    id: 'r1', name: 'UNREACHABLE-FW', vendor, mgmt_method: MONITORING_ONLY_METHOD,
    critical_cve_count: 0, patch_now_count: 0, scheduled_count: 0,
    compliance_pct: null, rule_count: 0, analysis_run_count: 0,
    critical_findings: 0, high_findings: 0, medium_findings: 0, low_findings: 0,
    last_cve_assessed_at: null, last_collected_at: null,
  });

  it('⛔ the row is MARKED monitoring-only, on a managed vendor', () => {
    // Roadmap row 1: nothing marked it, and `vendorMeta.js` justified dropping
    // "(logs only)" from the short label by citing a row marker that did not
    // exist. On a FortiGate there is no vendor tell left at all.
    assert.equal(decorate(logOnlyRow('fortinet')).monitoringOnly, true);
    assert.equal(decorate(logOnlyRow('juniper')).monitoringOnly, true);
  });

  it('⛔ it is derived from mgmt_method, NOT from the vendor', () => {
    // A managed vendor on a real transport must not be marked, and the flag
    // must not be read off VENDOR_META.monitoringOnly — which answers the
    // different question "could SecVault ever manage this brand".
    for (const m of ['api', 'ssh', 'smc', null, undefined, 'nonsense']) {
      assert.equal(
        decorate({ ...logOnlyRow('fortinet'), mgmt_method: m }).monitoringOnly, false,
        'mgmt_method=' + String(m) + ' must not read as log-only');
    }
    // ...and the vendor flag alone must not mark a row whose method is real.
    assert.equal(VENDOR_META.juniper.monitoringOnly, true, 'fixture assumption');
    assert.equal(
      decorate({ ...logOnlyRow('juniper'), mgmt_method: 'api' }).monitoringOnly, false,
      'the VENDOR flag leaked into the DEVICE state');
  });

  it('⛔ no score, no risk band — never a confident 100 it has not earned', () => {
    const d = decorate(logOnlyRow('fortinet'));
    assert.equal(d.riskScore, null, 'a never-analysed firewall must have no risk score');
    assert.equal(d.riskBand, null);
    assert.equal(d.compliancePct, null, 'a never-assessed firewall must have no compliance %');
    // securityScore is the fleet-facing number; it must be null (rendered
    // "—"), not a high score assembled from three unmeasurable components.
    assert.equal(d.securityScore, null,
      'a log-only firewall scored a number — it would outrank every assessed '
      + 'device on a page that sorts worst-first with nulls last');
  });
});

// ⛔ THE PROJECTION, WHICH IS THE ONE LOSS NOTHING ELSE ABOVE CAN SEE.
//
// `decorate()` and `deviceContextFacts()` are handed a row, so every test
// above passes `mgmt_method` in by hand. If the COLUMN is dropped from the
// SELECT, `row.mgmt_method` is `undefined`, `isMonitoringOnly` returns false,
// and NO device is ever marked anywhere — the whole visible half of this
// release reverts, with every unit test still green and no error in sight.
// That is the guard-that-cannot-fire pattern aimed at the marker.
//
// ⛔ SO THE STATEMENT THAT RUNS IS READ, NOT THE SOURCE'S SPELLING OF IT.
// CLAUDE.md's own prescription after tests/fixedVersionFromRanges.test.js was
// measured inert: call the real exported function with a stub pool and assert
// against the SQL it actually issues.
//
// ⛔ AND SQL COMMENTS ARE STRIPPED FIRST, WHICH IS NOT OPTIONAL HERE. Both
// queries carry a `--` comment EXPLAINING the mgmt_method projection and
// naming the column, so a naive scan is satisfied by the prose that justifies
// the thing it is supposed to be checking. This repo has hit that trap at
// least three times (notificationChannels.js's device-data comment, the
// EmptyState heading guard, the dataDirAcl scan), which is why it is written
// out rather than assumed.
const stripSqlComments = (sql) =>
  String(sql).replace(/--[^\n]*/g, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ');

/** Records every statement issued, answers everything with no rows. */
function recordingPool(statements) {
  return {
    query: async (sql) => {
      statements.push(typeof sql === 'string' ? sql : (sql && sql.text) || '');
      return { rows: [] };
    },
  };
}

describe('⛔ mgmt_method is actually SELECTed — or nothing is ever marked', () => {
  it('the inventory query projects it', async () => {
    const stmts = [];
    const { getDeviceInventory } = require('../lib/engines/deviceInventory');
    await getDeviceInventory(recordingPool(stmts));
    assert.ok(stmts.length > 0, 'no statement was issued');
    const bodies = stmts.map(stripSqlComments);
    // ⛔ BOUND TO THE STATEMENT THAT PRODUCES THE ROWS, not `some()` over all
    // of them: `getDeviceInventory` also issues an unrelated poll-health
    // aggregate, so `some()` would be satisfied by the wrong query. The device
    // query is the one selecting FROM devices.
    const deviceQuery = bodies.find((b) => /FROM\s+devices\s+d\b/i.test(b));
    assert.ok(deviceQuery, 'no statement selected FROM devices');
    assert.match(
      deviceQuery.slice(0, deviceQuery.search(/\bFROM\b/i)), /\bd\.mgmt_method\b/,
      'the Devices page query does not PROJECT d.mgmt_method (SQL comments '
      + 'stripped first, and the projection list only — a mention after FROM '
      + 'would not put the column on the row). Without it every row reads as '
      + 'managed and the "Logs only" marker can never render.'
    );
  });

  it('the per-device context query projects it', async () => {
    const stmts = [];
    const { loadDeviceContext } = require('../lib/deviceContext');
    await loadDeviceContext(recordingPool(stmts), '00000000-0000-0000-0000-000000000001');
    assert.ok(stmts.length > 0, 'no statement was issued');
    const bodies = stmts.map(stripSqlComments);
    assert.ok(
      bodies.some((b) => /\bd\.mgmt_method\b/.test(b)),
      'the device-context query does not project d.mgmt_method, so the header '
      + 'cannot explain a row of em-dashes on six per-device pages'
    );
  });

  it('⛔ the guard is not satisfiable by the comment alone', () => {
    // Proving the stripper works, so the assertions above cannot go vacuous.
    const sql = "SELECT d.id, -- d.mgmt_method is projected below\n d.name FROM devices d";
    assert.ok(!/\bd\.mgmt_method\b/.test(stripSqlComments(sql)),
      'stripSqlComments left a commented-out column visible');
    assert.ok(/\bd\.mgmt_method\b/.test(stripSqlComments('SELECT d.mgmt_method FROM devices d')));
  });
});

describe('⛔ it does NOT read as assessed — the per-device header', () => {
  it('the context marks it, on a managed vendor', () => {
    const f = deviceContextFacts({
      id: 'd1', name: 'UNREACHABLE-FW', vendor: 'fortinet',
      mgmt_method: MONITORING_ONLY_METHOD, mgmt_ip: '10.0.0.9',
    });
    assert.equal(f.monitoringOnly, true);
    assert.equal(f.vendor, 'fortinet', 'the vendor is unchanged — only the device is log-only');
  });

  it('and leaves a managed device unmarked', () => {
    const f = deviceContextFacts({
      id: 'd2', name: 'MANAGED-FW', vendor: 'fortinet', mgmt_method: 'api',
      mgmt_ip: '10.0.0.1',
    });
    assert.equal(f.monitoringOnly, false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// The marker itself, RENDERED.
// ─────────────────────────────────────────────────────────────────────────────
function installRenderHooks() {
  const swc = require('next/dist/build/swc');
  const origExt = Module._extensions['.js'];
  Module._extensions['.js'] = function (mod, filename) {
    if (filename.split(path.sep).join('/').includes('/node_modules/')) {
      return origExt(mod, filename);
    }
    const out = swc.transformSync(fs.readFileSync(filename, 'utf8'), {
      filename,
      jsc: {
        parser: { syntax: 'ecmascript', jsx: true },
        target: 'es2020',
        transform: { react: { runtime: 'automatic' } },
      },
      module: { type: 'commonjs' },
    });
    return mod._compile(out.code, filename);
  };
}

let React = null;
let renderToStaticMarkup = null;
let MonitoringOnlyMark = null;
let MONITORING_ONLY_LABEL = null;
let loadError = null;
try {
  installRenderHooks();
  React = require('react');
  ({ renderToStaticMarkup } = require('react-dom/server'));
  const mod = require('../components/devices/MonitoringOnlyMark');
  MonitoringOnlyMark = mod.default;
  MONITORING_ONLY_LABEL = mod.MONITORING_ONLY_LABEL;
} catch (err) {
  // A failure, never a skip: a suite that quietly stops checking is the same
  // shape of problem as the bug it covers.
  loadError = err;
}

const html = (props) => {
  assert.ok(MonitoringOnlyMark, 'could not load MonitoringOnlyMark: '
    + (loadError ? loadError.message : 'unknown'));
  return renderToStaticMarkup(React.createElement(MonitoringOnlyMark, props));
};
const text = (props) => html(props).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();

// ⛔ THE MARKER IS MOUNTED — THE GAP THAT MADE EVERY TEST BELOW VACUOUS.
//
// Review proved it: deleting the `<MonitoringOnlyMark …/>` line from BOTH
// `app/(dashboard)/devices/page.js` and `components/devices/DeviceContextHeader.js`
// left the whole suite GREEN. `decorate()` still returned `monitoringOnly: true`
// and nothing showed it, so a log-only FortiGate row went back to being
// pixel-identical to an assessed-and-clean one — the single sentence this
// release exists to prevent. The component was tested in isolation and never
// asserted to be USED.
//
// ⛔ THIS IS A MOUNT-SITE GUARD, NOT A RENDER ASSERTION, AND THE LIMIT IS
// STATED RATHER THAN HIDDEN. `/devices` is a server component that queries the
// database, so `npm test` cannot render it (nothing in the suite renders a
// page — that is `npm run smoke`'s job, and it asserts a per-page content
// marker, not this). What a source scan CAN prove is that the call site has not
// disappeared, which is the regression that actually happened in review.
//
// ⛔ IT REQUIRES AN IMPORT **AND** A JSX USE, because this repo has twice
// watched a scan be satisfied by an import line alone (`useFocusTrap`,
// `hasFixedVersionsSql`), and comments are stripped first, because it has twice
// watched one be satisfied by the prose explaining the thing it checks
// (`notificationChannels.js`, the EmptyState heading guard).
describe('⛔ the marker is actually MOUNTED where a reader meets the device', () => {
  const stripComments = (src) => src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');

  const SITES = [
    ['app/(dashboard)/devices/page.js', 'the fleet inventory row'],
    ['components/devices/DeviceContextHeader.js', 'all six per-device pages'],
  ];

  for (const [rel, what] of SITES) {
    it(`${rel} mounts it — ${what}`, () => {
      const src = stripComments(fs.readFileSync(path.join(REPO, rel), 'utf8'));
      assert.match(src, /import\s+MonitoringOnlyMark\s+from/,
        rel + ' does not import the marker');
      assert.match(src, /<MonitoringOnlyMark[\s/>]/,
        rel + ' imports the marker and never renders it, so ' + what
        + ' shows a log-only firewall as indistinguishable from an assessed one');
      // ⛔ And it must be fed the DEVICE-level flag. A site passing a literal
      // `false`, or the vendor flag, renders nothing or the wrong thing while
      // satisfying the two assertions above.
      assert.match(src, /monitoringOnly=\{/,
        rel + ' renders the marker without passing monitoringOnly');
      assert.ok(!/monitoringOnly=\{false\}/.test(src),
        rel + ' hardcodes monitoringOnly={false}, so the marker can never render');
      assert.ok(!/VENDOR_META\[[^\]]*\]\.monitoringOnly/.test(src),
        rel + ' reads the VENDOR-level flag, which answers a different question '
        + 'and both misses a log-only FortiGate and mislabels a managed Juniper');
    });
  }
});

// ⛔ CONVERTING AN ALREADY-COLLECTED FIREWALL TO LOGS-ONLY IS REFUSED.
//
// v2.237.0 made this reachable for the first time: before it,
// `PUT {mgmt_method:'syslog'}` was a 400 for every managed vendor because the
// key did not exist in `accessMethods`. The PUT deletes credentials and NOTHING
// else, and `collectAndStore` then skips the device for ever — so its stored
// version, ruleset, config, CVE assessments and compliance findings are FROZEN
// and every engine keeps asserting them. Measured on the real `decorate()`
// during review: a converted FortiGate scores **97, band "excellent"**.
//
// ⛔ The decision lives in `lib/monitoringOnly.js` rather than inline in the
// route precisely so these can be behavioural: there is no route harness here,
// and `apisweep` refuses mutating verbs.
describe('⛔ managed → logs-only conversion is refused, both directions checked', () => {
  it('refuses a managed device being converted', () => {
    for (const from of ['api', 'ssh', 'smc']) {
      const r = refuseMonitoringOnlyConversion(from, MONITORING_ONLY_METHOD);
      assert.ok(r, from + ' → ' + MONITORING_ONLY_METHOD + ' was allowed');
      assert.equal(r.code, 'monitoring_only_conversion_refused');
      assert.match(r.error, /Delete the firewall and add it again/,
        'the refusal must name the path that works, not just say no');
    }
  });

  it('⛔ refuses a LEGACY row too — a null method is not already log-only', () => {
    // `mgmt_method` is nullable on every row written before the access-method
    // selector existed, and such a device IS collected from (dispatch falls
    // back to DEFAULT_METHOD). Treating null as "already log-only" would let
    // the whole legacy fleet be converted with its evidence stranded.
    const r = refuseMonitoringOnlyConversion(null, MONITORING_ONLY_METHOD);
    assert.ok(r, 'a legacy null-method device was allowed to convert');
  });

  it('⛔ ALLOWS the reverse — that is the documented remedy', () => {
    // logs-only → a real transport is MONITORING_ONLY_REMEDY itself, and it
    // strands nothing: there is no collected evidence to freeze.
    for (const to of ['api', 'ssh', 'smc']) {
      assert.equal(refuseMonitoringOnlyConversion(MONITORING_ONLY_METHOD, to), null, to);
    }
  });

  it('allows a no-op and every unrelated method change', () => {
    assert.equal(
      refuseMonitoringOnlyConversion(MONITORING_ONLY_METHOD, MONITORING_ONLY_METHOD), null,
      'a log-only device saving other metadata must not be refused');
    assert.equal(refuseMonitoringOnlyConversion('api', 'ssh'), null);
    assert.equal(refuseMonitoringOnlyConversion('api', undefined), null,
      'a PUT that does not mention mgmt_method must not be refused');
  });

  it('⛔ the route actually CALLS it, and answers 409', () => {
    // The pure function above can be perfect and unreferenced — the
    // `getThreatCoverage` shape, awaited into a variable no widget read.
    const src = fs.readFileSync(path.join(REPO, 'app/api/devices/[id]/route.js'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');
    assert.match(src, /refuseMonitoringOnlyConversion\s*\(/,
      'the PUT route does not call the conversion refusal');
    assert.match(src, /status:\s*409/,
      'the refusal is not returned as a 409 conflict');
    // ⛔ It must read the STORED method, not the requested one twice.
    assert.match(src, /refuseMonitoringOnlyConversion\(\s*existing\.mgmt_method\s*,/,
      'the refusal is not given the stored method, so it cannot tell a '
      + 'conversion from a log-only device saving unrelated metadata');
  });
});

// ⛔ POST /api/devices REFUSES A SUPPLIED CREDENTIAL for a log-only device.
// Review found this guard had ZERO tests anywhere, although its own comment
// records two measured v2.236.0 bugs it fixed — including a 201 that wrote a
// real encrypted credential onto a device defined as having none. It is the
// guard that actually protects `device_credentials`; `buildCredentialPlaintext`
// returning null is a client-side helper and is the thing that WAS tested.
describe('⛔ the credential refusals exist in the routes themselves', () => {
  const routeSrc = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');

  it('POST refuses credential, smc_api_key and credential_profile_id alike', () => {
    const src = routeSrc('app/api/devices/route.js');
    assert.match(src, /credentialShape\s*===\s*'none'/,
      'POST does not gate on the monitoring-only credential shape');
    for (const field of ['credential', 'smc_api_key', 'credential_profile_id']) {
      assert.ok(src.includes(field),
        'POST does not consider ' + field + ' — a credential could arrive by that name');
    }
    // ⛔ And it must store NO PORT: an absent defaultPort governs the default,
    // never a value the client typed.
    assert.match(src, /credentialShape\s*===\s*'none'/);
    // ⛔ `/noPort/` ALONE WAS INERT — proved by mutation: `const noPort = false;`
    // still contains the identifier, so the assertion passed while a
    // client-supplied `mgmt_port: 443` went back to being stored on a firewall
    // SecVault will never dial. The identifier must be DERIVED, and a literal
    // is refused by name.
    assert.match(src, /noPort\s*=\s*[^;]*credentialShape/,
      'POST does not derive its no-port decision from the credential shape, so '
      + 'mgmt_port: 443 can be stored on a firewall SecVault will never dial');
    assert.ok(!/\bnoPort\s*=\s*(?:true|false)\b/.test(src),
      'POST hardcodes its no-port decision, so the guard cannot fire');
    assert.match(src, /smcPortValue\s*=\s*noPort/,
      'the SMC port is not gated on it');
    assert.match(src, /mgmtPortValue\s*=\s*noPort/,
      'the management port is not gated on it');
  });

  it('the SNMP route refuses too — it is the third setCredential caller', () => {
    const src = routeSrc('app/api/devices/[id]/snmp/route.js');
    assert.match(src, /isMonitoringOnly\s*\(/,
      'the SNMP route writes an SNMP credential to a log-only device: SNMP is '
      + 'independent of the management API, the device page offers the card '
      + 'unconditionally, and the poll can never run because getAdapter refuses');
    assert.match(src, /status:\s*409/, 'the SNMP refusal is not a 409');
  });
});

describe('⛔ the marker renders words, not just a colour', () => {
  it('⛔ it actually RENDERS for a log-only device', () => {
    // The wrong answer here is an empty string, which no source scan sees.
    const out = text({ monitoringOnly: true });
    assert.ok(out.length > 0, 'the marker rendered NOTHING for a log-only device');
    assert.ok(out.includes(MONITORING_ONLY_LABEL),
      'expected ' + JSON.stringify(MONITORING_ONLY_LABEL) + ', got ' + JSON.stringify(out));
  });

  it('⛔ it renders NOTHING when the device is managed', () => {
    // Mounted unconditionally on every row and every per-device page, so a
    // marker that renders regardless would label the whole fleet log-only.
    assert.equal(html({ monitoringOnly: false }), '');
    assert.equal(html({}), '');
    assert.equal(html({ monitoringOnly: null }), '');
  });

  it('⛔ WCAG 1.4.1 — `aria-hidden` is on the GLYPH, not on the whole marker', () => {
    const out = html({ monitoringOnly: true });
    // ⛔ THE FIRST DRAFT MATCHED `/aria-hidden="true"/` ANYWHERE and was proved
    // inert by review: moving the attribute from the inner glyph span to the
    // OUTER span passed all eight assertions while removing the entire marker
    // from the accessibility tree — a screen-reader user would meet a FortiGate
    // row with an empty score and NO explanation, a worse 1.4.1 failure than
    // the one this attribute exists to prevent. So assert WHERE it sits.
    assert.match(out, /<span aria-hidden="true">[^A-Za-z<]*<\/span>/,
      'aria-hidden must sit on a child that contains no letters: ' + out);
    const outerTag = out.slice(0, out.indexOf('>') + 1);
    assert.ok(!/aria-hidden/.test(outerTag),
      'aria-hidden is on the OUTER element, which hides the whole marker from '
      + 'assistive technology: ' + outerTag);
    assert.ok(text({ monitoringOnly: true }).replace(/[^A-Za-z ]/g, '').trim().length > 0,
      'the marker carries no words');
  });

  it('⛔ HUELESS — an ALLOW-LIST, because a blocklist cannot see the good half of the ramp', () => {
    const out = html({ monitoringOnly: true });
    assert.match(out, /var\(--unmeasured\)/, 'the marker must use --unmeasured');
    // ⛔ THE FIRST DRAFT BLOCKED EIGHT NAMED TOKENS and review proved it inert:
    // adding `background: var(--tint-success)` or `border: 1px solid
    // var(--green)` passed, producing a GREEN-TINTED "Logs only" chip — which
    // reads as *fine/clean*, the worst available outcome for a marker whose
    // whole job is to say this firewall was never assessed. The omissions were
    // in the half of the ramp nobody thinks to block. So: extract every token
    // the markup actually uses and require the set to be a subset of what is
    // allowed here.
    const allowed = new Set(['--unmeasured', '--text-xs', '--hatch', '--s1']);
    const used = [...out.matchAll(/var\((--[a-z0-9-]+)/g)].map((m) => m[1]);
    assert.ok(used.length > 0, 'no tokens found — the style may have been dropped');
    for (const token of used) {
      assert.ok(allowed.has(token),
        'the marker uses var(' + token + '), which is not on the hueless '
        + 'allow-list. SecVault not being able to reach a firewall is not a '
        + 'severity, and it is certainly not a success.');
    }
  });

  it('⛔ it states the CLAIM **and the REMEDY**', () => {
    const out = html({ monitoringOnly: true });
    // The one shared pair, imported — never a second wording.
    assert.ok(MONITORING_ONLY_CLAIM.includes('not because it passed them'),
      'fixture assumption about the shared claim');
    assert.match(out, /title="/, 'the marker carries no explanation at all');
    assert.ok(out.includes('were never run'),
      'the title does not carry the shared claim: ' + out);
    // ⛔ THE REMEDY WAS IMPORTED AND NEVER ASSERTED, so dropping it from the
    // title passed. The component's own comment calls it "the whole reason
    // this is a deliberate state rather than a fault": without it the marker
    // says what is true and not what to do about it.
    assert.ok(MONITORING_ONLY_REMEDY.includes('Add a management connection'),
      'fixture assumption about the shared remedy');
    assert.ok(out.includes('Add a management connection'),
      'the title does not carry the remedy: ' + out);
  });
});
