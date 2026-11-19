// tests/monitoringOnly.test.js
//
// The monitoring-only device kind (v2.236.0): a firewall in the inventory for
// its LOGS, that SecVault never opens a management connection to.
//
// ⛔ WHAT THIS FEATURE IS ACTUALLY FOR, and why the tests are weighted the way
// they are. The easy half is letting the device be ADDED. The dangerous half is
// everything afterwards: `workQueueData.js` states it plainly — "a firewall
// that has not been collected from produces NO CVEs, NO compliance failures and
// NO rule findings — it is silently the cleanest device on the fleet." A
// monitoring-only firewall has that property BY CONSTRUCTION AND FOR EVER. So
// most of what follows asserts that it stays VISIBLE, stays counted, and can
// never read as assessed.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  MONITORING_ONLY_METHOD, MONITORING_ONLY_CLAIM, MONITORING_ONLY_REMEDY, isMonitoringOnly,
} = require('../lib/monitoringOnly');
const { ADAPTERS, DEFAULT_METHOD, getAdapter, collectAndStore } = require('../lib/adapters');
const {
  VENDOR_META, VENDOR_SLUGS, buildCredentialPlaintext, resolveAccessMethod, vendorLabel,
} = require('../components/devices/vendorMeta');
const {
  gatherCollectionGaps, gatherMonitoringOnly, PER_SOURCE_CAP,
} = require('../lib/engines/workQueueData');
const { bandFor } = require('../lib/engines/workQueue');
const { WORK_TYPE_LABEL } = require('../components/work/workItemTypes');
const fs = require('node:fs');
const path = require('node:path');

function stubPool(queue) {
  const seen = [];
  const results = queue.slice();
  return {
    sql: seen,
    async query(text, params) {
      seen.push({ text, params });
      const next = results.shift();
      if (next instanceof Error) throw next;
      return { rows: next || [], rowCount: (next || []).length };
    },
  };
}

const MONITORING_SLUGS = Object.keys(VENDOR_META).filter((s) => VENDOR_META[s].monitoringOnly);

// ⛔ `withCap` returns a BARE ARRAY under the cap and `{items, truncatedFrom}`
// at it. A test asserting only one shape passes or fails for the wrong reason
// depending on how many rows the stub happens to return.
const itemsOf = (out) => (Array.isArray(out) ? out : out.items);

describe('a monitoring-only firewall can be added', () => {
  it('⛔ the vendors that have a parser but no adapter are now addable', () => {
    // ⛔ THE GAP THIS CLOSED. `POST /api/devices` rejects any vendor outside
    // VENDOR_META, so a Juniper or SonicWall could not be added AT ALL — its
    // events were stored with `device_id NULL`, it appeared only on
    // /devices/discovered, and evidenceWindow, capacityForecast and
    // changeOutcome each excluded it by their deliberate `device_id IS NOT
    // NULL` filters. A firewall the product could read and could not name.
    assert.ok(VENDOR_SLUGS.includes('juniper'));
    assert.ok(VENDOR_SLUGS.includes('sonicwall'));
    assert.deepEqual(MONITORING_SLUGS.sort(), ['juniper', 'sonicwall']);
  });

  it('⛔ being addable did NOT make it collectable', () => {
    // ⛔ The whole safety argument rests on this staying true. If a
    // monitoring-only vendor ever gains an adapter it must be PROMOTED
    // deliberately, not drift into managed status.
    for (const slug of MONITORING_SLUGS) {
      assert.equal(ADAPTERS[slug], undefined, `${slug} must have no adapter`);
      assert.equal(DEFAULT_METHOD[slug], undefined, `${slug} must have no DEFAULT_METHOD`);
    }
  });

  it('offers exactly one access method and builds NO credential', () => {
    // ⛔ `credentialShape: 'none'` or buildCredentialPlaintext falls through to
    // its userpass branch and returns `{"username":"","password":""}` — an
    // EMPTY CREDENTIAL stored in device_credentials, which reads as
    // "credentials were supplied and are blank" rather than "this device has
    // none by design".
    for (const slug of MONITORING_SLUGS) {
      const meta = VENDOR_META[slug];
      assert.deepEqual(Object.keys(meta.accessMethods), [MONITORING_ONLY_METHOD]);
      assert.equal(meta.defaultAccessMethod, MONITORING_ONLY_METHOD);
      assert.equal(
        buildCredentialPlaintext(slug, MONITORING_ONLY_METHOD,
          { username: 'a', password: 'b', secret: 'c' }),
        null
      );
      // ⛔ No defaultPort: a port would be written to `mgmt_port` and would
      // claim SecVault talks to something on it.
      assert.equal(resolveAccessMethod(slug, null).config.defaultPort, null);
    }
  });

  it('⛔ requires mgmt_ip, because that is what attributes its syslog', () => {
    // ⛔ NOT a leftover from the managed vendors. The collector's IP->device
    // map is vendor-agnostic — it selects mgmt_ip/snmp_host/smc_host plus
    // device_syslog_sources with no vendor filter — so for a log-only firewall
    // `mgmt_ip` IS the address its syslog arrives from. It is the one field
    // that makes attribution work, which is the entire point of adding it.
    for (const slug of MONITORING_SLUGS) assert.equal(VENDOR_META[slug].connection, 'mgmt');
    const collector = fs.readFileSync(
      path.join(__dirname, '../services/collector.js'), 'utf8');
    assert.match(collector, /SELECT id, mgmt_ip, snmp_host, smc_host FROM devices/);
    assert.equal(/FROM devices WHERE active = true AND vendor/.test(collector), false,
      'the device map must stay vendor-agnostic');
  });

  it('the short label carries no "(logs only)" qualifier', () => {
    // ⛔ It is used in narrow fleet-table columns beside managed firewalls,
    // where a parenthetical truncates to noise. The state belongs on the row,
    // never in the vendor's name.
    for (const slug of MONITORING_SLUGS) {
      const short = vendorLabel(slug, { short: true });
      assert.ok(short && !/logs only/i.test(short), `${slug} short label: ${short}`);
      assert.notEqual(short, slug, 'and it must not fall through to the raw slug');
    }
  });
});

describe('it is skipped, not failed', () => {
  const device = { id: 'd1', name: 'SRX-EDGE', vendor: 'juniper', mgmt_method: 'syslog' };

  it('isMonitoringOnly keys on the METHOD, not the vendor', () => {
    // ⛔ Modelling it as a vendor property would be untrue the day somebody
    // owns a Fortinet they have no credentials for — the common case this
    // unlocks next, and a strictly better state than leaving that firewall out
    // of the inventory so its syslog lands unattributed.
    assert.equal(isMonitoringOnly(device), true);
    assert.equal(isMonitoringOnly({ vendor: 'juniper', mgmt_method: 'api' }), false);
    assert.equal(isMonitoringOnly({ vendor: 'fortinet', mgmt_method: 'syslog' }), true);
    assert.equal(isMonitoringOnly(null), false);
    assert.equal(isMonitoringOnly({}), false);
  });

  it('⛔ collectAndStore returns a SKIP and reports no errors', async () => {
    // ⛔ Without this every pull throws and the device looks BROKEN — a
    // reachability problem somebody would go and investigate — rather than
    // deliberately log-only.
    const r = await collectAndStore(device, null);
    assert.equal(r.skipped, true);
    assert.equal(r.skippedReason, 'monitoring_only');
    assert.deepEqual(r.errors, []);
    assert.equal(r.version, null);
    assert.equal(r.rulesCount, null);
    assert.equal(r.configCollected, false);
  });

  it('⛔ it never touches the database, so last_collected_at stays NULL', async () => {
    // ⛔ Stamping it would make the device read as freshly collected on every
    // dashboard — the failed-read-as-a-fact rule aimed at the one field that
    // decides whether anybody looks at it again. A null pool proves no query
    // was attempted at all.
    const r = await collectAndStore(device, null);
    assert.equal(r.skipped, true);
  });

  it('getAdapter names the STATE rather than reporting an unsupported vendor', () => {
    // ⛔ "Unsupported vendor" would send somebody to write an adapter for a
    // firewall nobody asked to connect to.
    assert.throws(() => getAdapter(device, null), (e) => {
      assert.match(e.message, /monitoring-only/);
      assert.match(e.message, /SRX-EDGE/);
      assert.equal(/Unsupported vendor/.test(e.message), false);
      return true;
    });
  });
});

describe('it stays visible in the work queue', () => {
  const row = { device_id: 'd1', device_name: 'SRX-EDGE', vendor: 'juniper' };
  // ⛔ THE LAST-LOG FACT COMES FROM A SEPARATE, BUCKET-BOUNDED AGGREGATE, not a
  // per-device subquery. `syslog_rollup_hourly`'s only usable index leads with
  // `bucket_hour`, so a correlated `WHERE device_id = $1` seq-scanned the 8 GiB
  // permanent table — worst exactly for a device that had gone quiet, which is
  // the branch the item text is written for.
  const logged = [{ device_id: 'd1', last_log_at: new Date() }];

  it('⛔ it is EXCLUDED from collection_gap — all three query sites agree', async () => {
    // ⛔ THE SITE THAT MATTERS MOST IS THE THIRD. `gatherCoverageGaps` uses the
    // same predicate to decide which devices `collection_gap` already OWNS and
    // excludes them from itself. A device dropped from collection_gap's LIST
    // but still counted as owned would be reported by NEITHER source — the
    // silent disappearance the double-listing rule exists to prevent, arrived
    // at from the other side. One predicate, three uses.
    const pool = stubPool([[], [{ n: 0 }]]);
    await gatherCollectionGaps(pool);
    for (const q of pool.sql) {
      assert.match(q.text, /mgmt_method IS DISTINCT FROM \$2/,
        'every collection_gap query must exclude the monitoring-only method');
      assert.ok(q.params.includes(MONITORING_ONLY_METHOD));
    }
    const src = fs.readFileSync(
      path.join(__dirname, '../lib/engines/workQueueData.js'), 'utf8');
    const uses = src.match(/\$\{COLLECTABLE_SQL\}/g) || [];
    assert.equal(uses.length, 2,
      'the shared predicate covers the LIST and its COUNT — and only those two');
  });

  it('⛔ the ownership set is the UNION, not the same predicate', async () => {
    // ⛔ THIS TEST REPLACES ONE THAT ASSERTED THE OPPOSITE, AND THE FIRST DRAFT
    // OF v2.236.0 SHIPPED THE BUG IT ENCODED. `gatherCoverageGaps` asks "is
    // some other source already reporting this firewall's first step?", which
    // is NOT "does collection_gap list it?" — since v2.236.0 two sources
    // qualify. Reusing the shared predicate there excluded monitoring-only
    // devices from the ownership set, so `coverage_gap` listed them AGAIN
    // beside `monitoring_only`, and told the operator to collect a ruleset
    // from a firewall with no credentials.
    const src = fs.readFileSync(
      path.join(__dirname, '../lib/engines/workQueueData.js'), 'utf8');
    const block = src.slice(src.indexOf('const owned = new Set()'),
      src.indexOf('const owned = new Set()') + 500);
    assert.match(block, /d\.mgmt_method = \$2\s*\n\s*OR d\.last_collected_at IS NULL/,
      'the ownership set must be the UNION of collection_gap and monitoring_only');
    assert.equal(/\$\{COLLECTABLE_SQL\}/.test(block), false,
      'it must NOT reuse the list predicate');
  });

  it('⛔ IS DISTINCT FROM, never <> — mgmt_method is nullable on legacy rows', () => {
    // `NULL <> 'syslog'` is NULL, not true, so a plain inequality would
    // silently drop every pre-mgmt_method device from the one source that
    // reports firewalls nobody can see.
    const src = fs.readFileSync(
      path.join(__dirname, '../lib/engines/workQueueData.js'), 'utf8');
    const block = src.slice(src.indexOf('const COLLECTABLE_SQL'), src.indexOf('const COLLECTABLE_SQL') + 400);
    assert.match(block, /IS DISTINCT FROM/);
    assert.equal(/mgmt_method\s*<>/.test(block), false);
  });

  it('⛔ it IS listed by its own source, never merely hidden', async () => {
    const pool = stubPool([[row], logged, [{ n: 1 }]]);
    const items = itemsOf(await gatherMonitoringOnly(pool));
    assert.equal(items.length, 1);
    const item = items[0];
    assert.equal(item.type, 'monitoring_only');
    assert.deepEqual(item.deviceIds, ['d1']);
    assert.match(item.title, /never been assessed/);
  });

  it('⛔ it can NEVER reach act_now', async () => {
    // We are not asserting anything is wrong with the firewall; we are
    // asserting we cannot see it, which needs a person with credentials.
    const pool = stubPool([[row], logged, [{ n: 1 }]]);
    for (const item of itemsOf(await gatherMonitoringOnly(pool))) {
      assert.equal(item.evidence, 'unmeasured');
      assert.equal(bandFor(item), 'verify');
    }
  });

  it('⛔ the claim says NOT RUN, never passed or clean', async () => {
    // ⛔ The single sentence this whole feature exists to make true.
    assert.match(MONITORING_ONLY_CLAIM, /never run/);
    for (const word of ['passed', 'clean', 'compliant', 'secure', 'no issues']) {
      assert.equal(
        new RegExp(`\\b${word}\\b`, 'i').test(MONITORING_ONLY_CLAIM.replace(/not because[\s\S]*/, '')),
        false,
        `the claim must not contain "${word}" as a positive statement`
      );
    }
    // And the remedy is real and actionable, not a shrug.
    assert.match(MONITORING_ONLY_REMEDY, /management connection/);
    assert.match(MONITORING_ONLY_REMEDY, /log collection is unaffected/);
  });

  it('⛔ ONE sentence, imported — the item does not write its own', () => {
    const src = fs.readFileSync(
      path.join(__dirname, '../lib/engines/workQueueData.js'), 'utf8');
    assert.match(src, /why: MONITORING_ONLY_CLAIM/);
    assert.match(src, /action: MONITORING_ONLY_REMEDY/);
  });

  it('a device sending no logs either is told so, separately', async () => {
    // ⛔ Whether its LOGS arrive is a SEPARATE fact from whether it is
    // assessed. A log-only firewall that has also gone quiet is contributing
    // nothing at all, and that is the one thing it was added for.
    // No row in the aggregate = nothing rolled up in the window.
    const pool = stubPool([[row], [], [{ n: 1 }]]);
    const out = itemsOf(await gatherMonitoringOnly(pool));
    assert.match(out[0].why, /contributing nothing at all/);
    const loud = stubPool([[row], logged, [{ n: 1 }]]);
    const out2 = itemsOf(await gatherMonitoringOnly(loud));
    assert.equal(/contributing nothing at all/.test(out2[0].why), false);
    // ⛔ And the aggregate is BOUNDED so it can use the bucket_hour index.
    assert.match(pool.sql[1].text, /bucket_hour > now\(\) - interval/);
    assert.match(pool.sql[1].text, /device_id = ANY/);
  });

  it('it is capped and the truncation is disclosed', async () => {
    const many = Array.from({ length: PER_SOURCE_CAP }, (_, i) => ({
      device_id: `d${i}`, device_name: `FW-${i}`, vendor: 'juniper',
    }));
    const pool = stubPool([many, [], [{ n: 77 }]]);
    const out = await gatherMonitoringOnly(pool);
    assert.equal(itemsOf(out).length, PER_SOURCE_CAP);
    assert.equal(out.truncatedFrom, 77, 'the cap must disclose the real total');
  });

  it('⛔ it is in NEVER_ACT_NOW_SOURCES, or it silences ALL outbound alerting', () => {
    // ⛔ A LATENT TOTAL OUTAGE. Its items can never reach `act_now`, so it
    // meets the criterion — but the dispatcher REFUSES to reconcile a
    // truncated queue, so past PER_SOURCE_CAP log-only firewalls this source
    // would report `truncatedFrom` on every 15-minute poll and permanently
    // silence every `work_act_now` alert, with no recovery. The identical
    // structural dead end this file already records as fixed once, for
    // `coverage`.
    const { NEVER_ACT_NOW_SOURCES } = require('../lib/engines/workQueueData');
    assert.ok(NEVER_ACT_NOW_SOURCES.includes('monitoring_only'));
  });

  it('⛔ its label is NOT "Collection"', () => {
    // Sharing a label would put both under one filter option and lose the
    // distinction the two sources exist to draw.
    assert.equal(WORK_TYPE_LABEL.monitoring_only, 'Logs only');
    assert.notEqual(WORK_TYPE_LABEL.monitoring_only, WORK_TYPE_LABEL.collection_gap);
  });
});

describe('the Add Device form asks for no credential', () => {
  it('⛔ every credential control is gated on needsCredential', () => {
    // ⛔ Without the gate the form falls through to its Username/Password
    // branch — the else arm, reached by any shape that is not `secret` or
    // `apikey_or_userpass` — and asks for credentials for a firewall SecVault
    // will never connect to. buildCredentialPlaintext returns null for this
    // shape, so what the operator typed would be silently discarded and they
    // would be left believing a management connection exists.
    const src = fs.readFileSync(
      path.join(__dirname, '../components/devices/DeviceForm.js'), 'utf8')
      .replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
    assert.match(src, /const needsCredential = shape !== 'none'/);
    // The secret/userpass block, the auth-mode switch, the saved-profile
    // picker and the save-as-profile checkbox — all four.
    const gated = src.match(/needsCredential/g) || [];
    assert.ok(gated.length >= 5,
      `expected the declaration plus four gated blocks, found ${gated.length}`);
  });
});
