'use strict';

// ⛔ ROADMAP ROW 37: A WHOLE-CONFIG READ FAILURE WAS PERSISTED AS A MASS CONFIG DELETION.
//
// `detectAndStoreDiff` diffed the two newest device_configs rows with no test of whether the
// NEWER one is usable, and `diffConfigs` treats a truncated tree as a legitimate config — so
// every section absent from a short snapshot came out as `removed`.
//
// Measured on production: TSR_EKM, 2026-08-06 10:26 — `0 added, 142 removed` across six
// unrelated top-level sections, then `142 added, 0 removed` with an identical breakdown 54
// minutes later. Nothing changed on the device. The operator was told the firewall's SSL-VPN,
// FortiGuard, SNMP, NTP and syslog configuration had been wiped, and the false change drove a
// CVE re-match, an `auto` backup row and the `config_diff` outbound alert.
//
// The threshold is MEASURED: across the whole retained history on the reference fleet (259
// consecutive snapshot pairs, 16 firewalls, both vendors) ZERO pairs lose a top-level section.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { detectAndStoreDiff, lostTopLevelSections } = require('../lib/engines/configDiff');

// The six sections TSR_EKM "lost", plus the ones it kept.
const FULL = {
  system: { hostname: 'TSR_EKM' },
  firewall: { policy: [{ id: 1, action: 'accept' }] },
  ssl_vpn: { port: 10443, source_interface: 'wan1' },
  fortiguard: { protocol: 'https' },
  snmp: { community: 'public' },
  log_syslogd: { server: '10.0.0.1' },
  ntp: { ntpsync: 'enable' },
  autoupdate: { schedule: 'daily' },
};
// What a truncated pull produced: the first `config <word>` block only.
const TRUNCATED = {
  system: { hostname: 'TSR_EKM' },
  firewall: { policy: [{ id: 1, action: 'accept' }] },
};

function diffPool(latest, previous) {
  const calls = { inserts: 0 };
  return {
    calls,
    query: async (sql, params) => {
      const q = String(sql);
      if (/FROM device_configs/i.test(q)) {
        return {
          rows: [
            { id: 'c-new', config_parsed: latest, collected_at: '2026-08-06T10:26:00Z' },
            { id: 'c-old', config_parsed: previous, collected_at: '2026-08-06T09:26:00Z' },
          ],
        };
      }
      if (/INSERT INTO config_diffs/i.test(q)) {
        calls.inserts += 1;
        calls.lastDiff = JSON.parse(params[1]);
        return { rows: [{ id: 'd-1' }] };
      }
      return { rows: [] };
    },
  };
}

describe('lostTopLevelSections', () => {
  it('names the sections that vanished, sorted', () => {
    assert.deepEqual(
      lostTopLevelSections(FULL, TRUNCATED),
      ['autoupdate', 'fortiguard', 'log_syslogd', 'ntp', 'snmp', 'ssl_vpn']
    );
  });

  it('is empty when nothing vanished, including when sections were ADDED', () => {
    assert.deepEqual(lostTopLevelSections(FULL, FULL), []);
    assert.deepEqual(lostTopLevelSections(TRUNCATED, FULL), [], 'a new section is not a loss');
  });

  it('⛔ reports nothing when either side is not a real object', () => {
    // "Every section vanished" is true of a null snapshot and useless — that case has its own
    // branch and its own sentence in detectAndStoreDiff.
    for (const bad of [null, undefined, [], 'config system', 7]) {
      assert.deepEqual(lostTopLevelSections(FULL, bad), [], `new=${JSON.stringify(bad)}`);
      assert.deepEqual(lostTopLevelSections(bad, FULL), [], `old=${JSON.stringify(bad)}`);
    }
  });

  it('a nested change is not a section loss', () => {
    const changed = { ...FULL, snmp: { community: 'private' } };
    assert.deepEqual(lostTopLevelSections(FULL, changed), []);
  });
});

describe('detectAndStoreDiff refuses to record a mass deletion it cannot believe', () => {
  it('⛔ stores NO config_diffs row for the TSR_EKM truncation shape', async () => {
    const pool = diffPool(TRUNCATED, FULL);
    const out = await detectAndStoreDiff('d-1', pool, 'fortinet');
    assert.equal(pool.calls.inserts, 0, 'the fabricated 142-removal row must never be written');
    assert.equal(out.changed, false);
    assert.equal(out.diffId, null);
  });

  it('⛔ reports the suppression instead of swallowing it', async () => {
    // A guard that withheld the diff silently would be indistinguishable from a device that
    // stopped changing — the same failed-read-as-a-fact bug, aimed at its own fix.
    const out = await detectAndStoreDiff('d-1', diffPool(TRUNCATED, FULL), 'fortinet');
    assert.equal(out.suppressed, true);
    assert.equal(typeof out.suppressedReason, 'string');
    assert.deepEqual(out.lostSections, [
      'autoupdate', 'fortiguard', 'log_syslogd', 'ntp', 'snmp', 'ssl_vpn',
    ], 'the reason must NAME the sections, so an operator can check them on the device');
  });

  it('the reason says truncation-or-scope, never "the configuration was deleted"', async () => {
    const out = await detectAndStoreDiff('d-1', diffPool(TRUNCATED, FULL), 'fortinet');
    assert.match(out.suppressedReason, /truncated or scope-restricted/);
    assert.doesNotMatch(out.suppressedReason, /deleted|removed from the device/i);
  });

  it('⛔ an unusable newest snapshot has its OWN sentence, not the section one', async () => {
    for (const bad of [null, {}]) {
      const out = await detectAndStoreDiff('d-1', diffPool(bad, FULL), 'fortinet');
      assert.equal(out.suppressed, true);
      assert.match(out.suppressedReason, /empty or unparseable/);
      assert.deepEqual(out.lostSections, [], 'no section list — nothing was comparable');
    }
  });

  it('a FIRST usable snapshot after an unusable one is not a suppression', async () => {
    // The reverse direction: recovering from a bad pull must not be withheld too, or a device
    // would never produce a diff again after one truncated collection.
    const pool = diffPool(FULL, TRUNCATED);
    const out = await detectAndStoreDiff('d-1', pool, 'fortinet');
    assert.equal(out.suppressed, false);
    assert.equal(out.changed, true, 'the sections reappearing IS a recorded change');
    assert.equal(pool.calls.inserts, 1);
  });
});

describe('a real configuration change still records normally', () => {
  it('⛔ records a genuine within-section change — the no-regression case', async () => {
    // A guard that suppressed everything would pass every test above.
    const changed = { ...FULL, snmp: { community: 'private' } };
    const pool = diffPool(changed, FULL);
    const out = await detectAndStoreDiff('d-1', pool, 'fortinet');
    assert.equal(out.changed, true);
    assert.equal(out.suppressed, false);
    assert.equal(pool.calls.inserts, 1);
  });

  it('records a genuine rule addition', async () => {
    const changed = {
      ...FULL,
      firewall: { policy: [{ id: 1, action: 'accept' }, { id: 2, action: 'accept' }] },
    };
    const pool = diffPool(changed, FULL);
    assert.equal((await detectAndStoreDiff('d-1', pool, 'fortinet')).changed, true);
    assert.equal(pool.calls.inserts, 1);
  });

  it('an identical snapshot is still no change, and is NOT reported as suppressed', async () => {
    const pool = diffPool(FULL, FULL);
    const out = await detectAndStoreDiff('d-1', pool, 'fortinet');
    assert.equal(out.changed, false);
    assert.equal(out.suppressed, false, 'nothing was withheld — there was nothing to withhold');
    assert.equal(pool.calls.inserts, 0);
  });

  it('fewer than two snapshots is neither a change nor a suppression', async () => {
    const pool = { query: async () => ({ rows: [{ id: 'c', config_parsed: FULL }] }) };
    const out = await detectAndStoreDiff('d-1', pool, 'fortinet');
    assert.equal(out.changed, false);
    assert.ok(!out.suppressed);
  });
});
