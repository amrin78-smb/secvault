// tests/deviceDiscovery.test.js
//
// Syslog-discovered senders. Per tests/README.md, the cases that matter most
// here are the ones where SecVault CANNOT know something — those are what
// regress silently, because the wrong answer is a plausible inventory row
// rather than a crash.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  correlateSender,
  runDeviceDiscovery,
  DEFAULT_MIN_HOURS,
  DEFAULT_MIN_EVENTS,
} = require('../lib/engines/deviceDiscovery');

function stubPool(handlers) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      for (const [pat, rows] of handlers) {
        if (sql.includes(pat)) {
          const r = typeof rows === 'function' ? rows(params) : rows;
          return { rows: r, rowCount: r.length };
        }
      }
      return { rows: [], rowCount: 0 };
    },
  };
}

// The five real HA pairs on this fleet, verified live.
const HA = [
  { device_id: 'd-itc', device_name: 'ITC-SK', peer_mgmt_ip: '172.48.0.27', peer_serial: '023001020785' },
  { device_id: 'd-smt', device_name: 'SMT', peer_mgmt_ip: '172.24.0.27', peer_serial: '023001021712' },
  { device_id: 'd-idc', device_name: 'IDC FW', peer_mgmt_ip: '192.168.3.251', peer_serial: '016201042291' },
];

describe('correlateSender: most "unknown" senders are already known', () => {
  it('⛔ recognises an HA passive peer by its peer address', () => {
    // THE finding that shaped this feature: 5 of 8 unmatched senders on the
    // live fleet are HA peers SecVault already holds in device_ha_status.
    // Auto-adding them would have created five duplicate firewalls.
    const r = correlateSender({ source_ip: '172.48.0.27/32' }, HA, []);
    assert.equal(r.kind, 'ha-peer');
    assert.equal(r.deviceName, 'ITC-SK');
    assert.match(r.evidence, /peer address 172\.48\.0\.27/);
  });

  it('recognises a peer by SERIAL even when its address changed', () => {
    // A renumbered peer is still the same box. Serial is what ties the old and
    // new addresses together.
    const r = correlateSender(
      { source_ip: '10.99.99.99', observed_serial: '023001021712' },
      HA,
      []
    );
    assert.equal(r.kind, 'ha-peer');
    assert.equal(r.deviceName, 'SMT');
    assert.match(r.evidence, /peer serial/);
  });

  it('a genuinely unmanaged firewall is reported as such', () => {
    const r = correlateSender({ source_ip: '10.204.6.1' }, HA, []);
    assert.equal(r.kind, 'unmanaged');
    assert.equal(r.deviceId, null);
  });

  it('an already-linked alias is not re-offered', () => {
    const r = correlateSender({ source_ip: '10.204.6.1' }, HA, [
      { device_id: 'd-x', device_name: 'OkeanosFOOD', source_ip: '10.204.6.1' },
    ]);
    assert.equal(r.kind, 'known-alias');
    assert.equal(r.deviceName, 'OkeanosFOOD');
  });

  it('⛔ states the EVIDENCE, not just a verdict', () => {
    // An operator about to merge two firewalls must see what matched.
    const r = correlateSender({ source_ip: '192.168.3.251' }, HA, []);
    assert.ok(r.evidence && r.evidence.length > 10);
  });
});

describe('runDeviceDiscovery: never fabricates inventory', () => {
  const CANDIDATE_SQL = 'FROM syslog_rollup_hourly';
  const IDENTITY_SQL = 'FROM syslog_events';
  const UPSERT_SQL = 'INSERT INTO discovered_devices';

  it('⛔ requires sustained traffic — the thresholds are in the SQL', async () => {
    const pool = stubPool([[CANDIDATE_SQL, []]]);
    const s = await runDeviceDiscovery(pool);
    const q = pool.calls.find((c) => c.sql.includes(CANDIDATE_SQL));
    // A single stray or spoofed packet must not mint an inventory row. Live,
    // the one junk sender (127.0.0.1) showed 1 hour / 1 event while every real
    // one showed 18 hours.
    assert.match(q.sql, /count\(DISTINCT bucket_hour\) >= \$2/);
    assert.match(q.sql, /sum\(event_count\) >= \$3/);
    assert.equal(q.params[1], DEFAULT_MIN_HOURS);
    assert.equal(q.params[2], DEFAULT_MIN_EVENTS);
    assert.equal(s.candidates, 0);
  });

  it('⛔ excludes loopback, link-local and CGNAT', async () => {
    const pool = stubPool([[CANDIDATE_SQL, []]]);
    await runDeviceDiscovery(pool);
    const q = pool.calls.find((c) => c.sql.includes(CANDIDATE_SQL));
    for (const cidr of ['127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10']) {
      assert.ok(q.sql.includes(cidr), 'missing ' + cidr);
    }
  });

  it('⛔ the lookback is BOUNDED, and cast explicitly', async () => {
    // The rollup copies device_id verbatim and never re-resolves it, so
    // historical rows for a promoted sender keep device_id NULL forever. An
    // unbounded window would re-list every promoted device on every run.
    const pool = stubPool([[CANDIDATE_SQL, []]]);
    await runDeviceDiscovery(pool, { lookbackHours: 48 });
    const q = pool.calls.find((c) => c.sql.includes(CANDIDATE_SQL));
    assert.match(q.sql, /bucket_hour >= now\(\) - \(\$1::int \* interval '1 hour'\)/);
  });

  it('⛔ a pass that saw no vendor does not ERASE one seen earlier', async () => {
    // Vendor detection is intermittent — one live sender read 0% vendor for a
    // full hour despite being a Palo Alto whose log format the parser does not
    // yet recognise. COALESCE is what stops "not seen this pass" overwriting
    // "seen last pass" with NULL.
    const pool = stubPool([
      [CANDIDATE_SQL, [{
        source_ip: '10.204.6.1', event_count: '4371185', observed_hours: 18,
        first_seen_at: new Date(0), last_seen_at: new Date(0), vendors: [],
      }]],
      [IDENTITY_SQL, []],
      [UPSERT_SQL, [{ inserted: true }]],
    ]);
    await runDeviceDiscovery(pool);
    const up = pool.calls.find((c) => c.sql.includes(UPSERT_SQL));
    assert.match(up.sql, /observed_vendor\s*=\s*COALESCE\(EXCLUDED\.observed_vendor/);
    assert.match(up.sql, /observed_hostname\s*=\s*COALESCE\(EXCLUDED\.observed_hostname/);
    // and it stored NULL rather than a guessed vendor
    assert.equal(up.params[1], null);
  });

  it('⛔ an operator DECISION is never overwritten by an observation', async () => {
    const pool = stubPool([
      [CANDIDATE_SQL, [{
        source_ip: '10.204.6.1', event_count: '500', observed_hours: 5,
        first_seen_at: new Date(0), last_seen_at: new Date(0), vendors: ['fortinet'],
      }]],
      [IDENTITY_SQL, []],
      [UPSERT_SQL, [{ inserted: false }]],
    ]);
    await runDeviceDiscovery(pool);
    const up = pool.calls.find((c) => c.sql.includes(UPSERT_SQL));
    // A promoted/ignored sender must not be resurrected as 'new'.
    for (const col of ['status', 'decided_by', 'decided_at', 'promoted_device_id', 'linked_device_id']) {
      assert.ok(
        !new RegExp(`${col}\\s*=\\s*EXCLUDED`).test(up.sql),
        `${col} must not be overwritten by the discovery job`
      );
    }
  });

  it('flags a source emitting more than one vendor as a possible relay', async () => {
    const pool = stubPool([
      [CANDIDATE_SQL, [{
        source_ip: '10.1.1.1', event_count: '900', observed_hours: 9,
        first_seen_at: new Date(0), last_seen_at: new Date(0),
        vendors: ['fortinet', 'paloalto'],
      }]],
      [IDENTITY_SQL, []],
      [UPSERT_SQL, [{ inserted: true }]],
    ]);
    await runDeviceDiscovery(pool);
    const up = pool.calls.find((c) => c.sql.includes(UPSERT_SQL));
    assert.equal(up.params[3], true, 'vendor_conflict must be set');
  });

  it('never throws — a DB failure is reported in the summary', async () => {
    const pool = { async query() { throw new Error('connection reset'); } };
    const s = await runDeviceDiscovery(pool);
    assert.ok(s.errors.length > 0);
    assert.equal(s.inserted, 0);
  });
});
