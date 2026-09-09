'use strict';
// Pins the three defects behind one wrong sentence on screen.
//
// On 2026-09-09 the Devices table said "Failing 0% of polls succeeding" about
// OKF(F2) — a FortiGate that had just been collected in full, was answering its
// metric and test polls, and was reachable over SSH. Three separate bugs
// stacked up to produce it:
//
//   1. `vpn` was missing from VALID_SOURCES, so recordConnectivity's
//      unrecognised-source fallback silently filed every VPN observation under
//      `collect`. The tooltip then blamed a collect that had never run.
//   2. An UNREADABLE OPTIONAL CAPABILITY was recorded as the device being
//      unreachable. The SSH session connected, logged in and ran the command;
//      only SSL-VPN was absent. "This feature is not configured" became "this
//      device is down" — the failed-read-as-a-fact rule one layer up.
//   3. The note printed a bare percentage with no subject. worstRate is the
//      MINIMUM across sources by design, so without naming the source it reads
//      as "nothing about this device works".

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  VALID_SOURCES,
  recordConnectivity,
  pollHealthBand,
} = require('../lib/engines/connectivityHistory');
const {
  CapabilityUnavailableError,
  isCapabilityUnavailable,
} = require('../lib/adapters/interface');

function makePool() {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql: String(sql), params });
      return { rows: [], rowCount: 0 };
    },
  };
}

describe('connectivity sources', () => {
  it('accepts vpn as a real source instead of relabelling it collect', async () => {
    // ⛔ The bug. VPN observations were added 2026-08-25 precisely so a failing
    // VPN poll would stop reading as healthy, but the source string was never
    // whitelisted — so they landed on `collect` and misattributed the failure.
    assert.ok(VALID_SOURCES.has('vpn'));
    const pool = makePool();
    await recordConnectivity(pool, 'dev-1', { reachable: false, source: 'vpn', message: 'x' });
    assert.equal(pool.calls[0].params[3], 'vpn');
  });

  it('covers every source the pollers actually write', () => {
    for (const s of ['test', 'collect', 'metrics', 'vpn']) {
      assert.ok(VALID_SOURCES.has(s), `${s} must be a recognised source`);
    }
  });

  it('still files an unknown source rather than losing the observation', async () => {
    // The fallback is deliberate — a bad source string must not silently drop
    // an observation. It is only dangerous when a REAL source is missing from
    // the set, which the tests above are what prevent.
    const pool = makePool();
    await recordConnectivity(pool, 'dev-1', { reachable: false, source: 'nonsense' });
    assert.equal(pool.calls[0].params[3], 'collect');
  });

  it('never throws — the caller is always doing something more important', async () => {
    const exploding = { query: async () => { throw new Error('db gone'); } };
    await recordConnectivity(exploding, 'dev-1', { reachable: true, source: 'metrics' });
  });
});

describe('a capability that cannot be read is not an unreachable device', () => {
  it('flags CapabilityUnavailableError as not-reachability-evidence', () => {
    const err = new CapabilityUnavailableError('no SSL-VPN here', { capability: 'vpn_session_summary' });
    assert.equal(isCapabilityUnavailable(err), true);
    assert.equal(err.deviceWasReached, true);
    assert.equal(err.capability, 'vpn_session_summary');
  });

  it('leaves an ordinary transport failure counting against the device', () => {
    // ⛔ The counter-test. An SSH timeout IS reachability evidence and must
    // keep marking the device unreachable — the fix must not swallow real
    // outages along with absent features.
    assert.equal(isCapabilityUnavailable(new Error('connect ETIMEDOUT')), false);
    assert.equal(isCapabilityUnavailable(null), false);
    assert.equal(isCapabilityUnavailable(undefined), false);
  });

  it('detects the marker by flag, not instanceof', () => {
    // Adapters and engines load through several paths here; an instanceof
    // across two module instances of the same file silently returns false.
    assert.equal(isCapabilityUnavailable({ deviceWasReached: true }), true);
  });

  it('the Fortinet SSL-VPN parse refusal throws the typed error', () => {
    // Pinned at the source level: requiring the adapter drags in ssh2 and a
    // live session, and what matters is that this specific refusal is typed.
    const fs = require('node:fs');
    const src = fs.readFileSync(require.resolve('../lib/adapters/fortinet/ssh.js'), 'utf8');
    assert.match(src, /throw new CapabilityUnavailableError\(/);
    assert.match(src, /Refusing to guess a session count/);
    const idx = src.indexOf('Refusing to guess a session count');
    const before = src.slice(Math.max(0, idx - 900), idx);
    assert.match(before, /CapabilityUnavailableError/, 'the refusal must throw the typed error');
  });
});

describe('the poll-health note says WHAT is failing', () => {
  it('reports which source is worst alongside the rate', () => {
    // worstRate is the minimum across sources, so the number is meaningless
    // without its subject.
    const src = require('node:fs').readFileSync(
      require.resolve('../lib/engines/connectivityHistory.js'), 'utf8'
    );
    assert.match(src, /worstSource/);
    assert.match(src, /d\.worstSource = r\.source/);
  });

  it('renders the operator-facing source name, not the internal key', () => {
    const src = require('node:fs').readFileSync(
      require.resolve('../components/devices/DevicePostureCells.js'), 'utf8'
    );
    assert.match(src, /SOURCE_LABEL/);
    assert.match(src, /VPN session polling/);
    assert.match(src, /config collection/);
  });
});

describe('bands', () => {
  it('no observations is unknown, NOT healthy', () => {
    // ⛔ A device nobody has polled has not been proven fine. This is the same
    // rule as the security score: absence of data is not a good result.
    assert.equal(pollHealthBand(null), 'unknown');
    assert.equal(pollHealthBand({ worstRate: null }), 'unknown');
    assert.equal(pollHealthBand({ worstRate: undefined }), 'unknown');
  });

  it('a measured zero is failing, and a measured one is healthy', () => {
    assert.equal(pollHealthBand({ worstRate: 0 }), 'failing');
    assert.equal(pollHealthBand({ worstRate: 1 }), 'healthy');
  });
});
