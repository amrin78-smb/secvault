'use strict';
// Pins the boundary between "this device is DOWN" and "this FEATURE is absent",
// in both directions, plus the monthly report's clock.
//
// ⛔ WHY THIS EXISTS. CapabilityUnavailableError was added on 2026-09-09 for
// exactly one call site, and the other seven kept throwing bare Errors. Every
// one of them sits AFTER a successful connect + login + command, so each one
// could still turn "SSL-VPN is not configured" / "this ASA has no VPN licence"
// into `reachable: false` — the sentence "Failing 0% of polls succeeding" about
// a firewall that had just been collected in full.
//
// The opposite error shipped the same day in paloalto/index.js's API
// getPerformanceMetrics(): both device calls only console.warn'd, so a totally
// unreachable firewall RETURNED NORMALLY with all-null metrics and the poller
// wrote `reachable: true` on the fleet's densest heartbeat. The metric row was
// honest; the reachability boolean was fabricated.
//
// Both are the same rule pointing opposite ways, and a test that only covers
// one of them is how the other comes back. So every conversion below is paired
// with its NEGATIVE: a genuine transport failure must stay a plain Error and
// keep counting against the device. That is this file's "we could not measure
// it" case — the one that regresses silently, because a wrong reachability
// boolean is a plausible-looking boolean rather than a crash.
//
// ⛔ Detection is asserted on the err.deviceWasReached FLAG, never instanceof:
// adapters and engines load through several paths here and an instanceof across
// two module instances of interface.js silently returns false — which fails
// CLOSED to "unreachable" and quietly restores the bug.
//
// No database and no device: every adapter here gets its transport stubbed on
// the instance, so nothing in this file can open a socket.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { isCapabilityUnavailable } = require('../lib/adapters/interface');
const { FortinetSshAdapter } = require('../lib/adapters/fortinet/ssh');
const { FortinetAdapter } = require('../lib/adapters/fortinet/index');
const { PaloaltoSshAdapter } = require('../lib/adapters/paloalto/ssh');
const { PaloaltoAdapter } = require('../lib/adapters/paloalto/index');
const { CiscoAsaAdapter } = require('../lib/adapters/cisco_asa/index');
const fortinetApi = require('../lib/adapters/fortinet/api');
const paloaltoApi = require('../lib/adapters/paloalto/api');
const { reportingPeriod, dispatchMonthlyReport } = require('../lib/engines/complianceReport');

const REPO = path.join(__dirname, '..');
const DEVICE = { id: 'dev-1', name: 'TEST-FW', mgmt_ip: '10.0.0.1', vendor: 'test' };
const POOL = { query: async () => ({ rows: [], rowCount: 0 }) };

// Captures the rejection of `fn()` without letting a RESOLVE pass silently —
// "it returned instead of throwing" is itself one of the bugs under test.
async function rejection(fn) {
  try {
    const value = await fn();
    assert.fail(`expected a rejection, but it resolved with ${JSON.stringify(value)}`);
  } catch (err) {
    if (err instanceof assert.AssertionError) throw err;
    return err;
  }
}

function assertReachedButUnreadable(err) {
  assert.equal(
    isCapabilityUnavailable(err),
    true,
    `the transport succeeded here, so this must NOT count against reachability: ${err.message}`
  );
  assert.equal(err.deviceWasReached, true, 'detection is by flag, not instanceof');
  assert.equal(err.capability, 'vpn_session_summary');
}

function assertCountsAgainstReachability(err) {
  assert.equal(
    isCapabilityUnavailable(err),
    false,
    `a connect/login/timeout failure IS reachability evidence and must keep counting: ${err.message}`
  );
  assert.ok(err instanceof Error);
}

// ---------------------------------------------------------------------------
// Fortinet — SSH transport
// ---------------------------------------------------------------------------

describe('Fortinet SSH getVpnSessionSummary', () => {
  function adapter() {
    return new FortinetSshAdapter({ device: DEVICE, pool: POOL });
  }

  it('an access-profile rejection is a reached device, not a down one', async () => {
    const a = adapter();
    a._getSystemStatus = async () => ({}); // not multi-VDOM
    // The SSH batch RESOLVED — connect, login and command all succeeded. What
    // came back is the device's own refusal, printed at its own prompt.
    a._run = async () => [{ command: 'get vpn ssl monitor', output: '\n-1: Permission denied\n' }];
    assertReachedButUnreadable(await rejection(() => a.getVpnSessionSummary()));
  });

  it('an unreadable VDOM list is a scope limit on the admin account, not a down device', async () => {
    const a = adapter();
    a._getSystemStatus = async () => ({ vdom_mode: 'multi-vdom' });
    // null here means `show system vdom` ANSWERED and carried no VDOM block; a
    // failed batch would have thrown out of _run() before this point.
    a._discoverVdomsForVpnPoll = async () => null;
    assertReachedButUnreadable(await rejection(() => a.getVpnSessionSummary()));
  });

  it('refusing to send unsafe VDOM names is a fact about the names, not the firewall', async () => {
    const a = adapter();
    a._getSystemStatus = async () => ({ vdom_mode: 'multi-vdom' });
    a._discoverVdomsForVpnPoll = async () => ['root', 'bad name; reboot'];
    assertReachedButUnreadable(await rejection(() => a.getVpnSessionSummary()));
  });

  it('"failed for every VDOM" is safe to treat as reached — one batch, already resolved', async () => {
    const a = adapter();
    a._getSystemStatus = async () => ({ vdom_mode: 'multi-vdom' });
    a._discoverVdomsForVpnPoll = async () => ['root', 'vd2'];
    // Every command rode in ONE _run() that RESOLVED, so each per-VDOM failure
    // below is a rejection or a parse miss — never a transport failure.
    a._run = async (commands) =>
      commands.map((command) => ({ command, output: '\ncommand parse error\n' }));
    assertReachedButUnreadable(await rejection(() => a.getVpnSessionSummary()));
  });

  it('⛔ NEGATIVE: an SSH transport failure stays plain and keeps counting against the device', async () => {
    const a = adapter();
    a._getSystemStatus = async () => ({});
    a._run = async () => {
      throw new Error('connect ETIMEDOUT 10.0.0.1:22');
    };
    assertCountsAgainstReachability(await rejection(() => a.getVpnSessionSummary()));
  });
});

// ---------------------------------------------------------------------------
// Fortinet — REST transport
// ---------------------------------------------------------------------------

describe('Fortinet REST getVpnSessionSummary', () => {
  function adapter() {
    const a = new FortinetAdapter({ device: DEVICE, pool: POOL });
    a._withSession = async (fn) => fn({ stub: true });
    a._discoverVdoms = async () => null;
    return a;
  }

  // Patch the module object (not a destructured binding) — index.js calls
  // api.getSslVpnMonitor() through the same object, so this is visible to it.
  async function withStubbedMonitor(impl, fn) {
    const original = fortinetApi.getSslVpnMonitor;
    fortinetApi.getSslVpnMonitor = impl;
    try {
      return await fn();
    } finally {
      fortinetApi.getSslVpnMonitor = original;
    }
  }

  it("a response with no 'results' array is a reached device with no SSL-VPN", async () => {
    const a = adapter();
    // The HTTP call RETURNED. Auth worked, the endpoint answered — the body
    // just carries no session array, which on FortiOS means the feature is off.
    await withStubbedMonitor(
      async () => ({ http_status: 200, some_other_shape: true }),
      async () => assertReachedButUnreadable(await rejection(() => a.getVpnSessionSummary()))
    );
  });

  it('⛔ NEGATIVE: a failed HTTP call stays plain and keeps counting against the device', async () => {
    const a = adapter();
    await withStubbedMonitor(
      async () => {
        throw new Error('connect ECONNREFUSED 10.0.0.1:443');
      },
      async () => assertCountsAgainstReachability(await rejection(() => a.getVpnSessionSummary()))
    );
  });
});

// ---------------------------------------------------------------------------
// Palo Alto — SSH transport
// ---------------------------------------------------------------------------

describe('Palo Alto SSH getVpnSessionSummary', () => {
  it('a rejected op-command is a reached device, not a down one', async () => {
    const a = new PaloaltoSshAdapter({ device: DEVICE, pool: POOL });
    a._run = async (commands) => commands.map((command) => ({ command, output: '\nInvalid syntax.\n' }));
    assertReachedButUnreadable(await rejection(() => a.getVpnSessionSummary()));
  });

  it('⛔ NEGATIVE: an SSH transport failure stays plain and keeps counting against the device', async () => {
    const a = new PaloaltoSshAdapter({ device: DEVICE, pool: POOL });
    a._run = async () => {
      throw new Error('All configured authentication methods failed');
    };
    assertCountsAgainstReachability(await rejection(() => a.getVpnSessionSummary()));
  });
});

// ---------------------------------------------------------------------------
// Cisco ASA
// ---------------------------------------------------------------------------

describe('Cisco ASA getVpnSessionSummary', () => {
  it('a privilege rejection is a reached device, not a down one', async () => {
    const a = new CiscoAsaAdapter({ device: DEVICE, pool: POOL });
    a._run = async (commands) =>
      commands.map((command) => ({ command, output: '\nERROR: Command authorization failed\n' }));
    assertReachedButUnreadable(await rejection(() => a.getVpnSessionSummary()));
  });

  it('output that is not a session-summary table (an ASA with no VPN licence) is reached, not down', async () => {
    const a = new CiscoAsaAdapter({ device: DEVICE, pool: POOL });
    // Not a CLI rejection — the ASA answered, the answer just is not a summary
    // table. On an unlicensed ASA that is the NORMAL answer.
    a._run = async (commands) => commands.map((command) => ({ command, output: 'INFO: nothing to report\n' }));
    assertReachedButUnreadable(await rejection(() => a.getVpnSessionSummary()));
  });

  it('⛔ NEGATIVE: an SSH transport failure stays plain and keeps counting against the device', async () => {
    const a = new CiscoAsaAdapter({ device: DEVICE, pool: POOL });
    a._run = async () => {
      throw new Error('connect ETIMEDOUT');
    };
    assertCountsAgainstReachability(await rejection(() => a.getVpnSessionSummary()));
  });
});

// ---------------------------------------------------------------------------
// The opposite direction: a dead device must not be reported as up
// ---------------------------------------------------------------------------

describe('Palo Alto API getPerformanceMetrics', () => {
  function adapter() {
    const a = new PaloaltoAdapter({ device: DEVICE, pool: POOL });
    a._getConn = async () => ({ stub: true });
    return a;
  }

  async function withStubbedApi({ resources, session }, fn) {
    const originals = {
      showSystemResources: paloaltoApi.showSystemResources,
      showSessionInfo: paloaltoApi.showSessionInfo,
    };
    if (resources) paloaltoApi.showSystemResources = resources;
    if (session) paloaltoApi.showSessionInfo = session;
    try {
      return await fn();
    } finally {
      paloaltoApi.showSystemResources = originals.showSystemResources;
      paloaltoApi.showSessionInfo = originals.showSessionInfo;
    }
  }

  it('⛔ THROWS when the primary reading fails — it must never return all-nulls as a successful poll', async () => {
    // Before 2026-09-09 this resolved with every metric null, and the poller
    // then recorded `reachable: true` for a firewall that answered nothing.
    await withStubbedApi(
      {
        resources: async () => {
          throw new Error('connect ETIMEDOUT 10.0.0.1:443');
        },
        session: async () => {
          throw new Error('connect ETIMEDOUT 10.0.0.1:443');
        },
      },
      async () => {
        const err = await rejection(() => adapter().getPerformanceMetrics());
        // Plain, NOT the capability class: at this point an op-command rejection
        // is indistinguishable from a connection that died mid-request, and
        // mislabelling a real outage as a capability gap hides the outage.
        assertCountsAgainstReachability(err);
        assert.match(err.message, /show system resources failed/);
      }
    );
  });

  it('session info stays best-effort — a secondary failure must not lose the primary reading', async () => {
    await withStubbedApi(
      {
        resources: async () => 'top - up 1 day\n%Cpu(s): 3.0 us\n',
        session: async () => {
          throw new Error('op command timed out');
        },
      },
      async () => {
        const metrics = await adapter().getPerformanceMetrics();
        assert.equal(typeof metrics, 'object');
        // Unknown stays null — never a fabricated 0 session count.
        assert.equal(metrics.sessionCount, null);
      }
    );
  });
});

// ---------------------------------------------------------------------------
// The poller side — converting an adapter throw changes nothing on its own
// ---------------------------------------------------------------------------

describe('engine-worker pollers distinguish reached-but-unreadable from unreachable', () => {
  const src = fs.readFileSync(path.join(REPO, 'services', 'engine-worker.js'), 'utf8');

  // The metric poll's catch block, from its logger.warn to the end of the
  // recordConnectivity handling.
  const metricsCatch = src.slice(
    src.indexOf('Job [snmp-poll] failed for device'),
    src.indexOf("Job [snmp-poll] finished in")
  );

  it('the METRICS poll consults isCapabilityUnavailable (it did not until 2026-09-09)', () => {
    assert.ok(metricsCatch.length > 0, 'could not locate the snmp-poll catch block');
    assert.match(
      metricsCatch,
      /isCapabilityUnavailable\(err\)/,
      'the densest heartbeat on the fleet must not file an absent capability as an outage'
    );
  });

  it('the METRICS poll still has all three outcomes, reachable:false among them', () => {
    assert.match(metricsCatch, /reachable: true/, 'reached-but-unreadable must record reachable:true');
    assert.match(metricsCatch, /reachable: false/, 'a real transport failure must still record reachable:false');
  });

  it('the VPN poll keeps its own check', () => {
    const vpnCatch = src.slice(
      src.indexOf('Job [vpn-session-poll] failed for device'),
      src.indexOf('Job [vpn-session-poll] finished in')
    );
    assert.match(vpnCatch, /isCapabilityUnavailable\(err\)/);
  });

  it('detection is by flag, never instanceof, anywhere in the worker', () => {
    assert.doesNotMatch(src, /instanceof CapabilityUnavailableError/);
  });
});

// ---------------------------------------------------------------------------
// The monthly compliance report's clock
// ---------------------------------------------------------------------------

describe('compliance report period', () => {
  // Month indices are 0-based: 9 = October, 10 = November, 0 = January.
  it('is the month that JUST ENDED, from the local clock the cron fires on', () => {
    assert.equal(reportingPeriod(new Date(2026, 9, 1, 6, 0)), '2026-09');
  });

  it('an engine restart later the same day answers the SAME period (the double-send)', () => {
    // ⛔ The bug: 06:00 ICT on 1 Oct is 23:00 UTC on 30 Sep, so the old
    // getUTCMonth() derivation said 2026-09 at the tick and 2026-10 at a restart
    // hours later — the same report emailed twice under two different keys.
    assert.equal(reportingPeriod(new Date(2026, 9, 1, 6, 0)), reportingPeriod(new Date(2026, 9, 1, 23, 59)));
    assert.equal(reportingPeriod(new Date(2026, 9, 20, 12, 0)), '2026-09');
  });

  it('the next month asks a genuinely new question (the permanent skip)', () => {
    // ⛔ The other half of the bug: 1 Nov 06:00 ICT is 31 Oct 23:00 UTC, so the
    // old derivation asked for 2026-10 — already logged 'success' by that
    // restart — and the tick was skipped, every month from then on.
    assert.equal(reportingPeriod(new Date(2026, 10, 1, 6, 0)), '2026-10');
    assert.notEqual(reportingPeriod(new Date(2026, 10, 1, 6, 0)), reportingPeriod(new Date(2026, 9, 1, 6, 0)));
  });

  it('rolls the year back at the January boundary', () => {
    assert.equal(reportingPeriod(new Date(2026, 0, 1, 6, 0)), '2025-12');
  });

  it('⛔ uses the LOCAL clock — a UTC getter here is the bug returning', () => {
    const src = fs.readFileSync(path.join(REPO, 'lib', 'engines', 'complianceReport.js'), 'utf8');
    const body = src.slice(src.indexOf('function reportingPeriod('));
    const fnOnly = body.slice(0, body.indexOf('\n}') + 2);
    assert.doesNotMatch(fnOnly, /getUTC/, 'the period must be read from the same clock the cron fires on');
  });

  it('the engine worker states the period explicitly rather than letting it be inferred twice', () => {
    const src = fs.readFileSync(path.join(REPO, 'services', 'engine-worker.js'), 'utf8');
    assert.match(src, /dispatchMonthlyReport\(pool,\s*\{\s*period\s*\}\)/);
    assert.match(src, /reportingPeriod\(\)/);
    // The comment on the cron said "06:00 UTC" and was factually wrong.
    assert.doesNotMatch(src, /06:00 UTC/);
  });

  it('an explicit period is honoured by dispatchMonthlyReport', async () => {
    const seen = [];
    const pool = {
      query: async (sql, params) => {
        seen.push({ sql: String(sql), params });
        return { rows: [{ id: 'already-sent' }], rowCount: 1 };
      },
    };
    const result = await dispatchMonthlyReport(pool, { period: '2026-09' });
    assert.equal(result.skipped, true);
    assert.equal(result.period, '2026-09');
    assert.deepEqual(seen[0].params, ['2026-09']);
  });

  it('a malformed explicit period falls back to the computed one, never to a bad key', async () => {
    const pool = { query: async () => ({ rows: [{ id: 'x' }], rowCount: 1 }) };
    const result = await dispatchMonthlyReport(pool, { period: 'not-a-period' });
    assert.match(result.period, /^\d{4}-\d{2}$/);
    assert.equal(result.period, reportingPeriod());
  });
});

// ---------------------------------------------------------------------------
// device_interfaces.ip_address — "no address" is not an address
// ---------------------------------------------------------------------------

describe('interface addresses', () => {
  // 95 of 241 live rows (39%, 10 devices) held the literal string 'N/A',
  // because PAN-OS prints that for an interface with no IP configured. It is a
  // TEXT column, so nothing errored — and every `ip_address IS NOT NULL` test
  // counted those interfaces as ADDRESSED. Same class as hit_count's old
  // DEFAULT 0. Fixed at the collection point, in the adapter.
  it('Palo Alto API turns "N/A" into NULL before it can be stored', async () => {
    const a = new PaloaltoAdapter({ device: DEVICE, pool: POOL });
    a._getConn = async () => ({ stub: true });
    const original = paloaltoApi.showInterfacesAll;
    const parser = require('../lib/adapters/paloalto/parser');
    const originalParse = parser.parseInterfacesXml;
    paloaltoApi.showInterfacesAll = async () => ({ stub: true });
    parser.parseInterfacesXml = () => [
      { name: 'ethernet1/1', ipAddress: '10.1.1.1/24', zone: 'trust', vdom: null, enabled: true },
      { name: 'tunnel.1', ipAddress: 'N/A', zone: null, vdom: null, enabled: true },
      { name: 'ethernet1/9', ipAddress: '   ', zone: null, vdom: null, enabled: false },
      { name: 'ethernet1/8', ipAddress: 'none', zone: null, vdom: null, enabled: false },
    ];
    try {
      const { interfaces } = await a.getInterfaces();
      assert.equal(interfaces[0].ipAddress, '10.1.1.1/24', 'a real address must survive untouched');
      assert.equal(interfaces[1].ipAddress, null, "PAN-OS's literal 'N/A' is not an address");
      assert.equal(interfaces[2].ipAddress, null, 'an empty string is not an address');
      assert.equal(interfaces[3].ipAddress, null, "'none' is not an address");
      // Every interface is still REPORTED — this nulls a field, it never drops a row.
      assert.equal(interfaces.length, 4);
    } finally {
      paloaltoApi.showInterfacesAll = original;
      parser.parseInterfacesXml = originalParse;
    }
  });
});
